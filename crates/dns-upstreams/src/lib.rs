//! Forwards DNS queries to a pool of upstream servers.
//!
//! By default, servers are tried in configured order, so failover is deterministic. A load balanced
//! pool starts each query on the next server instead. Each exchange uses a fresh random transaction
//! ID, and responses that don't match the question are ignored.

mod dnssec;
mod server;
mod transport;

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use thiserror::Error;
use tokio::time::{Instant, timeout};
use tracing::{debug, warn};

pub use dnssec::{DnssecStatus, DnssecValidator, TrustAnchors, Validated};
pub use server::{ServerParseError, UpstreamServer};
use transport::{ExchangeError, Transport};

/// Largest EDNS UDP payload offered upstream, following the DNS Flag Day 2020 recommendation.
pub const MAX_UDP_PAYLOAD: u16 = 1232;

/// In a load balanced pool, this many failures in a row sets a server aside. One lost packet
/// shouldn't move traffic.
const FAILURES_BEFORE_REST: u32 = 2;
/// How long a server is set aside, so a dead one delays one query in this long, not every other one.
const REST: Duration = Duration::from_secs(30);

/// How to reach a pool of upstream servers.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Servers in the order they are tried, unless `load_balance` is on.
    pub servers: Vec<UpstreamServer>,
    /// Starts each query on the next server, instead of always on the first.
    pub load_balance: bool,
    /// Time allowed for one server, including any TCP fallback.
    pub attempt_timeout: Duration,
    /// Time allowed for the whole query, across all servers and rounds.
    pub total_timeout: Duration,
    /// How many times to go through the server list.
    pub rounds: u32,
    /// Certificates to trust for encrypted upstreams, as DER. By default this is the Mozilla root
    /// program's list, built in so it doesn't depend on the host.
    pub trust_roots: Option<Vec<Vec<u8>>>,
}

/// The parts of a client's question that are forwarded upstream.
///
/// Other EDNS options, such as client subnet and cookies, are deliberately not forwarded.
#[derive(Clone, Debug)]
pub struct UpstreamRequest {
    pub query: Query,
    pub recursion_desired: bool,
    pub checking_disabled: bool,
    /// Present when the client used EDNS.
    pub edns: Option<EdnsRequest>,
}

/// The EDNS parameters forwarded upstream.
#[derive(Clone, Copy, Debug)]
pub struct EdnsRequest {
    pub max_payload: u16,
    pub dnssec_ok: bool,
}

/// Why no upstream produced a usable response.
#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("no upstream server responded")]
    AllFailed,
    #[error("failed to encode the upstream query: {0}")]
    Encode(#[from] hickory_proto::ProtoError),
}

/// A pool couldn't be built from its configuration.
#[derive(Debug, Error)]
pub enum PoolConfigError {
    #[error("upstream {server}: {reason}")]
    Server { server: String, reason: String },
}

/// An answer and the server that gave it.
#[derive(Clone, Debug)]
pub struct Forwarded {
    pub message: Message,
    pub server: String,
}

#[derive(Debug, Default)]
struct ServerCounters {
    responses: AtomicU64,
    failures: AtomicU64,
    last_latency_us: AtomicU64,
    failures_in_a_row: AtomicU32,
    /// When a set aside server returns, in milliseconds since the pool started. Zero if it's in use.
    resting_until_ms: AtomicU64,
}

/// What this node has seen from one upstream server since it started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerStats {
    pub server: String,
    pub responses: u64,
    pub failures: u64,
    pub last_latency_us: u64,
}

struct PooledServer {
    label: String,
    transport: Transport,
    counters: ServerCounters,
}

/// A pool of upstream servers.
pub struct UpstreamPool {
    servers: Vec<PooledServer>,
    load_balance: bool,
    next_start: AtomicUsize,
    started: Instant,
    attempt_timeout: Duration,
    total_timeout: Duration,
    rounds: u32,
    last_server: Mutex<Option<String>>,
}

impl UpstreamPool {
    pub fn new(config: PoolConfig) -> Result<Self, PoolConfigError> {
        let tls_roots = transport::root_store(config.trust_roots.as_deref())?;
        let servers = config
            .servers
            .iter()
            .map(|server| {
                Ok(PooledServer {
                    label: server.to_string(),
                    transport: Transport::new(server, &tls_roots)?,
                    counters: ServerCounters::default(),
                })
            })
            .collect::<Result<Vec<_>, PoolConfigError>>()?;
        Ok(Self {
            servers,
            load_balance: config.load_balance,
            next_start: AtomicUsize::new(0),
            started: Instant::now(),
            attempt_timeout: config.attempt_timeout,
            total_timeout: config.total_timeout,
            rounds: config.rounds,
            last_server: Mutex::new(None),
        })
    }

    /// Counters for each server, in configured order.
    pub fn stats(&self) -> Vec<ServerStats> {
        self.servers
            .iter()
            .map(|server| ServerStats {
                server: server.label.clone(),
                responses: server.counters.responses.load(Ordering::Relaxed),
                failures: server.counters.failures.load(Ordering::Relaxed),
                last_latency_us: server.counters.last_latency_us.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// The server that most recently answered, for reporting.
    pub fn last_server(&self) -> Option<String> {
        self.last_server
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The order to try servers for one query. A load balanced pool rotates through them, and
    /// leaves servers that are set aside for last, so they're still used if nothing else answers.
    fn attempt_order(&self) -> Vec<usize> {
        let count = self.servers.len();
        if !self.load_balance || count == 0 {
            return (0..count).collect();
        }
        let start = self.next_start.fetch_add(1, Ordering::Relaxed) % count;
        let now = self.elapsed_ms();
        let (mut order, resting): (Vec<usize>, Vec<usize>) = (0..count)
            .map(|offset| (start + offset) % count)
            .partition(|&index| {
                self.servers[index]
                    .counters
                    .resting_until_ms
                    .load(Ordering::Relaxed)
                    <= now
            });
        order.extend(resting);
        order
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// A server that gave any response is reachable, even if the response was a failure.
    fn note_reachable(&self, server: &PooledServer) {
        server
            .counters
            .failures_in_a_row
            .store(0, Ordering::Relaxed);
        server.counters.resting_until_ms.store(0, Ordering::Relaxed);
    }

    fn note_unreachable(&self, server: &PooledServer) {
        let failures = server
            .counters
            .failures_in_a_row
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        if self.load_balance && failures >= FAILURES_BEFORE_REST {
            let until = self.elapsed_ms() + u64::try_from(REST.as_millis()).unwrap_or(u64::MAX);
            server
                .counters
                .resting_until_ms
                .store(until, Ordering::Relaxed);
            warn!(server = %server.label, "upstream isn't responding, so it's being set aside");
        }
    }

    /// Forwards a query, trying servers until one gives a usable answer.
    ///
    /// SERVFAIL and REFUSED move on to the next server. If every server fails that way, the last
    /// such response is returned so the client sees what upstream said.
    pub async fn forward(&self, request: &UpstreamRequest) -> Result<Forwarded, UpstreamError> {
        let deadline = Instant::now() + self.total_timeout;
        let mut last_failure = None;
        let order = self.attempt_order();

        for round in 0..self.rounds {
            for server in order.iter().filter_map(|&index| self.servers.get(index)) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    warn!("upstream deadline reached");
                    return last_failure.ok_or(UpstreamError::AllFailed);
                }
                let budget = remaining.min(self.attempt_timeout);
                let (id, wire) = encode_query(request, server.transport.uses_zero_id())?;
                let started = Instant::now();
                let label = &server.label;

                let exchange = server.transport.exchange(&wire, id, &request.query);
                match timeout(budget, exchange).await {
                    Ok(Ok(response)) if is_retryable(response.metadata.response_code) => {
                        self.note_reachable(server);
                        server.counters.failures.fetch_add(1, Ordering::Relaxed);
                        // Query names stay out of WARN and INFO logs for privacy (spec section 7.3).
                        warn!(
                            server = %label, round,
                            rcode = %response.metadata.response_code,
                            "upstream failed, trying the next server"
                        );
                        last_failure = Some(Forwarded {
                            message: response,
                            server: label.clone(),
                        });
                    }
                    Ok(Ok(response)) => {
                        self.note_reachable(server);
                        debug!(server = %label, round, query = %request.query, "upstream answered");
                        server.counters.responses.fetch_add(1, Ordering::Relaxed);
                        let latency = u64::try_from(started.elapsed().as_micros());
                        server
                            .counters
                            .last_latency_us
                            .store(latency.unwrap_or(u64::MAX), Ordering::Relaxed);
                        *self
                            .last_server
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner) = Some(label.clone());
                        return Ok(Forwarded {
                            message: response,
                            server: label.clone(),
                        });
                    }
                    Ok(Err(error)) => {
                        self.note_unreachable(server);
                        server.counters.failures.fetch_add(1, Ordering::Relaxed);
                        warn!(server = %label, round, %error, "upstream exchange failed");
                    }
                    Err(_) => {
                        self.note_unreachable(server);
                        server.counters.failures.fetch_add(1, Ordering::Relaxed);
                        let error = ExchangeError::Timeout;
                        warn!(server = %label, round, %error, "upstream exchange failed");
                    }
                }
            }
        }
        last_failure.ok_or(UpstreamError::AllFailed)
    }
}

fn is_retryable(code: ResponseCode) -> bool {
    matches!(code, ResponseCode::ServFail | ResponseCode::Refused)
}

fn encode_query(request: &UpstreamRequest, zero_id: bool) -> Result<(u16, Vec<u8>), UpstreamError> {
    // RFC 8484 recommends ID 0 over HTTPS, which authenticates the response anyway.
    let id: u16 = if zero_id { 0 } else { rand::random() };
    let mut message = Message::query();
    message.metadata.id = id;
    message.metadata.recursion_desired = request.recursion_desired;
    message.metadata.checking_disabled = request.checking_disabled;
    message.add_query(request.query.clone());

    if let Some(params) = request.edns {
        let mut edns = Edns::new();
        edns.set_max_payload(params.max_payload.clamp(512, MAX_UDP_PAYLOAD));
        edns.set_dnssec_ok(params.dnssec_ok);
        message.set_edns(edns);
    }
    Ok((id, message.to_vec()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(load_balance: bool) -> UpstreamPool {
        UpstreamPool::new(PoolConfig {
            servers: ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
                .iter()
                .map(|server| server.parse().unwrap())
                .collect(),
            load_balance,
            attempt_timeout: Duration::from_millis(50),
            total_timeout: Duration::from_millis(100),
            rounds: 1,
            trust_roots: None,
        })
        .unwrap()
    }

    #[test]
    fn servers_stay_in_order_unless_load_balanced() {
        let pool = pool(false);
        for _ in 0..3 {
            pool.note_unreachable(&pool.servers[0]);
            assert_eq!(pool.attempt_order(), [0, 1, 2]);
        }
    }

    #[test]
    fn a_load_balanced_pool_rotates_its_starting_server() {
        let pool = pool(true);
        assert_eq!(pool.attempt_order(), [0, 1, 2]);
        assert_eq!(pool.attempt_order(), [1, 2, 0]);
        assert_eq!(pool.attempt_order(), [2, 0, 1]);
        assert_eq!(pool.attempt_order(), [0, 1, 2]);
    }

    #[test]
    fn a_failing_server_is_set_aside_and_can_return() {
        let pool = pool(true);
        let failing = &pool.servers[1];

        // One lost packet doesn't count.
        pool.note_unreachable(failing);
        assert_eq!(pool.attempt_order(), [0, 1, 2]);

        pool.note_unreachable(failing);
        assert_eq!(
            pool.attempt_order(),
            [2, 0, 1],
            "tried only as a last resort"
        );
        assert_eq!(pool.attempt_order(), [2, 0, 1]);
        assert_eq!(pool.attempt_order(), [0, 2, 1]);

        pool.note_reachable(failing);
        assert_eq!(pool.attempt_order(), [1, 2, 0]);
    }

    #[test]
    fn a_rest_ends_on_its_own_and_one_more_failure_restarts_it() {
        let pool = pool(true);
        let failing = &pool.servers[0];
        pool.note_unreachable(failing);
        pool.note_unreachable(failing);
        assert_eq!(pool.attempt_order().last(), Some(&0));

        // The rest is over, but it hasn't answered yet.
        failing
            .counters
            .resting_until_ms
            .store(1, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(pool.attempt_order().len(), 3);
        assert_ne!(pool.attempt_order().last(), Some(&0));

        pool.note_unreachable(failing);
        assert_eq!(pool.attempt_order().last(), Some(&0));
    }
}
