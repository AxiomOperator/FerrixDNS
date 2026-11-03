//! Forwards DNS queries to an ordered pool of upstream servers.
//!
//! Servers are always tried in configured order, so failover is deterministic. Each exchange uses
//! a fresh random transaction ID and source port, and responses that don't match the question are
//! ignored.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{Instant, timeout};
use tracing::{debug, warn};

/// Largest EDNS UDP payload offered upstream, following the DNS Flag Day 2020 recommendation.
pub const MAX_UDP_PAYLOAD: u16 = 1232;
const UDP_RECEIVE_BUFFER: usize = 4096;

/// How to reach a pool of upstream servers.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Servers in the order they are tried.
    pub servers: Vec<SocketAddr>,
    /// Time allowed for one server, including any TCP fallback.
    pub attempt_timeout: Duration,
    /// Time allowed for the whole query, across all servers and rounds.
    pub total_timeout: Duration,
    /// How many times to go through the server list.
    pub rounds: u32,
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

#[derive(Debug, Error)]
enum ExchangeError {
    #[error("timed out")]
    Timeout,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("TCP response failed validation")]
    InvalidTcpResponse,
    #[error("upstream response is too long or malformed: {0}")]
    Decode(String),
}

/// An ordered pool of upstream servers.
#[derive(Clone, Debug)]
pub struct UpstreamPool {
    config: PoolConfig,
}

impl UpstreamPool {
    pub fn new(config: PoolConfig) -> Self {
        Self { config }
    }

    /// Forwards a query, trying servers in order until one gives a usable answer.
    ///
    /// SERVFAIL and REFUSED move on to the next server. If every server fails that way, the last
    /// such response is returned so the client sees what upstream said.
    pub async fn forward(&self, request: &UpstreamRequest) -> Result<Message, UpstreamError> {
        let deadline = Instant::now() + self.config.total_timeout;
        let mut last_failure = None;

        for round in 0..self.config.rounds {
            for server in &self.config.servers {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    warn!("upstream deadline reached");
                    return last_failure.ok_or(UpstreamError::AllFailed);
                }
                let budget = remaining.min(self.config.attempt_timeout);
                let (id, wire) = encode_query(request)?;

                match timeout(budget, exchange(*server, &wire, id, &request.query)).await {
                    Ok(Ok(response)) if is_retryable(response.metadata.response_code) => {
                        // Query names stay out of WARN and INFO logs for privacy (spec section 7.3).
                        warn!(
                            %server, round,
                            rcode = %response.metadata.response_code,
                            "upstream failed, trying the next server"
                        );
                        last_failure = Some(response);
                    }
                    Ok(Ok(response)) => {
                        debug!(%server, round, query = %request.query, "upstream answered");
                        return Ok(response);
                    }
                    Ok(Err(error)) => {
                        warn!(%server, round, %error, "upstream exchange failed");
                    }
                    Err(_) => {
                        let error = ExchangeError::Timeout;
                        warn!(%server, round, %error, "upstream exchange failed");
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

fn encode_query(request: &UpstreamRequest) -> Result<(u16, Vec<u8>), UpstreamError> {
    let id: u16 = rand::random();
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

fn matches_query(response: &Message, id: u16, query: &Query) -> bool {
    response.metadata.id == id
        && response.metadata.message_type == MessageType::Response
        && response.metadata.op_code == OpCode::Query
        && response.queries.len() == 1
        && response.queries.first() == Some(query)
}

async fn exchange(
    server: SocketAddr,
    wire: &[u8],
    id: u16,
    query: &Query,
) -> Result<Message, ExchangeError> {
    let response = exchange_udp(server, wire, id, query).await?;
    if response.metadata.truncation {
        debug!(%server, %query, "UDP response truncated, retrying over TCP");
        return exchange_tcp(server, wire, id, query).await;
    }
    Ok(response)
}

/// Waits for a matching response. Anything else is ignored rather than ending the wait, so an
/// off-path attacker can't cause a failure by sending a forged packet first.
async fn exchange_udp(
    server: SocketAddr,
    wire: &[u8],
    id: u16,
    query: &Query,
) -> Result<Message, ExchangeError> {
    let bind_ip = match server.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let socket = UdpSocket::bind((bind_ip, 0)).await?;
    // A connected socket only receives packets from this server.
    socket.connect(server).await?;
    socket.send(wire).await?;

    let mut buffer = vec![0_u8; UDP_RECEIVE_BUFFER];
    loop {
        let length = socket.recv(&mut buffer).await?;
        let Some(received) = buffer.get(..length) else {
            continue;
        };
        match Message::from_vec(received) {
            Ok(response) if matches_query(&response, id, query) => return Ok(response),
            Ok(_) => debug!(%server, "ignored UDP response that doesn't match the query"),
            Err(error) => debug!(%server, %error, "ignored malformed UDP response"),
        }
    }
}

async fn exchange_tcp(
    server: SocketAddr,
    wire: &[u8],
    id: u16,
    query: &Query,
) -> Result<Message, ExchangeError> {
    let length = u16::try_from(wire.len())
        .map_err(|_| ExchangeError::Decode("query is too long for TCP framing".to_owned()))?;

    let mut stream = TcpStream::connect(server).await?;
    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(wire);
    stream.write_all(&framed).await?;

    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix).await?;
    let mut buffer = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut buffer).await?;

    let response =
        Message::from_vec(&buffer).map_err(|error| ExchangeError::Decode(error.to_string()))?;
    if matches_query(&response, id, query) {
        Ok(response)
    } else {
        Err(ExchangeError::InvalidTcpResponse)
    }
}
