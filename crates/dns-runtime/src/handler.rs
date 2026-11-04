use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use dns_cache::{CacheKey, DnsCache};
use dns_policy::{
    BlockConfig, BlockResponse, ClientSource, Decision, DecisionSource, DomainName, Filtering,
    LOCAL_NEGATIVE_TTL_SECONDS, LocalAnswer, LocalData, LocalQuery, LocalRecord, QueryLogMode,
    Verdict,
};
use dns_telemetry::{Outcome, QueryEvent, Telemetry};
use dns_upstreams::{
    DnssecStatus, DnssecValidator, EdnsRequest, MAX_UDP_PAYLOAD, UpstreamPool, UpstreamRequest,
};
use hickory_server::net::runtime::Time;
use hickory_server::proto::op::{
    Edns, Header, HeaderCounts, LowerQuery, Message, MessageType, Metadata, OpCode, ResponseCode,
};
use hickory_server::proto::rr::rdata::opt::EdnsOption;
use hickory_server::proto::rr::rdata::{A, AAAA, CNAME, NS, PTR, SOA};
use hickory_server::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::Services;
use crate::devices::DeviceInfo;
use crate::policy::PolicyHandle;
use crate::rate_limit::RateDecision;

/// EDNS option code for Extended DNS Errors (RFC 8914).
const EDE_OPTION_CODE: u16 = 15;
/// The "Blocked" Extended DNS Error, as its two-byte wire value (RFC 8914 section 4.16).
const EDE_BLOCKED: [u8; 2] = 15_u16.to_be_bytes();
/// The "DNSSEC Bogus" Extended DNS Error (RFC 8914 section 4.7).
const EDE_DNSSEC_BOGUS: [u8; 2] = 6_u16.to_be_bytes();

/// Validates requests, applies policy and forwards allowed queries upstream.
pub struct ForwardHandler {
    pool: Arc<UpstreamPool>,
    permits: Semaphore,
    policy: PolicyHandle,
    telemetry: Option<Arc<Telemetry>>,
    cache: Option<Arc<DnsCache>>,
    validator: Option<DnssecValidator>,
    services: Services,
}

/// What a handler is built from.
pub(crate) struct HandlerConfig {
    pub pool: Arc<UpstreamPool>,
    pub max_concurrent_requests: usize,
    pub policy: PolicyHandle,
    pub telemetry: Option<Arc<Telemetry>>,
    pub cache: Option<Arc<DnsCache>>,
    pub validator: Option<DnssecValidator>,
    pub services: Services,
}

/// Who sent a query.
struct Caller {
    address: IpAddr,
    device: Option<Arc<DeviceInfo>>,
}

impl Caller {
    fn source(&self) -> ClientSource<'_> {
        ClientSource {
            address: self.address,
            mac: self.device.as_ref().and_then(|device| device.mac),
            hostname: self
                .device
                .as_ref()
                .and_then(|device| device.hostname.as_ref()),
        }
    }
}

/// Why a query was blocked, owned so it can outlive the policy snapshot.
#[derive(Clone, Debug, Default)]
struct BlockReason {
    rule_id: Option<String>,
    source_list_id: Option<String>,
    matched_name: Option<String>,
}

impl BlockReason {
    fn new(decision: &Decision<'_>, matched_name: &str) -> Self {
        let (rule_id, source_list_id) = match decision.source {
            DecisionSource::Rule(id) => (Some(id.to_owned()), None),
            DecisionSource::List(id) => (None, Some(id.to_owned())),
            DecisionSource::Default => (None, None),
        };
        Self {
            rule_id,
            source_list_id,
            matched_name: Some(matched_name.to_owned()),
        }
    }
}

/// How a request ended, for telemetry.
struct Finished {
    info: ResponseInfo,
    outcome: Outcome,
    reason: BlockReason,
    upstream: Option<String>,
    /// False for rate-limited queries that have already been reported recently.
    recorded: bool,
}

impl Finished {
    fn plain(info: ResponseInfo, outcome: Outcome) -> Self {
        Self {
            info,
            outcome,
            reason: BlockReason::default(),
            upstream: None,
            recorded: true,
        }
    }
}

/// How an upstream answer was obtained, and what the client asked for.
struct AnswerMeta<'a> {
    caller: &'a Caller,
    dnssec_ok: bool,
    /// Whether this node validated the answer with DNSSEC.
    validated: bool,
    /// The server that answered, or `None` for an answer from the cache.
    upstream: Option<String>,
}

enum AnswerAction {
    Return,
    Block(BlockConfig, BlockReason),
    Fail,
}

impl ForwardHandler {
    pub(crate) fn new(config: HandlerConfig) -> Self {
        Self {
            pool: config.pool,
            permits: Semaphore::new(config.max_concurrent_requests),
            policy: config.policy,
            telemetry: config.telemetry,
            cache: config.cache,
            validator: config.validator,
            services: config.services,
        }
    }

    fn filtering(&self) -> Filtering {
        if self.services.pause.is_active() {
            Filtering::EmergencyOnly
        } else {
            Filtering::Normal
        }
    }

    /// Finds out who's asking. A query only waits for this when policy depends on the answer.
    async fn caller(&self, address: IpAddr) -> Caller {
        let address = address.to_canonical();
        let devices = &self.services.devices;
        let device = match devices.get(address) {
            Some(device) => Some(device),
            None if self.policy.load().needs_device(address) => devices.identify(address).await,
            None => {
                devices.observe(address);
                None
            }
        };
        Caller { address, device }
    }

    /// Refuses a client that's over its limit. This comes first, so floods stay cheap.
    async fn rate_limited<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &R,
    ) -> Option<Finished> {
        let address = request.src().ip().to_canonical();
        let policy = self.policy.load();
        let limit = policy.rate_limit_for(address)?;
        let RateDecision::Limited { report } = self.services.rate_limiter.check(address, limit)
        else {
            return None;
        };
        if report {
            // Addresses are only logged where the operator has chosen to keep them.
            if policy.telemetry().mode == QueryLogMode::Full {
                warn!(client = %address, limit, "a client is over its query limit");
            } else {
                warn!(limit, "a client is over its query limit");
            }
        }
        drop(policy);
        let info = send_error(request, ResponseCode::Refused, response_handle.clone()).await;
        Some(Finished {
            recorded: report,
            ..Finished::plain(info, Outcome::RateLimited)
        })
    }

    /// Checks a query name, returning how to answer if it's blocked.
    fn query_block(
        &self,
        caller: &Caller,
        name: &DomainName,
    ) -> Option<(BlockConfig, BlockReason)> {
        let policy = self.policy.load();
        match policy.check_query_with(self.filtering(), caller.source(), name) {
            Verdict::Allow | Verdict::ChainTooDeep | Verdict::BlockTarget { .. } => None,
            Verdict::Block(decision) => {
                debug!(name = name.as_str(), ?decision, "blocked query");
                Some((policy.block(), BlockReason::new(&decision, name.as_str())))
            }
        }
    }

    /// Checks an upstream answer against the policy active now, not when the query arrived.
    fn answer_action(
        &self,
        caller: &Caller,
        name: &DomainName,
        targets: &[DomainName],
    ) -> AnswerAction {
        let policy = self.policy.load();
        match policy.check_answer_with(self.filtering(), caller.source(), name, targets) {
            Verdict::Allow => AnswerAction::Return,
            Verdict::Block(decision) => {
                debug!(name = name.as_str(), ?decision, "blocked answer");
                AnswerAction::Block(policy.block(), BlockReason::new(&decision, name.as_str()))
            }
            Verdict::BlockTarget {
                decision,
                target_index,
            } => {
                debug!(name = name.as_str(), ?decision, "blocked CNAME target");
                let matched = targets
                    .get(target_index)
                    .map_or(name.as_str(), DomainName::as_str);
                AnswerAction::Block(policy.block(), BlockReason::new(&decision, matched))
            }
            Verdict::ChainTooDeep => AnswerAction::Fail,
        }
    }

    /// Runs the request path. Everything observable about the result comes back in `Finished`.
    async fn process<R: ResponseHandler>(&self, request: &Request, response_handle: R) -> Finished {
        if let Some(finished) = self.rate_limited(request, &response_handle).await {
            return finished;
        }
        if request.metadata.op_code != OpCode::Query {
            let info = send_error(request, ResponseCode::NotImp, response_handle).await;
            return Finished::plain(info, Outcome::Rejected);
        }
        if request.edns.as_ref().is_some_and(|edns| edns.version() > 0) {
            let info = send_error(request, ResponseCode::BADVERS, response_handle).await;
            return Finished::plain(info, Outcome::Rejected);
        }

        let [question] = request.queries.queries() else {
            let info = send_error(request, ResponseCode::FormErr, response_handle).await;
            return Finished::plain(info, Outcome::Rejected);
        };
        // Only Internet-class lookups are forwarded, and zone transfers are never served.
        if question.query_class() != DNSClass::IN
            || matches!(question.query_type(), RecordType::AXFR | RecordType::IXFR)
        {
            let info = send_error(request, ResponseCode::Refused, response_handle).await;
            return Finished::plain(info, Outcome::Rejected);
        }

        // A name that can't be normalized can't be checked, so it must not get past policy.
        let Ok(name) = DomainName::parse(&question.name().to_string()) else {
            debug!(src = %request.src(), "refused a name that can't be normalized");
            let info = send_error(request, ResponseCode::Refused, response_handle).await;
            return Finished::plain(info, Outcome::Rejected);
        };
        let caller = self.caller(request.src().ip()).await;

        // Names this node owns are answered here and never go upstream.
        if let Some(finished) = self
            .answer_locally(request, question, &name, &caller, response_handle.clone())
            .await
        {
            return finished;
        }

        // Blocked queries need no upstream capacity, so they're decided before admission.
        if let Some((block, reason)) = self.query_block(&caller, &name) {
            let info = send_blocked(request, question, block, response_handle).await;
            return Finished {
                info,
                outcome: Outcome::Blocked,
                reason,
                upstream: None,
                recorded: true,
            };
        }

        // Names with their own servers never reach the default upstreams, even if those fail.
        let route = self
            .policy
            .load()
            .forward_route(&name)
            .map(|route| (route.route, Arc::clone(&route.servers), route.load_balance));

        let edns = request.edns.as_ref().map(|edns| EdnsRequest {
            max_payload: edns.max_payload(),
            dnssec_ok: edns.flags().dnssec_ok,
        });
        let dnssec_ok = edns.is_some_and(|edns| edns.dnssec_ok);
        let cache_key = self.cache.as_ref().map(|_| CacheKey {
            name: name.as_str().to_owned(),
            record_type: question.query_type(),
            dnssec_ok,
            checking_disabled: request.metadata.checking_disabled,
            route: route.as_ref().map_or(0, |(number, _, _)| *number),
        });
        if let (Some(cache), Some(key)) = (&self.cache, &cache_key)
            && let Some(hit) = cache.get(key)
        {
            return self
                .finish_answer(
                    request,
                    question,
                    &name,
                    hit.message,
                    AnswerMeta {
                        caller: &caller,
                        dnssec_ok,
                        validated: hit.validated,
                        upstream: None,
                    },
                    response_handle,
                )
                .await;
        }

        let Ok(_permit) = self.permits.try_acquire() else {
            debug!(src = %request.src(), "over the concurrent request limit");
            let info = send_error(request, ResponseCode::ServFail, response_handle).await;
            return Finished::plain(info, Outcome::Failed);
        };

        // CD means the client wants to validate for itself, so this node stays out of the way.
        // Forward zones are usually private, so they have no chain of trust to validate against.
        if let Some(validator) = &self.validator
            && !request.metadata.checking_disabled
            && route.is_none()
        {
            let validated = match validator.resolve(question.original().clone()).await {
                Ok(validated) => validated,
                Err(error) => {
                    warn!(%error, "forwarding failed");
                    let info = send_error(request, ResponseCode::ServFail, response_handle).await;
                    return Finished::plain(info, Outcome::Failed);
                }
            };
            if validated.status == DnssecStatus::Bogus {
                debug!(name = name.as_str(), "DNSSEC validation failed");
                let info = send_dnssec_bogus(request, response_handle).await;
                return Finished::plain(info, Outcome::Failed);
            }
            let secure = validated.status == DnssecStatus::Secure;
            if let (Some(cache), Some(key)) = (&self.cache, cache_key) {
                cache.insert(key, &validated.message, secure);
            }
            return self
                .finish_answer(
                    request,
                    question,
                    &name,
                    validated.message,
                    AnswerMeta {
                        caller: &caller,
                        dnssec_ok,
                        validated: secure,
                        upstream: self.pool.last_server(),
                    },
                    response_handle,
                )
                .await;
        }

        let upstream_request = UpstreamRequest {
            query: question.original().clone(),
            recursion_desired: request.metadata.recursion_desired,
            checking_disabled: request.metadata.checking_disabled,
            edns,
        };

        let pool = match &route {
            Some((_, servers, load_balance)) => {
                match self.services.conditional.pool(servers, *load_balance) {
                    Ok(pool) => pool,
                    Err(error) => {
                        warn!(%error, "cannot reach a forward zone's servers");
                        let info =
                            send_error(request, ResponseCode::ServFail, response_handle).await;
                        return Finished::plain(info, Outcome::Failed);
                    }
                }
            }
            None => Arc::clone(&self.pool),
        };
        let forwarded = match pool.forward(&upstream_request).await {
            Ok(forwarded) => forwarded,
            Err(error) => {
                warn!(%error, "forwarding failed");
                let info = send_error(request, ResponseCode::ServFail, response_handle).await;
                return Finished::plain(info, Outcome::Failed);
            }
        };

        // The answer is stored before policy runs, because the cache holds upstream answers and
        // never policy decisions. Policy checks every answer, wherever it came from.
        if let (Some(cache), Some(key)) = (&self.cache, cache_key) {
            cache.insert(key, &forwarded.message, false);
        }
        self.finish_answer(
            request,
            question,
            &name,
            forwarded.message,
            AnswerMeta {
                caller: &caller,
                dnssec_ok,
                validated: false,
                upstream: Some(forwarded.server),
            },
            response_handle,
        )
        .await
    }

    /// Answers from local zones and reserved names, if this node owns the question.
    async fn answer_locally<R: ResponseHandler>(
        &self,
        request: &Request,
        question: &LowerQuery,
        name: &DomainName,
        caller: &Caller,
        response_handle: R,
    ) -> Option<Finished> {
        let (answer, blocked) = {
            let policy = self.policy.load();
            let answer = policy.local_answer(name, local_query(question.query_type()))?;
            // An operator's forward zone takes over a reserved name, like a private reverse zone.
            if !answer.policy_applies && policy.forward_route(name).is_some() {
                return None;
            }
            let blocked = match policy.check_local_with(self.filtering(), caller.source(), &answer)
            {
                Verdict::Allow | Verdict::ChainTooDeep => None,
                Verdict::Block(decision) => {
                    Some((policy.block(), BlockReason::new(&decision, name.as_str())))
                }
                Verdict::BlockTarget {
                    decision,
                    target_index,
                } => {
                    let matched = answer
                        .names
                        .get(target_index + 1)
                        .map_or(name.as_str(), DomainName::as_str);
                    Some((policy.block(), BlockReason::new(&decision, matched)))
                }
            };
            (answer, blocked)
        };
        if let Some((block, reason)) = blocked {
            let info = send_blocked(request, question, block, response_handle).await;
            return Some(Finished {
                info,
                outcome: Outcome::Blocked,
                reason,
                upstream: None,
                recorded: true,
            });
        }
        let info = send_local(request, question, &answer, response_handle).await;
        Some(Finished::plain(info, Outcome::Local))
    }

    /// Applies policy to an upstream answer, whether it's fresh or cached, and responds.
    async fn finish_answer<R: ResponseHandler>(
        &self,
        request: &Request,
        question: &LowerQuery,
        name: &DomainName,
        message: Message,
        meta: AnswerMeta<'_>,
        response_handle: R,
    ) -> Finished {
        let AnswerMeta {
            caller,
            dnssec_ok,
            validated,
            upstream,
        } = meta;
        let action = match cname_targets(&message) {
            Some(targets) => self.answer_action(caller, name, &targets),
            None => AnswerAction::Fail,
        };
        match action {
            AnswerAction::Return => {
                let failed = matches!(
                    message.metadata.response_code,
                    ResponseCode::ServFail | ResponseCode::Refused
                );
                let info =
                    send_upstream_response(request, message, dnssec_ok, validated, response_handle)
                        .await;
                let outcome = match (failed, &upstream) {
                    (true, _) => Outcome::Failed,
                    (false, Some(_)) => Outcome::Forwarded,
                    (false, None) => Outcome::Cached,
                };
                Finished {
                    info,
                    outcome,
                    reason: BlockReason::default(),
                    upstream,
                    recorded: true,
                }
            }
            AnswerAction::Block(block, reason) => {
                let info = send_blocked(request, question, block, response_handle).await;
                Finished {
                    info,
                    outcome: Outcome::Blocked,
                    reason,
                    upstream,
                    recorded: true,
                }
            }
            AnswerAction::Fail => {
                debug!(src = %request.src(), "an answer's CNAME chain can't be checked");
                let info = send_error(request, ResponseCode::ServFail, response_handle).await;
                Finished::plain(info, Outcome::Failed)
            }
        }
    }

    /// Records a finished request. This only touches memory and a bounded queue.
    fn record(&self, request: &Request, finished: Finished, started: Instant) {
        let Some(telemetry) = &self.telemetry else {
            return;
        };
        if !finished.recorded {
            return;
        }
        let policy = self.policy.load();
        let source = request.src().ip().to_canonical();
        let question = request.queries.queries().first();
        let occurred_at_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
            });
        let event = QueryEvent {
            seq: 0,
            occurred_at_ms,
            client_id: {
                let caller = Caller {
                    address: source,
                    device: self.services.devices.get(source),
                };
                policy
                    .identity(caller.source())
                    .map(|identity| identity.id.to_string())
            },
            client_ip: Some(source.to_string()),
            qname: question.map(|question| {
                let name = question.name().to_string();
                let trimmed = name.strip_suffix('.').unwrap_or(&name);
                if trimmed.is_empty() {
                    ".".to_owned()
                } else {
                    trimmed.to_owned()
                }
            }),
            matched_name: finished.reason.matched_name,
            qtype: question.map_or_else(
                || "NONE".to_owned(),
                |question| question.query_type().to_string(),
            ),
            outcome: finished.outcome,
            rcode: finished.info.response_code.to_str().to_owned(),
            rule_id: finished.reason.rule_id,
            source_list_id: finished.reason.source_list_id,
            upstream: finished.upstream,
            duration_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            revision_id: Some(policy.revision().to_owned()),
        };
        telemetry.record(event, policy.telemetry().mode);
    }
}

fn local_query(record_type: RecordType) -> LocalQuery {
    match record_type {
        RecordType::A => LocalQuery::A,
        RecordType::AAAA => LocalQuery::Aaaa,
        RecordType::CNAME => LocalQuery::Cname,
        RecordType::PTR => LocalQuery::Ptr,
        RecordType::SOA => LocalQuery::Soa,
        RecordType::NS => LocalQuery::Ns,
        RecordType::ANY => LocalQuery::Any,
        _ => LocalQuery::Other,
    }
}

fn wire_name(name: &DomainName) -> Option<Name> {
    Name::from_ascii(format!("{}.", name.as_str())).ok()
}

fn zone_soa(zone: &DomainName, ttl: u32) -> Option<Record> {
    let owner = wire_name(zone)?;
    let host = Name::from_ascii(format!("ns.{}.", zone.as_str())).ok()?;
    let admin = Name::from_ascii(format!("hostmaster.{}.", zone.as_str())).ok()?;
    let rdata = SOA::new(
        host,
        admin,
        1,
        3600,
        600,
        86_400,
        LOCAL_NEGATIVE_TTL_SECONDS,
    );
    Some(Record::from_rdata(owner, ttl, RData::SOA(rdata)))
}

fn wire_record(record: &LocalRecord) -> Option<Record> {
    let owner = wire_name(&record.name)?;
    let data = match &record.data {
        LocalData::A(ip) => RData::A(A(*ip)),
        LocalData::Aaaa(ip) => RData::AAAA(AAAA(*ip)),
        LocalData::Cname(target) => RData::CNAME(CNAME(wire_name(target)?)),
        LocalData::Ptr(target) => RData::PTR(PTR(wire_name(target)?)),
        LocalData::Soa => return zone_soa(&record.name, record.ttl),
        LocalData::Ns => RData::NS(NS(Name::from_ascii(format!(
            "ns.{}.",
            record.name.as_str()
        ))
        .ok()?)),
    };
    Some(Record::from_rdata(owner, record.ttl, data))
}

async fn send_local<R: ResponseHandler>(
    request: &Request,
    question: &LowerQuery,
    answer: &LocalAnswer,
    mut response_handle: R,
) -> ResponseInfo {
    let records: Vec<Record> = answer.records.iter().filter_map(wire_record).collect();
    let code = if answer.nxdomain {
        ResponseCode::NXDomain
    } else {
        ResponseCode::NoError
    };
    // Negative answers carry a SOA, so clients know how long to cache them (RFC 2308).
    let authorities: Vec<Record> = if records.is_empty() {
        match &answer.zone {
            Some(zone) => zone_soa(zone, LOCAL_NEGATIVE_TTL_SECONDS),
            None => block_soa(question.original().name(), LOCAL_NEGATIVE_TTL_SECONDS),
        }
        .into_iter()
        .collect()
    } else {
        Vec::new()
    };

    let edns = response_edns(request);
    let mut metadata = response_metadata(request, code);
    metadata.authoritative = answer.zone.is_some();
    let builder = MessageResponseBuilder::new(&request.queries, edns.as_ref());
    let response = builder.build(
        metadata,
        records.iter(),
        authorities.iter(),
        std::iter::empty(),
        std::iter::empty(),
    );
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(error) => {
            warn!(%error, "failed to send a local DNS response");
            failed_info(metadata)
        }
    }
}

/// The CNAME targets in an answer, or `None` if one can't be normalized.
///
/// A target that can't be checked isn't let through, so the caller treats `None` as a failure.
fn cname_targets(upstream: &Message) -> Option<Vec<DomainName>> {
    upstream
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::CNAME(CNAME(target)) => Some(target),
            _ => None,
        })
        .map(|target| DomainName::parse(&target.to_string()).ok())
        .collect()
}

/// A synthetic SOA, so clients cache blocked answers for the configured TTL (RFC 2308).
fn block_soa(owner: &Name, ttl: u32) -> Option<Record> {
    let host = Name::from_ascii("blocked.ferrixdns.invalid.").ok()?;
    let admin = Name::from_ascii("hostmaster.ferrixdns.invalid.").ok()?;
    let rdata = SOA::new(host, admin, 1, 3600, 600, 86_400, ttl);
    Some(Record::from_rdata(owner.clone(), ttl, RData::SOA(rdata)))
}

async fn send_blocked<R: ResponseHandler>(
    request: &Request,
    question: &LowerQuery,
    block: BlockConfig,
    mut response_handle: R,
) -> ResponseInfo {
    let owner = question.original().name();
    let address = match (block.response, question.query_type()) {
        (BlockResponse::ZeroAddress, RecordType::A) => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
        (BlockResponse::ZeroAddress, RecordType::AAAA) => {
            Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)))
        }
        _ => None,
    };
    let code = match block.response {
        BlockResponse::Nxdomain => ResponseCode::NXDomain,
        BlockResponse::ZeroAddress => ResponseCode::NoError,
    };
    let answers: Vec<Record> = address
        .map(|rdata| Record::from_rdata(owner.clone(), block.ttl_seconds, rdata))
        .into_iter()
        .collect();
    // Negative answers carry the SOA. A synthesized address carries its own TTL.
    let authorities: Vec<Record> = if answers.is_empty() {
        block_soa(owner, block.ttl_seconds).into_iter().collect()
    } else {
        Vec::new()
    };

    let mut edns = response_edns(request);
    if let Some(edns) = &mut edns {
        edns.options_mut()
            .insert(EdnsOption::Unknown(EDE_OPTION_CODE, EDE_BLOCKED.to_vec()));
    }
    let metadata = response_metadata(request, code);
    let builder = MessageResponseBuilder::new(&request.queries, edns.as_ref());
    let response = builder.build(
        metadata,
        answers.iter(),
        authorities.iter(),
        std::iter::empty(),
        std::iter::empty(),
    );
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(error) => {
            warn!(%error, "failed to send DNS block response");
            failed_info(metadata)
        }
    }
}

/// The OPT record for a response, or `None` when the client didn't use EDNS.
///
/// `max_payload` also limits the UDP response size, so the encoder truncates to what the client
/// accepts, capped at the size that avoids IP fragmentation.
fn response_edns(request: &Request) -> Option<Edns> {
    let client = request.edns.as_ref()?;
    let mut edns = Edns::new();
    edns.set_max_payload(client.max_payload().clamp(512, MAX_UDP_PAYLOAD));
    edns.set_dnssec_ok(client.flags().dnssec_ok);
    Some(edns)
}

fn response_metadata(request: &Request, code: ResponseCode) -> Metadata {
    let mut metadata = Metadata::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    metadata.recursion_desired = request.metadata.recursion_desired;
    metadata.recursion_available = true;
    metadata.checking_disabled = request.metadata.checking_disabled;
    metadata.response_code = code;
    metadata
}

fn failed_info(metadata: Metadata) -> ResponseInfo {
    Header {
        metadata,
        counts: HeaderCounts::default(),
    }
    .into()
}

async fn send_error<R: ResponseHandler>(
    request: &Request,
    code: ResponseCode,
    mut response_handle: R,
) -> ResponseInfo {
    let edns = response_edns(request);
    let metadata = response_metadata(request, code);
    let builder = MessageResponseBuilder::new(&request.queries, edns.as_ref());
    match response_handle
        .send_response(builder.build_no_records(metadata))
        .await
    {
        Ok(info) => info,
        Err(error) => {
            warn!(%error, "failed to send DNS error response");
            failed_info(metadata)
        }
    }
}

/// SERVFAIL with an Extended DNS Error saying why, so a failure isn't mistaken for an outage.
async fn send_dnssec_bogus<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
) -> ResponseInfo {
    let mut edns = response_edns(request);
    if let Some(edns) = &mut edns {
        edns.options_mut().insert(EdnsOption::Unknown(
            EDE_OPTION_CODE,
            EDE_DNSSEC_BOGUS.to_vec(),
        ));
    }
    let metadata = response_metadata(request, ResponseCode::ServFail);
    let builder = MessageResponseBuilder::new(&request.queries, edns.as_ref());
    match response_handle
        .send_response(builder.build_no_records(metadata))
        .await
    {
        Ok(info) => info,
        Err(error) => {
            warn!(%error, "failed to send DNS error response");
            failed_info(metadata)
        }
    }
}

async fn send_upstream_response<R: ResponseHandler>(
    request: &Request,
    upstream: Message,
    dnssec_ok: bool,
    validated: bool,
    mut response_handle: R,
) -> ResponseInfo {
    let upstream = upstream.maybe_strip_dnssec_records(dnssec_ok);
    let edns = response_edns(request);

    // AA stays clear because this node isn't the answer's authority. AD is only ever this node's
    // own conclusion, never copied from upstream, and only for clients that asked (RFC 6840).
    let mut metadata = response_metadata(request, upstream.metadata.response_code);
    metadata.truncation = upstream.metadata.truncation;
    metadata.authentic_data = validated && (dnssec_ok || request.metadata.authentic_data);

    let builder = MessageResponseBuilder::new(&request.queries, edns.as_ref());
    let response = builder.build(
        metadata,
        upstream.answers.iter(),
        upstream.authorities.iter(),
        std::iter::empty(),
        upstream.additionals.iter(),
    );
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(error) => {
            warn!(%error, "failed to send DNS response");
            failed_info(metadata)
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for ForwardHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let started = Instant::now();
        let finished = self.process(request, response_handle).await;
        let info = finished.info;
        self.record(request, finished, started);
        info
    }
}
