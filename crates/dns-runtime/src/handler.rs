use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use dns_policy::{BlockConfig, BlockResponse, DomainName, Verdict};
use dns_upstreams::{EdnsRequest, MAX_UDP_PAYLOAD, UpstreamPool, UpstreamRequest};
use hickory_server::net::runtime::Time;
use hickory_server::proto::op::{
    Edns, Header, HeaderCounts, LowerQuery, Message, MessageType, Metadata, OpCode, ResponseCode,
};
use hickory_server::proto::rr::rdata::opt::EdnsOption;
use hickory_server::proto::rr::rdata::{A, AAAA, CNAME, SOA};
use hickory_server::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::policy::PolicyHandle;

/// EDNS option code for Extended DNS Errors (RFC 8914).
const EDE_OPTION_CODE: u16 = 15;
/// The "Blocked" Extended DNS Error, as its two-byte wire value (RFC 8914 section 4.16).
const EDE_BLOCKED: [u8; 2] = 15_u16.to_be_bytes();

/// Validates requests, applies policy and forwards allowed queries upstream.
pub struct ForwardHandler {
    pool: Arc<UpstreamPool>,
    permits: Semaphore,
    policy: PolicyHandle,
}

impl ForwardHandler {
    pub fn new(
        pool: Arc<UpstreamPool>,
        max_concurrent_requests: usize,
        policy: PolicyHandle,
    ) -> Self {
        Self {
            pool,
            permits: Semaphore::new(max_concurrent_requests),
            policy,
        }
    }

    /// Checks a query name, returning how to answer if it's blocked.
    fn query_block(&self, source: IpAddr, name: &DomainName) -> Option<BlockConfig> {
        let policy = self.policy.load();
        match policy.check_query(source, name) {
            Verdict::Allow | Verdict::ChainTooDeep => None,
            Verdict::Block(decision) => {
                debug!(name = name.as_str(), ?decision, "blocked query");
                Some(policy.block())
            }
        }
    }

    /// Checks an upstream answer against the policy active now, not when the query arrived.
    fn answer_action(
        &self,
        source: IpAddr,
        name: &DomainName,
        targets: &[DomainName],
    ) -> AnswerAction {
        let policy = self.policy.load();
        match policy.check_answer(source, name, targets) {
            Verdict::Allow => AnswerAction::Return,
            Verdict::Block(decision) => {
                debug!(name = name.as_str(), ?decision, "blocked answer");
                AnswerAction::Block(policy.block())
            }
            Verdict::ChainTooDeep => AnswerAction::Fail,
        }
    }
}

enum AnswerAction {
    Return,
    Block(BlockConfig),
    Fail,
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

async fn send_upstream_response<R: ResponseHandler>(
    request: &Request,
    upstream: Message,
    dnssec_ok: bool,
    mut response_handle: R,
) -> ResponseInfo {
    let upstream = upstream.maybe_strip_dnssec_records(dnssec_ok);
    let edns = response_edns(request);

    // AD and AA stay clear: this node hasn't validated the answer and isn't its authority.
    let mut metadata = response_metadata(request, upstream.metadata.response_code);
    metadata.truncation = upstream.metadata.truncation;

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
        if request.metadata.op_code != OpCode::Query {
            return send_error(request, ResponseCode::NotImp, response_handle).await;
        }
        if request.edns.as_ref().is_some_and(|edns| edns.version() > 0) {
            return send_error(request, ResponseCode::BADVERS, response_handle).await;
        }

        let [question] = request.queries.queries() else {
            return send_error(request, ResponseCode::FormErr, response_handle).await;
        };
        // Only Internet-class lookups are forwarded, and zone transfers are never served.
        if question.query_class() != DNSClass::IN
            || matches!(question.query_type(), RecordType::AXFR | RecordType::IXFR)
        {
            return send_error(request, ResponseCode::Refused, response_handle).await;
        }

        // A name that can't be normalized can't be checked, so it must not get past policy.
        let Ok(name) = DomainName::parse(&question.name().to_string()) else {
            debug!(src = %request.src(), "refused a name that can't be normalized");
            return send_error(request, ResponseCode::Refused, response_handle).await;
        };
        let source = request.src().ip();

        // Blocked queries need no upstream capacity, so they're decided before admission.
        if let Some(block) = self.query_block(source, &name) {
            return send_blocked(request, question, block, response_handle).await;
        }

        let Ok(_permit) = self.permits.try_acquire() else {
            debug!(src = %request.src(), "over the concurrent request limit");
            return send_error(request, ResponseCode::ServFail, response_handle).await;
        };

        let edns = request.edns.as_ref().map(|edns| EdnsRequest {
            max_payload: edns.max_payload(),
            dnssec_ok: edns.flags().dnssec_ok,
        });
        let dnssec_ok = edns.is_some_and(|edns| edns.dnssec_ok);
        let upstream_request = UpstreamRequest {
            query: question.original().clone(),
            recursion_desired: request.metadata.recursion_desired,
            checking_disabled: request.metadata.checking_disabled,
            edns,
        };

        let upstream = match self.pool.forward(&upstream_request).await {
            Ok(upstream) => upstream,
            Err(error) => {
                warn!(%error, "forwarding failed");
                return send_error(request, ResponseCode::ServFail, response_handle).await;
            }
        };

        let action = match cname_targets(&upstream) {
            Some(targets) => self.answer_action(source, &name, &targets),
            None => AnswerAction::Fail,
        };
        match action {
            AnswerAction::Return => {
                send_upstream_response(request, upstream, dnssec_ok, response_handle).await
            }
            AnswerAction::Block(block) => {
                send_blocked(request, question, block, response_handle).await
            }
            AnswerAction::Fail => {
                debug!(src = %request.src(), "an answer's CNAME chain can't be checked");
                send_error(request, ResponseCode::ServFail, response_handle).await
            }
        }
    }
}
