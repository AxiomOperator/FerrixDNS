use std::sync::Arc;

use dns_upstreams::{EdnsRequest, MAX_UDP_PAYLOAD, UpstreamPool, UpstreamRequest};
use hickory_server::net::runtime::Time;
use hickory_server::proto::op::{
    Edns, Header, HeaderCounts, Message, MessageType, Metadata, OpCode, ResponseCode,
};
use hickory_server::proto::rr::{DNSClass, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

/// Validates requests and forwards them upstream.
pub struct ForwardHandler {
    pool: Arc<UpstreamPool>,
    permits: Semaphore,
}

impl ForwardHandler {
    pub fn new(pool: Arc<UpstreamPool>, max_concurrent_requests: usize) -> Self {
        Self {
            pool,
            permits: Semaphore::new(max_concurrent_requests),
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

        match self.pool.forward(&upstream_request).await {
            Ok(upstream) => {
                send_upstream_response(request, upstream, dnssec_ok, response_handle).await
            }
            Err(error) => {
                warn!(%error, "forwarding failed");
                send_error(request, ResponseCode::ServFail, response_handle).await
            }
        }
    }
}
