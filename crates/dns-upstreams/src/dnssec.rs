//! Independent DNSSEC validation, using Hickory's validator on top of the upstream pool.
//!
//! Upstreams are asked with CD set, so this node sees the signatures and decides for itself rather
//! than trusting an upstream's AD bit (spec section 3.4).

use std::pin::Pin;
use std::sync::Arc;

use dns_cache::{CacheKey, DnsCache};
use futures_util::{Stream, StreamExt, stream};
use hickory_net::NetError;
use hickory_net::dnssec::DnssecDnsHandle;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::xfer::DnsHandle;
use hickory_proto::dnssec::Proof;
use hickory_proto::op::{DnsRequest, DnsRequestOptions, DnsResponse, Message, Query, ResponseCode};
use hickory_proto::rr::Record;

pub use hickory_proto::dnssec::TrustAnchors;

use crate::{EdnsRequest, MAX_UDP_PAYLOAD, UpstreamError, UpstreamPool, UpstreamRequest};

/// What validation concluded about an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnssecStatus {
    /// Signed, and the chain to a trust anchor checks out.
    Secure,
    /// The zone is provably not signed, so there's nothing to check.
    Insecure,
    /// Should be signed, but the signatures are missing or wrong. This might be an attack.
    Bogus,
}

/// A validated answer.
#[derive(Clone, Debug)]
pub struct Validated {
    pub message: Message,
    pub status: DnssecStatus,
}

/// Connects the validator to the pool. Its own lookups of DNSKEY and DS records go through here.
#[derive(Clone)]
struct PoolHandle {
    pool: Arc<UpstreamPool>,
    cache: Option<Arc<DnsCache>>,
}

impl PoolHandle {
    async fn lookup(self, request: DnsRequest) -> Result<DnsResponse, NetError> {
        let query = request
            .queries
            .first()
            .cloned()
            .ok_or_else(|| NetError::from("no query in request"))?;
        let key = CacheKey {
            name: query.name().to_string().to_ascii_lowercase(),
            record_type: query.query_type(),
            dnssec_ok: true,
            checking_disabled: true,
            route: 0,
        };
        if let Some(hit) = self.cache.as_ref().and_then(|cache| cache.get(&key)) {
            return DnsResponse::from_message(hit.message)
                .map_err(|error| NetError::from(error.to_string()));
        }

        let forwarded = self
            .pool
            .forward(&UpstreamRequest {
                query,
                recursion_desired: true,
                checking_disabled: true,
                edns: Some(EdnsRequest {
                    max_payload: MAX_UDP_PAYLOAD,
                    dnssec_ok: true,
                }),
            })
            .await
            .map_err(|error| NetError::from(error.to_string()))?;
        if let Some(cache) = &self.cache {
            cache.insert(key, &forwarded.message, false);
        }
        DnsResponse::from_message(forwarded.message)
            .map_err(|error| NetError::from(error.to_string()))
    }
}

impl DnsHandle for PoolHandle {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let handle = self.clone();
        Box::pin(stream::once(handle.lookup(request)))
    }
}

/// Validates answers against the root trust anchors, or the given ones.
pub struct DnssecValidator {
    handle: DnssecDnsHandle<PoolHandle>,
}

fn worst_proof(records: &[Record]) -> Option<Proof> {
    let mut worst = None;
    for record in records {
        match record.proof {
            Proof::Bogus => return Some(Proof::Bogus),
            Proof::Secure => worst = worst.or(Some(Proof::Secure)),
            other => worst = Some(other),
        }
    }
    worst
}

fn status_of(message: &Message) -> DnssecStatus {
    let proof = if message.answers.is_empty() {
        worst_proof(&message.authorities)
    } else {
        worst_proof(&message.answers)
    };
    match proof {
        Some(Proof::Bogus) => DnssecStatus::Bogus,
        Some(Proof::Secure) => DnssecStatus::Secure,
        _ => DnssecStatus::Insecure,
    }
}

impl DnssecValidator {
    pub fn new(
        pool: Arc<UpstreamPool>,
        cache: Option<Arc<DnsCache>>,
        anchors: Option<TrustAnchors>,
    ) -> Self {
        let inner = PoolHandle { pool, cache };
        let handle = match anchors {
            Some(anchors) => DnssecDnsHandle::with_trust_anchor(inner, Arc::new(anchors)),
            None => DnssecDnsHandle::new(inner),
        };
        Self { handle }
    }

    /// Looks up a query and validates the answer.
    pub async fn resolve(&self, query: Query) -> Result<Validated, UpstreamError> {
        let request = DnsRequest::from_query(query, DnsRequestOptions::default());
        let result = self.handle.send(request).next().await;
        match result {
            Some(Ok(response)) => {
                let message = response.into_message();
                let status = status_of(&message);
                Ok(Validated { message, status })
            }
            // A negative answer whose proof of non-existence didn't check out.
            Some(Err(NetError::Dns(hickory_net::DnsError::Nsec {
                response, proof, ..
            }))) => {
                let status = if proof.is_bogus() {
                    DnssecStatus::Bogus
                } else {
                    DnssecStatus::Insecure
                };
                Ok(Validated {
                    message: (*response).into_message(),
                    status,
                })
            }
            Some(Err(NetError::Dns(hickory_net::DnsError::DnssecBogus))) => Ok(Validated {
                message: bogus_message(),
                status: DnssecStatus::Bogus,
            }),
            Some(Err(_)) | None => Err(UpstreamError::AllFailed),
        }
    }
}

fn bogus_message() -> Message {
    let mut message = Message::query();
    message.metadata.response_code = ResponseCode::ServFail;
    message
}
