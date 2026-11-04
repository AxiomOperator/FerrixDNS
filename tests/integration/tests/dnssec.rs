//! DNSSEC validation against a zone signed here, using its key as the trust anchor.

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use dns_cache::{CacheConfig, DnsCache};
use dns_runtime::DnssecConfig;
use dns_upstreams::TrustAnchors;
use hickory_proto::dnssec::crypto::Ed25519SigningKey;
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, RRSIG};
use hickory_proto::dnssec::{DnssecSigner, SigningKey};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType};
use integration::{ServerOptions, exchange_udp, query_message, start_server};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use rustls::pki_types::PrivatePkcs8KeyDer;
use time::OffsetDateTime;
use tokio::net::UdpSocket;

const ZONE: &str = "signed.test.";
const GOOD_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const FORGED_ADDRESS: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 66);

fn name(value: &str) -> Name {
    Name::from_str(value).unwrap()
}

struct SignedZone {
    signer: DnssecSigner,
    dnskey: DNSKEY,
}

impl SignedZone {
    fn generate() -> (Self, TrustAnchors) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let der = PrivatePkcs8KeyDer::from(pkcs8.as_ref());
        let key = Ed25519SigningKey::from_pkcs8(&der).unwrap();
        let public = key.to_public_key().unwrap();
        let dnskey = DNSKEY::from_key(&public);

        let mut anchors = TrustAnchors::empty();
        anchors.insert_with_name(&public, LowerName::from(name(ZONE)));

        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            name(ZONE),
            Duration::from_secs(3600),
        );
        (Self { signer, dnskey }, anchors)
    }

    fn sign_rrset(&self, records: &[Record], inception: OffsetDateTime) -> Record {
        let first = &records[0];
        let mut rrset = RecordSet::new(first.name.clone(), first.record_type(), 0);
        for record in records {
            rrset.insert(record.clone(), 0);
        }
        let rrsig = RRSIG::from_rrset(&rrset, DNSClass::IN, inception, &self.signer).unwrap();
        Record::from_rdata(
            first.name.clone(),
            60,
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
        )
    }

    fn a_record(owner: &Name, address: Ipv4Addr) -> Record {
        Record::from_rdata(owner.clone(), 60, RData::A(A(address)))
    }

    /// Builds the scripted answer. The first label picks what's wrong with it, if anything.
    fn respond(&self, query: &Message) -> Message {
        let mut response = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        response.add_queries(query.queries.iter().cloned());
        if query.edns.is_some() {
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            edns.set_dnssec_ok(true);
            response.set_edns(edns);
        }

        let question = &query.queries[0];
        let owner = question.name().clone();
        let now = OffsetDateTime::now_utc() - time::Duration::seconds(30);

        if question.query_type() == RecordType::DNSKEY && owner == name(ZONE) {
            let record = Record::from_rdata(
                owner,
                60,
                RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
            );
            let signature = self.sign_rrset(std::slice::from_ref(&record), now);
            response.add_answer(record);
            response.add_answer(signature);
            return response;
        }

        let label = owner
            .iter()
            .next()
            .map(|label| String::from_utf8_lossy(label).into_owned())
            .unwrap_or_default();
        let good = Self::a_record(&owner, GOOD_ADDRESS);
        match label.as_str() {
            "www" => {
                let signature = self.sign_rrset(std::slice::from_ref(&good), now);
                response.add_answer(good);
                response.add_answer(signature);
            }
            // The signature covers the real address, but the answer has been changed.
            "tampered" => {
                let signature = self.sign_rrset(std::slice::from_ref(&good), now);
                response.add_answer(Self::a_record(&owner, FORGED_ADDRESS));
                response.add_answer(signature);
            }
            // The signature has been stripped from a signed zone.
            "stripped" => {
                response.add_answer(good);
            }
            // The signature ran out a day ago.
            "expired" => {
                let long_ago = OffsetDateTime::now_utc() - time::Duration::days(2);
                let signature = self.sign_rrset(std::slice::from_ref(&good), long_ago);
                response.add_answer(good);
                response.add_answer(signature);
            }
            _ => response.metadata.response_code = ResponseCode::NXDomain,
        }
        response
    }
}

async fn start_signed_upstream(zone: SignedZone) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 4096];
        loop {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = Message::from_vec(&buffer[..length]).unwrap();
            let bytes = zone.respond(&query).to_vec().unwrap();
            socket.send_to(&bytes, peer).await.unwrap();
        }
    });
    address
}

async fn validating_server(cache: Option<Arc<DnsCache>>) -> SocketAddr {
    let (zone, anchors) = SignedZone::generate();
    let upstream = start_signed_upstream(zone).await;
    let mut options = ServerOptions::new(vec![upstream]);
    options.dnssec = Some(DnssecConfig {
        trust_anchors: Some(anchors),
    });
    options.cache = cache;
    start_server(options).await
}

fn do_query(qname: &str) -> Message {
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    query_message(qname, RecordType::A, Some(edns))
}

fn has_rrsig(message: &Message) -> bool {
    message
        .answers
        .iter()
        .any(|record| record.record_type() == RecordType::RRSIG)
}

#[tokio::test]
async fn a_correctly_signed_answer_is_secure_and_sets_ad_for_clients_that_ask() {
    let server = validating_server(None).await;

    let (with_do, _) = exchange_udp(server, &do_query("www.signed.test.")).await;
    assert_eq!(with_do.metadata.response_code, ResponseCode::NoError);
    assert!(with_do.metadata.authentic_data, "this node validated it");
    assert!(has_rrsig(&with_do), "DO clients get the signatures");

    // A client that didn't ask gets neither AD nor signatures (RFC 6840, RFC 4035).
    let plain = query_message("www.signed.test.", RecordType::A, None);
    let (plain, _) = exchange_udp(server, &plain).await;
    assert_eq!(plain.metadata.response_code, ResponseCode::NoError);
    assert!(!plain.metadata.authentic_data);
    assert!(!has_rrsig(&plain));
    assert_eq!(plain.answers.len(), 1);

    // Setting AD in the query asks for it without DO (RFC 6840 section 5.7).
    let mut with_ad = query_message("www.signed.test.", RecordType::A, None);
    with_ad.metadata.authentic_data = true;
    let (with_ad, _) = exchange_udp(server, &with_ad).await;
    assert!(with_ad.metadata.authentic_data);
}

#[tokio::test]
async fn tampered_stripped_and_expired_answers_become_servfail() {
    let server = validating_server(None).await;
    for qname in [
        "tampered.signed.test.",
        "stripped.signed.test.",
        "expired.signed.test.",
    ] {
        let (response, _) = exchange_udp(server, &do_query(qname)).await;
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::ServFail,
            "{qname}"
        );
        assert!(
            response.answers.is_empty(),
            "{qname}: the forged data must not reach the client"
        );

        let options = format!("{:?}", response.edns.unwrap().options());
        assert!(
            options.contains('6'),
            "{qname}: expected EDE 6 in {options}"
        );
    }
}

#[tokio::test]
async fn checking_disabled_clients_get_the_answer_to_validate_themselves() {
    let server = validating_server(None).await;
    let mut query = do_query("tampered.signed.test.");
    query.metadata.checking_disabled = true;
    let (response, _) = exchange_udp(server, &query).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
        !response.metadata.authentic_data,
        "this node didn't validate it"
    );
    assert!(has_rrsig(&response));
    assert!(response.metadata.checking_disabled);
}

#[tokio::test]
async fn the_cache_keeps_validation_results_and_never_stores_bogus_answers() {
    let cache = Arc::new(DnsCache::new(CacheConfig::default()));
    let server = validating_server(Some(Arc::clone(&cache))).await;

    for _ in 0..2 {
        let (response, _) = exchange_udp(server, &do_query("www.signed.test.")).await;
        assert!(
            response.metadata.authentic_data,
            "AD must survive the cache"
        );
    }
    let hits = cache.stats().hits;
    assert!(hits >= 1, "expected a cache hit, got {hits}");

    for _ in 0..2 {
        let (response, _) = exchange_udp(server, &do_query("tampered.signed.test.")).await;
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    }
}

#[tokio::test]
async fn without_validation_ad_is_never_claimed() {
    let (zone, _) = SignedZone::generate();
    let upstream = start_signed_upstream(zone).await;
    let server = start_server(ServerOptions::new(vec![upstream])).await;
    let (response, _) = exchange_udp(server, &do_query("www.signed.test.")).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(!response.metadata.authentic_data);
    assert!(
        has_rrsig(&response),
        "signatures still pass through for DO clients"
    );
}
