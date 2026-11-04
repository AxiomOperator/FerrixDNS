//! Policy enforcement on the DNS path, against a scripted upstream.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use dns_policy::{CompiledPolicy, PolicyDocument};
use dns_runtime::PolicyHandle;
use hickory_proto::op::{Edns, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use integration::{
    Fixture, ServerOptions, ask, exchange_tcp, exchange_udp, query_message, send_udp_raw,
    start_server,
};

fn compile(source: &str) -> CompiledPolicy {
    let document = PolicyDocument::parse(source).unwrap();
    CompiledPolicy::compile("test", &document, SystemTime::now(), None).unwrap()
}

fn handle(source: &str) -> PolicyHandle {
    Arc::new(ArcSwap::from_pointee(compile(source)))
}

async fn server_with_policy(fixture: &Fixture, policy: PolicyHandle) -> SocketAddr {
    let mut options = ServerOptions::new(vec![fixture.addr]);
    options.policy = policy;
    options.attempt_timeout = Duration::from_secs(1);
    start_server(options).await
}

fn deny(pattern: &str, match_type: &str) -> String {
    format!(
        "schema_version = 1\n[[rules]]\nid = \"r1\"\naction = \"deny\"\nmatch = \"{match_type}\"\npattern = \"{pattern}\"\n"
    )
}

#[tokio::test]
async fn blocked_queries_get_nxdomain_without_contacting_upstream() {
    let fixture = Fixture::start().await;
    let server =
        server_with_policy(&fixture, handle(&deny("blocked.fixture.test", "suffix"))).await;

    for qname in [
        "blocked.fixture.test.",
        "a.blocked.fixture.test.",
        "A.BLOCKED.fixture.TEST.",
    ] {
        let message = query_message(qname, RecordType::A, None);
        let (udp, _) = exchange_udp(server, &message).await;
        assert_eq!(
            udp.metadata.response_code,
            ResponseCode::NXDomain,
            "{qname}"
        );
        assert!(udp.answers.is_empty());

        let tcp = exchange_tcp(server, &message).await;
        assert_eq!(
            tcp.metadata.response_code,
            ResponseCode::NXDomain,
            "{qname}"
        );
    }
    assert_eq!(fixture.udp_queries() + fixture.tcp_queries(), 0);
}

#[tokio::test]
async fn unrelated_queries_are_still_forwarded() {
    let fixture = Fixture::start().await;
    let server =
        server_with_policy(&fixture, handle(&deny("blocked.fixture.test", "suffix"))).await;
    let response = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(fixture.udp_queries(), 1);
}

#[tokio::test]
async fn nxdomain_block_carries_a_soa_with_the_configured_ttl() {
    let fixture = Fixture::start().await;
    let policy = format!(
        "{}\n[block]\nttl_seconds = 17\n",
        deny("x.fixture.test", "exact")
    );
    let server = server_with_policy(&fixture, handle(&policy)).await;

    let response = ask(server, "x.fixture.test.", RecordType::A).await;
    assert_eq!(response.authorities.len(), 1);
    let soa = &response.authorities[0];
    assert_eq!(soa.ttl, 17);
    let RData::SOA(rdata) = &soa.data else {
        panic!("expected a SOA");
    };
    assert_eq!(
        rdata.minimum, 17,
        "RFC 2308 caps negative caching with this"
    );
}

#[tokio::test]
async fn zero_address_mode_answers_by_query_type() {
    let fixture = Fixture::start().await;
    let policy = format!(
        "{}\n[block]\nresponse = \"zero_address\"\nttl_seconds = 17\n",
        deny("x.fixture.test", "exact")
    );
    let server = server_with_policy(&fixture, handle(&policy)).await;

    let a = ask(server, "x.fixture.test.", RecordType::A).await;
    assert_eq!(a.metadata.response_code, ResponseCode::NoError);
    assert_eq!(a.answers[0].ttl, 17);
    let RData::A(address) = &a.answers[0].data else {
        panic!("expected an A record");
    };
    assert!(address.0.is_unspecified());

    let aaaa = ask(server, "x.fixture.test.", RecordType::AAAA).await;
    let RData::AAAA(address) = &aaaa.answers[0].data else {
        panic!("expected an AAAA record");
    };
    assert!(address.0.is_unspecified());

    for qtype in [RecordType::TXT, RecordType::HTTPS, RecordType::MX] {
        let other = ask(server, "x.fixture.test.", qtype).await;
        assert_eq!(
            other.metadata.response_code,
            ResponseCode::NoError,
            "{qtype}"
        );
        assert!(other.answers.is_empty(), "{qtype}");
        assert_eq!(
            other.authorities[0].record_type(),
            RecordType::SOA,
            "{qtype}"
        );
    }
    assert_eq!(fixture.udp_queries(), 0);
}

#[tokio::test]
async fn block_responses_never_claim_validation_and_report_extended_error_to_edns_clients() {
    let fixture = Fixture::start().await;
    let server = server_with_policy(&fixture, handle(&deny("x.fixture.test", "exact"))).await;

    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    let message = query_message("x.fixture.test.", RecordType::A, Some(edns));
    let (response, _) = exchange_udp(server, &message).await;
    assert!(!response.metadata.authentic_data);
    assert!(response.metadata.recursion_available);

    let options = format!("{:?}", response.edns.unwrap().options());
    assert!(options.contains("15"), "expected EDE code 15 in {options}");

    let plain = ask(server, "x.fixture.test.", RecordType::A).await;
    assert!(
        plain.edns.is_none(),
        "must not add EDNS for clients without it"
    );
}

#[tokio::test]
async fn a_blocked_cname_target_blocks_the_answer() {
    let fixture = Fixture::start().await;
    // The fixture answers cname.fixture.test with a CNAME to a.fixture.test.
    let server = server_with_policy(&fixture, handle(&deny("a.fixture.test", "exact"))).await;

    let response = ask(server, "cname.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        response.answers.is_empty(),
        "the upstream answer must not leak"
    );
    assert_eq!(
        fixture.udp_queries(),
        1,
        "the target is only known from upstream"
    );
}

#[tokio::test]
async fn explicit_allow_ignores_list_denies_on_targets_but_not_rule_denies() {
    let fixture = Fixture::start().await;
    let list_deny = r#"
schema_version = 1
[[rules]]
id = "r1"
action = "allow"
match = "exact"
pattern = "cname.fixture.test"
[[lists]]
id = "l1"
action = "deny"
domains = ["a.fixture.test"]
"#;
    let server = server_with_policy(&fixture, handle(list_deny)).await;
    let response = ask(server, "cname.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 2);

    let rule_deny = r#"
schema_version = 1
[[rules]]
id = "r1"
action = "allow"
match = "exact"
pattern = "cname.fixture.test"
[[rules]]
id = "r2"
action = "deny"
match = "exact"
pattern = "a.fixture.test"
"#;
    let server = server_with_policy(&fixture, handle(rule_deny)).await;
    let response = ask(server, "cname.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
async fn client_identity_comes_from_the_source_address() {
    let fixture = Fixture::start().await;
    let policy = |address: &str| {
        format!(
            r#"
schema_version = 1
[[clients]]
id = "this-test"
addresses = ["{address}"]
groups = ["kids"]
[[rules]]
id = "r1"
action = "deny"
match = "exact"
pattern = "a.fixture.test"
scope = {{ kind = "group", id = "kids" }}
"#
        )
    };

    let matching = server_with_policy(&fixture, handle(&policy("127.0.0.0/8"))).await;
    let response = ask(matching, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);

    let other = server_with_policy(&fixture, handle(&policy("10.0.0.1"))).await;
    let response = ask(other, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
}

#[tokio::test]
async fn a_new_policy_applies_without_restarting() {
    let fixture = Fixture::start().await;
    let policy = handle(&deny("a.fixture.test", "exact"));
    let server = server_with_policy(&fixture, Arc::clone(&policy)).await;

    let before = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(before.metadata.response_code, ResponseCode::NXDomain);

    policy.store(Arc::new(compile(&deny("txt.fixture.test", "exact"))));

    let unblocked = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(unblocked.metadata.response_code, ResponseCode::NoError);
    let blocked = ask(server, "txt.fixture.test.", RecordType::TXT).await;
    assert_eq!(blocked.metadata.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
async fn a_policy_published_while_upstream_answers_still_applies() {
    let fixture = Fixture::start().await;
    let policy = handle("schema_version = 1");
    let server = server_with_policy(&fixture, Arc::clone(&policy)).await;

    // The fixture takes 300 ms to answer this name.
    let in_flight =
        tokio::spawn(async move { ask(server, "slow.fixture.test.", RecordType::A).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    policy.store(Arc::new(compile(&deny("slow.fixture.test", "exact"))));

    let response = in_flight.await.unwrap();
    assert_eq!(fixture.udp_queries(), 1, "the query was already upstream");
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
async fn blocked_queries_are_answered_even_when_upstream_capacity_is_full() {
    let fixture = Fixture::start().await;
    let mut options = ServerOptions::new(vec![fixture.addr]);
    options.policy = handle(&deny("x.fixture.test", "exact"));
    options.max_concurrent_requests = 1;
    options.attempt_timeout = Duration::from_secs(1);
    let server = start_server(options).await;

    let slow = tokio::spawn(async move { ask(server, "slow.fixture.test.", RecordType::A).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let blocked = ask(server, "x.fixture.test.", RecordType::A).await;
    assert_eq!(blocked.metadata.response_code, ResponseCode::NXDomain);
    slow.await.unwrap();
}

#[tokio::test]
async fn names_that_cannot_be_normalized_are_refused_rather_than_let_through() {
    let fixture = Fixture::start().await;
    let server = server_with_policy(&fixture, handle(&deny("fixture.test", "suffix"))).await;

    // Legal on the wire, but its escaped form is longer than a domain name may be. Letting it
    // through unchecked would be a way past every suffix rule.
    let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for _ in 0..3 {
        packet.push(60);
        packet.extend_from_slice(&[b' '; 60]);
    }
    packet.extend_from_slice(b"\x07fixture\x04test\x00\x00\x01\x00\x01");

    let reply = send_udp_raw(server, &packet, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(reply[3] & 0x0f, 5, "expected REFUSED");
    assert_eq!(fixture.udp_queries(), 0);
}

#[tokio::test]
async fn the_root_name_is_forwarded() {
    let fixture = Fixture::start().await;
    let server = server_with_policy(&fixture, handle(&deny("fixture.test", "suffix"))).await;
    // The fixture answers unknown names with NXDOMAIN, so reaching it is what's being checked.
    ask(server, ".", RecordType::NS).await;
    assert_eq!(fixture.udp_queries(), 1);
}

const LOCAL_POLICY: &str = r#"
schema_version = 1
[[local_zones]]
name = "home.arpa"
[[local_records]]
id = "1"
name = "nas.home.arpa"
type = "a"
value = "192.168.1.10"
[[local_records]]
id = "2"
name = "files.home.arpa"
type = "cname"
value = "nas.home.arpa"
[[local_records]]
id = "3"
name = "secret.home.arpa"
type = "a"
value = "192.168.1.11"
[[rules]]
id = "r1"
action = "deny"
match = "exact"
pattern = "secret.home.arpa"
[[lists]]
id = "l1"
action = "deny"
domains = ["nas.home.arpa"]
"#;

#[tokio::test]
async fn local_zones_answer_authoritatively_without_going_upstream() {
    let fixture = Fixture::start().await;
    let server = server_with_policy(&fixture, handle(LOCAL_POLICY)).await;

    // A blocklist entry doesn't block a name the operator created.
    let found = ask(server, "nas.home.arpa.", RecordType::A).await;
    assert_eq!(found.metadata.response_code, ResponseCode::NoError);
    assert!(found.metadata.authoritative);
    assert!(found.metadata.recursion_available);
    assert_eq!(found.answers.len(), 1);

    let chased = ask(server, "files.home.arpa.", RecordType::A).await;
    assert_eq!(chased.answers.len(), 2);

    let no_type = ask(server, "nas.home.arpa.", RecordType::MX).await;
    assert_eq!(no_type.metadata.response_code, ResponseCode::NoError);
    assert!(no_type.answers.is_empty());
    assert_eq!(no_type.authorities[0].record_type(), RecordType::SOA);

    let no_name = ask(server, "ghost.home.arpa.", RecordType::A).await;
    assert_eq!(no_name.metadata.response_code, ResponseCode::NXDomain);
    assert!(no_name.metadata.authoritative);
    assert_eq!(no_name.authorities[0].record_type(), RecordType::SOA);

    let apex = ask(server, "home.arpa.", RecordType::SOA).await;
    assert_eq!(apex.answers[0].record_type(), RecordType::SOA);

    let ptr = ask(server, "10.1.168.192.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(ptr.answers[0].record_type(), RecordType::PTR);

    assert_eq!(fixture.udp_queries() + fixture.tcp_queries(), 0);
}

#[tokio::test]
async fn rule_denies_still_apply_to_local_zones() {
    let fixture = Fixture::start().await;
    let server = server_with_policy(&fixture, handle(LOCAL_POLICY)).await;
    let blocked = ask(server, "secret.home.arpa.", RecordType::A).await;
    assert_eq!(blocked.metadata.response_code, ResponseCode::NXDomain);
    assert!(blocked.answers.is_empty());
    assert!(
        !blocked.metadata.authoritative,
        "this came from the block path"
    );
}

#[tokio::test]
async fn reserved_names_and_private_reverse_lookups_never_go_upstream() {
    let fixture = Fixture::start().await;
    let server = server_with_policy(&fixture, handle("schema_version = 1")).await;

    let localhost = ask(server, "localhost.", RecordType::A).await;
    let RData::A(address) = &localhost.answers[0].data else {
        panic!("expected an A record");
    };
    assert!(address.0.is_loopback());

    for (name, qtype) in [
        ("x.invalid.", RecordType::A),
        ("site.onion.", RecordType::A),
        ("printer.local.", RecordType::A),
        ("router.home.arpa.", RecordType::A),
        ("1.1.168.192.in-addr.arpa.", RecordType::PTR),
        ("1.0.0.10.in-addr.arpa.", RecordType::PTR),
    ] {
        let response = ask(server, name, qtype).await;
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NXDomain,
            "{name}"
        );
    }
    assert_eq!(
        fixture.udp_queries() + fixture.tcp_queries(),
        0,
        "these must not leak"
    );
}
