//! FR-007: answers come from the cache, and new policy still applies to every cached answer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use dns_cache::{CacheConfig, DnsCache};
use dns_policy::{CompiledPolicy, PolicyDocument};
use dns_runtime::PolicyHandle;
use hickory_proto::op::{Edns, ResponseCode};
use hickory_proto::rr::RecordType;
use integration::{Fixture, Mode, ServerOptions, ask, exchange_udp, query_message, start_server};

fn compile(source: &str) -> CompiledPolicy {
    let document = PolicyDocument::parse(source).unwrap();
    CompiledPolicy::compile("test", &document, SystemTime::now(), None).unwrap()
}

fn deny(pattern: &str) -> String {
    format!(
        "schema_version = 1\n[[rules]]\nid = \"r1\"\naction = \"deny\"\nmatch = \"exact\"\npattern = \"{pattern}\"\n"
    )
}

struct Cached {
    server: SocketAddr,
    fixture: Fixture,
    cache: Arc<DnsCache>,
    policy: PolicyHandle,
}

async fn start() -> Cached {
    let fixture = Fixture::start().await;
    start_with(fixture).await
}

async fn start_with(fixture: Fixture) -> Cached {
    let cache = Arc::new(DnsCache::new(CacheConfig::default()));
    let policy: PolicyHandle = Arc::new(ArcSwap::from_pointee(compile("schema_version = 1")));
    let mut options = ServerOptions::new(vec![fixture.addr]);
    options.cache = Some(Arc::clone(&cache));
    options.policy = Arc::clone(&policy);
    let server = start_server(options).await;
    Cached {
        server,
        fixture,
        cache,
        policy,
    }
}

#[tokio::test]
async fn repeated_queries_are_answered_from_the_cache() {
    let node = start().await;
    let first = ask(node.server, "a.fixture.test.", RecordType::A).await;
    let second = ask(node.server, "A.FIXTURE.TEST.", RecordType::A).await;
    assert_eq!(first.answers, second.answers);
    assert_eq!(
        node.fixture.udp_queries(),
        1,
        "the second query must not go upstream"
    );
    let stats = node.cache.stats();
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 1);
}

#[tokio::test]
async fn cached_answers_still_echo_the_client_id_and_flags() {
    let node = start().await;
    ask(node.server, "a.fixture.test.", RecordType::A).await;
    // exchange_udp checks the ID matches.
    let message = query_message("a.fixture.test.", RecordType::A, None);
    let (response, _) = exchange_udp(node.server, &message).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.metadata.recursion_available);
    assert!(!response.metadata.authentic_data);
    assert_eq!(node.fixture.udp_queries(), 1);
}

#[tokio::test]
async fn negative_answers_are_cached_and_failures_are_not() {
    let node = start().await;
    for _ in 0..2 {
        let response = ask(node.server, "nx.fixture.test.", RecordType::A).await;
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }
    assert_eq!(node.fixture.udp_queries(), 1);

    let failing = start_with(Fixture::with_mode(Mode::Always(ResponseCode::ServFail)).await).await;
    for _ in 0..2 {
        ask(failing.server, "a.fixture.test.", RecordType::A).await;
    }
    assert_eq!(
        failing.fixture.udp_queries(),
        2,
        "a failure must not be repeated from the cache"
    );
}

#[tokio::test]
async fn different_record_types_and_dnssec_flags_do_not_share_entries() {
    let node = start().await;
    ask(node.server, "txt.fixture.test.", RecordType::TXT).await;
    ask(node.server, "txt.fixture.test.", RecordType::A).await;
    assert_eq!(node.fixture.udp_queries(), 2);

    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    let with_dnssec = query_message("txt.fixture.test.", RecordType::TXT, Some(edns));
    exchange_udp(node.server, &with_dnssec).await;
    assert_eq!(node.fixture.udp_queries(), 3);
}

#[tokio::test]
async fn a_new_block_applies_to_an_already_cached_query_name() {
    let node = start().await;
    assert_eq!(
        ask(node.server, "a.fixture.test.", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    node.policy
        .store(Arc::new(compile(&deny("a.fixture.test"))));
    assert_eq!(
        ask(node.server, "a.fixture.test.", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
}

/// The release blocker in spec section 10: a cached answer must not escape a new rule.
#[tokio::test]
async fn a_new_block_on_a_cname_target_applies_to_a_cached_answer() {
    let node = start().await;
    // The fixture answers this with a CNAME to a.fixture.test.
    let first = ask(node.server, "cname.fixture.test.", RecordType::A).await;
    assert_eq!(first.answers.len(), 2);
    assert_eq!(node.fixture.udp_queries(), 1);

    node.policy
        .store(Arc::new(compile(&deny("a.fixture.test"))));
    let blocked = ask(node.server, "cname.fixture.test.", RecordType::A).await;
    assert_eq!(blocked.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        blocked.answers.is_empty(),
        "the cached answer must not leak"
    );
    assert_eq!(node.fixture.udp_queries(), 1, "this came from the cache");

    // Removing the rule brings the cached answer back, with no flush needed.
    node.policy.store(Arc::new(compile("schema_version = 1")));
    let restored = ask(node.server, "cname.fixture.test.", RecordType::A).await;
    assert_eq!(restored.answers.len(), 2);
    assert_eq!(node.fixture.udp_queries(), 1);
}

#[tokio::test]
async fn ttls_count_down_and_flushing_goes_back_upstream() {
    let node = start().await;
    let first = ask(node.server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(first.answers[0].ttl, 60);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = ask(node.server, "a.fixture.test.", RecordType::A).await;
    assert!(
        second.answers[0].ttl < 60,
        "TTL was {}",
        second.answers[0].ttl
    );

    node.cache.flush();
    ask(node.server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(node.fixture.udp_queries(), 2);
}

#[tokio::test]
async fn cached_answers_keep_serving_when_upstream_capacity_is_full() {
    let fixture = Fixture::start().await;
    let cache = Arc::new(DnsCache::new(CacheConfig::default()));
    let mut options = ServerOptions::new(vec![fixture.addr]);
    options.cache = Some(cache);
    options.max_concurrent_requests = 1;
    options.attempt_timeout = Duration::from_secs(1);
    let server = start_server(options).await;

    ask(server, "a.fixture.test.", RecordType::A).await;
    let slow = tokio::spawn(async move { ask(server, "slow.fixture.test.", RecordType::A).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let cached = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(cached.metadata.response_code, ResponseCode::NoError);
    slow.await.unwrap();
}
