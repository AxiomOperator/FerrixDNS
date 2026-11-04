//! Pausing, device identity, conditional forwarding and rate limiting, on the real DNS path.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use dns_policy::{CompiledPolicy, MacAddress, PolicyDocument};
use dns_runtime::{Neighbor, NeighborSource, PolicyHandle, Services};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use integration::{Fixture, Mode, ServerOptions, ask, start_server_with_services};
use tokio::net::UdpSocket;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0, 0, 1];

fn handle(source: &str) -> PolicyHandle {
    let document = PolicyDocument::parse(source).unwrap();
    let compiled = CompiledPolicy::compile("test", &document, SystemTime::now(), None).unwrap();
    Arc::new(ArcSwap::from_pointee(compiled))
}

/// An upstream that says every name exists, so an NXDOMAIN can only come from this node.
async fn upstream() -> Fixture {
    Fixture::with_mode(Mode::Always(ResponseCode::NoError)).await
}

async fn start(upstream: SocketAddr, policy: &str) -> (SocketAddr, Services) {
    let mut options = ServerOptions::new(vec![upstream]);
    options.policy = handle(policy);
    start_server_with_services(options).await
}

const BLOCKS: &str = r#"
schema_version = 1
[[rules]]
id = "normal"
action = "deny"
match = "exact"
pattern = "ads.example"
[[rules]]
id = "urgent"
action = "deny"
match = "exact"
pattern = "malware.example"
emergency = true
[[lists]]
id = "list"
action = "deny"
domains = ["tracker.example"]
"#;

async fn code(server: SocketAddr, name: &str) -> ResponseCode {
    ask(server, name, RecordType::A)
        .await
        .metadata
        .response_code
}

#[tokio::test]
async fn pausing_lets_blocked_names_through_except_emergency_denies() {
    let fixture = upstream().await;
    let (server, services) = start(fixture.addr, BLOCKS).await;

    assert_eq!(code(server, "ads.example.").await, ResponseCode::NXDomain);
    assert_eq!(
        code(server, "tracker.example.").await,
        ResponseCode::NXDomain
    );
    assert_eq!(fixture.udp_queries(), 0);

    services.pause.pause(Duration::from_secs(60));
    assert_eq!(code(server, "ads.example.").await, ResponseCode::NoError);
    assert_eq!(
        code(server, "tracker.example.").await,
        ResponseCode::NoError
    );
    assert_eq!(
        code(server, "malware.example.").await,
        ResponseCode::NXDomain
    );

    services.pause.resume();
    assert_eq!(code(server, "ads.example.").await, ResponseCode::NXDomain);
}

#[tokio::test]
async fn a_pause_ends_by_itself() {
    let fixture = upstream().await;
    let (server, services) = start(fixture.addr, BLOCKS).await;
    services.pause.pause(Duration::from_millis(100));
    assert_eq!(code(server, "ads.example.").await, ResponseCode::NoError);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(code(server, "ads.example.").await, ResponseCode::NXDomain);
}

const DEVICE_RULES: &str = r#"
schema_version = 1
[[clients]]
id = "tablet"
macs = ["aa:bb:cc:00:00:01"]
[[rules]]
id = "r"
action = "deny"
match = "exact"
pattern = "games.example"
scope = { kind = "client", id = "tablet" }
"#;

#[tokio::test]
async fn a_mac_address_identifies_a_client_from_its_very_first_query() {
    let fixture = upstream().await;
    let mut options = ServerOptions::new(vec![fixture.addr]);
    options.policy = handle(DEVICE_RULES);
    options.neighbors = NeighborSource::fixed(vec![Neighbor {
        address: LOOPBACK,
        mac: MacAddress::new(MAC),
        active: true,
    }]);
    let (server, services) = start_server_with_services(options).await;

    assert_eq!(code(server, "games.example.").await, ResponseCode::NXDomain);
    let device = services.devices.get(LOOPBACK).unwrap();
    assert_eq!(device.mac, Some(MacAddress::new(MAC)));
    assert!(device.on_network);
}

#[tokio::test]
async fn a_different_mac_address_gets_the_default_policy() {
    let fixture = upstream().await;
    let mut options = ServerOptions::new(vec![fixture.addr]);
    options.policy = handle(DEVICE_RULES);
    options.neighbors = NeighborSource::fixed(vec![Neighbor {
        address: LOOPBACK,
        mac: MacAddress::new([0xaa, 0xbb, 0xcc, 0, 0, 2]),
        active: true,
    }]);
    let (server, _) = start_server_with_services(options).await;
    assert_eq!(code(server, "games.example.").await, ResponseCode::NoError);
}

/// A small DNS server, standing in for a router that knows the network's names.
async fn start_router(names: Vec<(&'static str, RData)>) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 1024];
        loop {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = Message::from_vec(&buffer[..length]).unwrap();
            let question = query.queries[0].clone();
            let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
            reply.metadata.message_type = MessageType::Response;
            reply.metadata.recursion_available = true;
            reply.add_query(question.clone());
            let found = names
                .iter()
                .find(|(name, _)| Name::from_ascii(name).unwrap() == *question.name());
            match found {
                Some((_, data)) => {
                    reply.add_answer(Record::from_rdata(
                        question.name().clone(),
                        60,
                        data.clone(),
                    ));
                }
                None => reply.metadata.response_code = ResponseCode::NXDomain,
            }
            let bytes = reply.to_vec().unwrap();
            socket.send_to(&bytes, peer).await.unwrap();
        }
    });
    address
}

fn address_of(message: &Message) -> Option<Ipv4Addr> {
    message
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::A(A(ip)) => Some(*ip),
            _ => None,
        })
}

#[tokio::test]
async fn forward_zones_use_their_own_servers_and_nothing_else() {
    let fixture = upstream().await;
    let router_answer = Ipv4Addr::new(192, 168, 1, 50);
    let router = start_router(vec![("nas.lan.", RData::A(A(router_answer)))]).await;
    let policy = format!(
        r#"
schema_version = 1
[[forward_zones]]
id = "router"
zones = ["lan"]
servers = ["{router}"]
"#
    );
    let (server, _) = start(fixture.addr, &policy).await;

    let answer = ask(server, "nas.lan.", RecordType::A).await;
    assert_eq!(address_of(&answer), Some(router_answer));
    assert_eq!(
        fixture.udp_queries(),
        0,
        "the default upstream must not hear about this"
    );

    // A name the router doesn't know isn't retried with the public upstreams.
    assert_eq!(code(server, "missing.lan.").await, ResponseCode::NXDomain);
    assert_eq!(fixture.udp_queries(), 0);

    // Everything else still goes to the default upstream.
    assert_eq!(code(server, "other.example.").await, ResponseCode::NoError);
    assert_eq!(fixture.udp_queries(), 1);
}

#[tokio::test]
async fn a_failed_forward_zone_fails_instead_of_leaking_upstream() {
    let fixture = upstream().await;
    let policy = r#"
schema_version = 1
[[forward_zones]]
id = "router"
zones = ["lan"]
servers = ["127.0.0.1:9"]
"#;
    let (server, _) = start(fixture.addr, policy).await;
    assert_eq!(code(server, "nas.lan.").await, ResponseCode::ServFail);
    assert_eq!(fixture.udp_queries(), 0);
}

#[tokio::test]
async fn policy_still_applies_to_forwarded_names() {
    let fixture = upstream().await;
    let router = start_router(vec![("ads.lan.", RData::A(A(Ipv4Addr::new(10, 0, 0, 1))))]).await;
    let policy = format!(
        r#"
schema_version = 1
[[forward_zones]]
id = "router"
zones = ["lan"]
servers = ["{router}"]
[[rules]]
id = "r"
action = "deny"
match = "exact"
pattern = "ads.lan"
"#
    );
    let (server, _) = start(fixture.addr, &policy).await;
    assert_eq!(code(server, "ads.lan.").await, ResponseCode::NXDomain);
}

#[tokio::test]
async fn forwarded_networks_take_over_their_private_reverse_lookups() {
    let fixture = upstream().await;
    let host = Name::from_ascii("printer.lan.").unwrap();
    let router = start_router(vec![(
        "9.0.0.10.in-addr.arpa.",
        RData::PTR(PTR(host.clone())),
    )])
    .await;
    let policy = format!(
        "schema_version = 1\n[[forward_zones]]\nid = \"r\"\nzones = [\"10.0.0.0/8\"]\nservers = [\"{router}\"]\n"
    );
    let (server, _) = start(fixture.addr, &policy).await;

    let reverse = ask(server, "9.0.0.10.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(reverse.metadata.response_code, ResponseCode::NoError);
    assert!(matches!(&reverse.answers[0].data, RData::PTR(PTR(name)) if *name == host));

    // Without a forward zone, other private ranges stay on this node.
    let other = ask(server, "9.1.168.192.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(other.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(fixture.udp_queries(), 0);
}

#[tokio::test]
async fn forward_routes_keep_their_answers_apart_in_the_cache() {
    let fixture = upstream().await;
    let first = Ipv4Addr::new(10, 0, 0, 1);
    let second = Ipv4Addr::new(10, 0, 0, 2);
    let router_one = start_router(vec![("nas.lan.", RData::A(A(first)))]).await;
    let router_two = start_router(vec![("nas.lan.", RData::A(A(second)))]).await;
    let document = |router: SocketAddr| {
        format!(
            "schema_version = 1\n[[forward_zones]]\nid = \"r\"\nzones = [\"lan\"]\nservers = [\"{router}\"]\n"
        )
    };
    let policy = handle(&document(router_one));
    let mut options = ServerOptions::new(vec![fixture.addr]);
    options.policy = Arc::clone(&policy);
    options.cache = Some(Arc::new(dns_cache::DnsCache::new(
        dns_cache::CacheConfig::default(),
    )));
    let (server, _) = start_server_with_services(options).await;

    let answer = ask(server, "nas.lan.", RecordType::A).await;
    assert_eq!(address_of(&answer), Some(first));

    let changed = PolicyDocument::parse(&document(router_two)).unwrap();
    policy.store(Arc::new(
        CompiledPolicy::compile("next", &changed, SystemTime::now(), None).unwrap(),
    ));
    let answer = ask(server, "nas.lan.", RecordType::A).await;
    assert_eq!(address_of(&answer), Some(second));
}

const LIMITED: &str = r#"
schema_version = 1
[rate_limit]
queries_per_minute = 10
exempt = []
"#;

#[tokio::test]
async fn a_client_over_its_limit_is_refused_without_reaching_upstream() {
    let fixture = upstream().await;
    let (server, services) = start(fixture.addr, LIMITED).await;

    for index in 0..10 {
        assert_eq!(
            code(server, &format!("host-{index}.example.")).await,
            ResponseCode::NoError
        );
    }
    let answered = fixture.udp_queries();
    assert_eq!(
        code(server, "one-more.example.").await,
        ResponseCode::Refused
    );
    assert_eq!(fixture.udp_queries(), answered);
    assert_eq!(services.rate_limiter.limited_total(), 1);
    assert!(
        services
            .rate_limiter
            .currently_limited()
            .contains(&LOOPBACK)
    );
}

#[tokio::test]
async fn exempt_networks_and_the_default_loopback_exemption_have_no_limit() {
    let fixture = upstream().await;
    let exempt =
        "schema_version = 1\n[rate_limit]\nqueries_per_minute = 1\nexempt = [\"127.0.0.1\"]\n";
    let (server, services) = start(fixture.addr, exempt).await;
    for _ in 0..5 {
        assert_eq!(code(server, "a.example.").await, ResponseCode::NoError);
    }
    assert_eq!(services.rate_limiter.limited_total(), 0);

    let off = "schema_version = 1\n[rate_limit]\nqueries_per_minute = 0\nexempt = []\n";
    let (server, services) = start(fixture.addr, off).await;
    for _ in 0..5 {
        assert_eq!(code(server, "b.example.").await, ResponseCode::NoError);
    }
    assert_eq!(services.rate_limiter.limited_total(), 0);
}

#[tokio::test]
async fn the_limit_also_covers_blocked_and_local_answers() {
    let fixture = upstream().await;
    let policy = "schema_version = 1\n[rate_limit]\nqueries_per_minute = 2\nexempt = []\n\
                  [[rules]]\nid = \"r\"\naction = \"deny\"\nmatch = \"exact\"\npattern = \"ads.example\"\n";
    let (server, _) = start(fixture.addr, policy).await;
    assert_eq!(code(server, "ads.example.").await, ResponseCode::NXDomain);
    assert_eq!(code(server, "localhost.").await, ResponseCode::NoError);
    assert_eq!(code(server, "ads.example.").await, ResponseCode::Refused);
    assert_eq!(code(server, "localhost.").await, ResponseCode::Refused);
}
