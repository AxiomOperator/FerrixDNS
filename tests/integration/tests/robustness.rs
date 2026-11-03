//! Request validation, access control, admission control and malformed input.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::op::{Edns, Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, RecordType};
use integration::{
    Fixture, ServerOptions, ask, exchange_tcp, exchange_udp, name, query_message, send_udp_raw,
    start_server,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

async fn running_server() -> SocketAddr {
    let fixture = Fixture::start().await;
    start_server(ServerOptions::new(vec![fixture.addr])).await
}

async fn assert_still_serving(server: SocketAddr) {
    let response = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
}

#[tokio::test]
async fn refuses_sources_outside_the_allow_list_over_udp_and_tcp() {
    let fixture = Fixture::start().await;
    let mut options = ServerOptions::new(vec![fixture.addr]);
    options.allow = vec!["10.0.0.0/8".parse().unwrap()];
    let server = start_server(options).await;

    let message = query_message("a.fixture.test.", RecordType::A, None);
    let (udp, _) = exchange_udp(server, &message).await;
    assert_eq!(udp.metadata.response_code, ResponseCode::Refused);
    let tcp = exchange_tcp(server, &message).await;
    assert_eq!(tcp.metadata.response_code, ResponseCode::Refused);
    assert_eq!(fixture.udp_queries() + fixture.tcp_queries(), 0);
}

#[tokio::test]
async fn an_empty_allow_list_refuses_everyone() {
    let fixture = Fixture::start().await;
    let mut options = ServerOptions::new(vec![fixture.addr]);
    options.allow = vec![];
    let server = start_server(options).await;
    let response = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
}

#[test]
fn the_default_allow_list_excludes_public_addresses() {
    let allow = dns_runtime::default_allow();
    let contains = |address: &str| {
        let ip: std::net::IpAddr = address.parse().unwrap();
        allow.iter().any(|network| network.contains(&ip))
    };
    for private in [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.20",
        "::1",
        "fd00::1",
    ] {
        assert!(contains(private), "{private} should be served");
    }
    for public in ["8.8.8.8", "172.32.0.1", "2001:4860:4860::8888"] {
        assert!(!contains(public), "{public} must not be served");
    }
}

#[tokio::test]
async fn sheds_requests_over_the_concurrency_limit() {
    let fixture = Fixture::start().await;
    let mut options = ServerOptions::new(vec![fixture.addr]);
    options.max_concurrent_requests = 1;
    options.attempt_timeout = Duration::from_secs(1);
    let server = start_server(options).await;

    let slow = tokio::spawn(async move { ask(server, "slow.fixture.test.", RecordType::A).await });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let shed = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(shed.metadata.response_code, ResponseCode::ServFail);

    let completed = slow.await.unwrap();
    assert_eq!(completed.metadata.response_code, ResponseCode::NoError);

    // The permit is released, so requests are served again.
    assert_still_serving(server).await;
}

#[tokio::test]
async fn rejects_unsupported_opcodes() {
    let server = running_server().await;
    for op_code in [OpCode::Status, OpCode::Notify, OpCode::Update] {
        let mut message = query_message("a.fixture.test.", RecordType::SOA, None);
        message.metadata.op_code = op_code;
        let (response, _) = exchange_udp(server, &message).await;
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NotImp,
            "{op_code:?}"
        );
    }
}

#[tokio::test]
async fn rejects_requests_without_exactly_one_question() {
    let server = running_server().await;

    let mut two = query_message("a.fixture.test.", RecordType::A, None);
    two.add_query(Query::query(name("b.fixture.test."), RecordType::A));
    let (response, _) = exchange_udp(server, &two).await;
    assert_eq!(response.metadata.response_code, ResponseCode::FormErr);

    let mut none = Message::query();
    none.metadata.id = 7;
    let (response, _) = exchange_udp(server, &none).await;
    assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
}

#[tokio::test]
async fn refuses_zone_transfers_and_other_classes() {
    let fixture = Fixture::start().await;
    let server = start_server(ServerOptions::new(vec![fixture.addr])).await;

    for qtype in [RecordType::AXFR, RecordType::IXFR] {
        let message = query_message("fixture.test.", qtype, None);
        let response = exchange_tcp(server, &message).await;
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::Refused,
            "{qtype}"
        );
    }

    let mut chaos = query_message("version.bind.", RecordType::TXT, None);
    chaos.queries[0].set_query_class(DNSClass::CH);
    let (response, _) = exchange_udp(server, &chaos).await;
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);

    assert_eq!(fixture.udp_queries() + fixture.tcp_queries(), 0);
}

#[tokio::test]
async fn answers_badvers_for_unknown_edns_versions() {
    let server = running_server().await;
    let mut edns = Edns::new();
    edns.set_version(1);
    let message = query_message("a.fixture.test.", RecordType::A, Some(edns));
    let (response, _) = exchange_udp(server, &message).await;
    // Hickory decodes 16 as BADSIG, which shares its number with BADVERS (RFC 6891).
    assert_eq!(u16::from(response.metadata.response_code), 16);
    assert_eq!(response.edns.unwrap().version(), 0);
}

#[tokio::test]
async fn survives_handcrafted_malformed_packets() {
    let server = running_server().await;
    let header = |qdcount: u8| vec![0x12, 0x34, 0x01, 0x00, 0x00, qdcount, 0, 0, 0, 0, 0, 0];

    let mut compression_loop = header(1);
    compression_loop.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);

    let mut forward_pointer = header(1);
    forward_pointer.extend_from_slice(&[0xc0, 0xff, 0x00, 0x01, 0x00, 0x01]);

    let mut overrun_label = header(1);
    overrun_label.extend_from_slice(&[0x3f, b'a']);

    let mut reserved_label = header(1);
    reserved_label.extend_from_slice(&[0x80, b'a', 0x00, 0x00, 0x01, 0x00, 0x01]);

    let mut oversized_name = header(1);
    for _ in 0..40 {
        oversized_name.push(63);
        oversized_name.extend_from_slice(&[b'a'; 63]);
    }
    oversized_name.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);

    let mut count_lie = header(1);
    count_lie[6] = 0xff;
    count_lie[7] = 0xff;
    count_lie.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);

    let packets = [
        vec![],
        vec![0x00],
        vec![0xff; 11],
        header(1),
        header(255),
        compression_loop,
        forward_pointer,
        overrun_label,
        reserved_label,
        oversized_name,
        count_lie,
    ];
    for packet in &packets {
        // Silence and an error are both acceptable here. Staying up is what matters.
        let reply = send_udp_raw(server, packet, Duration::from_millis(100)).await;
        if let Some(reply) = reply {
            let response = Message::from_vec(&reply).unwrap();
            assert_ne!(
                response.metadata.response_code,
                ResponseCode::NoError,
                "{packet:02x?}"
            );
        }
    }
    assert_still_serving(server).await;
}

#[tokio::test]
async fn does_not_answer_messages_marked_as_responses() {
    let server = running_server().await;
    let mut message = query_message("a.fixture.test.", RecordType::A, None);
    message.metadata.message_type = hickory_proto::op::MessageType::Response;
    let bytes = message.to_vec().unwrap();
    let reply = send_udp_raw(server, &bytes, Duration::from_millis(100)).await;
    assert!(
        reply.is_none(),
        "answering responses enables reflection loops"
    );
}

#[tokio::test]
async fn survives_random_and_mutated_packets() {
    let server = running_server().await;
    let valid = query_message("a.fixture.test.", RecordType::A, Some(Edns::new()))
        .to_vec()
        .unwrap();
    // A fixed seed keeps failures reproducible.
    let mut rng = StdRng::seed_from_u64(0xF3DD_1C5D);

    for iteration in 0..2000 {
        let packet: Vec<u8> = if iteration % 2 == 0 {
            let length = rng.random_range(0..512);
            (0..length).map(|_| rng.random()).collect()
        } else {
            let mut mutated = valid.clone();
            for _ in 0..rng.random_range(1..8) {
                let index = rng.random_range(0..mutated.len());
                mutated[index] = rng.random();
            }
            mutated
        };
        // Replies aren't awaited, which also exercises the listener under load.
        send_udp_raw(server, &packet, Duration::ZERO).await;
    }
    assert_still_serving(server).await;
}
