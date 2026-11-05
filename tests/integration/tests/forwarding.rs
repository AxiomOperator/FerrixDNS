//! FR-001 and FR-002: answering over UDP and TCP, and forwarding through upstream pools.

use std::time::{Duration, Instant};

use hickory_proto::op::{Edns, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use integration::{
    Fixture, Mode, ServerOptions, ask, exchange_tcp, exchange_udp, query_message, send_udp_raw,
    start_server,
};

async fn server_for(fixture: &Fixture) -> std::net::SocketAddr {
    start_server(ServerOptions::new(vec![fixture.addr])).await
}

fn edns(max_payload: u16, dnssec_ok: bool) -> Edns {
    let mut edns = Edns::new();
    edns.set_max_payload(max_payload);
    edns.set_dnssec_ok(dnssec_ok);
    edns
}

fn txt_of(response: &hickory_proto::op::Message) -> String {
    match &response.answers[0].data {
        RData::TXT(txt) => txt
            .txt_data
            .iter()
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect(),
        other => panic!("expected TXT, got {other:?}"),
    }
}

#[tokio::test]
async fn answers_each_record_type_over_udp_and_tcp() {
    let fixture = Fixture::start().await;
    let server = server_for(&fixture).await;
    let cases = [
        ("a.fixture.test.", RecordType::A),
        ("aaaa.fixture.test.", RecordType::AAAA),
        ("mx.fixture.test.", RecordType::MX),
        ("txt.fixture.test.", RecordType::TXT),
        ("ptr.fixture.test.", RecordType::PTR),
        ("srv.fixture.test.", RecordType::SRV),
        ("https.fixture.test.", RecordType::HTTPS),
        ("svcb.fixture.test.", RecordType::SVCB),
    ];
    for (qname, qtype) in cases {
        let message = query_message(qname, qtype, None);
        let (udp, _) = exchange_udp(server, &message).await;
        assert_eq!(udp.metadata.response_code, ResponseCode::NoError, "{qname}");
        assert_eq!(udp.answers.len(), 1, "{qname}");
        assert_eq!(udp.answers[0].record_type(), qtype, "{qname}");

        let tcp = exchange_tcp(server, &message).await;
        assert_eq!(tcp.answers, udp.answers, "{qname}");
    }
}

#[tokio::test]
async fn returns_the_whole_cname_chain() {
    let fixture = Fixture::start().await;
    let server = server_for(&fixture).await;
    let response = ask(server, "cname.fixture.test.", RecordType::A).await;
    assert_eq!(response.answers.len(), 2);
    assert_eq!(response.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(response.answers[1].record_type(), RecordType::A);
}

#[tokio::test]
async fn preserves_negative_answers_and_their_soa() {
    let fixture = Fixture::start().await;
    let server = server_for(&fixture).await;

    let nxdomain = ask(server, "nx.fixture.test.", RecordType::A).await;
    assert_eq!(nxdomain.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(nxdomain.authorities[0].record_type(), RecordType::SOA);

    let nodata = ask(server, "nodata.fixture.test.", RecordType::A).await;
    assert_eq!(nodata.metadata.response_code, ResponseCode::NoError);
    assert!(nodata.answers.is_empty());
    assert_eq!(nodata.authorities[0].record_type(), RecordType::SOA);
}

#[tokio::test]
async fn echoes_the_question_with_its_original_case() {
    let fixture = Fixture::start().await;
    let server = server_for(&fixture).await;

    // Built by hand because `Name::from_str` lowercases. Clients using 0x20 case randomization
    // reject answers that change the case of their question.
    let question = b"\x01A\x07FiXtUrE\x04tEsT\x00\x00\x01\x00\x01";
    let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    packet.extend_from_slice(question);

    let reply = send_udp_raw(server, &packet, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(&reply[12..12 + question.len()], question);
    let response = hickory_proto::op::Message::from_vec(&reply).unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
}

#[tokio::test]
async fn sets_recursion_available_and_never_claims_validation_or_authority() {
    let fixture = Fixture::start().await;
    let server = server_for(&fixture).await;
    let response = ask(server, "authenticated.fixture.test.", RecordType::A).await;
    assert!(response.metadata.recursion_available);
    assert!(!response.metadata.authentic_data);
    assert!(!response.metadata.authoritative);
}

#[tokio::test]
async fn falls_back_to_tcp_upstream_and_truncates_for_small_udp_clients() {
    let fixture = Fixture::start().await;
    let server = server_for(&fixture).await;

    // The client has no EDNS, so its UDP answer is limited to 512 bytes.
    let message = query_message("large.fixture.test.", RecordType::TXT, None);
    let (udp, size) = exchange_udp(server, &message).await;
    assert!(udp.metadata.truncation);
    assert!(size <= 512, "UDP response was {size} bytes");
    assert_eq!(
        fixture.tcp_queries(),
        1,
        "the forwarder must retry upstream over TCP"
    );

    // Over TCP the client receives everything.
    let tcp = exchange_tcp(server, &message).await;
    assert!(!tcp.metadata.truncation);
    assert_eq!(tcp.answers.len(), 30);
}

#[tokio::test]
async fn caps_edns_udp_responses_to_avoid_fragmentation() {
    let fixture = Fixture::start().await;
    let server = server_for(&fixture).await;
    let message = query_message(
        "large.fixture.test.",
        RecordType::TXT,
        Some(edns(4096, false)),
    );
    let (response, size) = exchange_udp(server, &message).await;
    assert!(response.metadata.truncation);
    assert!(size <= 1232, "UDP response was {size} bytes");
    assert_eq!(response.edns.unwrap().max_payload(), 1232);
}

#[tokio::test]
async fn forwards_edns_flags_but_not_client_options() {
    use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};

    let fixture = Fixture::start().await;
    let server = server_for(&fixture).await;

    let mut with_options = edns(4096, true);
    with_options
        .options_mut()
        .insert(EdnsOption::Unknown(EdnsCode::Cookie.into(), vec![1; 8]));
    let mut message = query_message("flags.fixture.test.", RecordType::TXT, Some(with_options));
    message.metadata.checking_disabled = true;

    let (response, _) = exchange_udp(server, &message).await;
    assert_eq!(
        txt_of(&response),
        "edns=true payload=1232 do=true options=0 rd=true cd=true"
    );
    assert!(response.edns.unwrap().flags().dnssec_ok);
    assert!(response.metadata.checking_disabled);
}

#[tokio::test]
async fn does_not_add_edns_for_clients_without_it() {
    let fixture = Fixture::start().await;
    let server = server_for(&fixture).await;
    let response = ask(server, "flags.fixture.test.", RecordType::TXT).await;
    assert_eq!(
        txt_of(&response),
        "edns=false payload=0 do=false options=0 rd=true cd=false"
    );
    assert!(response.edns.is_none());
}

#[tokio::test]
async fn ignores_forged_upstream_packets() {
    let fixture = Fixture::start().await;
    let server = server_for(&fixture).await;
    let response = ask(server, "spoof.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    let RData::A(address) = &response.answers[0].data else {
        panic!("expected an A record");
    };
    assert_eq!(
        address.0.to_string(),
        "192.0.2.1",
        "the forged answer must be ignored"
    );
}

#[tokio::test]
async fn fails_over_when_a_server_is_unreachable() {
    let healthy = Fixture::start().await;
    // Bind and release a port, so nothing is listening on it.
    let closed = {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.local_addr().unwrap()
    };
    let server = start_server(ServerOptions::new(vec![closed, healthy.addr])).await;
    let response = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
}

#[tokio::test]
async fn fails_over_on_timeout_servfail_and_refused() {
    for mode in [
        Mode::Silent,
        Mode::Always(ResponseCode::ServFail),
        Mode::Always(ResponseCode::Refused),
    ] {
        let failing = Fixture::with_mode(mode).await;
        let healthy = Fixture::start().await;
        let server = start_server(ServerOptions::new(vec![failing.addr, healthy.addr])).await;
        let response = ask(server, "a.fixture.test.", RecordType::A).await;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(failing.udp_queries(), 1);
        assert_eq!(healthy.udp_queries(), 1);
    }
}

#[tokio::test]
async fn does_not_fail_over_on_nxdomain() {
    let first = Fixture::start().await;
    let second = Fixture::start().await;
    let server = start_server(ServerOptions::new(vec![first.addr, second.addr])).await;
    let response = ask(server, "nx.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(second.udp_queries(), 0);
}

#[tokio::test]
async fn always_tries_servers_in_configured_order() {
    let first = Fixture::start().await;
    let second = Fixture::start().await;
    let server = start_server(ServerOptions::new(vec![first.addr, second.addr])).await;
    for _ in 0..10 {
        ask(server, "a.fixture.test.", RecordType::A).await;
    }
    assert_eq!(first.udp_queries(), 10);
    assert_eq!(second.udp_queries(), 0);
}

#[tokio::test]
async fn retries_the_pool_for_the_configured_rounds() {
    let silent = Fixture::with_mode(Mode::Silent).await;
    let mut options = ServerOptions::new(vec![silent.addr]);
    options.attempt_timeout = Duration::from_millis(50);
    options.rounds = 3;
    let server = start_server(options).await;
    let response = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(silent.udp_queries(), 3);
}

#[tokio::test]
async fn returns_servfail_within_the_deadline_when_all_servers_are_silent() {
    let silent = Fixture::with_mode(Mode::Silent).await;
    let mut options = ServerOptions::new(vec![silent.addr]);
    options.attempt_timeout = Duration::from_millis(200);
    options.total_timeout = Duration::from_millis(300);
    options.rounds = 100;
    let server = start_server(options).await;

    let started = Instant::now();
    let response = ask(server, "a.fixture.test.", RecordType::A).await;
    let elapsed = started.elapsed();
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert!(
        elapsed >= Duration::from_millis(280),
        "gave up early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(900),
        "ignored the deadline: {elapsed:?}"
    );
}

#[tokio::test]
async fn returns_the_upstream_failure_when_every_server_fails() {
    let refused = Fixture::with_mode(Mode::Always(ResponseCode::Refused)).await;
    let server = server_for(&refused).await;
    let response = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn handles_many_concurrent_queries() {
    let fixture = Fixture::start().await;
    let server = server_for(&fixture).await;
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..200 {
        tasks.spawn(async move {
            let qname = if index % 2 == 0 {
                "a.fixture.test."
            } else {
                "txt.fixture.test."
            };
            let qtype = if index % 2 == 0 {
                RecordType::A
            } else {
                RecordType::TXT
            };
            ask(server, qname, qtype).await
        });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(
            result.unwrap().metadata.response_code,
            ResponseCode::NoError
        );
    }
}

#[tokio::test]
async fn load_balancing_shares_queries_between_servers() {
    let first = Fixture::start().await;
    let second = Fixture::start().await;
    let mut options = ServerOptions::new(vec![first.addr, second.addr]);
    options.load_balance = true;
    let server = start_server(options).await;

    for _ in 0..20 {
        let response = ask(server, "a.fixture.test.", RecordType::A).await;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    }
    assert_eq!(first.udp_queries(), 10);
    assert_eq!(second.udp_queries(), 10);
}

#[tokio::test]
async fn servers_are_used_in_order_unless_load_balanced() {
    let first = Fixture::start().await;
    let second = Fixture::start().await;
    let server = start_server(ServerOptions::new(vec![first.addr, second.addr])).await;

    for _ in 0..10 {
        ask(server, "a.fixture.test.", RecordType::A).await;
    }
    assert_eq!(first.udp_queries(), 10);
    assert_eq!(second.udp_queries(), 0);
}

#[tokio::test]
async fn load_balancing_stops_waiting_for_a_silent_server() {
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let working = Fixture::start().await;
    let mut options = ServerOptions::new(vec![silent.local_addr().unwrap(), working.addr]);
    options.load_balance = true;
    let server = start_server(options).await;

    // Every query is answered, though it takes a couple of timeouts to notice the silent server.
    for _ in 0..4 {
        let response = ask(server, "a.fixture.test.", RecordType::A).await;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    }
    let started = Instant::now();
    for _ in 0..10 {
        let response = ask(server, "a.fixture.test.", RecordType::A).await;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    }
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "ten queries took {:?}, so at least one waited for the silent server",
        started.elapsed()
    );
}

#[tokio::test]
async fn allowed_networks_decide_who_gets_answered_including_everyone() {
    let fixture = Fixture::start().await;
    let server_allowing = |networks: &[&str]| {
        let mut options = ServerOptions::new(vec![fixture.addr]);
        options.allow = networks
            .iter()
            .map(|network| network.parse().unwrap())
            .collect();
        start_server(options)
    };

    let everyone = server_allowing(&["0.0.0.0/0", "::/0"]).await;
    let answer = ask(everyone, "a.fixture.test.", RecordType::A).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);

    let all_of_ipv4 = server_allowing(&["0.0.0.0/0"]).await;
    let answer = ask(all_of_ipv4, "a.fixture.test.", RecordType::A).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);

    let others_only = server_allowing(&["10.0.0.0/8"]).await;
    let answer = ask(others_only, "a.fixture.test.", RecordType::A).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::Refused);

    let loopback = server_allowing(&["127.0.0.1/32"]).await;
    let answer = ask(loopback, "a.fixture.test.", RecordType::A).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
}
