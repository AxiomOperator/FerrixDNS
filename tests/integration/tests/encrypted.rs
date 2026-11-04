//! DNS over TLS and DNS over HTTPS upstreams, with real TLS and certificate checks.

use std::net::SocketAddr;
use std::time::Duration;

use dns_upstreams::UpstreamServer;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use integration::{Fixture, ServerOptions, ask, start_server, test_certificate};

const NAME: &str = "dns.fixture.test";

fn tls(name: &str, address: SocketAddr) -> UpstreamServer {
    UpstreamServer::Tls {
        server_name: name.to_owned(),
        address,
    }
}

fn https(name: &str, address: SocketAddr) -> UpstreamServer {
    UpstreamServer::Https {
        server_name: name.to_owned(),
        path: "/dns-query".to_owned(),
        address,
    }
}

async fn server_with(upstream: UpstreamServer, root: Vec<u8>) -> SocketAddr {
    let mut options = ServerOptions::new(vec![]);
    options.upstreams = vec![upstream];
    options.trust_roots = Some(vec![root]);
    options.attempt_timeout = Duration::from_secs(2);
    options.total_timeout = Duration::from_secs(3);
    start_server(options).await
}

#[tokio::test]
async fn answers_over_dns_over_tls_and_reuses_the_connection() {
    let fixture = Fixture::start().await;
    let certificate = test_certificate(NAME, &[b"dot"]);
    let root = certificate.trust_root.clone();
    let address = fixture.serve_tls(certificate).await;
    let server = server_with(tls(NAME, address), root).await;

    for _ in 0..5 {
        let response = ask(server, "a.fixture.test.", RecordType::A).await;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
    }
    assert_eq!(fixture.tcp_queries(), 5);
    assert_eq!(
        fixture.udp_queries(),
        0,
        "nothing may fall back to plain DNS"
    );
}

#[tokio::test]
async fn answers_over_dns_over_https() {
    let fixture = Fixture::start().await;
    let certificate = test_certificate(NAME, &[b"http/1.1"]);
    let root = certificate.trust_root.clone();
    let address = fixture.serve_https(certificate).await;
    let server = server_with(https(NAME, address), root).await;

    let response = ask(server, "txt.fixture.test.", RecordType::TXT).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(fixture.tcp_queries(), 1);
    assert_eq!(fixture.udp_queries(), 0);
}

#[tokio::test]
async fn the_wrong_certificate_name_fails_instead_of_connecting_anyway() {
    let fixture = Fixture::start().await;

    let certificate = test_certificate(NAME, &[b"dot"]);
    let root = certificate.trust_root.clone();
    let address = fixture.serve_tls(certificate).await;
    let server = server_with(tls("other.fixture.test", address), root).await;
    let response = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);

    let certificate = test_certificate(NAME, &[b"http/1.1"]);
    let root = certificate.trust_root.clone();
    let address = fixture.serve_https(certificate).await;
    let server = server_with(https("other.fixture.test", address), root).await;
    let response = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);

    assert_eq!(
        fixture.tcp_queries() + fixture.udp_queries(),
        0,
        "no query may reach it"
    );
}

#[tokio::test]
async fn an_untrusted_certificate_fails_instead_of_connecting_anyway() {
    let fixture = Fixture::start().await;
    let certificate = test_certificate(NAME, &[b"dot"]);
    let address = fixture.serve_tls(certificate).await;
    let other_root = test_certificate(NAME, &[]).trust_root;
    let server = server_with(tls(NAME, address), other_root).await;

    let response = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(fixture.tcp_queries(), 0);
}

#[tokio::test]
async fn the_default_trust_store_rejects_a_private_certificate() {
    let fixture = Fixture::start().await;
    let address = fixture.serve_tls(test_certificate(NAME, &[b"dot"])).await;
    let mut options = ServerOptions::new(vec![]);
    options.upstreams = vec![tls(NAME, address)];
    let server = start_server(options).await;
    let response = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(fixture.tcp_queries(), 0);
}

#[tokio::test]
async fn encrypted_upstreams_fail_over_to_the_next_server() {
    let healthy = Fixture::start().await;
    let certificate = test_certificate(NAME, &[b"dot"]);
    let root = certificate.trust_root.clone();
    let address = healthy.serve_tls(certificate).await;

    // Nothing listens on this port.
    let closed: SocketAddr = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let mut options = ServerOptions::new(vec![]);
    options.upstreams = vec![tls(NAME, closed), tls(NAME, address)];
    options.trust_roots = Some(vec![root]);
    options.attempt_timeout = Duration::from_secs(1);
    options.total_timeout = Duration::from_secs(3);
    let server = start_server(options).await;

    let response = ask(server, "a.fixture.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
}
