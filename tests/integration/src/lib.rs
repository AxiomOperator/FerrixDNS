//! A scripted upstream DNS server and a small test client.
//!
//! The first label of the query name selects the fixture's behavior; see [`Fixture::respond`].

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dns_runtime::{DnsServer, PolicyHandle, RuntimeConfig, empty_policy};
use dns_upstreams::{PoolConfig, UpstreamServer};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::svcb::SVCB;
use hickory_proto::rr::rdata::{A, AAAA, CNAME, HTTPS, MX, PTR, SOA, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

/// How the whole fixture behaves, regardless of the query.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    /// Answer every query with this response code.
    Always(ResponseCode),
    /// Never answer.
    Silent,
}

/// A running upstream fixture on loopback, serving UDP and TCP on one port.
#[derive(Clone)]
pub struct Fixture {
    pub addr: SocketAddr,
    mode: Mode,
    udp_queries: Arc<AtomicUsize>,
    tcp_queries: Arc<AtomicUsize>,
}

pub fn name(value: &str) -> Name {
    Name::from_str(value).unwrap()
}

fn record(owner: &Name, rdata: RData) -> Record {
    Record::from_rdata(owner.clone(), 60, rdata)
}

fn soa() -> Record {
    record(
        &name("fixture.test."),
        RData::SOA(SOA::new(
            name("ns.fixture.test."),
            name("admin.fixture.test."),
            1,
            3600,
            600,
            86400,
            30,
        )),
    )
}

impl Fixture {
    pub async fn start() -> Self {
        Self::with_mode(Mode::Normal).await
    }

    pub async fn with_mode(mode: Mode) -> Self {
        let (socket, listener) = dns_runtime::bind_udp_and_tcp("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let fixture = Self {
            addr,
            mode,
            udp_queries: Arc::default(),
            tcp_queries: Arc::default(),
        };
        tokio::spawn(fixture.clone().serve_udp(socket));
        tokio::spawn(fixture.clone().serve_tcp(listener));
        fixture
    }

    pub fn udp_queries(&self) -> usize {
        self.udp_queries.load(Ordering::SeqCst)
    }

    pub fn tcp_queries(&self) -> usize {
        self.tcp_queries.load(Ordering::SeqCst)
    }

    async fn serve_udp(self, socket: UdpSocket) {
        let socket = Arc::new(socket);
        let mut buffer = vec![0_u8; 4096];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buffer[..length]) else {
                continue;
            };
            self.udp_queries.fetch_add(1, Ordering::SeqCst);
            let fixture = self.clone();
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                fixture.reply_udp(&socket, peer, &query).await;
            });
        }
    }

    async fn reply_udp(&self, socket: &UdpSocket, peer: SocketAddr, query: &Message) {
        let first_label = first_label(query);
        if self.mode == Mode::Normal && first_label == "spoof" {
            // Forged and malformed packets arrive before the real answer.
            let mut wrong_id = self.respond(query).unwrap();
            wrong_id.metadata.id = query.metadata.id.wrapping_add(1);
            wrong_id.answers = vec![record(
                query.queries[0].name(),
                RData::A(A(Ipv4Addr::new(203, 0, 113, 66))),
            )];
            socket
                .send_to(&wrong_id.to_vec().unwrap(), peer)
                .await
                .unwrap();

            let mut wrong_question = self.respond(query).unwrap();
            wrong_question.queries = vec![Query::query(name("evil.test."), RecordType::A)];
            socket
                .send_to(&wrong_question.to_vec().unwrap(), peer)
                .await
                .unwrap();

            socket
                .send_to(&[0xde, 0xad, 0xbe, 0xef], peer)
                .await
                .unwrap();
            sleep(Duration::from_millis(20)).await;
        }
        if self.mode == Mode::Normal && first_label == "slow" {
            sleep(Duration::from_millis(300)).await;
        }
        let Some(mut response) = self.respond(query) else {
            return;
        };
        // Like a real server, truncate what doesn't fit the requester's UDP buffer.
        let limit = query.edns.as_ref().map_or(512, Edns::max_payload);
        if response.to_vec().unwrap().len() > usize::from(limit) {
            response.answers.clear();
            response.metadata.truncation = true;
        }
        socket
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
    }

    async fn serve_tcp(self, listener: TcpListener) {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let fixture = self.clone();
            tokio::spawn(async move {
                let _ = fixture.handle_tcp(stream).await;
            });
        }
    }

    async fn handle_tcp(&self, mut stream: TcpStream) -> std::io::Result<()> {
        let length = stream.read_u16().await?;
        let mut buffer = vec![0_u8; usize::from(length)];
        stream.read_exact(&mut buffer).await?;
        let query = Message::from_vec(&buffer).unwrap();
        self.tcp_queries.fetch_add(1, Ordering::SeqCst);
        if let Some(response) = self.respond(&query) {
            let bytes = response.to_vec().unwrap();
            stream
                .write_u16(u16::try_from(bytes.len()).unwrap())
                .await?;
            stream.write_all(&bytes).await?;
        }
        Ok(())
    }

    /// Builds the scripted response. `None` means no response is sent.
    fn respond(&self, query: &Message) -> Option<Message> {
        let mut response = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        response.add_queries(query.queries.iter().cloned());
        if query.edns.is_some() {
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            response.set_edns(edns);
        }

        match self.mode {
            Mode::Silent => return None,
            Mode::Always(code) => {
                response.metadata.response_code = code;
                return Some(response);
            }
            Mode::Normal => {}
        }

        let question = query.queries.first()?;
        let owner = question.name();
        let label = first_label(query);
        match label.as_str() {
            "a" | "spoof" | "slow" => {
                response.add_answer(record(owner, RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))));
            }
            "aaaa" => {
                response.add_answer(record(
                    owner,
                    RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
                ));
            }
            "cname" => {
                let target = name("a.fixture.test.");
                response.add_answer(record(owner, RData::CNAME(CNAME(target.clone()))));
                response.add_answer(record(&target, RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))));
            }
            "mx" => {
                response.add_answer(record(
                    owner,
                    RData::MX(MX::new(10, name("mail.fixture.test."))),
                ));
            }
            "txt" => {
                response.add_answer(record(
                    owner,
                    RData::TXT(TXT::new(vec!["hello".to_owned()])),
                ));
            }
            "ptr" => {
                response.add_answer(record(owner, RData::PTR(PTR(name("host.fixture.test.")))));
            }
            "srv" => {
                response.add_answer(record(
                    owner,
                    RData::SRV(SRV::new(1, 2, 443, name("host.fixture.test."))),
                ));
            }
            "https" => {
                response.add_answer(record(
                    owner,
                    RData::HTTPS(HTTPS(SVCB::new(1, name("."), vec![]))),
                ));
            }
            "svcb" => {
                response.add_answer(record(
                    owner,
                    RData::SVCB(SVCB::new(1, name("host.fixture.test."), vec![])),
                ));
            }
            "nx" => {
                response.metadata.response_code = ResponseCode::NXDomain;
                response.add_authority(soa());
            }
            "nodata" => {
                response.add_authority(soa());
            }
            "large" => {
                for index in 0..30 {
                    let text = format!("{index:03}-{}", "x".repeat(200));
                    response.add_answer(record(owner, RData::TXT(TXT::new(vec![text]))));
                }
            }
            "flags" => {
                // Reports what the fixture received, so tests can check what was forwarded.
                let edns = query.edns.as_ref();
                let report = format!(
                    "edns={} payload={} do={} options={} rd={} cd={}",
                    edns.is_some(),
                    edns.map_or(0, Edns::max_payload),
                    edns.is_some_and(|edns| edns.flags().dnssec_ok),
                    edns.map_or(0, |edns| edns.options().as_ref().len()),
                    query.metadata.recursion_desired,
                    query.metadata.checking_disabled,
                );
                response.add_answer(record(owner, RData::TXT(TXT::new(vec![report]))));
            }
            "authenticated" => {
                response.metadata.authentic_data = true;
                response.metadata.authoritative = true;
                response.add_answer(record(owner, RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))));
            }
            "silent" => return None,
            _ => response.metadata.response_code = ResponseCode::NXDomain,
        }
        Some(response)
    }
}

fn first_label(query: &Message) -> String {
    query
        .queries
        .first()
        .and_then(|question| {
            question
                .name()
                .iter()
                .next()
                .map(|label| String::from_utf8_lossy(label).to_ascii_lowercase())
        })
        .unwrap_or_default()
}

/// A self-signed certificate for a DNS name, as a server's chain and key plus a trust root.
pub struct TestCertificate {
    pub trust_root: Vec<u8>,
    pub server_config: rustls::ServerConfig,
}

pub fn test_certificate(name: &str, alpn: &[&[u8]]) -> TestCertificate {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
    let der = certified.cert.der().clone();
    let key =
        rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    server_config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    TestCertificate {
        trust_root: der.to_vec(),
        server_config,
    }
}

impl Fixture {
    /// Serves this fixture over DNS over TLS.
    pub async fn serve_tls(&self, certificate: TestCertificate) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(certificate.server_config));
        let fixture = self.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (acceptor, fixture) = (acceptor.clone(), fixture.clone());
                tokio::spawn(async move {
                    // A client that rejects the certificate fails the handshake here.
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    // One connection can carry many queries.
                    while let Ok(length) = stream.read_u16().await {
                        let mut buffer = vec![0_u8; usize::from(length)];
                        if stream.read_exact(&mut buffer).await.is_err() {
                            return;
                        }
                        let query = Message::from_vec(&buffer).unwrap();
                        fixture.tcp_queries.fetch_add(1, Ordering::SeqCst);
                        let Some(response) = fixture.respond(&query) else {
                            return;
                        };
                        let bytes = response.to_vec().unwrap();
                        stream
                            .write_u16(u16::try_from(bytes.len()).unwrap())
                            .await
                            .unwrap();
                        stream.write_all(&bytes).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                });
            }
        });
        address
    }

    /// Serves this fixture over DNS over HTTPS, using HTTP/1.1.
    pub async fn serve_https(&self, certificate: TestCertificate) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(certificate.server_config));
        let fixture = self.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (acceptor, fixture) = (acceptor.clone(), fixture.clone());
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut received = Vec::new();
                    let mut chunk = [0_u8; 4096];
                    let (headers_end, content_length) = loop {
                        let Ok(count) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if count == 0 {
                            return;
                        }
                        received.extend_from_slice(&chunk[..count]);
                        if let Some(end) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                            let headers =
                                String::from_utf8_lossy(&received[..end]).to_ascii_lowercase();
                            assert!(headers.starts_with("post /dns-query "), "{headers}");
                            assert!(headers.contains("content-type: application/dns-message"));
                            let length = headers
                                .lines()
                                .find_map(|line| line.strip_prefix("content-length: "))
                                .unwrap()
                                .trim()
                                .parse::<usize>()
                                .unwrap();
                            break (end + 4, length);
                        }
                    };
                    while received.len() < headers_end + content_length {
                        let count = stream.read(&mut chunk).await.unwrap();
                        received.extend_from_slice(&chunk[..count]);
                    }
                    let query = Message::from_vec(&received[headers_end..]).unwrap();
                    assert_eq!(query.metadata.id, 0, "RFC 8484 recommends ID 0");
                    fixture.tcp_queries.fetch_add(1, Ordering::SeqCst);
                    let bytes = fixture.respond(&query).unwrap().to_vec().unwrap();
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n",
                        bytes.len()
                    );
                    stream.write_all(head.as_bytes()).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                    stream.shutdown().await.unwrap();
                });
            }
        });
        address
    }
}

/// Options for starting the server under test.
pub struct ServerOptions {
    pub upstreams: Vec<UpstreamServer>,
    pub load_balance: bool,
    pub trust_roots: Option<Vec<Vec<u8>>>,
    pub dnssec: Option<dns_runtime::DnssecConfig>,
    pub allow: Vec<IpNet>,
    pub max_concurrent_requests: usize,
    pub attempt_timeout: Duration,
    pub total_timeout: Duration,
    pub rounds: u32,
    pub policy: PolicyHandle,
    pub cache: Option<Arc<dns_cache::DnsCache>>,
    pub neighbors: dns_runtime::NeighborSource,
}

impl ServerOptions {
    pub fn new(upstreams: Vec<SocketAddr>) -> Self {
        Self {
            upstreams: upstreams.into_iter().map(UpstreamServer::from).collect(),
            load_balance: false,
            trust_roots: None,
            dnssec: None,
            allow: dns_runtime::default_allow(),
            max_concurrent_requests: 1024,
            attempt_timeout: Duration::from_millis(200),
            total_timeout: Duration::from_millis(1000),
            rounds: 1,
            policy: empty_policy(),
            cache: None,
            neighbors: dns_runtime::NeighborSource::fixed(vec![]),
        }
    }
}

/// Starts the server under test on a free loopback port and returns its address.
pub async fn start_server(options: ServerOptions) -> SocketAddr {
    start_server_with_services(options).await.0
}

/// Like [`start_server`], also returning the parts that the API would control.
pub async fn start_server_with_services(
    options: ServerOptions,
) -> (SocketAddr, dns_runtime::Services) {
    let server = DnsServer::bind(RuntimeConfig {
        listen: vec!["127.0.0.1:0".parse().unwrap()],
        allow: options.allow,
        upstreams: PoolConfig {
            servers: options.upstreams,
            load_balance: options.load_balance,
            trust_roots: options.trust_roots,
            attempt_timeout: options.attempt_timeout,
            total_timeout: options.total_timeout,
            rounds: options.rounds,
        },
        max_concurrent_requests: options.max_concurrent_requests,
        policy: options.policy,
        telemetry: None,
        cache: options.cache,
        dnssec: options.dnssec,
        neighbors: options.neighbors,
    })
    .await
    .unwrap();
    let addr = server.local_addrs()[0];
    let services = server.services();
    tokio::spawn(server.run(std::future::pending()));
    (addr, services)
}

/// Builds a query with a random ID and recursion desired.
pub fn query_message(qname: &str, qtype: RecordType, edns: Option<Edns>) -> Message {
    let mut message = Message::query();
    message.metadata.id = rand::random();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name(qname), qtype));
    if let Some(edns) = edns {
        message.set_edns(edns);
    }
    message
}

/// Sends raw bytes over UDP and returns the raw reply, if one arrives before the timeout.
pub async fn send_udp_raw(server: SocketAddr, bytes: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(server).await.unwrap();
    socket.send(bytes).await.unwrap();
    let mut buffer = vec![0_u8; 65535];
    let length = timeout(wait, socket.recv(&mut buffer)).await.ok()?.ok()?;
    buffer.truncate(length);
    Some(buffer)
}

/// Exchanges a message over UDP, returning the response and its size on the wire.
pub async fn exchange_udp(server: SocketAddr, message: &Message) -> (Message, usize) {
    let bytes = message.to_vec().unwrap();
    let reply = send_udp_raw(server, &bytes, Duration::from_secs(5))
        .await
        .expect("no UDP response");
    let response = Message::from_vec(&reply).unwrap();
    assert_eq!(
        response.metadata.id, message.metadata.id,
        "ID must be echoed"
    );
    assert_eq!(response.metadata.message_type, MessageType::Response);
    (response, reply.len())
}

/// Exchanges a message over TCP.
pub async fn exchange_tcp(server: SocketAddr, message: &Message) -> Message {
    let bytes = message.to_vec().unwrap();
    let mut stream = TcpStream::connect(server).await.unwrap();
    stream
        .write_u16(u16::try_from(bytes.len()).unwrap())
        .await
        .unwrap();
    stream.write_all(&bytes).await.unwrap();
    let length = timeout(Duration::from_secs(5), stream.read_u16())
        .await
        .expect("no TCP response")
        .unwrap();
    let mut buffer = vec![0_u8; usize::from(length)];
    stream.read_exact(&mut buffer).await.unwrap();
    let response = Message::from_vec(&buffer).unwrap();
    assert_eq!(
        response.metadata.id, message.metadata.id,
        "ID must be echoed"
    );
    response
}

/// Sends a simple query over UDP.
pub async fn ask(server: SocketAddr, qname: &str, qtype: RecordType) -> Message {
    exchange_udp(server, &query_message(qname, qtype, None))
        .await
        .0
}
