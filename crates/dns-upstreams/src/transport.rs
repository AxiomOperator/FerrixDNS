use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::debug;

use crate::PoolConfigError;
use crate::server::UpstreamServer;

const UDP_RECEIVE_BUFFER: usize = 4096;
const DNS_MESSAGE: &str = "application/dns-message";
/// DNS messages can't be longer than this, so a longer HTTPS body isn't a DNS message.
const MAX_MESSAGE_BYTES: usize = 65_535;
const MAX_IDLE_TLS_CONNECTIONS: usize = 16;
/// Servers commonly close idle connections, so older ones aren't worth trying.
const TLS_IDLE_LIMIT: Duration = Duration::from_secs(20);

#[derive(Debug, Error)]
pub(crate) enum ExchangeError {
    #[error("timed out")]
    Timeout,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("the response doesn't match the query")]
    Mismatch,
    #[error("upstream response is too long or malformed: {0}")]
    Decode(String),
    #[error("HTTP request failed: {0}")]
    Http(String),
}

pub(crate) fn root_store(
    trust_roots: Option<&[Vec<u8>]>,
) -> Result<Arc<RootCertStore>, PoolConfigError> {
    install_crypto_provider();
    let mut store = RootCertStore::empty();
    match trust_roots {
        Some(roots) => {
            for der in roots {
                store
                    .add(CertificateDer::from(der.clone()))
                    .map_err(|error| PoolConfigError::Server {
                        server: "trust roots".to_owned(),
                        reason: error.to_string(),
                    })?;
            }
        }
        None => store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    Ok(Arc::new(store))
}

/// Selects ring for all TLS in the process. Repeated calls have no effect.
pub(crate) fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn client_config(roots: &Arc<RootCertStore>, alpn: &[&[u8]]) -> ClientConfig {
    let mut config = ClientConfig::builder()
        .with_root_certificates(Arc::clone(roots))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    config
}

/// How queries reach one server.
pub(crate) enum Transport {
    Plain(SocketAddr),
    Tls(TlsTransport),
    Https(HttpsTransport),
}

impl Transport {
    pub(crate) fn new(
        server: &UpstreamServer,
        roots: &Arc<RootCertStore>,
    ) -> Result<Self, PoolConfigError> {
        let failed = |reason: String| PoolConfigError::Server {
            server: server.to_string(),
            reason,
        };
        match server {
            UpstreamServer::Plain(address) => Ok(Self::Plain(*address)),
            UpstreamServer::Tls {
                server_name,
                address,
            } => {
                let name = ServerName::try_from(server_name.clone())
                    .map_err(|error| failed(error.to_string()))?;
                Ok(Self::Tls(TlsTransport {
                    address: *address,
                    name,
                    connector: TlsConnector::from(Arc::new(client_config(roots, &[b"dot"]))),
                    idle: Mutex::new(Vec::new()),
                }))
            }
            UpstreamServer::Https {
                server_name,
                path,
                address,
            } => {
                let client = reqwest::Client::builder()
                    .tls_backend_preconfigured(client_config(roots, &[b"h2", b"http/1.1"]))
                    // The configured address avoids depending on this node for name lookups.
                    .resolve(server_name, *address)
                    .pool_idle_timeout(Duration::from_secs(60))
                    .https_only(true)
                    .redirect(reqwest::redirect::Policy::none())
                    .user_agent(concat!("FerrixDNS/", env!("CARGO_PKG_VERSION")))
                    .build()
                    .map_err(|error| failed(error.to_string()))?;
                Ok(Self::Https(HttpsTransport {
                    client,
                    url: format!("https://{server_name}:{}{path}", address.port()),
                }))
            }
        }
    }

    pub(crate) fn uses_zero_id(&self) -> bool {
        matches!(self, Self::Https(_))
    }

    pub(crate) async fn exchange(
        &self,
        wire: &[u8],
        id: u16,
        query: &Query,
    ) -> Result<Message, ExchangeError> {
        match self {
            Self::Plain(address) => exchange_plain(*address, wire, id, query).await,
            Self::Tls(transport) => transport.exchange(wire, id, query).await,
            Self::Https(transport) => transport.exchange(wire, id, query).await,
        }
    }
}

fn matches_query(response: &Message, id: u16, query: &Query) -> bool {
    response.metadata.id == id
        && response.metadata.message_type == MessageType::Response
        && response.metadata.op_code == OpCode::Query
        && response.queries.len() == 1
        && response.queries.first() == Some(query)
}

fn decode_matching(bytes: &[u8], id: u16, query: &Query) -> Result<Message, ExchangeError> {
    let response =
        Message::from_vec(bytes).map_err(|error| ExchangeError::Decode(error.to_string()))?;
    if matches_query(&response, id, query) {
        Ok(response)
    } else {
        Err(ExchangeError::Mismatch)
    }
}

async fn exchange_plain(
    server: SocketAddr,
    wire: &[u8],
    id: u16,
    query: &Query,
) -> Result<Message, ExchangeError> {
    let response = exchange_udp(server, wire, id, query).await?;
    if response.metadata.truncation {
        debug!(%server, %query, "UDP response truncated, retrying over TCP");
        let mut stream = TcpStream::connect(server).await?;
        return roundtrip(&mut stream, wire, id, query).await;
    }
    Ok(response)
}

/// Waits for a matching response. Anything else is ignored rather than ending the wait, so an
/// off-path attacker can't cause a failure by sending a forged packet first.
async fn exchange_udp(
    server: SocketAddr,
    wire: &[u8],
    id: u16,
    query: &Query,
) -> Result<Message, ExchangeError> {
    let bind_ip = match server.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let socket = UdpSocket::bind((bind_ip, 0)).await?;
    // A connected socket only receives packets from this server.
    socket.connect(server).await?;
    socket.send(wire).await?;

    let mut buffer = vec![0_u8; UDP_RECEIVE_BUFFER];
    loop {
        let length = socket.recv(&mut buffer).await?;
        let Some(received) = buffer.get(..length) else {
            continue;
        };
        match Message::from_vec(received) {
            Ok(response) if matches_query(&response, id, query) => return Ok(response),
            Ok(_) => debug!(%server, "ignored UDP response that doesn't match the query"),
            Err(error) => debug!(%server, %error, "ignored malformed UDP response"),
        }
    }
}

/// One query and answer over a stream, using TCP's two-byte length framing (RFC 1035, RFC 7858).
async fn roundtrip<S>(
    stream: &mut S,
    wire: &[u8],
    id: u16,
    query: &Query,
) -> Result<Message, ExchangeError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let length = u16::try_from(wire.len())
        .map_err(|_| ExchangeError::Decode("query is too long for TCP framing".to_owned()))?;
    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(wire);
    stream.write_all(&framed).await?;
    stream.flush().await?;

    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix).await?;
    let mut buffer = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut buffer).await?;
    decode_matching(&buffer, id, query)
}

/// DNS over TLS, reusing connections because each new handshake costs several round trips.
pub(crate) struct TlsTransport {
    address: SocketAddr,
    name: ServerName<'static>,
    connector: TlsConnector,
    idle: Mutex<Vec<(TlsStream<TcpStream>, Instant)>>,
}

impl TlsTransport {
    fn take_idle(&self) -> Option<TlsStream<TcpStream>> {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some((stream, since)) = idle.pop() {
            if since.elapsed() < TLS_IDLE_LIMIT {
                return Some(stream);
            }
        }
        None
    }

    fn put_idle(&self, stream: TlsStream<TcpStream>) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() < MAX_IDLE_TLS_CONNECTIONS {
            idle.push((stream, Instant::now()));
        }
    }

    async fn exchange(
        &self,
        wire: &[u8],
        id: u16,
        query: &Query,
    ) -> Result<Message, ExchangeError> {
        // An idle connection may have been closed by the server, which isn't an upstream failure.
        if let Some(mut stream) = self.take_idle()
            && let Ok(response) = roundtrip(&mut stream, wire, id, query).await
        {
            self.put_idle(stream);
            return Ok(response);
        }

        let tcp = TcpStream::connect(self.address).await?;
        tcp.set_nodelay(true)?;
        // A failed certificate check ends the attempt here. There's no fallback to plain DNS.
        let mut stream = self.connector.connect(self.name.clone(), tcp).await?;
        let response = roundtrip(&mut stream, wire, id, query).await?;
        self.put_idle(stream);
        Ok(response)
    }
}

/// DNS over HTTPS (RFC 8484).
pub(crate) struct HttpsTransport {
    client: reqwest::Client,
    url: String,
}

impl HttpsTransport {
    async fn exchange(
        &self,
        wire: &[u8],
        id: u16,
        query: &Query,
    ) -> Result<Message, ExchangeError> {
        let mut response = self
            .client
            .post(&self.url)
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .header(ACCEPT, DNS_MESSAGE)
            .body(wire.to_vec())
            .send()
            .await
            .map_err(|error| ExchangeError::Http(describe(&error)))?;
        if !response.status().is_success() {
            return Err(ExchangeError::Http(format!("HTTP {}", response.status())));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| ExchangeError::Http(describe(&error)))?
        {
            if body.len() + chunk.len() > MAX_MESSAGE_BYTES {
                return Err(ExchangeError::Decode(
                    "the HTTPS body is too long".to_owned(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        decode_matching(&body, id, query)
    }
}

fn describe(error: &reqwest::Error) -> String {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        message = format!("{message}: {cause}");
        source = cause.source();
    }
    message
}
