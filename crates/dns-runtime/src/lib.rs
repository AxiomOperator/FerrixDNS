//! DNS listeners and the request path: validate, filter, admit, forward and respond.

mod handler;
mod policy;

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dns_upstreams::{PoolConfig, UpstreamPool};
use hickory_server::Server;
use ipnet::IpNet;
use tokio::net::{TcpListener, UdpSocket};
use tracing::info;

pub use handler::ForwardHandler;
pub use policy::{PolicyHandle, PolicyLoadError, PolicyManager, empty_policy};

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_RESPONSE_BUFFER: usize = 32;
const PORT_ZERO_RETRIES: u32 = 32;

/// Settings for the DNS listeners and request path.
#[derive(Clone)]
pub struct RuntimeConfig {
    /// Addresses to listen on, each over both UDP and TCP.
    pub listen: Vec<SocketAddr>,
    /// Source networks that may query. All others receive REFUSED.
    pub allow: Vec<IpNet>,
    pub upstreams: PoolConfig,
    /// Requests allowed in flight upstream. Requests above this receive SERVFAIL.
    pub max_concurrent_requests: usize,
    /// The active policy, which can be replaced while the server runs.
    pub policy: PolicyHandle,
}

/// The networks served by default: loopback, private and link-local addresses.
///
/// Anything else must be allowed explicitly, so a node is never an open resolver by default.
pub fn default_allow() -> Vec<IpNet> {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    .iter()
    .filter_map(|network| network.parse().ok())
    .collect()
}

fn deny_everything() -> Vec<IpNet> {
    ["0.0.0.0/0", "::/0"]
        .iter()
        .filter_map(|network| network.parse().ok())
        .collect()
}

fn bind_error(protocol: &str, address: SocketAddr, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("cannot listen on {protocol} {address}: {error}"),
    )
}

/// Binds UDP and TCP to the same address.
///
/// With port 0 the UDP socket picks the port, and that port may already be taken for TCP, so this
/// tries a few different ports. A specific port is only tried once.
pub async fn bind_udp_and_tcp(address: SocketAddr) -> io::Result<(UdpSocket, TcpListener)> {
    let mut retries = if address.port() == 0 {
        PORT_ZERO_RETRIES
    } else {
        0
    };
    loop {
        let socket = UdpSocket::bind(address)
            .await
            .map_err(|error| bind_error("UDP", address, error))?;
        let local = socket.local_addr()?;
        match TcpListener::bind(local).await {
            Ok(listener) => return Ok((socket, listener)),
            Err(error) if retries > 0 && error.kind() == io::ErrorKind::AddrInUse => retries -= 1,
            Err(error) => return Err(bind_error("TCP", local, error)),
        }
    }
}

/// A DNS server bound to its listeners and ready to run.
pub struct DnsServer {
    server: Server<ForwardHandler>,
    local_addrs: Vec<SocketAddr>,
}

impl DnsServer {
    /// Binds every listener over UDP and TCP. Port 0 picks one free port for both.
    pub async fn bind(config: RuntimeConfig) -> io::Result<Self> {
        let pool = Arc::new(UpstreamPool::new(config.upstreams));
        let handler = ForwardHandler::new(pool, config.max_concurrent_requests, config.policy);
        // Allowed networks only take effect where a deny matches, so deny everything first.
        let mut server = Server::with_access(handler, deny_everything(), config.allow);

        let mut local_addrs = Vec::with_capacity(config.listen.len());
        for address in config.listen {
            let (socket, listener) = bind_udp_and_tcp(address).await?;
            let local = socket.local_addr()?;
            server.register_socket(socket);
            server.register_listener(listener, TCP_IDLE_TIMEOUT, TCP_RESPONSE_BUFFER);
            info!(address = %local, "listening for DNS over UDP and TCP");
            local_addrs.push(local);
        }
        Ok(Self {
            server,
            local_addrs,
        })
    }

    /// The bound addresses, useful when a listener asked for port 0.
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local_addrs
    }

    /// Serves until `shutdown` completes or a listener fails.
    pub async fn run(mut self, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        tokio::select! {
            result = self.server.block_until_done() => result.map_err(io::Error::other),
            () = shutdown => {
                info!("shutting down");
                self.server.shutdown_gracefully().await.map_err(io::Error::other)
            }
        }
    }
}
