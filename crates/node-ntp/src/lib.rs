//! A small NTP server that shares this machine's clock with the network.
//!
//! It doesn't discipline the clock itself. That stays the job of the machine's time service, such
//! as chrony or systemd-timesyncd. When the kernel says nothing is keeping the clock accurate,
//! replies say so, and clients ignore them rather than following a clock that may be wrong.

mod clock;

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use dns_runtime::{RateDecision, RateLimiter};
use ipnet::IpNet;
use tokio::net::UdpSocket;
use tracing::{info, warn};

use clock::{ClockMonitor, ntp_timestamp};
pub use clock::{ClockState, current_state};

const PACKET_LENGTH: usize = 48;
/// An unusually large request isn't refused, because NTP allows extension fields, but only the
/// fixed header is ever read or answered.
const RECEIVE_BUFFER: usize = 512;
const MODE_CLIENT: u8 = 3;
const MODE_SERVER: u8 = 4;
const LEAP_NONE: u8 = 0;
const LEAP_UNSYNCHRONIZED: u8 = 3;
/// A synchronized host usually gets its time from public stratum 2 servers.
const STRATUM_SYNCHRONIZED: u8 = 3;
const STRATUM_UNSYNCHRONIZED: u8 = 16;
const STRATUM_KISS: u8 = 0;
/// About a microsecond, as a power of two. This is the clock's read precision.
const PRECISION: i8 = -20;
/// Devices rarely poll more than a few times a minute, even while starting up.
const REQUESTS_PER_MINUTE: u32 = 120;

/// How NTP is set up, and what it's done.
#[derive(Debug, Default)]
pub struct NtpStats {
    served: AtomicU64,
    limited: AtomicU64,
}

impl NtpStats {
    pub fn served(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }

    pub fn limited(&self) -> u64 {
        self.limited.load(Ordering::Relaxed)
    }
}

/// A bound NTP server and what's needed to report on it.
pub struct NtpServer {
    sockets: Vec<UdpSocket>,
    allow: Arc<Vec<IpNet>>,
    stats: Arc<NtpStats>,
}

impl NtpServer {
    /// Binds every address. Only sources in `allow` get a reply.
    pub async fn bind(listen: &[SocketAddr], allow: Vec<IpNet>) -> io::Result<Self> {
        let mut sockets = Vec::with_capacity(listen.len());
        for address in listen {
            let socket = UdpSocket::bind(address).await.map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "cannot listen for NTP on {address}: {error}. If another time server \
                         already uses this port, stop it or leave NTP off here"
                    ),
                )
            })?;
            info!(address = %socket.local_addr()?, "listening for NTP");
            sockets.push(socket);
        }
        Ok(Self {
            sockets,
            allow: Arc::new(allow),
            stats: Arc::default(),
        })
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.sockets.iter().map(UdpSocket::local_addr).collect()
    }

    pub fn stats(&self) -> Arc<NtpStats> {
        Arc::clone(&self.stats)
    }

    /// Serves until `shutdown` completes.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let limiter = Arc::new(RateLimiter::default());
        let mut tasks = tokio::task::JoinSet::new();
        for socket in self.sockets {
            tasks.spawn(serve_socket(
                socket,
                Arc::clone(&self.allow),
                Arc::clone(&self.stats),
                Arc::clone(&limiter),
            ));
        }
        shutdown.await;
        tasks.abort_all();
    }
}

async fn serve_socket(
    socket: UdpSocket,
    allow: Arc<Vec<IpNet>>,
    stats: Arc<NtpStats>,
    limiter: Arc<RateLimiter>,
) {
    let mut clock = ClockMonitor::default();
    let mut warned = false;
    let mut buffer = [0_u8; RECEIVE_BUFFER];
    loop {
        let (length, peer) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(error) => {
                warn!(%error, "NTP receive failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let received = SystemTime::now();
        let source = peer.ip().to_canonical();
        if !is_allowed(&allow, source) {
            continue;
        }
        let Some(request) = buffer.get(..length) else {
            continue;
        };
        let limited = limiter.check(source, REQUESTS_PER_MINUTE) != RateDecision::Allow;
        let state = clock.state();
        if matches!(state, ClockState::Unsynchronized) && !warned {
            warn!("this machine's clock isn't synchronized, so NTP clients will ignore this node");
            warned = true;
        }
        let reply = if limited {
            stats.limited.fetch_add(1, Ordering::Relaxed);
            kiss_reply(request)
        } else {
            build_reply(request, state, received, SystemTime::now())
        };
        let Some(reply) = reply else { continue };
        if !limited {
            stats.served.fetch_add(1, Ordering::Relaxed);
        }
        if let Err(error) = socket.send_to(&reply, peer).await {
            warn!(%error, "NTP send failed");
        }
    }
}

fn is_allowed(allow: &[IpNet], source: IpAddr) -> bool {
    allow.iter().any(|network| network.contains(&source))
}

/// The version to answer with, if this is a request this server should answer.
fn request_version(request: &[u8]) -> Option<u8> {
    if request.len() < PACKET_LENGTH {
        return None;
    }
    let first = *request.first()?;
    let (version, mode) = ((first >> 3) & 0x07, first & 0x07);
    // Replying to anything but a client request could start a loop between two servers.
    (mode == MODE_CLIENT && (1..=4).contains(&version)).then_some(version)
}

/// A "slow down" reply (RFC 5905 section 7.4), which is no larger than the request.
fn kiss_reply(request: &[u8]) -> Option<[u8; PACKET_LENGTH]> {
    let version = request_version(request)?;
    let mut reply = [0_u8; PACKET_LENGTH];
    reply[0] = (LEAP_UNSYNCHRONIZED << 6) | (version << 3) | MODE_SERVER;
    reply[1] = STRATUM_KISS;
    reply[3] = PRECISION.to_be_bytes()[0];
    reply[12..16].copy_from_slice(b"RATE");
    reply[24..32].copy_from_slice(request.get(40..48)?);
    Some(reply)
}

/// Seconds as NTP's short format: 16 bits, then a 16-bit fraction.
fn short_format(duration: Duration) -> u32 {
    let scaled = duration.as_nanos().saturating_mul(1 << 16) / 1_000_000_000;
    u32::try_from(scaled).unwrap_or(u32::MAX)
}

fn build_reply(
    request: &[u8],
    state: ClockState,
    received: SystemTime,
    transmit: SystemTime,
) -> Option<[u8; PACKET_LENGTH]> {
    let version = request_version(request)?;
    let (leap, stratum, dispersion) = match state {
        ClockState::Synchronized { max_error } => (LEAP_NONE, STRATUM_SYNCHRONIZED, max_error),
        // Serving is more useful than silence on a host where this can't be read, and a machine
        // that blocks the system call is very likely managed. The System page shows this state.
        ClockState::Unknown => (LEAP_NONE, STRATUM_SYNCHRONIZED, Duration::from_secs(1)),
        ClockState::Unsynchronized => (
            LEAP_UNSYNCHRONIZED,
            STRATUM_UNSYNCHRONIZED,
            Duration::from_secs(16),
        ),
    };
    let mut reply = [0_u8; PACKET_LENGTH];
    reply[0] = (leap << 6) | (version << 3) | MODE_SERVER;
    reply[1] = stratum;
    // The client's polling interval, echoed so it isn't told to change it.
    reply[2] = *request.get(2)?;
    reply[3] = PRECISION.to_be_bytes()[0];
    // Root delay stays zero, because this node can't see its host's distance from a reference.
    reply[8..12].copy_from_slice(&short_format(dispersion).to_be_bytes());
    reply[12..16].copy_from_slice(b"LOCL");
    reply[16..24].copy_from_slice(&ntp_timestamp(received).to_be_bytes());
    // The client's transmit time comes back as the origin, which proves this answers its request.
    reply[24..32].copy_from_slice(request.get(40..48)?);
    reply[32..40].copy_from_slice(&ntp_timestamp(received).to_be_bytes());
    reply[40..48].copy_from_slice(&ntp_timestamp(transmit).to_be_bytes());
    Some(reply)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const SYNCED: ClockState = ClockState::Synchronized {
        max_error: Duration::from_millis(500),
    };

    fn request(version: u8, mode: u8) -> [u8; PACKET_LENGTH] {
        let mut packet = [0_u8; PACKET_LENGTH];
        packet[0] = (version << 3) | mode;
        packet[2] = 6;
        packet[40..48].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        packet
    }

    fn reply(request: &[u8], state: ClockState) -> Option<[u8; PACKET_LENGTH]> {
        let received = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        build_reply(
            request,
            state,
            received,
            received + Duration::from_millis(1),
        )
    }

    #[test]
    fn answers_a_client_with_its_origin_and_this_clock() {
        let answer = reply(&request(4, MODE_CLIENT), SYNCED).unwrap();
        assert_eq!(answer[0], (LEAP_NONE << 6) | (4 << 3) | MODE_SERVER);
        assert_eq!(answer[1], STRATUM_SYNCHRONIZED);
        assert_eq!(answer[2], 6);
        assert_eq!(&answer[12..16], b"LOCL");
        assert_eq!(answer[24..32], [1, 2, 3, 4, 5, 6, 7, 8]);
        // Half a second of possible error, in 16.16 fixed point.
        assert_eq!(answer[8..12], 0x8000_u32.to_be_bytes());
        let seconds =
            |range: std::ops::Range<usize>| u32::from_be_bytes(answer[range].try_into().unwrap());
        assert_eq!(seconds(32..36), 1_800_000_000 + 2_208_988_800);
        assert_eq!(seconds(40..44), 1_800_000_000 + 2_208_988_800);
        assert!(answer[44..48] > answer[36..40]);
    }

    #[test]
    fn answers_in_the_clients_version() {
        for version in 1..=4 {
            let answer = reply(&request(version, MODE_CLIENT), SYNCED).unwrap();
            assert_eq!((answer[0] >> 3) & 0x07, version);
        }
    }

    #[test]
    fn says_so_when_the_clock_isnt_synchronized() {
        let answer = reply(&request(4, MODE_CLIENT), ClockState::Unsynchronized).unwrap();
        assert_eq!(answer[0] >> 6, LEAP_UNSYNCHRONIZED);
        assert_eq!(answer[1], STRATUM_UNSYNCHRONIZED);
    }

    #[test]
    fn ignores_anything_but_a_valid_client_request() {
        assert!(reply(&request(4, MODE_SERVER), SYNCED).is_none());
        assert!(reply(&request(4, 6), SYNCED).is_none());
        assert!(reply(&request(0, MODE_CLIENT), SYNCED).is_none());
        assert!(reply(&request(5, MODE_CLIENT), SYNCED).is_none());
        assert!(reply(&[0x23; PACKET_LENGTH - 1], SYNCED).is_none());
        assert!(reply(&[], SYNCED).is_none());
    }

    #[test]
    fn extension_fields_never_make_a_reply_larger() {
        let mut long = request(4, MODE_CLIENT).to_vec();
        long.extend_from_slice(&[0; 100]);
        assert_eq!(reply(&long, SYNCED).unwrap().len(), PACKET_LENGTH);
    }

    #[test]
    fn kiss_replies_tell_clients_to_slow_down() {
        let answer = kiss_reply(&request(4, MODE_CLIENT)).unwrap();
        assert_eq!(answer[1], STRATUM_KISS);
        assert_eq!(&answer[12..16], b"RATE");
        assert_eq!(answer[24..32], [1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(kiss_reply(&request(4, MODE_SERVER)).is_none());
    }

    async fn exchange(server: SocketAddr, packet: &[u8]) -> Option<Vec<u8>> {
        let socket = UdpSocket::bind("127.0.0.1:0").await.ok()?;
        socket.send_to(packet, server).await.ok()?;
        let mut buffer = [0_u8; 512];
        let wait = Duration::from_millis(300);
        let (length, _) = tokio::time::timeout(wait, socket.recv_from(&mut buffer))
            .await
            .ok()?
            .ok()?;
        Some(buffer[..length].to_vec())
    }

    #[tokio::test]
    async fn serves_real_packets_and_stays_quiet_for_others() {
        let loopback: IpNet = "127.0.0.0/8".parse().unwrap();
        let server = NtpServer::bind(&[(Ipv4Addr::LOCALHOST, 0).into()], vec![loopback])
            .await
            .unwrap();
        let address = server.local_addrs().unwrap()[0];
        let stats = server.stats();
        tokio::spawn(server.run(std::future::pending()));

        let answer = exchange(address, &request(4, MODE_CLIENT)).await.unwrap();
        assert_eq!(answer.len(), PACKET_LENGTH);
        assert_eq!(answer[0] & 0x07, MODE_SERVER);
        assert_eq!(answer[24..32], [1, 2, 3, 4, 5, 6, 7, 8]);
        // A real timestamp, somewhere after this was written.
        let seconds = u32::from_be_bytes(answer[40..44].try_into().unwrap());
        assert!(u64::from(seconds) > 3_990_000_000);
        assert_eq!(stats.served(), 1);

        assert!(exchange(address, b"not ntp").await.is_none());
        assert_eq!(stats.served(), 1);
    }

    #[tokio::test]
    async fn sources_outside_the_allowed_networks_get_nothing() {
        let elsewhere: IpNet = "192.0.2.0/24".parse().unwrap();
        let server = NtpServer::bind(&[(Ipv4Addr::LOCALHOST, 0).into()], vec![elsewhere])
            .await
            .unwrap();
        let address = server.local_addrs().unwrap()[0];
        tokio::spawn(server.run(std::future::pending()));
        assert!(exchange(address, &request(4, MODE_CLIENT)).await.is_none());
    }

    #[tokio::test]
    async fn a_flood_gets_told_to_slow_down() {
        let loopback: IpNet = "127.0.0.0/8".parse().unwrap();
        let server = NtpServer::bind(&[(Ipv4Addr::LOCALHOST, 0).into()], vec![loopback])
            .await
            .unwrap();
        let address = server.local_addrs().unwrap()[0];
        let stats = server.stats();
        tokio::spawn(server.run(std::future::pending()));
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buffer = [0_u8; 512];
        for _ in 0..REQUESTS_PER_MINUTE {
            socket
                .send_to(&request(4, MODE_CLIENT), address)
                .await
                .unwrap();
            socket.recv_from(&mut buffer).await.unwrap();
        }
        socket
            .send_to(&request(4, MODE_CLIENT), address)
            .await
            .unwrap();
        socket.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[12..16], b"RATE");
        assert_eq!(stats.limited(), 1);
    }
}
