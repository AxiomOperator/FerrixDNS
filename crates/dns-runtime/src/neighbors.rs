//! Reads the kernel's neighbor table: which MAC address each nearby IP address belongs to.
//!
//! This speaks netlink directly, because a container image won't have `ip`, and `/proc/net/arp`
//! only covers IPv4.

use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use dns_policy::MacAddress;
use socket2::{Domain, Protocol, Socket, Type};

const AF_NETLINK: i32 = 16;
const NETLINK_ROUTE: i32 = 0;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NUD_INCOMPLETE: u16 = 0x01;
const NUD_REACHABLE: u16 = 0x02;
const NUD_DELAY: u16 = 0x08;
const NUD_PROBE: u16 = 0x10;
const NUD_FAILED: u16 = 0x20;
const NUD_NOARP: u16 = 0x40;
const NUD_PERMANENT: u16 = 0x80;
const HEADER_LENGTH: usize = 16;
const NDMSG_LENGTH: usize = 12;
const SEQUENCE: u32 = 0x4e45_4947;

/// One entry in the neighbor table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub address: IpAddr,
    pub mac: MacAddress,
    /// True if the kernel has recently confirmed this device, not just remembered it.
    pub active: bool,
}

type ReadNeighbors = dyn Fn() -> io::Result<Vec<Neighbor>> + Send + Sync;

/// Where neighbor entries come from.
#[derive(Clone)]
pub struct NeighborSource(Arc<ReadNeighbors>);

impl NeighborSource {
    /// The kernel's table, for real use.
    pub fn kernel() -> Self {
        Self(Arc::new(read_kernel_table))
    }

    /// A fixed table, for tests.
    pub fn fixed(neighbors: Vec<Neighbor>) -> Self {
        Self(Arc::new(move || Ok(neighbors.clone())))
    }

    pub(crate) fn read(&self) -> io::Result<Vec<Neighbor>> {
        (self.0)()
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw = bytes.get(offset..offset + 2)?;
    Some(u16::from_ne_bytes(raw.try_into().ok()?))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset + 4)?;
    Some(u32::from_ne_bytes(raw.try_into().ok()?))
}

fn request() -> Vec<u8> {
    let length = u32::try_from(HEADER_LENGTH + NDMSG_LENGTH).unwrap_or(u32::MAX);
    let mut message = Vec::with_capacity(HEADER_LENGTH + NDMSG_LENGTH);
    message.extend_from_slice(&length.to_ne_bytes());
    message.extend_from_slice(&RTM_GETNEIGH.to_ne_bytes());
    message.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    message.extend_from_slice(&SEQUENCE.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    // An all-zero ndmsg asks for every address family and interface.
    message.resize(HEADER_LENGTH + NDMSG_LENGTH, 0);
    message
}

fn read_kernel_table() -> io::Result<Vec<Neighbor>> {
    let mut socket = Socket::new(
        Domain::from(AF_NETLINK),
        Type::RAW,
        Some(Protocol::from(NETLINK_ROUTE)),
    )?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    // With no destination, a netlink message goes to the kernel.
    socket.send(&request())?;

    let mut neighbors = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let length = socket.read(&mut buffer)?;
        let received = buffer.get(..length).unwrap_or_default();
        if parse_messages(received, &mut neighbors)? {
            return Ok(neighbors);
        }
    }
}

/// Reads one batch of messages into `neighbors`, returning true at the end of the dump.
fn parse_messages(mut bytes: &[u8], neighbors: &mut Vec<Neighbor>) -> io::Result<bool> {
    while bytes.len() >= HEADER_LENGTH {
        let malformed = || io::Error::new(io::ErrorKind::InvalidData, "bad netlink message");
        let length = u32_at(bytes, 0).ok_or_else(malformed)? as usize;
        let kind = u16_at(bytes, 4).ok_or_else(malformed)?;
        if length < HEADER_LENGTH || length > bytes.len() {
            return Err(malformed());
        }
        let body = bytes.get(HEADER_LENGTH..length).ok_or_else(malformed)?;
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let code = u32_at(body, 0).ok_or_else(malformed)?;
                if code != 0 {
                    return Err(io::Error::from_raw_os_error(
                        i32::try_from(code.wrapping_neg()).unwrap_or(i32::MAX),
                    ));
                }
                return Ok(true);
            }
            RTM_NEWNEIGH => neighbors.extend(parse_neighbor(body)),
            _ => {}
        }
        bytes = bytes.get(length.next_multiple_of(4)..).unwrap_or_default();
    }
    Ok(false)
}

fn parse_neighbor(body: &[u8]) -> Option<Neighbor> {
    let state = u16_at(body, 8)?;
    if state & (NUD_INCOMPLETE | NUD_FAILED | NUD_NOARP) != 0 {
        return None;
    }
    let mut attributes = body.get(NDMSG_LENGTH..)?;
    let (mut address, mut mac) = (None, None);
    while attributes.len() >= 4 {
        let length = usize::from(u16_at(attributes, 0)?);
        let kind = u16_at(attributes, 2)?;
        if length < 4 {
            return None;
        }
        let value = attributes.get(4..length)?;
        match kind {
            NDA_DST => address = parse_address(value),
            NDA_LLADDR => {
                let octets: [u8; 6] = value.try_into().ok()?;
                mac = Some(MacAddress::new(octets));
            }
            _ => {}
        }
        attributes = attributes
            .get(length.next_multiple_of(4)..)
            .unwrap_or_default();
    }
    let (address, mac) = (address?, mac?);
    if address.is_multicast() || address.is_loopback() || mac.octets() == [0; 6] {
        return None;
    }
    Some(Neighbor {
        address,
        mac,
        active: state & (NUD_REACHABLE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT) != 0,
    })
}

fn parse_address(value: &[u8]) -> Option<IpAddr> {
    match value.len() {
        4 => {
            let octets: [u8; 4] = value.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        16 => {
            let octets: [u8; 16] = value.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)).to_canonical())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REACHABLE: u16 = NUD_REACHABLE;
    const STALE: u16 = 0x04;
    const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0, 0, 1];

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u16::try_from(value.len() + 4).unwrap().to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        bytes
    }

    fn message(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let length = u32::try_from(HEADER_LENGTH + body.len()).unwrap();
        bytes.extend_from_slice(&length.to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&[0; 10]);
        bytes.extend_from_slice(body);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        bytes
    }

    fn neighbor(state: u16, address: &[u8], mac: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![0_u8; 8];
        body.extend_from_slice(&state.to_ne_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend(attribute(NDA_DST, address));
        if let Some(mac) = mac {
            body.extend(attribute(NDA_LLADDR, mac));
        }
        message(RTM_NEWNEIGH, &body)
    }

    fn parsed(bytes: &[u8]) -> (Vec<Neighbor>, bool) {
        let mut neighbors = Vec::new();
        let done = parse_messages(bytes, &mut neighbors).unwrap();
        (neighbors, done)
    }

    #[test]
    fn parses_ipv4_and_ipv6_entries_across_a_dump() {
        let ipv6: Ipv6Addr = "fd00::5".parse().unwrap();
        let mut bytes = neighbor(REACHABLE, &[192, 168, 1, 5], Some(&MAC));
        bytes.extend(neighbor(STALE, &ipv6.octets(), Some(&MAC)));
        let (neighbors, done) = parsed(&bytes);
        assert!(!done);
        assert_eq!(
            neighbors,
            [
                Neighbor {
                    address: "192.168.1.5".parse().unwrap(),
                    mac: MacAddress::new(MAC),
                    active: true,
                },
                Neighbor {
                    address: IpAddr::V6(ipv6),
                    mac: MacAddress::new(MAC),
                    active: false,
                },
            ]
        );
        assert!(parsed(&message(NLMSG_DONE, &[0; 4])).1);
    }

    #[test]
    fn skips_entries_that_arent_devices() {
        let multicast: Ipv6Addr = "ff02::1".parse().unwrap();
        for entry in [
            neighbor(NUD_FAILED, &[192, 168, 1, 5], Some(&MAC)),
            neighbor(NUD_INCOMPLETE, &[192, 168, 1, 5], None),
            neighbor(NUD_NOARP, &multicast.octets(), Some(&MAC)),
            neighbor(REACHABLE, &multicast.octets(), Some(&MAC)),
            neighbor(REACHABLE, &[127, 0, 0, 1], Some(&MAC)),
            neighbor(REACHABLE, &[192, 168, 1, 5], Some(&[0; 6])),
            neighbor(REACHABLE, &[192, 168, 1, 5], None),
            neighbor(REACHABLE, &[192, 168, 1, 5], Some(&[1, 2, 3])),
        ] {
            assert!(parsed(&entry).0.is_empty());
        }
    }

    #[test]
    fn reports_kernel_errors_and_malformed_data() {
        let denied = (-13_i32).to_ne_bytes();
        let mut neighbors = Vec::new();
        let error = parse_messages(&message(NLMSG_ERROR, &denied), &mut neighbors).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let mut truncated = neighbor(REACHABLE, &[192, 168, 1, 5], Some(&MAC));
        truncated.truncate(20);
        assert!(parse_messages(&truncated, &mut neighbors).is_err());
    }

    #[test]
    fn the_kernel_table_can_be_read() {
        read_kernel_table().unwrap();
    }
}
