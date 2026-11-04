//! What's known about a device, beyond the address it sent a query from.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use thiserror::Error;

use crate::name::DomainName;

/// A MAC address that couldn't be parsed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("expected a MAC address such as aa:bb:cc:dd:ee:ff")]
pub struct MacParseError;

/// A device's hardware address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl FromStr for MacAddress {
    type Err = MacParseError;

    /// Accepts colons or hyphens, in either case.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut octets = [0_u8; 6];
        let mut parts = value.split([':', '-']);
        for octet in &mut octets {
            let part = parts.next().ok_or(MacParseError)?;
            if part.len() != 2 {
                return Err(MacParseError);
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| MacParseError)?;
        }
        if parts.next().is_some() {
            return Err(MacParseError);
        }
        Ok(Self(octets))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(formatter, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
    }
}

/// Who sent a query, as far as this node can tell.
#[derive(Clone, Copy, Debug)]
pub struct ClientSource<'a> {
    pub address: IpAddr,
    pub mac: Option<MacAddress>,
    pub hostname: Option<&'a DomainName>,
}

impl From<IpAddr> for ClientSource<'static> {
    fn from(address: IpAddr) -> Self {
        Self {
            address,
            mac: None,
            hostname: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_addresses_parse_and_normalize() {
        let mac: MacAddress = "AA-BB-cc:dd:EE:0f".parse().unwrap();
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:0f");
        for invalid in [
            "",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "a:b:c:d:e:f",
            "zz:bb:cc:dd:ee:ff",
        ] {
            assert!(invalid.parse::<MacAddress>().is_err(), "{invalid}");
        }
    }
}
