use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use thiserror::Error;

const PLAIN_PORT: u16 = 53;
const TLS_PORT: u16 = 853;
const HTTPS_PORT: u16 = 443;
const DEFAULT_DOH_PATH: &str = "/dns-query";

/// An upstream server.
///
/// Encrypted servers name their certificate and also give an IP address to connect to. This node
/// usually is the network's DNS, so looking up an upstream's name would depend on itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamServer {
    /// UDP, falling back to TCP for truncated answers: `1.1.1.1` or `1.1.1.1:53`.
    Plain(SocketAddr),
    /// DNS over TLS: `tls://cloudflare-dns.com@1.1.1.1` or `...@1.1.1.1:853`.
    Tls {
        server_name: String,
        address: SocketAddr,
    },
    /// DNS over HTTPS: `https://cloudflare-dns.com/dns-query@1.1.1.1`.
    Https {
        server_name: String,
        path: String,
        address: SocketAddr,
    },
}

/// Why an upstream couldn't be understood.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ServerParseError {
    #[error(
        "{0:?} isn't an upstream. Use 1.1.1.1, tls://cloudflare-dns.com@1.1.1.1 or \
         https://cloudflare-dns.com/dns-query@1.1.1.1"
    )]
    Invalid(String),
    #[error(
        "{0:?} needs an IP address to connect to, because this node can't look up its own \
         upstream. Add it after the name, as in tls://cloudflare-dns.com@1.1.1.1"
    )]
    MissingAddress(String),
}

fn parse_address(value: &str, default_port: u16) -> Option<SocketAddr> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Some(address);
    }
    let bare = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(value);
    bare.parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, default_port))
}

fn is_host_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

impl FromStr for UpstreamServer {
    type Err = ServerParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || ServerParseError::Invalid(value.to_owned());
        if let Some(rest) = value.strip_prefix("tls://") {
            let (server_name, address) = rest
                .rsplit_once('@')
                .ok_or_else(|| ServerParseError::MissingAddress(value.to_owned()))?;
            if !is_host_name(server_name) {
                return Err(invalid());
            }
            return Ok(Self::Tls {
                server_name: server_name.to_owned(),
                address: parse_address(address, TLS_PORT).ok_or_else(invalid)?,
            });
        }
        if let Some(rest) = value.strip_prefix("https://") {
            let (target, address) = rest
                .rsplit_once('@')
                .ok_or_else(|| ServerParseError::MissingAddress(value.to_owned()))?;
            let (server_name, path) = match target.split_once('/') {
                Some((name, path)) => (name, format!("/{path}")),
                None => (target, DEFAULT_DOH_PATH.to_owned()),
            };
            if !is_host_name(server_name) {
                return Err(invalid());
            }
            return Ok(Self::Https {
                server_name: server_name.to_owned(),
                path,
                address: parse_address(address, HTTPS_PORT).ok_or_else(invalid)?,
            });
        }
        parse_address(value, PLAIN_PORT)
            .map(Self::Plain)
            .ok_or_else(invalid)
    }
}

impl fmt::Display for UpstreamServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(address) => write!(formatter, "{address}"),
            Self::Tls {
                server_name,
                address,
            } => write!(formatter, "tls://{server_name}@{address}"),
            Self::Https {
                server_name,
                path,
                address,
            } => write!(formatter, "https://{server_name}{path}@{address}"),
        }
    }
}

impl From<SocketAddr> for UpstreamServer {
    fn from(address: SocketAddr) -> Self {
        Self::Plain(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(value: &str) -> UpstreamServer {
        value.parse().unwrap()
    }

    #[test]
    fn parses_plain_servers() {
        let expected = UpstreamServer::Plain("1.1.1.1:53".parse().unwrap());
        assert_eq!(parsed("1.1.1.1"), expected);
        assert_eq!(parsed("1.1.1.1:53"), expected);
        assert_eq!(parsed("1.1.1.1:5353").to_string(), "1.1.1.1:5353");
        assert_eq!(
            parsed("2606:4700:4700::1111").to_string(),
            "[2606:4700:4700::1111]:53"
        );
        assert_eq!(parsed("[::1]:5300").to_string(), "[::1]:5300");
    }

    #[test]
    fn parses_tls_servers() {
        let expected = UpstreamServer::Tls {
            server_name: "cloudflare-dns.com".to_owned(),
            address: "1.1.1.1:853".parse().unwrap(),
        };
        assert_eq!(parsed("tls://cloudflare-dns.com@1.1.1.1"), expected);
        assert_eq!(parsed("tls://cloudflare-dns.com@1.1.1.1:853"), expected);
        assert_eq!(expected.to_string(), "tls://cloudflare-dns.com@1.1.1.1:853");
        assert_eq!(
            parsed("tls://dns.example@[2001:db8::1]").to_string(),
            "tls://dns.example@[2001:db8::1]:853"
        );
    }

    #[test]
    fn parses_https_servers() {
        let expected = UpstreamServer::Https {
            server_name: "cloudflare-dns.com".to_owned(),
            path: "/dns-query".to_owned(),
            address: "1.1.1.1:443".parse().unwrap(),
        };
        assert_eq!(
            parsed("https://cloudflare-dns.com/dns-query@1.1.1.1"),
            expected
        );
        assert_eq!(parsed("https://cloudflare-dns.com@1.1.1.1"), expected);
        assert_eq!(
            parsed("https://dns.example/custom/path@1.1.1.1:8443").to_string(),
            "https://dns.example/custom/path@1.1.1.1:8443"
        );
        // A port belongs on the address, because that's what gets connected to.
        assert!(
            "https://dns.example:8443/q@1.1.1.1"
                .parse::<UpstreamServer>()
                .is_err()
        );
    }

    #[test]
    fn encrypted_servers_need_an_address() {
        for value in [
            "tls://cloudflare-dns.com",
            "https://cloudflare-dns.com/dns-query",
        ] {
            assert!(matches!(
                value.parse::<UpstreamServer>(),
                Err(ServerParseError::MissingAddress(_))
            ));
        }
    }

    #[test]
    fn rejects_invalid_servers() {
        for value in [
            "",
            "dns.google",
            "tls://name@nope",
            "tls://@1.1.1.1",
            "tls://bad name@1.1.1.1",
            "http://dns.example@1.1.1.1",
        ] {
            assert!(value.parse::<UpstreamServer>().is_err(), "{value}");
        }
    }
}
