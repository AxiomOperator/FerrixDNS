//! Conditional forwarding: names that go to specific servers instead of the default upstreams.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::document::PolicyError;
use crate::name::DomainName;

/// Sends the names under some zones to specific servers, usually a router or AD DNS.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ForwardZoneDef {
    pub id: String,
    /// Domains, such as `lan`, or networks, such as `192.168.1.0/24`, whose reverse lookups go to
    /// these servers.
    pub zones: Vec<String>,
    /// Servers in the order they're tried, written like `--upstream` values.
    pub servers: Vec<String>,
    /// Shares queries between the servers, instead of using the first one that works.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub load_balance: bool,
}

/// Where a forwarded name goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardRoute {
    pub id: String,
    pub servers: Arc<[String]>,
    pub load_balance: bool,
    /// Identifies these servers in cache keys, so answers never cross between them.
    pub route: u32,
}

/// Compiled forward zones.
#[derive(Debug, Default)]
pub struct ForwardZones {
    routes: Vec<ForwardRoute>,
    zones: HashMap<Box<str>, usize>,
}

fn invalid(id: &str, reason: impl std::fmt::Display) -> PolicyError {
    PolicyError::Forward(format!("forward zone {id}: {reason}"))
}

/// A stable, non-zero number for a list of servers. Zero means the default upstreams.
fn route_number(servers: &[String]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    for server in servers {
        for byte in server.bytes().chain(std::iter::once(0)) {
            hash = (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193);
        }
    }
    hash.max(1)
}

/// The reverse zones that cover a network exactly.
///
/// Reverse zones split on octets for IPv4 and on nibbles for IPv6, so a network between those
/// boundaries becomes several zones. One narrower than a /24 or /124 can't be expressed as zones.
pub fn reverse_zones(network: IpNet) -> Result<Vec<String>, String> {
    let network = network.trunc();
    let prefix = u32::from(network.prefix_len());
    match network.addr() {
        IpAddr::V4(address) => {
            if !(8..=24).contains(&prefix) {
                return Err(format!("use a prefix from /8 to /24, not /{prefix}"));
            }
            let boundary = prefix.div_ceil(8) * 8;
            let base = u32::from(address);
            Ok((0..1_u32 << (boundary - prefix))
                .map(|offset| {
                    let octets = (base + (offset << (32 - boundary))).to_be_bytes();
                    let mut labels: Vec<String> = octets
                        .iter()
                        .take((boundary / 8) as usize)
                        .rev()
                        .map(ToString::to_string)
                        .collect();
                    labels.push("in-addr.arpa".to_owned());
                    labels.join(".")
                })
                .collect())
        }
        IpAddr::V6(address) => {
            if !(4..=124).contains(&prefix) {
                return Err(format!("use a prefix from /4 to /124, not /{prefix}"));
            }
            let boundary = prefix.div_ceil(4) * 4;
            let base = u128::from(address);
            Ok((0..1_u128 << (boundary - prefix))
                .map(|offset| {
                    let value = base + (offset << (128 - boundary));
                    let mut labels: Vec<String> = (0..boundary / 4)
                        .rev()
                        .map(|nibble| format!("{:x}", (value >> (124 - nibble * 4)) & 0xf))
                        .collect();
                    labels.push("ip6.arpa".to_owned());
                    labels.join(".")
                })
                .collect())
        }
    }
}

/// Turns one `zones` entry into DNS zone names.
fn zone_names(id: &str, value: &str) -> Result<Vec<String>, PolicyError> {
    if value.contains('/') {
        let network: IpNet = value
            .parse()
            .map_err(|_| invalid(id, format!("{value:?} isn't a valid network")))?;
        return reverse_zones(network).map_err(|reason| invalid(id, format!("{value}: {reason}")));
    }
    let name = DomainName::parse(value)
        .map_err(|error| invalid(id, format!("{value:?} isn't a valid name: {error}")))?;
    Ok(vec![name.as_str().to_owned()])
}

impl ForwardZones {
    /// Compiles forward zones. A managed local zone owns its names, so a forward zone can't be
    /// inside one.
    pub fn compile<'a>(
        definitions: &[ForwardZoneDef],
        local_zones: impl Iterator<Item = &'a str> + Clone,
    ) -> Result<Self, PolicyError> {
        let mut compiled = Self::default();
        let mut ids = std::collections::HashSet::new();
        for definition in definitions {
            let id = definition.id.as_str();
            if !ids.insert(id) {
                return Err(PolicyError::DuplicateId {
                    kind: "forward zone",
                    id: id.to_owned(),
                });
            }
            if definition.zones.is_empty() {
                return Err(invalid(id, "it needs at least one domain or network"));
            }
            if definition.servers.is_empty() {
                return Err(invalid(id, "it needs at least one server"));
            }
            let position = compiled.routes.len();
            compiled.routes.push(ForwardRoute {
                id: id.to_owned(),
                servers: definition.servers.iter().cloned().collect(),
                load_balance: definition.load_balance,
                route: route_number(&definition.servers),
            });
            for value in &definition.zones {
                for zone in zone_names(id, value)? {
                    check_zone(id, &zone, local_zones.clone())?;
                    if compiled
                        .zones
                        .insert(zone.as_str().into(), position)
                        .is_some()
                    {
                        return Err(invalid(id, format!("{zone} is forwarded more than once")));
                    }
                }
            }
        }
        Ok(compiled)
    }

    /// The most specific route for a name.
    pub fn route(&self, name: &DomainName) -> Option<&ForwardRoute> {
        if self.zones.is_empty() {
            return None;
        }
        let position = name.suffixes().find_map(|suffix| self.zones.get(suffix))?;
        self.routes.get(*position)
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }
}

fn check_zone<'a>(
    id: &str,
    zone: &str,
    mut local_zones: impl Iterator<Item = &'a str>,
) -> Result<(), PolicyError> {
    let is_under = |name: &str, parent: &str| {
        name == parent
            || name
                .strip_suffix(parent)
                .is_some_and(|prefix| prefix.ends_with('.'))
    };
    if zone.is_empty() {
        return Err(invalid(
            id,
            "the root can't be forwarded; that's what upstreams do",
        ));
    }
    if is_under(zone, "localhost") {
        return Err(invalid(id, "localhost always means this machine"));
    }
    if let Some(owner) = local_zones.find(|local| is_under(zone, local)) {
        return Err(invalid(
            id,
            format!("{zone} is inside the local zone {owner}, which answers it"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(value: &str) -> IpNet {
        value.parse().unwrap()
    }

    fn definition(zones: &[&str], servers: &[&str]) -> ForwardZoneDef {
        ForwardZoneDef {
            id: "f".to_owned(),
            zones: zones.iter().map(ToString::to_string).collect(),
            servers: servers.iter().map(ToString::to_string).collect(),
            load_balance: false,
        }
    }

    fn compile(zones: &[&str]) -> Result<ForwardZones, PolicyError> {
        ForwardZones::compile(&[definition(zones, &["192.168.1.1"])], std::iter::empty())
    }

    #[test]
    fn networks_become_the_reverse_zones_that_cover_them() {
        assert_eq!(
            reverse_zones(network("192.168.1.0/24")).unwrap(),
            ["1.168.192.in-addr.arpa"]
        );
        assert_eq!(
            reverse_zones(network("10.0.0.0/8")).unwrap(),
            ["10.in-addr.arpa"]
        );
        assert_eq!(
            reverse_zones(network("192.168.2.9/23")).unwrap(),
            ["2.168.192.in-addr.arpa", "3.168.192.in-addr.arpa"]
        );
        assert_eq!(
            reverse_zones(network("2001:db8::/32")).unwrap(),
            ["8.b.d.0.1.0.0.2.ip6.arpa"]
        );
        assert_eq!(
            reverse_zones(network("fd00::/7")).unwrap(),
            ["c.f.ip6.arpa", "d.f.ip6.arpa"]
        );
        assert!(reverse_zones(network("192.168.1.0/25")).is_err());
        assert!(reverse_zones(network("0.0.0.0/0")).is_err());
    }

    #[test]
    fn routes_pick_the_most_specific_zone_on_label_boundaries() {
        let zones = ForwardZones::compile(
            &[
                ForwardZoneDef {
                    id: "outer".to_owned(),
                    zones: vec!["corp.example".to_owned()],
                    servers: vec!["10.0.0.1".to_owned()],
                    load_balance: false,
                },
                ForwardZoneDef {
                    id: "inner".to_owned(),
                    zones: vec!["lab.corp.example".to_owned(), "10.1.0.0/16".to_owned()],
                    servers: vec!["10.0.0.2".to_owned()],
                    load_balance: false,
                },
            ],
            std::iter::empty(),
        )
        .unwrap();
        let route = |name: &str| {
            zones
                .route(&DomainName::parse(name).unwrap())
                .map(|route| route.id.as_str())
        };
        assert_eq!(route("corp.example"), Some("outer"));
        assert_eq!(route("a.CORP.example."), Some("outer"));
        assert_eq!(route("a.lab.corp.example"), Some("inner"));
        assert_eq!(route("9.1.1.10.in-addr.arpa"), Some("inner"));
        assert_eq!(route("notcorp.example"), None);
        assert_eq!(route("example"), None);
    }

    #[test]
    fn route_numbers_follow_the_servers_and_are_never_the_default() {
        let number = |servers: &[&str]| {
            route_number(&servers.iter().map(ToString::to_string).collect::<Vec<_>>())
        };
        assert_eq!(number(&["10.0.0.1"]), number(&["10.0.0.1"]));
        assert_ne!(number(&["10.0.0.1"]), number(&["10.0.0.2"]));
        assert_ne!(
            number(&["10.0.0.1", "10.0.0.2"]),
            number(&["10.0.0.2", "10.0.0.1"])
        );
        assert_ne!(number(&[]), 0);
    }

    #[test]
    fn bad_zones_are_rejected() {
        assert!(compile(&[]).is_err());
        assert!(compile(&["."]).is_err());
        assert!(compile(&["localhost"]).is_err());
        assert!(compile(&["a.localhost"]).is_err());
        assert!(compile(&["192.168.1.0/25"]).is_err());
        assert!(compile(&["not a network/24"]).is_err());
        assert!(compile(&["lan", "lan"]).is_err());
        assert!(ForwardZones::compile(&[definition(&["lan"], &[])], std::iter::empty()).is_err());
        let nested = ForwardZones::compile(
            &[definition(&["a.home.arpa"], &["10.0.0.1"])],
            ["home.arpa"].into_iter(),
        );
        assert!(
            nested
                .unwrap_err()
                .to_string()
                .contains("inside the local zone")
        );
    }
}
