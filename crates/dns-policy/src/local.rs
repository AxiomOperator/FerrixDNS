//! Local DNS: names this node answers itself, from managed zones and reserved names.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::document::PolicyError;
use crate::name::DomainName;

/// Longest allowed chain of CNAMEs inside local zones.
const MAX_LOCAL_CHAIN: usize = 16;
const DEFAULT_TTL_SECONDS: u32 = 300;
const MAX_TTL_SECONDS: u32 = 86_400;
/// How long clients may cache "no such name" from a local zone.
pub const LOCAL_NEGATIVE_TTL_SECONDS: u32 = 60;

fn default_ttl() -> u32 {
    DEFAULT_TTL_SECONDS
}

/// A record type that can be stored in a local zone.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum LocalRecordType {
    A,
    Aaaa,
    Cname,
    Ptr,
}

/// A zone this node is authoritative for.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalZoneDef {
    pub name: String,
}

/// A record in a local zone.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalRecordDef {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: LocalRecordType,
    pub value: String,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u32,
}

/// The data of an answer record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(DomainName),
    Ptr(DomainName),
    /// The zone's synthesized SOA.
    Soa,
    /// The zone's synthesized name server.
    Ns,
}

/// One record in an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalRecord {
    pub name: DomainName,
    pub ttl: u32,
    pub data: LocalData,
}

/// The kind of question being asked, reduced to what local answers care about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalQuery {
    A,
    Aaaa,
    Cname,
    Ptr,
    Soa,
    Ns,
    Any,
    Other,
}

/// How to answer a question this node owns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAnswer {
    pub records: Vec<LocalRecord>,
    /// True for a name that doesn't exist, as opposed to one without this record type.
    pub nxdomain: bool,
    /// The zone that owns the answer. Reserved names have none.
    pub zone: Option<DomainName>,
    /// Names policy rules must allow: the question, and any CNAME targets followed.
    pub names: Vec<DomainName>,
    /// False for reserved names, which policy doesn't apply to.
    pub policy_applies: bool,
}

#[derive(Debug)]
struct Zone {
    /// Names with no records of their own but with descendants, which exist in the DNS.
    empty_non_terminals: HashSet<Box<str>>,
}

/// Compiled local zones, plus PTRs generated from their private addresses.
#[derive(Debug, Default)]
pub struct LocalZones {
    zones: HashMap<Box<str>, Zone>,
    records: HashMap<Box<str>, Vec<LocalRecord>>,
    generated_ptrs: HashMap<Box<str>, LocalRecord>,
}

fn invalid(message: String) -> PolicyError {
    PolicyError::LocalDns(message)
}

fn parent(name: &str) -> Option<&str> {
    name.split_once('.').map(|(_, parent)| parent)
}

fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(name), |current| parent(current))
}

/// The reverse-lookup name for an address.
pub fn reverse_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(ip) => {
            let mut labels: Vec<String> = Vec::with_capacity(34);
            for byte in ip.octets().iter().rev() {
                labels.push(format!("{:x}", byte & 0x0f));
                labels.push(format!("{:x}", byte >> 4));
            }
            labels.push("ip6".to_owned());
            labels.push("arpa".to_owned());
            labels.join(".")
        }
    }
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local() || ip.is_loopback(),
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80 || ip.is_loopback()
        }
    }
}

impl LocalZones {
    /// Compiles and validates zones and records.
    pub fn compile(
        zones: &[LocalZoneDef],
        records: &[LocalRecordDef],
    ) -> Result<Self, PolicyError> {
        let mut compiled = Self::default();
        for zone in zones {
            let name = DomainName::parse(&zone.name)
                .map_err(|error| invalid(format!("zone {:?}: {error}", zone.name)))?;
            if name.is_root() {
                return Err(invalid("the root can't be a local zone".to_owned()));
            }
            if compiled.zones.contains_key(name.as_str()) {
                return Err(invalid(format!("zone {} is listed twice", name.as_str())));
            }
            compiled.zones.insert(
                name.as_str().into(),
                Zone {
                    empty_non_terminals: HashSet::new(),
                },
            );
        }

        let mut seen_ids = HashSet::new();
        let mut seen_records = HashSet::new();
        for record in records {
            if !seen_ids.insert(record.id.as_str()) {
                return Err(PolicyError::DuplicateId {
                    kind: "local record",
                    id: record.id.clone(),
                });
            }
            compiled.add_record(record, &mut seen_records)?;
        }
        compiled.validate_cnames()?;
        compiled.index_empty_non_terminals();
        compiled.generate_ptrs();
        Ok(compiled)
    }

    fn add_record(
        &mut self,
        record: &LocalRecordDef,
        seen: &mut HashSet<(String, LocalRecordType, String)>,
    ) -> Result<(), PolicyError> {
        let name = DomainName::parse(&record.name)
            .map_err(|error| invalid(format!("record {:?}: {error}", record.name)))?;
        if self.zone_of(name.as_str()).is_none() {
            return Err(invalid(format!(
                "{} isn't in a local zone. Add the zone first, because this node only answers \
                 for zones it manages",
                name.as_str()
            )));
        }
        if record.ttl_seconds > MAX_TTL_SECONDS {
            return Err(invalid(format!(
                "{}: the TTL can be at most {MAX_TTL_SECONDS} seconds",
                name.as_str()
            )));
        }
        let bad_value = |expected: &str| {
            invalid(format!(
                "{}: {:?} isn't {expected}",
                name.as_str(),
                record.value
            ))
        };
        let data = match record.record_type {
            LocalRecordType::A => LocalData::A(
                record
                    .value
                    .trim()
                    .parse()
                    .map_err(|_| bad_value("an IPv4 address"))?,
            ),
            LocalRecordType::Aaaa => LocalData::Aaaa(
                record
                    .value
                    .trim()
                    .parse()
                    .map_err(|_| bad_value("an IPv6 address"))?,
            ),
            LocalRecordType::Cname => LocalData::Cname(
                DomainName::parse(record.value.trim()).map_err(|_| bad_value("a domain name"))?,
            ),
            LocalRecordType::Ptr => LocalData::Ptr(
                DomainName::parse(record.value.trim()).map_err(|_| bad_value("a domain name"))?,
            ),
        };
        let key = (
            name.as_str().to_owned(),
            record.record_type,
            format!("{data:?}"),
        );
        if !seen.insert(key) {
            return Err(invalid(format!(
                "{} has the same record twice",
                name.as_str()
            )));
        }
        self.records
            .entry(name.as_str().into())
            .or_default()
            .push(LocalRecord {
                name,
                ttl: record.ttl_seconds,
                data,
            });
        Ok(())
    }

    /// RFC 1034: a CNAME must be the only record at its name, and chains must end.
    fn validate_cnames(&self) -> Result<(), PolicyError> {
        for (name, records) in &self.records {
            let cnames = records
                .iter()
                .filter(|record| matches!(record.data, LocalData::Cname(_)))
                .count();
            if cnames == 0 {
                continue;
            }
            if records.len() > 1 {
                return Err(invalid(format!(
                    "{name} has a CNAME, so it can't have any other records"
                )));
            }
            if self.zones.contains_key(name) {
                return Err(invalid(format!(
                    "{name} is a zone's own name, so it can't be a CNAME"
                )));
            }

            let mut visited = HashSet::new();
            let mut current: &str = name;
            while let Some(LocalData::Cname(target)) = self
                .records
                .get(current)
                .and_then(|records| records.first())
                .map(|record| &record.data)
            {
                if !visited.insert(current) {
                    return Err(invalid(format!("{name} is part of a CNAME loop")));
                }
                if visited.len() > MAX_LOCAL_CHAIN {
                    return Err(invalid(format!("{name} has too many CNAMEs in a row")));
                }
                if self.zone_of(target.as_str()).is_none() {
                    return Err(invalid(format!(
                        "{name} points to {}, which isn't in a local zone. Local CNAMEs can only \
                         point to names this node manages",
                        target.as_str()
                    )));
                }
                current = target.as_str();
            }
        }
        Ok(())
    }

    fn index_empty_non_terminals(&mut self) {
        let names: Vec<Box<str>> = self.records.keys().cloned().collect();
        for name in names {
            let Some(zone_name) = self.zone_of(&name).map(str::to_owned) else {
                continue;
            };
            let intermediate: Vec<Box<str>> = suffixes(&name)
                .skip(1)
                .take_while(|suffix| suffix.len() > zone_name.len())
                .map(Into::into)
                .collect();
            if let Some(zone) = self.zones.get_mut(zone_name.as_str()) {
                zone.empty_non_terminals.extend(intermediate);
            }
        }
    }

    /// Reverse lookups for private addresses get an answer from the matching forward record.
    /// Public addresses are left alone, because their reverse zones belong to someone else.
    fn generate_ptrs(&mut self) {
        let mut names: Vec<&Box<str>> = self.records.keys().collect();
        // Sorted, so which name wins for a shared address doesn't vary between compiles.
        names.sort_unstable();
        let mut generated = HashMap::new();
        for name in names {
            for record in &self.records[name] {
                let address = match record.data {
                    LocalData::A(ip) => IpAddr::V4(ip),
                    LocalData::Aaaa(ip) => IpAddr::V6(ip),
                    _ => continue,
                };
                if !is_private(address) {
                    continue;
                }
                let reverse = reverse_name(address);
                let Ok(owner) = DomainName::parse(&reverse) else {
                    continue;
                };
                generated
                    .entry(Box::<str>::from(reverse))
                    .or_insert_with(|| LocalRecord {
                        name: owner,
                        ttl: record.ttl,
                        data: LocalData::Ptr(record.name.clone()),
                    });
            }
        }
        self.generated_ptrs = generated;
    }

    /// The most specific zone containing a name.
    fn zone_of<'a>(&self, name: &'a str) -> Option<&'a str> {
        suffixes(name).find(|suffix| self.zones.contains_key(*suffix))
    }

    /// Whether this node owns the name, so it must not go upstream.
    pub fn answer(&self, name: &DomainName, query: LocalQuery) -> Option<LocalAnswer> {
        if let Some(zone) = self.zone_of(name.as_str()) {
            return self.answer_from_zone(name, zone, query);
        }
        if let Some(ptr) = self.generated_ptrs.get(name.as_str()) {
            let records = match query {
                LocalQuery::Ptr | LocalQuery::Any => vec![ptr.clone()],
                _ => vec![],
            };
            return Some(LocalAnswer {
                records,
                nxdomain: false,
                zone: None,
                names: vec![name.clone()],
                policy_applies: true,
            });
        }
        reserved_answer(name, query)
    }

    fn answer_from_zone(
        &self,
        name: &DomainName,
        zone: &str,
        query: LocalQuery,
    ) -> Option<LocalAnswer> {
        let zone_name = DomainName::parse(zone).ok()?;
        let mut answer = LocalAnswer {
            records: Vec::new(),
            nxdomain: false,
            zone: Some(zone_name),
            names: vec![name.clone()],
            policy_applies: true,
        };

        let mut current = name.clone();
        for _ in 0..MAX_LOCAL_CHAIN {
            let records = self.records.get(current.as_str());
            let cname = records.and_then(|records| {
                records.iter().find_map(|record| match &record.data {
                    LocalData::Cname(target) => Some((record, target)),
                    _ => None,
                })
            });
            if let Some((record, target)) = cname {
                answer.records.push(record.clone());
                if query == LocalQuery::Cname {
                    return Some(answer);
                }
                answer.names.push(target.clone());
                current = target.clone();
                continue;
            }

            let is_apex = self.zones.contains_key(current.as_str());
            if let Some(records) = records {
                answer.records.extend(
                    records
                        .iter()
                        .filter(|record| data_matches(&record.data, query))
                        .cloned(),
                );
            }
            if is_apex {
                for (kind, data) in [
                    (LocalQuery::Soa, LocalData::Soa),
                    (LocalQuery::Ns, LocalData::Ns),
                ] {
                    if query == kind || query == LocalQuery::Any {
                        answer.records.push(LocalRecord {
                            name: current.clone(),
                            ttl: DEFAULT_TTL_SECONDS,
                            data,
                        });
                    }
                }
            }
            if answer.records.is_empty() {
                let exists = records.is_some()
                    || is_apex
                    || self.zone_of(current.as_str()).is_some_and(|owner| {
                        self.zones
                            .get(owner)
                            .is_some_and(|zone| zone.empty_non_terminals.contains(current.as_str()))
                    });
                answer.nxdomain = !exists;
            }
            return Some(answer);
        }
        None
    }
}

fn data_matches(data: &LocalData, query: LocalQuery) -> bool {
    matches!(
        (data, query),
        (_, LocalQuery::Any)
            | (LocalData::A(_), LocalQuery::A)
            | (LocalData::Aaaa(_), LocalQuery::Aaaa)
            | (LocalData::Ptr(_), LocalQuery::Ptr)
    )
}

/// True if a name is `suffix` or under it.
fn is_under(name: &str, suffix: &str) -> bool {
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// RFC 6303: reverse zones for private and special addresses, which must not leak upstream.
fn is_private_reverse(name: &str) -> bool {
    const IPV4: &[&str] = &[
        "10.in-addr.arpa",
        "168.192.in-addr.arpa",
        "254.169.in-addr.arpa",
        "127.in-addr.arpa",
        "0.in-addr.arpa",
        "255.255.255.255.in-addr.arpa",
    ];
    const IPV6: &[&str] = &[
        "c.f.ip6.arpa",
        "d.f.ip6.arpa",
        "8.e.f.ip6.arpa",
        "9.e.f.ip6.arpa",
        "a.e.f.ip6.arpa",
        "b.e.f.ip6.arpa",
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
    ];
    if IPV4.iter().chain(IPV6).any(|zone| is_under(name, zone)) {
        return true;
    }
    (16..32).any(|octet| is_under(name, &format!("{octet}.172.in-addr.arpa")))
}

/// Answers for names RFCs reserve, which must never be forwarded.
fn reserved_answer(name: &DomainName, query: LocalQuery) -> Option<LocalAnswer> {
    let text = name.as_str();
    let plain = |records: Vec<LocalRecord>, nxdomain: bool| {
        Some(LocalAnswer {
            records,
            nxdomain,
            zone: None,
            names: vec![name.clone()],
            policy_applies: false,
        })
    };

    // RFC 6761: localhost always means this machine.
    if is_under(text, "localhost") {
        let data = match query {
            LocalQuery::A => Some(LocalData::A(Ipv4Addr::LOCALHOST)),
            LocalQuery::Aaaa => Some(LocalData::Aaaa(Ipv6Addr::LOCALHOST)),
            _ => None,
        };
        let records = data
            .map(|data| LocalRecord {
                name: name.clone(),
                ttl: DEFAULT_TTL_SECONDS,
                data,
            })
            .into_iter()
            .collect();
        return plain(records, false);
    }

    // invalid (RFC 6761), onion (RFC 7686), local (RFC 6762, resolved by mDNS), home.arpa
    // (RFC 8375, when no local zone claims it) and resolver.arpa (RFC 9462).
    const NO_SUCH_NAME: &[&str] = &["invalid", "onion", "local", "home.arpa", "resolver.arpa"];
    if NO_SUCH_NAME.iter().any(|suffix| is_under(text, suffix)) || is_private_reverse(text) {
        return plain(Vec::new(), true);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> DomainName {
        DomainName::parse(value).unwrap()
    }

    fn zone(value: &str) -> LocalZoneDef {
        LocalZoneDef {
            name: value.to_owned(),
        }
    }

    fn record(id: &str, owner: &str, record_type: LocalRecordType, value: &str) -> LocalRecordDef {
        LocalRecordDef {
            id: id.to_owned(),
            name: owner.to_owned(),
            record_type,
            value: value.to_owned(),
            ttl_seconds: 300,
        }
    }

    fn zones() -> LocalZones {
        LocalZones::compile(
            &[zone("home.arpa"), zone("lab.example")],
            &[
                record("1", "nas.home.arpa", LocalRecordType::A, "192.168.1.10"),
                record("2", "nas.home.arpa", LocalRecordType::Aaaa, "fd00::10"),
                record(
                    "3",
                    "files.home.arpa",
                    LocalRecordType::Cname,
                    "nas.home.arpa",
                ),
                record(
                    "4",
                    "deep.a.b.home.arpa",
                    LocalRecordType::A,
                    "192.168.1.11",
                ),
                record("5", "pub.lab.example", LocalRecordType::A, "8.8.8.8"),
            ],
        )
        .unwrap()
    }

    fn error_of(zones_def: &[LocalZoneDef], records: &[LocalRecordDef]) -> String {
        LocalZones::compile(zones_def, records)
            .expect_err("this should be rejected")
            .to_string()
    }

    #[test]
    fn answers_records_of_the_requested_type() {
        let answer = zones()
            .answer(&name("NAS.home.arpa."), LocalQuery::A)
            .unwrap();
        assert_eq!(answer.records.len(), 1);
        assert_eq!(
            answer.records[0].data,
            LocalData::A("192.168.1.10".parse().unwrap())
        );
        assert!(!answer.nxdomain);
        assert_eq!(answer.zone.unwrap().as_str(), "home.arpa");
        assert!(answer.policy_applies);

        let any = zones()
            .answer(&name("nas.home.arpa"), LocalQuery::Any)
            .unwrap();
        assert_eq!(any.records.len(), 2);
    }

    #[test]
    fn distinguishes_missing_names_from_missing_types() {
        let zones = zones();
        let no_type = zones
            .answer(&name("nas.home.arpa"), LocalQuery::Ptr)
            .unwrap();
        assert!(no_type.records.is_empty());
        assert!(!no_type.nxdomain, "the name exists, so this is NODATA");

        let no_name = zones
            .answer(&name("ghost.home.arpa"), LocalQuery::A)
            .unwrap();
        assert!(no_name.nxdomain);
        assert_eq!(no_name.zone.unwrap().as_str(), "home.arpa");

        // RFC 8020: a parent of an existing name exists, even with no records.
        let empty = zones.answer(&name("a.b.home.arpa"), LocalQuery::A).unwrap();
        assert!(empty.records.is_empty());
        assert!(!empty.nxdomain);
        let below_missing = zones
            .answer(&name("x.deep.a.b.home.arpa"), LocalQuery::A)
            .unwrap();
        assert!(below_missing.nxdomain);
    }

    #[test]
    fn names_outside_managed_zones_are_not_claimed() {
        assert!(
            zones()
                .answer(&name("example.com"), LocalQuery::A)
                .is_none()
        );
        assert!(
            zones()
                .answer(&name("nothome.arpa"), LocalQuery::A)
                .is_none()
        );
    }

    #[test]
    fn follows_cnames_and_reports_every_name_for_policy() {
        let zones = zones();
        let answer = zones
            .answer(&name("files.home.arpa"), LocalQuery::A)
            .unwrap();
        assert_eq!(answer.records.len(), 2);
        assert!(matches!(answer.records[0].data, LocalData::Cname(_)));
        assert!(matches!(answer.records[1].data, LocalData::A(_)));
        let names: Vec<_> = answer.names.iter().map(DomainName::as_str).collect();
        assert_eq!(names, ["files.home.arpa", "nas.home.arpa"]);

        let cname_only = zones
            .answer(&name("files.home.arpa"), LocalQuery::Cname)
            .unwrap();
        assert_eq!(cname_only.records.len(), 1);
    }

    #[test]
    fn the_zone_apex_has_a_soa_and_ns() {
        let zones = zones();
        let soa = zones.answer(&name("home.arpa"), LocalQuery::Soa).unwrap();
        assert_eq!(soa.records[0].data, LocalData::Soa);
        let ns = zones.answer(&name("home.arpa"), LocalQuery::Ns).unwrap();
        assert_eq!(ns.records[0].data, LocalData::Ns);
        let none = zones.answer(&name("home.arpa"), LocalQuery::A).unwrap();
        assert!(none.records.is_empty());
        assert!(!none.nxdomain);
    }

    #[test]
    fn the_most_specific_zone_wins() {
        let zones = LocalZones::compile(
            &[zone("example"), zone("sub.example")],
            &[record("1", "a.sub.example", LocalRecordType::A, "10.0.0.1")],
        )
        .unwrap();
        let answer = zones
            .answer(&name("ghost.sub.example"), LocalQuery::A)
            .unwrap();
        assert_eq!(answer.zone.unwrap().as_str(), "sub.example");
    }

    #[test]
    fn generates_ptrs_for_private_addresses_only() {
        let zones = zones();
        let v4 = zones
            .answer(&name("10.1.168.192.in-addr.arpa"), LocalQuery::Ptr)
            .unwrap();
        assert_eq!(v4.records[0].data, LocalData::Ptr(name("nas.home.arpa")));

        let v6_name = reverse_name("fd00::10".parse().unwrap());
        assert!(v6_name.ends_with(".d.f.ip6.arpa"), "{v6_name}");
        let v6 = zones.answer(&name(&v6_name), LocalQuery::Ptr).unwrap();
        assert_eq!(v6.records[0].data, LocalData::Ptr(name("nas.home.arpa")));

        assert!(
            zones
                .answer(&name("8.8.8.8.in-addr.arpa"), LocalQuery::Ptr)
                .is_none()
        );
    }

    #[test]
    fn validation_rejects_bad_zones_and_records() {
        let home = [zone("home.arpa")];
        let a = LocalRecordType::A;
        let cname = LocalRecordType::Cname;
        for (zones_def, records, expected) in [
            (vec![zone(".")], vec![], "root"),
            (vec![zone("a..b")], vec![], "empty label"),
            (vec![zone("x.y"), zone("X.Y.")], vec![], "listed twice"),
            (
                vec![],
                vec![record("1", "a.home.arpa", a, "10.0.0.1")],
                "isn't in a local zone",
            ),
            (
                home.to_vec(),
                vec![record("1", "a.home.arpa", a, "nope")],
                "IPv4",
            ),
            (
                home.to_vec(),
                vec![record(
                    "1",
                    "a.home.arpa",
                    LocalRecordType::Aaaa,
                    "10.0.0.1",
                )],
                "IPv6",
            ),
            (
                home.to_vec(),
                vec![record("1", "a.home.arpa", cname, "a..b")],
                "domain name",
            ),
            (
                home.to_vec(),
                vec![
                    record("1", "a.home.arpa", a, "10.0.0.1"),
                    record("2", "a.home.arpa", a, "10.0.0.1"),
                ],
                "same record twice",
            ),
            (
                home.to_vec(),
                vec![
                    record("1", "a.home.arpa", a, "10.0.0.1"),
                    record("1", "b.home.arpa", a, "10.0.0.1"),
                ],
                "duplicate",
            ),
            (
                home.to_vec(),
                vec![
                    record("1", "a.home.arpa", cname, "b.home.arpa"),
                    record("2", "a.home.arpa", a, "10.0.0.1"),
                ],
                "any other records",
            ),
            (
                home.to_vec(),
                vec![record("1", "home.arpa", cname, "b.home.arpa")],
                "zone's own name",
            ),
            (
                home.to_vec(),
                vec![record("1", "a.home.arpa", cname, "example.com")],
                "isn't in a local zone",
            ),
            (
                home.to_vec(),
                vec![record("1", "a.home.arpa", cname, "a.home.arpa")],
                "loop",
            ),
            (
                home.to_vec(),
                vec![
                    record("1", "a.home.arpa", cname, "b.home.arpa"),
                    record("2", "b.home.arpa", cname, "a.home.arpa"),
                ],
                "loop",
            ),
        ] {
            let message = error_of(&zones_def, &records);
            assert!(message.contains(expected), "{expected}: {message}");
        }

        let mut long_ttl = record("1", "a.home.arpa", a, "10.0.0.1");
        long_ttl.ttl_seconds = 86_401;
        assert!(error_of(&home, &[long_ttl]).contains("TTL"));

        let long_chain: Vec<_> = (0..20)
            .map(|index| {
                record(
                    &index.to_string(),
                    &format!("c{index}.home.arpa"),
                    cname,
                    &format!("c{}.home.arpa", index + 1),
                )
            })
            .collect();
        assert!(error_of(&home, &long_chain).contains("too many"));
    }

    #[test]
    fn localhost_always_means_this_machine() {
        let zones = LocalZones::default();
        let a = zones.answer(&name("localhost"), LocalQuery::A).unwrap();
        assert_eq!(a.records[0].data, LocalData::A(Ipv4Addr::LOCALHOST));
        assert!(!a.policy_applies);
        let aaaa = zones
            .answer(&name("foo.localhost"), LocalQuery::Aaaa)
            .unwrap();
        assert_eq!(aaaa.records[0].data, LocalData::Aaaa(Ipv6Addr::LOCALHOST));
        let other = zones.answer(&name("localhost"), LocalQuery::Other).unwrap();
        assert!(other.records.is_empty());
        assert!(!other.nxdomain);
        assert!(zones.answer(&name("notlocalhost"), LocalQuery::A).is_none());
    }

    #[test]
    fn reserved_names_and_private_reverse_lookups_stay_local() {
        let zones = LocalZones::default();
        for reserved in [
            "x.invalid",
            "invalid",
            "site.onion",
            "printer.local",
            "router.home.arpa",
            "_dns.resolver.arpa",
            "1.1.168.192.in-addr.arpa",
            "1.0.0.10.in-addr.arpa",
            "1.0.16.172.in-addr.arpa",
            "1.0.31.172.in-addr.arpa",
            "1.0.254.169.in-addr.arpa",
            "1.0.0.127.in-addr.arpa",
            "a.b.d.f.ip6.arpa",
            "a.8.e.f.ip6.arpa",
        ] {
            let answer = zones
                .answer(&name(reserved), LocalQuery::Ptr)
                .unwrap_or_else(|| {
                    panic!("{reserved} must not be forwarded");
                });
            assert!(answer.nxdomain, "{reserved}");
        }
        for public in [
            "example.com",
            "fixture.test",
            "1.0.32.172.in-addr.arpa",
            "1.0.15.172.in-addr.arpa",
            "8.8.8.8.in-addr.arpa",
            "1.0.0.2.ip6.arpa",
            "local.example.com",
        ] {
            assert!(
                zones.answer(&name(public), LocalQuery::Ptr).is_none(),
                "{public}"
            );
        }
    }

    #[test]
    fn a_zone_can_claim_a_reserved_name() {
        let zones = zones();
        let answer = zones.answer(&name("nas.home.arpa"), LocalQuery::A).unwrap();
        assert_eq!(answer.records.len(), 1);
    }
}
