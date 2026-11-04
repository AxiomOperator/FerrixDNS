use std::collections::BTreeSet;

use dns_policy::{DomainName, ListEntry, ListFormat};
use thiserror::Error;

/// The most entries accepted from one list. Compiled lists use memory in proportion to this.
pub const MAX_LIST_ENTRIES: usize = 5_000_000;

/// Hostnames that hosts files define for the local machine, which must never be blocked.
const LOCAL_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// Why a list was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("the list has more than {MAX_LIST_ENTRIES} entries")]
    TooManyEntries,
    #[error("the list has no valid entries in the selected format")]
    NoValidEntries,
}

/// A parsed list, deduplicated and in a stable order.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedList {
    pub artifact: Vec<u8>,
    pub entry_count: usize,
    pub invalid_line_count: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Exact,
    Suffix,
}

fn domain(value: &str) -> Option<DomainName> {
    // Single-label names and wildcards aren't domains this list format can safely block.
    if !value.contains('.') || value.contains('*') || value.contains('/') {
        return None;
    }
    if LOCAL_NAMES.contains(&value.to_ascii_lowercase().as_str()) {
        return None;
    }
    DomainName::parse(value).ok().filter(|name| !name.is_root())
}

/// What one line contributed: nothing (blank or comment), entries, or an invalid line.
enum Line {
    Skip,
    Entries(Vec<(Kind, DomainName)>),
    Invalid,
}

fn parse_hosts_line(line: &str) -> Line {
    let line = line.split('#').next().unwrap_or_default().trim();
    if line.is_empty() {
        return Line::Skip;
    }
    let mut fields = line.split_whitespace();
    let is_address = fields
        .next()
        .is_some_and(|field| field.parse::<std::net::IpAddr>().is_ok());
    if !is_address {
        return Line::Invalid;
    }
    let hosts: Vec<&str> = fields.collect();
    if hosts.is_empty() {
        return Line::Invalid;
    }
    let entries: Vec<_> = hosts
        .iter()
        .filter_map(|host| domain(host).map(|name| (Kind::Exact, name)))
        .collect();
    if entries.is_empty() {
        // Lines like `127.0.0.1 localhost` are expected in hosts files and aren't errors.
        let all_local = hosts
            .iter()
            .all(|host| LOCAL_NAMES.contains(&host.to_ascii_lowercase().as_str()));
        return if all_local { Line::Skip } else { Line::Invalid };
    }
    Line::Entries(entries)
}

fn parse_domains_line(line: &str) -> Line {
    let line = line.split('#').next().unwrap_or_default().trim();
    if line.is_empty() {
        return Line::Skip;
    }
    match domain(line) {
        Some(name) => Line::Entries(vec![(Kind::Exact, name)]),
        None => Line::Invalid,
    }
}

fn parse_adblock_line(line: &str) -> Line {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
        return Line::Skip;
    }
    // Only plain domain rules are supported. Exceptions, paths and options are reported invalid.
    let name = line
        .strip_prefix("||")
        .and_then(|rest| rest.strip_suffix('^'))
        .and_then(domain);
    match name {
        Some(name) => Line::Entries(vec![(Kind::Suffix, name)]),
        None => Line::Invalid,
    }
}

/// Parses downloaded text in an explicitly chosen format.
pub fn parse_list(format: ListFormat, text: &str) -> Result<ParsedList, ParseError> {
    let parse_line = match format {
        ListFormat::Hosts => parse_hosts_line,
        ListFormat::Domains => parse_domains_line,
        ListFormat::Adblock => parse_adblock_line,
    };

    let mut seen = BTreeSet::new();
    let mut invalid_line_count = 0;
    for line in text.lines() {
        match parse_line(line) {
            Line::Skip => {}
            Line::Invalid => invalid_line_count += 1,
            Line::Entries(entries) => {
                for (kind, name) in entries {
                    seen.insert((kind, name.as_str().to_owned()));
                }
                if seen.len() > MAX_LIST_ENTRIES {
                    return Err(ParseError::TooManyEntries);
                }
            }
        }
    }
    if seen.is_empty() {
        return Err(ParseError::NoValidEntries);
    }

    let mut artifact = Vec::with_capacity(seen.len() * 24);
    for (kind, name) in &seen {
        artifact.extend_from_slice(match kind {
            Kind::Exact => b"e ",
            Kind::Suffix => b"s ",
        });
        artifact.extend_from_slice(name.as_bytes());
        artifact.push(b'\n');
    }
    Ok(ParsedList {
        artifact,
        entry_count: seen.len(),
        invalid_line_count,
    })
}

/// Why a stored artifact couldn't be read back.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArtifactError {
    #[error("the list artifact isn't valid UTF-8")]
    NotUtf8,
    #[error("the list artifact has an invalid line: {0:?}")]
    InvalidLine(String),
}

/// Encodes entries in the artifact format. This is mostly useful for tests.
pub fn encode_artifact(entries: &[ListEntry]) -> Vec<u8> {
    let mut artifact = Vec::new();
    for entry in entries {
        let (prefix, name): (&[u8], _) = match entry {
            ListEntry::Exact(name) => (b"e ", name),
            ListEntry::Suffix(name) => (b"s ", name),
        };
        artifact.extend_from_slice(prefix);
        artifact.extend_from_slice(name.as_str().as_bytes());
        artifact.push(b'\n');
    }
    artifact
}

/// Reads a normalized artifact into list entries.
pub fn decode_artifact(artifact: &[u8]) -> Result<Vec<ListEntry>, ArtifactError> {
    let text = std::str::from_utf8(artifact).map_err(|_| ArtifactError::NotUtf8)?;
    text.lines()
        .map(|line| {
            let invalid = || ArtifactError::InvalidLine(line.to_owned());
            let (kind, value) = line.split_once(' ').ok_or_else(invalid)?;
            let name = DomainName::parse(value).map_err(|_| invalid())?;
            match kind {
                "e" => Ok(ListEntry::Exact(name)),
                "s" => Ok(ListEntry::Suffix(name)),
                _ => Err(invalid()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(parsed: &ParsedList) -> Vec<&str> {
        std::str::from_utf8(&parsed.artifact)
            .unwrap()
            .lines()
            .collect()
    }

    #[test]
    fn parses_hosts_files() {
        let parsed = parse_list(
            ListFormat::Hosts,
            "# A comment\n\
             127.0.0.1 localhost\n\
             ::1 ip6-localhost ip6-loopback\n\
             0.0.0.0 ADS.example.com # trailing comment\n\
             0.0.0.0 a.example b.example\n\
             0.0.0.0 ads.example.com\n\
             not-an-address ads.example\n\
             0.0.0.0\n\
             0.0.0.0 singlelabel\n\n",
        )
        .unwrap();
        assert_eq!(
            lines(&parsed),
            ["e a.example", "e ads.example.com", "e b.example"]
        );
        assert_eq!(parsed.entry_count, 3);
        assert_eq!(parsed.invalid_line_count, 3);
    }

    #[test]
    fn parses_domain_lists() {
        let parsed = parse_list(
            ListFormat::Domains,
            "# comment\nads.example\nTRACKER.example.\n\nbad name.example\n*.wild.example\nbücher.example\n",
        )
        .unwrap();
        assert_eq!(
            lines(&parsed),
            [
                "e ads.example",
                "e tracker.example",
                "e xn--bcher-kva.example"
            ]
        );
        assert_eq!(parsed.invalid_line_count, 2);
    }

    #[test]
    fn parses_domain_only_adblock_rules_as_suffixes() {
        let parsed = parse_list(
            ListFormat::Adblock,
            "[Adblock Plus 2.0]\n! comment\n||ads.example^\n||tracker.example^$third-party\n@@||good.example^\n/banner/*\n",
        )
        .unwrap();
        assert_eq!(lines(&parsed), ["s ads.example"]);
        assert_eq!(parsed.invalid_line_count, 3);
    }

    #[test]
    fn rejects_lists_with_nothing_usable() {
        assert_eq!(
            parse_list(ListFormat::Hosts, "<html>Not a list</html>\n"),
            Err(ParseError::NoValidEntries)
        );
        assert_eq!(
            parse_list(ListFormat::Domains, "# only comments\n"),
            Err(ParseError::NoValidEntries)
        );
    }

    #[test]
    fn artifacts_are_stable_regardless_of_input_order() {
        let first = parse_list(ListFormat::Domains, "a.example\nb.example\n").unwrap();
        let second = parse_list(ListFormat::Domains, "b.example\na.example\na.example\n").unwrap();
        assert_eq!(first.artifact, second.artifact);
    }

    #[test]
    fn artifacts_round_trip() {
        let parsed = parse_list(ListFormat::Adblock, "||ads.example^\n").unwrap();
        let entries = decode_artifact(&parsed.artifact).unwrap();
        assert!(matches!(&entries[0], ListEntry::Suffix(name) if name.as_str() == "ads.example"));
        assert_eq!(encode_artifact(&entries), parsed.artifact);
    }

    #[test]
    fn corrupt_artifacts_are_rejected() {
        assert!(decode_artifact(b"x ads.example\n").is_err());
        assert!(decode_artifact(b"nospace\n").is_err());
        assert!(decode_artifact(&[0xff, 0xfe]).is_err());
    }
}
