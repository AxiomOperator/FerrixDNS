use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::compile::{
    CompileError, ListEntry, ListLayer, ListSource, MatchType, PolicySnapshot, Rule, RuleAction,
    RuleOverlay, Scope,
};
use crate::evaluate::{Action, ChainOutcome, ClientContext, Decision, NameContext};
use crate::local::{LocalAnswer, LocalQuery, LocalRecordDef, LocalZoneDef, LocalZones};
use crate::name::{DomainName, NameError};

/// The policy document version this build understands.
pub const SCHEMA_VERSION: u32 = 1;
/// Longest accepted TTL for blocked answers. Long TTLs delay exceptions on client caches.
pub const MAX_BLOCK_TTL_SECONDS: u32 = 86_400;
const DEFAULT_BLOCK_TTL_SECONDS: u32 = 60;
const DEFAULT_QUERY_HISTORY_DAYS: u32 = 7;
const DEFAULT_QUERY_HISTORY_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_LIST_REFRESH_SECONDS: u64 = 86_400;

/// Why a policy document was rejected.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid policy document: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("unsupported schema_version {found}; this build supports {SCHEMA_VERSION}")]
    UnsupportedSchema { found: u32 },
    #[error("block.ttl_seconds must be at most {MAX_BLOCK_TTL_SECONDS}")]
    BlockTtlTooLong,
    #[error("duplicate {kind} id {id:?}")]
    DuplicateId { kind: &'static str, id: String },
    #[error(
        "rule {rule_id}: invalid expires_at {value:?}; use RFC 3339 UTC, such as 2026-12-01T00:00:00Z"
    )]
    InvalidExpiry { rule_id: String, value: String },
    #[error("client {client_id}: invalid address {value:?}")]
    InvalidAddress { client_id: String, value: String },
    #[error("address {value} is assigned to both client {first} and client {second}")]
    DuplicateAddress {
        value: String,
        first: String,
        second: String,
    },
    #[error("list {list_id}: invalid entry {value:?}: {source}")]
    InvalidListEntry {
        list_id: String,
        value: String,
        source: NameError,
    },
    #[error("list {list_id}: cannot load its downloaded content: {reason}")]
    ArtifactUnavailable { list_id: String, reason: String },
    #[error("{0}")]
    LocalDns(String),
    #[error("cannot serialize the policy document: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error(transparent)]
    Compile(#[from] CompileError),
}

/// Loads a downloaded list's normalized content by hash.
pub type ArtifactLoader<'a> = &'a dyn Fn(&str) -> Result<Vec<u8>, String>;

fn no_artifacts(_: &str) -> Result<Vec<u8>, String> {
    Err("no list artifact store is available".to_owned())
}

/// How blocked queries are answered.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockResponse {
    /// NXDOMAIN for every query type.
    #[default]
    Nxdomain,
    /// `0.0.0.0` for A and `::` for AAAA. Other query types get an empty NOERROR answer.
    ZeroAddress,
}

fn default_block_ttl() -> u32 {
    DEFAULT_BLOCK_TTL_SECONDS
}

/// How blocked queries are answered, and how long clients may cache that answer.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BlockConfig {
    #[serde(default)]
    pub response: BlockResponse,
    #[serde(default = "default_block_ttl")]
    pub ttl_seconds: u32,
}

impl Default for BlockConfig {
    fn default() -> Self {
        Self {
            response: BlockResponse::default(),
            ttl_seconds: DEFAULT_BLOCK_TTL_SECONDS,
        }
    }
}

/// What the node records about each query.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryLogMode {
    /// Per-query history including the client. Kept only on this node.
    #[default]
    Full,
    /// Per-query history without client addresses or identities.
    Anonymized,
    /// Counters only.
    AggregateOnly,
    /// Nothing is recorded.
    Disabled,
}

fn default_history_days() -> u32 {
    DEFAULT_QUERY_HISTORY_DAYS
}

fn default_history_bytes() -> u64 {
    DEFAULT_QUERY_HISTORY_MAX_BYTES
}

/// How much query data the node keeps. Whichever limit is reached first applies.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub mode: QueryLogMode,
    #[serde(default = "default_history_days")]
    pub query_history_days: u32,
    #[serde(default = "default_history_bytes")]
    pub query_history_max_bytes: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            mode: QueryLogMode::default(),
            query_history_days: DEFAULT_QUERY_HISTORY_DAYS,
            query_history_max_bytes: DEFAULT_QUERY_HISTORY_MAX_BYTES,
        }
    }
}

/// A named group that clients, rules and lists can refer to.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupDef {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A known client and the addresses that identify it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClientDef {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// IP addresses or CIDR networks. The most specific match wins.
    pub addresses: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

fn enabled_by_default() -> bool {
    true
}

fn global_scope() -> Scope {
    Scope::Global
}

/// A rule as written in a policy document.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    pub id: String,
    pub action: RuleAction,
    #[serde(rename = "match")]
    pub match_type: MatchType,
    pub pattern: String,
    #[serde(default = "global_scope")]
    pub scope: Scope,
    #[serde(default)]
    pub emergency: bool,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// When the rule stops applying, in RFC 3339 UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Increments on each change, for optimistic concurrency.
    #[serde(default = "first_revision")]
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

fn first_revision() -> u64 {
    1
}

fn default_refresh_seconds() -> u64 {
    DEFAULT_LIST_REFRESH_SECONDS
}

/// The format of a downloaded list.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListFormat {
    /// `0.0.0.0 ads.example` lines.
    Hosts,
    /// One domain per line.
    Domains,
    /// Domain-only Adblock syntax: `||ads.example^`.
    Adblock,
}

/// A list of domains, written directly in the document or downloaded from a URL.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListDef {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub action: RuleAction,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Where to download the list. Lists without a URL use `domains` and `suffixes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<ListFormat>,
    #[serde(default = "default_refresh_seconds")]
    pub refresh_seconds: u64,
    /// The downloaded content this revision enforces. Pinning it makes rollbacks exact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
    /// Groups the list applies to. With no groups, it applies at global scope.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Names matched exactly.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Names matched along with their subdomains.
    #[serde(default)]
    pub suffixes: Vec<String>,
}

/// The full local policy: the source that revisions are stored and compiled from.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub schema_version: u32,
    /// This node's site, used to select site-scoped rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default)]
    pub block: BlockConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupDef>,
    #[serde(default)]
    pub clients: Vec<ClientDef>,
    #[serde(default)]
    pub rules: Vec<RuleDef>,
    #[serde(default)]
    pub lists: Vec<ListDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_zones: Vec<LocalZoneDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_records: Vec<LocalRecordDef>,
}

impl Default for PolicyDocument {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            site: None,
            block: BlockConfig::default(),
            telemetry: TelemetryConfig::default(),
            groups: Vec::new(),
            clients: Vec::new(),
            rules: Vec::new(),
            lists: Vec::new(),
            local_zones: Vec::new(),
            local_records: Vec::new(),
        }
    }
}

impl PolicyDocument {
    /// The document as TOML, in the form stored for each revision.
    pub fn to_toml(&self) -> Result<String, PolicyError> {
        Ok(toml::to_string_pretty(self)?)
    }

    /// Parses a TOML document and checks its schema version.
    pub fn parse(source: &str) -> Result<Self, PolicyError> {
        let document: Self = toml::from_str(source)?;
        if document.schema_version != SCHEMA_VERSION {
            return Err(PolicyError::UnsupportedSchema {
                found: document.schema_version,
            });
        }
        Ok(document)
    }

    fn compile_rules(&self) -> Result<Vec<Rule>, PolicyError> {
        let mut seen = HashSet::new();
        self.rules
            .iter()
            .map(|rule| {
                if !seen.insert(rule.id.as_str()) {
                    return Err(PolicyError::DuplicateId {
                        kind: "rule",
                        id: rule.id.clone(),
                    });
                }
                let expires_at = rule
                    .expires_at
                    .as_deref()
                    .map(|value| {
                        humantime::parse_rfc3339(value).map_err(|_| PolicyError::InvalidExpiry {
                            rule_id: rule.id.clone(),
                            value: value.to_owned(),
                        })
                    })
                    .transpose()?;
                Ok(Rule {
                    id: rule.id.clone(),
                    action: rule.action,
                    match_type: rule.match_type,
                    pattern: rule.pattern.clone(),
                    scope: rule.scope.clone(),
                    is_emergency: rule.emergency,
                    enabled: rule.enabled,
                    expires_at,
                })
            })
            .collect()
    }

    fn compile_lists(&self, artifacts: ArtifactLoader<'_>) -> Result<ListLayer, PolicyError> {
        let mut seen = HashSet::new();
        let lists = self
            .lists
            .iter()
            .filter(|list| list.enabled)
            .map(|list| {
                if !seen.insert(list.id.as_str()) {
                    return Err(PolicyError::DuplicateId {
                        kind: "list",
                        id: list.id.clone(),
                    });
                }
                let parse = |value: &String| {
                    DomainName::parse(value).map_err(|source| PolicyError::InvalidListEntry {
                        list_id: list.id.clone(),
                        value: value.clone(),
                        source,
                    })
                };
                let mut entries = Vec::with_capacity(list.domains.len() + list.suffixes.len());
                for value in &list.domains {
                    entries.push(ListEntry::Exact(parse(value)?));
                }
                for value in &list.suffixes {
                    entries.push(ListEntry::Suffix(parse(value)?));
                }
                let artifact = list
                    .artifact_sha256
                    .as_deref()
                    .map(|sha256| {
                        artifacts(sha256).map_err(|reason| PolicyError::ArtifactUnavailable {
                            list_id: list.id.clone(),
                            reason,
                        })
                    })
                    .transpose()?;
                Ok(ListSource {
                    id: list.id.clone(),
                    action: list.action,
                    groups: list.groups.clone(),
                    entries,
                    artifact,
                })
            })
            .collect::<Result<Vec<_>, PolicyError>>()?;
        Ok(ListLayer::compile(&lists)?)
    }

    /// Problems that don't stop the policy working, but probably aren't what the operator meant.
    pub fn warnings(&self) -> Vec<String> {
        let groups: HashSet<&str> = self
            .clients
            .iter()
            .flat_map(|client| client.groups.iter().map(String::as_str))
            .collect();
        // A group that exists but is empty is fine, so warnings only use client memberships.
        let clients: HashSet<&str> = self.clients.iter().map(|c| c.id.as_str()).collect();

        let mut warnings = Vec::new();
        for rule in &self.rules {
            let problem = match &rule.scope {
                Scope::Client(id) if !clients.contains(id.as_str()) => {
                    Some(format!("client {id:?}, which isn't defined"))
                }
                Scope::Group(id) if !groups.contains(id.as_str()) => {
                    Some(format!("group {id:?}, which has no clients"))
                }
                Scope::Site(id) if self.site.as_deref() != Some(id.as_str()) => {
                    Some(format!("site {id:?}, which isn't this node's site"))
                }
                _ => None,
            };
            if let Some(problem) = problem {
                warnings.push(format!(
                    "rule {} never applies: it targets {problem}",
                    rule.id
                ));
            }
        }
        for list in &self.lists {
            for group in &list.groups {
                if !groups.contains(group.as_str()) {
                    warnings.push(format!(
                        "list {} doesn't apply to group {group:?}, which has no clients",
                        list.id
                    ));
                }
            }
        }
        warnings
    }
}

/// A known client's identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub id: Box<str>,
    pub groups: Vec<Box<str>>,
}

/// Maps source addresses to known clients.
#[derive(Debug, Default)]
pub struct Identities {
    clients: Vec<Identity>,
    exact: HashMap<IpAddr, usize>,
    /// Sorted from most to least specific.
    networks: Vec<(IpNet, usize)>,
}

impl Identities {
    fn compile(definitions: &[ClientDef]) -> Result<Self, PolicyError> {
        let mut identities = Self::default();
        let mut owners: HashMap<IpNet, &str> = HashMap::new();
        let mut ids = HashSet::new();

        for (position, client) in definitions.iter().enumerate() {
            if !ids.insert(client.id.as_str()) {
                return Err(PolicyError::DuplicateId {
                    kind: "client",
                    id: client.id.clone(),
                });
            }
            identities.clients.push(Identity {
                id: client.id.as_str().into(),
                groups: client.groups.iter().map(|g| g.as_str().into()).collect(),
            });

            for value in &client.addresses {
                let network = parse_network(value).ok_or_else(|| PolicyError::InvalidAddress {
                    client_id: client.id.clone(),
                    value: value.clone(),
                })?;
                if let Some(first) = owners.insert(network, &client.id)
                    && first != client.id
                {
                    return Err(PolicyError::DuplicateAddress {
                        value: network.to_string(),
                        first: first.to_owned(),
                        second: client.id.clone(),
                    });
                }
                if network.prefix_len() == network.max_prefix_len() {
                    identities.exact.insert(network.addr(), position);
                } else {
                    identities.networks.push((network, position));
                }
            }
        }
        identities
            .networks
            .sort_by_key(|(network, _)| std::cmp::Reverse(network.prefix_len()));
        Ok(identities)
    }

    /// The client for a source address, preferring the most specific match.
    pub fn lookup(&self, address: IpAddr) -> Option<&Identity> {
        let address = address.to_canonical();
        let position = self.exact.get(&address).copied().or_else(|| {
            self.networks
                .iter()
                .find(|(network, _)| network.contains(&address))
                .map(|(_, position)| *position)
        })?;
        self.clients.get(position)
    }
}

fn parse_network(value: &str) -> Option<IpNet> {
    if let Ok(network) = value.parse::<IpNet>() {
        return Some(network.trunc());
    }
    value
        .parse::<IpAddr>()
        .ok()
        .map(|ip| IpNet::from(ip.to_canonical()))
}

/// The result of checking a name or an answer against policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict<'s> {
    Allow,
    Block(Decision<'s>),
    /// A CNAME target at this position in the answer is blocked.
    BlockTarget {
        decision: Decision<'s>,
        target_index: usize,
    },
    /// The answer has too many CNAME targets to check.
    ChainTooDeep,
}

/// Everything the DNS path needs from one policy revision.
#[derive(Debug)]
pub struct CompiledPolicy {
    snapshot: PolicySnapshot,
    identities: Identities,
    site: Option<Box<str>>,
    block: BlockConfig,
    telemetry: TelemetryConfig,
    local: LocalZones,
}

impl CompiledPolicy {
    /// A policy with no rules, which allows everything.
    pub fn empty() -> Self {
        Self {
            snapshot: PolicySnapshot::new(
                "empty",
                Arc::new(ListLayer::default()),
                Arc::new(RuleOverlay::default()),
            ),
            identities: Identities::default(),
            site: None,
            block: BlockConfig::default(),
            telemetry: TelemetryConfig::default(),
            local: LocalZones::default(),
        }
    }

    /// Compiles a document. When `previous` holds identical lists, its list layer is reused so
    /// rule changes don't recompile lists.
    pub fn compile(
        revision: &str,
        document: &PolicyDocument,
        now: SystemTime,
        previous: Option<(&PolicyDocument, &Self)>,
    ) -> Result<Self, PolicyError> {
        Self::compile_with(revision, document, now, previous, &no_artifacts)
    }

    /// Like [`Self::compile`], loading downloaded lists through `artifacts`.
    pub fn compile_with(
        revision: &str,
        document: &PolicyDocument,
        now: SystemTime,
        previous: Option<(&PolicyDocument, &Self)>,
        artifacts: ArtifactLoader<'_>,
    ) -> Result<Self, PolicyError> {
        if document.block.ttl_seconds > MAX_BLOCK_TTL_SECONDS {
            return Err(PolicyError::BlockTtlTooLong);
        }
        let reusable = previous
            .filter(|(old, _)| old.lists == document.lists)
            .map(|(_, policy)| Arc::clone(policy.snapshot.lists()));
        let lists = match reusable {
            Some(lists) => lists,
            None => Arc::new(document.compile_lists(artifacts)?),
        };
        let rules = RuleOverlay::compile(&document.compile_rules()?, now)?;

        Ok(Self {
            snapshot: PolicySnapshot::new(revision, lists, Arc::new(rules)),
            identities: Identities::compile(&document.clients)?,
            site: document.site.as_deref().map(Into::into),
            block: document.block,
            telemetry: document.telemetry,
            local: LocalZones::compile(&document.local_zones, &document.local_records)?,
        })
    }

    /// The compiled rules and lists.
    pub fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }

    /// The revision this policy was built from.
    pub fn revision(&self) -> &str {
        self.snapshot.revision()
    }

    /// How blocked queries are answered.
    pub fn block(&self) -> BlockConfig {
        self.block
    }

    /// The answer for a name this node owns, which must not go upstream.
    pub fn local_answer(&self, name: &DomainName, query: LocalQuery) -> Option<LocalAnswer> {
        self.local.answer(name, query)
    }

    /// Checks a local answer's names against rules. Subscribed lists don't apply to local names.
    pub fn check_local(&self, source: IpAddr, answer: &LocalAnswer) -> Verdict<'_> {
        if !answer.policy_applies {
            return Verdict::Allow;
        }
        let identity = self.identities.lookup(source);
        let groups: Vec<&str> = identity
            .map(|identity| identity.groups.iter().map(AsRef::as_ref).collect())
            .unwrap_or_default();
        let context = self.context(identity, &groups);
        for (index, name) in answer.names.iter().enumerate() {
            let decision = self
                .snapshot
                .evaluate(name, &context, NameContext::LocalZone);
            if decision.action == Action::Deny {
                return if index == 0 {
                    Verdict::Block(decision)
                } else {
                    Verdict::BlockTarget {
                        decision,
                        target_index: index - 1,
                    }
                };
            }
        }
        Verdict::Allow
    }

    /// What the node records about queries.
    pub fn telemetry(&self) -> TelemetryConfig {
        self.telemetry
    }

    /// The known client for a source address.
    pub fn identity(&self, source: IpAddr) -> Option<&Identity> {
        self.identities.lookup(source)
    }

    /// The full decision for a name and client, including an allow by default.
    pub fn explain(&self, source: IpAddr, name: &DomainName) -> Decision<'_> {
        let identity = self.identities.lookup(source);
        let groups: Vec<&str> = identity
            .map(|identity| identity.groups.iter().map(AsRef::as_ref).collect())
            .unwrap_or_default();
        let context = self.context(identity, &groups);
        self.snapshot
            .evaluate(name, &context, NameContext::Forwarded)
    }

    /// The earliest moment a rule expires, when this policy must be rebuilt.
    pub fn next_expiry(&self) -> Option<SystemTime> {
        self.snapshot.rules().next_expiry()
    }

    /// Checks a query name for a client.
    pub fn check_query(&self, source: IpAddr, name: &DomainName) -> Verdict<'_> {
        let identity = self.identities.lookup(source);
        let groups: Vec<&str> = identity
            .map(|identity| identity.groups.iter().map(AsRef::as_ref).collect())
            .unwrap_or_default();
        let context = self.context(identity, &groups);
        let decision = self
            .snapshot
            .evaluate(name, &context, NameContext::Forwarded);
        match decision.action {
            Action::Allow => Verdict::Allow,
            Action::Deny => Verdict::Block(decision),
        }
    }

    /// Checks an upstream answer: the query name again, then each CNAME target.
    ///
    /// Rechecking the query name applies any policy published while upstream was answering.
    pub fn check_answer(
        &self,
        source: IpAddr,
        name: &DomainName,
        targets: &[DomainName],
    ) -> Verdict<'_> {
        let identity = self.identities.lookup(source);
        let groups: Vec<&str> = identity
            .map(|identity| identity.groups.iter().map(AsRef::as_ref).collect())
            .unwrap_or_default();
        let context = self.context(identity, &groups);
        let decision = self
            .snapshot
            .evaluate(name, &context, NameContext::Forwarded);
        if decision.action == Action::Deny {
            return Verdict::Block(decision);
        }
        match self
            .snapshot
            .evaluate_cname_targets(&decision, targets, &context)
        {
            ChainOutcome::Allowed => Verdict::Allow,
            ChainOutcome::Blocked {
                decision,
                target_index,
            } => Verdict::BlockTarget {
                decision,
                target_index,
            },
            ChainOutcome::TooDeep => Verdict::ChainTooDeep,
        }
    }

    fn context<'a>(
        &'a self,
        identity: Option<&'a Identity>,
        groups: &'a [&'a str],
    ) -> ClientContext<'a> {
        ClientContext {
            client: identity.map(|identity| identity.id.as_ref()),
            groups,
            site: self.site.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const EXAMPLE: &str = r#"
schema_version = 1
site = "hq"

[block]
response = "zero_address"
ttl_seconds = 30

[[clients]]
id = "laptop"
addresses = ["192.168.1.20", "2001:db8::20"]
groups = ["kids"]

[[clients]]
id = "lan"
addresses = ["192.168.1.0/24"]

[[rules]]
id = "r1"
action = "deny"
match = "suffix"
pattern = "ads.example"

[[rules]]
id = "r2"
action = "allow"
match = "exact"
pattern = "good.ads.example"
scope = { kind = "client", id = "laptop" }
reason = "Needed for homework"

[[rules]]
id = "r3"
action = "deny"
match = "exact"
pattern = "site.example"
scope = { kind = "site", id = "hq" }

[[lists]]
id = "l1"
action = "deny"
groups = ["kids"]
domains = ["games.example"]
suffixes = ["social.example"]
"#;

    fn compile(source: &str) -> CompiledPolicy {
        let document = PolicyDocument::parse(source).unwrap();
        CompiledPolicy::compile("rev", &document, SystemTime::now(), None).unwrap()
    }

    fn name(value: &str) -> DomainName {
        DomainName::parse(value).unwrap()
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn blocked(policy: &CompiledPolicy, source: &str, domain: &str) -> bool {
        matches!(
            policy.check_query(ip(source), &name(domain)),
            Verdict::Block(_)
        )
    }

    #[test]
    fn documents_survive_a_toml_round_trip() {
        let mut document = PolicyDocument::parse(EXAMPLE).unwrap();
        document.groups.push(GroupDef {
            id: "kids".into(),
            description: Some("Children".into()),
        });
        document.telemetry.mode = QueryLogMode::Anonymized;
        document.lists.push(ListDef {
            id: "remote".into(),
            name: Some("Remote".into()),
            action: RuleAction::Deny,
            enabled: true,
            url: Some("https://lists.example/hosts".into()),
            format: Some(ListFormat::Hosts),
            refresh_seconds: 3600,
            artifact_sha256: Some("abc".into()),
            groups: vec![],
            domains: vec![],
            suffixes: vec![],
        });
        let toml = document.to_toml().unwrap();
        assert_eq!(PolicyDocument::parse(&toml).unwrap(), document, "{toml}");
    }

    #[test]
    fn downloaded_lists_load_through_the_artifact_loader() {
        let mut document = PolicyDocument::default();
        document.lists.push(ListDef {
            id: "remote".into(),
            name: None,
            action: RuleAction::Deny,
            enabled: true,
            url: Some("https://lists.example/hosts".into()),
            format: Some(ListFormat::Hosts),
            refresh_seconds: 3600,
            artifact_sha256: Some("hash".into()),
            groups: vec![],
            domains: vec![],
            suffixes: vec![],
        });
        let missing = CompiledPolicy::compile("rev", &document, SystemTime::now(), None);
        assert!(matches!(
            missing,
            Err(PolicyError::ArtifactUnavailable { .. })
        ));

        let loader = |sha256: &str| {
            assert_eq!(sha256, "hash");
            Ok(b"e ads.example\n".to_vec())
        };
        let policy =
            CompiledPolicy::compile_with("rev", &document, SystemTime::now(), None, &loader)
                .unwrap();
        assert!(blocked(&policy, "10.0.0.1", "ads.example"));

        document.lists[0].enabled = false;
        let disabled = CompiledPolicy::compile("rev", &document, SystemTime::now(), None).unwrap();
        assert!(!blocked(&disabled, "10.0.0.1", "ads.example"));
    }

    #[test]
    fn parses_a_full_document() {
        let policy = compile(EXAMPLE);
        assert_eq!(policy.block().response, BlockResponse::ZeroAddress);
        assert_eq!(policy.block().ttl_seconds, 30);
        assert!(
            PolicyDocument::parse(EXAMPLE)
                .unwrap()
                .warnings()
                .is_empty()
        );
    }

    #[test]
    fn minimal_document_uses_defaults() {
        let policy = compile("schema_version = 1");
        assert_eq!(policy.block(), BlockConfig::default());
        assert_eq!(policy.block().response, BlockResponse::Nxdomain);
        assert!(!blocked(&policy, "10.0.0.1", "example.com"));
    }

    #[test]
    fn identity_selects_client_group_and_site_rules() {
        let policy = compile(EXAMPLE);
        // A global deny, but the laptop has a client-scoped allow.
        assert!(!blocked(&policy, "192.168.1.20", "good.ads.example"));
        assert!(blocked(&policy, "192.168.1.21", "good.ads.example"));
        // Group-scoped lists reach only the group's clients.
        assert!(blocked(&policy, "192.168.1.20", "games.example"));
        assert!(blocked(&policy, "192.168.1.20", "x.social.example"));
        assert!(!blocked(&policy, "192.168.1.21", "games.example"));
        // Site rules apply to everyone on this node, including unknown clients.
        assert!(blocked(&policy, "10.9.9.9", "site.example"));
    }

    #[test]
    fn most_specific_address_wins_and_mapped_ipv4_is_canonicalized() {
        let policy = compile(EXAMPLE);
        let identity = |value| {
            policy
                .identities
                .lookup(ip(value))
                .map(|i| i.id.to_string())
        };
        assert_eq!(identity("192.168.1.20").as_deref(), Some("laptop"));
        assert_eq!(identity("192.168.1.99").as_deref(), Some("lan"));
        assert_eq!(identity("::ffff:192.168.1.20").as_deref(), Some("laptop"));
        assert_eq!(identity("2001:db8::20").as_deref(), Some("laptop"));
        assert_eq!(identity("10.0.0.1"), None);
    }

    #[test]
    fn network_host_bits_are_ignored() {
        let policy = compile(
            r#"
schema_version = 1
[[clients]]
id = "lan"
addresses = ["10.1.2.3/24"]
"#,
        );
        assert!(policy.identities.lookup(ip("10.1.2.200")).is_some());
    }

    fn assert_rejected(source: &str, expected: &str) {
        let document = PolicyDocument::parse(source);
        let error = match document {
            Err(error) => error.to_string(),
            Ok(document) => CompiledPolicy::compile("rev", &document, SystemTime::now(), None)
                .expect_err("the document should be rejected")
                .to_string(),
        };
        assert!(error.contains(expected), "{error}");
    }

    #[test]
    fn rejects_invalid_documents() {
        assert_rejected("schema_version = 2", "unsupported schema_version 2");
        assert_rejected("site = \"hq\"", "schema_version");
        assert_rejected("schema_version = 1\nunknown = true", "unknown");
        assert_rejected(
            "schema_version = 1\n[block]\nttl_seconds = 86401",
            "ttl_seconds",
        );
        assert_rejected(
            "schema_version = 1\n[block]\nresponse = \"drop\"",
            "unknown variant",
        );

        let rule = |extra: &str| {
            format!(
                "schema_version = 1\n[[rules]]\nid = \"r1\"\naction = \"deny\"\nmatch = \"exact\"\npattern = \"a.example\"\n{extra}"
            )
        };
        assert_rejected(&rule("expires_at = \"tomorrow\""), "invalid expires_at");
        assert_rejected(&rule("scope = { kind = \"planet\" }"), "unknown variant");
        assert_rejected(
            &format!(
                "{}\n{}",
                rule(""),
                &rule("")["schema_version = 1\n".len()..]
            ),
            "duplicate rule id",
        );

        assert_rejected(
            "schema_version = 1\n[[clients]]\nid = \"a\"\naddresses = [\"nope\"]",
            "invalid address",
        );
        assert_rejected(
            "schema_version = 1\n[[clients]]\nid = \"a\"\naddresses = [\"10.0.0.1\"]\n[[clients]]\nid = \"b\"\naddresses = [\"10.0.0.1/32\"]",
            "assigned to both",
        );
        assert_rejected(
            "schema_version = 1\n[[lists]]\nid = \"l\"\naction = \"deny\"\ndomains = [\"a..b\"]",
            "invalid entry",
        );
    }

    #[test]
    fn warns_about_scopes_that_can_never_apply() {
        let document = PolicyDocument::parse(
            r#"
schema_version = 1
site = "hq"
[[rules]]
id = "r1"
action = "deny"
match = "exact"
pattern = "a.example"
scope = { kind = "group", id = "typo" }
[[rules]]
id = "r2"
action = "deny"
match = "exact"
pattern = "a.example"
scope = { kind = "client", id = "ghost" }
[[rules]]
id = "r3"
action = "deny"
match = "exact"
pattern = "a.example"
scope = { kind = "site", id = "branch" }
[[lists]]
id = "l1"
action = "deny"
groups = ["typo"]
"#,
        )
        .unwrap();
        assert_eq!(document.warnings().len(), 4);
    }

    #[test]
    fn checks_answers_against_query_and_targets() {
        let policy = compile(EXAMPLE);
        let source = ip("10.0.0.1");
        assert_eq!(
            policy.check_answer(source, &name("a.example"), &[name("b.example")]),
            Verdict::Allow
        );
        assert!(matches!(
            policy.check_answer(source, &name("a.example"), &[name("x.ads.example")]),
            Verdict::BlockTarget {
                target_index: 0,
                ..
            }
        ));
        assert!(matches!(
            policy.check_answer(source, &name("x.ads.example"), &[]),
            Verdict::Block(_)
        ));
        let deep = vec![name("b.example"); crate::MAX_CNAME_CHAIN + 1];
        assert_eq!(
            policy.check_answer(source, &name("a.example"), &deep),
            Verdict::ChainTooDeep
        );
    }

    #[test]
    fn reuses_the_list_layer_only_when_lists_are_unchanged() {
        let first = PolicyDocument::parse(EXAMPLE).unwrap();
        let now = SystemTime::now();
        let old = CompiledPolicy::compile("rev-1", &first, now, None).unwrap();

        let mut rules_changed = first.clone();
        rules_changed.rules.pop();
        let reused =
            CompiledPolicy::compile("rev-2", &rules_changed, now, Some((&first, &old))).unwrap();
        assert!(Arc::ptr_eq(old.snapshot.lists(), reused.snapshot.lists()));
        assert!(!Arc::ptr_eq(old.snapshot.rules(), reused.snapshot.rules()));

        let mut lists_changed = first.clone();
        lists_changed.lists.clear();
        let rebuilt =
            CompiledPolicy::compile("rev-3", &lists_changed, now, Some((&first, &old))).unwrap();
        assert!(!Arc::ptr_eq(old.snapshot.lists(), rebuilt.snapshot.lists()));
        assert!(!blocked(&rebuilt, "192.168.1.20", "games.example"));
    }

    #[test]
    fn expired_rules_are_excluded_when_compiled_later() {
        let document = PolicyDocument::parse(
            r#"
schema_version = 1
[[rules]]
id = "r1"
action = "deny"
match = "exact"
pattern = "a.example"
expires_at = "2026-12-01T00:00:00Z"
"#,
        )
        .unwrap();
        let expiry = humantime::parse_rfc3339("2026-12-01T00:00:00Z").unwrap();

        let before =
            CompiledPolicy::compile("rev", &document, expiry - Duration::from_secs(1), None)
                .unwrap();
        assert_eq!(before.next_expiry(), Some(expiry));
        assert!(blocked(&before, "10.0.0.1", "a.example"));

        let after = CompiledPolicy::compile("rev", &document, expiry, None).unwrap();
        assert_eq!(after.next_expiry(), None);
        assert!(!blocked(&after, "10.0.0.1", "a.example"));
    }
}
