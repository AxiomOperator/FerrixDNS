use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use regex::{RegexSet, RegexSetBuilder};
use serde::Deserialize;
use thiserror::Error;

use crate::name::{DomainName, NameError};

/// Longest accepted regex pattern, in bytes.
pub const MAX_REGEX_PATTERN_LEN: usize = 1024;
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// What a rule or list does when it matches.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

/// How a rule's pattern is compared with a name.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MatchType {
    Exact,
    /// Matches the name itself and its subdomains, on label boundaries.
    Suffix,
    Regex,
}

/// Who a rule applies to.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "id", rename_all = "lowercase")]
pub enum Scope {
    Client(String),
    Group(String),
    Site(String),
    Global,
}

/// A rule as defined by an operator or the controller.
#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub action: RuleAction,
    pub match_type: MatchType,
    pub pattern: String,
    pub scope: Scope,
    pub is_emergency: bool,
    pub enabled: bool,
    pub expires_at: Option<SystemTime>,
}

/// One entry from a subscribed list.
#[derive(Clone, Debug)]
pub enum ListEntry {
    Exact(DomainName),
    Suffix(DomainName),
}

/// A subscribed list and its parsed entries.
#[derive(Clone, Debug)]
pub struct ListSource {
    pub id: String,
    pub action: RuleAction,
    /// Groups the list applies to. A list with no groups applies at global scope.
    pub groups: Vec<String>,
    pub entries: Vec<ListEntry>,
}

/// Why rules could not be compiled.
#[derive(Debug, Error)]
pub enum CompileError {
    #[error("rule {rule_id}: invalid pattern: {source}")]
    InvalidName { rule_id: String, source: NameError },
    #[error("rule {rule_id}: the root name cannot be used as a pattern")]
    RootPattern { rule_id: String },
    #[error("rule {rule_id}: regex is longer than {MAX_REGEX_PATTERN_LEN} bytes")]
    RegexTooLong { rule_id: String },
    #[error("rule {rule_id}: invalid regex: {source}")]
    InvalidRegex {
        rule_id: String,
        source: regex::Error,
    },
    #[error("regex set exceeds the compiled size limit: {0}")]
    RegexSetTooLarge(regex::Error),
    #[error("rule {rule_id}: only deny rules can be emergency rules")]
    EmergencyAllow { rule_id: String },
}

/// One tier's regexes. `ids` is sorted and parallel to the patterns in `set`.
#[derive(Debug)]
pub(crate) struct RegexMatcher {
    set: RegexSet,
    ids: Vec<Box<str>>,
}

impl RegexMatcher {
    /// The lowest rule ID whose regex matches.
    pub(crate) fn first_match(&self, name: &str) -> Option<&str> {
        let index = self.set.matches(name).iter().next()?;
        self.ids.get(index).map(AsRef::as_ref)
    }
}

/// The rules for one action, within one scope.
#[derive(Debug, Default)]
pub(crate) struct Matchers {
    pub(crate) exact: HashMap<Box<str>, Box<str>>,
    pub(crate) suffix: HashMap<Box<str>, Box<str>>,
    pub(crate) regex: Option<RegexMatcher>,
}

/// All rules for one scope, such as a single client or group.
#[derive(Debug, Default)]
pub(crate) struct ScopeRules {
    pub(crate) emergency: Matchers,
    pub(crate) allow: Matchers,
    pub(crate) deny: Matchers,
}

/// Compiled rules and everything else that can change without recompiling lists.
#[derive(Debug, Default)]
pub struct RuleOverlay {
    pub(crate) clients: HashMap<Box<str>, ScopeRules>,
    pub(crate) groups: HashMap<Box<str>, ScopeRules>,
    pub(crate) sites: HashMap<Box<str>, ScopeRules>,
    pub(crate) global: ScopeRules,
    next_expiry: Option<SystemTime>,
}

#[derive(Default)]
struct PendingMatchers {
    exact: HashMap<Box<str>, Box<str>>,
    suffix: HashMap<Box<str>, Box<str>>,
    regex: Vec<(String, Box<str>)>,
}

impl PendingMatchers {
    fn finish(mut self) -> Result<Matchers, CompileError> {
        self.regex.sort_by(|left, right| left.1.cmp(&right.1));
        let regex = if self.regex.is_empty() {
            None
        } else {
            let (patterns, ids): (Vec<_>, Vec<_>) = self.regex.into_iter().unzip();
            let set = RegexSetBuilder::new(patterns)
                .case_insensitive(true)
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(CompileError::RegexSetTooLarge)?;
            Some(RegexMatcher { set, ids })
        };
        Ok(Matchers {
            exact: self.exact,
            suffix: self.suffix,
            regex,
        })
    }
}

#[derive(Default)]
struct PendingScope {
    emergency: PendingMatchers,
    allow: PendingMatchers,
    deny: PendingMatchers,
}

impl PendingScope {
    fn finish(self) -> Result<ScopeRules, CompileError> {
        Ok(ScopeRules {
            emergency: self.emergency.finish()?,
            allow: self.allow.finish()?,
            deny: self.deny.finish()?,
        })
    }
}

fn finish_map(
    pending: HashMap<Box<str>, PendingScope>,
) -> Result<HashMap<Box<str>, ScopeRules>, CompileError> {
    pending
        .into_iter()
        .map(|(key, scope)| Ok((key, scope.finish()?)))
        .collect()
}

fn insert_lowest(map: &mut HashMap<Box<str>, Box<str>>, key: &str, id: &str) {
    match map.get_mut(key) {
        Some(existing) if **existing <= *id => {}
        Some(existing) => *existing = id.into(),
        None => {
            map.insert(key.into(), id.into());
        }
    }
}

fn parse_pattern(rule: &Rule) -> Result<DomainName, CompileError> {
    let name = DomainName::parse(&rule.pattern).map_err(|source| CompileError::InvalidName {
        rule_id: rule.id.clone(),
        source,
    })?;
    if name.is_root() {
        return Err(CompileError::RootPattern {
            rule_id: rule.id.clone(),
        });
    }
    Ok(name)
}

fn validate_regex(rule: &Rule) -> Result<(), CompileError> {
    if rule.pattern.len() > MAX_REGEX_PATTERN_LEN {
        return Err(CompileError::RegexTooLong {
            rule_id: rule.id.clone(),
        });
    }
    // Checking each pattern alone attributes a bad pattern to its rule.
    RegexSetBuilder::new([&rule.pattern])
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map(|_| ())
        .map_err(|source| CompileError::InvalidRegex {
            rule_id: rule.id.clone(),
            source,
        })
}

impl RuleOverlay {
    /// Compiles rules, leaving out disabled rules and those already expired at `now`.
    pub fn compile(rules: &[Rule], now: SystemTime) -> Result<Self, CompileError> {
        let mut clients: HashMap<Box<str>, PendingScope> = HashMap::new();
        let mut groups: HashMap<Box<str>, PendingScope> = HashMap::new();
        let mut sites: HashMap<Box<str>, PendingScope> = HashMap::new();
        let mut global = PendingScope::default();
        let mut next_expiry: Option<SystemTime> = None;

        for rule in rules {
            if rule.is_emergency && rule.action != RuleAction::Deny {
                return Err(CompileError::EmergencyAllow {
                    rule_id: rule.id.clone(),
                });
            }

            // Validate disabled and expired rules too, so they cannot fail later when re-enabled.
            let normalized = match rule.match_type {
                MatchType::Exact | MatchType::Suffix => Some(parse_pattern(rule)?),
                MatchType::Regex => {
                    validate_regex(rule)?;
                    None
                }
            };

            if !rule.enabled {
                continue;
            }
            if let Some(expires_at) = rule.expires_at {
                if expires_at <= now {
                    continue;
                }
                next_expiry = Some(next_expiry.map_or(expires_at, |next| next.min(expires_at)));
            }

            let scope = match &rule.scope {
                Scope::Client(id) => clients.entry(id.as_str().into()).or_default(),
                Scope::Group(id) => groups.entry(id.as_str().into()).or_default(),
                Scope::Site(id) => sites.entry(id.as_str().into()).or_default(),
                Scope::Global => &mut global,
            };
            let matchers = match (rule.is_emergency, rule.action) {
                (true, _) => &mut scope.emergency,
                (false, RuleAction::Allow) => &mut scope.allow,
                (false, RuleAction::Deny) => &mut scope.deny,
            };

            match (rule.match_type, normalized) {
                (MatchType::Exact, Some(name)) => {
                    insert_lowest(&mut matchers.exact, name.as_str(), &rule.id);
                }
                (MatchType::Suffix, Some(name)) => {
                    insert_lowest(&mut matchers.suffix, name.as_str(), &rule.id);
                }
                _ => matchers
                    .regex
                    .push((rule.pattern.clone(), rule.id.as_str().into())),
            }
        }

        Ok(Self {
            clients: finish_map(clients)?,
            groups: finish_map(groups)?,
            sites: finish_map(sites)?,
            global: global.finish()?,
            next_expiry,
        })
    }

    /// The earliest moment a compiled rule expires, when the overlay must be rebuilt.
    pub fn next_expiry(&self) -> Option<SystemTime> {
        self.next_expiry
    }
}

/// Subscribed entries for one action, within one scope. Values index into [`ListLayer::ids`].
#[derive(Debug, Default)]
pub(crate) struct ListMatchers {
    pub(crate) exact: HashMap<Box<str>, u32>,
    pub(crate) suffix: HashMap<Box<str>, u32>,
}

#[derive(Debug, Default)]
pub(crate) struct ListIndex {
    pub(crate) allow: ListMatchers,
    pub(crate) deny: ListMatchers,
}

/// Compiled subscribed lists. This is rebuilt only when list content or assignments change.
#[derive(Debug, Default)]
pub struct ListLayer {
    /// Sorted list IDs, so a lower index always means a lower ID.
    pub(crate) ids: Vec<Box<str>>,
    pub(crate) groups: HashMap<Box<str>, ListIndex>,
    pub(crate) global: ListIndex,
}

fn insert_lowest_index(map: &mut HashMap<Box<str>, u32>, key: &str, index: u32) {
    match map.get_mut(key) {
        Some(existing) => *existing = (*existing).min(index),
        None => {
            map.insert(key.into(), index);
        }
    }
}

fn add_entries(index: &mut ListIndex, list: &ListSource, position: u32) {
    let matchers = match list.action {
        RuleAction::Allow => &mut index.allow,
        RuleAction::Deny => &mut index.deny,
    };
    for entry in &list.entries {
        match entry {
            ListEntry::Exact(name) if !name.is_root() => {
                insert_lowest_index(&mut matchers.exact, name.as_str(), position);
            }
            ListEntry::Suffix(name) if !name.is_root() => {
                insert_lowest_index(&mut matchers.suffix, name.as_str(), position);
            }
            // A list must never be able to match every name through the root.
            ListEntry::Exact(_) | ListEntry::Suffix(_) => {}
        }
    }
}

impl ListLayer {
    /// Compiles lists into per-scope indexes. Root entries are ignored.
    pub fn compile(lists: &[ListSource]) -> Self {
        let mut sorted: Vec<&ListSource> = lists.iter().collect();
        sorted.sort_by(|left, right| left.id.cmp(&right.id));

        let mut layer = Self {
            ids: sorted.iter().map(|list| list.id.as_str().into()).collect(),
            ..Self::default()
        };

        for (position, list) in (0_u32..).zip(sorted) {
            if list.groups.is_empty() {
                add_entries(&mut layer.global, list, position);
            }
            for group in &list.groups {
                let index = layer.groups.entry(group.as_str().into()).or_default();
                add_entries(index, list, position);
            }
        }
        layer
    }
}

/// An immutable policy revision that can be evaluated without locks or I/O.
#[derive(Clone, Debug)]
pub struct PolicySnapshot {
    pub(crate) revision: Arc<str>,
    pub(crate) lists: Arc<ListLayer>,
    pub(crate) rules: Arc<RuleOverlay>,
}

impl PolicySnapshot {
    /// Combines layers. Either layer can be shared with the previous snapshot.
    pub fn new(revision: &str, lists: Arc<ListLayer>, rules: Arc<RuleOverlay>) -> Self {
        Self {
            revision: revision.into(),
            lists,
            rules,
        }
    }

    /// The revision this snapshot was built from.
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// The compiled list layer, for reuse when only rules change.
    pub fn lists(&self) -> &Arc<ListLayer> {
        &self.lists
    }

    /// The compiled rule overlay.
    pub fn rules(&self) -> &Arc<RuleOverlay> {
        &self.rules
    }
}
