use crate::compile::{ListIndex, ListLayer, ListMatchers, Matchers, PolicySnapshot, ScopeRules};
use crate::name::DomainName;

/// Most CNAME targets evaluated for one answer. Longer chains should return SERVFAIL.
pub const MAX_CNAME_CHAIN: usize = 16;

/// Who is asking. Each field selects the rules that apply at that scope.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientContext<'a> {
    pub client: Option<&'a str>,
    pub groups: &'a [&'a str],
    pub site: Option<&'a str>,
}

/// Where a name sits, which determines whether subscribed lists apply to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameContext {
    /// A name resolved upstream. Rules and lists both apply.
    Forwarded,
    /// A name in a managed local zone. Only rules apply.
    LocalZone,
}

/// The outcome of evaluating a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
}

/// The scope that decided an outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeLevel {
    Client,
    Group,
    Site,
    Global,
}

/// The precedence tier that decided an outcome, from highest to lowest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    EmergencyDeny,
    ExactAllow,
    SuffixAllow,
    RegexAllow,
    ExactDeny,
    SuffixDeny,
    SubscribedAllow,
    SubscribedDeny,
    RegexDeny,
    DefaultAllow,
}

/// What produced a decision. IDs are borrowed from the snapshot, so evaluation doesn't allocate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionSource<'s> {
    Rule(&'s str),
    List(&'s str),
    Default,
}

/// A policy decision and enough detail to explain it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision<'s> {
    pub action: Action,
    pub tier: Tier,
    /// `None` only for the default allow.
    pub scope: Option<ScopeLevel>,
    pub source: DecisionSource<'s>,
}

impl Decision<'_> {
    /// Whether the name matched an allow rule or a subscribed allow, not just the default.
    pub fn is_explicit_allow(&self) -> bool {
        self.action == Action::Allow && self.tier != Tier::DefaultAllow
    }
}

/// The outcome of checking the CNAME targets in an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainOutcome<'s> {
    /// No target is blocked, so the answer can be returned.
    Allowed,
    /// The target at `target_index` is blocked, so the answer must be replaced by a block response.
    Blocked {
        target_index: usize,
        decision: Decision<'s>,
    },
    /// The chain has more than [`MAX_CNAME_CHAIN`] targets.
    TooDeep,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Subscribed {
    All,
    AllowOnly,
    None,
}

fn lowest<'s>(candidates: impl Iterator<Item = &'s str>) -> Option<&'s str> {
    candidates.min()
}

fn exact_match<'s>(matchers: &'s Matchers, name: &DomainName) -> Option<&'s str> {
    matchers.exact.get(name.as_str()).map(AsRef::as_ref)
}

fn suffix_match<'s>(matchers: &'s Matchers, name: &DomainName) -> Option<&'s str> {
    if matchers.suffix.is_empty() {
        return None;
    }
    name.suffixes()
        .find_map(|suffix| matchers.suffix.get(suffix))
        .map(AsRef::as_ref)
}

fn regex_match<'s>(matchers: &'s Matchers, name: &DomainName) -> Option<&'s str> {
    matchers.regex.as_ref()?.first_match(name.as_str())
}

fn list_match(matchers: &ListMatchers, name: &DomainName) -> Option<u32> {
    let exact = matchers.exact.get(name.as_str());
    let suffix = if matchers.suffix.is_empty() {
        None
    } else {
        name.suffixes()
            .find_map(|suffix| matchers.suffix.get(suffix))
    };
    let position = match (exact, suffix) {
        (Some(left), Some(right)) => left.min(right),
        (left, right) => left.or(right)?,
    };
    u32::try_from(position).ok()
}

fn lowest_list(layer: &ListLayer, positions: impl Iterator<Item = u32>) -> Option<&str> {
    let position = positions.min()?;
    layer
        .ids
        .get(usize::try_from(position).ok()?)
        .map(AsRef::as_ref)
}

/// Evaluates every rule and list at one scope, returning the first tier that matches.
fn evaluate_level<'s, R, L>(
    layer: &'s ListLayer,
    name: &DomainName,
    level: ScopeLevel,
    rules: R,
    lists: L,
    subscribed: Subscribed,
) -> Option<Decision<'s>>
where
    R: Iterator<Item = &'s ScopeRules> + Clone,
    L: Iterator<Item = &'s ListIndex> + Clone,
{
    let rule_decision = |action, tier, id| Decision {
        action,
        tier,
        scope: Some(level),
        source: DecisionSource::Rule(id),
    };
    let list_decision = |action, tier, id| Decision {
        action,
        tier,
        scope: Some(level),
        source: DecisionSource::List(id),
    };

    if let Some(id) = lowest(rules.clone().filter_map(|r| exact_match(&r.allow, name))) {
        return Some(rule_decision(Action::Allow, Tier::ExactAllow, id));
    }
    if let Some(id) = lowest(rules.clone().filter_map(|r| suffix_match(&r.allow, name))) {
        return Some(rule_decision(Action::Allow, Tier::SuffixAllow, id));
    }
    if let Some(id) = lowest(rules.clone().filter_map(|r| regex_match(&r.allow, name))) {
        return Some(rule_decision(Action::Allow, Tier::RegexAllow, id));
    }
    if let Some(id) = lowest(rules.clone().filter_map(|r| exact_match(&r.deny, name))) {
        return Some(rule_decision(Action::Deny, Tier::ExactDeny, id));
    }
    if let Some(id) = lowest(rules.clone().filter_map(|r| suffix_match(&r.deny, name))) {
        return Some(rule_decision(Action::Deny, Tier::SuffixDeny, id));
    }
    if subscribed != Subscribed::None {
        let allowed = lists.clone().filter_map(|l| list_match(&l.allow, name));
        if let Some(id) = lowest_list(layer, allowed) {
            return Some(list_decision(Action::Allow, Tier::SubscribedAllow, id));
        }
    }
    if subscribed == Subscribed::All {
        let denied = lists.filter_map(|l| list_match(&l.deny, name));
        if let Some(id) = lowest_list(layer, denied) {
            return Some(list_decision(Action::Deny, Tier::SubscribedDeny, id));
        }
    }
    if let Some(id) = lowest(rules.filter_map(|r| regex_match(&r.deny, name))) {
        return Some(rule_decision(Action::Deny, Tier::RegexDeny, id));
    }
    None
}

fn emergency_match<'s>(rules: &'s ScopeRules, name: &DomainName) -> Option<&'s str> {
    let candidates = [
        exact_match(&rules.emergency, name),
        suffix_match(&rules.emergency, name),
        regex_match(&rules.emergency, name),
    ];
    lowest(candidates.into_iter().flatten())
}

impl PolicySnapshot {
    /// Decides a name for a client, following the precedence in ADR-003.
    pub fn evaluate<'s>(
        &'s self,
        name: &DomainName,
        client: &ClientContext<'_>,
        context: NameContext,
    ) -> Decision<'s> {
        let subscribed = match context {
            NameContext::Forwarded => Subscribed::All,
            NameContext::LocalZone => Subscribed::None,
        };
        self.evaluate_with(name, client, subscribed)
    }

    /// Checks an answer's CNAME targets, in order, after the query name was allowed.
    ///
    /// When the query name was explicitly allowed, subscribed denies on targets are ignored so
    /// the exception still works. Rule and emergency denies on targets still block.
    pub fn evaluate_cname_targets<'s>(
        &'s self,
        query_decision: &Decision<'_>,
        targets: &[DomainName],
        client: &ClientContext<'_>,
    ) -> ChainOutcome<'s> {
        if targets.len() > MAX_CNAME_CHAIN {
            return ChainOutcome::TooDeep;
        }
        let subscribed = if query_decision.is_explicit_allow() {
            Subscribed::AllowOnly
        } else {
            Subscribed::All
        };
        for (target_index, target) in targets.iter().enumerate() {
            let decision = self.evaluate_with(target, client, subscribed);
            if decision.action == Action::Deny {
                return ChainOutcome::Blocked {
                    target_index,
                    decision,
                };
            }
        }
        ChainOutcome::Allowed
    }

    fn evaluate_with<'s>(
        &'s self,
        name: &DomainName,
        client: &ClientContext<'_>,
        subscribed: Subscribed,
    ) -> Decision<'s> {
        let overlay = &*self.rules;
        let layer = &*self.lists;

        let client_rules = client.client.and_then(|id| overlay.clients.get(id));
        let group_rules = client
            .groups
            .iter()
            .filter_map(|group| overlay.groups.get(*group));
        let site_rules = client.site.and_then(|id| overlay.sites.get(id));
        let group_lists = client
            .groups
            .iter()
            .filter_map(|group| layer.groups.get(*group));

        // Emergency denies apply at every scope, ahead of everything else.
        let emergency = |level: ScopeLevel, rules: &'s ScopeRules| {
            emergency_match(rules, name).map(|id| (id, level))
        };
        let emergency_hit = client_rules
            .and_then(|rules| emergency(ScopeLevel::Client, rules))
            .into_iter()
            .chain(
                group_rules
                    .clone()
                    .filter_map(|r| emergency(ScopeLevel::Group, r)),
            )
            .chain(site_rules.and_then(|rules| emergency(ScopeLevel::Site, rules)))
            .chain(emergency(ScopeLevel::Global, &overlay.global))
            .min_by_key(|(id, _)| *id);
        if let Some((id, level)) = emergency_hit {
            return Decision {
                action: Action::Deny,
                tier: Tier::EmergencyDeny,
                scope: Some(level),
                source: DecisionSource::Rule(id),
            };
        }

        let no_lists = None::<&ListIndex>.into_iter();
        let decided = evaluate_level(
            layer,
            name,
            ScopeLevel::Client,
            client_rules.into_iter(),
            no_lists.clone(),
            subscribed,
        )
        .or_else(|| {
            evaluate_level(
                layer,
                name,
                ScopeLevel::Group,
                group_rules,
                group_lists,
                subscribed,
            )
        })
        .or_else(|| {
            evaluate_level(
                layer,
                name,
                ScopeLevel::Site,
                site_rules.into_iter(),
                no_lists,
                subscribed,
            )
        })
        .or_else(|| {
            evaluate_level(
                layer,
                name,
                ScopeLevel::Global,
                std::iter::once(&overlay.global),
                std::iter::once(&layer.global),
                subscribed,
            )
        });

        decided.unwrap_or(Decision {
            action: Action::Allow,
            tier: Tier::DefaultAllow,
            scope: None,
            source: DecisionSource::Default,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use crate::compile::{
        CompileError, ListEntry, ListLayer, ListSource, MatchType, Rule, RuleAction, RuleOverlay,
        Scope,
    };

    use super::*;

    fn name(value: &str) -> DomainName {
        DomainName::parse(value).unwrap()
    }

    fn rule(
        id: &str,
        action: RuleAction,
        match_type: MatchType,
        pattern: &str,
        scope: Scope,
    ) -> Rule {
        Rule {
            id: id.into(),
            action,
            match_type,
            pattern: pattern.into(),
            scope,
            is_emergency: false,
            enabled: true,
            expires_at: None,
        }
    }

    fn allow(id: &str, match_type: MatchType, pattern: &str, scope: Scope) -> Rule {
        rule(id, RuleAction::Allow, match_type, pattern, scope)
    }

    fn deny(id: &str, match_type: MatchType, pattern: &str, scope: Scope) -> Rule {
        rule(id, RuleAction::Deny, match_type, pattern, scope)
    }

    fn list(id: &str, action: RuleAction, groups: &[&str], entries: &[&str]) -> ListSource {
        ListSource {
            id: id.into(),
            action,
            groups: groups.iter().map(ToString::to_string).collect(),
            entries: entries
                .iter()
                .map(|entry| ListEntry::Exact(name(entry)))
                .collect(),
            artifact: None,
        }
    }

    fn snapshot(rules: &[Rule], lists: &[ListSource]) -> PolicySnapshot {
        PolicySnapshot::new(
            "rev-1",
            Arc::new(ListLayer::compile(lists).unwrap()),
            Arc::new(RuleOverlay::compile(rules, SystemTime::now()).unwrap()),
        )
    }

    const LAPTOP: ClientContext<'static> = ClientContext {
        client: Some("laptop"),
        groups: &["kids", "guests"],
        site: Some("hq"),
    };

    fn decide<'s>(snapshot: &'s PolicySnapshot, value: &str) -> Decision<'s> {
        snapshot.evaluate(&name(value), &LAPTOP, NameContext::Forwarded)
    }

    #[test]
    fn allows_by_default() {
        let policy = snapshot(&[], &[]);
        let decision = decide(&policy, "example.com");
        assert_eq!(decision.action, Action::Allow);
        assert_eq!(decision.tier, Tier::DefaultAllow);
        assert_eq!(decision.scope, None);
        assert!(!decision.is_explicit_allow());
    }

    #[test]
    fn suffix_matches_apex_and_subdomains_but_not_lookalikes() {
        let policy = snapshot(
            &[deny("r1", MatchType::Suffix, "example.com", Scope::Global)],
            &[],
        );
        assert_eq!(decide(&policy, "example.com").action, Action::Deny);
        assert_eq!(decide(&policy, "a.b.EXAMPLE.com.").action, Action::Deny);
        assert_eq!(decide(&policy, "notexample.com").action, Action::Allow);
        assert_eq!(
            decide(&policy, "example.com.evil.net").action,
            Action::Allow
        );
    }

    #[test]
    fn exact_matches_only_the_name() {
        let policy = snapshot(
            &[deny("r1", MatchType::Exact, "ads.example", Scope::Global)],
            &[],
        );
        assert_eq!(decide(&policy, "ADS.example.").action, Action::Deny);
        assert_eq!(decide(&policy, "x.ads.example").action, Action::Allow);
    }

    #[test]
    fn idn_rule_matches_its_a_label_query() {
        let policy = snapshot(
            &[deny(
                "r1",
                MatchType::Exact,
                "bücher.example",
                Scope::Global,
            )],
            &[],
        );
        assert_eq!(
            decide(&policy, "xn--bcher-kva.example").action,
            Action::Deny
        );
    }

    #[test]
    fn regex_is_case_insensitive_and_runs_on_the_normalized_name() {
        let policy = snapshot(
            &[deny("r1", MatchType::Regex, r"^AD[0-9]+\.", Scope::Global)],
            &[],
        );
        assert_eq!(decide(&policy, "ad12.example").tier, Tier::RegexDeny);
        assert_eq!(decide(&policy, "adx.example").action, Action::Allow);
    }

    #[test]
    fn narrow_scope_deny_beats_global_exact_allow() {
        let policy = snapshot(
            &[
                allow("r1", MatchType::Exact, "x.example", Scope::Global),
                deny(
                    "r2",
                    MatchType::Exact,
                    "x.example",
                    Scope::Client("laptop".into()),
                ),
            ],
            &[],
        );
        let decision = decide(&policy, "x.example");
        assert_eq!(decision.action, Action::Deny);
        assert_eq!(decision.scope, Some(ScopeLevel::Client));
    }

    #[test]
    fn a_weak_narrow_match_still_beats_a_strong_broad_match() {
        let policy = snapshot(
            &[
                allow("r1", MatchType::Exact, "x.example", Scope::Global),
                deny("r2", MatchType::Regex, "x", Scope::Group("kids".into())),
            ],
            &[],
        );
        let decision = decide(&policy, "x.example");
        assert_eq!(decision.tier, Tier::RegexDeny);
        assert_eq!(decision.scope, Some(ScopeLevel::Group));
    }

    #[test]
    fn scopes_apply_in_order() {
        let at = |scope: Scope| deny("r", MatchType::Exact, "x.example", scope);
        let expected = [
            (Scope::Client("laptop".into()), ScopeLevel::Client),
            (Scope::Group("guests".into()), ScopeLevel::Group),
            (Scope::Site("hq".into()), ScopeLevel::Site),
            (Scope::Global, ScopeLevel::Global),
        ];
        for (scope, level) in expected {
            let policy = snapshot(&[at(scope)], &[]);
            assert_eq!(decide(&policy, "x.example").scope, Some(level));
        }
    }

    #[test]
    fn rules_for_other_clients_do_not_apply() {
        let policy = snapshot(
            &[
                deny(
                    "r1",
                    MatchType::Exact,
                    "x.example",
                    Scope::Client("phone".into()),
                ),
                deny(
                    "r2",
                    MatchType::Exact,
                    "x.example",
                    Scope::Group("staff".into()),
                ),
                deny(
                    "r3",
                    MatchType::Exact,
                    "x.example",
                    Scope::Site("branch".into()),
                ),
            ],
            &[],
        );
        assert_eq!(decide(&policy, "x.example").action, Action::Allow);
    }

    #[test]
    fn tiers_apply_in_order_within_a_scope() {
        let domain = "ads.example";
        let all = || {
            vec![
                (
                    allow("exact-allow", MatchType::Exact, domain, Scope::Global),
                    Tier::ExactAllow,
                ),
                (
                    allow("suffix-allow", MatchType::Suffix, domain, Scope::Global),
                    Tier::SuffixAllow,
                ),
                (
                    allow("regex-allow", MatchType::Regex, "ads", Scope::Global),
                    Tier::RegexAllow,
                ),
                (
                    deny("exact-deny", MatchType::Exact, domain, Scope::Global),
                    Tier::ExactDeny,
                ),
                (
                    deny("suffix-deny", MatchType::Suffix, domain, Scope::Global),
                    Tier::SuffixDeny,
                ),
            ]
        };
        let lists = [
            list("list-allow", RuleAction::Allow, &[], &[domain]),
            list("list-deny", RuleAction::Deny, &[], &[domain]),
        ];
        let regex_deny = deny("regex-deny", MatchType::Regex, "ads", Scope::Global);

        // Remove the winner at each step, so the next tier must decide.
        let mut rules = all();
        while !rules.is_empty() {
            let expected = rules[0].1;
            let mut current: Vec<Rule> = rules.iter().map(|(rule, _)| rule.clone()).collect();
            current.push(regex_deny.clone());
            let policy = snapshot(&current, &lists);
            assert_eq!(decide(&policy, domain).tier, expected);
            rules.remove(0);
        }

        let policy = snapshot(std::slice::from_ref(&regex_deny), &lists);
        assert_eq!(decide(&policy, domain).tier, Tier::SubscribedAllow);
        let policy = snapshot(std::slice::from_ref(&regex_deny), &lists[1..]);
        assert_eq!(decide(&policy, domain).tier, Tier::SubscribedDeny);
        let policy = snapshot(std::slice::from_ref(&regex_deny), &[]);
        assert_eq!(decide(&policy, domain).tier, Tier::RegexDeny);
    }

    #[test]
    fn emergency_deny_wins_at_every_scope() {
        let scopes = [
            Scope::Client("laptop".into()),
            Scope::Group("kids".into()),
            Scope::Site("hq".into()),
            Scope::Global,
        ];
        for scope in scopes {
            let mut emergency = deny("emergency", MatchType::Suffix, "example", scope);
            emergency.is_emergency = true;
            let policy = snapshot(
                &[
                    emergency,
                    allow(
                        "r2",
                        MatchType::Exact,
                        "x.example",
                        Scope::Client("laptop".into()),
                    ),
                ],
                &[],
            );
            let decision = decide(&policy, "x.example");
            assert_eq!(decision.tier, Tier::EmergencyDeny);
            assert_eq!(decision.source, DecisionSource::Rule("emergency"));
        }
    }

    #[test]
    fn emergency_rules_must_deny() {
        let mut emergency = allow("r1", MatchType::Exact, "x.example", Scope::Global);
        emergency.is_emergency = true;
        let result = RuleOverlay::compile(&[emergency], SystemTime::now());
        assert!(matches!(result, Err(CompileError::EmergencyAllow { .. })));
    }

    #[test]
    fn multiple_groups_count_as_one_scope() {
        let policy = snapshot(
            &[
                deny(
                    "r1",
                    MatchType::Exact,
                    "x.example",
                    Scope::Group("kids".into()),
                ),
                allow(
                    "r2",
                    MatchType::Exact,
                    "x.example",
                    Scope::Group("guests".into()),
                ),
            ],
            &[],
        );
        // The allow tier decides, whichever group holds the rule.
        assert_eq!(decide(&policy, "x.example").tier, Tier::ExactAllow);
    }

    #[test]
    fn group_ties_attribute_the_lowest_id_regardless_of_input_order() {
        let first = deny(
            "r1",
            MatchType::Exact,
            "x.example",
            Scope::Group("guests".into()),
        );
        let second = deny(
            "r2",
            MatchType::Exact,
            "x.example",
            Scope::Group("kids".into()),
        );
        for rules in [
            [first.clone(), second.clone()],
            [second.clone(), first.clone()],
        ] {
            let policy = snapshot(&rules, &[]);
            assert_eq!(
                decide(&policy, "x.example").source,
                DecisionSource::Rule("r1")
            );
        }
    }

    #[test]
    fn duplicate_patterns_and_lists_attribute_the_lowest_id() {
        let rules = [
            deny("r9", MatchType::Exact, "x.example", Scope::Global),
            deny("r1", MatchType::Exact, "x.example", Scope::Global),
        ];
        let policy = snapshot(&rules, &[]);
        assert_eq!(
            decide(&policy, "x.example").source,
            DecisionSource::Rule("r1")
        );

        let lists = [
            list("l9", RuleAction::Deny, &[], &["y.example"]),
            list("l1", RuleAction::Deny, &[], &["y.example"]),
        ];
        let policy = snapshot(&[], &lists);
        assert_eq!(
            decide(&policy, "y.example").source,
            DecisionSource::List("l1")
        );
    }

    #[test]
    fn regex_ties_attribute_the_lowest_id() {
        let rules = [
            deny("r9", MatchType::Regex, "example", Scope::Global),
            deny("r1", MatchType::Regex, "example", Scope::Global),
        ];
        let policy = snapshot(&rules, &[]);
        assert_eq!(
            decide(&policy, "x.example").source,
            DecisionSource::Rule("r1")
        );
    }

    #[test]
    fn lists_apply_to_their_groups_or_globally() {
        let lists = [
            list("kids-list", RuleAction::Deny, &["kids"], &["a.example"]),
            list("staff-list", RuleAction::Deny, &["staff"], &["b.example"]),
            list("global-list", RuleAction::Deny, &[], &["c.example"]),
        ];
        let policy = snapshot(&[], &lists);

        let decision = decide(&policy, "a.example");
        assert_eq!(decision.source, DecisionSource::List("kids-list"));
        assert_eq!(decision.scope, Some(ScopeLevel::Group));

        assert_eq!(decide(&policy, "b.example").action, Action::Allow);

        let decision = decide(&policy, "c.example");
        assert_eq!(decision.source, DecisionSource::List("global-list"));
        assert_eq!(decision.scope, Some(ScopeLevel::Global));
    }

    #[test]
    fn suffix_list_entries_match_subdomains() {
        let source = ListSource {
            id: "l1".into(),
            action: RuleAction::Deny,
            groups: vec![],
            entries: vec![ListEntry::Suffix(name("tracker.example"))],
            artifact: None,
        };
        let policy = snapshot(&[], &[source]);
        assert_eq!(
            decide(&policy, "x.tracker.example").tier,
            Tier::SubscribedDeny
        );
        assert_eq!(decide(&policy, "nottracker.example").action, Action::Allow);
    }

    #[test]
    fn artifacts_compile_and_match_like_entries() {
        let source = ListSource {
            id: "l1".into(),
            action: RuleAction::Deny,
            groups: vec![],
            entries: vec![],
            artifact: Some(b"e ads.example\ns tracker.example\n".to_vec()),
        };
        let policy = snapshot(&[], &[source]);
        assert_eq!(decide(&policy, "ads.example").tier, Tier::SubscribedDeny);
        assert_eq!(decide(&policy, "x.ads.example").action, Action::Allow);
        assert_eq!(
            decide(&policy, "x.tracker.example").tier,
            Tier::SubscribedDeny
        );

        let corrupt = ListSource {
            id: "l2".into(),
            action: RuleAction::Deny,
            groups: vec![],
            entries: vec![],
            artifact: Some(b"z nope\n".to_vec()),
        };
        assert!(matches!(
            ListLayer::compile(&[corrupt]),
            Err(CompileError::ListArtifact { .. })
        ));
    }

    #[test]
    fn root_list_entries_are_ignored() {
        let source = ListSource {
            id: "l1".into(),
            action: RuleAction::Deny,
            groups: vec![],
            entries: vec![ListEntry::Suffix(name(".")), ListEntry::Exact(name("."))],
            artifact: None,
        };
        let policy = snapshot(&[], &[source]);
        assert_eq!(decide(&policy, "example.com").action, Action::Allow);
        assert_eq!(decide(&policy, ".").action, Action::Allow);
    }

    #[test]
    fn root_patterns_are_rejected() {
        let result = RuleOverlay::compile(
            &[deny("r1", MatchType::Suffix, ".", Scope::Global)],
            SystemTime::now(),
        );
        assert!(matches!(result, Err(CompileError::RootPattern { .. })));
    }

    #[test]
    fn local_zone_names_ignore_lists_but_not_rules() {
        let lists = [list("l1", RuleAction::Deny, &[], &["nas.home.arpa"])];
        let policy = snapshot(
            &[deny(
                "r1",
                MatchType::Exact,
                "secret.home.arpa",
                Scope::Global,
            )],
            &lists,
        );
        let check = |value| {
            policy
                .evaluate(&name(value), &LAPTOP, NameContext::LocalZone)
                .action
        };
        assert_eq!(check("nas.home.arpa"), Action::Allow);
        assert_eq!(check("secret.home.arpa"), Action::Deny);
    }

    #[test]
    fn disabled_and_expired_rules_do_not_apply() {
        let now = SystemTime::now();
        let mut disabled = deny("r1", MatchType::Exact, "a.example", Scope::Global);
        disabled.enabled = false;
        let mut expired = deny("r2", MatchType::Exact, "b.example", Scope::Global);
        expired.expires_at = Some(now - Duration::from_secs(1));
        let mut at_now = deny("r3", MatchType::Exact, "c.example", Scope::Global);
        at_now.expires_at = Some(now);

        let overlay = RuleOverlay::compile(&[disabled, expired, at_now], now).unwrap();
        assert_eq!(overlay.next_expiry(), None);
        let policy =
            PolicySnapshot::new("rev-1", Arc::new(ListLayer::default()), Arc::new(overlay));
        for domain in ["a.example", "b.example", "c.example"] {
            assert_eq!(decide(&policy, domain).action, Action::Allow);
        }
    }

    #[test]
    fn next_expiry_is_the_earliest_active_expiry() {
        let now = SystemTime::now();
        let soon = now + Duration::from_secs(60);
        let later = now + Duration::from_secs(600);
        let mut first = deny("r1", MatchType::Exact, "a.example", Scope::Global);
        first.expires_at = Some(later);
        let mut second = deny("r2", MatchType::Exact, "b.example", Scope::Global);
        second.expires_at = Some(soon);
        let mut disabled = deny("r3", MatchType::Exact, "c.example", Scope::Global);
        disabled.expires_at = Some(now + Duration::from_secs(1));
        disabled.enabled = false;

        let overlay = RuleOverlay::compile(&[first, second, disabled], now).unwrap();
        assert_eq!(overlay.next_expiry(), Some(soon));
    }

    #[test]
    fn disabled_rules_are_still_validated() {
        let mut bad = deny("r1", MatchType::Regex, "(", Scope::Global);
        bad.enabled = false;
        let result = RuleOverlay::compile(&[bad], SystemTime::now());
        assert!(matches!(result, Err(CompileError::InvalidRegex { .. })));
    }

    #[test]
    fn oversized_regexes_are_rejected_and_pathological_ones_stay_fast() {
        let too_long = deny(
            "r1",
            MatchType::Regex,
            &"a".repeat(crate::compile::MAX_REGEX_PATTERN_LEN + 1),
            Scope::Global,
        );
        assert!(matches!(
            RuleOverlay::compile(&[too_long], SystemTime::now()),
            Err(CompileError::RegexTooLong { .. })
        ));

        let huge = deny("r2", MatchType::Regex, r"(\w{1000}){1000}", Scope::Global);
        assert!(matches!(
            RuleOverlay::compile(&[huge], SystemTime::now()),
            Err(CompileError::InvalidRegex { .. })
        ));

        // This pattern takes exponential time on a backtracking engine.
        let policy = snapshot(
            &[deny("r3", MatchType::Regex, r"^(a+)+$", Scope::Global)],
            &[],
        );
        let input = format!("{}.b", "a".repeat(60));
        let started = std::time::Instant::now();
        assert_eq!(decide(&policy, &input).action, Action::Allow);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn cname_target_blocked_by_a_new_rule_is_caught() {
        let policy = snapshot(
            &[deny("r1", MatchType::Exact, "ads.tracker", Scope::Global)],
            &[],
        );
        let query = decide(&policy, "a.example");
        let targets = [name("b.example"), name("ads.tracker")];
        let outcome = policy.evaluate_cname_targets(&query, &targets, &LAPTOP);
        let ChainOutcome::Blocked {
            target_index,
            decision,
        } = outcome
        else {
            panic!("expected a blocked chain, got {outcome:?}");
        };
        assert_eq!(target_index, 1);
        assert_eq!(decision.source, DecisionSource::Rule("r1"));
    }

    #[test]
    fn list_blocked_target_blocks_a_default_allowed_query() {
        let lists = [list("l1", RuleAction::Deny, &[], &["ads.tracker"])];
        let policy = snapshot(&[], &lists);
        let query = decide(&policy, "a.example");
        let outcome = policy.evaluate_cname_targets(&query, &[name("ads.tracker")], &LAPTOP);
        assert!(matches!(
            outcome,
            ChainOutcome::Blocked {
                target_index: 0,
                ..
            }
        ));
    }

    #[test]
    fn explicit_allow_ignores_list_denies_on_targets_only() {
        let lists = [list("l1", RuleAction::Deny, &[], &["cdn.tracker"])];
        let rules = [
            allow("r1", MatchType::Exact, "shop.example", Scope::Global),
            deny("r2", MatchType::Exact, "bad.tracker", Scope::Global),
        ];
        let policy = snapshot(&rules, &lists);
        let query = decide(&policy, "shop.example");

        let listed = policy.evaluate_cname_targets(&query, &[name("cdn.tracker")], &LAPTOP);
        assert_eq!(listed, ChainOutcome::Allowed);

        let ruled = policy.evaluate_cname_targets(&query, &[name("bad.tracker")], &LAPTOP);
        assert!(matches!(ruled, ChainOutcome::Blocked { .. }));
    }

    #[test]
    fn subscribed_allow_on_the_query_also_counts_as_an_explicit_allow() {
        let lists = [
            list("allowed", RuleAction::Allow, &[], &["shop.example"]),
            list("denied", RuleAction::Deny, &[], &["cdn.tracker"]),
        ];
        let policy = snapshot(&[], &lists);
        let query = decide(&policy, "shop.example");
        assert!(query.is_explicit_allow());
        let outcome = policy.evaluate_cname_targets(&query, &[name("cdn.tracker")], &LAPTOP);
        assert_eq!(outcome, ChainOutcome::Allowed);
    }

    #[test]
    fn emergency_deny_on_a_target_blocks_an_explicitly_allowed_query() {
        let mut emergency = deny("r2", MatchType::Exact, "bad.tracker", Scope::Global);
        emergency.is_emergency = true;
        let rules = [
            allow("r1", MatchType::Exact, "shop.example", Scope::Global),
            emergency,
        ];
        let policy = snapshot(&rules, &[]);
        let query = decide(&policy, "shop.example");
        let outcome = policy.evaluate_cname_targets(&query, &[name("bad.tracker")], &LAPTOP);
        assert!(matches!(outcome, ChainOutcome::Blocked { .. }));
    }

    #[test]
    fn chain_depth_limit_is_enforced() {
        let policy = snapshot(&[], &[]);
        let query = decide(&policy, "a.example");
        let at_limit = vec![name("b.example"); MAX_CNAME_CHAIN];
        assert_eq!(
            policy.evaluate_cname_targets(&query, &at_limit, &LAPTOP),
            ChainOutcome::Allowed
        );
        let over_limit = vec![name("b.example"); MAX_CNAME_CHAIN + 1];
        assert_eq!(
            policy.evaluate_cname_targets(&query, &over_limit, &LAPTOP),
            ChainOutcome::TooDeep
        );
    }

    #[test]
    fn decisions_do_not_depend_on_input_order() {
        let rules = vec![
            allow(
                "r1",
                MatchType::Suffix,
                "good.example",
                Scope::Group("kids".into()),
            ),
            deny(
                "r2",
                MatchType::Exact,
                "x.good.example",
                Scope::Group("guests".into()),
            ),
            deny("r3", MatchType::Regex, "^x", Scope::Global),
            deny("r4", MatchType::Suffix, "example", Scope::Site("hq".into())),
            allow(
                "r5",
                MatchType::Exact,
                "y.example",
                Scope::Client("laptop".into()),
            ),
        ];
        let lists = vec![
            list("l1", RuleAction::Deny, &["kids"], &["z.example"]),
            list("l2", RuleAction::Allow, &["guests"], &["z.example"]),
        ];
        let names = [
            "x.good.example",
            "y.example",
            "z.example",
            "other.example",
            "x.net",
        ];

        let baseline = snapshot(&rules, &lists);
        let expected: Vec<_> = names.iter().map(|n| decide(&baseline, n)).collect();

        for rotation in 1..rules.len() {
            let mut rotated = rules.clone();
            rotated.rotate_left(rotation);
            let mut reversed_lists = lists.clone();
            reversed_lists.reverse();
            let policy = snapshot(&rotated, &reversed_lists);
            let actual: Vec<_> = names.iter().map(|n| decide(&policy, n)).collect();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn layers_can_be_swapped_independently() {
        let lists = Arc::new(
            ListLayer::compile(&[list("l1", RuleAction::Deny, &[], &["a.example"])]).unwrap(),
        );
        let first = PolicySnapshot::new(
            "rev-1",
            Arc::clone(&lists),
            Arc::new(RuleOverlay::default()),
        );
        assert_eq!(decide(&first, "a.example").action, Action::Deny);

        let overlay = RuleOverlay::compile(
            &[allow("r1", MatchType::Exact, "a.example", Scope::Global)],
            SystemTime::now(),
        )
        .unwrap();
        let second = PolicySnapshot::new("rev-2", Arc::clone(first.lists()), Arc::new(overlay));
        assert!(Arc::ptr_eq(first.lists(), second.lists()));
        assert_eq!(second.revision(), "rev-2");
        assert_eq!(decide(&second, "a.example").action, Action::Allow);
        assert_eq!(decide(&first, "a.example").action, Action::Deny);
    }
}
