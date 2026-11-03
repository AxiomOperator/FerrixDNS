//! Measures compile time, memory and evaluation latency with a large generated list.
//!
//! Run with: cargo run --release -p dns-policy --example bench_policy -- 1000000
//!
//! This is a quick local measurement, not the benchmark profile in spec section 8.6.

#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use dns_policy::{
    ClientContext, DomainName, ListEntry, ListLayer, ListSource, MatchType, NameContext,
    PolicySnapshot, Rule, RuleAction, RuleOverlay, Scope,
};

fn resident_mib() -> f64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|kib| kib.parse::<f64>().ok())
        .map_or(0.0, |kib| kib / 1024.0)
}

fn percentile(sorted: &[u128], fraction: f64) -> u128 {
    let index = ((sorted.len() - 1) as f64 * fraction) as usize;
    sorted[index]
}

fn main() {
    let entries: usize = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000);

    let base = resident_mib();
    let list = ListSource {
        id: "generated".into(),
        action: RuleAction::Deny,
        groups: vec![],
        entries: (0..entries)
            .map(|index| {
                let name = DomainName::parse(&format!("host{index}.ads{}.example", index % 997));
                ListEntry::Exact(name.expect("generated names are valid"))
            })
            .collect(),
    };

    let started = Instant::now();
    let layer = ListLayer::compile(std::slice::from_ref(&list));
    let compile_time = started.elapsed();
    drop(list);
    let after_compile = resident_mib();

    let rules: Vec<Rule> = (0..1000)
        .map(|index| Rule {
            id: format!("r{index}"),
            action: RuleAction::Deny,
            match_type: if index % 10 == 0 {
                MatchType::Regex
            } else {
                MatchType::Suffix
            },
            pattern: if index % 10 == 0 {
                format!("^ad{index}[0-9]*\\.")
            } else {
                format!("rule{index}.example")
            },
            scope: Scope::Global,
            is_emergency: false,
            enabled: true,
            expires_at: None,
        })
        .collect();
    let overlay = RuleOverlay::compile(&rules, SystemTime::now()).expect("generated rules compile");
    let snapshot = PolicySnapshot::new("bench", Arc::new(layer), Arc::new(overlay));

    let names: Vec<DomainName> = (0..200_000_usize)
        .map(|index| {
            let text = match index % 3 {
                0 => format!(
                    "host{}.ads{}.example",
                    index * 7 % entries,
                    (index * 7 % entries) % 997
                ),
                1 => format!("www.site{index}.example.com"),
                _ => format!("a.b.c.d.e.deep{index}.example.org"),
            };
            DomainName::parse(&text).expect("generated names are valid")
        })
        .collect();

    let client = ClientContext::default();
    let mut samples = Vec::with_capacity(names.len());
    let mut denied = 0_usize;
    for name in &names {
        let started = Instant::now();
        let decision = snapshot.evaluate(name, &client, NameContext::Forwarded);
        samples.push(started.elapsed().as_nanos());
        denied += usize::from(decision.action == dns_policy::Action::Deny);
    }
    samples.sort_unstable();

    println!("list entries:       {entries}");
    println!("rules:              {} (100 regex)", rules.len());
    println!("list compile:       {compile_time:?}");
    println!("list layer memory:  about {:.0} MiB", after_compile - base);
    println!("evaluations:        {} ({denied} denied)", samples.len());
    println!("p50:                {} ns", percentile(&samples, 0.50));
    println!("p95:                {} ns", percentile(&samples, 0.95));
    println!("p99:                {} ns", percentile(&samples, 0.99));
    println!("max:                {} ns", samples[samples.len() - 1]);
}
