//! Immutable DNS policy: normalized names, compiled rules and lists, and scope-first evaluation.
//!
//! Compilation happens outside the DNS hot path and produces a [`CompiledPolicy`], which is then
//! read without locks or I/O. The precedence model is recorded in ADR-003.

mod compile;
mod document;
mod evaluate;
mod name;

pub use compile::{
    CompileError, ListEntry, ListLayer, ListSource, MAX_REGEX_PATTERN_LEN, MatchType,
    PolicySnapshot, Rule, RuleAction, RuleOverlay, Scope,
};
pub use document::{
    BlockConfig, BlockResponse, ClientDef, CompiledPolicy, Identities, Identity, ListDef,
    MAX_BLOCK_TTL_SECONDS, PolicyDocument, PolicyError, RuleDef, SCHEMA_VERSION, Verdict,
};
pub use evaluate::{
    Action, ChainOutcome, ClientContext, Decision, DecisionSource, MAX_CNAME_CHAIN, NameContext,
    ScopeLevel, Tier,
};
pub use name::{DomainName, NameError};
