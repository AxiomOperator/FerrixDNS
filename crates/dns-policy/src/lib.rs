//! Immutable DNS policy: normalized names, compiled rules and lists, and scope-first evaluation.
//!
//! Compilation happens outside the DNS hot path and produces a [`CompiledPolicy`], which is then
//! read without locks or I/O. The precedence model is recorded in ADR-003.

mod compile;
mod document;
mod evaluate;
mod local;
mod name;

pub use compile::{
    CompileError, ListEntry, ListLayer, ListSource, MAX_REGEX_PATTERN_LEN, MatchType,
    PolicySnapshot, Rule, RuleAction, RuleOverlay, Scope,
};
pub use document::{
    ArtifactLoader, BlockConfig, BlockResponse, ClientDef, CompiledPolicy, GroupDef, Identities,
    Identity, ListDef, ListFormat, MAX_BLOCK_TTL_SECONDS, PolicyDocument, PolicyError,
    QueryLogMode, RuleDef, SCHEMA_VERSION, TelemetryConfig, Verdict,
};
pub use evaluate::{
    Action, ChainOutcome, ClientContext, Decision, DecisionSource, MAX_CNAME_CHAIN, NameContext,
    ScopeLevel, Tier,
};
pub use local::{
    LOCAL_NEGATIVE_TTL_SECONDS, LocalAnswer, LocalData, LocalQuery, LocalRecord, LocalRecordDef,
    LocalRecordType, LocalZoneDef, LocalZones, reverse_name,
};
pub use name::{DomainName, NameError};
