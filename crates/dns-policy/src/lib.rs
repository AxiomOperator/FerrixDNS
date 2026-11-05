//! Immutable DNS policy: normalized names, compiled rules and lists, and scope-first evaluation.
//!
//! Compilation happens outside the DNS hot path and produces a [`CompiledPolicy`], which is then
//! read without locks or I/O. The precedence model is recorded in ADR-003.

mod compile;
mod device;
mod document;
mod evaluate;
mod forward;
mod local;
mod name;
mod services;

pub use compile::{
    CompileError, ListEntry, ListLayer, ListSource, MAX_REGEX_PATTERN_LEN, MatchType,
    PolicySnapshot, Rule, RuleAction, RuleOverlay, Scope,
};
pub use device::{ClientSource, MacAddress, MacParseError};
pub use document::{
    ArtifactLoader, BlockConfig, BlockResponse, BlockedServiceDef, ClientDef, CompiledPolicy,
    DEFAULT_RATE_LIMIT_PER_MINUTE, Filtering, GroupDef, Identities, Identity, ListDef, ListFormat,
    MAX_BLOCK_TTL_SECONDS, PolicyDocument, PolicyError, QueryLogMode, RateLimitConfig, RuleDef,
    SCHEMA_VERSION, TelemetryConfig, Verdict,
};
pub use evaluate::{
    Action, ChainOutcome, ClientContext, Decision, DecisionSource, MAX_CNAME_CHAIN, NameContext,
    ScopeLevel, Tier,
};
pub use forward::{ForwardRoute, ForwardZoneDef, ForwardZones, reverse_zones};
pub use local::{
    LOCAL_NEGATIVE_TTL_SECONDS, LocalAnswer, LocalData, LocalQuery, LocalRecord, LocalRecordDef,
    LocalRecordType, LocalZoneDef, LocalZones, reverse_name,
};
pub use name::{DomainName, NameError};
pub use services::{SERVICES, Service, find_service, service_of_rule, service_rule_ids};
