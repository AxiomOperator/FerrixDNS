//! The JSON contract. Keep these separate from storage types, so the API can stay stable.

use std::collections::HashMap;

use dns_policy::{
    BlockResponse, ClientDef, ListFormat, MatchType, QueryLogMode, RuleAction, RuleDef, Scope,
};
use dns_storage::ListStatus;
use dns_telemetry::{Outcome, QueryEvent};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::util::to_iso;

/// A single resource.
#[derive(Debug, Serialize, ToSchema)]
pub struct Envelope<T> {
    pub data: T,
}

impl<T> Envelope<T> {
    pub fn new(data: T) -> Self {
        Self { data }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Health {
    pub status: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Readiness {
    pub status: String,
    pub policy_revision: String,
    pub telemetry_available: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthStatus {
    /// True until the first administrator has been created.
    pub setup_required: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetupRequest {
    /// The one-time token from the node's log.
    pub token: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionInfo {
    pub username: String,
    /// Send this in the `X-CSRF-Token` header on requests that change anything.
    pub csrf_token: String,
    pub expires_at: String,
    /// True when the policy comes from a file, which disables editing.
    pub policy_read_only: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ActionDto {
    Allow,
    Deny,
}

impl From<RuleAction> for ActionDto {
    fn from(action: RuleAction) -> Self {
        match action {
            RuleAction::Allow => Self::Allow,
            RuleAction::Deny => Self::Deny,
        }
    }
}

impl From<ActionDto> for RuleAction {
    fn from(action: ActionDto) -> Self {
        match action {
            ActionDto::Allow => Self::Allow,
            ActionDto::Deny => Self::Deny,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum MatchTypeDto {
    Exact,
    Suffix,
    Regex,
}

impl From<MatchType> for MatchTypeDto {
    fn from(value: MatchType) -> Self {
        match value {
            MatchType::Exact => Self::Exact,
            MatchType::Suffix => Self::Suffix,
            MatchType::Regex => Self::Regex,
        }
    }
}

impl From<MatchTypeDto> for MatchType {
    fn from(value: MatchTypeDto) -> Self {
        match value {
            MatchTypeDto::Exact => Self::Exact,
            MatchTypeDto::Suffix => Self::Suffix,
            MatchTypeDto::Regex => Self::Regex,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ScopeKind {
    Global,
    Site,
    Group,
    Client,
}

/// Who a rule applies to. `id` is required except for global scope.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ScopeDto {
    pub kind: ScopeKind,
    #[serde(default)]
    pub id: Option<String>,
}

impl From<&Scope> for ScopeDto {
    fn from(scope: &Scope) -> Self {
        let (kind, id) = match scope {
            Scope::Global => (ScopeKind::Global, None),
            Scope::Site(id) => (ScopeKind::Site, Some(id.clone())),
            Scope::Group(id) => (ScopeKind::Group, Some(id.clone())),
            Scope::Client(id) => (ScopeKind::Client, Some(id.clone())),
        };
        Self { kind, id }
    }
}

impl ScopeDto {
    pub fn into_scope(self) -> Option<Scope> {
        match (self.kind, self.id) {
            (ScopeKind::Global, _) => Some(Scope::Global),
            (ScopeKind::Site, Some(id)) if !id.is_empty() => Some(Scope::Site(id)),
            (ScopeKind::Group, Some(id)) if !id.is_empty() => Some(Scope::Group(id)),
            (ScopeKind::Client, Some(id)) if !id.is_empty() => Some(Scope::Client(id)),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RuleDto {
    pub id: String,
    pub action: ActionDto,
    pub match_type: MatchTypeDto,
    pub pattern: String,
    pub scope: ScopeDto,
    pub emergency: bool,
    pub enabled: bool,
    pub expires_at: Option<String>,
    pub reason: Option<String>,
    /// Send this back in `If-Match` when changing the rule.
    pub revision: u64,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<&RuleDef> for RuleDto {
    fn from(rule: &RuleDef) -> Self {
        Self {
            id: rule.id.clone(),
            action: rule.action.into(),
            match_type: rule.match_type.into(),
            pattern: rule.pattern.clone(),
            scope: (&rule.scope).into(),
            emergency: rule.emergency,
            enabled: rule.enabled,
            expires_at: rule.expires_at.clone(),
            reason: rule.reason.clone(),
            revision: rule.revision,
            created_at: rule.created_at.clone(),
            updated_at: rule.updated_at.clone(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRule {
    pub action: ActionDto,
    pub match_type: MatchTypeDto,
    pub pattern: String,
    pub scope: ScopeDto,
    #[serde(default)]
    pub emergency: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Changes to a rule. Absent fields stay as they are. An empty `expires_at` or `reason` clears it.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRule {
    pub action: Option<ActionDto>,
    pub match_type: Option<MatchTypeDto>,
    pub pattern: Option<String>,
    pub scope: Option<ScopeDto>,
    pub emergency: Option<bool>,
    pub enabled: Option<bool>,
    pub expires_at: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TestRuleRequest {
    pub domain: String,
    /// The client to evaluate for. Without one, only site and global rules apply.
    #[serde(default)]
    pub client_ip: Option<String>,
}

/// Why a name would be allowed or blocked.
#[derive(Debug, Serialize, ToSchema)]
pub struct TestRuleResponse {
    pub domain: String,
    pub normalized_domain: String,
    pub action: ActionDto,
    /// The precedence tier that decided, such as `exact_deny` or `default_allow`.
    pub tier: String,
    /// The scope that decided, if any rule or list matched.
    pub scope: Option<String>,
    pub rule_id: Option<String>,
    pub rule_pattern: Option<String>,
    pub list_id: Option<String>,
    pub list_name: Option<String>,
    pub client_id: Option<String>,
    pub revision: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ListFormatDto {
    Hosts,
    Domains,
    Adblock,
}

impl From<ListFormat> for ListFormatDto {
    fn from(value: ListFormat) -> Self {
        match value {
            ListFormat::Hosts => Self::Hosts,
            ListFormat::Domains => Self::Domains,
            ListFormat::Adblock => Self::Adblock,
        }
    }
}

impl From<ListFormatDto> for ListFormat {
    fn from(value: ListFormatDto) -> Self {
        match value {
            ListFormatDto::Hosts => Self::Hosts,
            ListFormatDto::Domains => Self::Domains,
            ListFormatDto::Adblock => Self::Adblock,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListDto {
    pub id: String,
    pub name: Option<String>,
    pub action: ActionDto,
    pub enabled: bool,
    pub url: Option<String>,
    pub format: Option<ListFormatDto>,
    pub groups: Vec<String>,
    pub refresh_seconds: u64,
    pub entry_count: i64,
    pub invalid_line_count: i64,
    pub last_checked_at: Option<String>,
    pub last_success_at: Option<String>,
    /// Why the last download failed. The previous content stays active.
    pub last_error: Option<String>,
    pub artifact_sha256: Option<String>,
}

impl ListDto {
    pub fn new(list: &dns_policy::ListDef, status: Option<&ListStatus>) -> Self {
        let inline = i64::try_from(list.domains.len() + list.suffixes.len()).unwrap_or(i64::MAX);
        Self {
            id: list.id.clone(),
            name: list.name.clone(),
            action: list.action.into(),
            enabled: list.enabled,
            url: list.url.clone(),
            format: list.format.map(Into::into),
            groups: list.groups.clone(),
            refresh_seconds: list.refresh_seconds,
            entry_count: inline + status.map_or(0, |status| status.entry_count),
            invalid_line_count: status.map_or(0, |status| status.invalid_line_count),
            last_checked_at: status
                .and_then(|status| status.last_checked_at_ms)
                .map(to_iso),
            last_success_at: status
                .and_then(|status| status.last_success_at_ms)
                .map(to_iso),
            last_error: status.and_then(|status| status.last_error.clone()),
            artifact_sha256: list.artifact_sha256.clone(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateList {
    pub name: String,
    pub url: String,
    pub format: ListFormatDto,
    pub action: ActionDto,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default = "default_refresh")]
    pub refresh_seconds: u64,
}

fn default_refresh() -> u64 {
    86_400
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateList {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub groups: Option<Vec<String>>,
    pub refresh_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct JobDto {
    pub id: String,
    pub list_id: String,
    pub state: JobState,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClientDto {
    /// The client's ID, or its address if it hasn't been named.
    pub id: String,
    pub known: bool,
    pub name: Option<String>,
    pub addresses: Vec<String>,
    pub macs: Vec<String>,
    pub hostnames: Vec<String>,
    pub groups: Vec<String>,
    /// Queries in the last 7 days.
    pub query_count: i64,
    pub last_seen_at: Option<String>,
}

impl ClientDto {
    pub fn known(client: &ClientDef, activity: &HashMap<String, (i64, i64)>) -> Self {
        let seen = activity.get(&client.id);
        Self {
            id: client.id.clone(),
            known: true,
            name: client.name.clone(),
            addresses: client.addresses.clone(),
            macs: client.macs.clone(),
            hostnames: client.hostnames.clone(),
            groups: client.groups.clone(),
            query_count: seen.map_or(0, |seen| seen.0),
            last_seen_at: seen.map(|seen| to_iso(seen.1)),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateClient {
    pub name: String,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub macs: Vec<String>,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateClient {
    pub name: Option<String>,
    pub addresses: Option<Vec<String>>,
    pub macs: Option<Vec<String>>,
    pub hostnames: Option<Vec<String>>,
    pub groups: Option<Vec<String>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GroupDto {
    pub id: String,
    pub description: Option<String>,
    pub client_count: usize,
    pub rule_count: usize,
    pub list_count: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateGroup {
    pub id: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateGroup {
    pub description: Option<String>,
}

/// A zone this node answers for itself.
#[derive(Debug, Serialize, ToSchema)]
pub struct LocalZoneDto {
    pub name: String,
    pub record_count: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLocalZone {
    pub name: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum LocalRecordTypeDto {
    A,
    Aaaa,
    Cname,
    Ptr,
}

impl From<dns_policy::LocalRecordType> for LocalRecordTypeDto {
    fn from(value: dns_policy::LocalRecordType) -> Self {
        match value {
            dns_policy::LocalRecordType::A => Self::A,
            dns_policy::LocalRecordType::Aaaa => Self::Aaaa,
            dns_policy::LocalRecordType::Cname => Self::Cname,
            dns_policy::LocalRecordType::Ptr => Self::Ptr,
        }
    }
}

impl From<LocalRecordTypeDto> for dns_policy::LocalRecordType {
    fn from(value: LocalRecordTypeDto) -> Self {
        match value {
            LocalRecordTypeDto::A => Self::A,
            LocalRecordTypeDto::Aaaa => Self::Aaaa,
            LocalRecordTypeDto::Cname => Self::Cname,
            LocalRecordTypeDto::Ptr => Self::Ptr,
        }
    }
}

/// A record in a local zone.
#[derive(Debug, Serialize, ToSchema)]
pub struct LocalRecordDto {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: LocalRecordTypeDto,
    pub value: String,
    pub ttl_seconds: u32,
}

impl From<&dns_policy::LocalRecordDef> for LocalRecordDto {
    fn from(record: &dns_policy::LocalRecordDef) -> Self {
        Self {
            id: record.id.clone(),
            name: record.name.clone(),
            record_type: record.record_type.into(),
            value: record.value.clone(),
            ttl_seconds: record.ttl_seconds,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLocalRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: LocalRecordTypeDto,
    pub value: String,
    #[serde(default = "default_local_ttl")]
    pub ttl_seconds: u32,
}

fn default_local_ttl() -> u32 {
    300
}

/// Changes to a record. Absent fields stay as they are.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateLocalRecord {
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub record_type: Option<LocalRecordTypeDto>,
    pub value: Option<String>,
    pub ttl_seconds: Option<u32>,
}

/// The answer cache's size and hit counts since the node started.
#[derive(Debug, Serialize, ToSchema)]
pub struct CacheDto {
    pub enabled: bool,
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
    pub bytes: u64,
    pub max_bytes: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamDto {
    pub server: String,
    pub responses: u64,
    pub failures: u64,
    pub last_latency_us: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamTestResult {
    pub ok: bool,
    pub server: Option<String>,
    pub rcode: Option<String>,
    pub latency_ms: u64,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RevisionDto {
    pub revision: String,
    pub active: bool,
    pub rule_count: usize,
    pub list_count: usize,
    pub client_count: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ActivateRequest {
    pub revision: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BlockResponseDto {
    Nxdomain,
    ZeroAddress,
}

impl From<BlockResponse> for BlockResponseDto {
    fn from(value: BlockResponse) -> Self {
        match value {
            BlockResponse::Nxdomain => Self::Nxdomain,
            BlockResponse::ZeroAddress => Self::ZeroAddress,
        }
    }
}

impl From<BlockResponseDto> for BlockResponse {
    fn from(value: BlockResponseDto) -> Self {
        match value {
            BlockResponseDto::Nxdomain => Self::Nxdomain,
            BlockResponseDto::ZeroAddress => Self::ZeroAddress,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryLogModeDto {
    Full,
    Anonymized,
    AggregateOnly,
    Disabled,
}

impl From<QueryLogMode> for QueryLogModeDto {
    fn from(value: QueryLogMode) -> Self {
        match value {
            QueryLogMode::Full => Self::Full,
            QueryLogMode::Anonymized => Self::Anonymized,
            QueryLogMode::AggregateOnly => Self::AggregateOnly,
            QueryLogMode::Disabled => Self::Disabled,
        }
    }
}

impl From<QueryLogModeDto> for QueryLogMode {
    fn from(value: QueryLogModeDto) -> Self {
        match value {
            QueryLogModeDto::Full => Self::Full,
            QueryLogModeDto::Anonymized => Self::Anonymized,
            QueryLogModeDto::AggregateOnly => Self::AggregateOnly,
            QueryLogModeDto::Disabled => Self::Disabled,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct SettingsDto {
    pub block_response: BlockResponseDto,
    pub block_ttl_seconds: u32,
    pub query_log_mode: QueryLogModeDto,
    pub query_history_days: u32,
    pub query_history_max_bytes: u64,
    /// Queries per minute for each client address, which is also the largest burst. 0 turns the
    /// limit off.
    pub rate_limit_queries_per_minute: u32,
    /// Addresses or networks with no limit.
    pub rate_limit_exempt: Vec<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct RestoreParams {
    /// Validate the backup and report what it contains, without changing anything.
    #[serde(default)]
    pub dry_run: bool,
}

/// What a backup contains, and whether it was restored.
#[derive(Debug, Serialize, ToSchema)]
pub struct RestoreResult {
    pub dry_run: bool,
    pub created_at: String,
    pub app_version: String,
    pub revision: String,
    pub revision_count: usize,
    pub rule_count: usize,
    pub list_count: usize,
    pub client_count: usize,
    pub local_record_count: usize,
    /// True if the backup holds accounts, which only `ferrixdns backup restore` can restore.
    pub has_credentials: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SystemStatus {
    pub version: String,
    pub uptime_seconds: u64,
    pub policy_revision: String,
    pub policy_read_only: bool,
    pub policy_warnings: Vec<String>,
    pub dns_listeners: Vec<String>,
    /// Whether this node validates answers with DNSSEC itself.
    pub dnssec_validation: bool,
    pub rule_count: usize,
    pub list_count: usize,
    pub client_count: usize,
    pub telemetry_available: bool,
    pub queries_recorded: u64,
    pub events_dropped: u64,
    pub telemetry_write_errors: u64,
    pub query_history_bytes: u64,
    pub query_history_retained_seconds: u64,
    /// Queries refused for being over a client's limit, since the node started.
    pub rate_limited_queries: u64,
    /// Present when this node serves NTP.
    pub ntp: Option<NtpStatusDto>,
}

/// The state of this node's NTP server.
#[derive(Debug, Serialize, ToSchema)]
pub struct NtpStatusDto {
    pub listeners: Vec<String>,
    /// `synchronized`, `unsynchronized` or `unknown`.
    pub clock: String,
    pub requests_served: u64,
    pub requests_limited: u64,
}

/// Whether blocking is paused.
#[derive(Debug, Serialize, ToSchema)]
pub struct BlockingDto {
    pub paused: bool,
    /// When blocking resumes.
    pub paused_until: Option<String>,
    pub remaining_seconds: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PauseBlocking {
    /// How long to pause for, up to a day.
    pub seconds: u64,
}

/// Names that go to specific servers instead of the default upstreams.
#[derive(Debug, Serialize, ToSchema)]
pub struct ForwardZoneDto {
    pub id: String,
    /// Domains, or networks whose reverse lookups go to these servers.
    pub zones: Vec<String>,
    pub servers: Vec<String>,
    /// Shares queries between the servers, instead of using the first one that works.
    pub load_balance: bool,
    /// What's been seen from these servers since the node started. Empty until they're used.
    pub stats: Vec<UpstreamDto>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateForwardZone {
    pub zones: Vec<String>,
    pub servers: Vec<String>,
    #[serde(default)]
    pub load_balance: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateForwardZone {
    pub zones: Option<Vec<String>>,
    pub servers: Option<Vec<String>>,
    pub load_balance: Option<bool>,
}

/// A device seen on the network or asking this node.
#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkDeviceDto {
    /// Its MAC address, or its IP address if the MAC isn't known.
    pub id: String,
    pub mac: Option<String>,
    pub addresses: Vec<String>,
    pub hostname: Option<String>,
    /// Whether the kernel's neighbor table lists it right now.
    pub on_network: bool,
    pub last_active_at: Option<String>,
    pub first_seen_at: Option<String>,
    /// The named client this device counts as.
    pub client_id: Option<String>,
    pub client_name: Option<String>,
    pub groups: Vec<String>,
    /// Queries in the last 7 days, when they can be told apart from other devices'.
    pub query_count: Option<i64>,
    pub last_query_at: Option<String>,
    /// Whether it's over its query limit right now.
    pub rate_limited: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEventDto {
    pub id: String,
    pub occurred_at: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct OverviewParams {
    /// Start of the range, in UTC ISO 8601. Defaults to 24 hours ago.
    pub from: Option<String>,
    /// End of the range, in UTC ISO 8601. Defaults to now.
    pub to: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BucketDto {
    pub start: String,
    /// Answered queries, including those from the cache and local zones.
    pub forwarded: i64,
    pub blocked: i64,
    pub rejected: i64,
    pub failed: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CountDto {
    pub name: String,
    pub count: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OverviewDto {
    pub from: String,
    pub to: String,
    /// The length of each bucket, in seconds.
    pub bucket_seconds: i64,
    pub total: i64,
    /// Answered queries, including those from the cache and local zones.
    pub forwarded: i64,
    pub cached: i64,
    pub local: i64,
    pub blocked: i64,
    pub rejected: i64,
    pub failed: i64,
    pub average_latency_us: i64,
    pub buckets: Vec<BucketDto>,
    pub top_clients: Vec<CountDto>,
    pub top_blocked_domains: Vec<CountDto>,
    pub top_domains: Vec<CountDto>,
    pub query_log_mode: QueryLogModeDto,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct QueryParams {
    /// From the previous page's `next_cursor`.
    pub cursor: Option<String>,
    /// Page size, from 1 to 200.
    pub limit: Option<u32>,
    /// Matches anywhere in the query name.
    pub qname: Option<String>,
    /// A client ID or address.
    pub client: Option<String>,
    /// `forwarded`, `cached`, `local`, `blocked`, `rejected`, `rate_limited` or `failed`.
    pub action: Option<String>,
    pub qtype: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QueryClientDto {
    pub id: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QuestionDto {
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub record_type: String,
}

#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryAction {
    Forwarded,
    Cached,
    Local,
    Blocked,
    Rejected,
    Failed,
    RateLimited,
}

impl From<Outcome> for QueryAction {
    fn from(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Forwarded => Self::Forwarded,
            Outcome::Cached => Self::Cached,
            Outcome::Local => Self::Local,
            Outcome::Blocked => Self::Blocked,
            Outcome::Rejected => Self::Rejected,
            Outcome::Failed => Self::Failed,
            Outcome::RateLimited => Self::RateLimited,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DecisionDto {
    pub action: QueryAction,
    /// `rule`, `subscribed_list` or `none`.
    pub source: String,
    pub rule_id: Option<String>,
    pub rule_pattern: Option<String>,
    pub list_id: Option<String>,
    pub list_name: Option<String>,
    /// The name that matched, which differs from the question for a blocked CNAME target.
    pub matched_name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QueryEventDto {
    /// Unique within this node. Empty on live events that haven't been stored yet.
    pub id: String,
    pub occurred_at: String,
    pub client: QueryClientDto,
    pub question: QuestionDto,
    pub decision: DecisionDto,
    pub rcode: String,
    pub duration_us: u64,
    pub upstream: Option<String>,
    pub revision_id: Option<String>,
}

impl QueryEventDto {
    pub fn new(
        event: QueryEvent,
        rules: &HashMap<String, String>,
        lists: &HashMap<String, String>,
    ) -> Self {
        let source = if event.rule_id.is_some() {
            "rule"
        } else if event.source_list_id.is_some() {
            "subscribed_list"
        } else {
            "none"
        };
        Self {
            id: if event.seq > 0 {
                event.seq.to_string()
            } else {
                String::new()
            },
            occurred_at: to_iso(event.occurred_at_ms),
            client: QueryClientDto {
                id: event.client_id,
                address: event.client_ip,
            },
            question: QuestionDto {
                name: event.qname,
                record_type: event.qtype,
            },
            decision: DecisionDto {
                action: event.outcome.into(),
                source: source.to_owned(),
                rule_pattern: event.rule_id.as_ref().and_then(|id| rules.get(id).cloned()),
                list_name: event
                    .source_list_id
                    .as_ref()
                    .and_then(|id| lists.get(id).cloned()),
                rule_id: event.rule_id,
                list_id: event.source_list_id,
                matched_name: event.matched_name,
            },
            rcode: event.rcode,
            duration_us: event.duration_us,
            upstream: event.upstream,
            revision_id: event.revision_id,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PageInfo {
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QueryPageDto {
    pub data: Vec<QueryEventDto>,
    pub page: PageInfo,
}

/// A change to how the dashboard is reached, which undoes itself unless it's kept.
#[derive(Serialize, ToSchema)]
pub struct PendingNodeChange {
    pub seconds_left: u64,
}

/// The node's own settings, and how a change to them is going.
#[derive(Serialize, ToSchema)]
pub struct NodeSettingsView {
    /// The saved values, which the node uses from its next start.
    pub settings: crate::NodeSettings,
    /// The values from the command line and environment, without any changes from here.
    pub startup: crate::NodeSettings,
    /// Which settings differ from the startup values.
    pub changed: Vec<String>,
    /// Different each time the node starts.
    pub boot_id: String,
    pub pending: Option<PendingNodeChange>,
    /// Why the last change was undone.
    pub last_failure: Option<String>,
}

/// The result of saving the node's settings.
#[derive(Serialize, ToSchema)]
pub struct SaveNodeSettingsResponse {
    pub view: NodeSettingsView,
    /// Whether the node is restarting to use them.
    pub restarting: bool,
}
