//! What the controller's dashboard API sends and receives.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// A group of nodes that enforce the same policy.
#[derive(Debug, Serialize, ToSchema)]
pub struct SiteDto {
    pub id: String,
    pub name: String,
    pub created_at: String,
    /// Deploys changed list downloads by itself, without waiting for someone to press Deploy.
    pub auto_deploy_lists: bool,
    pub node_count: usize,
    pub nodes_online: usize,
    pub rule_count: usize,
    pub list_count: usize,
    /// The policy being edited has changes that haven't been deployed.
    pub has_undeployed_changes: bool,
    pub deployed_generation: Option<u64>,
    pub policy_revision: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSite {
    pub name: String,
    /// Start with a copy of this site's policy.
    pub copy_from: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSite {
    pub name: Option<String>,
    pub auto_deploy_lists: Option<bool>,
}

/// One upstream server, as a node last reported it.
#[derive(Debug, Serialize, ToSchema)]
pub struct NodeUpstreamDto {
    pub server: String,
    pub responses: u64,
    pub failures: u64,
    pub last_latency_us: u64,
}

/// A DNS node managed by this controller.
#[derive(Debug, Serialize, ToSchema)]
pub struct NodeDto {
    pub id: String,
    pub name: String,
    pub site_id: String,
    pub site_name: String,
    pub online: bool,
    pub enrolled_at: String,
    pub last_seen: Option<String>,
    pub version: String,
    pub applied_generation: u64,
    /// The generation it should reach. Nothing means no deployment applies to it yet.
    pub desired_generation: Option<u64>,
    pub policy_revision: String,
    pub uptime_seconds: u64,
    pub listeners: Vec<String>,
    pub blocking_paused: bool,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_entries: u64,
    pub cache_stale_served: u64,
    pub cache_prefetches: u64,
    pub upstreams: Vec<NodeUpstreamDto>,
    /// Queries in the last hour.
    pub queries_last_hour: i64,
    pub blocked_last_hour: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateNode {
    pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateEnrollmentToken {
    pub site_id: String,
    /// How long it can be used, from 1 minute to 7 days. An hour if not given.
    pub ttl_minutes: Option<u32>,
}

/// A token that lets one new node join. It's only shown once.
#[derive(Debug, Serialize, ToSchema)]
pub struct EnrollmentTokenCreated {
    pub id: String,
    pub token: String,
    pub expires_at: String,
    pub controller_url: String,
}

/// A token that hasn't been used yet. Its secret can't be shown again.
#[derive(Debug, Serialize, ToSchema)]
pub struct EnrollmentTokenDto {
    pub id: String,
    pub site_id: String,
    pub site_name: String,
    pub created_at: String,
    pub expires_at: String,
    pub created_by: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDeployment {
    pub site_id: String,
    /// `all` sends it to every node at once. `canary` tries it on one node first.
    pub strategy: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RollbackRequest {
    pub reason: Option<String>,
}

/// How far one node has got with a deployment.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeploymentNodeDto {
    pub node_id: String,
    pub node_name: String,
    pub online: bool,
    pub is_canary: bool,
    /// `pending`, `downloading`, `staged`, `activating`, `healthy`, `failed` or `reverted`.
    pub state: String,
    pub detail: Option<String>,
    pub updated_at: Option<String>,
}

/// A rollout of one bundle to one site.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeploymentDto {
    pub id: String,
    pub site_id: String,
    pub site_name: String,
    pub generation: u64,
    /// `policy`, `list_refresh` or `rollback`.
    pub kind: String,
    /// `all` or `canary`.
    pub strategy: String,
    /// `canary`, `rolling_out`, `succeeded`, `partially_failed`, `failed` or `superseded`.
    pub status: String,
    pub reason: String,
    pub created_by: String,
    pub created_at: String,
    pub rollback_of: Option<String>,
    pub policy_sha256: String,
    pub nodes: Vec<DeploymentNodeDto>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct DeploymentParams {
    pub site_id: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct FleetOverviewParams {
    /// How much history to include, up to 2,160 hours. An hour if not given.
    pub hours: Option<u32>,
}

/// Fleet query counts for a stretch of time.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct FleetBucketDto {
    pub start: String,
    pub answered: i64,
    pub blocked: i64,
    pub failed: i64,
}

/// One node's share of the fleet's queries.
#[derive(Debug, Serialize, ToSchema)]
pub struct FleetNodeCount {
    pub node_id: String,
    pub node_name: String,
    pub site_name: String,
    pub total: i64,
    pub blocked: i64,
    pub average_latency_us: i64,
}

/// The whole fleet at a glance. Query names and client addresses stay on each node.
#[derive(Debug, Serialize, ToSchema)]
pub struct FleetOverviewDto {
    pub site_count: usize,
    pub node_count: usize,
    pub nodes_online: usize,
    pub sites_with_undeployed_changes: usize,
    pub total: i64,
    pub answered: i64,
    pub cached: i64,
    pub stale: i64,
    pub blocked: i64,
    pub failed: i64,
    pub average_latency_us: i64,
    pub bucket_seconds: i64,
    pub buckets: Vec<FleetBucketDto>,
    pub by_node: Vec<FleetNodeCount>,
}

/// The controller itself.
#[derive(Debug, Serialize, ToSchema)]
pub struct ControllerInfo {
    pub version: String,
    pub url: String,
    /// The fingerprint of the key that signs bundles.
    pub signing_key: String,
    /// The SHA-256 of a self-signed certificate that nodes pin.
    pub tls_pin: Option<String>,
}
