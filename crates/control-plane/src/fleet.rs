//! The dashboard API for the fleet: sites, nodes, enrollment and deployments.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use dns_policy::PolicyDocument;
use fleet_contract::{EnrollmentToken, Manifest, ManifestFile, sha256_hex};
use node_api::{ApiError, ApiResult, AuthSession, Envelope, ErrorEnvelope, audit, now_ms, to_iso};
use serde_json::json;
use tracing::info;
use ulid::Ulid;

use crate::ControlState;
use crate::dto::{
    ControllerInfo, CreateDeployment, CreateEnrollmentToken, CreateSite, DeploymentDto,
    DeploymentNodeDto, DeploymentParams, EnrollmentTokenCreated, EnrollmentTokenDto,
    FleetBucketDto, FleetNodeCount, FleetOverviewDto, FleetOverviewParams, NodeDto,
    NodeUpstreamDto, RollbackRequest, SiteDto, UpdateNode, UpdateSite,
};
use crate::store::{Deployment, NewDeployment, Node, OFFLINE_AFTER_MS, PendingToken, Site};

const DEFAULT_TOKEN_MINUTES: u32 = 60;
const MAX_TOKEN_MINUTES: u32 = 7 * 24 * 60;
const MAX_NAME: usize = 100;
const DEPLOYMENT_HISTORY: i64 = 50;
const HOUR_MS: i64 = 3_600_000;
const MAX_OVERVIEW_HOURS: u32 = 90 * 24;

fn db_error(error: sqlx::Error) -> ApiError {
    ApiError::internal(error)
}

fn is_online(node: &Node, now: i64) -> bool {
    node.last_seen_ms
        .is_some_and(|seen| now - seen < OFFLINE_AFTER_MS)
}

fn clean_name(name: &str, what: &str) -> ApiResult<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(ApiError::invalid(
            "NAME_INVALID",
            format!("Give the {what} a name of at most {MAX_NAME} characters"),
        ));
    }
    Ok(name.to_owned())
}

fn site_not_found() -> ApiError {
    ApiError::not_found("That site")
}

// --- Controller ---

/// What this controller is, and what nodes check it by.
#[utoipa::path(get, path = "/api/v1/fleet/controller", responses(
    (status = 200, body = Envelope<ControllerInfo>), (status = 401, body = ErrorEnvelope),
))]
pub async fn controller_info(
    _auth: AuthSession,
    State(state): State<ControlState>,
) -> Json<Envelope<ControllerInfo>> {
    Json(Envelope::new(ControllerInfo {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        url: state.public_url.to_string(),
        signing_key: sha256_hex(state.signing.public_key().as_bytes()),
        tls_pin: state.tls_pin.as_deref().map(str::to_owned),
    }))
}

// --- Sites ---

async fn site_dto(
    state: &ControlState,
    site: &Site,
    nodes: &[Node],
    now: i64,
) -> ApiResult<SiteDto> {
    let handle = state.site_handle(&site.id).ok_or_else(site_not_found)?;
    let document = handle.manager.document();
    let revision = document_sha256(&document)?;
    let latest = state
        .store
        .latest_deployment(&site.id)
        .await
        .map_err(db_error)?;
    let deployed = match &latest {
        Some(deployment) => state
            .store
            .bundle(&deployment.bundle_id)
            .await
            .map_err(db_error)?,
        None => None,
    };
    let members: Vec<&Node> = nodes
        .iter()
        .filter(|node| node.site_id == site.id)
        .collect();
    Ok(SiteDto {
        id: site.id.clone(),
        name: site.name.clone(),
        created_at: to_iso(site.created_at_ms),
        auto_deploy_lists: site.auto_deploy_lists,
        node_count: members.len(),
        nodes_online: members.iter().filter(|node| is_online(node, now)).count(),
        rule_count: document.rules.len(),
        list_count: document.lists.len(),
        has_undeployed_changes: match &deployed {
            Some(bundle) => bundle.policy_sha256 != revision,
            // A site nobody has touched has nothing to deploy.
            None => document != PolicyDocument::default(),
        },
        deployed_generation: latest.map(|deployment| deployment.generation),
        policy_revision: revision,
    })
}

fn document_sha256(document: &PolicyDocument) -> ApiResult<String> {
    Ok(sha256_hex(
        document.to_toml().map_err(ApiError::internal)?.as_bytes(),
    ))
}

/// All sites.
#[utoipa::path(get, path = "/api/v1/fleet/sites", responses(
    (status = 200, body = Envelope<Vec<SiteDto>>), (status = 401, body = ErrorEnvelope),
))]
pub async fn list_sites(
    _auth: AuthSession,
    State(state): State<ControlState>,
) -> ApiResult<Json<Envelope<Vec<SiteDto>>>> {
    let now = now_ms();
    let nodes = state.store.nodes().await.map_err(db_error)?;
    let mut sites = Vec::new();
    for site in state.store.sites().await.map_err(db_error)? {
        sites.push(site_dto(&state, &site, &nodes, now).await?);
    }
    Ok(Json(Envelope::new(sites)))
}

/// Adds a site, optionally starting from a copy of another site's policy.
#[utoipa::path(post, path = "/api/v1/fleet/sites", request_body = CreateSite, responses(
    (status = 201, body = Envelope<SiteDto>),
    (status = 401, body = ErrorEnvelope),
    (status = 409, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn create_site(
    auth: AuthSession,
    State(state): State<ControlState>,
    Json(request): Json<CreateSite>,
) -> ApiResult<Response> {
    let name = clean_name(&request.name, "site")?;
    let sites = state.store.sites().await.map_err(db_error)?;
    if sites
        .iter()
        .any(|site| site.name.eq_ignore_ascii_case(&name))
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "SITE_EXISTS",
            "There's already a site with that name",
        ));
    }
    let source = request
        .copy_from
        .filter(|id| !id.is_empty())
        .map(|id| state.site_handle(&id).ok_or_else(site_not_found))
        .transpose()?;

    let site = Site {
        id: Ulid::generate().to_string(),
        name,
        created_at_ms: now_ms(),
        auto_deploy_lists: true,
    };
    let handle = state
        .start_site(&site.id)
        .await
        .map_err(ApiError::internal)?;
    if let Some(source) = source {
        crate::copy_policy(&source, &handle).await?;
    }
    state.store.create_site(&site).await.map_err(db_error)?;
    audit(
        &state.app,
        &auth.session.username,
        "site.create",
        &site.id,
        json!({"name": site.name}),
    )
    .await;
    let dto = site_dto(&state, &site, &[], now_ms()).await?;
    Ok((StatusCode::CREATED, Json(Envelope::new(dto))).into_response())
}

/// Renames a site, or changes how it deploys list updates.
#[utoipa::path(patch, path = "/api/v1/fleet/sites/{id}", params(("id" = String, Path)),
    request_body = UpdateSite, responses(
    (status = 200, body = Envelope<SiteDto>),
    (status = 401, body = ErrorEnvelope),
    (status = 404, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn update_site(
    auth: AuthSession,
    State(state): State<ControlState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateSite>,
) -> ApiResult<Json<Envelope<SiteDto>>> {
    let site = state
        .store
        .site(&id)
        .await
        .map_err(db_error)?
        .ok_or_else(site_not_found)?;
    let name = match request.name {
        Some(name) => clean_name(&name, "site")?,
        None => site.name.clone(),
    };
    let auto = request.auto_deploy_lists.unwrap_or(site.auto_deploy_lists);
    state
        .store
        .update_site(&id, &name, auto)
        .await
        .map_err(db_error)?;
    audit(
        &state.app,
        &auth.session.username,
        "site.update",
        &id,
        json!({"name": name, "auto_deploy_lists": auto}),
    )
    .await;
    let site = Site {
        name,
        auto_deploy_lists: auto,
        ..site
    };
    let nodes = state.store.nodes().await.map_err(db_error)?;
    Ok(Json(Envelope::new(
        site_dto(&state, &site, &nodes, now_ms()).await?,
    )))
}

/// Removes a site and its policy. A site with nodes can't be removed.
#[utoipa::path(delete, path = "/api/v1/fleet/sites/{id}", params(("id" = String, Path)), responses(
    (status = 204),
    (status = 401, body = ErrorEnvelope),
    (status = 404, body = ErrorEnvelope),
    (status = 409, body = ErrorEnvelope),
))]
pub async fn delete_site(
    auth: AuthSession,
    State(state): State<ControlState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let site = state
        .store
        .site(&id)
        .await
        .map_err(db_error)?
        .ok_or_else(site_not_found)?;
    if !state
        .store
        .site_nodes(&id)
        .await
        .map_err(db_error)?
        .is_empty()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "SITE_HAS_NODES",
            "This site still has nodes. Remove them first.",
        ));
    }
    state.store.delete_site(&id).await.map_err(db_error)?;
    state.stop_site(&id);
    audit(
        &state.app,
        &auth.session.username,
        "site.delete",
        &id,
        json!({"name": site.name}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// --- Nodes ---

#[derive(Default, serde::Deserialize)]
struct NodeReport {
    #[serde(default)]
    uptime_seconds: u64,
    #[serde(default)]
    listeners: Vec<String>,
    #[serde(default)]
    blocking_paused: bool,
    #[serde(default)]
    cache: Option<fleet_contract::CacheReport>,
    #[serde(default)]
    upstreams: Vec<fleet_contract::UpstreamReport>,
}

fn node_dto(
    node: Node,
    sites: &HashMap<String, String>,
    latest: &HashMap<String, Deployment>,
    counts: &HashMap<String, (i64, i64)>,
    now: i64,
) -> NodeDto {
    let report: NodeReport = serde_json::from_str(&node.report_json).unwrap_or_default();
    let cache = report.cache.unwrap_or_default();
    let (queries, blocked) = counts.get(&node.id).copied().unwrap_or((0, 0));
    NodeDto {
        online: is_online(&node, now),
        site_name: sites.get(&node.site_id).cloned().unwrap_or_default(),
        desired_generation: latest.get(&node.id).map(|deployment| deployment.generation),
        enrolled_at: to_iso(node.enrolled_at_ms),
        last_seen: node.last_seen_ms.map(to_iso),
        uptime_seconds: report.uptime_seconds,
        listeners: report.listeners,
        blocking_paused: report.blocking_paused,
        cache_hits: cache.hits,
        cache_misses: cache.misses,
        cache_entries: cache.entries,
        cache_stale_served: cache.stale_served,
        cache_prefetches: cache.prefetches,
        upstreams: report
            .upstreams
            .into_iter()
            .map(|upstream| NodeUpstreamDto {
                server: upstream.server,
                responses: upstream.responses,
                failures: upstream.failures,
                last_latency_us: upstream.last_latency_us,
            })
            .collect(),
        queries_last_hour: queries,
        blocked_last_hour: blocked,
        id: node.id,
        name: node.name,
        site_id: node.site_id,
        version: node.version,
        applied_generation: node.applied_generation,
        policy_revision: node.policy_revision,
    }
}

/// All nodes, and what they last reported.
#[utoipa::path(get, path = "/api/v1/fleet/nodes", responses(
    (status = 200, body = Envelope<Vec<NodeDto>>), (status = 401, body = ErrorEnvelope),
))]
pub async fn list_nodes(
    _auth: AuthSession,
    State(state): State<ControlState>,
) -> ApiResult<Json<Envelope<Vec<NodeDto>>>> {
    let now = now_ms();
    let sites: HashMap<String, String> = state
        .store
        .sites()
        .await
        .map_err(db_error)?
        .into_iter()
        .map(|site| (site.id, site.name))
        .collect();
    let nodes = state.store.nodes().await.map_err(db_error)?;

    let mut desired = HashMap::new();
    for node in &nodes {
        if let Some(deployment) = state.store.desired_bundle(node).await.map_err(db_error)? {
            desired.insert(node.id.clone(), deployment);
        }
    }
    let mut counts: HashMap<String, (i64, i64)> = HashMap::new();
    for row in state
        .store
        .rollups(now - HOUR_MS, now)
        .await
        .map_err(db_error)?
    {
        let entry = counts.entry(row.node_id).or_default();
        entry.0 += row.count;
        if row.outcome == "blocked" {
            entry.1 += row.count;
        }
    }
    Ok(Json(Envelope::new(
        nodes
            .into_iter()
            .map(|node| node_dto(node, &sites, &desired, &counts, now))
            .collect(),
    )))
}

/// Renames a node.
#[utoipa::path(patch, path = "/api/v1/fleet/nodes/{id}", params(("id" = String, Path)),
    request_body = UpdateNode, responses(
    (status = 204),
    (status = 401, body = ErrorEnvelope),
    (status = 404, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn update_node(
    auth: AuthSession,
    State(state): State<ControlState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateNode>,
) -> ApiResult<StatusCode> {
    let name = clean_name(&request.name, "node")?;
    if state.store.node(&id).await.map_err(db_error)?.is_none() {
        return Err(ApiError::not_found("That node"));
    }
    state
        .store
        .rename_node(&id, &name)
        .await
        .map_err(db_error)?;
    audit(
        &state.app,
        &auth.session.username,
        "node.rename",
        &id,
        json!({"name": name}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes a node. It stops being able to reach this controller, and keeps serving DNS with the
/// last policy it applied.
#[utoipa::path(delete, path = "/api/v1/fleet/nodes/{id}", params(("id" = String, Path)), responses(
    (status = 204), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope),
))]
pub async fn delete_node(
    auth: AuthSession,
    State(state): State<ControlState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let Some(node) = state.store.node(&id).await.map_err(db_error)? else {
        return Err(ApiError::not_found("That node"));
    };
    state.store.delete_node(&id).await.map_err(db_error)?;
    audit(
        &state.app,
        &auth.session.username,
        "node.remove",
        &id,
        json!({"name": node.name, "site_id": node.site_id}),
    )
    .await;
    // A deployment may have been waiting for this node.
    if let Some(latest) = state
        .store
        .latest_deployment(&node.site_id)
        .await
        .map_err(db_error)?
    {
        crate::nodes::refresh_status(&state.store, &latest)
            .await
            .map_err(db_error)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

// --- Enrollment ---

/// Tokens that haven't been used yet.
#[utoipa::path(get, path = "/api/v1/fleet/enrollment-tokens", responses(
    (status = 200, body = Envelope<Vec<EnrollmentTokenDto>>), (status = 401, body = ErrorEnvelope),
))]
pub async fn list_tokens(
    _auth: AuthSession,
    State(state): State<ControlState>,
) -> ApiResult<Json<Envelope<Vec<EnrollmentTokenDto>>>> {
    let sites: HashMap<String, String> = state
        .store
        .sites()
        .await
        .map_err(db_error)?
        .into_iter()
        .map(|site| (site.id, site.name))
        .collect();
    let tokens = state
        .store
        .pending_tokens(now_ms())
        .await
        .map_err(db_error)?;
    Ok(Json(Envelope::new(
        tokens
            .into_iter()
            .map(|token| EnrollmentTokenDto {
                id: token.id,
                site_name: sites.get(&token.site_id).cloned().unwrap_or_default(),
                site_id: token.site_id,
                created_at: to_iso(token.created_at_ms),
                expires_at: to_iso(token.expires_at_ms),
                created_by: token.created_by,
            })
            .collect(),
    )))
}

/// Creates a token that lets one new node join a site. It works once, and is only shown now.
#[utoipa::path(post, path = "/api/v1/fleet/enrollment-tokens", request_body = CreateEnrollmentToken,
    responses(
    (status = 201, body = Envelope<EnrollmentTokenCreated>),
    (status = 401, body = ErrorEnvelope),
    (status = 404, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn create_token(
    auth: AuthSession,
    State(state): State<ControlState>,
    Json(request): Json<CreateEnrollmentToken>,
) -> ApiResult<Response> {
    if state
        .store
        .site(&request.site_id)
        .await
        .map_err(db_error)?
        .is_none()
    {
        return Err(site_not_found());
    }
    let minutes = request.ttl_minutes.unwrap_or(DEFAULT_TOKEN_MINUTES);
    if !(1..=MAX_TOKEN_MINUTES).contains(&minutes) {
        return Err(ApiError::invalid(
            "TTL_INVALID",
            "A token can last from 1 minute to 7 days",
        ));
    }
    let secret_bytes: [u8; 32] = rand::random();
    let secret: String = secret_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let now = now_ms();
    let pending = PendingToken {
        id: Ulid::generate().to_string(),
        site_id: request.site_id,
        created_at_ms: now,
        expires_at_ms: now + i64::from(minutes) * 60_000,
        created_by: auth.session.username.clone(),
    };
    state
        .store
        .create_token(&pending, &sha256_hex(secret.as_bytes()))
        .await
        .map_err(db_error)?;
    let token = EnrollmentToken {
        url: state.public_url.to_string(),
        secret,
        controller_key: state.signing.public_key(),
        tls_pin: state.tls_pin.as_deref().map(str::to_owned),
    };
    audit(
        &state.app,
        &auth.session.username,
        "enrollment_token.create",
        &pending.id,
        json!({"site_id": pending.site_id, "minutes": minutes}),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(Envelope::new(EnrollmentTokenCreated {
            id: pending.id,
            token: token.encode(),
            expires_at: to_iso(pending.expires_at_ms),
            controller_url: state.public_url.to_string(),
        })),
    )
        .into_response())
}

/// Cancels a token that hasn't been used.
#[utoipa::path(delete, path = "/api/v1/fleet/enrollment-tokens/{id}", params(("id" = String, Path)),
    responses(
    (status = 204), (status = 401, body = ErrorEnvelope), (status = 404, body = ErrorEnvelope),
))]
pub async fn delete_token(
    auth: AuthSession,
    State(state): State<ControlState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !state.store.delete_token(&id).await.map_err(db_error)? {
        return Err(ApiError::not_found("That token"));
    }
    audit(
        &state.app,
        &auth.session.username,
        "enrollment_token.delete",
        &id,
        json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// --- Deployments ---

/// What goes in a bundle.
pub(crate) struct BundleContents {
    pub policy: Vec<u8>,
    pub lists: Vec<Vec<u8>>,
}

/// Reads a site's policy and its lists as they stand now.
async fn current_contents(state: &ControlState, site_id: &str) -> ApiResult<BundleContents> {
    let handle = state.site_handle(site_id).ok_or_else(site_not_found)?;
    let manager = Arc::clone(&handle.manager);
    tokio::task::spawn_blocking(move || {
        let document = manager.document();
        let policy = document.to_toml().map_err(ApiError::internal)?.into_bytes();
        let store = manager.artifacts();
        let mut lists = Vec::new();
        for list in &document.lists {
            if !list.enabled {
                continue;
            }
            if let Some(sha256) = &list.artifact_sha256 {
                let content = store
                    .as_ref()
                    .and_then(|store| store.get(sha256).ok())
                    .ok_or_else(|| {
                        ApiError::new(
                            StatusCode::CONFLICT,
                            "LIST_UNAVAILABLE",
                            format!(
                                "The source {} hasn't been downloaded yet. Refresh it, then deploy.",
                                list.name.as_deref().unwrap_or(&list.id)
                            ),
                        )
                    })?;
                lists.push(content);
            }
        }
        Ok::<_, ApiError>(BundleContents { policy, lists })
    })
    .await
    .map_err(ApiError::internal)?
}

/// Signs and stores a bundle, and makes it the site's newest deployment.
pub(crate) async fn publish(
    state: &ControlState,
    site_id: &str,
    contents: BundleContents,
    options: PublishOptions<'_>,
) -> ApiResult<Deployment> {
    let content_store = state.content.clone();
    let BundleContents { policy, lists } = contents;
    let (policy_file, list_files) = tokio::task::spawn_blocking(move || {
        let policy_file = ManifestFile {
            sha256: content_store.put(&policy)?,
            size: policy.len() as u64,
        };
        let mut list_files = Vec::with_capacity(lists.len());
        for list in &lists {
            list_files.push(ManifestFile {
                sha256: content_store.put(list)?,
                size: list.len() as u64,
            });
        }
        Ok::<_, std::io::Error>((policy_file, list_files))
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;

    let now = now_ms();
    let generation = state
        .store
        .next_generation(site_id)
        .await
        .map_err(db_error)?;
    let bundle_id = Ulid::generate().to_string();
    let manifest = serde_json::to_string(&Manifest {
        bundle_id: bundle_id.clone(),
        site_id: site_id.to_owned(),
        generation,
        policy_schema_version: dns_policy::SCHEMA_VERSION,
        policy: policy_file.clone(),
        lists: list_files.clone(),
        created_at_ms: now,
        issuer: sha256_hex(state.signing.public_key().as_bytes()),
    })
    .map_err(ApiError::internal)?;
    let signature = state.signing.sign_manifest(&manifest);
    let files: Vec<String> = std::iter::once(policy_file.sha256.clone())
        .chain(list_files.into_iter().map(|file| file.sha256))
        .collect();

    let canary = if options.strategy == "canary" {
        let nodes = state.store.site_nodes(site_id).await.map_err(db_error)?;
        // A node that's online can give an answer soon.
        nodes
            .iter()
            .find(|node| is_online(node, now))
            .or(nodes.first())
            .map(|node| node.id.clone())
    } else {
        None
    };
    let deployment_id = Ulid::generate().to_string();
    state
        .store
        .create_deployment(&NewDeployment {
            site_id,
            bundle_id: &bundle_id,
            manifest: &manifest,
            signature: &signature,
            policy_sha256: &policy_file.sha256,
            files: &files,
            generation,
            created_at_ms: now,
            deployment_id: &deployment_id,
            kind: options.kind,
            // Without a node to try it on, there's nothing to wait for.
            strategy: if canary.is_some() { "canary" } else { "all" },
            canary_node_id: canary.as_deref(),
            reason: options.reason,
            created_by: options.actor,
            rollback_of: options.rollback_of,
        })
        .await
        .map_err(db_error)?;
    info!(
        site = site_id,
        generation,
        kind = options.kind,
        "created a deployment"
    );
    state
        .store
        .deployment(&deployment_id)
        .await
        .map_err(db_error)?
        .ok_or_else(|| ApiError::not_found("That deployment"))
}

pub(crate) struct PublishOptions<'a> {
    pub kind: &'a str,
    pub strategy: &'a str,
    pub reason: &'a str,
    pub actor: &'a str,
    pub rollback_of: Option<&'a str>,
}

async fn deployment_dto(
    state: &ControlState,
    deployment: Deployment,
    now: i64,
) -> ApiResult<DeploymentDto> {
    let site = state
        .store
        .site(&deployment.site_id)
        .await
        .map_err(db_error)?;
    let bundle = state
        .store
        .bundle(&deployment.bundle_id)
        .await
        .map_err(db_error)?;
    let progress: HashMap<String, crate::store::NodeProgress> = state
        .store
        .progress(&deployment.id)
        .await
        .map_err(db_error)?
        .into_iter()
        .map(|item| (item.node_id.clone(), item))
        .collect();
    let nodes = state
        .store
        .site_nodes(&deployment.site_id)
        .await
        .map_err(db_error)?;
    let nodes = nodes
        .into_iter()
        .map(|node| {
            let entry = progress.get(&node.id);
            let is_canary = deployment.canary_node_id.as_deref() == Some(node.id.as_str());
            // A node already at or past this generation got here without reporting this one.
            let state_name = match entry {
                Some(entry) => entry.state.clone(),
                None if node.applied_generation >= deployment.generation => "healthy".to_owned(),
                None => "pending".to_owned(),
            };
            DeploymentNodeDto {
                online: is_online(&node, now),
                is_canary,
                state: state_name,
                detail: entry.and_then(|entry| entry.detail.clone()),
                updated_at: entry.map(|entry| to_iso(entry.updated_at_ms)),
                node_id: node.id,
                node_name: node.name,
            }
        })
        .collect();
    Ok(DeploymentDto {
        site_name: site.map(|site| site.name).unwrap_or_default(),
        created_at: to_iso(deployment.created_at_ms),
        policy_sha256: bundle
            .map(|bundle| bundle.policy_sha256)
            .unwrap_or_default(),
        nodes,
        id: deployment.id,
        site_id: deployment.site_id,
        generation: deployment.generation,
        kind: deployment.kind,
        strategy: deployment.strategy,
        status: deployment.status,
        reason: deployment.reason,
        created_by: deployment.created_by,
        rollback_of: deployment.rollback_of,
    })
}

/// Deploys a site's current policy on the controller's own initiative.
pub(crate) async fn deploy_current(
    state: &ControlState,
    site_id: &str,
    kind: &str,
    reason: &str,
    actor: &str,
) -> ApiResult<Deployment> {
    let contents = current_contents(state, site_id).await?;
    let deployment = publish(
        state,
        site_id,
        contents,
        PublishOptions {
            kind,
            strategy: "all",
            reason,
            actor,
            rollback_of: None,
        },
    )
    .await?;
    audit(
        &state.app,
        actor,
        "deployment.create",
        &deployment.id,
        json!({"site_id": site_id, "generation": deployment.generation, "kind": kind}),
    )
    .await;
    Ok(deployment)
}

/// Recent deployments, newest first, and how far each node has got.
#[utoipa::path(get, path = "/api/v1/fleet/deployments", params(DeploymentParams), responses(
    (status = 200, body = Envelope<Vec<DeploymentDto>>), (status = 401, body = ErrorEnvelope),
))]
pub async fn list_deployments(
    _auth: AuthSession,
    State(state): State<ControlState>,
    Query(params): Query<DeploymentParams>,
) -> ApiResult<Json<Envelope<Vec<DeploymentDto>>>> {
    let now = now_ms();
    let deployments = state
        .store
        .deployments(params.site_id.as_deref(), DEPLOYMENT_HISTORY)
        .await
        .map_err(db_error)?;
    let mut items = Vec::with_capacity(deployments.len());
    for deployment in deployments {
        items.push(deployment_dto(&state, deployment, now).await?);
    }
    Ok(Json(Envelope::new(items)))
}

/// One deployment.
#[utoipa::path(get, path = "/api/v1/fleet/deployments/{id}", params(("id" = String, Path)), responses(
    (status = 200, body = Envelope<DeploymentDto>),
    (status = 401, body = ErrorEnvelope),
    (status = 404, body = ErrorEnvelope),
))]
pub async fn get_deployment(
    _auth: AuthSession,
    State(state): State<ControlState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Envelope<DeploymentDto>>> {
    let deployment = state
        .store
        .deployment(&id)
        .await
        .map_err(db_error)?
        .ok_or_else(|| ApiError::not_found("That deployment"))?;
    Ok(Json(Envelope::new(
        deployment_dto(&state, deployment, now_ms()).await?,
    )))
}

/// Sends a site's current policy to its nodes.
#[utoipa::path(post, path = "/api/v1/fleet/deployments", request_body = CreateDeployment, responses(
    (status = 201, body = Envelope<DeploymentDto>),
    (status = 401, body = ErrorEnvelope),
    (status = 404, body = ErrorEnvelope),
    (status = 409, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn create_deployment(
    auth: AuthSession,
    State(state): State<ControlState>,
    Json(request): Json<CreateDeployment>,
) -> ApiResult<Response> {
    if state
        .store
        .site(&request.site_id)
        .await
        .map_err(db_error)?
        .is_none()
    {
        return Err(site_not_found());
    }
    let strategy = request.strategy.as_deref().unwrap_or("all");
    if !matches!(strategy, "all" | "canary") {
        return Err(ApiError::invalid(
            "STRATEGY_INVALID",
            "Choose all or canary",
        ));
    }
    let contents = current_contents(&state, &request.site_id).await?;
    let reason = request.reason.unwrap_or_default();
    let deployment = publish(
        &state,
        &request.site_id,
        contents,
        PublishOptions {
            kind: "policy",
            strategy,
            reason: &reason,
            actor: &auth.session.username,
            rollback_of: None,
        },
    )
    .await?;
    audit(
        &state.app,
        &auth.session.username,
        "deployment.create",
        &deployment.id,
        json!({"site_id": request.site_id, "generation": deployment.generation, "strategy": strategy, "reason": reason}),
    )
    .await;
    let dto = deployment_dto(&state, deployment, now_ms()).await?;
    Ok((StatusCode::CREATED, Json(Envelope::new(dto))).into_response())
}

/// Lets a canary's deployment go to every node, without waiting for the canary to report back.
#[utoipa::path(post, path = "/api/v1/fleet/deployments/{id}/promote", params(("id" = String, Path)),
    responses(
    (status = 200, body = Envelope<DeploymentDto>),
    (status = 401, body = ErrorEnvelope),
    (status = 404, body = ErrorEnvelope),
    (status = 409, body = ErrorEnvelope),
))]
pub async fn promote_deployment(
    auth: AuthSession,
    State(state): State<ControlState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Envelope<DeploymentDto>>> {
    let deployment = state
        .store
        .deployment(&id)
        .await
        .map_err(db_error)?
        .ok_or_else(|| ApiError::not_found("That deployment"))?;
    if deployment.status != "canary" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "NOT_A_CANARY",
            "This deployment isn't waiting on a canary",
        ));
    }
    state
        .store
        .set_deployment_status(&id, "rolling_out")
        .await
        .map_err(db_error)?;
    audit(
        &state.app,
        &auth.session.username,
        "deployment.promote",
        &id,
        json!({}),
    )
    .await;
    let updated = state
        .store
        .deployment(&id)
        .await
        .map_err(db_error)?
        .ok_or_else(|| ApiError::not_found("That deployment"))?;
    Ok(Json(Envelope::new(
        deployment_dto(&state, updated, now_ms()).await?,
    )))
}

/// Sends a site back to what a deployment contained, as a new, higher generation.
///
/// The policy being edited isn't changed, so it then shows as having undeployed changes.
#[utoipa::path(post, path = "/api/v1/fleet/deployments/{id}/rollback", params(("id" = String, Path)),
    request_body = RollbackRequest, responses(
    (status = 201, body = Envelope<DeploymentDto>),
    (status = 401, body = ErrorEnvelope),
    (status = 404, body = ErrorEnvelope),
))]
pub async fn rollback_deployment(
    auth: AuthSession,
    State(state): State<ControlState>,
    Path(id): Path<String>,
    Json(request): Json<RollbackRequest>,
) -> ApiResult<Response> {
    let target = state
        .store
        .deployment(&id)
        .await
        .map_err(db_error)?
        .ok_or_else(|| ApiError::not_found("That deployment"))?;
    let bundle = state
        .store
        .bundle(&target.bundle_id)
        .await
        .map_err(db_error)?
        .ok_or_else(|| ApiError::not_found("That deployment's bundle"))?;
    let manifest: Manifest = serde_json::from_str(&bundle.manifest).map_err(ApiError::internal)?;

    let content = state.content.clone();
    let contents = tokio::task::spawn_blocking(move || {
        let policy = content.get(&manifest.policy.sha256)?;
        let lists = manifest
            .lists
            .iter()
            .map(|file| content.get(&file.sha256))
            .collect::<Result<Vec<_>, _>>()?;
        Ok::<_, std::io::Error>(BundleContents { policy, lists })
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;

    let reason = request
        .reason
        .unwrap_or_else(|| format!("Back to generation {}", target.generation));
    let deployment = publish(
        &state,
        &target.site_id,
        contents,
        PublishOptions {
            kind: "rollback",
            strategy: "all",
            reason: &reason,
            actor: &auth.session.username,
            rollback_of: Some(&target.id),
        },
    )
    .await?;
    audit(
        &state.app,
        &auth.session.username,
        "deployment.rollback",
        &deployment.id,
        json!({"site_id": target.site_id, "generation": deployment.generation, "to_generation": target.generation}),
    )
    .await;
    let dto = deployment_dto(&state, deployment, now_ms()).await?;
    Ok((StatusCode::CREATED, Json(Envelope::new(dto))).into_response())
}

// --- Overview ---

fn fleet_bucket_ms(span_ms: i64) -> i64 {
    if span_ms <= 2 * HOUR_MS {
        60_000
    } else if span_ms <= 24 * HOUR_MS {
        300_000
    } else if span_ms <= 7 * 24 * HOUR_MS {
        HOUR_MS
    } else {
        6 * HOUR_MS
    }
}

/// The fleet's health and query counts. All of it comes from what nodes report, and names and
/// client addresses stay on each node.
#[utoipa::path(get, path = "/api/v1/fleet/overview", params(FleetOverviewParams), responses(
    (status = 200, body = Envelope<FleetOverviewDto>),
    (status = 401, body = ErrorEnvelope),
))]
pub async fn fleet_overview(
    _auth: AuthSession,
    State(state): State<ControlState>,
    Query(params): Query<FleetOverviewParams>,
) -> ApiResult<Json<Envelope<FleetOverviewDto>>> {
    let hours = params.hours.unwrap_or(1).clamp(1, MAX_OVERVIEW_HOURS);
    let now = now_ms();
    let span = i64::from(hours) * HOUR_MS;
    let bucket_ms = fleet_bucket_ms(span);
    let first_bucket = (now - span) - (now - span) % bucket_ms;

    let sites = state.store.sites().await.map_err(db_error)?;
    let nodes = state.store.nodes().await.map_err(db_error)?;
    let mut undeployed = 0;
    for site in &sites {
        if site_dto(&state, site, &nodes, now)
            .await?
            .has_undeployed_changes
        {
            undeployed += 1;
        }
    }

    let bucket_count = usize::try_from((now - first_bucket) / bucket_ms + 1).unwrap_or(1);
    let mut buckets: Vec<FleetBucketDto> = (0..bucket_count)
        .map(|index| FleetBucketDto {
            start: to_iso(first_bucket + i64::try_from(index).unwrap_or(0) * bucket_ms),
            ..FleetBucketDto::default()
        })
        .collect();
    let (mut answered, mut cached, mut stale, mut blocked, mut failed, mut total) =
        (0, 0, 0, 0, 0, 0);
    let mut latency_sum = 0_i64;
    let mut latency_count = 0_i64;
    let mut per_node: HashMap<String, (i64, i64, i64, i64)> = HashMap::new();
    for row in state
        .store
        .rollups(first_bucket, now)
        .await
        .map_err(db_error)?
    {
        let index = usize::try_from((row.bucket_start_ms - first_bucket) / bucket_ms).unwrap_or(0);
        let bucket = buckets.get_mut(index);
        total += row.count;
        let entry = per_node.entry(row.node_id).or_default();
        entry.0 += row.count;
        match row.outcome.as_str() {
            "blocked" => {
                blocked += row.count;
                entry.1 += row.count;
                if let Some(bucket) = bucket {
                    bucket.blocked += row.count;
                }
            }
            "failed" | "rejected" | "rate_limited" => {
                failed += row.count;
                if let Some(bucket) = bucket {
                    bucket.failed += row.count;
                }
            }
            outcome => {
                answered += row.count;
                match outcome {
                    "cached" => cached += row.count,
                    "stale" => stale += row.count,
                    _ => {}
                }
                if let Some(bucket) = bucket {
                    bucket.answered += row.count;
                }
            }
        }
        latency_sum += row.latency_sum_us;
        latency_count += row.count;
        entry.2 += row.latency_sum_us;
        entry.3 += row.count;
    }

    let site_names: HashMap<&str, &str> = sites
        .iter()
        .map(|site| (site.id.as_str(), site.name.as_str()))
        .collect();
    let mut by_node: Vec<FleetNodeCount> = nodes
        .iter()
        .map(|node| {
            let (count, blocked, latency, samples) =
                per_node.get(&node.id).copied().unwrap_or_default();
            FleetNodeCount {
                node_id: node.id.clone(),
                node_name: node.name.clone(),
                site_name: site_names
                    .get(node.site_id.as_str())
                    .copied()
                    .unwrap_or_default()
                    .to_owned(),
                total: count,
                blocked,
                average_latency_us: latency.checked_div(samples).unwrap_or(0),
            }
        })
        .collect();
    by_node.sort_by(|left, right| {
        right
            .total
            .cmp(&left.total)
            .then_with(|| left.node_name.cmp(&right.node_name))
    });

    Ok(Json(Envelope::new(FleetOverviewDto {
        site_count: sites.len(),
        node_count: nodes.len(),
        nodes_online: nodes.iter().filter(|node| is_online(node, now)).count(),
        sites_with_undeployed_changes: undeployed,
        total,
        answered,
        cached,
        stale,
        blocked,
        failed,
        average_latency_us: latency_sum.checked_div(latency_count).unwrap_or(0),
        bucket_seconds: bucket_ms / 1000,
        buckets,
        by_node,
    })))
}
