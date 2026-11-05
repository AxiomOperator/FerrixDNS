//! What nodes call. Every request except enrolling is signed by the node's own key.

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use fleet_contract::{
    Ack, AckState, DesiredBundle, EnrollRequest, EnrollResponse, Heartbeat, HeartbeatResponse,
    MAX_CLOCK_SKEW_MS, NODE_HEADER, SIGNATURE_HEADER, SignedBundle, TIME_HEADER, sha256_hex,
    verify_enrollment, verify_request,
};
use node_api::{ApiError, ApiResult, audit, now_ms};
use serde_json::json;
use tracing::{info, warn};
use ulid::Ulid;

use crate::ControlState;
use crate::store::{Deployment, HeartbeatUpdate, Node, Store};

/// The most rows of query counts accepted in one report.
const MAX_ROLLUP_ROWS: usize = 20_000;
const MAX_FIELD: usize = 200;
/// Query counts are accepted for minutes this far back, and a little way ahead for clock drift.
const MAX_ROLLUP_AGE_MS: i64 = 90 * 24 * 60 * 60 * 1000;
const MAX_ROLLUP_AHEAD_MS: i64 = 60 * 60 * 1000;

fn db_error(error: sqlx::Error) -> ApiError {
    ApiError::internal(error)
}

fn unauthorized() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "NODE_NOT_RECOGNIZED",
        "This request isn't signed by a node this controller knows",
    )
}

/// Checks who sent a request. The signature covers its method, path, time and body.
async fn authenticate(
    state: &ControlState,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> ApiResult<Node> {
    let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    let node_id = text(NODE_HEADER).ok_or_else(unauthorized)?;
    let time: i64 = text(TIME_HEADER)
        .and_then(|value| value.parse().ok())
        .ok_or_else(unauthorized)?;
    let signature = text(SIGNATURE_HEADER).ok_or_else(unauthorized)?;
    if (now_ms() - time).abs() > MAX_CLOCK_SKEW_MS {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "CLOCK_SKEW",
            "This node's clock is more than 5 minutes from the controller's",
        ));
    }
    let node = state
        .store
        .node(node_id)
        .await
        .map_err(db_error)?
        .ok_or_else(unauthorized)?;
    let path = uri
        .path_and_query()
        .map_or(uri.path(), |path| path.as_str());
    if !verify_request(
        &node.public_key,
        method.as_str(),
        path,
        time,
        body,
        signature,
    ) {
        return Err(unauthorized());
    }
    Ok(node)
}

/// Lets a new node join, in exchange for a token that only works once.
pub async fn enroll(
    State(state): State<ControlState>,
    Json(request): Json<EnrollRequest>,
) -> ApiResult<Json<EnrollResponse>> {
    let refused = || {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "ENROLLMENT_REFUSED",
            "This enrollment token isn't valid. It may have expired or been used already.",
        )
    };
    if !verify_enrollment(&request.public_key, &request.secret, &request.proof) {
        return Err(refused());
    }
    let name: String = request.name.trim().chars().take(MAX_FIELD).collect();
    let now = now_ms();
    let node = Node {
        id: Ulid::generate().to_string(),
        site_id: String::new(),
        name: if name.is_empty() {
            "New node".to_owned()
        } else {
            name
        },
        public_key: request.public_key,
        enrolled_at_ms: now,
        last_seen_ms: None,
        version: request.version.chars().take(MAX_FIELD).collect(),
        applied_generation: 0,
        policy_revision: String::new(),
        report_json: "{}".to_owned(),
        rollups_stored_through_ms: 0,
    };
    let secret_hash = sha256_hex(request.secret.as_bytes());
    let site_id = state
        .store
        .enroll(&secret_hash, now, &node)
        .await
        .map_err(|error| match &error {
            // The same key can't join twice.
            sqlx::Error::Database(database) if database.is_unique_violation() => refused(),
            _ => db_error(error),
        })?
        .ok_or_else(refused)?;
    info!(node = %node.id, site = %site_id, "a node joined");
    audit(
        &state.app,
        "controller",
        "node.enroll",
        &node.id,
        json!({"name": node.name, "site_id": site_id}),
    )
    .await;
    Ok(Json(EnrollResponse {
        node_id: node.id,
        site_id,
    }))
}

/// Records what a node reports, and tells it what it should be running.
pub async fn heartbeat(
    State(state): State<ControlState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<HeartbeatResponse>> {
    let node = authenticate(&state, &headers, &method, &uri, &body).await?;
    let report: Heartbeat = serde_json::from_slice(&body)
        .map_err(|error| ApiError::invalid("REPORT_INVALID", error.to_string()))?;
    if report.rollups.len() > MAX_ROLLUP_ROWS {
        return Err(ApiError::invalid("REPORT_INVALID", "Too many query counts"));
    }
    let now = now_ms();
    let rollups: Vec<_> = report
        .rollups
        .iter()
        .filter(|row| {
            row.count >= 0
                && row.latency_sum_us >= 0
                && row.outcome.len() <= MAX_FIELD
                && row.bucket_start_ms >= now - MAX_ROLLUP_AGE_MS
                && row.bucket_start_ms <= now + MAX_ROLLUP_AHEAD_MS
        })
        .cloned()
        .collect();
    // The node's whole report, minus the counts stored separately, for the dashboard.
    let report_json = json!({
        "uptime_seconds": report.uptime_seconds,
        "listeners": report.listeners,
        "blocking_paused": report.blocking_paused,
        "cache": report.cache,
        "upstreams": report.upstreams,
    })
    .to_string();
    let version: String = report.version.chars().take(MAX_FIELD).collect();
    let revision: String = report.policy_revision.chars().take(MAX_FIELD).collect();
    let stored_through = state
        .store
        .record_heartbeat(
            &node,
            &HeartbeatUpdate {
                now_ms: now,
                version: &version,
                applied_generation: report.applied_generation,
                policy_revision: &revision,
                report_json: &report_json,
                rollups: &rollups,
            },
        )
        .await
        .map_err(db_error)?;

    let desired = state.store.desired_bundle(&node).await.map_err(db_error)?;
    if let Some(deployment) = &desired
        && report.applied_generation >= deployment.generation
    {
        // An acknowledgement can be lost, but a report of what's applied says the same thing.
        note_applied(&state.store, &node, deployment, now)
            .await
            .map_err(db_error)?;
    }
    Ok(Json(HeartbeatResponse {
        desired: desired.map(|deployment| DesiredBundle {
            bundle_id: deployment.bundle_id,
            generation: deployment.generation,
        }),
        rollups_stored_through_ms: stored_through,
    }))
}

async fn note_applied(
    store: &Store,
    node: &Node,
    deployment: &Deployment,
    now: i64,
) -> Result<(), sqlx::Error> {
    let progress = store.progress(&deployment.id).await?;
    let recorded = progress
        .iter()
        .find(|item| item.node_id == node.id)
        .is_some_and(|item| item.state == "healthy");
    if !recorded {
        store
            .record_progress(&deployment.id, &node.id, "healthy", None, now)
            .await?;
        refresh_status(store, deployment).await?;
    }
    Ok(())
}

/// Hands over a bundle's exact signed bytes.
pub async fn get_bundle(
    State(state): State<ControlState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<SignedBundle>> {
    let node = authenticate(&state, &headers, &method, &uri, &[]).await?;
    let bundle = state
        .store
        .bundle(&id)
        .await
        .map_err(db_error)?
        .filter(|bundle| bundle.site_id == node.site_id)
        .ok_or_else(|| ApiError::not_found("That bundle"))?;
    Ok(Json(SignedBundle {
        manifest: bundle.manifest,
        signature: bundle.signature,
    }))
}

/// Hands over a file, if one of this node's site's bundles includes it.
pub async fn get_artifact(
    State(state): State<ControlState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(sha256): Path<String>,
) -> ApiResult<Response> {
    let node = authenticate(&state, &headers, &method, &uri, &[]).await?;
    if !state
        .store
        .site_may_read(&node.site_id, &sha256)
        .await
        .map_err(db_error)?
    {
        return Err(ApiError::not_found("That file"));
    }
    let content = state.content.clone();
    let bytes = tokio::task::spawn_blocking(move || content.get(&sha256))
        .await
        .map_err(ApiError::internal)?
        .map_err(|error| {
            warn!(%error, "a stored file can't be read");
            ApiError::not_found("That file")
        })?;
    Ok((
        [(CONTENT_TYPE, "application/octet-stream")],
        Body::from(bytes),
    )
        .into_response())
}

/// Records how far a node has got with a bundle. Sending the same news twice changes nothing.
pub async fn ack_bundle(
    State(state): State<ControlState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let node = authenticate(&state, &headers, &method, &uri, &body).await?;
    let ack: Ack = serde_json::from_slice(&body)
        .map_err(|error| ApiError::invalid("ACK_INVALID", error.to_string()))?;
    let deployment = state
        .store
        .deployment_for_bundle(&id)
        .await
        .map_err(db_error)?
        .filter(|deployment| deployment.site_id == node.site_id)
        .ok_or_else(|| ApiError::not_found("That bundle"))?;
    let detail: Option<String> = ack.detail.map(|detail| detail.chars().take(2000).collect());
    let now = now_ms();
    state
        .store
        .record_progress(
            &deployment.id,
            &node.id,
            ack.state.as_str(),
            detail.as_deref(),
            now,
        )
        .await
        .map_err(db_error)?;
    if ack.state == AckState::Healthy {
        state
            .store
            .note_applied_generation(
                &node.id,
                deployment.generation,
                ack.policy_revision.as_deref(),
            )
            .await
            .map_err(db_error)?;
    }
    if matches!(ack.state, AckState::Failed | AckState::Reverted) {
        warn!(
            node = %node.id,
            generation = deployment.generation,
            state = ack.state.as_str(),
            "a node couldn't apply a bundle"
        );
        audit(
            &state.app,
            "controller",
            "deployment.node_problem",
            &deployment.id,
            json!({"node": node.name, "state": ack.state.as_str(), "detail": detail}),
        )
        .await;
    }
    if matches!(
        ack.state,
        AckState::Healthy | AckState::Failed | AckState::Reverted
    ) {
        refresh_status(&state.store, &deployment)
            .await
            .map_err(db_error)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Works out where a deployment stands from what its nodes have said.
pub(crate) async fn refresh_status(
    store: &Store,
    deployment: &Deployment,
) -> Result<(), sqlx::Error> {
    // Read it again, because it may have moved on since the caller looked.
    let Some(current) = store.deployment(&deployment.id).await? else {
        return Ok(());
    };
    if current.status == "superseded" {
        return Ok(());
    }
    let progress = store.progress(&current.id).await?;
    let state_of = |node_id: &str| {
        progress
            .iter()
            .find(|item| item.node_id == node_id)
            .map(|item| item.state.as_str())
    };

    if current.status == "canary" {
        let Some(canary) = current.canary_node_id.as_deref() else {
            return Ok(());
        };
        let next = match state_of(canary) {
            Some("healthy") => Some("rolling_out"),
            Some("failed" | "reverted") => Some("failed"),
            _ => None,
        };
        if let Some(next) = next {
            store.set_deployment_status(&current.id, next).await?;
        }
        return Ok(());
    }
    if current.status == "failed" && current.strategy == "canary" {
        return Ok(());
    }

    let nodes = store.site_nodes(&current.site_id).await?;
    if nodes.is_empty() {
        return Ok(());
    }
    let (mut healthy, mut bad, mut waiting) = (0, 0, 0);
    for node in &nodes {
        match state_of(&node.id) {
            Some("healthy") => healthy += 1,
            Some("failed" | "reverted") => bad += 1,
            _ if node.applied_generation >= current.generation => healthy += 1,
            _ => waiting += 1,
        }
    }
    let status = match (waiting, bad, healthy) {
        (0, 0, _) => "succeeded",
        (0, _, 0) => "failed",
        (0, _, _) => "partially_failed",
        _ => "rolling_out",
    };
    if status != current.status {
        store.set_deployment_status(&current.id, status).await?;
    }
    Ok(())
}
