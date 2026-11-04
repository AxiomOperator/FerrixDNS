//! HTTP handlers. Each one is documented for the OpenAPI contract.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::node_settings::{
    CONFIRM_WITHIN, NodeControl, NodeSettings, ParsedSettings, SettingsStoreError,
    check_data_folder,
};
use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::header::{ETAG, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive};
use axum::response::{IntoResponse, Response, Sse};
use dns_policy::{
    Action, ClientDef, ClientSource, DecisionSource, DomainName, ForwardZoneDef, GroupDef, ListDef,
    PolicyDocument, QueryLogMode, RuleDef, Scope,
};
use dns_runtime::DeviceInfo;
use dns_runtime::MutationError;
use dns_storage::{AuditEvent, NetworkDevice, sha256_hex};
use dns_telemetry::{QueryFilter, Telemetry};
use dns_upstreams::UpstreamRequest;
use futures_util::{Stream, StreamExt};
use hickory_proto::op::Query as DnsQuery;
use hickory_proto::rr::{Name, RecordType};
use tokio_stream::wrappers::BroadcastStream;
use tracing::warn;
use ulid::Ulid;

use crate::AppState;
use crate::auth::{
    AuthSession, MIN_PASSWORD_LENGTH, SESSION_LIFETIME, check_origin, expired_session_cookie,
    random_token, session_cookie,
};
use crate::dto::*;
use crate::error::{ApiError, ErrorEnvelope};
use crate::refresh::spawn_refresh;
use crate::util::{from_iso, normalize_expiry, now_ms, to_iso};

const MAX_NAME_LENGTH: usize = 100;
const RESTART_DELAY: Duration = Duration::from_millis(300);
const MIN_LIST_REFRESH_SECONDS: u64 = 300;
const CLIENT_ACTIVITY_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1000;

type ApiResult<T> = Result<T, ApiError>;

/// Applies a policy change off the async runtime.
async fn mutate<T, F>(state: &AppState, change: F) -> ApiResult<(T, String)>
where
    T: Send + 'static,
    F: FnOnce(&mut PolicyDocument) -> Result<T, ApiError> + Send + 'static,
{
    let manager = Arc::clone(&state.manager);
    tokio::task::spawn_blocking(move || manager.mutate(change))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::from)
}

/// Records an action. A failure here is logged, because the change has already happened.
async fn audit(
    state: &AppState,
    actor: &str,
    action: &str,
    target: &str,
    details: serde_json::Value,
) {
    let event = AuditEvent {
        id: Ulid::generate().to_string(),
        occurred_at_ms: now_ms(),
        actor: actor.to_owned(),
        action: action.to_owned(),
        target: target.to_owned(),
        details_json: details.to_string(),
    };
    if let Err(error) = state.db.add_audit_event(&event).await {
        warn!(%error, action, "failed to record an audit event");
    }
}

fn telemetry(state: &AppState) -> ApiResult<&Arc<Telemetry>> {
    state
        .telemetry
        .as_ref()
        .ok_or_else(ApiError::telemetry_unavailable)
}

fn set_cookie(headers: &mut HeaderMap, value: &str) -> ApiResult<()> {
    let value = value.parse().map_err(ApiError::internal)?;
    headers.insert(SET_COOKIE, value);
    Ok(())
}

// --- Health ---

/// Process liveness, with no private details.
#[utoipa::path(get, path = "/api/v1/health/live", responses((status = 200, body = Health)))]
pub async fn health_live() -> Json<Health> {
    Json(Health {
        status: "ok".to_owned(),
    })
}

/// DNS and policy readiness.
#[utoipa::path(get, path = "/api/v1/health/ready",
    responses((status = 200, body = Readiness), (status = 401, body = ErrorEnvelope)))]
pub async fn health_ready(_auth: AuthSession, State(state): State<AppState>) -> Json<Readiness> {
    Json(Readiness {
        status: "ok".to_owned(),
        policy_revision: state.manager.handle().load().revision().to_owned(),
        telemetry_available: state.telemetry.is_some(),
    })
}

// --- Authentication ---

/// Whether first-run setup is still needed.
#[utoipa::path(get, path = "/api/v1/auth/status", responses((status = 200, body = AuthStatus)))]
pub async fn auth_status(State(state): State<AppState>) -> ApiResult<Json<AuthStatus>> {
    Ok(Json(AuthStatus {
        setup_required: state.db.user_count().await? == 0,
    }))
}

fn validate_new_password(password: &str) -> ApiResult<()> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(ApiError::invalid(
            "PASSWORD_TOO_SHORT",
            format!("Use at least {MIN_PASSWORD_LENGTH} characters"),
        ));
    }
    Ok(())
}

async fn start_session(
    state: &AppState,
    user_id: &str,
    username: &str,
) -> ApiResult<(HeaderMap, SessionInfo)> {
    let token = random_token();
    let csrf_token = random_token();
    let now = now_ms();
    let lifetime = i64::try_from(SESSION_LIFETIME.as_millis()).map_err(ApiError::internal)?;
    let expires_at_ms = now + lifetime;
    state
        .db
        .create_session(
            &sha256_hex(token.as_bytes()),
            user_id,
            &csrf_token,
            now,
            expires_at_ms,
        )
        .await?;
    // Sign-ins are a natural, infrequent moment to clear out old sessions.
    state.db.delete_expired_sessions(now).await?;

    let mut headers = HeaderMap::new();
    set_cookie(&mut headers, &session_cookie(&token, state.secure_cookies))?;
    Ok((
        headers,
        SessionInfo {
            username: username.to_owned(),
            csrf_token,
            expires_at: to_iso(expires_at_ms),
            policy_read_only: state.manager.is_read_only(),
        },
    ))
}

/// Creates the first administrator using the one-time token from the node's log.
#[utoipa::path(post, path = "/api/v1/auth/setup", request_body = SetupRequest, responses(
    (status = 201, body = Envelope<SessionInfo>),
    (status = 403, body = ErrorEnvelope),
    (status = 409, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn auth_setup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<SetupRequest>,
) -> ApiResult<Response> {
    check_origin(&headers, &state.hosts)?;
    state.login_guard.check(peer.ip())?;
    if state.db.user_count().await? > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "SETUP_COMPLETE",
            "An administrator already exists",
        ));
    }
    let provided = sha256_hex(request.token.trim().as_bytes());
    let expected = state.setup_token_hash();
    if expected.as_deref() != Some(provided.as_str()) {
        state.login_guard.record_failure(peer.ip());
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "SETUP_TOKEN_INVALID",
            "That setup token isn't valid. The node prints the current one in its log.",
        ));
    }
    let username = request.username.trim().to_owned();
    if username.is_empty() || username.len() > MAX_NAME_LENGTH {
        return Err(ApiError::invalid("USERNAME_INVALID", "Enter a username"));
    }
    validate_new_password(&request.password)?;

    let hash = state.passwords.hash(request.password).await?;
    let id = Ulid::generate().to_string();
    if !state
        .db
        .create_first_user(&id, &username, &hash, now_ms())
        .await?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "SETUP_COMPLETE",
            "An administrator already exists",
        ));
    }
    state.clear_setup_token();
    state.login_guard.record_success(peer.ip());
    audit(
        &state,
        &username,
        "auth.setup",
        &username,
        serde_json::json!({}),
    )
    .await;

    let (cookie, session) = start_session(&state, &id, &username).await?;
    Ok((StatusCode::CREATED, cookie, Json(Envelope::new(session))).into_response())
}

/// Signs in and sets the session cookie.
#[utoipa::path(post, path = "/api/v1/auth/login", request_body = LoginRequest, responses(
    (status = 200, body = Envelope<SessionInfo>),
    (status = 401, body = ErrorEnvelope),
    (status = 429, body = ErrorEnvelope),
))]
pub async fn auth_login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Response> {
    check_origin(&headers, &state.hosts)?;
    state.login_guard.check(peer.ip())?;

    let user = state.db.find_user(request.username.trim()).await?;
    let hash = user.as_ref().map(|user| user.password_hash.clone());
    if !state.passwords.verify(request.password, hash).await? {
        state.login_guard.record_failure(peer.ip());
        audit(
            &state,
            request.username.trim(),
            "auth.login_failed",
            &peer.ip().to_string(),
            serde_json::json!({}),
        )
        .await;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "INVALID_CREDENTIALS",
            "That username or password isn't right",
        ));
    }
    state.login_guard.record_success(peer.ip());
    let user = user.ok_or_else(|| ApiError::internal("verified a password with no user"))?;
    let (cookie, session) = start_session(&state, &user.id, &user.username).await?;
    Ok((cookie, Json(Envelope::new(session))).into_response())
}

/// Ends this session.
#[utoipa::path(post, path = "/api/v1/auth/logout",
    responses((status = 204), (status = 401, body = ErrorEnvelope)))]
pub async fn auth_logout(auth: AuthSession, State(state): State<AppState>) -> ApiResult<Response> {
    state.db.delete_session(&auth.token_hash).await?;
    let mut headers = HeaderMap::new();
    set_cookie(&mut headers, &expired_session_cookie(state.secure_cookies))?;
    Ok((StatusCode::NO_CONTENT, headers).into_response())
}

/// The signed-in user, and the CSRF token for changing requests.
#[utoipa::path(get, path = "/api/v1/auth/session",
    responses((status = 200, body = Envelope<SessionInfo>), (status = 401, body = ErrorEnvelope)))]
pub async fn auth_session(
    auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<SessionInfo>> {
    Json(Envelope::new(SessionInfo {
        username: auth.session.username,
        csrf_token: auth.session.csrf_token,
        expires_at: to_iso(auth.session.expires_at_ms),
        policy_read_only: state.manager.is_read_only(),
    }))
}

/// Changes the password and ends every session, including this one.
#[utoipa::path(post, path = "/api/v1/auth/password", request_body = ChangePasswordRequest, responses(
    (status = 204), (status = 401, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope),
))]
pub async fn auth_password(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<ChangePasswordRequest>,
) -> ApiResult<Response> {
    validate_new_password(&request.new_password)?;
    let user = state
        .db
        .find_user(&auth.session.username)
        .await?
        .ok_or_else(ApiError::unauthenticated)?;
    if !state
        .passwords
        .verify(request.current_password, Some(user.password_hash))
        .await?
    {
        return Err(ApiError::invalid(
            "INVALID_CREDENTIALS",
            "Your current password isn't right",
        ));
    }
    let hash = state.passwords.hash(request.new_password).await?;
    state.db.set_password(&user.username, &hash).await?;
    audit(
        &state,
        &user.username,
        "auth.password_changed",
        &user.username,
        serde_json::json!({}),
    )
    .await;
    let mut headers = HeaderMap::new();
    set_cookie(&mut headers, &expired_session_cookie(state.secure_cookies))?;
    Ok((StatusCode::NO_CONTENT, headers).into_response())
}

// --- Overview and queries ---

/// Counters and rate buckets for a time range.
#[utoipa::path(get, path = "/api/v1/overview", params(OverviewParams), responses(
    (status = 200, body = Envelope<OverviewDto>),
    (status = 401, body = ErrorEnvelope),
    (status = 503, body = ErrorEnvelope),
))]
pub async fn overview(
    _auth: AuthSession,
    State(state): State<AppState>,
    Query(params): Query<OverviewParams>,
) -> ApiResult<Json<Envelope<OverviewDto>>> {
    let now = now_ms();
    let parse = |value: &Option<String>, fallback: i64| match value {
        Some(value) => from_iso(value).ok_or_else(|| {
            ApiError::invalid(
                "TIME_INVALID",
                "Use a UTC time such as 2026-12-01T00:00:00Z",
            )
        }),
        None => Ok(fallback),
    };
    let to = parse(&params.to, now)?;
    let from = parse(&params.from, now - 24 * 60 * 60 * 1000)?;
    if from >= to {
        return Err(ApiError::invalid(
            "TIME_INVALID",
            "The range must start before it ends",
        ));
    }
    let overview = telemetry(&state)?
        .overview(from, to)
        .await
        .map_err(ApiError::internal)?;
    let counts = |items: Vec<(String, i64)>| {
        items
            .into_iter()
            .map(|(name, count)| CountDto { name, count })
            .collect()
    };
    Ok(Json(Envelope::new(OverviewDto {
        from: to_iso(overview.from_ms),
        to: to_iso(overview.to_ms),
        bucket_seconds: overview.bucket_ms / 1000,
        total: overview.total,
        forwarded: overview.forwarded,
        cached: overview.cached,
        local: overview.local,
        blocked: overview.blocked,
        rejected: overview.rejected,
        failed: overview.failed,
        average_latency_us: overview.average_latency_us,
        buckets: overview
            .buckets
            .into_iter()
            .map(|bucket| BucketDto {
                start: to_iso(bucket.start_ms),
                forwarded: bucket.forwarded,
                blocked: bucket.blocked,
                rejected: bucket.rejected,
                failed: bucket.failed,
            })
            .collect(),
        top_clients: counts(
            overview
                .top_clients
                .into_iter()
                .map(|client| (client.client, client.count))
                .collect(),
        ),
        top_blocked_domains: counts(
            overview
                .top_blocked_domains
                .into_iter()
                .map(|domain| (domain.domain, domain.count))
                .collect(),
        ),
        top_domains: counts(
            overview
                .top_domains
                .into_iter()
                .map(|domain| (domain.domain, domain.count))
                .collect(),
        ),
        query_log_mode: state.manager.handle().load().telemetry().mode.into(),
    })))
}

/// Labels for rule and list IDs, so the UI can explain decisions.
fn policy_labels(document: &PolicyDocument) -> (HashMap<String, String>, HashMap<String, String>) {
    let rules = document
        .rules
        .iter()
        .map(|rule| (rule.id.clone(), rule.pattern.clone()))
        .collect();
    let lists = document
        .lists
        .iter()
        .map(|list| {
            (
                list.id.clone(),
                list.name.clone().unwrap_or_else(|| list.id.clone()),
            )
        })
        .collect();
    (rules, lists)
}

/// A page of the query log, newest first.
#[utoipa::path(get, path = "/api/v1/queries", params(QueryParams), responses(
    (status = 200, body = QueryPageDto),
    (status = 401, body = ErrorEnvelope),
    (status = 503, body = ErrorEnvelope),
))]
pub async fn queries(
    _auth: AuthSession,
    State(state): State<AppState>,
    Query(params): Query<QueryParams>,
) -> ApiResult<Json<QueryPageDto>> {
    let time = |value: Option<String>| {
        value
            .map(|value| {
                from_iso(&value).ok_or_else(|| {
                    ApiError::invalid(
                        "TIME_INVALID",
                        "Use a UTC time such as 2026-12-01T00:00:00Z",
                    )
                })
            })
            .transpose()
    };
    let before_seq = params
        .cursor
        .map(|cursor| {
            cursor
                .parse()
                .map_err(|_| ApiError::invalid("CURSOR_INVALID", "That page cursor isn't valid"))
        })
        .transpose()?;
    let not_empty = |value: Option<String>| value.filter(|value| !value.is_empty());
    let filter = QueryFilter {
        before_seq,
        limit: params.limit.unwrap_or(50),
        qname: not_empty(params.qname).map(|name| name.to_ascii_lowercase()),
        client: not_empty(params.client),
        outcome: not_empty(params.action),
        qtype: not_empty(params.qtype).map(|qtype| qtype.to_ascii_uppercase()),
        from_ms: time(params.from)?,
        to_ms: time(params.to)?,
    };
    let page = telemetry(&state)?.query_log(&filter).await;
    let (rules, lists) = policy_labels(&state.manager.document());
    Ok(Json(QueryPageDto {
        page: PageInfo {
            has_more: page.next_before_seq.is_some(),
            next_cursor: page.next_before_seq.map(|seq| seq.to_string()),
        },
        data: page
            .events
            .into_iter()
            .map(|event| QueryEventDto::new(event, &rules, &lists))
            .collect(),
    }))
}

/// Live query events as server-sent events. Each `data` is a `QueryEventDto`.
#[utoipa::path(get, path = "/api/v1/queries/stream", responses(
    (status = 200, content_type = "text/event-stream", body = QueryEventDto),
    (status = 401, body = ErrorEnvelope),
    (status = 503, body = ErrorEnvelope),
))]
pub async fn queries_stream(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let receiver = telemetry(&state)?.subscribe();
    let manager = Arc::clone(&state.manager);
    let stream = BroadcastStream::new(receiver).filter_map(move |item| {
        let manager = Arc::clone(&manager);
        async move {
            // A slow client misses events, and it can refresh to catch up.
            let event = item.ok()?;
            let (rules, lists) = policy_labels(&manager.document());
            let dto = QueryEventDto::new(event, &rules, &lists);
            Some(Ok(Event::default().event("query").json_data(dto).ok()?))
        }
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

// --- Rules ---

/// All rules.
#[utoipa::path(get, path = "/api/v1/rules",
    responses((status = 200, body = Envelope<Vec<RuleDto>>), (status = 401, body = ErrorEnvelope)))]
pub async fn list_rules(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<Vec<RuleDto>>> {
    let document = state.manager.document();
    Json(Envelope::new(
        document.rules.iter().map(RuleDto::from).collect(),
    ))
}

fn invalid_scope() -> ApiError {
    ApiError::invalid("RULE_INVALID", "Choose who this rule applies to")
}

fn validate_rule_shape(
    pattern: &str,
    action: dns_policy::RuleAction,
    emergency: bool,
) -> ApiResult<()> {
    if pattern.trim().is_empty() {
        return Err(ApiError::invalid(
            "RULE_INVALID",
            "Enter a domain or pattern",
        ));
    }
    if emergency && action != dns_policy::RuleAction::Deny {
        return Err(ApiError::invalid(
            "RULE_INVALID",
            "Only deny rules can be emergency rules",
        ));
    }
    Ok(())
}

fn not_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

/// Creates a rule. On success it's already active on this node.
#[utoipa::path(post, path = "/api/v1/rules", request_body = CreateRule, responses(
    (status = 201, body = Envelope<RuleDto>),
    (status = 401, body = ErrorEnvelope),
    (status = 409, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn create_rule(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<CreateRule>,
) -> ApiResult<Response> {
    let action = dns_policy::RuleAction::from(request.action);
    validate_rule_shape(&request.pattern, action, request.emergency)?;
    let scope = request.scope.into_scope().ok_or_else(invalid_scope)?;
    let now = to_iso(now_ms());
    let rule = RuleDef {
        id: Ulid::generate().to_string(),
        action,
        match_type: request.match_type.into(),
        pattern: request.pattern.trim().to_owned(),
        scope,
        emergency: request.emergency,
        enabled: request.enabled,
        expires_at: normalize_expiry(request.expires_at)?,
        reason: not_empty(request.reason),
        revision: 1,
        created_at: Some(now.clone()),
        updated_at: Some(now),
    };
    let stored = rule.clone();
    mutate(&state, move |document| {
        document.rules.push(stored);
        Ok(())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "rule.create",
        &rule.id,
        serde_json::json!({"pattern": rule.pattern, "reason": rule.reason}),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        [(ETAG, format!("\"{}\"", rule.revision))],
        Json(Envelope::new(RuleDto::from(&rule))),
    )
        .into_response())
}

/// One rule.
#[utoipa::path(get, path = "/api/v1/rules/{id}", params(("id" = String, Path)), responses(
    (status = 200, body = Envelope<RuleDto>),
    (status = 401, body = ErrorEnvelope),
    (status = 404, body = ErrorEnvelope),
))]
pub async fn get_rule(
    _auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let document = state.manager.document();
    let rule = document
        .rules
        .iter()
        .find(|rule| rule.id == id)
        .ok_or_else(|| ApiError::not_found("That rule"))?;
    Ok((
        [(ETAG, format!("\"{}\"", rule.revision))],
        Json(Envelope::new(RuleDto::from(rule))),
    )
        .into_response())
}

/// The revision a request expects, from `If-Match`, which is required to change a rule.
fn expected_revision(headers: &HeaderMap) -> ApiResult<u64> {
    headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().trim_matches('"').parse().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::PRECONDITION_REQUIRED,
                "PRECONDITION_REQUIRED",
                "Send the rule's revision in If-Match",
            )
        })
}

fn stale_write() -> ApiError {
    ApiError::new(
        StatusCode::PRECONDITION_FAILED,
        "STALE_WRITE",
        "This rule changed since you loaded it. Reload and try again.",
    )
}

/// Changes a rule. Stale writes are rejected using `If-Match`.
#[utoipa::path(patch, path = "/api/v1/rules/{id}", params(("id" = String, Path)), request_body = UpdateRule, responses(
    (status = 200, body = Envelope<RuleDto>),
    (status = 404, body = ErrorEnvelope),
    (status = 412, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
    (status = 428, body = ErrorEnvelope),
))]
pub async fn update_rule(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpdateRule>,
) -> ApiResult<Response> {
    let expected = expected_revision(&headers)?;
    let expires_at = request
        .expires_at
        .map(|value| normalize_expiry(Some(value)))
        .transpose()?;
    let scope = request
        .scope
        .map(|scope| scope.into_scope().ok_or_else(invalid_scope))
        .transpose()?;
    let rule_id = id.clone();
    let now = to_iso(now_ms());
    let (rule, _) = mutate(&state, move |document| {
        let rule = document
            .rules
            .iter_mut()
            .find(|rule| rule.id == rule_id)
            .ok_or_else(|| ApiError::not_found("That rule"))?;
        if rule.revision != expected {
            return Err(stale_write());
        }
        if let Some(action) = request.action {
            rule.action = action.into();
        }
        if let Some(match_type) = request.match_type {
            rule.match_type = match_type.into();
        }
        if let Some(pattern) = request.pattern {
            rule.pattern = pattern.trim().to_owned();
        }
        if let Some(scope) = scope {
            rule.scope = scope;
        }
        if let Some(emergency) = request.emergency {
            rule.emergency = emergency;
        }
        if let Some(enabled) = request.enabled {
            rule.enabled = enabled;
        }
        if let Some(expires_at) = expires_at {
            rule.expires_at = expires_at;
        }
        if let Some(reason) = request.reason {
            rule.reason = not_empty(Some(reason));
        }
        validate_rule_shape(&rule.pattern, rule.action, rule.emergency)?;
        rule.revision += 1;
        rule.updated_at = Some(now);
        Ok(rule.clone())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "rule.update",
        &id,
        serde_json::json!({"pattern": rule.pattern, "enabled": rule.enabled}),
    )
    .await;
    Ok((
        [(ETAG, format!("\"{}\"", rule.revision))],
        Json(Envelope::new(RuleDto::from(&rule))),
    )
        .into_response())
}

/// Deletes a rule. Stale writes are rejected using `If-Match`.
#[utoipa::path(delete, path = "/api/v1/rules/{id}", params(("id" = String, Path)), responses(
    (status = 204),
    (status = 404, body = ErrorEnvelope),
    (status = 412, body = ErrorEnvelope),
    (status = 428, body = ErrorEnvelope),
))]
pub async fn delete_rule(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let expected = expected_revision(&headers)?;
    let rule_id = id.clone();
    let (pattern, _) = mutate(&state, move |document| {
        let position = document
            .rules
            .iter()
            .position(|rule| rule.id == rule_id)
            .ok_or_else(|| ApiError::not_found("That rule"))?;
        if document.rules[position].revision != expected {
            return Err(stale_write());
        }
        Ok(document.rules.remove(position).pattern)
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "rule.delete",
        &id,
        serde_json::json!({"pattern": pattern}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

fn tier_name(tier: dns_policy::Tier) -> &'static str {
    use dns_policy::Tier;
    match tier {
        Tier::EmergencyDeny => "emergency_deny",
        Tier::ExactAllow => "exact_allow",
        Tier::SuffixAllow => "suffix_allow",
        Tier::RegexAllow => "regex_allow",
        Tier::ExactDeny => "exact_deny",
        Tier::SuffixDeny => "suffix_deny",
        Tier::SubscribedAllow => "subscribed_allow",
        Tier::SubscribedDeny => "subscribed_deny",
        Tier::RegexDeny => "regex_deny",
        Tier::DefaultAllow => "default_allow",
    }
}

fn scope_name(scope: dns_policy::ScopeLevel) -> &'static str {
    use dns_policy::ScopeLevel;
    match scope {
        ScopeLevel::Client => "client",
        ScopeLevel::Group => "group",
        ScopeLevel::Site => "site",
        ScopeLevel::Global => "global",
    }
}

/// Explains what the active policy would decide for a domain and client.
#[utoipa::path(post, path = "/api/v1/rules/test", request_body = TestRuleRequest, responses(
    (status = 200, body = Envelope<TestRuleResponse>),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn test_rule(
    _auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<TestRuleRequest>,
) -> ApiResult<Json<Envelope<TestRuleResponse>>> {
    let name = DomainName::parse(request.domain.trim())
        .map_err(|error| ApiError::invalid("DOMAIN_INVALID", error.to_string()))?;
    let source = match not_empty(request.client_ip) {
        Some(value) => value
            .trim()
            .parse()
            .map_err(|_| ApiError::invalid("ADDRESS_INVALID", "Enter a valid IP address"))?,
        // No client has this address, so only site and global rules apply.
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };

    let (rules, lists) = policy_labels(&state.manager.document());
    let policy = state.manager.handle().load_full();
    let device = state.services.devices.get(source.to_canonical());
    let caller = device_source(source, device.as_deref());
    let decision = policy.explain(caller, &name);
    let (rule_id, list_id) = match decision.source {
        DecisionSource::Rule(id) => (Some(id.to_owned()), None),
        DecisionSource::List(id) => (None, Some(id.to_owned())),
        DecisionSource::Default => (None, None),
    };
    Ok(Json(Envelope::new(TestRuleResponse {
        domain: request.domain,
        normalized_domain: name.as_str().to_owned(),
        action: match decision.action {
            Action::Allow => ActionDto::Allow,
            Action::Deny => ActionDto::Deny,
        },
        tier: tier_name(decision.tier).to_owned(),
        scope: decision.scope.map(|scope| scope_name(scope).to_owned()),
        rule_pattern: rule_id.as_ref().and_then(|id| rules.get(id).cloned()),
        list_name: list_id.as_ref().and_then(|id| lists.get(id).cloned()),
        rule_id,
        list_id,
        client_id: policy
            .identity(caller)
            .map(|identity| identity.id.to_string()),
        revision: policy.revision().to_owned(),
    })))
}

// --- Lists ---

/// All lists and their download status.
#[utoipa::path(get, path = "/api/v1/lists",
    responses((status = 200, body = Envelope<Vec<ListDto>>), (status = 401, body = ErrorEnvelope)))]
pub async fn list_lists(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> ApiResult<Json<Envelope<Vec<ListDto>>>> {
    let statuses = state.db.list_statuses().await?;
    let document = state.manager.document();
    Ok(Json(Envelope::new(
        document
            .lists
            .iter()
            .map(|list| {
                ListDto::new(
                    list,
                    statuses.iter().find(|status| status.list_id == list.id),
                )
            })
            .collect(),
    )))
}

fn validate_refresh(seconds: u64) -> ApiResult<()> {
    if seconds < MIN_LIST_REFRESH_SECONDS {
        return Err(ApiError::invalid(
            "LIST_INVALID",
            format!("Refresh lists at most every {MIN_LIST_REFRESH_SECONDS} seconds"),
        ));
    }
    Ok(())
}

/// Adds a subscribed list and starts downloading it.
#[utoipa::path(post, path = "/api/v1/lists", request_body = CreateList, responses(
    (status = 202, body = Envelope<ListDto>),
    (status = 409, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn create_list(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<CreateList>,
) -> ApiResult<Response> {
    let name = request.name.trim().to_owned();
    if name.is_empty() || name.len() > MAX_NAME_LENGTH {
        return Err(ApiError::invalid(
            "LIST_INVALID",
            "Enter a name for this list",
        ));
    }
    let url = request.url.trim().to_owned();
    state
        .fetcher
        .validate_url(&url)
        .map_err(|error| ApiError::invalid("LIST_URL_INVALID", error.to_string()))?;
    validate_refresh(request.refresh_seconds)?;

    let list = ListDef {
        id: Ulid::generate().to_string(),
        name: Some(name),
        action: request.action.into(),
        enabled: true,
        url: Some(url.clone()),
        format: Some(request.format.into()),
        refresh_seconds: request.refresh_seconds,
        artifact_sha256: None,
        groups: request.groups,
        domains: vec![],
        suffixes: vec![],
    };
    let stored = list.clone();
    mutate(&state, move |document| {
        if document
            .lists
            .iter()
            .any(|list| list.url.as_deref() == Some(url.as_str()))
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "LIST_EXISTS",
                "A list with that URL already exists",
            ));
        }
        document.lists.push(stored);
        Ok(())
    })
    .await?;
    spawn_refresh(&state, &list.id);
    audit(
        &state,
        &auth.session.username,
        "list.create",
        &list.id,
        serde_json::json!({"url": list.url}),
    )
    .await;
    Ok((
        StatusCode::ACCEPTED,
        Json(Envelope::new(ListDto::new(&list, None))),
    )
        .into_response())
}

/// One list.
#[utoipa::path(get, path = "/api/v1/lists/{id}", params(("id" = String, Path)), responses(
    (status = 200, body = Envelope<ListDto>), (status = 404, body = ErrorEnvelope),
))]
pub async fn get_list(
    _auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Envelope<ListDto>>> {
    let status = state.db.list_status(&id).await?;
    let document = state.manager.document();
    let list = document
        .lists
        .iter()
        .find(|list| list.id == id)
        .ok_or_else(|| ApiError::not_found("That list"))?;
    Ok(Json(Envelope::new(ListDto::new(list, status.as_ref()))))
}

/// Changes a list's settings.
#[utoipa::path(patch, path = "/api/v1/lists/{id}", params(("id" = String, Path)), request_body = UpdateList, responses(
    (status = 200, body = Envelope<ListDto>),
    (status = 404, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn update_list(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateList>,
) -> ApiResult<Json<Envelope<ListDto>>> {
    if let Some(seconds) = request.refresh_seconds {
        validate_refresh(seconds)?;
    }
    let list_id = id.clone();
    let (list, _) = mutate(&state, move |document| {
        let list = document
            .lists
            .iter_mut()
            .find(|list| list.id == list_id)
            .ok_or_else(|| ApiError::not_found("That list"))?;
        if let Some(name) = request.name {
            list.name = not_empty(Some(name));
        }
        if let Some(enabled) = request.enabled {
            list.enabled = enabled;
        }
        if let Some(groups) = request.groups {
            list.groups = groups;
        }
        if let Some(seconds) = request.refresh_seconds {
            list.refresh_seconds = seconds;
        }
        Ok(list.clone())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "list.update",
        &id,
        serde_json::json!({"enabled": list.enabled}),
    )
    .await;
    let status = state.db.list_status(&id).await?;
    Ok(Json(Envelope::new(ListDto::new(&list, status.as_ref()))))
}

/// Removes a list. Its entries stop applying immediately.
#[utoipa::path(delete, path = "/api/v1/lists/{id}", params(("id" = String, Path)), responses(
    (status = 204), (status = 404, body = ErrorEnvelope),
))]
pub async fn delete_list(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let list_id = id.clone();
    mutate(&state, move |document| {
        let position = document
            .lists
            .iter()
            .position(|list| list.id == list_id)
            .ok_or_else(|| ApiError::not_found("That list"))?;
        document.lists.remove(position);
        Ok(())
    })
    .await?;
    state.db.delete_list_status(&id).await?;
    audit(
        &state,
        &auth.session.username,
        "list.delete",
        &id,
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Starts downloading a list now.
#[utoipa::path(post, path = "/api/v1/lists/{id}/refresh", params(("id" = String, Path)), responses(
    (status = 202, body = Envelope<JobDto>), (status = 404, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope),
))]
pub async fn refresh_list(
    _auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let document = state.manager.document();
    let list = document
        .lists
        .iter()
        .find(|list| list.id == id)
        .ok_or_else(|| ApiError::not_found("That list"))?;
    if list.url.is_none() {
        return Err(ApiError::invalid(
            "LIST_NOT_DOWNLOADED",
            "This list has no URL to download",
        ));
    }
    let job = spawn_refresh(&state, &id);
    Ok((StatusCode::ACCEPTED, Json(Envelope::new(job))).into_response())
}

/// The progress of a background job.
#[utoipa::path(get, path = "/api/v1/jobs/{id}", params(("id" = String, Path)), responses(
    (status = 200, body = Envelope<JobDto>), (status = 404, body = ErrorEnvelope),
))]
pub async fn get_job(
    _auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Envelope<JobDto>>> {
    let job = state
        .jobs
        .get(&id)
        .ok_or_else(|| ApiError::not_found("That job"))?;
    Ok(Json(Envelope::new(job)))
}

// --- Clients ---

/// Named clients, plus addresses seen in recent queries that haven't been named.
#[utoipa::path(get, path = "/api/v1/clients",
    responses((status = 200, body = Envelope<Vec<ClientDto>>), (status = 401, body = ErrorEnvelope)))]
pub async fn list_clients(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> ApiResult<Json<Envelope<Vec<ClientDto>>>> {
    let activity = match &state.telemetry {
        Some(telemetry) => telemetry
            .client_activity(now_ms() - CLIENT_ACTIVITY_WINDOW_MS)
            .await
            .map_err(ApiError::internal)?,
        None => HashMap::new(),
    };
    let document = state.manager.document();
    let mut clients: Vec<ClientDto> = document
        .clients
        .iter()
        .map(|client| ClientDto::known(client, &activity))
        .collect();

    let policy = state.manager.handle().load_full();
    let known_ids: HashSet<&str> = document
        .clients
        .iter()
        .map(|client| client.id.as_str())
        .collect();
    let mut observed: Vec<ClientDto> = activity
        .iter()
        .filter(|(key, _)| !known_ids.contains(key.as_str()))
        // An address now covered by a named client isn't a separate device any more.
        .filter(|(key, _)| {
            key.parse::<IpAddr>().is_ok_and(|address| {
                let device = state.services.devices.get(address);
                policy
                    .identity(device_source(address, device.as_deref()))
                    .is_none()
            })
        })
        .map(|(key, (count, last_seen))| {
            let device = key
                .parse::<IpAddr>()
                .ok()
                .and_then(|address| state.services.devices.get(address));
            ClientDto {
                id: key.clone(),
                known: false,
                name: None,
                addresses: vec![key.clone()],
                macs: device
                    .as_ref()
                    .and_then(|device| device.mac)
                    .map(|mac| mac.to_string())
                    .into_iter()
                    .collect(),
                hostnames: device
                    .as_ref()
                    .and_then(|device| device.hostname.as_ref())
                    .map(|name| name.as_str().to_owned())
                    .into_iter()
                    .collect(),
                groups: vec![],
                query_count: *count,
                last_seen_at: Some(to_iso(*last_seen)),
            }
        })
        .collect();
    observed.sort_by_key(|client| std::cmp::Reverse(client.query_count));
    clients.extend(observed);
    Ok(Json(Envelope::new(clients)))
}

fn validate_client_shape(client: &ClientDef) -> ApiResult<()> {
    let has = |values: &[String]| values.iter().any(|value| !value.trim().is_empty());
    if !(has(&client.addresses) || has(&client.macs) || has(&client.hostnames)) {
        return Err(ApiError::invalid(
            "CLIENT_INVALID",
            "Enter at least one address, MAC address or host name",
        ));
    }
    Ok(())
}

/// How the DNS path would see an address, with whatever's known about its device.
fn device_source(address: IpAddr, device: Option<&DeviceInfo>) -> ClientSource<'_> {
    ClientSource {
        address,
        mac: device.and_then(|device| device.mac),
        hostname: device.and_then(|device| device.hostname.as_ref()),
    }
}

fn clean_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

/// Names a client, identified by its addresses.
#[utoipa::path(post, path = "/api/v1/clients", request_body = CreateClient, responses(
    (status = 201, body = Envelope<ClientDto>), (status = 409, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope),
))]
pub async fn create_client(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<CreateClient>,
) -> ApiResult<Response> {
    let name = request.name.trim().to_owned();
    if name.is_empty() || name.len() > MAX_NAME_LENGTH {
        return Err(ApiError::invalid(
            "CLIENT_INVALID",
            "Enter a name for this client",
        ));
    }
    let client = dns_policy::ClientDef {
        id: Ulid::generate().to_string(),
        name: Some(name),
        addresses: clean_list(request.addresses),
        macs: clean_list(request.macs),
        hostnames: clean_list(request.hostnames),
        groups: clean_list(request.groups),
    };
    validate_client_shape(&client)?;
    let stored = client.clone();
    mutate(&state, move |document| {
        document.clients.push(stored);
        Ok(())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "client.create",
        &client.id,
        serde_json::json!({"name": client.name}),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(Envelope::new(ClientDto::known(&client, &HashMap::new()))),
    )
        .into_response())
}

/// Changes a named client.
#[utoipa::path(patch, path = "/api/v1/clients/{id}", params(("id" = String, Path)), request_body = UpdateClient, responses(
    (status = 200, body = Envelope<ClientDto>), (status = 404, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope),
))]
pub async fn update_client(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateClient>,
) -> ApiResult<Json<Envelope<ClientDto>>> {
    let client_id = id.clone();
    let (client, _) = mutate(&state, move |document| {
        let client = document
            .clients
            .iter_mut()
            .find(|client| client.id == client_id)
            .ok_or_else(|| ApiError::not_found("That client"))?;
        if let Some(name) = request.name {
            client.name = not_empty(Some(name));
        }
        if let Some(addresses) = request.addresses {
            client.addresses = clean_list(addresses);
        }
        if let Some(macs) = request.macs {
            client.macs = clean_list(macs);
        }
        if let Some(hostnames) = request.hostnames {
            client.hostnames = clean_list(hostnames);
        }
        validate_client_shape(client)?;
        if let Some(groups) = request.groups {
            client.groups = clean_list(groups);
        }
        Ok(client.clone())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "client.update",
        &id,
        serde_json::json!({"name": client.name}),
    )
    .await;
    Ok(Json(Envelope::new(ClientDto::known(
        &client,
        &HashMap::new(),
    ))))
}

/// Forgets a named client. Rules scoped to it stop applying.
#[utoipa::path(delete, path = "/api/v1/clients/{id}", params(("id" = String, Path)), responses(
    (status = 204), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope),
))]
pub async fn delete_client(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let client_id = id.clone();
    mutate(&state, move |document| {
        let in_use = document
            .rules
            .iter()
            .any(|rule| matches!(&rule.scope, Scope::Client(scoped) if *scoped == client_id));
        if in_use {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "CLIENT_IN_USE",
                "Rules are scoped to this client. Change or delete them first.",
            ));
        }
        let position = document
            .clients
            .iter()
            .position(|client| client.id == client_id)
            .ok_or_else(|| ApiError::not_found("That client"))?;
        document.clients.remove(position);
        Ok(())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "client.delete",
        &id,
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// --- Groups ---

fn group_dto(id: &str, description: Option<String>, document: &PolicyDocument) -> GroupDto {
    GroupDto {
        id: id.to_owned(),
        description,
        client_count: document
            .clients
            .iter()
            .filter(|client| client.groups.iter().any(|group| group == id))
            .count(),
        rule_count: document
            .rules
            .iter()
            .filter(|rule| matches!(&rule.scope, Scope::Group(group) if group == id))
            .count(),
        list_count: document
            .lists
            .iter()
            .filter(|list| list.groups.iter().any(|group| group == id))
            .count(),
    }
}

/// Groups, including any referred to by clients, rules or lists.
#[utoipa::path(get, path = "/api/v1/groups",
    responses((status = 200, body = Envelope<Vec<GroupDto>>), (status = 401, body = ErrorEnvelope)))]
pub async fn list_groups(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<Vec<GroupDto>>> {
    let document = state.manager.document();
    let mut ids: Vec<&str> = document
        .groups
        .iter()
        .map(|group| group.id.as_str())
        .collect();
    ids.extend(
        document
            .clients
            .iter()
            .flat_map(|client| client.groups.iter().map(String::as_str)),
    );
    ids.extend(
        document
            .lists
            .iter()
            .flat_map(|list| list.groups.iter().map(String::as_str)),
    );
    ids.extend(document.rules.iter().filter_map(|rule| match &rule.scope {
        Scope::Group(id) => Some(id.as_str()),
        _ => None,
    }));
    ids.sort_unstable();
    ids.dedup();
    let groups = ids
        .into_iter()
        .map(|id| {
            let description = document
                .groups
                .iter()
                .find(|group| group.id == id)
                .and_then(|group| group.description.clone());
            group_dto(id, description, &document)
        })
        .collect();
    Json(Envelope::new(groups))
}

/// Creates a group.
#[utoipa::path(post, path = "/api/v1/groups", request_body = CreateGroup, responses(
    (status = 201, body = Envelope<GroupDto>), (status = 409, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope),
))]
pub async fn create_group(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<CreateGroup>,
) -> ApiResult<Response> {
    let id = request.id.trim().to_owned();
    if id.is_empty() || id.len() > MAX_NAME_LENGTH {
        return Err(ApiError::invalid(
            "GROUP_INVALID",
            "Enter a name for this group",
        ));
    }
    let group = GroupDef {
        id: id.clone(),
        description: not_empty(request.description),
    };
    let (dto, _) = mutate(&state, move |document| {
        if document.groups.iter().any(|group| group.id == id) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "GROUP_EXISTS",
                "That group already exists",
            ));
        }
        let dto = group_dto(&group.id, group.description.clone(), document);
        document.groups.push(group);
        Ok(dto)
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "group.create",
        &dto.id,
        serde_json::json!({}),
    )
    .await;
    Ok((StatusCode::CREATED, Json(Envelope::new(dto))).into_response())
}

/// Changes a group's description.
#[utoipa::path(patch, path = "/api/v1/groups/{id}", params(("id" = String, Path)), request_body = UpdateGroup, responses(
    (status = 200, body = Envelope<GroupDto>), (status = 404, body = ErrorEnvelope),
))]
pub async fn update_group(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateGroup>,
) -> ApiResult<Json<Envelope<GroupDto>>> {
    let group_id = id.clone();
    let (dto, _) = mutate(&state, move |document| {
        let description = not_empty(request.description);
        match document
            .groups
            .iter_mut()
            .find(|group| group.id == group_id)
        {
            Some(group) => group.description = description.clone(),
            // A group referred to elsewhere but not yet defined becomes defined on first edit.
            None => document.groups.push(GroupDef {
                id: group_id.clone(),
                description: description.clone(),
            }),
        }
        Ok(group_dto(&group_id, description, document))
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "group.update",
        &id,
        serde_json::json!({}),
    )
    .await;
    Ok(Json(Envelope::new(dto)))
}

/// Deletes an unused group.
#[utoipa::path(delete, path = "/api/v1/groups/{id}", params(("id" = String, Path)), responses(
    (status = 204), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope),
))]
pub async fn delete_group(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let group_id = id.clone();
    mutate(&state, move |document| {
        let dto = group_dto(&group_id, None, document);
        if dto.client_count + dto.rule_count + dto.list_count > 0 {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "GROUP_IN_USE",
                "Clients, rules or lists still use this group. Change them first.",
            ));
        }
        let position = document
            .groups
            .iter()
            .position(|group| group.id == group_id)
            .ok_or_else(|| ApiError::not_found("That group"))?;
        document.groups.remove(position);
        Ok(())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "group.delete",
        &id,
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// --- DNS ---

/// Upstream servers and what this node has seen from them since it started.
#[utoipa::path(get, path = "/api/v1/dns/upstreams",
    responses((status = 200, body = Envelope<Vec<UpstreamDto>>), (status = 401, body = ErrorEnvelope)))]
pub async fn list_upstreams(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<Vec<UpstreamDto>>> {
    Json(Envelope::new(
        state
            .pool
            .stats()
            .into_iter()
            .map(|stats| UpstreamDto {
                server: stats.server,
                responses: stats.responses,
                failures: stats.failures,
                last_latency_us: stats.last_latency_us,
            })
            .collect(),
    ))
}

/// The answer cache's size and hit counts.
#[utoipa::path(get, path = "/api/v1/dns/cache",
    responses((status = 200, body = Envelope<CacheDto>), (status = 401, body = ErrorEnvelope)))]
pub async fn cache_stats(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<CacheDto>> {
    let stats = state.cache.as_ref().map(|cache| cache.stats());
    Json(Envelope::new(CacheDto {
        enabled: stats.is_some(),
        hits: stats.map_or(0, |stats| stats.hits),
        misses: stats.map_or(0, |stats| stats.misses),
        entries: stats.map_or(0, |stats| stats.entries),
        bytes: stats.map_or(0, |stats| stats.bytes),
        max_bytes: stats.map_or(0, |stats| stats.max_bytes),
    }))
}

/// Removes every cached answer.
#[utoipa::path(delete, path = "/api/v1/dns/cache",
    responses((status = 204), (status = 401, body = ErrorEnvelope)))]
pub async fn flush_cache(auth: AuthSession, State(state): State<AppState>) -> StatusCode {
    if let Some(cache) = &state.cache {
        cache.flush();
    }
    audit(
        &state,
        &auth.session.username,
        "cache.flush",
        "cache",
        serde_json::json!({}),
    )
    .await;
    StatusCode::NO_CONTENT
}

/// Sends a test query through the upstream pool.
#[utoipa::path(post, path = "/api/v1/dns/upstreams/test",
    responses((status = 200, body = Envelope<UpstreamTestResult>), (status = 401, body = ErrorEnvelope)))]
pub async fn test_upstreams(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<UpstreamTestResult>> {
    let request = UpstreamRequest {
        query: DnsQuery::query(Name::root(), RecordType::NS),
        recursion_desired: true,
        checking_disabled: false,
        edns: None,
    };
    let started = Instant::now();
    let result = state.pool.forward(&request).await;
    let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Json(Envelope::new(match result {
        Ok(forwarded) => UpstreamTestResult {
            ok: true,
            server: Some(forwarded.server),
            rcode: Some(forwarded.message.metadata.response_code.to_str().to_owned()),
            latency_ms,
            message: None,
        },
        Err(error) => UpstreamTestResult {
            ok: false,
            server: None,
            rcode: None,
            latency_ms,
            message: Some(error.to_string()),
        },
    }))
}

// --- Pausing blocking ---

const MAX_PAUSE_SECONDS: u64 = 86_400;

fn blocking_dto(state: &AppState) -> BlockingDto {
    let remaining = state.services.pause.remaining();
    BlockingDto {
        paused: remaining.is_some(),
        paused_until: remaining
            .map(|left| to_iso(now_ms() + i64::try_from(left.as_millis()).unwrap_or(i64::MAX))),
        // Rounded up, so a pause never shows as over before it is.
        remaining_seconds: remaining.map_or(0, |left| left.as_millis().div_ceil(1000) as u64),
    }
}

/// Whether blocking is paused, and until when.
#[utoipa::path(get, path = "/api/v1/blocking", responses(
    (status = 200, body = Envelope<BlockingDto>), (status = 401, body = ErrorEnvelope),
))]
pub async fn get_blocking(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<BlockingDto>> {
    Json(Envelope::new(blocking_dto(&state)))
}

/// Pauses all blocking for a set time, except emergency denies. A restart also ends the pause.
#[utoipa::path(post, path = "/api/v1/blocking/pause", request_body = PauseBlocking, responses(
    (status = 200, body = Envelope<BlockingDto>), (status = 422, body = ErrorEnvelope),
))]
pub async fn pause_blocking(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<PauseBlocking>,
) -> ApiResult<Json<Envelope<BlockingDto>>> {
    if request.seconds == 0 || request.seconds > MAX_PAUSE_SECONDS {
        return Err(ApiError::invalid(
            "PAUSE_INVALID",
            "Pause blocking for between 1 second and 1 day",
        ));
    }
    state
        .services
        .pause
        .pause(Duration::from_secs(request.seconds));
    audit(
        &state,
        &auth.session.username,
        "blocking.pause",
        "blocking",
        serde_json::json!({"seconds": request.seconds}),
    )
    .await;
    Ok(Json(Envelope::new(blocking_dto(&state))))
}

/// Ends a pause, so blocking applies again now.
#[utoipa::path(post, path = "/api/v1/blocking/resume", responses(
    (status = 200, body = Envelope<BlockingDto>), (status = 401, body = ErrorEnvelope),
))]
pub async fn resume_blocking(
    auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<BlockingDto>> {
    state.services.pause.resume();
    audit(
        &state,
        &auth.session.username,
        "blocking.resume",
        "blocking",
        serde_json::json!({}),
    )
    .await;
    Json(Envelope::new(blocking_dto(&state)))
}

// --- Conditional forwarding ---

fn forward_zone_dto(state: &AppState, zone: &ForwardZoneDef) -> ForwardZoneDto {
    ForwardZoneDto {
        id: zone.id.clone(),
        zones: zone.zones.clone(),
        servers: zone.servers.clone(),
        load_balance: zone.load_balance,
        stats: state
            .services
            .conditional
            .stats(&zone.servers, zone.load_balance)
            .into_iter()
            .map(|stats| UpstreamDto {
                server: stats.server,
                responses: stats.responses,
                failures: stats.failures,
                last_latency_us: stats.last_latency_us,
            })
            .collect(),
    }
}

/// Domains and networks that go to specific servers.
#[utoipa::path(get, path = "/api/v1/dns/forwarders", responses(
    (status = 200, body = Envelope<Vec<ForwardZoneDto>>), (status = 401, body = ErrorEnvelope),
))]
pub async fn list_forwarders(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<Vec<ForwardZoneDto>>> {
    let document = state.manager.document();
    Json(Envelope::new(
        document
            .forward_zones
            .iter()
            .map(|zone| forward_zone_dto(&state, zone))
            .collect(),
    ))
}

/// Sends some domains and reverse lookups to specific servers, active as soon as this returns.
#[utoipa::path(post, path = "/api/v1/dns/forwarders", request_body = CreateForwardZone, responses(
    (status = 201, body = Envelope<ForwardZoneDto>), (status = 422, body = ErrorEnvelope),
))]
pub async fn create_forwarder(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<CreateForwardZone>,
) -> ApiResult<Response> {
    let zone = ForwardZoneDef {
        id: Ulid::generate().to_string(),
        zones: clean_list(request.zones),
        servers: clean_list(request.servers),
        load_balance: request.load_balance,
    };
    let stored = zone.clone();
    mutate(&state, move |document| {
        document.forward_zones.push(stored);
        Ok(())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "forwarder.create",
        &zone.id,
        serde_json::json!({"zones": zone.zones, "servers": zone.servers, "load_balance": zone.load_balance}),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(Envelope::new(forward_zone_dto(&state, &zone))),
    )
        .into_response())
}

/// Changes a forward zone.
#[utoipa::path(patch, path = "/api/v1/dns/forwarders/{id}", params(("id" = String, Path)),
    request_body = UpdateForwardZone, responses(
    (status = 200, body = Envelope<ForwardZoneDto>), (status = 404, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn update_forwarder(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateForwardZone>,
) -> ApiResult<Json<Envelope<ForwardZoneDto>>> {
    let zone_id = id.clone();
    let (zone, _) = mutate(&state, move |document| {
        let zone = document
            .forward_zones
            .iter_mut()
            .find(|zone| zone.id == zone_id)
            .ok_or_else(|| ApiError::not_found("That forwarding rule"))?;
        if let Some(zones) = request.zones {
            zone.zones = clean_list(zones);
        }
        if let Some(servers) = request.servers {
            zone.servers = clean_list(servers);
        }
        if let Some(load_balance) = request.load_balance {
            zone.load_balance = load_balance;
        }
        Ok(zone.clone())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "forwarder.update",
        &id,
        serde_json::json!({"zones": zone.zones, "servers": zone.servers, "load_balance": zone.load_balance}),
    )
    .await;
    Ok(Json(Envelope::new(forward_zone_dto(&state, &zone))))
}

/// Stops forwarding a zone's names to its servers.
#[utoipa::path(delete, path = "/api/v1/dns/forwarders/{id}", params(("id" = String, Path)), responses(
    (status = 204), (status = 404, body = ErrorEnvelope),
))]
pub async fn delete_forwarder(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let zone_id = id.clone();
    mutate(&state, move |document| {
        let position = document
            .forward_zones
            .iter()
            .position(|zone| zone.id == zone_id)
            .ok_or_else(|| ApiError::not_found("That forwarding rule"))?;
        document.forward_zones.remove(position);
        Ok(())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "forwarder.delete",
        &id,
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// --- Network devices ---

/// How long a device stays in the overview after it was last seen.
const DEVICE_RETENTION_MS: i64 = 90 * 24 * 60 * 60 * 1000;

/// Groups what's known by device: a MAC address can hold several IP addresses.
fn group_devices(devices: &[Arc<DeviceInfo>]) -> HashMap<String, Vec<&DeviceInfo>> {
    let mut groups: HashMap<String, Vec<&DeviceInfo>> = HashMap::new();
    for device in devices {
        let key = device
            .mac
            .map_or_else(|| device.address.to_string(), |mac| mac.to_string());
        groups.entry(key).or_default().push(device);
    }
    groups
}

/// A device can only have its queries counted if its client covers nothing else.
fn counts_only_this_device(client: &ClientDef) -> bool {
    client
        .addresses
        .iter()
        .all(|value| value.parse::<IpAddr>().is_ok())
}

/// Devices on the network or asking this node, with the client each one counts as.
#[utoipa::path(get, path = "/api/v1/network/devices", responses(
    (status = 200, body = Envelope<Vec<NetworkDeviceDto>>), (status = 401, body = ErrorEnvelope),
))]
pub async fn list_network_devices(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> ApiResult<Json<Envelope<Vec<NetworkDeviceDto>>>> {
    let now = now_ms();
    let activity = match &state.telemetry {
        Some(telemetry) => telemetry
            .client_activity(now - CLIENT_ACTIVITY_WINDOW_MS)
            .await
            .map_err(ApiError::internal)?,
        None => HashMap::new(),
    };
    let stored = state.db.network_devices(now - DEVICE_RETENTION_MS).await?;
    let current = state.services.devices.snapshot();
    let limited = state.services.rate_limiter.currently_limited();
    let document = state.manager.document();
    let policy = state.manager.handle().load_full();
    // With client details left out of the log, per-device counts are unknown rather than zero.
    let keeps_clients = policy.telemetry().mode == QueryLogMode::Full;

    let mut seen_addresses = HashSet::new();
    let mut rows = Vec::new();
    let groups = group_devices(&current);
    let mut stored_by_mac: HashMap<&str, &NetworkDevice> = stored
        .iter()
        .map(|device| (device.mac.as_str(), device))
        .collect();

    for (id, group) in &groups {
        let saved = stored_by_mac.remove(id.as_str());
        let mut addresses: Vec<IpAddr> = group.iter().map(|device| device.address).collect();
        addresses.sort_unstable();
        seen_addresses.extend(addresses.iter().copied());
        // The hostname and identity come from whichever address has the most to say.
        let best = group.iter().max_by_key(|device| {
            (
                device.hostname.is_some(),
                device.on_network,
                device.last_active_ms,
            )
        });
        let Some(best) = best else { continue };
        let identity = policy.identity(device_source(best.address, Some(best)));
        let client = identity.and_then(|identity| {
            document
                .clients
                .iter()
                .find(|client| client.id.as_str() == identity.id.as_ref())
        });
        let by_address = addresses
            .iter()
            .filter_map(|address| activity.get(&address.to_string()))
            .fold((0, 0), |(count, last), (more, seen)| {
                (count + more, i64::max(last, *seen))
            });
        let by_client = client
            .filter(|client| counts_only_this_device(client))
            .and_then(|client| activity.get(&client.id));
        let (query_count, last_query) = match (client, by_client) {
            (Some(_), Some((count, last))) => (Some(by_address.0 + count), Some(*last)),
            (Some(client), None) if !counts_only_this_device(client) => (None, None),
            _ => (
                Some(by_address.0),
                (by_address.1 > 0).then_some(by_address.1),
            ),
        };
        rows.push(NetworkDeviceDto {
            id: id.clone(),
            mac: best.mac.map(|mac| mac.to_string()),
            addresses: addresses.iter().map(ToString::to_string).collect(),
            hostname: group
                .iter()
                .find_map(|device| device.hostname.as_ref())
                .map(|name| name.as_str().to_owned())
                .or_else(|| saved.and_then(|device| device.hostname.clone())),
            on_network: group.iter().any(|device| device.on_network),
            last_active_at: group
                .iter()
                .map(|device| device.last_active_ms)
                .max()
                .map(to_iso),
            first_seen_at: saved.map(|device| to_iso(device.first_seen_ms)),
            client_id: identity.map(|identity| identity.id.to_string()),
            client_name: client.and_then(|client| client.name.clone()),
            groups: identity
                .map(|identity| identity.groups.iter().map(ToString::to_string).collect())
                .unwrap_or_default(),
            query_count: query_count.filter(|_| keeps_clients),
            last_query_at: last_query.map(to_iso),
            rate_limited: addresses.iter().any(|address| limited.contains(address)),
        });
    }

    // Devices remembered from earlier, which aren't around now.
    for device in stored_by_mac.into_values() {
        let addresses: Vec<IpAddr> = device
            .addresses
            .iter()
            .filter_map(|address| address.parse().ok())
            .collect();
        seen_addresses.extend(addresses.iter().copied());
        let mac = device.mac.parse().ok();
        let hostname = device
            .hostname
            .as_deref()
            .and_then(|name| DomainName::parse(name).ok());
        let identity = addresses.first().and_then(|address| {
            policy.identity(ClientSource {
                address: *address,
                mac,
                hostname: hostname.as_ref(),
            })
        });
        rows.push(NetworkDeviceDto {
            id: device.mac.clone(),
            mac: Some(device.mac.clone()),
            addresses: device.addresses.clone(),
            hostname: device.hostname.clone(),
            on_network: false,
            last_active_at: Some(to_iso(device.last_seen_ms)),
            first_seen_at: Some(to_iso(device.first_seen_ms)),
            client_id: identity.map(|identity| identity.id.to_string()),
            client_name: identity.and_then(|identity| {
                document
                    .clients
                    .iter()
                    .find(|client| client.id.as_str() == identity.id.as_ref())
                    .and_then(|client| client.name.clone())
            }),
            groups: identity
                .map(|identity| identity.groups.iter().map(ToString::to_string).collect())
                .unwrap_or_default(),
            query_count: None,
            last_query_at: None,
            rate_limited: false,
        });
    }

    // Addresses from the query log that have nothing else known about them.
    for (key, (count, last_seen)) in &activity {
        let Ok(address) = key.parse::<IpAddr>() else {
            continue;
        };
        if seen_addresses.contains(&address) {
            continue;
        }
        rows.push(NetworkDeviceDto {
            id: key.clone(),
            mac: None,
            addresses: vec![key.clone()],
            hostname: None,
            on_network: false,
            last_active_at: Some(to_iso(*last_seen)),
            first_seen_at: None,
            client_id: None,
            client_name: None,
            groups: vec![],
            query_count: Some(*count),
            last_query_at: Some(to_iso(*last_seen)),
            rate_limited: limited.contains(&address),
        });
    }

    rows.sort_by(|left, right| {
        right
            .on_network
            .cmp(&left.on_network)
            .then_with(|| right.last_active_at.cmp(&left.last_active_at))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(Json(Envelope::new(rows)))
}

/// Saves the devices on the network now, so the overview remembers them after a restart.
///
/// With query logging reduced, the operator has asked this node to keep less about devices, so
/// nothing is saved. What's already saved ages out as usual.
pub async fn save_network_devices(state: &AppState) {
    let now = now_ms();
    if let Err(error) = state
        .db
        .forget_network_devices(now - DEVICE_RETENTION_MS)
        .await
    {
        warn!(%error, "cannot forget old network devices");
    }
    if state.manager.handle().load().telemetry().mode != QueryLogMode::Full {
        return;
    }
    let current = state.services.devices.snapshot();
    let rows: Vec<NetworkDevice> = group_devices(&current)
        .into_iter()
        .filter(|(_, group)| group.iter().any(|device| device.mac.is_some()))
        .map(|(mac, group)| NetworkDevice {
            mac,
            addresses: group
                .iter()
                .map(|device| device.address.to_string())
                .collect(),
            hostname: group
                .iter()
                .find_map(|device| device.hostname.as_ref())
                .map(|name| name.as_str().to_owned()),
            first_seen_ms: now,
            last_seen_ms: group
                .iter()
                .map(|device| device.last_active_ms)
                .max()
                .unwrap_or(now),
        })
        .collect();
    if let Err(error) = state.db.record_network_devices(&rows).await {
        warn!(%error, "cannot save network devices");
    }
}

// --- Local DNS ---

fn normalized_name(value: &str, code: &'static str) -> ApiResult<String> {
    let name = DomainName::parse(value.trim())
        .map_err(|error| ApiError::invalid(code, format!("{value:?}: {error}")))?;
    if name.is_root() {
        return Err(ApiError::invalid(code, "The root name can't be used here"));
    }
    Ok(name.as_str().to_owned())
}

fn in_zone(record: &dns_policy::LocalRecordDef, zone: &str) -> bool {
    record.name == zone
        || record
            .name
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Zones this node answers for itself.
#[utoipa::path(get, path = "/api/v1/dns/zones",
    responses((status = 200, body = Envelope<Vec<LocalZoneDto>>), (status = 401, body = ErrorEnvelope)))]
pub async fn list_zones(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<Vec<LocalZoneDto>>> {
    let document = state.manager.document();
    Json(Envelope::new(
        document
            .local_zones
            .iter()
            .map(|zone| LocalZoneDto {
                record_count: document
                    .local_records
                    .iter()
                    .filter(|record| in_zone(record, &zone.name))
                    .count(),
                name: zone.name.clone(),
            })
            .collect(),
    ))
}

/// Adds a zone. Every name in it is then answered by this node, never upstream.
#[utoipa::path(post, path = "/api/v1/dns/zones", request_body = CreateLocalZone, responses(
    (status = 201, body = Envelope<LocalZoneDto>),
    (status = 409, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn create_zone(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<CreateLocalZone>,
) -> ApiResult<Response> {
    let name = normalized_name(&request.name, "ZONE_INVALID")?;
    let stored = name.clone();
    mutate(&state, move |document| {
        document
            .local_zones
            .push(dns_policy::LocalZoneDef { name: stored });
        Ok(())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "zone.create",
        &name,
        serde_json::json!({}),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(Envelope::new(LocalZoneDto {
            name,
            record_count: 0,
        })),
    )
        .into_response())
}

/// Removes an empty zone.
#[utoipa::path(delete, path = "/api/v1/dns/zones/{name}", params(("name" = String, Path)), responses(
    (status = 204), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope),
))]
pub async fn delete_zone(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    let zone = name.clone();
    mutate(&state, move |document| {
        let position = document
            .local_zones
            .iter()
            .position(|candidate| candidate.name == zone)
            .ok_or_else(|| ApiError::not_found("That zone"))?;
        // A nested zone keeps its own records, so only this zone's direct owners count.
        let in_use = document.local_records.iter().any(|record| {
            in_zone(record, &zone)
                && !document.local_zones.iter().any(|other| {
                    other.name != zone
                        && other.name.len() > zone.len()
                        && in_zone(record, &other.name)
                })
        });
        if in_use {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "ZONE_IN_USE",
                "This zone still has records. Delete them first.",
            ));
        }
        document.local_zones.remove(position);
        Ok(())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "zone.delete",
        &name,
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Records in local zones.
#[utoipa::path(get, path = "/api/v1/dns/records",
    responses((status = 200, body = Envelope<Vec<LocalRecordDto>>), (status = 401, body = ErrorEnvelope)))]
pub async fn list_records(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<Vec<LocalRecordDto>>> {
    let document = state.manager.document();
    Json(Envelope::new(
        document
            .local_records
            .iter()
            .map(LocalRecordDto::from)
            .collect(),
    ))
}

/// Adds a record to a local zone.
#[utoipa::path(post, path = "/api/v1/dns/records", request_body = CreateLocalRecord, responses(
    (status = 201, body = Envelope<LocalRecordDto>),
    (status = 409, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn create_record(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<CreateLocalRecord>,
) -> ApiResult<Response> {
    let record = dns_policy::LocalRecordDef {
        id: Ulid::generate().to_string(),
        name: normalized_name(&request.name, "RECORD_INVALID")?,
        record_type: request.record_type.into(),
        value: request.value.trim().to_owned(),
        ttl_seconds: request.ttl_seconds,
    };
    let stored = record.clone();
    mutate(&state, move |document| {
        document.local_records.push(stored);
        Ok(())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "record.create",
        &record.name,
        serde_json::json!({"value": record.value}),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(Envelope::new(LocalRecordDto::from(&record))),
    )
        .into_response())
}

/// Changes a record in a local zone.
#[utoipa::path(patch, path = "/api/v1/dns/records/{id}", params(("id" = String, Path)), request_body = UpdateLocalRecord, responses(
    (status = 200, body = Envelope<LocalRecordDto>),
    (status = 404, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn update_record(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<UpdateLocalRecord>,
) -> ApiResult<Json<Envelope<LocalRecordDto>>> {
    let name = request
        .name
        .as_deref()
        .map(|name| normalized_name(name, "RECORD_INVALID"))
        .transpose()?;
    let record_id = id.clone();
    let (record, _) = mutate(&state, move |document| {
        let record = document
            .local_records
            .iter_mut()
            .find(|record| record.id == record_id)
            .ok_or_else(|| ApiError::not_found("That record"))?;
        if let Some(name) = name {
            record.name = name;
        }
        if let Some(record_type) = request.record_type {
            record.record_type = record_type.into();
        }
        if let Some(value) = request.value {
            record.value = value.trim().to_owned();
        }
        if let Some(ttl_seconds) = request.ttl_seconds {
            record.ttl_seconds = ttl_seconds;
        }
        Ok(record.clone())
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "record.update",
        &record.name,
        serde_json::json!({"value": record.value}),
    )
    .await;
    Ok(Json(Envelope::new(LocalRecordDto::from(&record))))
}

/// Deletes a record from a local zone.
#[utoipa::path(delete, path = "/api/v1/dns/records/{id}", params(("id" = String, Path)), responses(
    (status = 204), (status = 404, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope),
))]
pub async fn delete_record(
    auth: AuthSession,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let record_id = id.clone();
    let (name, _) = mutate(&state, move |document| {
        let position = document
            .local_records
            .iter()
            .position(|record| record.id == record_id)
            .ok_or_else(|| ApiError::not_found("That record"))?;
        Ok(document.local_records.remove(position).name)
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "record.delete",
        &name,
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// --- Config ---

/// Stored policy revisions, newest first.
#[utoipa::path(get, path = "/api/v1/config/revisions",
    responses((status = 200, body = Envelope<Vec<RevisionDto>>), (status = 401, body = ErrorEnvelope)))]
pub async fn list_revisions(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> ApiResult<Json<Envelope<Vec<RevisionDto>>>> {
    let manager = Arc::clone(&state.manager);
    let revisions = tokio::task::spawn_blocking(move || manager.revisions())
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    Ok(Json(Envelope::new(
        revisions
            .into_iter()
            .map(|revision| RevisionDto {
                revision: revision.revision,
                active: revision.active,
                rule_count: revision.rule_count,
                list_count: revision.list_count,
                client_count: revision.client_count,
            })
            .collect(),
    )))
}

/// Rolls back or restores: makes a stored revision active again.
#[utoipa::path(post, path = "/api/v1/config/activate", request_body = ActivateRequest, responses(
    (status = 204), (status = 404, body = ErrorEnvelope), (status = 409, body = ErrorEnvelope),
))]
pub async fn activate_revision(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<ActivateRequest>,
) -> ApiResult<StatusCode> {
    let manager = Arc::clone(&state.manager);
    let revision = request.revision.clone();
    tokio::task::spawn_blocking(move || manager.activate(&revision))
        .await
        .map_err(ApiError::internal)?
        .map_err(|error| match error {
            MutationError::Rejected(_) => ApiError::not_found("That revision"),
            MutationError::ReadOnly => MutationError::<ApiError>::ReadOnly.into(),
            MutationError::NoStateDirectory => MutationError::<ApiError>::NoStateDirectory.into(),
            MutationError::Invalid(invalid) => MutationError::<ApiError>::Invalid(invalid).into(),
            MutationError::Storage(storage) => MutationError::<ApiError>::Storage(storage).into(),
        })?;
    audit(
        &state,
        &auth.session.username,
        "config.activate",
        &request.revision,
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

fn settings_dto(document: &PolicyDocument) -> SettingsDto {
    SettingsDto {
        block_response: document.block.response.into(),
        block_ttl_seconds: document.block.ttl_seconds,
        query_log_mode: document.telemetry.mode.into(),
        query_history_days: document.telemetry.query_history_days,
        query_history_max_bytes: document.telemetry.query_history_max_bytes,
        rate_limit_queries_per_minute: document.rate_limit.queries_per_minute,
        rate_limit_exempt: document.rate_limit.exempt.clone(),
    }
}

/// Blocking and query logging settings.
#[utoipa::path(get, path = "/api/v1/settings",
    responses((status = 200, body = Envelope<SettingsDto>), (status = 401, body = ErrorEnvelope)))]
pub async fn get_settings(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<SettingsDto>> {
    Json(Envelope::new(settings_dto(&state.manager.document())))
}

/// Changes blocking and query logging settings.
#[utoipa::path(put, path = "/api/v1/settings", request_body = SettingsDto, responses(
    (status = 200, body = Envelope<SettingsDto>), (status = 409, body = ErrorEnvelope), (status = 422, body = ErrorEnvelope),
))]
pub async fn put_settings(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<SettingsDto>,
) -> ApiResult<Json<Envelope<SettingsDto>>> {
    if request.query_history_days == 0 {
        return Err(ApiError::invalid(
            "SETTINGS_INVALID",
            "Keep at least 1 day of history",
        ));
    }
    let (dto, _) = mutate(&state, move |document| {
        document.block.response = request.block_response.into();
        document.block.ttl_seconds = request.block_ttl_seconds;
        document.telemetry.mode = request.query_log_mode.into();
        document.telemetry.query_history_days = request.query_history_days;
        document.telemetry.query_history_max_bytes = request.query_history_max_bytes;
        document.rate_limit.queries_per_minute = request.rate_limit_queries_per_minute;
        document.rate_limit.exempt = clean_list(request.rate_limit_exempt);
        Ok(settings_dto(document))
    })
    .await?;
    audit(
        &state,
        &auth.session.username,
        "settings.update",
        "settings",
        serde_json::json!({}),
    )
    .await;
    Ok(Json(Envelope::new(dto)))
}

// --- Backup ---

/// Builds a backup archive from a node's state. Accounts are only included with a passphrase.
pub async fn build_backup(
    manager: Arc<dns_runtime::PolicyManager>,
    db: dns_storage::ConfigDb,
    credentials_passphrase: Option<String>,
) -> Result<Vec<u8>, BackupBuildError> {
    let list_statuses = db.list_statuses().await?;
    let audit_events = db.recent_audit_events(100_000).await?;
    let credentials = match credentials_passphrase {
        Some(passphrase) => Some((db.users().await?, passphrase)),
        None => None,
    };
    tokio::task::spawn_blocking(move || {
        let export = manager.export()?;
        let source = dns_backup::BackupSource {
            revisions: export
                .revisions
                .into_iter()
                .map(|(sha256, content)| dns_backup::Revision { sha256, content })
                .collect(),
            artifacts: export.artifacts.into_iter().collect(),
            list_statuses,
            audit_events,
            credentials,
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        Ok(dns_backup::create_backup(&source)?)
    })
    .await
    .map_err(|error| BackupBuildError::Task(error.to_string()))?
}

/// Why a backup couldn't be built.
#[derive(Debug, thiserror::Error)]
pub enum BackupBuildError {
    #[error(transparent)]
    Database(#[from] dns_storage::ConfigDbError),
    #[error(transparent)]
    Storage(#[from] std::io::Error),
    #[error(transparent)]
    Backup(#[from] dns_backup::BackupError),
    #[error("the backup task failed: {0}")]
    Task(String),
}

/// Downloads a backup of policy, lists and history. Accounts and query logs are left out.
#[utoipa::path(post, path = "/api/v1/backup", responses(
    (status = 200, content_type = "application/gzip", body = Vec<u8>),
    (status = 401, body = ErrorEnvelope),
))]
pub async fn create_backup(
    auth: AuthSession,
    State(state): State<AppState>,
) -> ApiResult<Response> {
    let archive = build_backup(Arc::clone(&state.manager), state.db.clone(), None)
        .await
        .map_err(ApiError::internal)?;
    audit(
        &state,
        &auth.session.username,
        "backup.create",
        "backup",
        serde_json::json!({}),
    )
    .await;
    let stamp = to_iso(now_ms()).replace(':', "-");
    let name = format!(
        "ferrixdns-backup-{}.tar.gz",
        stamp.get(..19).unwrap_or("backup")
    );
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/gzip".to_owned(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
            (axum::http::header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        archive,
    )
        .into_response())
}

/// Validates a backup and, unless `dry_run` is set, restores it. Everything's checked first, so a
/// bad backup changes nothing.
#[utoipa::path(post, path = "/api/v1/backup/restore", params(RestoreParams),
    request_body(content = Vec<u8>, content_type = "application/gzip"), responses(
    (status = 200, body = Envelope<RestoreResult>),
    (status = 409, body = ErrorEnvelope),
    (status = 422, body = ErrorEnvelope),
))]
pub async fn restore_backup(
    auth: AuthSession,
    State(state): State<AppState>,
    Query(params): Query<RestoreParams>,
    body: axum::body::Bytes,
) -> ApiResult<Json<Envelope<RestoreResult>>> {
    let backup = tokio::task::spawn_blocking(move || dns_backup::read_backup(&body))
        .await
        .map_err(ApiError::internal)?
        .map_err(|error| ApiError::invalid("BACKUP_INVALID", error.to_string()))?;

    let summary = backup.summary.clone();
    let result = RestoreResult {
        dry_run: params.dry_run,
        created_at: to_iso(summary.created_at_ms),
        app_version: summary.app_version,
        revision: summary.revision,
        revision_count: summary.revision_count,
        rule_count: summary.rule_count,
        list_count: summary.list_count,
        client_count: summary.client_count,
        local_record_count: summary.local_record_count,
        has_credentials: summary.has_credentials,
    };
    if params.dry_run {
        return Ok(Json(Envelope::new(result)));
    }

    let revisions: Vec<(String, Vec<u8>)> = backup
        .revisions
        .iter()
        .map(|revision| (revision.sha256.clone(), revision.content.clone()))
        .collect();
    let artifacts: Vec<(String, Vec<u8>)> = backup
        .artifacts
        .iter()
        .map(|(sha256, content)| (sha256.clone(), content.clone()))
        .collect();
    let manager = Arc::clone(&state.manager);
    tokio::task::spawn_blocking(move || manager.restore(&revisions, &artifacts))
        .await
        .map_err(ApiError::internal)?
        .map_err(|error| match error {
            MutationError::Rejected(_) => {
                ApiError::invalid("BACKUP_INVALID", "The backup has no usable policy")
            }
            MutationError::ReadOnly => MutationError::<ApiError>::ReadOnly.into(),
            MutationError::NoStateDirectory => MutationError::<ApiError>::NoStateDirectory.into(),
            MutationError::Invalid(invalid) => MutationError::<ApiError>::Invalid(invalid).into(),
            MutationError::Storage(storage) => MutationError::<ApiError>::Storage(storage).into(),
        })?;
    state
        .db
        .replace_list_statuses(&backup.list_statuses)
        .await?;
    state.db.import_audit_events(&backup.audit_events).await?;
    audit(
        &state,
        &auth.session.username,
        "backup.restore",
        &result.revision,
        serde_json::json!({"app_version": result.app_version}),
    )
    .await;
    Ok(Json(Envelope::new(result)))
}

// --- System ---

/// Node health, versions and storage use.
#[utoipa::path(get, path = "/api/v1/system/status",
    responses((status = 200, body = Envelope<SystemStatus>), (status = 401, body = ErrorEnvelope)))]
pub async fn system_status(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> Json<Envelope<SystemStatus>> {
    let document = state.manager.document();
    let stats = match &state.telemetry {
        Some(telemetry) => Some(telemetry.stats(now_ms()).await),
        None => None,
    };
    Json(Envelope::new(SystemStatus {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        uptime_seconds: state.started.elapsed().as_secs(),
        policy_revision: state.manager.handle().load().revision().to_owned(),
        policy_read_only: state.manager.is_read_only(),
        policy_warnings: document.warnings(),
        dns_listeners: state
            .dns_listeners
            .iter()
            .map(ToString::to_string)
            .collect(),
        dnssec_validation: state.dnssec_validation,
        rule_count: document.rules.len(),
        list_count: document.lists.len(),
        client_count: document.clients.len(),
        telemetry_available: stats.is_some(),
        queries_recorded: stats.map_or(0, |stats| stats.recorded),
        events_dropped: stats.map_or(0, |stats| stats.dropped),
        telemetry_write_errors: stats.map_or(0, |stats| stats.write_errors),
        query_history_bytes: stats.map_or(0, |stats| stats.retained_bytes),
        query_history_retained_seconds: stats.map_or(0, |stats| stats.retained_seconds),
        rate_limited_queries: state.services.rate_limiter.limited_total(),
        ntp: state.ntp.as_ref().map(|ntp| NtpStatusDto {
            listeners: ntp.listeners.iter().map(ToString::to_string).collect(),
            clock: match node_ntp::current_state() {
                node_ntp::ClockState::Synchronized { .. } => "synchronized",
                node_ntp::ClockState::Unsynchronized => "unsynchronized",
                node_ntp::ClockState::Unknown => "unknown",
            }
            .to_owned(),
            requests_served: ntp.stats.served(),
            requests_limited: ntp.stats.limited(),
        }),
    }))
}

fn node_control(state: &AppState) -> ApiResult<&NodeControl> {
    state.node.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "NODE_SETTINGS_UNAVAILABLE",
            "This node's settings can't be changed here",
        )
    })
}

fn settings_store_error(error: SettingsStoreError) -> ApiError {
    match error {
        SettingsStoreError::TrialInProgress => ApiError::new(
            StatusCode::CONFLICT,
            "NODE_SETTINGS_PENDING",
            "The last change is still being tried. Keep or undo it first.",
        ),
        other => ApiError::internal(other),
    }
}

fn node_settings_view(control: &NodeControl) -> ApiResult<NodeSettingsView> {
    let saved = control.store.read().map_err(settings_store_error)?;
    let merged = |changes| {
        control
            .startup
            .with_changes(changes)
            .map_err(ApiError::internal)
    };
    let settings = merged(&saved.changes)?;
    let pending = saved
        .trial
        .as_ref()
        .and_then(|trial| trial.confirm_by_ms)
        .map(|confirm_by_ms| PendingNodeChange {
            seconds_left: confirm_by_ms.saturating_sub(unsigned_now_ms()) / 1000,
        });
    Ok(NodeSettingsView {
        changed: settings
            .differences(&control.startup)
            .keys()
            .cloned()
            .collect(),
        settings,
        startup: control.startup.clone(),
        boot_id: control.boot_id.clone(),
        pending,
        last_failure: saved.last_failure,
    })
}

fn unsigned_now_ms() -> u64 {
    u64::try_from(now_ms()).unwrap_or(0)
}

fn request_restart(control: &NodeControl) {
    // The response has to reach the browser before the listeners close.
    let restart = control.restart.clone();
    tokio::spawn(async move {
        tokio::time::sleep(RESTART_DELAY).await;
        let _ = restart.send(true);
    });
}

/// Whether the node itself holds an address, which makes binding it here fail for no real reason.
fn already_held(address: SocketAddr, held: &[SocketAddr]) -> bool {
    held.iter().any(|ours| {
        ours.port() == address.port()
            && (ours.ip() == address.ip()
                || ours.ip().is_unspecified()
                || address.ip().is_unspecified())
    })
}

/// Tries each new address now, so a port that's taken is a message instead of a failed restart.
async fn probe_addresses(
    state: &AppState,
    control: &NodeControl,
    parsed: &ParsedSettings,
) -> Result<(), String> {
    let mut held: Vec<SocketAddr> = state.dns_listeners.to_vec();
    held.push(control.web_address);
    if let Some(ntp) = &state.ntp {
        held.extend(&ntp.listeners);
    }
    let is_new = |address: &SocketAddr| address.port() != 0 && !already_held(*address, &held);
    for address in parsed.listen.iter().filter(|address| is_new(address)) {
        dns_runtime::bind_udp_and_tcp(*address)
            .await
            .map_err(|error| format!("Can't use this DNS address: {error}"))?;
    }
    if is_new(&parsed.web_listen) {
        tokio::net::TcpListener::bind(parsed.web_listen)
            .await
            .map_err(|error| {
                format!(
                    "Can't use the dashboard address {}: {error}",
                    parsed.web_listen
                )
            })?;
    }
    for address in parsed.ntp_listen.iter().filter(|address| is_new(address)) {
        tokio::net::UdpSocket::bind(address)
            .await
            .map_err(|error| format!("Can't use the time server address {address}: {error}"))?;
    }
    Ok(())
}

/// The node's own settings, such as its addresses and upstreams.
#[utoipa::path(get, path = "/api/v1/node-settings",
    responses((status = 200, body = Envelope<NodeSettingsView>), (status = 401, body = ErrorEnvelope)))]
pub async fn get_node_settings(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> ApiResult<Json<Envelope<NodeSettingsView>>> {
    Ok(Json(Envelope::new(node_settings_view(node_control(
        &state,
    )?)?)))
}

/// Saves the node's own settings and restarts it to use them.
#[utoipa::path(put, path = "/api/v1/node-settings", request_body = NodeSettings,
    responses(
        (status = 200, body = Envelope<SaveNodeSettingsResponse>),
        (status = 400, body = ErrorEnvelope),
        (status = 401, body = ErrorEnvelope),
        (status = 409, body = ErrorEnvelope),
    ))]
pub async fn put_node_settings(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(request): Json<NodeSettings>,
) -> ApiResult<Json<Envelope<SaveNodeSettingsResponse>>> {
    let control = node_control(&state)?;
    let invalid = |message: String| ApiError::invalid("NODE_SETTINGS_INVALID", message);
    // Reading the files a setting names can block.
    let desired = tokio::task::spawn_blocking(move || request.validated())
        .await
        .map_err(ApiError::internal)?
        .map_err(invalid)?;

    let saved = control.store.read().map_err(settings_store_error)?;
    if saved.trial.is_some() {
        return Err(settings_store_error(SettingsStoreError::TrialInProgress));
    }
    let existing = control
        .startup
        .with_changes(&saved.changes)
        .map_err(ApiError::internal)?;
    if desired == existing {
        return Ok(Json(Envelope::new(SaveNodeSettingsResponse {
            view: node_settings_view(control)?,
            restarting: false,
        })));
    }
    desired.check_reachable_after(&existing).map_err(invalid)?;
    if desired.state_dir != existing.state_dir {
        let (target, current) = (desired.state_dir.clone(), existing.state_dir.clone());
        tokio::task::spawn_blocking(move || {
            check_data_folder(FsPath::new(&target), FsPath::new(&current))
        })
        .await
        .map_err(ApiError::internal)?
        .map_err(invalid)?;
    }
    let parsed = desired.parse().map_err(invalid)?;
    probe_addresses(&state, control, &parsed)
        .await
        .map_err(invalid)?;

    let changed: Vec<String> = desired.differences(&existing).keys().cloned().collect();
    let confirm_by_ms = desired.changes_dashboard_access(&existing).then(|| {
        unsigned_now_ms().saturating_add(u64::try_from(CONFIRM_WITHIN.as_millis()).unwrap_or(0))
    });
    control
        .store
        .begin(desired.differences(&control.startup), confirm_by_ms)
        .map_err(settings_store_error)?;
    audit(
        &state,
        &auth.session.username,
        "node_settings.update",
        "node-settings",
        serde_json::json!({ "changed": changed }),
    )
    .await;
    let view = node_settings_view(control)?;
    request_restart(control);
    Ok(Json(Envelope::new(SaveNodeSettingsResponse {
        view,
        restarting: true,
    })))
}

/// Keeps a change to how the dashboard is reached, before it undoes itself.
#[utoipa::path(post, path = "/api/v1/node-settings/confirm",
    responses(
        (status = 200, body = Envelope<NodeSettingsView>),
        (status = 401, body = ErrorEnvelope),
        (status = 409, body = ErrorEnvelope),
    ))]
pub async fn confirm_node_settings(
    auth: AuthSession,
    State(state): State<AppState>,
) -> ApiResult<Json<Envelope<NodeSettingsView>>> {
    let control = node_control(&state)?;
    if !control.store.commit().map_err(settings_store_error)? {
        return Err(no_pending_change());
    }
    audit(
        &state,
        &auth.session.username,
        "node_settings.confirm",
        "node-settings",
        serde_json::json!({}),
    )
    .await;
    Ok(Json(Envelope::new(node_settings_view(control)?)))
}

fn no_pending_change() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "NODE_SETTINGS_NOT_PENDING",
        "There's no change waiting. It may have already been undone.",
    )
}

/// Undoes a change to how the dashboard is reached and restarts the node.
#[utoipa::path(post, path = "/api/v1/node-settings/undo",
    responses(
        (status = 200, body = Envelope<NodeSettingsView>),
        (status = 401, body = ErrorEnvelope),
        (status = 409, body = ErrorEnvelope),
    ))]
pub async fn undo_node_settings(
    auth: AuthSession,
    State(state): State<AppState>,
) -> ApiResult<Json<Envelope<NodeSettingsView>>> {
    let control = node_control(&state)?;
    if !control.store.revert(None).map_err(settings_store_error)? {
        return Err(no_pending_change());
    }
    audit(
        &state,
        &auth.session.username,
        "node_settings.undo",
        "node-settings",
        serde_json::json!({}),
    )
    .await;
    let view = node_settings_view(control)?;
    request_restart(control);
    Ok(Json(Envelope::new(view)))
}

/// Recent administrative actions, newest first.
#[utoipa::path(get, path = "/api/v1/audit-events",
    responses((status = 200, body = Envelope<Vec<AuditEventDto>>), (status = 401, body = ErrorEnvelope)))]
pub async fn audit_events(
    _auth: AuthSession,
    State(state): State<AppState>,
) -> ApiResult<Json<Envelope<Vec<AuditEventDto>>>> {
    let events = state.db.recent_audit_events(200).await?;
    Ok(Json(Envelope::new(
        events
            .into_iter()
            .map(|event| AuditEventDto {
                id: event.id,
                occurred_at: to_iso(event.occurred_at_ms),
                actor: event.actor,
                action: event.action,
                target: event.target,
                details: serde_json::from_str(&event.details_json).unwrap_or_default(),
            })
            .collect(),
    )))
}
