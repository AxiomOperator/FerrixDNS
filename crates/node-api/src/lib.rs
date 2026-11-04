//! The node's authenticated HTTP API and embedded web UI.

mod auth;
mod dto;
mod error;
mod refresh;
mod routes;
mod util;

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, HOST};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, serve};
use dns_lists::Fetcher;
use dns_runtime::PolicyManager;
use dns_storage::{ConfigDb, sha256_hex};
use dns_telemetry::Telemetry;
use dns_upstreams::UpstreamPool;
use rust_embed::RustEmbed;
use tokio::net::TcpListener;
use tracing::{info, warn};
use utoipa::OpenApi;

pub use auth::{MIN_PASSWORD_LENGTH, hash_password};
pub use routes::{BackupBuildError, build_backup};

use auth::{LoginGuard, PasswordWorker, random_token};
use error::ApiError;
use refresh::Jobs;

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
     style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; \
     font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

/// The largest backup that can be uploaded to restore.
const MAX_BACKUP_UPLOAD: usize = 1024 * 1024 * 1024;

#[derive(RustEmbed)]
#[folder = "../../frontend/dist"]
struct UiAssets;

/// Host names this node answers to, which blocks DNS rebinding attacks against the admin API.
#[derive(Clone, Debug)]
pub struct AllowedHosts {
    names: Arc<Vec<String>>,
}

impl AllowedHosts {
    /// Allows loopback names plus any extra host names.
    pub fn new(extra: impl IntoIterator<Item = String>) -> Self {
        let mut names = vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "[::1]".to_owned(),
        ];
        names.extend(extra.into_iter().map(|name| name.to_ascii_lowercase()));
        Self {
            names: Arc::new(names),
        }
    }

    /// Checks a `Host` value, ignoring any port.
    pub fn allows(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        let without_port = if host.starts_with('[') {
            host.split_once(']')
                .map_or(host.as_str(), |(address, _)| &host[..=address.len()])
        } else {
            host.split(':').next().unwrap_or(&host)
        };
        self.names.iter().any(|name| name == without_port)
    }
}

/// Everything the API needs. Cloning is cheap.
#[derive(Clone)]
pub struct AppState {
    pub(crate) manager: Arc<PolicyManager>,
    pub(crate) telemetry: Option<Arc<Telemetry>>,
    pub(crate) db: ConfigDb,
    pub(crate) pool: Arc<UpstreamPool>,
    pub(crate) cache: Option<Arc<dns_cache::DnsCache>>,
    pub(crate) fetcher: Fetcher,
    pub(crate) jobs: Jobs,
    pub(crate) hosts: AllowedHosts,
    pub(crate) passwords: PasswordWorker,
    pub(crate) login_guard: LoginGuard,
    pub(crate) setup_token_hash: Arc<Mutex<Option<String>>>,
    pub(crate) secure_cookies: bool,
    pub(crate) dns_listeners: Arc<Vec<SocketAddr>>,
    pub(crate) started: Instant,
    pub(crate) dnssec_validation: bool,
    pub(crate) hsts: bool,
}

impl AppState {
    pub(crate) fn setup_token_hash(&self) -> Option<String> {
        self.setup_token_hash
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn clear_setup_token(&self) {
        *self
            .setup_token_hash
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }
}

/// What's needed to start the API.
pub struct ApiConfig {
    pub manager: Arc<PolicyManager>,
    pub telemetry: Option<Arc<Telemetry>>,
    pub db: ConfigDb,
    pub pool: Arc<UpstreamPool>,
    pub cache: Option<Arc<dns_cache::DnsCache>>,
    pub fetcher: Fetcher,
    pub hosts: AllowedHosts,
    /// Marks cookies `Secure`, for when the API is reached over HTTPS.
    pub secure_cookies: bool,
    pub dns_listeners: Vec<SocketAddr>,
    pub dnssec_validation: bool,
    /// Sends HSTS. Only use this with a certificate browsers already trust, because HSTS removes
    /// their option to click through a warning.
    pub hsts: bool,
}

/// A started API: its state, plus the one-time setup token if setup is still needed.
pub struct Api {
    state: AppState,
    setup_token: Option<String>,
}

impl Api {
    /// Prepares the API, generating a setup token if there's no administrator yet.
    pub async fn new(config: ApiConfig) -> Result<Self, ApiStartError> {
        let needs_setup = config.db.user_count().await? == 0;
        let setup_token = needs_setup.then(random_token);
        let passwords = tokio::task::spawn_blocking(PasswordWorker::new)
            .await
            .map_err(|error| ApiStartError::Password(error.to_string()))?
            .map_err(|error| ApiStartError::Password(error.message))?;
        let state = AppState {
            manager: config.manager,
            telemetry: config.telemetry,
            db: config.db,
            pool: config.pool,
            cache: config.cache,
            fetcher: config.fetcher,
            jobs: Jobs::default(),
            hosts: config.hosts,
            passwords,
            login_guard: LoginGuard::default(),
            setup_token_hash: Arc::new(Mutex::new(
                setup_token
                    .as_ref()
                    .map(|token| sha256_hex(token.as_bytes())),
            )),
            secure_cookies: config.secure_cookies,
            dns_listeners: Arc::new(config.dns_listeners),
            started: Instant::now(),
            dnssec_validation: config.dnssec_validation,
            hsts: config.hsts,
        };
        Ok(Self { state, setup_token })
    }

    /// The token for first-run setup, which the node shows the operator.
    pub fn setup_token(&self) -> Option<&str> {
        self.setup_token.as_deref()
    }

    /// The API's routes, for serving or testing.
    pub fn router(&self) -> Router {
        router(self.state.clone())
    }

    /// Serves until `shutdown` completes, and starts scheduled list refreshes.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> io::Result<()> {
        tokio::spawn(refresh::run_schedule(self.state.clone()));
        let app = router(self.state);
        info!(address = %listener.local_addr()?, "serving the web UI and API");
        serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await
    }

    /// Like [`Self::serve`], over TLS.
    pub async fn serve_tls(
        self,
        listener: TcpListener,
        tls: Arc<rustls::ServerConfig>,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> io::Result<()> {
        tokio::spawn(refresh::run_schedule(self.state.clone()));
        let app = router(self.state);
        info!(address = %listener.local_addr()?, "serving the web UI and API over TLS");

        let handle = axum_server::Handle::new();
        let stopping = handle.clone();
        tokio::spawn(async move {
            shutdown.await;
            stopping.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
        });
        let config = axum_server::tls_rustls::RustlsConfig::from_config(tls);
        axum_server::from_tcp_rustls(listener.into_std()?, config)?
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
    }
}

/// Why the API couldn't start.
#[derive(Debug, thiserror::Error)]
pub enum ApiStartError {
    #[error(transparent)]
    Database(#[from] dns_storage::ConfigDbError),
    #[error("cannot prepare password hashing: {0}")]
    Password(String),
}

fn api_routes() -> Router<AppState> {
    use routes::*;
    Router::new()
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/auth/status", get(auth_status))
        .route("/auth/setup", post(auth_setup))
        .route("/auth/login", post(auth_login))
        .route("/auth/logout", post(auth_logout))
        .route("/auth/session", get(auth_session))
        .route("/auth/password", post(auth_password))
        .route("/overview", get(overview))
        .route("/queries", get(queries))
        .route("/queries/stream", get(queries_stream))
        .route("/rules", get(list_rules).post(create_rule))
        .route("/rules/test", post(test_rule))
        .route(
            "/rules/{id}",
            get(get_rule).patch(update_rule).delete(delete_rule),
        )
        .route("/lists", get(list_lists).post(create_list))
        .route(
            "/lists/{id}",
            get(get_list).patch(update_list).delete(delete_list),
        )
        .route("/lists/{id}/refresh", post(refresh_list))
        .route("/jobs/{id}", get(get_job))
        .route("/clients", get(list_clients).post(create_client))
        .route(
            "/clients/{id}",
            axum::routing::patch(update_client).delete(delete_client),
        )
        .route("/groups", get(list_groups).post(create_group))
        .route(
            "/groups/{id}",
            axum::routing::patch(update_group).delete(delete_group),
        )
        .route("/dns/cache", get(cache_stats).delete(flush_cache))
        .route("/dns/zones", get(list_zones).post(create_zone))
        .route("/dns/zones/{name}", axum::routing::delete(delete_zone))
        .route("/dns/records", get(list_records).post(create_record))
        .route(
            "/dns/records/{id}",
            axum::routing::patch(update_record).delete(delete_record),
        )
        .route("/dns/upstreams", get(list_upstreams))
        .route("/dns/upstreams/test", post(test_upstreams))
        .route("/config/revisions", get(list_revisions))
        .route("/config/activate", post(activate_revision))
        .route("/settings", get(get_settings).put(put_settings))
        .route("/backup", post(create_backup))
        .route(
            "/backup/restore",
            post(restore_backup).layer(axum::extract::DefaultBodyLimit::max(MAX_BACKUP_UPLOAD)),
        )
        .route("/system/status", get(system_status))
        .route("/audit-events", get(audit_events))
        .fallback(|| async { ApiError::not_found("That API endpoint") })
}

fn router(state: AppState) -> Router {
    let hsts = state.hsts;
    let app = Router::new()
        .nest("/api/v1", api_routes())
        .fallback(static_asset)
        .layer(middleware::from_fn_with_state(state.clone(), check_host))
        .layer(middleware::from_fn(security_headers))
        .with_state(state);
    if hsts {
        app.layer(middleware::from_fn(strict_transport_security))
    } else {
        app
    }
}

async fn strict_transport_security(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
    response
}

/// Rejects requests for unknown host names, which is what DNS rebinding depends on.
async fn check_host(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // HTTP/2 carries the host in the request's authority instead of a Host header.
    let allowed = request
        .headers()
        .get(HOST)
        .and_then(|host| host.to_str().ok())
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str())
        })
        .is_some_and(|host| state.hosts.allows(host));
    if !allowed {
        warn!("rejected a request with an unrecognized Host header");
        return Err(ApiError::new(
            StatusCode::MISDIRECTED_REQUEST,
            "HOST_NOT_ALLOWED",
            "This node doesn't answer to that host name. Start it with --web-host to allow it.",
        ));
    }
    Ok(next.run(request).await)
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn content_type_for(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// Serves the embedded UI, sending unknown paths to `index.html` for client-side routing.
async fn static_asset(method: Method, uri: Uri) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = uri.path().trim_start_matches('/');
    if !path.is_empty()
        && let Some(asset) = UiAssets::get(path)
    {
        // Vite puts a content hash in everything under assets/, so it never goes stale.
        let cache = if path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return (
            [
                (CONTENT_TYPE, content_type_for(path)),
                (CACHE_CONTROL, cache),
            ],
            Body::from(asset.data.into_owned()),
        )
            .into_response();
    }
    match UiAssets::get("index.html") {
        Some(index) => (
            [
                (CONTENT_TYPE, "text/html; charset=utf-8"),
                (CACHE_CONTROL, "no-cache"),
            ],
            Body::from(index.data.into_owned()),
        )
            .into_response(),
        None => Html(
            "<!doctype html><title>FerrixDNS</title><h1>The web UI hasn't been built</h1>\
             <p>Run <code>pnpm --dir frontend install</code> and \
             <code>pnpm --dir frontend build</code>, then rebuild the node. \
             The API and DNS are running normally.</p>",
        )
        .into_response(),
    }
}

#[derive(OpenApi)]
#[openapi(
    info(title = "FerrixDNS Node API", version = "1"),
    paths(
        routes::health_live,
        routes::health_ready,
        routes::auth_status,
        routes::auth_setup,
        routes::auth_login,
        routes::auth_logout,
        routes::auth_session,
        routes::auth_password,
        routes::overview,
        routes::queries,
        routes::queries_stream,
        routes::list_rules,
        routes::create_rule,
        routes::get_rule,
        routes::update_rule,
        routes::delete_rule,
        routes::test_rule,
        routes::list_lists,
        routes::create_list,
        routes::get_list,
        routes::update_list,
        routes::delete_list,
        routes::refresh_list,
        routes::get_job,
        routes::list_clients,
        routes::create_client,
        routes::update_client,
        routes::delete_client,
        routes::list_groups,
        routes::create_group,
        routes::update_group,
        routes::delete_group,
        routes::list_zones,
        routes::create_zone,
        routes::delete_zone,
        routes::list_records,
        routes::create_record,
        routes::update_record,
        routes::delete_record,
        routes::cache_stats,
        routes::flush_cache,
        routes::list_upstreams,
        routes::test_upstreams,
        routes::list_revisions,
        routes::activate_revision,
        routes::get_settings,
        routes::put_settings,
        routes::create_backup,
        routes::restore_backup,
        routes::system_status,
        routes::audit_events,
    )
)]
struct ApiDoc;

/// The API contract as OpenAPI JSON, from which the UI's types are generated.
pub fn openapi_json() -> Result<String, serde_json::Error> {
    ApiDoc::openapi().to_pretty_json()
}

/// Sets an administrator's password and ends their sessions, for `ferrixdns` account recovery.
pub async fn reset_password(
    db: &ConfigDb,
    username: &str,
    password: String,
) -> Result<bool, ResetPasswordError> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(ResetPasswordError::TooShort);
    }
    let hash = tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|error| ResetPasswordError::Hash(error.to_string()))?
        .map_err(|error| ResetPasswordError::Hash(error.message))?;
    Ok(db.set_password(username, &hash).await?)
}

/// Why a password couldn't be reset.
#[derive(Debug, thiserror::Error)]
pub enum ResetPasswordError {
    #[error("use at least {MIN_PASSWORD_LENGTH} characters")]
    TooShort,
    #[error("cannot hash the password: {0}")]
    Hash(String),
    #[error(transparent)]
    Database(#[from] dns_storage::ConfigDbError),
}

#[cfg(test)]
mod tests;
