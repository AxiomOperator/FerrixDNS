//! The central controller: sites, nodes, signed policy bundles and fleet metrics.
//!
//! Policy for each site is edited with the same API as a standalone node, on a policy manager that
//! serves no DNS. Deploying signs what's there into a bundle, and nodes fetch it themselves. Nodes
//! never wait for the controller to answer DNS. See ADR-015.

mod dto;
mod fleet;
mod nodes;
mod store;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, FromRef, Path as AxumPath, Request, State};
use axum::http::header::HOST;
use axum::http::{HeaderValue, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, patch, post};
use dns_lists::{FetchLimits, Fetcher};
use dns_policy::PolicyDocument;
use dns_runtime::{PolicyManager, Services};
use dns_storage::{ArtifactStore, ConfigDb};
use dns_upstreams::{PoolConfig, UpstreamPool};
use fleet_contract::{SigningKey, sha256_hex};
use node_api::{AllowedHosts, Api, ApiConfig, ApiError, AppState, ServerRole, now_ms, protect};
use tokio::task::JoinHandle;
use tower::ServiceExt;
use tracing::{error, info, warn};
use utoipa::OpenApi;

pub use store::StoreError;
use store::{Site, Store};

const SIGNING_KEY_FILE: &str = "signing.key";
const FLEET_DB: &str = "fleet.db";
const CONFIG_DB: &str = "config.db";
const CONTENT_DIRECTORY: &str = "bundle-files";
const SITES_DIRECTORY: &str = "sites";
const OWN_POLICY_DIRECTORY: &str = "controller";
/// The largest message a node sends: its report, or an acknowledgement.
const MAX_NODE_BODY: usize = 8 * 1024 * 1024;
const LIST_DEPLOY_CHECK: Duration = Duration::from_secs(60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);

/// The parts of the node API a site's policy is edited with. A site serves no DNS, so nothing
/// about live traffic applies to it.
const SITE_PATHS: &[&str] = &[
    "rules",
    "lists",
    "jobs",
    "clients",
    "groups",
    "blocked-services",
    "dns/zones",
    "dns/records",
    "dns/forwarders",
    "settings",
    "config/revisions",
    "config/activate",
];

/// The parts of the node API that apply to the controller itself.
const OWN_API_PATHS: &[&str] = &["/api/v1/auth/", "/api/v1/health/", "/api/v1/audit-events"];

/// Why the controller couldn't start.
#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[error("cannot use the controller's state directory: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("cannot open the accounts database: {0}")]
    Config(#[from] dns_storage::ConfigDbError),
    #[error(transparent)]
    Api(#[from] node_api::ApiStartError),
    #[error("cannot load a site's policy: {0}")]
    Policy(#[from] dns_runtime::PolicyLoadError),
    #[error("the signing key can't be used: {0}")]
    Key(#[from] fleet_contract::ContractError),
    #[error("cannot prepare list downloads: {0}")]
    Fetcher(String),
    #[error("cannot prepare the controller: {0}")]
    Setup(String),
    #[error("a database request failed: {0}")]
    Database(#[from] sqlx::Error),
}

/// What's needed to start a controller.
pub struct ControllerConfig {
    pub state_dir: PathBuf,
    /// The address nodes use to reach this controller.
    pub public_url: String,
    /// The SHA-256 of a self-signed certificate, which nodes then pin.
    pub tls_pin: Option<String>,
    pub hosts: Vec<String>,
    pub secure_cookies: bool,
    pub hsts: bool,
    pub allow_private_list_urls: bool,
}

struct SiteHandle {
    manager: Arc<PolicyManager>,
    router: Router,
    refreshes: JoinHandle<()>,
}

/// Everything the controller's handlers need. Cloning is cheap.
#[derive(Clone)]
pub struct ControlState {
    pub(crate) store: Store,
    pub(crate) app: AppState,
    pub(crate) content: ArtifactStore,
    pub(crate) signing: Arc<SigningKey>,
    pub(crate) public_url: Arc<str>,
    pub(crate) tls_pin: Option<Arc<str>>,
    sites: Arc<RwLock<HashMap<String, Arc<SiteHandle>>>>,
    state_dir: Arc<PathBuf>,
    site_template: Arc<SiteTemplate>,
}

impl FromRef<ControlState> for AppState {
    fn from_ref(state: &ControlState) -> Self {
        state.app.clone()
    }
}

/// What every site's API shares.
struct SiteTemplate {
    db: ConfigDb,
    fetcher: Fetcher,
    hosts: AllowedHosts,
    secure_cookies: bool,
    hsts: bool,
}

/// A pool with no servers, for the parts of the API that need one. Nothing here sends DNS.
fn empty_pool() -> Result<Arc<UpstreamPool>, ControllerError> {
    UpstreamPool::new(PoolConfig {
        servers: Vec::new(),
        load_balance: false,
        attempt_timeout: Duration::from_millis(1),
        total_timeout: Duration::from_millis(1),
        rounds: 1,
        trust_roots: None,
    })
    .map(Arc::new)
    .map_err(|error| ControllerError::Setup(error.to_string()))
}

impl ControlState {
    pub(crate) fn site_handle(&self, id: &str) -> Option<Arc<SiteHandleView>> {
        self.sites
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .map(|handle| {
                Arc::new(SiteHandleView {
                    manager: Arc::clone(&handle.manager),
                })
            })
    }

    fn site_router(&self, id: &str) -> Option<Router> {
        self.sites
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .map(|handle| handle.router.clone())
    }

    fn site_directory(&self, id: &str) -> PathBuf {
        self.state_dir.join(SITES_DIRECTORY).join(id)
    }

    /// Loads a site's policy and starts refreshing its lists.
    pub(crate) async fn start_site(
        &self,
        id: &str,
    ) -> Result<Arc<SiteHandleView>, ControllerError> {
        let directory = self.site_directory(id);
        let manager =
            tokio::task::spawn_blocking(move || PolicyManager::start(None, Some(directory)))
                .await
                .map_err(|error| ControllerError::Setup(error.to_string()))??;
        let template = &self.site_template;
        let api = Api::new(ApiConfig {
            manager: Arc::clone(&manager),
            telemetry: None,
            db: template.db.clone(),
            pool: empty_pool()?,
            cache: None,
            fetcher: template.fetcher.clone(),
            hosts: template.hosts.clone(),
            secure_cookies: template.secure_cookies,
            dns_listeners: Vec::new(),
            dnssec_validation: false,
            hsts: template.hsts,
            services: Services::detached(Vec::new()),
            ntp: None,
            node: None,
            role: ServerRole::Controller,
        })
        .await?;
        let refreshes = api.spawn_list_refreshes();
        let handle = SiteHandle {
            manager: Arc::clone(&manager),
            router: api.router(),
            refreshes,
        };
        self.sites
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.to_owned(), Arc::new(handle));
        Ok(Arc::new(SiteHandleView { manager }))
    }

    /// Stops a site's work and removes its policy files.
    pub(crate) fn stop_site(&self, id: &str) {
        let handle = self
            .sites
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        if let Some(handle) = handle {
            handle.refreshes.abort();
        }
        let directory = self.site_directory(id);
        if let Err(problem) = fs::remove_dir_all(&directory)
            && problem.kind() != io::ErrorKind::NotFound
        {
            warn!(%problem, directory = %directory.display(), "cannot remove a deleted site's files");
        }
    }
}

/// A site's policy.
pub(crate) struct SiteHandleView {
    pub manager: Arc<PolicyManager>,
}

/// Gives a new site a copy of another site's policy and lists.
pub(crate) async fn copy_policy(
    from: &SiteHandleView,
    to: &SiteHandleView,
) -> Result<(), ApiError> {
    let (source, target) = (Arc::clone(&from.manager), Arc::clone(&to.manager));
    tokio::task::spawn_blocking(move || {
        let export = source.export().map_err(ApiError::internal)?;
        if export.revisions.is_empty() {
            return Ok(());
        }
        let newest: Vec<(String, Vec<u8>)> = export.revisions.into_iter().take(1).collect();
        target
            .restore(&newest, &export.artifacts)
            .map(|_| ())
            .map_err(ApiError::internal)
    })
    .await
    .map_err(ApiError::internal)?
}

/// A controller, ready to serve.
pub struct Controller {
    state: ControlState,
    setup_token: Option<String>,
}

/// Loads the signing key, creating it the first time. Whoever holds this can direct every node.
fn load_signing_key(path: &Path) -> Result<SigningKey, ControllerError> {
    match fs::read(path) {
        Ok(bytes) => Ok(SigningKey::from_pkcs8(&bytes)?),
        Err(problem) if problem.kind() == io::ErrorKind::NotFound => {
            use std::io::Write;
            let (key, stored) = SigningKey::generate()?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&stored)?;
            file.sync_all()?;
            Ok(key)
        }
        Err(problem) => Err(problem.into()),
    }
}

impl Controller {
    pub async fn new(config: ControllerConfig) -> Result<Self, ControllerError> {
        let state_dir = config.state_dir;
        fs::create_dir_all(state_dir.join(SITES_DIRECTORY))?;
        let store = Store::open(&state_dir.join(FLEET_DB)).await?;
        let db = ConfigDb::open(&state_dir.join(CONFIG_DB)).await?;
        let signing = load_signing_key(&state_dir.join(SIGNING_KEY_FILE))?;
        let content = ArtifactStore::open(state_dir.join(CONTENT_DIRECTORY))?;
        let fetcher = Fetcher::new(FetchLimits::default(), config.allow_private_list_urls)
            .map_err(|error| ControllerError::Fetcher(error.to_string()))?;
        let hosts = AllowedHosts::new(config.hosts);

        // Sign-in and the dashboard itself are the same as a node's. This manager's policy is never
        // served or edited.
        let own_directory = state_dir.join(OWN_POLICY_DIRECTORY);
        let own_manager =
            tokio::task::spawn_blocking(move || PolicyManager::start(None, Some(own_directory)))
                .await
                .map_err(|error| ControllerError::Setup(error.to_string()))??;
        let api = Api::new(ApiConfig {
            manager: own_manager,
            telemetry: None,
            db: db.clone(),
            pool: empty_pool()?,
            cache: None,
            fetcher: fetcher.clone(),
            hosts: hosts.clone(),
            secure_cookies: config.secure_cookies,
            dns_listeners: Vec::new(),
            dnssec_validation: false,
            hsts: config.hsts,
            services: Services::detached(Vec::new()),
            ntp: None,
            node: None,
            role: ServerRole::Controller,
        })
        .await?;
        let setup_token = api.setup_token().map(ToOwned::to_owned);

        let state = ControlState {
            store,
            app: api.state(),
            content,
            signing: Arc::new(signing),
            public_url: config.public_url.trim_end_matches('/').into(),
            tls_pin: config.tls_pin.map(Into::into),
            sites: Arc::default(),
            state_dir: Arc::new(state_dir),
            site_template: Arc::new(SiteTemplate {
                db,
                fetcher,
                hosts,
                secure_cookies: config.secure_cookies,
                hsts: config.hsts,
            }),
        };
        for site in state.store.sites().await? {
            state.start_site(&site.id).await?;
        }
        Ok(Self { state, setup_token })
    }

    /// The token for first-run setup, which the controller shows the operator.
    pub fn setup_token(&self) -> Option<&str> {
        self.setup_token.as_deref()
    }

    /// Starts the controller's own background work.
    pub fn start_background_work(&self) {
        tokio::spawn(deploy_list_updates(self.state.clone()));
        tokio::spawn(clean_up(self.state.clone()));
    }

    /// The controller's routes.
    pub fn router(&self) -> Router {
        let state = self.state.clone();
        let fleet = Router::new()
            .route("/controller", get(fleet::controller_info))
            .route("/overview", get(fleet::fleet_overview))
            .route("/sites", get(fleet::list_sites).post(fleet::create_site))
            .route(
                "/sites/{id}",
                patch(fleet::update_site).delete(fleet::delete_site),
            )
            .route("/nodes", get(fleet::list_nodes))
            .route(
                "/nodes/{id}",
                patch(fleet::update_node).delete(fleet::delete_node),
            )
            .route(
                "/enrollment-tokens",
                get(fleet::list_tokens).post(fleet::create_token),
            )
            .route("/enrollment-tokens/{id}", delete(fleet::delete_token))
            .route(
                "/deployments",
                get(fleet::list_deployments).post(fleet::create_deployment),
            )
            .route("/deployments/{id}", get(fleet::get_deployment))
            .route("/deployments/{id}/promote", post(fleet::promote_deployment))
            .route(
                "/deployments/{id}/rollback",
                post(fleet::rollback_deployment),
            );

        let dashboard: Router = Router::new()
            .nest("/api/v1/fleet", fleet)
            .route("/api/v1/sites/{site}/{*rest}", any(site_policy))
            .with_state(state.clone());
        let dashboard = protect(dashboard, &state.app);

        // Nodes prove who they are with signatures, and may know this server by any name.
        let node_routes: Router = Router::new()
            .route("/enroll", post(nodes::enroll))
            .route("/heartbeat", post(nodes::heartbeat))
            .route("/bundles/{id}", get(nodes::get_bundle))
            .route("/bundles/{id}/ack", post(nodes::ack_bundle))
            .route("/artifacts/{sha256}", get(nodes::get_artifact))
            .layer(axum::extract::DefaultBodyLimit::max(MAX_NODE_BODY))
            .with_state(state.clone());

        let own = self.own_api();
        Router::new()
            .nest("/node/v1", node_routes)
            .merge(dashboard)
            .fallback(any(move |request: Request| {
                let own = own.clone();
                async move { own_api(own, request).await }
            }))
    }

    fn own_api(&self) -> Router {
        node_api::dashboard_router(self.state.app.clone())
    }
}

/// Sign-in, the audit log and the dashboard's files. Every other node API path is hidden, because
/// on a controller those belong to a site.
async fn own_api(router: Router, request: Request) -> Response {
    let path = request.uri().path();
    let is_api = path == "/api" || path.starts_with("/api/");
    if is_api
        && !OWN_API_PATHS
            .iter()
            .any(|allowed| path.starts_with(allowed))
    {
        return ApiError::not_found("That API endpoint").into_response();
    }
    match router.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// Passes a request about a site's policy to that site's API.
async fn site_policy(
    State(state): State<ControlState>,
    AxumPath((site, rest)): AxumPath<(String, String)>,
    request: Request<Body>,
) -> Response {
    let allowed = SITE_PATHS.iter().any(|path| {
        rest == *path
            || rest
                .strip_prefix(path)
                .is_some_and(|tail| tail.starts_with('/'))
    });
    if !allowed {
        return ApiError::not_found("That API endpoint").into_response();
    }
    let Some(router) = state.site_router(&site) else {
        return ApiError::not_found("That site").into_response();
    };
    let query = request
        .uri()
        .query()
        .map_or(String::new(), |query| format!("?{query}"));
    let Ok(uri) = format!("/api/v1/{rest}{query}").parse::<Uri>() else {
        return ApiError::not_found("That API endpoint").into_response();
    };
    // A new request, because this route's own path parameters would otherwise reach the site's.
    let (parts, body) = request.into_parts();
    let mut forwarded = Request::new(body);
    *forwarded.method_mut() = parts.method;
    *forwarded.uri_mut() = uri;
    *forwarded.version_mut() = parts.version;
    *forwarded.headers_mut() = parts.headers;
    // HTTP/2 carries the host name in the address being replaced, and the site's API checks it.
    if !forwarded.headers().contains_key(HOST)
        && let Some(authority) = parts.uri.authority()
        && let Ok(host) = HeaderValue::from_str(authority.as_str())
    {
        forwarded.headers_mut().insert(HOST, host);
    }
    if let Some(peer) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
        forwarded.extensions_mut().insert(*peer);
    }
    match router.oneshot(forwarded).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// Whether two policies differ only in the lists' downloaded content.
fn only_lists_changed(old: &PolicyDocument, new: &PolicyDocument) -> bool {
    let without_content = |document: &PolicyDocument| {
        let mut copy = document.clone();
        for list in &mut copy.lists {
            list.artifact_sha256 = None;
        }
        copy
    };
    old != new && without_content(old) == without_content(new)
}

/// Sends out changed list downloads. Any other change waits for someone to deploy it.
async fn deploy_list_updates(state: ControlState) {
    loop {
        tokio::time::sleep(LIST_DEPLOY_CHECK).await;
        if let Err(problem) = deploy_list_updates_once(&state).await {
            error!(%problem, "cannot check for list updates to deploy");
        }
    }
}

async fn deploy_list_updates_once(state: &ControlState) -> Result<(), ControllerError> {
    for site in state.store.sites().await? {
        if let Err(problem) = deploy_site_list_update(state, &site).await {
            warn!(site = %site.name, %problem, "cannot deploy a list update");
        }
    }
    Ok(())
}

async fn deploy_site_list_update(state: &ControlState, site: &Site) -> Result<(), String> {
    if !site.auto_deploy_lists {
        return Ok(());
    }
    let describe = |error: sqlx::Error| error.to_string();
    // Lists only update themselves on a site that has been deployed at least once.
    let Some(latest) = state
        .store
        .latest_deployment(&site.id)
        .await
        .map_err(describe)?
    else {
        return Ok(());
    };
    let Some(bundle) = state
        .store
        .bundle(&latest.bundle_id)
        .await
        .map_err(describe)?
    else {
        return Ok(());
    };
    let Some(handle) = state.site_handle(&site.id) else {
        return Ok(());
    };
    let content = state.content.clone();
    let hash = bundle.policy_sha256.clone();
    let deployed = tokio::task::spawn_blocking(move || content.get(&hash))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    let deployed = std::str::from_utf8(&deployed)
        .ok()
        .and_then(|text| PolicyDocument::parse(text).ok())
        .ok_or("the deployed policy can't be read")?;
    let current = handle.manager.document();
    if !only_lists_changed(&deployed, &current) {
        return Ok(());
    }
    let revision = current.to_toml().map_err(|error| error.to_string())?;
    if sha256_hex(revision.as_bytes()) == bundle.policy_sha256 {
        return Ok(());
    }
    info!(site = %site.name, "deploying updated lists");
    fleet::deploy_current(
        state,
        &site.id,
        "list_refresh",
        "Lists updated",
        "controller",
    )
    .await
    .map_err(|error| format!("{error:?}"))?;
    Ok(())
}

async fn clean_up(state: ControlState) {
    loop {
        tokio::time::sleep(CLEANUP_INTERVAL).await;
        if let Err(problem) = state.store.forget_old_rollups(now_ms()).await {
            warn!(%problem, "cannot clean up old fleet counts");
        }
    }
}

#[derive(OpenApi)]
#[openapi(paths(
    fleet::controller_info,
    fleet::fleet_overview,
    fleet::list_sites,
    fleet::create_site,
    fleet::update_site,
    fleet::delete_site,
    fleet::list_nodes,
    fleet::update_node,
    fleet::delete_node,
    fleet::list_tokens,
    fleet::create_token,
    fleet::delete_token,
    fleet::list_deployments,
    fleet::get_deployment,
    fleet::create_deployment,
    fleet::promote_deployment,
    fleet::rollback_deployment,
))]
struct ControlDoc;

/// The dashboard API contract, which the UI's types are generated from.
pub fn openapi() -> utoipa::openapi::OpenApi {
    ControlDoc::openapi()
}
