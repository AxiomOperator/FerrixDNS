//! Connects a node to its central controller.
//!
//! This runs beside the DNS path and nothing in that path waits for it. If the controller can't be
//! reached, the node keeps enforcing the last policy it applied, including across restarts. See
//! ADR-015.

mod tls;

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use dns_cache::DnsCache;
use dns_runtime::{PolicyManager, Services};
use dns_telemetry::Telemetry;
use dns_upstreams::UpstreamPool;
use fleet_contract::{
    Ack, AckState, CacheReport, DesiredBundle, EnrollRequest, EnrollResponse, EnrollmentToken,
    Heartbeat, HeartbeatResponse, Manifest, ManifestFile, NODE_HEADER, RollupRow, SIGNATURE_HEADER,
    SignedBundle, SigningKey, TIME_HEADER, UpstreamReport, sha256_hex, verify_manifest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

const AGENT_DIRECTORY: &str = "agent";
const IDENTITY_FILE: &str = "identity.json";
const KEY_FILE: &str = "node.key";
const STATE_FILE: &str = "state.json";

/// How often a node reports in and asks what it should be running.
const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(10);
/// The longest wait after failures, so an outage doesn't turn into a flood when it ends.
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Query counts are sent again this far back, in case a newer copy of a minute came along.
const ROLLUP_OVERLAP_MS: i64 = 120_000;
/// The most history sent at once after an outage. The rest follows in later reports.
const MAX_ROLLUP_SPAN_MS: i64 = 6 * 60 * 60 * 1000;
/// The smoke test asks for a name the node answers itself, so upstreams can't affect it.
const SMOKE_QUERY: &[u8] =
    b"\x46\x58\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09localhost\x00\x00\x01\x00\x01";
const SMOKE_ATTEMPTS: u32 = 3;
const SMOKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Why the agent couldn't start.
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("this node needs a state directory to join a controller")]
    NoStateDirectory,
    #[error("this node hasn't joined a controller, so give it an enrollment token")]
    NoToken,
    #[error(transparent)]
    Token(#[from] fleet_contract::ContractError),
    #[error("the controller's address must use https, unless it's on this machine: {0}")]
    InsecureUrl(String),
    #[error("cannot use the controller's connection settings: {0}")]
    Tls(String),
    #[error("cannot read or write the node's identity: {0}")]
    Io(#[from] io::Error),
    #[error("the node's identity files are damaged: {0}")]
    Damaged(String),
}

/// What the agent is given to work with.
pub struct AgentConfig {
    pub state_dir: PathBuf,
    /// Only used to join. Once a node has an identity, it's ignored.
    pub enroll_token: Option<String>,
    /// A PEM file of a private certificate authority that signed the controller's certificate.
    pub controller_ca: Option<PathBuf>,
    pub name: String,
    pub manager: Arc<PolicyManager>,
    pub telemetry: Option<Arc<Telemetry>>,
    pub cache: Option<Arc<DnsCache>>,
    pub pool: Arc<UpstreamPool>,
    pub services: Services,
    pub listeners: Vec<SocketAddr>,
    /// How often to report in. `None` uses the normal interval.
    pub sync_interval: Option<Duration>,
}

/// How this node knows its controller, kept apart from its private key.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Identity {
    node_id: String,
    site_id: String,
    url: String,
    controller_key: String,
    tls_pin: Option<String>,
}

/// What survives a restart, written only once it's true.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AgentState {
    applied_generation: u64,
    /// The newest generation that went wrong here. It isn't tried again.
    #[serde(default)]
    rejected_generation: u64,
    #[serde(default)]
    rollups_stored_through_ms: i64,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

/// Replaces a file in one step, so a crash leaves either the old content or the new.
fn write_atomic(path: &Path, content: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write;

    let temporary = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&temporary)?;
    file.write_all(content)?;
    file.sync_all()?;
    fs::rename(&temporary, path)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, AgentError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| AgentError::Damaged(format!("{}: {error}", path.display()))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn is_local_url(url: &str) -> bool {
    let rest = url.strip_prefix("http://").unwrap_or_default();
    let host = rest.split(['/', ':']).next().unwrap_or_default();
    matches!(host, "127.0.0.1" | "localhost") || rest.starts_with("[::1]")
}

fn check_url(url: &str) -> Result<(), AgentError> {
    if url.starts_with("https://") || is_local_url(url) {
        Ok(())
    } else {
        Err(AgentError::InsecureUrl(url.to_owned()))
    }
}

fn http_client(
    identity_pin: Option<&str>,
    ca_file: Option<&Path>,
) -> Result<reqwest::Client, AgentError> {
    let ca = ca_file.map(fs::read).transpose()?;
    let tls = tls::client_config(identity_pin, ca.as_deref()).map_err(AgentError::Tls)?;
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("FerrixDNS-node/", env!("CARGO_PKG_VERSION")))
        .tls_backend_preconfigured(tls)
        .build()
        .map_err(|error| AgentError::Tls(error.to_string()))
}

/// A connection to the controller, signing every request.
struct Link {
    client: reqwest::Client,
    identity: Identity,
    key: SigningKey,
}

/// What can go wrong talking to the controller.
#[derive(Debug, Error)]
enum SyncError {
    #[error("{0}")]
    Network(String),
    #[error("the controller answered HTTP {status}: {message}")]
    Refused { status: u16, message: String },
    #[error("the answer couldn't be understood: {0}")]
    Malformed(String),
}

impl SyncError {
    /// This node is no longer known to the controller.
    fn is_revoked(&self) -> bool {
        matches!(self, Self::Refused { status: 401, .. })
    }
}

impl Link {
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, SyncError> {
        let time = now_ms();
        let signature = self.key.sign_request(method.as_str(), path, time, &body);
        let response = self
            .client
            .request(method, format!("{}{path}", self.identity.url))
            .header(NODE_HEADER, &self.identity.node_id)
            .header(TIME_HEADER, time.to_string())
            .header(SIGNATURE_HEADER, signature)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| SyncError::Network(without_url(&error)))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| SyncError::Network(without_url(&error)))?;
        if status.is_success() {
            Ok(bytes.to_vec())
        } else {
            Err(SyncError::Refused {
                status: status.as_u16(),
                message: String::from_utf8_lossy(&bytes).chars().take(300).collect(),
            })
        }
    }

    async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, SyncError> {
        let body =
            serde_json::to_vec(body).map_err(|error| SyncError::Malformed(error.to_string()))?;
        let reply = self.call(reqwest::Method::POST, path, body).await?;
        serde_json::from_slice(&reply).map_err(|error| SyncError::Malformed(error.to_string()))
    }

    async fn get(&self, path: &str) -> Result<Vec<u8>, SyncError> {
        self.call(reqwest::Method::GET, path, Vec::new()).await
    }

    async fn ack(&self, bundle_id: &str, ack: &Ack) {
        let result: Result<serde_json::Value, _> = self
            .post(&format!("/node/v1/bundles/{bundle_id}/ack"), ack)
            .await;
        // Heartbeats report the applied generation anyway, so a lost ack corrects itself.
        if let Err(problem) = result {
            warn!(%problem, "cannot tell the controller about a bundle");
        }
    }
}

fn without_url(error: &reqwest::Error) -> String {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        text = format!("{text}: {cause}");
        source = cause.source();
    }
    text
}

/// A connected, enrolled agent.
pub struct Agent {
    config: AgentConfig,
    link: Link,
    state: AgentState,
    state_path: PathBuf,
    started: Instant,
}

async fn enroll(
    token: &EnrollmentToken,
    key: &SigningKey,
    client: &reqwest::Client,
    name: &str,
) -> Result<EnrollResponse, SyncError> {
    let request = EnrollRequest {
        secret: token.secret.clone(),
        public_key: key.public_key(),
        proof: key.sign_enrollment(&token.secret),
        name: name.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    let body =
        serde_json::to_vec(&request).map_err(|error| SyncError::Malformed(error.to_string()))?;
    let response = client
        .post(format!("{}/node/v1/enroll", token.url))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .map_err(|error| SyncError::Network(without_url(&error)))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| SyncError::Network(without_url(&error)))?;
    if !status.is_success() {
        return Err(SyncError::Refused {
            status: status.as_u16(),
            message: String::from_utf8_lossy(&bytes).chars().take(300).collect(),
        });
    }
    serde_json::from_slice(&bytes).map_err(|error| SyncError::Malformed(error.to_string()))
}

/// Loads the node's private key, creating it the first time. It never leaves this machine.
fn load_key(directory: &Path) -> Result<SigningKey, AgentError> {
    let path = directory.join(KEY_FILE);
    match fs::read(&path) {
        Ok(bytes) => SigningKey::from_pkcs8(&bytes)
            .map_err(|error| AgentError::Damaged(format!("{}: {error}", path.display()))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let (key, stored) = SigningKey::generate()?;
            write_atomic(&path, &stored, 0o600)?;
            Ok(key)
        }
        Err(error) => Err(error.into()),
    }
}

/// Whether this node has already joined a controller.
pub fn is_enrolled(state_dir: &Path) -> bool {
    state_dir.join(AGENT_DIRECTORY).join(IDENTITY_FILE).exists()
}

impl Agent {
    /// Loads this node's identity, or joins the controller named in the token. This waits and
    /// retries while the controller can't be reached, unless the controller refuses the token.
    pub async fn connect(config: AgentConfig) -> Result<Self, AgentError> {
        let directory = config.state_dir.join(AGENT_DIRECTORY);
        fs::create_dir_all(&directory)?;
        let key = load_key(&directory)?;
        let identity_path = directory.join(IDENTITY_FILE);
        let ca = config.controller_ca.clone();

        let identity = match read_json::<Identity>(&identity_path)? {
            Some(identity) => identity,
            None => {
                let text = config.enroll_token.as_deref().ok_or(AgentError::NoToken)?;
                let token = EnrollmentToken::decode(text)?;
                check_url(&token.url)?;
                let client = http_client(token.tls_pin.as_deref(), ca.as_deref())?;
                let enrolled = enroll_until_answered(&token, &key, &client, &config.name).await?;
                let identity = Identity {
                    node_id: enrolled.node_id,
                    site_id: enrolled.site_id,
                    url: token.url,
                    controller_key: token.controller_key,
                    tls_pin: token.tls_pin,
                };
                let bytes = serde_json::to_vec_pretty(&identity)
                    .map_err(|error| AgentError::Damaged(error.to_string()))?;
                write_atomic(&identity_path, &bytes, 0o600)?;
                info!(node = %identity.node_id, site = %identity.site_id, "joined the controller");
                identity
            }
        };
        check_url(&identity.url)?;

        let client = http_client(identity.tls_pin.as_deref(), ca.as_deref())?;
        let state_path = directory.join(STATE_FILE);
        let state = read_json(&state_path)?.unwrap_or_default();
        Ok(Self {
            config,
            link: Link {
                client,
                identity,
                key,
            },
            state,
            state_path,
            started: Instant::now(),
        })
    }

    /// Reports in and applies bundles, until the task is stopped. DNS is never affected by this.
    pub async fn run(mut self) {
        let interval = self.config.sync_interval.unwrap_or(DEFAULT_SYNC_INTERVAL);
        let mut failures: u32 = 0;
        loop {
            match self.sync().await {
                Ok(()) => failures = 0,
                Err(problem) if problem.is_revoked() => {
                    failures = failures.saturating_add(1);
                    error!(
                        "the controller no longer recognizes this node. It keeps enforcing its \
                         current policy. To rejoin, remove the agent folder in its state directory \
                         and give it a new token"
                    );
                }
                Err(problem) => {
                    failures = failures.saturating_add(1);
                    warn!(%problem, "cannot reach the controller; DNS isn't affected");
                }
            }
            tokio::time::sleep(next_wait(interval, failures)).await;
        }
    }

    /// One report, and whatever it asks for.
    pub async fn sync(&mut self) -> Result<(), SyncFailure> {
        self.sync_inner().await.map_err(SyncFailure)
    }

    async fn sync_inner(&mut self) -> Result<(), SyncError> {
        let heartbeat = self.heartbeat().await;
        let reply: HeartbeatResponse = self.link.post("/node/v1/heartbeat", &heartbeat).await?;
        if reply.rollups_stored_through_ms > self.state.rollups_stored_through_ms {
            self.state.rollups_stored_through_ms = reply.rollups_stored_through_ms;
            self.save_state();
        }
        if let Some(desired) = reply.desired
            && desired.generation > self.state.applied_generation
            && desired.generation != self.state.rejected_generation
        {
            self.apply(&desired).await?;
        }
        Ok(())
    }

    async fn heartbeat(&self) -> Heartbeat {
        let config = &self.config;
        let cache = config.cache.as_ref().map(|cache| {
            let stats = cache.stats();
            CacheReport {
                hits: stats.hits,
                misses: stats.misses,
                entries: stats.entries,
                stale_served: stats.stale_served,
                prefetches: stats.prefetches,
            }
        });
        Heartbeat {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            name: config.name.clone(),
            uptime_seconds: self.started.elapsed().as_secs(),
            listeners: config.listeners.iter().map(ToString::to_string).collect(),
            applied_generation: self.state.applied_generation,
            policy_revision: config.manager.revision(),
            blocking_paused: config.services.pause.is_active(),
            cache,
            upstreams: config
                .pool
                .stats()
                .into_iter()
                .map(|stats| UpstreamReport {
                    server: stats.server,
                    responses: stats.responses,
                    failures: stats.failures,
                    last_latency_us: stats.last_latency_us,
                })
                .collect(),
            rollups: self.rollups().await,
        }
    }

    /// Finished minutes of query counts that the controller may not have yet.
    async fn rollups(&self) -> Vec<RollupRow> {
        let Some(telemetry) = &self.config.telemetry else {
            return Vec::new();
        };
        let now = now_ms();
        let this_minute = now - now % 60_000;
        let from = (self.state.rollups_stored_through_ms - ROLLUP_OVERLAP_MS)
            .max(this_minute - MAX_ROLLUP_SPAN_MS);
        // After a long outage the oldest is sent first, and each report moves forward.
        let to = (from + MAX_ROLLUP_SPAN_MS).min(this_minute);
        match telemetry.minute_counts(from, to).await {
            Ok(counts) => counts
                .into_iter()
                .map(|count| RollupRow {
                    bucket_start_ms: count.bucket_start_ms,
                    outcome: count.outcome,
                    count: count.count,
                    latency_sum_us: count.latency_sum_us,
                })
                .collect(),
            Err(problem) => {
                warn!(%problem, "cannot read query counts to report");
                Vec::new()
            }
        }
    }

    fn save_state(&self) {
        match serde_json::to_vec_pretty(&self.state) {
            Ok(bytes) => {
                if let Err(problem) = write_atomic(&self.state_path, &bytes, 0o600) {
                    error!(%problem, "cannot save the agent's state");
                }
            }
            Err(problem) => error!(%problem, "cannot save the agent's state"),
        }
    }

    fn check_manifest(
        &self,
        desired: &DesiredBundle,
        signed: &SignedBundle,
    ) -> Result<Manifest, String> {
        let identity = &self.link.identity;
        if !verify_manifest(
            &identity.controller_key,
            &signed.manifest,
            &signed.signature,
        ) {
            return Err("its signature doesn't match this node's controller".to_owned());
        }
        let manifest: Manifest = serde_json::from_str(&signed.manifest)
            .map_err(|problem| format!("its manifest can't be read: {problem}"))?;
        if manifest.site_id != identity.site_id {
            return Err("it's for a different site".to_owned());
        }
        if manifest.bundle_id != desired.bundle_id || manifest.generation != desired.generation {
            return Err("it isn't the bundle that was asked for".to_owned());
        }
        if manifest.generation <= self.state.applied_generation {
            return Err(format!(
                "its generation {} isn't newer than this node's {}",
                manifest.generation, self.state.applied_generation
            ));
        }
        Ok(manifest)
    }

    async fn fetch_file(&self, file: &ManifestFile) -> Result<Vec<u8>, FetchFailure> {
        let bytes = self
            .link
            .get(&format!("/node/v1/artifacts/{}", file.sha256))
            .await
            .map_err(FetchFailure::Retry)?;
        // The signed manifest pins this hash, so whoever served the file doesn't need trusting.
        if sha256_hex(&bytes) != file.sha256 {
            return Err(FetchFailure::Bad(format!(
                "file {} doesn't match its hash",
                file.sha256
            )));
        }
        Ok(bytes)
    }

    async fn apply(&mut self, desired: &DesiredBundle) -> Result<(), SyncError> {
        let bundle_id = &desired.bundle_id;
        let generation = desired.generation;
        let ack = |state, detail: Option<String>, policy_revision: Option<String>| Ack {
            generation,
            state,
            detail,
            policy_revision,
        };

        let body = self
            .link
            .get(&format!("/node/v1/bundles/{bundle_id}"))
            .await?;
        let signed: SignedBundle = serde_json::from_slice(&body)
            .map_err(|error| SyncError::Malformed(error.to_string()))?;
        let manifest = match self.check_manifest(desired, &signed) {
            Ok(manifest) => manifest,
            Err(problem) => {
                error!(%problem, generation, "refusing a bundle");
                self.reject(generation);
                self.link
                    .ack(
                        bundle_id,
                        &ack(AckState::Failed, Some(format!("Refused: {problem}")), None),
                    )
                    .await;
                return Ok(());
            }
        };

        self.link
            .ack(bundle_id, &ack(AckState::Downloading, None, None))
            .await;
        let policy = match self.fetch_file(&manifest.policy).await {
            Ok(policy) => policy,
            Err(FetchFailure::Retry(problem)) => return Err(problem),
            Err(FetchFailure::Bad(problem)) => return self.refuse(desired, problem).await,
        };
        let mut lists = Vec::new();
        for file in &manifest.lists {
            if self.config.manager.has_artifact(&file.sha256) {
                continue;
            }
            match self.fetch_file(file).await {
                Ok(list) => lists.push(list),
                Err(FetchFailure::Retry(problem)) => return Err(problem),
                Err(FetchFailure::Bad(problem)) => return self.refuse(desired, problem).await,
            }
        }
        self.link
            .ack(bundle_id, &ack(AckState::Staged, None, None))
            .await;

        let previous = self.config.manager.revision();
        self.link
            .ack(bundle_id, &ack(AckState::Activating, None, None))
            .await;
        let manager = Arc::clone(&self.config.manager);
        let applied = tokio::task::spawn_blocking(move || manager.apply_bundle(&policy, &lists))
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result.map_err(|error| error.to_string()));
        let revision = match applied {
            Ok(revision) => revision,
            Err(problem) => {
                error!(%problem, generation, "cannot apply a bundle; keeping the current policy");
                return self.refuse(desired, problem).await;
            }
        };

        if let Err(problem) = self.smoke_test().await {
            error!(%problem, generation, "DNS stopped answering after a bundle; going back");
            let manager = Arc::clone(&self.config.manager);
            let back = previous.clone();
            let reverted = tokio::task::spawn_blocking(move || manager.revert_bundle(&back)).await;
            let detail = match reverted {
                Ok(Ok(())) => format!("{problem} This node went back to its previous policy."),
                Ok(Err(failure)) => format!("{problem} Going back also failed: {failure}"),
                Err(failure) => format!("{problem} Going back also failed: {failure}"),
            };
            self.reject(generation);
            self.link
                .ack(
                    bundle_id,
                    &ack(
                        AckState::Reverted,
                        Some(detail),
                        Some(self.config.manager.revision()),
                    ),
                )
                .await;
            return Ok(());
        }

        self.state.applied_generation = generation;
        self.save_state();
        info!(generation, revision = %revision, "bundle applied");
        self.link
            .ack(bundle_id, &ack(AckState::Healthy, None, Some(revision)))
            .await;
        Ok(())
    }

    fn reject(&mut self, generation: u64) {
        self.state.rejected_generation = generation;
        self.save_state();
    }

    async fn refuse(&mut self, desired: &DesiredBundle, problem: String) -> Result<(), SyncError> {
        self.reject(desired.generation);
        let ack = Ack {
            generation: desired.generation,
            state: AckState::Failed,
            detail: Some(problem),
            policy_revision: None,
        };
        self.link.ack(&desired.bundle_id, &ack).await;
        Ok(())
    }

    /// Checks DNS still answers. Any response counts, because even a refusal shows the listener
    /// works, and this machine's address may not be in the allowed networks.
    async fn smoke_test(&self) -> Result<(), String> {
        let Some(address) = self.config.listeners.first().copied() else {
            return Ok(());
        };
        let address = local_target(address);
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let mut last = String::new();
        for _ in 0..SMOKE_ATTEMPTS {
            match ask_once(bind, address).await {
                Ok(()) => return Ok(()),
                Err(problem) => last = problem,
            }
        }
        Err(format!("DNS on {address} didn't answer: {last}."))
    }
}

/// Why a file from a bundle couldn't be used.
enum FetchFailure {
    /// The network failed, which may pass.
    Retry(SyncError),
    /// The file is wrong, and trying again won't help.
    Bad(String),
}

async fn ask_once(bind: &str, address: SocketAddr) -> Result<(), String> {
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|error| error.to_string())?;
    socket
        .connect(address)
        .await
        .map_err(|error| error.to_string())?;
    socket
        .send(SMOKE_QUERY)
        .await
        .map_err(|error| error.to_string())?;
    let mut reply = [0_u8; 512];
    let length = tokio::time::timeout(SMOKE_TIMEOUT, socket.recv(&mut reply))
        .await
        .map_err(|_| "timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    if length >= 12 && reply[..2] == SMOKE_QUERY[..2] {
        Ok(())
    } else {
        Err("the reply wasn't a DNS answer".to_owned())
    }
}

/// A listener on every address is reached over loopback.
fn local_target(address: SocketAddr) -> SocketAddr {
    let mut target = address;
    if address.ip().is_unspecified() {
        target.set_ip(if address.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    target
}

/// A failed report, for callers driving [`Agent::sync`] themselves.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct SyncFailure(SyncError);

impl SyncFailure {
    /// This node is no longer known to the controller.
    pub fn is_revoked(&self) -> bool {
        self.0.is_revoked()
    }
}

/// Retries a little later each time, with some randomness so nodes don't all return at once.
fn next_wait(interval: Duration, failures: u32) -> Duration {
    let base = if failures == 0 {
        interval
    } else {
        interval
            .saturating_mul(2_u32.saturating_pow(failures.min(8)))
            .min(MAX_BACKOFF)
    };
    let jitter = rand::random::<f64>() * 0.2 + 0.9;
    base.mul_f64(jitter)
}

/// Asks the controller to take this node, retrying until it gets a clear answer.
async fn enroll_until_answered(
    token: &EnrollmentToken,
    key: &SigningKey,
    client: &reqwest::Client,
    name: &str,
) -> Result<EnrollResponse, AgentError> {
    let mut failures = 0;
    loop {
        match enroll(token, key, client, name).await {
            Ok(enrolled) => return Ok(enrolled),
            Err(SyncError::Refused { status, message }) if (400..500).contains(&status) => {
                return Err(AgentError::Damaged(format!(
                    "the controller refused this enrollment token. It may have expired or been \
                     used already, so create a new one: {message}"
                )));
            }
            Err(problem) => {
                failures += 1;
                warn!(%problem, "cannot reach the controller to join it; DNS isn't affected");
                tokio::time::sleep(next_wait(DEFAULT_SYNC_INTERVAL, failures)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn only_https_or_this_machine_is_accepted() {
        assert!(check_url("https://control.example:8443").is_ok());
        assert!(check_url("http://127.0.0.1:8443").is_ok());
        assert!(check_url("http://localhost:1").is_ok());
        assert!(check_url("http://[::1]:1").is_ok());
        assert!(check_url("http://control.example").is_err());
        assert!(check_url("http://127.0.0.1.example.com").is_err());
        assert!(check_url("ftp://127.0.0.1").is_err());
    }

    #[test]
    fn waits_grow_with_failures_and_stay_bounded() {
        let interval = Duration::from_secs(10);
        assert!(next_wait(interval, 0) <= Duration::from_secs(11));
        assert!(next_wait(interval, 3) >= Duration::from_secs(70));
        assert!(next_wait(interval, 50) <= MAX_BACKOFF.mul_f64(1.1));
    }

    #[test]
    fn keys_are_private_and_stable() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let first = load_key(directory.path()).unwrap();
        let second = load_key(directory.path()).unwrap();
        assert_eq!(first.public_key(), second.public_key());
        let mode = fs::metadata(directory.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "only the owner can read it");
    }
}
