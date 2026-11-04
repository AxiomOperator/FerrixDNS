//! Settings for the node itself, such as its addresses and upstreams, changed from the dashboard.
//!
//! The command line and environment give the starting values. Only what differs from them is saved,
//! so a value nobody changed here keeps following the service's configuration. These settings are
//! applied by restarting the node, which reuses all of its normal startup checks.
//!
//! A bad address must not leave a node that can't be reached, so a change starts as a trial. If the
//! node can't start with it, the previous settings return. A change to how the dashboard is reached
//! must also be confirmed from the dashboard, in case the new address works but nobody can get to it.
//!
//! The settings file always stays in the folder given by `--state-dir`, even after the data moves,
//! because that's the only place the node knows to look when it starts.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use dns_policy::PolicyDocument;
use dns_upstreams::UpstreamServer;
use ipnet::IpNet;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::watch;
use utoipa::ToSchema;

const FILE_NAME: &str = "node-settings.json";
const DATA_MARKER: &str = "config.db";
const SCHEMA_VERSION: u32 = 1;
const MAX_POLICY_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PEM_FILE_BYTES: u64 = 1024 * 1024;
const MAX_CACHE_MIB: u64 = 1024 * 1024;
const MAX_TTL_SECONDS: u64 = 7 * 86_400;
const MAX_TIMEOUT_MS: u64 = 60_000;
/// Each request in flight uses a socket, and the installed service allows 65,536 open files.
const MAX_CONCURRENT_REQUESTS: u64 = 60_000;

/// How long someone has to confirm a change to how the dashboard is reached.
pub const CONFIRM_WITHIN: Duration = Duration::from_secs(120);

/// How the dashboard is served.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebTlsMode {
    #[default]
    Off,
    SelfSigned,
    Files,
}

/// Every setting of the node that can be changed from the dashboard.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NodeSettings {
    pub listen: Vec<String>,
    pub allow: Vec<String>,
    pub upstreams: Vec<String>,
    /// Shares queries between the upstreams, instead of using the first one that works.
    pub upstream_load_balance: bool,
    pub dnssec_validate: bool,
    pub attempt_timeout_ms: u64,
    pub query_timeout_ms: u64,
    pub max_concurrent_requests: u64,
    pub cache_mib: u64,
    pub cache_max_ttl: u64,
    pub cache_negative_ttl: u64,
    pub web_listen: String,
    pub web_hosts: Vec<String>,
    pub web_tls_mode: WebTlsMode,
    pub web_tls_cert: Option<String>,
    pub web_tls_key: Option<String>,
    pub web_insecure_remote: bool,
    pub ntp_listen: Vec<String>,
    pub allow_private_list_urls: bool,
    pub policy_file: Option<String>,
    /// Where the node keeps its data. Moving it copies the data at the next start.
    pub state_dir: String,
    /// What the node logs, in the format of `RUST_LOG`.
    pub log_filter: String,
}

/// The settings that need parsing, as the types the node uses.
pub struct ParsedSettings {
    pub listen: Vec<SocketAddr>,
    pub allow: Vec<IpNet>,
    pub upstreams: Vec<UpstreamServer>,
    pub web_listen: SocketAddr,
    pub ntp_listen: Vec<SocketAddr>,
}

fn parse_addresses(values: &[String], what: &str) -> Result<Vec<SocketAddr>, String> {
    values
        .iter()
        .map(|value| {
            value.trim().parse().map_err(|_| {
                format!(
                    "{value:?} isn't a valid {what}. Use an address and port, like 192.168.1.10:53"
                )
            })
        })
        .collect()
}

impl NodeSettings {
    /// Parses the values that the node needs as addresses and servers.
    pub fn parse(&self) -> Result<ParsedSettings, String> {
        Ok(ParsedSettings {
            listen: parse_addresses(&self.listen, "DNS address")?,
            allow: self
                .allow
                .iter()
                .map(|value| {
                    value.trim().parse().map_err(|_| {
                        format!("{value:?} isn't a valid network. Use one like 192.168.1.0/24")
                    })
                })
                .collect::<Result<_, String>>()?,
            upstreams: self
                .upstreams
                .iter()
                .map(|value| {
                    value
                        .trim()
                        .parse::<UpstreamServer>()
                        .map_err(|error| error.to_string())
                })
                .collect::<Result<_, String>>()?,
            web_listen: self.web_listen.trim().parse().map_err(|_| {
                format!(
                    "{:?} isn't a valid dashboard address. Use an address and port, like \
                     0.0.0.0:8443",
                    self.web_listen
                )
            })?,
            ntp_listen: parse_addresses(&self.ntp_listen, "time server address")?,
        })
    }

    /// Whether a change could affect how the dashboard is reached.
    pub fn changes_dashboard_access(&self, other: &Self) -> bool {
        self.web_listen != other.web_listen
            || self.web_hosts != other.web_hosts
            || self.web_tls_mode != other.web_tls_mode
            || self.web_tls_cert != other.web_tls_cert
            || self.web_tls_key != other.web_tls_key
            || self.web_insecure_remote != other.web_insecure_remote
    }

    /// Checks the settings, and returns them written the one way the node writes them, so comparing
    /// settings doesn't depend on how someone typed them. This reads any files they name.
    pub fn validated(&self) -> Result<Self, String> {
        let parsed = self.parse()?;
        let mut clean = self.clone();
        clean.listen = strings(&parsed.listen);
        clean.allow = strings(&parsed.allow);
        clean.upstreams = strings(&parsed.upstreams);
        clean.web_listen = parsed.web_listen.to_string();
        clean.ntp_listen = strings(&parsed.ntp_listen);
        clean.web_hosts = clean_hosts(&self.web_hosts)?;
        clean.policy_file = clean_path(self.policy_file.as_deref());
        clean.web_tls_cert = None;
        clean.web_tls_key = None;
        clean.state_dir = self.state_dir.trim().to_owned();
        clean.log_filter = self.log_filter.trim().to_owned();

        require(!parsed.listen.is_empty(), "Add at least one DNS address")?;
        require(
            !parsed.upstreams.is_empty(),
            "Add at least one upstream server",
        )?;
        require(
            !parsed.allow.is_empty(),
            "Add at least one network that may send queries. Without one, every query is refused",
        )?;
        require(
            (1..=MAX_TIMEOUT_MS).contains(&self.attempt_timeout_ms),
            "The time for one upstream must be between 1 and 60,000 ms",
        )?;
        require(
            (self.attempt_timeout_ms..=MAX_TIMEOUT_MS).contains(&self.query_timeout_ms),
            "The time for a whole query must be at least the time for one upstream, and at most \
             60,000 ms",
        )?;
        require(
            (1..=MAX_CONCURRENT_REQUESTS).contains(&self.max_concurrent_requests),
            "Requests in flight must be between 1 and 60,000",
        )?;
        require(
            self.cache_mib <= MAX_CACHE_MIB,
            "The cache can use at most 1,048,576 MiB",
        )?;
        require(
            (1..=MAX_TTL_SECONDS).contains(&self.cache_max_ttl),
            "The longest cache time must be between 1 second and 7 days",
        )?;
        require(
            self.cache_negative_ttl <= MAX_TTL_SECONDS,
            "The cache time for \"not found\" answers can be at most 7 days",
        )?;

        require(!clean.state_dir.is_empty(), "Give a data folder")?;
        if tracing_subscriber::EnvFilter::try_new(&clean.log_filter).is_err() {
            return Err(format!(
                "{:?} isn't a log filter. Use something like info or warn,ferrixdns=debug",
                clean.log_filter
            ));
        }

        match self.web_tls_mode {
            WebTlsMode::Off => {
                require(
                    parsed.web_listen.ip().is_loopback() || self.web_insecure_remote,
                    "Plain HTTP on a network address would expose passwords and query logs. Turn \
                     on TLS, or accept that risk with the plain HTTP option",
                )?;
            }
            WebTlsMode::SelfSigned => clean.web_insecure_remote = false,
            WebTlsMode::Files => {
                clean.web_insecure_remote = false;
                let (Some(cert), Some(key)) = (
                    clean_path(self.web_tls_cert.as_deref()),
                    clean_path(self.web_tls_key.as_deref()),
                ) else {
                    return Err("Give the paths of both the certificate and its key".to_owned());
                };
                load_tls_files(Path::new(&cert), Path::new(&key))?;
                clean.web_tls_cert = Some(cert);
                clean.web_tls_key = Some(key);
            }
        }
        if let Some(policy_file) = &clean.policy_file {
            check_policy_file(Path::new(policy_file))?;
        }
        Ok(clean)
    }

    /// Checks that a change to dashboard access leaves a name to reach the dashboard by. Only a
    /// change is held to this, so a node reached by loopback can still save its other settings.
    pub fn check_reachable_after(&self, existing: &Self) -> Result<(), String> {
        let every_address = self
            .web_listen
            .parse::<SocketAddr>()
            .is_ok_and(|address| address.ip().is_unspecified());
        require(
            !self.changes_dashboard_access(existing)
                || !every_address
                || !self.web_hosts.is_empty(),
            "On every address, the dashboard only answers to names it knows. Add the name or \
             address you'll use to reach it",
        )
    }

    /// The settings that differ from `base`, by name.
    pub fn differences(&self, base: &Self) -> Map<String, Value> {
        let (mut ours, theirs) = (object(self), object(base));
        ours.retain(|name, value| theirs.get(name) != Some(value));
        ours
    }

    /// These settings with saved changes on top.
    pub fn with_changes(&self, changes: &Map<String, Value>) -> Result<Self, serde_json::Error> {
        let mut merged = object(self);
        for (name, value) in changes {
            // A setting from another version is ignored, which keeps a downgrade working.
            if merged.contains_key(name) {
                merged.insert(name.clone(), value.clone());
            }
        }
        serde_json::from_value(Value::Object(merged))
    }
}

fn object(settings: &NodeSettings) -> Map<String, Value> {
    match serde_json::to_value(settings) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    }
}

fn strings<T: ToString>(values: &[T]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn clean_path(path: Option<&str>) -> Option<String> {
    path.map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
}

fn clean_hosts(hosts: &[String]) -> Result<Vec<String>, String> {
    let mut seen = HashSet::new();
    let mut clean = Vec::with_capacity(hosts.len());
    for host in hosts {
        let host = host.trim().to_ascii_lowercase();
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let name = if let Ok(address) = bare.parse::<Ipv6Addr>() {
            format!("[{address}]")
        } else if bare.parse::<IpAddr>().is_ok()
            || (!bare.is_empty()
                && bare == host
                && bare
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.')))
        {
            host.clone()
        } else {
            return Err(format!(
                "{host:?} isn't a host name. Use a name or address without a port, like \
                 dns.home.arpa"
            ));
        };
        if seen.insert(name.clone()) {
            clean.push(name);
        }
    }
    Ok(clean)
}

/// Only regular files of a sensible size are read, because a path like /dev/zero would never end.
fn check_is_file(path: &Path, limit: u64, what: &str) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("Can't read the {what} {}: {error}", path.display()))?;
    require(
        metadata.is_file() && metadata.len() <= limit,
        &format!("The {what} {} isn't a usable file", path.display()),
    )
}

/// The contents stay out of the error, because this can be pointed at any file the node can read.
fn check_policy_file(path: &Path) -> Result<(), String> {
    check_is_file(path, MAX_POLICY_FILE_BYTES, "policy file")?;
    let source = fs::read_to_string(path)
        .map_err(|error| format!("Can't read the policy file {}: {error}", path.display()))?;
    let invalid = || {
        format!(
            "{} isn't a valid policy. Check it with: ferrixdns policy validate {0}",
            path.display()
        )
    };
    let document = PolicyDocument::parse(&source).map_err(|_| invalid())?;
    dns_runtime::validate_forward_servers(&document).map_err(|_| invalid())
}

/// Whether a folder already holds a node's data. The database is copied last, so its presence also
/// means an earlier copy finished.
fn holds_node_data(folder: &Path) -> bool {
    folder.join(DATA_MARKER).is_file()
}

/// Checks that the node can move its data to a folder, or use the data already there.
pub fn check_data_folder(target: &Path, current: &Path) -> Result<(), String> {
    require(
        target.is_absolute(),
        "Give the data folder as a full path, like /var/lib/ferrixdns",
    )?;
    let describe = |error: io::Error| {
        format!(
            "Can't use the data folder {}: {error}. A service can only write where it's allowed \
             to, so it may need adding to ReadWritePaths or a container volume",
            target.display()
        )
    };
    fs::create_dir_all(target).map_err(describe)?;
    let probe = target.join(".ferrixdns-write-test");
    fs::write(&probe, b"").map_err(describe)?;
    fs::remove_file(&probe).map_err(describe)?;

    let (target_real, current_real) = (
        target.canonicalize().map_err(describe)?,
        current.canonicalize().map_err(describe)?,
    );
    require(
        !target_real.starts_with(&current_real) && !current_real.starts_with(&target_real),
        "The new data folder can't be inside the current one, or contain it",
    )?;
    let is_empty = fs::read_dir(target).map_err(describe)?.next().is_none();
    require(
        is_empty || holds_node_data(target),
        "The new data folder must be empty, or already hold this node's data",
    )
}

fn copy_tree(from: &Path, to: &Path, skip: &[&str]) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_str().is_some_and(|name| skip.contains(&name)) {
            continue;
        }
        // Only folders and regular files are node data. Anything else isn't followed.
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&entry.path(), &to.join(&name), &[])?;
        } else if kind.is_file() {
            fs::copy(entry.path(), to.join(&name))?;
        }
    }
    Ok(())
}

/// Copies a node's data to a new folder, unless the data is already there. The old folder stays as
/// it was, so going back loses nothing. Nothing has the data open when this runs at startup.
pub fn move_data(from: &Path, to: &Path) -> io::Result<()> {
    if holds_node_data(to) {
        return Ok(());
    }
    let copied = copy_tree(from, to, &[DATA_MARKER, FILE_NAME]).and_then(|()| {
        let database = from.join(DATA_MARKER);
        if database.is_file() {
            let temp = to.join(format!("{DATA_MARKER}.moving"));
            fs::copy(&database, &temp)?;
            fs::rename(&temp, to.join(DATA_MARKER))?;
        }
        Ok(())
    });
    if copied.is_err() {
        // The folder was empty when this started, so a partial copy can be cleared.
        for entry in fs::read_dir(to)?.flatten() {
            let path = entry.path();
            let _ = if path.is_dir() {
                fs::remove_dir_all(path)
            } else {
                fs::remove_file(path)
            };
        }
    }
    copied
}

fn saved_value(state_dir: &Path, name: &str) -> Option<Value> {
    SettingsStore::new(state_dir)
        .read()
        .ok()?
        .changes
        .get(name)
        .cloned()
}

/// Where the data of a node started with this `--state-dir` is, following any move.
pub fn data_dir(state_dir: &Path) -> PathBuf {
    saved_value(state_dir, "state_dir")
        .and_then(|value| value.as_str().map(PathBuf::from))
        .unwrap_or_else(|| state_dir.to_path_buf())
}

/// The log filter saved from the dashboard, if any.
pub fn saved_log_filter(state_dir: &Path) -> Option<String> {
    saved_value(state_dir, "log_filter")?
        .as_str()
        .map(str::to_owned)
}

/// An address that reaches a DNS listener saved from the dashboard, if any, for health checks.
pub fn saved_dns_address(state_dir: &Path) -> Option<SocketAddr> {
    let listeners = saved_value(state_dir, "listen")?;
    let mut address: SocketAddr = listeners.as_array()?.first()?.as_str()?.parse().ok()?;
    if address.ip().is_unspecified() {
        address.set_ip(if address.is_ipv4() {
            IpAddr::from([127, 0, 0, 1])
        } else {
            IpAddr::from(Ipv6Addr::LOCALHOST)
        });
    }
    Some(address)
}

/// A TLS configuration for the web UI from a certificate chain and its private key.
pub fn tls_server_config(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|_| "The TLS certificate and key can't be used together".to_owned())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Loads an operator's certificate chain and private key.
pub fn load_tls_files(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, String> {
    check_is_file(cert, MAX_PEM_FILE_BYTES, "certificate")?;
    check_is_file(key, MAX_PEM_FILE_BYTES, "private key")?;
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|_| format!("Can't read the certificate {}", cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|_| format!("Can't read the private key {}", key.display()))?;
    tls_server_config(chain, key)
}

/// A change being tried, and what to return to if it doesn't work.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Trial {
    pub previous: Map<String, Value>,
    /// When the change must be confirmed by. Without this, starting successfully is enough.
    pub confirm_by_ms: Option<u64>,
}

/// What's saved.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SavedSettings {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub changes: Map<String, Value>,
    #[serde(default)]
    pub trial: Option<Trial>,
    #[serde(default)]
    pub last_failure: Option<String>,
}

const fn schema_version() -> u32 {
    SCHEMA_VERSION
}

impl Default for SavedSettings {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            changes: Map::new(),
            trial: None,
            last_failure: None,
        }
    }
}

/// Why saved settings couldn't be used.
#[derive(Debug, thiserror::Error)]
pub enum SettingsStoreError {
    #[error("cannot access the node's saved settings: {0}")]
    Io(#[from] io::Error),
    #[error("the node's saved settings are damaged: {0}")]
    Damaged(#[from] serde_json::Error),
    #[error("a change is already being tried")]
    TrialInProgress,
}

/// The settings file in the state directory. Backups leave it out, because a node's addresses and
/// certificates belong to its machine.
#[derive(Debug)]
pub struct SettingsStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl SettingsStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join(FILE_NAME),
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_unlocked(&self) -> Result<SavedSettings, SettingsStoreError> {
        match fs::read(&self.path) {
            Ok(content) => Ok(serde_json::from_slice(&content)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(SavedSettings::default()),
            Err(error) => Err(error.into()),
        }
    }

    fn write_unlocked(&self, saved: &SavedSettings) -> Result<(), SettingsStoreError> {
        let content = serde_json::to_vec_pretty(saved)?;
        let temp = self.path.with_extension("json.tmp");
        let mut file = fs::File::create(&temp)?;
        file.write_all(&content)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, &self.path)?;
        if let Some(directory) = self.path.parent() {
            fs::File::open(directory)?.sync_all()?;
        }
        Ok(())
    }

    fn update<T>(
        &self,
        change: impl FnOnce(&mut SavedSettings) -> Result<T, SettingsStoreError>,
    ) -> Result<T, SettingsStoreError> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let existing = self.read_unlocked()?;
        let mut saved = existing.clone();
        let result = change(&mut saved)?;
        if saved != existing {
            self.write_unlocked(&saved)?;
        }
        Ok(result)
    }

    pub fn read(&self) -> Result<SavedSettings, SettingsStoreError> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.read_unlocked()
    }

    /// Starts trying new settings. The current ones are kept to return to.
    pub fn begin(
        &self,
        changes: Map<String, Value>,
        confirm_by_ms: Option<u64>,
    ) -> Result<(), SettingsStoreError> {
        self.update(|saved| {
            if saved.trial.is_some() {
                return Err(SettingsStoreError::TrialInProgress);
            }
            let previous = std::mem::replace(&mut saved.changes, changes);
            saved.trial = Some(Trial {
                previous,
                confirm_by_ms,
            });
            saved.last_failure = None;
            Ok(())
        })
    }

    /// Keeps the settings being tried. Returns whether there were any.
    pub fn commit(&self) -> Result<bool, SettingsStoreError> {
        self.update(|saved| Ok(saved.trial.take().is_some()))
    }

    /// Returns to the settings from before the trial. Returns whether there was a trial.
    pub fn revert(&self, failure: Option<String>) -> Result<bool, SettingsStoreError> {
        self.update(|saved| {
            let Some(trial) = saved.trial.take() else {
                return Ok(false);
            };
            saved.changes = trial.previous;
            saved.last_failure = failure;
            Ok(true)
        })
    }

    /// Forgets everything saved, for recovering a node from the command line.
    pub fn clear(&self) -> Result<bool, SettingsStoreError> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

/// What the API needs to change the node's settings.
#[derive(Clone)]
pub struct NodeControl {
    pub store: Arc<SettingsStore>,
    /// The values from the command line and environment.
    pub startup: NodeSettings,
    /// Different each time the node starts, so the dashboard can tell a restart has finished.
    pub boot_id: String,
    /// The address the dashboard is bound to.
    pub web_address: SocketAddr,
    /// Asks the node to restart.
    pub restart: watch::Sender<bool>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn settings() -> NodeSettings {
        NodeSettings {
            listen: vec!["127.0.0.1:5300".to_owned()],
            allow: vec!["127.0.0.0/8".to_owned()],
            upstreams: vec!["1.1.1.1:53".to_owned()],
            attempt_timeout_ms: 800,
            query_timeout_ms: 2500,
            max_concurrent_requests: 4096,
            cache_mib: 64,
            cache_max_ttl: 86_400,
            cache_negative_ttl: 300,
            web_listen: "127.0.0.1:8080".to_owned(),
            state_dir: "/var/lib/ferrixdns".to_owned(),
            log_filter: "info".to_owned(),
            ..NodeSettings::default()
        }
    }

    fn rejected(change: impl FnOnce(&mut NodeSettings)) -> String {
        let mut candidate = settings();
        change(&mut candidate);
        candidate.validated().unwrap_err()
    }

    #[test]
    fn only_what_differs_is_saved_and_the_rest_follows_startup() {
        let mut changed = settings();
        changed.upstreams = vec!["9.9.9.9:53".to_owned()];
        let differences = changed.differences(&settings());
        assert_eq!(differences.len(), 1);
        assert!(differences.contains_key("upstreams"));

        // The service's configuration changed a value nobody set here, and an old setting remains.
        let mut new_startup = settings();
        new_startup.cache_mib = 128;
        let mut saved = differences;
        saved.insert("from_a_newer_version".to_owned(), Value::Bool(true));
        let merged = new_startup.with_changes(&saved).unwrap();
        assert_eq!(merged.cache_mib, 128);
        assert_eq!(merged.upstreams, vec!["9.9.9.9:53"]);
    }

    #[test]
    fn validation_writes_values_one_way() {
        let mut typed = settings();
        typed.upstreams = vec![" 1.1.1.1 ".to_owned()];
        typed.listen = vec!["127.0.0.1:5300 ".to_owned()];
        typed.web_hosts = vec!["DNS.Home.Arpa".to_owned(), "dns.home.arpa".to_owned()];
        typed.policy_file = Some("  ".to_owned());
        let clean = typed.validated().unwrap();
        assert_eq!(clean.upstreams, vec!["1.1.1.1:53"]);
        assert_eq!(clean.listen, vec!["127.0.0.1:5300"]);
        assert_eq!(clean.web_hosts, vec!["dns.home.arpa"]);
        assert_eq!(clean.policy_file, None);
    }

    #[test]
    fn rejects_settings_that_would_break_the_node() {
        assert!(rejected(|s| s.listen.clear()).contains("DNS address"));
        assert!(rejected(|s| s.listen = vec!["nope".to_owned()]).contains("isn't a valid"));
        assert!(rejected(|s| s.upstreams.clear()).contains("upstream"));
        assert!(rejected(|s| s.upstreams = vec!["dns.google".to_owned()]).contains("upstream"));
        assert!(rejected(|s| s.allow.clear()).contains("refused"));
        assert!(rejected(|s| s.attempt_timeout_ms = 0).contains("one upstream"));
        assert!(rejected(|s| s.query_timeout_ms = 10).contains("whole query"));
        assert!(rejected(|s| s.max_concurrent_requests = 0).contains("in flight"));
        assert!(rejected(|s| s.cache_max_ttl = 0).contains("cache time"));
        assert!(rejected(|s| s.web_hosts = vec!["a b".to_owned()]).contains("host name"));
    }

    #[test]
    fn the_dashboard_must_stay_safe_and_reachable_on_a_network() {
        assert!(rejected(|s| s.web_listen = "192.168.1.10:8080".to_owned()).contains("Plain HTTP"));

        let mut no_names = settings();
        no_names.web_listen = "0.0.0.0:8443".to_owned();
        no_names.web_tls_mode = WebTlsMode::SelfSigned;
        let no_names = no_names.validated().unwrap();
        let error = no_names.check_reachable_after(&settings()).unwrap_err();
        assert!(error.contains("name or address"), "{error}");
        // Saving something else on a node already set up this way isn't blocked.
        let mut other_change = no_names.clone();
        other_change.cache_mib = 1;
        assert!(other_change.check_reachable_after(&no_names).is_ok());

        let mut accepted = settings();
        accepted.web_listen = "0.0.0.0:8443".to_owned();
        accepted.web_tls_mode = WebTlsMode::SelfSigned;
        accepted.web_hosts = vec!["192.168.1.10".to_owned(), "::1".to_owned()];
        accepted.web_insecure_remote = true;
        let clean = accepted.validated().unwrap();
        assert_eq!(clean.web_hosts, vec!["192.168.1.10", "[::1]"]);
        assert!(!clean.web_insecure_remote, "TLS replaces plain HTTP");
    }

    #[test]
    fn file_settings_must_point_at_usable_files_without_revealing_them() {
        let directory = tempfile::tempdir().unwrap();
        let secret = directory.path().join("secret");
        fs::write(&secret, "the secret contents").unwrap();
        let secret = secret.to_str().unwrap().to_owned();

        let policy_error = rejected(|s| s.policy_file = Some(secret.clone()));
        assert!(policy_error.contains("isn't a valid policy"));
        assert!(!policy_error.contains("secret contents"));
        assert!(rejected(|s| s.policy_file = Some("/dev/zero".to_owned())).contains("usable file"));

        let tls_error = rejected(|s| {
            s.web_tls_mode = WebTlsMode::Files;
            s.web_tls_cert = Some(secret.clone());
            s.web_tls_key = Some(secret.clone());
        });
        assert!(!tls_error.contains("secret contents"), "{tls_error}");
        assert!(
            rejected(|s| {
                s.web_tls_mode = WebTlsMode::Files;
                s.web_tls_cert = Some(secret.clone());
            })
            .contains("both")
        );
    }

    #[test]
    fn a_trial_can_be_kept_or_undone_and_only_one_runs_at_a_time() {
        let directory = tempfile::tempdir().unwrap();
        let store = SettingsStore::new(directory.path());
        let first: Map<String, Value> =
            serde_json::from_str(r#"{"upstreams":["9.9.9.9:53"]}"#).unwrap();
        let second: Map<String, Value> = serde_json::from_str(r#"{"cache_mib":1}"#).unwrap();

        store.begin(first.clone(), None).unwrap();
        assert!(matches!(
            store.begin(second.clone(), None),
            Err(SettingsStoreError::TrialInProgress)
        ));
        assert!(store.commit().unwrap());
        assert!(!store.commit().unwrap());
        assert_eq!(store.read().unwrap().changes, first);

        store.begin(second.clone(), Some(5)).unwrap();
        assert_eq!(store.read().unwrap().changes, second);
        assert!(store.revert(Some("it failed".to_owned())).unwrap());
        let saved = store.read().unwrap();
        assert_eq!(saved.changes, first);
        assert_eq!(saved.last_failure.as_deref(), Some("it failed"));
        assert!(saved.trial.is_none());
        assert!(!store.revert(None).unwrap());

        // A new change clears the old failure.
        store.begin(second, None).unwrap();
        assert!(store.read().unwrap().last_failure.is_none());
    }

    #[test]
    fn moving_data_copies_everything_and_keeps_the_old_folder() {
        let directory = tempfile::tempdir().unwrap();
        let (from, to) = (directory.path().join("from"), directory.path().join("to"));
        fs::create_dir_all(from.join("lists")).unwrap();
        fs::write(from.join("config.db"), "database").unwrap();
        fs::write(from.join("lists/a.list"), "list").unwrap();
        fs::write(from.join(FILE_NAME), "{}").unwrap();

        check_data_folder(&to, &from).unwrap();
        move_data(&from, &to).unwrap();
        assert_eq!(
            fs::read_to_string(to.join("config.db")).unwrap(),
            "database"
        );
        assert_eq!(fs::read_to_string(to.join("lists/a.list")).unwrap(), "list");
        assert!(
            !to.join(FILE_NAME).exists(),
            "the settings stay where they're looked for"
        );
        assert!(from.join("config.db").exists());

        // Data already there is used, not overwritten.
        fs::write(to.join("config.db"), "newer").unwrap();
        check_data_folder(&to, &from).unwrap();
        move_data(&from, &to).unwrap();
        assert_eq!(fs::read_to_string(to.join("config.db")).unwrap(), "newer");
    }

    #[test]
    fn the_data_folder_must_be_usable() {
        let directory = tempfile::tempdir().unwrap();
        let current = directory.path().join("current");
        fs::create_dir_all(&current).unwrap();
        assert!(
            check_data_folder(Path::new("relative"), &current)
                .unwrap_err()
                .contains("full path")
        );
        assert!(
            check_data_folder(&current.join("inside"), &current)
                .unwrap_err()
                .contains("inside")
        );
        assert!(
            check_data_folder(directory.path(), &current)
                .unwrap_err()
                .contains("inside")
        );
        let other = directory.path().join("other");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("someone-elses-file"), "").unwrap();
        assert!(
            check_data_folder(&other, &current)
                .unwrap_err()
                .contains("empty")
        );
        let denied = check_data_folder(Path::new("/proc/ferrixdns-data"), &current).unwrap_err();
        assert!(denied.contains("ReadWritePaths"), "{denied}");
    }

    #[test]
    fn a_bad_log_filter_is_refused() {
        assert!(rejected(|s| s.log_filter = "not=a=filter".to_owned()).contains("log filter"));
    }

    #[test]
    fn saved_values_are_found_for_commands_outside_the_node() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(data_dir(directory.path()), directory.path());
        assert_eq!(saved_dns_address(directory.path()), None);
        fs::write(
            directory.path().join(FILE_NAME),
            r#"{"changes":{"state_dir":"/data/new","listen":["0.0.0.0:5300"],"log_filter":"warn"}}"#,
        )
        .unwrap();
        assert_eq!(data_dir(directory.path()), Path::new("/data/new"));
        assert_eq!(saved_log_filter(directory.path()).as_deref(), Some("warn"));
        assert_eq!(
            saved_dns_address(directory.path()),
            Some("127.0.0.1:5300".parse().unwrap())
        );
    }

    #[test]
    fn a_damaged_file_is_reported_and_clearing_recovers() {
        let directory = tempfile::tempdir().unwrap();
        let store = SettingsStore::new(directory.path());
        assert!(!store.clear().unwrap());
        fs::write(store.path(), "not json").unwrap();
        assert!(matches!(store.read(), Err(SettingsStoreError::Damaged(_))));
        assert!(store.clear().unwrap());
        assert!(store.read().unwrap().changes.is_empty());
    }
}
