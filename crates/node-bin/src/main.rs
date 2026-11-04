//! `ferrixdns`: the FerrixDNS node.

mod tls;

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use dns_cache::{CacheConfig, DnsCache};
use dns_lists::{FetchLimits, Fetcher};
use dns_policy::{CompiledPolicy, PolicyDocument};
use dns_runtime::{
    DnsServer, DnssecConfig, NeighborSource, PolicyManager, RuntimeConfig, default_allow,
    validate_forward_servers,
};
use dns_storage::ConfigDb;
use dns_telemetry::Telemetry;
use dns_upstreams::{PoolConfig, UpstreamServer};
use ipnet::IpNet;
use node_api::{
    AllowedHosts, Api, ApiConfig, CONFIRM_WITHIN, NodeControl, NodeSettings, NtpInfo,
    SettingsStore, WebTlsMode,
};
use node_ntp::NtpServer;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "ferrixdns", version, about = "FerrixDNS node")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve DNS, applying policy and forwarding allowed queries upstream
    Serve(Box<ServeArgs>),
    /// Work with policy files
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Recover access to the web UI
    #[command(subcommand)]
    Admin(AdminCommand),
    /// Back up and restore a node's policy, lists and history
    #[command(subcommand)]
    Backup(BackupCommand),
    /// Check that a node is answering DNS, for monitoring and container health checks
    Health {
        /// The node's DNS address
        #[arg(
            long = "address",
            env = "FERRIXDNS_HEALTH_ADDRESS",
            default_value = "127.0.0.1:53"
        )]
        address: SocketAddr,
        /// The node's state directory. A DNS address saved from its dashboard is used over --address
        #[arg(long, env = "FERRIXDNS_STATE_DIR")]
        state_dir: Option<PathBuf>,
    },
    /// Print the API contract as OpenAPI JSON
    Openapi,
}

#[derive(Subcommand)]
enum BackupCommand {
    /// Write a backup to a file. This is safe while the node runs
    Create {
        #[arg(long, env = "FERRIXDNS_STATE_DIR")]
        state_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Include accounts, encrypted with the passphrase in FERRIXDNS_BACKUP_PASSPHRASE
        #[arg(long)]
        include_credentials: bool,
    },
    /// Check a backup and restore it. Stop the node first
    Restore {
        #[arg(long, env = "FERRIXDNS_STATE_DIR")]
        state_dir: PathBuf,
        #[arg(long)]
        input: PathBuf,
        /// Check the backup and show what it contains, without changing anything
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Set an administrator's password from standard input and end their sessions
    ResetPassword {
        /// The node's state directory
        #[arg(long)]
        state_dir: PathBuf,
        /// The administrator to change
        #[arg(long)]
        username: String,
    },
    /// Forget node settings saved from the dashboard, returning to the command line and
    /// environment. Takes effect when the node next starts
    ResetSettings {
        /// The node's state directory
        #[arg(long)]
        state_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Check a policy file without applying it
    Validate {
        /// The policy file to check
        file: PathBuf,
    },
}

#[derive(Args)]
struct ServeArgs {
    /// Address to listen on over UDP and TCP (repeatable)
    #[arg(long, env = "FERRIXDNS_LISTEN", value_delimiter = ',', required = true)]
    listen: Vec<SocketAddr>,

    /// Upstream server, tried in the order given (repeatable). Use 1.1.1.1 for plain DNS,
    /// tls://cloudflare-dns.com@1.1.1.1 for DNS over TLS, or
    /// https://cloudflare-dns.com/dns-query@1.1.1.1 for DNS over HTTPS
    #[arg(
        long,
        env = "FERRIXDNS_UPSTREAM",
        value_delimiter = ',',
        required = true
    )]
    upstream: Vec<UpstreamServer>,

    /// Share queries between the upstream servers, instead of using the first one that works
    #[arg(long, env = "FERRIXDNS_UPSTREAM_LOAD_BALANCE")]
    upstream_load_balance: bool,

    /// Validate answers with DNSSEC on this node. Upstreams must return signatures
    #[arg(long, env = "FERRIXDNS_DNSSEC_VALIDATE")]
    dnssec_validate: bool,

    /// Source network allowed to query (repeatable). Replaces the default of loopback and
    /// private networks
    #[arg(long, env = "FERRIXDNS_ALLOW", value_delimiter = ',')]
    allow: Vec<IpNet>,

    /// Policy file to apply. Send SIGHUP to reload it without restarting
    #[arg(long, env = "FERRIXDNS_POLICY")]
    policy: Option<PathBuf>,

    /// Directory for durable state, which restores the last good policy after a restart
    #[arg(long, env = "FERRIXDNS_STATE_DIR")]
    state_dir: Option<PathBuf>,

    /// Address for the web UI and API. Needs --state-dir
    #[arg(long, env = "FERRIXDNS_WEB_LISTEN", requires = "state_dir")]
    web_listen: Option<SocketAddr>,

    /// Extra host name the web UI may be reached at (repeatable), such as dns.home.arpa
    #[arg(long, env = "FERRIXDNS_WEB_HOST", value_delimiter = ',')]
    web_host: Vec<String>,

    /// Certificate chain for the web UI, as PEM
    #[arg(long, env = "FERRIXDNS_WEB_TLS_CERT", requires = "web_tls_key")]
    web_tls_cert: Option<PathBuf>,

    /// Private key for the web UI, as PEM
    #[arg(long, env = "FERRIXDNS_WEB_TLS_KEY", requires = "web_tls_cert")]
    web_tls_key: Option<PathBuf>,

    /// Serve the web UI over TLS with a self-signed certificate, kept in the state directory.
    /// Browsers will warn about it, so check its fingerprint against the node's log
    #[arg(
        long,
        env = "FERRIXDNS_WEB_TLS_SELF_SIGNED",
        conflicts_with = "web_tls_cert",
        conflicts_with = "web_insecure_remote"
    )]
    web_tls_self_signed: bool,

    /// Allow the web UI on a non-loopback address over plain HTTP. Passwords and query logs can
    /// then be read by anyone on the network path
    #[arg(long, env = "FERRIXDNS_WEB_INSECURE_REMOTE")]
    web_insecure_remote: bool,

    /// Let list downloads reach loopback and private addresses
    #[arg(long, env = "FERRIXDNS_ALLOW_PRIVATE_LIST_URLS")]
    allow_private_list_urls: bool,

    /// Memory for cached answers, in MiB. 0 turns the cache off
    #[arg(long, env = "FERRIXDNS_CACHE_MIB", default_value_t = 64)]
    cache_mib: u64,

    /// Longest time to keep any answer in the cache, in seconds
    #[arg(long, env = "FERRIXDNS_CACHE_MAX_TTL", default_value_t = 86_400)]
    cache_max_ttl: u64,

    /// Longest time to keep "not found" answers in the cache, in seconds
    #[arg(long, env = "FERRIXDNS_CACHE_NEGATIVE_TTL", default_value_t = 300)]
    cache_negative_ttl: u64,

    /// Maximum requests in flight upstream
    #[arg(
        long,
        env = "FERRIXDNS_MAX_CONCURRENT_REQUESTS",
        default_value_t = 4096
    )]
    max_concurrent_requests: usize,

    /// Time allowed for one upstream server, in milliseconds
    #[arg(long, env = "FERRIXDNS_ATTEMPT_TIMEOUT_MS", default_value_t = 800)]
    attempt_timeout_ms: u64,

    /// Time allowed for a whole query, in milliseconds
    #[arg(long, env = "FERRIXDNS_QUERY_TIMEOUT_MS", default_value_t = 2500)]
    query_timeout_ms: u64,

    /// Address to serve NTP on (repeatable), such as 0.0.0.0:123. This shares this machine's
    /// clock, so it needs a time service like chrony on another port, or systemd-timesyncd
    #[arg(long, env = "FERRIXDNS_NTP_LISTEN", value_delimiter = ',')]
    ntp_listen: Vec<SocketAddr>,
}

impl ServeArgs {
    /// The settings given on the command line and in the environment.
    fn node_settings(&self) -> NodeSettings {
        let path = |path: Option<&PathBuf>| path.map(|path| path.display().to_string());
        let strings = |values: &[SocketAddr]| values.iter().map(ToString::to_string).collect();
        let allow = if self.allow.is_empty() {
            default_allow()
        } else {
            self.allow.clone()
        };
        NodeSettings {
            listen: strings(&self.listen),
            allow: allow.iter().map(ToString::to_string).collect(),
            upstreams: self.upstream.iter().map(ToString::to_string).collect(),
            upstream_load_balance: self.upstream_load_balance,
            dnssec_validate: self.dnssec_validate,
            attempt_timeout_ms: self.attempt_timeout_ms,
            query_timeout_ms: self.query_timeout_ms,
            max_concurrent_requests: u64::try_from(self.max_concurrent_requests)
                .unwrap_or(u64::MAX),
            cache_mib: self.cache_mib,
            cache_max_ttl: self.cache_max_ttl,
            cache_negative_ttl: self.cache_negative_ttl,
            web_listen: self
                .web_listen
                .map(|address| address.to_string())
                .unwrap_or_default(),
            web_hosts: self.web_host.clone(),
            web_tls_mode: if self.web_tls_self_signed {
                WebTlsMode::SelfSigned
            } else if self.web_tls_cert.is_some() {
                WebTlsMode::Files
            } else {
                WebTlsMode::Off
            },
            web_tls_cert: path(self.web_tls_cert.as_ref()),
            web_tls_key: path(self.web_tls_key.as_ref()),
            web_insecure_remote: self.web_insecure_remote,
            ntp_listen: strings(&self.ntp_listen),
            allow_private_list_urls: self.allow_private_list_urls,
            policy_file: path(self.policy.as_ref()),
            state_dir: path(self.state_dir.as_ref()).unwrap_or_default(),
            log_filter: std::env::var("RUST_LOG").unwrap_or_else(|_| DEFAULT_LOG_FILTER.to_owned()),
        }
    }

    /// Replaces these arguments with settings saved from the dashboard.
    fn use_settings(&mut self, settings: &NodeSettings) -> Result<(), String> {
        let parsed = settings.parse()?;
        self.listen = parsed.listen;
        self.allow = parsed.allow;
        self.upstream = parsed.upstreams;
        self.upstream_load_balance = settings.upstream_load_balance;
        self.web_listen = Some(parsed.web_listen);
        self.ntp_listen = parsed.ntp_listen;
        self.dnssec_validate = settings.dnssec_validate;
        self.attempt_timeout_ms = settings.attempt_timeout_ms;
        self.query_timeout_ms = settings.query_timeout_ms;
        self.max_concurrent_requests =
            usize::try_from(settings.max_concurrent_requests).map_err(|error| error.to_string())?;
        self.cache_mib = settings.cache_mib;
        self.cache_max_ttl = settings.cache_max_ttl;
        self.cache_negative_ttl = settings.cache_negative_ttl;
        self.web_host.clone_from(&settings.web_hosts);
        self.web_tls_self_signed = settings.web_tls_mode == WebTlsMode::SelfSigned;
        let files = settings.web_tls_mode == WebTlsMode::Files;
        self.web_tls_cert = settings
            .web_tls_cert
            .as_ref()
            .filter(|_| files)
            .map(PathBuf::from);
        self.web_tls_key = settings
            .web_tls_key
            .as_ref()
            .filter(|_| files)
            .map(PathBuf::from);
        self.web_insecure_remote = settings.web_insecure_remote;
        self.allow_private_list_urls = settings.allow_private_list_urls;
        self.policy = settings.policy_file.as_ref().map(PathBuf::from);
        self.state_dir = Some(PathBuf::from(&settings.state_dir));
        Ok(())
    }
}

const DEFAULT_LOG_FILTER: &str = "info,hickory_server=warn";

#[tokio::main]
async fn main() -> Result<()> {
    // hickory_server logs each query name at INFO, which spec section 7.3 rules out by default.
    let cli = Cli::parse();
    let saved_filter = match &cli.command {
        Command::Serve(args) if args.web_listen.is_some() => args
            .state_dir
            .as_deref()
            .and_then(node_api::saved_log_filter),
        _ => None,
    };
    let filter = saved_filter
        .and_then(|filter| EnvFilter::try_new(filter).ok())
        .or_else(|| EnvFilter::try_from_default_env().ok())
        .unwrap_or_else(|| EnvFilter::new(DEFAULT_LOG_FILTER));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    match cli.command {
        Command::Serve(args) => serve(*args).await,
        Command::Policy(PolicyCommand::Validate { file }) => validate_policy(&file),
        Command::Admin(AdminCommand::ResetPassword {
            state_dir,
            username,
        }) => reset_password(&state_dir, &username).await,
        Command::Admin(AdminCommand::ResetSettings { state_dir }) => reset_settings(&state_dir),
        Command::Backup(command) => backup(command).await,
        Command::Health { address, state_dir } => health(
            state_dir
                .as_deref()
                .and_then(node_api::saved_dns_address)
                .unwrap_or(address),
        ),
        Command::Openapi => {
            println!("{}", node_api::openapi_json()?);
            Ok(())
        }
    }
}

fn validate_policy(file: &Path) -> Result<()> {
    let source =
        std::fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))?;
    let document = PolicyDocument::parse(&source)?;
    validate_forward_servers(&document)?;
    CompiledPolicy::compile("validate", &document, SystemTime::now(), None)?;

    for warning in document.warnings() {
        eprintln!("warning: {warning}");
    }
    println!(
        "{} is valid: {} rules, {} lists, {} clients",
        file.display(),
        document.rules.len(),
        document.lists.len(),
        document.clients.len()
    );
    Ok(())
}

/// Sends a query for `localhost.`, which a node answers itself, so this tests the DNS path without
/// depending on upstreams.
fn health(address: SocketAddr) -> Result<()> {
    const REFUSED: u8 = 5;
    const QUERY: &[u8] =
        b"\x48\x4c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09localhost\x00\x00\x01\x00\x01";
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.connect(address)?;
    socket.send(QUERY)?;
    let mut reply = [0_u8; 512];
    let length = socket
        .recv(&mut reply)
        .with_context(|| format!("no DNS answer from {address}"))?;
    let (id, flags) = (reply.get(..2), reply.get(3).copied());
    let code = flags.map(|flags| flags & 0x0f);
    if length >= 12 && id == Some(&QUERY[..2]) && code == Some(REFUSED) {
        bail!(
            "{address} refused this check, because {} isn't in its allowed networks",
            socket.local_addr()?.ip()
        );
    }
    if length < 12 || id != Some(&QUERY[..2]) || code != Some(0) {
        bail!("{address} answered, but not correctly");
    }
    println!("{address} is answering DNS");
    Ok(())
}

const PASSPHRASE_VARIABLE: &str = "FERRIXDNS_BACKUP_PASSPHRASE";

async fn backup(command: BackupCommand) -> Result<()> {
    match command {
        BackupCommand::Create {
            state_dir,
            output,
            include_credentials,
        } => {
            let passphrase = if include_credentials {
                let passphrase = std::env::var(PASSPHRASE_VARIABLE).with_context(|| {
                    format!("set {PASSPHRASE_VARIABLE} to protect the accounts")
                })?;
                if passphrase.chars().count() < node_api::MIN_PASSWORD_LENGTH {
                    bail!(
                        "use a passphrase of at least {} characters",
                        node_api::MIN_PASSWORD_LENGTH
                    );
                }
                Some(passphrase)
            } else {
                None
            };
            let state_dir = node_api::data_dir(&state_dir);
            let directory = state_dir.clone();
            let manager =
                tokio::task::spawn_blocking(move || PolicyManager::start(None, Some(directory)))
                    .await??;
            let db = ConfigDb::open(&state_dir.join("config.db")).await?;
            let archive = node_api::build_backup(manager, db, passphrase).await?;
            dns_backup::write_private_file(&output, &archive)
                .with_context(|| format!("cannot write {}", output.display()))?;
            println!(
                "Wrote {} ({} bytes). Query logs aren't included.",
                output.display(),
                archive.len()
            );
            Ok(())
        }
        BackupCommand::Restore {
            state_dir,
            input,
            dry_run,
        } => restore(&state_dir, &input, dry_run).await,
    }
}

async fn restore(state_dir: &Path, input: &Path, dry_run: bool) -> Result<()> {
    let state_dir = &node_api::data_dir(state_dir);
    let archive =
        std::fs::read(input).with_context(|| format!("cannot read {}", input.display()))?;
    let backup = dns_backup::read_backup(&archive)?;
    let summary = &backup.summary;
    println!(
        "Valid backup from version {}: {} rules, {} sources, {} clients, {} local records, \
         {} policy revisions.",
        summary.app_version,
        summary.rule_count,
        summary.list_count,
        summary.client_count,
        summary.local_record_count,
        summary.revision_count
    );

    let passphrase = std::env::var(PASSPHRASE_VARIABLE).ok();
    let users = match (&passphrase, summary.has_credentials) {
        (Some(passphrase), true) => backup.credentials(passphrase)?,
        (None, true) => {
            println!(
                "Accounts are in this backup, but won't be restored without {PASSPHRASE_VARIABLE}."
            );
            None
        }
        _ => None,
    };
    if dry_run {
        println!("Dry run: nothing was changed.");
        return Ok(());
    }

    let directory = state_dir.to_path_buf();
    let manager =
        tokio::task::spawn_blocking(move || PolicyManager::start(None, Some(directory))).await??;
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
    let revision = manager
        .restore(&revisions, &artifacts)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    let db = ConfigDb::open(&state_dir.join("config.db")).await?;
    db.replace_list_statuses(&backup.list_statuses).await?;
    db.import_audit_events(&backup.audit_events).await?;
    if let Some(users) = users {
        let now_ms = i64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_millis(),
        )?;
        db.replace_users(&users, now_ms).await?;
        println!(
            "Restored {} accounts. Existing sessions have ended.",
            users.len()
        );
    }
    println!(
        "Restored policy revision {}.",
        revision.get(..12).unwrap_or(&revision)
    );
    Ok(())
}

fn reset_settings(state_dir: &Path) -> Result<()> {
    if SettingsStore::new(state_dir).clear()? {
        println!("Saved settings removed. Restart the node to use its startup values.");
    } else {
        println!("There are no saved settings.");
    }
    Ok(())
}

async fn reset_password(state_dir: &Path, username: &str) -> Result<()> {
    let state_dir = &node_api::data_dir(state_dir);
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .context("cannot read the new password")?;
    let db = ConfigDb::open(&state_dir.join("config.db"))
        .await
        .context("cannot open the config database")?;
    let found = node_api::reset_password(
        &db,
        username,
        password.trim_end_matches(['\r', '\n']).to_owned(),
    )
    .await?;
    if !found {
        bail!("there's no administrator named {username}");
    }
    println!("Password changed. Existing sessions have ended.");
    Ok(())
}

/// Opens query telemetry. DNS must keep working without it, so a failure is only logged.
async fn open_telemetry(
    state_dir: Option<&Path>,
    manager: &PolicyManager,
) -> Option<Arc<Telemetry>> {
    let directory = state_dir?.join("telemetry");
    match Telemetry::open(directory, manager.telemetry_settings()).await {
        Ok(telemetry) => Some(Arc::new(telemetry)),
        Err(open_error) => {
            error!(error = %open_error, "query telemetry is unavailable; DNS isn't affected");
            None
        }
    }
}

/// How long the DNS server gets to finish before a restart goes ahead anyway.
const RESTART_GRACE: Duration = Duration::from_secs(3);

/// Replaces this process with a new copy of itself, which picks up saved settings. The process ID,
/// environment and capabilities stay the same, so this works the same under any service manager.
fn restart_process() -> anyhow::Error {
    info!("restarting to apply settings");
    let mut arguments = std::env::args_os();
    let mut command = std::process::Command::new("/proc/self/exe");
    if let Some(name) = arguments.next() {
        command.arg0(name);
    }
    anyhow::Error::new(command.args(arguments).exec()).context("cannot restart the node")
}

/// Applies saved settings to the arguments, returning what the API needs to change them.
fn apply_saved_settings(args: &mut ServeArgs) -> Result<Option<NodeSettingsState>> {
    let (Some(state_dir), true) = (args.state_dir.clone(), args.web_listen.is_some()) else {
        // Without a dashboard the rest doesn't apply, but the data is still where it was moved to.
        args.state_dir = args.state_dir.as_deref().map(node_api::data_dir);
        return Ok(None);
    };
    let store = Arc::new(SettingsStore::new(&state_dir));
    let startup = args.node_settings();
    // A trial past its deadline was never confirmed, and the node went down before it could undo it.
    if let Ok(saved) = store.read()
        && let Some(deadline) = saved.trial.and_then(|trial| trial.confirm_by_ms)
        && deadline <= unix_ms()
    {
        store.revert(Some(UNCONFIRMED.to_owned()))?;
    }
    let applied = store
        .read()
        .map_err(|error| error.to_string())
        .and_then(|saved| {
            startup
                .with_changes(&saved.changes)
                .map_err(|error| error.to_string())
        })
        .and_then(|settings| {
            args.use_settings(&settings)?;
            Ok(settings)
        });
    match applied {
        Ok(settings) => {
            let changed: Vec<String> = settings.differences(&startup).keys().cloned().collect();
            if !changed.is_empty() {
                info!(
                    ?changed,
                    "using settings saved from the dashboard over the startup values"
                );
            }
        }
        Err(problem) => {
            // DNS matters more than these settings, so the node starts without them.
            error!(%problem, path = %store.path().display(), "ignoring the saved settings");
            args.use_settings(&startup).map_err(anyhow::Error::msg)?;
        }
    }
    Ok(Some(NodeSettingsState { store, startup }))
}

const UNCONFIRMED: &str = "The change to dashboard access wasn't kept within 2 minutes, so the \
                           previous settings were restored.";

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

struct NodeSettingsState {
    store: Arc<SettingsStore>,
    startup: NodeSettings,
}

/// Undoes an unconfirmed change when its time is up.
async fn undo_when_unconfirmed(store: Arc<SettingsStore>, restart: watch::Sender<bool>) {
    let Ok(saved) = store.read() else { return };
    let Some(deadline) = saved.trial.and_then(|trial| trial.confirm_by_ms) else {
        return;
    };
    let wait = Duration::from_millis(deadline.saturating_sub(unix_ms())).min(CONFIRM_WITHIN);
    tokio::time::sleep(wait).await;
    match store.revert(Some(UNCONFIRMED.to_owned())) {
        Ok(true) => {
            warn!("a change to dashboard access wasn't kept, so it's being undone");
            let _ = restart.send(true);
        }
        Ok(false) => {}
        Err(error) => error!(%error, "cannot undo an unconfirmed change"),
    }
}

/// Copies the node's data when the change being tried moves it. Nothing has the data open yet.
async fn move_data_for_trial(settings: &NodeSettingsState, target: Option<&Path>) -> Result<()> {
    let Ok(saved) = settings.store.read() else {
        return Ok(());
    };
    let Some(trial) = saved.trial else {
        return Ok(());
    };
    let previous = settings.startup.with_changes(&trial.previous)?;
    let from = PathBuf::from(previous.state_dir);
    let Some(to) = target.map(Path::to_path_buf).filter(|to| *to != from) else {
        return Ok(());
    };
    info!(from = %from.display(), to = %to.display(), "moving the node's data");
    let message = format!("cannot move the data to {}", to.display());
    tokio::task::spawn_blocking(move || node_api::move_data(&from, &to))
        .await?
        .context(message)
}

async fn serve(mut args: ServeArgs) -> Result<()> {
    let settings = apply_saved_settings(&mut args)?;
    let store = settings
        .as_ref()
        .map(|settings| Arc::clone(&settings.store));
    let moved = match &settings {
        Some(settings) => move_data_for_trial(settings, args.state_dir.as_deref()).await,
        None => Ok(()),
    };
    let outcome = match moved {
        Ok(()) => run_node(args, settings).await,
        Err(failure) => Err(failure),
    };
    match outcome {
        Ok(false) => Ok(()),
        Ok(true) => Err(restart_process()),
        Err(failure) => {
            let Some(store) = store else {
                return Err(failure);
            };
            // Only a change being tried is undone. Saved settings that worked before stay saved,
            // because an address can be missing for a moment while a machine boots.
            let reason = format!("The node couldn't start with that change: {failure:#}");
            if store.revert(Some(reason))? {
                error!(error = %format!("{failure:#}"), "couldn't start with changed settings; restoring the previous ones");
                return Err(restart_process());
            }
            if store.read().is_ok_and(|saved| !saved.changes.is_empty()) {
                error!(
                    path = %store.path().display(),
                    "settings saved from the dashboard are in use. If they're the cause, remove \
                     them with: ferrixdns admin reset-settings"
                );
            }
            Err(failure)
        }
    }
}

/// Runs the node until it stops, returning whether it should restart.
async fn run_node(args: ServeArgs, settings: Option<NodeSettingsState>) -> Result<bool> {
    let uses_tls = args.web_tls_self_signed || args.web_tls_cert.is_some();
    if let Some(web_listen) = args.web_listen
        && !web_listen.ip().is_loopback()
        && !args.web_insecure_remote
        && !uses_tls
    {
        bail!(
            "plain HTTP on {web_listen} would expose passwords and query logs on the network. \
             Use --web-tls-self-signed, or --web-tls-cert with --web-tls-key. If you accept the \
             risk, pass --web-insecure-remote"
        );
    }
    if args.policy.is_some() && args.state_dir.is_none() {
        warn!("--state-dir isn't set, so the policy can't be restored if the file is lost");
    }
    // Compilation can be slow with large lists, so it stays off the async runtime threads.
    let state_dir = args.state_dir;
    let (source, store_dir) = (args.policy, state_dir.clone());
    let manager = tokio::task::spawn_blocking(move || PolicyManager::start(source, store_dir))
        .await
        .context("the policy loader failed")?
        .context("failed to load the policy")?;
    let telemetry = open_telemetry(state_dir.as_deref(), &manager).await;

    let cache = (args.cache_mib > 0).then(|| {
        Arc::new(DnsCache::new(CacheConfig {
            max_bytes: args.cache_mib.saturating_mul(1024 * 1024),
            max_ttl: Duration::from_secs(args.cache_max_ttl),
            negative_ttl_cap: Duration::from_secs(args.cache_negative_ttl),
        }))
    });

    let allow = if args.allow.is_empty() {
        default_allow()
    } else {
        args.allow
    };
    let ntp = if args.ntp_listen.is_empty() {
        None
    } else {
        Some(NtpServer::bind(&args.ntp_listen, allow.clone()).await?)
    };
    let config = RuntimeConfig {
        listen: args.listen,
        allow,
        upstreams: PoolConfig {
            servers: args.upstream,
            load_balance: args.upstream_load_balance,
            attempt_timeout: Duration::from_millis(args.attempt_timeout_ms),
            total_timeout: Duration::from_millis(args.query_timeout_ms),
            rounds: 2,
            trust_roots: None,
        },
        max_concurrent_requests: args.max_concurrent_requests,
        policy: manager.handle(),
        telemetry: telemetry.clone(),
        cache: cache.clone(),
        dnssec: args.dnssec_validate.then(DnssecConfig::default),
        neighbors: NeighborSource::kernel(),
    };

    // The policy is loaded before binding, so no query is ever answered without it.
    let server = DnsServer::bind(config)
        .await
        .context("failed to bind DNS listeners")?;

    let (stop_sender, stop) = watch::channel(false);
    let (restart_sender, restart) = watch::channel(false);
    let ntp_info = ntp
        .as_ref()
        .map(|ntp| {
            Ok::<_, std::io::Error>(NtpInfo {
                listeners: ntp.local_addrs()?,
                stats: ntp.stats(),
            })
        })
        .transpose()?;
    if let Some(ntp) = ntp {
        let mut stopped = stop.clone();
        tokio::spawn(ntp.run(async move {
            let _ = stopped.wait_for(|stopped| *stopped).await;
        }));
    }
    if let Some(web_listen) = args.web_listen {
        let web = WebOptions {
            listen: web_listen,
            hosts: args.web_host,
            allow_private_list_urls: args.allow_private_list_urls,
            dnssec_validation: args.dnssec_validate,
            tls_files: args.web_tls_cert.zip(args.web_tls_key),
            tls_self_signed: args.web_tls_self_signed,
            state_dir: state_dir.unwrap_or_default(),
            ntp: ntp_info,
            settings,
            restart: restart_sender.clone(),
        };
        start_web(web, &manager, telemetry, cache, &server, stop).await?;
    }

    tokio::spawn(Arc::clone(&manager).run_expiry_timer());
    tokio::spawn(reload_on_hangup(manager));

    let mut asked_to_restart = restart.clone();
    let mut restart_requested = restart.clone();
    let run = server.run(async move {
        tokio::select! {
            () = shutdown_signal() => {}
            _ = asked_to_restart.wait_for(|restart| *restart) => {}
        }
        let _ = stop_sender.send(true);
    });
    let grace = async move {
        let _ = restart_requested.wait_for(|restart| *restart).await;
        tokio::time::sleep(RESTART_GRACE).await;
    };
    let result = tokio::select! {
        result = run => result,
        () = grace => Ok(()),
    };
    result.context("DNS server failed")?;
    let restarting = *restart.borrow();
    Ok(restarting)
}

struct WebOptions {
    listen: SocketAddr,
    hosts: Vec<String>,
    allow_private_list_urls: bool,
    dnssec_validation: bool,
    tls_files: Option<(PathBuf, PathBuf)>,
    tls_self_signed: bool,
    state_dir: PathBuf,
    ntp: Option<NtpInfo>,
    settings: Option<NodeSettingsState>,
    restart: watch::Sender<bool>,
}

async fn start_web(
    web: WebOptions,
    manager: &Arc<PolicyManager>,
    telemetry: Option<Arc<Telemetry>>,
    cache: Option<Arc<DnsCache>>,
    server: &DnsServer,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let db = ConfigDb::open(&web.state_dir.join("config.db"))
        .await
        .context("cannot open the config database")?;
    let fetcher = Fetcher::new(FetchLimits::default(), web.allow_private_list_urls)
        .context("cannot prepare list downloads")?;

    let mut hosts = web.hosts;
    if !web.listen.ip().is_unspecified() {
        hosts.push(match web.listen {
            SocketAddr::V4(address) => address.ip().to_string(),
            SocketAddr::V6(address) => format!("[{}]", address.ip()),
        });
    }

    let tls = match &web.tls_files {
        Some((cert, key)) => Some(tls::from_files(cert, key)?),
        None if web.tls_self_signed => Some(tls::self_signed(&web.state_dir, &hosts)?),
        None => None,
    };
    let has_operator_certificate = web.tls_files.is_some();

    let listener = TcpListener::bind(web.listen)
        .await
        .with_context(|| format!("cannot listen on {} for the web UI", web.listen))?;
    let address = listener.local_addr()?;

    let node = web.settings.map(|settings| NodeControl {
        store: Arc::clone(&settings.store),
        startup: settings.startup,
        boot_id: unix_ms().to_string(),
        web_address: address,
        restart: web.restart.clone(),
    });
    // The node came up with any change being tried. One that affects access still needs keeping.
    if let Some(node) = &node
        && let Ok(saved) = node.store.read()
        && let Some(trial) = saved.trial
    {
        if trial.confirm_by_ms.is_some() {
            tokio::spawn(undo_when_unconfirmed(Arc::clone(&node.store), web.restart));
        } else {
            node.store.commit()?;
        }
    }

    let api = Api::new(ApiConfig {
        manager: Arc::clone(manager),
        telemetry,
        db,
        pool: server.pool(),
        cache,
        fetcher,
        hosts: AllowedHosts::new(hosts),
        secure_cookies: tls.is_some(),
        hsts: has_operator_certificate,
        dns_listeners: server.local_addrs().to_vec(),
        dnssec_validation: web.dnssec_validation,
        services: server.services(),
        ntp: web.ntp,
        node,
    })
    .await?;

    let scheme = if tls.is_some() { "https" } else { "http" };
    info!(url = %format!("{scheme}://{address}/"), "web UI ready");
    if let Some(token) = api.setup_token() {
        // Whoever can read this log can claim the node, which is the point of the token.
        warn!(setup_token = %token, "no administrator exists yet; use this token to set one up");
    }

    tokio::spawn(async move {
        let shutdown = async move {
            let _ = stop.wait_for(|stopped| *stopped).await;
        };
        let served = match tls {
            Some(tls) => api.serve_tls(listener, tls, shutdown).await,
            None => api.serve(listener, shutdown).await,
        };
        // DNS keeps serving even if the web UI stops.
        if let Err(serve_error) = served {
            error!(error = %serve_error, "the web UI stopped; DNS isn't affected");
        }
    });
    Ok(())
}

async fn reload_on_hangup(manager: Arc<PolicyManager>) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = match signal(SignalKind::hangup()) {
        Ok(stream) => stream,
        Err(error) => {
            error!(%error, "cannot listen for SIGHUP; policy reloads are unavailable");
            return;
        }
    };
    while hangup.recv().await.is_some() {
        let reloading = Arc::clone(&manager);
        match tokio::task::spawn_blocking(move || reloading.reload()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => error!(%error, "policy reload failed; keeping the active policy"),
            Err(error) => error!(%error, "the policy reload task failed"),
        }
    }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let terminate = async {
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            // Without a SIGTERM handler, keep serving and rely on Ctrl-C.
            Err(_) => std::future::pending().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
}
