//! `ferrixdns`: the FerrixDNS node.

mod tls;

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use dns_cache::{CacheConfig, DnsCache};
use dns_lists::{FetchLimits, Fetcher};
use dns_policy::{CompiledPolicy, PolicyDocument};
use dns_runtime::{DnsServer, DnssecConfig, PolicyManager, RuntimeConfig, default_allow};
use dns_storage::ConfigDb;
use dns_telemetry::Telemetry;
use dns_upstreams::{PoolConfig, UpstreamServer};
use ipnet::IpNet;
use node_api::{AllowedHosts, Api, ApiConfig};
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
}

#[tokio::main]
async fn main() -> Result<()> {
    // hickory_server logs each query name at INFO, which spec section 7.3 rules out by default.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,hickory_server=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    match Cli::parse().command {
        Command::Serve(args) => serve(*args).await,
        Command::Policy(PolicyCommand::Validate { file }) => validate_policy(&file),
        Command::Admin(AdminCommand::ResetPassword {
            state_dir,
            username,
        }) => reset_password(&state_dir, &username).await,
        Command::Backup(command) => backup(command).await,
        Command::Health { address } => health(address),
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
    if length < 12 || id != Some(&QUERY[..2]) || flags.map(|flags| flags & 0x0f) != Some(0) {
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

async fn reset_password(state_dir: &Path, username: &str) -> Result<()> {
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

async fn serve(args: ServeArgs) -> Result<()> {
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
    let config = RuntimeConfig {
        listen: args.listen,
        allow,
        upstreams: PoolConfig {
            servers: args.upstream,
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
    };

    // The policy is loaded before binding, so no query is ever answered without it.
    let server = DnsServer::bind(config)
        .await
        .context("failed to bind DNS listeners")?;

    let (stop_sender, stop) = watch::channel(false);
    if let Some(web_listen) = args.web_listen {
        let web = WebOptions {
            listen: web_listen,
            hosts: args.web_host,
            allow_private_list_urls: args.allow_private_list_urls,
            dnssec_validation: args.dnssec_validate,
            tls_files: args.web_tls_cert.zip(args.web_tls_key),
            tls_self_signed: args.web_tls_self_signed,
            state_dir: state_dir.unwrap_or_default(),
        };
        start_web(web, &manager, telemetry, cache, &server, stop).await?;
    }

    tokio::spawn(Arc::clone(&manager).run_expiry_timer());
    tokio::spawn(reload_on_hangup(manager));

    let result = server
        .run(async move {
            shutdown_signal().await;
            let _ = stop_sender.send(true);
        })
        .await;
    result.context("DNS server failed")
}

struct WebOptions {
    listen: SocketAddr,
    hosts: Vec<String>,
    allow_private_list_urls: bool,
    dnssec_validation: bool,
    tls_files: Option<(PathBuf, PathBuf)>,
    tls_self_signed: bool,
    state_dir: PathBuf,
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
    })
    .await?;

    let listener = TcpListener::bind(web.listen)
        .await
        .with_context(|| format!("cannot listen on {} for the web UI", web.listen))?;
    let address = listener.local_addr()?;
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
