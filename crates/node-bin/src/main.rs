//! `fx`: the FerrixDNS node.

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use dns_policy::{CompiledPolicy, PolicyDocument};
use dns_runtime::{DnsServer, PolicyManager, RuntimeConfig, default_allow};
use dns_upstreams::PoolConfig;
use ipnet::IpNet;
use tracing::{error, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "fx", version, about = "FerrixDNS node")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve DNS, applying policy and forwarding allowed queries upstream
    Serve(ServeArgs),
    /// Work with policy files
    #[command(subcommand)]
    Policy(PolicyCommand),
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
    #[arg(long, required = true)]
    listen: Vec<SocketAddr>,

    /// Upstream server, tried in the order given (repeatable)
    #[arg(long, required = true)]
    upstream: Vec<SocketAddr>,

    /// Source network allowed to query (repeatable). Replaces the default of loopback and
    /// private networks
    #[arg(long)]
    allow: Vec<IpNet>,

    /// Policy file to apply. Send SIGHUP to reload it without restarting
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Directory for durable state, which restores the last good policy after a restart
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Maximum requests in flight upstream
    #[arg(long, default_value_t = 4096)]
    max_concurrent_requests: usize,

    /// Time allowed for one upstream server, in milliseconds
    #[arg(long, default_value_t = 800)]
    attempt_timeout_ms: u64,

    /// Time allowed for a whole query, in milliseconds
    #[arg(long, default_value_t = 2500)]
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
        Command::Serve(args) => serve(args).await,
        Command::Policy(PolicyCommand::Validate { file }) => validate_policy(&file),
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

async fn serve(args: ServeArgs) -> Result<()> {
    if args.policy.is_some() && args.state_dir.is_none() {
        warn!("--state-dir isn't set, so the policy can't be restored if the file is lost");
    }
    // Compilation can be slow with large lists, so it stays off the async runtime threads.
    let (source, state_dir) = (args.policy, args.state_dir);
    let manager = tokio::task::spawn_blocking(move || PolicyManager::start(source, state_dir))
        .await
        .context("the policy loader failed")?
        .context("failed to load the policy")?;

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
        },
        max_concurrent_requests: args.max_concurrent_requests,
        policy: manager.handle(),
    };

    // The policy is loaded before binding, so no query is ever answered without it.
    let server = DnsServer::bind(config)
        .await
        .context("failed to bind DNS listeners")?;

    tokio::spawn(Arc::clone(&manager).run_expiry_timer());
    tokio::spawn(reload_on_hangup(manager));

    server
        .run(shutdown_signal())
        .await
        .context("DNS server failed")
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
