//! `fx`: the FerrixDNS node.

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use dns_runtime::{DnsServer, RuntimeConfig, default_allow};
use dns_upstreams::PoolConfig;
use ipnet::IpNet;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "fx", version, about = "FerrixDNS node")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve DNS by forwarding to upstream servers
    Serve(ServeArgs),
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
    }
}

async fn serve(args: ServeArgs) -> Result<()> {
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
    };

    let server = DnsServer::bind(config)
        .await
        .context("failed to bind DNS listeners")?;
    server
        .run(shutdown_signal())
        .await
        .context("DNS server failed")
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
