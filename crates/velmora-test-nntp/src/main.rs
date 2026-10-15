//! `nntp-fixture-server` binary: run the synthetic NNTP fixture server standalone.
//!
//! Used for manual debugging and non-Cargo harnesses (stream/ingest workers).
//! CI integration tests use the in-process `TestNntpServer`.

use std::collections::HashMap;

use clap::Parser;
use nntune_test_nntp::server::serve;
use nntune_test_nntp::{ServerConfig, UserConfig};

#[derive(Parser, Debug)]
#[command(
    name = "nntp-fixture-server",
    about = "Synthetic NNTP fixture server for NNTune v2 CI"
)]
struct Args {
    /// Port to listen on.
    #[arg(long, default_value_t = 9119)]
    port: u16,
    /// user:password:max_connections (repeatable). Defaults to testuser/testpass:2.
    #[arg(long = "user")]
    users: Vec<String>,
    /// Throttle article bodies to this many bytes/sec (slow-link simulation).
    #[arg(long)]
    slow_bps: Option<u64>,
    /// Extra latency (ms) before each article response.
    #[arg(long, default_value_t = 0)]
    latency_ms: u64,
    /// message-id:bytes — drop the connection after N body bytes (repeatable).
    #[arg(long = "drop-after")]
    drop_after: Vec<String>,
    /// Do not require AUTHINFO before GROUP/ARTICLE.
    #[arg(long)]
    no_require_auth: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let config = build_config(&args);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", args.port)).await?;
    tracing::info!("nntp fixture server on {}", listener.local_addr()?);
    println!("nntp fixture server on {}", listener.local_addr()?);
    serve(listener, config).await;
    Ok(())
}

fn build_config(args: &Args) -> ServerConfig {
    let mut users = HashMap::new();
    if args.users.is_empty() {
        users.insert(
            "testuser".to_string(),
            UserConfig {
                password: "testpass".to_string(),
                max_connections: 2,
            },
        );
    } else {
        for spec in &args.users {
            let mut parts = spec.splitn(3, ':');
            match (parts.next(), parts.next(), parts.next()) {
                (Some(u), Some(p), Some(m)) => {
                    users.insert(
                        u.to_string(),
                        UserConfig {
                            password: p.to_string(),
                            max_connections: m.parse().unwrap_or(2),
                        },
                    );
                }
                _ => eprintln!("ignoring malformed --user {spec:?}, want user:password:max"),
            }
        }
    }
    let mut drop_after = HashMap::new();
    for spec in &args.drop_after {
        if let Some((id, n)) = spec.split_once(':') {
            if let Ok(n) = n.parse() {
                drop_after.insert(id.to_string(), n);
            }
        }
    }
    ServerConfig {
        users,
        articles: nntune_test_nntp::default_corpus(),
        group: "alt.binaries.nntune.test".to_string(),
        require_auth: !args.no_require_auth,
        missing_ids: nntune_test_nntp::fixtures::always_missing_ids()
            .into_iter()
            .collect(),
        slow_bytes_per_sec: args.slow_bps,
        latency_ms: args.latency_ms,
        drop_after_bytes: drop_after,
    }
}
