//! `fakesrv`: the synthetic NNTP server on a fixed loopback port, for
//! end-to-end runs under `wrangler dev` (plaintext, dev only).
//!
//! ```text
//! fakesrv [--listen 127.0.0.1:11119] [--max-conns 2]
//! ```
//!
//! Login comes from `FAKESRV_USER` / `FAKESRV_PASS` (default
//! `testuser` / `testpass`); they are throwaway test values. The listen
//! address must be loopback. The server posts into an in-memory spool and
//! serves until killed.

use std::net::SocketAddr;
use std::process::ExitCode;

use velmora_test_nntp::{server::serve, ServerConfig, UserConfig};

const DEFAULT_LISTEN: &str = "127.0.0.1:11119";
const DEFAULT_MAX_CONNS: usize = 2;
const GROUP: &str = "alt.binaries.test";

struct Args {
    listen: SocketAddr,
    max_conns: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut listen = DEFAULT_LISTEN.to_string();
    let mut max_conns = DEFAULT_MAX_CONNS;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--listen" => listen = it.next().ok_or("--listen needs ADDR:PORT")?,
            "--max-conns" => {
                max_conns = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .filter(|n| *n > 0)
                    .ok_or("--max-conns needs a positive integer")?;
            }
            "-h" | "--help" => {
                return Err("usage: fakesrv [--listen 127.0.0.1:11119] [--max-conns 2]".into())
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let listen: SocketAddr = listen.parse().map_err(|_| "--listen is not ADDR:PORT")?;
    if !listen.ip().is_loopback() {
        return Err("--listen must be a loopback address".into());
    }
    Ok(Args { listen, max_conns })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("fakesrv: {msg}");
            return ExitCode::from(2);
        }
    };
    let user = std::env::var("FAKESRV_USER").unwrap_or_else(|_| "testuser".into());
    let pass = std::env::var("FAKESRV_PASS").unwrap_or_else(|_| "testpass".into());

    let mut config = ServerConfig::for_test();
    config.group = GROUP.to_string();
    config.users.clear();
    config.users.insert(
        user,
        UserConfig {
            password: pass,
            max_connections: args.max_conns,
        },
    );

    let listener = match tokio::net::TcpListener::bind(args.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fakesrv: bind {}: {e}", args.listen);
            return ExitCode::FAILURE;
        }
    };
    println!("fakesrv listening on {}", args.listen);
    serve(listener, config).await;
    ExitCode::SUCCESS
}
