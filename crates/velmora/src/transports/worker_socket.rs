//! Cloudflare Workers NNTP transport over the runtime `connect()` TCP socket.
//!
//! Opens `hostname:port` with [`worker::Socket`] (implicit TLS for NNTPS via
//! [`SecureTransport::On`](worker::SecureTransport)). The socket already
//! implements tokio's `AsyncRead`/`AsyncWrite`; per-operation timeouts are
//! enforced by racing each operation against
//! [`worker::Delay`](https://docs.rs/worker/latest/worker/struct.Delay.html)
//! and reporting expiry as [`io::ErrorKind::TimedOut`], matching the native
//! transport's contract.

#![cfg(all(feature = "worker-transport", target_arch = "wasm32"))]

use std::io;
use std::pin::pin;
use std::time::Duration;

use futures_util::future::{self, Either};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{Delay, SecureTransport, Socket};

use crate::nntp::NntpConfig;
use crate::transport::Transport;

/// Workers transport over a `connect()` TCP socket.
pub struct WorkerTransport {
    socket: Socket,
    timeout: Duration,
}

fn timed_out(op: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("NNTP {op} timed out on Workers socket"),
    )
}

async fn with_timeout<T>(
    timeout: Duration,
    op: &'static str,
    fut: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let fut = pin!(fut);
    let delay = pin!(Delay::from(timeout));
    match future::select(fut, delay).await {
        Either::Left((out, _)) => out,
        Either::Right(_) => Err(timed_out(op)),
    }
}

impl WorkerTransport {
    /// Pinned NZB-fetch entry point (wasm32): runs the fail-closed
    /// [`crate::pinned_transport`] policy via
    /// [`crate::pinned_transport::pinned_rejection_message`] (TLS-first, then
    /// port allowlist `119`/`563`) BEFORE opening the `connect()` socket,
    /// then delegates to [`Self::connect`].
    ///
    /// A TLS-off config without the plaintext acknowledgment, or an
    /// off-allowlist config, fails here with `worker::Error::RustError`
    /// whose message carries the stable code (`transport_tls_required` /
    /// `transport_port_not_allowed`); the diagnostic is names-only, never
    /// credentials. The NZB intake wiring on Workers consumes this (not
    /// [`Self::connect`]).
    pub fn connect_pinned(config: &NntpConfig) -> worker::Result<Self> {
        if let Some(message) = crate::pinned_transport::pinned_rejection_message(config) {
            return Err(worker::Error::RustError(message));
        }
        Self::connect(config)
    }

    /// Opens `config.host:config.port` (implicit TLS when `config.tls`).
    ///
    /// General entry point: still dials plaintext fixtures when `config.tls`
    /// is false. The NZB fetch path must use [`Self::connect_pinned`], which
    /// enforces the fail-closed [`crate::pinned_transport`] policy before
    /// any socket open.
    pub fn connect(config: &NntpConfig) -> worker::Result<Self> {
        let secure = if config.tls {
            SecureTransport::On
        } else {
            SecureTransport::Off
        };
        let socket = Socket::builder()
            .secure_transport(secure)
            .connect(config.host.clone(), config.port)?;
        Ok(WorkerTransport {
            socket,
            timeout: config.timeout,
        })
    }

    /// Wraps an already-connected [`Socket`] (e.g. after `STARTTLS` via
    /// [`Socket::start_tls`], owned by the caller).
    pub fn from_socket(socket: Socket, timeout: Duration) -> Self {
        WorkerTransport { socket, timeout }
    }
}

impl Transport for WorkerTransport {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        with_timeout(self.timeout, "read", self.socket.read(buf)).await
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        with_timeout(self.timeout, "write", self.socket.write_all(buf)).await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        with_timeout(self.timeout, "shutdown", self.socket.shutdown()).await
    }
}
