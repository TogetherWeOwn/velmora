//! Cloudflare Workers NNTP transport over the runtime `connect()` TCP socket.
//!
//! Opens `hostname:port` with the runtime's `connect()` (implicit TLS for
//! NNTPS, `secureTransport: "on"`) and reads and writes it through
//! `worker_stream`, which holds one stream reader and one writer for the
//! connection's life. Per-operation timeouts are
//! enforced by racing each operation against
//! [`worker::Delay`](https://docs.rs/worker/latest/worker/struct.Delay.html)
//! and reporting expiry as [`io::ErrorKind::TimedOut`], matching the native
//! transport's contract.

#![cfg(all(feature = "worker-transport", target_arch = "wasm32"))]

use std::future::Future;
use std::io;
use std::pin::pin;
use std::task::Context;
use std::time::Duration;

use futures_util::future::{self, Either};
use futures_util::task::noop_waker_ref;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{Delay, Socket};

use super::worker_stream::WorkerStream;

use crate::nntp::NntpConfig;
use crate::transport::Transport;

/// Workers transport over a `connect()` TCP socket.
pub struct WorkerTransport {
    io: Io,
    timeout: Duration,
}

enum Io {
    /// A socket this transport opened.
    Stream(WorkerStream),
    /// A socket the caller opened ([`WorkerTransport::from_socket`]).
    Socket(Socket),
}

fn timed_out(op: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("NNTP {op} timed out on Workers socket"),
    )
}

pub(super) async fn with_timeout<T>(
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
        let stream = WorkerStream::open(&config.host, config.port, config.tls)?;
        Ok(WorkerTransport {
            io: Io::Stream(stream),
            timeout: config.timeout,
        })
    }

    /// Wraps an already-connected [`Socket`] (e.g. after `STARTTLS` via
    /// [`Socket::start_tls`], owned by the caller).
    pub fn from_socket(socket: Socket, timeout: Duration) -> Self {
        WorkerTransport {
            io: Io::Socket(socket),
            timeout,
        }
    }
}

/// A transport that is dropped (a call that ran out of time, a session
/// given up without a goodbye) asks the runtime to close its connection;
/// otherwise the runtime would keep the socket, and the provider would keep
/// counting it, until the invocation ends. `close()` is called and not
/// awaited: the first poll makes the runtime's call, and its promise is let
/// go. The runtime flushes pending writes before it tears down, so a socket
/// dropped with a stalled write (a POST cut off against a peer that stopped
/// reading) may still stay open until the invocation ends: provider
/// connection counts on the posting path must not rely on this.
impl Drop for WorkerTransport {
    fn drop(&mut self) {
        match &mut self.io {
            // The stream asks for the close when it is dropped, below.
            Io::Stream(_) => {}
            Io::Socket(socket) => {
                let mut close = pin!(socket.close());
                let mut cx = Context::from_waker(noop_waker_ref());
                let _ = close.as_mut().poll(&mut cx);
            }
        }
    }
}

impl Transport for WorkerTransport {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.io {
            Io::Stream(stream) => with_timeout(self.timeout, "read", stream.read(buf)).await,
            Io::Socket(socket) => with_timeout(self.timeout, "read", socket.read(buf)).await,
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match &mut self.io {
            Io::Stream(stream) => with_timeout(self.timeout, "write", stream.write_all(buf)).await,
            Io::Socket(socket) => with_timeout(self.timeout, "write", socket.write_all(buf)).await,
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match &mut self.io {
            Io::Stream(stream) => with_timeout(self.timeout, "shutdown", stream.shutdown()).await,
            Io::Socket(socket) => with_timeout(self.timeout, "shutdown", socket.shutdown()).await,
        }
    }
}
