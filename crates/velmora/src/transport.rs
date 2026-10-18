//! Portable NNTP transport abstraction.
//!
//! This module uses [`Transport`] as a byte pipe rather than accessing the
//! network or clock directly. Every implementation enforces the configured
//! per-operation timeout, reporting expiry as [`io::ErrorKind::TimedOut`].
//!
//! - Native (tokio + rustls): [`crate::transports::tokio_tls`] (feature
//!   `native-tls`).
//! - Cloudflare Workers (`connect()` socket): [`crate::transports::worker_socket`]
//!   (feature `worker-transport`, wasm32 only).
//! - Tests: implement [`Transport`] over an in-memory script.
//!
//! [`BufferedTransport`] adds CRLF line framing and NNTP dot-block reading on
//! top of any [`Transport`].

use std::io;

/// Byte pipe underlying the NNTP client.
///
/// # Timeouts
///
/// Every method must enforce the connection's read/write timeout and report
/// expiry as an [`io::Error`] with kind [`io::ErrorKind::TimedOut`]. The core
/// protocol code owns no timers so it stays portable across tokio (native)
/// and Workers (where [`worker::Delay`](https://docs.rs/worker) backs the
/// timeout) runtimes.
pub trait Transport {
    /// Read up to `buf.len()` bytes; returns the byte count (`0` on EOF).
    /// Must enforce the read timeout.
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl std::future::Future<Output = io::Result<usize>> + 'a;

    /// Write the whole buffer; must enforce the write timeout.
    fn write_all<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> impl std::future::Future<Output = io::Result<()>> + 'a;

    /// Shut down the connection (NNTP `QUIT` should already have been sent).
    fn shutdown<'a>(&'a mut self) -> impl std::future::Future<Output = io::Result<()>> + 'a;
}

/// Maximum accepted length of one server line (protects the line buffer from
/// unbounded growth on a hostile or broken server).
pub const MAX_LINE_BYTES: usize = 16 * 1024;

/// Default maximum decoded wire bytes in a single article/dot-block (v1 parity).
pub const MAX_ARTICLE_BYTES: usize = 64 * 1024 * 1024;

/// Message of the [`io::Error`] a dot-block read returns when the article
/// exceeds the configured byte limit. Callers classify that error with
/// [`is_article_limit_error`] instead of treating it as a connection or
/// provider failure: the article is simply too large to hand back.
pub const ARTICLE_LIMIT_ERROR: &str = "NNTP article exceeds byte limit";

/// Whether `error` is the article-byte-limit refusal above. The
/// connection that produced it has been invalidated (the dot-block was
/// abandoned mid-stream) and cannot be reused.
pub fn is_article_limit_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::InvalidData && error.to_string() == ARTICLE_LIMIT_ERROR
}

/// CRLF line framing and NNTP dot-block reading over any [`Transport`].
pub struct BufferedTransport<T: Transport> {
    inner: T,
    buf: Vec<u8>,
    max_article_bytes: usize,
    usable: bool,
}

/// Borrow-safe cancellation cleanup for [`BufferedTransport::read_dot_block`].
///
/// The guard owns both mutable borrows for the duration of the dot-block
/// read, so every line append goes through it. If the read completes, the
/// caller disarms the guard and keeps the output. If the inner operation
/// returns `Err` or the awaiting future is dropped after its first poll, the
/// guard is still armed when it is dropped and restores the caller's original
/// output prefix while poisoning the connection. The guard is only created
/// after the first poll starts running the `async` body, so dropping the
/// future before its first poll performs no cleanup and causes no false
/// poisoning. No `unsafe` code, protocol changes, or read-line redesign.
struct DotBlockCancelGuard<'a, T: Transport> {
    transport: &'a mut BufferedTransport<T>,
    out: &'a mut Vec<u8>,
    start: usize,
    armed: bool,
}

impl<T: Transport> Drop for DotBlockCancelGuard<'_, T> {
    fn drop(&mut self) {
        if self.armed {
            self.out.truncate(self.start);
            self.transport.invalidate();
        }
    }
}

impl<T: Transport> DotBlockCancelGuard<'_, T> {
    async fn run(&mut self) -> io::Result<()> {
        loop {
            let line = self.transport.read_line().await?;
            if line == b"." {
                return Ok(());
            }
            let content = if line.starts_with(b"..") {
                &line[1..]
            } else {
                &line[..]
            };
            let remaining = self
                .transport
                .max_article_bytes
                .saturating_sub(self.out.len() - self.start);
            if content.len() + 2 > remaining {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    ARTICLE_LIMIT_ERROR,
                ));
            }
            self.out.extend_from_slice(content);
            self.out.extend_from_slice(b"\r\n");
        }
    }
}

impl<T: Transport> BufferedTransport<T> {
    /// Wraps a connected transport (the server greeting is still unread).
    pub fn new(inner: T) -> Self {
        Self::with_article_limit(inner, MAX_ARTICLE_BYTES)
    }

    /// Wraps a transport with a per-dot-block byte limit, clamped to the hard
    /// [`MAX_ARTICLE_BYTES`] ceiling. Zero permits only empty dot-blocks.
    pub fn with_article_limit(inner: T, max_article_bytes: usize) -> Self {
        BufferedTransport {
            inner,
            buf: Vec::with_capacity(4096),
            max_article_bytes: max_article_bytes.min(MAX_ARTICLE_BYTES),
            usable: true,
        }
    }

    /// Prevents reuse after reply framing or a pipeline is no longer aligned.
    pub(crate) fn invalidate(&mut self) {
        self.usable = false;
        self.buf.clear();
    }

    fn ensure_usable(&self) -> io::Result<()> {
        if self.usable {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "NNTP connection is unusable; reconnect before retrying",
            ))
        }
    }

    /// Returns the wrapped transport.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Shuts the wrapped transport down.
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }

    /// Reads one CRLF-terminated server line, returned WITHOUT the terminator.
    /// Bare-LF line endings are tolerated.
    pub async fn read_line(&mut self) -> io::Result<Vec<u8>> {
        self.ensure_usable()?;
        let result = self.read_line_inner().await;
        if result.is_err() {
            self.invalidate();
        }
        result
    }

    async fn read_line_inner(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                if pos >= MAX_LINE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "NNTP line exceeds 16 KiB",
                    ));
                }
                let mut line = self.buf.drain(..=pos).collect::<Vec<u8>>();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            if self.buf.len() >= MAX_LINE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "NNTP line exceeds 16 KiB",
                ));
            }
            let mut chunk = [0u8; 4096];
            let n = self.inner.read(&mut chunk).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "NNTP connection closed mid-line",
                    ));
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "NNTP connection closed without CRLF",
                ));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Reads an NNTP multi-line (dot-terminated) data block into `out`,
    /// performing dot-unstuffing (`..X` → `.X`). The terminating lone `.`
    /// line is consumed and not written. The limit counts appended bytes,
    /// including CRLF, not pre-existing contents. On failure, partial output is
    /// rolled back and this connection cannot be reused. Dropping the returned
    /// future after it has been polled performs the same rollback and
    /// poisoning; dropping before the first poll runs no code and leaves the
    /// connection untouched.
    pub async fn read_dot_block(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        self.ensure_usable()?;
        let start = out.len();
        let mut guard = DotBlockCancelGuard {
            transport: self,
            out,
            start,
            armed: true,
        };
        let result = guard.run().await;
        if result.is_ok() {
            guard.armed = false;
        }
        // On `Err` the guard stays armed so its `Drop` performs the same
        // truncate + invalidate as cancellation. On `Ok` it is disarmed, so
        // completed output and connection usability are retained.
        result
    }

    /// Sends one protocol line (appends CRLF) in a single write, so one
    /// command is always one packet on the wire.
    pub async fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        self.ensure_usable()?;
        if line.contains(&b'\r') || line.contains(&b'\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NNTP command contains a line break",
            ));
        }
        let mut framed = Vec::with_capacity(line.len() + 2);
        framed.extend_from_slice(line);
        framed.extend_from_slice(b"\r\n");
        let result = self.inner.write_all(&framed).await;
        if result.is_err() {
            self.invalidate();
        }
        result
    }
}
