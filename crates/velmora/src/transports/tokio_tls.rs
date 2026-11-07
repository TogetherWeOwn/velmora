//! Native NNTP transport: tokio TCP with optional rustls TLS.
//!
//! Trust roots come from the Mozilla bundle ([`webpki_roots`]) so behaviour
//! does not depend on the host OS certificate store — the same handshake
//! succeeds on a laptop, in CI, and in a Container.

#![cfg(all(feature = "native-tls", not(target_arch = "wasm32")))]

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::nntp::NntpConfig;
use crate::transport::Transport;

enum Stream {
    Plain(TcpStream),
    // Boxed: the TLS stream is an order of magnitude larger than TcpStream.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// Native transport over TCP, optionally wrapped in TLS.
pub struct NativeTlsTransport {
    stream: Stream,
    timeout: Duration,
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "NNTP operation timed out")
}

async fn with_timeout<T>(
    timeout: Duration,
    fut: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| timed_out())?
}

/// Connects to `config.host:config.port` (implicit TLS when `config.tls`),
/// applying `config.timeout` to the TCP connect itself.
///
/// General entry point: still dials plaintext fixtures/tests when
/// `config.tls` is false. The NZB fetch path must use [`connect_pinned`],
/// which enforces the fail-closed [`crate::pinned_transport`] policy before
/// any TCP dial.
pub async fn connect(config: &NntpConfig) -> io::Result<NativeTlsTransport> {
    let addr = format!("{}:{}", config.host, config.port);
    let tcp = with_timeout(config.timeout, TcpStream::connect(addr)).await?;
    // NNTP is latency-sensitive but not throughput-critical on the command
    // channel; article bodies stream through the same socket, so keep Nagle
    // off for pipelined command latency.
    tcp.set_nodelay(true)?;
    let stream = if config.tls {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = ServerName::try_from(config.host.clone())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid TLS server name {:?}", config.host),
                )
            })?
            .to_owned();
        let tls = with_timeout(config.timeout, connector.connect(server_name, tcp)).await?;
        Stream::Tls(Box::new(tls))
    } else {
        Stream::Plain(tcp)
    };
    Ok(NativeTlsTransport {
        stream,
        timeout: config.timeout,
    })
}

/// Pinned NZB-fetch entry point: runs the fail-closed
/// [`crate::pinned_transport`] policy (TLS-first, then port allowlist
/// `119`/`563`) BEFORE any TCP dial, then delegates to [`connect`].
///
/// A TLS-off config without the plaintext acknowledgment, or an
/// off-allowlist config, fails here with `InvalidInput` whose message
/// carries the stable code (`transport_tls_required` /
/// `transport_port_not_allowed`); the diagnostic is names-only, never
/// credentials. The NZB intake wiring consumes this (not [`connect`]) plus
/// [`crate::pinned_transport::with_cancel`] for the fetch itself.
pub async fn connect_pinned(config: &NntpConfig) -> io::Result<NativeTlsTransport> {
    if let Some(message) = crate::pinned_transport::pinned_rejection_message(config) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, message));
    }
    connect(config).await
}

impl Transport for NativeTlsTransport {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let timeout = self.timeout;
        match &mut self.stream {
            Stream::Plain(s) => with_timeout(timeout, s.read(buf)).await,
            Stream::Tls(s) => with_timeout(timeout, s.read(buf)).await,
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let timeout = self.timeout;
        match &mut self.stream {
            Stream::Plain(s) => with_timeout(timeout, s.write_all(buf)).await,
            Stream::Tls(s) => with_timeout(timeout, s.write_all(buf)).await,
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        let timeout = self.timeout;
        match &mut self.stream {
            Stream::Plain(s) => with_timeout(timeout, s.shutdown()).await,
            Stream::Tls(s) => with_timeout(timeout, s.shutdown()).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::nntp::NntpConfig;

    const SENTINEL_USER: &str = "sentinel-user-9f3c";
    const SENTINEL_PASS: &str = "sentinel-pass-7a1e";

    fn pinned_config(host: &str, port: u16, tls: bool) -> NntpConfig {
        NntpConfig {
            host: host.to_owned(),
            port,
            tls,
            allow_insecure_plaintext: false,
            username: Some(SENTINEL_USER.to_owned()),
            password: Some(SENTINEL_PASS.to_owned()),
            // Short deadline so a validation-skipping mutant fails fast
            // instead of hanging on a real dial.
            timeout: Duration::from_millis(200),
            max_pipelined: 1,
            max_article_bytes: crate::transport::MAX_ARTICLE_BYTES,
        }
    }

    fn assert_pinned_rejection(err: &io::Error, code: &str) {
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(
            msg.contains(code),
            "error message must carry stable code {code}: {msg}"
        );
        assert!(
            !msg.contains(SENTINEL_USER) && !msg.contains(SENTINEL_PASS),
            "error message must stay names-only: {msg}"
        );
    }

    /// TLS-off configs fail before any TCP dial, even when a listener is
    /// bound on the target port (kills a mutant that skips validation: the
    /// mutant would dial plaintext and return `Ok`).
    #[tokio::test]
    async fn connect_pinned_rejects_tls_off_before_any_dial() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        listener
            .set_nonblocking(true)
            .expect("listener nonblocking");
        let port = listener.local_addr().expect("listener addr").port();

        let err = match connect_pinned(&pinned_config("127.0.0.1", port, false)).await {
            Err(err) => err,
            Ok(_) => panic!("TLS-off config must be rejected before dial"),
        };
        assert_pinned_rejection(&err, "transport_tls_required");

        assert!(
            matches!(
                listener.accept(),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
            ),
            "rejected config must not have dialled the bound listener"
        );
    }

    /// TLS-on configs with an off-allowlist port fail before any TCP dial
    /// (kills a mutant that skips validation: the mutant would attempt a
    /// real dial and surface `ConnectionRefused`, not `InvalidInput`).
    #[tokio::test]
    async fn connect_pinned_rejects_off_allowlist_port_before_any_dial() {
        let err = match connect_pinned(&pinned_config("127.0.0.1", 80, true)).await {
            Err(err) => err,
            Ok(_) => panic!("port-80 config must be rejected before dial"),
        };
        assert_pinned_rejection(&err, "transport_port_not_allowed");
    }
}
