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
