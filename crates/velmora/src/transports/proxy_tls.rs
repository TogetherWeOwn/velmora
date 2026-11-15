//! TLS to a provider on a connection that a SOCKS5 proxy opened, made
//! here (rustls) and not by the runtime.
//!
//! The Workers runtime checks a certificate against the name it dialled.
//! Behind a proxy that is the proxy's name, and the option that names
//! another host for the check (`startTls({ expectedServerHostname })`) is
//! not applied by the deployed runtime. So on a proxied connection the
//! engine runs TLS itself, over the plain socket to the proxy:
//!
//! 1. the [`crate::socks5`] handshake, `CONNECT host:port` by name;
//! 2. a TLS handshake with that same `host` as SNI and as the name the
//!    certificate must carry, against the public roots.
//!
//! The proxy relays ciphertext. Nothing of NNTP is written before step 2
//! is done: this module hands out a TLS stream and no plain one.
//!
//! The steps are generic over the stream so that the native tests run
//! them over TCP; the Workers connector is
//! [`super::worker_socks5`].

use std::future::{poll_fn, Future};
use std::io;
use std::pin::pin;
use std::task::Poll;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::nntp::NntpConfig;
use crate::socks5::{self, Progress, Socks5Proxy};
use crate::transport::Transport;

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// The name the provider's certificate must carry: `config.host`, which
/// must be a DNS name. Fail closed, with no socket needed: a config
/// without TLS is refused, whatever `allow_insecure_plaintext` says, and
/// so is a host that is an IP literal (a certificate for an address is
/// not what a provider presents, and the proxy is asked by name).
pub fn server_name(config: &NntpConfig) -> io::Result<ServerName<'static>> {
    if !config.tls {
        return Err(refused(
            "transport_tls_required: no plaintext through a proxy",
        ));
    }
    match ServerName::try_from(config.host.clone()) {
        Ok(name @ ServerName::DnsName(_)) => Ok(name),
        _ => Err(refused(
            "transport_tls_required: a proxied host must be a DNS name",
        )),
    }
}

/// The connector production uses: the public roots, chain, name and
/// time checked, TLS 1.2 and 1.3 (the same as a native connection).
pub fn public_connector() -> io::Result<TlsConnector> {
    super::peer_tls::public_connector()
}

/// The plain connection to the proxy, for the handshake only.
struct Plain<'a, S>(&'a mut S);

impl<S: AsyncRead + AsyncWrite + Unpin> Transport for Plain<'_, S> {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).await
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf).await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}

/// Runs both steps on `stream`, a plain connection to `proxy`, and
/// returns the TLS stream to `config.host`.
///
/// `limit` bounds everything: when it ends first, the call fails. Each
/// failure has a fixed text and a class:
/// - [`io::ErrorKind::InvalidInput`]: refused by [`server_name`], before
///   a byte was written;
/// - [`socks5::is_proxy_failure`]: the proxy refused the login, answered
///   out of protocol, or did not get as far as accepting the login in
///   time;
/// - [`socks5::is_target_failure`]: the proxy did not connect to the
///   host, TLS with the host failed ([`socks5::ERR_TLS`]: a handshake
///   that broke, a chain that is not trusted, a certificate for another
///   name), or time ran out after the proxy accepted the login.
///
/// No error carries the TLS library's text, a host or a login. On an
/// error `stream` is dropped; the caller closes what is under it.
pub async fn connect<S>(
    mut stream: S,
    connector: &TlsConnector,
    config: &NntpConfig,
    proxy: &Socks5Proxy,
    progress: &Progress,
    limit: impl Future<Output = ()>,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = server_name(config)?;
    let steps = async {
        socks5::connect_tracked(
            &mut Plain(&mut stream),
            &proxy.username,
            &proxy.password,
            &config.host,
            config.port,
            progress,
        )
        .await?;
        // The handshake read every reply to its end, so the first byte
        // rustls reads is the server's.
        connector
            .connect(name, stream)
            .await
            .map_err(|e| socks5::target_failure(e.kind(), socks5::ERR_TLS))
    };
    let mut steps = pin!(steps);
    let mut limit = pin!(limit);
    let out = poll_fn(|cx| {
        if let Poll::Ready(out) = steps.as_mut().poll(cx) {
            return Poll::Ready(Some(out));
        }
        limit.as_mut().poll(cx).map(|()| None)
    })
    .await;
    match out {
        Some(out) => out,
        // The proxy accepted the login: the wait was for the host.
        None if progress.logged_in() => Err(socks5::target_failure(
            io::ErrorKind::TimedOut,
            socks5::ERR_TIMEOUT,
        )),
        None => Err(socks5::proxy_failure(
            io::ErrorKind::TimedOut,
            socks5::ERR_TIMEOUT,
        )),
    }
}

/// Writes all of `buf` and flushes it into the stream under TLS.
pub async fn write_all_flushed<S>(tls: &mut TlsStream<S>, buf: &[u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    super::peer_tls::write_all_flushed(tls, buf).await
}
