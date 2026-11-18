//! Workers NNTP transport through a SOCKS5 proxy, with TLS end to end.
//!
//! The Worker's source address changes from one invocation to the next;
//! a provider that limits the addresses of an account sees each as a new
//! one. A proxy with a fixed address in between gives the provider one
//! address to count.
//!
//! The order is fixed, and nothing of NNTP is sent before the last step:
//!
//! 1. `connect()` to the proxy in plain TCP.
//! 2. The [`crate::socks5`] handshake: login, `CONNECT host:port` with
//!    the provider's host name.
//! 3. A TLS handshake with the provider on that connection, made in the
//!    Worker ([`super::proxy_tls`]): the certificate is checked against
//!    the provider's name and the public roots.
//!
//! Step 3 is not the runtime's TLS. The runtime checks a certificate
//! against the name it dialled, here the proxy's, and the option that
//! names another host for the check (`startTls` with
//! `expectedServerHostname`) is not applied by the deployed runtime: a
//! connection upgraded that way ends before the server's first byte. A
//! direct connection keeps the runtime's TLS
//! ([`super::worker_socket`]).
//!
//! The proxy relays ciphertext: it sees the provider's host name and
//! port, and never the NNTP login or an article. There is no path from
//! here to plaintext NNTP: a configuration without TLS is refused before
//! any socket opens, and the only stream this module hands out is the
//! one under TLS.

#![cfg(all(feature = "worker-socks5-tls", target_arch = "wasm32"))]

use std::io;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio_rustls::client::TlsStream;
use worker::js_sys::{Object, Reflect};
use worker::wasm_bindgen::JsValue;
use worker::{worker_sys, Delay};

use super::proxy_tls;
use super::worker_socket::with_timeout;
use super::worker_stream::WorkerStream;
use crate::nntp::NntpConfig;
use crate::socks5::{self, Progress, Socks5Proxy};
use crate::transport::Transport;

/// The runtime would not open the socket to the proxy. Class-only: the
/// runtime's own message may name a host.
fn open_failed() -> io::Error {
    socks5::proxy_failure(io::ErrorKind::ConnectionRefused, socks5::ERR_IO)
}

fn refused(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn set(object: &Object, key: &str, value: JsValue) -> io::Result<()> {
    Reflect::set(object, &JsValue::from_str(key), &value)
        .map(|_| ())
        .map_err(|_| open_failed())
}

/// An NNTP connection to a provider through a SOCKS5 proxy, under TLS
/// made in the Worker. There is no plain stream to reach.
pub struct WorkerProxiedTransport {
    // Dropping the stream asks the runtime to close the connection: with
    // the transport, or with a connect that failed, ran out of time or was
    // dropped by its caller (`worker_stream`; a stalled write may keep the
    // socket until the invocation ends, as for a direct socket).
    tls: TlsStream<WorkerStream>,
    timeout: Duration,
}

impl WorkerProxiedTransport {
    /// Opens `config.host:config.port` through `proxy`, with TLS from
    /// here to the provider (see the module text).
    ///
    /// Fail closed, before any socket opens: `config.tls` must be set
    /// (there is no plaintext through a proxy, whatever
    /// `allow_insecure_plaintext` says), the host must be a DNS name,
    /// and the config must pass the [`crate::pinned_transport`] policy
    /// like `WorkerTransport::connect_pinned`. Those refusals are
    /// [`io::ErrorKind::InvalidInput`] with the policy's stable code.
    ///
    /// Any other error is a failed connect, with a fixed message:
    /// - [`socks5::is_proxy_failure`]: the proxy could not be reached,
    ///   refused the login or answered out of protocol;
    /// - [`socks5::is_target_failure`]: the proxy did not connect to the
    ///   provider's host, or TLS with it failed (a certificate that is
    ///   not the provider's fails here, before anything of NNTP).
    ///
    /// The whole connect is bounded by `config.timeout`, and so is each
    /// read and write after it. The caller may bound the call further;
    /// dropping this future closes the connection. `progress` then
    /// tells the caller whether the proxy had accepted the login, that
    /// is, whether the wait was for the provider's host.
    pub async fn connect_pinned(
        config: &NntpConfig,
        proxy: &Socks5Proxy,
        progress: &Progress,
    ) -> io::Result<Self> {
        proxy_tls::server_name(config)?;
        if let Some(message) = crate::pinned_transport::pinned_rejection_message(config) {
            return Err(refused(message));
        }
        let connector = proxy_tls::public_connector()?;

        let address = Object::new();
        set(&address, "hostname", JsValue::from_str(&proxy.host))?;
        set(&address, "port", JsValue::from_f64(f64::from(proxy.port)))?;
        let options = Object::new();
        set(&options, "allowHalfOpen", JsValue::FALSE)?;
        // The runtime's socket carries the SOCKS5 handshake and then
        // TLS records only.
        set(&options, "secureTransport", JsValue::from_str("off"))?;
        let raw = worker_sys::connect(address.into(), options.into()).map_err(|_| open_failed())?;
        let stream = WorkerStream::new(raw).map_err(|_| open_failed())?;

        let tls = proxy_tls::connect(
            stream,
            &connector,
            config,
            proxy,
            progress,
            Delay::from(config.timeout),
        )
        .await?;
        Ok(WorkerProxiedTransport {
            tls,
            timeout: config.timeout,
        })
    }
}

impl Transport for WorkerProxiedTransport {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        with_timeout(self.timeout, "read", self.tls.read(buf)).await
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        with_timeout(
            self.timeout,
            "write",
            proxy_tls::write_all_flushed(&mut self.tls, buf),
        )
        .await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        with_timeout(self.timeout, "shutdown", self.tls.shutdown()).await
    }
}
