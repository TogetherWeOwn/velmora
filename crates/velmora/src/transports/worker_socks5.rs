//! Workers NNTP transport through a SOCKS5 proxy, with TLS end to end.
//!
//! The Worker's source address changes from one invocation to the next;
//! a provider that limits the addresses of an account sees each as a new
//! one. A proxy with a fixed address in between gives the provider one
//! address to count.
//!
//! The order is fixed, and nothing of NNTP is sent before the last step:
//!
//! 1. `connect()` to the proxy in plain TCP, opened as `starttls` so that
//!    the same connection can be upgraded later.
//! 2. The [`crate::socks5`] handshake: login, `CONNECT host:port` with
//!    the provider's host name.
//! 3. `startTls({ expectedServerHostname: host })` on that connection.
//!    The runtime then runs the TLS handshake with the provider through
//!    the proxy and checks the certificate against the provider's name,
//!    as it does for a direct `secureTransport: "on"` socket. Without the
//!    option the runtime would check against the name it dialled, the
//!    proxy's, and no provider certificate would pass.
//!
//! The proxy relays ciphertext: it sees the provider's host name and
//! port, and never the NNTP login or an article. There is no path from
//! here to plaintext NNTP: a configuration without TLS is refused before
//! any socket opens, and a failed upgrade closes the connection.
//!
//! The Worker SDK's `Socket::start_tls` takes no options (0.8.7), so step
//! 3 is a binding of its own to the same runtime method.

#![cfg(all(feature = "worker-transport", target_arch = "wasm32"))]

use std::future::Future;
use std::io;
use std::pin::pin;
use std::task::Context;
use std::time::Duration;

use futures_util::task::noop_waker_ref;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::js_sys::{Object, Reflect};
use worker::wasm_bindgen::prelude::*;
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::{worker_sys, Socket};

use super::worker_socket::{with_timeout, WorkerTransport};
use crate::nntp::NntpConfig;
use crate::socks5::{self, Progress, Socks5Proxy};
use crate::transport::Transport;

#[wasm_bindgen(wasm_bindgen = worker::wasm_bindgen)]
extern "C" {
    /// The runtime's socket, seen as the one method the SDK does not
    /// bind with its options.
    type UpgradableSocket;

    #[wasm_bindgen(method, catch, js_name = startTls)]
    fn start_tls_with(
        this: &UpgradableSocket,
        options: &JsValue,
    ) -> Result<worker_sys::Socket, JsValue>;
}

/// The runtime would not open the socket to the proxy. Class-only: the
/// runtime's own message may name a host.
fn open_failed() -> io::Error {
    socks5::proxy_failure(io::ErrorKind::ConnectionRefused, socks5::ERR_IO)
}

fn refused(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// The plain connection to the proxy, for the length of the handshake.
/// Dropped with its socket still in it (an error, a handshake that ran
/// out of time and was dropped), it asks the runtime to close the
/// connection, as [`WorkerTransport`] does.
struct ProxyStage {
    socket: Option<Socket>,
    timeout: Duration,
}

impl ProxyStage {
    fn socket(&mut self) -> io::Result<&mut Socket> {
        self.socket.as_mut().ok_or_else(open_failed)
    }
}

impl Drop for ProxyStage {
    fn drop(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            let mut close = pin!(socket.close());
            let mut cx = Context::from_waker(noop_waker_ref());
            let _ = close.as_mut().poll(&mut cx);
        }
    }
}

impl Transport for ProxyStage {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let timeout = self.timeout;
        with_timeout(timeout, "read", self.socket()?.read(buf)).await
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let timeout = self.timeout;
        with_timeout(timeout, "write", self.socket()?.write_all(buf)).await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        let timeout = self.timeout;
        with_timeout(timeout, "shutdown", self.socket()?.shutdown()).await
    }
}

fn set(object: &Object, key: &str, value: JsValue) -> io::Result<()> {
    Reflect::set(object, &JsValue::from_str(key), &value)
        .map(|_| ())
        .map_err(|_| open_failed())
}

impl WorkerTransport {
    /// Opens `config.host:config.port` through `proxy`, with TLS from
    /// here to the provider (see the module text).
    ///
    /// Fail closed, before any socket opens: `config.tls` must be set
    /// (there is no plaintext through a proxy, whatever
    /// `allow_insecure_plaintext` says), and the config must pass the
    /// [`crate::pinned_transport`] policy like
    /// [`Self::connect_pinned`]. Those refusals are
    /// [`io::ErrorKind::InvalidInput`] with the policy's stable code.
    ///
    /// Any other error is a failed connect, with a fixed message:
    /// - [`socks5::is_proxy_failure`]: the proxy could not be reached,
    ///   refused the login or answered out of protocol;
    /// - [`socks5::is_target_failure`]: the proxy did not connect to the
    ///   provider's host;
    /// - neither: the upgrade to TLS could not start.
    ///
    /// The TLS handshake itself runs with the first read or write on the
    /// returned transport, so a certificate that does not match shows
    /// there, as on a direct socket.
    ///
    /// Each read and write is bounded by `config.timeout`. The caller
    /// bounds the whole call; dropping this future closes the connection.
    /// `progress` then tells the caller whether the proxy had accepted
    /// the login, that is, whether the wait was for the provider's host.
    pub async fn connect_pinned_via_socks5(
        config: &NntpConfig,
        proxy: &Socks5Proxy,
        progress: &Progress,
    ) -> io::Result<Self> {
        if !config.tls {
            return Err(refused(
                "transport_tls_required: no plaintext through a proxy".into(),
            ));
        }
        if let Some(message) = crate::pinned_transport::pinned_rejection_message(config) {
            return Err(refused(message));
        }

        let address = Object::new();
        set(&address, "hostname", JsValue::from_str(&proxy.host))?;
        set(&address, "port", JsValue::from_f64(f64::from(proxy.port)))?;
        let options = Object::new();
        set(&options, "allowHalfOpen", JsValue::FALSE)?;
        set(&options, "secureTransport", JsValue::from_str("starttls"))?;
        // Built before the socket opens: nothing after the handshake
        // can fail without the connection being closed.
        let tls_options = Object::new();
        set(
            &tls_options,
            "expectedServerHostname",
            JsValue::from_str(&config.host),
        )?;
        let raw = worker_sys::connect(address.into(), options.into()).map_err(|_| open_failed())?;

        let mut stage = ProxyStage {
            socket: Some(Socket::from(raw.clone())),
            timeout: config.timeout,
        };
        socks5::connect_tracked(
            &mut stage,
            &proxy.username,
            &proxy.password,
            &config.host,
            config.port,
            progress,
        )
        .await?;

        // The handshake is over and every reply was read to its end: no
        // read or write is pending, so the streams are free to hand
        // over. From here the plain socket is not closed on drop; the
        // upgrade takes the connection.
        drop(stage.socket.take());
        match raw
            .unchecked_ref::<UpgradableSocket>()
            .start_tls_with(&tls_options.into())
        {
            Ok(tls) => Ok(WorkerTransport::from_socket(
                Socket::from(tls),
                config.timeout,
            )),
            Err(_) => {
                // Never go on in plaintext: the connection is given up.
                let _ = raw.close();
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "socks5: TLS upgrade could not start",
                ))
            }
        }
    }
}
