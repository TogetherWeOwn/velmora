//! Request-local connections over a Hyperdrive binding. This adapter never
//! stores a Worker socket, client, driver, or parsed credentials.

use std::future::{ready, Ready};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::future::abortable;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, TlsConnect, TlsStream};
use tokio_postgres::Config;
use velmora_bridge::pg::{classify_connect_error, PgConnect, PgConnection};
use velmora_bridge::{BridgeError, Result};
use worker::js_sys::{Object, Reflect};
use worker::wasm_bindgen::closure::Closure;
use worker::wasm_bindgen::JsValue;
use worker::wasm_bindgen_futures::spawn_local;
use worker::{worker_sys, Hyperdrive, Socket};

pub struct HyperdriveConnect(Hyperdrive);

impl HyperdriveConnect {
    pub fn new(binding: Hyperdrive) -> Self {
        Self(binding)
    }
}

impl PgConnect for HyperdriveConnect {
    async fn connect(&self) -> Result<PgConnection> {
        let config: Config = self.0.connection_string().parse().map_err(|_| failed())?;
        let socket = ManagedSocket::connect(&self.0.host(), self.0.port())?;
        let (client, connection) = config
            .connect_raw(socket, UpgradeTls)
            .await
            .map_err(classify_connect_error)?;
        let (driver, stop) = abortable(connection);
        // The driver runs until the request drops its connection. That
        // aborts it here, and the abort drops the actual transport, whose
        // Drop requests the socket close without waiting for it.
        spawn_local(async move {
            let _ = driver.await;
        });
        Ok(PgConnection::new(client, move || stop.abort()))
    }
}

// workers-rs' Socket remains the Tokio I/O implementation but does not close
// its JS socket on Drop. Hold a raw close handle from creation, including
// while connect_raw is still waiting for TLS/authentication responses.
struct CloseSocket(Option<worker_sys::Socket>);

thread_local! {
    // One shared no-op rejection handler, so a close leaks no closure.
    static IGNORE_REJECTION: Closure<dyn FnMut(JsValue)> = Closure::new(|_: JsValue| {});
}

impl Drop for CloseSocket {
    fn drop(&mut self) {
        if let Some(socket) = self.0.take() {
            // Request close now, in this invocation. A rejection is handled
            // in JS, so nothing in Rust waits on the close or sees provider
            // or socket error strings.
            if let Ok(done) = socket.close() {
                IGNORE_REJECTION.with(|ignore| {
                    let _ = done.catch(ignore);
                });
            }
        }
    }
}

struct ManagedSocket {
    io: Socket,
    close: CloseSocket,
}

impl ManagedSocket {
    fn from_raw(raw: worker_sys::Socket) -> Self {
        let close = CloseSocket(Some(raw.clone()));
        Self {
            io: raw.into(),
            close,
        }
    }

    fn connect(host: &str, port: u16) -> Result<Self> {
        fn set(obj: &Object, key: &str, value: JsValue) -> Result<()> {
            match Reflect::set(obj, &JsValue::from_str(key), &value) {
                Ok(true) => Ok(()),
                _ => Err(failed()),
            }
        }
        let address = Object::new();
        set(&address, "hostname", JsValue::from_str(host))?;
        set(&address, "port", JsValue::from_f64(f64::from(port)))?;
        let options = Object::new();
        set(&options, "allowHalfOpen", JsValue::FALSE)?;
        set(&options, "secureTransport", JsValue::from_str("starttls"))?;
        let raw = worker_sys::connect(address.into(), options.into()).map_err(|_| failed())?;
        Ok(Self::from_raw(raw))
    }
}

struct UpgradeTls;

impl TlsConnect<ManagedSocket> for UpgradeTls {
    type Stream = ManagedSocket;
    type Error = io::Error;
    type Future = Ready<io::Result<Self::Stream>>;

    fn connect(self, mut socket: ManagedSocket) -> Self::Future {
        let error = || io::Error::other("Hyperdrive socket TLS upgrade failed");
        // startTls retires the old socket. Leave its guard armed if the
        // upgrade throws; otherwise let the new raw handle own closure.
        let upgraded = socket
            .close
            .0
            .as_ref()
            .ok_or_else(error)
            .and_then(|raw| raw.start_tls().map_err(|_| error()));
        ready(upgraded.map(|raw| {
            let _old = socket.close.0.take();
            ManagedSocket::from_raw(raw)
        }))
    }
}

impl TlsStream for ManagedSocket {
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

impl AsyncRead for ManagedSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for ManagedSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

fn failed() -> BridgeError {
    // Neither driver nor Cloudflare errors can be logged here: they can
    // contain the database configuration or server message text.
    BridgeError::Sql("pg: statement failed".into())
}
