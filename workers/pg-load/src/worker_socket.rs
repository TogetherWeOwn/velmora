//! Close both handshake and established sockets when a read probe times out.

use std::{
    future::{ready, Ready},
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, TlsConnect, TlsStream};
use velmora_bridge::{BridgeError, Result};
use worker::{
    js_sys::{Object, Reflect},
    wasm_bindgen::JsValue,
    wasm_bindgen_futures::{spawn_local, JsFuture},
    worker_sys, Socket,
};

pub(super) struct ManagedSocket {
    io: Socket,
    close: Option<worker_sys::Socket>,
}

impl ManagedSocket {
    fn from_raw(raw: worker_sys::Socket) -> Self {
        Self {
            io: raw.clone().into(),
            close: Some(raw),
        }
    }

    pub(super) fn connect(host: &str, port: u16) -> Result<Self> {
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

impl Drop for ManagedSocket {
    fn drop(&mut self) {
        if let Some(socket) = self.close.take() {
            if let Ok(done) = socket.close() {
                spawn_local(async move {
                    let _ = JsFuture::from(done).await;
                });
            }
        }
    }
}

pub(super) struct UpgradeTls;
impl TlsConnect<ManagedSocket> for UpgradeTls {
    type Stream = ManagedSocket;
    type Error = io::Error;
    type Future = Ready<io::Result<Self::Stream>>;

    fn connect(self, mut socket: ManagedSocket) -> Self::Future {
        let error = || io::Error::other("Hyperdrive socket TLS upgrade failed");
        let upgraded = socket
            .close
            .as_ref()
            .ok_or_else(error)
            .and_then(|raw| raw.start_tls().map_err(|_| error()));
        ready(upgraded.map(|raw| {
            let _old = socket.close.take(); // startTls retired the old handle
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
    BridgeError::Sql("pg: statement failed".into())
}
