//! Qualification adapter: rustls over a literal-IP Worker TCP socket.
//! No runtime uses this adapter until real Worker fixture qualification and
//! account-lifetime gates pass. Enabling its feature alone does not dial.
//!
//! The caller MUST retain `WorkerSocketControl` outside the operation future,
//! hold account capacity before `open`, and release it only after `close`
//! succeeds. Errors, TTLs and dropping a future are not closure evidence.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::io;
use std::rc::Rc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio_rustls::client::TlsStream;
use worker::js_sys::{Object, Promise, Reflect};
use worker::wasm_bindgen::JsValue;
use worker::wasm_bindgen_futures::JsFuture;
use worker::{worker_sys, Socket};

use super::peer_tls::{public_connector, PeerTlsTarget};
use super::worker_socket::with_timeout;
use crate::transport::Transport;

fn socket_error() -> io::Error {
    io::Error::other("NNTP Worker TCP operation failed")
}

struct SocketState {
    raw: worker_sys::Socket,
    closing: Cell<bool>,
    close_promise: RefCell<Option<Promise>>,
    confirmed_closed: Cell<bool>,
}

/// Raw forced-close authority, independent of TLS handshake and I/O ownership.
/// `close` returning Ok is the only closure evidence this adapter supplies.
/// Failure/timeout must leave the caller's account capacity fenced.
#[derive(Clone)]
pub struct WorkerSocketControl(Rc<SocketState>);

impl WorkerSocketControl {
    fn request_close(&self) -> io::Result<Promise> {
        self.0.closing.set(true);
        if let Some(promise) = self.0.close_promise.borrow().as_ref() {
            return Ok(promise.clone());
        }
        let promise = self.0.raw.close().map_err(|_| socket_error())?;
        *self.0.close_promise.borrow_mut() = Some(promise.clone());
        Ok(promise)
    }

    pub async fn close(&self, timeout: Duration) -> io::Result<()> {
        if self.0.confirmed_closed.get() {
            return Ok(());
        }
        let close = self.request_close()?;
        with_timeout(timeout, "forced close", async {
            JsFuture::from(close).await.map_err(|_| socket_error())?;
            let closed = self.0.raw.closed().map_err(|_| socket_error())?;
            JsFuture::from(closed).await.map_err(|_| socket_error())?;
            Ok(())
        })
        .await?;
        self.0.confirmed_closed.set(true);
        Ok(())
    }

    pub fn confirmed_closed(&self) -> bool {
        self.0.confirmed_closed.get()
    }

    fn ensure_open(&self) -> io::Result<()> {
        if self.0.closing.get() {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "NNTP socket is closing",
            ))
        } else {
            Ok(())
        }
    }
}

struct OpeningGuard {
    control: WorkerSocketControl,
    armed: bool,
}

impl Drop for OpeningGuard {
    fn drop(&mut self) {
        if self.armed {
            // Initiates physical closure even if the future was never polled.
            // The retained supervisor still has to await and confirm closure.
            let _ = self.control.request_close();
        }
    }
}

/// An authenticated TLS byte pipe; no raw plaintext transport is exposed.
pub struct WorkerPinnedTlsTransport {
    tls: TlsStream<Socket>,
    control: WorkerSocketControl,
    timeout: Duration,
}

impl WorkerPinnedTlsTransport {
    /// Admit an account slot BEFORE calling this. The target must come from
    /// current authenticated resolution evidence with the full DNS answer set
    /// vetted. This method does not validate that evidence or send AUTHINFO.
    /// Keep the returned control outside the setup future, including on Err.
    pub fn open(
        target: PeerTlsTarget,
        timeout: Duration,
    ) -> io::Result<(
        WorkerSocketControl,
        impl Future<Output = io::Result<WorkerPinnedTlsTransport>>,
    )> {
        let connector = public_connector()?;
        let address = Object::new();
        Reflect::set(
            &address,
            &"hostname".into(),
            &target.peer().ip().to_string().into(),
        )
        .map_err(|_| socket_error())?;
        Reflect::set(
            &address,
            &"port".into(),
            &JsValue::from(target.peer().port()),
        )
        .map_err(|_| socket_error())?;
        let options = Object::new();
        // The private raw socket carries only rustls records, never NNTP.
        Reflect::set(&options, &"secureTransport".into(), &"off".into())
            .map_err(|_| socket_error())?;
        Reflect::set(&options, &"allowHalfOpen".into(), &JsValue::FALSE)
            .map_err(|_| socket_error())?;
        let raw =
            worker_sys::connect(address.into(), options.into()).map_err(|_| socket_error())?;
        let control = WorkerSocketControl(Rc::new(SocketState {
            raw: raw.clone(),
            closing: Cell::new(false),
            close_promise: RefCell::new(None),
            confirmed_closed: Cell::new(false),
        }));
        let guard = OpeningGuard {
            control: control.clone(),
            armed: true,
        };
        let setup = async move {
            // Move the whole Drop guard, not separately captured fields.
            let mut guard = guard;
            guard.control.ensure_open()?;
            let socket = Socket::from(raw);
            with_timeout(timeout, "open", async {
                socket.opened().await.map_err(|_| socket_error())
            })
            .await?;
            guard.control.ensure_open()?;
            let tls = with_timeout(
                timeout,
                "TLS handshake",
                connector.connect(target.server_name(), socket),
            )
            .await?;
            guard.control.ensure_open()?;
            let transport = Self {
                tls,
                control: guard.control.clone(),
                timeout,
            };
            guard.armed = false;
            Ok(transport)
        };
        Ok((control, setup))
    }
}

impl Drop for WorkerPinnedTlsTransport {
    fn drop(&mut self) {
        let _ = self.control.request_close();
    }
}

impl Transport for WorkerPinnedTlsTransport {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.control.ensure_open()?;
        with_timeout(self.timeout, "TLS read", self.tls.read(buf)).await
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.control.ensure_open()?;
        with_timeout(
            self.timeout,
            "TLS write",
            super::peer_tls::write_all_flushed(&mut self.tls, buf),
        )
        .await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.control.close(self.timeout).await
    }
}
