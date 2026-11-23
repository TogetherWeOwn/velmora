//! The permit gate as a Durable Object, and the Worker's way to ask it.
//!
//! All rules are in `velmora_bridge::gate`. Here: one object per gate
//! name, its one stored record, and the two ways in.
//!
//! - A **session** is a WebSocket the object accepts for hibernation.
//!   The first request rides in a header of the upgrade and its reply
//!   is the first message, so taking the slots of a job is one round
//!   trip and one billed request. What follows (renewals, more slots,
//!   the release) are messages, billed at a twentieth of a request.
//!   The session's slots are kept in the socket's attachment: the
//!   runtime may drop the object from memory between two messages
//!   (after about ten seconds without one), bills no duration while it
//!   is out, and hands every open socket back when the next event
//!   brings it in again. Nothing is written to storage for a slot and
//!   no timer keeps the object in memory.
//! - A plain JSON `POST` asks without a session (the rollout step, the
//!   load for the operator). It can take no slot.
//!
//! A Rust object class cannot export RPC methods, so there is no stub
//! to hold instead of the socket.
//!
//! Nothing here logs a provider's host or credentials: they never reach
//! the object. A log line carries the gate's state as numbers only.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::future::Future;
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::Duration;

use velmora_bridge::gate::{
    open_detached, Gate, GateAnswer, GateRecord, GateReply, GateRequest, GateSession, GateStore,
    GateTransport, SessionState,
};
use velmora_bridge::ingress::Spawner;
use velmora_bridge::{BridgeError, Clock, Result};
use worker::wasm_bindgen::closure::Closure;
use worker::wasm_bindgen::{self, JsCast, JsValue};
use worker::web_sys;
use worker::{
    console_log, durable_object, DurableObject, Env, Method, ObjectNamespace, Request, RequestInit,
    Response, State, Storage, Stub, WebSocket, WebSocketIncomingMessage, WebSocketPair,
    WorkerVersionMetadata,
};

use crate::d1::D1Sql;
use crate::env::WorkerClock;

/// Name of the Durable Object namespace binding.
pub const GATE_BINDING: &str = "PERMIT_GATE";

/// Name of the version metadata binding: the id of the deployed version
/// tells a gate that it runs new code (`Gate::new`).
pub const VERSION_BINDING: &str = "CF_VERSION_METADATA";

/// Key of the one value a gate stores.
const RECORD_KEY: &str = "record";

/// The header of a session's upgrade request that carries its first
/// [`GateRequest`], as JSON in ASCII.
const REQUEST_HEADER: &str = "x-velmora-gate";

/// JSON with every character outside ASCII escaped: a header value.
/// Parsed from the text, here and in the caller: a permit's token is a
/// 64-bit number, and a JavaScript number does not hold one.
fn ascii_json<T: serde::Serialize>(value: &T) -> Option<String> {
    let raw = serde_json::to_string(value).ok()?;
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c.is_ascii() {
            true => out.push(c),
            false => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    Some(out)
}

/// The record as one JSON string in the object's storage.
struct DoStore(Storage);

impl GateStore for DoStore {
    async fn load(&self) -> Result<Option<GateRecord>> {
        let raw: Option<String> = self
            .0
            .get(RECORD_KEY)
            .await
            .map_err(|_| BridgeError::Sql("gate: storage read failed".into()))?;
        raw.map(|raw| serde_json::from_str(&raw))
            .transpose()
            .map_err(|_| BridgeError::Sql("gate: stored record unreadable".into()))
    }

    async fn save(&self, record: &GateRecord) -> Result<()> {
        let raw = serde_json::to_string(record)
            .map_err(|_| BridgeError::Sql("gate: record encode failed".into()))?;
        self.0
            .put(RECORD_KEY, raw)
            .await
            .map_err(|_| BridgeError::Sql("gate: storage write failed".into()))
    }
}

/// The session a socket was accepted for, from its attachment.
fn attached(ws: &WebSocket) -> Option<SessionState> {
    let raw = ws.deserialize_attachment::<String>().ok().flatten()?;
    serde_json::from_str(&raw).ok()
}

/// Keeps the session with its socket. `false`: it could not be kept.
fn attach(ws: &WebSocket, session: &SessionState) -> bool {
    serde_json::to_string(session).is_ok_and(|raw| ws.serialize_attachment(raw).is_ok())
}

#[durable_object]
pub struct PermitGate {
    state: State,
    /// `Err`: a binding is missing; every request fails with its name.
    gate: core::result::Result<Rc<Gate<D1Sql, DoStore>>, &'static str>,
    /// A slot went to a job in the line since the object came into
    /// memory: said once in the log.
    handed: core::cell::Cell<bool>,
}

impl PermitGate {
    /// The gate, started: with the sessions whose sockets are still
    /// open when the object has just come into memory. `ending`: the
    /// session whose socket is closing, which is none of them.
    async fn ready(
        &self,
        ending: Option<u64>,
    ) -> core::result::Result<&Rc<Gate<D1Sql, DoStore>>, String> {
        let gate = self.gate.as_ref().map_err(|name| format!("gate: {name}"))?;
        if gate.started() {
            return Ok(gate);
        }
        let now = WorkerClock.now();
        let mut sessions = Vec::new();
        for ws in self.state.get_websockets() {
            match attached(&ws) {
                Some(session) if Some(session.id) == ending => {}
                Some(session) if !session.stale(now) => sessions.push(session),
                // Nothing live on it and long silent, or not a session.
                _ => {
                    let _ = ws.close(Some(1001), Some("idle"));
                }
            }
        }
        let open = sessions.len();
        gate.resume(sessions, now)
            .await
            .map_err(|e| format!("gate: {e}"))?;
        // Once per time the object comes into memory.
        if let Some(record) = gate.record() {
            console_log!(
                "permit gate started: sessions={} jobs_until={} reads_until={} warm_until={} seized={}",
                open,
                record.jobs_until,
                record.reads_until,
                record.warm_jobs.max(record.warm_reads),
                record.seized.len()
            );
        }
        Ok(gate)
    }

    /// Closes the sessions whose holder has gone without a word: its
    /// slots have run out and it has not asked since. The socket of
    /// such a session may be all that keeps the holder's invocation
    /// from ending.
    fn reap(&self, gate: &Gate<D1Sql, DoStore>) {
        let now = WorkerClock.now();
        for ws in self.state.get_websockets() {
            if let Some(session) = attached(&ws).filter(|s| s.stale(now)) {
                gate.close(session.id);
                let _ = ws.close(Some(1001), Some("idle"));
            }
        }
    }

    /// The end of a session's socket, however it came. What it held
    /// goes to the line.
    async fn ended(&self, ws: &WebSocket) {
        let Some(session) = attached(ws) else {
            return;
        };
        if let Ok(gate) = self.ready(Some(session.id)).await {
            gate.close(session.id);
            gate.settle(WorkerClock.now()).await;
            self.deliver(gate).await;
        }
    }

    /// Sends the sessions that waited in the line the slots they were
    /// handed, each kept with its socket first. A session that cannot
    /// be sent to has ended: its slot goes to the next in the line.
    async fn deliver(&self, gate: &Gate<D1Sql, DoStore>) {
        loop {
            let pushes = gate.pushes();
            if pushes.is_empty() {
                return;
            }
            let sockets = self.state.get_websockets();
            let (mut lost, mut slot) = (false, false);
            for (id, reply) in pushes {
                let ws = sockets
                    .iter()
                    .find(|ws| attached(ws).is_some_and(|s| s.id == id));
                let sent = ws.is_some_and(|ws| {
                    attach(ws, &gate.session(id, WorkerClock.now()))
                        && serde_json::to_string(&reply)
                            .is_ok_and(|raw| ws.send_with_str(&raw).is_ok())
                });
                // A reply without a slot tells a job to ask elsewhere.
                slot |= sent && matches!(reply.answers[..], [GateAnswer::Acquired(Some(_))]);
                if !sent {
                    gate.close(id);
                    if let Some(ws) = ws {
                        let _ = ws.close(Some(1011), Some("gate: session not kept"));
                    }
                    lost = true;
                }
            }
            if slot && !self.handed.replace(true) {
                console_log!("permit gate line: a slot went to a job that waited");
            }
            if !lost {
                return;
            }
            gate.settle(WorkerClock.now()).await;
        }
    }
}

impl DurableObject for PermitGate {
    fn new(state: State, env: Env) -> Self {
        let gate = match (
            env.d1("CATALOG"),
            env.get_binding::<WorkerVersionMetadata>(VERSION_BINDING),
        ) {
            (Err(_), _) => Err("missing binding CATALOG"),
            (_, Err(_)) => Err("missing binding CF_VERSION_METADATA"),
            (Ok(db), Ok(version)) => Ok(Rc::new(Gate::new(
                D1Sql::new(db),
                DoStore(state.storage()),
                version.id(),
            ))),
        };
        PermitGate {
            state,
            gate,
            handed: core::cell::Cell::new(false),
        }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        let gate = match self.ready(None).await {
            Ok(gate) => gate,
            Err(e) => return Response::error(e, 500),
        };
        // Every job and every sweep comes this way once.
        self.reap(gate);
        let upgrade = req
            .headers()
            .get("upgrade")?
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
        let raw = match upgrade {
            true => req.headers().get(REQUEST_HEADER)?,
            false => req.text().await.ok(),
        };
        let Some(request) = raw.and_then(|raw| serde_json::from_str::<GateRequest>(&raw).ok())
        else {
            return Response::error("gate: bad request", 400);
        };
        // A class only, as everywhere.
        let refused = |e: BridgeError| Response::error(format!("gate: {e}"), 500);
        let now = WorkerClock.now();
        if !upgrade {
            let reply = gate.handle(None, request, now).await;
            self.deliver(gate).await;
            return match reply {
                Ok(reply) => match serde_json::to_string(&reply) {
                    Ok(raw) => Response::ok(raw),
                    Err(_) => Response::error("gate: reply encode failed", 500),
                },
                Err(e) => refused(e),
            };
        }
        let id = match gate.open(now).await {
            Ok(id) => id,
            Err(e) => return refused(e),
        };
        let reply = match gate.handle(Some(id), request, now).await {
            Ok(reply) => reply,
            Err(e) => {
                gate.close(id);
                gate.settle(WorkerClock.now()).await;
                self.deliver(gate).await;
                return refused(e);
            }
        };
        // The session is kept with its socket before the reply leaves:
        // a slot the caller hears of is one the object finds again.
        let accepted = (|| {
            let raw = serde_json::to_string(&reply).ok()?;
            let pair = WebSocketPair::new().ok()?;
            self.state.accept_web_socket(&pair.server);
            let kept = attach(&pair.server, &gate.session(id, WorkerClock.now()))
                && pair.server.send_with_str(&raw).is_ok();
            if !kept {
                let _ = pair
                    .server
                    .close(Some(1011), Some("gate: session not kept"));
                return None;
            }
            Response::from_websocket(pair.client).ok()
        })();
        if accepted.is_none() {
            gate.close(id);
            gate.settle(WorkerClock.now()).await;
        }
        // What this request freed for the line, or found run out.
        self.deliver(gate).await;
        match accepted {
            Some(response) => Ok(response),
            None => Response::error("gate: session not opened", 500),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> worker::Result<()> {
        let end = |code: u16, why: &str| {
            let _ = ws.close(Some(code), Some(why));
        };
        let gate = match self.ready(None).await {
            Ok(gate) => gate,
            Err(_) => {
                end(1011, "gate: not ready");
                return Ok(());
            }
        };
        let Some(session) = attached(&ws) else {
            end(1008, "gate: no session");
            return Ok(());
        };
        let request = match &message {
            WebSocketIncomingMessage::String(raw) => serde_json::from_str::<GateRequest>(raw).ok(),
            WebSocketIncomingMessage::Binary(_) => None,
        };
        let Some(request) = request else {
            gate.close(session.id);
            end(1008, "gate: bad request");
            // What the session held is free: for the line, now.
            gate.settle(WorkerClock.now()).await;
            self.deliver(gate).await;
            return Ok(());
        };
        // A request the gate could not answer is told so: the session
        // and what is held on it stand, and the caller asks again.
        let id = request.id;
        let reply = match gate
            .handle(Some(session.id), request, WorkerClock.now())
            .await
        {
            Ok(reply) => reply,
            Err(_) => GateReply::failed(id),
        };
        let sent = attach(&ws, &gate.session(session.id, WorkerClock.now()))
            && serde_json::to_string(&reply).is_ok_and(|raw| ws.send_with_str(&raw).is_ok());
        if !sent {
            gate.close(session.id);
            end(1011, "gate: session not kept");
            gate.settle(WorkerClock.now()).await;
        }
        self.deliver(gate).await;
        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> worker::Result<()> {
        self.ended(&ws).await;
        // Answers the caller's close where the runtime has not.
        let code = u16::try_from(code).ok().filter(|c| *c == 1000);
        let _ = ws.close(code.or(Some(1000)), Some("closed"));
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, _error: worker::Error) -> worker::Result<()> {
        self.ended(&ws).await;
        Ok(())
    }
}

thread_local! {
    static DETACHED_OPENS: Cell<usize> = const { Cell::new(0) };
}

struct DetachedOpen;

impl DetachedOpen {
    fn start() -> Self {
        DETACHED_OPENS.with(|n| n.set(n.get() + 1));
        Self
    }
}

impl Drop for DetachedOpen {
    fn drop(&mut self) {
        DETACHED_OPENS.with(|n| n.set(n.get() - 1));
    }
}

fn tracked_open_spawner(spawn: Spawner) -> Spawner {
    Rc::new(move |task| {
        let in_flight = DetachedOpen::start();
        spawn(Box::pin(async move {
            let _in_flight = in_flight;
            task.await;
        }));
    })
}

/// Used with the current invocation's `wait_until` once no more work can
/// start an open. The cached transport does not own a Context, and
/// `spawn_local` alone does not keep it alive.
pub fn drain_detached_opens() -> Option<impl Future<Output = ()>> {
    (DETACHED_OPENS.get() != 0).then(|| drain_detached_opens_after(std::future::ready(())))
}

/// A streamed body can start an open after the response is returned, so
/// wait for the body to finish before checking the count or starting the
/// cleanup timeout.
pub async fn drain_detached_opens_after(body_done: impl Future<Output = ()>) {
    wait_for_detached_opens(body_done, worker::Delay::from).await;
}

async fn wait_for_detached_opens<F: Future<Output = ()>>(
    body_done: impl Future<Output = ()>,
    delay: impl Fn(Duration) -> F,
) {
    body_done.await;
    let drain = async {
        while DETACHED_OPENS.get() != 0 {
            delay(Duration::from_millis(50)).await;
        }
    };
    let timeout = delay(Duration::from_secs(30));
    let _ = futures_util::future::select(std::pin::pin!(drain), std::pin::pin!(timeout)).await;
}

/// Asks the gate objects of one namespace.
pub struct DoTransport {
    namespace: ObjectNamespace,
    spawn: Spawner,
}

impl DoTransport {
    pub fn new(namespace: ObjectNamespace, spawn: Spawner) -> Self {
        DoTransport {
            namespace,
            spawn: tracked_open_spawner(spawn),
        }
    }

    fn stub(&self, gate: &str) -> Result<Stub> {
        self.namespace
            .id_from_name(gate)
            .and_then(|id| id.get_stub())
            .map_err(|_| failed("no object"))
    }

    async fn fetch(stub: Stub, req: Request) -> Result<Response> {
        stub.fetch_with_request(req)
            .await
            .map_err(|_| failed("call failed"))
    }
}

fn failed(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("gate: {what}"))
}

/// What a session's socket has delivered and not been asked for yet.
#[derive(Default)]
struct Inbox {
    replies: VecDeque<String>,
    closed: bool,
    waker: Option<Waker>,
}

impl Inbox {
    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

/// A session with one gate: the caller's end of its WebSocket. It
/// belongs to the invocation that opened it and ends with it.
pub struct DoSession {
    ws: WebSocket,
    inbox: Rc<RefCell<Inbox>>,
    on_message: Closure<dyn FnMut(web_sys::MessageEvent)>,
    on_end: Closure<dyn FnMut(JsValue)>,
    closed: Cell<bool>,
}

impl DoSession {
    /// Listens first, then accepts: what the gate sent with the
    /// opening is delivered once the socket is accepted.
    fn new(ws: WebSocket) -> Result<Self> {
        let inbox = Rc::new(RefCell::new(Inbox::default()));
        let on_message = Closure::<dyn FnMut(web_sys::MessageEvent)>::new({
            let inbox = Rc::clone(&inbox);
            move |event: web_sys::MessageEvent| {
                let mut inbox = inbox.borrow_mut();
                match event.data().as_string() {
                    Some(raw) => inbox.replies.push_back(raw),
                    None => inbox.closed = true,
                }
                inbox.wake();
            }
        });
        let on_end = Closure::<dyn FnMut(JsValue)>::new({
            let inbox = Rc::clone(&inbox);
            move |_: JsValue| {
                let mut inbox = inbox.borrow_mut();
                inbox.closed = true;
                inbox.wake();
            }
        });
        let socket: &web_sys::WebSocket = ws.as_ref();
        let listening = socket
            .add_event_listener_with_callback("message", on_message.as_ref().unchecked_ref())
            .and_then(|()| {
                socket.add_event_listener_with_callback("close", on_end.as_ref().unchecked_ref())
            })
            .and_then(|()| {
                socket.add_event_listener_with_callback("error", on_end.as_ref().unchecked_ref())
            });
        let session = DoSession {
            ws,
            inbox,
            on_message,
            on_end,
            closed: Cell::new(false),
        };
        if listening.is_err() || session.ws.accept().is_err() {
            return Err(failed("session refused"));
        }
        Ok(session)
    }

    /// The reply to request `id`. Replies to requests their caller gave
    /// up on are passed over.
    async fn reply(&self, id: u64) -> Result<GateReply> {
        core::future::poll_fn(|cx| {
            // Closed from this end: what was held on it is free, and
            // a reply that still arrives says nothing that holds.
            if self.closed.get() {
                return Poll::Ready(Err(failed("session ended")));
            }
            let mut inbox = self.inbox.borrow_mut();
            while let Some(raw) = inbox.replies.pop_front() {
                match serde_json::from_str::<GateReply>(&raw) {
                    Ok(reply) if reply.id == id => return Poll::Ready(Ok(reply)),
                    Ok(_) => {}
                    Err(_) => return Poll::Ready(Err(failed("reply unreadable"))),
                }
            }
            if inbox.closed {
                return Poll::Ready(Err(failed("session ended")));
            }
            inbox.waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

impl GateSession for DoSession {
    async fn pushed(&self, id: u64) -> Result<GateReply> {
        self.reply(id).await
    }

    async fn call(&self, request: GateRequest) -> Result<GateReply> {
        if self.closed.get() || self.inbox.borrow().closed {
            return Err(failed("session ended"));
        }
        let raw = serde_json::to_string(&request).map_err(|_| failed("request encode failed"))?;
        self.ws
            .send_with_str(&raw)
            .map_err(|_| failed("session ended"))?;
        self.reply(request.id).await
    }

    fn close(&self) {
        if !self.closed.replace(true) {
            let _ = self.ws.close(Some(1000), Some("done"));
        }
    }
}

impl Drop for DoSession {
    fn drop(&mut self) {
        // The socket may outlive this end of it (a session forgotten
        // after its invocation ended): it must not call what is gone.
        let socket: &web_sys::WebSocket = self.ws.as_ref();
        let (message, end) = (
            self.on_message.as_ref().unchecked_ref(),
            self.on_end.as_ref().unchecked_ref(),
        );
        let _ = socket.remove_event_listener_with_callback("message", message);
        let _ = socket.remove_event_listener_with_callback("close", end);
        let _ = socket.remove_event_listener_with_callback("error", end);
        // A session nobody holds any more holds no slot: the gate
        // frees what was taken on it when it closes. From another
        // invocation the close is refused, and the socket has ended
        // with the invocation that opened it.
        if !self.closed.replace(true) {
            let _ = self.ws.close(Some(1000), Some("dropped"));
        }
    }
}

impl GateTransport for DoTransport {
    type Session = DoSession;

    async fn open(&self, request: GateRequest) -> Result<(DoSession, GateReply)> {
        let header = ascii_json(&request).ok_or_else(|| failed("request encode failed"))?;
        let mut req = Request::new("https://permit-gate/session", Method::Get)
            .map_err(|_| failed("request refused"))?;
        let set = req.headers_mut().and_then(|headers| {
            headers.set("upgrade", "websocket")?;
            headers.set(REQUEST_HEADER, &header)
        });
        set.map_err(|_| failed("request refused"))?;
        let stub = self.stub(&request.gate)?;
        let session = open_detached(
            &self.spawn,
            Box::pin(async move {
                let resp = Self::fetch(stub, req).await?;
                let ws = resp.websocket().ok_or_else(|| failed("call refused"))?;
                DoSession::new(ws)
            }),
        )
        .await?;
        match session.reply(request.id).await {
            Ok(reply) => Ok((session, reply)),
            Err(e) => {
                session.close();
                Err(e)
            }
        }
    }

    async fn call(&self, request: GateRequest) -> Result<GateReply> {
        let body = serde_json::to_string(&request).map_err(|_| failed("request encode failed"))?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_body(Some(JsValue::from_str(&body)));
        let req = Request::new_with_init("https://permit-gate/", &init)
            .map_err(|_| failed("request refused"))?;
        let mut resp = Self::fetch(self.stub(&request.gate)?, req).await?;
        if resp.status_code() != 200 {
            return Err(failed("call refused"));
        }
        let raw = resp.text().await.map_err(|_| failed("reply unreadable"))?;
        serde_json::from_str(&raw).map_err(|_| failed("reply unreadable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    use crate::http::BodyDone;

    #[derive(Default)]
    struct TestClock(Cell<Duration>);

    impl TestClock {
        fn advance(&self, ms: u64) {
            self.0.set(self.0.get() + Duration::from_millis(ms));
        }

        fn delay(&self, duration: Duration) -> impl Future<Output = ()> + '_ {
            let deadline = self.0.get() + duration;
            std::future::poll_fn(move |_| {
                if self.0.get() >= deadline {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
        }
    }

    #[test]
    fn stream_drain_waits_for_body_and_an_open_started_after_headers() {
        let clock = TestClock::default();
        let done = BodyDone::default();
        let body = done.track(Box::pin(futures_util::stream::pending()));
        let mut wait = std::pin::pin!(wait_for_detached_opens(done.wait(), |d| clock.delay(d)));
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());

        assert_eq!(DETACHED_OPENS.get(), 0);
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        let opening = DetachedOpen::start();
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        drop(body);
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        drop(opening);
        clock.advance(50);
        assert!(wait.as_mut().poll(&mut cx).is_ready());
    }

    #[test]
    fn disconnect_drops_the_pending_pull_before_draining_its_open() {
        use futures_util::Stream;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::task::{Wake, Waker};

        #[derive(Default)]
        struct PullWake(AtomicBool);
        impl Wake for PullWake {
            fn wake(self: Arc<Self>) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let clock = TestClock::default();
        let done = BodyDone::default();
        let tasks = Rc::new(RefCell::new(Vec::new()));
        let queued = Rc::clone(&tasks);
        let spawn = tracked_open_spawner(Rc::new(move |task| queued.borrow_mut().push(task)));
        let closed = Rc::new(Cell::new(0));
        let session = Session(Rc::clone(&closed));
        let pull_lifetime = Rc::new(());
        let pull_guard = Rc::clone(&pull_lifetime);
        let pull = futures_util::stream::once(async move {
            let _pull_guard = pull_guard;
            let _session = open_detached(&spawn, Box::pin(async { Ok(session) })).await?;
            Ok(vec![1])
        });
        let mut body = std::pin::pin!(done.track(Box::pin(pull)));
        let mut wait =
            std::pin::pin!(wait_for_detached_opens(done.clone().wait(), |d| clock.delay(d)));
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        let pull_woke = Arc::new(PullWake::default());
        let pull_waker = Waker::from(Arc::clone(&pull_woke));
        let mut pull_cx = std::task::Context::from_waker(&pull_waker);

        assert!(wait.as_mut().poll(&mut cx).is_pending());
        assert!(body.as_mut().poll_next(&mut pull_cx).is_pending());
        assert_eq!(DETACHED_OPENS.get(), 1);
        assert_eq!(Rc::strong_count(&pull_lifetime), 2);
        assert!(!pull_woke.0.load(Ordering::Relaxed));
        done.abort();
        assert!(
            pull_woke.0.load(Ordering::Relaxed),
            "abort did not wake the pending body pull"
        );
        assert_eq!(
            Rc::strong_count(&pull_lifetime),
            1,
            "pending pull was not dropped on abort"
        );
        assert!(std::pin::pin!(done.wait())
            .as_mut()
            .poll(&mut cx)
            .is_ready());
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        assert!(matches!(
            body.as_mut().poll_next(&mut cx),
            Poll::Ready(None)
        ));
        assert_eq!(tasks.borrow().len(), 1, "no further open was started");

        let mut task = tasks.borrow_mut().pop().unwrap();
        assert!(task.as_mut().poll(&mut cx).is_ready());
        assert_eq!(closed.get(), 1);
        assert_eq!(DETACHED_OPENS.get(), 0);
        clock.advance(50);
        assert!(wait.as_mut().poll(&mut cx).is_ready());
    }

    #[test]
    fn stream_drain_times_out_thirty_seconds_after_the_body_ends() {
        let clock = TestClock::default();
        let done = BodyDone::default();
        let body = done.track(Box::pin(futures_util::stream::pending()));
        let mut wait = std::pin::pin!(wait_for_detached_opens(done.wait(), |d| clock.delay(d)));
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        let _opening = DetachedOpen::start();

        assert!(wait.as_mut().poll(&mut cx).is_pending());
        clock.advance(60_000);
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        drop(body);
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        clock.advance(29_999);
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        clock.advance(1);
        assert!(wait.as_mut().poll(&mut cx).is_ready());
        assert_eq!(DETACHED_OPENS.get(), 1);
    }

    struct Session(Rc<Cell<u32>>);

    impl GateSession for Session {
        async fn call(&self, _: GateRequest) -> Result<GateReply> {
            unreachable!("the detached receiver never used the session")
        }

        fn close(&self) {
            assert_eq!(DETACHED_OPENS.get(), 1, "still in flight during cleanup");
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn detached_opens_are_counted_through_completion_and_late_close() {
        let tasks = Rc::new(RefCell::new(Vec::new()));
        let queued = Rc::clone(&tasks);
        let spawn = tracked_open_spawner(Rc::new(move |task| queued.borrow_mut().push(task)));
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(drain_detached_opens().is_none());

        let error = open_detached::<Session>(&spawn, Box::pin(async { Err(failed("test open")) }));
        let mut error = std::pin::pin!(error);
        assert_eq!(DETACHED_OPENS.get(), 1);
        assert!(drain_detached_opens().is_some());
        let mut task = tasks.borrow_mut().pop().unwrap();
        assert!(task.as_mut().poll(&mut cx).is_ready());
        assert!(matches!(error.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
        assert!(drain_detached_opens().is_none());

        let closed = Rc::new(Cell::new(0));
        let session = Session(Rc::clone(&closed));
        let receiving = open_detached(&spawn, Box::pin(async { Ok(session) }));
        let mut receiving = std::pin::pin!(receiving);
        assert_eq!(DETACHED_OPENS.get(), 1);
        let mut task = tasks.borrow_mut().pop().unwrap();
        assert!(task.as_mut().poll(&mut cx).is_ready());
        assert!(drain_detached_opens().is_none());
        assert!(matches!(
            receiving.as_mut().poll(&mut cx),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(closed.get(), 0);

        let ready = Rc::new(Cell::new(false));
        let (finish, count) = (Rc::clone(&ready), Rc::clone(&closed));
        let receiving = open_detached(
            &spawn,
            Box::pin(std::future::poll_fn(move |_| {
                if finish.get() {
                    Poll::Ready(Ok(Session(Rc::clone(&count))))
                } else {
                    Poll::Pending
                }
            })),
        );
        assert_eq!(DETACHED_OPENS.get(), 1);
        let mut task = tasks.borrow_mut().pop().unwrap();
        assert!(task.as_mut().poll(&mut cx).is_pending());
        drop(receiving);
        assert_eq!(DETACHED_OPENS.get(), 1);
        assert_eq!(closed.get(), 0);
        ready.set(true);
        assert!(task.as_mut().poll(&mut cx).is_ready());
        assert_eq!(closed.get(), 1);
        assert!(drain_detached_opens().is_none());
    }
}
