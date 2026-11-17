//! The permit gate as a Durable Object, and the Worker's way to ask it.
//!
//! All rules are in `velmora_bridge::gate`. Here: one object per gate
//! name, asked with a JSON `POST` over the object's fetch interface (a
//! Rust object class cannot export RPC methods), its one stored record,
//! and the timer that keeps the object in memory while a permit is
//! live. Without the timer an object that serves plain requests leaves
//! memory seconds after the last one, and every pause between two
//! renewals would be a restart.
//!
//! Nothing here logs a provider's host or credentials: they never reach
//! the object. A log line carries the gate's state as numbers only.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use velmora_bridge::gate::{Gate, GateRecord, GateReply, GateRequest, GateStore, GateTransport};
use velmora_bridge::{BridgeError, Clock, Result};
use worker::wasm_bindgen::{self, JsValue};
use worker::{
    console_log, durable_object, DurableObject, Env, Method, ObjectNamespace, Request, RequestInit,
    Response, State, Storage,
};

use crate::d1::D1Sql;
use crate::env::WorkerClock;

/// Name of the Durable Object namespace binding.
pub const GATE_BINDING: &str = "PERMIT_GATE";

/// Key of the one value a gate stores.
const RECORD_KEY: &str = "record";

/// The longest the timer sleeps between two looks at the gate.
const TICK_MAX_MS: i64 = 5_000;
const TICK_MIN_MS: i64 = 250;
/// A timer silent for this long is taken to be gone.
const TICK_LOST_MS: i64 = 60_000;

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

#[durable_object]
pub struct PermitGate {
    state: State,
    /// `None`: the catalogue binding is missing; every request fails.
    gate: Option<Rc<Gate<D1Sql, DoStore>>>,
    /// The timer: which one runs, and when it last looked at the gate.
    /// One that has not looked for [`TICK_LOST_MS`] was cancelled by
    /// the runtime, and the next request starts another.
    ticking: Rc<Cell<(u64, i64)>>,
}

impl PermitGate {
    /// Starts the timer unless it runs: it sleeps, lets the gate do its
    /// housekeeping, and ends once the gate has nothing live and
    /// nothing stored, so that the object can leave memory.
    fn keep_awake(&self, gate: &Rc<Gate<D1Sql, DoStore>>) {
        let now = WorkerClock.now().0;
        let (run, beat) = self.ticking.get();
        let running = beat != 0 && (now - beat).abs() < TICK_LOST_MS;
        if running || gate.next_wake(WorkerClock.now()).is_none() {
            return;
        }
        let run = run.wrapping_add(1);
        self.ticking.set((run, now));
        let (gate, ticking) = (Rc::clone(gate), Rc::clone(&self.ticking));
        self.state.wait_until(async move {
            while let Some(wake) = gate.next_wake(WorkerClock.now()) {
                let ms = (wake.0 - WorkerClock.now().0).clamp(TICK_MIN_MS, TICK_MAX_MS);
                worker::Delay::from(Duration::from_millis(ms as u64)).await;
                // Another was started in its place: one is enough.
                if ticking.get().0 != run {
                    return;
                }
                ticking.set((run, WorkerClock.now().0));
                gate.tick(WorkerClock.now()).await;
            }
            if ticking.get().0 == run {
                ticking.set((run, 0));
            }
        });
    }
}

impl DurableObject for PermitGate {
    fn new(state: State, env: Env) -> Self {
        let gate = env
            .d1("CATALOG")
            .ok()
            .map(|db| Rc::new(Gate::new(D1Sql::new(db), DoStore(state.storage()))));
        PermitGate {
            state,
            gate,
            ticking: Rc::new(Cell::new((0, 0))),
        }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        let Some(gate) = &self.gate else {
            return Response::error("gate: missing binding CATALOG", 500);
        };
        // Parsed from the text, here and in the caller: a permit's token
        // is a 64-bit number, and a JavaScript number does not hold one.
        let request = match req.text().await {
            Ok(raw) => serde_json::from_str::<GateRequest>(&raw).ok(),
            Err(_) => None,
        };
        let Some(request) = request else {
            return Response::error("gate: bad request", 400);
        };
        let fresh = gate.record().is_none();
        let answered = gate.handle(request, WorkerClock.now()).await;
        if fresh {
            // Once per start: how often the object loses its memory.
            if let Some(record) = gate.record() {
                console_log!(
                    "permit gate started: jobs_until={} reads_until={} seized={}",
                    record.jobs_until,
                    record.reads_until,
                    record.seized.len()
                );
            }
        }
        self.keep_awake(gate);
        match answered {
            Ok(reply) => match serde_json::to_string(&reply) {
                Ok(raw) => Response::ok(raw),
                Err(_) => Response::error("gate: reply encode failed", 500),
            },
            // A class only, as everywhere.
            Err(e) => Response::error(format!("gate: {e}"), 500),
        }
    }
}

/// Asks the gate objects of one namespace.
pub struct DoTransport {
    namespace: ObjectNamespace,
}

impl DoTransport {
    pub fn new(namespace: ObjectNamespace) -> Self {
        DoTransport { namespace }
    }
}

impl GateTransport for DoTransport {
    async fn call(&self, request: GateRequest) -> Result<GateReply> {
        let failed = |what: &'static str| BridgeError::Sql(format!("gate: {what}"));
        let body = serde_json::to_string(&request).map_err(|_| failed("request encode failed"))?;
        let stub = self
            .namespace
            .id_from_name(&request.gate)
            .and_then(|id| id.get_stub())
            .map_err(|_| failed("no object"))?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_body(Some(JsValue::from_str(&body)));
        let req = Request::new_with_init("https://permit-gate/", &init)
            .map_err(|_| failed("request refused"))?;
        let mut resp = stub
            .fetch_with_request(req)
            .await
            .map_err(|_| failed("call failed"))?;
        if resp.status_code() != 200 {
            return Err(failed("call refused"));
        }
        let raw = resp.text().await.map_err(|_| failed("reply unreadable"))?;
        serde_json::from_str(&raw).map_err(|_| failed("reply unreadable"))
    }
}
