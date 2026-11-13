//! Bindings and secrets -> validated `Bridge`, built once per isolate.
//!
//! Values are read inside the process and never logged; a refusal names a
//! variable, binding or rule only. A refused configuration is not cached,
//! so every request fails closed with a class-only `500` until it is fixed.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use velmora_bridge::config::{BridgeConfig, KekRing};
use velmora_bridge::ingress::{ByteBudget, Sleeper};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::{Bridge, Clock, UnixMs};
use worker::Env;

use crate::d1::D1Sql;
use crate::nntp::WorkerConnector;
use crate::queues::{DropNotify, QueueSink, DEV_DROP_NOTIFY_N};
use crate::r2::R2Blobs;

/// Wall clock of the Workers runtime (advances on I/O only).
pub struct WorkerClock;

impl Clock for WorkerClock {
    fn now(&self) -> UnixMs {
        // Milliseconds since the epoch fit an i64 for the next 290 My.
        UnixMs(worker::Date::now().as_millis() as i64)
    }
}

pub type WorkerBridge =
    Bridge<SqlCatalog<D1Sql>, R2Blobs, WorkerConnector, QueueSink, KekRing, WorkerClock>;

/// Var or secret by name; `None` when absent.
fn lookup(env: &Env, name: &str) -> Option<String> {
    env.var(name)
        .map(|v| v.to_string())
        .or_else(|_| env.secret(name).map(|s| s.to_string()))
        .ok()
}

thread_local! {
    static BRIDGE: RefCell<Option<Rc<WorkerBridge>>> = const { RefCell::new(None) };
}

/// The isolate's bridge, built on first use. Construction is synchronous,
/// so two requests can never race to build it.
pub fn bridge(env: &Env) -> Result<Rc<WorkerBridge>, String> {
    if let Some(b) = BRIDGE.with(|c| c.borrow().clone()) {
        return Ok(b);
    }
    let b = Rc::new(build(env)?);
    BRIDGE.with(|c| *c.borrow_mut() = Some(Rc::clone(&b)));
    Ok(b)
}

/// Lets a request wait for budget without reading its body.
fn sleeper() -> Sleeper {
    Rc::new(|ms| Box::pin(worker::Delay::from(Duration::from_millis(u64::from(ms)))))
}

/// Builds the bridge or returns a class-only reason.
fn build(env: &Env) -> Result<WorkerBridge, String> {
    let get = |name: &str| lookup(env, name);
    let cfg = BridgeConfig::from_vars(get).map_err(|e| e.to_string())?;
    let kek = KekRing::from_vars(cfg.kek_active, get).map_err(|e| e.to_string())?;
    let drop_notify = DropNotify::from_var(cfg.is_dev(), get(DEV_DROP_NOTIFY_N).as_deref())?;
    let binding = |name: &'static str| move |_| format!("missing binding {name}");
    Ok(Bridge {
        catalog: SqlCatalog::new(D1Sql::new(env.d1("CATALOG").map_err(binding("CATALOG"))?)),
        safety: R2Blobs::new(env.bucket("SAFETY").map_err(binding("SAFETY"))?),
        cache: R2Blobs::new(env.bucket("CACHE").map_err(binding("CACHE"))?),
        nntp: WorkerConnector::new(),
        jobs: QueueSink::new(
            env.queue("POST_Q").map_err(binding("POST_Q"))?,
            env.queue("VERIFY_Q").map_err(binding("VERIFY_Q"))?,
            drop_notify,
        ),
        kek,
        clock: WorkerClock,
        budget: ByteBudget::new(cfg.inflight_budget_bytes).with_sleeper(sleeper()),
        cfg,
    })
}
