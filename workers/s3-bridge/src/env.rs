//! Bindings and secrets -> validated `Bridge`, built once per isolate.
//!
//! Values are read inside the process and never logged; a refusal names a
//! variable, binding or rule only. A refused configuration is not cached,
//! so every request fails closed with a class-only `500` until it is fixed.
//!
//! Dev only: `DEV_MEMORY_LOG=on` adds a line after every request with the
//! size of the isolate's wasm memory and its byte budget (see
//! [`memory_line`]). It is how the memory bound of concurrent uploads is
//! measured on a test deployment.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use velmora_bridge::config::{BridgeConfig, KekRing};
use velmora_bridge::ingress::{ByteBudget, Sleeper};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::{Bridge, Clock, UnixMs};
use worker::Env;

use crate::d1::D1Sql;
use crate::e2::FetchHttp;
use crate::nntp::WorkerConnector;
use crate::queues::{DropNotify, QueueSink, DEV_DROP_NOTIFY_N};
use crate::r2::R2Blobs;
use velmora_bridge::remote::{RemoteConfig, S3Remote};

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
    /// When the memory log is on: the time this isolate built its bridge,
    /// which names the isolate in the log.
    static MEMORY_LOG: Cell<Option<i64>> = const { Cell::new(None) };
}

/// Name of the dev-only memory log variable.
pub const DEV_MEMORY_LOG: &str = "DEV_MEMORY_LOG";

/// `dev` is the validated environment. Outside dev the value is never
/// read (always off). In dev, absent, empty or `off` is off, `on` is on
/// and anything else is refused.
fn memory_log_from_var(dev: bool, raw: Option<&str>) -> Result<bool, String> {
    if !dev {
        return Ok(false);
    }
    match raw.map(str::trim) {
        None | Some("" | "off") => Ok(false),
        Some("on") => Ok(true),
        Some(_) => Err(format!("invalid {DEV_MEMORY_LOG}")),
    }
}

/// Size of the wasm linear memory. It only grows, so the value an
/// isolate logs last is the most that isolate has held.
#[cfg(target_arch = "wasm32")]
fn wasm_memory_bytes() -> u64 {
    const PAGE_BYTES: u64 = 65_536;
    core::arch::wasm32::memory_size(0) as u64 * PAGE_BYTES
}

#[cfg(not(target_arch = "wasm32"))]
fn wasm_memory_bytes() -> u64 {
    0
}

/// Dev only (`DEV_MEMORY_LOG=on`): one line after a request with the
/// isolate, the size of its wasm memory and its byte budget. Sizes and
/// a start time only.
pub fn memory_line(bridge: &WorkerBridge) -> Option<String> {
    let isolate = MEMORY_LOG.with(Cell::get)?;
    Some(format!(
        "memory: isolate={isolate} wasm_bytes={} budget_in_use={} budget_peak={}",
        wasm_memory_bytes(),
        bridge.budget.in_use(),
        bridge.budget.peak(),
    ))
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
    if memory_log_from_var(cfg.is_dev(), get(DEV_MEMORY_LOG).as_deref())? {
        MEMORY_LOG.with(|c| c.set(Some(WorkerClock.now().0)));
    }
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

/// The recovery store, when `RECOVERY_COPY` is on. A refused
/// configuration is a class-only reason; it never stops the S3 service,
/// only the copy.
pub fn recovery_store(env: &Env) -> Result<Option<S3Remote<FetchHttp>>, String> {
    let cfg = RemoteConfig::from_vars(|name| lookup(env, name)).map_err(|e| e.to_string())?;
    Ok(cfg.map(|cfg| S3Remote::new(cfg, FetchHttp)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_log_is_dev_only_and_refuses_garbage() {
        for raw in [None, Some(""), Some("off"), Some(" off ")] {
            assert_eq!(memory_log_from_var(true, raw), Ok(false));
        }
        assert_eq!(memory_log_from_var(true, Some("on")), Ok(true));
        for raw in ["1", "true", "ON"] {
            let err = memory_log_from_var(true, Some(raw)).unwrap_err();
            assert_eq!(err, "invalid DEV_MEMORY_LOG");
        }
        // Outside dev the value is never read.
        for raw in [None, Some("on"), Some("garbage")] {
            assert_eq!(memory_log_from_var(false, raw), Ok(false));
        }
    }
}
