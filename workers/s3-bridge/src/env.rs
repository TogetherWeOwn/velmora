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
use velmora_bridge::gate::{shards_from_var, GateClient, GateSharding, PermitMode};
use velmora_bridge::ingress::{ByteBudget, Sleeper};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::{Bridge, Clock, UnixMs};
use worker::Env;

use crate::catalog_sql::CatalogSql;
use crate::e2::FetchHttp;
use crate::gate::{DoTransport, GATE_BINDING};
use crate::jobs::{abandon_from_var, set_abandon, DEV_ABANDON_JOB_N};
use crate::nntp::WorkerConnector;
use crate::queues::{binding_name, bound_queues, DropNotify, QueueSink, AUX_Q, DEV_DROP_NOTIFY_N};
use crate::r2::{tombstone_delay_from_var, R2Blobs, DEV_TOMBSTONE_PUT_DELAY_MS};
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
    Bridge<SqlCatalog<CatalogSql>, R2Blobs, WorkerConnector, QueueSink, KekRing, WorkerClock>;

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
    /// The time this isolate built its bridge.
    static ISOLATE: Cell<i64> = const { Cell::new(0) };
}

/// Names the isolate in a log line: the time it built its bridge.
pub fn isolate() -> i64 {
    ISOLATE.with(Cell::get)
}

/// `d1` (default): provider permits are slot rows of the catalogue.
/// `do`: they are held in memory by the permit gate.
pub const PERMITS: &str = "PERMITS";
/// `account` (default): gates per account, and per pool of accounts
/// that share a limit. `one`: the same gates for every provider.
pub const PERMIT_GATES: &str = "PERMIT_GATES";
/// How many gates share one account or pool (default 1).
pub const PERMIT_SHARDS: &str = "PERMIT_SHARDS";

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

/// Lets a request wait for budget without reading its body, and paces the
/// keepalive of a deferred document.
pub fn sleeper() -> Sleeper {
    Rc::new(|ms| Box::pin(worker::Delay::from(Duration::from_millis(u64::from(ms)))))
}

/// Builds the bridge or returns a class-only reason.
fn build(env: &Env) -> Result<WorkerBridge, String> {
    let get = |name: &str| lookup(env, name);
    let cfg = BridgeConfig::from_vars(get).map_err(|e| e.to_string())?;
    let kek = KekRing::from_vars(cfg.kek_active, get).map_err(|e| e.to_string())?;
    let drop_notify = DropNotify::from_var(cfg.is_dev(), get(DEV_DROP_NOTIFY_N).as_deref())?;
    let tombstone_delay =
        tombstone_delay_from_var(cfg.is_dev(), get(DEV_TOMBSTONE_PUT_DELAY_MS).as_deref())?;
    let abandon = abandon_from_var(cfg.is_dev(), get(DEV_ABANDON_JOB_N).as_deref())?;
    let built_at = WorkerClock.now().0;
    if memory_log_from_var(cfg.is_dev(), get(DEV_MEMORY_LOG).as_deref())? {
        MEMORY_LOG.with(|c| c.set(Some(built_at)));
    }
    ISOLATE.with(|c| c.set(built_at));
    set_abandon(abandon);
    let binding = |name: &'static str| move |_| format!("missing binding {name}");
    let catalog = CatalogSql::from_env(env)?;
    // `PERMITS`: where provider permits come from. With the gate bound,
    // a Worker on `d1` still tells a gate that holds slot rows to let
    // go, so the switch can be turned back.
    let permits = PermitMode::from_var(get(PERMITS).as_deref())?;
    let sharding = GateSharding::from_var(get(PERMIT_GATES).as_deref())?;
    let shards = shards_from_var(get(PERMIT_SHARDS).as_deref())?;
    let mut catalog = match env.durable_object(GATE_BINDING) {
        Ok(namespace) => SqlCatalog::with_gate(
            catalog,
            GateClient::new(
                DoTransport::new(namespace),
                || WorkerClock.now(),
                permits,
                sharding,
                shards,
                &cfg.providers,
            )
            .into_gate(),
        ),
        Err(_) if permits == PermitMode::Gate => {
            return Err(format!("missing binding {GATE_BINDING}"))
        }
        Err(_) => SqlCatalog::new(catalog),
    };
    match get("BUCKET_CORS").as_deref().map(str::trim) {
        None | Some("") | Some("off") => {}
        Some("on") => catalog.enable_bucket_cors().map_err(|e| e.to_string())?,
        Some(_) => return Err("invalid BUCKET_CORS".into()),
    }
    Ok(Bridge {
        catalog,
        safety: R2Blobs::new(env.bucket("SAFETY").map_err(binding("SAFETY"))?)
            .with_tombstone_delay(tombstone_delay),
        cache: R2Blobs::new(env.bucket("CACHE").map_err(binding("CACHE"))?),
        nntp: WorkerConnector::new(),
        jobs: QueueSink::new(
            queues(env, "POST_Q")?,
            queues(env, "VERIFY_Q")?,
            aux_queue(env)?,
            drop_notify,
        )
        .map_err(|name| format!("missing binding {name}"))?,
        kek,
        clock: WorkerClock,
        budget: ByteBudget::new(cfg.inflight_budget_bytes)
            .with_job_capacity(cfg.job_budget_bytes)
            .with_sleeper(sleeper())
            .with_spawner(Rc::new(worker::wasm_bindgen_futures::spawn_local)),
        cfg,
    })
}

/// The recovery store, when `RECOVERY_COPY` is on. A refused
/// configuration is a class-only reason; it never stops the S3 service,
/// only the copy.
pub fn recovery_store(env: &Env) -> Result<Option<S3Remote<FetchHttp>>, String> {
    let cfg = RemoteConfig::from_vars(|name| lookup(env, name)).map_err(|e| e.to_string())?;
    Ok(cfg.map(|cfg| S3Remote::new(cfg, FetchHttp::default())))
}

/// True when `RECOVERY_COPY` is `on`, whatever the rest of its
/// configuration is ([`recovery_store`] checks that).
pub fn recovery_copy_on(env: &Env) -> bool {
    lookup(env, "RECOVERY_COPY").is_some_and(|v| v.trim() == "on")
}

/// The queues of one kind that are bound: `first` (`POST_Q`), then
/// `POST_Q2`, `POST_Q3`, ... A missing first binding or a gap in the
/// numbers is refused ([`bound_queues`]).
/// The queue of the jobs without an extent: `None` when `AUX_Q` is not
/// bound. A binding of that name that is not a queue is refused, since
/// the jobs would otherwise go to the first verify queue unnoticed.
fn aux_queue(env: &Env) -> Result<Option<worker::Queue>, String> {
    let bound = worker::js_sys::Reflect::get(env, &worker::wasm_bindgen::JsValue::from_str(AUX_Q))
        .is_ok_and(|v| !v.is_undefined() && !v.is_null());
    match env.queue(AUX_Q) {
        Ok(queue) => Ok(Some(queue)),
        Err(_) if !bound => Ok(None),
        Err(_) => Err(format!("binding {AUX_Q} is not a queue")),
    }
}

fn queues(env: &Env, first: &str) -> Result<Vec<worker::Queue>, String> {
    let count = bound_queues(first, |name| env.queue(name).is_ok())?;
    (0..count)
        .map(|index| {
            let name = binding_name(first, index);
            env.queue(&name)
                .map_err(|_| format!("missing binding {name}"))
        })
        .collect()
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

    #[test]
    fn tombstone_delay_is_dev_only_and_refuses_garbage() {
        for raw in [None, Some(""), Some(" ")] {
            assert_eq!(tombstone_delay_from_var(true, raw), Ok(0));
        }
        assert_eq!(tombstone_delay_from_var(true, Some("1500")), Ok(1500));
        assert_eq!(tombstone_delay_from_var(true, Some("60000")), Ok(60_000));
        for raw in ["60001", "-1", "1.5", "slow"] {
            let err = tombstone_delay_from_var(true, Some(raw)).unwrap_err();
            assert_eq!(err, "invalid DEV_TOMBSTONE_PUT_DELAY_MS");
        }
        // Outside dev the value is never read.
        for raw in [None, Some("1500"), Some("garbage")] {
            assert_eq!(tombstone_delay_from_var(false, raw), Ok(0));
        }
    }
}
