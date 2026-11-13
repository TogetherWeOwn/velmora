//! Bindings and secrets -> validated `Bridge` (integration lane).
//!
//! Walking skeleton: builds the full `Bridge` per call. Values are read
//! inside the process and never logged; errors name a variable or rule.

use velmora_bridge::config::{BridgeConfig, KekRing};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::{Bridge, Clock, UnixMs};
use worker::Env;

use crate::d1::D1Sql;
use crate::nntp::WorkerConnector;
use crate::queues::QueueSink;
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

/// Builds the bridge or returns a class-only reason.
pub fn build(env: &Env) -> Result<WorkerBridge, String> {
    let get = |name: &str| lookup(env, name);
    let cfg = BridgeConfig::from_vars(get).map_err(|e| e.to_string())?;
    let kek = KekRing::from_vars(cfg.kek_active, get).map_err(|e| e.to_string())?;
    let binding = |name: &'static str| move |_| format!("missing binding {name}");
    Ok(Bridge {
        catalog: SqlCatalog::new(D1Sql::new(env.d1("CATALOG").map_err(binding("CATALOG"))?)),
        safety: R2Blobs::new(env.bucket("SAFETY").map_err(binding("SAFETY"))?),
        cache: R2Blobs::new(env.bucket("CACHE").map_err(binding("CACHE"))?),
        nntp: WorkerConnector::new(),
        jobs: QueueSink::new(
            env.queue("POST_Q").map_err(binding("POST_Q"))?,
            env.queue("VERIFY_Q").map_err(binding("VERIFY_Q"))?,
        ),
        kek,
        clock: WorkerClock,
        budget: ByteBudget::new(cfg.inflight_budget_bytes),
        cfg,
    })
}
