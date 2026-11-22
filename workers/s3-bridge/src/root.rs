//! The Worker's ports of the composition root (`velmora_bridge::root`),
//! from its bindings (lane L6, package L6-5).
//!
//! - `SAFETY`: the records under `m/` (tenant chains, key chains, routes,
//!   revocations, key locations), put once (`records::R2Records`).
//! - `KEYS_A`, `KEYS_B`: the key buckets, by the binding names the key
//!   locations name. An unbound one is left out, and a load from it
//!   fails as an unbound location.
//! - `DIRECTORY`: the directory database; unbound, the key routes read
//!   the route records only.
//! - the KEK ring of the isolate's bridge, and the Worker's clock.
//! - for the unit clients (`velmora_bridge::root::UnitPorts`, L6-5b):
//!   `UNIT`, the unit objects; the bridge's `SAFETY` blob store (the
//!   lease proof's reads and the stamp objects); the bridge's queue sink,
//!   which sends the key chain's `apply_control` intents.
//!
//! **Off as shipped:** the Worker builds a root only with `UNIT` bound
//! (`units::route_request`, the unit consumer), which no production
//! configuration does.

use std::rc::Rc;

use velmora_bridge::config::KekRing;
use velmora_bridge::keys::tk::KeyBuckets;
use velmora_bridge::root::{RootCache, RootPorts, UnitPorts};
use velmora_bridge::unit::UnitName;
use velmora_bridge::{BridgeError, Result};
use worker::{Env, ObjectNamespace};

use crate::d1::D1Sql;
use crate::env::{WorkerBridge, WorkerClock};
use crate::queues::QueueSink;
use crate::r2::R2Blobs;
use crate::records::R2Records;
use crate::units::{UnitStub, UNIT_BINDING};

/// The key buckets, by binding name (`keys::locations::two_in_account`).
const KEY_BUCKETS: [&str; 2] = ["KEYS_A", "KEYS_B"];

/// The root's ports in a Worker.
pub struct WorkerPorts<'a> {
    records: R2Records,
    keys: Vec<(&'static str, R2Records)>,
    kek: &'a KekRing,
    directory: Option<D1Sql>,
    clock: WorkerClock,
    units: Option<ObjectNamespace>,
    safety: &'a R2Blobs,
    control: &'a QueueSink,
}

impl<'a> WorkerPorts<'a> {
    /// The ports from `env`, with the bridge's KEK ring, `SAFETY` blob
    /// store and queue sink. Only `SAFETY` is required; the reason names
    /// the binding, nothing else.
    pub fn from_env(
        env: &Env,
        bridge: &'a WorkerBridge,
    ) -> std::result::Result<WorkerPorts<'a>, String> {
        let records = R2Records::new(
            env.bucket("SAFETY")
                .map_err(|_| "missing binding SAFETY".to_string())?,
        );
        let keys = KEY_BUCKETS
            .iter()
            .filter_map(|name| env.bucket(name).ok().map(|b| (*name, R2Records::new(b))))
            .collect();
        let directory = env.d1("DIRECTORY").ok().map(D1Sql::new);
        Ok(WorkerPorts {
            records,
            keys,
            kek: &bridge.kek,
            directory,
            clock: WorkerClock,
            units: env.durable_object(UNIT_BINDING).ok(),
            safety: &bridge.safety,
            control: &bridge.jobs,
        })
    }
}

impl RootPorts for WorkerPorts<'_> {
    type Records = R2Records;
    type KeyStore = R2Records;
    type Kek = KekRing;
    type Sql = D1Sql;
    type Clock = WorkerClock;

    fn records(&self) -> &R2Records {
        &self.records
    }

    fn key_buckets(&self) -> KeyBuckets<'_, R2Records> {
        KeyBuckets {
            by_name: self
                .keys
                .iter()
                .map(|(name, store)| (*name, store))
                .collect(),
        }
    }

    fn kek(&self) -> &KekRing {
        self.kek
    }

    fn directory(&self) -> Option<&D1Sql> {
        self.directory.as_ref()
    }

    fn clock(&self) -> &WorkerClock {
        &self.clock
    }
}

impl UnitPorts for WorkerPorts<'_> {
    type Object = UnitStub;
    type Safety = R2Blobs;
    type Control = QueueSink;

    fn object(&self, name: &UnitName) -> Result<UnitStub> {
        let namespace = self
            .units
            .as_ref()
            .ok_or(BridgeError::NotImplemented("no unit binding"))?;
        UnitStub::new(namespace, name)
    }

    fn safety(&self) -> &R2Blobs {
        self.safety
    }

    fn control(&self) -> &QueueSink {
        self.control
    }
}

thread_local! {
    /// What this isolate keeps between invocations: tenant keys (each for
    /// at most the loader's time), tenant heads, key locations, key
    /// routes, and the unit clients' renewal state (AM-71).
    static CACHE: Rc<RootCache> = Rc::default();
}

/// The isolate's root cache.
pub fn cache() -> Rc<RootCache> {
    CACHE.with(Rc::clone)
}
