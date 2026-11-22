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
//!
//! **Off as shipped:** the request path builds a root only with `UNIT`
//! bound (`units::route_request`), which no production configuration
//! does. The management entry (`mgmt.rs`) builds one for every request
//! (no store read: `Root::new` only prunes the isolate's caches); its
//! handlers, which run only after the token gate, are the readers of
//! `SAFETY` and the directory's feed. It has no binding in production.

use std::rc::Rc;

use velmora_bridge::config::KekRing;
use velmora_bridge::keys::tk::KeyBuckets;
use velmora_bridge::root::{RootCache, RootPorts};
use worker::Env;

use crate::d1::D1Sql;
use crate::env::WorkerClock;
use crate::records::R2Records;

/// The key buckets, by binding name (`keys::locations::two_in_account`).
const KEY_BUCKETS: [&str; 2] = ["KEYS_A", "KEYS_B"];

/// The root's ports in a Worker.
pub struct WorkerPorts<'a> {
    records: R2Records,
    keys: Vec<(&'static str, R2Records)>,
    kek: &'a KekRing,
    directory: Option<D1Sql>,
    clock: WorkerClock,
}

impl<'a> WorkerPorts<'a> {
    /// The ports from `env`, with the bridge's KEK ring. Only `SAFETY` is
    /// required; the reason names the binding, nothing else.
    pub fn from_env(env: &Env, kek: &'a KekRing) -> Result<WorkerPorts<'a>, String> {
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
            kek,
            directory,
            clock: WorkerClock,
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

thread_local! {
    /// What this isolate keeps between invocations: tenant keys (each for
    /// at most the loader's time), tenant heads, key locations.
    static CACHE: Rc<RootCache> = Rc::default();
}

/// The isolate's root cache.
pub fn cache() -> Rc<RootCache> {
    CACHE.with(Rc::clone)
}
