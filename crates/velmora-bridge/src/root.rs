//! The composition root of the tenancy plane (lane L6, package L6-5): the
//! one place that puts the record store, the seal, the key loader, the
//! directory and the router together, so that the Worker and the
//! management adapters (`TenantDoor`, `RootUnit`, `PrincipalChain`) call
//! one surface.
//!
//! The logic is here, generic over [`RootPorts`], so that it runs in
//! native tests; the Worker gives the concrete ports (`workers/s3-bridge`,
//! `root.rs`), built from its `Env` once per invocation. [`RootCache`]
//! is what an isolate keeps between invocations: the tenant keys it
//! loaded (each for at most `keys::tk::TK_CACHE_MS`), the tenant heads
//! the router read (`unit_router::HEAD_MAX_AGE_MS`), the key locations
//! (the same 60 s), and the key routes to managed tenants that were read
//! (no time limit: a route never changes; at most [`ROUTE_CACHE_KEYS`]).
//! Every [`Root::new`] drops the expired keys, so an isolate that loads
//! none for a while holds none past its time.
//!
//! **Off as shipped.** Nothing in a production Worker builds a [`Root`]:
//! the Worker makes one only when `UNIT` is bound, and no production
//! configuration binds it.
//!
//! # What it gives
//!
//! - [`Root::heads`]: tenant heads, door parts only ([`DoorSeal`]): the
//!   router's and the unit client's `TenantHeads`. No tenant key is
//!   loaded for them.
//! - [`Root::tenant_head`]: the verified head with its private part. A
//!   key version the isolate does not hold is loaded once, pinned to the
//!   check value the head commits for it, and the head is read again.
//! - [`Root::chain`]: the tenant chain over the real seal, for writers.
//!   A writer loads the version it seals under first ([`Root::load_key`]).
//! - [`Root::tenant_keys`]: the tenant's loaded key ring, for the key
//!   chain (L4's reader and writer).
//! - [`Root::key_routes`]: an access key id to its tenant
//!   ([`unit_router::KeyRoutes`]): the directory's `key_routes` row, and
//!   on a failed directory read the route record `m/kr/<akid>`; with the
//!   failed-read answer that ADR §8.4 (DUR-10) needs
//!   ([`KeyTenant::Unrouted`]).
//! - [`Root::records`], [`Root::kek`], [`Root::directory`]: the parts, for
//!   the adapters that need them directly.
//!
//! - [`Root::unit_client`] (with [`UnitPorts`]): L2's unit client of one
//!   unit over the isolate's renewal state, with the root's key feed
//!   ([`feed::RootKeyFeed`]) and finisher ([`client::RootFinisher`]);
//!   [`Root::clients`] and [`Root::router`] for the request router and the
//!   management plane (AM-71, package L6-5b).
//!
//! Every error is a fixed string or the chain's own class: no key byte,
//! record byte or name of another tenant reaches one.

pub mod client;
mod control;
pub mod feed;
pub mod request;

pub use client::{
    ControlSend, RootClients, RootFinisher, RootHeads, RootRouter, RootUnitClient, Shared,
    UnitPorts,
};
pub use feed::{unit_item, RootKeyFeed};

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use velmora::rng::FillRandom;

use crate::crypto::scheme2::{TenantKey, KCV_LEN};
use crate::directory::chain::{ChainError, ReadRecord, TenantChain};
use crate::directory::record::{Lifecycle, Tenant, TenantDoor};
use crate::directory::seal::{committed_check, ChainSeal, DoorSeal, SealKeys};
use crate::directory::store::SqlDirectory;
use crate::keys::locations::{read_locations, KeyLocations};
use crate::keys::routes::read_route;
use crate::keys::tk::{is_foreign, KeyBuckets, LoadedRing, TkCache, ERR_TK_MISSING};
use crate::ports::{Clock, Kek, Sql};
use crate::records::RecordStore;
use crate::types::{BridgeError, Result, UnixMs};
use crate::unit::Seqs;
use crate::unit_lease::client::{InFlight, Sleep};
use crate::unit_router::{HeadCache, KeyRoutes, KeyTenant, HEAD_MAX_AGE_MS};
use crate::TenantId;

const ERR_NO_LOCATIONS: BridgeError = BridgeError::Crypto("no key locations recorded");
const ERR_NO_CHECK: BridgeError =
    BridgeError::Crypto("head names no committed check value for its key version");
const ERR_ROUTE_TENANT: BridgeError = BridgeError::Crypto("key route names no tenant id");
const ERR_NO_TENANT: BridgeError = BridgeError::Invalid("tenant has no chain");

/// At most this many key routes are kept per isolate; past it the cache
/// is emptied (a route is read again on its next use).
pub const ROUTE_CACHE_KEYS: usize = 4096;

/// No numbers known: the unit's own answer is the first call's floor.
const NO_SEQS: Seqs = Seqs {
    state_seq: 0,
    keys_seq: 0,
};

/// What the root is built from: the Worker's bindings, or test doubles.
pub trait RootPorts {
    /// The safety bucket's records (`m/`): tenant chains, key chains,
    /// routes, revocations, key locations.
    type Records: RecordStore;
    /// The key buckets (`KEYS_A`, `KEYS_B`).
    type KeyStore: RecordStore;
    type Kek: Kek;
    /// The directory database.
    type Sql: Sql;
    type Clock: Clock;
    fn records(&self) -> &Self::Records;
    fn key_buckets(&self) -> KeyBuckets<'_, Self::KeyStore>;
    fn kek(&self) -> &Self::Kek;
    /// `None` when the directory database is not bound.
    fn directory(&self) -> Option<&Self::Sql>;
    fn clock(&self) -> &Self::Clock;
}

/// What an isolate keeps between invocations.
#[derive(Default)]
pub struct RootCache {
    /// Unwrapped tenant keys, as the loader caches them.
    pub tks: TkCache,
    /// The keys the seal may use (each for at most the loader's time).
    pub seal_keys: SealKeys,
    /// The router's tenant heads.
    pub heads: HeadCache,
    locations: RefCell<Option<(KeyLocations, UnixMs)>>,
    /// Key routes to managed tenants, with the floor the first read gave
    /// (ADR §8.4 step 2: a route never changes, so it is kept with no time
    /// limit; the move and its undo replace every isolate by a deploy).
    /// Only routes that were read are kept: never "no route", whose key
    /// may get one later, and never a failed read.
    routes: RefCell<HashMap<String, (crate::unit::TenantId, Seqs)>>,
    /// The unit clients' renewal state (rule 11's spacing and backoff, the
    /// renewals in flight), by unit, bounded at 4,096 units (AM-71).
    pub flights: InFlight,
}

impl RootCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Use the isolate's request-local timer for shared renewals and syncs.
    pub fn with_sleep(sleep: Sleep) -> Self {
        Self {
            flights: InFlight::with_sleep(sleep),
            ..Self::default()
        }
    }
}

/// The composition root of one invocation.
pub struct Root<'a, P: RootPorts, R> {
    ports: &'a P,
    cache: &'a RootCache,
    doors: DoorSeal<'a, P::Kek>,
    seal: ChainSeal<'a, P::Kek, R, P::Clock>,
}

impl<'a, P: RootPorts, R: FillRandom> Root<'a, P, R> {
    /// `rng` is the system CSPRNG in the Worker.
    pub fn new(ports: &'a P, cache: &'a RootCache, rng: R) -> Self {
        // No unwrapped key outlives its time in the isolate, also when
        // this invocation loads none.
        let now = ports.clock().now();
        cache.tks.prune(now);
        cache.seal_keys.prune(now);
        Root {
            ports,
            cache,
            doors: DoorSeal::new(ports.kek()),
            seal: ChainSeal::new(ports.kek(), &cache.seal_keys, ports.clock(), rng),
        }
    }

    pub fn records(&self) -> &'a P::Records {
        self.ports.records()
    }

    pub fn kek(&self) -> &'a P::Kek {
        self.ports.kek()
    }

    pub fn clock(&self) -> &'a P::Clock {
        self.ports.clock()
    }

    /// The directory, when it is bound.
    pub fn directory(&self) -> Option<SqlDirectory<'a, P::Sql>> {
        self.ports.directory().map(|sql| SqlDirectory { sql })
    }

    /// The router's tenant head cache.
    pub fn head_cache(&self) -> &'a HeadCache {
        &self.cache.heads
    }

    /// The real seal (for writers that seal records themselves).
    pub fn seal(&self) -> &ChainSeal<'a, P::Kek, R, P::Clock> {
        &self.seal
    }

    /// Tenant heads, door parts only: no tenant key, no private part, no
    /// write.
    pub fn heads(&self) -> TenantChain<'_, P::Records, DoorSeal<'a, P::Kek>> {
        TenantChain {
            store: self.ports.records(),
            seal: &self.doors,
        }
    }

    /// The tenant chain over the real seal.
    pub fn chain(&self) -> TenantChain<'_, P::Records, ChainSeal<'a, P::Kek, R, P::Clock>> {
        TenantChain {
            store: self.ports.records(),
            seal: &self.seal,
        }
    }

    /// The verified head of `tenant`'s chain with its private part; `None`
    /// when the tenant has no chain. A key version that is not held is
    /// loaded once (pinned to the check value the head commits for it),
    /// and the head is read again. A shredding or shredded tenant whose
    /// key cannot be loaded any more reads with no private part.
    pub async fn tenant_head(
        &self,
        tenant: &TenantId,
    ) -> std::result::Result<Option<ReadRecord>, ChainError> {
        let t = Tenant::Managed(tenant.clone());
        match self.chain().head(&t, 0).await {
            Err(ChainError::KeyNotHeld { version }) => {
                let door = self
                    .heads()
                    .head(&t, 0)
                    .await?
                    .ok_or(ChainError::Damaged("head_gone"))?
                    .door;
                self.load_for(tenant, &door, version).await?;
                self.chain().head(&t, 0).await
            }
            other => other,
        }
    }

    /// Loads version `version` of `tenant`'s key as the head `door`
    /// commits it, and holds it for the seal.
    async fn load_for(
        &self,
        tenant: &TenantId,
        door: &TenantDoor,
        version: u32,
    ) -> std::result::Result<(), ChainError> {
        let kcv = committed_check(door, version).ok_or(ChainError::Damaged("no_key_check"))?;
        match self.load_key(tenant, version, kcv).await {
            Ok(_) => Ok(()),
            // A shred destroys the keys before its stub: the private part
            // of a shredding tenant is empty to every reader.
            Err(_) if matches!(door.lifecycle, Lifecycle::Shredding | Lifecycle::Shredded) => {
                self.cache.seal_keys.gone(tenant, version);
                Ok(())
            }
            Err(e) => Err(ChainError::Store(e)),
        }
    }

    /// Version `version` of `tenant`'s key with the committed check value
    /// `kcv`, from the key buckets through the isolate's loader, and held
    /// for the seal. A writer calls this before it seals under a version
    /// (the commit of a new version included: its blobs are stored before
    /// it is committed).
    pub async fn load_key(
        &self,
        tenant: &TenantId,
        version: u32,
        kcv: [u8; KCV_LEN],
    ) -> Result<Rc<TenantKey>> {
        let locations = self.locations().await?;
        let loaded = self
            .cache
            .tks
            .load(
                &locations,
                &self.ports.key_buckets(),
                self.ports.kek(),
                self.ports.clock(),
                tenant,
                version,
                kcv,
            )
            .await;
        let key = match loaded {
            Ok(key) => key,
            Err(e) => {
                // A marker or a foreign name refuses the tenant at once,
                // here as in the loader: the seal drops its keys too.
                if is_foreign(&e) {
                    self.cache.seal_keys.forget(tenant);
                }
                return Err(e);
            }
        };
        // Dated from its unwrap, which the loader's cache knows.
        let now = self.ports.clock().now();
        let loaded_at = self
            .cache
            .tks
            .loaded_at(tenant, version, &kcv)
            .unwrap_or(now);
        self.cache.seal_keys.hold(key.clone(), loaded_at, now)?;
        Ok(key)
    }

    /// The tenant's key ring as its head names it: the version in force
    /// and every older committed version whose key still exists (a
    /// retired one has none, and is left out). Any other failure to load
    /// a version fails the call: a ring missing a live version would fold
    /// that version's subjects as closed. For the key chain's reader and
    /// writer.
    pub async fn tenant_keys(&self, tenant: &TenantId) -> Result<LoadedRing> {
        let t = Tenant::Managed(tenant.clone());
        let door = self
            .heads()
            .head(&t, 0)
            .await
            .map_err(chain_error)?
            .ok_or(ERR_NO_TENANT)?
            .door;
        let check = |v: u32| committed_check(&door, v).ok_or(ERR_NO_CHECK);
        let current = self
            .load_key(tenant, door.tk_version, check(door.tk_version)?)
            .await?;
        let mut others = Vec::new();
        for &v in door.key_checks.keys().filter(|&&v| v != door.tk_version) {
            match self.load_key(tenant, v, check(v)?).await {
                Ok(key) => others.push(key),
                Err(e) if is_missing(&e) => {}
                Err(e) => return Err(e),
            }
        }
        LoadedRing::new(current, others)
    }

    /// The key locations, read from `m/kl/` at most once per
    /// [`HEAD_MAX_AGE_MS`] per isolate. None recorded: no tenant key can
    /// be loaded (fail closed).
    async fn locations(&self) -> Result<KeyLocations> {
        let now = self.ports.clock().now();
        if let Some((set, at)) = &*self.cache.locations.borrow() {
            if now.0 >= at.0 && now.0 - at.0 < HEAD_MAX_AGE_MS {
                return Ok(set.clone());
            }
        }
        let set = read_locations(self.ports.records(), self.ports.kek(), 0)
            .await?
            .ok_or(ERR_NO_LOCATIONS)?;
        *self.cache.locations.borrow_mut() = Some((set.clone(), now));
        Ok(set)
    }

    /// Access key ids to tenants (ADR §8.4 step 2).
    pub fn key_routes(&self) -> RootRoutes<'_, 'a, P, R> {
        RootRoutes { root: self }
    }
}

/// The loader found no copy of the version in any location: a retired
/// version.
fn is_missing(e: &BridgeError) -> bool {
    matches!((e, &ERR_TK_MISSING), (BridgeError::Crypto(a), BridgeError::Crypto(b)) if a == b)
}

fn chain_error(e: ChainError) -> BridgeError {
    match e {
        ChainError::Store(e) => e,
        _ => BridgeError::Crypto("tenant head unreadable"),
    }
}

/// [`KeyRoutes`] over the directory, then the route records.
pub struct RootRoutes<'r, 'a, P: RootPorts, R> {
    root: &'r Root<'a, P, R>,
}

impl<P: RootPorts, R: FillRandom> RootRoutes<'_, '_, P, R> {
    /// The route record `m/kr/<akid>`, after a failed directory read.
    async fn route_record(&self, akid: &str) -> Result<KeyTenant> {
        match read_route(self.root.records(), self.root.kek(), akid).await? {
            Some(route) => {
                let tenant = crate::unit::TenantId::parse(&route.tenant).ok_or(ERR_ROUTE_TENANT)?;
                // A record carries no numbers: the unit's own answer is the
                // first call's floor (rule 5).
                Ok(self.keep(akid, tenant, NO_SEQS))
            }
            None => Ok(KeyTenant::Unrouted),
        }
    }

    /// Keeps a route that was read, and answers it.
    fn keep(&self, akid: &str, tenant: crate::unit::TenantId, floor: Seqs) -> KeyTenant {
        let mut routes = self.root.cache.routes.borrow_mut();
        if routes.len() >= ROUTE_CACHE_KEYS {
            routes.clear();
        }
        routes.insert(akid.to_owned(), (tenant.clone(), floor));
        KeyTenant::Managed { tenant, floor }
    }
}

impl<P: RootPorts, R: FillRandom> KeyRoutes for RootRoutes<'_, '_, P, R> {
    async fn tenant_of(&self, akid: &str) -> Result<KeyTenant> {
        if let Some((tenant, floor)) = self.root.cache.routes.borrow().get(akid) {
            return Ok(KeyTenant::Managed {
                tenant: tenant.clone(),
                floor: *floor,
            });
        }
        let Some(dir) = self.root.directory() else {
            return self.route_record(akid).await;
        };
        // One read: the route and the tenant's numbers (ADR §8.4 step 2).
        let route = match dir.route_tenant(akid).await {
            Ok(route) => route,
            Err(_) => return self.route_record(akid).await,
        };
        match route {
            // The directory was read and names no route: tenant 0's key, or
            // none at all, which tenant 0's catalogue answers.
            None | Some((Tenant::Zero, _)) => Ok(KeyTenant::Zero),
            Some((Tenant::Managed(t), seqs)) => {
                let tenant = crate::unit::TenantId::parse(t.as_str()).ok_or(ERR_ROUTE_TENANT)?;
                // A floor for the first call of a cold isolate; a row that
                // is gone gives none (the unit's own answer then is).
                let floor = seqs.map_or(NO_SEQS, |(state_seq, keys_seq)| Seqs {
                    state_seq,
                    keys_seq,
                });
                Ok(self.keep(akid, tenant, floor))
            }
        }
    }
}
