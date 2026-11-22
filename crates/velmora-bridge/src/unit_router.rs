//! The way from a managed tenant to its units (ADR-TENANCY §2.7, §8.4;
//! design round 5, AM-51).
//!
//! This module holds the ports the queue consumer and the request router
//! share. [`TenantHeads`] reads a tenant's verified chain head: the
//! consumer asks it whether a unit that answered `Unborn` is listed
//! (rule 7) and whether a tenant whose unit refused a job is being
//! shredded (AM-50); the router takes the units and the numbers from it.
//! [`KeyRoutes`] turns an access key id into its tenant (§8.4 step 2).
//! [`UnitRouter`] is the router's port: the S3 path and the management
//! plane (L5) call a managed tenant's units through it.
//!
//! The adapters come from other lanes' code: the tenant chain reader
//! (`directory`, L3) and the key routes (the directory's `key_routes`,
//! and L4's `keys/routes.rs` when its read fails). A build without them
//! uses [`NoHeads`], which fails every read, so the consumer hands the
//! message back and never acknowledges on a head it could not read.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::config::Maintenance;
use crate::tenant_catalog::UnitPort;
use crate::types::{BridgeError, Result, UnixMs};
use crate::unit::{CallKind, Seqs, TenantId, TenantState, UnitAnswer, UnitCall, UnitName, UnitOp};
use crate::unit_consumer::ConsumerClient;

/// What the consumer and the router take from a tenant's verified head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadView {
    /// The head's `state_seq`, and the key chain head's `keys_seq`.
    pub seqs: Seqs,
    pub state: TenantState,
    /// The units the head lists, by number.
    pub units: Vec<u32>,
}

impl HeadView {
    /// The head lists `unit` (of its own tenant: the caller asked for it).
    pub fn lists(&self, unit: &UnitName) -> bool {
        self.units.contains(&unit.unit)
    }

    /// The tenant is being shredded or is shredded: its jobs stop by
    /// design (ADR §13.3).
    pub fn shredding(&self) -> bool {
        matches!(self.state, TenantState::Shredding | TenantState::Shredded)
    }
}

/// A tenant's chain head, read from R2 and verified. `Err` for a read that
/// failed or a head that did not verify: never a guess.
#[allow(async_fn_in_trait)]
pub trait TenantHeads {
    async fn head(&self, tenant: &TenantId) -> Result<HeadView>;
}

/// No chain reader in this build: every read fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHeads;

/// The error of [`NoHeads`].
pub const NO_HEAD_READER: &str = "no tenant head reader in this build";

impl TenantHeads for NoHeads {
    async fn head(&self, _: &TenantId) -> Result<HeadView> {
        Err(BridgeError::NotImplemented(NO_HEAD_READER))
    }
}

// ---------------------------------------------------------------------------
// The router's port (design round 5, AM-51): the S3 path and the
// management plane (L5) reach a managed tenant's units through it.
// ---------------------------------------------------------------------------

/// What an access key id's route says (ADR §8.4 step 2): the directory's
/// `key_routes` row, or the route record `m/kr/<akid>` when the directory
/// read failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyTenant {
    /// Tenant 0's key, or one no route names: tenant 0's catalogue decides
    /// (D1 `access_keys`), as today.
    Zero,
    /// A managed tenant's key.
    Managed(TenantId),
}

/// An access key id to its tenant. `Err`: the route could not be read or
/// did not verify (never a guess).
#[allow(async_fn_in_trait)]
pub trait KeyRoutes {
    async fn tenant_of(&self, access_key_id: &str) -> Result<KeyTenant>;
}

/// No key routes in this build: every read fails, so every request takes
/// tenant 0's path (ADR §8.4, a failed route read, DUR-10).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRoutes;

/// The error of [`NoRoutes`].
pub const NO_KEY_ROUTES: &str = "no key routes in this build";

impl KeyRoutes for NoRoutes {
    async fn tenant_of(&self, _: &str) -> Result<KeyTenant> {
        Err(BridgeError::NotImplemented(NO_KEY_ROUTES))
    }
}

/// A unit the router chose, and what every call to it carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Routed {
    pub unit: UnitName,
    /// The tenant's numbers as the router last read them (rule 5).
    pub seqs: Seqs,
    /// A record lists the unit (rule 7). The router names only listed
    /// units, so it is always set on a routed call.
    pub listed: bool,
}

/// Why the router answers instead of a unit. Each is a fixed answer with
/// no field of the request or the unit in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteRefusal {
    /// `MAINTENANCE=restore` and the request writes: `503` with
    /// `Retry-After`, and no unit call (AM-50).
    Maintenance,
    /// The head does not list the unit, or the bucket's unit is not known
    /// to this build: `503`, fail closed.
    NotPlaced,
    /// A head or route read failed or did not verify, or the unit could
    /// not be reached: `503`.
    Unavailable,
    /// The unit is closed (restoring or provisioning): `503`.
    Closed,
    /// A listed unit is unborn: `503`, and the Worker pages "catalogue
    /// lost" (rule 7).
    CatalogueLost,
    /// The unit's numbers still differ after one refresh, or its lease
    /// could not be renewed: `503`.
    NotFresh,
}

impl RouteRefusal {
    /// The fixed word of the log line.
    pub fn code(self) -> &'static str {
        match self {
            RouteRefusal::Maintenance => "maintenance",
            RouteRefusal::NotPlaced => "not_placed",
            RouteRefusal::Unavailable => "unavailable",
            RouteRefusal::Closed => "closed",
            RouteRefusal::CatalogueLost => "catalogue_lost",
            RouteRefusal::NotFresh => "not_fresh",
        }
    }

    /// The Worker pages for it.
    pub fn alert(self) -> bool {
        matches!(self, RouteRefusal::CatalogueLost)
    }
}

/// The request router (ADR §2.7): `(tenant, bucket)` to a unit, from the
/// tenant's verified head and the root unit's placement list, cached per
/// isolate; and one call to that unit. L5's management handlers call
/// units through this port, as the S3 path does.
#[allow(async_fn_in_trait)]
pub trait UnitRouter {
    /// The unit of `tenant` that holds `bucket`; `None`: the tenant's
    /// root unit, for calls that name no bucket (keys, principals, bucket
    /// create, the tenant's own reads).
    async fn route(
        &self,
        tenant: &TenantId,
        bucket: Option<&str>,
    ) -> std::result::Result<Routed, RouteRefusal>;

    /// One call to `routed`, carrying its numbers and `listed`. Under
    /// `MAINTENANCE=restore` a `Request` call that writes (any op but
    /// `Ping`, `KeyRow` and `ReadPlan`) is refused before any unit call.
    /// A request call the unit answers `Stale`, `SyncNeeded` or
    /// `renew_needed` is refreshed (head re-read, `sync`, or `renew`) and
    /// sent once more (rules 5 and 12). `Closed` and `Unborn` become
    /// refusals; any other answer is the caller's to map.
    async fn call(
        &self,
        routed: &Routed,
        kind: CallKind,
        authenticated: bool,
        op: UnitOp,
    ) -> std::result::Result<UnitAnswer, RouteRefusal>;
}

/// A call to a unit that writes, for the maintenance gate: every op but
/// the three reads (`UnitOp::is_read`).
pub fn writes(kind: CallKind, op: &UnitOp) -> bool {
    kind == CallKind::Request && !op.is_read()
}

// ---------------------------------------------------------------------------
// The router
// ---------------------------------------------------------------------------

/// How long an isolate uses a tenant head it read: the 60 s of ADR §8.4
/// ("any mutable fact cached ... used for at most 60 s"), never extended
/// because of an error.
pub const HEAD_MAX_AGE_MS: i64 = 60_000;

/// The heads an isolate read, per tenant, with the time each was read.
#[derive(Debug, Default)]
pub struct HeadCache {
    heads: RefCell<HashMap<TenantId, (HeadView, UnixMs)>>,
}

/// At most this many tenants are kept; past it the cache is emptied (an
/// isolate that serves that many tenants re-reads their heads).
const HEAD_CACHE_TENANTS: usize = 1024;

impl HeadCache {
    fn get(&self, tenant: &TenantId, now: UnixMs) -> Option<HeadView> {
        let heads = self.heads.borrow();
        let (head, at) = heads.get(tenant)?;
        // A clock that went back counts as old.
        (now.0 >= at.0 && now.0 - at.0 < HEAD_MAX_AGE_MS).then(|| head.clone())
    }

    fn put(&self, tenant: &TenantId, head: HeadView, now: UnixMs) {
        let mut heads = self.heads.borrow_mut();
        if heads.len() >= HEAD_CACHE_TENANTS && !heads.contains_key(tenant) {
            heads.clear();
        }
        heads.insert(tenant.clone(), (head, now));
    }

    fn forget(&self, tenant: &TenantId) {
        self.heads.borrow_mut().remove(tenant);
    }
}

/// The way to one unit's object (the Worker's `UnitStub`).
pub trait UnitPorts {
    type Port: UnitPort;
    /// `Err`: the object cannot be named or reached.
    fn open(&self, unit: &UnitName) -> Result<Self::Port>;
}

/// The router of one request (or one management call): the isolate's
/// head cache, the ports, and the request's clock reading.
pub struct Router<'a, P, H, C> {
    pub maintenance: Maintenance,
    pub ports: &'a P,
    pub heads: &'a H,
    pub client: &'a C,
    pub cache: &'a HeadCache,
    pub now: UnixMs,
}

/// The root unit of a tenant: unit 0 (ADR §2.5).
const ROOT_UNIT: u32 = 0;

impl<P: UnitPorts, H: TenantHeads, C: ConsumerClient> Router<'_, P, H, C> {
    async fn head(
        &self,
        tenant: &TenantId,
        fresh: bool,
    ) -> std::result::Result<HeadView, RouteRefusal> {
        if !fresh {
            if let Some(head) = self.cache.get(tenant, self.now) {
                return Ok(head);
            }
        }
        self.cache.forget(tenant);
        let head = self
            .heads
            .head(tenant)
            .await
            .map_err(|_| RouteRefusal::Unavailable)?;
        self.cache.put(tenant, head.clone(), self.now);
        Ok(head)
    }
}

impl<P: UnitPorts, H: TenantHeads, C: ConsumerClient> UnitRouter for Router<'_, P, H, C> {
    async fn route(
        &self,
        tenant: &TenantId,
        bucket: Option<&str>,
    ) -> std::result::Result<Routed, RouteRefusal> {
        if tenant.is_zero() {
            // Tenant 0's catalogue is D1 (or, after the move, unit 0 by
            // its own record): never through this router in this build.
            return Err(RouteRefusal::NotPlaced);
        }
        let head = self.head(tenant, false).await?;
        let root = UnitName::new(tenant.clone(), ROOT_UNIT);
        if !head.lists(&root) {
            return Err(RouteRefusal::NotPlaced);
        }
        // The root unit's placement list is not read by this build: only
        // a tenant whose head lists the root unit alone has a known place
        // for every bucket.
        if bucket.is_some() && head.units != [ROOT_UNIT] {
            return Err(RouteRefusal::NotPlaced);
        }
        Ok(Routed {
            unit: root,
            seqs: head.seqs,
            listed: true,
        })
    }

    async fn call(
        &self,
        routed: &Routed,
        kind: CallKind,
        authenticated: bool,
        op: UnitOp,
    ) -> std::result::Result<UnitAnswer, RouteRefusal> {
        if self.maintenance == Maintenance::Restore && writes(kind, &op) {
            return Err(RouteRefusal::Maintenance);
        }
        let port = self
            .ports
            .open(&routed.unit)
            .map_err(|_| RouteRefusal::Unavailable)?;
        let mut seqs = routed.seqs;
        let mut again = false;
        loop {
            let call = UnitCall {
                name: routed.unit.clone(),
                kind,
                seqs: Some(seqs),
                authenticated,
                listed: routed.listed,
                op: op.clone(),
            };
            let answer = port
                .call(&call)
                .await
                .map_err(|_| RouteRefusal::Unavailable)?;
            match answer {
                UnitAnswer::Closed { .. } => return Err(RouteRefusal::Closed),
                UnitAnswer::Unborn { listed: true } => return Err(RouteRefusal::CatalogueLost),
                // The router names only listed units; an unlisted answer
                // is a unit that does not exist.
                UnitAnswer::Unborn { listed: false } => return Err(RouteRefusal::NotPlaced),
                // A request with lower numbers: refresh and retry once
                // (rule 5).
                UnitAnswer::Stale { .. } if kind == CallKind::Request && !again => {
                    seqs = self.head(&routed.unit.tenant, true).await?.seqs;
                }
                // The caller knows a newer record: `sync` first (rule 5).
                UnitAnswer::SyncNeeded { .. } if kind == CallKind::Request && !again => {
                    seqs = self
                        .client
                        .sync(&routed.unit)
                        .await
                        .map_err(|_| RouteRefusal::NotFresh)?;
                }
                UnitAnswer::Stale { .. } | UnitAnswer::SyncNeeded { .. }
                    if kind == CallKind::Request =>
                {
                    return Err(RouteRefusal::NotFresh)
                }
                other => return Ok(other),
            }
            again = true;
        }
    }
}
