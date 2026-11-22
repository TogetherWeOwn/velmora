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

use crate::types::{BridgeError, Result};
use crate::unit::{CallKind, Seqs, TenantId, TenantState, UnitAnswer, UnitName, UnitOp};

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
