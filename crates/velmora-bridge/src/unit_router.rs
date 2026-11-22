//! The way from a managed tenant to its units (ADR-TENANCY §2.7, §8.4;
//! design round 5, AM-51).
//!
//! This module holds what the queue consumer and the request router take
//! from a tenant's verified chain head. The head is read through the unit
//! client's port, [`crate::unit_lease::client::TenantHeads`] (L3's chain
//! reader behind it); [`read_head`] turns its answer into a [`HeadView`].
//! The consumer asks it whether a unit that answered `Unborn` is listed
//! (rule 7) and whether a tenant whose unit refused a job is being
//! shredded (AM-50).
//!
//! A build without a chain reader uses [`NoHeads`], which fails every
//! read, so the consumer hands the message back and never acknowledges on
//! a head it could not read.
//!
//! # The request router
//!
//! [`UnitRouter`] is the router's port (ADR §2.7, AM-51): the S3 path
//! (`service::serve_managed`) and the management plane (L5) reach a
//! managed tenant's units through it. [`Router`] implements it:
//!
//! - **Key to tenant** is [`KeyRoutes`], before the router: the
//!   directory's `key_routes` row, or the route record `m/kr/<akid>` when
//!   that read failed (§8.4). A build without them uses [`NoRoutes`].
//! - **Tenant and bucket to unit:** the tenant's verified head, cached per
//!   isolate for less than [`HEAD_MAX_AGE_MS`]. A call that names no
//!   bucket goes to the root unit (unit 0); a bucket goes to the unit its
//!   placement names, or to the root unit when it has none (a bucket is
//!   born there). The unit must be listed by the head.
//! - **The call** goes through the unit client of that unit
//!   ([`RequestClient`], L2's `UnitClient::call`, which runs rule 5:
//!   renew, sync or the unit's numbers, then once more). It carries the
//!   head's `state_seq`, the highest `keys_seq` a unit of the tenant
//!   answered, and `listed`. Under `MAINTENANCE=restore` a request call
//!   that writes is refused before any call (AM-50).

use std::cell::RefCell;
use std::collections::HashMap;

use crate::config::Maintenance;
use crate::directory::chain::ChainError;
use crate::directory::record::{Lifecycle, TenantDoor};
use crate::ports::{BlobStore, Clock};
use crate::types::{BridgeError, Result, UnixMs};
use crate::unit::{CallKind, Seqs, TenantId, UnitAnswer, UnitCall, UnitName, UnitOp, UnitReply};
use crate::unit_lease::client::{
    Answered, KeyFeed, KeyFinisher, Page, Renewal, Synced, TenantHeads, UnitClient, UnitReplies,
};
use crate::unit_lease::renewal::ChainNames;

/// What the consumer and the router take from a tenant's verified head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadView {
    /// The head record's seq (the tenant's `state_seq`).
    pub seq: u64,
    pub lifecycle: Lifecycle,
    /// The units the head lists, by number.
    pub units: Vec<u32>,
    /// Where each placed bucket lives: (bucket, unit).
    pub placements: Vec<(String, u32)>,
}

impl HeadView {
    pub fn of(door: &TenantDoor) -> HeadView {
        HeadView {
            seq: door.seq,
            lifecycle: door.lifecycle,
            units: door.units.clone(),
            placements: door
                .placements
                .iter()
                .map(|p| (p.bucket.clone(), p.unit))
                .collect(),
        }
    }

    /// The unit that holds `bucket`: its placement's, else the root unit,
    /// where a bucket is born.
    pub fn unit_of(&self, bucket: &str) -> u32 {
        self.placements
            .iter()
            .find(|(b, _)| b == bucket)
            .map_or(ROOT_UNIT, |(_, unit)| *unit)
    }

    /// The head lists `unit` (of its own tenant: the caller asked for it).
    pub fn lists(&self, unit: &UnitName) -> bool {
        self.units.contains(&unit.unit)
    }

    /// The tenant is being shredded or is shredded: its jobs stop by
    /// design (ADR §13.3).
    pub fn shredding(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Shredding | Lifecycle::Shredded)
    }
}

/// The tenant's verified head. `Ok(None)`: the tenant has no chain, so no
/// record lists any unit of it. `Err`: the read failed or did not verify,
/// never a guess. The chain is listed from its start (`known` 0): this is
/// the rare path of a refusal, and a message's numbers are not trusted as
/// a floor (a `known` above the head is an error, not the head).
pub async fn read_head<H: TenantHeads>(
    heads: &H,
    tenant: &TenantId,
) -> std::result::Result<Option<HeadView>, ChainError> {
    read_head_after(heads, tenant, 0).await
}

/// [`read_head`], listing after `known` (a seq this isolate verified).
async fn read_head_after<H: TenantHeads>(
    heads: &H,
    tenant: &TenantId,
    known: u64,
) -> std::result::Result<Option<HeadView>, ChainError> {
    Ok(heads.head(tenant, known).await?.as_ref().map(HeadView::of))
}

/// No chain reader in this build: every read fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHeads;

/// The error of [`NoHeads`].
pub const NO_HEAD_READER: &str = "no tenant head reader in this build";

impl TenantHeads for NoHeads {
    async fn head(
        &self,
        _: &TenantId,
        _: u64,
    ) -> std::result::Result<Option<TenantDoor>, ChainError> {
        Err(ChainError::Store(BridgeError::NotImplemented(
            NO_HEAD_READER,
        )))
    }
}

/// A tenant head for tests: `tenant` at `seq`, in `lifecycle`, listing
/// `units`; every other field at its default. Read from JSON as a record's
/// door part is, so it holds only fields a record can hold.
#[cfg(any(test, feature = "testkit"))]
pub fn test_door(tenant: &TenantId, seq: u64, lifecycle: Lifecycle, units: &[u32]) -> TenantDoor {
    serde_json::from_value(serde_json::json!({
        "v": crate::directory::record::RECORD_FORMAT,
        "tenant": tenant.as_str(),
        "seq": seq,
        "written_at": 1,
        "created_at": 1,
        "lifecycle": lifecycle,
        "units": units,
        "max_move_epoch": 0,
        "tk_version": 1,
        "key_checks": {"1": "00".repeat(16)},
        "highest_claimed": 1,
        "jurisdiction": "us",
    }))
    .expect("a door part")
}

// ---------------------------------------------------------------------------
// The request router (design round 5, AM-51)
// ---------------------------------------------------------------------------

/// The root unit of a tenant (ADR §2.5).
pub const ROOT_UNIT: u32 = 0;

/// What an access key id's route says (ADR §8.4 step 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyTenant {
    /// Tenant 0's key, or one no route names: tenant 0's catalogue decides
    /// (D1 `access_keys`), as today.
    Zero,
    /// A managed tenant's key, with the numbers the directory handed out
    /// with its route: a floor for the first call of a cold isolate (rule
    /// 5, §8.4 step 2). Zeros when the route came from the `m/kr/` record
    /// (a failed directory read), which carries none.
    Managed { tenant: TenantId, floor: Seqs },
    /// No route names the key, and the directory could not be read (the
    /// route record was the answer): ADR §8.4 (DUR-10). Tenant 0's path
    /// only for a key tenant 0's catalogue holds; any other key answers
    /// `503`, not `403 InvalidAccessKeyId`, since a route may exist that
    /// the directory could not show.
    Unrouted,
}

/// An access key id to its tenant: the directory's `key_routes` row, or
/// the route record `m/kr/<akid>` when the directory read failed. `Err`:
/// neither could be read or verified (never a guess).
#[allow(async_fn_in_trait)]
pub trait KeyRoutes {
    async fn tenant_of(&self, access_key_id: &str) -> Result<KeyTenant>;
}

/// No key routes in this build: every read fails. The Worker then takes
/// tenant 0's path, where a key tenant 0 does not hold answers `403`; ADR
/// §8.4 (DUR-10) asks for `503` after a failed route read, which comes
/// with the real adapter (design question 11 in the lane log).
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
    /// The head's `state_seq`, and the highest `keys_seq` a unit of the
    /// tenant answered this isolate (0 before the first answer: the unit
    /// then answers its own, and the client sends once more, rule 5).
    pub seqs: Seqs,
    /// A record lists the unit (rule 7): always set, the router names
    /// only listed units.
    pub listed: bool,
}

/// Why the router answers instead of a unit: each is `503` with
/// `Retry-After` but `AccountProblem` (`403`), with no field of the request
/// or the unit in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteRefusal {
    /// `MAINTENANCE=restore` and the request writes: no unit call (AM-50).
    Maintenance,
    /// The head does not list the unit, the tenant has no chain, or the
    /// unit says no record lists it.
    NotPlaced,
    /// A head read failed or did not verify, or the unit could not be
    /// reached.
    Unavailable,
    /// The unit is closed (restoring or provisioning).
    Closed,
    /// A listed unit of a `live` tenant is unborn: the Worker pages
    /// "catalogue lost" (rule 7; AM-58: not while `provisioning`, which
    /// answers `Unavailable`).
    CatalogueLost,
    /// The unit still refused the numbers after the client's one fix.
    NotFresh,
    /// The tenant is being shredded: `403 AccountProblem`, as the unit
    /// answers a held tenant (AM-50's shredding row, on the request path).
    AccountProblem,
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
            RouteRefusal::AccountProblem => "account_problem",
        }
    }

    /// The Worker pages for it.
    pub fn alert(self) -> bool {
        matches!(self, RouteRefusal::CatalogueLost)
    }
}

/// The request router's port (ADR §2.7). L5's management handlers call
/// units through it, as the S3 path does.
#[allow(async_fn_in_trait)]
pub trait UnitRouter {
    /// The unit of `tenant` that holds `bucket`; `None`: the root unit,
    /// for calls that name no bucket (keys, principals, bucket create).
    /// `floor`: numbers the caller knows (the key route's, rule 5; zeros
    /// for none). A head below `floor.state_seq` is read again, and if it
    /// stays below, refused; `keys_seq` is at least `floor.keys_seq`.
    async fn route(
        &self,
        tenant: &TenantId,
        bucket: Option<&str>,
        floor: Seqs,
    ) -> std::result::Result<Routed, RouteRefusal>;

    /// One call to `routed`, carrying its numbers and `listed`, through
    /// the unit client (rule 5 runs there). Under `MAINTENANCE=restore` a
    /// call that writes ([`writes`]) is refused before any call. `Closed`,
    /// `Unborn` and numbers still refused become refusals; any other
    /// answer is the caller's to map. `renew_due` in the answer asks the
    /// caller for a background renewal (`waitUntil`). The client's pages
    /// come with every outcome: the caller logs each as an alert.
    async fn call(
        &self,
        routed: &Routed,
        kind: CallKind,
        authenticated: bool,
        op: UnitOp,
    ) -> (std::result::Result<Answered, RouteRefusal>, Vec<Page>);
}

/// A call to a unit that writes on a caller's behalf, for the maintenance
/// gate: a `Request` call of any op but the three reads
/// (`UnitOp::is_read`), and the reservation calls that can change rows
/// (`Reserve`, `BindBucket`, `Release`, `ReleaseBound`, and
/// `BucketBinding`, which can write a fence), which the management plane
/// sends as Worker calls. The tools' own calls (`sync`, the key apply,
/// the import, the gate, the restore calls, `renew`, `Recount`, `Export`)
/// and `ResolveActing` pass: the owner move's window runs on them (DS1
/// §3.4).
pub fn writes(kind: CallKind, op: &UnitOp) -> bool {
    let reserves = matches!(
        op,
        UnitOp::Reserve { .. }
            | UnitOp::BindBucket { .. }
            | UnitOp::Release { .. }
            | UnitOp::ReleaseBound { .. }
            | UnitOp::BucketBinding { .. }
    );
    reserves || (kind == CallKind::Request && !op.is_read())
}

/// The unit client of one unit as the router calls it: L2's
/// `UnitClient::call` (rule 5 on the request path).
#[allow(async_fn_in_trait)]
pub trait RequestClient {
    async fn call(&self, call: UnitCall) -> (Result<Answered>, Vec<Page>);
}

impl<U, B, T, N, H, K, F> RequestClient for UnitClient<U, B, T, N, H, K, F>
where
    U: UnitReplies,
    B: BlobStore,
    T: Clock,
    N: ChainNames,
    H: TenantHeads,
    K: KeyFeed,
    F: KeyFinisher,
{
    async fn call(&self, call: UnitCall) -> (Result<Answered>, Vec<Page>) {
        UnitClient::call(self, call).await
    }
}

/// The unit clients: one for a routed unit (the client is made for one
/// unit, with `listed` as routed).
pub trait RequestClients {
    type Client: RequestClient;
    /// `Err`: the unit's object cannot be named or reached.
    fn client(&self, routed: &Routed) -> Result<Self::Client>;
}

/// How long an isolate uses a tenant head it read: the 60 s of ADR §8.4
/// ("any mutable fact cached ... used for at most 60 s"), never extended
/// because of an error.
pub const HEAD_MAX_AGE_MS: i64 = 60_000;

/// At most this many tenants are kept; past it the cache is emptied.
const HEAD_CACHE_TENANTS: usize = 1024;

#[derive(Clone, Debug)]
struct Cached {
    view: HeadView,
    read_at: UnixMs,
    /// The highest `keys_seq` a unit of the tenant answered.
    keys_seq: u64,
    /// A unit answered a `state_seq` above the head's: read it again.
    moved: bool,
}

/// The heads an isolate read, per tenant.
#[derive(Debug, Default)]
pub struct HeadCache {
    heads: RefCell<HashMap<TenantId, Cached>>,
}

impl HeadCache {
    /// The head, if read less than [`HEAD_MAX_AGE_MS`] ago (a clock that
    /// went back counts as old), and the entry's last seq and `keys_seq`
    /// whatever its age.
    fn get(&self, tenant: &TenantId, now: UnixMs) -> (Option<Cached>, u64, u64) {
        let heads = self.heads.borrow();
        let Some(c) = heads.get(tenant) else {
            return (None, 0, 0);
        };
        let fresh =
            !c.moved && now.0 >= c.read_at.0 && now.0.saturating_sub(c.read_at.0) < HEAD_MAX_AGE_MS;
        (fresh.then(|| c.clone()), c.view.seq, c.keys_seq)
    }

    fn put(&self, tenant: &TenantId, view: HeadView, keys_seq: u64, now: UnixMs) {
        let mut heads = self.heads.borrow_mut();
        if heads.len() >= HEAD_CACHE_TENANTS && !heads.contains_key(tenant) {
            heads.clear();
        }
        // Two requests that overlap: the newer head and the higher
        // numbers stay.
        if let Some(c) = heads.get(tenant) {
            if c.view.seq > view.seq {
                return;
            }
        }
        let keys_seq = heads
            .get(tenant)
            .map_or(keys_seq, |c| c.keys_seq.max(keys_seq));
        heads.insert(
            tenant.clone(),
            Cached {
                view,
                read_at: now,
                keys_seq,
                moved: false,
            },
        );
    }

    /// The lifecycle of the head this isolate holds for `tenant`, of any
    /// age.
    fn lifecycle(&self, tenant: &TenantId) -> Option<Lifecycle> {
        self.heads.borrow().get(tenant).map(|c| c.view.lifecycle)
    }

    /// A unit of `tenant` answered `seqs`: keep its `keys_seq`; a
    /// `state_seq` above the cached head's means the head moved, and it
    /// is read again on the next route.
    fn answered(&self, tenant: &TenantId, seqs: Seqs) {
        let mut heads = self.heads.borrow_mut();
        let Some(c) = heads.get_mut(tenant) else {
            return;
        };
        c.keys_seq = c.keys_seq.max(seqs.keys_seq);
        if seqs.state_seq > c.view.seq {
            c.moved = true;
        }
    }
}

/// The router of one request (or one management call): the isolate's
/// head cache, the clients and heads, and a clock read at every route.
pub struct Router<'a, C, H, T> {
    pub maintenance: Maintenance,
    pub clients: &'a C,
    pub heads: &'a H,
    pub cache: &'a HeadCache,
    pub clock: &'a T,
}

impl<C: RequestClients, H: TenantHeads, T: Clock> UnitRouter for Router<'_, C, H, T> {
    async fn route(
        &self,
        tenant: &TenantId,
        bucket: Option<&str>,
        floor: Seqs,
    ) -> std::result::Result<Routed, RouteRefusal> {
        if tenant.is_zero() {
            // Tenant 0's catalogue is D1, never through this router.
            return Err(RouteRefusal::NotPlaced);
        }
        let now = self.clock.now();
        let (cached, known, keys_seq) = self.cache.get(tenant, now);
        let keys_seq = keys_seq.max(floor.keys_seq);
        // A cached head below the floor is old: read it again.
        let view = match cached.filter(|c| c.view.seq >= floor.state_seq) {
            Some(c) => c.view,
            None => {
                let view = read_head_after(self.heads, tenant, known)
                    .await
                    .map_err(|_| RouteRefusal::Unavailable)?
                    .ok_or(RouteRefusal::NotPlaced)?;
                // A verified head below what the directory handed out: the
                // chain is behind its own record, never routed by.
                if view.seq < floor.state_seq {
                    return Err(RouteRefusal::Unavailable);
                }
                self.cache.put(tenant, view.clone(), keys_seq, now);
                view
            }
        };
        let unit = bucket.map_or(ROOT_UNIT, |b| view.unit_of(b));
        if !view.units.contains(&unit) {
            return Err(RouteRefusal::NotPlaced);
        }
        Ok(Routed {
            unit: UnitName::new(tenant.clone(), unit),
            seqs: Seqs {
                state_seq: view.seq,
                keys_seq,
            },
            listed: true,
        })
    }

    async fn call(
        &self,
        routed: &Routed,
        kind: CallKind,
        authenticated: bool,
        op: UnitOp,
    ) -> (std::result::Result<Answered, RouteRefusal>, Vec<Page>) {
        let (result, pages) = self.call_with_reply(routed, kind, authenticated, op).await;
        (result.map_err(|(refusal, _)| refusal), pages)
    }
}

impl<C: RequestClients, H: TenantHeads, T: Clock> Router<'_, C, H, T> {
    /// [`UnitRouter::call`], with the unit's own answer beside a refusal
    /// when one came (`None`: no call was made, or no answer came). The
    /// request path uses it: an answer the unit gave before it ran the
    /// call (`closed`, `unborn`, a lease or numbers still refused) tells
    /// the request client that a publication wrote nothing.
    pub async fn call_with_reply(
        &self,
        routed: &Routed,
        kind: CallKind,
        authenticated: bool,
        op: UnitOp,
    ) -> (
        std::result::Result<Answered, (RouteRefusal, Option<UnitReply>)>,
        Vec<Page>,
    ) {
        if self.maintenance == Maintenance::Restore && writes(kind, &op) {
            return (Err((RouteRefusal::Maintenance, None)), Vec::new());
        }
        let Ok(client) = self.clients.client(routed) else {
            return (Err((RouteRefusal::Unavailable, None)), Vec::new());
        };
        let (answered, pages) = client
            .call(UnitCall {
                name: routed.unit.clone(),
                kind,
                seqs: Some(routed.seqs),
                authenticated,
                listed: routed.listed,
                op,
            })
            .await;
        let Ok(answered) = answered else {
            return (Err((RouteRefusal::Unavailable, None)), pages);
        };
        let tenant = &routed.unit.tenant;
        // Rule 7 pages only for a live tenant (AM-58): while the head is
        // `provisioning` an unborn root unit is expected, and any other
        // tenant's unborn unit answers `503` with no page too.
        let lost = match self.cache.lifecycle(tenant) {
            Some(Lifecycle::Live) => RouteRefusal::CatalogueLost,
            _ => RouteRefusal::Unavailable,
        };
        if let Some(seqs) = answered.refreshed {
            self.cache.answered(tenant, seqs);
        }
        // What the client's own fix came to names the refusal when the
        // unit still refused the numbers (AM-50's rows, on the request path).
        let fixed = match (&answered.renewal, &answered.synced) {
            (Some(Renewal::Closed { .. }), _) | (_, Some(Synced::LiftPending { .. })) => {
                Some(RouteRefusal::Closed)
            }
            (Some(Renewal::Unborn), _) | (_, Some(Synced::Unborn)) => Some(lost),
            (Some(Renewal::NotListed), _) | (_, Some(Synced::NotListed)) => {
                Some(RouteRefusal::NotPlaced)
            }
            (Some(Renewal::Shredding), _) => Some(RouteRefusal::AccountProblem),
            _ => None,
        };
        let refused = match &answered.reply.answer {
            UnitAnswer::Closed { .. } => Some(RouteRefusal::Closed),
            UnitAnswer::Unborn { listed: true } => Some(lost),
            UnitAnswer::Unborn { listed: false } => Some(RouteRefusal::NotPlaced),
            UnitAnswer::Stale { .. }
            | UnitAnswer::SyncNeeded { .. }
            | UnitAnswer::RenewNeeded { .. }
                if kind == CallKind::Request =>
            {
                Some(fixed.unwrap_or(RouteRefusal::NotFresh))
            }
            UnitAnswer::Ok { seqs, .. } => {
                self.cache.answered(tenant, *seqs);
                None
            }
            _ => None,
        };
        let result = match refused {
            Some(refusal) => Err((refusal, Some(answered.reply))),
            None => Ok(answered),
        };
        (result, pages)
    }
}

/// No unit clients in this build: every routed call is `Unavailable`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoClients;

/// The client [`NoClients`] never makes.
pub enum NoClient {}

impl RequestClient for NoClient {
    async fn call(&self, _: UnitCall) -> (Result<Answered>, Vec<Page>) {
        match *self {}
    }
}

/// The error of [`NoClients`].
pub const NO_REQUEST_CLIENT: &str = "no unit client in this build";

impl RequestClients for NoClients {
    type Client = NoClient;
    fn client(&self, _: &Routed) -> Result<NoClient> {
        Err(BridgeError::NotImplemented(NO_REQUEST_CLIENT))
    }
}
