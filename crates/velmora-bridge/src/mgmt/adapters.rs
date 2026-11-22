//! The management plane's three store adapters (design round 6, L5-R4,
//! AM-66): the ports of [`crate::mgmt::principal`] over the stores of the
//! tenancy plane.
//!
//! - [`HeadDoor`]: [`TenantDoor`] over the tenant's verified head, door
//!   part only ([`TenantHeads`]: `Root::heads()` of L6's composition root,
//!   `crate::root`), and [`BucketNames`] for the names of placed buckets.
//! - [`RoutedUnit`]: [`RootUnit`] over the request router
//!   ([`UnitRouter`], L6) and L2's unit client behind it, and, through
//!   [`RootKeys`], the root unit's key-chain apply ([`KeyTarget`], with
//!   [`KeyTarget::apply_kept`], which L4's writer calls for the kept
//!   answer).
//! - [`KeyChain`]: [`PrincipalChain`] over L4's writer under a reservation
//!   ([`KeyEnv::create_reserved`], [`KeyEnv::carrying`],
//!   [`KeyEnv::finish_subject`]).
//!
//! **What each adapter decides:** nothing of the call. They translate
//! between the plane's ports and the stores' own types and answers. A
//! store answer an adapter cannot read is an `Err` (the call answers
//! `503`), never a guess.
//!
//! **Bucket names are not in the head** (AM-57: a bucket's name is in the
//! private part of the record that created it, and in the unit's bucket
//! row made from it). The head says which bucket ids are placed; the
//! names come from [`BucketNames`], a read of the root unit's bucket rows
//! (a `RequestCall` of L1-5, not built: [`NoBucketNames`] fails, so a
//! grant on a placed bucket answers `503` until it exists, and a grant on
//! an unplaced id still answers `404 bucket_not_found`).

use std::cell::{Cell, RefCell};

use velmora::rng::FillRandom;
use velmora_mgmt_types::Code;

use crate::directory::chain::ChainError;
use crate::directory::record::{TenantDoor as Door, TenantState};
use crate::keys::checkpoint::read_key_chain;
use crate::keys::gate::MoveGate;
use crate::keys::ports::{
    Applied, ApplyEntry, ControlIntents, KeptAnswer as ChainKept, KeyAdmission, KeyTarget, Refusal,
};
use crate::keys::record::{
    Access as ChainAccess, DoorGrant, Entry, KeyTable, PrivateGrant, Rid as ChainRid, Subject,
    SubjectDoor, SubjectKind, SubjectPrivate, SubjectStatus as ChainStatus, TkRing,
};
use crate::keys::reserved::{Finished, Reserved, ReservedAnswer};
use crate::keys::writer::KeyEnv;
use crate::mgmt::principal::{
    reserve_answer, ChainWrite, DoorState, NewPrincipal, PrincipalChain, RecordedPrincipal,
    ReserveAnswer, RootUnit, TenantDoor,
};
use crate::ports::{Clock, Kek};
use crate::records::RecordStore;
use crate::types::{BridgeError, Result};
use crate::unit::keys::{
    Access as UnitAccess, KeptAnswer as UnitKept, KeyGrant, SubjectStatus as UnitStatus,
};
use crate::unit::reserve::Rid as UnitRid;
use crate::unit::{CallKind, Seqs, TenantId, UnitAnswer, UnitOp};
use crate::unit_lease::client::{Answered, Page, TenantHeads};
use crate::unit_router::{RouteRefusal, Routed, UnitRouter};

/// The head could not be read now (a store fault, a key not loaded yet).
pub const ERR_HEAD: BridgeError = BridgeError::Invalid("mgmt: tenant head unreadable");
/// The head does not verify (a record missing, out of order, or not what
/// its name says; a private part that does not open): the chain's reader
/// fails closed, and the answer is `500`, which pages.
pub const ERR_HEAD_DAMAGED: BridgeError = BridgeError::Crypto("mgmt: tenant head damaged");

/// Whether `e` is [`ERR_HEAD_DAMAGED`].
pub fn head_damaged(e: &BridgeError) -> bool {
    matches!((e, &ERR_HEAD_DAMAGED), (BridgeError::Crypto(a), BridgeError::Crypto(b)) if a == b)
}
/// The root unit answered what the call never answers.
pub const ERR_UNIT_ANSWER: BridgeError = BridgeError::Invalid("mgmt: unexpected unit answer");
/// The router refused the call (any [`RouteRefusal`]).
pub const ERR_ROUTE: BridgeError = BridgeError::Invalid("mgmt: root unit not reachable");
/// The adapter of one tenant was asked for another.
pub const ERR_TENANT: BridgeError = BridgeError::Invalid("mgmt: adapter of another tenant");
/// A placed bucket the names read did not name.
pub const ERR_NAMES: BridgeError = BridgeError::Invalid("mgmt: bucket names incomplete");
/// The names of placed buckets cannot be read in this build.
pub const ERR_NO_NAMES: BridgeError =
    BridgeError::NotImplemented("mgmt: no bucket names read in this build");
/// An apply entry the root unit's wire has no form for yet (a marker
/// item, AM-62, comes with L1-4e).
pub const ERR_MARKER: BridgeError =
    BridgeError::NotImplemented("mgmt: the unit wire has no marker item yet");

const NO_SEQS: Seqs = Seqs {
    state_seq: 0,
    keys_seq: 0,
};

// ---------------------------------------------------------------------------
// TenantDoor
// ---------------------------------------------------------------------------

/// How a management write reads the tenant's state from its head.
/// `restoring` on any unit holds every write (`409 tenant_restoring`),
/// the root unit's included; a deletion or a `locked` hold refuses
/// opening writes, a `read_only` hold too (the unit decides which).
pub fn door_state(door: &Door) -> DoorState {
    match door.state() {
        TenantState::Provisioning => DoorState::Provisioning,
        TenantState::Shredding | TenantState::Shredded | TenantState::Deleting => {
            DoorState::Unavailable
        }
        _ if !door.restoring.is_empty() => DoorState::Restoring,
        TenantState::Suspended(crate::directory::record::HoldMode::Locked) => {
            DoorState::Unavailable
        }
        TenantState::Suspended(crate::directory::record::HoldMode::ReadOnly) => DoorState::ReadOnly,
        TenantState::Active => DoorState::Open,
    }
}

/// The names of buckets the root unit holds rows for (AM-57), in the
/// order asked; `None` for an id it holds no row for.
#[allow(async_fn_in_trait)]
pub trait BucketNames {
    async fn names(&self, tenant: &TenantId, ids: &[String]) -> Result<Vec<Option<String>>>;
}

/// No bucket names read in this build (L1-5's `RequestCall` is not
/// built): every read fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoBucketNames;

impl BucketNames for NoBucketNames {
    async fn names(&self, _: &TenantId, _: &[String]) -> Result<Vec<Option<String>>> {
        Err(ERR_NO_NAMES)
    }
}

/// [`TenantDoor`] over the tenant's verified head (door part only).
pub struct HeadDoor<'a, H, N> {
    pub heads: &'a H,
    pub names: &'a N,
}

impl<H: TenantHeads, N: BucketNames> HeadDoor<'_, H, N> {
    /// The verified head; `None`: the tenant has no chain.
    pub async fn head(&self, tenant: &TenantId) -> Result<Option<Door>> {
        self.heads.head(tenant, 0).await.map_err(|e| match e {
            ChainError::Damaged(why) => {
                // Fixed words only: the reason is a static string.
                crate::trace::alert(|| format!("mgmt: tenant head damaged ({why})"));
                ERR_HEAD_DAMAGED
            }
            ChainError::PrivateUnreadable => {
                crate::trace::alert(|| "mgmt: tenant head private part unreadable".to_string());
                ERR_HEAD_DAMAGED
            }
            _ => ERR_HEAD,
        })
    }
}

impl<H: TenantHeads, N: BucketNames> crate::mgmt::tenant::TenantHeadRead for HeadDoor<'_, H, N> {
    async fn door(&self, tenant: &TenantId) -> Result<Option<Door>> {
        self.head(tenant).await
    }
}

impl<H: TenantHeads, N: BucketNames> TenantDoor for HeadDoor<'_, H, N> {
    async fn state(&self, tenant: &TenantId) -> Result<Option<DoorState>> {
        Ok(self.head(tenant).await?.as_ref().map(door_state))
    }

    async fn bucket_names(&self, tenant: &TenantId, ids: &[String]) -> Result<Vec<Option<String>>> {
        let Some(door) = self.head(tenant).await? else {
            return Ok(vec![None; ids.len()]);
        };
        let placed: Vec<bool> = ids
            .iter()
            .map(|id| door.placements.iter().any(|p| &p.bucket == id))
            .collect();
        let asked: Vec<String> = ids
            .iter()
            .zip(&placed)
            .filter(|(_, p)| **p)
            .map(|(id, _)| id.clone())
            .collect();
        if asked.is_empty() {
            return Ok(vec![None; ids.len()]);
        }
        let names = self.names.names(tenant, &asked).await?;
        if names.len() != asked.len() || names.iter().any(Option::is_none) {
            // The head places it and the unit holds no row: the unit is
            // behind its head (a `sync` is due), never "gone".
            return Err(ERR_NAMES);
        }
        let mut names = names.into_iter();
        Ok(placed
            .iter()
            .map(|p| if *p { names.next().flatten() } else { None })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// RootUnit (and the root unit's KeyTarget)
// ---------------------------------------------------------------------------

/// [`RootUnit`] over the request router. The client's pages, the
/// router's refusals that page (rule 7's "catalogue lost": a listed unit
/// of a `live` tenant that is unborn) and the client's "renew in the
/// background" come back with every call; the Worker logs the pages and
/// the alerts as alerts and runs the renewal under `waitUntil`
/// ([`RoutedUnit::take_pages`], [`RoutedUnit::take_alerts`],
/// [`RoutedUnit::renew_due`]).
pub struct RoutedUnit<'a, R> {
    pub router: &'a R,
    pages: RefCell<Vec<Page>>,
    alerts: RefCell<Vec<RouteRefusal>>,
    renew_due: Cell<bool>,
}

impl<'a, R: UnitRouter> RoutedUnit<'a, R> {
    pub fn new(router: &'a R) -> Self {
        RoutedUnit {
            router,
            pages: RefCell::new(Vec::new()),
            alerts: RefCell::new(Vec::new()),
            renew_due: Cell::new(false),
        }
    }

    /// The pages of every call so far (each one an alert).
    pub fn take_pages(&self) -> Vec<Page> {
        std::mem::take(&mut *self.pages.borrow_mut())
    }

    /// The router's refusals so far that page ([`RouteRefusal::alert`]).
    pub fn take_alerts(&self) -> Vec<RouteRefusal> {
        std::mem::take(&mut *self.alerts.borrow_mut())
    }

    fn noted(&self, r: RouteRefusal) -> RouteRefusal {
        if r.alert() {
            self.alerts.borrow_mut().push(r);
        }
        r
    }

    /// A unit asked for a background renewal.
    pub fn renew_due(&self) -> bool {
        self.renew_due.get()
    }

    /// The tenant's root unit.
    pub async fn route(&self, tenant: &TenantId) -> std::result::Result<Routed, RouteRefusal> {
        self.router.route(tenant, None, NO_SEQS).await
    }

    /// One Worker call to the root unit of `tenant`.
    pub async fn call(
        &self,
        tenant: &TenantId,
        op: UnitOp,
    ) -> std::result::Result<Answered, RouteRefusal> {
        let routed = self.route(tenant).await.map_err(|r| self.noted(r))?;
        let (answered, pages) = self.router.call(&routed, CallKind::Worker, true, op).await;
        self.pages.borrow_mut().extend(pages);
        match &answered {
            Ok(a) if a.renew_due => self.renew_due.set(true),
            Ok(_) => {}
            Err(r) => {
                self.noted(*r);
            }
        }
        answered
    }

    /// The root unit's key-chain apply, as L4's writer calls it.
    pub fn keys(&self, tenant: TenantId) -> RootKeys<'_, 'a, R> {
        RootKeys { unit: self, tenant }
    }
}

impl<R: UnitRouter> RootUnit for RoutedUnit<'_, R> {
    async fn reserve(&self, tenant: &TenantId, op: &UnitOp) -> Result<ReserveAnswer> {
        if !matches!(op, UnitOp::Reserve { .. }) {
            return Err(BridgeError::Invalid("mgmt: not a reservation ask"));
        }
        Ok(match self.call(tenant, op.clone()).await {
            Ok(answered) => reserve_answer(&answered.reply.answer),
            // A shredding tenant: the tenant-state answer, read from the
            // head again by the call.
            Err(RouteRefusal::AccountProblem) => ReserveAnswer::AccountProblem,
            Err(_) => ReserveAnswer::Unavailable,
        })
    }

    async fn release(&self, tenant: &TenantId, rid: &UnitRid) -> Result<()> {
        match self.call(tenant, UnitOp::Release { rid: *rid }).await {
            Ok(Answered {
                reply:
                    crate::unit::UnitReply {
                        answer: UnitAnswer::Ok { .. },
                        ..
                    },
                ..
            }) => Ok(()),
            Ok(_) => Err(ERR_UNIT_ANSWER),
            Err(_) => Err(ERR_ROUTE),
        }
    }
}

/// The root unit of one tenant as a [`KeyTarget`] of L4's writer: the
/// key-chain apply (`ApplyKeys`), with the answers it keeps (AM-38).
pub struct RootKeys<'u, 'a, R> {
    unit: &'u RoutedUnit<'a, R>,
    tenant: TenantId,
}

fn unit_access(a: ChainAccess) -> UnitAccess {
    match a {
        ChainAccess::Ro => UnitAccess::Ro,
        ChainAccess::Rw => UnitAccess::Rw,
    }
}

fn chain_access(a: UnitAccess) -> ChainAccess {
    match a {
        UnitAccess::Ro => ChainAccess::Ro,
        UnitAccess::Rw => ChainAccess::Rw,
    }
}

fn unit_status(s: ChainStatus) -> UnitStatus {
    match s {
        ChainStatus::Active => UnitStatus::Active,
        ChainStatus::Disabled => UnitStatus::Disabled,
        ChainStatus::Revoked => UnitStatus::Revoked,
    }
}

/// An item of the key table in the unit's wire form: the composition
/// root's mapping (`root::feed::unit_item`, L6-5b), so the request path's
/// feed and this adapter send the same bytes. A held subject, of either
/// held form, goes `held` with no secret and no grant limit; an
/// [`ApplyEntry::Held`] keeps its `owner_ref` (AM-72); a marker is a
/// marker item.
pub fn unit_entry(entry: &ApplyEntry) -> Result<crate::unit::keys::ApplyEntry> {
    crate::root::feed::unit_item(entry)
}

fn unit_kept(a: &ChainKept) -> UnitKept {
    UnitKept {
        rid: UnitRid(a.rid.0),
        status: a.status,
        body: a.body.clone(),
    }
}

impl<R: UnitRouter> RootKeys<'_, '_, R> {
    async fn send(&self, op: UnitOp) -> Result<UnitAnswer> {
        self.unit
            .call(&self.tenant, op)
            .await
            .map(|a| a.reply.answer)
            .map_err(|_| ERR_ROUTE)
    }

    async fn apply_with(
        &self,
        from_seq: u64,
        entries: &[ApplyEntry],
        answers: &[ChainKept],
    ) -> Result<Applied> {
        let entries = entries.iter().map(unit_entry).collect::<Result<Vec<_>>>()?;
        let answers = answers.iter().map(unit_kept).collect();
        match self
            .send(UnitOp::ApplyKeys {
                from_seq,
                entries,
                answers,
            })
            .await?
        {
            UnitAnswer::Ok { seqs, .. } => Ok(Applied::Done {
                keys_seq: seqs.keys_seq,
            }),
            UnitAnswer::KeysBehind { seqs } => Ok(Applied::Behind {
                keys_seq: seqs.keys_seq,
            }),
            _ => Err(ERR_UNIT_ANSWER),
        }
    }
}

impl<R: UnitRouter> KeyTarget for RootKeys<'_, '_, R> {
    fn label(&self) -> &str {
        "root"
    }

    /// The unit's `keys_seq`, from its answer to `HeldKeys` (a read-only
    /// Worker call; `Ping` is a request call, which the unit refuses as
    /// a Worker's).
    async fn keys_seq(&self) -> Result<u64> {
        match self.send(UnitOp::HeldKeys {}).await? {
            UnitAnswer::Ok { seqs, .. } => Ok(seqs.keys_seq),
            _ => Err(ERR_UNIT_ANSWER),
        }
    }

    async fn closed(&self) -> Result<Vec<String>> {
        match self.send(UnitOp::HeldKeys {}).await? {
            UnitAnswer::Ok { body, .. } => body
                .get("held")
                .cloned()
                .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
                .ok_or(ERR_UNIT_ANSWER),
            _ => Err(ERR_UNIT_ANSWER),
        }
    }

    async fn apply(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied> {
        self.apply_with(from_seq, entries, &[]).await
    }

    async fn apply_kept(
        &self,
        from_seq: u64,
        entries: &[ApplyEntry],
        answers: &[ChainKept],
    ) -> Result<Applied> {
        self.apply_with(from_seq, entries, answers).await
    }
}

// ---------------------------------------------------------------------------
// PrincipalChain
// ---------------------------------------------------------------------------

/// [`PrincipalChain`] over L4's writer of one tenant ([`KeyEnv`]). It
/// keeps the key table between the calls of one request (each call brings
/// it to the chain's head first) and the random source the writer seals
/// with.
pub struct KeyChain<'e, 'a, S, K, T, A, I, U, D, C, G, R> {
    pub env: &'e KeyEnv<'a, S, K, T, A, I, U, D, C, G>,
    table: RefCell<Option<KeyTable>>,
    rng: RefCell<Option<R>>,
}

impl<'e, 'a, S, K, T, A, I, U, D, C, G, R> KeyChain<'e, 'a, S, K, T, A, I, U, D, C, G, R> {
    pub fn new(env: &'e KeyEnv<'a, S, K, T, A, I, U, D, C, G>, rng: R) -> Self {
        KeyChain {
            env,
            table: RefCell::new(None),
            rng: RefCell::new(Some(rng)),
        }
    }

    /// With a key table of the tenant read earlier (an isolate's cache):
    /// each call brings it to the chain's head first.
    pub fn with_table(
        env: &'e KeyEnv<'a, S, K, T, A, I, U, D, C, G>,
        table: KeyTable,
        rng: R,
    ) -> Self {
        KeyChain {
            env,
            table: RefCell::new(Some(table)),
            rng: RefCell::new(Some(rng)),
        }
    }

    /// The key table as the last call left it (to keep for the next
    /// request of the isolate).
    pub fn into_table(self) -> Option<KeyTable> {
        self.table.into_inner()
    }
}

/// A principal create's subject: kind `principal`, active, no secret, the
/// `owner_ref` and the grants in the private part, plain grants only.
pub fn principal_subject(p: &NewPrincipal) -> Subject {
    Subject {
        door: SubjectDoor {
            id: p.id.clone(),
            kind: SubjectKind::Principal,
            status: ChainStatus::Active,
            made_by: p.made_by.clone(),
            grants: p
                .grants
                .iter()
                .map(|g| DoorGrant {
                    bucket_id: g.bucket_id.clone(),
                    access: chain_access(g.access),
                    expires_at: g.expires_at,
                })
                .collect(),
            created_at: u64::try_from(p.created_at.0).unwrap_or(0),
            secret_kek_version: None,
        },
        private: SubjectPrivate {
            owner_ref: Some(p.owner_ref.clone()),
            label: None,
            grants: p
                .grants
                .iter()
                .map(|g| PrivateGrant {
                    bucket_id: g.bucket_id.clone(),
                    prefix: g.prefix.clone(),
                    ip_list: g.ip_list.clone(),
                })
                .collect(),
            secret_wrapped: None,
        },
    }
}

/// A principal as the key table holds it; `None` when the entry is not a
/// principal whose private part is open (no `owner_ref` to name).
pub fn recorded(entry: &Entry) -> Option<RecordedPrincipal> {
    if entry.door.kind != SubjectKind::Principal {
        return None;
    }
    let private = entry.private.as_ref()?;
    let grants = entry
        .door
        .grants
        .iter()
        .zip(&private.grants)
        .map(|(d, p)| KeyGrant {
            bucket_id: d.bucket_id.clone(),
            access: unit_access(d.access),
            expires_at: d.expires_at,
            prefix: p.prefix.clone(),
            ip_list: p.ip_list.clone(),
        })
        .collect();
    Some(RecordedPrincipal {
        id: entry.door.id.clone(),
        owner_ref: private.owner_ref.clone()?,
        status: unit_status(entry.door.status),
        grants,
    })
}

/// The contract code of a refusal of L4's writer for a principal create.
/// A refusal that no correct create meets (an id that exists, a subject
/// that is not there, a route) is `internal_error`.
pub fn refusal_code(r: Refusal) -> Code {
    match r {
        Refusal::CapFull => Code::CapReached,
        Refusal::NotSubset => Code::GrantNotHeld,
        Refusal::GrantLimitsNotServed => Code::GrantLimitsNotServed,
        Refusal::GrantCap => Code::GrantLimitReached,
        Refusal::CreatorNotActive => Code::ActingPrincipalInactive,
        Refusal::Conflict | Refusal::NotFound | Refusal::IdTaken => Code::InternalError,
    }
}

impl<S, K, T, A, I, U, D, C, G, R> KeyChain<'_, '_, S, K, T, A, I, U, D, C, G, R>
where
    S: RecordStore,
    K: Kek,
    T: TkRing,
    A: KeyAdmission,
    I: ControlIntents,
    U: KeyTarget,
    D: KeyTarget,
    C: Clock,
    G: MoveGate,
    R: FillRandom,
{
    fn check(&self, tenant: &TenantId) -> Result<()> {
        match self.env.tenant.as_str() == tenant.as_str() {
            true => Ok(()),
            false => Err(ERR_TENANT),
        }
    }

    /// The table, taken out for one call (no borrow is held across an
    /// await); [`Self::put_back`] returns it. A first call reads the chain
    /// from its newest checkpoint that holds (ADR §8.5), not from seq 1;
    /// the writer then brings it to the head.
    async fn take_table(&self) -> Result<KeyTable> {
        let held = self.table.borrow_mut().take();
        match held {
            // A table of another tenant is never used (`with_table`).
            Some(table) if table.tenant() != self.env.tenant => Err(ERR_TENANT),
            Some(table) => Ok(table),
            None => {
                Ok(
                    read_key_chain(self.env.store, self.env.kek, self.env.ring, self.env.tenant)
                        .await?
                        .table,
                )
            }
        }
    }

    fn put_back(&self, table: KeyTable) {
        *self.table.borrow_mut() = Some(table);
    }

    /// The table's principal `id`, as [`ChainWrite::Done`] states it; a
    /// subject the table does not state as an open principal is not done.
    fn done(table: &KeyTable, id: &str) -> ChainWrite {
        match table.get(id).and_then(recorded) {
            Some(p) => ChainWrite::Done(p),
            None => ChainWrite::Unfinished,
        }
    }
}

impl<S, K, T, A, I, U, D, C, G, R> PrincipalChain for KeyChain<'_, '_, S, K, T, A, I, U, D, C, G, R>
where
    S: RecordStore,
    K: Kek,
    T: TkRing,
    A: KeyAdmission,
    I: ControlIntents,
    U: KeyTarget,
    D: KeyTarget,
    C: Clock,
    G: MoveGate,
    R: FillRandom,
{
    async fn carrying(
        &self,
        tenant: &TenantId,
        rid: &UnitRid,
        above: u64,
    ) -> Result<Option<RecordedPrincipal>> {
        self.check(tenant)?;
        let mut table = self.take_table().await?;
        let found = self.env.carrying(&mut table, &ChainRid(rid.0), above).await;
        let out = match found {
            // A record of the reservation names a subject the table does
            // not state as a principal: not this call's create.
            Ok(Some(c)) => {
                table
                    .get(&c.id)
                    .and_then(recorded)
                    .map(Some)
                    .ok_or(BridgeError::Invalid(
                        "mgmt: a record of the reservation is no principal",
                    ))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        };
        self.put_back(table);
        out
    }

    async fn finish(&self, tenant: &TenantId, id: &str) -> Result<ChainWrite> {
        self.check(tenant)?;
        let mut table = self.take_table().await?;
        let found = self.env.finish_subject(&mut table, id).await;
        let out = match found {
            Ok(Finished::Done { .. }) => Ok(Self::done(&table, id)),
            Ok(Finished::Unfinished) => Ok(ChainWrite::Unfinished),
            Ok(Finished::NotHeld) => Ok(ChainWrite::Busy),
            Err(e) => Err(e),
        };
        self.put_back(table);
        out
    }

    async fn create(
        &self,
        tenant: &TenantId,
        principal: &NewPrincipal,
        answer: &UnitKept,
    ) -> Result<ChainWrite> {
        self.check(tenant)?;
        if answer.rid != principal.rid || principal.seq == 0 {
            return Err(BridgeError::Invalid(
                "mgmt: the create is not its reservation's",
            ));
        }
        let mut table = self.take_table().await?;
        let Some(mut rng) = self.rng.borrow_mut().take() else {
            self.put_back(table);
            return Err(BridgeError::Invalid("mgmt: no random source"));
        };
        let subject = principal_subject(principal);
        let kept = ChainKept {
            rid: ChainRid(answer.rid.0),
            status: answer.status,
            body: answer.body.clone(),
        };
        let reserved = Reserved {
            rid: ChainRid(principal.rid.0),
            keys_seq: principal.seq - 1,
            answer: &kept,
        };
        let written = self
            .env
            .create_reserved(&mut table, &subject, reserved, &mut rng)
            .await;
        *self.rng.borrow_mut() = Some(rng);
        let out = match written {
            Ok(ReservedAnswer::Done { .. }) => Ok(Self::done(&table, &principal.id)),
            Ok(ReservedAnswer::Unfinished { .. }) => Ok(ChainWrite::Unfinished),
            Ok(ReservedAnswer::Lost) => Ok(ChainWrite::Lost),
            Ok(ReservedAnswer::Busy | ReservedAnswer::Frozen) => Ok(ChainWrite::Busy),
            Ok(ReservedAnswer::KeyMoved) => Ok(ChainWrite::Refused(Code::KeyMoved)),
            Ok(ReservedAnswer::Refused(r)) => Ok(ChainWrite::Refused(refusal_code(r))),
            // Answers of `change_reserved` only; a create never gets one.
            Ok(ReservedAnswer::InHead { .. } | ReservedAnswer::Closes) => {
                Err(BridgeError::Invalid("mgmt: a create got a change's answer"))
            }
            Err(e) => Err(e),
        };
        self.put_back(table);
        out
    }
}

// ---------------------------------------------------------------------------
// ControlIntents over the queue and the directory
// ---------------------------------------------------------------------------

/// [`ControlIntents`] of the Worker: the queue message
/// `apply_control(tenant, chain, seq)` is the durable part, sent through
/// the root's [`ControlSend`](crate::root::ControlSend) with its delay; the
/// directory's `pending_ops` row is its visible copy, noted and cleared
/// only while `DIRECTORY` is bound (AM-75: with it unbound there is no row
/// to keep, and the message alone finishes the change).
pub struct QueueIntents<'a, C, Q, T> {
    pub control: &'a C,
    pub directory: Option<crate::directory::store::SqlDirectory<'a, Q>>,
    pub clock: &'a T,
}

/// A tenant id that is no managed tenant (tenant 0 has no intents here).
pub const ERR_INTENT_TENANT: BridgeError =
    BridgeError::Invalid("mgmt: an intent for a tenant that is not managed");

fn intent_chain(chain: crate::keys::ports::ControlChain) -> crate::jobmsg::IntentChain {
    match chain {
        crate::keys::ports::ControlChain::Tenant => crate::jobmsg::IntentChain::Tenant,
        crate::keys::ports::ControlChain::Keys => crate::jobmsg::IntentChain::Keys,
    }
}

fn row_chain(chain: crate::keys::ports::ControlChain) -> crate::directory::store::ChainKind {
    match chain {
        crate::keys::ports::ControlChain::Tenant => crate::directory::store::ChainKind::Tenant,
        crate::keys::ports::ControlChain::Keys => crate::directory::store::ChainKind::Keys,
    }
}

impl<C, Q, T> ControlIntents for QueueIntents<'_, C, Q, T>
where
    C: crate::root::ControlSend,
    Q: crate::ports::Sql,
    T: Clock,
{
    async fn send(
        &self,
        tenant: &crate::TenantId,
        chain: crate::keys::ports::ControlChain,
        seq: u64,
    ) -> Result<()> {
        let intent = crate::jobmsg::ControlIntent::new(tenant.as_str(), intent_chain(chain), seq)
            .ok_or(ERR_INTENT_TENANT)?;
        self.control.send_control(&intent).await
    }

    async fn note(
        &self,
        tenant: &crate::TenantId,
        chain: crate::keys::ports::ControlChain,
        seq: u64,
        kind: &str,
    ) -> Result<()> {
        let Some(dir) = &self.directory else {
            return Ok(());
        };
        dir.add_pending(&crate::directory::store::PendingOp {
            tenant: crate::directory::record::Tenant::Managed(tenant.clone()),
            chain: row_chain(chain),
            seq,
            kind: kind.to_string(),
            created_at: self.clock.now(),
        })
        .await
    }

    async fn clear(
        &self,
        tenant: &crate::TenantId,
        chain: crate::keys::ports::ControlChain,
        seq: u64,
    ) -> Result<()> {
        let Some(dir) = &self.directory else {
            return Ok(());
        };
        dir.clear_pending(
            &crate::directory::record::Tenant::Managed(tenant.clone()),
            row_chain(chain),
            seq,
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_map_to_contract_codes() {
        assert_eq!(refusal_code(Refusal::CapFull), Code::CapReached);
        assert_eq!(refusal_code(Refusal::NotSubset), Code::GrantNotHeld);
        assert_eq!(refusal_code(Refusal::IdTaken), Code::InternalError);
    }

    #[test]
    fn a_marker_is_a_marker_item() {
        assert!(matches!(
            unit_entry(&ApplyEntry::Marker {
                seq: 3,
                marker: crate::keys::record::Marker::KeysFrozen,
            }),
            Ok(crate::unit::keys::ApplyEntry::Marker(m)) if m.seq == 3
        ));
    }
}
