//! The move's flip, its give-up before the flip, and the exit that every
//! give-up ends with (DS1 §3.4 step 8, §3.8; AM-15, AM-16, AM-23, AM-30,
//! AM-31).
//!
//! The flip runs after the verify (step 7). Before it writes anything it
//! checks the whole window: tenant 0 `moving` into the owner, the frozen
//! catalogue carrying this window's marker, the owner's `restoring` entry
//! of this window (or its lift), the owner's placements against the
//! frozen D1's buckets (DS1 §3.5, [`placement_check`]), and for every
//! moved key a route record that is absent or names the owner and a
//! directory row on tenant 0 or the owner. A key that would stop the flip
//! halfway therefore stops it before (a), while the give-up is still
//! open. Then, in this order, each sub-step reading what is there first,
//! so a crash anywhere is finished by running [`flip`] again:
//!
//! - **(a)** the legacy stamp on the frozen catalogue
//!   ([`super::fence::put_legacy_stamp`]): from here every destructive act
//!   on the frozen D1 is fenced for good;
//! - **(b)** the move's lift (AM-15). The revocation sweep runs first
//!   ([`super::move_keys::revocation_sweep`], AM-31). The tool opens a
//!   gate report of kind `move` on the unit, `replay_id` = (S, the unit's
//!   stamp ordinal, a nonce) where S is the `since_seq` of unit 0's entry,
//!   closed complete with no blocker; reads `GateStatus`, which must pass
//!   for that report (else a new report with a new nonce); writes one
//!   owner record that lifts the entry with the report's `LiftProof`; then
//!   `sync` with that proof and `renew`. If the head already lacks the
//!   entry, no report is opened: `sync` runs with the lift record's proof
//!   as it stands. A refused `sync` re-enters: a new `restoring` entry for
//!   unit 0, the unit synced to it, and (b) again under the new S. (c)
//!   waits until `sync` answers ok;
//! - **(b1)** the move floor (AM-67): once the unit's own
//!   `restoring_since` is empty, the unit's `lifted_at` (from
//!   `ImportProgress`) goes into the owner's record as `move_floors[0]`
//!   ([`super::chain::TenantChain::set_move_floor`]). (b2) and (c) run only
//!   once the head holds a floor at or above it, so no time restore can
//!   reach into the seal-to-lift span after the flip; a unit that does not
//!   say its `lifted_at` stops the flip here;
//! - **(b2)** V9 through the open unit (AM-30): a failure stops the flip
//!   here, and the tool gives up ([`give_up`]);
//! - **(c)** the owner's key chain applied to the unit once more and the
//!   directory's `keys_seq` for the owner raised to at least the unit's
//!   (AM-16); then for every moved key its route record `m/kr/<akid>`
//!   naming the owner ([`RouteRecords::put`]), then the directory's
//!   `key_routes` row ([`super::store::SqlDirectory::move_route`]);
//! - **(d)** one tenant-0 record: `moved`, at the legacy stamp's counter;
//!   then the directory's copy of tenant 0's selector (AM-20).
//!
//! [`give_up`] is the way back while tenant 0 is still `moving`, in the
//! order of DS1 §3.8 row 8 and AM-23: the owner's unit closed again, the
//! route records that name the owner put back on tenant 0 by the
//! conditional replace of DS1 §2.2 ([`RouteRecords::replace`]), the
//! directory rows back, tenant 0's record back to `d1` (and the
//! directory's copy of it), then the grant revocations on the moved-in
//! buckets and `UnplaceMovedBuckets` ([`exit_placements`]). A V9 failure
//! at (b2) writes tenant 0's `d1` record first and then runs the same
//! give-up, so no later run of the flip samples V9 again.
//! The rest of the give-up (empty the unit, thaw and level the frozen D1,
//! the revocations of [`super::move_keys::revocations_to_d1`], migrations
//! on, the lift) are tool steps outside this module.
//!
//! The actors are the planes the tool holds for each record: the move
//! tool lifts the owner's entry with its `move` report and writes tenant
//! 0's records and the placements; the operator sets a `restoring` entry.

use std::collections::BTreeSet;

use super::chain::{ChainError, ControlSeal, TenantChain, Written};
use super::fence::{legacy_stamp_key, marker, put_legacy_stamp, stamp_row};
use super::move_keys::{apply_owner_keys, revocation_sweep, KeyStepError, KeyUnit, OwnerKeys};
use super::record::{Lifecycle, Selector, Tenant, TenantDoor};
use super::store::{RouteKind, SqlDirectory};
use super::transition::{Actor, Change, MAX_MOVED_BUCKETS};
use crate::ports::{BlobStore, Clock, Sql, SqlValue};
use crate::records::RecordStore;
use crate::types::{BridgeError, UnixMs};
use crate::unit::call::Refused as UnitRefused;
use crate::unit::lift::{GateRefusal, LiftProof, ReplayId};

/// Why the flip or the give-up stopped. Every sub-step it finished stays
/// finished and is found again by the next run.
#[derive(Debug)]
pub enum FlipError {
    Store(BridgeError),
    Chain(ChainError),
    /// A key step (the sweep, the key apply) stopped.
    Keys(KeyStepError),
    /// Tenant 0's head is not this move's window (or, for the flip, its
    /// flip): `moving` (or `moved`) into the owner.
    NotThisMove,
    /// The owner's root unit has a `restoring` entry of another window.
    OtherWindow {
        since_seq: u64,
    },
    /// A route record names another tenant: the key is not the owner's.
    RouteTaken(String),
    /// A directory route row names neither tenant 0 nor the owner, or is
    /// missing.
    RouteRow(String),
    /// The frozen catalogue does not carry this window's cutover marker.
    Marker,
    /// The owner has no live directory row to move routes to.
    OwnerRow,
    /// The owner's placements are not the frozen D1's buckets less the
    /// excluded ones (DS1 §3.5): `missing` are not placed, `extra` are
    /// placed and not moved (or placed on another unit).
    Placements {
        missing: Vec<String>,
        extra: Vec<String>,
    },
    /// The unit refused the `move` report.
    Report(GateRefusal),
    /// `GateStatus` did not pass for a fresh `move` report.
    LiftNotOk,
    /// The unit refused `sync`: a closing record, a refusal that is not
    /// the gate's, or the gate's after [`MAX_REENTRIES`] re-entries.
    SyncRefused(UnitRefused),
    /// V9 failed in the open unit; the move was given up (AM-30).
    V9Failed,
    /// V9 failed, and the give-up it started stopped with this error: run
    /// [`give_up`] again.
    V9GiveUp(Box<FlipError>),
    /// The owner's unit is open, but it does not say when the move's lift
    /// landed (`ImportProgress.lifted_at`), or it still has a `restoring`
    /// entry: no floor can be written, so (b2) and (c) do not run.
    NoLiftTime,
    /// The owner's head does not hold the move floor (b1) wrote.
    FloorMissing,
    /// The unit's import is not this window's sealed import: not sealed
    /// under `flips + 1`, or bound below the window's record `zero_seq`
    /// (a given-up window's, whose unit was not emptied).
    NotThisImport,
    /// The frozen D1 has no bucket to move (less the excluded ones): there
    /// is nothing a flip could serve, and a give-up would have no
    /// placement to keep its exit open.
    NothingMoved,
}

impl From<BridgeError> for FlipError {
    fn from(e: BridgeError) -> Self {
        FlipError::Store(e)
    }
}

impl From<ChainError> for FlipError {
    fn from(e: ChainError) -> Self {
        FlipError::Chain(e)
    }
}

impl From<KeyStepError> for FlipError {
    fn from(e: KeyStepError) -> Self {
        FlipError::Keys(e)
    }
}

/// The unit's answer to `sync`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Synced {
    Ok,
    /// Refused: `gate` (the in-unit lift check: re-enter), `stale_sync`
    /// (read the head again), `keys_not_applied` (apply the keys, send
    /// again), or another reason (stop).
    Refused(UnitRefused),
}

/// The unit's answer to the `move` report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reported {
    /// Opened (`GateOpenMove`) and closed complete with no blocker
    /// (`GateReport`).
    Done,
    /// Refused (`move_not_bound`, `import_not_sealed`,
    /// `stamp_not_levelled`, `not_restoring`).
    Refused(GateRefusal),
}

/// What `GateStatus` says of the stored report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GateView {
    /// The stored report's replay id, if a report is stored.
    pub replay_id: Option<ReplayId>,
    /// The stored report is of kind `move`.
    pub kind_move: bool,
    /// A lift would pass now.
    pub lift_ok: bool,
    /// The proof a lift record must carry for it.
    pub proof: Option<LiftProof>,
}

/// The owner's root unit, as step 8 calls it (the unit calls of L1's
/// package 4 through the Worker's stub fetch).
#[allow(async_fn_in_trait)]
pub trait OwnerUnit: KeyUnit {
    /// `sync` with the owner's verified head `owner`. `lift`: for a head
    /// without unit 0's entry, the proof of the newest record of this
    /// window that lifted it (that record, or one below `owner`); `None`
    /// for a head that has the entry. The unit lifts when its own check
    /// gives that proof; a refusal comes back as [`Synced::Refused`].
    async fn sync(
        &self,
        owner: &TenantDoor,
        lift: Option<&LiftProof>,
    ) -> crate::types::Result<Synced>;
    /// `renew`.
    async fn renew(&self) -> crate::types::Result<()>;
    /// The unit's own `restoring_since` (`Ping` or `GateStatus`): `None`
    /// once the lift landed.
    async fn restoring_since(&self) -> crate::types::Result<Option<u64>>;
    /// The unit's stamp counter (`GateStatus.stamp_counter`, `null` = 0):
    /// the ordinal a `move` report names.
    async fn stamp_ordinal(&self) -> crate::types::Result<u64>;
    /// Opens a gate report of kind `move` with `replay_id` and closes it
    /// complete with no blocker (AM-15), passing tenant 0's verified head
    /// `zero` under the rule-5 check.
    async fn report_move(
        &self,
        zero: &TenantDoor,
        replay_id: &ReplayId,
    ) -> crate::types::Result<Reported>;
    /// `GateStatus`.
    async fn gate_status(&self) -> crate::types::Result<GateView>;
    /// The import the unit holds (`ImportProgress` and its tenant-0 seq),
    /// as [`super::move_copy::UnitImport::import_state`] reads it.
    async fn move_import(&self) -> crate::types::Result<Option<super::move_copy::ImportState>>;
    /// V9 (AM-30): the sampled reads through the open unit's read plan,
    /// signed by a moved key; `true` when every one passed.
    async fn v9(&self) -> crate::types::Result<bool>;
    /// A new nonce for a replay id: random, at most
    /// [`crate::unit::lift::MAX_NONCE`] bytes.
    fn nonce(&self) -> String;
}

/// The route records `m/kr/<akid>`.
#[allow(async_fn_in_trait)]
pub trait RouteRecords {
    /// Puts the route of `akid` (of `kind`, from its directory row) to
    /// `tenant`, or finds it there. `false` = the record names another
    /// tenant.
    async fn put(&self, akid: &str, tenant: &Tenant, kind: RouteKind)
        -> crate::types::Result<bool>;
    /// The tenant the route record of `akid` names; `None` = no record.
    async fn get(&self, akid: &str) -> crate::types::Result<Option<String>>;
    /// The ETag-conditional replace of DS1 §2.2: the record of `akid` that
    /// names `from` now names `to` with `kind` (from the key's directory
    /// row; a later window's keymap may change it), or already names `to`.
    /// `false` = it names a third tenant (or no record exists).
    async fn replace(
        &self,
        akid: &str,
        from: &Tenant,
        to: &Tenant,
        kind: RouteKind,
    ) -> crate::types::Result<bool>;
}

/// The move a flip or a give-up acts on.
pub struct Window<'a> {
    /// The owner's tenant.
    pub owner: &'a Tenant,
    /// The seq of a tenant-0 record of this window: `moving` into the
    /// owner, at or below the copy's `MoveHead.seq` (the window's first
    /// record is best; [`super::move_copy::bound`] answers the head the
    /// copy ran under). The unit's import must be bound at or above it. The window is the run of `moving` records from it;
    /// a record that ends the run (`d1`, `moved`) ends the window, so a run
    /// of an older window never acts on a later one.
    pub zero_seq: u64,
    /// The `since_seq` of the owner's root-unit `restoring` entry that the
    /// window set (the copy's [`super::move_copy::bound`]). A re-entry of
    /// the lift sets a later one, which is this window's too.
    pub since: u64,
    /// Every moved key id.
    pub keys: &'a [String],
    /// The bucket ids that stay in the frozen D1 (the `keymap`'s excluded
    /// set, the canary).
    pub excluded: &'a BTreeSet<String>,
}

/// What the flip did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flipped {
    /// The legacy stamp's counter, named by the `moved` record.
    pub stamp: u64,
    /// Whether this run wrote the `moved` record (`false`: found).
    pub wrote: bool,
}

/// The most tenant-0 records one window may hold: the walk of
/// [`window_state`] reads each. The owner's records of one window are
/// walked under the same bound.
pub const MAX_WINDOW_RECORDS: u64 = 256;

/// How often (b) re-enters through a new `restoring` entry after a
/// refused `sync`.
pub const MAX_REENTRIES: u32 = 3;

/// How often a failed V9 tries tenant 0's `d1` record.
pub const V9_GIVE_UP_TRIES: u32 = 3;

/// How many `move` reports (b) opens before it stops.
pub const REPORT_TRIES: u32 = 2;

/// Where this window stands, from tenant 0's chain.
// Short-lived: made and matched in one call, never stored.
#[allow(clippy::large_enum_variant)]
enum WindowState {
    /// Open: tenant 0's head, `moving` into the owner.
    Open(TenantDoor),
    /// Flipped, at this stamp.
    Flipped(u64),
    /// Given up; the catalogue the window froze.
    GivenUp(String),
}

/// Walks tenant 0's records from `window.zero_seq` to the head: a run of
/// `moving` records into the owner, then at most one record that ended it.
async fn window_state<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    window: &Window<'_>,
) -> Result<WindowState, FlipError> {
    let head = chain
        .head(&Tenant::Zero, 0)
        .await?
        .ok_or(FlipError::NotThisMove)?
        .door;
    if head.seq < window.zero_seq || head.seq - window.zero_seq >= MAX_WINDOW_RECORDS {
        return Err(FlipError::NotThisMove);
    }
    let mut frozen: Option<String> = None;
    let mut given_up = false;
    for seq in window.zero_seq..=head.seq {
        let door = match seq == head.seq {
            true => head.clone(),
            false => {
                chain
                    .read(&Tenant::Zero, seq)
                    .await?
                    .ok_or(FlipError::Chain(ChainError::Damaged(
                        "window_record_missing",
                    )))?
                    .door
            }
        };
        let z = door.tenant_zero.as_ref().ok_or(FlipError::NotThisMove)?;
        if given_up {
            // After the give-up only records of no window may follow: a
            // later window must not be steered by this one's answer.
            if z.selector != Selector::D1 || (z.moved.is_some() && !z.undone()) {
                return Err(FlipError::NotThisMove);
            }
            if seq == head.seq {
                break;
            }
            continue;
        }
        let to_owner = z.moved.as_ref().filter(|m| m.to == *window.owner);
        match (z.selector, to_owner, &frozen) {
            (Selector::Moving, Some(m), _) => {
                frozen = Some(m.catalogue_id_frozen.clone());
                if seq == head.seq {
                    return Ok(WindowState::Open(door));
                }
            }
            (Selector::Moved, Some(m), Some(_)) => {
                return m
                    .stamp
                    .map(WindowState::Flipped)
                    .ok_or(FlipError::NotThisMove)
            }
            (Selector::D1, _, Some(_)) => given_up = true,
            _ => return Err(FlipError::NotThisMove),
        }
    }
    match (given_up, frozen) {
        (true, Some(f)) => Ok(WindowState::GivenUp(f)),
        _ => Err(FlipError::NotThisMove),
    }
}

async fn head_of<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    tenant: &Tenant,
) -> Result<TenantDoor, FlipError> {
    Ok(chain
        .head(tenant, 0)
        .await?
        .ok_or(FlipError::Chain(ChainError::Refused(
            super::transition::Refusal {
                status: 409,
                code: "no_tenant",
            },
        )))?
        .door)
}

fn door_of(written: Written) -> TenantDoor {
    match written {
        Written::Wrote(record) => record.door,
        Written::Unchanged(read) => read.door,
    }
}

/// Runs step 8, from wherever an earlier run stopped. `frozen` and
/// `safety` hold the frozen catalogue and its stamp; `dir` the directory;
/// `keys` the owner's key chain; `clock` the tool's clock, read at the
/// start and again for (b1), whose record is checked against the time the
/// unit's lift landed, later in the same run.
#[allow(clippy::too_many_arguments)]
pub async fn flip<S, C, F, B, Q, U, R, K, T>(
    chain: &TenantChain<'_, S, C>,
    frozen: &F,
    safety: &B,
    dir: &SqlDirectory<'_, Q>,
    unit: &U,
    routes: &R,
    keys: &K,
    window: &Window<'_>,
    clock: &T,
) -> Result<Flipped, FlipError>
where
    S: RecordStore,
    C: ControlSeal,
    F: Sql,
    B: BlobStore,
    Q: Sql,
    U: OwnerUnit,
    R: RouteRecords,
    K: OwnerKeys,
    T: Clock,
{
    let now = clock.now();
    let zero = match window_state(chain, window).await? {
        WindowState::Open(zero) => zero,
        // Flipped already: the directory's copy of the selector, which a
        // crash after the record may have missed; nothing else to do.
        WindowState::Flipped(stamp) => {
            dir.apply_tenant(&head_of(chain, &Tenant::Zero).await?, now)
                .await?;
            return Ok(Flipped {
                stamp,
                wrote: false,
            });
        }
        WindowState::GivenUp(_) => return Err(FlipError::NotThisMove),
    };
    let z = zero.tenant_zero.as_ref().expect("checked by window_state");
    let m = z.moved.as_ref().expect("checked by window_state");
    // The whole window is checked before the first write.
    let owner = head_of(chain, window.owner).await?;
    window_entry(chain, &owner, window).await?;
    let ordinal = z.flips.checked_add(1).and_then(|o| i64::try_from(o).ok());
    if ordinal.is_none() || marker(frozen).await? != ordinal {
        return Err(FlipError::Marker);
    }
    placement_check(frozen, &owner, window.excluded).await?;
    let kinds = routes_movable(dir, routes, window).await?;
    let routes_started = any_route_put(routes, window).await?;

    // (a) The legacy stamp, under the catalogue the window froze.
    let stamp = put_legacy_stamp(frozen, safety, &m.catalogue_id_frozen, now).await?;

    // (b) The owner's root unit opens through the move's lift.
    let owner = open_unit(chain, dir, unit, keys, &zero, window, now).await?;

    // (b1) The move floor, from the unit's own lift time, under a clock
    // read now: the lift may have landed minutes after the run began.
    move_floor(chain, dir, unit, &owner, clock.now()).await?;

    // (b2) V9, once the unit is open; a run that already put a route
    // passed it.
    // A failure gives the move up at once, tenant 0's record first, so no
    // later run samples V9 again and flips (AM-30, DS1 §3.8 row 7). No
    // route names the owner yet, so nothing reaches the open unit before
    // the give-up closes it.
    if !routes_started && !unit.v9().await? {
        // Every error from here keeps the V9 answer: a re-run finds the
        // window given up and cannot report the failing check again.
        // The `d1` record is tried a few times: until it lands, a re-run
        // would sample V9 again.
        let gave_up = async {
            let mut last = None;
            for _ in 0..V9_GIVE_UP_TRIES {
                // Each try checks that the window is still this one: a
                // give-up by another run ends the loop, a later window
                // stops it.
                match window_state(chain, window).await {
                    Ok(WindowState::GivenUp(_)) => {
                        last = None;
                        dir.apply_tenant(&head_of(chain, &Tenant::Zero).await?, now)
                            .await?;
                        break;
                    }
                    Ok(WindowState::Open(z)) if z.seq == zero.seq => {}
                    Ok(_) => return Err(FlipError::NotThisMove),
                    Err(e) => {
                        last = Some(e);
                        continue;
                    }
                }
                match chain
                    .write(
                        &Tenant::Zero,
                        &Change::GiveUpMove,
                        Actor::MoveTool,
                        now,
                        zero.seq,
                    )
                    .await
                {
                    Ok(written) => {
                        last = None;
                        dir.apply_tenant(&door_of(written), now).await?;
                        break;
                    }
                    Err(e) => last = Some(FlipError::Chain(e)),
                }
            }
            if let Some(e) = last {
                return Err(e);
            }
            give_up(chain, frozen, safety, dir, unit, routes, keys, window, now).await
        };
        return match gave_up.await {
            Ok(_) => Err(FlipError::V9Failed),
            Err(e) => Err(FlipError::V9GiveUp(Box::new(e))),
        };
    }

    // (c) The keys once more, the directory's keys_seq, then the routes:
    // the record first, then the directory row.
    let keys_seq = apply_owner_keys(keys, unit).await?;
    dir.raise_keys_seq(&owner.tenant, keys_seq).await?;
    let zero_tenant = Tenant::Zero;
    for (akid, kind) in window.keys.iter().zip(kinds) {
        let named = match routes.get(akid).await?.as_deref() == Some(Tenant::Zero.as_str()) {
            // An earlier window's give-up put it back on tenant 0.
            true => {
                routes
                    .replace(akid, &zero_tenant, window.owner, kind)
                    .await?
            }
            false => routes.put(akid, window.owner, kind).await?,
        };
        if !named {
            return Err(FlipError::RouteTaken(akid.clone()));
        }
        if !dir.move_route(akid, &zero_tenant, window.owner).await? {
            let row = dir.route(akid).await?;
            if !row.is_some_and(|r| r.tenant == *window.owner) {
                return Err(FlipError::RouteRow(akid.clone()));
            }
        }
    }

    // (d) Tenant 0: moved, at the stamp's counter, on the head this run
    // checked (a give-up and a new window in between stop it); then the
    // directory's copy of the selector.
    match window_state(chain, window).await? {
        WindowState::Open(now_zero) if now_zero.seq == zero.seq => {}
        _ => return Err(FlipError::NotThisMove),
    }
    let written = chain
        .write(
            &zero_tenant,
            &Change::FlipMove { stamp },
            Actor::MoveTool,
            now,
            zero.seq,
        )
        .await?;
    let wrote = matches!(written, Written::Wrote(_));
    dir.apply_tenant(&door_of(written), now).await?;
    Ok(Flipped { stamp, wrote })
}

/// Step 8(b1) (AM-67): after the unit says its entry is gone, its
/// `lifted_at` into the owner's `move_floors[0]`, by the chain's own
/// tenant-0 read. Answers the owner's head that holds the floor. Every run
/// of step 8 that finds the entry lifted passes here first; a repeat is
/// `Unchanged`.
async fn move_floor<S, C, Q, U>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    unit: &U,
    owner: &TenantDoor,
    now: UnixMs,
) -> Result<TenantDoor, FlipError>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
    U: OwnerUnit,
{
    if unit.restoring_since().await?.is_some() {
        return Err(FlipError::NoLiftTime);
    }
    let lifted_at = unit
        .move_import()
        .await?
        .and_then(|i| i.lifted_at)
        .ok_or(FlipError::NoLiftTime)?;
    let written = chain
        .set_move_floor(&owner.tenant, 0, lifted_at, Actor::MoveTool, now, owner.seq)
        .await?;
    let head = door_of(written);
    if !head.move_floors.get(&0).is_some_and(|f| *f >= lifted_at) {
        return Err(FlipError::FloorMissing);
    }
    dir.apply_tenant(&head, now).await?;
    Ok(head)
}

/// Step 8(b): the owner's unit 0 lifted by the move's report and synced
/// open (AM-15). Answers the owner's head the unit opened under.
async fn open_unit<S, C, Q, U, K>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    unit: &U,
    keys: &K,
    zero: &TenantDoor,
    window: &Window<'_>,
    now: UnixMs,
) -> Result<TenantDoor, FlipError>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
    U: OwnerUnit,
    K: OwnerKeys,
{
    for reentry in 0..=MAX_REENTRIES {
        let owner = head_of(chain, window.owner).await?;
        let (owner, proof) = match owner.restoring_entry(0) {
            Some(e) if e.since_seq >= window.since => {
                let since = e.since_seq;
                // The unit closed under this entry first: a re-entry that
                // stopped after its record left the unit on the old one,
                // and the report binds the unit's own entry.
                close_unit(unit, &owner).await?;
                // The import is this window's and sealed: a `move` report
                // would otherwise lift (and claim) another window's.
                let flips = zero.tenant_zero.as_ref().map(|z| z.flips);
                let ours = unit.move_import().await?.is_some_and(|i| {
                    i.sealed.is_some()
                        && i.sealed == flips.and_then(|f| f.checked_add(1))
                        && i.t0_seq.is_some_and(|t| t >= window.zero_seq)
                });
                if !ours {
                    return Err(FlipError::NotThisImport);
                }
                // AM-31: the sweep before the lift record.
                revocation_sweep(keys, unit, window.keys).await?;
                let proof = move_lift_proof(unit, zero, since).await?;
                let lift = Change::LiftRestoring {
                    unit: 0,
                    since_seq: since,
                    proof: proof.clone(),
                };
                let written = chain
                    .write(window.owner, &lift, Actor::MoveTool, now, owner.seq)
                    .await?;
                (door_of(written), proof)
            }
            Some(e) => {
                return Err(FlipError::OtherWindow {
                    since_seq: e.since_seq,
                })
            }
            // Lifted by an earlier run: its record's proof, as it stands.
            None => {
                let proof = lift_record_proof(chain, &owner, window).await?;
                (owner, proof)
            }
        };
        // An opening record: the directory before the unit.
        dir.apply_tenant(&owner, now).await?;
        let mut answer = unit.sync(&owner, Some(&proof)).await?;
        if answer == Synced::Refused(UnitRefused::KeysNotApplied) {
            apply_owner_keys(keys, unit).await?;
            answer = unit.sync(&owner, Some(&proof)).await?;
        }
        match answer {
            Synced::Ok => {
                unit.renew().await?;
                return Ok(owner);
            }
            // A newer record of the owner: read the head again.
            Synced::Refused(UnitRefused::StaleSync) if reentry < MAX_REENTRIES => {}
            // The lift landed already (a lost answer): the unit is open.
            Synced::Refused(UnitRefused::Gate(_)) if unit.restoring_since().await?.is_none() => {
                unit.renew().await?;
                return Ok(owner);
            }
            // Re-entry: a new entry, the unit closed under it, (b) again.
            Synced::Refused(UnitRefused::Gate(_)) if reentry < MAX_REENTRIES => {
                let closed = door_of(
                    chain
                        .write(
                            window.owner,
                            &Change::SetRestoring { unit: 0 },
                            Actor::Operator,
                            now,
                            owner.seq,
                        )
                        .await?,
                );
                close_unit(unit, &closed).await?;
                // A closing record: the unit before the directory.
                dir.apply_tenant(&closed, now).await?;
            }
            Synced::Refused(r) => return Err(FlipError::SyncRefused(r)),
        }
    }
    unreachable!("the last re-entry returns")
}

/// The owner's unit 0 closed: this window's entry (or a later one) kept,
/// or a new one set if an earlier step lifted it; the unit synced to it,
/// then the directory (a closing record: the unit first).
async fn close_owner<S, C, Q, U>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    unit: &U,
    window: &Window<'_>,
    now: UnixMs,
) -> Result<TenantDoor, FlipError>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
    U: OwnerUnit,
{
    let owner = head_of(chain, window.owner).await?;
    let owner = match owner.restoring_entry(0) {
        // This window's entry, a re-entry's, or the one an earlier run of
        // this give-up set; an older entry is another window's.
        Some(r) if r.since_seq >= window.since => owner,
        Some(r) => {
            return Err(FlipError::OtherWindow {
                since_seq: r.since_seq,
            })
        }
        None => door_of(
            chain
                .write(
                    window.owner,
                    &Change::SetRestoring { unit: 0 },
                    Actor::Operator,
                    now,
                    owner.seq,
                )
                .await?,
        ),
    };
    close_unit(unit, &owner).await?;
    dir.apply_tenant(&owner, now).await?;
    Ok(owner)
}

/// Syncs the unit to a head that closes it. No `renew`: a `restoring`
/// unit refuses it (AM-20), and a closed unit serves nothing.
async fn close_unit<U: OwnerUnit>(unit: &U, owner: &TenantDoor) -> Result<(), FlipError> {
    match unit.sync(owner, None).await? {
        Synced::Ok => Ok(()),
        Synced::Refused(code) => Err(FlipError::SyncRefused(code)),
    }
}

/// The `LiftProof` of a `move` report for the entry at `since` that the
/// unit's gate passes: the stored report's if it is one, else a new
/// report's (AM-15).
pub async fn move_lift_proof<U: OwnerUnit>(
    unit: &U,
    zero: &TenantDoor,
    since: u64,
) -> Result<LiftProof, FlipError> {
    let usable = |view: &GateView, want: Option<&ReplayId>| -> Option<LiftProof> {
        let proof = view.proof.as_ref()?;
        let ok = view.kind_move
            && view.lift_ok
            && view.replay_id.as_ref() == Some(&proof.replay_id)
            && proof.replay_id.since == since
            && proof.acknowledged.is_empty()
            && want.is_none_or(|w| *w == proof.replay_id);
        ok.then(|| proof.clone())
    };
    if let Some(proof) = usable(&unit.gate_status().await?, None) {
        return Ok(proof);
    }
    for _ in 0..REPORT_TRIES {
        let replay_id = ReplayId {
            since,
            ordinal: unit.stamp_ordinal().await?,
            nonce: unit.nonce(),
        };
        match unit.report_move(zero, &replay_id).await? {
            Reported::Done => {}
            Reported::Refused(code) => return Err(FlipError::Report(code)),
        }
        if let Some(proof) = usable(&unit.gate_status().await?, Some(&replay_id)) {
            return Ok(proof);
        }
    }
    Err(FlipError::LiftNotOk)
}

/// The proof of the newest record of this window that lifted unit 0's
/// entry: walked down from the owner's head, which has no entry, to the
/// window's first entry.
async fn lift_record_proof<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    owner: &TenantDoor,
    window: &Window<'_>,
) -> Result<LiftProof, FlipError> {
    if owner.seq < window.since || owner.seq - window.since >= MAX_WINDOW_RECORDS {
        return Err(FlipError::OtherWindow { since_seq: 0 });
    }
    for seq in (window.since..=owner.seq).rev() {
        let door = match seq == owner.seq {
            true => owner.clone(),
            false => {
                chain
                    .read(window.owner, seq)
                    .await?
                    .ok_or(FlipError::Chain(ChainError::Damaged(
                        "window_record_missing",
                    )))?
                    .door
            }
        };
        if let Some(l) = door.lifted.as_ref().filter(|l| l.unit == 0) {
            return match l.since_seq >= window.since {
                true => Ok(l.proof.clone()),
                false => Err(FlipError::OtherWindow {
                    since_seq: l.since_seq,
                }),
            };
        }
        // An entry below the newest lift is not lifted by it.
        if door.restoring_entry(0).is_some() && seq != owner.seq {
            break;
        }
    }
    Err(FlipError::OtherWindow { since_seq: 0 })
}

/// The owner's unit 0 entry is this window's (set at `since`, or by a
/// re-entry after it), or was lifted in this window. Refused for an entry
/// of another window, for a window whose `since` names a record that did
/// not set the entry, and for a missing entry that this window never
/// lifted.
async fn window_entry<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    owner: &TenantDoor,
    window: &Window<'_>,
) -> Result<(), FlipError> {
    let set = match window.since == owner.seq {
        true => Some(owner.clone()),
        false => chain
            .read(window.owner, window.since)
            .await?
            .map(|r| r.door),
    };
    let ours = set.is_some_and(|d| {
        d.restoring_entry(0)
            .is_some_and(|e| e.since_seq == window.since)
    });
    if !ours {
        return Err(FlipError::OtherWindow { since_seq: 0 });
    }
    match owner.restoring_entry(0) {
        Some(r) if r.since_seq >= window.since => Ok(()),
        Some(r) => Err(FlipError::OtherWindow {
            since_seq: r.since_seq,
        }),
        None => lift_record_proof(chain, owner, window).await.map(|_| ()),
    }
}

/// The placement check of DS1 §3.5: the owner's placements on unit 0 are
/// exactly the frozen D1's buckets less the excluded ones, and the owner
/// has no placement on another unit. The bucket ids are read in pages of
/// at most 500 by primary key.
pub async fn placement_check<F: Sql>(
    frozen: &F,
    owner: &TenantDoor,
    excluded: &BTreeSet<String>,
) -> Result<(), FlipError> {
    const PAGE: usize = 500;
    let mut moved = BTreeSet::new();
    let mut after: Option<String> = None;
    loop {
        let rows = match &after {
            None => {
                frozen
                    .query("SELECT id FROM buckets ORDER BY id LIMIT 500", &[])
                    .await?
            }
            Some(a) => {
                frozen
                    .query(
                        "SELECT id FROM buckets WHERE id > ?1 ORDER BY id LIMIT 500",
                        &[SqlValue::Text(a.clone())],
                    )
                    .await?
            }
        };
        for row in &rows {
            let Some(SqlValue::Text(id)) = row.first() else {
                return Err(BridgeError::Invalid("move flip: bucket id").into());
            };
            if !excluded.contains(id) {
                moved.insert(id.clone());
            }
            after = Some(id.clone());
        }
        if moved.len() > MAX_MOVED_BUCKETS {
            return Err(BridgeError::Invalid("move flip: too many buckets").into());
        }
        if rows.len() < PAGE {
            break;
        }
    }
    if moved.is_empty() {
        return Err(FlipError::NothingMoved);
    }
    let placed: BTreeSet<String> = owner
        .placements
        .iter()
        .filter(|p| p.unit == 0)
        .map(|p| p.bucket.clone())
        .collect();
    let missing: Vec<String> = moved.difference(&placed).cloned().collect();
    let mut extra: Vec<String> = placed.difference(&moved).cloned().collect();
    extra.extend(
        owner
            .placements
            .iter()
            .filter(|p| p.unit != 0)
            .map(|p| p.bucket.clone()),
    );
    match missing.is_empty() && extra.is_empty() {
        true => Ok(()),
        false => Err(FlipError::Placements { missing, extra }),
    }
}

/// The read-only pre-pass of (c): every moved key can be moved. Answers
/// each key's kind, from its directory row.
async fn routes_movable<Q: Sql, R: RouteRecords>(
    dir: &SqlDirectory<'_, Q>,
    routes: &R,
    window: &Window<'_>,
) -> Result<Vec<RouteKind>, FlipError> {
    let live = dir
        .tenant(window.owner)
        .await?
        .is_some_and(|row| row.door.lifecycle != Lifecycle::Shredded);
    if !live {
        return Err(FlipError::OwnerRow);
    }
    let mut kinds = Vec::with_capacity(window.keys.len());
    for akid in window.keys {
        // No record, the owner's, or tenant 0's (put back by an earlier
        // window's give-up; (c) replaces it).
        if let Some(t) = routes.get(akid).await? {
            if t != window.owner.as_str() && t != Tenant::Zero.as_str() {
                return Err(FlipError::RouteTaken(akid.clone()));
            }
        }
        match dir.route(akid).await? {
            Some(r) if r.tenant.is_zero() || r.tenant == *window.owner => kinds.push(r.kind),
            _ => return Err(FlipError::RouteRow(akid.clone())),
        }
    }
    Ok(kinds)
}

/// Whether a route record of a moved key already names the owner.
async fn any_route_put<R: RouteRecords>(
    routes: &R,
    window: &Window<'_>,
) -> Result<bool, FlipError> {
    for akid in window.keys {
        if routes.get(akid).await?.as_deref() == Some(window.owner.as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What the give-up leaves to the tool: the frozen catalogue to thaw, and
/// whether (a) put its legacy stamp, after which the thawed D1's stamp
/// must be levelled before tenant 0 serves from it (its reads fail closed
/// until then, which maintenance covers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GaveUp {
    pub catalogue_id_frozen: String,
    pub stamp_put: bool,
}

/// Gives the move up before the flip, in the exit order of AM-23: the
/// owner's unit closed again, the route records and the directory rows
/// back on tenant 0, tenant
/// 0's record back to `d1` and the directory's copy of it, then
/// [`exit_placements`]. Runs again from wherever it stopped. Refused once
/// tenant 0 is `moved` (the way back is then the reverse move).
#[allow(clippy::too_many_arguments)]
pub async fn give_up<S, C, F, B, Q, U, R, K>(
    chain: &TenantChain<'_, S, C>,
    frozen: &F,
    safety: &B,
    dir: &SqlDirectory<'_, Q>,
    unit: &U,
    routes: &R,
    keys: &K,
    window: &Window<'_>,
    now: UnixMs,
) -> Result<GaveUp, FlipError>
where
    S: RecordStore,
    C: ControlSeal,
    F: Sql,
    B: BlobStore,
    Q: Sql,
    U: OwnerUnit,
    R: RouteRecords,
    K: OwnerKeys,
{
    let (frozen_id, zero) = match window_state(chain, window).await? {
        WindowState::Open(zero) => {
            let frozen_id = zero
                .tenant_zero
                .as_ref()
                .and_then(|z| z.moved.as_ref())
                .map(|m| m.catalogue_id_frozen.clone())
                .expect("checked by window_state");
            // The owner's unit closed again, if an earlier step opened it;
            // then the route records back on tenant 0 by the conditional
            // replace (DS1 §3.8 row 8).
            close_owner(chain, dir, unit, window, now).await?;
            let zero_tenant = Tenant::Zero;
            for akid in window.keys {
                if routes.get(akid).await?.as_deref() != Some(window.owner.as_str()) {
                    continue;
                }
                let Some(row) = dir.route(akid).await? else {
                    return Err(FlipError::RouteRow(akid.clone()));
                };
                if !routes
                    .replace(akid, window.owner, &zero_tenant, row.kind)
                    .await?
                {
                    return Err(FlipError::RouteTaken(akid.clone()));
                }
            }
            // The directory rows back on tenant 0.
            for akid in window.keys {
                if !dir.move_route(akid, window.owner, &zero_tenant).await? {
                    let row = dir.route(akid).await?;
                    if !row.is_some_and(|r| r.tenant.is_zero()) {
                        return Err(FlipError::RouteRow(akid.clone()));
                    }
                }
            }
            // (1) Tenant 0 back at `d1`.
            let zero = door_of(
                chain
                    .write(
                        &zero_tenant,
                        &Change::GiveUpMove,
                        Actor::MoveTool,
                        now,
                        zero.seq,
                    )
                    .await?,
            );
            (frozen_id, zero)
        }
        // Given up by an earlier run (or by the flip after V9): finish the
        // exit, answer again. While the exit is open the unit is closed
        // first, as the exit needs.
        WindowState::GivenUp(frozen_id) => {
            if head_of(chain, window.owner).await?.moved_in.is_some() {
                close_owner(chain, dir, unit, window, now).await?;
            }
            (frozen_id, head_of(chain, &Tenant::Zero).await?)
        }
        // The way back after the flip is the reverse move.
        WindowState::Flipped(_) => return Err(FlipError::NotThisMove),
    };
    dir.apply_tenant(&zero, now).await?;
    let stamp_put = stamp_put(frozen, safety, &frozen_id).await?;
    // (2) and (3).
    exit_placements(chain, dir, keys, window.owner, now).await?;
    Ok(GaveUp {
        catalogue_id_frozen: frozen_id,
        stamp_put,
    })
}

/// AM-67 writer 2: after every exit that empties a unit of the owner with
/// `deleteAll()` (a give-up, P12, the undo copy's day 30), the floor of
/// that unit raised to `emptied_at`, the clock read after `deleteAll()`
/// answered. So a bookmark from before the empty, restored later, cannot
/// open the seal-to-`deleteAll()` span to a time target, also for a window
/// whose import never lifted. Run again until it answers; a repeat is
/// `Unchanged`. Answers the owner's head, which the directory copies.
pub async fn floor_after_empty<S, C, Q>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    owner: &Tenant,
    unit: u32,
    emptied_at: UnixMs,
) -> Result<TenantDoor, FlipError>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
{
    let written = chain
        .set_move_floor(owner, unit, emptied_at, Actor::MoveTool, emptied_at, 0)
        .await?;
    let head = door_of(written);
    if !head
        .move_floors
        .get(&unit)
        .is_some_and(|f| *f >= emptied_at)
    {
        return Err(FlipError::FloorMissing);
    }
    dir.apply_tenant(&head, emptied_at).await?;
    Ok(head)
}

/// Steps (2) and (3) of every exit of the move (AM-23), once tenant 0 is
/// back at `d1`: the closing records that revoke every grant on the
/// owner's buckets of unit 0, then `UnplaceMovedBuckets` with every one
/// of those placements (buckets made after the move included), and the
/// directory's copy of the owner's record. Nothing to do for a tenant
/// that no move filled, or whose exit is done (`moved_in` unset): answers
/// whether this run removed the placements. The unit must still be
/// closed.
pub async fn exit_placements<S, C, Q, K>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    keys: &K,
    owner: &Tenant,
    now: UnixMs,
) -> Result<bool, FlipError>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
    K: OwnerKeys,
{
    let head = head_of(chain, owner).await?;
    if head.moved_in.is_none() {
        // Done, or never filled: the directory's copy as it stands (a
        // crash after the unplace may have missed it).
        dir.apply_tenant(&head, now).await?;
        return Ok(false);
    }
    let buckets: Vec<String> = head
        .placements
        .iter()
        .filter(|p| p.unit == 0)
        .map(|p| p.bucket.clone())
        .collect();
    if !buckets.is_empty() {
        keys.revoke_grants(&buckets).await?;
    }
    let written = chain
        .unplace_moved_buckets(owner, &buckets, 0, now, head.seq)
        .await?;
    dir.apply_tenant(&door_of(written), now).await?;
    Ok(true)
}

/// Whether (a) put the legacy stamp of the frozen catalogue `frozen_id`
/// (the stamp one above the stamp row's counter).
async fn stamp_put<F: Sql, B: BlobStore>(
    frozen: &F,
    safety: &B,
    frozen_id: &str,
) -> Result<bool, FlipError> {
    let counter = stamp_row(frozen).await?.map(|(c, _)| c);
    Ok(safety
        .head(&legacy_stamp_key(frozen_id, counter))
        .await?
        .is_some())
}
