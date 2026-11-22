//! The move's flip, and its give-up before the flip (DS1 §3.4 step 8,
//! §3.8).
//!
//! The flip runs after the verify (step 7). Before it writes anything it
//! checks the whole window: tenant 0 `moving` into the owner, the frozen
//! catalogue carrying this window's marker, the owner's `restoring` entry
//! of this window (or its lift), and for every moved key a route record
//! that is absent or names the owner and a directory row on tenant 0 or
//! the owner. A key that would stop the flip halfway therefore stops it
//! before (a), while the give-up is still open. Then, in this order, each
//! sub-step reading what is there first, so a crash anywhere is finished
//! by running [`flip`] again:
//!
//! - **(a)** the legacy stamp on the frozen catalogue
//!   ([`super::fence::put_legacy_stamp`]): from here every destructive act
//!   on the frozen D1 is fenced for good;
//! - **(b)** one owner-tenant record that lifts unit 0's `restoring` entry
//!   of this window, then the unit's `sync` and `renew`
//!   ([`UnitSync::apply_head`]). The unit serves, but no route names it yet;
//! - **(c)** for every moved key, its route record `m/kr/<akid>` naming the
//!   owner ([`RouteRecords::put`]), then the directory's `key_routes` row
//!   ([`super::store::SqlDirectory::move_route`]);
//! - **(d)** one tenant-0 record: `moved`, at the legacy stamp's counter.
//!
//! [`give_up`] is the way back while tenant 0 is still `moving`: the
//! owner's unit closed again, the directory rows back on tenant 0, tenant
//! 0's record back to `d1`. It refuses once a route record names the
//! owner: a route record is put once, and putting it back needs the
//! conditional replace of DS1 §2.2, which no code has yet. The rest of the
//! give-up (empty the unit, thaw and level the frozen D1, migrations on,
//! the lift) are tool steps outside this module.
//!
//! The actors are the planes the tool holds for each record: the restore
//! tool lifts a `restoring` entry, the operator sets one, the move tool
//! writes tenant 0's records.

use super::chain::{ChainError, ControlSeal, TenantChain, Written};
use super::fence::{legacy_stamp_key, marker, put_legacy_stamp, stamp_row};
use super::record::{Lifecycle, Selector, Tenant, TenantDoor};
use super::store::{RouteKind, SqlDirectory};
use super::transition::{Actor, Change};
use crate::ports::{BlobStore, Sql};
use crate::records::RecordStore;
use crate::types::{BridgeError, UnixMs};

/// Why the flip or the give-up stopped. Every sub-step it finished stays
/// finished and is found again by the next run.
#[derive(Debug)]
pub enum FlipError {
    Store(BridgeError),
    Chain(ChainError),
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
    /// Route records already name the owner; the give-up cannot put them
    /// back.
    RoutesPut(Vec<String>),
    /// The frozen catalogue does not carry this window's cutover marker.
    Marker,
    /// The owner has no live directory row to move routes to.
    OwnerRow,
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

/// The owner's root unit.
#[allow(async_fn_in_trait)]
pub trait UnitSync {
    /// `sync` with the owner's head, then `renew`: after the lift record
    /// the unit opens, after a new `restoring` entry it closes.
    async fn apply_head(&self, owner: &TenantDoor) -> crate::types::Result<()>;
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
}

/// The move a flip or a give-up acts on.
pub struct Window<'a> {
    /// The owner's tenant.
    pub owner: &'a Tenant,
    /// The `since_seq` of the owner's root-unit `restoring` entry that the
    /// window set (the copy's [`super::move_copy::bound`]).
    pub since: u64,
    /// Every moved key id.
    pub keys: &'a [String],
}

/// What the flip did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flipped {
    /// The legacy stamp's counter, named by the `moved` record.
    pub stamp: u64,
    /// Whether this run wrote the `moved` record (`false`: found).
    pub wrote: bool,
}

/// The tenant-0 head, verified to be this move's: `moving` into the owner,
/// or `moved` into it when `flipped` is allowed.
async fn zero_head<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    owner: &Tenant,
    flipped: bool,
) -> Result<TenantDoor, FlipError> {
    let head = chain
        .head(&Tenant::Zero, 0)
        .await?
        .ok_or(FlipError::NotThisMove)?;
    let ours = head.door.tenant_zero.as_ref().is_some_and(|z| {
        let to_owner = z.moved.as_ref().is_some_and(|m| m.to == *owner);
        let state = z.selector == Selector::Moving || (flipped && z.selector == Selector::Moved);
        to_owner && state
    });
    match ours {
        true => Ok(head.door),
        false => Err(FlipError::NotThisMove),
    }
}

async fn owner_head<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    owner: &Tenant,
) -> Result<TenantDoor, FlipError> {
    Ok(chain
        .head(owner, 0)
        .await?
        .ok_or(FlipError::Chain(ChainError::Refused(
            super::transition::Refusal {
                status: 409,
                code: "no_tenant",
            },
        )))?
        .door)
}

/// Runs step 8, from wherever an earlier run stopped. `frozen` and
/// `safety` hold the frozen catalogue and its stamp; `dir` the directory.
#[allow(clippy::too_many_arguments)]
pub async fn flip<S, C, F, B, Q, U, R>(
    chain: &TenantChain<'_, S, C>,
    frozen: &F,
    safety: &B,
    dir: &SqlDirectory<'_, Q>,
    unit: &U,
    routes: &R,
    window: &Window<'_>,
    now: UnixMs,
) -> Result<Flipped, FlipError>
where
    S: RecordStore,
    C: ControlSeal,
    F: Sql,
    B: BlobStore,
    Q: Sql,
    U: UnitSync,
    R: RouteRecords,
{
    let zero = zero_head(chain, window.owner, true).await?;
    let z = zero.tenant_zero.as_ref().expect("checked by zero_head");
    let m = z.moved.as_ref().expect("checked by zero_head");
    if z.selector == Selector::Moved {
        // Flipped already: nothing to do, nothing to undo here.
        let stamp = m.stamp.ok_or(FlipError::NotThisMove)?;
        return Ok(Flipped {
            stamp,
            wrote: false,
        });
    }
    // The whole window is checked before the first write.
    let owner = owner_head(chain, window.owner).await?;
    let lifted = window_entry(chain, &owner, window).await?;
    let ordinal = z.flips.checked_add(1).and_then(|o| i64::try_from(o).ok());
    if ordinal.is_none() || marker(frozen).await? != ordinal {
        return Err(FlipError::Marker);
    }
    let kinds = routes_movable(dir, routes, window).await?;

    // (a) The legacy stamp, under the catalogue the window froze.
    let stamp = put_legacy_stamp(frozen, safety, &m.catalogue_id_frozen, now).await?;

    // (b) The owner's root unit opens.
    let owner = match lifted {
        true => owner,
        false => {
            let lift = Change::LiftRestoring {
                unit: 0,
                since_seq: window.since,
            };
            match chain
                .write(window.owner, &lift, Actor::RestoreTool, now, owner.seq)
                .await?
            {
                Written::Wrote(record) => record.door,
                Written::Unchanged(read) => read.door,
            }
        }
    };
    unit.apply_head(&owner).await?;

    // (c) Routes: the record first, then the directory row.
    let zero_tenant = Tenant::Zero;
    for (akid, kind) in window.keys.iter().zip(kinds) {
        if !routes.put(akid, window.owner, kind).await? {
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
    // checked (a give-up and a new window in between stop it).
    let now_zero = zero_head(chain, window.owner, false).await?;
    if now_zero.seq != zero.seq {
        return Err(FlipError::NotThisMove);
    }
    let wrote = matches!(
        chain
            .write(
                &zero_tenant,
                &Change::FlipMove { stamp },
                Actor::MoveTool,
                now,
                zero.seq,
            )
            .await?,
        Written::Wrote(_)
    );
    Ok(Flipped { stamp, wrote })
}

/// Whether the owner's root unit 0 entry of this window is already lifted
/// (`true`) or still set (`false`). Refused for an entry of another
/// window, and for a missing entry that this window never set.
async fn window_entry<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    owner: &TenantDoor,
    window: &Window<'_>,
) -> Result<bool, FlipError> {
    match owner.restoring_entry(0) {
        Some(r) if r.since_seq == window.since => Ok(false),
        Some(r) => Err(FlipError::OtherWindow {
            since_seq: r.since_seq,
        }),
        None => {
            // Lifted by an earlier run: the record at `since` set it, and
            // no later entry stands (the head has none).
            let set = chain.read(window.owner, window.since).await?;
            let ours = set.is_some_and(|r| {
                r.door
                    .restoring_entry(0)
                    .is_some_and(|e| e.since_seq == window.since)
            });
            match ours {
                true => Ok(true),
                false => Err(FlipError::OtherWindow { since_seq: 0 }),
            }
        }
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
        if let Some(t) = routes.get(akid).await? {
            if t != window.owner.as_str() {
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

/// What the give-up leaves to the tool: the frozen catalogue to thaw, and
/// whether (a) put its legacy stamp, after which the thawed D1's stamp
/// must be levelled before tenant 0 serves from it (its reads fail closed
/// until then, which maintenance covers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GaveUp {
    pub catalogue_id_frozen: String,
    pub stamp_put: bool,
}

/// Gives the move up before the flip: the owner's unit closed again, the
/// directory rows back on tenant 0, tenant 0's record back to `d1`. Runs
/// again from wherever it stopped. Refused once tenant 0 is `moved` (the
/// way back is then the reverse move) and once a route record names the
/// owner.
#[allow(clippy::too_many_arguments)]
pub async fn give_up<S, C, F, B, Q, U, R>(
    chain: &TenantChain<'_, S, C>,
    frozen: &F,
    safety: &B,
    dir: &SqlDirectory<'_, Q>,
    unit: &U,
    routes: &R,
    window: &Window<'_>,
    now: UnixMs,
) -> Result<Option<GaveUp>, FlipError>
where
    S: RecordStore,
    C: ControlSeal,
    F: Sql,
    B: BlobStore,
    Q: Sql,
    U: UnitSync,
    R: RouteRecords,
{
    let zero = match zero_head(chain, window.owner, false).await {
        Ok(zero) => zero,
        // Given up by an earlier run: tenant 0 is on its D1 with no move.
        Err(FlipError::NotThisMove) if given_up(chain).await? => return Ok(None),
        Err(e) => return Err(e),
    };
    let frozen_id = zero
        .tenant_zero
        .as_ref()
        .and_then(|z| z.moved.as_ref())
        .map(|m| m.catalogue_id_frozen.clone())
        .expect("checked by zero_head");
    let mut put = Vec::new();
    for akid in window.keys {
        if routes.get(akid).await?.as_deref() == Some(window.owner.as_str()) {
            put.push(akid.clone());
        }
    }
    if !put.is_empty() {
        return Err(FlipError::RoutesPut(put));
    }
    // The owner's unit closed again, if an earlier step opened it.
    let owner = owner_head(chain, window.owner).await?;
    let owner = match owner.restoring_entry(0) {
        // This window's entry, or the one an earlier run of this give-up
        // set after it; an older entry is another window's.
        Some(r) if r.since_seq >= window.since => owner,
        Some(r) => {
            return Err(FlipError::OtherWindow {
                since_seq: r.since_seq,
            })
        }
        None => match chain
            .write(
                window.owner,
                &Change::SetRestoring { unit: 0 },
                Actor::Operator,
                now,
                owner.seq,
            )
            .await?
        {
            Written::Wrote(record) => record.door,
            Written::Unchanged(read) => read.door,
        },
    };
    unit.apply_head(&owner).await?;
    // The directory rows back on tenant 0.
    let zero_tenant = Tenant::Zero;
    for akid in window.keys {
        if !dir.move_route(akid, window.owner, &zero_tenant).await? {
            let row = dir.route(akid).await?;
            if !row.is_some_and(|r| r.tenant.is_zero()) {
                return Err(FlipError::RouteRow(akid.clone()));
            }
        }
    }
    // Whether (a) ran, read before tenant 0's record forgets the window.
    let counter = stamp_row(frozen).await?.map(|(c, _)| c);
    let stamp_put = safety
        .head(&legacy_stamp_key(&frozen_id, counter))
        .await?
        .is_some();
    chain
        .write(
            &zero_tenant,
            &Change::GiveUpMove,
            Actor::MoveTool,
            now,
            zero.seq,
        )
        .await?;
    Ok(Some(GaveUp {
        catalogue_id_frozen: frozen_id,
        stamp_put,
    }))
}

/// Tenant 0 on its D1 with no move open.
async fn given_up<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
) -> Result<bool, FlipError> {
    let Some(head) = chain.head(&Tenant::Zero, 0).await? else {
        return Ok(false);
    };
    Ok(head
        .door
        .tenant_zero
        .as_ref()
        .is_some_and(|z| z.selector == Selector::D1 && (z.moved.is_none() || z.undone())))
}
