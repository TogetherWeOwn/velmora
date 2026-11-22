//! The move's window step 2 (DS1 §3.4, AM-53) and the thaw of an undo's
//! key freeze (AM-28 with AM-54 LOW 1).
//!
//! [`open_window`] runs after the close and the drain (steps 0 and 1, CI
//! deploys) and the catalogue migration switch: the cutover marker and
//! the freeze triggers on the D1 catalogue ([`super::fence::freeze`]),
//! then tenant 0's `moving` record, then one owner record that sets the
//! root unit's `restoring` entry **anew**, with that record's seq as its
//! `since_seq`, also when an entry is already set (a give-up or an undo
//! leaves it set: the emptied unit is re-created only with a `restore`
//! token, which needs the entry). That record also clears an undo's key
//! freeze (`keys_frozen`), and the tool then writes `KeysThawed` in the
//! owner's key chain ([`thaw_keys`]). Then an unborn unit is created
//! again with a `restore` token, and the unit is synced closed under the
//! new entry. A new `since_seq` per window means that a
//! given-up window's import, seal or report never matches this one's.
//!
//! **Refusal (AM-53).** P12 (AM-47, [`super::move_preflight::p12`])
//! empties a unit that holds an earlier move's import before step 0. Step
//! 2 reads `ImportProgress` again, before tenant 0's `moving` record and
//! again just before the owner's record, and stops if it is not empty:
//! P12 was skipped or raced. A re-run after the owner's record skips the
//! second read (the window's own import may exist by then).
//!
//! Every part reads what is there first, so a crash anywhere is finished
//! by running [`open_window`] again: the marker and triggers are put
//! again only where missing, the `moving` record answers `Unchanged`, and
//! the owner record names its window (`window_entry`), so a repeat for
//! the same window writes nothing. The synthetic tenant's lock (A10) is
//! not this module's.

use super::chain::{ChainError, ControlSeal, TenantChain, Written};
use super::fence::freeze;
use super::move_copy::ImportState;
use super::move_flip::{Synced, MAX_WINDOW_RECORDS};
use super::move_keys::{KeyFreeze, KeyPut};
use super::record::{Selector, Tenant, TenantDoor};
use super::store::SqlDirectory;
use super::transition::{Actor, Change};
use crate::ports::Sql;
use crate::records::RecordStore;
use crate::types::{BridgeError, UnixMs};
use crate::unit::call::Refused as UnitRefused;

/// Why step 2 or the thaw stopped. What it wrote stays written and is
/// found again by the next run.
#[derive(Debug)]
pub enum WindowError {
    Store(BridgeError),
    Chain(ChainError),
    /// Tenant 0 is not `d1` with no move open (or `moving` into the owner,
    /// for a repeat), or its window is longer than the walk's bound.
    NotThisMove,
    /// The unit still holds an earlier window's import (AM-53): finish
    /// that give-up (`deleteAll()`) first. `t0_seq` is the tenant-0 seq
    /// the import is bound to, if the unit says.
    EarlierImport {
        t0_seq: Option<u64>,
    },
    /// The unit refused to close under the new entry.
    SyncRefused(UnitRefused),
    /// The key-chain writer refused `KeysThawed`.
    ThawRefused(&'static str),
    /// The key chain kept moving under the thaw.
    ThawBusy,
}

impl From<BridgeError> for WindowError {
    fn from(e: BridgeError) -> Self {
        WindowError::Store(e)
    }
}

impl From<ChainError> for WindowError {
    fn from(e: ChainError) -> Self {
        WindowError::Chain(e)
    }
}

/// The owner's root unit, as step 2 calls it.
#[allow(async_fn_in_trait)]
pub trait WindowUnit {
    /// `sync` with the owner's verified head `owner`, which carries the
    /// root unit's `restoring` entry: the unit closes under it.
    async fn sync(&self, owner: &TenantDoor) -> crate::types::Result<Synced>;
    /// The import the unit holds (`ImportProgress`, with its tenant-0
    /// seq): `None` when it holds none, an unborn unit included.
    async fn import_state(&self) -> crate::types::Result<Option<ImportState>>;
    /// After the owner's record of step 2: an unborn unit (emptied by a
    /// give-up's or an undo's `deleteAll()`) is created again with a
    /// `restore` token for the entry that record set (ADR §2.4 rule 6,
    /// AM-53); a unit that exists is left alone.
    async fn ensure_born(&self, owner: &TenantDoor) -> crate::types::Result<()>;
}

/// What step 2 did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The seq of tenant 0's record that opened the window.
    pub zero_seq: u64,
    /// The `since_seq` of the owner's root-unit entry for this window.
    pub since: u64,
    /// The freeze a `KeysThawed` ended in this run, if any.
    pub thawed: Option<u64>,
}

/// Tries of the thaw against a key chain that moves.
pub const THAW_TRIES: u32 = 5;

fn door_of(written: Written) -> TenantDoor {
    match written {
        Written::Wrote(record) => record.door,
        Written::Unchanged(read) => read.door,
    }
}

async fn head_of<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    tenant: &Tenant,
) -> Result<TenantDoor, WindowError> {
    Ok(chain
        .head(tenant, 0)
        .await?
        .ok_or(WindowError::Chain(ChainError::Refused(
            super::transition::Refusal {
                status: 409,
                code: "no_tenant",
            },
        )))?
        .door)
}

fn moving_into(door: &TenantDoor, owner: &Tenant) -> bool {
    door.tenant_zero.as_ref().is_some_and(|z| {
        z.selector == Selector::Moving && z.moved.as_ref().is_some_and(|m| m.to == *owner)
    })
}

/// The seq of the first record of tenant 0's run of `moving` records into
/// `owner` that ends at `head` (the record that opened the window).
pub async fn window_start<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    head: &TenantDoor,
    owner: &Tenant,
) -> Result<u64, WindowError> {
    if !moving_into(head, owner) {
        return Err(WindowError::NotThisMove);
    }
    let mut start = head.seq;
    for _ in 0..MAX_WINDOW_RECORDS {
        if start <= 1 {
            return Ok(start);
        }
        let below = chain
            .read(&Tenant::Zero, start - 1)
            .await?
            .ok_or(WindowError::Chain(ChainError::Damaged(
                "window_record_missing",
            )))?;
        if !moving_into(&below.door, owner) {
            return Ok(start);
        }
        start -= 1;
    }
    Err(WindowError::NotThisMove)
}

/// Window step 2 into `owner`, freezing the catalogue `frozen`, whose id
/// is `catalogue_id_frozen` (the one `d1` means now). See the
/// [module](self).
#[allow(clippy::too_many_arguments)]
pub async fn open_window<S, C, F, Q, U, K>(
    chain: &TenantChain<'_, S, C>,
    frozen: &F,
    dir: &SqlDirectory<'_, Q>,
    unit: &U,
    keys: &K,
    owner: &Tenant,
    catalogue_id_frozen: &str,
    now: UnixMs,
) -> Result<Opened, WindowError>
where
    S: RecordStore,
    C: ControlSeal,
    F: Sql,
    Q: Sql,
    U: WindowUnit,
    K: KeyFreeze,
{
    let zero = head_of(chain, &Tenant::Zero).await?;
    let started = moving_into(&zero, owner);
    if !started {
        // Before the window's first record, any import is an earlier
        // window's.
        if let Some(i) = unit.import_state().await? {
            return Err(WindowError::EarlierImport { t0_seq: i.t0_seq });
        }
        let z = zero.tenant_zero.as_ref().ok_or(WindowError::NotThisMove)?;
        let ordinal = z.flips.checked_add(1).ok_or(WindowError::NotThisMove)?;
        freeze(frozen, ordinal).await?;
    }
    let zero = door_of(
        chain
            .write(
                &Tenant::Zero,
                &Change::StartMove {
                    to: owner.clone(),
                    catalogue_id_frozen: catalogue_id_frozen.to_string(),
                },
                Actor::MoveTool,
                now,
                zero.seq,
            )
            .await?,
    );
    let window = window_start(chain, &zero, owner).await?;
    let mut head = head_of(chain, owner).await?;
    let done = head
        .window_entry
        .is_some_and(|w| w.zero_seq == window && w.unit == 0);
    if !done {
        // AM-53: read again just before the record; any import state now
        // means P12 was skipped or raced.
        if let Some(i) = unit.import_state().await? {
            return Err(WindowError::EarlierImport { t0_seq: i.t0_seq });
        }
        head = door_of(
            chain
                .open_window_entry(owner, 0, window, now, head.seq)
                .await?,
        );
    }
    let since = head
        .window_entry
        .filter(|w| w.zero_seq == window)
        .map(|w| w.since_seq)
        .ok_or(WindowError::NotThisMove)?;
    let thawed = thaw_keys(chain, keys, owner).await?;
    // The unit closes under this window's entry; a later record of the
    // window (a placement) keeps it, a re-entry of 8(b) sets a later one.
    let head = head_of(chain, owner).await?;
    if head.restoring_entry(0).is_some() {
        unit.ensure_born(&head).await?;
        match unit.sync(&head).await? {
            Synced::Ok => {}
            Synced::Refused(r) => return Err(WindowError::SyncRefused(r)),
        }
    }
    dir.apply_tenant(&zero, now).await?;
    dir.apply_tenant(&head, now).await?;
    Ok(Opened {
        zero_seq: window,
        since,
        thawed,
    })
}

/// Ends an undo's key freeze in the owner's key chain once the owner's
/// tenant head no longer carries `keys_frozen` (AM-28): window step 2
/// cleared it, or the gate's lift of an undo given up while tenant 0 is
/// still `moved`. Writes `KeysThawed{ends: frozen_at}`, the freeze the
/// key head names (AM-54 LOW 1); nothing when the key head is not
/// frozen, or while the tenant head still carries the freeze. Answers the
/// freeze it ended.
pub async fn thaw_keys<S, C, K>(
    chain: &TenantChain<'_, S, C>,
    keys: &K,
    owner: &Tenant,
) -> Result<Option<u64>, WindowError>
where
    S: RecordStore,
    C: ControlSeal,
    K: KeyFreeze,
{
    if head_of(chain, owner).await?.keys_frozen.is_some() {
        return Ok(None);
    }
    for _ in 0..THAW_TRIES {
        let Some(ends) = keys.key_head().await?.frozen_at else {
            return Ok(None);
        };
        match keys.put_keys_thawed(ends).await? {
            KeyPut::Done => return Ok(Some(ends)),
            KeyPut::Lost => continue,
            KeyPut::Refused(code) => return Err(WindowError::ThawRefused(code)),
        }
    }
    Err(WindowError::ThawBusy)
}
