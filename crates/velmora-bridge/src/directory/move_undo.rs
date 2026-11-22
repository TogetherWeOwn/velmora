//! The undo of a flipped move, for 30 days (DS1 §3.7, AM-26, AM-28 with
//! AM-54, AM-23).
//!
//! **Primary route: the reverse move.** The mirror of the window, under
//! the same freeze, maintenance and deploy rules. The steps the tool runs
//! here, each reading what is there first, so a crash anywhere is
//! finished by running the step again:
//!
//! 1. [`freeze_keys`]: the owner's key chain frozen by a `KeysFrozen`
//!    record at its head + 1 (`K_u` = that record's seq − 1, also written
//!    to the undo's receipt in R2), then one owner record that sets the
//!    root unit's `restoring` entry with `keys_frozen = {at: K_u}`, then
//!    the unit synced closed. The undo does not start unless the owner has
//!    only its root unit, and an entry already set must carry this freeze.
//!    An existing `frozen_at` is adopted only when the receipt names it
//!    (or this run's own put made it); any other is ended by `KeysThawed`
//!    and a new `KeysFrozen` is put (AM-54 LOW 1). The close, the drain and
//!    the merge freeze before it are CI steps.
//! 2. [`prepare_fresh`]: the fresh D1 (made by the deploy tooling with the
//!    catalogue's migrations) under a **new** catalogue id, never `main`
//!    and never a catalogue a move froze: its `d1_migrations` hold every
//!    name the frozen D1's do and no other (DEL-4); its stamp row names
//!    the new id at counter 0, a fresh level under `rs/<new id>/`.
//! 3. [`copy_back`]: the unit's rows paged with `Export` in `rows` mode
//!    into the fresh D1, in [`ImportTable::ALL`]'s order, with the reverse
//!    transforms: a bucket that existed before the move gets its scheme-1
//!    wrap and owner **byte for byte from the frozen D1**; one made after
//!    the move gets a fresh scheme-1 wrap ([`ReverseTransform::new_bucket`],
//!    the key lane's code in the Worker); `hot_cache_bytes` becomes 0 (warm
//!    copies are not copied back) and `hot_safety_bytes` too unless the
//!    extent is `held` or `releasing`; an outbox row with a live lease
//!    stops the copy, an expired one is cleared with its fencing token
//!    kept. **Step 4 runs inside step 3:** the safety copy `x/<t>/<id>` of
//!    every held or releasing extent that the frozen D1 does not hold is
//!    copied to `x/<id>` and read back by SHA-256
//!    ([`BlobsBack::to_flat`]) before its page of rows is written, so a
//!    resumed copy never skips one. A page is written in key order, so
//!    the copy resumes from the fresh D1's last key per table.
//!
//!    [`build_keys`] then gives D1 the owner's keys **from the key chain up
//!    to `K_u`, never further** (AM-28): each key's effective grant at
//!    `K_u` (its grants ∩ its `made_by` principals' grants, the lower
//!    access per bucket), `disabled` if the key or a principal is not
//!    `active`; a key with no `made_by` (the internal key) and principals
//!    are not carried. A key that existed before the move keeps its `ak/v1`
//!    wrap from the frozen D1; one made after it gets a fresh `ak/v1` wrap
//!    ([`ReverseTransform::new_key`]), **except** a key with a prefix, an
//!    expiry or an address list on a grant, and an app password made after
//!    the move: D1 cannot hold those limits or the kind, so they are not
//!    carried, are revoked (step 5) and listed for the owner to make again.
//!    `kind`, `made_by` and `owner_ref` are dropped. The build's last act
//!    is the first **revocation override** ([`override_revocations`]):
//!    every `m/rk/<t>/<akid>` and flat `m/rk/<akid>` (delimited listings)
//!    removes its key's row and grants, as tenant 0's own revoke does.
//! 5. [`revocations_back`]: a flat `m/rk/<akid>` for every key revoked in
//!    the chain up to `K_u`, for every `m/rk/<t>/<akid>`, and for every key
//!    not carried for its limits or kind; then the owner's `VMR2` records
//!    written after the flip re-sealed as v1 under tenant 0's layout
//!    ([`RecordsBack`], the record lane's code).
//! 6. [`routes_back`]: for every key the chain holds at `K_u`, its route
//!    record `m/kr/<akid>` put back on tenant 0 by the conditional replace
//!    of DS1 §2.2, then its directory row. From here a key resolves to
//!    tenant 0, which is still `moved`, so it gets `503` (§2.3).
//! 7. [`verify_back`]: V1, V3, V4, V5 and V6, mirrored, against the fresh
//!    D1: V1 by `Export` in `hash` mode, page by page, against the same
//!    key range of the fresh D1 hashed with the unit's own
//!    [`hash_rows`]; V6 rebuilds the same projection and override.
//! 8. [`flip_back`], after the deploy with the fresh D1's binding (ADR
//!    §11.4 undo step 2b, a CI deploy): one tenant-0 record, `d1` with the
//!    undo stamp and the new catalogue id; the second revocation override,
//!    just before the lift deploy; then the exit order of AM-23 (the
//!    grant revocations on the moved-in buckets, which the frozen
//!    key-chain writer accepts, then `UnplaceMovedBuckets`). The lift is a
//!    CI deploy. The owner's unit stays closed for 30 days, then is
//!    emptied with `deleteAll()`.
//!
//! **Fallback route** (the owner's unit cannot be read): the frozen D1 is
//! thawed and replayed into (tool and record-lane steps), then
//! [`build_keys`] and [`override_revocations`] run on it as they run on
//! the fresh one (a key row the thawed D1 holds is updated in place, the
//! row of a key not carried is removed with its grants), and
//! [`flip_back_onto_frozen`] writes `UndoMoveOntoFrozen`, runs the second
//! override and the exit order. Step 1 is the same [`freeze_keys`]; a
//! fallback after the reverse move's step 1 adopts its freeze.
//!
//! **Every revocation reaches the restored D1.** The D1 build stops at
//! `K_u`; a revoke made after it is refused by the frozen key chain, but
//! its `m/rk/` put comes first and always wins: the override at the end
//! of the build catches every revocation put before it, the second one
//! catches every one put before the lift, and a revoke whose put lands
//! after the second listing saw tenant 0's `d1` record on its re-read and
//! applied itself to D1 (the key lane's writer, AM-28, AM-54 LOW 2, 3).
//!
//! Nothing here writes to the frozen D1 (the fallback's thawed D1
//! excepted), deletes a blob, or reads a production table by more than a
//! bounded page or an indexed point lookup.

use std::collections::{BTreeMap, BTreeSet};

use super::chain::{ChainError, ControlSeal, TenantChain, Written};
use super::fence::{catalogue_tables, marker, stamp_row};
use super::move_flip::{exit_placements, FlipError, RouteRecords, Synced};
use super::move_keys::{KeyFreeze, KeyPut, KeyStepError, OwnerKeys};
use super::record::{Selector, Tenant, TenantDoor};
use super::store::{RouteKind, SqlDirectory, APP_PASSWORD_PREFIX};
use super::transition::{Actor, Change};
use crate::ports::{Sql, SqlValue};
use crate::records::RecordStore;
use crate::types::{BridgeError, UnixMs};
use crate::unit::call::Refused as UnitRefused;
use crate::unit::export::{hash_rows, key_of, ExportMode, ExportRefusal, ExportTable, MAX_ROWS};
use crate::unit::import::{ImportTable, ImportValue};
use crate::unit::keys::{Access, KeyEntry, KeyKind, SubjectStatus, MAX_DEPTH, MAX_ENTRIES};

// ---------------------------------------------------------------------------
// Errors and ports
// ---------------------------------------------------------------------------

/// Why a step of the undo stopped. Everything it did stays done and is
/// found again by the next run.
#[derive(Debug)]
pub enum UndoError {
    Store(BridgeError),
    Chain(ChainError),
    Keys(KeyStepError),
    Flip(FlipError),
    /// Tenant 0 is not `moved` into the owner (for step 8: nor `d1` after
    /// this undo).
    NotThisMove,
    /// The owner has a unit besides its root unit (AM-28).
    NotOnlyRootUnit,
    /// The owner's root unit is `restoring` without this undo's key
    /// freeze (a restore under way): the undo does not start.
    EntryWithoutFreeze,
    /// The undo's receipt names another `K_u` than the owner's head.
    ReceiptDiffers {
        receipt: u64,
        head: u64,
    },
    /// The key-chain writer refused `KeysFrozen` or `KeysThawed`.
    FreezeRefused(&'static str),
    /// The key chain kept moving under the freeze.
    FreezeBusy,
    /// The owner's head does not carry the key freeze at the `K_u` the
    /// step was given: a wrong `K_u`, or the freeze already ended.
    NotFrozen,
    /// The unit refused to close.
    SyncRefused(UnitRefused),
    /// The unit holds data tables that `Export` does not page (AM-26).
    UnknownTables(Vec<String>),
    /// The fresh D1's migration bookkeeping is not the frozen D1's.
    Migrations {
        missing: Vec<String>,
        extra: Vec<String>,
    },
    /// The fresh catalogue's id is `main`, one a move froze, or not the one
    /// its stamp row names; or the fresh D1 lacks a table, or carries a
    /// cutover marker.
    FreshCatalogue(&'static str),
    /// The unit refused an `Export`.
    ExportRefused {
        table: &'static str,
        refusal: ExportRefusal,
    },
    /// The unit answered a page that is not the next rows of the table.
    Diverged {
        table: &'static str,
    },
    /// An outbox row of the unit still holds a live lease: the drain did
    /// not finish.
    LiveLease,
    /// A route record names a third tenant.
    RouteTaken(String),
    /// A directory route row names neither tenant 0 nor the owner.
    RouteRow(String),
    /// A mirrored check failed: the check's name and the ids that failed
    /// it (at most [`MAX_LISTED`]).
    Verify {
        check: &'static str,
        ids: Vec<String>,
    },
}

impl From<BridgeError> for UndoError {
    fn from(e: BridgeError) -> Self {
        UndoError::Store(e)
    }
}

impl From<ChainError> for UndoError {
    fn from(e: ChainError) -> Self {
        UndoError::Chain(e)
    }
}

impl From<KeyStepError> for UndoError {
    fn from(e: KeyStepError) -> Self {
        UndoError::Keys(e)
    }
}

impl From<FlipError> for UndoError {
    fn from(e: FlipError) -> Self {
        UndoError::Flip(e)
    }
}

type Result<T> = std::result::Result<T, UndoError>;

/// The most ids a [`UndoError::Verify`] lists.
pub const MAX_LISTED: usize = 64;

/// One `Export` answer (`docs/units.md`, "Export", AM-26).
#[derive(Clone, PartialEq, Eq)]
pub enum Exported {
    /// `rows` mode: the next rows after `after`, every column in
    /// [`ExportTable::columns`] order.
    Rows {
        rows: Vec<Vec<ImportValue>>,
        more: bool,
    },
    /// `hash` mode: the page's count, last key and digest.
    Hash {
        count: u64,
        last: Option<Vec<ImportValue>>,
        sha256: String,
        more: bool,
    },
    Refused(ExportRefusal),
}

impl std::fmt::Debug for Exported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Exported::Rows { rows, more } => f
                .debug_struct("Rows")
                .field("rows", &rows.len())
                .field("more", more)
                .finish(),
            Exported::Hash { count, more, .. } => f
                .debug_struct("Hash")
                .field("count", count)
                .field("more", more)
                .finish_non_exhaustive(),
            Exported::Refused(r) => f.debug_tuple("Refused").field(r).finish(),
        }
    }
}

/// The owner's root unit, as the undo calls it (L1's unit calls through
/// the Worker's stub fetch).
#[allow(async_fn_in_trait)]
pub trait UndoUnit {
    /// `sync` with the owner's verified head, which carries the root
    /// unit's `restoring` entry: the unit closes.
    async fn sync(&self, owner: &TenantDoor) -> crate::types::Result<Synced>;
    /// `Export{table, after, limit, mode}`.
    async fn export(
        &self,
        table: ExportTable,
        after: Option<&[ImportValue]>,
        limit: u32,
        mode: ExportMode,
    ) -> crate::types::Result<Exported>;
    /// The names of every table the unit holds (the preflight of AM-26).
    async fn tables(&self) -> crate::types::Result<Vec<String>>;
}

/// The owner's key chain and the revocations, as the undo holds them (the
/// key lane's code in the Worker).
#[allow(async_fn_in_trait)]
pub trait UndoKeys: OwnerKeys + KeyFreeze {
    /// One page of the owner's revocations `m/rk/<t>/` (a delimited
    /// listing): the key ids after `after`, and where the next page
    /// starts.
    async fn tenant_revocations(
        &self,
        after: Option<&str>,
    ) -> crate::types::Result<(Vec<String>, Option<String>)>;
    /// Puts tenant 0's flat revocation `m/rk/<akid>`, or finds it there.
    async fn put_flat_revocation(&self, akid: &str) -> crate::types::Result<()>;
}

/// The undo's receipt in R2 (AM-28): the `K_u` its step 1 froze at. One
/// receipt per undo of one flip: the wiring names it by the owner and
/// tenant 0's flip stamp, so an undo of a later move never reads an
/// earlier one's.
#[allow(async_fn_in_trait)]
pub trait UndoReceipt {
    /// The `K_u` the receipt names, `None` before step 1 wrote it.
    async fn k_u(&self) -> crate::types::Result<Option<u64>>;
    /// Writes `k_u`, **replacing** what the receipt named (a freeze the
    /// tool ended with `KeysThawed` is replaced by the new one). The tool
    /// reads it back before the tenant record.
    async fn put_k_u(&self, k_u: u64) -> crate::types::Result<()>;
}

/// A bucket made after the move, as D1 stores it.
#[derive(Clone, PartialEq, Eq)]
pub struct BucketBack {
    /// Tenant 0's principal for the bucket.
    pub owner: String,
    /// The bucket key wrapped under the KEK (scheme 1).
    pub bdk_wrapped: Vec<u8>,
    pub kek_version: i64,
}

/// A key made after the move, as D1 stores it.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyBack {
    /// Tenant 0's principal for the key.
    pub principal: String,
    /// The secret wrapped as `ak/v1`.
    pub secret_wrapped: Vec<u8>,
    pub kek_version: i64,
}

/// The reverse wraps and the mirrored checks that need a key (the key
/// lane's code, in the Worker only: plaintexts live in one isolate's
/// memory for the call, never in a log, a message or a row).
#[allow(async_fn_in_trait)]
pub trait ReverseTransform {
    /// A bucket made after the move (`row`: the unit's row): its key
    /// unwrapped under the owner's tenant key and wrapped under the KEK.
    async fn new_bucket(&self, row: &[ImportValue]) -> crate::types::Result<BucketBack>;
    /// A key made after the move: its `ak/v2` secret wrapped as `ak/v1`.
    async fn new_key(&self, entry: &KeyEntry) -> crate::types::Result<KeyBack>;
    /// V4, first half: the bucket key from D1's wrap (`d1`) equals the one
    /// from the unit's (`unit`), compared in constant time.
    async fn same_bdk(
        &self,
        d1: &[ImportValue],
        unit: &[ImportValue],
    ) -> crate::types::Result<bool>;
    /// V4, second half: every file-key wrap of `extents` (D1 rows of the
    /// bucket `d1`) opens under the bucket key from D1's wrap. Answers the
    /// extent ids that did not.
    async fn file_keys_open(
        &self,
        d1: &[ImportValue],
        extents: &[Vec<ImportValue>],
    ) -> crate::types::Result<Vec<String>>;
    /// V5: the secret of D1's `ak/v1` wrap equals the one of the entry's
    /// `ak/v2` wrap.
    async fn same_secret(
        &self,
        d1_secret: &[u8],
        d1_kek_version: i64,
        entry: &KeyEntry,
    ) -> crate::types::Result<bool>;
}

/// The safety copies, back under tenant 0's flat names.
#[allow(async_fn_in_trait)]
pub trait BlobsBack {
    /// Step 4: `x/<t>/<id>` copied to `x/<id>` and read back, its SHA-256
    /// equal to `cipher_sha256`; a flat copy already there is read back
    /// the same way. An error on a mismatch.
    async fn to_flat(&self, extent_id: &str, cipher_sha256: &[u8]) -> crate::types::Result<()>;
    /// V3: `x/<id>` exists and its SHA-256 equals `cipher_sha256` (a full
    /// read).
    async fn flat_ok(&self, extent_id: &str, cipher_sha256: &[u8]) -> crate::types::Result<bool>;
}

/// Step 5's records (the record lane's code).
#[allow(async_fn_in_trait)]
pub trait RecordsBack {
    /// Every `VMR2` record of the owner written after the flip at
    /// `flipped_at`, re-sealed as v1 under tenant 0's layout
    /// (put-if-absent, read back), so a later tenant-0 replay finds
    /// post-move commits and deletes. Resumable. Answers how many it wrote
    /// or found.
    async fn reseal_after_flip(&self, flipped_at: UnixMs) -> crate::types::Result<u64>;
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn door_of(written: Written) -> TenantDoor {
    match written {
        Written::Wrote(record) => record.door,
        Written::Unchanged(read) => read.door,
    }
}

async fn head_of<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    tenant: &Tenant,
) -> Result<TenantDoor> {
    Ok(chain
        .head(tenant, 0)
        .await?
        .ok_or(UndoError::Chain(ChainError::Refused(
            super::transition::Refusal {
                status: 409,
                code: "no_tenant",
            },
        )))?
        .door)
}

fn moved_into(zero: &TenantDoor, owner: &Tenant) -> bool {
    zero.tenant_zero.as_ref().is_some_and(|z| {
        z.selector == Selector::Moved && z.moved.as_ref().is_some_and(|m| m.to == *owner)
    })
}

/// The owner's head, frozen at `k_u` with the root unit's entry set.
async fn frozen_owner<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    owner: &Tenant,
    k_u: u64,
) -> Result<TenantDoor> {
    let head = head_of(chain, owner).await?;
    let frozen = head.keys_frozen.is_some_and(|f| f.at == k_u) && head.restoring_entry(0).is_some();
    match frozen {
        true => Ok(head),
        false => Err(UndoError::NotFrozen),
    }
}

/// Steps 2 to 7 run only inside the undo: the owner frozen at `k_u` with
/// its entry, and tenant 0 still `moved` into the owner, read from its
/// chain. Once tenant 0's undo `d1` record exists, D1 is the catalogue
/// again and no step may write to it (a re-run of the copy would bring
/// back rows deleted since). Answers tenant 0's head.
async fn undo_open<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    owner: &Tenant,
    k_u: u64,
) -> Result<TenantDoor> {
    frozen_owner(chain, owner, k_u).await?;
    let zero = head_of(chain, &Tenant::Zero).await?;
    match moved_into(&zero, owner) {
        true => Ok(zero),
        false => Err(UndoError::NotThisMove),
    }
}

/// The key chain still frozen at `k_u` (AM-28): a thaw that raced the
/// undo, or a `K_u` that is not this freeze's, stops the step.
async fn key_chain_frozen<K: KeyFreeze>(keys: &K, k_u: u64) -> Result<()> {
    match keys.key_head().await?.frozen_at == Some(k_u) {
        true => Ok(()),
        false => Err(UndoError::NotFrozen),
    }
}

fn from_sql(v: &SqlValue) -> ImportValue {
    match v {
        SqlValue::Null => ImportValue::Null,
        SqlValue::Int(n) => ImportValue::Int(*n),
        SqlValue::Text(s) => ImportValue::Text(s.clone()),
        SqlValue::Blob(b) => ImportValue::Blob(b.clone()),
    }
}

fn to_sql(v: &ImportValue) -> SqlValue {
    match v {
        ImportValue::Null => SqlValue::Null,
        ImportValue::Int(n) => SqlValue::Int(*n),
        ImportValue::Text(s) => SqlValue::Text(s.clone()),
        ImportValue::Blob(b) => SqlValue::Blob(b.clone()),
    }
}

fn index(table: ImportTable, column: &str) -> Option<usize> {
    table.columns().iter().position(|c| *c == column)
}

fn get<'a>(table: ImportTable, row: &'a [ImportValue], column: &str) -> Option<&'a ImportValue> {
    index(table, column).and_then(|i| row.get(i))
}

fn put(table: ImportTable, row: &mut [ImportValue], column: &str, value: ImportValue) {
    if let Some(i) = index(table, column) {
        row[i] = value;
    }
}

fn text(v: Option<&ImportValue>) -> Option<&str> {
    match v {
        Some(ImportValue::Text(s)) => Some(s),
        _ => None,
    }
}

fn shape(what: &'static str) -> UndoError {
    UndoError::Store(BridgeError::Invalid(what))
}

fn quoted(cols: &[&str]) -> String {
    cols.iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `(k1, k2) > (?1, ?2)` (or `k1 > ?1`), with parameters from `first`.
fn key_after(table: ImportTable, first: usize) -> String {
    let keys: Vec<String> = table
        .key_columns()
        .iter()
        .map(|k| format!("\"{k}\""))
        .collect();
    let params: Vec<String> = (0..keys.len()).map(|i| format!("?{}", first + i)).collect();
    match keys.len() {
        1 => format!("{} > {}", keys[0], params[0]),
        _ => format!("({}) > ({})", keys.join(", "), params.join(", ")),
    }
}

fn key_at_most(table: ImportTable, first: usize) -> String {
    key_after(table, first).replacen(" > ", " <= ", 1)
}

fn order(table: ImportTable, desc: bool) -> String {
    table
        .key_columns()
        .iter()
        .map(|k| match desc {
            true => format!("\"{k}\" DESC"),
            false => format!("\"{k}\""),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// Step 1: the key freeze
// ---------------------------------------------------------------------------

/// Tries of the freeze against a key chain that moves.
pub const FREEZE_TRIES: u32 = 5;

/// Undo step 1 (and the fallback's first step): see the [module](self).
/// Answers `K_u`.
pub async fn freeze_keys<S, C, Q, U, K, R>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    unit: &U,
    keys: &K,
    receipt: &R,
    owner: &Tenant,
    now: UnixMs,
) -> Result<u64>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
    U: UndoUnit,
    K: KeyFreeze,
    R: UndoReceipt,
{
    let head = head_of(chain, owner).await?;
    let receipt_k_u = receipt.k_u().await?;
    // A repeat: the owner already frozen, with the entry.
    if let (Some(f), Some(_)) = (head.keys_frozen, head.restoring_entry(0)) {
        match receipt_k_u {
            Some(r) if r != f.at => {
                return Err(UndoError::ReceiptDiffers {
                    receipt: r,
                    head: f.at,
                })
            }
            Some(_) => {}
            None => receipt.put_k_u(f.at).await?,
        }
        close(unit, &head).await?;
        dir.apply_tenant(&head, now).await?;
        return Ok(f.at);
    }
    let zero = head_of(chain, &Tenant::Zero).await?;
    if !moved_into(&zero, owner) {
        return Err(UndoError::NotThisMove);
    }
    if head.units != [0] {
        return Err(UndoError::NotOnlyRootUnit);
    }
    if head.restoring_entry(0).is_some() || head.keys_frozen.is_some() {
        return Err(UndoError::EntryWithoutFreeze);
    }
    let k_u = freeze_chain(keys, receipt_k_u).await?;
    // The receipt before the tenant record: a re-run adopts the freeze
    // only through it.
    if receipt_k_u != Some(k_u) {
        receipt.put_k_u(k_u).await?;
        match receipt.k_u().await? {
            Some(r) if r == k_u => {}
            Some(r) => {
                return Err(UndoError::ReceiptDiffers {
                    receipt: r,
                    head: k_u,
                })
            }
            None => return Err(UndoError::NotFrozen),
        }
    }
    let head = door_of(chain.freeze_for_undo(owner, 0, k_u, now, head.seq).await?);
    if head.keys_frozen.map(|f| f.at) != Some(k_u) {
        return Err(UndoError::NotFrozen);
    }
    // No thaw raced the tenant record.
    key_chain_frozen(keys, k_u).await?;
    close(unit, &head).await?;
    dir.apply_tenant(&head, now).await?;
    Ok(k_u)
}

/// The `KeysFrozen` of this undo: adopted when the receipt names it, or
/// put now. A freeze of no undo this receipt knows is ended first.
async fn freeze_chain<K: KeyFreeze>(keys: &K, receipt: Option<u64>) -> Result<u64> {
    // The freeze this run tried to put: a lost answer may hide that it
    // landed.
    let mut tried: Option<u64> = None;
    for _ in 0..FREEZE_TRIES {
        let head = keys.key_head().await?;
        match head.frozen_at {
            Some(f) if Some(f) == receipt || Some(f) == tried => return Ok(f),
            Some(f) => match keys.put_keys_thawed(f).await? {
                KeyPut::Done | KeyPut::Lost => continue,
                KeyPut::Refused(code) => return Err(UndoError::FreezeRefused(code)),
            },
            None => {
                tried = Some(head.seq);
                match keys.put_keys_frozen(head.seq).await {
                    Ok(KeyPut::Done) => return Ok(head.seq),
                    Ok(KeyPut::Lost) | Err(_) => continue,
                    Ok(KeyPut::Refused(code)) => return Err(UndoError::FreezeRefused(code)),
                }
            }
        }
    }
    Err(UndoError::FreezeBusy)
}

async fn close<U: UndoUnit>(unit: &U, owner: &TenantDoor) -> Result<()> {
    match unit.sync(owner).await? {
        Synced::Ok => Ok(()),
        Synced::Refused(r) => Err(UndoError::SyncRefused(r)),
    }
}

// ---------------------------------------------------------------------------
// Preflight and step 2: the fresh D1
// ---------------------------------------------------------------------------

/// The tables of a unit (and of D1) that the reverse move does not page:
/// the key projection (built from the key chain), the stamp and
/// bookkeeping rows (the fresh D1 gets its own), the counters (from a
/// recount), the intents (drained) and the operational tables. Every
/// table named `unit_*` (the unit's own), `sqlite_*` or `_cf_*` is not
/// paged either.
pub const NOT_PAGED: [&str; 14] = [
    "access_keys",
    "d1_migrations",
    "grants",
    "key_floors",
    "meta",
    "provider_health",
    "provider_permits",
    "restore_state",
    "rollback_stamp",
    "scan_cursors",
    "tx_guard",
    "usage_buckets",
    "usage_global",
    "write_intents",
];

fn own_table(name: &str) -> bool {
    name.starts_with("unit_")
        || name.starts_with("sqlite_")
        || name.starts_with("_cf_")
        || NOT_PAGED.contains(&name)
}

/// The preflight of AM-26: every table of the unit is one `Export` pages
/// or one the reverse move does not page by name ([`NOT_PAGED`]), so a
/// table added later by a cohort migration is never left behind
/// silently.
pub async fn preflight<U: UndoUnit>(unit: &U) -> Result<()> {
    let paged: BTreeSet<&str> = ImportTable::ALL.iter().map(|t| t.name()).collect();
    let unknown: Vec<String> = unit
        .tables()
        .await?
        .into_iter()
        .filter(|t| !own_table(t) && !paged.contains(t.as_str()))
        .collect();
    match unknown.is_empty() {
        true => Ok(()),
        false => Err(UndoError::UnknownTables(unknown)),
    }
}

async fn migration_names<S: Sql>(db: &S) -> Result<BTreeSet<String>> {
    let rows = db
        .query(
            "SELECT name FROM d1_migrations ORDER BY id LIMIT 10000",
            &[],
        )
        .await?;
    rows.iter()
        .map(|r| match r.first() {
            Some(SqlValue::Text(n)) => Ok(n.clone()),
            _ => Err(shape("move undo: d1_migrations row")),
        })
        .collect()
}

/// Step 2 on the fresh D1 `fresh`, whose catalogue id is `catalogue_id`,
/// against the frozen one, inside the undo of the move into `owner`
/// frozen at `k_u`. See the [module](self).
pub async fn prepare_fresh<S, C, F, D>(
    chain: &TenantChain<'_, S, C>,
    frozen: &F,
    fresh: &D,
    owner: &Tenant,
    k_u: u64,
    catalogue_id: &str,
) -> Result<()>
where
    S: RecordStore,
    C: ControlSeal,
    F: Sql,
    D: Sql,
{
    let zero = undo_open(chain, owner, k_u).await?;
    let z = zero.tenant_zero.as_ref().ok_or(UndoError::NotThisMove)?;
    let m = z.moved.as_ref().ok_or(UndoError::NotThisMove)?;
    if !super::transition::valid_name(catalogue_id)
        || catalogue_id == m.catalogue_id_frozen
        || catalogue_id == "main"
        || z.frozen_catalogues.iter().any(|c| c == catalogue_id)
    {
        return Err(UndoError::FreshCatalogue("catalogue_id_not_fresh"));
    }
    let tables: BTreeSet<String> = catalogue_tables(fresh).await?.into_iter().collect();
    let needed = ImportTable::ALL.iter().map(|t| t.name()).chain([
        "access_keys",
        "grants",
        "rollback_stamp",
        "meta",
    ]);
    if needed.into_iter().any(|t| !tables.contains(t)) {
        return Err(UndoError::FreshCatalogue("fresh_schema_incomplete"));
    }
    if marker(fresh).await?.is_some() {
        return Err(UndoError::FreshCatalogue("fresh_has_marker"));
    }
    // DEL-4: the same applied names, so `migrations list` reports none
    // pending and the next deploy applies nothing.
    let want = migration_names(frozen).await?;
    let have = migration_names(fresh).await?;
    let missing: Vec<String> = want.difference(&have).cloned().collect();
    let extra: Vec<String> = have.difference(&want).cloned().collect();
    if !missing.is_empty() || !extra.is_empty() {
        return Err(UndoError::Migrations { missing, extra });
    }
    // A fresh level: no stamp object under the new id exists, and the row
    // names the id the Worker of step 8's deploy is configured with.
    fresh
        .exec(
            "INSERT INTO rollback_stamp (id, counter, catalogue_id, rolled_back_at) \
             VALUES (1, 0, ?1, NULL) ON CONFLICT(id) DO NOTHING",
            &[SqlValue::Text(catalogue_id.to_string())],
        )
        .await?;
    match stamp_row(fresh).await? {
        Some((_, id)) if id == catalogue_id => Ok(()),
        _ => Err(UndoError::FreshCatalogue("stamp_row_names_another_id")),
    }
}

// ---------------------------------------------------------------------------
// Step 3 (with step 4): the rows
// ---------------------------------------------------------------------------

/// Rows asked per `Export` page.
pub const PAGE: u32 = MAX_ROWS;

/// Statements per D1 batch of the copy.
pub const WRITE_CHUNK: usize = 100;

/// The most pages one table is read in (a bound on a unit that never
/// says it is done).
pub const MAX_PAGES: u64 = 1 << 20;

/// What the copy did to one table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TableBack {
    pub table: &'static str,
    /// Rows read from the unit and written to the fresh D1 in this run.
    pub rows: u64,
    /// Buckets made after the move (fresh wrap).
    pub new_buckets: u64,
    /// Safety copies put back under their flat names in this run.
    pub flat_copies: u64,
    /// Outbox rows whose expired lease was cleared.
    pub leases_cleared: u64,
}

/// The statement that writes one row of `table` into a D1 catalogue, every
/// column in [`ImportTable::columns`] order (a test holds the two equal;
/// the extents insert is on the `plan_rev` contract's list).
/// The extents insert trigger writes `generation_extents` rows first, so
/// that table keeps an equal row (V1 compares them).
pub fn insert_back(table: ImportTable) -> &'static str {
    match table {
        ImportTable::Buckets => {
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, disposable, \
             created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)"
        }
        ImportTable::Generations => {
            "INSERT INTO generations(id, bucket_id, key, state, size, etag, checksum_json, \
             content_json, user_meta_json, extent_count, created_at, retired_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"
        }
        ImportTable::Objects => {
            "INSERT INTO objects(bucket_id, key, generation_id) VALUES (?1,?2,?3)"
        }
        ImportTable::Extents => {
            "INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, \
             plain_size, cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, \
             plain_sha256, cipher_sha256, safety_state, article_count, plan_rev, \
             last_verified_at, release_evidence, released_at, created_at, hot_safety_bytes, \
             hot_cache_bytes, last_read_at, evict_seq, plan, posted_at, reposted_at, parity, \
             parity_count) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,\
             ?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30)"
        }
        ImportTable::GenerationExtents => {
            "INSERT INTO generation_extents(generation_id, seq, extent_id, plain_offset) \
             VALUES (?1,?2,?3,?4) ON CONFLICT(generation_id, seq) DO NOTHING"
        }
        ImportTable::Articles => {
            "INSERT INTO articles(extent_id, idx, message_id, newsgroup, headers, \
             cipher_offset, cipher_len, payload_sha256, state, provider_id, posted_at, \
             yenc_name, reposted_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)"
        }
        ImportTable::Verifications => {
            "INSERT INTO verifications(extent_id, backbone, provider_id, verified_at, \
             plan_rev, articles_ok, articles_total, result, kind, articles_present, mode) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
        }
        ImportTable::VerifyRaises => {
            "INSERT INTO verify_raises(extent_id, backbone, plan_rev, raised_at) \
             VALUES (?1,?2,?3,?4)"
        }
        ImportTable::VerifyEscalations => {
            "INSERT INTO verify_escalations(backbone, until, raised_at, extent_id, result) \
             VALUES (?1,?2,?3,?4,?5)"
        }
        ImportTable::Outbox => {
            "INSERT INTO outbox(extent_id, generation_id, stage, attempts, next_at, \
             lease_token, lease_owner, lease_until, cursor, last_error, updated_at, sent_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"
        }
        ImportTable::Uploads => {
            "INSERT INTO uploads(id, bucket_id, key, content_json, user_meta_json, state, \
             revision, completed_generation_id, complete_digest, result_etag, initiated_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
        }
        ImportTable::UploadParts => {
            "INSERT INTO upload_parts(upload_id, part_number, extent_id, size, etag, \
             uploaded_at) VALUES (?1,?2,?3,?4,?5,?6)"
        }
        ImportTable::UploadPartExtents => {
            "INSERT INTO upload_part_extents(upload_id, part_number, piece, tenant_id, \
             extent_id) VALUES (?1,?2,?3,?4,?5)"
        }
        ImportTable::Gc => {
            "INSERT INTO gc(id, extent_id, action, due_at, done_at) VALUES (?1,?2,?3,?4,?5)"
        }
        ImportTable::UsageHours => {
            "INSERT INTO usage_hours(hour, posts, verifies, releases, dead, failures) \
             VALUES (?1,?2,?3,?4,?5,?6)"
        }
        ImportTable::UsageRecounts => {
            "INSERT INTO usage_recounts(id, started_at, finished_at, rows, adopted, drift, \
             detail) VALUES (?1,?2,?3,?4,?5,?6,?7)"
        }
    }
}

/// The last key of `table` in `db`, `None` for an empty table: one row
/// read through the primary key.
async fn last_key<D: Sql>(db: &D, table: ImportTable) -> Result<Option<Vec<ImportValue>>> {
    let sql = format!(
        "SELECT {} FROM \"{}\" ORDER BY {} LIMIT 1",
        quoted(table.key_columns()),
        table.name(),
        order(table, true)
    );
    let rows = db.query(&sql, &[]).await?;
    Ok(rows.first().map(|r| r.iter().map(from_sql).collect()))
}

/// Keys compare as SQLite orders them: every integer before every text.
fn key_cmp(a: &[ImportValue], b: &[ImportValue]) -> std::cmp::Ordering {
    fn rank(v: &ImportValue) -> u8 {
        match v {
            ImportValue::Null => 0,
            ImportValue::Int(_) => 1,
            ImportValue::Text(_) => 2,
            ImportValue::Blob(_) => 3,
        }
    }
    for (x, y) in a.iter().zip(b) {
        let o = rank(x).cmp(&rank(y)).then_with(|| match (x, y) {
            (ImportValue::Int(p), ImportValue::Int(q)) => p.cmp(q),
            (ImportValue::Text(p), ImportValue::Text(q)) => p.as_bytes().cmp(q.as_bytes()),
            (ImportValue::Blob(p), ImportValue::Blob(q)) => p.cmp(q),
            _ => std::cmp::Ordering::Equal,
        });
        if o != std::cmp::Ordering::Equal {
            return o;
        }
    }
    a.len().cmp(&b.len())
}

/// The undo a step acts on: the owner, the freeze, the fresh catalogue.
#[derive(Clone, Copy, Debug)]
pub struct Undo<'a> {
    pub owner: &'a Tenant,
    /// `K_u`, from step 1 ([`freeze_keys`]).
    pub k_u: u64,
    /// The fresh D1's catalogue id (step 2).
    pub catalogue_id: &'a str,
}

/// Step 3 with step 4: every table the unit imports, from the unit into
/// the fresh D1. See the [module](self). `now` decides whether an outbox
/// lease is live.
#[allow(clippy::too_many_arguments)]
pub async fn copy_back<S, C, U, F, D, T, B>(
    chain: &TenantChain<'_, S, C>,
    unit: &U,
    frozen: &F,
    fresh: &D,
    transform: &T,
    blobs: &B,
    undo: &Undo<'_>,
    now: UnixMs,
) -> Result<Vec<TableBack>>
where
    S: RecordStore,
    C: ControlSeal,
    U: UndoUnit,
    F: Sql,
    D: Sql,
    T: ReverseTransform,
    B: BlobsBack,
{
    undo_open(chain, undo.owner, undo.k_u).await?;
    // The fresh D1 of this undo, never raised yet: no Worker has served
    // from it, so nothing it holds is newer than the unit.
    match stamp_row(fresh).await? {
        Some((0, id)) if id == undo.catalogue_id => {}
        _ => return Err(UndoError::FreshCatalogue("fresh_not_prepared_or_serving")),
    }
    preflight(unit).await?;
    let mut out = Vec::new();
    for table in ImportTable::ALL {
        out.push(copy_table(unit, frozen, fresh, transform, blobs, table, now).await?);
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
async fn copy_table<U, F, D, T, B>(
    unit: &U,
    frozen: &F,
    fresh: &D,
    transform: &T,
    blobs: &B,
    table: ImportTable,
    now: UnixMs,
) -> Result<TableBack>
where
    U: UndoUnit,
    F: Sql,
    D: Sql,
    T: ReverseTransform,
    B: BlobsBack,
{
    let name = table.name();
    let mut done = TableBack {
        table: name,
        ..TableBack::default()
    };
    // Every table but one is written only here, in key order, so its
    // last key is where an earlier run stopped. The extents insert trigger
    // writes `generation_extents` rows too: that table is sent whole,
    // and a row already there is kept.
    let mut after = match table {
        ImportTable::GenerationExtents => None,
        _ => last_key(fresh, table).await?,
    };
    let width = table.columns().len();
    for _ in 0..MAX_PAGES {
        let answer = unit
            .export(
                ExportTable::Data(table),
                after.as_deref(),
                PAGE,
                ExportMode::Rows,
            )
            .await?;
        let (mut rows, more) = match answer {
            Exported::Rows { rows, more } => (rows, more),
            Exported::Refused(refusal) => {
                return Err(UndoError::ExportRefused {
                    table: name,
                    refusal,
                })
            }
            Exported::Hash { .. } => return Err(UndoError::Diverged { table: name }),
        };
        // The next rows after `after`, in key order, each of the table's
        // width; an empty page ends the table.
        let mut previous = after.clone();
        for row in &rows {
            if row.len() != width {
                return Err(UndoError::Diverged { table: name });
            }
            let key = key_of(ExportTable::Data(table), row);
            if previous
                .as_ref()
                .is_some_and(|p| key_cmp(&key, p) != std::cmp::Ordering::Greater)
            {
                return Err(UndoError::Diverged { table: name });
            }
            previous = Some(key);
        }
        if rows.is_empty() {
            return match more {
                true => Err(UndoError::Diverged { table: name }),
                false => Ok(done),
            };
        }
        transform_page(frozen, transform, blobs, table, &mut rows, &mut done, now).await?;
        for chunk in rows.chunks(WRITE_CHUNK) {
            let mut stmts = Vec::with_capacity(chunk.len());
            for r in chunk {
                stmts.push((insert_back(table), values_back(table, r)?));
            }
            fresh.batch(stmts).await?;
        }
        done.rows += rows.len() as u64;
        after = previous;
        if !more {
            return Ok(done);
        }
    }
    Err(UndoError::Diverged { table: name })
}

/// The bound values of one row. An extent's `plan_rev` is bound through
/// [`crate::plan_rev::bound`]: no revision above the highest this code
/// writes reaches the catalogue (the unit refuses one on import too).
fn values_back(table: ImportTable, row: &[ImportValue]) -> Result<Vec<SqlValue>> {
    let mut out: Vec<SqlValue> = row.iter().map(to_sql).collect();
    if table == ImportTable::Extents {
        let i = index(table, "plan_rev").ok_or(shape("move undo: plan_rev column"))?;
        let rev = match &row[i] {
            ImportValue::Int(r) => u32::try_from(*r).map_err(|_| shape("move undo: plan_rev"))?,
            _ => return Err(shape("move undo: plan_rev")),
        };
        out[i] = crate::plan_rev::bound(rev)?;
    }
    Ok(out)
}

/// The reverse transforms of one page (and step 4 for its extents).
#[allow(clippy::too_many_arguments)]
async fn transform_page<F: Sql, T: ReverseTransform, B: BlobsBack>(
    frozen: &F,
    transform: &T,
    blobs: &B,
    table: ImportTable,
    rows: &mut [Vec<ImportValue>],
    done: &mut TableBack,
    now: UnixMs,
) -> Result<()> {
    match table {
        ImportTable::Buckets => {
            for row in rows.iter_mut() {
                let id = text(get(table, row, "id"))
                    .ok_or(shape("move undo: bucket id"))?
                    .to_string();
                let old = frozen
                    .query(
                        "SELECT owner, bdk_wrapped, kek_version FROM buckets WHERE id = ?1",
                        &[SqlValue::Text(id)],
                    )
                    .await?;
                match old.first().map(|r| r.as_slice()) {
                    // Before the move: the frozen D1's wrap, byte for byte.
                    Some(
                        [owner @ SqlValue::Text(_), wrap @ SqlValue::Blob(_), kek @ SqlValue::Int(_)],
                    ) => {
                        put(table, row, "owner", from_sql(owner));
                        put(table, row, "bdk_wrapped", from_sql(wrap));
                        put(table, row, "kek_version", from_sql(kek));
                    }
                    Some(_) => return Err(shape("move undo: frozen bucket row")),
                    None => {
                        let back = transform.new_bucket(row).await?;
                        put(table, row, "owner", ImportValue::Text(back.owner));
                        put(
                            table,
                            row,
                            "bdk_wrapped",
                            ImportValue::Blob(back.bdk_wrapped),
                        );
                        put(
                            table,
                            row,
                            "kek_version",
                            ImportValue::Int(back.kek_version),
                        );
                        done.new_buckets += 1;
                    }
                }
            }
        }
        ImportTable::Extents => {
            // Held copies first: their flat names before their rows.
            let mut held: Vec<(String, Vec<u8>)> = Vec::new();
            for row in rows.iter_mut() {
                let state = text(get(table, row, "safety_state")).unwrap_or_default();
                let keeps = matches!(state, "held" | "releasing");
                put(table, row, "hot_cache_bytes", ImportValue::Int(0));
                if !keeps {
                    put(table, row, "hot_safety_bytes", ImportValue::Int(0));
                    continue;
                }
                let id = text(get(table, row, "id")).ok_or(shape("move undo: extent id"))?;
                let Some(ImportValue::Blob(sha)) = get(table, row, "cipher_sha256") else {
                    return Err(shape("move undo: extent digest"));
                };
                held.push((id.to_string(), sha.clone()));
            }
            let before = frozen_extents(frozen, &held).await?;
            for (id, sha) in held.iter().filter(|(id, _)| !before.contains(id)) {
                blobs.to_flat(id, sha).await?;
                done.flat_copies += 1;
            }
        }
        ImportTable::Outbox => {
            for row in rows.iter_mut() {
                let leased = !matches!(get(table, row, "lease_owner"), Some(ImportValue::Null))
                    || !matches!(get(table, row, "lease_until"), Some(ImportValue::Null));
                if !leased {
                    continue;
                }
                // Live while `lease_until >= now`, as the outbox holds it.
                if let Some(ImportValue::Int(until)) = get(table, row, "lease_until") {
                    if *until >= now.0 {
                        return Err(UndoError::LiveLease);
                    }
                }
                put(table, row, "lease_owner", ImportValue::Null);
                put(table, row, "lease_until", ImportValue::Null);
                done.leases_cleared += 1;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Which of `held` the frozen D1 holds: point lookups by primary key, at
/// most 100 ids per query.
async fn frozen_extents<F: Sql>(
    frozen: &F,
    held: &[(String, Vec<u8>)],
) -> Result<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    for chunk in held.chunks(100) {
        let params: Vec<String> = (1..=chunk.len()).map(|i| format!("?{i}")).collect();
        let sql = format!("SELECT id FROM extents WHERE id IN ({})", params.join(", "));
        let values: Vec<SqlValue> = chunk
            .iter()
            .map(|(id, _)| SqlValue::Text(id.clone()))
            .collect();
        for row in frozen.query(&sql, &values).await? {
            if let Some(SqlValue::Text(id)) = row.first() {
                found.insert(id.clone());
            }
        }
    }
    Ok(found)
}

// ---------------------------------------------------------------------------
// Step 3, keys: the projection at K_u
// ---------------------------------------------------------------------------

/// Why a key of the chain is not carried to D1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotCarried {
    /// Revoked in the chain at `K_u`.
    Revoked,
    /// A grant with a prefix, an expiry or an address list: D1 cannot hold
    /// the limit, so carrying it would widen it.
    LimitedGrant,
    /// An app password made after the move: D1 cannot hold the kind.
    AppPassword,
    /// No secret in the chain.
    NoSecret,
}

/// One key of the owner as D1 gets it.
#[derive(Clone, PartialEq, Eq)]
pub struct CarriedKey {
    pub entry: KeyEntry,
    /// `active` or `disabled`.
    pub active: bool,
    /// The effective grant per bucket.
    pub grants: BTreeMap<String, Access>,
}

impl std::fmt::Debug for CarriedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CarriedKey")
            .field("id", &self.entry.id)
            .field("active", &self.active)
            .field("grants", &self.grants.len())
            .finish()
    }
}

/// The owner's keys at `K_u`, as D1 is built from them (AM-28).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Projection {
    pub carried: BTreeMap<String, CarriedKey>,
    /// Keys of the chain that D1 does not get, and why.
    pub not_carried: BTreeMap<String, NotCarried>,
    /// Every subject the chain holds at `K_u` that is an access key (with a
    /// `made_by`): the routes step 6 moves.
    pub keys: BTreeSet<String>,
}

/// The last state of each subject in `entries` (chain order), a subject
/// once revoked staying revoked, as the unit applies them.
fn fold(entries: Vec<KeyEntry>) -> BTreeMap<String, (KeyEntry, bool)> {
    let mut last: BTreeMap<String, (KeyEntry, bool)> = BTreeMap::new();
    for e in entries {
        let revoked =
            e.status == SubjectStatus::Revoked || last.get(&e.id).is_some_and(|(_, r)| *r);
        last.insert(e.id.clone(), (e, revoked));
    }
    last
}

fn whole(g: &crate::unit::keys::KeyGrant) -> bool {
    g.prefix.is_none() && g.expires_at.is_none() && g.ip_list.is_empty()
}

/// A subject's grants per bucket, the widest among them.
fn widest(e: &KeyEntry) -> BTreeMap<String, Access> {
    let mut out: BTreeMap<String, Access> = BTreeMap::new();
    for g in e.grants.iter().filter(|g| whole(g)) {
        let a = out.entry(g.bucket_id.clone()).or_insert(g.access);
        *a = (*a).max(g.access);
    }
    out
}

/// The projection of the owner's chain `entries` (every record up to
/// `K_u`, chain order). `before_move` says whether the frozen D1 holds a
/// key; `buckets` are the bucket ids D1 holds (a grant on another is not
/// carried). Pure: the build and V6 make it the same way.
pub fn project(
    entries: Vec<KeyEntry>,
    before_move: &BTreeSet<String>,
    buckets: &BTreeSet<String>,
) -> Projection {
    let subjects = fold(entries);
    let mut out = Projection::default();
    for (id, (e, revoked)) in &subjects {
        if matches!(e.kind, KeyKind::Principal | KeyKind::Internal) || e.made_by.is_none() {
            continue;
        }
        out.keys.insert(id.clone());
        let existed = before_move.contains(id);
        let why = if *revoked {
            Some(NotCarried::Revoked)
        } else if e.grants.iter().any(|g| !whole(g)) {
            Some(NotCarried::LimitedGrant)
        } else if e.kind == KeyKind::AppPassword && !existed {
            Some(NotCarried::AppPassword)
        } else if e.secret_wrapped.is_none() && !existed {
            Some(NotCarried::NoSecret)
        } else {
            None
        };
        if let Some(why) = why {
            out.not_carried.insert(id.clone(), why);
            continue;
        }
        // Up the `made_by` chain: each a principal, each open, the lower
        // access per bucket (ADR §6.2). A chain that does not end within
        // the bound, or names a missing subject, leaves the key disabled.
        let mut active = e.status == SubjectStatus::Active && !e.held;
        let mut grants: BTreeMap<String, Access> = widest(e)
            .into_iter()
            .filter(|(b, _)| buckets.contains(b))
            .collect();
        let mut up = e.made_by.clone();
        let mut seen = BTreeSet::from([id.clone()]);
        let mut depth = 0;
        while let Some(p) = up {
            depth += 1;
            let principal = subjects
                .get(&p)
                .filter(|_| depth <= MAX_DEPTH && seen.insert(p.clone()));
            let Some((pe, prevoked)) = principal else {
                active = false;
                break;
            };
            if pe.kind != KeyKind::Principal
                || *prevoked
                || pe.status != SubjectStatus::Active
                || pe.held
            {
                active = false;
            }
            let theirs = widest(pe);
            grants = grants
                .into_iter()
                .filter_map(|(b, a)| theirs.get(&b).map(|pa| (b, a.min(*pa))))
                .collect();
            up = pe.made_by.clone();
        }
        out.carried.insert(
            id.clone(),
            CarriedKey {
                entry: e.clone(),
                active,
                grants,
            },
        );
    }
    out
}

/// Every entry of the owner's chain up to `k_u`, in chain order. The
/// freeze records (`KeysFrozen`, `KeysThawed`) are no subject's entry, so
/// `K_u` itself may be one: a page that ends below `k_u` and a next one
/// that is empty end the read.
pub async fn entries_to<K: OwnerKeys>(keys: &K, k_u: u64) -> Result<Vec<KeyEntry>> {
    let mut out = Vec::new();
    let mut from = 0u64;
    while from < k_u {
        let page = keys.entries(from, MAX_ENTRIES).await?;
        let Some(last) = page.last().map(|e| e.last_seq) else {
            // No entry follows `from`: only freeze records up to the head,
            // which must reach `k_u`.
            if keys.head().await? < k_u {
                return Err(UndoError::Keys(KeyStepError::Diverged));
            }
            break;
        };
        if last <= from {
            return Err(UndoError::Keys(KeyStepError::Diverged));
        }
        // A held entry may lack its private grant limits: the move sends
        // records as they state, never held.
        if let Some(e) = page.iter().find(|e| e.held && e.last_seq <= k_u) {
            return Err(UndoError::Keys(KeyStepError::HeldEntry(e.id.clone())));
        }
        out.extend(page.into_iter().filter(|e| e.last_seq <= k_u));
        from = last;
    }
    Ok(out)
}

/// The ids among `ids` that `db`'s `access_keys` holds (point lookups).
async fn keys_held<D: Sql>(db: &D, ids: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    let ids: Vec<&String> = ids.iter().collect();
    let mut found = BTreeSet::new();
    for chunk in ids.chunks(100) {
        let params: Vec<String> = (1..=chunk.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "SELECT access_key_id FROM access_keys WHERE access_key_id IN ({})",
            params.join(", ")
        );
        let values: Vec<SqlValue> = chunk
            .iter()
            .map(|id| SqlValue::Text((*id).clone()))
            .collect();
        for row in db.query(&sql, &values).await? {
            if let Some(SqlValue::Text(id)) = row.first() {
                found.insert(id.clone());
            }
        }
    }
    Ok(found)
}

/// The bucket ids of `db` (a D1 catalogue: at most a few hundred; read by
/// pages of the primary key).
async fn bucket_ids<D: Sql>(db: &D) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    let mut after = String::new();
    loop {
        let rows = db
            .query(
                "SELECT id FROM buckets WHERE id > ?1 ORDER BY id LIMIT 500",
                &[SqlValue::Text(after.clone())],
            )
            .await?;
        for row in &rows {
            match row.first() {
                Some(SqlValue::Text(id)) => {
                    out.insert(id.clone());
                    after = id.clone();
                }
                _ => return Err(shape("move undo: bucket id")),
            }
        }
        if rows.len() < 500 {
            return Ok(out);
        }
    }
}

/// What the key build did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeysBack {
    /// Keys D1 holds now, and whether each is `active`.
    pub carried: BTreeMap<String, bool>,
    /// Keys made after the move, with a fresh `ak/v1` wrap.
    pub new_keys: u64,
    /// Keys not carried, and why: the list for the owner.
    pub not_carried: BTreeMap<String, NotCarried>,
    /// Keys the revocation override set `disabled`.
    pub overridden: Vec<String>,
}

/// Step 3's keys on `d1` (the fresh D1, or the fallback's thawed one),
/// from the owner's chain up to `k_u`, then the first revocation override.
/// See the [module](self). The owner's head must carry the freeze at
/// `k_u`.
#[allow(clippy::too_many_arguments)]
pub async fn build_keys<S, C, F, D, K, T>(
    chain: &TenantChain<'_, S, C>,
    frozen: &F,
    d1: &D,
    keys: &K,
    transform: &T,
    owner: &Tenant,
    k_u: u64,
) -> Result<KeysBack>
where
    S: RecordStore,
    C: ControlSeal,
    F: Sql,
    D: Sql,
    K: UndoKeys,
    T: ReverseTransform,
{
    undo_open(chain, owner, k_u).await?;
    key_chain_frozen(keys, k_u).await?;
    let entries = entries_to(keys, k_u).await?;
    let ids: BTreeSet<String> = entries.iter().map(|e| e.id.clone()).collect();
    let before = keys_held(frozen, &ids).await?;
    let buckets = bucket_ids(d1).await?;
    let projection = project(entries, &before, &buckets);
    let mut out = KeysBack {
        not_carried: projection.not_carried.clone(),
        ..KeysBack::default()
    };
    for (id, key) in &projection.carried {
        let (principal, secret, kek, created) = match before.contains(id) {
            true => {
                let rows = frozen
                    .query(
                        "SELECT principal, secret_wrapped, kek_version, created_at \
                         FROM access_keys WHERE access_key_id = ?1",
                        &[SqlValue::Text(id.clone())],
                    )
                    .await?;
                match rows.first().map(|r| r.as_slice()) {
                    Some(
                        [p @ SqlValue::Text(_), s @ SqlValue::Blob(_), k @ SqlValue::Int(_), c @ SqlValue::Int(_)],
                    ) => (p.clone(), s.clone(), k.clone(), c.clone()),
                    _ => return Err(shape("move undo: frozen key row")),
                }
            }
            false => {
                let back = transform.new_key(&key.entry).await?;
                out.new_keys += 1;
                let created = i64::try_from(key.entry.created_at)
                    .map_err(|_| shape("move undo: key created_at"))?;
                (
                    SqlValue::Text(back.principal),
                    SqlValue::Blob(back.secret_wrapped),
                    SqlValue::Int(back.kek_version),
                    SqlValue::Int(created),
                )
            }
        };
        let status = match key.active {
            true => "active",
            false => "disabled",
        };
        let idv = SqlValue::Text(id.clone());
        let mut stmts: Vec<(&'static str, Vec<SqlValue>)> =
            vec![
            ("DELETE FROM grants WHERE access_key_id = ?1", vec![idv.clone()]),
            (
                "INSERT INTO access_keys(access_key_id, principal, secret_wrapped, kek_version, \
                 status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(access_key_id) DO UPDATE SET principal = excluded.principal, \
                 secret_wrapped = excluded.secret_wrapped, kek_version = excluded.kek_version, \
                 status = excluded.status, created_at = excluded.created_at",
                vec![
                    idv.clone(),
                    principal,
                    secret,
                    kek,
                    SqlValue::Text(status.into()),
                    created,
                ],
            ),
        ];
        for (bucket, access) in &key.grants {
            stmts.push((
                "INSERT INTO grants(access_key_id, bucket_id, perm) VALUES (?1, ?2, ?3)",
                vec![
                    idv.clone(),
                    SqlValue::Text(bucket.clone()),
                    SqlValue::Text(access.as_str().into()),
                ],
            ));
        }
        d1.batch(stmts).await?;
        out.carried.insert(id.clone(), key.active);
    }
    // A key not carried that D1 holds (the thawed D1 of the fallback): no
    // longer served.
    let gone: BTreeSet<String> = projection.not_carried.keys().cloned().collect();
    remove(d1, &gone).await?;
    out.overridden = override_revocations(d1, keys).await?;
    for id in &out.overridden {
        out.carried.remove(id);
    }
    Ok(out)
}

/// Keys per D1 batch of [`remove`] (two statements each).
pub const REMOVE_CHUNK: usize = 50;

/// The rows of `ids` and their grants removed from `d1`, as tenant 0's
/// revoke removes them (`delete_access_keys`). A key `d1` does not hold
/// is left alone. Idempotent.
async fn remove<D: Sql>(d1: &D, ids: &BTreeSet<String>) -> Result<()> {
    let ids: Vec<&String> = ids
        .iter()
        .filter(|id| crate::recovery::valid_key_id(id))
        .collect();
    for chunk in ids.chunks(REMOVE_CHUNK) {
        let mut stmts: Vec<(&'static str, Vec<SqlValue>)> = Vec::with_capacity(chunk.len() * 2);
        for id in chunk {
            let id = vec![SqlValue::Text((*id).clone())];
            stmts.push(("DELETE FROM grants WHERE access_key_id = ?1", id.clone()));
            stmts.push(("DELETE FROM access_keys WHERE access_key_id = ?1", id));
        }
        d1.batch(stmts).await?;
    }
    Ok(())
}

/// The most pages of one revocation listing.
pub const MAX_REVOCATION_PAGES: usize = 10_000;

async fn list_all<'a, Fut>(mut page: impl FnMut(Option<String>) -> Fut) -> Result<BTreeSet<String>>
where
    Fut: std::future::Future<Output = crate::types::Result<(Vec<String>, Option<String>)>> + 'a,
{
    let mut ids = BTreeSet::new();
    let mut after: Option<String> = None;
    for _ in 0..MAX_REVOCATION_PAGES {
        let (got, next) = page(after.clone()).await?;
        ids.extend(got);
        match next {
            Some(n) if Some(&n) != after.as_ref() => after = Some(n),
            Some(_) => return Err(UndoError::Keys(KeyStepError::Diverged)),
            None => return Ok(ids),
        }
    }
    Err(UndoError::Keys(KeyStepError::Diverged))
}

/// Every revocation the undo knows: the owner's `m/rk/<t>/` and tenant
/// 0's flat `m/rk/` (delimited listings).
async fn revocations<K: UndoKeys>(keys: &K) -> Result<BTreeSet<String>> {
    let mut ids =
        list_all(|after| async move { keys.tenant_revocations(after.as_deref()).await }).await?;
    ids.extend(
        list_all(|after| async move { keys.flat_revocations(after.as_deref()).await }).await?,
    );
    Ok(ids)
}

/// The revocation override (AM-28): the row and the grants of every key
/// named by an `m/rk/<t>/` or a flat `m/rk/` are removed from `d1`. Run as
/// the build's last act and again just before the lift deploy, after
/// tenant 0's `d1` record. Answers the key ids it found in `d1` and
/// removed.
pub async fn override_revocations<D: Sql, K: UndoKeys>(d1: &D, keys: &K) -> Result<Vec<String>> {
    let ids = revocations(keys).await?;
    let held = keys_held(d1, &ids).await?;
    remove(d1, &held).await?;
    Ok(held.into_iter().collect())
}

// ---------------------------------------------------------------------------
// Step 5: revocations and records
// ---------------------------------------------------------------------------

/// What step 5 did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordsBackDone {
    /// Flat revocations put (or found).
    pub flat_revocations: u64,
    /// Records re-sealed (or found).
    pub records: u64,
}

/// Step 5: see the [module](self). `flipped_at` is the flip's time, from
/// tenant 0's head.
#[allow(clippy::too_many_arguments)]
pub async fn revocations_back<S, C, F, K, R>(
    chain: &TenantChain<'_, S, C>,
    frozen: &F,
    keys: &K,
    records: &R,
    owner: &Tenant,
    k_u: u64,
) -> Result<RecordsBackDone>
where
    S: RecordStore,
    C: ControlSeal,
    F: Sql,
    K: UndoKeys,
    R: RecordsBack,
{
    let zero = undo_open(chain, owner, k_u).await?;
    let flipped_at = zero
        .tenant_zero
        .as_ref()
        .and_then(|z| z.moved.as_ref())
        .filter(|m| m.to == *owner)
        .and_then(|m| m.flipped_at)
        .ok_or(UndoError::NotThisMove)?;
    let entries = entries_to(keys, k_u).await?;
    let all: BTreeSet<String> = entries.iter().map(|e| e.id.clone()).collect();
    let before = keys_held(frozen, &all).await?;
    let projection = project(entries, &before, &BTreeSet::new());
    // Revoked in the chain at `K_u`, and the owner's revocations.
    let mut ids: BTreeSet<String> = projection
        .not_carried
        .iter()
        .filter(|(_, why)| **why == NotCarried::Revoked)
        .map(|(id, _)| id.clone())
        .collect();
    ids.extend(
        list_all(|after| async move { keys.tenant_revocations(after.as_deref()).await }).await?,
    );
    // Keys D1 cannot hold: revoked for good, listed for the owner.
    ids.extend(
        projection
            .not_carried
            .iter()
            .filter(|(_, why)| matches!(why, NotCarried::LimitedGrant | NotCarried::AppPassword))
            .map(|(id, _)| id.clone()),
    );
    let mut done = RecordsBackDone::default();
    for id in ids.iter().filter(|id| crate::recovery::valid_key_id(id)) {
        keys.put_flat_revocation(id).await?;
        done.flat_revocations += 1;
    }
    done.records = records.reseal_after_flip(flipped_at).await?;
    Ok(done)
}

// ---------------------------------------------------------------------------
// Step 6: routes
// ---------------------------------------------------------------------------

fn route_kind_of(akid: &str) -> RouteKind {
    match akid.starts_with(APP_PASSWORD_PREFIX) {
        true => RouteKind::AppPassword,
        false => RouteKind::S3,
    }
}

/// Step 6: every access key the owner's chain holds at `k_u`, its route
/// record and its directory row back on tenant 0. A key with neither is
/// left alone (nothing routes it to the owner). Answers how many routes
/// it moved or found moved.
pub async fn routes_back<S, C, Q, R, K>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    routes: &R,
    keys: &K,
    owner: &Tenant,
    k_u: u64,
) -> Result<u64>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
    R: RouteRecords,
    K: OwnerKeys,
{
    undo_open(chain, owner, k_u).await?;
    let zero = Tenant::Zero;
    let entries = entries_to(keys, k_u).await?;
    let ids = project(entries, &BTreeSet::new(), &BTreeSet::new()).keys;
    let mut moved = 0u64;
    for akid in &ids {
        let row = dir.route(akid).await?;
        if let Some(r) = &row {
            if r.tenant != zero && r.tenant != *owner {
                return Err(UndoError::RouteRow(akid.clone()));
            }
        }
        let kind = row.as_ref().map_or_else(|| route_kind_of(akid), |r| r.kind);
        match routes.get(akid).await?.as_deref() {
            None => {}
            Some(t) if t == zero.as_str() => {}
            Some(t) if t == owner.as_str() => {
                if !routes.replace(akid, owner, &zero, kind).await? {
                    return Err(UndoError::RouteTaken(akid.clone()));
                }
            }
            Some(_) => return Err(UndoError::RouteTaken(akid.clone())),
        }
        if row.is_some_and(|r| r.tenant == *owner) && !dir.move_route(akid, owner, &zero).await? {
            let again = dir.route(akid).await?;
            if !again.is_some_and(|r| r.tenant == zero) {
                return Err(UndoError::RouteRow(akid.clone()));
            }
        }
        moved += 1;
    }
    Ok(moved)
}

// ---------------------------------------------------------------------------
// Step 7: the mirrored checks
// ---------------------------------------------------------------------------

/// What the mirrored checks counted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedBack {
    /// V1: rows compared per table.
    pub rows: BTreeMap<&'static str, u64>,
    /// V3: held extents read back.
    pub held: u64,
    /// V4: buckets and file keys opened.
    pub buckets: u64,
    pub file_keys: u64,
    /// V5 and V6: keys compared.
    pub keys: u64,
}

fn fail(check: &'static str, mut ids: Vec<String>) -> UndoError {
    ids.truncate(MAX_LISTED);
    UndoError::Verify { check, ids }
}

/// Step 7: V1, V3, V4, V5 and V6, mirrored, on the fresh D1 `fresh`. See
/// the [module](self). The owner's head must carry the freeze at `k_u`.
#[allow(clippy::too_many_arguments)]
pub async fn verify_back<S, C, U, F, D, K, T, B>(
    chain: &TenantChain<'_, S, C>,
    unit: &U,
    frozen: &F,
    fresh: &D,
    keys: &K,
    transform: &T,
    blobs: &B,
    owner: &Tenant,
    k_u: u64,
) -> Result<VerifiedBack>
where
    S: RecordStore,
    C: ControlSeal,
    U: UndoUnit,
    F: Sql,
    D: Sql,
    K: UndoKeys,
    T: ReverseTransform,
    B: BlobsBack,
{
    undo_open(chain, owner, k_u).await?;
    let mut done = VerifiedBack::default();
    for table in ImportTable::ALL {
        let n = v1_table(unit, fresh, table).await?;
        done.rows.insert(table.name(), n);
    }
    done.held = v3(fresh, blobs).await?;
    let (buckets, file_keys) = v4(unit, fresh, transform).await?;
    done.buckets = buckets;
    done.file_keys = file_keys;
    done.keys = v5_v6(frozen, fresh, keys, transform, k_u).await?;
    Ok(done)
}

/// V1 for one table: the unit's pages in `hash` mode against the same key
/// range of the fresh D1, then no row of the fresh D1 after the unit's
/// last.
async fn v1_table<U: UndoUnit, D: Sql>(unit: &U, fresh: &D, table: ImportTable) -> Result<u64> {
    let name = table.name();
    let cols = quoted(table.columns());
    let mut after: Option<Vec<ImportValue>> = None;
    let mut total = 0u64;
    for _ in 0..MAX_PAGES {
        let answer = unit
            .export(
                ExportTable::Data(table),
                after.as_deref(),
                PAGE,
                ExportMode::Hash,
            )
            .await?;
        let (count, last, sha256, more) = match answer {
            Exported::Hash {
                count,
                last,
                sha256,
                more,
            } => (count, last, sha256, more),
            Exported::Refused(refusal) => {
                return Err(UndoError::ExportRefused {
                    table: name,
                    refusal,
                })
            }
            Exported::Rows { .. } => return Err(UndoError::Diverged { table: name }),
        };
        let Some(last) = last else {
            if count != 0 || more {
                return Err(UndoError::Diverged { table: name });
            }
            break;
        };
        let n = table.key_columns().len();
        let (sql, mut params) = match &after {
            None => (
                format!(
                    "SELECT {cols} FROM \"{name}\" WHERE {} ORDER BY {} LIMIT ?{}",
                    key_at_most(table, 1),
                    order(table, false),
                    n + 1
                ),
                Vec::new(),
            ),
            Some(a) => (
                format!(
                    "SELECT {cols} FROM \"{name}\" WHERE {} AND {} ORDER BY {} LIMIT ?{}",
                    key_after(table, 1),
                    key_at_most(table, n + 1),
                    order(table, false),
                    2 * n + 1
                ),
                a.iter().map(to_sql).collect::<Vec<_>>(),
            ),
        };
        params.extend(last.iter().map(to_sql));
        params.push(SqlValue::Int(i64::try_from(count + 1).unwrap_or(i64::MAX)));
        let rows: Vec<Vec<ImportValue>> = fresh
            .query(&sql, &params)
            .await?
            .iter()
            .map(|r| r.iter().map(from_sql).collect())
            .collect();
        let ours = hash_rows(ExportTable::Data(table), &rows)?;
        if rows.len() as u64 != count || ours != sha256 {
            return Err(fail("v1", vec![name.to_string()]));
        }
        total += count;
        after = Some(last);
        if !more {
            break;
        }
    }
    // Nothing after the unit's last row.
    if let Some(a) = &after {
        let sql = format!(
            "SELECT 1 FROM \"{name}\" WHERE {} LIMIT 1",
            key_after(table, 1)
        );
        let params: Vec<SqlValue> = a.iter().map(to_sql).collect();
        if !fresh.query(&sql, &params).await?.is_empty() {
            return Err(fail("v1", vec![name.to_string()]));
        }
    } else if last_key(fresh, table).await?.is_some() {
        return Err(fail("v1", vec![name.to_string()]));
    }
    Ok(total)
}

/// V3: every held or releasing extent of the fresh D1 has its flat safety
/// copy with its digest (a full read; such extents are few). Pages the
/// `extents_safety` index.
async fn v3<D: Sql, B: BlobsBack>(fresh: &D, blobs: &B) -> Result<u64> {
    let mut after = String::new();
    let mut failed = Vec::new();
    let mut n = 0u64;
    loop {
        let rows = fresh
            .query(
                // The index's own condition, word for word: the planner
                // takes a partial index only then.
                "SELECT id, cipher_sha256 FROM extents INDEXED BY extents_safety \
                 WHERE safety_state IN ('held', 'releasing') AND id > ?1 ORDER BY id LIMIT 500",
                &[SqlValue::Text(after.clone())],
            )
            .await?;
        for row in &rows {
            let (Some(SqlValue::Text(id)), Some(SqlValue::Blob(sha))) = (row.first(), row.get(1))
            else {
                return Err(shape("move undo: held extent row"));
            };
            if !blobs.flat_ok(id, sha).await? {
                failed.push(id.clone());
            }
            after = id.clone();
            n += 1;
        }
        if rows.len() < 500 {
            break;
        }
    }
    match failed.is_empty() {
        true => Ok(n),
        false => Err(fail("v3", failed)),
    }
}

/// V4: each bucket's key from D1's wrap equals the one from the unit's,
/// and every file key of every extent opens under D1's.
async fn v4<U: UndoUnit, D: Sql, T: ReverseTransform>(
    unit: &U,
    fresh: &D,
    transform: &T,
) -> Result<(u64, u64)> {
    let table = ImportTable::Buckets;
    let cols = quoted(table.columns());
    // The unit's bucket rows.
    let mut theirs: BTreeMap<String, Vec<ImportValue>> = BTreeMap::new();
    let mut after: Option<Vec<ImportValue>> = None;
    for _ in 0..MAX_PAGES {
        match unit
            .export(
                ExportTable::Data(table),
                after.as_deref(),
                PAGE,
                ExportMode::Rows,
            )
            .await?
        {
            Exported::Rows { rows, more } => {
                for row in rows {
                    let id = text(get(table, &row, "id"))
                        .ok_or(shape("move undo: bucket id"))?
                        .to_string();
                    after = Some(key_of(ExportTable::Data(table), &row));
                    theirs.insert(id, row);
                }
                if !more {
                    break;
                }
            }
            Exported::Refused(refusal) => {
                return Err(UndoError::ExportRefused {
                    table: table.name(),
                    refusal,
                })
            }
            Exported::Hash { .. } => {
                return Err(UndoError::Diverged {
                    table: table.name(),
                })
            }
        }
    }
    let mut ours: BTreeMap<String, Vec<ImportValue>> = BTreeMap::new();
    let mut failed = Vec::new();
    for id in bucket_ids(fresh).await? {
        let rows = fresh
            .query(
                &format!("SELECT {cols} FROM buckets WHERE id = ?1"),
                &[SqlValue::Text(id.clone())],
            )
            .await?;
        let row: Vec<ImportValue> = rows
            .first()
            .ok_or(shape("move undo: bucket row"))?
            .iter()
            .map(from_sql)
            .collect();
        match theirs.get(&id) {
            Some(unit_row) if transform.same_bdk(&row, unit_row).await? => {}
            _ => failed.push(id.clone()),
        }
        ours.insert(id, row);
    }
    if !failed.is_empty() || ours.len() != theirs.len() {
        failed.extend(theirs.keys().filter(|id| !ours.contains_key(*id)).cloned());
        return Err(fail("v4", failed));
    }
    // Every extent's file key, in pages of the primary key, grouped by
    // bucket within the page.
    let ext = ImportTable::Extents;
    let ecols = quoted(ext.columns());
    let mut after = String::new();
    let mut opened = 0u64;
    loop {
        let rows = fresh
            .query(
                &format!("SELECT {ecols} FROM extents WHERE id > ?1 ORDER BY id LIMIT 500"),
                &[SqlValue::Text(after.clone())],
            )
            .await?;
        let mut by_bucket: BTreeMap<String, Vec<Vec<ImportValue>>> = BTreeMap::new();
        for r in &rows {
            let row: Vec<ImportValue> = r.iter().map(from_sql).collect();
            let id = text(get(ext, &row, "id")).ok_or(shape("move undo: extent id"))?;
            after = id.to_string();
            let bucket = text(get(ext, &row, "bucket_id"))
                .ok_or(shape("move undo: extent bucket"))?
                .to_string();
            by_bucket.entry(bucket).or_default().push(row);
        }
        for (bucket, extents) in &by_bucket {
            let Some(b) = ours.get(bucket) else {
                failed.extend(
                    extents
                        .iter()
                        .filter_map(|e| text(get(ext, e, "id")).map(str::to_string)),
                );
                continue;
            };
            failed.extend(transform.file_keys_open(b, extents).await?);
            opened += extents.len() as u64;
        }
        if rows.len() < 500 {
            break;
        }
    }
    match failed.is_empty() {
        true => Ok((ours.len() as u64, opened)),
        false => Err(fail("v4", failed)),
    }
}

/// V5 and V6: D1's keys against the projection of the chain up to `k_u`
/// with the override, and every carried key's secret against the chain's.
async fn v5_v6<F: Sql, D: Sql, K: UndoKeys, T: ReverseTransform>(
    frozen: &F,
    fresh: &D,
    keys: &K,
    transform: &T,
    k_u: u64,
) -> Result<u64> {
    let entries = entries_to(keys, k_u).await?;
    let ids: BTreeSet<String> = entries.iter().map(|e| e.id.clone()).collect();
    let before = keys_held(frozen, &ids).await?;
    let buckets = bucket_ids(fresh).await?;
    let projection = project(entries, &before, &buckets);
    let revoked = revocations(keys).await?;
    let mut failed = Vec::new();
    let mut secrets = Vec::new();
    // Exactly the carried keys that no revocation names.
    let want: BTreeMap<String, (bool, BTreeMap<String, Access>)> = projection
        .carried
        .iter()
        .filter(|(id, _)| !revoked.contains(*id))
        .map(|(id, key)| (id.clone(), (key.active, key.grants.clone())))
        .collect();
    // Every row of D1's `access_keys`, by pages of the key.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut after = String::new();
    loop {
        let rows = fresh
            .query(
                "SELECT access_key_id, secret_wrapped, kek_version, status FROM access_keys \
                 WHERE access_key_id > ?1 ORDER BY access_key_id LIMIT 500",
                &[SqlValue::Text(after.clone())],
            )
            .await?;
        for row in &rows {
            let (
                Some(SqlValue::Text(id)),
                Some(SqlValue::Blob(secret)),
                Some(SqlValue::Int(kek)),
                Some(SqlValue::Text(status)),
            ) = (row.first(), row.get(1), row.get(2), row.get(3))
            else {
                return Err(shape("move undo: access key row"));
            };
            after = id.clone();
            seen.insert(id.clone());
            let grants = fresh
                .query(
                    "SELECT bucket_id, perm FROM grants WHERE access_key_id = ?1 \
                     ORDER BY bucket_id LIMIT 1000",
                    &[SqlValue::Text(id.clone())],
                )
                .await?;
            let mut have: BTreeMap<String, Access> = BTreeMap::new();
            for g in &grants {
                let access = match g.get(1) {
                    Some(SqlValue::Text(p)) if p == "rw" => Access::Rw,
                    Some(SqlValue::Text(p)) if p == "ro" => Access::Ro,
                    _ => return Err(shape("move undo: grant row")),
                };
                match g.first() {
                    Some(SqlValue::Text(b)) => {
                        have.insert(b.clone(), access);
                    }
                    _ => return Err(shape("move undo: grant row")),
                }
            }
            match want.get(id) {
                Some((active, grants)) => {
                    if (status == "active") != *active || have != *grants {
                        failed.push(id.clone());
                    }
                    let key = &projection.carried[id];
                    if !transform.same_secret(secret, *kek, &key.entry).await? {
                        secrets.push(id.clone());
                    }
                }
                // A row of no carried key, or of a revoked one.
                None => failed.push(id.clone()),
            }
        }
        if rows.len() < 500 {
            break;
        }
    }
    failed.extend(want.keys().filter(|id| !seen.contains(*id)).cloned());
    if !secrets.is_empty() {
        return Err(fail("v5", secrets));
    }
    match failed.is_empty() {
        true => Ok(want.len() as u64),
        false => Err(fail("v6", failed)),
    }
}

// ---------------------------------------------------------------------------
// Step 8: the flip back
// ---------------------------------------------------------------------------

/// What step 8 did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlippedBack {
    /// The undo stamp tenant 0's `d1` record carries.
    pub undo_stamp: u64,
    /// Whether this run wrote that record (`false`: found).
    pub wrote: bool,
    /// Keys the second override set `disabled`.
    pub overridden: Vec<String>,
    /// Whether this run removed the owner's placements.
    pub unplaced: bool,
}

/// Step 8 of the reverse move, after the deploy with the fresh D1's
/// binding (CI): tenant 0's record `d1` with the undo stamp (one above
/// the flip's) and the fresh catalogue id, the directory's copy of it,
/// the second revocation override on `fresh`, then the exit order of
/// AM-23. The lift deploy follows (CI). The owner's head must carry the
/// freeze at `k_u`.
#[allow(clippy::too_many_arguments)]
pub async fn flip_back<S, C, Q, D, K>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    fresh: &D,
    keys: &K,
    owner: &Tenant,
    k_u: u64,
    catalogue_id: &str,
    now: UnixMs,
) -> Result<FlippedBack>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
    D: Sql,
    K: UndoKeys,
{
    flip_back_to(
        chain,
        dir,
        fresh,
        keys,
        owner,
        k_u,
        Back::Fresh(catalogue_id),
        now,
    )
    .await
}

/// Step 8 of the fallback route, after the tool levelled the frozen
/// catalogue's stamp to `levelled_to` (at or above the flip's):
/// `UndoMoveOntoFrozen`, then as [`flip_back`] on the thawed D1.
#[allow(clippy::too_many_arguments)]
pub async fn flip_back_onto_frozen<S, C, Q, D, K>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    thawed: &D,
    keys: &K,
    owner: &Tenant,
    k_u: u64,
    levelled_to: u64,
    now: UnixMs,
) -> Result<FlippedBack>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
    D: Sql,
    K: UndoKeys,
{
    flip_back_to(
        chain,
        dir,
        thawed,
        keys,
        owner,
        k_u,
        Back::Frozen(levelled_to),
        now,
    )
    .await
}

enum Back<'a> {
    Fresh(&'a str),
    Frozen(u64),
}

#[allow(clippy::too_many_arguments)]
async fn flip_back_to<S, C, Q, D, K>(
    chain: &TenantChain<'_, S, C>,
    dir: &SqlDirectory<'_, Q>,
    d1: &D,
    keys: &K,
    owner: &Tenant,
    k_u: u64,
    back: Back<'_>,
    now: UnixMs,
) -> Result<FlippedBack>
where
    S: RecordStore,
    C: ControlSeal,
    Q: Sql,
    D: Sql,
    K: UndoKeys,
{
    frozen_owner(chain, owner, k_u).await?;
    let zero = head_of(chain, &Tenant::Zero).await?;
    let z = zero.tenant_zero.as_ref().ok_or(UndoError::NotThisMove)?;
    let m = z
        .moved
        .as_ref()
        .filter(|m| m.to == *owner)
        .ok_or(UndoError::NotThisMove)?;
    let stamp = m.stamp.ok_or(UndoError::NotThisMove)?;
    let undo_stamp = stamp.checked_add(1).ok_or(UndoError::NotThisMove)?;
    // `moved` into the owner, or `d1` already after this undo.
    let done = z.selector == Selector::D1
        && z.undo_stamp == Some(undo_stamp)
        && match &back {
            Back::Fresh(id) => z.catalogue_id.as_deref() == Some(*id),
            Back::Frozen(l) => {
                z.catalogue_id.as_deref() == Some(m.catalogue_id_frozen.as_str())
                    && m.levelled_to == Some(*l)
            }
        };
    if z.selector != Selector::Moved && !done {
        return Err(UndoError::NotThisMove);
    }
    // The D1 the record names is the one in hand: its stamp row's id, no
    // cutover marker, and for the fallback the frozen catalogue thawed.
    let named = match &back {
        Back::Fresh(id) => *id,
        Back::Frozen(_) => m.catalogue_id_frozen.as_str(),
    };
    if !matches!(stamp_row(d1).await?, Some((_, id)) if id == named) {
        return Err(UndoError::FreshCatalogue("d1_is_not_the_named_catalogue"));
    }
    if marker(d1).await?.is_some() {
        return Err(UndoError::FreshCatalogue("d1_has_marker"));
    }
    if matches!(back, Back::Frozen(_)) && !super::fence::freeze_state(d1).await?.thawed() {
        return Err(UndoError::FreshCatalogue("frozen_d1_not_thawed"));
    }
    let change = match back {
        Back::Fresh(id) => Change::UndoMove {
            undo_stamp,
            catalogue_id: id.to_string(),
        },
        Back::Frozen(levelled_to) => Change::UndoMoveOntoFrozen {
            undo_stamp,
            levelled_to,
        },
    };
    let written = chain
        .write(&Tenant::Zero, &change, Actor::MoveTool, now, zero.seq)
        .await?;
    let wrote = matches!(written, Written::Wrote(_));
    dir.apply_tenant(&door_of(written), now).await?;
    // Just before the lift deploy: every revocation put since the build,
    // flat first, so a later restore of tenant 0 (which reads only flat
    // `m/rk/`) keeps it revoked (DS1 §3.7 step 5, ADR §8.5).
    let owners =
        list_all(|after| async move { keys.tenant_revocations(after.as_deref()).await }).await?;
    for id in owners.iter().filter(|id| crate::recovery::valid_key_id(id)) {
        keys.put_flat_revocation(id).await?;
    }
    let overridden = override_revocations(d1, keys).await?;
    let unplaced = exit_placements(chain, dir, keys, owner, now).await?;
    Ok(FlippedBack {
        undo_stamp,
        wrote,
        overridden,
        unplaced,
    })
}
