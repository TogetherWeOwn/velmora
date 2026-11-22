//! The move's copy: the rows of tenant 0's frozen D1 catalogue into the
//! owner's root unit (DS1 §3.4 step 3, with the rules of §3.2).
//!
//! The move tool pages every table the unit imports
//! ([`ImportTable::ALL`], in that order) by its primary key, a bounded
//! range read of at most [`PAGE`] rows each, so D1 keeps answering reads
//! and no query reads more than one page. Each page becomes at most one
//! [`ImportBatch`]; its cursor is the primary key of the last row read,
//! and its `after` the cursor the unit stored for the table, so the unit
//! applies every batch once and in order and the copy resumes from the
//! unit's own progress ([`UnitImport::progress`]) after a crash or a lost
//! answer.
//!
//! **What changes on the way** (§3.2). Every value is copied with its
//! SQLite type class, except:
//!
//! - `buckets`: each row is handed to [`RowTransform::bucket`] (the
//!   re-wrap of its bucket key and its new owner, done by the key lane's
//!   code in the Worker). The excluded buckets ([`CopyPlan::excluded`],
//!   the canary) are not copied, and neither is any row of theirs: a row
//!   whose bucket, or whose extent's, generation's or upload's bucket, is
//!   excluded stays in the frozen D1 only, and is counted;
//! - `extents`: `hot_safety_bytes` and `hot_cache_bytes` become 0 unless
//!   [`RowTransform::rehomed`] says that copy was re-homed under the
//!   tenant's name (§3.3 P6), so the unit never counts a warm copy it does
//!   not have;
//! - `outbox`: a live lease stops the copy (the drain did not finish); an
//!   expired lease is cleared (`lease_owner`, `lease_until`), its fencing
//!   token (`lease_token`) kept, so the unit's next lease is above it;
//! - `usage_hours`: the frozen D1's hour under way (row 1 of
//!   `usage_global`) is filed at its place in hour order, added to that
//!   hour's row if one exists (AM-17).
//!
//! After the last batch, [`seal`] ends the import (`ImportSeal`, AM-29)
//! with every table's row count, so the `move` report and the move's
//! `Recount` can tell that the import is done.
//!
//! Nothing here writes to the frozen D1 or deletes anything. The unit
//! takes a batch only while tenant 0's verified head is `moving` into the
//! owner's tenant and the unit's `restoring` entry is the one named
//! ([`crate::unit::import`]); [`bound`] builds both from the two heads.

use std::collections::{BTreeMap, BTreeSet};

use super::record::{Selector, TenantDoor};
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, UnixMs};
use crate::unit::import::{
    ImportBatch, ImportCount, ImportRefusal, ImportTable, ImportValue, Imported, MoveHead,
    MAX_CURSOR, MAX_ROWS,
};

/// Rows read per page, and so at most per batch.
pub const PAGE: usize = MAX_ROWS;

/// How often one batch is sent again after an error that says nothing
/// about whether the unit applied it.
pub const SEND_TRIES: u32 = 3;

/// Why the copy stopped. Nothing it did is undone: the unit keeps what it
/// applied, and a later run resumes from the unit's progress.
#[derive(Debug)]
pub enum CopyError {
    /// The frozen D1 or the unit could not be reached, or answered rows of
    /// another shape.
    Store(BridgeError),
    /// The two heads do not bind an import: tenant 0 is not `moving` into
    /// this tenant, or the owner's root unit has no `restoring` entry.
    NotBound,
    /// The unit refused a batch.
    Refused {
        table: ImportTable,
        refusal: ImportRefusal,
    },
    /// The unit answered a cursor that is not the batch's.
    Diverged { table: ImportTable },
    /// A primary key does not fit the unit's cursor.
    CursorTooLong { table: ImportTable },
    /// An outbox row still holds a live lease: the drain did not finish.
    LiveLease,
    /// The unit refused `ImportSeal`; the import stays open.
    SealRefused(ImportRefusal),
    /// The unit is sealed for another ordinal or other counts.
    SealedOther,
    /// The unit holds an import of an earlier window (its tenant-0 seq is
    /// below this window's first record, or the unit does not say): the
    /// give-up did not empty it. Nothing is sent.
    OtherWindowImport,
    /// A batch was refused because the import is sealed: step 3 is done
    /// (the next run reads the seal and sends nothing).
    Sealed,
    /// [`seal`] was given counts for another set of tables than the
    /// import's: a run that did not reach every table.
    Incomplete,
}

impl From<BridgeError> for CopyError {
    fn from(e: BridgeError) -> Self {
        CopyError::Store(e)
    }
}

/// The owner's root unit, as the copy calls it.
#[allow(async_fn_in_trait)]
pub trait UnitImport {
    /// One import batch, bound to tenant 0's head `head` and the unit's
    /// `restoring` entry `since`. An `Err` says nothing about whether the
    /// unit applied it.
    async fn import(
        &self,
        head: &MoveHead,
        since: u64,
        batch: &ImportBatch,
    ) -> crate::types::Result<Imported>;
    /// Every table's stored cursor and row count: `(table, cursor, rows)`.
    async fn progress(&self) -> crate::types::Result<Vec<(String, String, u64)>>;
    /// `UnitOp::ImportSeal{head, since, tables}` (AM-29): ends the import.
    /// `head` is tenant 0's verified head (its `flips + 1` is the ordinal
    /// the seal records); `tables` names every import table once with the
    /// rows the unit took. A repeat under the same entry with the same
    /// counts answers done (`newly: false`); under a later entry the unit
    /// refuses it with an alarm, so [`seal`] reads [`Self::import_state`]
    /// first. An `Err` says nothing about whether it landed.
    async fn seal(
        &self,
        head: &MoveHead,
        since: u64,
        tables: &[ImportCount],
    ) -> crate::types::Result<Sealed>;
    /// The unit's import, from `ImportProgress` (`sealed`, `t0_seq` and
    /// the tables' rows; a table not listed counts 0): `None` before the
    /// first batch.
    async fn import_state(&self) -> crate::types::Result<Option<ImportState>>;
}

/// The import a unit holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportState {
    /// The newest tenant-0 seq a batch, the seal or a `move` report was
    /// bound to (`unit_import_move.t0_seq`). Every record of a window is at or above
    /// the window's first `moving` record, and every record of an earlier
    /// window is below it, so this tells a given-up window's import (whose
    /// unit was not emptied) from this one's. `None`: the unit did not say.
    pub t0_seq: Option<u64>,
    /// The `move_ordinal` of the seal, if the import is sealed.
    pub sealed: Option<u64>,
    pub tables: Vec<ImportCount>,
}

/// The unit's answer to `ImportSeal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sealed {
    /// The import is final under this ordinal (`sealed`).
    Done { ordinal: u64 },
    /// Refused (`count_mismatch`, `not_bound`).
    Refused(ImportRefusal),
}

/// What §3.2 changes on the way, computed outside this module.
pub trait RowTransform {
    /// A bucket row, columns in [`ImportTable::Buckets`] order, as the
    /// unit holds it: the bucket key re-wrapped for the tenant, the owner
    /// set. The id must stay the same.
    fn bucket(&self, row: &[ImportValue]) -> crate::types::Result<Vec<ImportValue>>;
    /// Whether the safety copy and the cache copy of `extent_id` were
    /// re-homed under the tenant's names: `(safety, cache)`.
    fn rehomed(&self, extent_id: &str) -> (bool, bool);
}

/// What the copy leaves out, and how much it reads at a time.
#[derive(Clone, Debug)]
pub struct CopyPlan {
    /// Bucket ids whose rows stay in the frozen D1 (the canary).
    pub excluded: BTreeSet<String>,
    /// Rows per page: 1 to [`PAGE`] (larger is taken as [`PAGE`]).
    pub page: usize,
    /// The seq of this window's first tenant-0 record (the `moving`
    /// record of step 2). An import the unit already holds is continued
    /// only when it was bound at or above it. The default takes none.
    pub window_start: u64,
}

impl Default for CopyPlan {
    fn default() -> Self {
        CopyPlan {
            excluded: BTreeSet::new(),
            page: PAGE,
            window_start: u64::MAX,
        }
    }
}

/// What one run did to one table. The counts are this run's only: a
/// resumed run does not see the rows before the unit's cursor, and rows
/// it read after the last batch it sent are read (and counted) again by
/// the next run. They are the copy's report, not V1's reference: V1
/// counts the frozen D1 and the unit itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TableCopy {
    pub table: &'static str,
    /// Rows read from the frozen D1 in this run.
    pub read: u64,
    /// Rows sent and applied in this run.
    pub sent: u64,
    /// Rows left out because their bucket is excluded.
    pub excluded: u64,
    /// Outbox rows whose expired lease was cleared.
    pub leases_cleared: u64,
    /// The unit's row count for the table after this run (all runs).
    pub unit_rows: u64,
}

/// Tenant 0's head as the import reads it, and the `since_seq` of the
/// owner's root-unit `restoring` entry: what binds every batch to this
/// move. `None` unless `zero` is tenant 0 `moving` into `owner`'s tenant
/// and `owner` has a `restoring` entry for unit 0.
pub fn bound(zero: &TenantDoor, owner: &TenantDoor) -> Option<(MoveHead, u64)> {
    let z = zero.tenant_zero.as_ref()?;
    let to = z.moved.as_ref().map(|m| m.to.clone())?;
    if !zero.tenant.is_zero()
        || z.selector != Selector::Moving
        || to != owner.tenant
        || owner.tenant.is_zero()
    {
        return None;
    }
    let since = owner.restoring_entry(0)?.since_seq;
    Some((move_head(zero)?, since))
}

/// Tenant 0's verified head as a unit call names it: `moving` into
/// `move.to`, with its `flips`. `None` for any other head.
pub fn move_head(zero: &TenantDoor) -> Option<MoveHead> {
    let z = zero.tenant_zero.as_ref()?;
    let to = z.moved.as_ref()?.to.clone();
    if !zero.tenant.is_zero() || z.selector != Selector::Moving || to.is_zero() {
        return None;
    }
    Some(MoveHead {
        seq: zero.seq,
        selector: "moving".into(),
        to: crate::unit::name::TenantId::parse(to.as_str()),
        flips: z.flips,
    })
}

/// The ordinal a window's import is sealed under: `flips + 1` of tenant
/// 0's head while it is `moving` (AM-7, AM-29). `None` for any other head.
pub fn move_ordinal(zero: &TenantDoor) -> Option<u64> {
    let z = zero.tenant_zero.as_ref()?;
    match (zero.tenant.is_zero(), z.selector, &z.moved) {
        (true, Selector::Moving, Some(_)) => z.flips.checked_add(1),
        _ => None,
    }
}

/// Ends the import after the last batch (AM-29): `ImportSeal` with every
/// table's row count as `copied` (the answer of [`copy_all`]) gives it.
/// The unit's seal is read first: sealed with this ordinal and these
/// counts is done without a call (a repeat after AM-15's re-entry would
/// page); sealed otherwise is refused. A lost answer sends the seal again,
/// and a refusal is done only if the seal is then found as above.
pub async fn seal<U: UnitImport>(
    unit: &U,
    head: &MoveHead,
    since: u64,
    window_start: u64,
    copied: &[TableCopy],
) -> Result<(), CopyError> {
    let ordinal = head.flips.checked_add(1).ok_or(CopyError::Incomplete)?;
    let mut tables = Vec::with_capacity(ImportTable::ALL.len());
    for table in ImportTable::ALL {
        let mut rows = copied.iter().filter(|c| c.table == table.name());
        match (rows.next(), rows.next()) {
            (Some(c), None) => tables.push(ImportCount {
                table,
                rows: c.unit_rows,
            }),
            _ => return Err(CopyError::Incomplete),
        }
    }
    if copied.len() != tables.len() {
        return Err(CopyError::Incomplete);
    }
    // This window's seal: its ordinal, bound in this window, these counts.
    let found = |state: Option<ImportState>| {
        let s = state?;
        let o = s.sealed?;
        Some(
            o == ordinal && s.t0_seq.is_some_and(|t| t >= window_start) && same(&s.tables, &tables),
        )
    };
    let state = unit.import_state().await?;
    // An open import of an earlier window is not sealed as this one's
    // (the seal would raise its tenant-0 seq into this window).
    if let Some(s) = &state {
        if !s.t0_seq.is_some_and(|t| t >= window_start) {
            return Err(CopyError::OtherWindowImport);
        }
    }
    match found(state) {
        Some(true) => return Ok(()),
        Some(false) => return Err(CopyError::SealedOther),
        None => {}
    }
    let mut last_err = None;
    for _ in 0..SEND_TRIES {
        match unit.seal(head, since, &tables).await {
            Ok(Sealed::Done { ordinal: o }) if o == ordinal => return Ok(()),
            Ok(Sealed::Done { .. }) => return Err(CopyError::SealedOther),
            Ok(Sealed::Refused(r)) => {
                return match found(unit.import_state().await?) {
                    Some(true) => Ok(()),
                    Some(false) => Err(CopyError::SealedOther),
                    None => Err(CopyError::SealRefused(r)),
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(CopyError::Store(last_err.unwrap_or(BridgeError::Invalid(
        "move copy: no try was made",
    ))))
}

/// The same count for every import table, in any order; a table that is
/// not named counts 0 (AM-29), and a table named twice makes the two
/// differ.
fn same(a: &[ImportCount], b: &[ImportCount]) -> bool {
    let counts = |v: &[ImportCount]| -> Option<BTreeMap<&'static str, u64>> {
        let mut m: BTreeMap<&'static str, u64> =
            ImportTable::ALL.iter().map(|t| (t.name(), 0)).collect();
        let mut seen = BTreeSet::new();
        for c in v {
            if !seen.insert(c.table.name()) {
                return None;
            }
            m.insert(c.table.name(), c.rows);
        }
        Some(m)
    };
    matches!((counts(a), counts(b)), (Some(x), Some(y)) if x == y)
}

/// Copies every table, in [`ImportTable::ALL`] order, resuming each from
/// the unit's stored cursor. `now` decides whether an outbox lease is
/// live.
pub async fn copy_all<S: Sql, U: UnitImport, T: RowTransform>(
    frozen: &S,
    unit: &U,
    transform: &T,
    plan: &CopyPlan,
    head: &MoveHead,
    since: u64,
    now: UnixMs,
) -> Result<Vec<TableCopy>, CopyError> {
    // An import the unit holds is continued only if this window bound it;
    // one left by a given-up window stops the copy before any call (a
    // batch would raise its tenant-0 seq): the unit must be emptied first.
    // A sealed one takes no batch (`import: sealed`): step 3 is done, and
    // each table's count is the seal's.
    if let Some(state) = unit.import_state().await? {
        if !state.t0_seq.is_some_and(|t| t >= plan.window_start) {
            return Err(CopyError::OtherWindowImport);
        }
        let Some(sealed) = state.sealed else {
            return copy_tables(frozen, unit, transform, plan, head, since, now).await;
        };
        if Some(sealed) != head.flips.checked_add(1) {
            return Err(CopyError::SealedOther);
        }
        return Ok(ImportTable::ALL
            .iter()
            .map(|t| TableCopy {
                table: t.name(),
                unit_rows: state
                    .tables
                    .iter()
                    .find(|c| c.table == *t)
                    .map_or(0, |c| c.rows),
                ..TableCopy::default()
            })
            .collect());
    }
    copy_tables(frozen, unit, transform, plan, head, since, now).await
}

async fn copy_tables<S: Sql, U: UnitImport, T: RowTransform>(
    frozen: &S,
    unit: &U,
    transform: &T,
    plan: &CopyPlan,
    head: &MoveHead,
    since: u64,
    now: UnixMs,
) -> Result<Vec<TableCopy>, CopyError> {
    let progress = unit.progress().await?;
    let mut out = Vec::with_capacity(ImportTable::ALL.len());
    for table in ImportTable::ALL {
        let stored = progress
            .iter()
            .find(|(t, _, _)| t == table.name())
            .map(|(_, c, n)| (c.clone(), *n));
        let copy = Copier {
            frozen,
            unit,
            transform,
            plan,
            head,
            since,
            now,
        };
        out.push(copy.table(table, stored).await?);
    }
    Ok(out)
}

struct Copier<'a, S, U, T> {
    frozen: &'a S,
    unit: &'a U,
    transform: &'a T,
    plan: &'a CopyPlan,
    head: &'a MoveHead,
    since: u64,
    now: UnixMs,
}

impl<S: Sql, U: UnitImport, T: RowTransform> Copier<'_, S, U, T> {
    async fn table(
        &self,
        table: ImportTable,
        stored: Option<(String, u64)>,
    ) -> Result<TableCopy, CopyError> {
        let mut done = TableCopy {
            table: table.name(),
            unit_rows: stored.as_ref().map_or(0, |(_, n)| *n),
            ..TableCopy::default()
        };
        // `after`: the unit's cursor; `position`: the last key read.
        let mut after = stored.map(|(c, _)| c);
        let mut position = match &after {
            Some(cursor) => Some(decode_cursor(cursor).ok_or(CopyError::Diverged { table })?),
            None => None,
        };
        let keys = key_columns(table);
        // The hour under way of the frozen D1's live counters (AM-17) is
        // filed into `usage_hours` where it falls in hour order: added to
        // its own hour's row, or as a row of its own. One that falls at or
        // before the unit's cursor was filed by an earlier run.
        let mut hour = match table {
            ImportTable::UsageHours => self.hour_under_way().await?,
            _ => None,
        };
        if let (Some((h, _)), Some(pos)) = (&hour, &position) {
            if matches!(pos.first(), Some(ImportValue::Int(c)) if c >= h) {
                hour = None;
            }
        }
        // Room in a full page for the filed hour's own row.
        let page_size = match table {
            ImportTable::UsageHours => self.plan.page.clamp(1, PAGE - 1),
            _ => self.plan.page.clamp(1, PAGE),
        };
        loop {
            let params: Vec<SqlValue> = position.iter().flatten().map(to_sql).collect();
            let select = select_page(table, position.is_some(), page_size);
            let page = self.frozen.query(&select, &params).await?;
            let mut rows = Vec::with_capacity(page.len());
            let mut last = None;
            for raw in &page {
                let width = table.columns().len();
                if raw.len() != width + 1 {
                    return Err(BridgeError::Invalid("move copy: page row shape").into());
                }
                let mut row: Vec<ImportValue> = raw[..width].iter().map(from_sql).collect();
                last = Some(key_of(table, keys, &row));
                done.read += 1;
                if self.excluded(table, &row, &raw[width]) {
                    done.excluded += 1;
                    continue;
                }
                self.change(table, &mut row, &mut done)?;
                if let Some((h, counts)) = hour {
                    let at = match row.first() {
                        Some(ImportValue::Int(at)) => *at,
                        _ => return Err(BridgeError::Invalid("move copy: hour").into()),
                    };
                    if at == h {
                        add_hour(&mut row, &counts)?;
                        hour = None;
                    } else if at > h {
                        rows.push(hour_row(h, &counts));
                        hour = None;
                    }
                }
                rows.push(row);
            }
            let Some(last) = last else { break };
            let cursor = encode_cursor(&last);
            if cursor.len() > MAX_CURSOR {
                return Err(CopyError::CursorTooLong { table });
            }
            self.send_rows(table, &mut after, cursor, rows, &mut done)
                .await?;
            position = Some(last);
            if page.len() < page_size {
                break;
            }
        }
        // After every hour filed: the hour under way as the last batch.
        if let Some((h, counts)) = hour {
            let cursor = encode_cursor(&[ImportValue::Int(h)]);
            self.send_rows(
                table,
                &mut after,
                cursor,
                vec![hour_row(h, &counts)],
                &mut done,
            )
            .await?;
        }
        Ok(done)
    }

    /// Sends `rows` (if any) as the batch after `after`, ending at
    /// `cursor`, and moves `after` on.
    async fn send_rows(
        &self,
        table: ImportTable,
        after: &mut Option<String>,
        cursor: String,
        rows: Vec<Vec<ImportValue>>,
        done: &mut TableCopy,
    ) -> Result<(), CopyError> {
        if rows.is_empty() {
            return Ok(());
        }
        let batch = ImportBatch {
            table,
            columns: table.columns().iter().map(|c| c.to_string()).collect(),
            after: after.clone(),
            cursor: cursor.clone(),
            rows,
        };
        let n = batch.rows.len() as u64;
        done.unit_rows = self.send(&batch).await?;
        done.sent += n;
        *after = Some(cursor);
        Ok(())
    }

    /// The frozen D1's hour under way: `(hour, [posts, verifies, releases,
    /// dead, failures])` of live row 1, as `usage::off` files it (an hour
    /// with no event is not filed).
    async fn hour_under_way(&self) -> Result<Option<(i64, [i64; 5])>, CopyError> {
        let rows = self
            .frozen
            .query(
                "SELECT hour, h_posts, h_verifies, h_releases, h_dead, h_failures \
                 FROM usage_global WHERE id = 1 AND hour > 0 \
                 AND h_posts + h_verifies + h_releases + h_dead + h_failures > 0",
                &[],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let int = |i: usize| match row.get(i) {
            Some(SqlValue::Int(n)) => Ok(*n),
            _ => Err(CopyError::Store(BridgeError::Invalid(
                "move copy: usage_global row",
            ))),
        };
        Ok(Some((
            int(0)?,
            [int(1)?, int(2)?, int(3)?, int(4)?, int(5)?],
        )))
    }

    /// Whether the row belongs to an excluded bucket. `bucket` is the
    /// page's extra column: the row's bucket id, through its parent where
    /// the table has none of its own (NULL: no parent row).
    fn excluded(&self, table: ImportTable, row: &[ImportValue], bucket: &SqlValue) -> bool {
        if self.plan.excluded.is_empty() {
            return false;
        }
        let id = match table {
            ImportTable::Buckets => match row.first() {
                Some(ImportValue::Text(id)) => Some(id.as_str()),
                _ => None,
            },
            _ => match bucket {
                SqlValue::Text(id) => Some(id.as_str()),
                _ => None,
            },
        };
        id.is_some_and(|id| self.plan.excluded.contains(id))
    }

    fn change(
        &self,
        table: ImportTable,
        row: &mut Vec<ImportValue>,
        done: &mut TableCopy,
    ) -> Result<(), CopyError> {
        match table {
            ImportTable::Buckets => {
                let moved = self.transform.bucket(row)?;
                if moved.len() != row.len() || moved.first() != row.first() {
                    return Err(BridgeError::Invalid("move copy: a bucket changed its id").into());
                }
                *row = moved;
            }
            ImportTable::Extents => {
                let id = match column(table, row, "id") {
                    Some(ImportValue::Text(id)) => id.clone(),
                    _ => return Err(BridgeError::Invalid("move copy: extent id").into()),
                };
                let (safety, cache) = self.transform.rehomed(&id);
                for (name, kept) in [("hot_safety_bytes", safety), ("hot_cache_bytes", cache)] {
                    if !kept {
                        set(table, row, name, ImportValue::Int(0));
                    }
                }
            }
            ImportTable::Outbox => {
                let leased = !matches!(column(table, row, "lease_owner"), Some(ImportValue::Null))
                    || !matches!(column(table, row, "lease_until"), Some(ImportValue::Null));
                if leased {
                    // Live while `lease_until >= now`, as the outbox
                    // holds it (a claim needs `lease_until < now`).
                    if let Some(ImportValue::Int(until)) = column(table, row, "lease_until") {
                        if *until >= self.now.0 {
                            return Err(CopyError::LiveLease);
                        }
                    }
                    set(table, row, "lease_owner", ImportValue::Null);
                    set(table, row, "lease_until", ImportValue::Null);
                    done.leases_cleared += 1;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Sends one batch; a lost answer sends it again, which the unit
    /// answers as applied before. Returns the unit's row count.
    async fn send(&self, batch: &ImportBatch) -> Result<u64, CopyError> {
        let mut last_err = None;
        for _ in 0..SEND_TRIES {
            match self.unit.import(self.head, self.since, batch).await {
                Ok(Imported::Done { cursor, rows, .. }) => {
                    if cursor != batch.cursor {
                        return Err(CopyError::Diverged { table: batch.table });
                    }
                    return Ok(rows);
                }
                Ok(Imported::Refused(ImportRefusal::Sealed)) => return Err(CopyError::Sealed),
                Ok(Imported::Refused(refusal)) => {
                    return Err(CopyError::Refused {
                        table: batch.table,
                        refusal,
                    })
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(CopyError::Store(last_err.unwrap_or(BridgeError::Invalid(
            "move copy: no try was made",
        ))))
    }
}

/// What the excluded rows add to the frozen D1's live state counters
/// (`usage_global` row 1): V2 compares the unit's recount with row 1
/// minus these (DS1 §3.5 V2, AM-17). The extent counters follow the
/// extent triggers of migration 0020 (by `safety_state`, bytes by
/// `cipher_size`), the outbox counters count rows by `stage`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExcludedSums {
    pub x_unreleased: i64,
    pub unreleased_bytes: i64,
    pub x_released: i64,
    pub released_bytes: i64,
    pub x_deleted: i64,
    /// Outbox rows by stage.
    pub outbox: BTreeMap<String, i64>,
    /// Row 1 covers all three tables (`all_x = all_o = all_g = 1`). V2's
    /// "row 1 minus these" means something only then: V2 fails unless set.
    pub covered: bool,
}

/// Sums the excluded rows of `extents` and `outbox` with the copy's own
/// bounded pages and exclusion rule. It reads the frozen D1 only and can
/// be run at any time, so a resumed copy does not change the answer: the
/// move tool runs it at step 7 for V2, never using [`TableCopy`]'s counts,
/// which cover one run (AM-17, AM-25). Each query is one page of at most
/// [`PAGE`] rows by primary key (plus a primary-key lookup of the parent
/// extent for `outbox`), filtered to the excluded buckets in code:
/// `extents` has no index by bucket, so `WHERE bucket_id = ?` would scan
/// the whole table in one query.
pub async fn excluded_sums<S: Sql>(frozen: &S, plan: &CopyPlan) -> Result<ExcludedSums, CopyError> {
    let mut sums = ExcludedSums::default();
    let coverage = frozen
        .query(
            "SELECT all_x = 1 AND all_o = 1 AND all_g = 1 FROM usage_global WHERE id = 1",
            &[],
        )
        .await?;
    sums.covered = matches!(
        coverage.first().and_then(|r| r.first()),
        Some(SqlValue::Int(1))
    );
    if plan.excluded.is_empty() {
        return Ok(sums);
    }
    let page_size = plan.page.clamp(1, PAGE);
    for table in [ImportTable::Extents, ImportTable::Outbox] {
        let keys = key_columns(table);
        let width = table.columns().len();
        let mut position: Option<Vec<ImportValue>> = None;
        loop {
            let params: Vec<SqlValue> = position.iter().flatten().map(to_sql).collect();
            let page = frozen
                .query(&select_page(table, position.is_some(), page_size), &params)
                .await?;
            for raw in &page {
                if raw.len() != width + 1 {
                    return Err(BridgeError::Invalid("move copy: page row shape").into());
                }
                let row: Vec<ImportValue> = raw[..width].iter().map(from_sql).collect();
                position = Some(key_of(table, keys, &row));
                let theirs = matches!(&raw[width], SqlValue::Text(b) if plan.excluded.contains(b));
                if !theirs {
                    continue;
                }
                let text = |name: &str| match column(table, &row, name) {
                    Some(ImportValue::Text(t)) => t.clone(),
                    _ => String::new(),
                };
                match table {
                    ImportTable::Extents => {
                        let size = match column(table, &row, "cipher_size") {
                            Some(ImportValue::Int(n)) => *n,
                            _ => 0,
                        };
                        match text("safety_state").as_str() {
                            "held" | "releasing" => {
                                sums.x_unreleased += 1;
                                sums.unreleased_bytes += size;
                            }
                            "released" => {
                                sums.x_released += 1;
                                sums.released_bytes += size;
                            }
                            "deleted" => sums.x_deleted += 1,
                            _ => {}
                        }
                    }
                    _ => *sums.outbox.entry(text("stage")).or_default() += 1,
                }
            }
            if page.len() < page_size {
                break;
            }
        }
    }
    Ok(sums)
}

/// The primary key of each imported table, in index order: what a page
/// is ordered and continued by.
pub fn key_columns(table: ImportTable) -> &'static [&'static str] {
    match table {
        ImportTable::Buckets
        | ImportTable::Generations
        | ImportTable::Extents
        | ImportTable::Uploads
        | ImportTable::Gc
        | ImportTable::UsageRecounts => &["id"],
        ImportTable::Objects => &["bucket_id", "key"],
        ImportTable::GenerationExtents => &["generation_id", "seq"],
        ImportTable::Articles => &["extent_id", "idx"],
        ImportTable::Verifications => &["extent_id", "backbone", "verified_at"],
        ImportTable::VerifyRaises => &["extent_id", "backbone", "plan_rev"],
        ImportTable::VerifyEscalations => &["backbone"],
        ImportTable::Outbox => &["extent_id"],
        ImportTable::UploadParts => &["upload_id", "part_number"],
        ImportTable::UploadPartExtents => &["upload_id", "part_number", "piece"],
        ImportTable::UsageHours => &["hour"],
    }
}

/// How a row reaches its bucket: the SQL for the page's extra column and
/// the join it needs.
fn bucket_of(table: ImportTable) -> (&'static str, &'static str) {
    match table {
        ImportTable::Buckets => ("t.\"id\"", ""),
        ImportTable::Generations
        | ImportTable::Objects
        | ImportTable::Extents
        | ImportTable::Uploads => ("t.\"bucket_id\"", ""),
        ImportTable::GenerationExtents => (
            "p.\"bucket_id\"",
            " LEFT JOIN \"generations\" p ON p.\"id\" = t.\"generation_id\"",
        ),
        ImportTable::Articles
        | ImportTable::Verifications
        | ImportTable::VerifyRaises
        | ImportTable::Outbox
        | ImportTable::Gc => (
            "p.\"bucket_id\"",
            " LEFT JOIN \"extents\" p ON p.\"id\" = t.\"extent_id\"",
        ),
        ImportTable::UploadParts | ImportTable::UploadPartExtents => (
            "p.\"bucket_id\"",
            " LEFT JOIN \"uploads\" p ON p.\"id\" = t.\"upload_id\"",
        ),
        // Shared state of every bucket: never excluded.
        ImportTable::VerifyEscalations | ImportTable::UsageHours | ImportTable::UsageRecounts => {
            ("NULL", "")
        }
    }
}

/// The page query: the table's columns in the unit's order, then the
/// row's bucket; after `position` when `continued`.
fn select_page(table: ImportTable, continued: bool, page: usize) -> String {
    let cols: Vec<String> = table
        .columns()
        .iter()
        .map(|c| format!("t.\"{c}\""))
        .collect();
    let keys: Vec<String> = key_columns(table)
        .iter()
        .map(|c| format!("t.\"{c}\""))
        .collect();
    let (bucket, join) = bucket_of(table);
    let mut sql = format!(
        "SELECT {}, {bucket} FROM \"{}\" t{join}",
        cols.join(", "),
        table.name()
    );
    if continued {
        let marks: Vec<String> = (1..=keys.len()).map(|i| format!("?{i}")).collect();
        sql.push_str(&format!(
            " WHERE ({}) > ({})",
            keys.join(", "),
            marks.join(", ")
        ));
    }
    sql.push_str(&format!(" ORDER BY {} LIMIT {page}", keys.join(", ")));
    sql
}

fn index(table: ImportTable, name: &str) -> Option<usize> {
    table.columns().iter().position(|c| *c == name)
}

fn column<'r>(table: ImportTable, row: &'r [ImportValue], name: &str) -> Option<&'r ImportValue> {
    index(table, name).and_then(|i| row.get(i))
}

fn set(table: ImportTable, row: &mut [ImportValue], name: &str, value: ImportValue) {
    if let Some(slot) = index(table, name).and_then(|i| row.get_mut(i)) {
        *slot = value;
    }
}

/// A `usage_hours` row of the hour under way.
fn hour_row(hour: i64, counts: &[i64; 5]) -> Vec<ImportValue> {
    std::iter::once(hour)
        .chain(counts.iter().copied())
        .map(ImportValue::Int)
        .collect()
}

/// Adds the hour under way to its hour's filed row, as the upsert of
/// `usage::off` does.
fn add_hour(row: &mut [ImportValue], counts: &[i64; 5]) -> Result<(), CopyError> {
    for (slot, add) in row.iter_mut().skip(1).zip(counts) {
        match slot {
            ImportValue::Int(n) => {
                *n = n
                    .checked_add(*add)
                    .ok_or(CopyError::Store(BridgeError::Invalid(
                        "move copy: hour sum",
                    )))?;
            }
            _ => return Err(BridgeError::Invalid("move copy: hour row").into()),
        }
    }
    Ok(())
}

fn key_of(table: ImportTable, keys: &[&str], row: &[ImportValue]) -> Vec<ImportValue> {
    keys.iter()
        .map(|k| column(table, row, k).cloned().unwrap_or(ImportValue::Null))
        .collect()
}

/// A cursor: the primary key of the last row read, as typed JSON.
pub fn encode_cursor(key: &[ImportValue]) -> String {
    serde_json::to_string(key).expect("typed values encode")
}

/// The primary key a cursor names; `None` for anything this module did
/// not write.
pub fn decode_cursor(cursor: &str) -> Option<Vec<ImportValue>> {
    serde_json::from_str(cursor).ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_imported_table_has_its_key_in_its_columns() {
        for table in ImportTable::ALL {
            for k in key_columns(table) {
                assert!(table.columns().contains(k), "{} {k}", table.name());
            }
        }
    }

    #[test]
    fn a_continued_page_starts_after_the_last_key() {
        assert_eq!(
            select_page(ImportTable::Objects, true, PAGE),
            "SELECT t.\"bucket_id\", t.\"key\", t.\"generation_id\", t.\"bucket_id\" \
             FROM \"objects\" t WHERE (t.\"bucket_id\", t.\"key\") > (?1, ?2) \
             ORDER BY t.\"bucket_id\", t.\"key\" LIMIT 500"
        );
        assert!(!select_page(ImportTable::Articles, false, 2).contains("WHERE"));
    }

    #[test]
    fn a_seal_state_without_its_empty_tables_is_the_same_seal() {
        let c = |table, rows| ImportCount { table, rows };
        let all: Vec<ImportCount> = ImportTable::ALL
            .iter()
            .map(|t| c(*t, u64::from(*t == ImportTable::Buckets) * 22))
            .collect();
        let short = vec![c(ImportTable::Buckets, 22)];
        assert!(same(&all, &short));
        assert!(same(&short, &all));
        assert!(!same(&all, &[c(ImportTable::Buckets, 21)]));
        assert!(!same(
            &all,
            &[c(ImportTable::Buckets, 22), c(ImportTable::Buckets, 22)]
        ));
        assert!(!same(
            &all,
            &[c(ImportTable::Buckets, 22), c(ImportTable::Gc, 1)]
        ));
    }

    #[test]
    fn a_cursor_keeps_each_value_with_its_type() {
        let key = vec![ImportValue::Text("b_1".into()), ImportValue::Int(7)];
        let c = encode_cursor(&key);
        assert_eq!(decode_cursor(&c), Some(key));
        assert_eq!(decode_cursor("not json"), None);
    }
}
