//! The move's read-only lines of precondition P2 that can stop it before
//! step 0 (DS1 §3.3 P2, AM-22, AM-25).
//!
//! - **Bucket ids** that are not `b_` + 16 lowercase hex (expected 0). A
//!   moved bucket keeps its id, and the owner's tenant places only ids of
//!   that form (`PlaceMovedBuckets`), so a non-zero count stops the move.
//! - **The excluded set** of the `keymap` (A11, the canary), recorded so
//!   that V1 and V2 read the same set the copy left out.
//! - **Integer cells**, per INTEGER-declared column of every table the
//!   import writes: cells whose `typeof()` is `real`, and INTEGER cells
//!   outside ±(2^53 − 1) (compared without `abs()`, which overflows on
//!   −2^63). A REAL cell that is whole and within ±(2^53 − 1) is
//!   converted by the import and only counted. Any other REAL cell, and
//!   such an INTEGER cell, stops the move: the adapters refuse to bind or
//!   read it, so the copy would stop mid-window.
//!
//! - **Stale owner revocations** (P8 as AM-28 amends it,
//!   [`p8_stale_revocations`]): a key the `keymap` maps to the owner that
//!   has an `m/rk/<t>/<akid>` but is not revoked in D1 (its row is still
//!   there). Such a key would be revoked in the owner's tenant and served
//!   by D1, so a non-empty list stops the move before step 0.
//!
//! - **The unit's stamp prefix** (P2 as AM-44 amends it,
//!   [`p2_stamp_prefix_clear`]): a unit the move fills whose
//!   `rs/<t>.<u>/` already holds stamps (a second attempt after a give-up,
//!   or a second move after an undo) needs the gate's stamp levelling
//!   before its `move` report; without it the move stops before step 0.
//! - **Import state in the target unit** (P12, AM-47, [`p12`]), read with
//!   tenant 0's head and the owner's: only a closed unit, and only while
//!   tenant 0 is `d1`, is emptied first (a give-up left unfinished, or an
//!   undone move's 30-day copy with the owner's G6); anything else stops
//!   the move with nothing written.
//!
//! Every query is one page of at most [`MAX_PAGE`] rows in primary-key
//! order; a cell's class is computed by SQLite, so no value outside the
//! safe range is ever read through an adapter. Nothing is written.

use std::collections::BTreeSet;

use serde::Serialize;

use super::move_copy::key_columns;
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result};
use crate::unit::import::ImportTable;

use super::record::{Selector, TenantDoor};

/// The largest page a P2 query reads.
pub const MAX_PAGE: usize = 1000;

/// The most cells of one class a line names (the counts are complete).
pub const MAX_SAMPLES: usize = 100;

/// 2^53 − 1: the largest integer a JS number holds exactly.
const SAFE: &str = "9007199254740991";

/// The class counts of one INTEGER-declared column.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CellLine {
    pub table: &'static str,
    pub column: String,
    /// REAL cells that are whole and within ±(2^53 − 1): converted.
    pub real_whole: u64,
    /// Other REAL cells: stop the move.
    pub real_other: u64,
    /// INTEGER cells outside ±(2^53 − 1): stop the move.
    pub int_unsafe: u64,
    /// The primary keys (typed JSON) of stopping cells, at most
    /// [`MAX_SAMPLES`].
    pub samples: Vec<String>,
}

/// What P2 records for the go receipt.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct P2Lines {
    /// Bucket ids not of the minted form, at most [`MAX_SAMPLES`].
    pub nonconforming_ids: Vec<String>,
    pub nonconforming_count: u64,
    /// The `keymap`'s excluded bucket ids.
    pub excluded: BTreeSet<String>,
    /// Every INTEGER-declared column of every imported table.
    pub cells: Vec<CellLine>,
    /// Tables whose scan stopped at a primary key that cannot be read or
    /// paged past (NULL, REAL or an unsafe integer): the rest of the table
    /// was not scanned.
    pub unreadable_keys: Vec<&'static str>,
}

impl P2Lines {
    /// Whether a line stops the move before step 0.
    pub fn stops(&self) -> bool {
        self.nonconforming_count > 0
            || !self.unreadable_keys.is_empty()
            || self
                .cells
                .iter()
                .any(|c| c.real_other > 0 || c.int_unsafe > 0)
    }
}

/// Reads the P2 lines from the live D1 `d1`, `page` rows per query (1 to
/// [`MAX_PAGE`]).
pub async fn p2_lines<S: Sql>(d1: &S, excluded: &BTreeSet<String>, page: usize) -> Result<P2Lines> {
    let page = page.clamp(1, MAX_PAGE);
    let mut lines = P2Lines {
        excluded: excluded.clone(),
        ..P2Lines::default()
    };
    // Bucket ids, paged by rowid (`buckets` is a rowid table whose `id`
    // has no NOT NULL), so an id that is not text is counted, not fatal.
    let mut after: i64 = 0;
    loop {
        let rows = d1
            .query(
                &format!(
                    "SELECT rowid, CASE WHEN typeof(id) = 'text' THEN id END, typeof(id) \
                     FROM buckets WHERE rowid > ?1 ORDER BY rowid LIMIT {page}"
                ),
                &[SqlValue::Int(after)],
            )
            .await?;
        for row in &rows {
            let (Some(SqlValue::Int(rowid)), Some(id), Some(SqlValue::Text(ty))) =
                (row.first(), row.get(1), row.get(2))
            else {
                return Err(BridgeError::Invalid("p2: bucket id"));
            };
            let shown = match id {
                SqlValue::Text(id) if super::transition::valid_bucket_id(id) => None,
                SqlValue::Text(id) => Some(id.clone()),
                _ => Some(format!("<{ty} at rowid {rowid}>")),
            };
            if let Some(shown) = shown {
                lines.nonconforming_count += 1;
                if lines.nonconforming_ids.len() < MAX_SAMPLES {
                    lines.nonconforming_ids.push(shown);
                }
            }
            after = *rowid;
        }
        if rows.len() < page {
            break;
        }
    }
    for table in ImportTable::ALL {
        let (cells, complete) = integer_cells(d1, table, page).await?;
        lines.cells.extend(cells);
        if !complete {
            lines.unreadable_keys.push(table.name());
        }
    }
    Ok(lines)
}

/// The INTEGER-declared columns of `table`, from the database's own
/// declaration.
async fn integer_columns<S: Sql>(d1: &S, table: ImportTable) -> Result<Vec<String>> {
    let rows = d1
        .query(&format!("PRAGMA table_info(\"{}\")", table.name()), &[])
        .await?;
    let mut out = Vec::new();
    // `cid, name, type, notnull, dflt_value, pk`.
    for row in &rows {
        let (Some(SqlValue::Text(name)), Some(SqlValue::Text(ty))) = (row.get(1), row.get(2))
        else {
            return Err(BridgeError::Invalid("p2: column declaration"));
        };
        // SQLite's rule: a declared type that contains INT has integer
        // affinity.
        if ty.to_ascii_uppercase().contains("INT") {
            if !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(BridgeError::Invalid("p2: column name"));
            }
            out.push(name.clone());
        }
    }
    Ok(out)
}

/// The class of each INTEGER-declared cell of `table`, a page at a time,
/// and whether the scan reached the end of the table.
async fn integer_cells<S: Sql>(
    d1: &S,
    table: ImportTable,
    page: usize,
) -> Result<(Vec<CellLine>, bool)> {
    let columns = integer_columns(d1, table).await?;
    if columns.is_empty() {
        return Ok((Vec::new(), true));
    }
    let keys = key_columns(table);
    let key_list: Vec<String> = keys.iter().map(|k| format!("\"{k}\"")).collect();
    // A key cell is read through the adapter only when it is text, a blob
    // or a safe integer; any other comes back NULL (its class is counted
    // by its own flag, as every INTEGER key column is also a flag column),
    // and the scan of the table stops there: it cannot be paged past.
    let key_reads: Vec<String> = keys
        .iter()
        .map(|k| {
            format!(
                "CASE WHEN typeof(\"{k}\") IN ('text', 'blob') \
                 OR (typeof(\"{k}\") = 'integer' AND \"{k}\" >= -{SAFE} AND \"{k}\" <= {SAFE}) \
                 THEN \"{k}\" END"
            )
        })
        .collect();
    let flags: Vec<String> = columns
        .iter()
        .map(|c| {
            format!(
                "CASE WHEN typeof(\"{c}\") = 'real' THEN \
                 (CASE WHEN \"{c}\" = round(\"{c}\") AND \"{c}\" >= -{SAFE} AND \"{c}\" <= {SAFE} \
                 THEN 1 ELSE 2 END) \
                 WHEN typeof(\"{c}\") = 'integer' AND (\"{c}\" > {SAFE} OR \"{c}\" < -{SAFE}) \
                 THEN 3 ELSE 0 END"
            )
        })
        .collect();
    let mut lines: Vec<CellLine> = columns
        .iter()
        .map(|c| CellLine {
            table: table.name(),
            column: c.clone(),
            ..CellLine::default()
        })
        .collect();
    let base = format!(
        "SELECT {}, {} FROM \"{}\"",
        key_reads.join(", "),
        flags.join(", "),
        table.name()
    );
    let marks: Vec<String> = (1..=keys.len()).map(|i| format!("?{i}")).collect();
    let mut position: Option<Vec<SqlValue>> = None;
    loop {
        let sql = match &position {
            None => format!("{base} ORDER BY {} LIMIT {page}", key_list.join(", ")),
            Some(_) => format!(
                "{base} WHERE ({}) > ({}) ORDER BY {} LIMIT {page}",
                key_list.join(", "),
                marks.join(", "),
                key_list.join(", ")
            ),
        };
        let rows = d1.query(&sql, position.as_deref().unwrap_or(&[])).await?;
        for row in &rows {
            if row.len() != keys.len() + columns.len() {
                return Err(BridgeError::Invalid("p2: page row shape"));
            }
            let key = &row[..keys.len()];
            for (line, flag) in lines.iter_mut().zip(&row[keys.len()..]) {
                let stops = match flag {
                    SqlValue::Int(0) => false,
                    SqlValue::Int(1) => {
                        line.real_whole += 1;
                        false
                    }
                    SqlValue::Int(2) => {
                        line.real_other += 1;
                        true
                    }
                    SqlValue::Int(3) => {
                        line.int_unsafe += 1;
                        true
                    }
                    _ => return Err(BridgeError::Invalid("p2: cell class")),
                };
                if stops && line.samples.len() < MAX_SAMPLES {
                    line.samples.push(key_text(key));
                }
            }
            if key.contains(&SqlValue::Null) {
                // An unreadable key (NULL, or an unsafe or REAL cell counted
                // above): the stop line is recorded; the rest of the table
                // is not scanned.
                return Ok((lines, false));
            }
            position = Some(key.to_vec());
        }
        if rows.len() < page {
            break;
        }
    }
    Ok((lines, true))
}

fn key_text(key: &[SqlValue]) -> String {
    let parts: Vec<serde_json::Value> = key
        .iter()
        .map(|v| match v {
            SqlValue::Null => serde_json::Value::Null,
            SqlValue::Int(n) => serde_json::json!(n),
            SqlValue::Text(s) => serde_json::json!(s),
            SqlValue::Blob(b) => serde_json::json!(format!("blob:{}", b.len())),
        })
        .collect();
    serde_json::Value::Array(parts).to_string()
}

/// P8 (AM-28): the keys among `mapped` (every key the `keymap` maps to
/// the owner, `drop` keys left out) that have the owner's revocation
/// `m/rk/<t>/<akid>` and are still served by `d1`: an `active` row, or a
/// row with a grant. Tenant 0's revoke removes the row; a give-up's
/// revocation leaves it `disabled` with no grant, which counts as
/// revoked. A non-empty answer stops the move before step 0. Two point
/// lookups per key with a revocation.
pub async fn p8_stale_revocations<S: Sql, K: super::move_keys::OwnerKeys>(
    d1: &S,
    keys: &K,
    mapped: &[String],
) -> Result<Vec<String>> {
    let mut stale = Vec::new();
    for akid in mapped {
        if !keys.tenant_revoked(akid).await? {
            continue;
        }
        let id = [SqlValue::Text(akid.clone())];
        let active = d1
            .query(
                "SELECT 1 FROM access_keys WHERE access_key_id = ?1 AND status = 'active'",
                &id,
            )
            .await?;
        let granted = d1
            .query("SELECT 1 FROM grants WHERE access_key_id = ?1 LIMIT 1", &id)
            .await?;
        if !active.is_empty() || !granted.is_empty() {
            stale.push(akid.clone());
        }
    }
    Ok(stale)
}

/// P2 (AM-44): whether the stamp prefix `rs/<t>.<u>/` of a unit the move
/// fills is empty, so the move may start. One list call of one key. A
/// prefix that holds stamps stops the move until step 8(b) levels the
/// unit's counter before its `move` report (W4-gate's stamp levelling),
/// which this code does not do yet.
pub async fn p2_stamp_prefix_clear<B: crate::ports::BlobStore>(
    safety: &B,
    unit: &crate::unit::name::UnitName,
) -> Result<bool> {
    let prefix = format!(
        "{}{}/",
        crate::stamp::STAMP_PREFIX,
        crate::unit::jobcall::stamp_id(unit)
    );
    Ok(safety.list(&prefix, "", 1).await?.is_empty())
}

/// A target unit as P12 reads it (`ImportProgress`, and whether the unit
/// exists and is closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnitView {
    /// The unit holds no import.
    Empty,
    /// The unit is unborn (emptied by a `deleteAll()`); `marker`: the
    /// emptied marker `m/ub/<t>/<u>` exists.
    Unborn { marker: bool },
    /// The unit holds an import; `closed`: it answers `Closed{restoring}`.
    Import {
        state: super::move_copy::ImportState,
        closed: bool,
    },
}

/// What P12 (AM-47) decides for a target unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P12 {
    /// No import state (or an unborn unit the day-30 `deleteAll()` left):
    /// go on.
    Empty,
    /// A give-up left unfinished: finish it with no G6 (`deleteAll()`,
    /// the unit re-created with a `restore` token under the entry it
    /// left), then read again.
    FinishGiveUp,
    /// An undone move's 30-day copy: stop before step 0, unless the
    /// owner's go (G6) names the early end of the undo copy; then empty it
    /// as above and read again.
    UndoCopy,
    /// Anything else (tenant 0 `moving` or `moved`, a unit that is not
    /// closed, a `move_lifted` the unit does not say, an unborn unit
    /// without its entry and marker): stop before step 0 and write
    /// nothing. A live unit is never emptied.
    Stop,
}

/// P12 for unit `unit` of the owner `owner_head`, from tenant 0's verified
/// head `zero` and the unit's view.
pub fn p12(zero: &TenantDoor, owner_head: &TenantDoor, unit: u32, view: &UnitView) -> P12 {
    let z = match zero.tenant_zero.as_ref() {
        Some(z) if zero.tenant.is_zero() => z,
        _ => return P12::Stop,
    };
    match view {
        UnitView::Empty => P12::Empty,
        UnitView::Unborn { marker } => {
            let listed =
                owner_head.units.contains(&unit) && owner_head.restoring_entry(unit).is_some();
            match listed && *marker {
                true => P12::Empty,
                false => P12::Stop,
            }
        }
        UnitView::Import { state, closed } => {
            if !closed || z.selector != Selector::D1 {
                return P12::Stop;
            }
            let undone_here =
                z.undone() && z.moved.as_ref().is_some_and(|m| m.to == owner_head.tenant);
            // The seal tells the two lifted states apart: a move that was
            // lifted and given up (V9) never raised `flips`, so its seal is
            // `flips + 1`; a move that flipped (and was undone) sealed at
            // or below `flips`. A later move into another tenant that gave
            // up clears `move` and leaves the undo copy here.
            let given_up_seal = z.flips.checked_add(1);
            let flipped_seal = state.sealed.is_some_and(|s| s <= z.flips);
            match (state.move_lifted, &z.moved) {
                (Some(false), _) => P12::FinishGiveUp,
                (Some(true), None) if state.sealed.is_some() && state.sealed == given_up_seal => {
                    P12::FinishGiveUp
                }
                (Some(true), None) if flipped_seal => P12::UndoCopy,
                (Some(true), Some(_)) if undone_here && flipped_seal => P12::UndoCopy,
                _ => P12::Stop,
            }
        }
    }
}
