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
//! Every query is one page of at most [`MAX_PAGE`] rows in primary-key
//! order; a cell's class is computed by SQLite, so no value outside the
//! safe range is ever read through an adapter. Nothing is written.

use std::collections::BTreeSet;

use serde::Serialize;

use super::move_copy::key_columns;
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result};
use crate::unit::import::ImportTable;

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
}

impl P2Lines {
    /// Whether a line stops the move before step 0.
    pub fn stops(&self) -> bool {
        self.nonconforming_count > 0
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
    // Bucket ids.
    let mut after: Option<SqlValue> = None;
    loop {
        let rows = match &after {
            None => {
                d1.query(
                    &format!("SELECT id FROM buckets ORDER BY id LIMIT {page}"),
                    &[],
                )
                .await?
            }
            Some(a) => {
                d1.query(
                    &format!("SELECT id FROM buckets WHERE id > ?1 ORDER BY id LIMIT {page}"),
                    std::slice::from_ref(a),
                )
                .await?
            }
        };
        for row in &rows {
            let Some(SqlValue::Text(id)) = row.first() else {
                return Err(BridgeError::Invalid("p2: bucket id"));
            };
            if !super::transition::valid_bucket_id(id) {
                lines.nonconforming_count += 1;
                if lines.nonconforming_ids.len() < MAX_SAMPLES {
                    lines.nonconforming_ids.push(id.clone());
                }
            }
            after = Some(SqlValue::Text(id.clone()));
        }
        if rows.len() < page {
            break;
        }
    }
    for table in ImportTable::ALL {
        lines.cells.extend(integer_cells(d1, table, page).await?);
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

/// The class of each INTEGER-declared cell of `table`, a page at a time.
async fn integer_cells<S: Sql>(d1: &S, table: ImportTable, page: usize) -> Result<Vec<CellLine>> {
    let columns = integer_columns(d1, table).await?;
    if columns.is_empty() {
        return Ok(Vec::new());
    }
    let keys = key_columns(table);
    let key_list: Vec<String> = keys.iter().map(|k| format!("\"{k}\"")).collect();
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
        key_list.join(", "),
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
            position = Some(key.to_vec());
        }
        if rows.len() < page {
            break;
        }
    }
    Ok(lines)
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
