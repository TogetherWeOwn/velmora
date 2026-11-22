//! The unit's rows read back out (`docs/units.md`, "Export"; ADR §2.4
//! rule 1, amendment AM-26).
//!
//! `export(table, after, limit, mode)` is read-only. It pages one table
//! in primary-key order, after the key `after` (none: from the start), at
//! most `limit` rows ([`MAX_ROWS`]), in the import's value encoding, so
//! the SQLite type class of every value is kept (X-1):
//!
//! - `mode = hash` answers the page's row count, its last key and
//!   [`hash_rows`] over its rows without the table's V1-excluded columns
//!   ([`ExportTable::hash_excluded`], a fixed list here). This is how the
//!   move's V1 and V6 read the unit: no row leaves it.
//! - `mode = rows` answers the rows themselves, also cut at [`MAX_BYTES`]
//!   of encoded rows (a larger row is answered alone): the reverse move
//!   (DS1 §3.7 step 3) only.
//!
//! A page is exactly the next rows after `after` in key order, so the
//! tool reads the same rows of the frozen D1 (the key range
//! `(after, last]`, after the §3.2 transforms and the hour filing) and
//! hashes them with the same [`hash_rows`]. `more` says whether rows
//! follow `last`.
//!
//! It is refused unless the unit's `restoring` entry is set (a closed
//! unit gives a consistent read, and no row leaves an open unit). It
//! reads only the tables the import writes and the key tables
//! (`unit_keys`, `unit_key_grants`); on the key tables it runs in `hash`
//! mode only, and the digest covers every column, the wrap included. It
//! never reads the unit's own tables (`unit_birth`, `unit_head`, the
//! lease, `unit_import*`, `unit_gate_*`). `buckets.bdk_wrapped` and
//! `extents.wrapped_file_key` leave in `rows` mode as stored, still
//! wrapped, to the move or undo tool in the Worker only: never to a log,
//! a receipt or a queue message.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::import::{ImportTable, ImportValue};
use super::keys::{self, KeyEntry, SubjectStatus};
use super::object::poll_once;
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result};

/// The most rows one answer carries.
pub const MAX_ROWS: u32 = 500;
/// The most bytes of encoded rows one `rows` answer carries; a larger row
/// is answered alone.
pub const MAX_BYTES: usize = 1 << 20;
/// What [`hash_rows`] starts with (version 1 of the encoding).
pub const DIGEST_DOMAIN: &[u8] = b"velmora/unit-export/v1\n";

/// The two key tables an export may hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyTable {
    UnitKeys,
    UnitKeyGrants,
}

/// A table an export reads: one the import writes, or a key table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ExportTable {
    Keys(KeyTable),
    Data(ImportTable),
}

impl ExportTable {
    pub fn name(self) -> &'static str {
        match self {
            ExportTable::Keys(KeyTable::UnitKeys) => "unit_keys",
            ExportTable::Keys(KeyTable::UnitKeyGrants) => "unit_key_grants",
            ExportTable::Data(t) => t.name(),
        }
    }

    /// The table's columns, in schema order (a test holds them to the
    /// schema): the order of every exported row.
    pub fn columns(self) -> &'static [&'static str] {
        match self {
            ExportTable::Keys(KeyTable::UnitKeys) => &[
                "id",
                "kind",
                "status",
                "held",
                "made_by",
                "created_at",
                "secret_wrapped",
                "secret_kek_version",
                "owner_ref",
                "last_seq",
            ],
            ExportTable::Keys(KeyTable::UnitKeyGrants) => &[
                "subject_id",
                "idx",
                "bucket_id",
                "access",
                "expires_at",
                "prefix",
                "ip_list",
            ],
            ExportTable::Data(t) => t.columns(),
        }
    }

    /// The primary key, in index order (a test holds it to the schema).
    pub fn key_columns(self) -> &'static [&'static str] {
        match self {
            ExportTable::Keys(KeyTable::UnitKeys) => &["id"],
            ExportTable::Keys(KeyTable::UnitKeyGrants) => &["subject_id", "idx"],
            ExportTable::Data(t) => t.key_columns(),
        }
    }

    /// The columns `hash` mode leaves out: the columns DS1 §3.5 V1
    /// excludes because the move transforms them (checked by V4 to V6 and
    /// their own rule) or the unit holds them otherwise (AM-26). The key
    /// tables leave out nothing.
    pub fn hash_excluded(self) -> &'static [&'static str] {
        match self {
            ExportTable::Data(ImportTable::Buckets) => &["owner", "bdk_wrapped", "kek_version"],
            ExportTable::Data(ImportTable::Extents) => &["hot_safety_bytes", "hot_cache_bytes"],
            ExportTable::Data(ImportTable::Outbox) => &["lease_owner", "lease_until"],
            _ => &[],
        }
    }

    /// Whether `rows` mode may read the table (not the key tables).
    pub fn rows_allowed(self) -> bool {
        matches!(self, ExportTable::Data(_))
    }

    /// The key columns declared `INTEGER` (the others are `TEXT`; a test
    /// holds both to the schema). A key value of the other class would
    /// compare past every row of the table (SQLite orders every integer
    /// before every text), so the page would end early without an error.
    pub fn integer_keys(self) -> &'static [&'static str] {
        match self {
            ExportTable::Keys(KeyTable::UnitKeyGrants) => &["idx"],
            ExportTable::Data(ImportTable::GenerationExtents) => &["seq"],
            ExportTable::Data(ImportTable::Articles) => &["idx"],
            ExportTable::Data(ImportTable::Verifications) => &["verified_at"],
            ExportTable::Data(ImportTable::VerifyRaises) => &["plan_rev"],
            ExportTable::Data(ImportTable::UploadParts) => &["part_number"],
            ExportTable::Data(ImportTable::UploadPartExtents) => &["part_number", "piece"],
            ExportTable::Data(ImportTable::Gc) | ExportTable::Data(ImportTable::UsageRecounts) => {
                &["id"]
            }
            ExportTable::Data(ImportTable::UsageHours) => &["hour"],
            _ => &[],
        }
    }

    /// Whether `key` is a key of this table: one value per key column,
    /// each of the column's class.
    pub fn is_key(self, key: &[ImportValue]) -> bool {
        let ints = self.integer_keys();
        key.len() == self.key_columns().len()
            && self.key_columns().iter().zip(key).all(|(c, v)| {
                matches!(
                    (ints.contains(c), v),
                    (true, ImportValue::Int(_)) | (false, ImportValue::Text(_))
                )
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportMode {
    Hash,
    Rows,
}

/// Why an export was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportRefusal {
    /// The unit's `restoring` entry is not set.
    NotRestoring,
    /// `rows` mode on a key table: only a digest leaves the unit.
    HashOnly,
    /// `limit` is 0 or above [`MAX_ROWS`], or `after` is not a key of the
    /// table (another number of values, or a value of another class than
    /// its column's).
    Malformed,
}

/// One page of a table, in key order.
#[derive(Clone, PartialEq, Eq)]
pub struct Page {
    pub rows: Vec<Vec<ImportValue>>,
    /// Rows follow the last one.
    pub more: bool,
}

impl std::fmt::Debug for Page {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Page")
            .field("rows", &self.rows.len())
            .field("more", &self.more)
            .finish()
    }
}

fn quoted(cols: &[&str]) -> Vec<String> {
    cols.iter().map(|c| format!("\"{c}\"")).collect()
}

/// The page query of `table`: every column, after a key when `after`,
/// in key order, `?{n+1}` rows at most (the caller asks one more than it
/// answers, to know whether rows follow).
pub fn page_sql(table: ExportTable, after: bool) -> String {
    let cols = quoted(table.columns()).join(", ");
    let keys = quoted(table.key_columns());
    let mut sql = format!("SELECT {cols} FROM \"{}\"", table.name());
    let n = keys.len();
    if after {
        let params: Vec<String> = (1..=n).map(|i| format!("?{i}")).collect();
        if n == 1 {
            sql.push_str(&format!(" WHERE {} > ?1", keys[0]));
        } else {
            sql.push_str(&format!(
                " WHERE ({}) > ({})",
                keys.join(", "),
                params.join(", ")
            ));
        }
    }
    let limit = if after { n + 1 } else { 1 };
    sql.push_str(&format!(" ORDER BY {} LIMIT ?{limit}", keys.join(", ")));
    sql
}

fn value(v: SqlValue) -> ImportValue {
    match v {
        SqlValue::Null => ImportValue::Null,
        SqlValue::Int(n) => ImportValue::Int(n),
        SqlValue::Text(s) => ImportValue::Text(s),
        SqlValue::Blob(b) => ImportValue::Blob(b),
    }
}

fn sql_value(v: &ImportValue) -> SqlValue {
    match v {
        ImportValue::Null => SqlValue::Null,
        ImportValue::Int(n) => SqlValue::Int(*n),
        ImportValue::Text(s) => SqlValue::Text(s.clone()),
        ImportValue::Blob(b) => SqlValue::Blob(b.clone()),
    }
}

/// Reads the next page of `table` after `after`: at most `limit` rows,
/// and, with `max_bytes`, no more encoded bytes than that unless the
/// first row alone is larger. `after` must be a key of the table and
/// `limit` within 1 to [`MAX_ROWS`] (the caller checked).
pub fn read_page<S: Sql>(
    sql: &S,
    table: ExportTable,
    after: Option<&[ImportValue]>,
    limit: u32,
    max_bytes: Option<usize>,
) -> Result<Page> {
    let mut params: Vec<SqlValue> = after
        .map(|a| a.iter().map(sql_value).collect())
        .unwrap_or_default();
    params.push(SqlValue::Int(i64::from(limit) + 1));
    let rows = poll_once(sql.query(&page_sql(table, after.is_some()), &params))??;
    let width = table.columns().len();
    let mut out = Vec::with_capacity(rows.len().min(limit as usize));
    let mut bytes = 0usize;
    let mut more = rows.len() > limit as usize;
    for r in rows.into_iter().take(limit as usize) {
        if r.len() != width {
            return Err(BridgeError::Sql("unit: export row width".into()));
        }
        let row: Vec<ImportValue> = r.into_iter().map(value).collect();
        if let Some(cap) = max_bytes {
            let size = serde_json::to_vec(&row)
                .map_err(|_| BridgeError::Invalid("unit: export row"))?
                .len();
            if !out.is_empty() && bytes + size > cap {
                more = true;
                break;
            }
            bytes += size;
        }
        out.push(row);
    }
    Ok(Page { rows: out, more })
}

fn put_value(h: &mut Sha256, v: &ImportValue) {
    match v {
        ImportValue::Null => h.update([0u8]),
        ImportValue::Int(n) => {
            h.update([1u8]);
            h.update(n.to_be_bytes());
        }
        ImportValue::Text(s) => {
            h.update([2u8]);
            h.update((s.len() as u64).to_be_bytes());
            h.update(s.as_bytes());
        }
        ImportValue::Blob(b) => {
            h.update([3u8]);
            h.update((b.len() as u64).to_be_bytes());
            h.update(b);
        }
    }
}

/// The digest of `hash` mode, as lowercase hex: SHA-256 over
/// [`DIGEST_DOMAIN`], the table name and `\n`, each hashed column name
/// followed by `,`, then `\n`, then per row each hashed value in column
/// order: a null as byte 0; an integer as byte 1 and 8 bytes big-endian;
/// a text as byte 2, its UTF-8 length as 8 bytes big-endian and its
/// bytes; a blob as byte 3, its length the same way and its bytes.
/// `rows` hold every column of the table, in [`ExportTable::columns`]
/// order; the [`ExportTable::hash_excluded`] ones are left out here. The
/// move tool hashes the frozen D1's rows of the same key range with this
/// function.
pub fn hash_rows(table: ExportTable, rows: &[Vec<ImportValue>]) -> Result<String> {
    let cols = table.columns();
    let excluded = table.hash_excluded();
    let keep: Vec<bool> = cols.iter().map(|c| !excluded.contains(c)).collect();
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update(table.name().as_bytes());
    h.update(b"\n");
    for (c, k) in cols.iter().zip(&keep) {
        if *k {
            h.update(c.as_bytes());
            h.update(b",");
        }
    }
    h.update(b"\n");
    for row in rows {
        if row.len() != cols.len() {
            return Err(BridgeError::Invalid("unit: export row width"));
        }
        for (v, k) in row.iter().zip(&keep) {
            if *k {
                put_value(&mut h, v);
            }
        }
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// The key of `row` (its key columns' values).
pub fn key_of(table: ExportTable, row: &[ImportValue]) -> Vec<ImportValue> {
    let cols = table.columns();
    table
        .key_columns()
        .iter()
        .filter_map(|k| cols.iter().position(|c| c == k).map(|i| row[i].clone()))
        .collect()
}

/// One export call, read-only, inside the caller's transaction.
pub fn export<S: Sql>(
    sql: &S,
    restoring_since: Option<u64>,
    table: ExportTable,
    after: Option<&[ImportValue]>,
    limit: u32,
    mode: ExportMode,
) -> Result<std::result::Result<Value, ExportRefusal>> {
    if restoring_since.is_none() {
        return Ok(Err(ExportRefusal::NotRestoring));
    }
    if mode == ExportMode::Rows && !table.rows_allowed() {
        return Ok(Err(ExportRefusal::HashOnly));
    }
    let key_ok = after.is_none_or(|a| table.is_key(a));
    if limit == 0 || limit > MAX_ROWS || !key_ok {
        return Ok(Err(ExportRefusal::Malformed));
    }
    let cap = (mode == ExportMode::Rows).then_some(MAX_BYTES);
    let page = read_page(sql, table, after, limit, cap)?;
    let last = page.rows.last().map(|r| key_of(table, r));
    let mut body = json!({
        "table": table.name(),
        "mode": mode,
        "count": page.rows.len(),
        "last": last,
        "more": page.more,
    });
    match mode {
        ExportMode::Hash => body["sha256"] = json!(hash_rows(table, &page.rows)?),
        ExportMode::Rows => body["rows"] = json!(page.rows),
    }
    Ok(Ok(body))
}

/// The key tables' rows a unit holds after a direct apply of `entries`
/// (chain order, from an empty unit: the move's step 5(e)), in key
/// order: what V6 hashes on the chain side with [`hash_rows`], against
/// `export` in `hash` mode on the unit. Each subject's row is its last
/// entry, and a subject once revoked stays revoked, as `keys::apply`
/// writes them.
#[allow(clippy::type_complexity)]
pub fn chain_key_rows(
    entries: &[KeyEntry],
) -> Result<(Vec<Vec<ImportValue>>, Vec<Vec<ImportValue>>)> {
    let mut last: BTreeMap<&str, (&KeyEntry, bool)> = BTreeMap::new();
    for e in entries {
        let revoked =
            e.status == SubjectStatus::Revoked || last.get(e.id.as_str()).is_some_and(|(_, r)| *r);
        last.insert(e.id.as_str(), (e, revoked));
    }
    let (mut keys_rows, mut grant_rows) = (Vec::new(), Vec::new());
    for (e, revoked) in last.into_values() {
        let status = if revoked {
            SubjectStatus::Revoked
        } else {
            e.status
        };
        let (row, grants) = keys::entry_values(e, status)?;
        keys_rows.push(row.into_iter().map(value).collect());
        for g in grants {
            grant_rows.push(g.into_iter().map(value).collect());
        }
    }
    Ok((keys_rows, grant_rows))
}
