//! The fence of the move: freezing tenant 0's D1 catalogue.
//!
//! The move of tenant 0's data reads the D1 catalogue while nothing may
//! change it, and keeps it unchanged for 30 days as the undo. Three things
//! fence it, against every version of the code, a rollback included:
//!
//! - the **cutover marker**, a row in `meta` written first, which code that
//!   knows about the move reads before it serves tenant 0 from this
//!   database ([`super::tenant_zero`]). Its value is the ordinal of the
//!   move (1 for the first), so a database that a later move freezes is
//!   told apart from one an earlier move left behind;
//! - **freeze triggers**: `BEFORE INSERT`, `UPDATE` and `DELETE` on every
//!   catalogue table raise `ABORT`. They stop every write to those tables
//!   by any code version for as long as they exist, and nothing else. The
//!   two operational tables of the connection permits and the provider
//!   health ([`OPERATIONAL_TABLES`]) are not fenced: they hold no catalogue
//!   data, the move copies neither, the undo needs neither, and every read
//!   from Usenet writes the permits;
//! - the **legacy stamp**: a stamp object one above the frozen counter,
//!   under the database's own catalogue id. From then on every stamp check
//!   of every code version finds this database rolled back, so no version
//!   raises its stamp or runs a stamp-checked destructive batch on it (GC,
//!   eviction by the cron, the intent sweep): the triggers stop writes to
//!   D1, the stamp stops the deletes in R2 that need no D1 write. The
//!   operator's own eviction call checks no stamp; it is not run in the
//!   window.
//!
//! Giving the move up before its flip thaws the database: the triggers
//! are dropped first, then the marker is cleared. The legacy stamp is put
//! only at the flip; a give-up after it levels the stamp again.
//!
//! **Not verified on D1 itself** (the drill shows each): reading
//! `sqlite_master` through the binding; `CREATE TRIGGER` and `DROP
//! TRIGGER` through `exec`; the form in which D1 stores a trigger's text
//! (compared exactly below);
//! that `_cf_` names all of the platform's own tables; and that a Time
//! Travel restore to before the freeze takes the triggers and the marker
//! with it.

use sha2::{Digest, Sha256};

use super::tenant_zero::CUTOVER_MARKER_KEY;
use crate::ports::{BlobMeta, BlobStore, Sql, SqlValue};
use crate::stamp::stamp_key;
use crate::types::{BridgeError, BucketId, ExtentId, Result, UnixMs};

/// The prefix of the freeze triggers' names.
pub const FREEZE_TRIGGER_PREFIX: &str = "move_freeze_";

/// The message every frozen write aborts with. No code reads it from an
/// error: the D1 adapter keeps only a class of an error, and the fence is
/// read back from `sqlite_master`, never from an error text.
pub const FROZEN_MESSAGE: &str = "catalogue frozen for the move";

/// Tables that hold operational state and no catalogue data: not frozen.
pub const OPERATIONAL_TABLES: [&str; 2] = ["provider_health", "provider_permits"];

/// The three statements a trigger fences, with the suffix of its name.
const OPERATIONS: [(&str, &str); 3] = [("ins", "INSERT"), ("upd", "UPDATE"), ("del", "DELETE")];

const ERR_NAME: BridgeError = BridgeError::Invalid("catalogue table name");
const ERR_NOT_FROZEN: BridgeError = BridgeError::Invalid("catalogue not frozen");
const ERR_ID: BridgeError = BridgeError::Invalid("catalogue id of the stamp row");

/// The longest table name the freeze takes: its trigger names, the
/// prefix and a suffix added, stay within [`MAX_TRIGGER_NAME`].
const MAX_TABLE_NAME: usize = 64;
const MAX_TRIGGER_NAME: usize = FREEZE_TRIGGER_PREFIX.len() + MAX_TABLE_NAME + 4;

fn plain_name(name: &str, max: usize) -> bool {
    (1..=max).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A table name the freeze can fence.
fn valid_table(name: &str) -> bool {
    plain_name(name, MAX_TABLE_NAME)
}

/// A trigger name under the freeze prefix that can be dropped.
fn valid_trigger(name: &str) -> bool {
    plain_name(name, MAX_TRIGGER_NAME)
}

fn trigger_name(table: &str, op: &str) -> String {
    format!("{FREEZE_TRIGGER_PREFIX}{table}_{op}")
}

/// The exact statement of a freeze trigger, as it is created and as the
/// state check compares it.
fn trigger_sql(table: &str, suffix: &str, op: &str) -> String {
    format!(
        "CREATE TRIGGER {} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT, '{FROZEN_MESSAGE}'); END",
        trigger_name(table, suffix)
    )
}

/// Every table to freeze, in name order: not SQLite's, not the
/// platform's, not the migration bookkeeping, not the operational ones.
pub async fn catalogue_tables<S: Sql>(catalog: &S) -> Result<Vec<String>> {
    let rows = catalog
        .query(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' \
             AND name <> 'd1_migrations' ORDER BY name",
            &[],
        )
        .await?;
    let mut out = Vec::new();
    for row in rows {
        match row.into_iter().next() {
            Some(SqlValue::Text(name)) if valid_table(&name) => {
                if !OPERATIONAL_TABLES.contains(&name.as_str()) {
                    out.push(name);
                }
            }
            _ => return Err(ERR_NAME),
        }
    }
    Ok(out)
}

/// The cutover marker's value, `None` when there is none.
pub async fn marker<S: Sql>(catalog: &S) -> Result<Option<i64>> {
    let rows = catalog
        .query(
            "SELECT v FROM meta WHERE k = ?1",
            &[SqlValue::Text(CUTOVER_MARKER_KEY.to_string())],
        )
        .await?;
    match rows.first().and_then(|r| r.first()) {
        None => Ok(None),
        Some(SqlValue::Int(v)) => Ok(Some(*v)),
        Some(_) => Err(BridgeError::Invalid("cutover marker")),
    }
}

/// Writes the cutover marker of move `ordinal`, if no marker is there.
/// The move tool passes `flips + 1` of tenant 0's head, the count the
/// request path judges the marker against. A
/// marker that is there is not written again (once the triggers exist,
/// even a write that would change nothing aborts); one of another move is
/// an error.
pub async fn write_marker<S: Sql>(catalog: &S, ordinal: u64) -> Result<()> {
    let ordinal = i64::try_from(ordinal).map_err(|_| BridgeError::Invalid("move ordinal"))?;
    match marker(catalog).await? {
        Some(v) if v == ordinal => Ok(()),
        Some(_) => Err(BridgeError::Invalid("cutover marker of another move")),
        None => catalog
            .exec(
                "INSERT INTO meta (k, v) VALUES (?1, ?2)",
                &[
                    SqlValue::Text(CUTOVER_MARKER_KEY.to_string()),
                    SqlValue::Int(ordinal),
                ],
            )
            .await
            .map(|_| ()),
    }
}

/// Freezes the catalogue for move `ordinal`: the marker first, then three
/// triggers on every table. A freeze trigger whose text is not exactly
/// the expected one is dropped and made again. It can be run again; it
/// ends by reading the fence back and fails unless it holds.
pub async fn freeze<S: Sql>(catalog: &S, ordinal: u64) -> Result<Vec<String>> {
    write_marker(catalog, ordinal).await?;
    let tables = catalogue_tables(catalog).await?;
    let existing = freeze_triggers(catalog).await?;
    for table in &tables {
        for (suffix, op) in OPERATIONS {
            let name = trigger_name(table, suffix);
            let want = trigger_sql(table, suffix, op);
            match existing.iter().find(|(n, _, _)| *n == name) {
                Some((_, t, sql)) if t == table && sql.trim() == want => continue,
                Some(_) => {
                    catalog
                        .exec(&format!("DROP TRIGGER IF EXISTS {name}"), &[])
                        .await?;
                }
                None => {}
            }
            catalog.exec(&want, &[]).await?;
        }
    }
    if !freeze_state(catalog).await?.frozen() {
        return Err(ERR_NOT_FROZEN);
    }
    Ok(tables)
}

/// What the catalogue holds of the fence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FreezeState {
    /// The marker's value.
    pub marker: Option<i64>,
    pub tables: Vec<String>,
    /// `table.operation` of every write that no freeze trigger fences.
    pub unfenced: Vec<String>,
    /// Triggers under the freeze prefix that are not exactly a freeze
    /// trigger of a table to freeze.
    pub stray: Vec<String>,
}

impl FreezeState {
    /// The marker is there and every write of every table is fenced by
    /// exactly its freeze trigger.
    pub fn frozen(&self) -> bool {
        self.marker.is_some() && self.unfenced.is_empty() && self.stray.is_empty()
    }

    /// Nothing of the fence is left.
    pub fn thawed(&self) -> bool {
        self.marker.is_none()
            && self.unfenced.len() == self.tables.len() * OPERATIONS.len()
            && self.stray.is_empty()
    }
}

/// Reads the fence back from the catalogue, without trusting the calls
/// that made it: a trigger counts only if its text is exactly the
/// expected statement.
pub async fn freeze_state<S: Sql>(catalog: &S) -> Result<FreezeState> {
    let marker = marker(catalog).await?;
    let tables = catalogue_tables(catalog).await?;
    let triggers = freeze_triggers(catalog).await?;
    let mut unfenced = Vec::new();
    let mut expected = Vec::new();
    for table in &tables {
        for (suffix, op) in OPERATIONS {
            let name = trigger_name(table, suffix);
            let want = trigger_sql(table, suffix, op);
            let fenced = triggers
                .iter()
                .any(|(n, t, sql)| *n == name && t == table && sql.trim() == want);
            if !fenced {
                unfenced.push(format!("{table}.{op}"));
            }
            expected.push(name);
        }
    }
    let stray = triggers
        .into_iter()
        .filter(|(n, t, sql)| {
            let exact = OPERATIONS.iter().any(|(suffix, op)| {
                *n == trigger_name(t, suffix) && sql.trim() == trigger_sql(t, suffix, op)
            });
            !(exact && expected.contains(n))
        })
        .map(|(n, _, _)| n)
        .collect();
    Ok(FreezeState {
        marker,
        tables,
        unfenced,
        stray,
    })
}

/// Every trigger under the freeze prefix: name, table, statement.
async fn freeze_triggers<S: Sql>(catalog: &S) -> Result<Vec<(String, String, String)>> {
    let rows = catalog
        .query(
            "SELECT name, tbl_name, sql FROM sqlite_master WHERE type = 'trigger' \
             AND substr(name, 1, ?1) = ?2 ORDER BY name",
            &[
                SqlValue::Int(FREEZE_TRIGGER_PREFIX.len() as i64),
                SqlValue::Text(FREEZE_TRIGGER_PREFIX.to_string()),
            ],
        )
        .await?;
    rows.into_iter()
        .map(|row| match row.as_slice() {
            [SqlValue::Text(n), SqlValue::Text(t), SqlValue::Text(sql)] if valid_trigger(n) => {
                Ok((n.clone(), t.clone(), sql.clone()))
            }
            _ => Err(BridgeError::Invalid("freeze trigger row")),
        })
        .collect()
}

/// Thaws the catalogue: every trigger under the freeze prefix is dropped,
/// then the marker is cleared. It can be run again.
pub async fn thaw<S: Sql>(catalog: &S) -> Result<()> {
    for (name, _, _) in freeze_triggers(catalog).await? {
        catalog
            .exec(&format!("DROP TRIGGER IF EXISTS {name}"), &[])
            .await?;
    }
    catalog
        .exec(
            "DELETE FROM meta WHERE k = ?1",
            &[SqlValue::Text(CUTOVER_MARKER_KEY.to_string())],
        )
        .await
        .map(|_| ())
}

/// The stamp row of the catalogue: its counter and its catalogue id,
/// `None` with no row.
pub async fn stamp_row<S: Sql>(catalog: &S) -> Result<Option<(u64, String)>> {
    let rows = catalog
        .query(
            "SELECT counter, catalogue_id FROM rollback_stamp WHERE id = 1",
            &[],
        )
        .await?;
    match rows.first().map(|r| r.as_slice()) {
        None => Ok(None),
        Some([SqlValue::Int(c), SqlValue::Text(id)]) => u64::try_from(*c)
            .map(|c| Some((c, id.clone())))
            .map_err(|_| BridgeError::Invalid("stamp counter")),
        Some(_) => Err(BridgeError::Invalid("stamp row")),
    }
}

/// The name of the legacy stamp of a catalogue frozen at `counter`.
pub fn legacy_stamp_key(catalogue_id: &str, counter: Option<u64>) -> String {
    stamp_key(catalogue_id, counter.map_or(1, |c| c + 1))
}

/// Puts the legacy stamp: the stamp object one above the frozen counter,
/// under the catalogue id that the stamp row itself carries (which must
/// be `catalogue_id`, the one the Worker checks under), with the time as
/// its body. Refused unless the catalogue is frozen, so no raise can move
/// the counter to the same value in between. An object that is already
/// there is kept, its time included. Answers the stamp's counter, which
/// the flip record names.
pub async fn put_legacy_stamp<S: Sql, B: BlobStore>(
    catalog: &S,
    safety: &B,
    catalogue_id: &str,
    now: UnixMs,
) -> Result<u64> {
    if !freeze_state(catalog).await?.frozen() {
        return Err(ERR_NOT_FROZEN);
    }
    let counter = match stamp_row(catalog).await? {
        Some((counter, id)) if id == catalogue_id => counter + 1,
        Some(_) => return Err(ERR_ID),
        None => 1,
    };
    let key = stamp_key(catalogue_id, counter);
    if safety.head(&key).await?.is_some() {
        return Ok(counter);
    }
    let body = now.0.to_string().into_bytes();
    let sha: [u8; 32] = Sha256::digest(&body).into();
    let bucket = BucketId::new("-");
    let meta = BlobMeta {
        bucket: &bucket,
        extent: &ExtentId::new("rollback-stamp"),
        cipher_sha256: &sha,
    };
    safety.put(&key, body, &meta).await?;
    Ok(counter)
}
