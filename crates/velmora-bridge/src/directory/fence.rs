//! The fence of the move: freezing tenant 0's D1 catalogue.
//!
//! The move of tenant 0's data reads the D1 catalogue while nothing may
//! change it, and keeps it unchanged for 30 days as the undo. Three things
//! fence it, against every version of the code, a rollback included:
//!
//! - the **cutover marker**, a row in `meta` written first, which code that
//!   knows about the move reads before it serves tenant 0 from this
//!   database ([`super::tenant_zero`]);
//! - **freeze triggers**: `BEFORE INSERT`, `UPDATE` and `DELETE` on every
//!   table of the catalogue raise `ABORT`. They stop every write to D1 by
//!   any code version for as long as they exist, and nothing else;
//! - the **legacy stamp**: a stamp object one above the frozen counter.
//!   From then on every stamp check of every code version finds this
//!   database rolled back, so no version raises its stamp, runs a GC
//!   delete, an eviction or an intent sweep on it: the triggers stop
//!   writes to D1, the stamp stops deletes in R2 that need no D1 write.
//!
//! Giving the move up before its flip thaws the database: the triggers
//! are dropped first, then the marker is cleared. The legacy stamp is put
//! only at the flip; a give-up after it levels the stamp again.

use sha2::{Digest, Sha256};

use super::tenant_zero::CUTOVER_MARKER_KEY;
use crate::ports::{BlobMeta, BlobStore, Sql, SqlValue};
use crate::stamp::stamp_key;
use crate::types::{BridgeError, BucketId, ExtentId, Result, UnixMs};

/// The prefix of the freeze triggers' names.
pub const FREEZE_TRIGGER_PREFIX: &str = "move_freeze_";

/// The message every frozen write aborts with.
pub const FROZEN_MESSAGE: &str = "catalogue frozen for the move";

/// The three statements a trigger fences, with the suffix of its name.
const OPERATIONS: [(&str, &str); 3] = [("ins", "INSERT"), ("upd", "UPDATE"), ("del", "DELETE")];

const ERR_NAME: BridgeError = BridgeError::Invalid("catalogue table name");

/// A table of the catalogue, by the rules its triggers can be named by.
fn valid_table(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn trigger_name(table: &str, op: &str) -> String {
    format!("{FREEZE_TRIGGER_PREFIX}{table}_{op}")
}

/// Every table of the catalogue, in name order: the tables of SQLite and
/// of the platform and the migration bookkeeping are not the catalogue.
pub async fn catalogue_tables<S: Sql>(catalog: &S) -> Result<Vec<String>> {
    let rows = catalog
        .query(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' \
             AND name <> 'd1_migrations' ORDER BY name",
            &[],
        )
        .await?;
    rows.into_iter()
        .map(|row| match row.into_iter().next() {
            Some(SqlValue::Text(name)) if valid_table(&name) => Ok(name),
            _ => Err(ERR_NAME),
        })
        .collect()
}

/// Writes the cutover marker, if it is not there. Its value is `now`.
/// A marker that is there is not written again: once the triggers exist,
/// even a write that would change nothing aborts.
pub async fn write_marker<S: Sql>(catalog: &S, now: UnixMs) -> Result<()> {
    let there = !catalog
        .query(
            "SELECT 1 FROM meta WHERE k = ?1",
            &[SqlValue::Text(CUTOVER_MARKER_KEY.to_string())],
        )
        .await?
        .is_empty();
    if there {
        return Ok(());
    }
    catalog
        .exec(
            "INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT (k) DO NOTHING",
            &[
                SqlValue::Text(CUTOVER_MARKER_KEY.to_string()),
                SqlValue::Int(now.0),
            ],
        )
        .await
        .map(|_| ())
}

/// Freezes the catalogue: the marker first, then three triggers on every
/// table. It can be run again: what exists stays.
pub async fn freeze<S: Sql>(catalog: &S, now: UnixMs) -> Result<Vec<String>> {
    write_marker(catalog, now).await?;
    let tables = catalogue_tables(catalog).await?;
    for table in &tables {
        for (suffix, op) in OPERATIONS {
            let sql = format!(
                "CREATE TRIGGER IF NOT EXISTS {} BEFORE {op} ON {table} \
                 BEGIN SELECT RAISE(ABORT, '{FROZEN_MESSAGE}'); END",
                trigger_name(table, suffix)
            );
            catalog.exec(&sql, &[]).await?;
        }
    }
    Ok(tables)
}

/// What the catalogue holds of the fence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FreezeState {
    pub marker: bool,
    pub tables: Vec<String>,
    /// `table.operation` of every write that no freeze trigger fences.
    pub unfenced: Vec<String>,
    /// Freeze triggers on a table that is no catalogue table now.
    pub stray: Vec<String>,
}

impl FreezeState {
    /// The marker is there and every write of every table is fenced.
    pub fn frozen(&self) -> bool {
        self.marker && self.unfenced.is_empty()
    }

    /// Nothing of the fence is left.
    pub fn thawed(&self) -> bool {
        !self.marker
            && self.unfenced.len() == self.tables.len() * OPERATIONS.len()
            && self.stray.is_empty()
    }
}

/// Reads the fence back from the catalogue, without trusting the calls
/// that made it.
pub async fn freeze_state<S: Sql>(catalog: &S) -> Result<FreezeState> {
    let marker = !catalog
        .query(
            "SELECT 1 FROM meta WHERE k = ?1",
            &[SqlValue::Text(CUTOVER_MARKER_KEY.to_string())],
        )
        .await?
        .is_empty();
    let tables = catalogue_tables(catalog).await?;
    let triggers = freeze_triggers(catalog).await?;
    let mut unfenced = Vec::new();
    for table in &tables {
        for (suffix, op) in OPERATIONS {
            let name = trigger_name(table, suffix);
            let fenced = triggers.iter().any(|(n, t, sql)| {
                *n == name && t == table && sql.contains(FROZEN_MESSAGE) && sql.contains(op)
            });
            if !fenced {
                unfenced.push(format!("{table}.{op}"));
            }
        }
    }
    let stray = triggers
        .into_iter()
        .filter(|(_, t, _)| !tables.contains(t))
        .map(|(n, _, _)| n)
        .collect();
    Ok(FreezeState {
        marker,
        tables,
        unfenced,
        stray,
    })
}

/// Every freeze trigger: name, table, statement.
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
            [SqlValue::Text(n), SqlValue::Text(t), SqlValue::Text(sql)] => {
                Ok((n.clone(), t.clone(), sql.clone()))
            }
            _ => Err(BridgeError::Invalid("freeze trigger row")),
        })
        .collect()
}

/// Thaws the catalogue: every freeze trigger is dropped, then the marker
/// is cleared. It can be run again.
pub async fn thaw<S: Sql>(catalog: &S) -> Result<()> {
    for (name, _, _) in freeze_triggers(catalog).await? {
        if !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(ERR_NAME);
        }
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

/// The counter of the catalogue's stamp row, `None` with no row.
pub async fn frozen_counter<S: Sql>(catalog: &S) -> Result<Option<u64>> {
    let rows = catalog
        .query("SELECT counter FROM rollback_stamp WHERE id = 1", &[])
        .await?;
    match rows.first().and_then(|r| r.first()) {
        None => Ok(None),
        Some(SqlValue::Int(c)) => u64::try_from(*c)
            .map(Some)
            .map_err(|_| BridgeError::Invalid("stamp counter")),
        Some(_) => Err(BridgeError::Invalid("stamp counter")),
    }
}

/// The name of the legacy stamp of a catalogue frozen at `counter`.
pub fn legacy_stamp_key(catalogue_id: &str, counter: Option<u64>) -> String {
    stamp_key(catalogue_id, counter.map_or(1, |c| c + 1))
}

/// Puts the legacy stamp: the stamp object one above the frozen counter,
/// with the time as its body, as every stamp object has. The counter
/// cannot move (the triggers abort it), so from here every stamp check
/// on this database says "rolled back". Answers the stamp's counter,
/// which the flip record names.
pub async fn put_legacy_stamp<S: Sql, B: BlobStore>(
    catalog: &S,
    safety: &B,
    catalogue_id: &str,
    now: UnixMs,
) -> Result<u64> {
    let counter = frozen_counter(catalog).await?.map_or(1, |c| c + 1);
    let key = stamp_key(catalogue_id, counter);
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
