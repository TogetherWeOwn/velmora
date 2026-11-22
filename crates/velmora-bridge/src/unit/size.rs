//! The size guard (`docs/units.md`, "Size guard"; ADR §2.6, §8.2).
//!
//! A Durable Object's SQLite stops at 10 GB with `SQLITE_FULL`. At the
//! guard, 8 GB of database or 3.4 M extents, a call that adds extents is
//! refused, in its own transaction, before it writes: it fails closed.
//! Reads, deletes and smaller overwrites go on. The Worker answers
//! `503 SlowDown` and pages (a bucket can move to another unit), or
//! `403 QuotaExceeded` when one bucket fills the unit (ADR §2.6; owner
//! item Q9).
//!
//! The database size is the object's own (`databaseSize`). The extent
//! count is the live usage counters' (`x_unreleased + x_released +
//! x_deleted`, every safety state) while they are on, so the guard reads
//! one row and never counts the table. While they are off (a closed unit
//! being filled), it is the rows the move's import has taken, which is
//! every extent such a unit holds; the larger of what is known counts.
//!
//! Today the calls that add extents to a unit are the move's import
//! batches; the request path's write admission takes the same check when
//! it moves into the unit.

use serde::{Deserialize, Serialize};

use super::object::poll_once;
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result};

/// The guard's database size (ADR §2.6: 8 GB of the platform's 10 GB).
pub const GUARD_BYTES: u64 = 8_000_000_000;
/// The guard's extent count (ADR §2.6: 3.4 M at 2,378 B an extent).
pub const GUARD_EXTENTS: u64 = 3_400_000;
/// The hard ceiling (est), between the guard and the platform's 10 GB:
/// above it no request call that adds a row runs, not even a delete's
/// floor or a smaller overwrite, so `SQLITE_FULL` is never reached and
/// the calls that free space (GC, aborts, settles) still run.
pub const HARD_BYTES: u64 = 9_000_000_000;

/// Where the guard stands. Tests lower it (ADR §8.2: "tested in W2
/// against a lowered limit").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeLimits {
    pub bytes: u64,
    pub extents: u64,
    /// [`HARD_BYTES`].
    pub hard_bytes: u64,
}

impl Default for SizeLimits {
    fn default() -> Self {
        SizeLimits {
            bytes: GUARD_BYTES,
            extents: GUARD_EXTENTS,
            hard_bytes: HARD_BYTES,
        }
    }
}

/// Why a call that adds extents was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SizeRefusal {
    /// The database is at the guard's size.
    DatabaseFull,
    /// The unit would hold more extents than the guard's count.
    TooManyExtents,
}

/// The extents the unit holds, as far as it knows without a count of
/// the table (module doc).
pub fn extents_held<S: Sql>(sql: &S) -> Result<u64> {
    let rows = poll_once(sql.query(
        "SELECT (SELECT CASE WHEN all_x = 1 THEN x_unreleased + x_released + x_deleted \
                   ELSE 0 END FROM usage_global WHERE id = 1), \
                (SELECT rows FROM unit_import WHERE tbl = 'extents')",
        &[],
    ))??;
    let n = |v: Option<&SqlValue>| match v {
        None | Some(SqlValue::Null) => Ok(0u64),
        Some(SqlValue::Int(n)) => u64::try_from(*n).map_err(|_| decode("extent count")),
        Some(_) => Err(decode("extent count")),
    };
    let row = rows.first();
    Ok(n(row.and_then(|r| r.first()))?.max(n(row.and_then(|r| r.get(1)))?))
}

/// The guard for a call that adds `adding` extents (0 for a call that
/// only grows the database), at `database_size` bytes.
pub fn admit<S: Sql>(
    sql: &S,
    limits: SizeLimits,
    database_size: u64,
    adding: u64,
) -> Result<std::result::Result<(), SizeRefusal>> {
    if database_size >= limits.bytes {
        return Ok(Err(SizeRefusal::DatabaseFull));
    }
    if adding > 0 && extents_held(sql)?.saturating_add(adding) > limits.extents {
        return Ok(Err(SizeRefusal::TooManyExtents));
    }
    Ok(Ok(()))
}

fn decode(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("unit: row decode: {what}"))
}
