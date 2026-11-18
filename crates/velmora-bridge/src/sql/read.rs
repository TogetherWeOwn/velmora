//! What a read needs from the catalogue, as one statement.
//!
//! A GET used to ask five things one after the other (the key, the
//! bucket, the grant, the live generation, its extents), each a round
//! trip to the database. Here they are the arms of one compound
//! `SELECT`: one round trip, and one moment of the catalogue for all of
//! them. Every row starts with a letter that says which arm it is from
//! and is filled up with `NULL` to the width of the widest arm.
//!
//! The arms are the statements of the single reads (`auth::access_key`,
//! `auth::bucket_by_name`, `auth::grant`, `objects::live_generation`,
//! `objects::extents_in`), with the bucket found by its name instead of
//! its id. The generation and extent arms answer only for a key that is
//! active and holds a grant on the bucket: what a request without one
//! would never have asked for stays in the database.

use std::sync::OnceLock;

use super::auth::bucket_row;
use super::objects::{
    extent_cols, generation_row, text, Cols, GENERATION_COLS, GENERATION_WIDTH, PLACED_EXTENT_COLS,
};
use super::SqlCatalog;
use crate::ports::{Row, Sql, SqlValue};
use crate::types::{
    AccessKeyRow, BridgeError, BucketId, GenerationId, KeyStatus, Perm, PinnedRead, ReadExtent,
    ReadLookup, ReadQuery, ReadWindow, Result,
};

/// Columns after the letter: an extent with its read stamp and the
/// generation it was found through.
const WIDTH: usize = 24;
/// Columns of a bucket row.
const BUCKET_WIDTH: usize = 7;

fn bad(what: &'static str) -> BridgeError {
    BridgeError::Sql(format!("read lookup: {what}"))
}

/// `, NULL` for each column an arm of `used` columns leaves empty.
fn pad(used: usize) -> String {
    ", NULL".repeat(WIDTH - used)
}

/// The key `?1` is active and holds a grant on bucket `b`.
const GRANTED: &str = "EXISTS (SELECT 1 FROM grants gr \
       JOIN access_keys k ON k.access_key_id = gr.access_key_id \
     WHERE gr.access_key_id = ?1 AND gr.bucket_id = b.id AND k.status = 'active')";

/// The extents arm: those of generation `g` that hold plaintext
/// `[{start}, {end})`, as `objects::extents_in` finds them.
fn extents_arm(from: &str, filter: &str, start: &str, end: &str) -> String {
    format!(
        "SELECT 'e', {PLACED_EXTENT_COLS}, e.last_read_at, e.hot_cache_bytes, g.id \
         FROM {from} \
           JOIN generation_extents ge ON ge.generation_id = g.id \
           JOIN extents e ON e.id = ge.extent_id \
         WHERE {filter} \
           AND ge.seq >= COALESCE((SELECT s.seq FROM generation_extents s \
                 WHERE s.generation_id = g.id AND s.plain_offset <= {start} \
                 ORDER BY s.seq DESC LIMIT 1), 0) \
           AND ge.seq <= COALESCE((SELECT s.seq FROM generation_extents s \
                 WHERE s.generation_id = g.id AND s.plain_offset < {end} \
                 ORDER BY s.seq DESC LIMIT 1), -1)"
    )
}

/// `?1` key id, `?2` bucket name, `?3` object key, `?4` start of the
/// window (the length of a tail), `?5` its end, `?6` 1 for a tail,
/// `?7` the longest window that brings extents, `?8` 1 to ask for them.
fn lookup_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let live = "buckets b \
               JOIN objects o ON o.bucket_id = b.id AND o.key = ?3 \
               JOIN generations g ON g.id = o.generation_id AND g.bucket_id = o.bucket_id";
        let start = "(CASE WHEN ?6 = 1 THEN max(g.size - ?4, 0) ELSE ?4 END)";
        let end = "min(?5, g.size)";
        let extents = extents_arm(
            live,
            &format!(
                "b.name = ?2 AND ?8 = 1 AND {GRANTED} \
                 AND {end} - {start} BETWEEN 1 AND ?7"
            ),
            start,
            end,
        );
        format!(
            "SELECT 'k', access_key_id, principal, secret_wrapped, kek_version, status, \
               created_at{} \
             FROM access_keys WHERE access_key_id = ?1 AND status = 'active' \
             UNION ALL \
             SELECT 'b', id, name, owner, bdk_wrapped, kek_version, disposable, created_at{} \
             FROM buckets WHERE name = ?2 \
             UNION ALL \
             SELECT 'p', gr.perm{} FROM grants gr \
               JOIN access_keys k ON k.access_key_id = gr.access_key_id \
               JOIN buckets b ON b.id = gr.bucket_id \
             WHERE gr.access_key_id = ?1 AND b.name = ?2 AND k.status = 'active' \
             UNION ALL \
             SELECT 'g', {GENERATION_COLS}{} FROM {live} WHERE b.name = ?2 AND {GRANTED} \
             UNION ALL \
             {extents}",
            pad(6),
            pad(BUCKET_WIDTH),
            pad(1),
            pad(GENERATION_WIDTH),
        )
    })
}

/// `?1` generation id, `?2` bucket id, `?3` start, `?4` end.
fn pinned_sql() -> &'static str {
    static SQL: OnceLock<String> = OnceLock::new();
    SQL.get_or_init(|| {
        let extents = extents_arm(
            "generations g",
            "g.id = ?1 AND g.bucket_id = ?2",
            "?3",
            "?4",
        );
        format!(
            "SELECT 'g', {GENERATION_COLS}, b.id, b.name, b.owner, b.bdk_wrapped, \
               b.kek_version, b.disposable, b.created_at{} \
             FROM generations g JOIN buckets b ON b.id = g.bucket_id \
             WHERE g.id = ?1 AND g.bucket_id = ?2 \
             UNION ALL \
             {extents}",
            pad(GENERATION_WIDTH + BUCKET_WIDTH),
        )
    })
}

/// The letter of a row and the columns after it.
fn arm(mut row: Row) -> Result<(String, Row)> {
    if row.len() != WIDTH + 1 {
        return Err(bad("row width"));
    }
    let rest = row.split_off(1);
    match row.pop() {
        Some(SqlValue::Text(letter)) => Ok((letter, rest)),
        _ => Err(bad("row letter")),
    }
}

fn int(v: u64) -> Result<SqlValue> {
    i64::try_from(v)
        .map(SqlValue::Int)
        .map_err(|_| bad("range offset"))
}

/// An extent arm row, and the generation it was found through.
fn read_extent(row: Row) -> Result<(ReadExtent, GenerationId)> {
    let mut c = Cols::new(row);
    let row = extent_cols(&mut c)?;
    let last_read_at = c.opt_ms()?;
    let cache_counted = c.num::<i64>()? > 0;
    let generation = GenerationId::new(c.text()?);
    Ok((
        ReadExtent {
            row,
            last_read_at,
            cache_counted,
        },
        generation,
    ))
}

/// Puts extent rows in the order of the generation. An arm of a
/// compound statement has no order of its own.
fn in_order(extents: &mut [ReadExtent]) -> Result<()> {
    if extents.iter().any(|e| e.row.seq.is_none()) {
        return Err(bad("extent without a place"));
    }
    extents.sort_by_key(|e| e.row.seq);
    Ok(())
}

/// At most one row of an arm.
fn once<T>(slot: &mut Option<T>, value: T) -> Result<()> {
    match slot.replace(value) {
        None => Ok(()),
        Some(_) => Err(bad("two rows of one kind")),
    }
}

pub(super) async fn read_lookup<S: Sql>(
    c: &SqlCatalog<S>,
    q: &ReadQuery<'_>,
) -> Result<ReadLookup> {
    // An offset past what the database counts in is past the end of any
    // object.
    let cap = |v: u64| SqlValue::Int(i64::try_from(v).unwrap_or(i64::MAX));
    let (from, to, tail, wanted) = match q.window {
        ReadWindow::Nothing => (SqlValue::Int(0), SqlValue::Int(0), 0, 0),
        ReadWindow::Span { start, end } => (cap(start), cap(end), 0, 1),
        ReadWindow::Tail { len } => (cap(len), SqlValue::Int(i64::MAX), 1, 1),
    };
    let rows = c
        .sql
        .query(
            lookup_sql(),
            &[
                text(q.akid),
                text(q.bucket),
                text(q.key),
                from,
                to,
                SqlValue::Int(tail),
                cap(q.max_len),
                SqlValue::Int(wanted),
            ],
        )
        .await?;
    let mut out = ReadLookup::default();
    // The generation each extent row was found through.
    let mut pins = Vec::new();
    for row in rows {
        let (letter, row) = arm(row)?;
        match letter.as_str() {
            "k" => {
                let mut r = Cols::new(row);
                let key = AccessKeyRow {
                    access_key_id: r.text()?,
                    principal: r.text()?,
                    secret_wrapped: r.blob()?,
                    kek_version: r.num()?,
                    status: r.parsed(KeyStatus::parse)?,
                    created_at: r.ms()?,
                };
                once(&mut out.key, key)?;
            }
            "b" => once(&mut out.bucket, bucket_row(row)?)?,
            "p" => {
                let perm = Cols::new(row).parsed(Perm::parse)?;
                once(&mut out.perm, perm)?;
            }
            "g" => once(&mut out.generation, generation_row(row)?)?,
            "e" => {
                // Judged below, once the generation row is there.
                let (extent, through) = read_extent(row)?;
                out.extents.push(extent);
                pins.push(through);
            }
            _ => return Err(bad("unknown row letter")),
        }
    }
    // The statement reads at one moment, so its extents are those of the
    // generation it returned. Checked all the same: extents of another
    // generation would be served as this object.
    let live = out.generation.as_ref().map(|g| &g.id);
    if pins.iter().any(|pin| Some(pin) != live) {
        return Err(bad("extents of another generation"));
    }
    in_order(&mut out.extents)?;
    Ok(out)
}

pub(super) async fn pinned_read<S: Sql>(
    c: &SqlCatalog<S>,
    bucket: &BucketId,
    generation: &GenerationId,
    start: u64,
    end: u64,
) -> Result<Option<PinnedRead>> {
    let rows = c
        .sql
        .query(
            pinned_sql(),
            &[
                text(generation.as_str()),
                text(bucket.as_str()),
                int(start)?,
                int(end)?,
            ],
        )
        .await?;
    let mut found = None;
    let mut extents = Vec::new();
    for row in rows {
        let (letter, mut row) = arm(row)?;
        match letter.as_str() {
            "g" => {
                let bucket = row.split_off(GENERATION_WIDTH);
                once(&mut found, (bucket_row(bucket)?, generation_row(row)?))?;
            }
            "e" => {
                let (extent, through) = read_extent(row)?;
                if through != *generation {
                    return Err(bad("extents of another generation"));
                }
                extents.push(extent);
            }
            _ => return Err(bad("unknown row letter")),
        }
    }
    let Some((bucket, generation)) = found else {
        return Ok(None);
    };
    in_order(&mut extents)?;
    Ok(Some(PinnedRead {
        bucket,
        generation,
        extents,
    }))
}
