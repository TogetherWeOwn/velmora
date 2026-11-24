//! Hot-tier accounting and eviction (catalogue lane B).
//!
//! R2 holds two kinds of copy of an extent:
//! - the safety copy (`x/`). While the extent is `held` or `releasing` it
//!   is *pinned*: not yet proven on enough backbones, or too young. Once
//!   released it is evictable, and `hot_safety_bytes` counts it.
//! - the cache fill (`c/`), counted by `hot_cache_bytes`. It only ever
//!   comes from a verified read from Usenet, so it is evictable whatever
//!   the state of the safety copy.
//!
//! The totals are recomputed from the rows, never kept as a counter, so
//! they cannot drift from what the rows say and cannot go negative. The
//! sums run over partial covering indexes.
//!
//! An eviction is fenced by `extents.evict_seq`:
//! - `begin_evict` is one statement that re-checks the extent (pinned or
//!   not, byte counts, sequence) against the listing and bumps the
//!   sequence. Two jobs cannot both begin, and the safety copy of a
//!   pinned extent is never part of an eviction.
//! - The job deletes the blobs.
//! - `finish_evict` zeroes the byte counts only if the sequence is still
//!   the one `begin_evict` left. A cache fill in between bumps it, so the
//!   fill stays counted.
//!
//! Every statement that changes `safety_state` bumps the sequence too, so
//! a listing never survives a state change.
//!
//! The counts are not exact, and they are not a bound in either
//! direction. Each error is limited to one extent's bytes and repairs
//! itself:
//! - counted but already gone (a delete raced a fill, the bucket's
//!   lifecycle rule expired the blob, or a read that was served from the
//!   cache blob counted it with `touch_read` after an eviction of the
//!   same extent had finished and deleted it): the next eviction of the
//!   extent zeroes the count;
//! - a cache blob that exists but is not counted (written before these
//!   columns existed, or by a request that was cancelled between its
//!   write and its second count while an eviction or a garbage
//!   collection of the same extent ran): a read served from it
//!   counts it again (`touch_read`; an isolate asks at most once an hour
//!   per extent), and an eviction of the extent deletes
//!   both keys whatever the counts say. One that is never read again and
//!   never evicted is left to the cache bucket's lifecycle rule.

use super::uploads::{int, ms, text, Cols};
use super::SqlCatalog;
use crate::ports::{Sql, SqlValue};
use crate::types::{EvictCandidate, ExtentId, HotStats, Result, UnixMs};

/// True for an extent whose safety copy is pinned. The text matches the
/// `extents_safety` index.
macro_rules! pinned {
    () => {
        "safety_state IN ('held', 'releasing')"
    };
}

/// True for an extent with bytes that may be evicted. The text matches
/// the `extents_evictable` index.
macro_rules! evictable {
    () => {
        "(hot_cache_bytes > 0 \
          OR (hot_safety_bytes > 0 AND safety_state NOT IN ('held', 'releasing')))"
    };
}

/// The evictable bytes of one row: the cache fill, and the safety copy
/// unless it is pinned.
macro_rules! evictable_bytes {
    () => {
        "hot_cache_bytes + CASE WHEN safety_state IN ('held', 'releasing') \
                                THEN 0 ELSE hot_safety_bytes END"
    };
}

async fn total<S: Sql>(c: &SqlCatalog<S>, sql: &str) -> Result<(u64, u64)> {
    let rows = c.sql.query(sql, &[]).await?;
    match rows.into_iter().next() {
        Some(row) => {
            let mut r = Cols::new(row);
            Ok((r.num()?, r.num()?))
        }
        None => Ok((0, 0)),
    }
}

const EVICTABLE_TOTAL: &str = concat!(
    "SELECT COALESCE(SUM(",
    evictable_bytes!(),
    "), 0), COUNT(*) FROM extents WHERE ",
    evictable!()
);
const PINNED_TOTAL: &str = concat!(
    "SELECT COALESCE(SUM(cipher_size), 0), COUNT(*) FROM extents WHERE ",
    pinned!()
);
const CANDIDATES: &str = concat!(
    "SELECT id, hot_safety_bytes, hot_cache_bytes, evict_seq, ",
    pinned!(),
    " FROM extents WHERE ",
    evictable!(),
    " ORDER BY last_read_at, id LIMIT ?1"
);

/// The periodic statements with the index each must be answered from
/// alone, without touching the table or sorting. Tests hold them to it.
pub const INDEX_ONLY: [(&str, &str); 3] = [
    (EVICTABLE_TOTAL, "extents_evictable"),
    (CANDIDATES, "extents_evictable"),
    (PINNED_TOTAL, "extents_safety"),
];

/// Evictable bytes and the extents that hold them.
async fn evictable<S: Sql>(c: &SqlCatalog<S>) -> Result<(u64, u64)> {
    total(c, EVICTABLE_TOTAL).await
}

pub(super) async fn evictable_bytes<S: Sql>(c: &SqlCatalog<S>) -> Result<u64> {
    Ok(evictable(c).await?.0)
}

/// Pinned and evictable totals. Pinned bytes are safety copies only: a
/// cache fill is evictable even while the extent's safety copy is pinned.
pub(super) async fn hot_stats<S: Sql>(c: &SqlCatalog<S>) -> Result<HotStats> {
    // Pinned totals from the usage counters once they are switched on:
    // one row read instead of every pinned extent. The evictable total
    // stays a read of its partial index, which holds only what the hot
    // tier holds and is bounded by the tier's cap, not by the catalogue.
    let usage = super::usage::counters(c).await?;
    let (pinned_bytes, pinned_extents) = if usage.seeded {
        (
            u64::try_from(usage.unreleased_bytes).unwrap_or(0),
            u64::try_from(usage.extents_unreleased).unwrap_or(0),
        )
    } else {
        total(c, PINNED_TOTAL).await?
    };
    let (evictable_bytes, evictable_extents) = evictable(c).await?;
    Ok(HotStats {
        pinned_bytes,
        pinned_extents,
        evictable_bytes,
        evictable_extents,
    })
}

/// Extents with evictable bytes, least recently read first.
pub(super) async fn evict_candidates<S: Sql>(
    c: &SqlCatalog<S>,
    limit: u32,
) -> Result<Vec<EvictCandidate>> {
    let rows = c
        .sql
        .query(
            c.sql.dialect().pick(CANDIDATES, CANDIDATES_PG),
            &[SqlValue::Int(i64::from(limit))],
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        out.push(EvictCandidate {
            extent: ExtentId::new(r.text()?),
            safety_bytes: r.num()?,
            cache_bytes: r.num()?,
            seq: r.num()?,
            pinned: r.num::<i64>()? != 0,
        });
    }
    Ok(out)
}

/// Starts an eviction: `true` only if the extent is exactly as `x`
/// describes it. One statement, so the check and the claim cannot be
/// separated.
///
/// - `x.pinned == false` claims both copies and requires that the safety
///   copy is not pinned now.
/// - `x.pinned == true` claims the cache fill only and requires a counted
///   one. The caller must not touch the safety copy.
pub(super) async fn begin_evict<S: Sql>(c: &SqlCatalog<S>, x: &EvictCandidate) -> Result<bool> {
    let sql = if x.pinned {
        BEGIN_EVICT_PINNED
    } else {
        BEGIN_EVICT_UNPINNED
    };
    let changed = c
        .sql
        .exec(
            sql,
            &[
                text(x.extent.as_str()),
                int(x.seq)?,
                int(x.safety_bytes)?,
                int(x.cache_bytes)?,
            ],
        )
        .await?;
    Ok(changed == 1)
}

/// Ends an eviction after the blobs are deleted: the claimed copies are
/// no longer counted. `false` when a hot copy was recorded since
/// `begin_evict`; the counts then stand.
pub(super) async fn finish_evict<S: Sql>(c: &SqlCatalog<S>, x: &EvictCandidate) -> Result<bool> {
    let sql = if x.pinned {
        FINISH_EVICT_PINNED
    } else {
        FINISH_EVICT_UNPINNED
    };
    let changed = c
        .sql
        .exec(
            sql,
            &[text(x.extent.as_str()), int(x.seq.saturating_add(1))?],
        )
        .await?;
    Ok(changed == 1)
}

/// Counts the extent's cache fill and stamps the read that caused it.
/// Called before the write (so that a request cancelled right after the
/// write leaves a counted blob) and again after it (so that an eviction
/// that ran in between does not leave it uncounted).
pub(super) async fn record_cache_fill<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    now: UnixMs,
) -> Result<()> {
    c.sql
        .exec(RECORD_CACHE_FILL, &[text(extent.as_str()), ms(now)])
        .await?;
    Ok(())
}

/// Stamps a read, unless the last stamp is less than `min_gap_ms` old.
/// Returns the stamp the extent has afterwards, so the caller knows when
/// the next write is due without asking again.
///
/// With `from_cache` the read was served from the cache fill, so one
/// exists: the same write counts it if it was not counted, and an
/// uncounted one is counted whatever the age of the stamp.
pub(super) async fn touch_read<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    now: UnixMs,
    min_gap_ms: i64,
    from_cache: bool,
) -> Result<UnixMs> {
    let changed = c
        .sql
        .exec(
            TOUCH_READ,
            &[
                text(extent.as_str()),
                ms(now),
                SqlValue::Int(now.0.saturating_sub(min_gap_ms)),
                SqlValue::Int(i64::from(from_cache)),
            ],
        )
        .await?;
    if changed == 1 {
        return Ok(now);
    }
    let rows = c.sql.query(LAST_READ_AT, &[text(extent.as_str())]).await?;
    let stored = match rows.into_iter().next() {
        Some(row) => Cols::new(row).opt_num()?.map(UnixMs),
        None => None,
    };
    Ok(stored.unwrap_or(now))
}

/// Whether the dispatcher's periodic total is due: none was taken in the
/// last `every_ms`.
pub(super) async fn hot_check_due<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
    every_ms: i64,
) -> Result<bool> {
    let rows = c
        .sql
        .query(
            RECENT_SWEEP,
            &[SqlValue::Int(now.0.saturating_sub(every_ms)), ms(now)],
        )
        .await?;
    Ok(rows.is_empty())
}

/// Records that the periodic total was taken at `now`.
pub(super) async fn hot_checked<S: Sql>(c: &SqlCatalog<S>, now: UnixMs) -> Result<()> {
    c.sql
        .exec(
            c.sql.dialect().pick(RECORD_HOT_SWEEP, RECORD_HOT_SWEEP_PG),
            &[ms(now)],
        )
        .await?;
    Ok(())
}

/// Records what a drain step leaves for the next one.
pub(super) async fn hot_drain_set<S: Sql>(c: &SqlCatalog<S>, left: u64) -> Result<()> {
    c.sql
        .exec(
            c.sql.dialect().pick(SET_HOT_DRAIN, SET_HOT_DRAIN_PG),
            &[int(left)?],
        )
        .await?;
    Ok(())
}

/// Takes up the drain where the last step left it. One statement, so
/// only one delivery of the job that carries `left` gets `true`.
pub(super) async fn hot_drain_claim<S: Sql>(c: &SqlCatalog<S>, left: u64) -> Result<bool> {
    if left == 0 {
        return Ok(false);
    }
    let changed = c.sql.exec(CLEAR_DRAIN, &[int(left)?]).await?;
    Ok(changed == 1)
}

/// The extent's fencing token now (0 for an unknown extent). Read it
/// before deleting blobs outside an eviction, then pass it to `hot_forget`.
pub(super) async fn hot_seq<S: Sql>(c: &SqlCatalog<S>, extent: &ExtentId) -> Result<u64> {
    let rows = c.sql.query(EVICTION_SEQ, &[text(extent.as_str())]).await?;
    match rows.into_iter().next() {
        Some(row) => Cols::new(row).num(),
        None => Ok(0),
    }
}

/// Blobs were deleted outside an eviction (admin evict): stop counting
/// them, and fence any eviction in flight. `seq` is `hot_seq` from before
/// the deletes: if a cold read recorded a fill (or an eviction ran) since
/// then, the counts stand, because the copy they count may exist. `false`
/// then.
pub(super) async fn hot_forget<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    seq: u64,
    safety: bool,
    cache: bool,
) -> Result<bool> {
    let changed = c
        .sql
        .exec(
            CLEAR_HOT_IF_SEQ,
            &[
                text(extent.as_str()),
                SqlValue::Int(i64::from(safety)),
                SqlValue::Int(i64::from(cache)),
                int(seq)?,
            ],
        )
        .await?;
    Ok(changed == 1)
}

const CANDIDATES_PG: &str = concat!(
    "SELECT id, hot_safety_bytes, hot_cache_bytes, evict_seq, ",
    pinned!(),
    " FROM extents WHERE ",
    evictable!(),
    " ORDER BY last_read_at ASC NULLS FIRST, id LIMIT ?1"
);

const BEGIN_EVICT_PINNED: &str = concat!(
    "UPDATE extents SET evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND evict_seq = ?2 \
               AND hot_safety_bytes = ?3 AND hot_cache_bytes = ?4 \
               AND hot_cache_bytes > 0 AND ",
    pinned!()
);

const BEGIN_EVICT_UNPINNED: &str = concat!(
    "UPDATE extents SET evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND evict_seq = ?2 \
               AND hot_safety_bytes = ?3 AND hot_cache_bytes = ?4 \
               AND NOT ",
    pinned!(),
    " AND ",
    evictable!()
);

const FINISH_EVICT_PINNED: &str =
    "UPDATE extents SET hot_cache_bytes = 0, evict_seq = evict_seq + 1 \
         WHERE id = ?1 AND evict_seq = ?2";

const FINISH_EVICT_UNPINNED: &str =
    "UPDATE extents SET hot_safety_bytes = 0, hot_cache_bytes = 0, \
           evict_seq = evict_seq + 1 \
         WHERE id = ?1 AND evict_seq = ?2";

const RECORD_CACHE_FILL: &str =
    "UPDATE extents SET hot_cache_bytes = cipher_size, last_read_at = ?2, \
               evict_seq = evict_seq + 1 \
             WHERE id = ?1";

const TOUCH_READ: &str = "UPDATE extents SET last_read_at = ?2, \
               evict_seq = evict_seq + \
                 CASE WHEN ?4 = 1 AND hot_cache_bytes = 0 THEN 1 ELSE 0 END, \
               hot_cache_bytes = CASE WHEN ?4 = 1 THEN cipher_size ELSE hot_cache_bytes END \
             WHERE id = ?1 AND (last_read_at IS NULL OR last_read_at <= ?3 \
                                OR (?4 = 1 AND hot_cache_bytes = 0))";

const LAST_READ_AT: &str = "SELECT last_read_at FROM extents WHERE id = ?1";

const RECENT_SWEEP: &str = "SELECT 1 FROM meta WHERE k = 'hot_checked_at' AND v > ?1 AND v <= ?2";

const CLEAR_DRAIN: &str = "UPDATE meta SET v = 0 WHERE k = 'hot_drain_left' AND v = ?1";

const EVICTION_SEQ: &str = "SELECT evict_seq FROM extents WHERE id = ?1";

const CLEAR_HOT_IF_SEQ: &str = "UPDATE extents SET \
               hot_safety_bytes = CASE WHEN ?2 = 1 THEN 0 ELSE hot_safety_bytes END, \
               hot_cache_bytes = CASE WHEN ?3 = 1 THEN 0 ELSE hot_cache_bytes END, \
               evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND evict_seq = ?4";

const RECORD_HOT_SWEEP: &str = "INSERT OR REPLACE INTO meta(k, v) VALUES ('hot_checked_at', ?1)";

const RECORD_HOT_SWEEP_PG: &str = "INSERT INTO meta(k, v) VALUES ('hot_checked_at', ?1) ON CONFLICT (k) DO UPDATE SET v = excluded.v";

const SET_HOT_DRAIN: &str = "INSERT OR REPLACE INTO meta(k, v) VALUES ('hot_drain_left', ?1)";

const SET_HOT_DRAIN_PG: &str = "INSERT INTO meta(k, v) VALUES ('hot_drain_left', ?1) ON CONFLICT (k) DO UPDATE SET v = excluded.v";

/// Actual Postgres texts and representative wire types for typed PREPARE.
#[cfg(all(feature = "pg-test-record", not(target_arch = "wasm32")))]
pub(super) fn pg_statements() -> Vec<(String, Vec<SqlValue>)> {
    const I: SqlValue = SqlValue::Int(0);
    const T: SqlValue = SqlValue::Text(String::new());
    vec![
        (EVICTABLE_TOTAL.to_owned(), vec![]),
        (PINNED_TOTAL.to_owned(), vec![]),
        (CANDIDATES_PG.to_owned(), vec![I]),
        (BEGIN_EVICT_PINNED.to_owned(), vec![T, I, I, I]),
        (BEGIN_EVICT_UNPINNED.to_owned(), vec![T, I, I, I]),
        (FINISH_EVICT_PINNED.to_owned(), vec![T, I]),
        (FINISH_EVICT_UNPINNED.to_owned(), vec![T, I]),
        (RECORD_CACHE_FILL.to_owned(), vec![T, I]),
        (TOUCH_READ.to_owned(), vec![T, I, I, I]),
        (LAST_READ_AT.to_owned(), vec![T]),
        (RECENT_SWEEP.to_owned(), vec![I, I]),
        (CLEAR_DRAIN.to_owned(), vec![I]),
        (EVICTION_SEQ.to_owned(), vec![T]),
        (CLEAR_HOT_IF_SEQ.to_owned(), vec![T, I, I, I]),
        (RECORD_HOT_SWEEP_PG.to_owned(), vec![I]),
        (SET_HOT_DRAIN_PG.to_owned(), vec![I]),
    ]
}
