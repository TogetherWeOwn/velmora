//! Hot-tier accounting and eviction (catalogue lane B).
//!
//! R2 holds two kinds of bytes for an extent. *Pinned* bytes are safety
//! copies that are still `held` or `releasing`: not yet proven on enough
//! backbones, or too young. *Evictable* bytes are released safety copies
//! (`hot_safety_bytes`) and cache fills (`hot_cache_bytes`); Usenet holds
//! the data, so R2 may drop them.
//!
//! The totals are recomputed from the rows, never kept as a counter, so
//! they cannot drift from what the rows say and cannot go negative. Both
//! sums run over a partial covering index: the evictable one reads one
//! index entry per evictable extent, a number the cap itself bounds.
//!
//! An eviction is fenced by `extents.evict_seq`:
//! - `begin_evict` is one statement that re-checks that the extent is
//!   still evictable and unchanged since it was listed, and bumps the
//!   sequence. Two jobs cannot both begin, and a pinned extent never
//!   begins.
//! - The job deletes the blobs.
//! - `finish_evict` zeroes the byte counts only if the sequence is still
//!   the one `begin_evict` left. A cache fill in between bumps it, so the
//!   fill stays counted.
//!
//! Whatever the interleaving, a blob that exists is counted. The reverse
//! can happen (counted, already gone); the next eviction of that extent
//! corrects it. Nothing moves an extent back to `held` or `releasing`.

use super::uploads::{int, ms, text, Cols};
use super::SqlCatalog;
use crate::ports::{Sql, SqlValue};
use crate::types::{EvictCandidate, ExtentId, HotStats, Result, UnixMs};

/// True for an extent with bytes that may be evicted. The text matches
/// the `extents_evictable` index.
macro_rules! evictable {
    () => {
        "hot_safety_bytes + hot_cache_bytes > 0 AND safety_state NOT IN ('held', 'releasing')"
    };
}

/// True for an extent whose safety copy is pinned. The text matches the
/// `extents_pinned` index.
macro_rules! pinned {
    () => {
        "safety_state IN ('held', 'releasing')"
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
    "SELECT COALESCE(SUM(hot_safety_bytes + hot_cache_bytes), 0), COUNT(*) \
     FROM extents WHERE ",
    evictable!()
);
const PINNED_TOTAL: &str = concat!(
    "SELECT COALESCE(SUM(cipher_size + hot_cache_bytes), 0), COUNT(*) \
     FROM extents WHERE ",
    pinned!()
);
const CANDIDATES: &str = concat!(
    "SELECT id, hot_safety_bytes, hot_cache_bytes, evict_seq FROM extents WHERE ",
    evictable!(),
    " ORDER BY last_read_at, id LIMIT ?1"
);

/// The periodic statements with the index each must be answered from
/// alone, without touching the table or sorting. Tests hold them to it.
pub const INDEX_ONLY: [(&str, &str); 3] = [
    (EVICTABLE_TOTAL, "extents_evictable"),
    (CANDIDATES, "extents_evictable"),
    (PINNED_TOTAL, "extents_pinned"),
];

/// Evictable bytes and the extents that hold them.
async fn evictable<S: Sql>(c: &SqlCatalog<S>) -> Result<(u64, u64)> {
    total(c, EVICTABLE_TOTAL).await
}

pub(super) async fn evictable_bytes<S: Sql>(c: &SqlCatalog<S>) -> Result<u64> {
    Ok(evictable(c).await?.0)
}

/// Pinned and evictable totals. A cache fill of a pinned extent is not
/// evicted, so it counts as pinned.
pub(super) async fn hot_stats<S: Sql>(c: &SqlCatalog<S>) -> Result<HotStats> {
    let (pinned_bytes, pinned_extents) = total(c, PINNED_TOTAL).await?;
    let (evictable_bytes, evictable_extents) = evictable(c).await?;
    Ok(HotStats {
        pinned_bytes,
        pinned_extents,
        evictable_bytes,
        evictable_extents,
    })
}

/// Evictable extents, least recently read first.
pub(super) async fn evict_candidates<S: Sql>(
    c: &SqlCatalog<S>,
    limit: u32,
) -> Result<Vec<EvictCandidate>> {
    let rows = c
        .sql
        .query(CANDIDATES, &[SqlValue::Int(i64::from(limit))])
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        out.push(EvictCandidate {
            extent: ExtentId::new(r.text()?),
            safety_bytes: r.num()?,
            cache_bytes: r.num()?,
            seq: r.num()?,
        });
    }
    Ok(out)
}

/// Starts an eviction: `true` only if the extent is still evictable and
/// exactly as `x` describes it. One statement, so the check and the claim
/// cannot be separated.
pub(super) async fn begin_evict<S: Sql>(c: &SqlCatalog<S>, x: &EvictCandidate) -> Result<bool> {
    let changed = c
        .sql
        .exec(
            concat!(
                "UPDATE extents SET evict_seq = evict_seq + 1 \
                 WHERE id = ?1 AND evict_seq = ?2 \
                   AND hot_safety_bytes = ?3 AND hot_cache_bytes = ?4 AND ",
                evictable!()
            ),
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

/// After the blobs were deleted: the bytes are no longer counted. `false`
/// if a copy was written since `begin_evict`; the counts then stand.
pub(super) async fn finish_evict<S: Sql>(c: &SqlCatalog<S>, x: &EvictCandidate) -> Result<bool> {
    let changed = c
        .sql
        .exec(
            "UPDATE extents SET hot_safety_bytes = 0, hot_cache_bytes = 0, \
               evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND evict_seq = ?2",
            &[text(x.extent.as_str()), int(x.seq.saturating_add(1))?],
        )
        .await?;
    Ok(changed == 1)
}

/// A cold read wrote the extent's ciphertext to the cache. Called after
/// the write, so an eviction that ran meanwhile cannot zero the count.
pub(super) async fn record_cache_fill<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    now: UnixMs,
) -> Result<()> {
    c.sql
        .exec(
            "UPDATE extents SET hot_cache_bytes = cipher_size, last_read_at = ?2, \
               evict_seq = evict_seq + 1 \
             WHERE id = ?1",
            &[text(extent.as_str()), ms(now)],
        )
        .await?;
    Ok(())
}

/// Stamps a read, unless the last stamp is less than `min_gap_ms` old.
/// Returns the stamp the extent has afterwards, so the caller knows when
/// the next write is due without asking again.
pub(super) async fn touch_read<S: Sql>(
    c: &SqlCatalog<S>,
    extent: &ExtentId,
    now: UnixMs,
    min_gap_ms: i64,
) -> Result<UnixMs> {
    let changed = c
        .sql
        .exec(
            "UPDATE extents SET last_read_at = ?2 \
             WHERE id = ?1 AND (last_read_at IS NULL OR last_read_at <= ?3)",
            &[
                text(extent.as_str()),
                ms(now),
                SqlValue::Int(now.0.saturating_sub(min_gap_ms)),
            ],
        )
        .await?;
    if changed == 1 {
        return Ok(now);
    }
    let rows = c
        .sql
        .query(
            "SELECT last_read_at FROM extents WHERE id = ?1",
            &[text(extent.as_str())],
        )
        .await?;
    let stored = match rows.into_iter().next() {
        Some(row) => Cols::new(row).opt_num()?.map(UnixMs),
        None => None,
    };
    Ok(stored.unwrap_or(now))
}

/// The extent's fencing token now (0 for an unknown extent). Read it
/// before deleting blobs outside an eviction, then pass it to `hot_forget`.
pub(super) async fn hot_seq<S: Sql>(c: &SqlCatalog<S>, extent: &ExtentId) -> Result<u64> {
    let rows = c
        .sql
        .query(
            "SELECT evict_seq FROM extents WHERE id = ?1",
            &[text(extent.as_str())],
        )
        .await?;
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
            "UPDATE extents SET \
               hot_safety_bytes = CASE WHEN ?2 = 1 THEN 0 ELSE hot_safety_bytes END, \
               hot_cache_bytes = CASE WHEN ?3 = 1 THEN 0 ELSE hot_cache_bytes END, \
               evict_seq = evict_seq + 1 \
             WHERE id = ?1 AND evict_seq = ?4",
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
