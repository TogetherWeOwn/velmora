//! Read-only hot-tier shape and isolated controller metadata. The eviction
//! predicate and byte expression below match the existing covering index.

use super::uploads::{guarded, text, Cols};
use super::SqlCatalog;
use crate::hotctl::{HIT_KEY, MISS_KEYS, REUSE_HOURS};
use crate::ports::{Guard, Sql, SqlValue, MAX_SQL_PARAMS};
use crate::types::{BridgeError, ExtentId, HotShape, Result, UnixMs};

macro_rules! evictable_bytes {
    () => { "hot_cache_bytes + CASE WHEN safety_state IN ('held', 'releasing') THEN 0 ELSE hot_safety_bytes END" };
}

pub(super) const HOT_SHAPE: &str =
    concat!(
    "SELECT COALESCE(SUM(", evictable_bytes!(), "), 0), ",
    "COALESCE(SUM(CASE WHEN last_read_at IS NULL THEN ", evictable_bytes!(), " ELSE 0 END), 0), ",
    "MIN(last_read_at) FROM extents WHERE ",
    "(hot_cache_bytes > 0 OR (hot_safety_bytes > 0 AND safety_state NOT IN ('held', 'releasing')))"
);

// `first` means no LRU timestamp, not necessarily no previous customer
// GET. Release can seed the existing recency field from creation time.
const GHOST: &str = "INSERT INTO meta(k, v) SELECT CASE \
    WHEN last_read_at IS NULL THEN ?22 \
    WHEN last_read_at >= ?2 THEN ?12 \
    WHEN last_read_at >= ?3 THEN ?13 \
    WHEN last_read_at >= ?4 THEN ?14 \
    WHEN last_read_at >= ?5 THEN ?15 \
    WHEN last_read_at >= ?6 THEN ?16 \
    WHEN last_read_at >= ?7 THEN ?17 \
    WHEN last_read_at >= ?8 THEN ?18 \
    WHEN last_read_at >= ?9 THEN ?19 \
    WHEN last_read_at >= ?10 THEN ?20 \
    WHEN last_read_at >= ?11 THEN ?21 \
    ELSE ?23 END, cipher_size FROM extents WHERE id = ?1 \
    ON CONFLICT(k) DO UPDATE SET v = meta.v + excluded.v";
const COUNTER_ADD: &str = "INSERT INTO meta(k, v) VALUES (?1, ?2) \
    ON CONFLICT(k) DO UPDATE SET v = meta.v + excluded.v";
// An absent row is a valid initial version. Check it inside the same
// transaction as all state writes, including the new version timestamp.
const STORE_GUARD: &str = "INSERT INTO tx_guard(ok) SELECT 0 WHERE \
    (SELECT v FROM meta WHERE k = 'hot_ctl_at') IS DISTINCT FROM ?1";
const STORE: &str = "INSERT INTO meta(k, v) VALUES (?1, ?2) \
    ON CONFLICT(k) DO UPDATE SET v = excluded.v";

pub(super) async fn shape<S: Sql>(c: &SqlCatalog<S>) -> Result<HotShape> {
    let rows = c.sql.query(HOT_SHAPE, &[]).await?;
    let mut row = Cols::new(
        rows.into_iter()
            .next()
            .ok_or(BridgeError::Invalid("missing hot shape"))?,
    );
    Ok(HotShape {
        evictable_bytes: row.num()?,
        never_read_bytes: row.num()?,
        oldest_read_at: row.opt_num()?.map(UnixMs),
    })
}

pub(super) async fn ghost<S: Sql>(c: &SqlCatalog<S>, extent: &ExtentId, now: UnixMs) -> Result<()> {
    let mut bind = vec![text(extent.as_str())];
    bind.extend(REUSE_HOURS.map(|h| SqlValue::Int(now.0.saturating_sub(i64::from(h) * 3_600_000))));
    bind.extend(MISS_KEYS[..REUSE_HOURS.len()].iter().map(|&key| text(key)));
    bind.push(text(MISS_KEYS[crate::hotctl::FIRST]));
    bind.push(text(MISS_KEYS[crate::hotctl::OLDER]));
    c.sql.exec(GHOST, &bind).await?;
    Ok(())
}

pub(super) async fn add<S: Sql>(c: &SqlCatalog<S>, hit_bytes: u64) -> Result<()> {
    if hit_bytes != 0 {
        let bytes =
            i64::try_from(hit_bytes).map_err(|_| BridgeError::Invalid("hot hit counter"))?;
        c.sql
            .exec(COUNTER_ADD, &[text(HIT_KEY), SqlValue::Int(bytes)])
            .await?;
    }
    Ok(())
}

fn state_key(k: &str) -> bool {
    k == "hot_cap_target" || k.starts_with("hot_ctl_")
}

pub(super) async fn load<S: Sql>(c: &SqlCatalog<S>, keys: &[&str]) -> Result<Vec<Option<i64>>> {
    if keys.len() > MAX_SQL_PARAMS
        || keys
            .iter()
            .any(|k| !state_key(k) && *k != HIT_KEY && !MISS_KEYS.contains(k))
    {
        return Err(BridgeError::Invalid("hot controller load keys"));
    }
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    // One snapshot for all counters. IN uses the primary key point lookups.
    let params = keys.iter().map(|&key| text(key)).collect::<Vec<_>>();
    let placeholders = (1..=keys.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!("SELECT k, v FROM meta WHERE k IN ({placeholders})");
    let mut result = vec![None; keys.len()];
    for row in c.sql.query(&sql, &params).await? {
        let mut row = Cols::new(row);
        let key = row.text()?;
        let value = row.num()?;
        for (slot, requested) in result.iter_mut().zip(keys) {
            if key == *requested {
                *slot = Some(value);
            }
        }
    }
    Ok(result)
}

pub(super) async fn store<S: Sql>(
    c: &SqlCatalog<S>,
    expected_at: Option<UnixMs>,
    entries: &[(&str, i64)],
) -> Result<bool> {
    if entries.len() > MAX_SQL_PARAMS || entries.iter().any(|(k, _)| !state_key(k)) {
        return Err(BridgeError::Invalid("hot controller store keys"));
    }
    let expected = expected_at.map_or(SqlValue::Null, |at| SqlValue::Int(at.0));
    let mut stmts = Vec::with_capacity(entries.len() + 1);
    stmts.push((STORE_GUARD, vec![expected]));
    stmts.extend(
        entries
            .iter()
            .map(|&(key, val)| (STORE, vec![text(key), SqlValue::Int(val)])),
    );
    Ok(matches!(guarded(c, stmts).await?, Guard::Applied(())))
}
