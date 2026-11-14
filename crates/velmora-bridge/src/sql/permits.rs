//! Provider connection permits: fenced D1 slots (catalogue lane B).
//!
//! One row per allowed connection. Acquiring a slot bumps its `token`;
//! renew and release name the slot **and** the token, so a holder whose
//! permit expired and was taken over can neither extend nor free it.
//!
//! # Source addresses (`max_ips`)
//!
//! Providers also limit the addresses an account is connected from at
//! once. All connections of one Worker invocation leave from one address,
//! so `holder` names the invocation (one job run, one cold read), and a
//! provider with `max_ips` hands slots to at most that many holders at a
//! time, each of which may take several.
//!
//! There is no holder row. A holder exists on a provider exactly while
//! one of its slots is live there (`lease_until >= now`), so:
//! - it cannot leak: when the last slot is released or expires, the
//!   address is free, with nothing else to clean up;
//! - it cannot come back: a renewal extends a live slot only, so a holder
//!   whose slots all expired has to acquire again, under the limit;
//! - the count and the take are one statement, like the pool count.

use super::uploads::{ms, text, Cols};
use super::SqlCatalog;
use crate::ports::{Permit, PermitClass, Sql, SqlValue, PERMIT_SECS};
use crate::types::{ProviderConfig, Result, UnixMs};

/// Permit lifetime; holders renew on a timer or before each article.
const PERMIT_TTL_MS: i64 = PERMIT_SECS as i64 * 1000;

/// Slots background jobs leave free for cold reads; of `max_ips`, the
/// addresses they leave free.
fn read_reserve(max: u32) -> u32 {
    u32::from(max >= 2)
}

/// Inserts the missing slots `0..max_conns` of each provider. Existing
/// slots, held or free, are left alone.
pub(super) async fn seed_permits<S: Sql>(
    c: &SqlCatalog<S>,
    providers: &[ProviderConfig],
) -> Result<()> {
    for p in providers {
        seed(c, p).await?;
    }
    Ok(())
}

async fn seed<S: Sql>(c: &SqlCatalog<S>, p: &ProviderConfig) -> Result<u64> {
    c.sql
        .exec(
            "INSERT OR IGNORE INTO provider_permits(provider_id, slot) \
             WITH RECURSIVE s(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM s WHERE n + 1 < ?2) \
             SELECT ?1, n FROM s WHERE n < ?2",
            &[text(&p.id), SqlValue::Int(i64::from(p.max_conns))],
        )
        .await
}

// One statement, so the pool count and the take cannot interleave with
// another acquire. `?6` is the pool (NULL = none) and `?7` its limit: the
// slot is taken only while fewer than `?7` slots tagged with the pool are
// held. The tag is written on every acquire, so a held slot always counts
// against the pool it was taken under.
//
// `?8` is the address limit (NULL = none). A holder that has a live slot
// on the provider already takes more without a count: it adds no address.
// Any other holder needs fewer than `?8` holders with a live slot there.
macro_rules! take_slot {
    ($order:literal) => {
        concat!(
            "UPDATE provider_permits SET token = token + 1, holder = ?2, lease_until = ?3, \
               pool = ?6 \
             WHERE provider_id = ?1 AND slot = (SELECT slot FROM provider_permits \
               WHERE provider_id = ?1 AND slot < ?4 AND lease_until < ?5 \
               ORDER BY slot ",
            $order,
            " LIMIT 1) \
               AND (?6 IS NULL OR (SELECT COUNT(*) FROM provider_permits \
                 WHERE pool = ?6 AND lease_until >= ?5) < ?7) \
               AND (?8 IS NULL \
                 OR EXISTS (SELECT 1 FROM provider_permits \
                   WHERE provider_id = ?1 AND holder = ?2 AND lease_until >= ?5) \
                 OR (SELECT COUNT(DISTINCT holder) FROM provider_permits \
                   WHERE provider_id = ?1 AND lease_until >= ?5) < ?8) \
             RETURNING slot, token"
        )
    };
}

/// Takes a free or expired slot below the caller's limit: all
/// `max_conns` slots for a read, one fewer for a background job when the
/// provider allows two or more. A provider in a pool also needs room under
/// `pool_max_conns`, counted over every account of the pool with the same
/// reserve. `None` = no connection may be opened.
///
/// `holder` names the caller's invocation. On a provider with `max_ips`
/// the slot is refused when the holder has none there yet and `max_ips`
/// other holders do (one fewer for a background job when the provider
/// allows two or more): reads may use every address, and a background job
/// starts on a provider only while that leaves one for a read.
pub(super) async fn acquire_permit<S: Sql>(
    c: &SqlCatalog<S>,
    p: &ProviderConfig,
    class: PermitClass,
    holder: &str,
    now: UnixMs,
) -> Result<Option<Permit>> {
    let limit = |max: u32| match class {
        PermitClass::Read => max,
        PermitClass::Background => max - read_reserve(max),
    };
    // The pool keeps a read reserve of its own, like each provider.
    let (pool, pool_limit) = match (&p.pool, p.pool_max_conns) {
        (Some(pool), Some(max)) => (text(pool), limit(max)),
        _ => (SqlValue::Null, 0),
    };
    let ips = match p.max_ips {
        Some(max) => SqlValue::Int(i64::from(limit(max))),
        None => SqlValue::Null,
    };
    let params = [
        text(&p.id),
        text(holder),
        ms(now.plus_ms(PERMIT_TTL_MS)),
        SqlValue::Int(i64::from(limit(p.max_conns))),
        ms(now),
        pool,
        SqlValue::Int(i64::from(pool_limit)),
        ips,
    ];
    // Reads fill from the top, so they use the reserved slot first and
    // leave the shared ones to background jobs.
    let sql = match class {
        PermitClass::Read => take_slot!("DESC"),
        PermitClass::Background => take_slot!("ASC"),
    };
    // A second try only when this call had to create the provider's slots.
    for attempt in 0..2 {
        let rows = c.sql.query(sql, &params).await?;
        if let Some(row) = rows.into_iter().next() {
            let mut r = Cols::new(row);
            return Ok(Some(Permit {
                provider: p.id.clone(),
                slot: r.num()?,
                token: r.num()?,
            }));
        }
        if attempt == 1 || seed(c, p).await? == 0 {
            break;
        }
    }
    Ok(None)
}

fn permit_params(p: &Permit) -> Result<Vec<SqlValue>> {
    Ok(vec![
        text(&p.provider),
        SqlValue::Int(i64::from(p.slot)),
        super::uploads::int(p.token)?,
    ])
}

/// Extends a permit that is still held and not yet expired. `false`: the
/// caller no longer owns a slot and must drop its connection.
pub(super) async fn renew_permit<S: Sql>(
    c: &SqlCatalog<S>,
    p: &Permit,
    now: UnixMs,
) -> Result<bool> {
    let (sql, params) = renew_stmt(p, now)?;
    Ok(c.sql.exec(sql, &params).await? > 0)
}

/// The renewal of one permit as a statement, for batches.
pub(super) fn renew_stmt(p: &Permit, now: UnixMs) -> Result<super::uploads::Stmt> {
    let mut params = permit_params(p)?;
    params.extend([ms(now.plus_ms(PERMIT_TTL_MS)), ms(now)]);
    Ok((
        "UPDATE provider_permits SET lease_until = ?4 \
         WHERE provider_id = ?1 AND slot = ?2 AND token = ?3 AND lease_until >= ?5",
        params,
    ))
}

/// Frees the slot if this permit still owns it; otherwise does nothing.
pub(super) async fn release_permit<S: Sql>(c: &SqlCatalog<S>, p: &Permit) -> Result<()> {
    c.sql
        .exec(
            "UPDATE provider_permits SET lease_until = 0, holder = NULL \
             WHERE provider_id = ?1 AND slot = ?2 AND token = ?3",
            &permit_params(p)?,
        )
        .await?;
    Ok(())
}
