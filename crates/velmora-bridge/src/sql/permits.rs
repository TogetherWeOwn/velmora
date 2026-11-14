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
//!
//! Each slot records whether a background job or a read took it. Reads
//! may use every address. Background jobs use one fewer when the
//! provider allows two or more, counted over background holders only: a
//! read in flight does not take an address away from the jobs, and the
//! jobs never take the last one from the reads.
//!
//! Before a slot is taken on such a provider, every slot of it that has
//! expired is freed. A renewal carries the time its caller read before
//! the round trip, so one that arrives late could otherwise extend a
//! slot that had expired by the time another holder was let in, and put
//! a holder too many on the provider. A freed slot cannot be renewed.
//!
//! # Lifetimes
//!
//! A slot lives as long as its class says ([`PermitClass::permit_secs`]),
//! from the acquire and from every renewal: a background job's
//! [`PERMIT_SECS`](crate::ports::PERMIT_SECS), a read's much shorter
//! [`READ_PERMIT_SECS`](crate::ports::READ_PERMIT_SECS). The renewal
//! takes the class from the row.
//!
//! A holder that goes away without releasing keeps its slots and its
//! address until they expire. A crashed job is one case. A cold read
//! whose client hung up is the other: the first piece of a response is
//! read while the request is kept alive, so it finishes and releases,
//! but the later pieces are read as the body is pulled, and their
//! future is dropped where it waits and cannot release. That is why a
//! read's slot is short-lived: on a provider with one address a dropped
//! read keeps every other caller out for that long and no longer.

use super::uploads::{ms, text, Cols};
use super::SqlCatalog;
use crate::ports::{Permit, PermitClass, Sql, SqlValue};
use crate::types::{ProviderConfig, Result, UnixMs};

/// Permit lifetime of a class; holders renew on a timer or before each
/// call to the provider.
const fn ttl_ms(class: PermitClass) -> i64 {
    class.permit_secs() as i64 * 1000
}

/// Slots of a pool that background jobs leave free for cold reads.
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
// Any other holder needs fewer than `?8` holders with a live slot there,
// and a background job (`?9` = 1) also fewer than `?10` background
// holders. `?9` is written on the slot.
macro_rules! take_slot {
    ($order:literal) => {
        concat!(
            "UPDATE provider_permits SET token = token + 1, holder = ?2, lease_until = ?3, \
               pool = ?6, background = ?9 \
             WHERE provider_id = ?1 AND slot = (SELECT slot FROM provider_permits \
               WHERE provider_id = ?1 AND slot < ?4 AND lease_until < ?5 \
               ORDER BY slot ",
            $order,
            " LIMIT 1) \
               AND (?6 IS NULL OR (SELECT COUNT(*) FROM provider_permits \
                 WHERE pool = ?6 AND lease_until >= ?5) < ?7) \
               AND (?8 IS NULL \
                 OR ((EXISTS (SELECT 1 FROM provider_permits \
                       WHERE provider_id = ?1 AND holder = ?2 AND lease_until >= ?5) \
                     OR (SELECT COUNT(DISTINCT holder) FROM provider_permits \
                       WHERE provider_id = ?1 AND lease_until >= ?5) < ?8) \
                   AND (?9 = 0 \
                     OR EXISTS (SELECT 1 FROM provider_permits \
                       WHERE provider_id = ?1 AND holder = ?2 AND lease_until >= ?5 \
                         AND background = 1) \
                     OR (SELECT COUNT(DISTINCT holder) FROM provider_permits \
                       WHERE provider_id = ?1 AND lease_until >= ?5 AND background = 1) < ?10))) \
             RETURNING slot, token"
        )
    };
}

/// Takes a free or expired slot below the caller's limit: all
/// `max_conns` slots for a read, and for a background job
/// [`ProviderConfig::background_conns`]. A provider in a pool also needs
/// room under `pool_max_conns`, counted over every account of the pool
/// with a reserve of its own. `None` = no connection may be opened.
///
/// `holder` names the caller's invocation. On a provider with `max_ips`
/// a holder that has no live slot there yet is refused while `max_ips`
/// holders do. A background job that has no live background slot there
/// yet is also refused while [`ProviderConfig::background_ips`] holders
/// have one.
pub(super) async fn acquire_permit<S: Sql>(
    c: &SqlCatalog<S>,
    p: &ProviderConfig,
    class: PermitClass,
    holder: &str,
    now: UnixMs,
) -> Result<Option<Permit>> {
    let background = class == PermitClass::Background;
    let conns = match class {
        PermitClass::Read => p.max_conns,
        PermitClass::Background => p.background_conns(),
    };
    // The pool keeps a read reserve of its own, like each provider.
    let (pool, pool_limit) = match (&p.pool, p.pool_max_conns) {
        (Some(pool), Some(max)) if background => (text(pool), max - read_reserve(max)),
        (Some(pool), Some(max)) => (text(pool), max),
        _ => (SqlValue::Null, 0),
    };
    let opt = |n: Option<u32>| n.map_or(SqlValue::Null, |n| SqlValue::Int(i64::from(n)));
    if p.max_ips.is_some() {
        free_expired(c, p, now).await?;
    }
    let params = [
        text(&p.id),
        text(holder),
        ms(now.plus_ms(ttl_ms(class))),
        SqlValue::Int(i64::from(conns)),
        ms(now),
        pool,
        SqlValue::Int(i64::from(pool_limit)),
        opt(p.max_ips),
        SqlValue::Int(i64::from(background)),
        opt(p.background_ips()),
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
                class,
            }));
        }
        if attempt == 1 || seed(c, p).await? == 0 {
            break;
        }
    }
    Ok(None)
}

/// Frees every slot of `p` that expired before `now`, so that no late
/// renewal can extend it (see the module docs). Free slots are not
/// written again.
async fn free_expired<S: Sql>(c: &SqlCatalog<S>, p: &ProviderConfig, now: UnixMs) -> Result<()> {
    c.sql
        .exec(
            "UPDATE provider_permits SET lease_until = 0, holder = NULL \
             WHERE provider_id = ?1 AND lease_until > 0 AND lease_until < ?2",
            &[text(&p.id), ms(now)],
        )
        .await?;
    Ok(())
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

/// The renewal of one permit as a statement, for batches. The slot is
/// extended by the lifetime of the class it was taken for, which the row
/// records: a read cannot renew itself into the long lifetime of a job.
pub(super) fn renew_stmt(p: &Permit, now: UnixMs) -> Result<super::uploads::Stmt> {
    let mut params = permit_params(p)?;
    params.extend([
        SqlValue::Int(ttl_ms(PermitClass::Background)),
        ms(now),
        SqlValue::Int(ttl_ms(PermitClass::Read)),
    ]);
    Ok((
        "UPDATE provider_permits \
         SET lease_until = ?5 + CASE background WHEN 1 THEN ?4 ELSE ?6 END \
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
