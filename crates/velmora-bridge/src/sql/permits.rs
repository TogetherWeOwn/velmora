//! Provider connection permits: fenced D1 slots (catalogue lane B).
//!
//! One row per allowed connection. Acquiring a slot bumps its `token`;
//! renew and release name the slot **and** the token, so a holder whose
//! permit expired and was taken over can neither extend nor free it.

use super::uploads::{ms, text, Cols};
use super::SqlCatalog;
use crate::ports::{Permit, PermitClass, Sql, SqlValue};
use crate::types::{ProviderConfig, Result, UnixMs};

/// Permit lifetime; holders renew before each article.
const PERMIT_TTL_MS: i64 = 120_000;

/// Slots background jobs leave free for cold reads.
fn read_reserve(max_conns: u32) -> u32 {
    u32::from(max_conns >= 2)
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

macro_rules! take_slot {
    ($order:literal) => {
        concat!(
            "UPDATE provider_permits SET token = token + 1, holder = ?2, lease_until = ?3 \
             WHERE provider_id = ?1 AND slot = (SELECT slot FROM provider_permits \
               WHERE provider_id = ?1 AND slot < ?4 AND lease_until < ?5 \
               ORDER BY slot ",
            $order,
            " LIMIT 1) RETURNING slot, token"
        )
    };
}

/// Takes a free or expired slot below the caller's limit: all
/// `max_conns` slots for a read, one fewer for a background job when the
/// provider allows two or more. `None` = no connection may be opened.
pub(super) async fn acquire_permit<S: Sql>(
    c: &SqlCatalog<S>,
    p: &ProviderConfig,
    class: PermitClass,
    holder: &str,
    now: UnixMs,
) -> Result<Option<Permit>> {
    let limit = match class {
        PermitClass::Read => p.max_conns,
        PermitClass::Background => p.max_conns - read_reserve(p.max_conns),
    };
    let params = [
        text(&p.id),
        text(holder),
        ms(now.plus_ms(PERMIT_TTL_MS)),
        SqlValue::Int(i64::from(limit)),
        ms(now),
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
    let mut params = permit_params(p)?;
    params.extend([ms(now.plus_ms(PERMIT_TTL_MS)), ms(now)]);
    let changed = c
        .sql
        .exec(
            "UPDATE provider_permits SET lease_until = ?4 \
             WHERE provider_id = ?1 AND slot = ?2 AND token = ?3 AND lease_until >= ?5",
            &params,
        )
        .await?;
    Ok(changed > 0)
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
