//! Provider load and health.
//!
//! A session that ends in a connect, auth or protocol failure is one
//! strike. [`FAILURE_THRESHOLD`] strikes in a row start a cooldown; so
//! does a single strike right after a cooldown, and each cooldown in a row
//! doubles the next up to [`COOLDOWN_MAX_MS`]. One good session clears it
//! all. A row changes on a change of state only, and each write is a single
//! statement guarded by the state it expects: a report that arrives while
//! the provider is cooling changes nothing, so parallel jobs that fail
//! together cannot stack cooldowns.

use super::uploads::{ms, text, Cols};
use super::SqlCatalog;
use crate::ports::{Sql, SqlValue};
use crate::types::{ProviderLoad, Result, UnixMs};

/// Failed sessions in a row that start the first cooldown.
pub const FAILURE_THRESHOLD: u32 = 3;
/// The first cooldown; every further one in a row doubles.
pub const COOLDOWN_BASE_MS: i64 = 60_000;
/// The longest cooldown.
pub const COOLDOWN_MAX_MS: i64 = 900_000;
/// Doublings after which the cooldown no longer grows.
const COOLDOWN_MAX_STEPS: i64 = 4;

pub(super) async fn provider_load<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
) -> Result<Vec<ProviderLoad>> {
    let rows = c
        .sql
        .query(
            "SELECT provider_id, SUM(held), SUM(uses), MAX(failures), MAX(cooldowns), \
               MAX(cooldown_until), COUNT(DISTINCT live_holder), \
               COUNT(DISTINCT live_job) FROM ( \
               SELECT provider_id, lease_until >= ?1 AS held, token AS uses, 0 AS failures, \
                 0 AS cooldowns, 0 AS cooldown_until, \
                 CASE WHEN lease_until >= ?1 THEN holder END AS live_holder, \
                 CASE WHEN lease_until >= ?1 AND background = 1 THEN holder END AS live_job \
                 FROM provider_permits \
               UNION ALL \
               SELECT provider_id, 0, 0, failures, cooldowns, cooldown_until, NULL, NULL \
                 FROM provider_health) \
             GROUP BY provider_id ORDER BY provider_id",
            &[ms(now)],
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        out.push(ProviderLoad {
            provider_id: r.text()?,
            held: r.num()?,
            uses: r.num()?,
            failures: r.num()?,
            cooldowns: r.num()?,
            cooldown_until: UnixMs(r.num()?),
            holders: r.num()?,
            background_holders: r.num()?,
        });
    }
    Ok(out)
}

pub(super) async fn provider_failed<S: Sql>(
    c: &SqlCatalog<S>,
    provider: &str,
    now: UnixMs,
) -> Result<()> {
    // `trip` = this strike starts a cooldown. Right-hand sides read the
    // row as it was before the statement.
    const TRIP: &str = "(failures + 1 >= ?3 OR cooldowns > 0)";
    let update = format!(
        "UPDATE provider_health SET \
           failures = CASE WHEN {TRIP} THEN 0 ELSE failures + 1 END, \
           cooldowns = CASE WHEN {TRIP} THEN MIN(cooldowns + 1, ?6) ELSE cooldowns END, \
           cooldown_until = CASE WHEN {TRIP} THEN ?2 + MIN(?4 << cooldowns, ?5) \
             ELSE cooldown_until END, \
           last_failure_at = ?2 \
         WHERE provider_id = ?1 AND cooldown_until <= ?2"
    );
    c.sql
        .exec(
            "INSERT OR IGNORE INTO provider_health(provider_id) VALUES (?1)",
            &[text(provider)],
        )
        .await?;
    c.sql
        .exec(
            &update,
            &[
                text(provider),
                ms(now),
                SqlValue::Int(i64::from(FAILURE_THRESHOLD)),
                SqlValue::Int(COOLDOWN_BASE_MS),
                SqlValue::Int(COOLDOWN_MAX_MS),
                SqlValue::Int(COOLDOWN_MAX_STEPS),
            ],
        )
        .await?;
    Ok(())
}

pub(super) async fn provider_recovered<S: Sql>(
    c: &SqlCatalog<S>,
    provider: &str,
    now: UnixMs,
) -> Result<()> {
    c.sql
        .exec(
            "UPDATE provider_health SET failures = 0, cooldowns = 0, cooldown_until = 0, \
               last_ok_at = ?2 \
             WHERE provider_id = ?1 AND cooldown_until <= ?2 \
               AND (failures > 0 OR cooldowns > 0)",
            &[text(provider), ms(now)],
        )
        .await?;
    Ok(())
}
