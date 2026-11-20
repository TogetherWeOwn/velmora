//! Provider load and health.
//!
//! A session that ends in a connect, auth or protocol failure is one
//! strike. [`FAILURE_THRESHOLD`] strikes in a row start a cooldown; so
//! does a single strike right after a cooldown, and each cooldown in a row
//! doubles the next up to [`COOLDOWN_MAX_MS`], or up to
//! [`LOGIN_REFUSED_COOLDOWN_MAX_MS`] when the strike is a refused login.
//! One good session clears it all; a provider that nothing picks gets
//! such a session from the cron run's probe ([`crate::probe`]), so its
//! strikes do not stay for good. Each strike is stored with why it was one, as a code
//! ([`ProviderFault`]); the good session clears that too. A row changes
//! on a change of state only, and each write is a single statement
//! guarded by the state it expects: a report that arrives while the
//! provider is cooling changes nothing, so parallel jobs that fail
//! together cannot stack cooldowns.

use super::uploads::{ms, text, Cols};
use super::SqlCatalog;
use crate::ports::{Sql, SqlValue};
use crate::types::{ProviderFault, ProviderLoad, Result, UnixMs};

/// Failed sessions in a row that start the first cooldown.
pub const FAILURE_THRESHOLD: u32 = 3;
/// The first cooldown; every further one in a row doubles.
pub const COOLDOWN_BASE_MS: i64 = 60_000;
/// The longest cooldown.
pub const COOLDOWN_MAX_MS: i64 = 900_000;
/// Doublings after which the cooldown no longer grows.
const COOLDOWN_MAX_STEPS: i64 = 4;
/// The longest cooldown after a refused login
/// ([`ProviderFault::LoginRefused`]). An account that is suspended or out
/// of quota stays so for hours or for good, and every probe of it is one
/// more refused login on the provider's record: a handful a day.
pub const LOGIN_REFUSED_COOLDOWN_MAX_MS: i64 = 6 * 3_600_000;
/// Doublings after which that cooldown no longer grows.
const LOGIN_REFUSED_COOLDOWN_MAX_STEPS: i64 = 9;
const _: () = assert!(COOLDOWN_BASE_MS << COOLDOWN_MAX_STEPS >= COOLDOWN_MAX_MS);
const _: () =
    assert!(COOLDOWN_BASE_MS << LOGIN_REFUSED_COOLDOWN_MAX_STEPS >= LOGIN_REFUSED_COOLDOWN_MAX_MS);

/// The longest cooldown a strike for `fault` can start, and the
/// doublings it takes to get there.
pub(crate) fn cooldown_cap(fault: ProviderFault) -> (i64, i64) {
    match fault {
        ProviderFault::LoginRefused => (
            LOGIN_REFUSED_COOLDOWN_MAX_MS,
            LOGIN_REFUSED_COOLDOWN_MAX_STEPS,
        ),
        ProviderFault::ConnectRefused
        | ProviderFault::SessionFailed
        | ProviderFault::ProxyFailed => (COOLDOWN_MAX_MS, COOLDOWN_MAX_STEPS),
    }
}

pub(super) async fn provider_load<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
) -> Result<Vec<ProviderLoad>> {
    let rows = c
        .sql
        .query(
            "SELECT provider_id, SUM(held), SUM(uses), MAX(failures), MAX(cooldowns), \
               MAX(cooldown_until), COUNT(DISTINCT live_holder), \
               COUNT(DISTINCT live_job), MAX(reason) FROM ( \
               SELECT provider_id, lease_until >= ?1 AS held, token AS uses, 0 AS failures, \
                 0 AS cooldowns, 0 AS cooldown_until, \
                 CASE WHEN lease_until >= ?1 THEN holder END AS live_holder, \
                 CASE WHEN lease_until >= ?1 AND background = 1 THEN holder END AS live_job, \
                 NULL AS reason \
                 FROM provider_permits \
               UNION ALL \
               SELECT provider_id, 0, 0, failures, cooldowns, cooldown_until, NULL, NULL, \
                 last_failure_reason \
                 FROM provider_health) \
             GROUP BY provider_id ORDER BY provider_id",
            &[ms(now)],
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut r = Cols::new(row);
        let mut load = ProviderLoad {
            provider_id: r.text()?,
            held: r.num()?,
            uses: r.num()?,
            failures: r.num()?,
            cooldowns: r.num()?,
            cooldown_until: UnixMs(r.num()?),
            holders: r.num()?,
            background_holders: r.num()?,
            // A code this version does not know reads as no reason.
            fault: r.opt_text()?.as_deref().and_then(ProviderFault::parse),
        };
        // No strike on record, no reason: a version from before the
        // column clears the strikes and leaves the reason behind.
        if load.healthy() {
            load.fault = None;
        }
        out.push(load);
    }
    Ok(out)
}

pub(super) async fn provider_failed<S: Sql>(
    c: &SqlCatalog<S>,
    provider: &str,
    fault: ProviderFault,
    now: UnixMs,
) -> Result<()> {
    // `trip` = this strike starts a cooldown. Right-hand sides read the
    // row as it was before the statement. The count of cooldowns in a
    // row may come from a longer cap than this strike's: `MIN` holds
    // both the count and the time to this one's.
    let (max_ms, max_steps) = cooldown_cap(fault);
    const TRIP: &str = "(failures + 1 >= ?3 OR cooldowns > 0)";
    let update = format!(
        "UPDATE provider_health SET \
           failures = CASE WHEN {TRIP} THEN 0 ELSE failures + 1 END, \
           cooldowns = CASE WHEN {TRIP} THEN MIN(cooldowns + 1, ?6) ELSE cooldowns END, \
           cooldown_until = CASE WHEN {TRIP} THEN ?2 + MIN(?4 << cooldowns, ?5) \
             ELSE cooldown_until END, \
           last_failure_at = ?2, last_failure_reason = ?7 \
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
                SqlValue::Int(max_ms),
                SqlValue::Int(max_steps),
                text(fault.as_str()),
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
               last_ok_at = ?2, last_failure_reason = NULL \
             WHERE provider_id = ?1 AND cooldown_until <= ?2 \
               AND (failures > 0 OR cooldowns > 0)",
            &[text(provider), ms(now)],
        )
        .await?;
    Ok(())
}

pub(super) async fn providers_to_probe<S: Sql>(
    c: &SqlCatalog<S>,
    now: UnixMs,
    quiet_since: UnixMs,
    login_quiet_since: UnixMs,
) -> Result<Vec<String>> {
    // One row per provider that ever failed, read whole: a handful.
    // Quiet counts from the later of the last strike and the end of the
    // last cooldown: a probe never answers for real work right after a
    // cooldown, and so never clears a ladder of cooldowns real work built.
    let rows = c
        .sql
        .query(
            "SELECT provider_id FROM provider_health \
             WHERE (failures > 0 OR cooldowns > 0) AND cooldown_until <= ?1 \
               AND MAX(COALESCE(last_failure_at, 0), cooldown_until) <= CASE \
                 WHEN last_failure_reason = ?4 THEN ?3 ELSE ?2 END \
             ORDER BY provider_id",
            &[
                ms(now),
                ms(quiet_since),
                ms(login_quiet_since),
                text(ProviderFault::LoginRefused.as_str()),
            ],
        )
        .await?;
    rows.into_iter().map(|row| Cols::new(row).text()).collect()
}
