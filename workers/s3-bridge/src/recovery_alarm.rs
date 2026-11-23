//! Best-effort observations only: never a dependency of the copier.
use velmora_bridge::config::Environment;
use velmora_bridge::copy::CopyCounts;
use velmora_bridge::{Sql, SqlValue, UnixMs};
use worker::{console_error, Env};

use crate::d1::D1Sql;

const RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const INSERT: &str = include_str!("recovery_alarm_insert.sql");
const OBSERVE: &str = include_str!("recovery_alarm_observe.sql");
// A pass retains at most 256 diagnostics; the indexed expiry batch can
// remove twice that many. The singleton keeps verified/refused times.
const PRUNE: &str = "DELETE FROM recovery_pass_job WHERE (pass_id, message_id) IN (
    SELECT pass_id, message_id FROM recovery_pass_job WHERE at < ?1 ORDER BY at LIMIT 512
)";

pub fn enabled(env: &Env, environment: Environment) -> bool {
    environment == Environment::Prod
        && !env
            .var("RECOVERY_ALARM")
            .is_ok_and(|v| v.to_string() == "off")
}

pub async fn record(
    env: &Env,
    pass: UnixMs,
    message_id: &str,
    at: UnixMs,
    counts: Option<&CopyCounts>,
) {
    let Ok(db) = env.d1("CATALOG") else {
        console_error!("recovery copy alarm: telemetry database unavailable");
        return;
    };
    let empty = CopyCounts::default();
    let counts = counts.unwrap_or(&empty);
    let int = |n: u64| SqlValue::Int(n as i64);
    let status = |n: Option<u16>| n.map_or(SqlValue::Null, |n| SqlValue::Int(n.into()));
    let text = |s: Option<&str>| s.map_or(SqlValue::Null, |s| SqlValue::Text(s.into()));
    let stamp = |time: Option<UnixMs>| SqlValue::Int(time.map_or(0, |t| t.0));
    let samples = vec![
        SqlValue::Int(pass.0),
        SqlValue::Text(message_id.into()),
        int(counts.copied),
        int(counts.pending),
        int(counts.source_unreadable),
        int(counts.refused_put.count),
        status(counts.refused_put.status),
        text(counts.refused_put.code),
        int(counts.refused_verify.count),
        status(counts.refused_verify.status),
        text(counts.refused_verify.code),
        int(counts.refused_plan.count),
        status(counts.refused_plan.status),
        text(counts.refused_plan.code),
        int(counts.unsignable.count),
        SqlValue::Int(counts.last_verified_write_at.is_some().into()),
        SqlValue::Int(at.0),
    ];
    let events = vec![
        SqlValue::Int(at.0),
        stamp(counts.last_refused_at),
        stamp(counts.last_verified_write_at),
        SqlValue::Int(pass.0),
    ];
    // Watermarks advance even when this is a retry of an existing message
    // or the diagnostic cap was reached. Enqueue success is not required.
    if D1Sql::new(db)
        .batch(vec![(INSERT, samples), (OBSERVE, events)])
        .await
        .is_err()
    {
        console_error!(
            "recovery copy alarm: pass={} telemetry write failed",
            pass.0
        );
    }
}

pub async fn prune(env: &Env, now: UnixMs) {
    let Ok(db) = env.d1("CATALOG") else { return };
    if D1Sql::new(db)
        .exec(PRUNE, &[SqlValue::Int(now.0 - RETENTION_MS)])
        .await
        .is_err()
    {
        console_error!("recovery copy alarm: telemetry pruning failed");
    }
}
