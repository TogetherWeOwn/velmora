//! Best-effort observations only: never a dependency of the copier.
use velmora_bridge::config::Environment;
use velmora_bridge::copy::{cursor_tag, CopyCounts, CopyProgress};
use velmora_bridge::{Sql, SqlValue, UnixMs};
use worker::{console_error, Env};

use crate::d1::D1Sql;

const MAX_SEQUENCE: u16 = 255; // Also enforced by the D1 migration.
const RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

const INSERT: &str = "INSERT OR IGNORE INTO recovery_pass_job (
    pass_id, job_seq, cursor_tag, next_tag, copied, failed, pending, source_unreadable,
    refused_put, put_status, put_code, refused_verify, verify_status, verify_code,
    refused_plan, plan_status, plan_code, unsignable, skipped_sweep, final, at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)";

// At most 256 new rows per pass, so this can drain steady-state expiry
// faster than it grows. Keep just the latest verified copy beyond the
// retention window to retain its age during a prolonged outage.
const PRUNE: &str = "DELETE FROM recovery_pass_job WHERE (pass_id, job_seq) IN (
    SELECT pass_id, job_seq FROM recovery_pass_job
    WHERE at < ?1 AND (pass_id, job_seq) IS NOT (
        SELECT pass_id, job_seq FROM recovery_pass_job WHERE copied > 0 AND at > 0 ORDER BY at DESC LIMIT 1
    ) ORDER BY at LIMIT 512
)";

pub fn enabled(env: &Env, environment: Environment) -> bool {
    environment == Environment::Prod
        && !env
            .var("RECOVERY_ALARM")
            .is_ok_and(|v| v.to_string() == "off")
}

pub fn sequence_for(pass: UnixMs, cursor: &str, sequence: Option<u16>) -> Option<u16> {
    sequence.filter(|&n| pass.0 > 0 && n <= MAX_SEQUENCE && (n == 0) == cursor.is_empty())
}

pub async fn record(
    env: &Env,
    pass: UnixMs,
    job_seq: u16,
    cursor: &str,
    at: UnixMs,
    counts: &CopyCounts,
    progress: CopyProgress,
) {
    let Ok(db) = env.d1("CATALOG") else {
        console_error!("recovery copy alarm: telemetry database unavailable");
        return;
    };
    let int = |n: u64| SqlValue::Int(n as i64);
    let status = |n: Option<u16>| n.map_or(SqlValue::Null, |n| SqlValue::Int(n.into()));
    let text = |s: Option<&str>| s.map_or(SqlValue::Null, |s| SqlValue::Text(s.into()));
    let params = [
        SqlValue::Int(pass.0),
        SqlValue::Int(job_seq.into()),
        SqlValue::Text(cursor_tag(cursor)),
        text(progress.next.as_deref()),
        int(counts.copied),
        int(counts.failed),
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
        SqlValue::Int(progress.skipped_sweep.into()),
        SqlValue::Int(progress.next.is_none().into()),
        SqlValue::Int(at.0),
    ];
    if D1Sql::new(db).exec(INSERT, &params).await.is_err() {
        console_error!(
            "recovery copy alarm: pass={} telemetry write failed",
            pass.0
        );
    }
}

pub async fn prune(env: &Env, now: UnixMs) {
    let Ok(db) = env.d1("CATALOG") else {
        return;
    };
    let params = [SqlValue::Int(now.0 - RETENTION_MS)];
    if D1Sql::new(db).exec(PRUNE, &params).await.is_err() {
        console_error!("recovery copy alarm: telemetry pruning failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_rejects_hints_legacy_messages_and_out_of_range_sequences() {
        assert_eq!(sequence_for(UnixMs(0), "hint", Some(1)), None);
        assert_eq!(sequence_for(UnixMs(1), "", None), None);
        assert_eq!(sequence_for(UnixMs(1), "", Some(0)), Some(0));
        assert_eq!(sequence_for(UnixMs(1), "cursor", Some(255)), Some(255));
        assert_eq!(sequence_for(UnixMs(1), "cursor", Some(256)), None);
        assert_eq!(sequence_for(UnixMs(1), "", Some(1)), None);
    }
}
