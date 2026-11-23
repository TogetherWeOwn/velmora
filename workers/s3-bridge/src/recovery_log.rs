//! Short-lived, best-effort telemetry; never a copy checkpoint.
use velmora_bridge::audit::AuditCounts;
use velmora_bridge::copy::{JobReport, StepError};
use velmora_bridge::remote::Problem;
use velmora_bridge::{JobOutcome, Result, Sql, SqlValue, UnixMs};

const INSERT: &str =
    "INSERT INTO recovery_copy_log (at, kind, pass, swept, problems, checked, detail)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
const PRUNE: &str =
    "DELETE FROM recovery_copy_log WHERE kind IN ('job', 'walk', 'audit') AND at < ?1";
const RETENTION_MS: i64 = 7 * 24 * 3_600_000;

pub struct Log {
    pub at: UnixMs,
    pub pass: UnixMs,
    pub destination: Option<String>,
    pub first: Option<Problem>,
}

impl Log {
    pub fn config_refused(pass: UnixMs, at: UnixMs) -> Self {
        Self {
            at,
            pass,
            destination: None,
            first: Some(Problem {
                operation: "config",
                kind: "config_error",
                status: None,
                code: None,
            }),
        }
    }

    async fn insert(
        &self,
        db: &impl Sql,
        kind: &'static str,
        swept: bool,
        problems: u64,
        checked: u64,
        counts: serde_json::Value,
    ) -> Result<()> {
        let first = self.first.map(|p| {
            serde_json::json!({
                "op": p.operation, "kind": p.kind, "status": p.status, "code": p.code,
            })
        });
        let detail = serde_json::json!({ "destination": self.destination, "counts": counts, "first": first });
        db.exec(
            INSERT,
            &[
                SqlValue::Int(self.at.0),
                SqlValue::Text(kind.into()),
                SqlValue::Int(self.pass.0),
                SqlValue::Int(swept.into()),
                SqlValue::Int(problems as i64),
                SqlValue::Int(checked as i64),
                SqlValue::Text(detail.to_string()),
            ],
        )
        .await
        .map(|_| ())
    }

    pub async fn job(&self, db: &impl Sql, report: &JobReport, problems: u64) -> Result<()> {
        if self.pass.0 == 0 {
            return Ok(());
        }
        let checked = report.counts.as_ref().map_or(0, |c| c.records);
        let job = self
            .insert(
                db,
                "job",
                report.swept,
                problems,
                checked,
                serde_json::json!(report.counts),
            )
            .await;
        if report.walk_ended {
            let walk = self
                .insert(db, "walk", false, 0, 0, serde_json::Value::Null)
                .await;
            return job.and(walk);
        }
        job
    }

    pub async fn audit(&self, db: &impl Sql, counts: &AuditCounts) -> Result<()> {
        self.insert(
            db,
            "audit",
            false,
            counts.problems(),
            counts.checked,
            serde_json::json!(counts),
        )
        .await
    }
}

pub fn source_problem(report: &JobReport) -> Option<Problem> {
    (report.error == Some(StepError::Source)).then_some(Problem {
        operation: "source",
        kind: "source_error",
        status: None,
        code: None,
    })
}

pub async fn prune(db: &impl Sql, now: UnixMs) -> Result<()> {
    db.exec(PRUNE, &[SqlValue::Int(now.0 - RETENTION_MS)])
        .await
        .map(|_| ())
}

/// Register best-effort persistence without taking a new queue decision.
pub fn complete_job(outcome: JobOutcome, persist: impl FnOnce()) -> JobOutcome {
    persist();
    outcome
}

#[cfg(test)]
#[path = "recovery_log_checks.rs"]
mod tests;
