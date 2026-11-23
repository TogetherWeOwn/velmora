//! Best-effort observations only: never a dependency of the copier.
use velmora_bridge::config::Environment;
use velmora_bridge::copy::JobObservation;
use velmora_bridge::{Sql, SqlValue, UnixMs};
use worker::{console_error, Env};

use crate::d1::D1Sql;
use crate::e2::FetchHttp;

const RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const INSERT: &str = include_str!("recovery_alarm_insert.sql");
const OBSERVE: &str = include_str!("recovery_alarm_observe.sql");
const FRONTIER: &str = include_str!("recovery_alarm_frontier.sql");
const CLEAN: &str = include_str!("recovery_alarm_clean.sql");
// A pass retains at most 256 diagnostics; expiry removes twice as many.
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
    observation: JobObservation,
    transport: &FetchHttp,
) {
    let Ok(db) = env.d1("CATALOG") else {
        console_error!("recovery copy alarm: telemetry database unavailable");
        return;
    };
    let counts = observation.counts.unwrap_or_default();
    let int = |n: u64| SqlValue::Int(n as i64);
    let status = |n: Option<u16>| n.map_or(SqlValue::Null, |n| SqlValue::Int(n.into()));
    let text = |s: Option<&str>| s.map_or(SqlValue::Null, |s| SqlValue::Text(s.into()));
    let stamp = |time: Option<UnixMs>| SqlValue::Int(time.map_or(0, |t| t.0));
    let mark = |yes: bool| SqlValue::Int(yes.into());
    let message = || SqlValue::Text(message_id.into());
    let verified = transport.last_verified_write.get();
    let problem = transport.last_problem.get();
    let mut statements = vec![
        (
            INSERT,
            vec![
                SqlValue::Int(pass.0),
                message(),
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
                mark(verified.is_some()),
                SqlValue::Int(at.0),
            ],
        ),
        (
            OBSERVE,
            vec![
                stamp(problem.map(|(time, _)| time)),
                text(problem.map(|(_, p)| p.operation)),
                text(problem.map(|(_, p)| p.kind)),
                status(problem.and_then(|(_, p)| p.status)),
                text(problem.and_then(|(_, p)| p.code)),
                problem
                    .and_then(|_| serde_json::to_string(&counts).ok())
                    .map_or(SqlValue::Null, SqlValue::Text),
                stamp(verified),
            ],
        ),
    ];
    if problem.is_none() {
        let mut finished = None;
        if let Some(walk) = observation.walk {
            finished = walk.next.is_none().then_some(walk.began_at);
            statements.push((
                FRONTIER,
                vec![
                    SqlValue::Int(walk.began_at.0),
                    SqlValue::Text(walk.from),
                    walk.next.map_or(SqlValue::Null, SqlValue::Text),
                    mark(walk.starts),
                    message(),
                ],
            ));
        }
        if observation.fresh_swept || finished.is_some() {
            statements.push((
                CLEAN,
                vec![
                    SqlValue::Int(at.0),
                    mark(observation.fresh_swept),
                    stamp(finished),
                    message(),
                ],
            ));
        }
    }
    // A failed write only leaves the walk's proof incomplete. The copier
    // still sends its successor and reports its own outcome unchanged.
    if D1Sql::new(db).batch(statements).await.is_err() {
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
