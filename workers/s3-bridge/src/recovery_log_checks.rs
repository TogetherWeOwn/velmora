use super::*;
use std::cell::RefCell;
use std::future::Future;
use std::task::{Context, Poll, Waker};
use velmora_bridge::{BridgeError, JobOutcome, Row};

#[derive(Default)]
struct Db {
    fail: bool,
    rows: RefCell<Vec<Vec<SqlValue>>>,
    prunes: RefCell<Vec<Vec<SqlValue>>>,
}

impl Sql for Db {
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        match sql {
            INSERT => self.rows.borrow_mut().push(params.to_vec()),
            PRUNE => self.prunes.borrow_mut().push(params.to_vec()),
            _ => panic!("unexpected statement"),
        }
        if self.fail {
            Err(BridgeError::Sql("fixture error".into()))
        } else {
            Ok(1)
        }
    }
    async fn query(&self, _: &str, _: &[SqlValue]) -> Result<Vec<Row>> {
        unreachable!()
    }
    async fn batch(&self, _: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        unreachable!()
    }
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    match std::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("fixture must finish synchronously"),
    }
}

fn log(pass: i64) -> Log {
    Log {
        at: UnixMs(20),
        pass: UnixMs(pass),
        destination: Some("0123456789abcdef".into()),
        first: None,
    }
}

#[test]
fn job_and_walk_rows_follow_only_successful_mark_writes_and_not_hints() {
    let db = Db::default();
    let report = JobReport {
        swept: true,
        walk_ended: true,
        ..JobReport::default()
    };
    ready(log(0).job(&db, &report, 1)).unwrap();
    assert!(db.rows.borrow().is_empty());
    ready(log(10).job(&db, &report, 1)).unwrap();
    let rows = db.rows.borrow();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0][0..6],
        [
            SqlValue::Int(20),
            SqlValue::Text("job".into()),
            SqlValue::Int(10),
            SqlValue::Int(1),
            SqlValue::Int(1),
            SqlValue::Int(0)
        ]
    );
    assert_eq!(rows[1][1], SqlValue::Text("walk".into()));
    assert_eq!(rows[1][3], SqlValue::Int(0));
}

#[test]
fn refused_and_error_job_rows_append_without_a_deduplication_key() {
    let db = Db::default();
    let report = JobReport {
        counts: Some(velmora_bridge::copy::CopyCounts {
            refused: 5,
            failed: 9,
            records: 10,
            plan_blocked: 2,
            ..Default::default()
        }),
        timing: velmora_bridge::copy::JobTiming {
            job_ms: 100,
            plan_checks: 6,
            plan_ms: 70,
            generation_reads: 6,
            generation_writes: 4,
            generation_ms: 20,
            queue_sends: 1,
            queue_ms: 10,
        },
        ..Default::default()
    };
    ready(log(10).job(&db, &report, report.problems())).unwrap();
    for error in [
        StepError::Store(velmora_bridge::remote::RemoteError::Refused(403)),
        StepError::Source,
    ] {
        let report = JobReport {
            error: Some(error),
            ..Default::default()
        };
        ready(log(10).job(&db, &report, report.problems())).unwrap();
    }
    let report = JobReport {
        outage: true,
        ..Default::default()
    };
    ready(log(10).job(&db, &report, report.problems())).unwrap();
    let rows = db.rows.borrow();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0][4..6], [SqlValue::Int(5), SqlValue::Int(10)]);
    let SqlValue::Text(detail) = &rows[0][6] else {
        panic!("no detail");
    };
    let detail: serde_json::Value = serde_json::from_str(detail).unwrap();
    assert_eq!(detail["counts"]["failed"], 9);
    assert_eq!(detail["counts"]["plan_blocked"], 2);
    assert_eq!(
        detail["timing"],
        serde_json::json!({
            "job_ms": 100,
            "plan_checks": 6,
            "plan_ms": 70,
            "generation_reads": 6,
            "generation_writes": 4,
            "generation_ms": 20,
            "queue_sends": 1,
            "queue_ms": 10,
        })
    );
    assert_eq!(detail["destination"], "0123456789abcdef");
    assert!(rows[1..]
        .iter()
        .all(|r| r[2] == SqlValue::Int(10) && r[4] == SqlValue::Int(1)));
}

#[test]
fn a_config_refusal_is_a_pass_problem_with_fixed_detail() {
    let db = Db::default();
    let log = Log::config_refused(UnixMs(10), UnixMs(20));
    ready(log.job(&db, &JobReport::default(), 1)).unwrap();
    let rows = db.rows.borrow();
    assert_eq!(rows[0][2], SqlValue::Int(10));
    assert_eq!(rows[0][4], SqlValue::Int(1));
    let SqlValue::Text(detail) = &rows[0][6] else {
        panic!("no detail");
    };
    let detail: serde_json::Value = serde_json::from_str(detail).unwrap();
    assert_eq!(
        detail["first"],
        serde_json::json!({"op":"config","kind":"config_error","status":null,"code":null})
    );
}

#[test]
fn prune_tick_needs_only_the_catalogue_and_runs_once_per_pass() {
    use velmora_bridge::copy::{PASS_INTERVAL_MS, START_WINDOW_MS};
    let db = Db::default();
    let due = UnixMs(PASS_INTERVAL_MS * 1000);
    for offset in [0, START_WINDOW_MS, 2 * START_WINDOW_MS] {
        let now = UnixMs(due.0 + offset);
        ready(prune_tick(&db, now, now)).unwrap();
    }
    assert_eq!(
        *db.prunes.borrow(),
        [vec![SqlValue::Int(due.0 - RETENTION_MS)]]
    );
    assert!(
        db.rows.borrow().is_empty(),
        "no copy or audit observation needed"
    );
}

#[test]
fn failed_telemetry_does_not_replace_ack_or_retry() {
    for expected in [JobOutcome::Ack, JobOutcome::Retry { delay_secs: 60 }] {
        let db = Db {
            fail: true,
            ..Db::default()
        };
        let mut failures = 0;
        let chosen = complete_job(expected, || {
            failures += usize::from(ready(log(10).job(&db, &JobReport::default(), 1)).is_err());
        });
        assert_eq!(chosen, expected);
        assert_eq!(failures, 1);
    }
}
