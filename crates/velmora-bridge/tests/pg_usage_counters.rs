//! PostgreSQL usage counters as statement triggers (`pg/0003`).
//!
//! - Bulk statements write each usage row at most once per statement,
//!   counted by `pg_stat_xact_user_tables`, and the counters are exact
//!   after every statement.
//! - Random portable statements give the same counters after every
//!   statement on SQLite (the D1 triggers), on the per-row PostgreSQL
//!   triggers of 0002 and on the statement triggers.
//! - The failure trigger: statement level, the statement shapes it relies
//!   on, bulk failures, and nothing left behind by a rolled-back statement.
//!
//! `VELMORA_TEST_PG_USAGE_STAGE=0002` runs the bulk and failure tests
//! against the per-row triggers instead, which they must fail.

#![cfg(all(feature = "testkit-pg", feature = "pg-test-record"))]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use tokio_postgres::{Client, SimpleQueryMessage};
use velmora_bridge::pg::normalize_statement;
use velmora_bridge::sql::{pg_background_statements, pg_datapath_statements};
use velmora_bridge::testkit::{RusqliteSql, TestPostgres, TestSql};
use velmora_bridge::{Sql, SqlValue};

const LATEST: &str = "0003";
const ROW_TRIGGERS: &str = "0002";
const HOUR: i64 = 3_600_000;
const T0: i64 = 1_762_992_000_000;

fn stage_under_test() -> String {
    std::env::var("VELMORA_TEST_PG_USAGE_STAGE").unwrap_or_else(|_| LATEST.into())
}

/// A session whose open transaction the server ends after 1 s idle. A test
/// that panics inside a transaction cannot roll it back, and the schema
/// drop (3 s lock timeout) runs while the test runtime is blocked; the
/// server-side timeout releases the locks first.
async fn session(pg: &TestPostgres) -> Client {
    let db = pg.client().await.unwrap();
    db.batch_execute("SET idle_in_transaction_session_timeout = '1s'")
        .await
        .unwrap();
    db
}

fn sqlstate(sql: &str, error: &tokio_postgres::Error) -> String {
    // Synthetic SQL only; never echo a server message.
    let code = error.code().map_or("none", |code| code.code());
    format!("SQLSTATE {code}: {sql}")
}

async fn rows(db: &Client, sql: &str) -> Vec<Vec<Option<String>>> {
    let messages = db
        .simple_query(sql)
        .await
        .unwrap_or_else(|e| panic!("{}", sqlstate(sql, &e)));
    messages
        .into_iter()
        .filter_map(|message| match message {
            SimpleQueryMessage::Row(row) => Some(
                (0..row.len())
                    .map(|i| row.get(i).map(str::to_owned))
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

/// Rows changed by the last statement of `sql`.
async fn exec(db: &Client, sql: &str) -> u64 {
    let messages = db
        .simple_query(sql)
        .await
        .unwrap_or_else(|e| panic!("{}", sqlstate(sql, &e)));
    messages
        .into_iter()
        .filter_map(|message| match message {
            SimpleQueryMessage::CommandComplete(n) => Some(n),
            _ => None,
        })
        .last()
        .unwrap_or(0)
}

const GLOBAL: &str = "id, cur_x, all_x, cur_o, all_o, cur_g, all_g, \
    x_unreleased, unreleased_bytes, x_released, released_bytes, x_deleted, \
    ob_post, ob_verify, ob_release, ob_done, ob_cancelled, ob_dead, \
    posts_total, verifies_total, releases_total, dead_total, failures_total, \
    hour, h_posts, h_verifies, h_releases, h_dead, h_failures";

const SNAPSHOT: [&str; 3] = [
    "SELECT 'global', * FROM (SELECT {GLOBAL} FROM usage_global) g ORDER BY 2",
    "SELECT 'bucket', kind, bucket_id, live_objects, live_bytes FROM usage_buckets ORDER BY 2, 3",
    "SELECT 'hour', hour, posts, verifies, releases, dead, failures FROM usage_hours ORDER BY 2",
];

fn snapshot_sql() -> Vec<String> {
    SNAPSHOT
        .iter()
        .map(|sql| sql.replace("{GLOBAL}", GLOBAL))
        .collect()
}

async fn pg_snapshot(db: &Client) -> Vec<String> {
    let mut out = Vec::new();
    for sql in snapshot_sql() {
        for row in rows(db, &sql).await {
            let cells: Vec<String> = row
                .into_iter()
                .map(|v| v.unwrap_or_else(|| "NULL".into()))
                .collect();
            out.push(cells.join("|"));
        }
    }
    out
}

async fn sqlite_snapshot(db: &RusqliteSql) -> Vec<String> {
    let mut out = Vec::new();
    for sql in snapshot_sql() {
        for row in db.query(&sql, &[]).await.unwrap() {
            let cells: Vec<String> = row
                .into_iter()
                .map(|v| match v {
                    SqlValue::Null => "NULL".into(),
                    SqlValue::Int(i) => i.to_string(),
                    SqlValue::Text(t) => t,
                    SqlValue::Blob(_) => unreachable!("no blob counters"),
                })
                .collect();
            out.push(cells.join("|"));
        }
    }
    out
}

/// One `usage_global` row: `name = value` for the named columns.
async fn global(db: &Client, id: i64, cols: &str) -> Vec<i64> {
    rows(
        db,
        &format!("SELECT {cols} FROM usage_global WHERE id = {id}"),
    )
    .await
    .remove(0)
    .into_iter()
    .map(|v| v.expect("non-NULL").parse().unwrap())
    .collect()
}

/// usage_global updates, usage_buckets inserts+updates, usage_hours
/// inserts+updates so far in this transaction. Use differences within one
/// transaction: the view also includes counts of earlier transactions that
/// the backend has not flushed yet.
async fn usage_writes(db: &Client) -> [i64; 3] {
    let row = rows(
        db,
        "SELECT COALESCE(sum(n_tup_upd) FILTER (WHERE relname = 'usage_global'), 0), \
                COALESCE(sum(n_tup_ins + n_tup_upd) FILTER (WHERE relname = 'usage_buckets'), 0), \
                COALESCE(sum(n_tup_ins + n_tup_upd) FILTER (WHERE relname = 'usage_hours'), 0) \
           FROM pg_stat_xact_user_tables WHERE schemaname = current_schema()",
    )
    .await
    .remove(0);
    [0, 1, 2].map(|i| row[i].as_deref().unwrap().parse().unwrap())
}

fn manifest_sql(needle: &[&str]) -> String {
    let all: Vec<String> = pg_datapath_statements()
        .into_iter()
        .map(|(sql, _)| sql.to_owned())
        .chain(pg_background_statements().into_iter().map(|(sql, _)| sql))
        .collect();
    let found: BTreeSet<&String> = all
        .iter()
        .filter(|sql| needle.iter().all(|n| sql.contains(n)))
        .collect();
    assert_eq!(
        found.len(),
        1,
        "expected one manifest statement with {needle:?}"
    );
    let sql = found.into_iter().next().unwrap();
    normalize_statement(sql).unwrap()
}

/// A statement of the bulk workload: its rows, and the most usage writes
/// it may cause (usage_global, usage_buckets, usage_hours).
struct Bulk {
    sql: String,
    params: Vec<i64>,
    bound: [i64; 3],
}

impl Bulk {
    fn new(sql: impl Into<String>, bound: [i64; 3]) -> Self {
        Self {
            sql: sql.into(),
            params: Vec::new(),
            bound,
        }
    }
}

async fn run_bulk(db: &Client, statement: &Bulk, rows_expected: u64) -> Duration {
    let before = usage_writes(db).await;
    let started = Instant::now();
    let changed = if statement.params.is_empty() {
        exec(db, &statement.sql).await
    } else {
        let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = statement
            .params
            .iter()
            .map(|p| p as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();
        db.execute(statement.sql.as_str(), &params)
            .await
            .unwrap_or_else(|e| panic!("{}", sqlstate(&statement.sql, &e)))
    };
    let elapsed = started.elapsed();
    let after = usage_writes(db).await;
    assert_eq!(changed, rows_expected, "rows changed by {}", statement.sql);
    let delta = [0, 1, 2].map(|i| after[i] - before[i]);
    assert!(
        (0..3).all(|i| delta[i] <= statement.bound[i]),
        "usage writes [global, buckets, hours] {delta:?} exceed {:?} for {} rows: {}",
        statement.bound,
        rows_expected,
        statement.sql
    );
    elapsed
}

/// One transaction of single statements over `n` rows each, with row 2 of
/// `usage_global` covering about half of every table. Every statement
/// writes each usage row at most once, and the counters are exact after
/// each of them.
async fn bulk_workload(n: i64) -> Duration {
    let pg = TestPostgres::through_stage(&stage_under_test(), true).unwrap();
    let db = session(&pg).await;
    let key = |i: i64| format!("k{i:07}");
    let covered = n / 2 + 1; // keys k0000000 ..= k{n/2}
    let (h0, h1) = (T0 / HOUR, T0 / HOUR + 1);
    exec(
        &db,
        &format!(
            "INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,created_at) \
               VALUES ('b','b','o','\\x',1,0); \
             UPDATE usage_global SET hour = {h0}, h_posts = 1 WHERE id = 1; \
             UPDATE usage_global SET cur_x = '{m}', cur_o = '{m}', cur_g = 'g{mid:07}' WHERE id = 2",
            m = key(n / 2),
            mid = n / 2
        ),
    )
    .await;
    exec(&db, "BEGIN; SET LOCAL statement_timeout = '120s'").await;
    let mut elapsed = Duration::ZERO;
    let x = "x_unreleased, unreleased_bytes, x_released, released_bytes, x_deleted";
    let ob = "ob_post, ob_dead, dead_total, hour, h_dead";
    let series = |cols: &str| format!("SELECT {cols} FROM generate_series(0, {}) i", n - 1);
    let k = "'k' || lpad(i::text, 7, '0')";
    let g = "'g' || lpad(i::text, 7, '0')";

    elapsed += run_bulk(
        &db,
        &Bulk::new(
            format!(
                "INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,\
                   plain_sha256,cipher_sha256,safety_state,created_at) {}",
                series(&format!(
                    "{k},'b','staged',1,10,'\\x','\\x','\\x','\\x','held',0"
                ))
            ),
            [2, 0, 0],
        ),
        n as u64,
    )
    .await;
    assert_eq!(global(&db, 1, x).await, [n, 10 * n, 0, 0, 0]);
    assert_eq!(global(&db, 2, x).await, [covered, 10 * covered, 0, 0, 0]);

    elapsed += run_bulk(
        &db,
        &Bulk::new(
            format!(
                "INSERT INTO outbox(extent_id,generation_id,stage,attempts,next_at,updated_at) {}",
                series(&format!("{k},'gen','post',60,0,{T0}"))
            ),
            [2, 0, 0],
        ),
        n as u64,
    )
    .await;
    assert_eq!(global(&db, 1, ob).await, [n, 0, 0, h0, 0]);
    assert_eq!(global(&db, 2, ob).await, [covered, 0, 0, 0, 0]);

    elapsed += run_bulk(
        &db,
        &Bulk::new(
            "UPDATE extents SET safety_state = 'released' WHERE safety_state = 'held'",
            [2, 0, 0],
        ),
        n as u64,
    )
    .await;
    assert_eq!(global(&db, 1, x).await, [0, 0, n, 10 * n, 0]);
    assert_eq!(global(&db, 2, x).await, [0, 0, covered, 10 * covered, 0]);

    // The app's bury, at a new hour: every row is above both attempt
    // thresholds, so it changes all n rows, and row 1 files hour h0.
    let mut bury = Bulk::new(
        manifest_sql(&["UPDATE outbox", "SET stage = 'dead'", "attempts > 50"]),
        [2, 0, 1],
    );
    bury.params = vec![50, T0 + HOUR];
    elapsed += run_bulk(&db, &bury, n as u64).await;
    assert_eq!(global(&db, 1, ob).await, [0, n, n, h1, n]);
    assert_eq!(global(&db, 2, ob).await, [0, covered, covered, h1, covered]);
    assert_eq!(
        rows(&db, "SELECT hour, posts, dead FROM usage_hours").await,
        [[h0, 1, 0].map(|v| Some(v.to_string())).to_vec()]
    );

    let generations = [
        (
            format!(
                "INSERT INTO generations(id,bucket_id,key,state,size,etag,content_json,user_meta_json,\
                   extent_count,created_at) {}",
                series(&format!("{g},'b','key' || i,'live',3,'e','{{}}','{{}}',0,0"))
            ),
            [n, 3 * n, covered, 3 * covered],
        ),
        (
            "UPDATE generations SET size = 4".to_owned(),
            [n, 4 * n, covered, 4 * covered],
        ),
        (
            "UPDATE generations SET state = 'superseded'".to_owned(),
            [0, 0, 0, 0],
        ),
        (
            "UPDATE generations SET state = 'live'".to_owned(),
            [n, 4 * n, covered, 4 * covered],
        ),
        ("DELETE FROM generations".to_owned(), [0, 0, 0, 0]),
    ];
    for (sql, [o1, b1, o2, b2]) in generations {
        elapsed += run_bulk(&db, &Bulk::new(sql, [0, 2, 0]), n as u64).await;
        assert_eq!(bucket_rows(&db).await, [vec![1, o1, b1], vec![2, o2, b2]]);
    }

    elapsed += run_bulk(&db, &Bulk::new("DELETE FROM outbox", [2, 0, 0]), n as u64).await;
    assert_eq!(global(&db, 1, ob).await, [0, 0, n, h1, n]);
    assert_eq!(global(&db, 2, ob).await, [0, 0, covered, h1, covered]);
    elapsed += run_bulk(&db, &Bulk::new("DELETE FROM extents", [2, 0, 0]), n as u64).await;
    assert_eq!(global(&db, 1, x).await, [0, 0, 0, 0, 0]);
    assert_eq!(global(&db, 2, x).await, [0, 0, 0, 0, 0]);
    exec(&db, "ROLLBACK").await;
    elapsed
}

/// Upper-case words of `sql` without comments or identifier quotes, so a
/// quoted or schema-qualified table name reads like a bare one.
fn sql_words(sql: &str) -> Vec<String> {
    let mut text = String::new();
    let mut rest = sql;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("--") {
            rest = after.split_once('\n').map_or("", |(_, tail)| tail);
            text.push(' ');
        } else if let Some(after) = rest.strip_prefix("/*") {
            rest = after.split_once("*/").map_or("", |(_, tail)| tail);
            text.push(' ');
        } else {
            let c = rest.chars().next().unwrap();
            if c != '"' {
                text.push(c);
            }
            rest = &rest[c.len_utf8()..];
        }
    }
    text.to_uppercase()
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
fn sql_words_reads_quoted_and_qualified_targets() {
    let words = sql_words("WITH a AS (UPDATE/**/\"cat\".\"outbox\" /* hidden1 */ SET x = 1) -- hidden2\nUPDATE ONLY outbox SET y = 2; MERGE/* hidden3 */INTO t");
    let updates: Vec<_> = words
        .windows(2)
        .filter(|w| w[0] == "UPDATE")
        .map(|w| w[1].clone())
        .collect();
    assert_eq!(updates, ["CAT.OUTBOX", "ONLY"]);
    assert!(!words.iter().any(|w| w.starts_with("HIDDEN")), "{words:?}");
    assert!(words.windows(2).any(|w| w[0] == "MERGE" && w[1] == "INTO"));
}

async fn bucket_rows(db: &Client) -> Vec<Vec<i64>> {
    rows(
        db,
        "SELECT kind, live_objects, live_bytes FROM usage_buckets WHERE bucket_id = 'b' ORDER BY kind",
    )
    .await
    .into_iter()
    .map(|r| r.into_iter().map(|v| v.unwrap().parse().unwrap()).collect())
    .collect()
}

#[tokio::test]
async fn bulk_statements_write_each_usage_row_once() {
    if !TestSql::postgres_selected() {
        return;
    }
    // Small first: the per-row triggers fail this on counts alone.
    bulk_workload(2_000).await;
    let elapsed = bulk_workload(100_000).await;
    assert!(
        elapsed < Duration::from_secs(60),
        "100,000-row statements took {elapsed:?} in total"
    );
    eprintln!("usage bulk workload, 12 statements of 100,000 rows: {elapsed:?}");
}

/// Time one statement inside a rolled-back transaction, after `prep` (not
/// timed) in the same transaction; return the rows it changed and the
/// elapsed time.
async fn timed_rollback(db: &Client, prep: &str, sql: &str) -> (u64, Duration) {
    exec(db, "BEGIN").await;
    if !prep.is_empty() {
        exec(db, prep).await;
    }
    let started = Instant::now();
    let changed = exec(db, sql).await;
    let elapsed = started.elapsed();
    exec(db, "ROLLBACK").await;
    (changed, elapsed)
}

/// The fastest of three timed, rolled-back runs: other tests share the
/// database, and their load only ever adds time. Each run starts from a
/// reset plan cache. With `replan` the bulk statement itself parses the
/// trigger queries; without it the single-row `warm` firing (rolled back)
/// parses them first, right before the run, so a plan-cache reset by
/// another session cannot swap a bulk-sized plan into a "cached" run.
async fn fastest_rollback(
    db: &Client,
    warm: &str,
    prep: &str,
    sql: &str,
    replan: bool,
) -> (u64, Duration) {
    let mut best = (0, Duration::MAX);
    for i in 0..3 {
        exec(db, "DISCARD PLANS").await;
        if !replan {
            assert_eq!(timed_rollback(db, "", warm).await.0, 1, "{warm}");
        }
        let run = timed_rollback(db, prep, sql).await;
        if i == 0 {
            best.0 = run.0;
        }
        assert_eq!(run.0, best.0, "{sql}");
        best.1 = best.1.min(run.1);
    }
    best
}

/// The same statement with this table's usage triggers disabled (fastest
/// of three, rolled back, after `prep` with them enabled): what the
/// statement costs without counters.
async fn fastest_without_usage_triggers(db: &Client, prep: &str, sql: &str) -> Duration {
    let (table, triggers): (&str, &[&str]) = if sql.contains(" extents ") {
        (
            "extents",
            &[
                "usage_extents_insert",
                "usage_extents_update",
                "usage_extents_delete",
            ],
        )
    } else if sql.contains(" outbox ") {
        (
            "outbox",
            &[
                "usage_outbox_insert",
                "usage_outbox_delete",
                "usage_outbox_failure",
                "usage_outbox_stage",
            ],
        )
    } else {
        (
            "generations",
            &[
                "usage_generations_insert",
                "usage_generations_update",
                "usage_generations_delete",
            ],
        )
    };
    let disable: Vec<String> = triggers
        .iter()
        .map(|t| format!("DISABLE TRIGGER {t}"))
        .collect();
    let mut best = Duration::MAX;
    for _ in 0..3 {
        exec(db, "BEGIN").await;
        if !prep.is_empty() {
            exec(db, prep).await;
        }
        exec(db, &format!("ALTER TABLE {table} {}", disable.join(", "))).await;
        let started = Instant::now();
        exec(db, sql).await;
        best = best.min(started.elapsed());
        exec(db, "ROLLBACK").await;
    }
    best
}

/// One bulk shape: a single-row firing with an event, untimed preparation
/// in the same transaction, and the timed statement, over the first n rows.
struct Shape {
    warm: String,
    prep: Box<dyn Fn(i64) -> String>,
    bulk: Box<dyn Fn(i64) -> String>,
}

fn shape(warm: &str, bulk: impl Fn(i64) -> String + 'static) -> Shape {
    Shape {
        warm: warm.to_owned(),
        prep: Box::new(|_| String::new()),
        bulk: Box::new(bulk),
    }
}

/// PL/pgSQL caches each trigger query with the transition-table size of
/// the firing that parsed it, and a pooled session's first event is usually
/// one row. Every changed trigger must stay linear with plans parsed by a
/// single-row firing and with plans parsed by the bulk statement: 10x the
/// rows may take at most 30x the time (quadratic is 100x), 20,000 rows at
/// most 4 s, and the counters at most twice what the statement costs with
/// them disabled.
#[tokio::test]
async fn bulk_statements_stay_linear_after_a_single_row_firing_on_the_same_session() {
    if !TestSql::postgres_selected() {
        return;
    }
    let pg = TestPostgres::through_stage(&stage_under_test(), true).unwrap();
    let db = session(&pg).await;
    let last = 20_005;
    exec(
        &db,
        &format!(
            "SET statement_timeout = '60s'; \
             INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,created_at) \
               VALUES ('b','b','o','\\x',1,0); \
             UPDATE usage_global SET cur_x = 'k0010000', cur_o = 'k0010000', cur_g = 'g0010000' WHERE id = 2; \
             INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,\
               plain_sha256,cipher_sha256,safety_state,created_at) \
               SELECT 'k' || lpad(i::text, 7, '0'),'b','staged',1,10,'\\x','\\x','\\x','\\x','held',0 \
                 FROM generate_series(0, {last}) i; \
             INSERT INTO outbox(extent_id,generation_id,stage,next_at,updated_at) \
               SELECT id,'gen','post',0,{T0} FROM extents; \
             INSERT INTO generations(id,bucket_id,key,state,size,etag,content_json,user_meta_json,\
               extent_count,created_at) \
               SELECT 'g' || lpad(i::text, 7, '0'),'b','key' || i,'live',3,'e','{{}}','{{}}',0,0 \
                 FROM generate_series(0, {last}) i"
        ),
    )
    .await;
    let below = |n: i64| format!("'k{n:07}'");
    let gbelow = |n: i64| format!("'g{n:07}'");
    let h = T0 + HOUR;
    // verify->done of a released extent at this update: a release, which
    // looks up each extent.
    let released = move |key: &str| {
        format!(
            "UPDATE outbox SET stage = 'verify' WHERE extent_id {key}; \
             UPDATE extents SET safety_state = 'released', released_at = {h} WHERE id {key}"
        )
    };
    let shapes = vec![
        shape(
            "UPDATE extents SET safety_state = 'released' WHERE id = 'k0020000'",
            move |n| format!("UPDATE extents SET safety_state = 'released' WHERE id < {}", below(n)),
        ),
        shape(
            "UPDATE generations SET state = 'superseded' WHERE id = 'g0020000'",
            move |n| format!("UPDATE generations SET state = 'superseded' WHERE id < {}", gbelow(n)),
        ),
        shape(
            "UPDATE outbox SET stage = 'verify', updated_at = 1762992000000 WHERE extent_id = 'k0020001'",
            move |n| {
                format!(
                    "UPDATE outbox SET stage = 'verify', updated_at = {h} WHERE extent_id < {}",
                    below(n)
                )
            },
        ),
        shape(
            "UPDATE outbox SET last_error = 'boom', updated_at = 1762992000000 WHERE extent_id = 'k0020002'",
            move |n| {
                format!(
                    "UPDATE outbox SET last_error = 'boom', updated_at = {h} WHERE extent_id < {}",
                    below(n)
                )
            },
        ),
        Shape {
            warm: format!(
                "{}; UPDATE outbox SET stage = 'done', updated_at = {h} WHERE extent_id = 'k0020004'",
                released("= 'k0020004'")
            ),
            prep: Box::new(move |n| released(&format!("< {}", below(n)))),
            bulk: Box::new(move |n| {
                format!(
                    "UPDATE outbox SET stage = 'done', updated_at = {h} WHERE extent_id < {}",
                    below(n)
                )
            }),
        },
        shape("DELETE FROM outbox WHERE extent_id = 'k0020003'", move |n| {
            format!("DELETE FROM outbox WHERE extent_id < {}", below(n))
        }),
        shape("DELETE FROM generations WHERE id = 'g0020003'", move |n| {
            format!("DELETE FROM generations WHERE id < {}", gbelow(n))
        }),
    ];
    // The release shape reaches the per-extent lookup: every row is a
    // release.
    let release = &shapes[4];
    exec(&db, "BEGIN").await;
    exec(&db, &(release.prep)(2_000)).await;
    let before = global(&db, 1, "releases_total").await;
    exec(&db, &(release.bulk)(2_000)).await;
    assert_eq!(global(&db, 1, "releases_total").await[0] - before[0], 2_000);
    exec(&db, "ROLLBACK").await;

    let mut report = Vec::new();
    // A trigger query keeps the transition-table size of the firing that
    // parsed it until the plan cache is reset, and any namespace change in
    // the database resets it (other sessions creating schemas, for one).
    // Measure both: plans parsed by the single-row firing ("cached"), where
    // a join of the transition tables can run as a nested loop, and plans
    // parsed by the bulk statement itself ("replanned"), where such a join
    // is estimated at about N*M/200 rows and crosses the JIT thresholds.
    for (mode, replan) in [("cached", false), ("replanned", true)] {
        for s in &shapes {
            let (small_rows, small) =
                fastest_rollback(&db, &s.warm, &(s.prep)(2_000), &(s.bulk)(2_000), replan).await;
            let (large_rows, large) =
                fastest_rollback(&db, &s.warm, &(s.prep)(20_000), &(s.bulk)(20_000), replan).await;
            let sql = (s.bulk)(20_000);
            assert_eq!((small_rows, large_rows), (2_000, 20_000), "{sql}");
            report.push(format!("{mode}: {small:?} -> {large:?}: {sql}"));
            assert!(
                large < Duration::from_secs(4)
                    && large.as_secs_f64() < 30.0 * small.as_secs_f64().max(0.01),
                "not linear on a warm session ({mode}): 2,000 rows {small:?}, 20,000 rows {large:?}: {sql}"
            );
            // A fixed cost that grows with the plan's estimate (JIT
            // compilation of a blind join) inflates both sizes alike, so
            // also bound the counters' share: at most twice what the
            // statement costs on its own.
            let bare = fastest_without_usage_triggers(&db, &(s.prep)(20_000), &sql).await;
            report.push(format!(
                "{mode}: 20,000 rows without usage triggers {bare:?}"
            ));
            assert!(
                large.as_secs_f64() < 3.0 * bare.as_secs_f64().max(0.005),
                "usage triggers cost more than twice the statement ({mode}): {large:?} with, {bare:?} without: {sql}"
            );
        }
    }
    eprintln!("warm-session usage triggers:\n{}", report.join("\n"));
}

/// The byte deltas are summed with their sign over both transition tables.
/// Negating a BIGINT-minimum cipher_size must not overflow before the
/// unchanged row's two sides cancel.
#[tokio::test]
async fn byte_deltas_do_not_overflow_at_the_bigint_boundary() {
    if !TestSql::postgres_selected() {
        return;
    }
    let pg = TestPostgres::through_stage(&stage_under_test(), true).unwrap();
    let db = session(&pg).await;
    exec(
        &db,
        "INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,created_at) \
           VALUES ('b','b','o','\\x',1,0); \
         INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,\
           plain_sha256,cipher_sha256,safety_state,created_at) VALUES \
           ('kmin','b','staged',1,-9223372036854775808,'\\x','\\x','\\x','\\x','held',0), \
           ('kten','b','staged',1,8,'\\x','\\x','\\x','\\x','held',0)",
    )
    .await;
    let x = "x_unreleased, unreleased_bytes, x_released, released_bytes";
    let min = i64::MIN;
    assert_eq!(global(&db, 1, x).await, [2, min + 8, 0, 0]);
    // One statement: the BIGINT-minimum extent unchanged, an 8-byte release.
    let changed = db
        .execute(
            "UPDATE extents SET safety_state = CASE id WHEN 'kten' THEN 'released' ELSE safety_state END \
             WHERE id IN ('kmin','kten')",
            &[],
        )
        .await
        .unwrap_or_else(|e| panic!("{}", sqlstate("UPDATE extents … kmin, kten", &e)));
    assert_eq!(changed, 2);
    assert_eq!(global(&db, 1, x).await, [1, min, 1, 8]);
}

// ---------------------------------------------------------------------------
// The failure trigger
// ---------------------------------------------------------------------------

#[tokio::test]
async fn failure_trigger_is_statement_level_and_exact() {
    if !TestSql::postgres_selected() {
        return;
    }
    let pg = TestPostgres::through_stage(&stage_under_test(), true).unwrap();
    let db = session(&pg).await;

    // Every usage trigger is a statement trigger. Only the failure trigger
    // has a column list, so only it sees SET targets, and it fires before
    // the stage trigger of the same statement.
    let triggers = rows(
        &db,
        "SELECT t.tgname, (t.tgtype & 1) = 1, \
                ARRAY(SELECT a.attname FROM unnest(t.tgattr) k(n) \
                      JOIN pg_attribute a ON a.attrelid = t.tgrelid AND a.attnum = k.n)::text, \
                t.tgoldtable IS NOT NULL, t.tgnewtable IS NOT NULL \
           FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
          WHERE c.relnamespace = to_regnamespace(current_schema()) AND t.tgname LIKE 'usage\\_%' \
          ORDER BY c.relname, t.tgname",
    )
    .await;
    let triggers: Vec<String> = triggers
        .into_iter()
        .map(|r| {
            r.into_iter()
                .map(Option::unwrap)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    assert_eq!(
        triggers,
        [
            "usage_extents_delete f {} t f",
            "usage_extents_insert f {} f t",
            "usage_extents_update f {} t t",
            "usage_generations_delete f {} t f",
            "usage_generations_insert f {} f t",
            "usage_generations_update f {} t t",
            "usage_outbox_delete f {} t f",
            "usage_outbox_failure f {last_error} f f",
            "usage_outbox_insert f {} f t",
            "usage_outbox_stage f {} t t",
        ]
    );

    // The SET list is per statement. Statement-level detection of a
    // last_error target is exact for every row only while no statement
    // updates outbox twice (writable CTEs) or merges into it.
    let all: Vec<String> = pg_datapath_statements()
        .into_iter()
        .map(|(sql, _)| sql.to_owned())
        .chain(pg_background_statements().into_iter().map(|(sql, _)| sql))
        .collect();
    assert!(
        all.iter().any(|sql| sql.contains("last_error = ?6")),
        "FAIL is in the manifest"
    );
    for sql in &all {
        let words = sql_words(sql);
        let target = |i: usize| {
            let next = words.get(i + 1).map(String::as_str);
            let name = if next == Some("ONLY") {
                words.get(i + 2)
            } else {
                words.get(i + 1)
            };
            name.map(|n| n.rsplit('.').next().unwrap() == "OUTBOX")
                .unwrap_or(false)
        };
        let updates = (0..words.len())
            .filter(|&i| words[i] == "UPDATE" && target(i))
            .count();
        assert!(updates <= 1, "two outbox updates in: {sql}");
        assert!(!words.iter().any(|w| w == "MERGE"), "MERGE in: {sql}");
        let inserts = (0..words.len()).any(|i| words[i] == "INTO" && target(i));
        let upsert = words.windows(2).any(|w| w[0] == "DO" && w[1] == "UPDATE");
        assert!(!(inserts && upsert), "outbox upsert in: {sql}");
    }

    let n = 2_000;
    exec(
        &db,
        &format!(
            "INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,created_at) \
               VALUES ('b','b','o','\\x',1,0); \
             INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,\
               plain_sha256,cipher_sha256,safety_state,created_at) \
               SELECT 'k' || lpad(i::text, 7, '0'),'b','staged',1,10,'\\x','\\x','\\x','\\x','held',0 \
                 FROM generate_series(0, {last}) i; \
             INSERT INTO outbox(extent_id,generation_id,stage,next_at,updated_at) \
               SELECT id,'gen','post',0,{T0} FROM extents; \
             INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,\
               plain_sha256,cipher_sha256,safety_state,created_at) \
               VALUES ('zzzk0000001','b','staged',1,10,'\\x','\\x','\\x','\\x','held',0); \
             INSERT INTO generations(id,bucket_id,key,state,size,etag,content_json,user_meta_json,\
               extent_count,created_at) VALUES ('g1','b','g1','live',1,'e','{{}}','{{}}',0,0); \
             UPDATE usage_global SET cur_o = 'k{half:07}' WHERE id = 2",
            last = n - 1,
            half = n / 2
        ),
    )
    .await;
    let f = "failures_total, h_failures, hour";
    let h = T0 / HOUR;
    exec(&db, "BEGIN").await;
    // The app's FAIL statement keyed by one row, then the same shape over
    // every row in one statement: each counts once per row, also when the
    // error text is unchanged.
    let fail = manifest_sql(&["UPDATE outbox SET next_at = ?5, last_error = ?6"]);
    let before = usage_writes(&db).await;
    let changed = db
        .execute(
            fail.as_str(),
            &[&"k0000000", &"gen", &"post", &0i64, &T0, &"boom", &T0],
        )
        .await
        .unwrap();
    assert_eq!(changed, 1);
    assert_eq!(global(&db, 1, f).await, [1, 1, h]);
    let bulk = Bulk::new(
        format!("UPDATE outbox SET last_error = 'boom', updated_at = {T0}"),
        [2, 0, 0],
    );
    run_bulk(&db, &bulk, n as u64).await;
    let after = usage_writes(&db).await;
    assert!(
        after[0] - before[0] <= 4,
        "usage_global writes {after:?} - {before:?}"
    );
    assert_eq!(global(&db, 1, f).await, [1 + n, 1 + n, h]);
    // Row 2 covers k0000000 (the single FAIL) and k0000000..=k0001000.
    assert_eq!(global(&db, 2, f).await, [n / 2 + 2, n / 2 + 2, h]);

    // Not a target, NULL, or a changed stage: no failure.
    run_bulk(
        &db,
        &Bulk::new(format!("UPDATE outbox SET updated_at = {T0}"), [0, 0, 0]),
        n as u64,
    )
    .await;
    run_bulk(
        &db,
        &Bulk::new(
            format!("UPDATE outbox SET last_error = NULL, updated_at = {T0}"),
            [0, 0, 0],
        ),
        n as u64,
    )
    .await;
    run_bulk(
        &db,
        &Bulk::new(
            format!("UPDATE outbox SET stage = 'verify', last_error = 'x', updated_at = {T0}"),
            [2, 0, 0],
        ),
        n as u64,
    )
    .await;
    assert_eq!(global(&db, 1, f).await, [1 + n, 1 + n, h]);
    assert_eq!(global(&db, 1, "posts_total, h_posts").await, [n, n]);

    // A statement that sets last_error and is refused after the failure
    // trigger ran (a primary-key change, VL002 from the stage trigger)
    // leaves nothing for the next statement once its savepoint rolls back.
    exec(&db, "SAVEPOINT s").await;
    let error = db
        .batch_execute(
            "UPDATE outbox SET extent_id = 'zzz' || extent_id, last_error = 'x' WHERE extent_id = 'k0000001'",
        )
        .await
        .expect_err("a primary-key change must be refused");
    assert_eq!(error.code().map(|c| c.code()), Some("VL002"));
    exec(&db, "ROLLBACK TO SAVEPOINT s").await;
    run_bulk(
        &db,
        &Bulk::new(format!("UPDATE outbox SET updated_at = {T0}"), [0, 0, 0]),
        n as u64,
    )
    .await;
    assert_eq!(global(&db, 1, f).await, [1 + n, 1 + n, h]);
    exec(&db, "ROLLBACK").await;

    for sql in [
        "UPDATE outbox SET extent_id = 'zzzk0000001' WHERE extent_id = 'k0000001'",
        "UPDATE extents SET id = 'zzzk0000009' WHERE id = 'zzzk0000001'",
        "UPDATE generations SET id = 'g9' WHERE id = 'g1'",
    ] {
        let error = db.batch_execute(sql).await.expect_err(sql);
        assert_eq!(error.code().map(|c| c.code()), Some("VL002"), "{sql}");
    }
}

// ---------------------------------------------------------------------------
// Equivalence: SQLite, per-row PG and statement PG after every statement
// ---------------------------------------------------------------------------

/// xorshift64*: the same sequences on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// Between 1 and `max` distinct items.
    fn some<'a>(&mut self, items: &'a [String], max: usize) -> Vec<&'a String> {
        let want = 1 + self.below(max.min(items.len()));
        let mut chosen: Vec<&String> = Vec::new();
        while chosen.len() < want {
            let item = self.pick(items);
            if !chosen.contains(&item) {
                chosen.push(item);
            }
        }
        chosen
    }
}

fn list(keys: &[&String]) -> String {
    keys.iter()
        .map(|k| format!("'{k}'"))
        .collect::<Vec<_>>()
        .join(",")
}

/// `CASE key WHEN 'k' THEN value ... ELSE otherwise END` with a random
/// value per key.
fn case(rng: &mut Rng, key: &str, keys: &[&String], values: &[&str], otherwise: &str) -> String {
    let mut sql = format!("CASE {key} ");
    for k in keys {
        sql += &format!("WHEN '{k}' THEN {} ", rng.pick(values));
    }
    sql + &format!("ELSE {otherwise} END")
}

/// One updated_at per statement. Mostly the current hour; sometimes a
/// later one (a roll: row 1 files the hour) or an earlier one.
fn at(rng: &mut Rng, hour: &mut i64) -> i64 {
    match rng.below(10) {
        0 => *hour += 1 + rng.below(2) as i64,
        1 => return (*hour - 1).max(0) * HOUR + rng.below(HOUR as usize) as i64,
        _ => {}
    }
    *hour * HOUR + rng.below(HOUR as usize) as i64
}

const STAGES: [&str; 6] = [
    "'post'",
    "'verify'",
    "'release'",
    "'done'",
    "'cancelled'",
    "'dead'",
];
const SAFETY: [&str; 4] = ["'held'", "'releasing'", "'released'", "'deleted'"];
const GEN_STATES: [&str; 3] = ["'live'", "'superseded'", "'deleted'"];
const BUCKETS: [&str; 3] = ["'bA'", "'ba'", "'bm'"];

/// One portable statement; `{B}` is the empty blob literal.
fn statement(rng: &mut Rng, extents: &[String], gens: &[String], hour: &mut i64) -> String {
    match rng.below(17) {
        0 => {
            let keys = rng.some(extents, 6);
            let values: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "('{k}','bA','staged',1,{},{{B}},{{B}},{{B}},{{B}},{},0)",
                        1 + rng.below(1000),
                        rng.pick(&SAFETY)
                    )
                })
                .collect();
            format!(
                "INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,\
                   plain_sha256,cipher_sha256,safety_state,created_at) VALUES {} ON CONFLICT DO NOTHING",
                values.join(",")
            )
        }
        1 | 2 => {
            let keys = rng.some(extents, 6);
            let state = case(rng, "id", &keys, &SAFETY, "safety_state");
            let sizes: Vec<String> = (0..3).map(|_| (1 + rng.below(1000)).to_string()).collect();
            let sizes: Vec<&str> = sizes
                .iter()
                .map(String::as_str)
                .chain(["cipher_size"])
                .collect();
            let cipher = case(rng, "id", &keys, &sizes, "cipher_size");
            match rng.below(3) {
                0 => format!("UPDATE extents SET safety_state = {state} WHERE id IN ({})", list(&keys)),
                1 => format!("UPDATE extents SET cipher_size = {cipher} WHERE id IN ({})", list(&keys)),
                _ => format!(
                    "UPDATE extents SET safety_state = {state}, cipher_size = {cipher} WHERE id IN ({})",
                    list(&keys)
                ),
            }
        }
        3 => {
            // Released now: a later verify->done of the same hour is a release.
            let keys = rng.some(extents, 4);
            format!(
                "UPDATE extents SET safety_state = 'released', released_at = {} WHERE id IN ({})",
                at(rng, hour),
                list(&keys)
            )
        }
        4 => {
            let keys = rng.some(extents, 4);
            format!(
                "DELETE FROM extents WHERE id IN ({}) AND id NOT IN (SELECT extent_id FROM outbox)",
                list(&keys)
            )
        }
        5 => {
            let keys = rng.some(extents, 6);
            let stage = case(rng, "id", &keys, &STAGES, "'post'");
            format!(
                "INSERT INTO outbox(extent_id,generation_id,stage,next_at,updated_at) \
                 SELECT id,'gen_none',{stage},0,0 FROM extents WHERE id IN ({}) ON CONFLICT DO NOTHING",
                list(&keys)
            )
        }
        6..=8 => {
            let keys = rng.some(extents, 6);
            let stage = case(rng, "extent_id", &keys, &STAGES, "stage");
            format!(
                "UPDATE outbox SET stage = {stage}, updated_at = {} WHERE extent_id IN ({})",
                at(rng, hour),
                list(&keys)
            )
        }
        9 | 10 => {
            // FAIL shapes: an error per row (some NULL), with or without a
            // stage change in the same statement.
            let keys = rng.some(extents, 6);
            let error = case(
                rng,
                "extent_id",
                &keys,
                &["'boom'", "'boom'", "NULL"],
                "last_error",
            );
            if rng.chance(30) {
                let stage = case(rng, "extent_id", &keys, &STAGES, "stage");
                format!(
                    "UPDATE outbox SET stage = {stage}, last_error = {error}, updated_at = {} \
                     WHERE extent_id IN ({})",
                    at(rng, hour),
                    list(&keys)
                )
            } else {
                format!(
                    "UPDATE outbox SET last_error = {error}, updated_at = {} WHERE extent_id IN ({})",
                    at(rng, hour),
                    list(&keys)
                )
            }
        }
        11 => {
            let keys = rng.some(extents, 6);
            match rng.below(3) {
                0 => format!(
                    "UPDATE outbox SET updated_at = {} WHERE extent_id IN ({})",
                    at(rng, hour),
                    list(&keys)
                ),
                1 => format!("DELETE FROM outbox WHERE extent_id IN ({})", list(&keys)),
                _ => format!(
                    "UPDATE outbox SET attempts = attempts + 1 WHERE extent_id IN ({})",
                    list(&keys)
                ),
            }
        }
        12 => {
            let keys = rng.some(gens, 6);
            let values: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "('{k}',{},'{k}',{},{},'e','{{}}','{{}}',0,0)",
                        rng.pick(&BUCKETS),
                        rng.pick(&GEN_STATES[..2]),
                        1 + rng.below(1000)
                    )
                })
                .collect();
            format!(
                "INSERT INTO generations(id,bucket_id,key,state,size,etag,content_json,user_meta_json,\
                   extent_count,created_at) VALUES {} ON CONFLICT DO NOTHING",
                values.join(",")
            )
        }
        13 | 14 => {
            let keys = rng.some(gens, 6);
            let state = case(rng, "id", &keys, &GEN_STATES[..2], "state");
            let sizes: Vec<String> = (0..2).map(|_| (1 + rng.below(1000)).to_string()).collect();
            let sizes: Vec<&str> = sizes.iter().map(String::as_str).chain(["size"]).collect();
            let size = case(rng, "id", &keys, &sizes, "size");
            let bucket = case(
                rng,
                "id",
                &keys,
                &[BUCKETS[0], BUCKETS[1], BUCKETS[2], "bucket_id"],
                "bucket_id",
            );
            format!(
                "UPDATE generations SET state = {state}, size = {size}, bucket_id = {bucket} WHERE id IN ({})",
                list(&keys)
            )
        }
        15 => {
            let keys = rng.some(gens, 6);
            if rng.chance(50) {
                format!("DELETE FROM generations WHERE id IN ({})", list(&keys))
            } else {
                format!(
                    "UPDATE generations SET state = 'deleted', retired_at = 1 WHERE id IN ({})",
                    list(&keys)
                )
            }
        }
        _ => {
            // A recount moving row 2's cursors, or the counters switched
            // off and on; zero-row statements of every kind.
            let cursor = |rng: &mut Rng, keys: &[String]| {
                let key = rng.pick(keys).clone();
                match rng.below(3) {
                    0 => key,
                    1 => format!("{key}~"),
                    _ => String::new(),
                }
            };
            match rng.below(5) {
                0 => format!(
                    "UPDATE usage_global SET cur_x = '{}', cur_o = '{}', cur_g = '{}' WHERE id = 2",
                    cursor(rng, extents),
                    cursor(rng, extents),
                    cursor(rng, gens)
                ),
                1 => format!(
                    "UPDATE usage_global SET all_x = {0}, all_o = {0}, all_g = {0} WHERE id = 2",
                    rng.below(2)
                ),
                2 => format!("UPDATE usage_global SET all_o = {} WHERE id = 1", rng.below(2)),
                3 => format!(
                    "UPDATE outbox SET stage = 'dead', last_error = 'x', updated_at = {} WHERE extent_id = 'none'",
                    at(rng, hour)
                ),
                _ => "UPDATE extents SET safety_state = 'deleted' WHERE id = 'none'; \
                      DELETE FROM generations WHERE id = 'none'"
                    .to_owned(),
            }
        }
    }
}

#[tokio::test]
async fn statement_counters_equal_row_counters_after_every_statement() {
    if !TestSql::postgres_selected() {
        return;
    }
    // Byte order differs from linguistic order across these keys.
    let extents: Vec<String> = [
        "eA", "eB", "eM", "eN", "ea", "eb", "em", "en", "ez", "eZ", "e_", "e0",
    ]
    .iter()
    .flat_map(|p| (0..2).map(move |i| format!("{p}{i}")))
    .collect();
    let gens: Vec<String> = ["gA", "gM", "ga", "gm", "gz", "g_"]
        .iter()
        .flat_map(|p| (0..2).map(move |i| format!("{p}{i}")))
        .collect();
    let seeds = std::env::var("VELMORA_TEST_USAGE_SEEDS").map_or(6u64, |v| {
        v.parse()
            .expect("VELMORA_TEST_USAGE_SEEDS must be a number")
    });
    assert!(seeds > 0, "VELMORA_TEST_USAGE_SEEDS must be at least 1");
    let mut statements = 0;
    for seed in 1..=seeds {
        let sqlite = RusqliteSql::with_schema().unwrap();
        let old = TestPostgres::through_stage(ROW_TRIGGERS, true).unwrap();
        let new = TestPostgres::through_stage(&stage_under_test(), true).unwrap();
        let (old_db, new_db) = (session(&old).await, session(&new).await);
        let setup = "INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,created_at) VALUES \
                     ('bA','bA','o',{B},1,0), ('ba','ba','o',{B},1,0), ('bm','bm','o',{B},1,0); \
                     UPDATE usage_global SET cur_x = 'eM0', cur_o = 'em1', cur_g = 'gM1' WHERE id = 2";
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ seed);
        // Start in hour 0 sometimes: a roll from hour 0 drops its counts.
        let mut hour = if seed % 2 == 0 { 0 } else { T0 / HOUR };
        let mut history = Vec::new();
        for step in 0..=150 {
            let sql = if step == 0 {
                setup.to_owned()
            } else {
                statement(&mut rng, &extents, &gens, &mut hour)
            };
            history.push(sql.clone());
            sqlite
                .apply(&sql.replace("{B}", "X''"))
                .unwrap_or_else(|e| panic!("seed {seed} step {step}: SQLite refused {sql}: {e:?}"));
            let pg_sql = sql.replace("{B}", "'\\x'::bytea");
            old_db
                .batch_execute(&pg_sql)
                .await
                .unwrap_or_else(|e| panic!("seed {seed} step {step}: {}", sqlstate(&sql, &e)));
            // The statement triggers write each usage row at most once per
            // statement, whatever the statement's row count.
            // Deltas within one transaction: the xact view also shows
            // counts of earlier transactions not yet flushed.
            exec(&new_db, "BEGIN").await;
            let before = usage_writes(&new_db).await;
            exec(&new_db, &pg_sql).await;
            let after = usage_writes(&new_db).await;
            exec(&new_db, "COMMIT").await;
            let writes = [0, 1, 2].map(|i| after[i] - before[i]);
            let n = 1 + sql.matches("; ").count() as i64;
            assert!(
                writes[0] <= 2 * n && writes[1] <= 2 * BUCKETS.len() as i64 * n && writes[2] <= n,
                "seed {seed} step {step}: usage writes {writes:?} for {sql}"
            );
            let expected = sqlite_snapshot(&sqlite).await;
            for (name, db) in [("per-row PG (0002)", &old_db), ("statement PG", &new_db)] {
                let actual = pg_snapshot(db).await;
                if actual != expected {
                    let tail = &history[history.len().saturating_sub(5)..];
                    panic!(
                        "seed {seed} step {step}: {name} differs from SQLite\nlast statements:\n{}\n\
                         SQLite: {expected:#?}\n{name}: {actual:#?}",
                        tail.join("\n")
                    );
                }
            }
            statements += 1;
        }
    }
    eprintln!(
        "usage equivalence: {statements} statements compared on SQLite, 0002 and {}",
        stage_under_test()
    );
}
