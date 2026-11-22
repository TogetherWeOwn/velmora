//! How a value is bound and read back, statement by statement, on the
//! native database. Run under `workers/unit-suite/run-suite.sh`, every
//! answer here is also asked of a Durable Object through `DoSql` and
//! compared, so this file is where a difference of binding between the
//! two engines shows (a JS number is a REAL in the object unless the
//! adapter casts it; a bare cast gives it an affinity a native integer
//! has not).

use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::{BridgeError, Sql, SqlValue};

const MAX_SAFE: i64 = (1 << 53) - 1;

fn int(i: i64) -> SqlValue {
    SqlValue::Int(i)
}

fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.into())
}

fn db() -> RusqliteSql {
    let db = RusqliteSql::open_in_memory().unwrap();
    db.apply(
        "CREATE TABLE t (n INTEGER, s TEXT, u, b BLOB, CHECK (n IS NULL OR n >= 0)); \
         CREATE TABLE uq (k TEXT PRIMARY KEY); \
         CREATE TABLE tx_guard (ok INTEGER NOT NULL CHECK (ok = 1)); \
         CREATE TRIGGER t_no_99 BEFORE INSERT ON t WHEN NEW.n = 99 \
           BEGIN SELECT RAISE(ABORT, 'ninety-nine is refused'); END;",
    )
    .unwrap();
    db
}

async fn one(db: &RusqliteSql, sql: &str, params: &[SqlValue]) -> SqlValue {
    let rows = db.query(sql, params).await.unwrap();
    assert_eq!(rows.len(), 1, "{sql}");
    rows[0][0].clone()
}

async fn count(db: &RusqliteSql, sql: &str, params: &[SqlValue]) -> i64 {
    match one(db, sql, params).await {
        SqlValue::Int(n) => n,
        other => panic!("{sql}: {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn an_integer_is_bound_as_an_integer() {
    let db = db();
    assert_eq!(
        one(&db, "SELECT typeof(?1)", &[int(5)]).await,
        text("integer")
    );
    assert_eq!(one(&db, "SELECT ?1 / 2", &[int(5)]).await, int(2));
    assert_eq!(one(&db, "SELECT ?1 % 3", &[int(7)]).await, int(1));
    assert_eq!(
        one(&db, "SELECT json_array(?1)", &[int(5)]).await,
        text("[5]")
    );
    assert_eq!(
        one(&db, "SELECT CAST(?1 AS TEXT)", &[int(5)]).await,
        text("5")
    );
    assert_eq!(
        one(&db, "SELECT printf('%d', ?1)", &[int(5)]).await,
        text("5")
    );
    // Into a TEXT column an integer is stored as its digits.
    db.exec(
        "INSERT INTO t (n, s, u) VALUES (?1, ?2, ?3)",
        &[int(1), int(7), int(8)],
    )
    .await
    .unwrap();
    assert_eq!(one(&db, "SELECT s FROM t", &[]).await, text("7"));
    assert_eq!(
        one(&db, "SELECT typeof(u) FROM t", &[]).await,
        text("integer")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_integer_compares_without_an_affinity() {
    let db = db();
    db.apply("INSERT INTO t (n, s, u) VALUES (7, '07', '5')")
        .unwrap();
    // A native integer has no affinity: TEXT stays TEXT on the other side.
    assert_eq!(
        count(&db, "SELECT count(*) FROM t WHERE s = ?1", &[int(7)]).await,
        0
    );
    assert_eq!(
        count(&db, "SELECT count(*) FROM t WHERE u = ?1", &[int(5)]).await,
        0
    );
    assert_eq!(count(&db, "SELECT '5' = ?1", &[int(5)]).await, 0);
    assert_eq!(
        count(
            &db,
            "SELECT json_extract('{\"a\":\"5\"}', '$.a') = ?1",
            &[int(5)]
        )
        .await,
        0
    );
    // An INTEGER column gives its affinity to the other side.
    assert_eq!(
        count(&db, "SELECT count(*) FROM t WHERE n = ?1", &[int(7)]).await,
        1
    );
    assert_eq!(
        count(&db, "SELECT count(*) FROM t WHERE n = ?1", &[text("7")]).await,
        1
    );
    // Numbering: a bare `?` after `?2` is `?3`.
    assert_eq!(
        one(&db, "SELECT ?2 || ?1 || ?", &[int(1), int(2), int(3)]).await,
        text("213")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn values_read_back_as_they_were_bound() {
    let db = db();
    for v in [
        int(0),
        int(-1),
        int(MAX_SAFE),
        int(-MAX_SAFE),
        text(""),
        text("x\u{e9}\u{1f600}"),
        SqlValue::Null,
        SqlValue::Blob(Vec::new()),
        SqlValue::Blob(vec![0, 255, 1]),
    ] {
        assert_eq!(one(&db, "SELECT ?1", std::slice::from_ref(&v)).await, v);
    }
}

/// AM-22: ±(2^53 - 1) are the largest integers either adapter binds.
/// They are stored as SQLite INTEGER, in a column with no affinity too,
/// and read back exactly. (±2^53 and beyond are refused at bind by each
/// adapter: `d1.rs` and `do_sql.rs` unit tests. They are not bound here,
/// because the native database takes them and the twin would differ.)
#[tokio::test(flavor = "current_thread")]
async fn the_safe_integer_edges_are_stored_as_integer() {
    let db = db();
    for v in [MAX_SAFE, -MAX_SAFE] {
        db.exec("DELETE FROM t", &[]).await.unwrap();
        assert_eq!(
            db.exec("INSERT INTO t (u) VALUES (?1)", &[int(v)])
                .await
                .unwrap(),
            1
        );
        let rows = db
            .query(
                "SELECT typeof(u), u, CAST(u AS TEXT), u = ?1 FROM t",
                &[int(v)],
            )
            .await
            .unwrap();
        assert_eq!(
            rows,
            vec![vec![text("integer"), int(v), text(&v.to_string()), int(1)]],
            "{v}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rows_changed_count_trigger_free_and_returning_statements() {
    let db = db();
    let n = db
        .exec(
            "INSERT INTO t (n) VALUES (?1), (?2), (?3)",
            &[int(1), int(2), int(3)],
        )
        .await
        .unwrap();
    assert_eq!(n, 3);
    assert_eq!(
        db.exec("UPDATE t SET n = n + 1 WHERE n >= ?1", &[int(2)])
            .await
            .unwrap(),
        2
    );
    assert_eq!(db.exec("SELECT 1", &[]).await.unwrap(), 0);
    let rows = db
        .query("INSERT INTO t (n) VALUES (?1) RETURNING n", &[int(9)])
        .await
        .unwrap();
    assert_eq!(rows, vec![vec![int(9)]]);
}

#[tokio::test(flavor = "current_thread")]
async fn errors_keep_their_class() {
    let db = db();
    db.exec("INSERT INTO uq (k) VALUES ('a')", &[])
        .await
        .unwrap();
    // A constraint.
    let dup = db.exec("INSERT INTO uq (k) VALUES ('a')", &[]).await;
    assert!(matches!(dup, Err(BridgeError::Sql(_))));
    let check = db.exec("INSERT INTO t (n) VALUES (?1)", &[int(-1)]).await;
    assert!(matches!(check, Err(BridgeError::Sql(_))));
    // A trigger's RAISE: a statement failure, not a constraint.
    let raised = db.exec("INSERT INTO t (n) VALUES (?1)", &[int(99)]).await;
    assert!(matches!(raised, Err(BridgeError::Sql(_))));
    // A statement that does not parse.
    assert!(db.query("SELEC 1", &[]).await.is_err());
    // The guard.
    let guard = db
        .batch(vec![
            ("INSERT INTO uq (k) VALUES ('b')", vec![]),
            ("INSERT INTO tx_guard (ok) VALUES (0)", vec![]),
        ])
        .await;
    assert!(matches!(guard, Err(BridgeError::GuardFailed)));
    assert_eq!(
        count(&db, "SELECT count(*) FROM uq", &[]).await,
        1,
        "rolled back"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_batch_is_all_or_nothing() {
    let db = db();
    let failed = db
        .batch(vec![
            ("INSERT INTO t (n) VALUES (?1)", vec![int(1)]),
            ("INSERT INTO t (n) VALUES (?1)", vec![int(-5)]),
        ])
        .await;
    assert!(failed.is_err());
    assert_eq!(count(&db, "SELECT count(*) FROM t", &[]).await, 0);
    let ok = db
        .batch(vec![
            ("INSERT INTO t (n) VALUES (?1)", vec![int(1)]),
            ("UPDATE t SET n = ?1", vec![int(2)]),
        ])
        .await
        .unwrap();
    assert_eq!(ok, vec![1, 1]);
}
