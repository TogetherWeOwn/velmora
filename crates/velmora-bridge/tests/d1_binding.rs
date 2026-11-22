//! The D1 adapter binds every integer as its decimal text through
//! `+CAST(?N AS INTEGER)` (`sql_bind::cast_bound`). Here each statement
//! runs twice on the native database: once with the integers bound
//! natively, once as the D1 adapter gives them. The answers must be the
//! same, and an integer above 2^53 must be stored exactly.
//!
//! Under `workers/unit-suite/run-suite.sh` every call here is also asked
//! of a Durable Object and compared; no value read back here is outside
//! `±(2^53 - 1)`, which a JS number cannot hold.

use velmora_bridge::sql_bind::cast_bound;
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::{Sql, SqlValue};

const ABOVE_2_53: i64 = (1 << 53) + 1;

fn int(i: i64) -> SqlValue {
    SqlValue::Int(i)
}

fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.into())
}

fn db() -> RusqliteSql {
    let db = RusqliteSql::open_in_memory().unwrap();
    db.apply(
        "CREATE TABLE t (n INTEGER, s TEXT, u, r REAL); \
         CREATE TABLE k (id INTEGER PRIMARY KEY, v INTEGER NOT NULL);",
    )
    .unwrap();
    db
}

/// The statement as the D1 adapter sends it: no `Int` is left.
fn as_d1(sql: &'static str, params: &[SqlValue]) -> (String, Vec<SqlValue>) {
    let (sql, values) = cast_bound(sql, params).unwrap();
    assert!(
        !values.iter().any(|v| matches!(v, SqlValue::Int(_))),
        "{sql}"
    );
    (sql.into_owned(), values)
}

async fn both(native: &RusqliteSql, d1: &RusqliteSql, sql: &'static str, params: &[SqlValue]) {
    let (cast, values) = as_d1(sql, params);
    if sql.trim_start().to_ascii_uppercase().starts_with("SELECT") {
        let want = native.query(sql, params).await.unwrap();
        let got = d1.query(&cast, &values).await.unwrap();
        assert_eq!(got, want, "{sql}");
    } else {
        let want = native.exec(sql, params).await.unwrap();
        let got = d1.exec(&cast, &values).await.unwrap();
        assert_eq!(got, want, "{sql}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn every_statement_answers_as_with_a_native_binding() {
    let (native, d1) = (db(), db());
    let cases: &[(&'static str, Vec<SqlValue>)] = &[
        (
            "INSERT INTO t (n, s, u, r) VALUES (?1, ?2, ?3, ?4)",
            vec![int(5), text("5"), int(7), int(2)],
        ),
        (
            "INSERT INTO t (n, s, u, r) VALUES (?, ?, ?, ?)",
            vec![int(-3), text("x"), text("8"), SqlValue::Null],
        ),
        (
            "INSERT INTO k (id, v) VALUES (?1, ?2)",
            vec![int(1), int(10)],
        ),
        (
            "INSERT INTO k (id, v) VALUES (?1, ?2)",
            vec![int(2), int(20)],
        ),
        (
            "UPDATE k SET v = v + ?1 WHERE id = ?2",
            vec![int(5), int(1)],
        ),
        (
            "SELECT typeof(?1), ?1 / 2, ?1 % 3, json_array(?1)",
            vec![int(5)],
        ),
        (
            "SELECT typeof(u), u, typeof(r), CAST(r AS TEXT), typeof(s) FROM t ORDER BY rowid",
            vec![],
        ),
        ("SELECT count(*) FROM t WHERE s = ?1", vec![int(5)]),
        (
            "SELECT count(*) FROM t WHERE n = ?1 AND u = ?2",
            vec![int(5), int(7)],
        ),
        (
            "SELECT id, v FROM k WHERE id IN (?1, ?2) ORDER BY id LIMIT ?3",
            vec![int(1), int(2), int(1)],
        ),
        (
            "SELECT id FROM k WHERE v > ?1 - ?2 ORDER BY id",
            vec![int(20), int(5)],
        ),
        (
            "SELECT max(v, ?1), coalesce(NULL, ?2), ?3 IS NULL FROM k ORDER BY id",
            vec![int(3), int(4), SqlValue::Null],
        ),
        ("DELETE FROM k WHERE id = ?1", vec![int(2)]),
        ("SELECT id, v FROM k ORDER BY id", vec![]),
    ];
    for (sql, params) in cases {
        both(&native, &d1, sql, params).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn an_integer_above_2_53_is_stored_exactly() {
    let d1 = db();
    for value in [ABOVE_2_53, -ABOVE_2_53, i64::MAX, i64::MIN] {
        let (sql, values) = as_d1("INSERT INTO t (n, u) VALUES (?1, ?1)", &[int(value)]);
        assert_eq!(d1.exec(&sql, &values).await.unwrap(), 1);
        let (sql, values) = as_d1(
            "SELECT typeof(n), typeof(u), CAST(n AS TEXT), CAST(u AS TEXT), n = ?1, u = ?1, \
             n - ?1 FROM t WHERE n = ?1",
            &[int(value)],
        );
        let rows = d1.query(&sql, &values).await.unwrap();
        assert_eq!(
            rows,
            vec![vec![
                text("integer"),
                text("integer"),
                text(&value.to_string()),
                text(&value.to_string()),
                int(1),
                int(1),
                int(0),
            ]],
            "{value}"
        );
    }
    // The neighbour that a JS number would have rounded it to is another
    // value.
    let (sql, values) = as_d1(
        "SELECT count(*) FROM t WHERE n = ?1",
        &[int(ABOVE_2_53 - 1)],
    );
    assert_eq!(d1.query(&sql, &values).await.unwrap(), vec![vec![int(0)]]);
}
