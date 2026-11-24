use super::params::{statement, Kind};
use crate::{BridgeError, Dialect, Sql};

#[test]
fn dialect_keeps_static_statement_pairs() {
    fn sqlite_default<S: Sql>(sql: &S) -> Dialect {
        sql.dialect()
    }
    let _: fn(&crate::testkit::RusqliteSql) -> Dialect = sqlite_default;
    assert_eq!(Dialect::Sqlite.pick("sqlite", "pg"), "sqlite");
    assert_eq!(Dialect::Postgres.pick("sqlite", "pg"), "pg");
}

#[test]
fn rewrite_preserves_literals_comments_and_repeated_ordinals() {
    let sql = "SELECT ?1, ?10, ?1, '?2''?', \"?4\", $$?55$$ /* ?6 /* ?7 */ */ -- ?8\n";
    let got = statement(sql).unwrap();
    assert_eq!(got.text, sql.replacen("?1, ?10, ?1", "$1, $10, $1", 1));
    assert_eq!(
        statement("SELECT ?, ?, ?").unwrap().text,
        "SELECT $1, $2, $3"
    );
    assert_eq!(
        statement("SELECT $1, ?2, ?").unwrap().text,
        "SELECT $1, $2, $3"
    );
}

#[test]
fn refuses_untranslated_sqlite_syntax_only_in_code() {
    for sql in [
        "INSERT OR /* comment */ IGNORE INTO x VALUES (?1)",
        "INSERT OR REPLACE INTO x VALUES (?1)",
        "SELECT json_each(?1)",
        "SELECT json_extract(?1)",
        "SELECT json_object (?1)",
        "SELECT * FROM x INDEXED BY i",
        "SELECT rowid FROM x",
        "SELECT typeof (?1)",
        "SELECT quote(?1)",
        "SELECT a GLOB 'x'",
        "SELECT instr(?1, ?2)",
        "SELECT * FROM sqlite_master",
        "SELECT printf(?1)",
        "SELECT strftime(?1)",
    ] {
        assert!(
            matches!(statement(sql), Err(BridgeError::Sql(e)) if e == "pg: untranslated statement"),
            "{sql}"
        );
    }
    assert!(
        statement("SELECT 'OR IGNORE', /* sqlite_master */ rowid_alias, current_schema()").is_ok()
    );
}

#[test]
fn only_read_statements_take_read_path() {
    assert_eq!(
        statement("/* UPDATE */ SELECT 'DELETE' AS name")
            .unwrap()
            .kind,
        Kind::Read
    );
    assert_eq!(
        statement("WITH v AS (SELECT 1) SELECT * FROM v")
            .unwrap()
            .kind,
        Kind::Read
    );
    for sql in [
        "UPDATE x SET n=1 RETURNING n",
        "WITH v AS (DELETE FROM x RETURNING *) SELECT * FROM v",
        "SELECT nextval('s')",
        "SELECT n FROM x FOR SHARE",
        "SELECT \"nextval\"('s')",
    ] {
        assert_eq!(statement(sql).unwrap().kind, Kind::Write, "{sql}");
    }
    assert!(statement("SELECT 1; COMMIT").is_err());
    assert!(super::is_read_only("SELECT name FROM sqlite_master"));
    assert!(!super::is_read_only(
        "WITH v AS (DELETE FROM x RETURNING *) SELECT * FROM v"
    ));
}

#[test]
fn bound_values_are_validated_before_connection() {
    use crate::{SqlValue, MAX_SQL_INT, MAX_SQL_PARAMS, MAX_SQL_VALUE_BYTES};
    for v in [MAX_SQL_INT, -MAX_SQL_INT] {
        assert!(super::value::Params::encode(&[SqlValue::Int(v)]).is_ok());
    }
    for v in [MAX_SQL_INT + 1, -MAX_SQL_INT - 1, i64::MIN, i64::MAX] {
        assert!(
            matches!(super::value::Params::encode(&[SqlValue::Int(v)]), Err(BridgeError::Sql(e)) if e == "pg: integer outside JS safe range")
        );
    }
    assert!(matches!(
        super::value::Params::encode(&[SqlValue::Text("upload\0id".into())]),
        Err(BridgeError::Invalid("catalog: text contains NUL"))
    ));
    assert!(super::value::Params::encode(&vec![SqlValue::Null; MAX_SQL_PARAMS + 1]).is_err());
    assert!(
        super::value::Params::encode(&[SqlValue::Blob(vec![0; MAX_SQL_VALUE_BYTES + 1])]).is_err()
    );
    assert_eq!(
        super::value::Params::encode(&[
            SqlValue::Text(String::new()),
            SqlValue::Blob(vec![]),
            SqlValue::Null
        ])
        .unwrap()
        .oids()
        .collect::<Vec<_>>(),
        vec![25, 17, 705]
    );
}

#[test]
fn numeric_accepts_only_finite_integral_i64_values() {
    fn raw(weight: i16, sign: u16, digits: &[u16]) -> Vec<u8> {
        [digits.len() as u16, weight as u16, sign, 4]
            .into_iter()
            .chain(digits.iter().copied())
            .flat_map(u16::to_be_bytes)
            .collect()
    }
    let numeric = super::value::numeric;
    assert_eq!(numeric(&raw(0, 0, &[42, 0])), Some(42));
    assert_eq!(
        numeric(&raw(4, 0, &[922, 3372, 368, 5477, 5807])),
        Some(i64::MAX)
    );
    assert_eq!(
        numeric(&raw(4, 0x4000, &[922, 3372, 368, 5477, 5808])),
        Some(i64::MIN)
    );
    assert_eq!(numeric(&raw(4, 0, &[922, 3372, 368, 5477, 5808])), None);
    assert_eq!(numeric(&raw(0, 0, &[42, 1])), None);
    assert_eq!(numeric(&raw(0, 0xc000, &[])), None);
    assert_eq!(numeric(&raw(0, 0xd000, &[])), None);
    assert_eq!(numeric(&raw(0, 0, &[10_000])), None);
    assert_eq!(numeric(&[]), None);
}

#[test]
fn only_the_named_check_is_a_guard_refusal() {
    use super::error::classify;
    assert!(matches!(
        classify("23514", Some("tx_guard_ok")),
        BridgeError::GuardFailed
    ));
    for (code, constraint) in [
        ("23514", Some("other")),
        ("23514", None),
        ("23505", Some("tx_guard_ok")),
        ("23503", None),
        ("VL001", None),
    ] {
        assert!(
            matches!(classify(code,constraint), BridgeError::Sql(e) if e=="pg: constraint violation")
        );
    }
    for code in ["55P03", "57014", "53300", "53400", "40001", "40P01"] {
        assert!(matches!(classify(code,None), BridgeError::Sql(e) if e=="pg: overloaded"));
    }
    for code in ["22021", "22P02", "42601", "08006"] {
        assert!(matches!(classify(code,None), BridgeError::Sql(e) if e=="pg: statement failed"));
    }
}

#[tokio::test]
async fn pipeline_queues_all_or_rolls_back_without_commit() {
    use super::batch::pipeline;
    use futures_util::future::poll_fn;
    use std::cell::RefCell;
    use std::task::Poll;
    let trace = RefCell::new(Vec::new());
    let pending_step = |name, answer| {
        let trace = &trace;
        let mut answer = Some(answer);
        let mut first = true;
        poll_fn(move |cx| {
            if first {
                first = false;
                trace.borrow_mut().push(name);
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(answer.take().unwrap())
            }
        })
    };
    let finish = |commit| {
        let trace = &trace;
        async move {
            trace
                .borrow_mut()
                .push(if commit { "commit" } else { "rollback" });
            Ok(())
        }
    };
    let fail = BridgeError::Sql("pg: statement failed".into());
    let result = pipeline(
        pending_step("begin", Ok(())),
        vec![
            pending_step("one", Ok(())),
            pending_step("two", Err(BridgeError::GuardFailed)),
            pending_step("three", Err(fail)),
        ],
        finish,
    )
    .await;
    assert!(matches!(result, Err(BridgeError::GuardFailed)));
    assert_eq!(*trace.borrow(), ["begin", "one", "two", "three", "commit"]);
    trace.borrow_mut().clear();
    let mut first = true;
    let ok = poll_fn(|cx| {
        if std::mem::take(&mut first) {
            trace.borrow_mut().push("one");
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    });
    let encode_err = poll_fn(|_| {
        trace.borrow_mut().push("encode_error");
        Poll::Ready(Err(BridgeError::Sql("pg: statement failed".into())))
    });
    let stmts: Vec<core::pin::Pin<Box<dyn core::future::Future<Output = crate::Result<()>>>>> =
        vec![Box::pin(ok), Box::pin(encode_err)];
    assert!(pipeline(pending_step("begin", Ok(())), stmts, finish)
        .await
        .is_err());
    assert_eq!(
        *trace.borrow(),
        ["begin", "one", "encode_error", "rollback"]
    );
}

#[tokio::test]
async fn pipeline_commit_reply_loss_is_not_a_guard_failure() {
    use super::batch::pipeline;
    use std::cell::Cell;
    let sent = Cell::new(false);
    let result = pipeline(async { Ok(()) }, vec![async { Ok(1) }], |commit| {
        let sent = &sent;
        async move {
            sent.set(commit);
            Err(super::error::statement_failed())
        }
    })
    .await;
    assert!(sent.get());
    assert!(matches!(result, Err(BridgeError::Sql(e)) if e=="pg: statement failed"));
}

#[tokio::test]
async fn unusable_sql_and_nul_are_refused_without_opening_a_connection() {
    use super::{PgConfig, PgConnect, PgConnection, PgSql};
    use crate::SqlValue;
    struct MustNotConnect;
    impl PgConnect for MustNotConnect {
        async fn connect(&self) -> crate::Result<PgConnection> {
            panic!("validation must precede I/O")
        }
    }
    let pg = PgSql::new(MustNotConnect, MustNotConnect, PgConfig::default());
    assert!(pg.batch(vec![]).await.unwrap().is_empty());
    let r = pg
        .batch(vec![
            ("INSERT INTO obj VALUES (?1)", vec![SqlValue::Int(1)]),
            ("SELECT ?1", vec![SqlValue::Text("access\0key".into())]),
        ])
        .await;
    assert!(matches!(
        r,
        Err(BridgeError::Invalid("catalog: text contains NUL"))
    ));
    assert!(
        matches!(pg.query("SELECT json_extract(?1)",&[SqlValue::Int(1)]).await,Err(BridgeError::Sql(e)) if e=="pg: untranslated statement")
    );
}
