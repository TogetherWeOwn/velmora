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
fn frozen_d1_comment_handling_matches_sqlite() {
    use rusqlite::{fallible_iterator::FallibleIterator, Batch, Connection};

    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE items (n INTEGER)").unwrap();

    let cases = [
        ("/* /* */ SELECT 1", true),
        ("/* /* */ DELETE FROM items -- */", false),
        ("SELECT 1 /* /* */; DELETE FROM items -- */", false),
        ("SELECT 1 /* /* */ DELETE FROM items */", false),
        ("SELECT 1 /* unfinished ; DELETE FROM items", true),
        ("SELECT 1 /*/ ; DELETE FROM items", true),
        ("SELECT 1 /*", false),
        ("SELECT 1; /*", false),
        ("/* only a comment", false),
        ("SELECT 'it''s /* not a comment */ -- ; DELETE'", true),
        (r#"SELECT 1 AS "a""/* -- ; DELETE""#, true),
        ("SELECT 1 AS `a``/* -- ; DELETE`", true),
        ("SELECT 1 AS [a/* -- ; DELETE]", true),
        ("SELECT 1 AS [a--] ; DELETE FROM items", false),
        ("SELECT 1 AS `a/*` ; DELETE FROM items", false),
        ("SELECT 1 AS [unterminated", false),
        ("SELECT 1 AS `unterminated", false),
        ("SELECT 1 -- ; DELETE FROM items", true),
        ("SELECT 1 -- comment\r ; DELETE FROM items", true),
        ("SELECT 1 -- comment\r\n ; DELETE FROM items", false),
        ("SELECT 1; /* trailing */ -- trailing", true),
        ("SELECT 1; /* between */ SELECT 2", false),
        (
            "SELECT $$; /* between */ DELETE FROM items WHERE n = $$",
            false,
        ),
        ("SELECT :arg(--); DELETE FROM items", false),
        ("SELECT $1(/*); DELETE FROM items", false),
        (
            "WITH x AS (SELECT 1) \u{FEFF}INSERT \u{FEFF}INTO items SELECT 1",
            false,
        ),
        ("SELECT \u{00E9}", false),
        ("SELECT name\u{00E9}", false),
        ("SELECT '\u{00E9}' AS [\u{00E9}] /* \u{FEFF} */", true),
        ("SELECT (1", false),
        ("SELECT 1)", false),
    ];

    let mut mismatches = Vec::new();
    for (sql, expected) in cases {
        // Batch follows sqlite3_prepare's tail instead of silently ignoring it.
        // The freeze allows exactly one statement, and only if it is read-only.
        let mut batch = Batch::new(&db, sql);
        let sqlite = matches!(batch.next(), Ok(Some(stmt)) if stmt.readonly())
            && matches!(batch.next(), Ok(None));
        assert_eq!(sqlite, expected, "SQLite fixture: {sql:?}");
        let guard = super::is_read_only(sql);
        if guard != sqlite {
            mismatches.push(format!("{sql:?}: guard={guard}, SQLite={sqlite}"));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn frozen_d1_refuses_named_binds_in_a_single_read() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    let sql = "SELECT :arg(--)";
    let stmt = db.prepare(sql).unwrap();
    assert!(stmt.readonly());
    assert_eq!(stmt.parameter_count(), 1);
    assert!(!super::is_read_only(sql));
    assert!(super::is_read_only("SELECT ?1"));
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
    for code in ["22021", "22P02", "25006", "42601", "08006"] {
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
            Err(BridgeError::Sql("pg: overloaded".into()))
        }
    })
    .await;
    assert!(sent.get());
    assert!(matches!(result, Err(BridgeError::Sql(e)) if e=="pg: statement failed"));
}

#[test]
fn escape_string_literals_are_not_catalogue_sql() {
    for sql in [r"SELECT E'\n'", r"SELECT e'\t'", r"SELECT 'ordinary' e'\n'"] {
        assert!(
            matches!(statement(sql), Err(BridgeError::Sql(e)) if e=="pg: untranslated statement"),
            "{sql}"
        );
    }
    assert!(statement("SELECT 'E''ordinary', \"e\" /* E'comment' */").is_ok());
}

#[tokio::test]
async fn a_wire_success_after_the_first_failure_is_never_a_known_refusal() {
    use super::batch::pipeline;
    use futures_util::future::poll_fn;
    use std::task::Poll;
    let step = |r| {
        let mut first = true;
        let mut answer = Some(r);
        poll_fn(move |cx| {
            if std::mem::take(&mut first) {
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(answer.take().unwrap())
            }
        })
    };
    let guard = step(Err(BridgeError::GuardFailed));
    let successful_stmt = step(Ok(()));
    let result = pipeline(async { Ok(()) }, vec![guard, successful_stmt], |_| async {
        Ok(())
    })
    .await;
    assert!(matches!(result, Err(BridgeError::Sql(e)) if e=="pg: statement failed"));
}

#[tokio::test]
async fn drops_unread_prelude_before_attempting_rollback() {
    use super::batch::pipeline;
    use std::cell::Cell;
    struct ReplyDropped<'a>(&'a Cell<bool>);
    impl Drop for ReplyDropped<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    let dropped = &Cell::new(false);
    let prelude = async {
        let _rx = ReplyDropped(dropped);
        std::future::pending::<crate::Result<()>>().await
    };
    let error = async { Err::<(), _>(super::error::statement_failed()) };
    let result = pipeline(prelude, vec![error], |committing| async move {
        assert!(!committing);
        assert!(
            dropped.get(),
            "rollback queued while unread prelude reply still owned"
        );
        Ok(())
    })
    .await;
    assert!(result.is_err());
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

#[test]
fn sql_futures_do_not_embed_the_connection_handshake() {
    use super::{PgConfig, PgConnect, PgConnection, PgSql};
    struct LargeHandshake;
    impl PgConnect for LargeHandshake {
        async fn connect(&self) -> crate::Result<PgConnection> {
            let handshake = [0_u8; 4096];
            futures_util::future::pending::<()>().await;
            std::hint::black_box(handshake);
            unreachable!()
        }
    }
    let pg = PgSql::new(LargeHandshake, LargeHandshake, PgConfig::default());
    let read = std::mem::size_of_val(&pg.query("SELECT 1", &[]));
    let write = std::mem::size_of_val(&pg.batch(vec![]));
    assert!(
        read < 4096 && write < 4096,
        "read future {read}, write future {write}"
    );
}
