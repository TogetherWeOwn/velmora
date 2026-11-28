//! The single-Sync write transport without a server: the error classes by
//! statement position, the prelude, and the refusals that precede any I/O.

use super::batch::{message_error, prelude, prelude_statements};
use super::{PgConfig, PgConnect, PgConnection, PgSql, WriteTx};
use crate::{Sql, SqlValue, MAX_SQL_INT};

const BOTH: [WriteTx; 2] = [WriteTx::SingleSync, WriteTx::Pipeline];

#[test]
fn refused_values_are_refused_identically_by_both_transports_without_io() {
    struct MustNotConnect;
    impl PgConnect for MustNotConnect {
        async fn connect(&self) -> crate::Result<PgConnection> {
            panic!("validation must precede I/O")
        }
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    for write_tx in BOTH {
        let pg = PgSql::new(
            MustNotConnect,
            MustNotConnect,
            PgConfig {
                write_tx,
                ..PgConfig::default()
            },
        );
        let refuse = |value: SqlValue| {
            let r = rt.block_on(pg.exec("INSERT INTO t VALUES (?1)", &[value]));
            format!("{:?}", r.unwrap_err())
        };
        for edge in [MAX_SQL_INT + 1, -MAX_SQL_INT - 1, i64::MIN, i64::MAX] {
            assert_eq!(
                refuse(SqlValue::Int(edge)),
                "Sql(\"pg: integer outside JS safe range\")",
                "{write_tx:?} {edge}"
            );
        }
        assert_eq!(
            refuse(SqlValue::Text("a\0b".into())),
            "Invalid(\"catalog: text contains NUL\")"
        );
    }
}

#[test]
fn the_prelude_statement_count_matches_the_prelude() {
    for key in [Some(7_413_000_001), None] {
        let statements = prelude(key).split("; ").count();
        assert_eq!(prelude_statements(key), statements);
    }
    assert_eq!(prelude_statements(Some(1)), 6);
    assert_eq!(prelude_statements(None), 5);
    // The prelude keeps bind parameter values out of the server's error
    // messages (a constraint error's DETAIL is a separate, pinned matter:
    // tests/pg-secret-row-writes.txt).
    assert!(prelude(Some(1)).contains("SET LOCAL log_parameter_max_length_on_error = 0"));
}

#[test]
fn errors_are_classed_by_statement_position() {
    let failed = "Sql(\"pg: statement failed\")";
    let over = "Sql(\"pg: overloaded\")";
    let guard = "GuardFailed";
    let constraint = "Sql(\"pg: constraint violation\")";
    let (p, n) = (6, 3);
    // With the server's ReadyForQuery E after the error, as it sends it.
    let class = |code: Option<(&str, Option<&str>)>, done| {
        format!("{:?}", message_error(code, done, p, n, Some(b'E')))
    };
    let tx_guard = Some(("23514", Some("tx_guard_ok")));
    // A catalogue statement: P <= index < P + n.
    for done in p..p + n {
        assert_eq!(class(tx_guard, done), guard);
        assert_eq!(class(Some(("23505", None)), done), constraint);
        assert_eq!(class(Some(("VL001", None)), done), constraint);
        for code in ["55P03", "57014", "40001", "40P01"] {
            assert_eq!(class(Some((code, None)), done), over, "{code}");
        }
        for code in [
            "22P02", "25006", "42601", "53300", "53400", "08006", "08P01", "XX000", "58000",
            "P0001",
        ] {
            assert_eq!(class(Some((code, None)), done), failed, "{code}");
        }
        assert_eq!(class(None, done), failed);
    }
    // A prelude statement after BEGIN: never a guard.
    for done in 1..p {
        assert_eq!(class(tx_guard, done), failed);
        assert_eq!(class(Some(("55P03", None)), done), over);
        assert_eq!(class(Some(("58000", None)), done), failed);
    }
    // The COMMIT position and beyond: always unknown.
    for done in [p + n, p + n + 1] {
        for code in [
            tx_guard,
            Some(("23505", None)),
            Some(("VL001", None)),
            Some(("57014", None)),
            Some(("40001", None)),
        ] {
            assert_eq!(class(code, done), failed);
        }
    }
    // Without ReadyForQuery E (none, or idle) nothing is a known refusal:
    // the server may have run the rest, COMMIT included.
    for status in [None, Some(b'I'), Some(b'T')] {
        for done in 1..p + n {
            for code in [
                tx_guard,
                Some(("23505", None)),
                Some(("55P03", None)),
                Some(("57014", None)),
            ] {
                assert_eq!(
                    format!("{:?}", message_error(code, done, p, n, status)),
                    failed,
                    "{status:?} {done} {code:?}"
                );
            }
        }
    }
    // BEGIN itself: a pooler's 58000 may follow forwarding.
    for code in [
        Some(("58000", None)),
        Some(("55P03", None)),
        tx_guard,
        Some(("08006", None)),
        None,
    ] {
        assert_eq!(class(code, 0), failed);
    }
}

#[test]
fn no_log_record_is_compiled_in() {
    // The driver debug-logs simple queries and extended-protocol
    // parameters, which carry catalogue values.
    assert_eq!(log::STATIC_MAX_LEVEL, log::LevelFilter::Off);
}

#[test]
fn the_switch_has_two_values() {
    assert_eq!(WriteTx::parse(None), Ok(WriteTx::SingleSync));
    assert_eq!(WriteTx::parse(Some("single-sync")), Ok(WriteTx::SingleSync));
    assert_eq!(WriteTx::parse(Some("pipeline")), Ok(WriteTx::Pipeline));
    for old in ["0", "1", "message", "sequential"] {
        assert!(WriteTx::parse(Some(old)).is_err());
    }
}
