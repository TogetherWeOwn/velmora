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
        "SELECT 1; COMMIT",
    ] {
        match statement(sql) {
            Ok(stmt) => assert_eq!(stmt.kind, Kind::Write, "{sql}"),
            Err(BridgeError::Sql(_)) => (),
            Err(e) => panic!("{e:?}"),
        }
    }
}
