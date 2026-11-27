//! Verify every catalogue PG statement parses with the adapter's wire types,
//! then compare the manifest with statements the real PG suite executed.

#![cfg(all(feature = "testkit-pg", feature = "pg-test-record"))]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio_postgres::types::Type;
use velmora_bridge::pg::normalize_statement;
use velmora_bridge::sql::{pg_background_statements, pg_datapath_statements};
use velmora_bridge::testkit::{TestPostgres, TestSql};
use velmora_bridge::{Sql, SqlValue};

const COVERAGE_DIR: &str = "VELMORA_PG_STATEMENTS_DIR";
const UNEXECUTED: &str = include_str!("pg-unexecuted.txt");

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct Statement {
    sql: String,
    parameter_oids: Vec<u32>,
}

fn oid(value: &SqlValue) -> u32 {
    match value {
        SqlValue::Null => Type::UNKNOWN.oid(),
        SqlValue::Int(_) => Type::INT8.oid(),
        SqlValue::Text(_) => Type::TEXT.oid(),
        SqlValue::Blob(_) => Type::BYTEA.oid(),
    }
}

fn manifest() -> BTreeSet<Statement> {
    pg_datapath_statements()
        .into_iter()
        .map(|(sql, params)| (sql.to_owned(), params))
        .chain(pg_background_statements())
        .map(|(raw, params)| Statement {
            sql: normalize_statement(&raw)
                .unwrap_or_else(|error| panic!("invalid enumerated catalogue SQL: {error}: {raw}")),
            parameter_oids: params.iter().map(oid).collect(),
        })
        .collect()
}

fn executed(dir: &Path) -> BTreeSet<Statement> {
    let mut out = BTreeSet::new();
    for entry in fs::read_dir(dir).expect("read statement recording directory") {
        let path = entry.expect("read statement recording entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        let file = fs::File::open(path).expect("open statement recording");
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line = line.expect("read statement recording line");
            // Do not echo an invalid recorder line into CI output.
            let statement: Statement = serde_json::from_str(&line)
                .unwrap_or_else(|_| panic!("invalid statement recording at line {}", index + 1));
            out.insert(statement);
        }
    }
    out
}

fn fingerprint(sql: &str) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(sql.as_bytes()) {
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    hex
}

fn exceptions(input: &str) -> BTreeMap<&str, &str> {
    let mut entries = BTreeMap::new();
    for line in input.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (hash, reason) = line.split_once(' ').expect("expected SHA-256 then reason");
        assert!(hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!reason.trim().is_empty(), "missing reason for {hash}");
        assert!(
            entries.insert(hash, reason.trim()).is_none(),
            "duplicate exception {hash}"
        );
    }
    entries
}

fn compare<'a>(
    declared: &BTreeSet<&'a str>,
    observed: &BTreeSet<&'a str>,
    exceptions: &BTreeMap<&str, &str>,
) -> Vec<String> {
    let missing: BTreeMap<_, _> = declared
        .difference(observed)
        .map(|sql| (fingerprint(sql), sql))
        .collect();
    let mut errors: Vec<_> = observed
        .difference(declared)
        .map(|sql| format!("executed but not enumerated: {sql}"))
        .collect();
    errors.extend(
        missing
            .iter()
            .filter(|(hash, _)| !exceptions.contains_key(hash.as_str()))
            .map(|(hash, sql)| format!("not executed ({hash}): {sql}")),
    );
    errors.extend(
        exceptions
            .keys()
            .filter(|hash| !missing.contains_key(**hash))
            .map(|hash| format!("stale unexecuted SQL exception: {hash}")),
    );
    errors
}

async fn prepare(client: &tokio_postgres::Client, statement: &Statement) -> Result<(), String> {
    let types: Vec<_> = statement
        .parameter_oids
        .iter()
        .map(|&oid| Type::from_oid(oid).unwrap_or_else(|| panic!("unexpected bind OID {oid}")))
        .collect();
    let prepared = client
        .prepare_typed(&statement.sql, &types)
        .await
        .map_err(|error| {
            let code = error.code().map_or("no SQLSTATE", |code| code.code());
            format!(
                "cannot prepare catalogue SQL ({code}), OIDs {:?}: {}",
                statement.parameter_oids, statement.sql
            )
        })?;
    let actual: Vec<_> = prepared.params().iter().map(Type::oid).collect();
    // The extended protocol uses OID 705 for NULLs so PostgreSQL infers the
    // column/expression type at that position. Every concrete bind must
    // match, and inferred parameters may never fill in missing entries.
    if actual.len() != statement.parameter_oids.len()
        || statement
            .parameter_oids
            .iter()
            .zip(&actual)
            .any(|(&declared, &reported)| declared != Type::UNKNOWN.oid() && declared != reported)
    {
        return Err(format!("catalogue SQL parameter signature mismatch: declared {:?}, PostgreSQL reported {actual:?}: {}", statement.parameter_oids, statement.sql));
    }
    Ok(())
}

async fn prepare_all(statements: &BTreeSet<Statement>) {
    let db = TestSql::with_schema_unrecorded().expect("Postgres statement test catalogue");
    let client = db
        .postgres()
        .expect("Postgres selected")
        .client()
        .await
        .unwrap();
    let mut errors = Vec::new();
    for statement in statements {
        if let Err(error) = prepare(&client, statement).await {
            errors.push(error);
        }
    }
    assert!(
        errors.is_empty(),
        "typed PostgreSQL catalogue PREPARE:\n{}",
        errors.join("\n")
    );
}

#[tokio::test]
async fn prepare_rejects_an_omitted_parameter_postgres_can_infer() {
    if !TestSql::postgres_selected() {
        return;
    }
    let db = TestSql::with_schema_unrecorded().unwrap();
    let client = db.postgres().unwrap().client().await.unwrap();
    let mut statement = Statement {
        sql: "SELECT $1::bigint, $2::text".into(),
        parameter_oids: vec![Type::INT8.oid()],
    };
    let error = prepare(&client, &statement).await.unwrap_err();
    assert!(
        error.contains("declared [20], PostgreSQL reported [20, 25]"),
        "{error}"
    );
    statement.parameter_oids.push(Type::UNKNOWN.oid());
    prepare(&client, &statement).await.unwrap();
}

#[tokio::test]
async fn postgres_testkit_reuses_a_session_without_its_state() {
    if !TestSql::postgres_selected() {
        return;
    }
    let db = TestSql::with_schema_unrecorded().unwrap();
    let lock_key = db.postgres_lock_key().unwrap();
    db.fixture_script(&format!(
        "CREATE TABLE testkit_session_probe (id bigint PRIMARY KEY);
         CREATE FUNCTION testkit_dirty_session() RETURNS bigint LANGUAGE plpgsql AS $$
         BEGIN
             PERFORM set_config('application_name', 'dirty testkit session', false);
             PERFORM pg_advisory_lock({lock_key}::bigint);
             RETURN pg_backend_pid();
         END;
         $$;"
    ))
    .unwrap();
    let probe = "SELECT pg_backend_pid(), current_setting('application_name'),
                 EXISTS (SELECT 1 FROM pg_locks
                         WHERE locktype = 'advisory' AND pid = pg_backend_pid()),
                 (SELECT count(*) FROM testkit_session_probe)";
    let fresh = db.query(probe, &[]).await.unwrap();
    let dirty = db
        .query(
            "INSERT INTO testkit_session_probe VALUES (1) RETURNING testkit_dirty_session()",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(dirty[0][0], fresh[0][0], "write should reuse the session");
    let reset = db.query(probe, &[]).await.unwrap();
    assert_eq!(reset[0][0], fresh[0][0], "read should reuse the session");
    assert!(reset[0][1] == fresh[0][1], "application_name was not reset");
    assert_eq!(reset[0][2], SqlValue::Int(0), "session lock was not reset");
    assert_eq!(reset[0][3], SqlValue::Int(1), "write should be committed");
}

#[tokio::test]
async fn postgres_testkit_does_not_reuse_a_failed_write_session() {
    if !TestSql::postgres_selected() {
        return;
    }
    let db = TestSql::with_schema_unrecorded().unwrap();
    db.fixture_script("CREATE TABLE testkit_error_probe (id bigint PRIMARY KEY); INSERT INTO testkit_error_probe VALUES (1);")
        .unwrap();
    let pid = "SELECT pg_backend_pid()";
    let before = db.query(pid, &[]).await.unwrap();
    assert!(db
        .exec("INSERT INTO testkit_error_probe VALUES (1)", &[])
        .await
        .is_err());
    let after = db.query(pid, &[]).await.unwrap();
    assert_ne!(before, after, "a failed write must retire the session");
}

#[tokio::test]
async fn postgres_testkit_preserves_private_type_lookup_statements() {
    if !TestSql::postgres_selected() {
        return;
    }
    // Type lookups happen on the one-Sync-per-statement transport only: the
    // single-Sync transport takes column types from the built-in table.
    let db = TestSql::Postgres(Box::new(TestPostgres::with_typed_writes().unwrap()));
    db.fixture_script(
        "CREATE TYPE testkit_enum_one AS ENUM ('value');
         CREATE TYPE testkit_enum_two AS ENUM ('value');",
    )
    .unwrap();
    let one = "SELECT 'value'::testkit_enum_one";
    let two = "SELECT 'value'::testkit_enum_two";
    db.fixture_exec(one, &[]).await.unwrap();
    db.fixture_exec(two, &[]).await.unwrap();

    // Also exercise both server type lookups on the same pooled connection.
    let pid = "SELECT pg_backend_pid()";
    let before = db.query(pid, &[]).await.unwrap();
    db.exec(one, &[]).await.unwrap();
    db.exec(two, &[]).await.unwrap();
    assert_eq!(before, db.query(pid, &[]).await.unwrap());
}

#[tokio::test]
async fn postgres_testkit_fixture_locks_do_not_remain_held_after_return() {
    if !TestSql::postgres_selected() {
        return;
    }
    let db = TestSql::with_schema_unrecorded().unwrap();
    let key = db.postgres_lock_key().unwrap();
    db.fixture_script(&format!(
        "CREATE FUNCTION testkit_session_lock() RETURNS void LANGUAGE sql AS $$
         SELECT pg_advisory_lock({key}::bigint);
         $$;"
    ))
    .unwrap();
    let lock = "SELECT testkit_session_lock()";
    let separate = db.postgres().unwrap().client().await.unwrap();
    let probe = format!(
        "SET lock_timeout = '500ms'; SELECT pg_advisory_lock({key}::bigint); \
         SELECT pg_advisory_unlock({key}::bigint);"
    );
    db.fixture_exec(lock, &[]).await.unwrap();
    separate
        .batch_execute(&probe)
        .await
        .unwrap_or_else(|err| panic!("fixture session retained its lock: {:?}", err.code()));

    // Drive an independent session without checking out the pooled one.
    // The reset must release the lock even if nobody reuses that connection.
    db.exec(lock, &[]).await.unwrap();
    separate
        .batch_execute(&probe)
        .await
        .unwrap_or_else(|err| panic!("pooled session retained its lock: {:?}", err.code()));
}

#[tokio::test]
async fn postgres_testkit_fixtures_do_not_leave_custom_guc_placeholders() {
    if !TestSql::postgres_selected() {
        return;
    }
    let db = TestSql::with_schema_unrecorded().unwrap();
    db.fixture_script(
        "CREATE FUNCTION testkit_custom_guc() RETURNS text LANGUAGE sql AS $$
         SELECT set_config('velmora_test.fixture_guc', 'present', false);
         $$;",
    )
    .unwrap();
    db.fixture_exec("SELECT testkit_custom_guc()", &[])
        .await
        .unwrap();
    let rows = db
        .fixture_query(
            "SELECT current_setting('velmora_test.fixture_guc', true)",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(rows, vec![vec![SqlValue::Null]]);
}

#[tokio::test]
async fn postgres_testkit_retires_sessions_after_reply_decode_errors() {
    if !TestSql::postgres_selected() {
        return;
    }
    let db = TestSql::with_schema_unrecorded().unwrap();
    db.fixture_script("CREATE TABLE testkit_decode_probe (id bigint PRIMARY KEY);")
        .unwrap();
    let pid = "SELECT pg_backend_pid()";
    for sql in [
        "SELECT 1.5::numeric",
        "INSERT INTO testkit_decode_probe VALUES (1) RETURNING 1.5::numeric",
    ] {
        let before = db.query(pid, &[]).await.unwrap();
        assert!(db.query(sql, &[]).await.is_err(), "expected decode error");
        let after = db.query(pid, &[]).await.unwrap();
        assert_ne!(
            before, after,
            "a decode failure must retire the session: {sql}"
        );
    }
}

#[tokio::test]
async fn postgres_gc_clean_verdict_keeps_sqlite_decimal_and_saturation_rules() {
    if !TestSql::postgres_selected() {
        return;
    }
    let db = TestSql::with_schema_unrecorded().unwrap();
    let client = db.postgres().unwrap().client().await.unwrap();
    let guards: Vec<_> = pg_background_statements()
        .into_iter()
        .filter(|(sql, _)| {
            sql.starts_with("INSERT INTO tx_guard") && sql.contains("^clean:([0-9]+)")
        })
        .collect();
    assert_eq!(
        guards.len(),
        1,
        "missing or ambiguous GC clean guard enumeration"
    );
    let stmt = client
        .prepare_typed(
            &normalize_statement(&guards[0].0).unwrap(),
            &[Type::TEXT, Type::INT8],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO scan_cursors(k,v) VALUES ('probe','dirty')",
            &[],
        )
        .await
        .unwrap();
    for (input, decimal) in [
        ("clean:123", Some(123)),
        ("clean:123x", Some(123)),
        ("clean:", None),
        ("clean:0000000000000000001", Some(1)),
        (
            "clean:00000000000000000000009223372036854775807",
            Some(i64::MAX),
        ),
        ("clean:9223372036854775808", Some(i64::MAX)),
        ("clean:99999999999999999999", Some(i64::MAX)),
        ("dirty", None),
    ] {
        client
            .execute(
                "UPDATE scan_cursors SET v = $1 WHERE k = 'probe'",
                &[&input],
            )
            .await
            .unwrap();
        // Query directly since the catalogue port intentionally rejects values >2^53-1.
        for threshold in [0, 1, 122, 123, i64::MAX - 1, i64::MAX] {
            let result = client.execute(&stmt, &[&"probe", &threshold]).await;
            if decimal.is_some_and(|value| value > threshold) {
                assert_eq!(result.unwrap(), 0, "{input} vs {threshold}");
            } else {
                let error = result.unwrap_err();
                let failure = error.as_db_error().expect("server CHECK refusal");
                assert_eq!(failure.code().code(), "23514", "{input} vs {threshold}");
                assert_eq!(failure.constraint(), Some("tx_guard_ok"));
            }
        }
    }
}

#[tokio::test]
async fn every_catalog_statement_prepares_with_wire_types() {
    if !TestSql::postgres_selected() {
        return;
    }
    let declared = manifest();
    assert!(!declared.is_empty(), "empty catalogue statement manifest");
    prepare_all(&declared).await;
}

#[tokio::test]
#[ignore = "run explicitly after collecting statements from the whole PG suite"]
async fn catalog_statement_coverage() {
    assert!(
        TestSql::postgres_selected(),
        "Postgres required for coverage check"
    );
    let dir = std::env::var_os(COVERAGE_DIR).expect("statement recording directory required");
    let actual = executed(Path::new(&dir));
    let declared = manifest();
    assert!(
        !actual.is_empty(),
        "no PostgreSQL catalogue statements were recorded"
    );
    assert!(
        !declared.is_empty(),
        "no PostgreSQL catalogue statements were enumerated"
    );
    let actual_texts: BTreeSet<_> = actual
        .iter()
        .map(|statement| statement.sql.as_str())
        .collect();
    let declared_texts: BTreeSet<_> = declared
        .iter()
        .map(|statement| statement.sql.as_str())
        .collect();
    let exercised = declared_texts.intersection(&actual_texts).count();
    println!(
        "PostgreSQL SQL texts: {exercised}/{} executed; {} unexecuted; {} unlisted",
        declared_texts.len(),
        declared_texts.len() - exercised,
        actual_texts.len() - exercised,
    );
    let errors = compare(&declared_texts, &actual_texts, &exceptions(UNEXECUTED));
    assert!(
        errors.is_empty(),
        "PostgreSQL statement coverage:\n{}",
        errors.join("\n")
    );
    // A nullable bind can produce more than one wire signature for a single
    // statement. Check every observed signature as well as the declared ones.
    prepare_all(
        &actual
            .difference(&declared)
            .map(|s| Statement {
                sql: s.sql.clone(),
                parameter_oids: s.parameter_oids.clone(),
            })
            .collect(),
    )
    .await;
}

#[test]
fn coverage_rejects_hidden_new_missing_and_stale_exceptions() {
    let declared = BTreeSet::from(["SELECT 1", "SELECT 2"]);
    let observed = BTreeSet::from(["SELECT 2", "SELECT 3"]);
    let allow = fingerprint("SELECT 2");
    let errors = compare(
        &declared,
        &observed,
        &BTreeMap::from([(allow.as_str(), "old reason")]),
    );
    assert_eq!(errors.len(), 3);
    assert!(errors
        .iter()
        .any(|error| error == "executed but not enumerated: SELECT 3"));
    assert!(errors
        .iter()
        .any(|error| error.starts_with("not executed (") && error.ends_with(": SELECT 1")));
    assert!(errors
        .iter()
        .any(|error| error.starts_with("stale unexecuted SQL exception: ")));
}

/// Tables whose rows carry wrapped key material. A CHECK, NOT NULL or
/// UNIQUE failure on them logs the failing row (or key) in the server's
/// error DETAIL, wrapped bytes included. This exists without the
/// single-Sync transport; the lists below make every statement, constraint
/// and trigger function that can raise there visible in review.
const SECRET_ROW_TABLES: [&str; 3] = ["buckets", "access_keys", "extents"];
const SECRET_ROW_WRITES: &str = include_str!("pg-secret-row-writes.txt");

fn writes_secret_row_table(sql: &str) -> Option<&'static str> {
    let upper = sql.to_ascii_uppercase();
    let words: Vec<&str> = upper
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    SECRET_ROW_TABLES.into_iter().find(|table| {
        let t = table.to_ascii_uppercase();
        words
            .windows(2)
            .any(|w| (w[0] == "INTO" || w[0] == "UPDATE") && w[1] == t)
    })
}

#[tokio::test]
async fn statements_constraints_and_triggers_that_can_log_secret_rows_are_pinned() {
    if !TestSql::postgres_selected() {
        return;
    }
    let mut actual = BTreeSet::new();
    for statement in manifest() {
        if let Some(table) = writes_secret_row_table(&statement.sql) {
            let head: String = statement
                .sql
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let head: String = head
                .chars()
                .take(72)
                .collect::<String>()
                .trim_end()
                .to_owned();
            actual.insert(format!(
                "statement {} {table}: {head}",
                &fingerprint(&statement.sql)[..16]
            ));
        }
    }
    let db = TestSql::with_schema_unrecorded().unwrap();
    let client = db.postgres().unwrap().client().await.unwrap();
    let tables: Vec<String> = SECRET_ROW_TABLES.iter().map(|t| t.to_string()).collect();
    for row in client
        .query(
            "SELECT c.relname, k.conname, k.contype::text FROM pg_constraint k \
             JOIN pg_class c ON c.oid = k.conrelid \
             WHERE c.relnamespace = current_schema()::regnamespace AND c.relname = ANY($1) \
               AND k.contype IN ('c', 'u', 'p')",
            &[&tables],
        )
        .await
        .unwrap()
    {
        actual.insert(format!(
            "constraint {}.{} {}",
            row.get::<_, String>(0),
            row.get::<_, String>(1),
            row.get::<_, String>(2)
        ));
    }
    for row in client
        .query(
            "SELECT c.relname, a.attname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid \
             WHERE c.relnamespace = current_schema()::regnamespace AND c.relname = ANY($1) \
               AND a.attnum > 0 AND NOT a.attisdropped AND a.attnotnull",
            &[&tables],
        )
        .await
        .unwrap()
    {
        actual.insert(format!(
            "not-null {}.{}",
            row.get::<_, String>(0),
            row.get::<_, String>(1)
        ));
    }
    // Trigger functions of the schema that write those tables, and the
    // triggers on them.
    for row in client
        .query(
            "SELECT p.proname, p.prosrc FROM pg_proc p \
             WHERE p.pronamespace = current_schema()::regnamespace",
            &[],
        )
        .await
        .unwrap()
    {
        let (name, source): (String, String) = (row.get(0), row.get(1));
        if let Some(table) = writes_secret_row_table(&source) {
            actual.insert(format!("function {name} {table}"));
        }
    }
    for row in client
        .query(
            "SELECT c.relname, t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
             WHERE c.relnamespace = current_schema()::regnamespace AND c.relname = ANY($1) \
               AND NOT t.tgisinternal",
            &[&tables],
        )
        .await
        .unwrap()
    {
        actual.insert(format!(
            "trigger {}.{}",
            row.get::<_, String>(0),
            row.get::<_, String>(1)
        ));
    }
    let mut pinned = BTreeSet::new();
    for line in SECRET_ROW_WRITES
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (entry, reason) = match line.split_once(" # ") {
            Some((entry, reason)) => (entry, reason.trim()),
            None => (line, ""),
        };
        let needs_reason = entry.starts_with("not-null ")
            || (entry.starts_with("constraint ") && entry.ends_with(" c"));
        assert!(
            !needs_reason || !reason.is_empty(),
            "no reason for: {entry}"
        );
        pinned.insert(entry.to_owned());
    }
    let added: Vec<_> = actual.difference(&pinned).collect();
    let removed: Vec<_> = pinned.difference(&actual).collect();
    assert!(
        added.is_empty() && removed.is_empty(),
        "update tests/pg-secret-row-writes.txt after review\nnew:\n{}\ngone:\n{}",
        added
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        removed
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}
