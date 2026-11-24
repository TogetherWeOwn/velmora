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
use velmora_bridge::testkit::TestSql;
use velmora_bridge::SqlValue;

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
