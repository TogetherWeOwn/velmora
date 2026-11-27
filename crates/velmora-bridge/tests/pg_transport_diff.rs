//! Differential test of the two write transports: every catalogue
//! statement of the manifests runs, rolled back, on the one-Sync-per-
//! statement transport and on the single-Sync transport against the same
//! catalogue state, alone and before a failing statement, with its
//! manifest values, with NULL in every position, at the integer edges, with
//! text full of quotes, backslashes and non-ASCII, and with refused values
//! (out-of-range integers, NUL). Counts, rows and error classes must be
//! identical. `VELMORA_TEST_PG_DIFFERENTIAL=1` does the same for every
//! write of any other test binary, with that test's own values.

#![cfg(all(feature = "testkit-pg", feature = "pg-test-record"))]

use velmora_bridge::pg::{is_postgres_read_only, ProbeOutcome};
use velmora_bridge::sql::{pg_background_statements, pg_datapath_statements};
use velmora_bridge::testkit::TestSql;
use velmora_bridge::{SqlValue, MAX_SQL_INT};

const NASTY: &str = "it's a \\ back\\\\slash; -- $1 ?1 /* $$ E'x' \"q\" é 中 😀 \u{1}\t\n\u{7f}";

fn variants(params: &[SqlValue]) -> Vec<(String, Vec<SqlValue>)> {
    let map = |int: i64, text: &str, blob: &[u8]| {
        params
            .iter()
            .map(|p| match p {
                SqlValue::Int(_) => SqlValue::Int(int),
                SqlValue::Text(_) => SqlValue::Text(text.into()),
                SqlValue::Blob(_) => SqlValue::Blob(blob.to_vec()),
                SqlValue::Null => SqlValue::Null,
            })
            .collect::<Vec<_>>()
    };
    let nulls = vec![SqlValue::Null; params.len()];
    let mut out = vec![
        ("manifest values".to_owned(), params.to_vec()),
        ("NULL in every position".to_owned(), nulls),
        (
            "upper edges".to_owned(),
            map(MAX_SQL_INT, NASTY, &[0, 0x27, 0x5c, 0xff]),
        ),
        (
            "lower edges".to_owned(),
            map(-MAX_SQL_INT, "''\\'\\\\", &[]),
        ),
        ("ones".to_owned(), map(1, "x", &[1])),
    ];
    // NULL in each single position, the others at their manifest values.
    for i in 0..params.len() {
        let mut v = params.to_vec();
        v[i] = SqlValue::Null;
        out.push((format!("NULL at ?{}", i + 1), v));
    }
    let first = |kind: fn(&SqlValue) -> bool, value: SqlValue| {
        params.iter().position(kind).map(|i| {
            let mut v = params.to_vec();
            v[i] = value;
            v
        })
    };
    for (name, refused) in [
        (
            "integer above the range",
            first(
                |p| matches!(p, SqlValue::Int(_)),
                SqlValue::Int(MAX_SQL_INT + 1),
            ),
        ),
        (
            "i64::MIN",
            first(|p| matches!(p, SqlValue::Int(_)), SqlValue::Int(i64::MIN)),
        ),
        (
            "text with NUL",
            first(
                |p| matches!(p, SqlValue::Text(_)),
                SqlValue::Text("a\0b".into()),
            ),
        ),
    ] {
        if let Some(v) = refused {
            out.push((name.to_owned(), v));
        }
    }
    out
}

fn same(a: &ProbeOutcome, b: &ProbeOutcome) -> bool {
    match (a, b) {
        (Ok(a), Ok(b)) => a == b,
        (Err(a), Err(b)) => format!("{a:?}") == format!("{b:?}"),
        _ => false,
    }
}

fn class(o: &ProbeOutcome) -> String {
    match o {
        Ok((counts, rows)) => format!("Ok(counts {counts:?}, rows {rows:?})"),
        Err(e) => format!("Err({e:?})"),
    }
}

#[tokio::test]
async fn both_transports_return_the_same_for_every_manifest_statement() {
    if !TestSql::postgres_selected() {
        return;
    }
    let db = TestSql::with_schema_unrecorded().unwrap();
    let pg = db.postgres().unwrap();
    let manifest: Vec<(String, Vec<SqlValue>)> = pg_datapath_statements()
        .into_iter()
        .map(|(sql, params)| (sql.to_owned(), params))
        .chain(pg_background_statements())
        .collect();
    let mut differences = Vec::new();
    let mut runs = 0;
    for (sql, params) in &manifest {
        // Write-routed statements can be a `query`: compare their rows too.
        let write = !is_postgres_read_only(sql);
        for (variant, values) in variants(params) {
            for (shape, collect_rows) in [
                ("alone", false),
                ("alone", true),
                ("before an error", false),
            ] {
                if collect_rows && !write {
                    continue;
                }
                let failing = ("SELECT 1/0", Vec::new());
                let one = (sql.as_str(), values.clone());
                let stmts = if shape == "alone" {
                    vec![one]
                } else {
                    vec![one, failing]
                };
                let variant = format!("{variant}, {shape}");
                let (pipelined, single_sync) = pg.compare_transports(&stmts, collect_rows).await;
                runs += 1;
                if !same(&pipelined, &single_sync) {
                    differences.push(format!(
                        "{variant}, rows={collect_rows}: pipelined {} / single Sync {}: {sql}",
                        class(&pipelined),
                        class(&single_sync)
                    ));
                }
            }
        }
    }
    assert!(runs > 8_000, "{runs} comparisons");
    assert!(
        differences.is_empty(),
        "{} of {runs} comparisons differ:\n{}",
        differences.len(),
        differences.join("\n")
    );
}
