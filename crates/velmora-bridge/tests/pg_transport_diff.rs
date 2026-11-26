//! Differential test of the two write transports: every catalogue
//! statement of the manifests runs, rolled back, on the typed transport and
//! on the one-message transport against the same catalogue state, with its
//! manifest values, with NULL in every position, at the integer edges, with
//! text full of quotes, backslashes and non-ASCII, and with refused values
//! (out-of-range integers, NUL). Counts, rows and error classes must be
//! identical. `VELMORA_TEST_PG_DIFFERENTIAL=1` does the same for every
//! write of any other test binary, with that test's own values.

#![cfg(all(feature = "testkit-pg", feature = "pg-test-record"))]

use velmora_bridge::pg::{is_postgres_read_only, normalize_statement, ProbeOutcome, WRITE_RESULTS};
use velmora_bridge::sql::{pg_background_statements, pg_datapath_statements};
use velmora_bridge::testkit::TestSql;
use velmora_bridge::{SqlValue, MAX_SQL_INT};

/// Positions where no caller binds NULL and where NULL in every position
/// makes the two transports differ. The typed transport sends a NULL as an
/// untyped parameter, so `?4 = ?5` with both NULL cannot be typed (42P18,
/// `statement failed`); two NULL literals compare as text and match no
/// row. The only caller, `outbox::record_verification`, binds ?4 and ?5
/// as `SqlValue::Int(i64::from(..))` (articles ok, articles total), and the
/// manifest declares them `I, I`. The NULL variant keeps them as integers;
/// every other position is still NULL. The excluded input is checked to
/// be refused by the typed transport, as it was before this change.
const NULL_EXCEPTIONS: &[(&str, &[usize])] = &[(
    "UPDATE extents SET last_verified_at = ?2 WHERE id = ?1 AND ?3 = 'ok' AND ?4 = ?5",
    &[4, 5],
)];

fn kept_non_null(sql: &str) -> &'static [usize] {
    NULL_EXCEPTIONS
        .iter()
        .find(|(prefix, _)| {
            sql.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .starts_with(prefix)
        })
        .map_or(&[], |(_, kept)| kept)
}

const NASTY: &str = "it's a \\ back\\\\slash; -- $1 ?1 /* $$ E'x' \"q\" é 中 😀 \u{1}\t\n\u{7f}";

fn variants(sql: &str, params: &[SqlValue]) -> Vec<(String, Vec<SqlValue>)> {
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
    let kept = kept_non_null(sql);
    let nulls = params
        .iter()
        .enumerate()
        .map(|(i, p)| {
            if kept.contains(&(i + 1)) {
                p.clone()
            } else {
                SqlValue::Null
            }
        })
        .collect();
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
        let normalized = normalize_statement(sql).unwrap();
        let declared =
            !is_postgres_read_only(sql) && WRITE_RESULTS.iter().any(|d| d.sql == normalized);
        for (variant, values) in variants(sql, params) {
            for collect_rows in [false, true] {
                if collect_rows && !declared {
                    continue;
                }
                let stmts = [(sql.as_str(), values.clone())];
                let (typed, message) = pg.compare_transports(&stmts, collect_rows).await;
                runs += 1;
                if !same(&typed, &message) {
                    differences.push(format!(
                        "{variant}, rows={collect_rows}: typed {} / message {}: {sql}",
                        class(&typed),
                        class(&message)
                    ));
                }
            }
        }
    }
    assert!(runs > 4_000, "{runs} comparisons");
    // The excluded input: the typed transport refuses it, as before.
    let (sql, params) = manifest
        .iter()
        .find(|(sql, _)| !kept_non_null(sql).is_empty())
        .expect("the listed exception is a manifest statement");
    let all_null = [(sql.as_str(), vec![SqlValue::Null; params.len()])];
    let (typed, _) = pg.compare_transports(&all_null, false).await;
    assert!(
        matches!(&typed, Err(velmora_bridge::BridgeError::Sql(e)) if e == "pg: statement failed"),
        "{}",
        class(&typed)
    );
    assert!(
        differences.is_empty(),
        "{} of {runs} comparisons differ:\n{}",
        differences.len(),
        differences.join("\n")
    );
}
