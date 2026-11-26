//! Property test of the one-message transport's literals on a real server
//! (`VELMORA_TEST_PG_URL`): every rendered value equals the typed parameter
//! it replaces, with the same type, under `standard_conforming_strings` on
//! and off and with client encodings UTF8, SJIS and GBK; worst-case values
//! of 2,000,000 bytes included. A database that cannot hold a character
//! refuses it rather than storing something else.

#![cfg(feature = "testkit-pg")]

mod pg_support;

use pg_support::{base_config, connect, unique};
use tokio_postgres::types::Type;
use tokio_postgres::{Client, SimpleQueryMessage};
use velmora_bridge::pg::literal_for_test;
use velmora_bridge::{SqlValue, MAX_SQL_INT, MAX_SQL_VALUE_BYTES};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn char(&mut self) -> char {
        loop {
            let code = match self.next() % 5 {
                0 => (self.next() % 0x80) as u32,
                1 => b"'\\$?;-/*E\"`"[(self.next() % 11) as usize] as u32,
                2 => 0x80 + (self.next() % 0x780) as u32,
                3 => 0x800 + (self.next() % 0xF800) as u32,
                _ => 0x10000 + (self.next() % 0xF_0000) as u32,
            };
            if let Some(c) = char::from_u32(code).filter(|&c| c != '\0') {
                return c;
            }
        }
    }
}

fn text(s: impl Into<String>) -> SqlValue {
    SqlValue::Text(s.into())
}

fn corpus() -> Vec<SqlValue> {
    let mut out: Vec<SqlValue> = [0, 1, -1, MAX_SQL_INT, -MAX_SQL_INT]
        .into_iter()
        .map(SqlValue::Int)
        .collect();
    out.push(SqlValue::Null);
    for s in [
        "",
        "'",
        "''",
        "\\",
        "\\\\",
        "\\'",
        "'\\",
        "$1",
        "?1",
        ";",
        "--",
        "/*",
        "*/",
        "$$",
        "$a$",
        "E'",
        "e'\\n'",
        "U&'\\0041'",
        "\"",
        "`",
        "\\x41",
        "\\u0041",
        "%s",
        "é",
        "中文",
        "😀",
        "a\u{7f}b",
        "\u{feff}BOM",
        "\u{fffd}",
        "\u{10ffff}",
        "\u{1}\u{1f}",
    ] {
        out.push(text(s));
    }
    // Every control character alone, then all of them together.
    for c in (1..0x20_u8).chain([0x7f]) {
        out.push(text((c as char).to_string()));
    }
    out.push(text(
        (1..0x20_u8)
            .chain([0x7f])
            .map(char::from)
            .collect::<String>(),
    ));
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for _ in 0..300 {
        let len = (rng.next() % 48) as usize;
        out.push(text((0..len).map(|_| rng.char()).collect::<String>()));
    }
    out.push(SqlValue::Blob(Vec::new()));
    out.push(SqlValue::Blob((0..=255).collect()));
    out.push(SqlValue::Blob(b"\\x00'\\".to_vec()));
    out
}

/// The worst inputs at the per-value limit.
fn worst_cases() -> Vec<SqlValue> {
    let n = MAX_SQL_VALUE_BYTES;
    vec![
        text("'".repeat(n)),
        text("\\".repeat(n)),
        text("\u{1}".repeat(n)),
        text("😀".repeat(n / 4)),
        SqlValue::Blob((0..n as u32).map(|i| (i % 256) as u8).collect()),
    ]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One boolean row from a simple query, as text.
async fn simple_bool(client: &Client, sql: &str) -> Result<bool, tokio_postgres::Error> {
    let messages = client.simple_query(sql).await?;
    let rows: Vec<_> = messages
        .iter()
        .filter_map(|m| match m {
            SimpleQueryMessage::Row(row) => Some(row.get(0).map(str::to_owned)),
            _ => None,
        })
        .collect();
    assert_eq!(rows.len(), 1);
    Ok(rows[0].as_deref() == Some("t"))
}

/// The literal against an ASCII reference: UTF-8 hex for text and bytea,
/// the decimal for integers. Valid under any client encoding.
fn reference_check(value: &SqlValue, lit: &str) -> String {
    match value {
        SqlValue::Int(v) => {
            format!("SELECT ({lit}) = {v}::int8 AND pg_typeof({lit}) = 'bigint'::regtype")
        }
        SqlValue::Text(s) => format!(
            "SELECT encode(convert_to({lit}, 'UTF8'), 'hex') = '{}' AND pg_typeof({lit}) = 'text'::regtype",
            hex(s.as_bytes())
        ),
        SqlValue::Blob(b) => format!(
            "SELECT encode({lit}, 'hex') = '{}' AND pg_typeof({lit}) = 'bytea'::regtype",
            hex(b)
        ),
        SqlValue::Null => format!("SELECT ({lit}) IS NULL"),
    }
}

/// The literal against the typed parameter it replaces (UTF8 runs only:
/// under another client encoding the driver's TEXT is itself transcoded).
async fn typed_check(client: &Client, value: &SqlValue, lit: &str) -> bool {
    let (ty, sql) = match value {
        SqlValue::Int(_) => (Type::INT8, "int8"),
        SqlValue::Text(_) => (Type::TEXT, "text"),
        SqlValue::Blob(_) => (Type::BYTEA, "bytea"),
        SqlValue::Null => (Type::TEXT, "text"),
    };
    let query = format!(
        "SELECT ({lit}) IS NOT DISTINCT FROM $1::{sql}, pg_typeof({lit})::text = pg_typeof($1::{sql})::text"
    );
    let statement = client.prepare_typed(&query, &[ty]).await.unwrap();
    let row = match value {
        SqlValue::Int(v) => client.query_one(&statement, &[v]).await,
        SqlValue::Text(s) => client.query_one(&statement, &[s]).await,
        SqlValue::Blob(b) => client.query_one(&statement, &[b]).await,
        SqlValue::Null => client.query_one(&statement, &[&None::<String>]).await,
    }
    .unwrap();
    let (same, same_type): (bool, bool) = (row.get(0), row.get(1));
    // A NULL literal is `text` where an untyped NULL parameter would be.
    same && (same_type || matches!(value, SqlValue::Null))
}

#[tokio::test]
async fn every_literal_equals_its_typed_parameter_in_every_session_mode() {
    let Some(config) = base_config() else { return };
    let client = connect(&config).await;
    let values: Vec<(SqlValue, String)> = corpus()
        .into_iter()
        .chain(worst_cases())
        .map(|v| {
            let lit = literal_for_test(&v).unwrap();
            assert!(lit.is_ascii());
            (v, lit)
        })
        .collect();
    for encoding in ["UTF8", "SJIS", "GBK"] {
        for scs in ["on", "off"] {
            client
                .batch_execute(&format!(
                    "SET client_encoding = '{encoding}'; SET standard_conforming_strings = {scs}"
                ))
                .await
                .unwrap();
            for (index, (value, lit)) in values.iter().enumerate() {
                assert!(
                    simple_bool(&client, &reference_check(value, lit))
                        .await
                        .unwrap(),
                    "value {index} under {encoding}, standard_conforming_strings={scs}"
                );
                if encoding == "UTF8" {
                    assert!(
                        typed_check(&client, value, lit).await,
                        "value {index} against its typed parameter, standard_conforming_strings={scs}"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn refused_integers_have_no_literal() {
    for v in [MAX_SQL_INT + 1, -MAX_SQL_INT - 1, i64::MIN, i64::MAX] {
        assert!(literal_for_test(&SqlValue::Int(v)).is_err(), "{v}");
    }
    assert!(literal_for_test(&text("a\0b")).is_err());
    assert!(literal_for_test(&SqlValue::Blob(vec![0; MAX_SQL_VALUE_BYTES + 1])).is_err());
    assert!(literal_for_test(&text("a".repeat(MAX_SQL_VALUE_BYTES + 1))).is_err());
}

#[tokio::test]
async fn a_server_encoding_that_cannot_hold_a_character_refuses_it() {
    let Some(config) = base_config() else { return };
    let admin = connect(&config).await;
    for (encoding, exact_or_error) in [("SQL_ASCII", false), ("LATIN1", true)] {
        let name = unique("velmora_a1_db");
        admin
            .batch_execute(&format!(
                "CREATE DATABASE {name} ENCODING '{encoding}' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0"
            ))
            .await
            .unwrap();
        let mut scoped = config.clone();
        scoped.dbname(&name);
        let client = connect(&scoped).await;
        // ASCII, quotes, backslashes and control characters always work.
        for s in ["plain", "it's", "a\\b", "\u{1}\u{1f}\u{7f}"] {
            let lit = literal_for_test(&text(s)).unwrap();
            // chr() of an ASCII code point is that character in any encoding.
            let reference: Vec<String> = s.chars().map(|c| format!("chr({})", c as u32)).collect();
            let sql = format!("SELECT ({lit}) = {}", reference.join(" || "));
            assert!(
                simple_bool(&client, &sql).await.unwrap(),
                "{encoding}: {s:?}"
            );
        }
        for s in ["é", "中", "😀"] {
            let lit = literal_for_test(&text(s)).unwrap();
            let result = simple_bool(
                &client,
                &format!(
                    "SELECT encode(convert_to({lit}, 'UTF8'), 'hex') = '{}'",
                    hex(s.as_bytes())
                ),
            )
            .await;
            match result {
                Err(_) => {}
                // A converting encoding may hold the character: then it is
                // exactly the character, never another one.
                Ok(same) => assert!(exact_or_error && same, "{encoding}: {s:?}"),
            }
            if !exact_or_error {
                assert!(
                    client.simple_query(&format!("SELECT {lit}")).await.is_err(),
                    "{encoding} must refuse {s:?}"
                );
            }
        }
        drop(client);
        admin
            .batch_execute(&format!("DROP DATABASE {name} WITH (FORCE)"))
            .await
            .unwrap();
    }
}
