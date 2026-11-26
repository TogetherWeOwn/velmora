//! The one-message write transport without a server: the literal renderer,
//! the size bound, the reply-position error classes, the declared result
//! decoder, and the refusals that must precede any I/O.

use std::cell::Cell;

use super::batch::{self, message_error, prelude, prelude_statements, Plan, Prepared, COMMIT};
use super::literal::{render_value, value_len, MAX_WRITE_MESSAGE_BYTES};
use super::results::{self, ResultType};
use super::{PgConfig, PgConnect, PgConnection, PgSql, WriteTx};
use crate::{BridgeError, Sql, SqlValue, MAX_SQL_INT};

const BOTH: [WriteTx; 2] = [WriteTx::Message, WriteTx::Pipeline];

/// Parse a rendered TEXT literal back, as PostgreSQL's E-string lexer does
/// for the escapes the renderer emits.
fn parse_text(lit: &str) -> String {
    let body = lit
        .strip_prefix("E'")
        .and_then(|s| s.strip_suffix("'::text"))
        .expect("E'...'::text");
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                assert_eq!(chars.next(), Some('\''), "a lone quote ends the literal");
                out.push('\'');
            }
            '\\' => match chars.next().expect("escape") {
                '\\' => out.push('\\'),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).unwrap()).unwrap());
                }
                'U' => {
                    let hex: String = chars.by_ref().take(8).collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).unwrap()).unwrap());
                }
                other => panic!("unexpected escape \\{other}"),
            },
            c => out.push(c),
        }
    }
    out
}

/// A deterministic generator, so a failure reproduces.
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
            let pick = self.next() % 6;
            let code = match pick {
                0 if self.next().is_multiple_of(7) => 0x7f,
                0 => (self.next() % 0x20) as u32,
                1 => b"'\\$?;-/*E\"`"[(self.next() % 11) as usize] as u32,
                2 => 0x20 + (self.next() % 0x5F) as u32,
                3 => 0x80 + (self.next() % 0x780) as u32,
                4 => 0x800 + (self.next() % 0xF800) as u32,
                _ => 0x10000 + (self.next() % 0xF_0000) as u32,
            };
            if let Some(c) = char::from_u32(code).filter(|&c| c != '\0') {
                return c;
            }
        }
    }
}

#[test]
fn literals_are_closed_typed_and_ascii() {
    let cases: &[(SqlValue, &str)] = &[
        (SqlValue::Int(0), "'0'::int8"),
        (SqlValue::Int(-1), "'-1'::int8"),
        (SqlValue::Int(MAX_SQL_INT), "'9007199254740991'::int8"),
        (SqlValue::Int(-MAX_SQL_INT), "'-9007199254740991'::int8"),
        (SqlValue::Null, "NULL"),
        (SqlValue::Text(String::new()), "E''::text"),
        (SqlValue::Text("it's".into()), "E'it''s'::text"),
        (SqlValue::Text(r"a\b".into()), r"E'a\\b'::text"),
        (
            SqlValue::Text("$1 ?1 ; -- /* $$ E'".into()),
            "E'$1 ?1 ; -- /* $$ E'''::text",
        ),
        (
            SqlValue::Text("\n\t\x1f\x7f".into()),
            r"E'\u000A\u0009\u001F\u007F'::text",
        ),
        (
            SqlValue::Text("é中😀".into()),
            r"E'\u00E9\u4E2D\U0001F600'::text",
        ),
        (SqlValue::Blob(Vec::new()), r"E'\\x'::bytea"),
        (
            SqlValue::Blob(vec![0, 0x5c, 0x27, 0xff]),
            r"E'\\x005c27ff'::bytea",
        ),
    ];
    for (value, expected) in cases {
        let lit = render_value(value).unwrap();
        assert_eq!(lit, *expected);
        assert_eq!(value_len(value).unwrap(), lit.len() as u64);
        assert!(lit.is_ascii());
    }
}

#[test]
fn rendered_text_round_trips_and_its_length_is_exact() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for round in 0..2_000 {
        let len = (rng.next() % 64) as usize;
        let text: String = (0..len).map(|_| rng.char()).collect();
        let value = SqlValue::Text(text.clone());
        let lit = render_value(&value).unwrap();
        assert!(lit.is_ascii(), "round {round}");
        assert_eq!(
            value_len(&value).unwrap(),
            lit.len() as u64,
            "round {round}"
        );
        assert_eq!(parse_text(&lit), text, "round {round}");
    }
}

#[test]
fn worst_case_texts_expand_as_sized() {
    // 2,000,000 bytes of the worst inputs: 2x for quotes and backslashes,
    // 6x for control characters, 2.5x for 4-byte characters.
    let n = crate::MAX_SQL_VALUE_BYTES;
    for (text, factor) in [
        ("'".repeat(n), 2.0),
        ("\\".repeat(n), 2.0),
        ("\x01".repeat(n), 6.0),
        ("😀".repeat(n / 4), 2.5),
    ] {
        let value = SqlValue::Text(text);
        let len = value_len(&value).unwrap();
        assert_eq!(len, (n as f64 * factor) as u64 + 9);
        assert_eq!(render_value(&value).unwrap().len() as u64, len);
    }
}

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
        // More markers than values: the server refused this before.
        let r = rt.block_on(pg.exec("INSERT INTO t VALUES (?1, ?2)", &[SqlValue::Int(1)]));
        assert!(matches!(r, Err(BridgeError::Sql(e)) if e == "pg: bind failed"));
        let r = rt.block_on(pg.batch(vec![
            ("INSERT INTO t VALUES (?1)", vec![SqlValue::Int(1)]),
            (
                "UPDATE t SET a = $3",
                vec![SqlValue::Int(1), SqlValue::Int(2)],
            ),
        ]));
        assert!(matches!(r, Err(BridgeError::Sql(e)) if e == "pg: bind failed"));
    }
}

struct Refuse(Cell<u32>);

impl PgConnect for &Refuse {
    async fn connect(&self) -> crate::Result<PgConnection> {
        self.0.set(self.0.get() + 1);
        Err(BridgeError::Sql("test: no server".into()))
    }
}

#[tokio::test]
async fn an_undeclared_write_query_is_refused_before_io_in_message_mode() {
    let undeclared = "UPDATE t SET a = ?1 RETURNING a";
    let declared = results::WRITE_RESULTS[0].sql;
    for write_tx in BOTH {
        let attempts = Refuse(Cell::new(0));
        let pg = PgSql::new(
            &attempts,
            &attempts,
            PgConfig {
                write_tx,
                ..PgConfig::default()
            },
        );
        let r = pg.query(undeclared, &[SqlValue::Int(1)]).await;
        let message = write_tx == WriteTx::Message;
        if message {
            assert!(matches!(r, Err(BridgeError::Sql(e)) if e == "pg: undeclared write result"));
        }
        assert_eq!(attempts.0.get(), u32::from(!message), "{write_tx:?}");
        // exec and batch take no rows, so they need no declaration.
        let _ = pg.exec(undeclared, &[SqlValue::Int(1)]).await;
        assert_eq!(attempts.0.get(), 1 + u32::from(!message));
        let max = super::params::statement(declared).unwrap().max_bind();
        let values = vec![SqlValue::Int(1); max];
        let _ = pg.query(declared, &values).await;
        assert_eq!(attempts.0.get(), 2 + u32::from(!message));
    }
}

fn prepared(stmts: &[(&str, Vec<SqlValue>)]) -> Vec<Prepared> {
    stmts
        .iter()
        .map(|(sql, values)| Prepared::new(sql, values).unwrap())
        .collect()
}

#[test]
fn the_message_is_the_prelude_the_statements_and_commit() {
    let p = prepared(&[
        (
            "INSERT INTO t VALUES (?1, ?2) -- trailing comment",
            vec![SqlValue::Int(7), SqlValue::Text("x'".into())],
        ),
        (
            "UPDATE t SET b = ?1 WHERE a = ?1 AND c = '?1' /* ?2 */",
            vec![SqlValue::Null],
        ),
    ]);
    let Plan::Message(m) =
        batch::plan(WriteTx::Message, Some(42), &p, false, COMMIT, None).unwrap()
    else {
        panic!("small batches are one message")
    };
    assert_eq!(
        m,
        format!(
            "{}\n;\nINSERT INTO t VALUES ('7'::int8, E'x'''::text) -- trailing comment\n;\n\
             UPDATE t SET b = NULL WHERE a = NULL AND c = '?1' /* ?2 */\n;\nCOMMIT",
            prelude(Some(42))
        )
    );
    assert!(m.starts_with(
        "BEGIN READ WRITE, ISOLATION LEVEL READ COMMITTED; SET LOCAL lock_timeout = '2s'; "
    ));
    assert!(m.contains(
        "; SET LOCAL bytea_output = 'hex'; SELECT pg_advisory_xact_lock(42::bigint)\n;\n"
    ));
}

#[test]
fn the_prelude_statement_count_matches_the_prelude() {
    for key in [Some(7_413_000_001), None] {
        let statements = prelude(key).split("; ").count();
        assert_eq!(prelude_statements(key), statements);
    }
    assert_eq!(prelude_statements(Some(1)), 6);
    assert_eq!(prelude_statements(None), 5);
}

#[test]
fn a_non_ascii_statement_text_is_refused() {
    let p = prepared(&[("INSERT INTO t VALUES ('é', ?1)", vec![SqlValue::Int(1)])]);
    let r = batch::plan(WriteTx::Message, Some(1), &p, false, COMMIT, None);
    assert!(matches!(r, Err(BridgeError::Sql(e)) if e == "pg: untranslated statement"));
    // The typed transport sends the text as it is today.
    assert!(matches!(
        batch::plan(WriteTx::Pipeline, Some(1), &p, false, COMMIT, None),
        Ok(Plan::Pipeline)
    ));
}

thread_local! {
    static HOOKED: Cell<usize> = const { Cell::new(0) };
}

fn hook(statements: usize) {
    HOOKED.with(|h| h.set(statements));
}

#[test]
fn the_size_bound_holds_on_both_sides() {
    // Three full 2 MB blobs, then a blob and a text sized so the message
    // is exactly the bound (blobs render at 2 bytes a byte, so the text
    // takes up an odd remainder).
    let full = vec![0xab_u8; crate::MAX_SQL_VALUE_BYTES];
    let build = |blob: usize, text: usize| {
        let mut stmts: Vec<(&str, Vec<SqlValue>)> = (0..3)
            .map(|_| {
                (
                    "INSERT INTO t VALUES (?1)",
                    vec![SqlValue::Blob(full.clone())],
                )
            })
            .collect();
        stmts.push((
            "INSERT INTO t VALUES (?1)",
            vec![SqlValue::Blob(vec![1; blob])],
        ));
        stmts.push((
            "INSERT INTO t VALUES (?1)",
            vec![SqlValue::Text("a".repeat(text))],
        ));
        prepared(&stmts)
    };
    let len = |p: &[Prepared], hook: Option<fn(usize)>| match batch::plan(
        WriteTx::Message,
        Some(1),
        p,
        false,
        COMMIT,
        hook,
    )
    .unwrap()
    {
        Plan::Message(m) => Some(m.len()),
        Plan::Pipeline => None,
    };
    let remain = MAX_WRITE_MESSAGE_BYTES - len(&build(0, 0), None).unwrap();
    let text = 1_000_000 + remain % 2;
    let blob = (remain - text) / 2;
    assert!(blob <= crate::MAX_SQL_VALUE_BYTES);
    assert_eq!(len(&build(blob, text), None), Some(MAX_WRITE_MESSAGE_BYTES));
    let before = batch::oversize_fallbacks();
    assert_eq!(len(&build(blob, text + 1), Some(hook)), None);
    assert_eq!(batch::oversize_fallbacks(), before + 1);
    assert_eq!(HOOKED.with(Cell::get), 5);
}

#[test]
fn errors_are_classed_by_reply_position() {
    let failed = "Sql(\"pg: statement failed\")";
    let over = "Sql(\"pg: overloaded\")";
    let guard = "GuardFailed";
    let constraint = "Sql(\"pg: constraint violation\")";
    let (p, n) = (6, 3);
    let class =
        |code: Option<(&str, Option<&str>)>, done| format!("{:?}", message_error(code, done, p, n));
    let tx_guard = Some(("23514", Some("tx_guard_ok")));
    // A catalogue statement: P <= done < P + n.
    for done in p..p + n {
        assert_eq!(class(tx_guard, done), guard);
        assert_eq!(class(Some(("23505", None)), done), constraint);
        assert_eq!(class(Some(("VL001", None)), done), constraint);
        for code in ["55P03", "57014", "40001", "40P01"] {
            assert_eq!(class(Some((code, None)), done), over, "{code}");
        }
        for code in [
            "22P02", "25006", "42601", "53300", "53400", "08006", "XX000", "58000", "P0001",
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
    // Before BEGIN completed: a proxy's 58000 may follow forwarding.
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
fn text_results_decode_exactly_as_the_binary_decoder() {
    use ResultType::*;
    let ok = |ty, s: &str| results::cell(ty, Some(s)).unwrap();
    let bad = |ty, s: &str| assert!(results::cell(ty, Some(s)).is_err(), "{ty:?} {s:?}");
    assert_eq!(results::cell(Int8, None).unwrap(), SqlValue::Null);
    assert_eq!(ok(Int8, "-9223372036854775808"), SqlValue::Int(i64::MIN));
    assert_eq!(ok(Int8, "9223372036854775807"), SqlValue::Int(i64::MAX));
    assert_eq!(ok(Int4, "-2147483648"), SqlValue::Int(-2_147_483_648));
    assert_eq!(ok(Int2, "32767"), SqlValue::Int(32_767));
    for s in [
        "",
        "-",
        "+1",
        " 1",
        "1 ",
        "1.0",
        "0x10",
        "9223372036854775808",
        "1e3",
    ] {
        bad(Int8, s);
    }
    bad(Int2, "32768");
    bad(Int4, "2147483648");
    assert_eq!(ok(Bool, "t"), SqlValue::Int(1));
    assert_eq!(ok(Bool, "f"), SqlValue::Int(0));
    for s in ["true", "1", "T", ""] {
        bad(Bool, s);
    }
    assert_eq!(ok(Numeric, "5"), SqlValue::Int(5));
    assert_eq!(ok(Numeric, "5.00"), SqlValue::Int(5));
    assert_eq!(ok(Numeric, "-0.000"), SqlValue::Int(0));
    assert_eq!(ok(Numeric, "-9223372036854775808"), SqlValue::Int(i64::MIN));
    for s in [
        "5.01",
        "0.5",
        "NaN",
        "Infinity",
        "-Infinity",
        "9223372036854775808",
        ".5",
        "5.",
        "1e2",
    ] {
        bad(Numeric, s);
    }
    assert_eq!(ok(Text, "1"), SqlValue::Text("1".into()));
    assert_eq!(ok(Name, ""), SqlValue::Text(String::new()));
    assert_eq!(ok(Bytea, "\\x"), SqlValue::Blob(Vec::new()));
    assert_eq!(ok(Bytea, "\\x00aBfF"), SqlValue::Blob(vec![0, 0xab, 0xff]));
    for s in ["", "\\x0", "\\x0g", "00", "\\X00", "\\000"] {
        bad(Bytea, s);
    }
}

#[test]
fn the_binary_and_text_numeric_decoders_agree() {
    // value::numeric on the binary form of each text form.
    fn binary(weight: i16, sign: u16, scale: u16, digits: &[u16]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend((digits.len() as u16).to_be_bytes());
        raw.extend(weight.to_be_bytes());
        raw.extend(sign.to_be_bytes());
        raw.extend(scale.to_be_bytes());
        digits.iter().for_each(|d| raw.extend(d.to_be_bytes()));
        raw
    }
    for (text, raw) in [
        ("5.00", binary(0, 0, 2, &[5])),
        ("5.01", binary(0, 0, 2, &[5, 100])),
        ("-12345678", binary(1, 0x4000, 0, &[1234, 5678])),
        ("NaN", binary(0, 0xC000, 0, &[])),
        ("0", binary(0, 0, 0, &[])),
    ] {
        assert_eq!(
            results::cell(ResultType::Numeric, Some(text)).ok(),
            super::value::numeric(&raw).map(SqlValue::Int),
            "{text}"
        );
    }
}

#[test]
fn no_log_record_is_compiled_in() {
    // The driver debug-logs the whole simple query, which carries values.
    assert_eq!(log::STATIC_MAX_LEVEL, log::LevelFilter::Off);
}
