//! `impl Sql` over the SQLite storage of a Durable Object.
//!
//! Every statement runs through the JavaScript shim (`shim.js`): a
//! `batch` inside `storage.transactionSync`, so it is all or nothing, and
//! rows changed are the difference of `total_changes()` around each
//! statement, which counts the rows triggers change (as D1's
//! `meta.changes` and the native test adapter do).
//!
//! Value mapping:
//! - `Null` <-> JS `null` (`undefined` reads as `Null` too).
//! - `Int` -> JS number, **bound through `+CAST(?N AS INTEGER)`**. The
//!   runtime binds every JS number as a SQLite REAL, so an integer bound
//!   plainly would be stored as `7.0` in a TEXT column, divide as a
//!   fraction (`?/2` of 5 is 2.5) and print as `5.0` in `json_array`.
//!   [`bind_text`] wraps every placeholder whose value is an `Int`, so
//!   SQLite sees the integer that a native binding gives, without the
//!   affinity a bare `CAST` would add. Only integers
//!   in `±(2^53 - 1)` are bound; others are refused before the call.
//! - `Int` <- JS number. A returned number that is fractional or outside
//!   `±(2^53 - 1)` is a decode error: the runtime rounds a larger
//!   integer silently (`SELECT 9007199254740993` reads as
//!   `9007199254740992`), so such a value is never taken.
//! - `Text` <-> JS string.
//! - `Blob` -> `Uint8Array`; a returned BLOB is an `ArrayBuffer`.
//!
//! Errors: a failure whose text is the `tx_guard` CHECK
//! ([`velmora_bridge::is_tx_guard_violation`]) is `GuardFailed`. Every
//! other failure is `BridgeError::Sql` with a class only, the classes of
//! the D1 adapter (`do: constraint violation`, `do: statement failed`):
//! no SQL text, parameter or database message leaves the adapter.

use std::borrow::Cow;

use velmora_bridge::{
    is_tx_guard_violation, BridgeError, Result, Row, Sql, SqlValue, MAX_SQL_PARAMS,
    MAX_SQL_VALUE_BYTES,
};
use worker::js_sys::{self, Array, ArrayBuffer, Uint8Array};
use worker::wasm_bindgen::{self, prelude::wasm_bindgen, JsCast, JsValue};
use worker::worker_sys::DurableObjectStorage;
use worker::Storage;

/// Largest integer a JS number holds exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INT: i64 = (1 << 53) - 1;

#[wasm_bindgen(module = "/src/shim.js")]
extern "C" {
    #[wasm_bindgen(js_name = doQuery, catch)]
    fn do_query(
        storage: &DurableObjectStorage,
        text: &str,
        params: &Array,
    ) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = doExec, catch)]
    fn do_exec(
        storage: &DurableObjectStorage,
        text: &str,
        params: &Array,
    ) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = doBatch, catch)]
    fn do_batch(
        storage: &DurableObjectStorage,
        stmts: &Array,
    ) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = doApply, catch)]
    fn do_apply(storage: &DurableObjectStorage, script: &str) -> std::result::Result<(), JsValue>;
    #[wasm_bindgen(js_name = doDatabaseSize, catch)]
    fn do_database_size(storage: &DurableObjectStorage) -> std::result::Result<JsValue, JsValue>;
}

/// The SQLite storage of one Durable Object as a [`Sql`].
pub struct DoSql {
    storage: DurableObjectStorage,
}

impl DoSql {
    pub fn new(storage: &Storage) -> Self {
        let raw: &JsValue = storage.as_raw().as_ref();
        DoSql {
            storage: raw.clone().unchecked_into(),
        }
    }

    /// Runs a script of several statements (a migration) in one
    /// transaction. Not a [`Sql`] call: catalogue code never runs a
    /// script.
    ///
    /// Comments after the last statement are dropped first: the runtime
    /// refuses a script whose last part holds no statement ("SQL code did
    /// not contain a statement"), and migration 0017 ends in a comment.
    /// A script of comments alone runs nothing.
    pub fn apply(&self, script: &str) -> Result<()> {
        let end = significant_end(script);
        if end == 0 {
            return Ok(());
        }
        do_apply(&self.storage, &script[..end]).map_err(map_err)
    }

    /// The storage handle, for the other shim calls of this crate.
    pub(crate) fn raw(&self) -> &DurableObjectStorage {
        &self.storage
    }

    /// Size of the database in bytes, as the runtime reports it.
    pub fn database_size(&self) -> Result<u64> {
        let n = do_database_size(&self.storage).map_err(map_err)?;
        let n = n.as_f64().ok_or_else(decode_err)?;
        u64::try_from(number_to_int(n)?).map_err(|_| decode_err())
    }

    fn prepared(sql: &str, params: &[SqlValue]) -> Result<(String, Array)> {
        check_params(params)?;
        let text = bind_text(sql, params)?.into_owned();
        let values = params.iter().map(to_js).collect::<Result<Array>>()?;
        Ok((text, values))
    }
}

impl Sql for DoSql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        let (text, values) = Self::prepared(sql, params)?;
        let rows = do_query(&self.storage, &text, &values).map_err(map_err)?;
        let rows = rows.dyn_into::<Array>().map_err(|_| decode_err())?;
        rows.iter()
            .map(|row| {
                let row = row.dyn_into::<Array>().map_err(|_| decode_err())?;
                row.iter().map(from_js).collect()
            })
            .collect()
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        let (text, values) = Self::prepared(sql, params)?;
        changes(&do_exec(&self.storage, &text, &values).map_err(map_err)?)
    }

    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        if stmts.is_empty() {
            return Ok(Vec::new());
        }
        let list = Array::new();
        for (sql, params) in &stmts {
            let (text, values) = Self::prepared(sql, params)?;
            let pair = Array::new();
            pair.push(&JsValue::from_str(&text));
            pair.push(&values);
            list.push(&pair);
        }
        let results = do_batch(&self.storage, &list).map_err(map_err)?;
        let results = results.dyn_into::<Array>().map_err(|_| decode_err())?;
        if results.length() as usize != stmts.len() {
            return Err(decode_err());
        }
        results.iter().map(|n| changes(&n)).collect()
    }
}

/// What [`lex`] finds in a statement.
struct Lexed {
    /// Every placeholder: its byte range and its number.
    placeholders: Vec<(usize, usize, usize)>,
    /// The end of the last part that is neither white space nor a comment.
    significant_end: usize,
    /// A `;` outside quotes and comments with a statement after it.
    second_statement: bool,
}

/// Bytes that may continue an identifier (SQLite: letters, digits, `_`,
/// `$`, and every byte of a character outside ASCII).
fn ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80
}

/// Reads `sql` as SQLite's tokenizer does, far enough to find its
/// placeholders, its last significant byte and a second statement:
/// string literals (`'…'`, with `x'…'` blobs), quoted identifiers (`"…"`,
/// `` `…` ``, `[…]`) and comments (`--…`, `/*…*/`) hold no placeholder.
/// A bare `?` takes the number one above the largest assigned before it.
/// A named parameter (`:a`, `@a`, `$a`: a sigil that starts a token) is
/// refused: no catalogue statement uses one, and its number would need
/// the statement's parse.
fn lex(sql: &str) -> Result<Lexed> {
    let bytes = sql.as_bytes();
    let mut placeholders = Vec::new();
    let mut largest = 0usize;
    let mut significant_end = 0;
    let mut after_semicolon = false;
    let mut second_statement = false;
    // Inside `CREATE [TEMP|TEMPORARY] TRIGGER … BEGIN … END`, a `;` ends
    // the statement only as `; END ;` (SQLite's `sqlite3_complete`): the
    // word END right after a `;` of the body, then a `;`. An `END` of a
    // `CASE` inside the body does not end it.
    // `create`: 0 = the statement does not start a trigger (yet), 1 =
    // after CREATE, 2 = after CREATE TEMP; `words` counts its words.
    let mut words = 0usize;
    let mut create = 0u8;
    let mut in_trigger = false;
    let mut semicolon_in_body = false;
    let mut end_after_semicolon = false;
    let mut i = 0;
    // Skips to the end of a quoted run that `close` ends; a doubled
    // `close` is an escaped one.
    let skip_quoted = |mut j: usize, close: u8, doubled: bool| -> usize {
        while j < bytes.len() {
            if bytes[j] == close {
                if doubled && bytes.get(j + 1) == Some(&close) {
                    j += 2;
                    continue;
                }
                return j + 1;
            }
            j += 1;
        }
        j
    };
    while i < bytes.len() {
        let token_start = i;
        match bytes[i] {
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
                continue;
            }
            c if c.is_ascii_whitespace() => {
                i += 1;
                continue;
            }
            b';' if !in_trigger || end_after_semicolon => {
                i += 1;
                significant_end = i;
                after_semicolon = true;
                words = 0;
                create = 0;
                in_trigger = false;
                semicolon_in_body = false;
                end_after_semicolon = false;
                continue;
            }
            b';' => {
                // A `;` of a trigger body.
                i += 1;
                second_statement |= after_semicolon;
                significant_end = i;
                semicolon_in_body = true;
                end_after_semicolon = false;
                continue;
            }
            b'\'' => i = skip_quoted(i + 1, b'\'', true),
            b'"' => i = skip_quoted(i + 1, b'"', true),
            b'`' => i = skip_quoted(i + 1, b'`', true),
            b'[' => i = skip_quoted(i + 1, b']', false),
            b':' | b'@' | b'$' | b'#'
                if (i == 0 || !ident_byte(bytes[i - 1]))
                    && bytes.get(i + 1).is_some_and(|c| ident_byte(*c)) =>
            {
                return Err(BridgeError::Sql("do: named parameter".into()));
            }
            b'?' => {
                i += 1;
                let digits = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let number = if i > digits {
                    sql[digits..i]
                        .parse::<usize>()
                        .map_err(|_| BridgeError::Sql("do: placeholder number".into()))?
                } else {
                    largest + 1
                };
                if number == 0 {
                    return Err(BridgeError::Sql("do: placeholder number".into()));
                }
                largest = largest.max(number);
                placeholders.push((token_start, i, number));
            }
            c if ident_byte(c) => {
                while i < bytes.len() && ident_byte(bytes[i]) {
                    i += 1;
                }
                let word = &sql[token_start..i];
                words += 1;
                let is = |w: &str| word.eq_ignore_ascii_case(w);
                create = match (words, create) {
                    (1, _) if is("create") => 1,
                    (2, 1) if is("trigger") => {
                        in_trigger = true;
                        0
                    }
                    (2, 1) if is("temp") || is("temporary") => 2,
                    (3, 2) if is("trigger") => {
                        in_trigger = true;
                        0
                    }
                    _ => 0,
                };
                end_after_semicolon = in_trigger && semicolon_in_body && is("end");
                semicolon_in_body = false;
                second_statement |= after_semicolon;
                significant_end = i;
                continue;
            }
            _ => i += 1,
        }
        words += 1;
        create = 0;
        semicolon_in_body = false;
        end_after_semicolon = false;
        // A significant token after a `;` begins a second statement.
        second_statement |= after_semicolon;
        significant_end = i;
    }
    Ok(Lexed {
        placeholders,
        significant_end,
        second_statement,
    })
}

/// The statement text the runtime is given: `sql` without the comments
/// after it, with every placeholder whose bound value is an
/// [`SqlValue::Int`] written `+CAST(?N AS INTEGER)`, and every bare `?`
/// given its number. Without an `Int` parameter the placeholders are left
/// as they are.
///
/// `CAST` makes the value an integer, as a native binding is; the unary
/// `+` takes away the INTEGER affinity that `CAST` would give it, so a
/// comparison with a TEXT or untyped value converts nothing, as with a
/// native binding (`'5' = ?1` with 5 is false on both). An index on the
/// other side of the comparison is still used.
///
/// One statement only: a second one after a `;` is refused, as rusqlite
/// refuses it.
pub fn bind_text<'a>(sql: &'a str, params: &[SqlValue]) -> Result<Cow<'a, str>> {
    let lexed = lex(sql)?;
    if lexed.second_statement {
        return Err(BridgeError::Sql("do: more than one statement".into()));
    }
    let sql = &sql[..lexed.significant_end];
    if !params.iter().any(|p| matches!(p, SqlValue::Int(_))) {
        return Ok(Cow::Borrowed(sql));
    }
    let mut out = String::with_capacity(sql.len() + 24 * params.len());
    let mut copied = 0;
    for (start, end, number) in lexed.placeholders {
        out.push_str(&sql[copied..start]);
        if matches!(params.get(number - 1), Some(SqlValue::Int(_))) {
            out.push_str(&format!("+CAST(?{number} AS INTEGER)"));
        } else {
            out.push_str(&format!("?{number}"));
        }
        copied = end;
    }
    out.push_str(&sql[copied..]);
    Ok(Cow::Owned(out))
}

/// The end of the last part of `sql` that is neither white space nor a
/// comment, by the rules of [`bind_text`]. A script that names a
/// parameter ends where it ends.
pub fn significant_end(sql: &str) -> usize {
    lex(sql).map_or(sql.len(), |l| l.significant_end)
}

/// Refuses what D1 refuses, with the same messages: more than
/// [`MAX_SQL_PARAMS`] bound values, or one above [`MAX_SQL_VALUE_BYTES`].
/// The SQLite storage of a Durable Object has the same two limits.
fn check_params(params: &[SqlValue]) -> Result<()> {
    if params.len() > MAX_SQL_PARAMS {
        return Err(BridgeError::Sql(format!(
            "too many bound parameters: {} > {MAX_SQL_PARAMS}",
            params.len()
        )));
    }
    let size = |v: &SqlValue| match v {
        SqlValue::Text(t) => t.len(),
        SqlValue::Blob(b) => b.len(),
        SqlValue::Null | SqlValue::Int(_) => 0,
    };
    if let Some(n) = params.iter().map(size).find(|n| *n > MAX_SQL_VALUE_BYTES) {
        return Err(BridgeError::Sql(format!(
            "bound value too large: {n} > {MAX_SQL_VALUE_BYTES}"
        )));
    }
    Ok(())
}

fn to_js(v: &SqlValue) -> Result<JsValue> {
    Ok(match v {
        SqlValue::Null => JsValue::NULL,
        SqlValue::Int(i) => JsValue::from_f64(int_to_number(*i)?),
        SqlValue::Text(s) => JsValue::from_str(s),
        SqlValue::Blob(b) => Uint8Array::from(b.as_slice()).into(),
    })
}

fn from_js(v: JsValue) -> Result<SqlValue> {
    if v.is_null() || v.is_undefined() {
        return Ok(SqlValue::Null);
    }
    if let Some(s) = v.as_string() {
        return Ok(SqlValue::Text(s));
    }
    if let Some(f) = v.as_f64() {
        return number_to_int(f).map(SqlValue::Int);
    }
    if let Some(buf) = v.dyn_ref::<ArrayBuffer>() {
        return Ok(SqlValue::Blob(Uint8Array::new(buf).to_vec()));
    }
    if let Some(arr) = v.dyn_ref::<Uint8Array>() {
        return Ok(SqlValue::Blob(arr.to_vec()));
    }
    Err(decode_err())
}

/// A rows-changed count from the shim; anything but a whole number is an
/// error, never "0 rows changed" (fenced catalogue calls read 0 as "lease
/// lost").
fn changes(n: &JsValue) -> Result<u64> {
    let f = n.as_f64().ok_or_else(decode_err)?;
    u64::try_from(number_to_int(f)?).map_err(|_| decode_err())
}

fn int_to_number(i: i64) -> Result<f64> {
    if !(-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&i) {
        return Err(BridgeError::Sql("do: integer outside JS safe range".into()));
    }
    Ok(i as f64)
}

fn number_to_int(f: f64) -> Result<i64> {
    let safe = MAX_SAFE_INT as f64;
    if !f.is_finite() || f.fract() != 0.0 || f.abs() > safe {
        return Err(BridgeError::Sql("do: number is not a safe integer".into()));
    }
    Ok(f as i64)
}

fn decode_err() -> BridgeError {
    BridgeError::Sql("do: unexpected result shape".into())
}

/// The runtime's error as a class. The `tx_guard` CHECK is
/// `GuardFailed`; a constraint failure and any other failure keep only
/// their class.
pub(crate) fn runtime_error(e: JsValue) -> BridgeError {
    map_err(e)
}

fn map_err(e: JsValue) -> BridgeError {
    let message = e
        .dyn_ref::<js_sys::Error>()
        .map(|e| String::from(e.message()))
        .or_else(|| e.as_string())
        .unwrap_or_default();
    if is_tx_guard_violation(&message) {
        BridgeError::GuardFailed
    } else if message.contains("constraint failed") {
        BridgeError::Sql("do: constraint violation".into())
    } else {
        BridgeError::Sql("do: statement failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(i: i64) -> SqlValue {
        SqlValue::Int(i)
    }

    fn text(s: &str) -> SqlValue {
        SqlValue::Text(s.into())
    }

    #[test]
    fn a_statement_without_an_integer_is_unchanged() {
        let sql = "SELECT a FROM t WHERE b = ? AND c = ?";
        let out = bind_text(sql, &[text("x"), SqlValue::Null]).unwrap();
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, sql);
    }

    #[test]
    fn bare_placeholders_are_numbered_and_integers_cast() {
        let out = bind_text(
            "INSERT INTO t VALUES (?, ?, ?)",
            &[int(1), text("a"), int(3)],
        )
        .unwrap();
        assert_eq!(
            out,
            "INSERT INTO t VALUES (+CAST(?1 AS INTEGER), ?2, +CAST(?3 AS INTEGER))"
        );
    }

    #[test]
    fn numbered_placeholders_keep_their_numbers() {
        let out = bind_text("SELECT ?2, ?1, ?2 + ?1", &[text("a"), int(7)]).unwrap();
        assert_eq!(
            out,
            "SELECT +CAST(?2 AS INTEGER), ?1, +CAST(?2 AS INTEGER) + ?1"
        );
    }

    #[test]
    fn a_bare_placeholder_follows_the_largest_number_so_far() {
        // SQLite: `?` after `?3` is `?4`, and after that `?` is `?5`.
        let out = bind_text(
            "SELECT ?3, ?, ?1, ?",
            &[int(1), int(2), int(3), int(4), int(5)],
        )
        .unwrap();
        assert_eq!(
            out,
            "SELECT +CAST(?3 AS INTEGER), +CAST(?4 AS INTEGER), +CAST(?1 AS INTEGER), +CAST(?5 AS INTEGER)"
        );
    }

    #[test]
    fn quoted_runs_and_comments_are_not_placeholders() {
        let sql = "SELECT '?', 'it''s ?', \"col?\", `b?`, [c?], x'3F' -- ? here\n, ? /* ? */ , ?";
        let out = bind_text(sql, &[int(1), int(2)]).unwrap();
        assert_eq!(
            out,
            "SELECT '?', 'it''s ?', \"col?\", `b?`, [c?], x'3F' -- ? here\n, +CAST(?1 AS INTEGER) /* ? */ , +CAST(?2 AS INTEGER)"
        );
    }

    #[test]
    fn json_paths_inside_literals_are_left_alone() {
        let sql = "SELECT json_extract(?, '$.a') WHERE ? = 1";
        let out = bind_text(sql, &[text("{}"), int(1)]).unwrap();
        assert_eq!(
            out,
            "SELECT json_extract(?1, '$.a') WHERE +CAST(?2 AS INTEGER) = 1"
        );
    }

    #[test]
    fn named_parameters_and_zero_are_refused() {
        assert!(bind_text("SELECT :a, ?", &[int(1)]).is_err());
        assert!(bind_text("SELECT ?0", &[int(1)]).is_err());
        // Not a parameter: a JSON path inside a literal, or a `$` alone.
        assert!(bind_text("SELECT '$x', ?", &[int(1)]).is_ok());
        assert!(bind_text("SELECT ? || '$'", &[int(1)]).is_ok());
    }

    #[test]
    fn an_unclosed_literal_or_comment_ends_the_scan() {
        assert_eq!(
            bind_text("SELECT ?, 'a?", &[int(1)]).unwrap(),
            "SELECT +CAST(?1 AS INTEGER), 'a?"
        );
        // An unclosed comment is a trailing comment: cut.
        assert_eq!(
            bind_text("SELECT ? /* ?", &[int(1)]).unwrap(),
            "SELECT +CAST(?1 AS INTEGER)"
        );
    }

    #[test]
    fn a_script_ends_at_its_last_statement() {
        let script = "CREATE TABLE t(a); -- one\n/* two */\nINSERT INTO t VALUES ('--');\n-- trailing\n-- comment\n";
        let end = significant_end(script);
        assert_eq!(
            &script[..end],
            "CREATE TABLE t(a); -- one\n/* two */\nINSERT INTO t VALUES ('--');"
        );
        assert_eq!(significant_end("  -- only\n"), 0);
        assert_eq!(significant_end("SELECT 1 /* x */"), 8);
        assert_eq!(significant_end("SELECT [a b]"), 12);
    }

    #[test]
    fn one_statement_only_and_the_comments_after_it_are_cut() {
        for sql in [
            "SELECT 1; SELECT 2",
            "SELECT 1;SELECT 2;",
            "SELECT 1; -- c\n SELECT 2",
        ] {
            assert!(bind_text(sql, &[]).is_err(), "{sql}");
        }
        assert_eq!(bind_text("SELECT 1;", &[]).unwrap(), "SELECT 1;");
        assert_eq!(bind_text("SELECT 1; -- c", &[]).unwrap(), "SELECT 1;");
        assert_eq!(
            bind_text("SELECT ?; /* c */", &[int(1)]).unwrap(),
            "SELECT +CAST(?1 AS INTEGER);"
        );
        // A `;` inside a literal or a comment is no end.
        assert_eq!(
            bind_text("SELECT ';' -- ;\n, 2", &[]).unwrap(),
            "SELECT ';' -- ;\n, 2"
        );
    }

    #[test]
    fn a_trigger_body_is_one_statement() {
        let trigger = "CREATE TRIGGER tr AFTER INSERT ON a BEGIN UPDATE c SET n = n + 1; \
                       DELETE FROM d WHERE x = 'end;'; END";
        assert_eq!(bind_text(trigger, &[]).unwrap(), trigger);
        let temp =
            "create temp trigger tr before delete on a begin select raise(abort, 'no'); end;";
        assert_eq!(bind_text(temp, &[]).unwrap(), temp);
        // After the trigger's END, a `;` ends it as any other statement.
        assert!(bind_text(&format!("{trigger}; SELECT 1"), &[]).is_err());
        // A column or a table named `trigger` does not make a trigger.
        assert!(bind_text("SELECT a AS b, c AS trigger FROM t; SELECT 2", &[]).is_err());
        assert!(bind_text("CREATE TABLE trigger(a); SELECT 1", &[]).is_err());
        // The END of a CASE inside the body does not end the trigger.
        let case = "CREATE TRIGGER t AFTER UPDATE ON a BEGIN \
                    UPDATE b SET x = CASE WHEN NEW.n > 0 THEN 1 ELSE 0 END; END";
        assert_eq!(bind_text(case, &[]).unwrap(), case);
        assert!(bind_text(&format!("{case}; SELECT 1"), &[]).is_err());
        assert_eq!(
            significant_end("CREATE TRIGGER t BEGIN SELECT 1; END; -- c"),
            37
        );
    }

    #[test]
    fn a_sigil_inside_an_identifier_is_no_parameter() {
        // `$` may continue an identifier; it starts no parameter there.
        assert_eq!(
            bind_text("SELECT a$b FROM t WHERE c = ?", &[int(1)]).unwrap(),
            "SELECT a$b FROM t WHERE c = +CAST(?1 AS INTEGER)"
        );
        // A parameter named outside ASCII is still a named parameter.
        assert!(bind_text("SELECT :\u{e9}, ?", &[int(1)]).is_err());
        assert!(bind_text("SELECT @x, ?", &[int(1)]).is_err());
        assert!(bind_text("SELECT $x, ?", &[int(1)]).is_err());
        assert!(bind_text("SELECT #x, ?", &[int(1)]).is_err());
    }

    #[test]
    fn a_script_of_comments_alone_has_no_end() {
        assert_eq!(significant_end("-- only\n/* and this */"), 0);
        assert_eq!(significant_end(""), 0);
    }

    #[test]
    fn unsafe_integers_are_refused_both_ways() {
        assert!(int_to_number(MAX_SAFE_INT).is_ok());
        assert!(int_to_number(-MAX_SAFE_INT).is_ok());
        assert!(int_to_number(MAX_SAFE_INT + 1).is_err());
        assert!(number_to_int(9_007_199_254_740_992.0).is_err());
        assert!(number_to_int(2.5).is_err());
        assert!(number_to_int(f64::NAN).is_err());
        assert_eq!(number_to_int(-42.0).unwrap(), -42);
    }

    #[test]
    fn parameter_limits_match_d1() {
        let many = vec![SqlValue::Null; MAX_SQL_PARAMS + 1];
        assert!(check_params(&many).is_err());
        assert!(check_params(&many[..MAX_SQL_PARAMS]).is_ok());
        let big = vec![SqlValue::Blob(vec![0; MAX_SQL_VALUE_BYTES + 1])];
        assert!(check_params(&big).is_err());
    }
}
