//! The statement text an adapter gives a runtime that binds every
//! number as a SQLite REAL: every placeholder whose value is an
//! [`SqlValue::Int`] is written `+CAST(?N AS INTEGER)`, so SQLite sees
//! the integer a native binding gives ([`bind_text`]).
//!
//! Two adapters use it. The Durable Object adapter (`velmora-unit-do`)
//! binds the integer as a JS number, so it takes only `±(2^53 - 1)`.
//! The D1 adapter of the Worker binds it as its decimal text
//! ([`cast_bound`]), so every `i64` is stored exactly.

use std::borrow::Cow;

use crate::ports::SqlValue;
use crate::types::{BridgeError, Result};

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
/// A named parameter (`:a`, `@a`, `$a`, `#a`, wherever it stands) is
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
            // A `$` inside an identifier was taken by the identifier
            // branch; any sigil that reaches here starts a parameter, also
            // right after a word (`LIMIT:n`, `WHERE@x`, `1#x`).
            b':' | b'@' | b'$' | b'#' if bytes.get(i + 1).is_some_and(|c| ident_byte(*c)) => {
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

/// The statement and the values for a runtime that binds text exactly:
/// [`bind_text`]'s statement, and every [`SqlValue::Int`] as its decimal
/// text, which `CAST(… AS INTEGER)` reads back as the same `i64`. The
/// returned values hold no `Int`.
pub fn cast_bound<'a>(sql: &'a str, params: &[SqlValue]) -> Result<(Cow<'a, str>, Vec<SqlValue>)> {
    let text = bind_text(sql, params)?;
    let values = params
        .iter()
        .map(|p| match p {
            SqlValue::Int(i) => SqlValue::Text(i.to_string()),
            other => other.clone(),
        })
        .collect();
    Ok((text, values))
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
        // Right after a word or a number, SQLite still reads a parameter.
        for sql in [
            "SELECT 1 LIMIT:n",
            "SELECT ?, 1 WHERE@x IS NULL OR ? = 2",
            "SELECT 1#x",
        ] {
            assert!(bind_text(sql, &[int(1), int(2)]).is_err(), "{sql}");
        }
    }

    #[test]
    fn a_script_of_comments_alone_has_no_end() {
        assert_eq!(significant_end("-- only\n/* and this */"), 0);
        assert_eq!(significant_end(""), 0);
    }
}
