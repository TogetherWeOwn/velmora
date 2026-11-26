//! One simple-Query message per write transaction: the bind markers of each
//! catalogue statement are replaced by closed, ASCII-only typed literals.
//!
//! Every value has already passed `value::Params::encode` (integer range,
//! NUL, size, count), so both transports refuse the same values. The
//! rendering is a closed set:
//!
//! | value | literal |
//! |---|---|
//! | INT8  | `'<decimal>'::int8` |
//! | TEXT  | `E'...'::text`; `\` and `'` doubled, every control character, DEL and non-ASCII code point as `\uXXXX` or `\UXXXXXXXX` |
//! | BYTEA | `E'\\x<lowercase hex>'::bytea` |
//! | NULL  | `NULL` |
//!
//! Every byte of the message is ASCII, so no client encoding can join a
//! byte to the next one, and an E-string means the same whatever
//! `standard_conforming_strings` is. A Unicode escape above U+007F needs a
//! server encoding that can hold the character; otherwise the server
//! raises an error and nothing commits.
//!
//! The message never reaches a log, an error or the test recorder: it
//! carries the values, which can include wrapped key material.

use std::fmt::Write as _;

use tokio_postgres::types::Type;

use super::batch::Prepared;
use crate::{BridgeError, Result};

/// The largest message sent as one Query. Above it, the transaction uses
/// the typed pipelined transport.
pub const MAX_WRITE_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Between statements. The newline ends a trailing line comment of the
/// statement before it; an empty statement between two `;` is skipped by
/// the server and has no reply.
const SEPARATOR: &str = "\n;\n";

enum Literal<'a> {
    Int(i64),
    Text(&'a str),
    Blob(&'a [u8]),
    Null,
}

fn shape() -> BridgeError {
    BridgeError::Sql("pg: bind failed".into())
}

fn literal<'a>(raw: Option<&'a [u8]>, ty: &Type) -> Result<Literal<'a>> {
    Ok(match (raw, ty) {
        (None, _) => Literal::Null,
        (Some(raw), &Type::INT8) => {
            Literal::Int(i64::from_be_bytes(raw.try_into().map_err(|_| shape())?))
        }
        (Some(raw), &Type::TEXT) => Literal::Text(std::str::from_utf8(raw).map_err(|_| shape())?),
        (Some(raw), &Type::BYTEA) => Literal::Blob(raw),
        _ => return Err(shape()),
    })
}

fn decimal_len(v: i64) -> u64 {
    let mut n = u64::from(v < 0) + 1;
    let mut m = v.unsigned_abs();
    while m >= 10 {
        m /= 10;
        n += 1;
    }
    n
}

fn char_len(c: char) -> u64 {
    match c {
        '\\' | '\'' => 2,
        c if (c as u32) < 0x20 || c == '\x7f' => 6,
        c if c.is_ascii() => 1,
        c if (c as u32) <= 0xFFFF => 6,
        _ => 10,
    }
}

/// The exact rendered length, computed before anything is allocated.
fn literal_len(lit: &Literal<'_>) -> u64 {
    match lit {
        // '<decimal>'::int8
        Literal::Int(v) => 1 + decimal_len(*v) + 7,
        // E'...'::text
        Literal::Text(s) => 2 + s.chars().map(char_len).sum::<u64>() + 7,
        // E'\\x...'::bytea
        Literal::Blob(b) => 5 + 2 * b.len() as u64 + 8,
        Literal::Null => 4,
    }
}

fn render_literal(out: &mut String, lit: &Literal<'_>) {
    match lit {
        Literal::Int(v) => {
            write!(out, "'{v}'::int8").expect("writing to a String does not fail");
        }
        Literal::Text(s) => {
            out.push_str("E'");
            for c in s.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '\'' => out.push_str("''"),
                    c if (c as u32) < 0x20 || c == '\x7f' || !c.is_ascii() => {
                        let code = c as u32;
                        if code <= 0xFFFF {
                            write!(out, "\\u{code:04X}")
                        } else {
                            write!(out, "\\U{code:08X}")
                        }
                        .expect("writing to a String does not fail");
                    }
                    c => out.push(c),
                }
            }
            out.push_str("'::text");
        }
        Literal::Blob(b) => {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.push_str("E'\\\\x");
            for byte in *b {
                out.push(HEX[usize::from(byte >> 4)] as char);
                out.push(HEX[usize::from(byte & 15)] as char);
            }
            out.push_str("'::bytea");
        }
        Literal::Null => out.push_str("NULL"),
    }
}

fn untranslated() -> BridgeError {
    BridgeError::Sql("pg: untranslated statement".into())
}

/// The whole write transaction as one Query string: `prelude`, every
/// statement with literals, then `end`. `None` when it would exceed
/// [`MAX_WRITE_MESSAGE_BYTES`]; then nothing has been allocated.
pub(super) fn message(prelude: &str, prepared: &[Prepared], end: &str) -> Result<Option<String>> {
    if !prelude.is_ascii() || !end.is_ascii() {
        return Err(untranslated());
    }
    // Sizing pass: the exact length, from the static text and each value.
    let mut total = prelude.len() as u64 + SEPARATOR.len() as u64 + end.len() as u64;
    for p in prepared {
        // The values are ASCII by construction; the statement text must be
        // too, so that the whole message is.
        if !p.statement.text.is_ascii() {
            return Err(untranslated());
        }
        let values = p.literals()?;
        let mut len = SEPARATOR.len() as u64 + p.statement.text.len() as u64;
        for bind in &p.statement.binds {
            let lit = values.get(bind.ordinal - 1).ok_or_else(shape)?;
            len = len - (bind.end - bind.start) as u64 + literal_len(lit);
        }
        total = total.saturating_add(len);
    }
    if total > MAX_WRITE_MESSAGE_BYTES as u64 {
        return Ok(None);
    }
    let mut out = String::with_capacity(total as usize);
    out.push_str(prelude);
    for p in prepared {
        out.push_str(SEPARATOR);
        let values = p.literals()?;
        let text = &p.statement.text;
        let mut at = 0;
        for bind in &p.statement.binds {
            out.push_str(&text[at..bind.start]);
            render_literal(&mut out, &values[bind.ordinal - 1]);
            at = bind.end;
        }
        out.push_str(&text[at..]);
    }
    out.push_str(SEPARATOR);
    out.push_str(end);
    // The sizing pass is exact, and the message is ASCII. Refuse rather
    // than send anything else.
    if out.len() as u64 != total || !out.is_ascii() {
        return Err(untranslated());
    }
    Ok(Some(out))
}

impl Prepared {
    fn literals(&self) -> Result<Vec<Literal<'_>>> {
        self.values()
            .wire()
            .map(|(raw, ty)| literal(raw, ty))
            .collect()
    }
}

/// One rendered value, for the property tests.
#[cfg(any(test, feature = "testkit-pg"))]
pub(crate) fn render_value(value: &crate::SqlValue) -> Result<String> {
    let params = super::value::Params::encode(std::slice::from_ref(value))?;
    let (raw, ty) = params.wire().next().ok_or_else(shape)?;
    let lit = literal(raw, ty)?;
    let mut out = String::with_capacity(literal_len(&lit) as usize);
    render_literal(&mut out, &lit);
    debug_assert_eq!(out.len() as u64, literal_len(&lit));
    Ok(out)
}

/// The rendered length of one value without rendering it.
#[cfg(test)]
pub(crate) fn value_len(value: &crate::SqlValue) -> Result<u64> {
    let params = super::value::Params::encode(std::slice::from_ref(value))?;
    let (raw, ty) = params.wire().next().ok_or_else(shape)?;
    Ok(literal_len(&literal(raw, ty)?))
}
