use crate::{BridgeError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Read,
    Write,
}

pub(crate) struct Statement {
    pub text: String,
    pub kind: Kind,
    pub select: bool,
    /// Every bind marker of `text`, in order: its byte range there and
    /// its 1-based ordinal. Only code tokens are markers, never text in a
    /// string, quoted identifier or comment.
    pub binds: Vec<Bind>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Bind {
    pub start: usize,
    pub end: usize,
    pub ordinal: usize,
}

impl Statement {
    /// The highest bind ordinal, or 0 without binds.
    pub fn max_bind(&self) -> usize {
        self.binds.iter().map(|b| b.ordinal).max().unwrap_or(0)
    }
}

fn untranslated() -> BridgeError {
    BridgeError::Sql("pg: untranslated statement".into())
}

fn word_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b >= 128
}

fn word_byte(b: u8) -> bool {
    word_start(b) || b.is_ascii_digit()
}

fn quoted(bytes: &[u8], mut i: usize) -> Result<usize> {
    let delim = bytes[i];
    i += 1;
    while i < bytes.len() {
        if bytes[i] == delim {
            i += 1;
            if bytes.get(i) != Some(&delim) {
                return Ok(i);
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    Err(untranslated())
}

fn writes_or_locks(token: &str) -> bool {
    matches!(
        token,
        "INSERT"
            | "UPDATE"
            | "DELETE"
            | "MERGE"
            | "NEXTVAL"
            | "SETVAL"
            | "INTO"
            | "SHARE"
            | "SET_CONFIG"
    ) || token.starts_with("PG_ADVISORY_")
        || token.starts_with("PG_TRY_ADVISORY_")
}

pub(crate) fn statement(sql: &str) -> Result<Statement> {
    scan(sql, true)
}

pub(crate) fn is_read_only(sql: &str) -> bool {
    scan(sql, false).is_ok_and(|s| s.kind == Kind::Read)
}

/// Translate bind markers, not SQL semantics. Tokenize code separately from
/// strings, identifiers and comments for both dialect refusal and routing.
fn scan(sql: &str, postgres: bool) -> Result<Statement> {
    if sql.as_bytes().contains(&0) {
        return Err(untranslated());
    }
    let bytes = sql.as_bytes();
    let mut text = String::with_capacity(sql.len());
    let (mut i, mut depth, mut ordinal) = (0, 0_usize, 0_usize);
    let mut command = None;
    let mut with = false;
    let mut writes = false;
    let mut ended = false;
    let mut previous = String::new();
    let mut binds = Vec::new();
    while i < bytes.len() {
        let start = i;
        match bytes[i] {
            b if b.is_ascii_whitespace() => i += 1,
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                i += 2;
                // SQLite ends line comments at LF or EOF, not a bare CR.
                while i < bytes.len() && bytes[i] != b'\n' && (!postgres || bytes[i] != b'\r') {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                // SQLite's tokenizer does not recognize a bare `/*` at EOF.
                if !postgres && i == bytes.len() {
                    return Err(untranslated());
                }
                // Only PostgreSQL nests block comments and requires a closer.
                let mut nesting = 1;
                while nesting != 0 {
                    match bytes.get(i..i + 2) {
                        Some(b"/*") if postgres => {
                            nesting += 1;
                            i += 2;
                        }
                        Some(b"*/") => {
                            nesting -= 1;
                            i += 2;
                        }
                        _ if i < bytes.len() => i += 1,
                        _ if !postgres => break,
                        _ => return Err(untranslated()),
                    }
                }
            }
            _ if ended => return Err(untranslated()),
            b'\'' => {
                i = quoted(bytes, i)?;
                previous.clear();
            }
            b'"' => {
                i = quoted(bytes, i)?;
                let token = sql[start + 1..i - 1].to_ascii_uppercase();
                writes |= writes_or_locks(&token);
                previous = token;
            }
            b'`' if !postgres => {
                i = quoted(bytes, i)?;
                previous.clear();
            }
            b'[' if !postgres => {
                // Unlike the other quotes, `]` is not escaped by doubling it.
                i += sql[i + 1..].find(']').ok_or_else(untranslated)? + 2;
                previous.clear();
            }
            b'$' | b':' | b'@' | b'#' if !postgres => {
                // Catalogue SQL uses positional `?` binds. Refuse SQLite named
                // binds: their parenthesized suffix can contain comment markers.
                return Err(untranslated());
            }
            b';' => {
                ended = true;
                i += 1;
            }
            b'(' => {
                if postgres
                    && matches!(
                        previous.as_str(),
                        "JSON_OBJECT" | "TYPEOF" | "QUOTE" | "INSTR" | "PRINTF" | "STRFTIME"
                    )
                {
                    return Err(untranslated());
                }
                depth += 1;
                previous.clear();
                i += 1;
            }
            b')' => {
                if !postgres && depth == 0 {
                    return Err(untranslated());
                }
                depth = depth.saturating_sub(1);
                previous.clear();
                i += 1;
            }
            b'?' | b'$' => {
                let marker = bytes[i];
                i += 1;
                let digits = i;
                while bytes.get(i).is_some_and(u8::is_ascii_digit) {
                    i += 1;
                }
                if i > digits || marker == b'?' {
                    let n = if i == digits {
                        ordinal.checked_add(1).ok_or_else(untranslated)?
                    } else {
                        sql[digits..i]
                            .parse::<usize>()
                            .ok()
                            .filter(|&n| n != 0)
                            .ok_or_else(untranslated)?
                    };
                    ordinal = ordinal.max(n);
                    let at = text.len();
                    text.push('$');
                    text.push_str(&n.to_string());
                    binds.push(Bind {
                        start: at,
                        end: text.len(),
                        ordinal: n,
                    });
                    previous.clear();
                    continue;
                }
                // Dollar-quoted strings (including an empty tag).
                if bytes.get(i).is_some_and(|&b| word_start(b)) {
                    i += 1;
                    while bytes.get(i).is_some_and(|&b| word_byte(b)) {
                        i += 1;
                    }
                }
                if bytes.get(i) != Some(&b'$') {
                    return Err(untranslated());
                }
                let delimiter = &sql[start..=i];
                i += 1;
                i += sql[i..].find(delimiter).ok_or_else(untranslated)? + delimiter.len();
                previous.clear();
            }
            // SQLite can treat a UTF-8 BOM as whitespace, not part of the
            // next keyword. Refuse unquoted non-ASCII instead of guessing.
            b if !postgres && !b.is_ascii() => return Err(untranslated()),
            b if word_start(b) => {
                i += 1;
                while bytes
                    .get(i)
                    .is_some_and(|&b| (postgres || b.is_ascii()) && (word_byte(b) || b == b'$'))
                {
                    i += 1;
                }
                let token = sql[start..i].to_ascii_uppercase();
                if postgres
                    && (matches!(
                        token.as_str(),
                        "JSON_EACH" | "JSON_EXTRACT" | "ROWID" | "GLOB" | "SQLITE_MASTER"
                    ) || matches!(
                        (previous.as_str(), token.as_str()),
                        ("OR", "IGNORE" | "REPLACE") | ("INDEXED", "BY")
                    ))
                {
                    return Err(untranslated());
                }
                // Catalogue statements do not use PostgreSQL escape literals.
                if postgres && token == "E" && bytes.get(i) == Some(&b'\'') {
                    return Err(untranslated());
                }
                let dml = matches!(token.as_str(), "INSERT" | "UPDATE" | "DELETE" | "MERGE");
                writes |= writes_or_locks(&token);
                if depth == 0 && command.is_none() {
                    if dml || token == "SELECT" {
                        command = Some(token == "SELECT");
                    } else if !with {
                        if token != "WITH" {
                            return Err(untranslated());
                        }
                        with = true;
                    }
                }
                previous = token;
            }
            _ => {
                previous.clear();
                i += 1;
            }
        }
        text.push_str(&sql[start..i]);
    }
    if !postgres && depth != 0 {
        return Err(untranslated());
    }
    let select = command.ok_or_else(untranslated)?;
    Ok(Statement {
        text,
        kind: if select && !writes {
            Kind::Read
        } else {
            Kind::Write
        },
        select,
        binds,
    })
}
