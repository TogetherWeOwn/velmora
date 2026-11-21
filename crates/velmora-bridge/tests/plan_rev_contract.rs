//! The `plan_rev` contract (`docs/units.md`, "Restore gate"), part 1:
//! the statements, by name.
//!
//! The stored plan of an extent never changes: `plan_rev` is 1 once a
//! plan is made, and no code raises it. A restore can therefore never
//! meet a plan that is newer than the one its articles were posted
//! under. This test reads the SQL of the catalogue crate, of the Workers
//! and of every migration, and holds the list of every statement that
//! writes `plan_rev` on an extent row, **word for word**:
//!
//! - the two that write the literal 1 (`sql/outbox.rs`, the article
//!   plan and the packed plan);
//! - the three inserts of an extent row, which copy a value
//!   (`sql/objects.rs`, `sql/uploads.rs`, `sql/replay.rs`);
//! - the three updates of the replay (`sql/replay.rs`), each with the
//!   guard that keeps it from changing a plan that is already there.
//!
//! A statement is found however it is written: a `concat!` is read as one
//! statement, raw strings and escapes are read, case and identifier
//! quotes do not matter, `UPDATE OR … [schema.]extents` and `INSERT …
//! INTO extents` without a column list (which writes every column) count.
//! Any found statement that is not on the list, word for word, fails, so
//! a changed guard or an added `ON CONFLICT … DO UPDATE` fails too.
//! Lifting this on purpose needs the plan-change design first; the test
//! is the gate and is not weakened to get green.

use std::path::{Path, PathBuf};

/// The statements that may write `plan_rev`, by file, whitespace
/// collapsed, exactly as the code has them.
const ALLOWED: &[(&str, &str)] = &[
    (
        "crates/velmora-bridge/src/sql/outbox.rs",
        "UPDATE extents SET article_count = ?2, plan_rev = 1 WHERE id = ?1 AND article_count IS NULL",
    ),
    (
        "crates/velmora-bridge/src/sql/outbox.rs",
        "UPDATE extents SET article_count = ?2, plan_rev = 1, plan = ?3, parity = ?5, parity_count = ?6 WHERE id = ?1 AND article_count IS NULL AND cipher_size = ?4",
    ),
    (
        "crates/velmora-bridge/src/sql/objects.rs",
        "INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, plain_size, cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, plain_sha256, cipher_sha256, safety_state, article_count, plan_rev, last_verified_at, release_evidence, released_at, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
    ),
    (
        "crates/velmora-bridge/src/sql/uploads.rs",
        "INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, plain_size, cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, plain_sha256, cipher_sha256, safety_state, article_count, plan_rev, created_at) VALUES (?1,?2,NULL,'staged',NULL,NULL,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,?12,?13)",
    ),
    (
        "crates/velmora-bridge/src/sql/replay.rs",
        "INSERT OR IGNORE INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, plain_size, cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, plain_sha256, cipher_sha256, safety_state, article_count, plan_rev, created_at) VALUES (?1,?2,NULL,'staged',NULL,NULL,?3,?4,?5,?6,?7,?8,?9,?10,?11,NULL,?12,?13)",
    ),
    (
        "crates/velmora-bridge/src/sql/replay.rs",
        "UPDATE extents SET article_count = ?2, plan_rev = ?3, plan = ?4, parity = ?5, parity_count = ?6 WHERE id = ?1 AND plan IS NULL AND NOT EXISTS (SELECT 1 FROM articles WHERE extent_id = ?1)",
    ),
    (
        "crates/velmora-bridge/src/sql/replay.rs",
        "UPDATE extents SET article_count = ?2, plan_rev = ?3 WHERE id = ?1 AND article_count IS NULL",
    ),
    (
        "crates/velmora-bridge/src/sql/replay.rs",
        "UPDATE extents SET article_count = ?2, plan_rev = ?3, plan = ?4, parity = ?6, parity_count = ?7 WHERE id = ?1 AND plan = ?5",
    ),
];

// ---------------------------------------------------------------------------
// Reading the sources
// ---------------------------------------------------------------------------

/// The SQL-bearing pieces of a Rust source: every string literal, and
/// every `concat!(…)` as one piece (its literals joined by a space), with
/// escapes read and runs of white space made one space.
fn rust_pieces(src: &str) -> Vec<String> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    // Inside a `concat!(`: the paren depth and the literals so far.
    let mut concat: Option<(usize, Vec<String>)> = None;
    while i < b.len() {
        if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            // Rust block comments nest.
            let mut depth = 0;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if b[i] == b'\'' {
            // A char literal ('x', '\n', '\u{..}', '"') or a lifetime.
            if b.get(i + 1) == Some(&b'\\') {
                let mut j = i + 2;
                while j < b.len() && b[j] != b'\'' {
                    j += 1;
                }
                i = j + 1;
            } else if b.get(i + 2) == Some(&b'\'') {
                i += 3;
            } else {
                // A multi-byte char literal, or a lifetime.
                let mut j = i + 1;
                while j < b.len() && (b[j] as char).is_alphanumeric() || j < b.len() && b[j] >= 0x80
                {
                    j += 1;
                }
                i = if b.get(j) == Some(&b'\'') { j + 1 } else { j };
            }
            continue;
        }
        // A raw string: r"…", r#"…"#, br#"…"#.
        let raw_start = if b[i] == b'r' && !prev_ident(b, i) {
            Some(i + 1)
        } else if b[i] == b'b' && b.get(i + 1) == Some(&b'r') && !prev_ident(b, i) {
            Some(i + 2)
        } else {
            None
        };
        if let Some(mut j) = raw_start {
            let mut hashes = 0;
            while b.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) == Some(&b'"') {
                let body_start = j + 1;
                let mut k = body_start;
                let end = loop {
                    if k >= b.len() {
                        break b.len();
                    }
                    if b[k] == b'"'
                        && b[k + 1..]
                            .iter()
                            .take(hashes)
                            .filter(|c| **c == b'#')
                            .count()
                            == hashes
                    {
                        break k;
                    }
                    k += 1;
                };
                let text = String::from_utf8_lossy(&b[body_start..end]).to_string();
                push(&mut out, &mut concat, text);
                i = (end + 1 + hashes).min(b.len());
                continue;
            }
        }
        if b[i] == b'"' {
            let (text, next) = cooked(b, i + 1);
            push(&mut out, &mut concat, text);
            i = next;
            continue;
        }
        if b[i..].starts_with(b"concat!") && !prev_ident(b, i) {
            // `concat!(…)`, `concat![…]` or `concat! {…}`.
            let mut j = i + "concat!".len();
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if matches!(b.get(j), Some(b'(' | b'[' | b'{')) {
                if concat.is_none() {
                    concat = Some((1, Vec::new()));
                } else if let Some((depth, _)) = concat.as_mut() {
                    *depth += 1;
                }
                i = j + 1;
                continue;
            }
        }
        if let Some((depth, parts)) = concat.as_mut() {
            match b[i] {
                b'(' | b'[' | b'{' => *depth += 1,
                b')' | b']' | b'}' => {
                    *depth -= 1;
                    if *depth == 0 {
                        // Rust joins the pieces of a `concat!` with nothing.
                        out.push(parts.concat());
                        concat = None;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    out
}

fn prev_ident(b: &[u8], i: usize) -> bool {
    i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')
}

fn push(out: &mut Vec<String>, concat: &mut Option<(usize, Vec<String>)>, text: String) {
    match concat {
        Some((_, parts)) => parts.push(text),
        None => out.push(text),
    }
}

/// A `"…"` literal from `start` (after the quote): its text with escapes
/// read (`\n` as a new line, which ends an SQL line comment; `\t`, `\r`
/// as white space; `\x..` and `\u{..}` as their characters; a line
/// continuation as nothing), and the index after the closing quote.
fn cooked(b: &[u8], start: usize) -> (String, usize) {
    let mut s = String::new();
    let mut i = start;
    while i < b.len() && b[i] != b'"' {
        if b[i] == b'\\' {
            match b.get(i + 1) {
                Some(b'\n') | Some(b'\r') => {
                    i += 2;
                    while i < b.len() && b[i].is_ascii_whitespace() {
                        i += 1;
                    }
                }
                Some(b'n') => {
                    s.push('\n');
                    i += 2;
                }
                Some(b't') | Some(b'r') => {
                    s.push(' ');
                    i += 2;
                }
                Some(b'x') => {
                    let hex = std::str::from_utf8(&b[i + 2..(i + 4).min(b.len())]).unwrap_or("");
                    if let Ok(n) = u8::from_str_radix(hex, 16) {
                        s.push(n as char);
                    }
                    i += 4;
                }
                Some(b'u') if b.get(i + 2) == Some(&b'{') => {
                    let close = b[i..]
                        .iter()
                        .position(|c| *c == b'}')
                        .map_or(b.len(), |k| i + k);
                    let hex = std::str::from_utf8(&b[i + 3..close]).unwrap_or("");
                    if let Some(c) = u32::from_str_radix(hex, 16).ok().and_then(char::from_u32) {
                        s.push(c);
                    }
                    i = close + 1;
                }
                Some(&c) => {
                    s.push(c as char);
                    i += 2;
                }
                None => i += 1,
            }
            continue;
        }
        s.push(b[i] as char);
        i += 1;
    }
    (s, i + 1)
}

fn normalise(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A `.sql` file as one piece; its comments are dropped by [`words`].
fn sql_pieces(src: &str) -> Vec<String> {
    vec![src.to_string()]
}

// ---------------------------------------------------------------------------
// Finding the statements that write plan_rev
// ---------------------------------------------------------------------------

/// The words of a piece of SQL, lower case, identifier quotes dropped,
/// string literals as one token, punctuation as its own token.
fn words(sql: &str) -> Vec<String> {
    let b = sql.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'-' && b.get(i + 1) == Some(&b'-') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i < b.len() && !(b[i] == b'*' && b.get(i + 1) == Some(&b'/')) {
                i += 1;
            }
            i += 2;
        } else if c.is_ascii_whitespace() {
            i += 1;
        } else if c == b'\'' {
            i += 1;
            while i < b.len() && !(b[i] == b'\'' && b.get(i + 1) != Some(&b'\'')) {
                i += if b[i] == b'\'' { 2 } else { 1 };
            }
            i += 1;
            out.push("'…'".to_string());
        } else if c == b'"' || c == b'`' || c == b'[' {
            let close = if c == b'[' { b']' } else { c };
            let start = i + 1;
            i = start;
            while i < b.len() && b[i] != close {
                i += 1;
            }
            out.push(sql[start..i.min(sql.len())].to_ascii_lowercase());
            i += 1;
        } else if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c >= 0x80 {
            let start = i;
            while i < b.len()
                && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$' || b[i] >= 0x80)
            {
                i += 1;
            }
            out.push(sql[start..i].to_ascii_lowercase());
        } else {
            out.push((c as char).to_string());
            i += 1;
        }
    }
    out
}

/// The table a statement writes after `UPDATE [OR x]` or `INTO`, with
/// an optional `schema.` in front, and the index after it.
fn target(w: &[String], mut j: usize, after_update: bool) -> Option<(String, usize)> {
    if after_update && w.get(j).map(String::as_str) == Some("or") {
        j += 2;
    }
    let (table, mut next) = if w.get(j + 1).map(String::as_str) == Some(".") {
        (w.get(j + 2)?.clone(), j + 3)
    } else {
        (w.get(j)?.clone(), j + 1)
    };
    // `AS alias`, `INDEXED BY index`, `NOT INDEXED`.
    loop {
        match (
            w.get(next).map(String::as_str),
            w.get(next + 1).map(String::as_str),
        ) {
            (Some("as"), Some(_)) => next += 2,
            (Some("indexed"), Some("by")) => next += 3,
            (Some("not"), Some("indexed")) => next += 2,
            _ => break,
        }
    }
    Some((table, next))
}

/// The words of a `SET` list that starts at `j` (after `SET`): every
/// word up to the first `WHERE`, `RETURNING`, `FROM` or `;` outside
/// brackets, or the end. A row value `(a, plan_rev) = (…)` is inside.
fn set_list(w: &[String], mut j: usize) -> &[String] {
    let start = j;
    let mut depth = 0i32;
    while let Some(t) = w.get(j) {
        match t.as_str() {
            "(" => depth += 1,
            ")" => {
                depth -= 1;
                if depth < 0 {
                    break;
                }
            }
            "where" | "returning" | "from" | ";" if depth == 0 => break,
            _ => {}
        }
        j += 1;
    }
    &w[start..j]
}

/// The words between the `(` at `j` and its `)`.
fn bracketed(w: &[String], j: usize) -> &[String] {
    let mut depth = 0i32;
    let mut k = j;
    while let Some(t) = w.get(k) {
        match t.as_str() {
            "(" => depth += 1,
            ")" => {
                depth -= 1;
                if depth == 0 {
                    return &w[j + 1..k];
                }
            }
            _ => {}
        }
        k += 1;
    }
    &w[j + 1..]
}

/// Whether a piece of SQL writes `plan_rev` on an extent row, or may: in
/// the `SET` list of an `UPDATE` of `extents`; in the column list of an
/// insert into `extents`, or in its `ON CONFLICT … DO UPDATE SET`; by an
/// insert into `extents` without a column list, which writes every
/// column; or by a table renamed to `extents` (a rebuild).
fn writes_plan_rev(sql: &str) -> bool {
    let w = words(sql);
    // `plan_rev`, or a `format!` placeholder that may hold it.
    let has = |list: &[String]| list.iter().any(|t| t == "plan_rev" || t == "{");
    // A table rebuilt and renamed to `extents` writes every row of it.
    if w.windows(3)
        .any(|x| x[0] == "rename" && x[1] == "to" && x[2] == "extents")
    {
        return true;
    }
    for (i, t) in w.iter().enumerate() {
        match t.as_str() {
            "update" => {
                let Some((table, after)) = target(&w, i + 1, true) else {
                    continue;
                };
                // A table given by a placeholder may be `extents`.
                if (table == "extents" || table == "{")
                    && w.get(after).map(String::as_str) == Some("set")
                    && has(set_list(&w, after + 1))
                {
                    return true;
                }
                if table == "{" {
                    return true;
                }
            }
            "into" => {
                let Some((table, after)) = target(&w, i + 1, false) else {
                    continue;
                };
                if table == "{" {
                    return true;
                }
                if table != "extents" {
                    continue;
                }
                if w.get(after).map(String::as_str) != Some("(") || has(bracketed(&w, after)) {
                    return true;
                }
                // Every `DO UPDATE SET` of an upsert writes the same row.
                for (k, x) in w[after..].windows(3).enumerate() {
                    if x[0] == "do"
                        && x[1] == "update"
                        && x[2] == "set"
                        && has(set_list(&w, after + k + 3))
                    {
                        return true;
                    }
                }
            }
            // A migration that drops, adds or renames the column, or makes
            // the table from a query.
            "alter" if w.get(i + 1).map(String::as_str) == Some("table") => {
                let Some((table, after)) = target(&w, i + 2, false) else {
                    continue;
                };
                let statement = w[after..].iter().take_while(|t| *t != ";");
                if table == "extents" && statement.into_iter().any(|t| t == "plan_rev") {
                    return true;
                }
            }
            "create" => {
                let mut j = i + 1;
                if matches!(w.get(j).map(String::as_str), Some("temp" | "temporary")) {
                    j += 1;
                }
                if w.get(j).map(String::as_str) != Some("table") {
                    continue;
                }
                j += 1;
                if w.get(j).map(String::as_str) == Some("if") {
                    j += 3;
                }
                // `[schema.]extents AS SELECT …` (not `target`: it would
                // read the AS as an alias).
                if w.get(j + 1).map(String::as_str) == Some(".") {
                    j += 2;
                }
                if w.get(j).map(String::as_str) == Some("extents")
                    && w.get(j + 1).map(String::as_str) == Some("as")
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn files(root: &Path, dirs: &[&str], ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = dirs.iter().map(|d| root.join(d)).collect();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path
                    .file_name()
                    .is_some_and(|n| n == "node_modules" || n == "build" || n == "target")
                {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == ext) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn found() -> Vec<(String, String)> {
    let root = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let rel = |p: &Path| {
        p.strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/")
    };
    let mut out = Vec::new();
    for path in files(&root, &["crates/velmora-bridge/src", "workers"], "rs") {
        let file = rel(&path);
        // The test doubles write fixtures; they are not catalogue code.
        if file.starts_with("crates/velmora-bridge/src/testkit") {
            continue;
        }
        for piece in rust_pieces(&std::fs::read_to_string(&path).unwrap()) {
            if writes_plan_rev(&piece) {
                out.push((file.clone(), normalise(&piece)));
            }
        }
    }
    for path in files(&root, &["workers", "crates/velmora-bridge/src"], "sql") {
        let file = rel(&path);
        for piece in sql_pieces(&std::fs::read_to_string(&path).unwrap()) {
            if writes_plan_rev(&piece) {
                out.push((file.clone(), normalise(&piece)));
            }
        }
    }
    out
}

#[test]
fn every_statement_that_writes_plan_rev_is_on_the_list_word_for_word() {
    let found = found();
    let unlisted: Vec<&(String, String)> = found
        .iter()
        .filter(|(file, sql)| !ALLOWED.iter().any(|(f, s)| f == file && s == sql))
        .collect();
    assert!(
        unlisted.is_empty(),
        "statements that write plan_rev and are not on the list, word for word:\n{}",
        unlisted
            .iter()
            .map(|(f, s)| format!("  {f}: {s}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    for (file, sql) in ALLOWED {
        let n = found.iter().filter(|(f, s)| f == file && s == sql).count();
        assert_eq!(n, 1, "{file}: found {n} times, once expected: {sql}");
    }
}

#[test]
fn the_scanner_finds_a_statement_however_it_is_written() {
    let one = |src: &str| -> Vec<String> {
        rust_pieces(src)
            .into_iter()
            .filter(|p| writes_plan_rev(p))
            .collect()
    };
    for src in [
        // Joined across a `concat!` and a line continuation.
        "const X: &str = concat!(\"UPDATE extents SET article_count = ?2, \", \"plan_rev = 2 WHERE id = ?1\");",
        "const X: &str = \"UPDATE extents SET plan_rev = ?2 \\\n     WHERE id = ?1\";",
        // Another form of UPDATE, a schema, case, quotes, a row value.
        "const X: &str = \"UPDATE OR IGNORE extents SET plan_rev = 2 WHERE id = ?1\";",
        "const X: &str = \"UPDATE main.extents SET plan_rev = 2\";",
        "const X: &str = \"update EXTENTS set PLAN_REV = 2\";",
        "const X: &str = \"UPDATE extents SET \\\"plan_rev\\\" = 2\";",
        "const X: &str = \"UPDATE extents SET (article_count, plan_rev) = (?2, 2)\";",
        "const X: &str = \"UPDATE extents SET seq = (SELECT 1 FROM g WHERE id = ?2), plan_rev = 2 WHERE id = ?1\";",
        // An escape and a raw string.
        "const X: &str = \"UPDATE extents\\nSET plan_rev = 2\";",
        "const X: &str = r#\"UPDATE \"extents\" SET plan_rev = 2\"#;",
        // An insert without a column list writes every column.
        "const X: &str = \"INSERT INTO extents SELECT * FROM old\";",
        "const X: &str = \"INSERT INTO extents VALUES (?1, ?2)\";",
        // An upsert.
        "const X: &str = \"INSERT INTO extents(id) VALUES (?1) ON CONFLICT(id) DO UPDATE SET plan_rev = plan_rev + 1\";",
        // An alias and the index hints.
        "const X: &str = \"UPDATE extents AS e SET plan_rev = 2\";",
        "const X: &str = \"UPDATE extents INDEXED BY ix SET plan_rev = 2\";",
        "const X: &str = \"UPDATE extents NOT INDEXED SET plan_rev = 2\";",
        // Comments inside the statement, and `--` inside a literal.
        "const X: &str = \"UPDATE /* c */ extents SET plan_rev = 2\";",
        "const X: &str = \"UPDATE extents -- c\\nSET plan_rev = 2\";",
        "const X: &str = \"UPDATE extents SET note = '--', plan_rev = 2\";",
        // Rust's own ways of building a literal.
        "const X: &str = concat![\"UPDATE extents SET \", \"plan_rev = 2\"];",
        "const X: &str = concat! (\"UPDATE extents SET plan_\", \"rev = 2\");",
        "const X: &str = \"UPDATE extents SET plan\\u{5f}rev = 2\";",
        "const X: &str = \"UPDATE extents SET plan\\x5frev = 2\";",
        // `format!`: a placeholder may hold the column or the table.
        "let s = format!(\"INSERT OR REPLACE INTO extents({EXTENT_COLS}) VALUES ({v})\");",
        "let s = format!(\"UPDATE extents SET {SET} WHERE id = ?1\");",
        "let s = format!(\"UPDATE {table} SET n = 1\");",
        "let s = format!(\"INSERT INTO {table} VALUES (?1)\");",
        // A second upsert clause.
        "const X: &str = \"INSERT INTO extents(id) VALUES (?1) ON CONFLICT(id) DO UPDATE SET n = 1 ON CONFLICT DO UPDATE SET plan_rev = 2\";",
    ] {
        assert_eq!(one(src).len(), 1, "not found: {src}");
    }
    // A comment does not hide what follows it.
    let after_comment = "/* a \" quote */ const X: &str = \"UPDATE extents SET plan_rev = 2\";";
    assert_eq!(one(after_comment).len(), 1);
    // Not writes of plan_rev on an extent row.
    for src in [
        "const X: &str = \"UPDATE extents SET article_count = 1 WHERE id = ?1\";",
        "const X: &str = \"UPDATE extents SET last_verified_at = ?2 WHERE ?6 = plan_rev\";",
        "const X: &str = \"INSERT INTO verifications(extent_id, plan_rev) VALUES (?1, ?2)\";",
        "const X: &str = \"UPDATE verify_raises SET plan_rev = (SELECT plan_rev FROM extents)\";",
        "const X: &str = \"SELECT plan_rev FROM extents\";",
        "// \"UPDATE extents SET plan_rev = 2\"",
    ] {
        assert!(one(src).is_empty(), "found: {src}");
    }
    // A migration's trigger body is read too, and a comment in it hides
    // nothing.
    let sql = "CREATE TRIGGER t AFTER INSERT ON x BEGIN UPDATE extents SET plan_rev = 2; END; -- plan_rev";
    assert!(writes_plan_rev(&sql_pieces(sql)[0]));
    let sql = "UPDATE /* backfill */ extents SET plan_rev = 2;";
    assert!(writes_plan_rev(&sql_pieces(sql)[0]));
    // Migrations that drop, add or rename the column, or make the table
    // from a query.
    for sql in [
        "ALTER TABLE extents DROP COLUMN plan_rev;",
        "ALTER TABLE extents ADD COLUMN plan_rev INTEGER NOT NULL DEFAULT 2;",
        "ALTER TABLE extents RENAME COLUMN other TO plan_rev;",
        "CREATE TABLE extents AS SELECT * FROM old;",
    ] {
        assert!(writes_plan_rev(&sql_pieces(sql)[0]), "{sql}");
    }
    assert!(!writes_plan_rev(
        "ALTER TABLE extents ADD COLUMN last_read_at INTEGER;"
    ));
    assert!(!writes_plan_rev(
        "CREATE TABLE extents (id TEXT, plan_rev INTEGER NOT NULL DEFAULT 0)"
    ));
    // A rebuild of the table writes every row of it.
    let rebuild = "CREATE TABLE extents_new (id TEXT, plan_rev INTEGER);\n\
                   INSERT INTO extents_new(id, plan_rev) SELECT id, plan_rev + 1 FROM extents;\n\
                   DROP TABLE extents;\nALTER TABLE extents_new RENAME TO extents;";
    assert!(writes_plan_rev(&sql_pieces(rebuild)[0]));
    // A character outside ASCII outside a literal does not trip the reader.
    assert!(one("let \u{e9} = 1; const X: &str = \"UPDATE extents SET plan_rev = 2\";").len() == 1);
}
