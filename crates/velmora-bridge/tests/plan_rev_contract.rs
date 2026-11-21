//! The `plan_rev` contract (`docs/units.md`, "Restore gate"), part 1:
//! the statements, by name.
//!
//! The stored plan of an extent never changes: `plan_rev` is 1 once a
//! plan is made, and no code raises it. A restore can therefore never
//! meet a plan that is newer than the one its articles were posted
//! under. This test reads the SQL of the catalogue crate and holds the
//! list of every statement that writes `plan_rev` on an extent row:
//!
//! - the two that write the literal 1 (`sql/outbox.rs`, the article
//!   plan and the packed plan);
//! - the three inserts of an extent row, which copy a value
//!   (`sql/objects.rs`, `sql/uploads.rs`, `sql/replay.rs`);
//! - the three updates of the replay (`sql/replay.rs`), each with the
//!   guard that keeps it from changing a plan that is already there.
//!
//! A statement that is not on the list fails, and so does a listed
//! update without its guard. Lifting this on purpose needs the
//! plan-change design first; the test is the gate
//! and is not weakened to get green.

use std::path::PathBuf;

/// One statement on the list: its file, a fragment that names it, and
/// for an update the guard it must carry.
struct Allowed {
    file: &'static str,
    names: &'static str,
    guard: Option<&'static str>,
    writes_literal_one: bool,
}

const ALLOWED: &[Allowed] = &[
    Allowed {
        file: "sql/outbox.rs",
        names: "UPDATE extents SET article_count = ?2, plan_rev = 1 WHERE id = ?1",
        guard: Some("article_count IS NULL"),
        writes_literal_one: true,
    },
    Allowed {
        file: "sql/outbox.rs",
        names: "UPDATE extents SET article_count = ?2, plan_rev = 1, plan = ?3,",
        guard: Some("article_count IS NULL"),
        writes_literal_one: true,
    },
    Allowed {
        file: "sql/objects.rs",
        names: "INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, plain_size,",
        guard: None,
        writes_literal_one: false,
    },
    Allowed {
        file: "sql/uploads.rs",
        names: "INSERT INTO extents(id, bucket_id, generation_id, state, seq, plain_offset, plain_size, cipher_size, media_header, key_mode, wrapped_file_key, plain_md5, plain_sha256, cipher_sha256, safety_state, article_count, plan_rev, created_at)",
        guard: None,
        writes_literal_one: false,
    },
    Allowed {
        file: "sql/replay.rs",
        names: "INSERT OR IGNORE INTO extents(",
        guard: None,
        writes_literal_one: false,
    },
    Allowed {
        file: "sql/replay.rs",
        names: "UPDATE extents SET article_count = ?2, plan_rev = ?3, plan = ?4, parity = ?5, parity_count = ?6",
        guard: Some("plan IS NULL AND NOT EXISTS (SELECT 1 FROM articles WHERE extent_id = ?1)"),
        writes_literal_one: false,
    },
    Allowed {
        file: "sql/replay.rs",
        names: "UPDATE extents SET article_count = ?2, plan_rev = ?3 WHERE",
        guard: Some("article_count IS NULL"),
        writes_literal_one: false,
    },
    Allowed {
        file: "sql/replay.rs",
        names: "UPDATE extents SET article_count = ?2, plan_rev = ?3, plan = ?4, parity = ?6, parity_count = ?7",
        guard: Some("plan = ?5"),
        writes_literal_one: false,
    },
];

/// Every string literal of a Rust source file, with `\` line
/// continuations joined and runs of white space made one space.
fn literals(src: &str) -> Vec<String> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'\'' => {
                // A char literal ('"' is one) or a lifetime: skip `'x'`
                // and `'\x'`, leave a lifetime alone.
                if bytes.get(i + 1) == Some(&b'\\') && bytes.get(i + 3) == Some(&b'\'') {
                    i += 4;
                } else if bytes.get(i + 2) == Some(&b'\'') {
                    i += 3;
                } else {
                    i += 1;
                }
            }
            b'"' => {
                let mut s = String::new();
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        match bytes.get(i + 1) {
                            Some(b'\n') => {
                                i += 2;
                                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                                    i += 1;
                                }
                                continue;
                            }
                            Some(&c) => {
                                s.push('\\');
                                s.push(c as char);
                                i += 2;
                                continue;
                            }
                            None => break,
                        }
                    }
                    s.push(bytes[i] as char);
                    i += 1;
                }
                i += 1;
                out.push(s.split_whitespace().collect::<Vec<_>>().join(" "));
            }
            _ => i += 1,
        }
    }
    out
}

/// A literal that writes `plan_rev` on an extent row.
fn writes_plan_rev(sql: &str) -> bool {
    let upper = sql.to_ascii_uppercase();
    let into_extents = upper.contains("INTO EXTENTS(") || upper.contains("INTO EXTENTS (");
    let update_extents = upper.starts_with("UPDATE EXTENTS ") || upper.contains(" UPDATE EXTENTS ");
    let names_it = sql.contains("plan_rev");
    if update_extents {
        // `SET ... plan_rev = ...` before the WHERE.
        let set = sql.split(" WHERE ").next().unwrap_or(sql);
        return set.contains("plan_rev =") || set.contains("plan_rev=");
    }
    into_extents && names_it
}

fn sources() -> Vec<(String, String)> {
    let root = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, std::fs::read_to_string(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn every_statement_that_writes_plan_rev_is_on_the_list_with_its_guard() {
    let mut found = Vec::new();
    for (file, text) in sources() {
        // The test doubles write fixtures; they are not catalogue code.
        if file == "testkit.rs" || file.starts_with("testkit") {
            continue;
        }
        for sql in literals(&text) {
            if writes_plan_rev(&sql) {
                found.push((file.clone(), sql));
            }
        }
    }
    let mut matched = vec![0usize; ALLOWED.len()];
    for (file, sql) in &found {
        let hits: Vec<usize> = ALLOWED
            .iter()
            .enumerate()
            .filter(|(_, a)| a.file == file && sql.contains(a.names))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "{file}: a statement that writes plan_rev and is not on the list (or matches {} entries): {sql}",
            hits.len()
        );
        let a = &ALLOWED[hits[0]];
        matched[hits[0]] += 1;
        if let Some(guard) = a.guard {
            let where_part = sql.split_once(" WHERE ").map_or("", |x| x.1);
            assert!(
                where_part.contains(guard),
                "{file}: a listed update without its guard `{guard}`: {sql}"
            );
        }
        if a.writes_literal_one {
            assert!(
                sql.contains("plan_rev = 1"),
                "{file}: this statement may only write the literal 1: {sql}"
            );
        }
    }
    for (a, n) in ALLOWED.iter().zip(&matched) {
        assert_eq!(
            *n, 1,
            "{}: `{}` found {n} times, once expected",
            a.file, a.names
        );
    }
    assert_eq!(found.len(), ALLOWED.len());
}

#[test]
fn the_scanner_sees_a_new_statement_and_a_missing_guard() {
    // The scanner itself: a statement written the way the catalogue
    // writes them is found, joined across its line continuations.
    let src = "const X: &str = \"UPDATE extents SET plan_rev = ?2 \\\n     WHERE id = ?1\";\n\
               let c = '\"'; // \"UPDATE extents SET plan_rev = 9\"\n";
    let lits = literals(src);
    assert_eq!(
        lits,
        vec!["UPDATE extents SET plan_rev = ?2 WHERE id = ?1".to_string()]
    );
    assert!(writes_plan_rev(&lits[0]));
    assert!(!writes_plan_rev(
        "UPDATE extents SET article_count = 1 WHERE plan_rev = 1"
    ));
    assert!(writes_plan_rev(
        "INSERT INTO extents(id, plan_rev) VALUES (?1, ?2)"
    ));
    assert!(!writes_plan_rev(
        "INSERT INTO verifications(extent_id, plan_rev) VALUES (?1, ?2)"
    ));
}
