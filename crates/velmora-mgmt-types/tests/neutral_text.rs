//! The crate's `src/` holds no deny-listed term (KA-F7 (1)).
//!
//! A caller keeps a checked copy of `src/` in a repository whose CI runs a
//! deny-list over every tracked file: customer-facing material there must
//! not name how or where data is stored, the internal project, people or
//! private paths. This test runs the same rules over `src/` here, so a
//! change that would fail the caller's copy fails this repository's CI
//! first. It is a port of that checker (`tools/f7/check.mjs` in
//! `TogetherWeOwn/kofra-api`); the term lists below are its
//! `tools/f7/terms.json` and `tools/f7/allow.json` at `bcc9dc5`, kept as
//! SHA-256 hashes of the lowercase terms, as there. When the caller's list
//! changes, copy it again.
//!
//! The port is conservative: it does not blank blobs before the short
//! class, and also checks candidates where blanking could expose a new
//! token or change a token part. Its email and whitespace rules can also
//! flag more than the checker. Every file under `src/` must be Rust source;
//! another kind fails the test until this port covers its rules.
//!
//! This file lives outside `src/`, so it is not part of the copy.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use velmora_mgmt_types::idem::{hex, key_hash};

// The checker's lists (`terms.json`), as SHA-256 hex of the lowercase terms.
const STRICT: [&str; 20] = [
    "0805febed88ee3f114f11b596db509d807297b6b97325446638ae97df6701b3d",
    "0aedb001db1b74b6344b5f172eb6c5507f0616ddc54864a4e44f4503321acba0",
    "0ed80614304d49d468706678f6384a1f9e3674af35fb4ae8d2222082c1dc8091",
    "21a27eee7361887f9472301251783f71c588e5dec08d785bab5b07546ecf4f86",
    "27a56e822eb824fdaa3be3ceef83f45155b7c024f19bcd6847eb50ed481c0df3",
    "304584d86d0c626480601a1147ec1b784070dd7569d41abf1b5e4cc159000547",
    "38acfb3b6047c1c6f2f010e022ebd59587dc1057b90f4b8e325503e8f324d74f",
    "4135727fb2a0f9f8e797ca7b9423c5c2ceda74d5b1e00b265fc0d2913caaa38e",
    "4a2693cccb61524b160fed27b73378e6abc0fc42cb2d455725af9f614ed68f92",
    "574623b392b52accfc77abdfbc05a05eb4ecc0f2f84cd2fe4db348a9c84fe988",
    "5bd20b1429301ffece1e15fb102ca635b14879d48431cd5aaa497b7491711545",
    "670d47ccb9a6cdef180e87d03ef6a3b783c771ecac19fb76c3ba5551ab369da8",
    "678b45d95ff7c75678781dfc03625a192042b7d832cded973eb9abc5fc78745d",
    "86681f107a8ad2abfe47bfbac4b8d4bbf84df5e5ad9c4ccc47d47c6cb1e9c715",
    "87e84d8d2bc2dacfe213b7966dff492352a5e30835c45ca939f7384e282fd326",
    "8801a13c3308b815bab6d6068c1cdbcd7d965f83ab31632f16d8ef4ab284240c",
    "a985b46c05be9e7f74d5f4eb7f655ec20c0946df17a32ad27f9a9ee74753f679",
    "ab39960d0fef3a6caee5cdcb7ec568464336be5a1598b3f69476d4c16c2f30fd",
    "b2e78e3a5bb1d60df728818ea576deafd6ba9b428fefe13794e012f226516dad",
    "fcb7233b835a8fea49703c0a1b44869bda47017040c1fb9228b7507db6a81c6b",
];
const STRICT_LENGTHS: [usize; 8] = [5, 6, 7, 8, 9, 10, 11, 15];
const SHORT: [&str; 5] = [
    "0a73e419735a5b4300bfe2f5a7a6da8f947801b6a4ca3aef7ee287ba66cb3482",
    "255b28b74315db29c415b09f585f2e7cc19caf029d4e200454515ba1b7dabe3d",
    "4bebff23ba85576aa1aae2da796fae9fe7c2ef3d6060f5f210f07b7a062588de",
    "5099941fc6e5440244a41b3f6e466d8933f73ea1647f042bf051b380a43acdcc",
    "e722121095c7998c703acdd37183ee8265c80f077df0620ebc1c7dd66c3ad1ec",
];
const SHORT_LENGTHS: [usize; 2] = [3, 4];
const PROSE: [&str; 13] = [
    "03e71c6d7dc6bd4e89ceaf32f6488ca0aa69b0de784b706cac5818d680e9d97f",
    "08fddbc83d3de346b066c02bde82e898a0a75742cdc23c0b87706152c6facebd",
    "1637cc683d5c44284751994ea032108f8d54ef4e4b989a7a593d14e312c6a5e9",
    "293b9207228b7854bc3ccb2959ebea1583e066d41983124a5b381d6fdf6575f8",
    "4ed379d418bb86290a01117e9ceb0debffc4d1b7087db6c04882fbc4e50132f4",
    "72231043bc1807e6f740b235eb7511ecb33255a6a375435631196de8a9750d4b",
    "84393add8c489d33569360efd1bcb5f70ed5a22408127d241c751e5ea345eb7c",
    "906c7ff47cd7c682246c270be1792afc3ab522478848b1dd13cb514e8a670035",
    "95bbb36a8786c764f97434bcf51679e4ec577b9035372341ca17142462c45899",
    "a44f1b975171163546d46ba5ca80652f85fcad7f665cf55d00a202ff9d0f7dbe",
    "ad936fcbed631fa67e05c3ea03953905221c9d46af0616b70badf105a966fb11",
    "cdee118dac7496e7cd8fee4d1c490b1f2bb4d550d47e77e67eea0dd7a4e44389",
    "f5c30f61e7389c2cf733ff6846d820421fb500fa9a127401f6c99af85c45cca5",
];

/// Exact words the prose class skips (`allow.json`).
const PROSE_ALLOW: [&str; 2] = ["POST", "POSTs"];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Hit {
    path: String,
    line: usize,
    class: &'static str,
    text: String,
}

struct Terms {
    strict: HashSet<&'static str>,
    short: HashSet<&'static str>,
    prose: HashSet<&'static str>,
    allow: HashSet<&'static str>,
}

impl Terms {
    fn new() -> Terms {
        Terms {
            strict: STRICT.into_iter().collect(),
            short: SHORT.into_iter().collect(),
            prose: PROSE.into_iter().collect(),
            allow: PROSE_ALLOW.into_iter().collect(),
        }
    }
}

fn sha(s: &str) -> String {
    hex(&key_hash(s))
}

fn is_sep(c: char) -> bool {
    matches!(c, '.' | '_' | '-')
}

/// `[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*`, every match in order.
fn tokens(line: &str) -> Vec<String> {
    let c: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        if !c[i].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let start = i;
        while i < c.len() && c[i].is_ascii_alphanumeric() {
            i += 1;
        }
        while i + 1 < c.len() && is_sep(c[i]) && c[i + 1].is_ascii_alphanumeric() {
            i += 1;
            while i < c.len() && c[i].is_ascii_alphanumeric() {
                i += 1;
            }
        }
        out.push(c[start..i].iter().collect());
    }
    out
}

/// The checker's token parts: split at `.`, `_` and `-`, and at the
/// lower-to-upper, acronym-to-word and letter-digit edges.
fn parts(raw: &str) -> Vec<String> {
    let c: Vec<char> = raw.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    for i in 0..c.len() {
        if is_sep(c[i]) {
            out.push(std::mem::take(&mut cur));
            continue;
        }
        if i > 0 && !cur.is_empty() {
            let (p, x) = (c[i - 1], c[i]);
            let next_lower = c.get(i + 1).is_some_and(|n| n.is_ascii_lowercase());
            let edge = (p.is_ascii_lowercase() && x.is_ascii_uppercase())
                || (p.is_ascii_uppercase() && x.is_ascii_uppercase() && next_lower)
                || (p.is_ascii_digit() && x.is_ascii_alphabetic())
                || (p.is_ascii_alphabetic() && x.is_ascii_digit());
            if edge {
                out.push(std::mem::take(&mut cur));
            }
        }
        cur.push(c[i]);
    }
    out.push(cur);
    out
}

/// Short matches in an unblanked ASCII token, including candidates
/// exposed by the checker's blob blanking.
fn is_short(t: &Terms, raw: &str) -> bool {
    let matches_prefix = |candidate: &str| {
        SHORT_LENGTHS.iter().any(|&len| {
            candidate
                .get(..len)
                .is_some_and(|prefix| t.short.contains(sha(&prefix.to_ascii_lowercase()).as_str()))
        })
    };
    let joined = raw.replace(is_sep, "");
    let mut offset = 0;
    for segment in raw.split(is_sep) {
        // Blanking consumes the rest of an alphanumeric run. A newly exposed
        // token starts at a segment boundary; its parts are already in `parts(raw)`.
        if matches_prefix(&joined[offset..]) {
            return true;
        }
        offset += segment.len();
    }
    if parts(raw).iter().any(|p| matches_prefix(p)) {
        return true;
    }

    // A checksum can also start inside a run. Ending the token there can
    // remove an acronym-to-word edge (the final capital loses its lowercase
    // lookahead). Recheck the last part of those prefixes.
    let sha_prefixes = raw.match_indices("sha").filter_map(|(i, _)| {
        // The hyphen may be outside this token when the payload starts with `+` or `/`.
        let algorithm = raw[i + "sha".len()..].split('-').next();
        matches!(algorithm, Some("1" | "256" | "384" | "512")).then_some(&raw[..i])
    });
    sha_prefixes
        .chain(raw.strip_suffix("h1"))
        .any(|prefix| parts(prefix).last().is_some_and(|p| matches_prefix(p)))
}

/// Strict and short hits in one line.
fn scan_line(t: &Terms, line: &str) -> Vec<(&'static str, String)> {
    let mut hits = Vec::new();
    for raw in tokens(line) {
        let token: String = raw.to_lowercase().chars().filter(|c| !is_sep(*c)).collect();
        for l in STRICT_LENGTHS {
            for i in 0..token.len().saturating_sub(l - 1) {
                if t.strict.contains(sha(&token[i..i + l]).as_str()) {
                    hits.push(("strict", raw.clone()));
                }
            }
        }
        if is_short(t, &raw) {
            hits.push(("short", raw));
        }
    }
    let mut seen = HashSet::new();
    hits.retain(|h| seen.insert(h.clone()));
    hits
}

/// Prose hits: `[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*` words, whole, without
/// their hyphens, and by part.
fn scan_prose(t: &Terms, text: &str) -> Vec<String> {
    let c: Vec<char> = text.chars().collect();
    let mut words = Vec::new();
    let mut i = 0;
    while i < c.len() {
        if !c[i].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let start = i;
        while i < c.len() && c[i].is_ascii_alphanumeric() {
            i += 1;
        }
        while i + 1 < c.len() && c[i] == '-' && c[i + 1].is_ascii_alphanumeric() {
            i += 1;
            while i < c.len() && c[i].is_ascii_alphanumeric() {
                i += 1;
            }
        }
        words.push(c[start..i].iter().collect::<String>());
    }
    let mut hits = Vec::new();
    for word in words {
        if t.allow.contains(word.as_str()) {
            continue;
        }
        let lower = word.to_lowercase();
        let mut cands = vec![lower.clone(), lower.replace('-', "")];
        cands.extend(
            parts(&word)
                .into_iter()
                .filter(|p| !p.is_empty() && !t.allow.contains(p.as_str()))
                .map(|p| p.to_lowercase()),
        );
        if cands.iter().any(|c| t.prose.contains(sha(c).as_str())) {
            hits.push(word);
        }
    }
    hits
}

/// A superset of JavaScript's `\s`: Rust's whitespace plus the BOM.
fn checker_whitespace(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

/// The checker's comment rule for code files:
/// `(?:^|\s)(?:\/\/+|#|\/\*+|\*)\s?(.*)$`, the leftmost match.
fn comment(line: &str) -> Option<&str> {
    let b = line.as_bytes();
    for (i, ch) in line.char_indices() {
        let at_start = i == 0
            || line[..i]
                .chars()
                .next_back()
                .is_some_and(checker_whitespace);
        if !at_start {
            continue;
        }
        let mut j = i;
        if line[i..].starts_with("//") {
            while j < b.len() && b[j] == b'/' {
                j += 1;
            }
        } else if line[i..].starts_with("/*") {
            j += 1;
            while j < b.len() && b[j] == b'*' {
                j += 1;
            }
        } else if ch == '#' || ch == '*' {
            j += 1;
        } else {
            continue;
        }
        let rest = &line[j..];
        return Some(match rest.chars().next() {
            Some(w) if checker_whitespace(w) => &rest[w.len_utf8()..],
            _ => rest,
        });
    }
    None
}

/// Any `local@domain.tld` address whose domain is not an allowed one
/// (stricter than the checker: the domain is matched loosely).
fn emails(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = line.as_bytes();
    for (at, _) in line.match_indices('@') {
        let local = |c: u8| c.is_ascii_alphanumeric() || b"._%+-".contains(&c);
        if at == 0 || !local(b[at - 1]) {
            continue;
        }
        let mut end = at + 1;
        while end < b.len() && (b[end].is_ascii_alphanumeric() || b".-".contains(&b[end])) {
            end += 1;
        }
        let domain = line[at + 1..end].trim_end_matches(['.', '-']);
        // `([A-Za-z0-9-]+\.)+[A-Za-z]{2,}` matches some prefix of the
        // run when a label is followed by a dot and two letters.
        let d = domain.as_bytes();
        let looks = (1..d.len()).any(|k| {
            d[k] == b'.'
                && d[k - 1] != b'.'
                && d.get(k + 1).is_some_and(u8::is_ascii_alphabetic)
                && d.get(k + 2).is_some_and(u8::is_ascii_alphabetic)
        });
        let ok = [
            "example.com",
            "example.org",
            "example.net",
            "kofra.app",
            "kofra.io",
        ]
        .iter()
        .any(|d| domain.eq_ignore_ascii_case(d));
        if looks && !ok {
            let mut start = at;
            while start > 0 && local(b[start - 1]) {
                start -= 1;
            }
            out.push(line[start..end].to_string());
        }
    }
    out
}

/// A home-directory path: `/home/<name>`, `/Users/<name>`, the root home,
/// `~/<path>`, or a Windows user folder.
fn home_path(line: &str) -> bool {
    let b = line.as_bytes();
    let fname = |c: &u8| c.is_ascii_alphanumeric() || b"._-".contains(c);
    for i in 0..b.len() {
        let rest = &b[i..];
        let free = i == 0 || !b[i - 1].is_ascii_alphanumeric();
        if free {
            for p in [&b"/home/"[..], &b"/Users/"[..]] {
                if rest.starts_with(p) && rest.get(p.len()).is_some_and(u8::is_ascii_alphabetic) {
                    return true;
                }
            }
            if let Some(after) = rest.strip_prefix(b"/root") {
                let ends = match after.first() {
                    None | Some(b'/') => true,
                    Some(b'.') => !after
                        .get(1)
                        .is_some_and(|c| c.is_ascii_alphanumeric() || b"_-".contains(c)),
                    Some(c) => !fname(c),
                };
                if ends {
                    return true;
                }
            }
            if rest.len() > 3
                && rest[0].is_ascii_alphabetic()
                && rest[1..].starts_with(b":\\")
                && (rest[3..].starts_with(b"Users\\") || rest[3..].starts_with(b"\\Users\\"))
            {
                return true;
            }
        }
        if rest.starts_with(b"~/")
            && rest.get(2).is_some_and(fname)
            && line[..i]
                .chars()
                .next_back()
                .is_none_or(|c| checker_whitespace(c) || "\"'=(:`".contains(c))
        {
            return true;
        }
    }
    false
}

/// Every finding in one file: its path, then its text.
fn scan_file(t: &Terms, rel: &str, text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut push = |line: usize, class: &'static str, text: String| {
        hits.push(Hit {
            path: rel.to_string(),
            line,
            class,
            text,
        })
    };
    for (class, s) in scan_line(t, rel) {
        push(0, class, s);
    }
    for e in emails(rel) {
        push(0, "email", e);
    }
    if home_path(rel) {
        push(0, "path", rel.to_string());
    }
    if text.contains('\0') {
        push(1, "binary", "NUL byte".into());
        return hits;
    }
    for (n, line) in text.split('\n').enumerate() {
        for (class, s) in scan_line(t, line) {
            push(n + 1, class, s);
        }
        for e in emails(line) {
            push(n + 1, "email", e);
        }
        if home_path(line) {
            push(n + 1, "path", line.trim().to_string());
        }
        if let Some(c) = comment(line) {
            for w in scan_prose(t, c) {
                push(n + 1, "prose", w);
            }
        }
    }
    hits
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn the_source_names_no_deny_listed_term() {
    let t = Terms::new();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut all = Vec::new();
    files(&src, &mut all);
    assert!(all.len() >= 10, "src/ looks empty: {all:?}");
    let mut hits = Vec::new();
    for p in &all {
        let rel = format!(
            "src/{}",
            p.strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        );
        assert!(
            rel.ends_with(".rs"),
            "{rel}: only Rust source is covered by this port; extend it first"
        );
        let text = fs::read_to_string(p).unwrap_or_else(|e| panic!("{rel}: {e}"));
        hits.extend(scan_file(&t, &rel, &text));
    }
    let report: Vec<String> = hits
        .iter()
        .map(|h| format!("{}:{}: {} term in {:?}", h.path, h.line, h.class, h.text))
        .collect();
    assert!(
        report.is_empty(),
        "{} finding(s); the caller's copy would fail its deny-list:\n{}",
        report.len(),
        report.join("\n")
    );
}

/// Positive controls: each class finds a term this repository may name
/// openly, and the rules around it behave as the checker's do.
#[test]
fn the_port_finds_what_the_checker_finds() {
    let t = Terms::new();
    let classes = |line: &str| -> Vec<&'static str> {
        let mut c: Vec<_> = scan_file(&t, "src/x.rs", line)
            .into_iter()
            .map(|h| h.class)
            .collect();
        c.dedup();
        c
    };
    // Strict: a substring of any token, in code as well as comments.
    assert_eq!(classes("let x = velmora_bridge;"), ["strict"]);
    assert_eq!(classes("const A: &str = \"MyVelmoraThing\";"), ["strict"]);
    assert_eq!(
        classes("use some.vel-mora.path;"),
        ["strict"],
        "separators are removed"
    );
    // Short: the start of a token or of a token part.
    assert_eq!(classes("fn nntp_client() {}"), ["short"]);
    assert_eq!(classes("fn fromNntp() {}"), ["short"]);
    assert!(classes("fn unntp() {}").is_empty(), "not at a part start");
    assert!(
        classes("let h = \"0123456789abcdef0123456789abcdef\";").is_empty(),
        "a hex run without a short term is clean"
    );
    // Prose: whole words of comments only.
    assert_eq!(classes("/// One article per call."), ["prose"]);
    assert_eq!(classes("let x = 1; // an article"), ["prose"]);
    assert_eq!(
        classes("#[doc = \"article\"]"),
        ["prose"],
        "`#` starts a comment for the checker"
    );
    assert!(
        classes("let article = 1;").is_empty(),
        "code words are not prose"
    );
    assert!(
        classes("/// A `POST` with no body.").is_empty(),
        "the allowed exact token"
    );
    // Addresses and home paths.
    assert_eq!(
        classes("/// a@example.com and b@kofra.app"),
        Vec::<&str>::new()
    );
    assert_eq!(classes("/// mail ops@corp.dev"), ["email"]);
    assert_eq!(
        classes("/// id a1@b2.cd3"),
        ["email"],
        "the checker backtracks to `b2.cd`"
    );
    assert_eq!(classes("/// see /home/someone/x"), ["path"]);
    assert_eq!(classes("/// see ~/notes"), ["path"]);
    // Blanking can expose a token start or change the last acronym part.
    let padded = format!("\"{}==B.nn.tp\"", "A".repeat(40));
    let probes = [
        ("\"h1:abc.nn.tp\"", "short"),
        ("\"xsha256-abc.nn.tp\"", "short"),
        (&padded, "short"),
        ("\"prefixNNTPsha256-abc\"", "short"),
        ("\"prefixNNTPsha256-+abc\"", "short"),
        ("\u{feff}//! One article per call.", "prose"),
        ("let a = 1;\u{feff}// an article", "prose"),
        ("/// see\u{a0}~/notes", "path"),
        ("/// see\u{b}~/notes", "path"),
    ];
    let missed: Vec<_> = probes
        .into_iter()
        .filter(|(line, class)| !classes(line).contains(class))
        .collect();
    assert!(missed.is_empty(), "missing expected findings: {missed:?}");
    // File paths are checked too.
    assert_eq!(
        scan_file(&t, "src/velmora.rs", "")
            .first()
            .map(|h| (h.line, h.class)),
        Some((0, "strict"))
    );
}

/// The hashes are what the checker compares: SHA-256 of the lowercase
/// term, as lowercase hex.
#[test]
fn the_term_lists_are_hashes() {
    for h in STRICT.iter().chain(SHORT.iter()).chain(PROSE.iter()) {
        assert_eq!(h.len(), 64, "{h}");
        assert!(
            h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{h}"
        );
    }
    assert!(STRICT.contains(&sha("velmora").as_str()));
    assert!(SHORT.contains(&sha("nntp").as_str()));
    assert!(PROSE.contains(&sha("article").as_str()));
}
