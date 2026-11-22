//! The WebDAV `If` header (RFC 4918 §10.4): parsing and evaluation.
//!
//! ```text
//! If = ( 1*No-tag-list | 1*Tagged-list )
//! Tagged-list = Resource-Tag 1*List
//! List = "(" 1*Condition ")"
//! Condition = ["Not"] ( State-token | "[" entity-tag "]" )
//! ```
//!
//! A list is true when all its conditions are; the header is true when
//! any list is. A state token is true when it names a lock that covers
//! the list's resource; an entity tag is true when it equals the
//! resource's current one (strong comparison). Every state token named
//! outside a `Not` counts as submitted for lock checks.

/// One condition of a list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cond {
    /// A state token (a lock token, or anything in angle brackets).
    Token(String),
    /// An entity tag as written, quotes included.
    ETag(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Condition {
    pub not: bool,
    pub cond: Cond,
}

/// One parenthesised list, with the resource it is tagged with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct List {
    /// The resource tag as written (an absolute URL or a path); `None`
    /// for an untagged list, which applies to the request URL.
    pub tag: Option<String>,
    pub conditions: Vec<Condition>,
}

/// An `If` header outside the grammar (`400`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadIf;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IfHeader {
    pub lists: Vec<List>,
}

/// What the evaluation needs to know of one resource.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub etag: Option<String>,
    pub tokens: Vec<String>,
}

fn skip_ws(s: &[u8], i: &mut usize) {
    while *i < s.len() && matches!(s[*i], b' ' | b'\t' | b'\r' | b'\n') {
        *i += 1;
    }
}

/// Reads up to the closing byte; the text in between.
fn until(s: &str, i: &mut usize, close: u8) -> Result<String, BadIf> {
    let b = s.as_bytes();
    let start = *i;
    while *i < b.len() && b[*i] != close {
        *i += 1;
    }
    if *i >= b.len() {
        return Err(BadIf);
    }
    let out = s[start..*i].to_owned();
    *i += 1;
    Ok(out)
}

/// Parses an `If` header value. A mix of tagged and untagged lists, an
/// empty list or anything outside the grammar is an error (`400`).
pub fn parse(value: &str) -> Result<IfHeader, BadIf> {
    let b = value.as_bytes();
    let mut i = 0;
    let mut out = IfHeader::default();
    let mut tag: Option<String> = None;
    let mut tagged = None;
    loop {
        skip_ws(b, &mut i);
        if i >= b.len() {
            break;
        }
        match b[i] {
            b'<' => {
                if tagged == Some(false) {
                    return Err(BadIf);
                }
                tagged = Some(true);
                i += 1;
                tag = Some(until(value, &mut i, b'>')?);
                // A tag must be followed by at least one list.
                skip_ws(b, &mut i);
                if i >= b.len() || b[i] != b'(' {
                    return Err(BadIf);
                }
            }
            b'(' => {
                if tagged.is_none() {
                    tagged = Some(false);
                }
                i += 1;
                let mut conditions = Vec::new();
                loop {
                    skip_ws(b, &mut i);
                    if i >= b.len() {
                        return Err(BadIf);
                    }
                    if b[i] == b')' {
                        i += 1;
                        break;
                    }
                    let mut not = false;
                    if b.len() - i >= 3 && b[i..i + 3].eq_ignore_ascii_case(b"not") {
                        not = true;
                        i += 3;
                        skip_ws(b, &mut i);
                        if i >= b.len() {
                            return Err(BadIf);
                        }
                    }
                    let cond = match b[i] {
                        b'<' => {
                            i += 1;
                            Cond::Token(until(value, &mut i, b'>')?)
                        }
                        b'[' => {
                            i += 1;
                            Cond::ETag(until(value, &mut i, b']')?.trim().to_owned())
                        }
                        _ => return Err(BadIf),
                    };
                    conditions.push(Condition { not, cond });
                }
                if conditions.is_empty() {
                    return Err(BadIf);
                }
                out.lists.push(List {
                    tag: tag.clone(),
                    conditions,
                });
            }
            _ => return Err(BadIf),
        }
    }
    if out.lists.is_empty() {
        return Err(BadIf);
    }
    Ok(out)
}

impl IfHeader {
    /// State tokens named outside `Not`, in order, without repeats.
    pub fn submitted(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for list in &self.lists {
            for c in &list.conditions {
                if let (false, Cond::Token(t)) = (c.not, &c.cond) {
                    if !out.contains(t) {
                        out.push(t.clone());
                    }
                }
            }
        }
        out
    }

    /// The distinct resource tags, in order.
    pub fn tags(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for list in &self.lists {
            if let Some(t) = &list.tag {
                if !out.contains(t) {
                    out.push(t.clone());
                }
            }
        }
        out
    }

    /// Evaluates the header. `state(None)` is the request URL;
    /// `state(Some(tag))` a tagged resource (a resource that does not
    /// exist, or one outside this server, has no etag and no locks).
    pub fn evaluate(&self, state: impl Fn(Option<&str>) -> State) -> bool {
        self.matching_list(state).is_some()
    }

    pub(crate) fn matching_list(&self, state: impl Fn(Option<&str>) -> State) -> Option<&List> {
        self.lists.iter().find(|list| {
            let s = state(list.tag.as_deref());
            list.conditions.iter().all(|c| {
                let held = match &c.cond {
                    Cond::Token(t) => s.tokens.iter().any(|have| have == t),
                    Cond::ETag(e) => {
                        !e.starts_with("W/") && s.etag.as_deref().is_some_and(|have| have == e)
                    }
                };
                held != c.not
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(t: &str) -> Condition {
        Condition {
            not: false,
            cond: Cond::Token(t.into()),
        }
    }

    #[test]
    fn parses_the_grammar() {
        let h = parse(r#"(<urn:uuid:a> ["e1"]) (Not <DAV:no-lock>)"#).unwrap();
        assert_eq!(h.lists.len(), 2);
        assert_eq!(
            h.lists[0].conditions,
            [
                tok("urn:uuid:a"),
                Condition {
                    not: false,
                    cond: Cond::ETag("\"e1\"".into())
                }
            ]
        );
        assert!(h.lists[1].conditions[0].not);
        assert_eq!(h.submitted(), ["urn:uuid:a"]);

        let h =
            parse(r#"<https://h/b/f.txt> (<urn:uuid:x>) <http://h/b/g> (["a"]) (not<urn:uuid:y>)"#)
                .unwrap();
        assert_eq!(h.lists.len(), 3);
        assert_eq!(h.lists[0].tag.as_deref(), Some("https://h/b/f.txt"));
        assert_eq!(h.lists[2].tag.as_deref(), Some("http://h/b/g"));
        assert_eq!(h.tags(), ["https://h/b/f.txt", "http://h/b/g"]);
        assert_eq!(h.submitted(), ["urn:uuid:x"]);

        for bad in [
            "",
            "()",
            "(<a>",
            "<x>",
            "<x> <y> (<a>)",
            "(<a>) <x> (<b>)",
            "<x> (<a>) (<b>) junk",
            "(Not)",
            "([e)",
            "urn:uuid:a",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn evaluates_lists() {
        let state = |tag: Option<&str>| match tag {
            None => State {
                etag: Some("\"e1\"".into()),
                tokens: vec!["urn:uuid:a".into()],
            },
            Some("/b/other") => State {
                etag: None,
                tokens: vec!["urn:uuid:o".into()],
            },
            Some(_) => State::default(),
        };
        let t = |s: &str| parse(s).unwrap().evaluate(state);
        assert!(t("(<urn:uuid:a>)"));
        assert!(!t("(<urn:uuid:b>)"));
        assert!(t("(<urn:uuid:b>) (<urn:uuid:a>)"));
        assert!(t(r#"(<urn:uuid:a> ["e1"])"#));
        assert!(!t(r#"(<urn:uuid:a> ["e2"])"#));
        assert!(!t(r#"(<urn:uuid:a> [W/"e1"])"#));
        assert!(t("(Not <DAV:no-lock>)"));
        assert!(!t("(<DAV:no-lock>)"));
        assert!(t(r#"(<urn:uuid:x> ["e1"]) (Not <DAV:no-lock> ["e1"])"#));
        assert!(t("</b/other> (<urn:uuid:o>)"));
        assert!(!t("</b/other> (<urn:uuid:a>)"));
        assert!(!t("<http://elsewhere/x> (<urn:uuid:a>)"));
    }
}
