//! Query strings: lists, the bucket name lookup, the key kind, usage days
//! and the tenant delete hold.
//!
//! A query is `name=value` pairs joined by `&`, each value percent-encoded
//! ([`encode`]); `+` is a plus sign, not a space. A parameter that the
//! call does not take, a parameter given twice (except `name`), a value
//! that does not decode and an empty pair each answer `400 bad_request`.
//! The builders here write the parameters in a fixed order, so that the
//! same request has the same fingerprint.
//!
//! **Lists:** `?after=<position>&limit=<n>`, `limit` 1 to 1,000 (default
//! 100). The answer is a [`Page`](crate::wire::Page) (`{items, next}`) or,
//! for the tenant events, an [`EventPage`](crate::wire::EventPage).

use std::ops::RangeInclusive;

use crate::codes::Code;
use crate::ids::valid_bucket_name;
use crate::position::{Day, InvalidPosition};
use crate::wire::KeyKind;

/// The `limit` of a list.
pub const LIMITS: RangeInclusive<u32> = 1..=1000;

/// The `limit` of a list that names none.
pub const DEFAULT_LIMIT: u32 = 100;

/// The most names of one bucket name lookup.
pub const MAX_NAMES: usize = 64;

/// The shortest hold of a tenant delete, in days.
pub const MIN_HOLD_DAYS: u32 = 7;

/// The longest hold of a tenant delete, in days.
pub const MAX_HOLD_DAYS: u32 = 3650;

/// Percent-encodes `v`: every byte but `A-Z a-z 0-9 - . _ ~`.
pub fn encode(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Decodes a percent-encoded value; `None` for a bad escape or a value
/// that is not UTF-8.
pub fn decode(v: &str) -> Option<String> {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3)?;
            let s = std::str::from_utf8(hex).ok()?;
            if !s.bytes().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u8::from_str_radix(s, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The pairs of a query (the part after `?`, without it), decoded, each
/// name one of `allowed`, and each but `name` at most once.
fn pairs(query: &str, allowed: &[&str]) -> Result<Vec<(String, String)>, Code> {
    let mut out: Vec<(String, String)> = Vec::new();
    if query.is_empty() {
        return Ok(out);
    }
    for part in query.split('&') {
        let (n, v) = part.split_once('=').ok_or(Code::BadRequest)?;
        let (n, v) = (
            decode(n).ok_or(Code::BadRequest)?,
            decode(v).ok_or(Code::BadRequest)?,
        );
        if !allowed.contains(&n.as_str()) || (n != "name" && out.iter().any(|(m, _)| *m == n)) {
            return Err(Code::BadRequest);
        }
        out.push((n, v));
    }
    Ok(out)
}

fn get<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find_map(|(n, v)| (n == name).then_some(v.as_str()))
}

fn join(parts: &[(&str, String)]) -> String {
    parts
        .iter()
        .map(|(n, v)| format!("{n}={}", encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `after` and `limit` of a list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct List {
    pub after: Option<String>,
    pub limit: u32,
}

impl Default for List {
    fn default() -> List {
        List {
            after: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

impl List {
    fn from_pairs(pairs: &[(String, String)]) -> Result<List, Code> {
        let after = get(pairs, "after").map(str::to_string);
        let limit = match get(pairs, "limit") {
            None => DEFAULT_LIMIT,
            Some(v) => {
                let canonical = !v.is_empty() && v.len() <= 4 && !v.starts_with('0');
                let n: u32 = canonical
                    .then(|| v.parse().ok())
                    .flatten()
                    .ok_or(Code::BadRequest)?;
                if !LIMITS.contains(&n) {
                    return Err(Code::BadRequest);
                }
                n
            }
        };
        if after.as_ref().is_some_and(|a| a.is_empty()) {
            return Err(Code::InvalidPosition);
        }
        Ok(List { after, limit })
    }

    /// The list parameters of a query that takes only these two.
    pub fn parse(query: &str) -> Result<List, Code> {
        List::from_pairs(&pairs(query, &["after", "limit"])?)
    }

    /// `after`, parsed as the list's position; `400 invalid_position`
    /// when it does not parse.
    pub fn after_as<T>(
        &self,
        parse: fn(&str) -> Result<T, InvalidPosition>,
    ) -> Result<Option<T>, Code> {
        self.after
            .as_deref()
            .map(|a| parse(a).map_err(|_| Code::InvalidPosition))
            .transpose()
    }

    fn parts(&self) -> Vec<(&'static str, String)> {
        let mut p = Vec::new();
        if let Some(a) = &self.after {
            p.push(("after", a.clone()));
        }
        p.push(("limit", self.limit.to_string()));
        p
    }

    /// The query of this list (no `?`).
    pub fn to_query(&self) -> String {
        join(&self.parts())
    }
}

/// `GET …/buckets`: a page in name order, or the exact lookup of up to
/// [`MAX_NAMES`] names (`?name=a&name=b`), which takes neither `after`
/// nor `limit`. The lookup answers one bucket per name found, in name
/// order, with `next: null`; a name that is no bucket of the tenant, or
/// no valid bucket name, is not in the answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BucketQuery {
    Page(List),
    Names(Vec<String>),
}

impl BucketQuery {
    pub fn parse(query: &str) -> Result<BucketQuery, Code> {
        let pairs = pairs(query, &["after", "limit", "name"])?;
        let names: Vec<String> = pairs
            .iter()
            .filter(|(n, _)| n == "name")
            .map(|(_, v)| v.clone())
            .collect();
        if names.is_empty() {
            return Ok(BucketQuery::Page(List::from_pairs(&pairs)?));
        }
        if names.len() != pairs.len()
            || names.len() > MAX_NAMES
            || names.iter().any(|n| n.is_empty() || n.len() > 255)
        {
            return Err(Code::BadRequest);
        }
        Ok(BucketQuery::Names(names))
    }

    /// The names of a lookup that can be buckets, each once, in name
    /// order.
    pub fn lookup_names(names: &[String]) -> Vec<&str> {
        let mut v: Vec<&str> = names
            .iter()
            .map(String::as_str)
            .filter(|n| valid_bucket_name(n))
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    pub fn to_query(&self) -> String {
        match self {
            BucketQuery::Page(l) => l.to_query(),
            BucketQuery::Names(names) => join(
                &names
                    .iter()
                    .map(|n| ("name", n.clone()))
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

/// `GET …/keys`: `?kind=` (`s3` or `app_password`; absent: both) and a
/// page in creation order. Never a principal, the internal key or a
/// revoked key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyQuery {
    pub kind: Option<KeyKind>,
    pub list: List,
}

impl KeyQuery {
    pub fn parse(query: &str) -> Result<KeyQuery, Code> {
        let pairs = pairs(query, &["kind", "after", "limit"])?;
        let kind = get(&pairs, "kind")
            .map(|k| KeyKind::parse(k).ok_or(Code::BadRequest))
            .transpose()?;
        Ok(KeyQuery {
            kind,
            list: List::from_pairs(&pairs)?,
        })
    }

    pub fn to_query(&self) -> String {
        let mut p = Vec::new();
        if let Some(k) = self.kind {
            p.push(("kind", k.as_str().to_string()));
        }
        p.extend(self.list.parts());
        join(&p)
    }
}

/// `GET …/usage/days`: the days after `after_day` (exclusive), oldest
/// first, and a page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageDaysQuery {
    pub after_day: Option<Day>,
    pub list: List,
}

impl UsageDaysQuery {
    pub fn parse(query: &str) -> Result<UsageDaysQuery, Code> {
        let pairs = pairs(query, &["after_day", "after", "limit"])?;
        let after_day = get(&pairs, "after_day")
            .map(|d| Day::parse(d).ok_or(Code::BadRequest))
            .transpose()?;
        Ok(UsageDaysQuery {
            after_day,
            list: List::from_pairs(&pairs)?,
        })
    }

    pub fn to_query(&self) -> String {
        let mut p = Vec::new();
        if let Some(d) = self.after_day {
            p.push(("after_day", d.to_string()));
        }
        p.extend(self.list.parts());
        join(&p)
    }
}

/// `DELETE /v1/tenants/{t}?hold_days=<n>`: required, 7 to 3,650.
pub fn parse_hold_days(query: &str) -> Result<u32, Code> {
    let pairs = pairs(query, &["hold_days"])?;
    let v = get(&pairs, "hold_days").ok_or(Code::BadRequest)?;
    let n: u32 = (!v.starts_with('0') && v.len() <= 4)
        .then(|| v.parse().ok())
        .flatten()
        .ok_or(Code::BadRequest)?;
    (MIN_HOLD_DAYS..=MAX_HOLD_DAYS)
        .contains(&n)
        .then_some(n)
        .ok_or(Code::BadRequest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::position::{KeyPosition, NamePosition};

    #[test]
    fn a_list_takes_after_and_limit() {
        assert_eq!(List::parse(""), Ok(List::default()));
        let l = List::parse("after=nbackups&limit=200").unwrap();
        assert_eq!(l.after.as_deref(), Some("nbackups"));
        assert_eq!(l.limit, 200);
        assert_eq!(List::parse(&l.to_query()), Ok(l.clone()));
        assert_eq!(
            l.after_as(NamePosition::parse),
            Ok(Some(NamePosition {
                name: "backups".into()
            }))
        );
        assert_eq!(l.after_as(KeyPosition::parse), Err(Code::InvalidPosition));
        for bad in [
            "limit=0",
            "limit=1001",
            "limit=01",
            "limit=-1",
            "limit=1&limit=2",
            "x=1",
            "after",
            "after=a&",
            "&",
        ] {
            assert_eq!(List::parse(bad).map(|_| ()), Err(Code::BadRequest), "{bad}");
        }
        assert_eq!(List::parse("after="), Err(Code::InvalidPosition));
        assert_eq!(List::parse("limit=1000").unwrap().limit, 1000);
    }

    #[test]
    fn values_are_percent_encoded() {
        assert_eq!(encode("a b+c/é"), "a%20b%2Bc%2F%C3%A9");
        assert_eq!(decode("a%20b%2Bc%2F%C3%A9").as_deref(), Some("a b+c/é"));
        assert_eq!(decode("a+b").as_deref(), Some("a+b"));
        for bad in ["%", "%2", "%zz", "%FF"] {
            assert_eq!(decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_name_lookup_takes_up_to_64_names_and_nothing_else() {
        let q = BucketQuery::parse("name=photos&name=backups").unwrap();
        assert_eq!(
            q,
            BucketQuery::Names(vec!["photos".into(), "backups".into()])
        );
        assert_eq!(BucketQuery::parse(&q.to_query()), Ok(q));
        assert!(matches!(
            BucketQuery::parse("limit=5"),
            Ok(BucketQuery::Page(_))
        ));
        assert_eq!(BucketQuery::parse("name=a&after=na"), Err(Code::BadRequest));
        assert_eq!(BucketQuery::parse("name=a&limit=5"), Err(Code::BadRequest));
        assert_eq!(BucketQuery::parse("name="), Err(Code::BadRequest));
        let many = vec!["name=abc"; 65].join("&");
        assert_eq!(BucketQuery::parse(&many), Err(Code::BadRequest));
        assert!(BucketQuery::parse(&vec!["name=abc"; 64].join("&")).is_ok());
        let names: Vec<String> = ["photos", "Bad_Name", "backups", "photos"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(BucketQuery::lookup_names(&names), vec!["backups", "photos"]);
    }

    #[test]
    fn keys_days_and_holds() {
        let k = KeyQuery::parse("kind=s3&limit=10").unwrap();
        assert_eq!(k.kind, Some(KeyKind::S3));
        assert_eq!(KeyQuery::parse(&k.to_query()), Ok(k));
        assert_eq!(KeyQuery::parse("kind=internal"), Err(Code::BadRequest));
        assert_eq!(KeyQuery::parse("kind=principal"), Err(Code::BadRequest));
        let d = UsageDaysQuery::parse("after_day=2026-11-01").unwrap();
        assert_eq!(d.after_day, Day::new(2026, 11, 1));
        assert_eq!(UsageDaysQuery::parse(&d.to_query()), Ok(d));
        assert_eq!(
            UsageDaysQuery::parse("after_day=2026-02-30"),
            Err(Code::BadRequest)
        );
        assert_eq!(parse_hold_days("hold_days=30"), Ok(30));
        assert_eq!(parse_hold_days("hold_days=7"), Ok(7));
        for bad in [
            "",
            "hold_days=6",
            "hold_days=3651",
            "hold_days=030",
            "hold_days=30&hold_days=30",
            "days=30",
        ] {
            assert_eq!(parse_hold_days(bad), Err(Code::BadRequest), "{bad}");
        }
    }
}
