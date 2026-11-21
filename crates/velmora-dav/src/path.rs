//! WebDAV URLs and S3 keys.
//!
//! `https://<host>/<bucket>/<path>`. The root lists the buckets the app
//! password holds a grant on. Inside a bucket a path names a key, byte
//! for byte in UTF-8, with no case folding and no Unicode normalisation.
//!
//! A collection is the prefix `<path>/`: it exists when its zero-byte
//! marker object `<path>/` does, or when any key starts with it. A path
//! with a trailing slash addresses the collection; one without it
//! addresses the file of that name if there is one, and otherwise the
//! collection.
//!
//! Keys that WebDAV cannot address are hidden, never changed: an empty
//! segment (`a//b`), a `.` or `..` segment, and a non-empty object whose
//! key ends in `/`.

/// Where a request points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Loc {
    /// `/`: the list of buckets.
    Root,
    /// `/<bucket>/<key>`. `key` is empty for the bucket itself; it ends in
    /// `/` when the URL did (a collection).
    Item { bucket: String, key: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// Not an origin-form path, a bad escape, or not UTF-8.
    Bad,
    /// A path that names a key WebDAV hides.
    Hidden,
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decodes to UTF-8. `+` stays `+`.
pub fn decode(raw: &str) -> Result<String, PathError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = bytes
                .get(i + 1)
                .copied()
                .and_then(hex)
                .ok_or(PathError::Bad)?;
            let lo = bytes
                .get(i + 2)
                .copied()
                .and_then(hex)
                .ok_or(PathError::Bad)?;
            out.push(hi * 16 + lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let s = String::from_utf8(out).map_err(|_| PathError::Bad)?;
    if s.chars().any(|c| c == '\0') {
        return Err(PathError::Bad);
    }
    Ok(s)
}

/// Percent-encodes everything but unreserved characters, and `/` when
/// `keep_slash`.
pub fn encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Whether a key (file form, or collection form with its trailing `/`)
/// can be addressed through WebDAV.
pub fn addressable(key: &str) -> bool {
    let body = key.strip_suffix('/').unwrap_or(key);
    !body.is_empty()
        && body
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

impl Loc {
    /// Parses the path of a request URL (no query, no fragment).
    pub fn parse(raw_path: &str) -> Result<Loc, PathError> {
        // A fragment is never part of a request target; a client that
        // sends one must not have it cut off and act on the rest.
        if raw_path.contains('#') {
            return Err(PathError::Bad);
        }
        let rest = raw_path.strip_prefix('/').ok_or(PathError::Bad)?;
        let decoded = decode(rest)?;
        if decoded.is_empty() {
            return Ok(Loc::Root);
        }
        let (bucket, key) = match decoded.split_once('/') {
            Some((b, k)) => (b.to_owned(), k.to_owned()),
            None => (decoded.clone(), String::new()),
        };
        if bucket.is_empty() {
            return Err(PathError::Hidden);
        }
        if !key.is_empty() && !addressable(&key) {
            return Err(PathError::Hidden);
        }
        Ok(Loc::Item { bucket, key })
    }

    pub fn bucket(&self) -> Option<&str> {
        match self {
            Loc::Root => None,
            Loc::Item { bucket, .. } => Some(bucket),
        }
    }

    pub fn key(&self) -> &str {
        match self {
            Loc::Root => "",
            Loc::Item { key, .. } => key,
        }
    }
}

/// The key as a collection: with exactly one trailing `/`; empty for the
/// bucket itself.
pub fn as_collection(key: &str) -> String {
    if key.is_empty() || key.ends_with('/') {
        key.to_owned()
    } else {
        format!("{key}/")
    }
}

/// The key as a file: without the trailing `/`.
pub fn as_file(key: &str) -> &str {
    key.strip_suffix('/').unwrap_or(key)
}

/// The collection that holds `key`: `""` for a key at the top of the
/// bucket.
pub fn parent(key: &str) -> String {
    let body = as_file(key);
    match body.rfind('/') {
        Some(i) => body[..=i].to_owned(),
        None => String::new(),
    }
}

/// The last segment of a key, without a trailing `/`.
pub fn leaf(key: &str) -> &str {
    let body = as_file(key);
    body.rsplit('/').next().unwrap_or(body)
}

/// The URL path of a key in a bucket. Collections keep their `/`.
pub fn href(bucket: &str, key: &str) -> String {
    format!("/{}/{}", encode(bucket, false), encode(key, true))
}

/// Whether `inner` is `outer` or inside it (`outer` in collection form).
pub fn within(outer: &str, inner: &str) -> bool {
    outer.is_empty() || inner == outer || (outer.ends_with('/') && inner.starts_with(outer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(bucket: &str, key: &str) -> Loc {
        Loc::Item {
            bucket: bucket.into(),
            key: key.into(),
        }
    }

    #[test]
    fn parses_urls() {
        assert_eq!(Loc::parse("/"), Ok(Loc::Root));
        assert_eq!(Loc::parse("/b"), Ok(item("b", "")));
        assert_eq!(Loc::parse("/b/"), Ok(item("b", "")));
        assert_eq!(Loc::parse("/b/a/c.txt"), Ok(item("b", "a/c.txt")));
        assert_eq!(Loc::parse("/b/a/"), Ok(item("b", "a/")));
        assert_eq!(
            Loc::parse("/b/caf%C3%A9/%E6%97%A5%E6%9C%AC.txt"),
            Ok(item("b", "café/日本.txt"))
        );
        assert_eq!(Loc::parse("/b/a%20b+c"), Ok(item("b", "a b+c")));
        assert_eq!(Loc::parse("/b/a%2Fb"), Ok(item("b", "a/b")));
        assert_eq!(Loc::parse("b"), Err(PathError::Bad));
        assert_eq!(Loc::parse("/b/%ZZ"), Err(PathError::Bad));
        assert_eq!(Loc::parse("/b/%FF"), Err(PathError::Bad));
        assert_eq!(Loc::parse("/b/a%00"), Err(PathError::Bad));
        assert_eq!(Loc::parse("/b/frag/#ment"), Err(PathError::Bad));
        for hidden in ["/b/a//c", "/b/./a", "/b/a/..", "/b/..", "//a", "/b//"] {
            assert_eq!(Loc::parse(hidden), Err(PathError::Hidden), "{hidden}");
        }
    }

    #[test]
    fn keys_and_hrefs() {
        assert_eq!(parent("a/b/c"), "a/b/");
        assert_eq!(parent("a/b/"), "a/");
        assert_eq!(parent("a"), "");
        assert_eq!(parent("a/"), "");
        assert_eq!(leaf("a/b/"), "b");
        assert_eq!(leaf("a/b c"), "b c");
        assert_eq!(as_collection("a"), "a/");
        assert_eq!(as_collection("a/"), "a/");
        assert_eq!(as_collection(""), "");
        assert_eq!(href("b", "a b/ü?#%"), "/b/a%20b/%C3%BC%3F%23%25");
        assert_eq!(href("b", "d/"), "/b/d/");
        assert_eq!(href("b", ""), "/b/");
        for key in ["a b/ü?#%", "x+y", "日本/"] {
            let h = href("bk", key);
            assert_eq!(Loc::parse(&h), Ok(item("bk", key)));
        }
        assert!(within("a/", "a/b"));
        assert!(within("a/", "a/"));
        assert!(!within("a/", "ab"));
        assert!(within("", "x"));
        assert!(within("f", "f"));
        assert!(!within("f", "f/x"));
        assert!(addressable("a/b/"));
        assert!(!addressable("a//b"));
        assert!(!addressable("/a"));
    }
}
