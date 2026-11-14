// Provenance: the delimiter fold, lookahead, XML field rules and `url_encode` /
// `xml_character` are carved from TogetherWeOwn/qerith at commit fc09396c,
// crates/qerith-core/src/s3/archive/listing.rs (the `Cursor` type, the body of
// `Adapter::list` and the two helpers), and the ListBuckets XML from
// crates/qerith-core/src/s3/archive/mod.rs lines 231-243. License: MIT.
// Re-typed away from the catalogue: the caller feeds rows instead of the adapter
// scanning a catalogue port, the server-side `TokenPort` handle store is replaced
// by a self-contained HMAC-tagged token whose key the caller supplies, and objects
// render with StorageClass STANDARD. `max-keys` above 1000 is capped (as S3 does)
// instead of rejected. ListObjects V1 (`marker`) is added on the same fold.

//! ListObjectsV2, ListObjects (V1) and ListBuckets: request parsing, the delimiter fold over rows
//! the caller fetches in key order, continuation tokens, and the XML renderers.
//! Pure: no I/O and no key material of its own.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::{decimal, iso_date_ms, xml, xml_response, ErrorCode, Response, Result, Target};

const MAX_KEYS: u32 = 1000;
const TOKEN_VERSION: u8 = 1;
const TAG_LEN: usize = 32;
const MAX_TOKEN_CHARS: usize = 8192;
/// Below this the caller passed the wrong thing, not a derived key.
const MIN_TOKEN_KEY: usize = 32;
const NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// Everything a continuation token is bound to. A token issued for one scope is
/// `InvalidArgument` under any other (other bucket, prefix, delimiter, ...).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenScope {
    pub bucket: String,
    pub prefix: String,
    pub delimiter: String,
    pub start_after: Option<String>,
    pub url_encoding: bool,
}

impl TokenScope {
    fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"velmora-list-scope-v1");
        let start_after = self.start_after.as_deref();
        for field in [
            Some(self.bucket.as_str()),
            Some(self.prefix.as_str()),
            Some(self.delimiter.as_str()),
            start_after,
        ] {
            match field {
                Some(v) => {
                    h.update([1]);
                    h.update((v.len() as u64).to_be_bytes());
                    h.update(v.as_bytes());
                }
                None => h.update([0]),
            }
        }
        h.update([u8::from(self.url_encoding)]);
        h.finalize().into()
    }
}

/// Resume point: the last key scanned, plus the CommonPrefix already emitted so
/// that its remaining members are skipped instead of emitted again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub after: String,
    pub skip_prefix: Option<String>,
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if bytes.len() < n {
        return None;
    }
    let (head, tail) = bytes.split_at(n);
    *bytes = tail;
    Some(head)
}

fn take_str(bytes: &mut &[u8]) -> Option<String> {
    let len = u32::from_be_bytes(take(bytes, 4)?.try_into().ok()?) as usize;
    String::from_utf8(take(bytes, len)?.to_vec()).ok()
}

fn mac(key: &[u8]) -> Result<Hmac<Sha256>> {
    if key.len() < MIN_TOKEN_KEY {
        return Err(ErrorCode::InternalError);
    }
    Hmac::<Sha256>::new_from_slice(key).map_err(|_| ErrorCode::InternalError)
}

/// Token = base64url(version, after, skip_prefix, scope_hash, HMAC-SHA256 tag).
pub fn issue_token(key: &[u8], scope: &TokenScope, cursor: &Cursor) -> Result<String> {
    let mut body = vec![TOKEN_VERSION];
    put_str(&mut body, &cursor.after);
    match &cursor.skip_prefix {
        Some(p) => {
            body.push(1);
            put_str(&mut body, p);
        }
        None => body.push(0),
    }
    body.extend_from_slice(&scope.hash());
    let mut m = mac(key)?;
    m.update(&body);
    body.extend_from_slice(&m.finalize().into_bytes());
    let token = URL_SAFE_NO_PAD.encode(body);
    // resolve_token refuses longer tokens; never hand out one that cannot resume.
    if token.len() > MAX_TOKEN_CHARS {
        return Err(ErrorCode::InternalError);
    }
    Ok(token)
}

/// Any malformed, forged or out-of-scope token is `InvalidArgument`.
pub fn resolve_token(key: &[u8], token: &str, scope: &TokenScope) -> Result<Cursor> {
    let mut m = mac(key)?;
    if token.len() > MAX_TOKEN_CHARS {
        return Err(ErrorCode::InvalidArgument);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ErrorCode::InvalidArgument)?;
    if raw.len() < TAG_LEN {
        return Err(ErrorCode::InvalidArgument);
    }
    let (body, tag) = raw.split_at(raw.len() - TAG_LEN);
    m.update(body);
    m.verify_slice(tag)
        .map_err(|_| ErrorCode::InvalidArgument)?;
    let parse = || {
        let mut rest = body;
        if take(&mut rest, 1)? != [TOKEN_VERSION] {
            return None;
        }
        let after = take_str(&mut rest)?;
        let skip_prefix = match take(&mut rest, 1)? {
            [0] => None,
            [1] => Some(take_str(&mut rest)?),
            _ => return None,
        };
        (rest == scope.hash()).then_some(Cursor { after, skip_prefix })
    };
    parse().ok_or(ErrorCode::InvalidArgument)
}

/// One object row as the catalogue returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectEntry {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub last_modified_ms: i64,
}

#[derive(Clone, Debug)]
enum Entry {
    Object(ObjectEntry),
    CommonPrefix(String),
}

/// One ListObjectsV2 page, or a V1 page from [`ListObjectsV2::parse_v1`].
/// The caller loops: query rows with
/// `key starts_with prefix() AND key > after()` in ascending key order, `push`
/// each while `wants_more()`, then `finish(exhausted)`, where `exhausted` means
/// the scan reached the end of the prefix range (false = the caller's query
/// budget ran out, which yields a valid truncated page).
#[derive(Clone, Debug)]
pub struct ListObjectsV2 {
    scope: TokenScope,
    max_keys: u32,
    token: Option<String>,
    cursor: Cursor,
    has_after: bool,
    scanned: usize,
    entries: Vec<(Entry, Cursor)>,
    /// ListObjects V1: `marker` is held as `start_after` (same semantics:
    /// keys and CommonPrefixes at or before it are skipped) and the page
    /// resumes by `NextMarker` instead of a token.
    v1: bool,
}

impl ListObjectsV2 {
    pub fn parse(target: &Target, token_key: &[u8]) -> Result<Self> {
        let max_keys = target
            .one("max-keys")?
            .map(decimal)
            .transpose()?
            .map_or(MAX_KEYS, |n| n.min(u64::from(MAX_KEYS)) as u32);
        let encoding = target.one("encoding-type")?;
        if !matches!(encoding, None | Some("url")) {
            return Err(ErrorCode::InvalidArgument);
        }
        let scope = TokenScope {
            bucket: target.bucket.clone(),
            prefix: target.one("prefix")?.unwrap_or("").into(),
            delimiter: target.one("delimiter")?.unwrap_or("").into(),
            start_after: target.one("start-after")?.map(str::to_owned),
            url_encoding: encoding.is_some(),
        };
        let token = target.one("continuation-token")?.map(str::to_owned);
        let cursor = match &token {
            Some(t) => resolve_token(token_key, t, &scope)?,
            None => Cursor {
                after: scope.start_after.clone().unwrap_or_default(),
                skip_prefix: None,
            },
        };
        Ok(Self {
            has_after: token.is_some() || scope.start_after.is_some(),
            scope,
            max_keys,
            token,
            cursor,
            scanned: 0,
            entries: Vec::new(),
            v1: false,
        })
    }

    /// ListObjects V1: `prefix`, `delimiter`, `marker`, `max-keys`,
    /// `encoding-type`. No token: the next page starts after `NextMarker`
    /// (or, without a delimiter, the last key), which the client sends back
    /// as `marker`.
    pub fn parse_v1(target: &Target) -> Result<Self> {
        let max_keys = target
            .one("max-keys")?
            .map(decimal)
            .transpose()?
            .map_or(MAX_KEYS, |n| n.min(u64::from(MAX_KEYS)) as u32);
        let encoding = target.one("encoding-type")?;
        if !matches!(encoding, None | Some("url")) {
            return Err(ErrorCode::InvalidArgument);
        }
        let marker = target.one("marker")?.filter(|m| !m.is_empty());
        let scope = TokenScope {
            bucket: target.bucket.clone(),
            prefix: target.one("prefix")?.unwrap_or("").into(),
            delimiter: target.one("delimiter")?.unwrap_or("").into(),
            start_after: marker.map(str::to_owned),
            url_encoding: encoding.is_some(),
        };
        Ok(Self {
            has_after: scope.start_after.is_some(),
            cursor: Cursor {
                after: scope.start_after.clone().unwrap_or_default(),
                skip_prefix: None,
            },
            scope,
            max_keys,
            token: None,
            scanned: 0,
            entries: Vec::new(),
            v1: true,
        })
    }

    pub fn scope(&self) -> &TokenScope {
        &self.scope
    }
    pub fn prefix(&self) -> &str {
        &self.scope.prefix
    }
    /// CommonPrefix already emitted; rows under it are skipped, so the caller
    /// may seek past it instead of scanning them.
    pub fn skip_prefix(&self) -> Option<&str> {
        self.cursor.skip_prefix.as_deref()
    }
    /// Exclusive lower bound for the next query; None = from the prefix start.
    pub fn after(&self) -> Option<&str> {
        self.has_after.then_some(self.cursor.after.as_str())
    }
    /// False once the page holds `max-keys` entries plus one lookahead.
    pub fn wants_more(&self) -> bool {
        self.max_keys > 0 && self.entries.len() <= self.max_keys as usize
    }

    pub fn push(&mut self, row: ObjectEntry) -> Result<()> {
        if !self.wants_more()
            || !row.key.starts_with(&self.scope.prefix)
            || self.after().is_some_and(|a| row.key.as_str() <= a)
        {
            return Err(ErrorCode::InternalError);
        }
        self.scanned += 1;
        self.has_after = true;
        // Even filtered group members advance a budget-limited page.
        self.cursor.after = row.key.clone();
        if self
            .cursor
            .skip_prefix
            .as_ref()
            .is_some_and(|p| row.key.starts_with(p))
        {
            return Ok(());
        }
        self.cursor.skip_prefix = None;
        let plen = self.scope.prefix.len();
        let common = (!self.scope.delimiter.is_empty())
            .then(|| {
                row.key[plen..]
                    .find(&self.scope.delimiter)
                    .map(|i| row.key[..plen + i + self.scope.delimiter.len()].to_owned())
            })
            .flatten();
        if common.as_ref().is_some_and(|p| {
            self.scope
                .start_after
                .as_ref()
                .is_some_and(|a| p.as_str() <= a.as_str())
        }) {
            return Ok(());
        }
        self.cursor = Cursor {
            after: row.key.clone(),
            skip_prefix: common.clone(),
        };
        let entry = match common {
            Some(p) => Entry::CommonPrefix(p),
            None => Entry::Object(row),
        };
        self.entries.push((entry, self.cursor.clone()));
        Ok(())
    }

    pub fn finish(mut self, exhausted: bool, token_key: &[u8]) -> Result<Response> {
        let max = self.max_keys as usize;
        let overflow = self.entries.len() > max;
        let budget = !overflow && !exhausted && max > 0;
        if budget && self.scanned == 0 {
            // A truncated page that scanned nothing would loop the client forever.
            return Err(ErrorCode::InternalError);
        }
        let truncated = overflow || budget;
        if overflow {
            self.entries.pop();
            // Revisit the lookahead entry: only delivered entries are consumed.
            self.cursor = self
                .entries
                .last()
                .ok_or(ErrorCode::InternalError)?
                .1
                .clone();
        }
        let scope = &self.scope;
        // XML 1.0 cannot represent every valid UTF-8 object key. Require URL
        // encoding for those pages; do not replace/control-normalize key bytes.
        let field = |s: &str| -> Result<String> {
            if scope.url_encoding {
                Ok(xml(&url_encode(s)))
            } else if s.chars().all(xml_character) {
                Ok(xml(s))
            } else {
                Err(ErrorCode::InvalidArgument)
            }
        };
        let mut out = if self.v1 {
            let mut head = format!(
                "<ListBucketResult xmlns=\"{NS}\"><Name>{}</Name><Prefix>{}</Prefix><Marker>{}</Marker>",
                xml(&scope.bucket),
                field(&scope.prefix)?,
                field(scope.start_after.as_deref().unwrap_or(""))?
            );
            // S3 sends NextMarker only with a delimiter; without one the
            // last key is the marker. `cursor.after` is the last key scanned,
            // which is also right for a page cut short by the query budget.
            if truncated && !scope.delimiter.is_empty() {
                head.push_str(&format!(
                    "<NextMarker>{}</NextMarker>",
                    field(&self.cursor.after)?
                ));
            }
            head.push_str(&format!(
                "<MaxKeys>{max}</MaxKeys><IsTruncated>{truncated}</IsTruncated>"
            ));
            head
        } else {
            format!(
                "<ListBucketResult xmlns=\"{NS}\"><Name>{}</Name><Prefix>{}</Prefix><KeyCount>{}</KeyCount><MaxKeys>{max}</MaxKeys><IsTruncated>{truncated}</IsTruncated>",
                xml(&scope.bucket),
                field(&scope.prefix)?,
                self.entries.len()
            )
        };
        if !scope.delimiter.is_empty() {
            out.push_str(&format!(
                "<Delimiter>{}</Delimiter>",
                field(&scope.delimiter)?
            ));
        }
        if let (false, Some(start)) = (self.v1, &scope.start_after) {
            out.push_str(&format!("<StartAfter>{}</StartAfter>", field(start)?));
        }
        if scope.url_encoding {
            out.push_str("<EncodingType>url</EncodingType>");
        }
        if let Some(token) = &self.token {
            out.push_str(&format!(
                "<ContinuationToken>{}</ContinuationToken>",
                xml(token)
            ));
        }
        for (entry, _) in &self.entries {
            match entry {
                Entry::Object(o) => out.push_str(&format!(
                    "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
                    field(&o.key)?,
                    iso_date_ms(o.last_modified_ms)?,
                    xml(&o.etag),
                    o.size
                )),
                Entry::CommonPrefix(p) => out.push_str(&format!(
                    "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                    field(p)?
                )),
            }
        }
        if truncated && !self.v1 {
            out.push_str(&format!(
                "<NextContinuationToken>{}</NextContinuationToken>",
                xml(&issue_token(token_key, scope, &self.cursor)?)
            ));
        }
        out.push_str("</ListBucketResult>");
        Ok(xml_response(out))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BucketEntry {
    pub name: String,
    pub created_ms: i64,
}

/// ListBuckets for the buckets the caller's key is granted, in caller order.
pub fn list_buckets_response(buckets: &[BucketEntry]) -> Result<Response> {
    let mut out = format!("<ListAllMyBucketsResult xmlns=\"{NS}\"><Buckets>");
    for b in buckets {
        out.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>{}</CreationDate></Bucket>",
            xml(&b.name),
            iso_date_ms(b.created_ms)?
        ));
    }
    out.push_str("</Buckets></ListAllMyBucketsResult>");
    Ok(xml_response(out))
}

fn xml_character(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
