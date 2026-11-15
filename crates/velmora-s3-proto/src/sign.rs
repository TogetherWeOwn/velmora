//! Client-side SigV4: signs a request this service sends to another
//! S3-compatible store (header authorization, path style, signed
//! payload hash). The counterpart of [`crate::verify`].
//!
//! Narrow on purpose: what is signed must be what is sent, byte for
//! byte, whatever HTTP client sends it. So a request that a client or
//! the store could write in another form is refused instead of signed:
//! - the path holds only the characters this service uses in its own
//!   blob keys, and no empty, `.` or `..` segment (a URL parser removes
//!   those);
//! - the host is a lower-case name without a port;
//! - only the headers of [`SIGNED_HEADERS`] and `x-amz-meta-*` are
//!   taken, never one the client or the signer sets itself;
//! - a query key is given once, and is not an `X-Amz-` parameter.
//!
//! Query keys and values are escaped by the signer.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use super::auth::signing_key;
use super::{hex, ErrorCode, Result};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// Deliberately not Debug: the secret must not enter logs.
pub struct SigningKey<'a> {
    pub access_key: &'a str,
    pub secret: &'a [u8],
    pub region: &'a str,
}

/// A request ready to send: the origin-form target and every header to
/// set besides `host`.
pub struct SignedRequest {
    pub target: String,
    pub headers: Vec<(String, String)>,
}

/// SHA-256 of an empty body, in hex.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-_.~".contains(&c)
}

/// `/`, or a path of segments of unreserved characters, each led by one
/// `/`, none empty, `.` or `..`: it is its own canonical form, and a URL
/// parser leaves it as it is.
fn valid_path(path: &str) -> bool {
    match path.strip_prefix('/') {
        Some("") => true,
        Some(rest) => rest.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(unreserved)
        }),
        None => false,
    }
}

/// A lower-case host name without a port: a URL parser leaves it as it
/// is. Labels of letters, digits and `-`, none empty, and the last one
/// starts with a letter: a parser reads a last label that is a number
/// (`127.1`, `0x7f.1`, `2130706433`) as an address and rewrites the host.
fn valid_host(host: &str) -> bool {
    host.split('.').all(valid_name)
        && host
            .rsplit('.')
            .next()
            .is_some_and(|last| last.starts_with(|c: char| c.is_ascii_lowercase()))
}

/// Headers a caller may have signed, besides `x-amz-meta-*`. The signer
/// adds `host`, `x-amz-date` and `x-amz-content-sha256` itself and
/// writes `authorization`; a header the HTTP client owns
/// (`content-length`, `connection`, ...) is never signed.
pub const SIGNED_HEADERS: [&str; 3] = ["content-md5", "content-type", "range"];

fn allowed_header(name: &str) -> bool {
    SIGNED_HEADERS.contains(&name) || name.strip_prefix("x-amz-meta-").is_some_and(valid_name)
}

fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.bytes() {
        if unreserved(c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn valid_value(value: &str) -> bool {
    // Printable ASCII, not empty, without leading, trailing or repeated
    // spaces: the value is its own canonical form.
    !value.is_empty()
        && value.bytes().all(|c| (0x20..0x7f).contains(&c))
        && value == value.trim()
        && !value.contains("  ")
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time in seconds, of a year of four
/// digits (a time in milliseconds is refused, not signed).
fn amz_date(unix_secs: i64) -> Result<String> {
    chrono::DateTime::from_timestamp(unix_secs, 0)
        .filter(|_| unix_secs >= 0)
        .map(|t| t.format("%Y%m%dT%H%M%SZ").to_string())
        .filter(|date| date.len() == 16)
        .ok_or(ErrorCode::InvalidArgument)
}

/// What to sign. `query` keys and values are escaped by the signer.
/// `headers` are extra headers to sign and send: lower-case names, of
/// [`SIGNED_HEADERS`] or `x-amz-meta-*`; `host`, `x-amz-date` and
/// `x-amz-content-sha256` are added. `payload_sha256` is the lower-case
/// hex SHA-256 of the body ([`EMPTY_SHA256`] for none).
pub struct Unsigned<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a [(&'a str, &'a str)],
    pub headers: &'a [(&'a str, &'a str)],
    pub payload_sha256: &'a str,
}

/// Signs `request` for `host` at `unix_secs`.
pub fn sign_request(
    key: &SigningKey<'_>,
    host: &str,
    unix_secs: i64,
    request: &Unsigned<'_>,
) -> Result<SignedRequest> {
    let Unsigned {
        method,
        path,
        query,
        headers,
        payload_sha256,
    } = *request;
    if !matches!(method, "GET" | "HEAD" | "PUT")
        || !valid_path(path)
        || !valid_host(host)
        || key.access_key.is_empty()
        || !key.access_key.bytes().all(|c| c.is_ascii_alphanumeric())
        || !valid_name(key.region)
        || payload_sha256.len() != 64
        || !payload_sha256
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || headers.iter().any(|(name, _)| !allowed_header(name))
        // This crate's verifier reads a comma in such a value as two
        // values that were merged, and refuses the request.
        || headers
            .iter()
            .any(|(name, value)| name.starts_with("x-amz-meta-") && value.contains(','))
    {
        return Err(ErrorCode::InvalidArgument);
    }
    let date = amz_date(unix_secs)?;

    let mut pairs: Vec<(String, String)> =
        query.iter().map(|(k, v)| (encode(k), encode(v))).collect();
    pairs.sort();
    if pairs.windows(2).any(|w| w[0].0 == w[1].0)
        || query
            .iter()
            .any(|(k, _)| k.is_empty() || k.to_ascii_lowercase().starts_with("x-amz-"))
    {
        return Err(ErrorCode::InvalidArgument);
    }
    let canonical_query = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let mut signed: Vec<(&str, &str)> = headers.to_vec();
    signed.push(("host", host));
    signed.push(("x-amz-content-sha256", payload_sha256));
    signed.push(("x-amz-date", &date));
    signed.sort();
    if signed.windows(2).any(|w| w[0].0 == w[1].0)
        || signed
            .iter()
            .any(|(name, value)| !valid_name(name) || !valid_value(value))
    {
        return Err(ErrorCode::InvalidArgument);
    }
    let names = signed
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let mut canonical = format!("{method}\n{path}\n{canonical_query}\n");
    for (name, value) in &signed {
        canonical.push_str(&format!("{name}:{value}\n"));
    }
    canonical.push_str(&format!("\n{names}\n{payload_sha256}"));

    let day = &date[..8];
    let scope = format!("{day}/{}/s3/aws4_request", key.region);
    let string_to_sign = format!(
        "{ALGORITHM}\n{date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let derived = signing_key(key.secret, day, key.region);
    let mut mac = Hmac::<Sha256>::new_from_slice(&derived).map_err(|_| ErrorCode::InternalError)?;
    mac.update(string_to_sign.as_bytes());
    let signature = hex(&mac.finalize().into_bytes());

    let authorization = format!(
        "{ALGORITHM} Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
        key.access_key
    );
    let mut out: Vec<(String, String)> = signed
        .iter()
        .filter(|(name, _)| *name != "host")
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    out.push(("authorization".to_owned(), authorization));
    let target = if canonical_query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{canonical_query}")
    };
    Ok(SignedRequest {
        target,
        headers: out,
    })
}

// ---------------------------------------------------------------------------
// The answer to a ListObjectsV2 this service sent
// ---------------------------------------------------------------------------

/// Largest list answer that is parsed: 1,000 keys of the longest size.
pub const MAX_LIST_BYTES: usize = 4 * 1024 * 1024;

/// One object of a list answer. `etag` is as sent, without its quotes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Listed {
    pub key: String,
    pub size: u64,
    pub etag: String,
}

/// A page of a list answer. `truncated` = the store has more keys; the
/// page then holds an object or `next_token` (`NextContinuationToken`),
/// so a caller always has a point to go on from.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListedPage {
    pub objects: Vec<Listed>,
    pub truncated: bool,
    pub next_token: Option<String>,
}

fn reference(entity: &str) -> Result<char> {
    Ok(match entity {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        s => {
            // Digits only (no sign), and no control character.
            let code = match s.strip_prefix("#x") {
                Some(hex) if hex.bytes().all(|c| c.is_ascii_hexdigit()) => {
                    u32::from_str_radix(hex, 16).ok()
                }
                Some(_) => None,
                None => s
                    .strip_prefix('#')
                    .and_then(digits)
                    .and_then(|c| u32::try_from(c).ok()),
            };
            code.and_then(char::from_u32)
                .filter(|c| *c >= ' ')
                .ok_or(ErrorCode::MalformedXML)?
        }
    })
}

/// A number written in digits only, as `Size` is.
fn digits(text: &str) -> Option<u64> {
    (!text.is_empty() && text.bytes().all(|c| c.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// The fields that are read, by the path of their element.
#[derive(Clone, Copy, PartialEq)]
enum Field {
    Truncated,
    Token,
    /// `EncodingType`: the keys of the answer are encoded.
    Encoded,
    Contents,
    Key,
    Size,
    ETag,
}

fn field(at: &[String], name: &str) -> Option<Field> {
    let at: Vec<&str> = at.iter().map(String::as_str).collect();
    Some(match (at.as_slice(), name) {
        (["ListBucketResult"], "IsTruncated") => Field::Truncated,
        (["ListBucketResult"], "NextContinuationToken") => Field::Token,
        (["ListBucketResult"], "EncodingType") => Field::Encoded,
        (["ListBucketResult"], "Contents") => Field::Contents,
        (["ListBucketResult", "Contents"], "Key") => Field::Key,
        (["ListBucketResult", "Contents"], "Size") => Field::Size,
        (["ListBucketResult", "Contents"], "ETag") => Field::ETag,
        _ => return None,
    })
}

/// Stores a field that must be given once.
fn once<T>(slot: &mut Option<T>, value: T) -> Result<()> {
    match slot.replace(value) {
        None => Ok(()),
        Some(_) => Err(ErrorCode::MalformedXML),
    }
}

/// Parses the body of a `ListObjectsV2` answer: `Key`, `Size` and `ETag`
/// of every `Contents`, `IsTruncated` and `NextContinuationToken`. Other
/// elements are skipped.
///
/// Strict where a lenient reading could give a shorter or another list:
/// - one root, and nothing but white space around it; the fields are
///   read under a root `ListBucketResult` only, so another root gives
///   no `IsTruncated` and is an error;
/// - no DTD, CDATA or processing instruction; a declaration only
///   before the root; no comment inside a field;
/// - no control character in a field, written as it is or as a
///   reference (tab and line feed included). A key with one makes the
///   whole page an error; the keys this is used for have none;
/// - a field that is read is given once, is not empty and holds text
///   only (no element inside it);
/// - an entry that lacks one of its three fields is an error;
/// - an answer with `EncodingType` (keys encoded by the store) is an
///   error: none is asked for;
/// - a truncated page has an object or a token.
pub fn parse_list(body: &[u8]) -> Result<ListedPage> {
    use quick_xml::{events::Event, Reader};

    if body.len() > MAX_LIST_BYTES {
        return Err(ErrorCode::InvalidRequest);
    }
    let bad = ErrorCode::MalformedXML;
    let mut reader = Reader::from_reader(body);
    let mut path: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut page = ListedPage::default();
    let mut truncated = None;
    let (mut key, mut size, mut etag) = (None, None, None);
    let mut rooted = false;
    // The field whose text is being read. No element may open in it.
    let mut leaf = false;
    loop {
        match reader.read_event().map_err(|_| bad)? {
            Event::Start(e) => {
                if path.len() >= 8 || (path.is_empty() && rooted) || leaf {
                    return Err(bad);
                }
                rooted = true;
                let name = e.local_name().as_ref().to_owned();
                let field = field(&path, &name);
                // Keys are asked for as they are. An answer that says it
                // encoded them would be read as other keys.
                if field == Some(Field::Encoded) {
                    return Err(bad);
                }
                leaf = matches!(field, Some(f) if f != Field::Contents);
                path.push(name);
                text.clear();
            }
            Event::Empty(e) => {
                // An empty element is never the root, never inside a
                // field, and never a field that is read.
                let name = e.local_name().as_ref().to_owned();
                if path.is_empty() || leaf || field(&path, &name).is_some() {
                    return Err(bad);
                }
            }
            // A declaration comes before the root, and a comment is
            // never inside a field: `fal<!-- -->se` is not `false`.
            Event::Decl(_) if !rooted => {}
            Event::Comment(_) if !leaf => {}
            Event::Text(e) => {
                let part = e.xml10_content();
                // Around the root, white space only. In a field, no
                // control character, as for a reference.
                if (path.is_empty() && !part.trim().is_empty())
                    || (leaf && part.chars().any(|c| c < ' '))
                {
                    return Err(bad);
                }
                text.push_str(&part);
            }
            Event::GeneralRef(e) => {
                if path.is_empty() {
                    return Err(bad);
                }
                text.push(reference(e.as_ref())?);
            }
            Event::End(_) => {
                let name = path.pop().ok_or(bad)?;
                let value = std::mem::take(&mut text);
                leaf = false;
                match field(&path, &name) {
                    Some(Field::Truncated) => once(
                        &mut truncated,
                        match value.as_str() {
                            "true" => true,
                            "false" => false,
                            _ => return Err(bad),
                        },
                    )?,
                    Some(Field::Token) if value.is_empty() => return Err(bad),
                    Some(Field::Token) => once(&mut page.next_token, value)?,
                    Some(Field::Key) if value.is_empty() => return Err(bad),
                    Some(Field::Key) => once(&mut key, value)?,
                    Some(Field::Size) => once(&mut size, digits(&value).ok_or(bad)?)?,
                    Some(Field::ETag) => {
                        let tag = value.trim_matches('"');
                        if tag.is_empty() {
                            return Err(bad);
                        }
                        once(&mut etag, tag.to_owned())?;
                    }
                    Some(Field::Contents) => page.objects.push(Listed {
                        key: key.take().ok_or(bad)?,
                        size: size.take().ok_or(bad)?,
                        etag: etag.take().ok_or(bad)?,
                    }),
                    Some(Field::Encoded) | None => {}
                }
            }
            Event::Eof => break,
            _ => return Err(bad),
        }
    }
    if !path.is_empty() {
        return Err(bad);
    }
    page.truncated = truncated.ok_or(bad)?;
    if page.truncated && page.objects.is_empty() && page.next_token.is_none() {
        return Err(bad);
    }
    Ok(page)
}
