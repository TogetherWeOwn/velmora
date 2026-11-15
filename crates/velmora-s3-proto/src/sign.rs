//! Client-side SigV4: signs a request this service sends to another
//! S3-compatible store (header authorization, path style, signed
//! payload hash). The counterpart of [`crate::verify`].
//!
//! Narrow on purpose. The path and every query value are restricted to
//! the characters this service uses in its own blob keys, so a request
//! that would need an escape the two sides could disagree on is refused
//! instead of signed.

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

/// A path of unreserved characters and `/`: it is its own canonical form.
fn valid_path(path: &str) -> bool {
    path.starts_with('/') && path.bytes().all(|c| unreserved(c) || c == b'/')
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
    // Printable ASCII without leading, trailing or repeated spaces: the
    // value is its own canonical form.
    value.bytes().all(|c| (0x20..0x7f).contains(&c))
        && value == value.trim()
        && !value.contains("  ")
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time in seconds.
fn amz_date(unix_secs: i64) -> Result<String> {
    chrono::DateTime::from_timestamp(unix_secs, 0)
        .map(|t| t.format("%Y%m%dT%H%M%SZ").to_string())
        .ok_or(ErrorCode::InvalidArgument)
}

/// What to sign. `query` values are escaped by the signer. `headers`
/// are extra headers to sign and send (lowercase names); `host`,
/// `x-amz-date` and `x-amz-content-sha256` are added. `payload_sha256`
/// is the hex SHA-256 of the body ([`EMPTY_SHA256`] for none).
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
        || !valid_value(host)
        || host.is_empty()
        || key.access_key.is_empty()
        || !key.access_key.bytes().all(|c| c.is_ascii_alphanumeric())
        || !valid_name(key.region)
        || payload_sha256.len() != 64
        || !payload_sha256.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err(ErrorCode::InvalidArgument);
    }
    let date = amz_date(unix_secs)?;

    let mut pairs: Vec<(String, String)> =
        query.iter().map(|(k, v)| (encode(k), encode(v))).collect();
    pairs.sort();
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

/// A page of a list answer. `truncated` = the store has more keys.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListedPage {
    pub objects: Vec<Listed>,
    pub truncated: bool,
}

fn reference(entity: &str) -> Result<char> {
    Ok(match entity {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        s => {
            let code = match s.strip_prefix("#x") {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => s.strip_prefix('#').and_then(|d| d.parse().ok()),
            };
            code.and_then(char::from_u32)
                .ok_or(ErrorCode::MalformedXML)?
        }
    })
}

/// Parses the body of a `ListObjectsV2` answer: `Key`, `Size` and `ETag`
/// of every `Contents`, and `IsTruncated`. Other elements are skipped.
/// No DTD, CDATA or processing instruction; an entry that lacks one of
/// the three fields is an error, never a shorter list.
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
    loop {
        match reader.read_event().map_err(|_| bad)? {
            Event::Start(e) => {
                if path.len() >= 8 || (path.is_empty() && rooted) {
                    return Err(bad);
                }
                rooted = true;
                path.push(e.local_name().as_ref().to_owned());
                text.clear();
            }
            Event::Empty(_) | Event::Decl(_) | Event::Comment(_) => {}
            Event::Text(e) => text.push_str(&e.xml10_content()),
            Event::GeneralRef(e) => text.push(reference(e.as_ref())?),
            Event::End(_) => {
                let name = path.pop().ok_or(bad)?;
                let at: Vec<&str> = path.iter().map(String::as_str).collect();
                let value = std::mem::take(&mut text);
                match (at.as_slice(), name.as_str()) {
                    (["ListBucketResult"], "IsTruncated") => {
                        truncated = Some(match value.as_str() {
                            "true" => true,
                            "false" => false,
                            _ => return Err(bad),
                        });
                    }
                    (["ListBucketResult", "Contents"], "Key") => key = Some(value),
                    (["ListBucketResult", "Contents"], "Size") => {
                        size = Some(value.parse::<u64>().map_err(|_| bad)?);
                    }
                    (["ListBucketResult", "Contents"], "ETag") => {
                        etag = Some(value.trim_matches('"').to_owned());
                    }
                    (["ListBucketResult"], "Contents") => page.objects.push(Listed {
                        key: key.take().ok_or(bad)?,
                        size: size.take().ok_or(bad)?,
                        etag: etag.take().ok_or(bad)?,
                    }),
                    ([], root) if root != "ListBucketResult" => return Err(bad),
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => return Err(bad),
        }
    }
    if !path.is_empty() || !rooted {
        return Err(bad);
    }
    page.truncated = truncated.ok_or(bad)?;
    Ok(page)
}
