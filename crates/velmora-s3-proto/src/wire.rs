// Provenance: copied from TogetherWeOwn/qerith at commit fc09396c,
// original path crates/qerith-core/src/s3/wire.rs. License: MIT.
// Copied verbatim except: this header; the `restore` subresource is removed from the
// accepted query keys (S3 STANDARD semantics); object keys over 1024 bytes or with C0
// controls / U+FFFE / U+FFFF (not representable in XML 1.0) are rejected; the
// CRC32C/CRC64NVME/SHA1 checksum headers and the aws-chunked headers are accepted;
// the SDK's `x-id` operation hint is accepted as a query parameter;
// `x-amz-bucket-object-lock-enabled: false` is accepted (Object Lock is not offered);
// the ListObjects V1 `marker` and the V2 `fetch-owner` query keys are accepted;
// `Headers::validate_features` is replaced by `Headers::check_features`, which names
// the header it refuses and accepts the no-op headers listed there.

use super::{ErrorCode, Policy, Result};

pub const MAX_KEY_BYTES: usize = 1024;

/// Parsed once from the raw HTTP origin-form target, never through a URL parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    raw_path: String,
    pub bucket: String,
    pub key: Option<String>,
    query: Vec<(Vec<u8>, Vec<u8>)>,
    encoded_query: Vec<(String, String)>,
}

/// The rule an object key is held to wherever a request names one, in
/// the path or in a DeleteObjects body: at most [`MAX_KEY_BYTES`] and no
/// character XML 1.0 cannot carry. The empty string passes: a path may
/// end in `/`, and the caller refuses a key it needs and did not get.
pub fn storable_key(key: &str) -> bool {
    key.len() <= MAX_KEY_BYTES
        && !key
            .chars()
            .any(|c| c < ' ' || matches!(c, '\u{fffe}' | '\u{ffff}'))
}

impl Target {
    pub fn parse(raw: &str, policy: &Policy) -> Result<Self> {
        if raw.len() > policy.limits.target_bytes
            || !raw.starts_with('/')
            || !raw.bytes().all(|c| c.is_ascii_graphic() && c != b'#')
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let (path, query) = raw.split_once('?').unwrap_or((raw, ""));
        let (bucket, key) = path[1..]
            .split_once('/')
            .map_or((&path[1..], None), |(b, k)| (b, Some(k)));
        // Explicit path-style addressing; a bucket cannot be percent-aliased.
        if (!bucket.is_empty() || key.is_some())
            && (bucket.len() < 3
                || bucket.len() > 63
                || !bucket
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b".-".contains(&c))
                || !bucket.as_bytes()[0].is_ascii_alphanumeric()
                || !bucket.as_bytes()[bucket.len() - 1].is_ascii_alphanumeric()
                || bucket.contains("..")
                || bucket.parse::<std::net::Ipv4Addr>().is_ok())
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let key = key
            .map(|k| String::from_utf8(decode(k)?).map_err(|_| ErrorCode::InvalidRequest))
            .transpose()?;
        // S3's key limit; also keeps every listing token under its size cap.
        // Keys XML 1.0 cannot carry are refused so they are never stored.
        if key.as_ref().is_some_and(|k| !storable_key(k)) {
            return Err(ErrorCode::InvalidArgument);
        }
        let mut pairs = Vec::new();
        let mut encoded_query = Vec::new();
        if !query.is_empty() {
            for pair in query.split('&') {
                if pairs.len() >= policy.limits.query_pairs {
                    return Err(ErrorCode::InvalidRequest);
                }
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                pairs.push((decode(k)?, decode(v)?));
                encoded_query.push((k.to_owned(), v.to_owned()));
            }
        }
        Ok(Self {
            raw_path: path.into(),
            bucket: bucket.into(),
            key,
            query: pairs,
            encoded_query,
        })
    }

    /// Preserve the encoded path exactly (including slash, dot segments and
    /// percent-escape case), matching the pinned S3 signer, not generic SigV4.
    pub fn canonical_path(&self) -> &str {
        &self.raw_path
    }

    pub fn canonical_query(&self, presigned: bool) -> String {
        // The target is already wire-encoded. Do not decode/re-encode escapes
        // or turn literal '+' into a space; match the pinned SDK URL signer.
        let mut pairs: Vec<_> = self
            .encoded_query
            .iter()
            .filter(|(k, _)| !presigned || k != "X-Amz-Signature")
            .cloned()
            .collect();
        pairs.sort();
        pairs
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    }

    pub fn query(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.query
    }

    pub(crate) fn one(&self, name: &str) -> Result<Option<&str>> {
        let mut values = self.query.iter().filter(|(k, _)| k == name.as_bytes());
        let v = values
            .next()
            .map(|(_, v)| std::str::from_utf8(v).map_err(|_| ErrorCode::InvalidRequest))
            .transpose()?;
        if values.next().is_some() {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(v)
    }

    pub(crate) fn validate_features(&self) -> Result<()> {
        for (key, _) in &self.query {
            let key = std::str::from_utf8(key).map_err(|_| ErrorCode::InvalidRequest)?;
            // No STS/session, policy/ACL/object-lock/encryption or unknown knobs.
            if !matches!(
                key,
                "X-Amz-Algorithm"
                    | "X-Amz-Credential"
                    | "X-Amz-Date"
                    | "X-Amz-Expires"
                    | "X-Amz-SignedHeaders"
                    | "X-Amz-Signature"
                    | "uploads"
                    | "uploadId"
                    | "partNumber"
                    | "location"
                    | "delete"
                    | "list-type"
                    | "prefix"
                    | "delimiter"
                    | "continuation-token"
                    | "start-after"
                    | "marker"
                    | "fetch-owner"
                    | "max-keys"
                    | "encoding-type"
                    | "key-marker"
                    | "upload-id-marker"
                    | "part-number-marker"
                    | "max-parts"
                    | "max-uploads"
                    // The AWS SDKs (Go v2, JS v3) append `x-id=<Operation>`.
                    // S3 ignores it for routing and so does the router; like
                    // every query pair it stays in the canonical query, so it
                    // is signed whenever it is sent.
                    | "x-id"
            ) {
                return Err(ErrorCode::InvalidRequest);
            }
            // Repetition remains represented by the parser/canonicalizer, but
            // ambiguous operation/feature selectors are not accepted by adapters.
            self.one(key)?;
        }
        Ok(())
    }
}

fn decode(value: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len());
    let mut iter = value.bytes();
    while let Some(b) = iter.next() {
        if b == b'%' {
            let a = iter
                .next()
                .and_then(|c| (c as char).to_digit(16))
                .ok_or(ErrorCode::InvalidRequest)?;
            let b = iter
                .next()
                .and_then(|c| (c as char).to_digit(16))
                .ok_or(ErrorCode::InvalidRequest)?;
            out.push((a * 16 + b) as u8);
        } else {
            out.push(b);
        } // '+' is a literal plus, never form-url-encoded space.
    }
    Ok(out)
}

/// Header names are case insensitive; repeated ordinary fields retain value
/// order. Ambiguous singleton fields are rejected before signing or framing.
#[derive(Clone, Debug)]
pub struct Headers {
    fields: Vec<(String, String)>,
    combined: Vec<(String, String)>,
}

pub(crate) fn persistent_metadata(name: &str) -> bool {
    name.starts_with("x-amz-meta-") && name.len() > 11
        || matches!(
            name,
            "content-type"
                | "content-encoding"
                | "content-language"
                | "content-disposition"
                | "cache-control"
                | "expires"
        )
}

pub(crate) fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}

pub(crate) fn valid_header_value(value: &str) -> bool {
    value.bytes().all(|c| c == b'\t' || (32..=126).contains(&c))
}

impl Headers {
    pub fn new(fields: &[(&str, &str)], policy: &Policy) -> Result<Self> {
        if fields.len() > policy.limits.header_count {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut bytes = 0usize;
        let mut out = Vec::new();
        for (name, value) in fields {
            bytes = bytes
                .checked_add(name.len())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or(ErrorCode::InvalidRequest)?;
            if bytes > policy.limits.header_bytes
                || !valid_header_name(name)
                || !valid_header_value(value)
            {
                return Err(ErrorCode::InvalidRequest);
            }
            let name = name.to_ascii_lowercase();
            if (name.starts_with("x-amz-")
                || matches!(
                    name.as_str(),
                    "host"
                        | "authorization"
                        | "content-length"
                        | "transfer-encoding"
                        | "content-md5"
                        | "content-encoding"
                        | "content-type"
                        | "content-disposition"
                        | "expires"
                        | "range"
                        | "if-modified-since"
                        | "if-unmodified-since"
                ))
                && out.iter().any(|(n, _)| n == &name)
            {
                return Err(ErrorCode::InvalidRequest);
            }
            out.push((name, value.trim_matches([' ', '\t']).to_owned()));
        }
        let mut combined: Vec<(String, String)> = Vec::new();
        for (name, value) in &out {
            if let Some((_, existing)) = combined.iter_mut().find(|(n, _)| n == name) {
                existing.push(',');
                existing.push_str(value);
            } else {
                combined.push((name.clone(), value.clone()));
            }
        }
        Ok(Self {
            fields: out,
            combined,
        })
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.combined
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.combined.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub(crate) fn validate_features(&self) -> Result<()> {
        self.check_features().map_err(|refusal| refusal.code)
    }

    /// The header policy, with the header a refusal is about. Three
    /// classes of `x-amz-*` header:
    ///
    /// * understood and acted on (dates, checksums, copy source, ...);
    /// * accepted and ignored, because the service already does what the
    ///   header asks or the header asks for nothing
    ///   ([`IGNORED_HEADERS`] and the values named below);
    /// * everything else, refused by name: `NotImplemented` for a header
    ///   that is not offered, a specific code for a value that is not.
    ///
    /// Nothing here reads a secret, so the answer may be given before the
    /// signature is checked. An ignored header is still canonical-request
    /// input when the client signed it, and like every `x-amz-*` header
    /// it must be signed (`verify`).
    pub fn check_features(&self) -> std::result::Result<(), HeaderRefusal> {
        let refuse = |code, header: &str| {
            Err(HeaderRefusal {
                code,
                header: header.to_owned(),
            })
        };
        if let (Some(wire), Some(sdk)) = (
            self.get("x-amz-checksum-algorithm"),
            self.get("x-amz-sdk-checksum-algorithm"),
        ) {
            if wire != sdk {
                return refuse(ErrorCode::InvalidRequest, "x-amz-sdk-checksum-algorithm");
            }
        }
        for (k, v) in self.iter() {
            if !k.starts_with("x-amz-") || k.starts_with("x-amz-meta-") {
                continue;
            }
            match k {
                "x-amz-checksum-algorithm" | "x-amz-sdk-checksum-algorithm" => {
                    if super::ChecksumAlgorithm::from_name(v).is_none() {
                        return refuse(ErrorCode::InvalidRequest, k);
                    }
                }
                // rclone sends `false` on CreateBucket. Object Lock is not
                // offered, so asking for it is refused, never ignored.
                "x-amz-bucket-object-lock-enabled" => {
                    if !v.eq_ignore_ascii_case("false") {
                        return refuse(ErrorCode::NotImplemented, k);
                    }
                }
                "x-amz-storage-class" => {
                    if super::storage_class(Some(v)).is_err() {
                        return refuse(ErrorCode::InvalidStorageClass, k);
                    }
                }
                "x-amz-checksum-mode" => {
                    if v != "ENABLED" {
                        return refuse(ErrorCode::InvalidRequest, k);
                    }
                }
                // Every object is private to the keys granted on its
                // bucket, which is what these two canned ACLs ask for.
                // Any other ACL would grant access this service cannot
                // give, so it is refused as S3 refuses an ACL on a bucket
                // with ACLs disabled.
                "x-amz-acl" => {
                    if !matches!(v, "private" | "bucket-owner-full-control") {
                        return refuse(ErrorCode::AccessControlListNotSupported, k);
                    }
                }
                // A no-op: every object is encrypted before it is stored,
                // with keys this service manages, whether or not the
                // client asks. `AES256` (SSE-S3) asks for exactly that.
                // `aws:kms` and customer keys name key management that is
                // not offered and are refused.
                "x-amz-server-side-encryption" => {
                    if v != "AES256" {
                        return refuse(ErrorCode::InvalidArgument, k);
                    }
                }
                // No bucket is requester-pays, where S3 ignores the header.
                "x-amz-request-payer" => {
                    if v != "requester" {
                        return refuse(ErrorCode::InvalidArgument, k);
                    }
                }
                // The size a multipart upload will have, as newer SDKs
                // declare it. CompleteMultipartUpload holds the object
                // to it; no other operation gives it a meaning.
                "x-amz-mp-object-size" => {
                    if super::decimal(v).is_err() {
                        return refuse(ErrorCode::InvalidArgument, k);
                    }
                }
                _ if UNDERSTOOD_HEADERS.contains(&k) || IGNORED_HEADERS.contains(&k) => {}
                _ if k.starts_with("x-amz-grant-") => {
                    return refuse(ErrorCode::AccessControlListNotSupported, k);
                }
                // Object lock, tagging, session tokens, customer keys,
                // redirects, bucket-owner checks, and whatever comes next:
                // each means something to the client that this service
                // would not do.
                _ => return refuse(ErrorCode::NotImplemented, k),
            }
        }
        Ok(())
    }
}

/// `x-amz-*` headers some handler or the verifier acts on, beyond those
/// [`Headers::check_features`] holds to a value.
const UNDERSTOOD_HEADERS: [&str; 17] = [
    "x-amz-date",
    "x-amz-content-sha256",
    "x-amz-checksum-sha256",
    "x-amz-checksum-crc32",
    "x-amz-checksum-crc32c",
    "x-amz-checksum-crc64nvme",
    "x-amz-checksum-sha1",
    "x-amz-checksum-type",
    "x-amz-decoded-content-length",
    "x-amz-trailer",
    "x-amz-copy-source",
    "x-amz-copy-source-range",
    "x-amz-metadata-directive",
    "x-amz-copy-source-if-match",
    "x-amz-copy-source-if-none-match",
    "x-amz-copy-source-if-modified-since",
    "x-amz-copy-source-if-unmodified-since",
];

/// `x-amz-*` headers accepted whatever their value, and ignored: they
/// describe the client and ask the service for nothing.
pub const IGNORED_HEADERS: [&str; 1] = [
    // The browser builds of the AWS SDK for JavaScript send (and sign)
    // their user agent here, where `User-Agent` cannot be set.
    "x-amz-user-agent",
];

/// A request header the service will not act on: the S3 error code and
/// the lowercase name of the header, so the answer can name it. The
/// name is request data: escape it before it is rendered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderRefusal {
    pub code: ErrorCode,
    pub header: String,
}

pub fn canonical_request(
    method: &str,
    target: &Target,
    headers: &Headers,
    signed_headers: &str,
    payload_hash: &str,
    presigned: bool,
) -> Result<String> {
    if !matches!(method, "GET" | "HEAD" | "PUT" | "POST" | "DELETE") {
        return Err(ErrorCode::NotImplemented);
    }
    let names: Vec<_> = signed_headers.split(';').collect();
    if names.is_empty()
        || names.windows(2).any(|w| w[0] >= w[1])
        || !names.contains(&"host")
        || names
            .iter()
            .any(|n| n.is_empty() || n.bytes().any(|c| c.is_ascii_uppercase()))
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut canonical = String::new();
    for name in names {
        let values: Vec<_> = headers
            .fields
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.split_ascii_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        if values.is_empty() {
            return Err(ErrorCode::InvalidRequest);
        }
        canonical.push_str(&format!("{name}:{}\n", values.join(",")));
    }
    Ok(format!(
        "{method}\n{}\n{}\n{canonical}\n{signed_headers}\n{payload_hash}",
        target.canonical_path(),
        target.canonical_query(presigned)
    ))
}
