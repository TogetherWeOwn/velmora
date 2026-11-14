// Provenance: copied from TogetherWeOwn/qerith at commit fc09396c,
// original path crates/qerith-core/src/s3/auth.rs. License: MIT.
// Copied verbatim except: test fixture path `../../tests/fixtures/published-crypto.json` -> `../tests/fixtures/published-crypto.json` (line 245); this header;
// added (not from qerith): `SINGLE_VALUE_HEADERS` (with the copy-source conditions) and the
// signed comma-value check in `verify`;
// the `STREAMING-*` (aws-chunked) payload values, the streaming seed in `VerifiedRequest`
// and the `signing_key`/`sign` helpers.

use chrono::NaiveDateTime;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use super::chunked::{Streaming, StreamingSeed};
use super::{canonical_request, decimal, hex, unhex, ErrorCode, Headers, Policy, Result, Target};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// Headers whose commas are taken literally. Any other signed header whose value
/// contains a comma is rejected: an edge that merges duplicate fields into one
/// `", "`-joined value makes a merged duplicate indistinguishable from a literal
/// comma. The standard headers listed here are safe to take literally: the
/// signature binds exactly the value string the server then uses. A merged
/// duplicate usually canonicalises differently from the client's signed fields
/// (`a, b` vs `a,b`) and fails closed with SignatureDoesNotMatch; where it does
/// match (`public` plus an empty field merges to `public,`), the verified string
/// is the one acted on, so nothing unsigned is ever accepted.
pub const SINGLE_VALUE_HEADERS: [&str; 23] = [
    "host",
    "content-type",
    "content-md5",
    "content-length",
    "range",
    "x-amz-date",
    "x-amz-content-sha256",
    "x-amz-security-token",
    "x-amz-copy-source",
    "x-amz-copy-source-if-modified-since",
    "x-amz-copy-source-if-unmodified-since",
    "x-amz-copy-source-if-match",
    "x-amz-copy-source-if-none-match",
    "expires",
    "date",
    "if-modified-since",
    "if-unmodified-since",
    "if-match",
    "if-none-match",
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMode {
    Header,
    Presigned,
}

/// Deliberately not Debug: signing secrets must not enter logs or artifacts.
pub struct Credential<'a> {
    pub secret: &'a [u8],
    pub principal: &'a str,
}

/// Local credential/scope/revocation hooks, not AWS IAM/STS. Unknown, expired,
/// disabled or revoked keys must return None. Authorization must not disclose
/// existence. Recheck it when queuing, publishing and admitting serving reads.
pub trait Authority {
    fn credential(&self, access_key: &str) -> Option<Credential<'_>>;
    fn authorize(&self, principal: &str, method: &str, target: &Target) -> bool;
}

#[derive(Clone, Debug)]
pub struct VerifiedRequest {
    pub principal: String,
    pub access_key: String,
    pub mode: AuthMode,
    payload: String,
    /// Set for the signed `STREAMING-*` payloads: chunk signatures chain
    /// from this request's signature.
    streaming: Option<StreamingSeed>,
}

impl VerifiedRequest {
    pub fn payload_hash(&self) -> &str {
        &self.payload
    }

    /// The aws-chunked variant the signed payload value selected, if any.
    pub fn streaming(&self) -> Option<Streaming> {
        Streaming::from_payload(&self.payload)
    }

    pub(crate) fn streaming_seed(&self) -> Option<&StreamingSeed> {
        self.streaming.as_ref()
    }

    pub fn recheck(&self, authority: &impl Authority, method: &str, target: &Target) -> Result<()> {
        let credential = authority
            .credential(&self.access_key)
            .ok_or(ErrorCode::AccessDenied)?;
        if credential.principal != self.principal
            || !authority.authorize(&self.principal, method, target)
        {
            return Err(ErrorCode::AccessDenied);
        }
        Ok(())
    }
}

/// Verify against a caller-supplied clock (Unix seconds). `https` must describe
/// trusted ingress transport, never an untrusted Forwarded/X-Forwarded-Proto.
/// Both signed and unsigned payload modes require HTTPS in this profile.
pub fn verify(
    method: &str,
    target: &Target,
    headers: &Headers,
    https: bool,
    now: i64,
    policy: &Policy,
    authority: &impl Authority,
) -> Result<VerifiedRequest> {
    if !https
        || !headers
            .get("host")
            .is_some_and(|host| host.eq_ignore_ascii_case(&policy.host))
    {
        return Err(ErrorCode::AccessDenied);
    }
    target.validate_features()?;
    headers.validate_features()?;
    let presigned = target.one("X-Amz-Algorithm")?.is_some();
    let (credential, signed, signature, date, mode) = if presigned {
        if headers.get("authorization").is_some()
            || headers.get("x-amz-date").is_some()
            || target.one("X-Amz-Algorithm")? != Some(ALGORITHM)
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let get = |key| target.one(key)?.ok_or(ErrorCode::InvalidRequest);
        (
            get("X-Amz-Credential")?,
            get("X-Amz-SignedHeaders")?,
            get("X-Amz-Signature")?,
            get("X-Amz-Date")?,
            AuthMode::Presigned,
        )
    } else {
        if target.query().iter().any(|(k, _)| k.starts_with(b"X-Amz-")) {
            return Err(ErrorCode::InvalidRequest);
        }
        let value = headers
            .get("authorization")
            .ok_or(ErrorCode::AccessDenied)?;
        let fields = value
            .strip_prefix("AWS4-HMAC-SHA256 ")
            .ok_or(ErrorCode::AccessDenied)?;
        let mut credential = None;
        let mut signed = None;
        let mut signature = None;
        for field in fields.split(',').map(str::trim) {
            let (key, value) = field.split_once('=').ok_or(ErrorCode::InvalidRequest)?;
            let dest = match key {
                "Credential" => &mut credential,
                "SignedHeaders" => &mut signed,
                "Signature" => &mut signature,
                _ => return Err(ErrorCode::InvalidRequest),
            };
            if dest.replace(value).is_some() {
                return Err(ErrorCode::InvalidRequest);
            }
        }
        (
            credential.ok_or(ErrorCode::InvalidRequest)?,
            signed.ok_or(ErrorCode::InvalidRequest)?,
            signature.ok_or(ErrorCode::InvalidRequest)?,
            headers.get("x-amz-date").ok_or(ErrorCode::InvalidRequest)?,
            AuthMode::Header,
        )
    };
    let scope: Vec<_> = credential.split('/').collect();
    if scope.len() != 5
        || scope[0].is_empty()
        || scope[1].len() != 8
        || scope[2] != policy.region
        || scope[3] != "s3"
        || scope[4] != "aws4_request"
        || date.len() != 16
        || !date.is_ascii()
        || &date[..8] != scope[1]
    {
        return Err(ErrorCode::AccessDenied);
    }
    let timestamp = NaiveDateTime::parse_from_str(date, "%Y%m%dT%H%M%SZ")
        .map_err(|_| ErrorCode::AccessDenied)?;
    if timestamp.format("%Y%m%dT%H%M%SZ").to_string() != date {
        return Err(ErrorCode::AccessDenied);
    }
    let time = timestamp.and_utc().timestamp();
    let skew = i64::from(policy.limits.clock_skew_seconds);
    if presigned {
        let ttl = decimal(
            target
                .one("X-Amz-Expires")?
                .ok_or(ErrorCode::InvalidRequest)?,
        )?;
        if ttl == 0 || ttl > u64::from(policy.limits.presign_seconds) {
            return Err(ErrorCode::InvalidArgument);
        }
        if now < time.saturating_sub(skew) || now >= time.saturating_add(ttl as i64) {
            return Err(ErrorCode::AccessDenied);
        }
    } else if now.abs_diff(time) > skew as u64 {
        return Err(ErrorCode::RequestTimeTooSkewed);
    }

    let names: Vec<_> = signed.split(';').collect();
    // Possibly merged duplicates are refused before any signature work.
    if names.iter().any(|name| {
        !SINGLE_VALUE_HEADERS.contains(name) && headers.get(name).is_some_and(|v| v.contains(','))
    }) {
        return Err(ErrorCode::InvalidRequest);
    }
    if !presigned && !names.contains(&"x-amz-date") {
        return Err(ErrorCode::InvalidRequest);
    }
    for (key, _) in headers.iter() {
        // The content SHA is itself canonical request input. All other semantic
        // fields must be signed; transport/client headers may remain unsigned.
        if (key.starts_with("x-amz-") && key != "x-amz-content-sha256"
            || super::wire::persistent_metadata(key)
            || matches!(
                key,
                "content-md5"
                    | "content-type"
                    | "content-encoding"
                    | "range"
                    | "if-match"
                    | "if-none-match"
                    | "if-modified-since"
                    | "if-unmodified-since"
            ))
            && !names.contains(&key)
        {
            return Err(ErrorCode::AccessDenied);
        }
    }
    let payload = match headers.get("x-amz-content-sha256") {
        Some(v) => v,
        None if presigned => "UNSIGNED-PAYLOAD",
        None => return Err(ErrorCode::InvalidRequest),
    };
    let streaming = Streaming::from_payload(payload);
    if streaming.is_some() && presigned {
        // A presigned URL has no seed signature for a chunk chain.
        return Err(ErrorCode::InvalidRequest);
    }
    if payload != "UNSIGNED-PAYLOAD"
        && streaming.is_none()
        && (payload.len() != 64
            || !payload
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
    {
        // Anything else (SigV4a `STREAMING-AWS4-ECDSA-*`) is not qualified.
        return Err(ErrorCode::InvalidRequest);
    }
    let canonical = canonical_request(method, target, headers, signed, payload, presigned)?;
    let scope_string = scope[1..].join("/");
    let string_to_sign = format!(
        "{ALGORITHM}\n{date}\n{scope_string}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let key = authority
        .credential(scope[0])
        .ok_or(ErrorCode::AccessDenied)?;
    let signing_key = signing_key(key.secret, scope[1], scope[2]);
    let signature = unhex(signature).map_err(|_| ErrorCode::SignatureDoesNotMatch)?;
    let mut verifier =
        Hmac::<Sha256>::new_from_slice(&signing_key).map_err(|_| ErrorCode::InternalError)?;
    verifier.update(string_to_sign.as_bytes());
    verifier
        .verify_slice(&signature)
        .map_err(|_| ErrorCode::SignatureDoesNotMatch)?;
    if !authority.authorize(key.principal, method, target) {
        return Err(ErrorCode::AccessDenied);
    }
    let streaming = streaming.filter(|s| s.signed()).map(|_| StreamingSeed {
        key: signing_key,
        timestamp: date.into(),
        scope: scope_string.clone(),
        signature: hex(&signature),
    });
    Ok(VerifiedRequest {
        principal: key.principal.into(),
        access_key: scope[0].into(),
        mode,
        payload: payload.into(),
        streaming,
    })
}

/// The SigV4 signing key for `s3` in `region` on `date` (`YYYYMMDD`).
pub(crate) fn signing_key(secret: &[u8], date: &str, region: &str) -> [u8; 32] {
    let mut prefixed = b"AWS4".to_vec();
    prefixed.extend_from_slice(secret);
    let date_key = hmac(&prefixed, date.as_bytes());
    let region_key = hmac(&date_key, region.as_bytes());
    let service_key = hmac(&region_key, b"s3");
    hmac(&service_key, b"aws4_request")
        .try_into()
        .expect("HMAC-SHA256 is 32 bytes")
}

/// HMAC-SHA256 of a string to sign.
#[cfg(test)]
pub(crate) fn sign(key: &[u8; 32], string_to_sign: &str) -> Vec<u8> {
    hmac(key, string_to_sign.as_bytes())
}

fn hmac(key: &[u8], value: &[u8]) -> Vec<u8> {
    // HMAC accepts arbitrary key lengths, including the specified AWS4 prefix.
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(value);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published_vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/fixtures/published-crypto.json")).unwrap()
    }

    #[test]
    fn rfc4231_case_one_hmac_sha256() {
        let vectors = published_vectors();
        let vector = &vectors["rfc4231_case_one"];
        let key = unhex(vector["key_hex"].as_str().unwrap()).unwrap();
        assert_eq!(key.len(), 20);
        assert_eq!(
            hex(&hmac(&key, vector["data"].as_str().unwrap().as_bytes())),
            vector["hmac_sha256"].as_str().unwrap()
        );
    }

    #[test]
    fn published_botocore_s3_query_signature() {
        // Published test_s3_sigv4_presign in Botocore's test_signers.py,
        // pinned source in docs/s3-wire.md. Its dummy service/region are
        // tested here only; production verification still requires s3 scope.
        let canonical = "GET\n/mybucket/keyname/.bar\nX-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=access_key%2F20140101%2Fmyregion%2Fmyservice%2Faws4_request&X-Amz-Date=20140101T000000Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host\nhost:s3.us-west-2.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD";
        let vectors = published_vectors();
        let vector = &vectors["botocore_s3_query"];
        let date_key = hmac(
            vector["prefixed_key"].as_str().unwrap().as_bytes(),
            b"20140101",
        );
        let region_key = hmac(&date_key, b"myregion");
        let service_key = hmac(&region_key, b"myservice");
        let signing_key = hmac(&service_key, b"aws4_request");
        let string = format!(
            "AWS4-HMAC-SHA256\n20140101T000000Z\n20140101/myregion/myservice/aws4_request\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        assert_eq!(
            hex(&hmac(&signing_key, string.as_bytes())),
            vector["signature"].as_str().unwrap()
        );
    }
}
