//! Plumbing shared by the S3 handlers: the protocol policy, header-only
//! authentication, error rendering, the mutation gates and the stored
//! metadata encoding.

use std::collections::BTreeMap;

use velmora_s3_proto::mutation::UploadMetadata;
use velmora_s3_proto::{
    verify, Authority, ChecksumAlgorithm, Credential, ErrorCode, Headers, Limits, Policy,
    StoredChecksum, Target, VerifiedRequest,
};
use zeroize::Zeroizing;

use crate::config::{BridgeConfig, Maintenance, REAL_DATA_READY};
use crate::crypto::unwrap_secret;
use crate::ingress::IngressError;
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::recovery::{discard_generation, Unpublished};
use crate::replay::ReplayProbe;
use crate::types::{Bucket, GenerationRow, KeyStatus, Perm, RespBody, S3Request, S3Response};

/// Longest accepted origin-form target: a 1024-byte key with every byte
/// percent-encoded, plus bucket and query.
const TARGET_BYTES: usize = 8 * 1024;
const HEADER_BYTES: usize = 32 * 1024;
const HEADER_COUNT: usize = 128;
const QUERY_PAIRS: usize = 32;
const CONTROL_XML_BYTES: usize = 1024 * 1024;
const CLOCK_SKEW_SECS: u32 = 900;
const PRESIGN_SECS: u32 = 604_800;

/// Headers that make a mutation conditional. The slice cannot evaluate
/// them atomically with the commit, so it refuses them outright.
const CONDITIONAL_HEADERS: [&str; 4] = [
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
];

/// The S3 XML error for a protocol error code.
pub(super) fn s3_error(code: ErrorCode) -> S3Response {
    let message = match code {
        ErrorCode::AccessDenied => "Access Denied",
        ErrorCode::SignatureDoesNotMatch => {
            "The request signature we calculated does not match the signature you provided."
        }
        ErrorCode::RequestTimeTooSkewed => {
            "The difference between the request time and the current time is too large."
        }
        ErrorCode::NoSuchKey => "The specified key does not exist.",
        ErrorCode::NoSuchBucket => "The specified bucket does not exist.",
        ErrorCode::PreconditionFailed => {
            "At least one of the preconditions you specified did not hold."
        }
        ErrorCode::InvalidRange => "The requested range cannot be satisfied.",
        ErrorCode::BadDigest => "The digest you specified did not match what we received.",
        ErrorCode::EntityTooLarge => "Your proposed upload exceeds the maximum allowed size.",
        ErrorCode::IncompleteBody => {
            "You did not provide the number of bytes specified by the Content-Length HTTP header."
        }
        ErrorCode::NotImplemented => return S3Response::not_implemented(),
        ErrorCode::SlowDown => return IngressError::SlowDown.response(),
        ErrorCode::InternalError => "We encountered an internal error. Please try again.",
        _ => "The request is not valid.",
    };
    S3Response::error(code.status(), &format!("{code:?}"), message)
}

/// `500 InternalError`. Carries no detail: the cause may name storage
/// keys or provider replies.
pub(super) fn internal() -> S3Response {
    s3_error(ErrorCode::InternalError)
}

/// `503 ServiceUnavailable` with `Retry-After`: the object exists but its
/// bytes cannot be produced right now.
pub(super) fn unavailable() -> S3Response {
    let mut resp = S3Response::error(
        503,
        "ServiceUnavailable",
        "The object cannot be read right now. Please try again.",
    );
    resp.headers.push(("retry-after".into(), "30".into()));
    resp
}

/// A protocol-crate response as a bridge response.
pub(super) fn from_proto(r: velmora_s3_proto::Response) -> S3Response {
    S3Response {
        status: r.status,
        headers: r.headers,
        body: if r.body.is_empty() {
            RespBody::Empty
        } else {
            RespBody::Bytes(r.body)
        },
    }
}

/// The protocol policy for this deployment. Uploads are capped at one
/// extent.
pub(super) fn policy(cfg: &BridgeConfig) -> Result<Policy, S3Response> {
    Policy::new(
        cfg.s3_host.clone(),
        cfg.region.clone(),
        Limits {
            target_bytes: TARGET_BYTES,
            control_xml_bytes: CONTROL_XML_BYTES,
            header_bytes: HEADER_BYTES,
            header_count: HEADER_COUNT,
            query_pairs: QUERY_PAIRS,
            upload_bytes: cfg.max_extent_bytes,
            clock_skew_seconds: CLOCK_SKEW_SECS,
            presign_seconds: PRESIGN_SECS,
        },
    )
    .map_err(|_| internal())
}

/// A request whose signature verified and whose key is granted the
/// operation on the addressed bucket.
pub(super) struct Authed {
    pub policy: Policy,
    pub target: Target,
    pub headers: Headers,
    pub verified: VerifiedRequest,
    /// The addressed bucket; `None` only for the service root.
    pub bucket: Option<Bucket>,
}

impl Authed {
    /// The addressed bucket and decoded key of an object request.
    pub(super) fn object(&self) -> Result<(&Bucket, &str), S3Response> {
        match (&self.bucket, self.target.key.as_deref()) {
            (Some(bucket), Some(key)) if !key.is_empty() => Ok((bucket, key)),
            _ => Err(s3_error(ErrorCode::InvalidRequest)),
        }
    }
}

/// The one credential this request names, with what it may do to the
/// addressed bucket. An unknown or disabled key has no secret; a missing
/// bucket or grant has no permission. Both end in `AccessDenied`.
struct OneKey {
    akid: String,
    principal: String,
    secret: Option<Zeroizing<Vec<u8>>>,
    perm: Option<Perm>,
}

impl Authority for OneKey {
    fn credential(&self, access_key: &str) -> Option<Credential<'_>> {
        let secret = self.secret.as_ref()?;
        (access_key == self.akid).then_some(Credential {
            secret,
            principal: &self.principal,
        })
    }

    fn authorize(&self, principal: &str, method: &str, target: &Target) -> bool {
        if principal != self.principal {
            return false;
        }
        if target.bucket.is_empty() {
            // The service root: any valid key may list its own buckets.
            return method == "GET";
        }
        match self.perm {
            Some(Perm::Rw) => true,
            Some(Perm::Ro) => matches!(method, "GET" | "HEAD"),
            None => false,
        }
    }
}

/// The access key id the request claims, from the `Authorization` header
/// or a presigned query. Only used to look the key up; the verifier
/// parses the credential strictly.
fn claimed_key(headers: &Headers, target: &Target) -> Option<String> {
    let credential = match headers.get("authorization") {
        Some(value) => value
            .split_once("Credential=")
            .map(|(_, rest)| rest.to_owned())?,
        None => target
            .query()
            .iter()
            .find(|(k, _)| k == b"X-Amz-Credential")
            .and_then(|(_, v)| String::from_utf8(v.clone()).ok())?,
    };
    let akid = credential.split(['/', ',']).next()?.trim();
    (!akid.is_empty()).then(|| akid.to_owned())
}

/// Headers the edge adds. They are never signed and their values are not
/// always printable ASCII, so they are dropped before header validation.
/// Dropping a header can only fail a signature, never satisfy one.
pub(super) fn edge_header(name: &str) -> bool {
    name.starts_with("cf-")
        || name.starts_with("x-forwarded-")
        || matches!(name, "cdn-loop" | "x-real-ip" | "true-client-ip")
}

/// Authenticates and authorizes from the request line and headers only.
/// The body is never touched. A missing bucket, an unknown or disabled
/// key and a missing grant are indistinguishable (`AccessDenied`).
pub(super) async fn authenticate<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: &S3Request,
) -> Result<Authed, S3Response>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let policy = policy(&bridge.cfg)?;
    let target = Target::parse(&req.raw_target, &policy).map_err(s3_error)?;
    let fields: Vec<(&str, &str)> = req
        .headers
        .iter()
        .filter(|(n, _)| !edge_header(n))
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let headers = Headers::new(&fields, &policy).map_err(s3_error)?;

    let mut authority = OneKey {
        akid: claimed_key(&headers, &target).unwrap_or_default(),
        principal: String::new(),
        secret: None,
        perm: None,
    };
    let mut bucket = None;
    if !authority.akid.is_empty() {
        let row = bridge
            .catalog
            .access_key(&authority.akid)
            .await
            .map_err(|_| internal())?
            .filter(|row| row.status == KeyStatus::Active);
        if let Some(row) = row {
            let secret = unwrap_secret(
                &bridge.kek,
                row.kek_version,
                &row.access_key_id,
                &row.secret_wrapped,
            )
            .map_err(|_| internal())?;
            authority.principal = row.principal;
            authority.secret = Some(secret);
            if !target.bucket.is_empty() {
                bucket = bridge
                    .catalog
                    .bucket_by_name(&target.bucket)
                    .await
                    .map_err(|_| internal())?;
            }
            if let Some(b) = &bucket {
                authority.perm = bridge
                    .catalog
                    .grant(&authority.akid, &b.id)
                    .await
                    .map_err(|_| internal())?;
            }
        }
    }

    // Transport was checked at ingress; plain HTTP never reaches a handler
    // outside the dev override.
    let verified = verify(
        req.method.as_str(),
        &target,
        &headers,
        true,
        bridge.clock.now().secs().0,
        &policy,
        &authority,
    )
    .map_err(s3_error)?;
    if !target.bucket.is_empty() && bucket.is_none() {
        return Err(s3_error(ErrorCode::AccessDenied));
    }
    Ok(Authed {
        policy,
        target,
        headers,
        verified,
        bucket,
    })
}

/// The gates every mutation passes after authentication and before its
/// body is read or anything is stored:
/// - a conditional header is `501 NotImplemented`, never ignored;
/// - a catalogue restore in progress is `503`;
/// - until catalogue recovery is proven, only disposable buckets take
///   writes.
pub(super) fn mutation_gate(
    cfg: &BridgeConfig,
    headers: &Headers,
    bucket: &Bucket,
) -> Result<(), S3Response> {
    if CONDITIONAL_HEADERS.iter().any(|h| headers.get(h).is_some()) {
        return Err(S3Response::not_implemented());
    }
    if cfg.maintenance == Maintenance::Restore {
        return Err(unavailable());
    }
    if !REAL_DATA_READY && !bucket.disposable {
        return Err(s3_error(ErrorCode::AccessDenied));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Stored metadata
// ---------------------------------------------------------------------------

fn json_map<'a>(pairs: impl Iterator<Item = (&'a String, &'a String)>) -> String {
    let map: BTreeMap<&str, &str> = pairs.map(|(k, v)| (k.as_str(), v.as_str())).collect();
    // A map of strings always serializes.
    serde_json::to_string(&map).unwrap_or_else(|_| "{}".into())
}

/// `(content_json, user_meta_json)` for a generation or upload row: two
/// JSON objects of lowercase header name to value. The first holds the
/// standard content headers, the second the `x-amz-meta-*` headers.
pub(super) fn metadata_json(meta: &UploadMetadata) -> (String, String) {
    let user = |k: &String| k.starts_with("x-amz-meta-");
    (
        json_map(meta.headers.iter().filter(|(k, _)| !user(k))),
        json_map(meta.headers.iter().filter(|(k, _)| user(k))),
    )
}

/// The stored headers of a generation, as the read planner wants them.
/// `None` when a row does not parse.
pub(super) fn stored_headers(g: &GenerationRow) -> Option<Vec<(String, String)>> {
    let mut out: BTreeMap<String, String> = serde_json::from_str(&g.content_json).ok()?;
    let user: BTreeMap<String, String> = serde_json::from_str(&g.user_meta_json).ok()?;
    out.extend(user);
    Some(out.into_iter().collect())
}

/// `checksum_json` for a full-object checksum the client supplied.
pub(super) fn checksum_json(algorithm: ChecksumAlgorithm, value: &str) -> String {
    serde_json::json!({ "algorithm": algorithm.name(), "type": "FULL_OBJECT", "value": value })
        .to_string()
}

/// The full-object checksum stored with a generation. Any other shape
/// (none, or a composite one) is not reported on reads.
pub(super) fn stored_checksum(g: &GenerationRow) -> Option<StoredChecksum> {
    let v: serde_json::Value = serde_json::from_str(g.checksum_json.as_deref()?).ok()?;
    if v.get("type")?.as_str()? != "FULL_OBJECT" {
        return None;
    }
    let algorithm = ChecksumAlgorithm::from_name(v.get("algorithm")?.as_str()?)?;
    StoredChecksum::full(algorithm, v.get("value")?.as_str()?.to_owned()).ok()
}

/// Removes the recovery record of a generation whose publication the
/// catalogue refused. The record of a published generation is never
/// removed: if a row exists under the id after all (the refusal says it
/// cannot), the record stays.
///
/// The delete is tried [`DISCARD_ATTEMPTS`] times. A record that is
/// still there after that replays as an object nobody was told exists:
/// never a lost one.
pub(crate) async fn discard_refused<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Bridge<C, B, N, J, K, T>,
    generation: &GenerationRow,
    refused: Unpublished,
) -> crate::types::Result<()> {
    let mut last = Ok(());
    for _ in 0..DISCARD_ATTEMPTS {
        last = match bridge.catalog.replay_probe(generation).await {
            Ok(ReplayProbe::Present) => return Ok(()),
            Ok(_) => discard_generation(&bridge.safety, &refused).await,
            Err(e) => Err(e),
        };
        if last.is_ok() {
            break;
        }
    }
    last
}

<<<<<<< HEAD
/// Refuses a mutation while a replay of the recovery records is under
/// way: the catalogue then holds only a part of them, and a write could
/// be published under an id that a record still to come overrides.
/// `MAINTENANCE=restore` refuses the same requests earlier; this one
/// still holds when maintenance is switched off before the replay ended.
pub(super) async fn restore_gate<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Bridge<C, B, N, J, K, T>,
) -> Result<(), S3Response> {
    match bridge.catalog.restore_pending().await {
        Ok(false) => Ok(()),
        Ok(true) => Err(unavailable()),
        Err(_) => Err(internal()),
    }
}
=======
const DISCARD_ATTEMPTS: usize = 3;
>>>>>>> bridge/h9-low-fixes
