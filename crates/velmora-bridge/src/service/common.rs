//! Plumbing shared by the S3 handlers: the protocol policy, header-only
//! authentication, error rendering, the mutation gates and the stored
//! metadata encoding.

use std::cell::Cell;
use std::collections::BTreeMap;

use velmora_s3_proto::mutation::UploadMetadata;
use velmora_s3_proto::{
    verify, Authority, ChecksumAlgorithm, Credential, ErrorCode, HeaderRefusal, Headers, Limits,
    Policy, StoredChecksum, Target, VerifiedRequest,
};
use zeroize::Zeroizing;

use crate::config::{BridgeConfig, Maintenance, REAL_DATA_READY};
use crate::crypto::unwrap_secret;
use crate::entry::Entry;
use crate::ingress::IngressError;
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::recovery::{discard_generation, revocation_recorded, Unpublished};
use crate::replay::ReplayProbe;
use crate::types::{
    Bucket, BucketId, GenerationId, GenerationRow, KeyStatus, Perm, Precondition,
    PreconditionError, RespBody, S3Request, S3Response,
};

/// Longest accepted origin-form target: a 1024-byte key with every byte
/// percent-encoded, plus bucket and query.
const TARGET_BYTES: usize = 8 * 1024;
const HEADER_BYTES: usize = 32 * 1024;
const HEADER_COUNT: usize = 128;
const QUERY_PAIRS: usize = 32;
const CONTROL_XML_BYTES: usize = 1024 * 1024;
const CLOCK_SKEW_SECS: u32 = 900;
const PRESIGN_SECS: u32 = 604_800;
/// Regions a credential scope may name besides the configured one. Most
/// clients sign for `us-east-1` unless told otherwise, and `auto` is
/// what S3-compatible endpoints without regions document. The region is
/// only a name here: one endpoint, no per-region data.
pub(super) const REGION_ALIASES: [&str; 2] = ["us-east-1", "auto"];

/// Headers that make a mutation conditional. A request that carries one
/// is either held to it by the batch that commits ([`conditional_gate`])
/// or refused ([`mutation_gate`]): none is ever ignored.
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
        ErrorCode::MalformedXML => "The XML you provided was not well-formed.",
        ErrorCode::NoSuchUpload => {
            "The specified upload does not exist. The upload ID may be invalid, or the upload \
             may have been aborted or completed."
        }
        ErrorCode::NotImplemented => return S3Response::not_implemented(),
        ErrorCode::SlowDown => return IngressError::SlowDown.response(),
        ErrorCode::InternalError => "We encountered an internal error. Please try again.",
        ErrorCode::InvalidAccessKeyId => {
            "The AWS Access Key Id you provided does not exist in our records."
        }
        ErrorCode::InvalidStorageClass => "The storage class you specified is not valid.",
        ErrorCode::AccessControlListNotSupported => "The bucket does not allow ACLs.",
        ErrorCode::AuthorizationHeaderMalformed => {
            "The authorization header is malformed; the region is wrong."
        }
        ErrorCode::AuthorizationQueryParametersError => {
            "Error parsing the X-Amz-Credential parameter; the region is wrong."
        }
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

/// `503 ServiceUnavailable` with `Retry-After` for a write: nothing is
/// published while the catalogue is being restored.
pub(super) fn writes_refused() -> S3Response {
    let mut resp = S3Response::error(
        503,
        "ServiceUnavailable",
        "Writes are refused until the catalogue has been restored. Please try again later.",
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

/// The protocol policy for this deployment. An upload is capped at the
/// largest PutObject body; UploadPart has its own policy, capped at one
/// extent.
pub(super) fn policy(cfg: &BridgeConfig) -> Result<Policy, S3Response> {
    policy_with(cfg, CONTROL_XML_BYTES, cfg.max_put_bytes)
}

/// [`policy`] with other caps on a control document and on a validated
/// body (DeleteObjects takes 1000 keys of up to 1024 bytes each, whatever
/// the limits on an object body are).
pub(super) fn policy_with(
    cfg: &BridgeConfig,
    control_xml_bytes: usize,
    upload_bytes: u64,
) -> Result<Policy, S3Response> {
    Policy::new(
        cfg.s3_host.clone(),
        cfg.region.clone(),
        Limits {
            target_bytes: TARGET_BYTES,
            control_xml_bytes,
            header_bytes: HEADER_BYTES,
            header_count: HEADER_COUNT,
            query_pairs: QUERY_PAIRS,
            upload_bytes,
            clock_skew_seconds: CLOCK_SKEW_SECS,
            presign_seconds: PRESIGN_SECS,
        },
    )
    .and_then(|policy| policy.with_region_aliases(&REGION_ALIASES))
    .map_err(|_| internal())
}

/// The answer to a header the service will not act on. It names the
/// header (in the message and, as S3 does for `NotImplemented`, in
/// `<Header>`), never its value.
pub(super) fn header_refused(refusal: &HeaderRefusal) -> S3Response {
    let header = refusal.header.as_str();
    let message = match refusal.code {
        ErrorCode::NotImplemented => {
            format!("The header '{header}' implies functionality that is not implemented.")
        }
        ErrorCode::InvalidStorageClass => {
            format!("The storage class you specified in '{header}' is not offered. Use STANDARD.")
        }
        ErrorCode::AccessControlListNotSupported => format!(
            "The header '{header}' asks for an ACL that is not supported. Objects are always \
             private; send 'private' or omit the header."
        ),
        ErrorCode::InvalidArgument if header == "x-amz-server-side-encryption" => format!(
            "The encryption method specified in '{header}' is not supported. Objects are \
             always encrypted at rest; send 'AES256' or omit the header."
        ),
        _ => format!("The value of the header '{header}' is not valid."),
    };
    let element = match refusal.code {
        ErrorCode::InvalidArgument => "ArgumentName",
        _ => "Header",
    };
    S3Response::error_with(
        refusal.code.status(),
        &format!("{:?}", refusal.code),
        &message,
        &[(element, header)],
    )
}

/// The answer to a `Host` that is not the configured endpoint, or
/// `None` when it is. The verifier refuses such a request whatever its
/// signature (a request is only good for the endpoint it was signed
/// for); this says why, before any key is looked up. The usual cause is
/// virtual-hosted-style addressing (`<bucket>.<endpoint>`), so that case
/// is named. The configured endpoint itself is not disclosed.
pub(super) fn host_refused(headers: &Headers, cfg: &BridgeConfig) -> Option<S3Response> {
    host_value_refused(headers.get("host")?, cfg)
}

/// [`host_refused`] for a `Host` value read off the raw request, as on a
/// route that parses no headers.
pub(super) fn host_value_refused(host: &str, cfg: &BridgeConfig) -> Option<S3Response> {
    if host.eq_ignore_ascii_case(&cfg.s3_host) {
        return None;
    }
    let suffix = format!(".{}", cfg.s3_host.to_ascii_lowercase());
    let message = if host.to_ascii_lowercase().ends_with(&suffix) {
        "Virtual-hosted-style requests are not supported. Use path-style addressing: \
         the bucket goes in the path, not in the host name."
    } else {
        "The Host header does not name this endpoint. Use the endpoint host name you were \
         given, with path-style addressing."
    };
    Some(S3Response::error_with(
        400,
        "InvalidRequest",
        message,
        &[("Header", "host")],
    ))
}

/// The region a credential scope names, when it is fit to be sent back
/// in an error (ASCII letters, digits and `-`, at most 32).
fn claimed_region(headers: &Headers, target: &Target) -> Option<String> {
    let credential = match headers.get("authorization") {
        Some(value) => value
            .split_once("Credential=")
            .map(|(_, rest)| rest.split(',').next().unwrap_or_default().to_owned())?,
        None => target
            .query()
            .iter()
            .find(|(k, _)| k == b"X-Amz-Credential")
            .and_then(|(_, v)| String::from_utf8(v.clone()).ok())?,
    };
    let region = credential.split('/').nth(2)?;
    (!region.is_empty()
        && region.len() <= 32
        && region
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    .then(|| region.to_owned())
}

/// The answer to a request the verifier refused. A scope for a region
/// this endpoint does not answer for is told which region to use, in
/// the words S3 uses; the configured region is no secret (HeadBucket
/// and GetBucketLocation report it).
pub(super) fn auth_refused(
    code: ErrorCode,
    policy: &Policy,
    headers: &Headers,
    target: &Target,
) -> S3Response {
    let expected = policy.region();
    let named = claimed_region(headers, target)
        .map(|r| format!("the region '{r}' is wrong; "))
        .unwrap_or_default();
    let message = match code {
        ErrorCode::AuthorizationHeaderMalformed => {
            format!("The authorization header is malformed; {named}expecting '{expected}'")
        }
        ErrorCode::AuthorizationQueryParametersError => {
            format!("Error parsing the X-Amz-Credential parameter; {named}expecting '{expected}'")
        }
        _ => return s3_error(code),
    };
    S3Response::error_with(
        code.status(),
        &format!("{code:?}"),
        &message,
        &[("Region", expected)],
    )
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
/// addressed bucket. An unknown, disabled or revoked key has no secret
/// (`InvalidAccessKeyId`, whatever the bucket); a missing bucket or grant
/// has no permission.
struct OneKey {
    akid: String,
    principal: String,
    secret: Option<Zeroizing<Vec<u8>>>,
    perm: Option<Perm>,
    /// Set when `authorize` refused a bucket this key has no grant on.
    /// The verifier asks `authorize` only once the signature has
    /// verified, so this is only ever set for an authenticated caller.
    no_bucket: Cell<bool>,
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
            None => {
                self.no_bucket.set(true);
                false
            }
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

/// Headers the edge adds, and the entry marker. They are never signed and
/// the edge's values are not always printable ASCII, so they are dropped
/// before header validation. Dropping a header can only fail a
/// signature, never satisfy one.
pub(super) fn edge_header(name: &str) -> bool {
    crate::entry::dropped_header(name)
}

/// Authenticates and authorizes from the request line and headers only.
/// The body is never touched. A key with no usable row is
/// `InvalidAccessKeyId` for every bucket.
///
/// A bucket that does not exist and one the key holds no grant on are
/// indistinguishable, to everyone: a caller that did not authenticate
/// gets the authentication error and learns nothing of the bucket, and
/// one that did gets `NoSuchBucket` for both (S3 checks in that order
/// too: signature, then bucket, then permission). To a key, a bucket it
/// has no grant on does not exist, so no key can probe for the names of
/// buckets that are not its own. A key that holds a grant too weak for
/// the operation (read-only, on a write) is `AccessDenied`.
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
    let target = Target::parse(&req.raw_target, &policy).map_err(s3_error);
    let fields: Vec<(&str, &str)> = req
        .headers
        .iter()
        .filter(|(n, _)| !edge_header(n))
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let headers = Headers::new(&fields, &policy).map_err(s3_error);
    // Refusals that name their cause. Neither reads anything but the
    // request itself and the configuration. The host comes before the
    // path is judged: on a virtual-hosted request the first segment is a
    // key, and "not a bucket name" would name the wrong mistake.
    if let Ok(headers) = &headers {
        if let Some(resp) = host_refused(headers, &bridge.cfg) {
            return Err(resp);
        }
    }
    let target = target?;
    let headers = headers?;
    headers
        .check_features()
        .map_err(|refusal| header_refused(&refusal))?;

    // The entry point admits one kind of key (`crate::entry`): a key of
    // the other kind is looked up as if it did not exist.
    let entry = Entry::of(&req.headers);
    let mut authority = OneKey {
        akid: claimed_key(&headers, &target)
            .filter(|akid| entry.admits(akid))
            .unwrap_or_default(),
        principal: String::new(),
        secret: None,
        perm: None,
        no_bucket: Cell::new(false),
    };
    let mut bucket = None;
    if !authority.akid.is_empty() {
        let row = bridge
            .catalog
            .access_key(&authority.akid)
            .await
            .map_err(|_| internal())?
            .filter(|row| row.status == KeyStatus::Active);
        // Under maintenance the catalogue may be a restored copy that
        // still holds a key revoked after it was taken, until the first
        // replay step deletes it; reads are served meanwhile. Its
        // revocation record is the authority then (one head per request,
        // in this mode only). Multipart refuses every request earlier.
        let row = match row {
            Some(row) if bridge.cfg.maintenance == Maintenance::Restore => {
                let revoked = revocation_recorded(&bridge.safety, &row.access_key_id)
                    .await
                    .map_err(|_| internal())?;
                (!revoked).then_some(row)
            }
            other => other,
        };
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
    .map_err(|code| {
        if code == ErrorCode::AccessDenied && authority.no_bucket.get() {
            // The signature verified; the key has no grant on a bucket
            // of this name, whether or not one exists.
            s3_error(ErrorCode::NoSuchBucket)
        } else {
            auth_refused(code, &policy, &headers, &target)
        }
    })?;
    if !target.bucket.is_empty() && bucket.is_none() {
        return Err(s3_error(ErrorCode::NoSuchBucket));
    }
    Ok(Authed {
        policy,
        target,
        headers,
        verified,
        bucket,
    })
}

/// The condition a write request names, if any. Understood are
/// `If-None-Match: *` and `If-Match` with `*` or one strong ETag, quoted
/// or bare. Everything else is `501 NotImplemented`: a date condition,
/// both headers at once, `If-None-Match` with an ETag, a list of ETags, a
/// weak one. A header that is not understood is refused, never ignored.
pub(super) fn precondition(headers: &Headers) -> Result<Option<Precondition>, S3Response> {
    let refused = || S3Response::not_implemented();
    if headers.get("if-modified-since").is_some() || headers.get("if-unmodified-since").is_some() {
        return Err(refused());
    }
    match (headers.get("if-none-match"), headers.get("if-match")) {
        (None, None) => Ok(None),
        (Some(none), None) if none.trim() == "*" => Ok(Some(Precondition::Absent)),
        (None, Some(tag)) => {
            let tag = tag.trim();
            if tag == "*" {
                return Ok(Some(Precondition::Exists));
            }
            let bare = tag
                .strip_prefix('"')
                .and_then(|t| t.strip_suffix('"'))
                .unwrap_or(tag);
            // What is left is one opaque tag: no quote (an unbalanced
            // one, or the `W/"…"` of a weak tag), no list.
            let opaque = !bare.is_empty()
                && bare
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && b != b'"' && b != b',');
            if !opaque {
                return Err(refused());
            }
            Ok(Some(Precondition::Etag(format!("\"{bare}\""))))
        }
        _ => Err(refused()),
    }
}

/// The answer to a write whose condition does not hold.
pub(super) fn precondition_error(e: PreconditionError) -> S3Response {
    s3_error(match e {
        PreconditionError::Failed => ErrorCode::PreconditionFailed,
        PreconditionError::NoSuchKey => ErrorCode::NoSuchKey,
    })
}

/// Judges `condition` against the live object of the key as the
/// catalogue has it now. A write is refused on this answer; it is never
/// accepted on it, only by the guard of its batch.
pub(super) async fn check_precondition<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &BucketId,
    key: &str,
    condition: &Precondition,
) -> Result<(), S3Response> {
    // The ETag is on the generation row; no extent row is read for it.
    let live = bridge
        .catalog
        .live_generation(bucket, key)
        .await
        .map_err(|_| internal())?;
    condition
        .check(live.as_ref().map(|g| g.etag.as_str()))
        .map_err(precondition_error)
}

/// The step of a conditional write between choosing the id `id` and
/// storing the recovery record under it: raises the floor of the key to
/// `id`, then judges the condition. Nothing for an unconditional write.
///
/// From the raise on, whatever is published or deleted on the key takes
/// an id above `id`. So:
/// - a condition that fails here is answered before any record exists:
///   a refused conditional write leaves nothing for a replay to publish;
/// - a record is stored only for a condition that held at this point. If
///   its batch is refused all the same, the key changed after the raise:
///   the record of that change sorts above this one, and a replay puts it
///   on top, should this record outlive its removal.
///
/// The batch judges the condition again, in its own guard
/// (`Catalog::commit_generation`): that one decides what is published.
pub(super) async fn hold_precondition<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &BucketId,
    key: &str,
    id: &GenerationId,
    condition: Option<&Precondition>,
) -> Result<(), S3Response> {
    let Some(condition) = condition else {
        return Ok(());
    };
    // Not marked as a generation record: none is stored yet, and
    // `write_generation` raises the floor again when one is.
    bridge
        .catalog
        .raise_floor(bucket, key, id, false)
        .await
        .map_err(|_| internal())?;
    check_precondition(bridge, bucket, key, condition).await
}

/// [`mutation_gate`] for the requests that can be conditional
/// (PutObject, CopyObject, DeleteObject): the same gates, and the
/// condition the request names instead of a refusal of it.
pub(super) fn conditional_gate(
    cfg: &BridgeConfig,
    headers: &Headers,
    bucket: &Bucket,
) -> Result<Option<Precondition>, S3Response> {
    let condition = precondition(headers)?;
    open_gate(cfg, bucket)?;
    Ok(condition)
}

/// The gates every mutation passes after authentication and before its
/// body is read or anything is stored:
/// - a conditional header is `501 NotImplemented`, never ignored (the
///   requests that honour one pass [`conditional_gate`] instead);
/// - a catalogue restore in progress is `503`;
/// - PutObject, CopyObject (the same request shape) and DeleteObject on a
///   non-disposable bucket are refused while `REAL_DATA_READY` is false
///   (it is true now that a lost catalogue can be rebuilt). The multipart
///   routes do not pass this gate, so the constant alone does not make an
///   existing real bucket read-only.
pub(super) fn mutation_gate(
    cfg: &BridgeConfig,
    headers: &Headers,
    bucket: &Bucket,
) -> Result<(), S3Response> {
    if CONDITIONAL_HEADERS.iter().any(|h| headers.get(h).is_some()) {
        return Err(S3Response::not_implemented());
    }
    open_gate(cfg, bucket)
}

fn open_gate(cfg: &BridgeConfig, bucket: &Bucket) -> Result<(), S3Response> {
    if cfg.maintenance == Maintenance::Restore {
        return Err(writes_refused());
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
    discard_unless_present(bridge, generation, refused)
        .await
        .map(|_| ())
}

/// [`discard_refused`], and whether the record is gone: `false` when a
/// row exists under the id and the record was kept for it.
pub(super) async fn discard_unless_present<
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
) -> crate::types::Result<bool> {
    let mut last = Ok(false);
    for _ in 0..DISCARD_ATTEMPTS {
        last = match bridge.catalog.replay_probe(generation).await {
            Ok(ReplayProbe::Present) => return Ok(false),
            Ok(_) => discard_generation(&bridge.safety, &refused)
                .await
                .map(|()| true),
            Err(e) => Err(e),
        };
        if last.is_ok() {
            break;
        }
    }
    last
}

/// [`discard_refused`] for a write that goes on to another attempt or
/// to an answer. A record that cannot be removed ends the request with
/// `500`. For a conditional write so does a record that was kept
/// because a row exists under its id: the write may then be published
/// (a replay read its record), and the request must neither say that it
/// was refused nor publish it a second time.
pub(super) async fn discard_before_retry<
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
    conditional: bool,
) -> Result<(), S3Response> {
    match discard_unless_present(bridge, generation, refused).await {
        Ok(true) => Ok(()),
        Ok(false) if !conditional => Ok(()),
        _ => Err(internal()),
    }
}

const DISCARD_ATTEMPTS: usize = 3;

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
        Ok(true) => Err(writes_refused()),
        Err(_) => Err(internal()),
    }
}
