//! Multipart uploads: Create, UploadPart, Complete, Abort.
//!
//! Every call authenticates from headers only, then addresses the upload
//! through an [`UploadTarget`] built from the *authorized* request target:
//! the bucket the signature was checked for, the decoded key and the
//! upload id. The catalogue filters on all three, so an id presented under
//! another bucket or key is an unknown upload (`NoSuchUpload`). The id is
//! never an authorization boundary.
//!
//! - **Create** stores the upload row (state `open`, revision 0) with the
//!   object metadata of the request.
//! - **UploadPart** seals the body like a single PUT into a fresh extent,
//!   stores the ciphertext in the safety store and records it as a staged
//!   part. Nothing is posted before Complete.
//! - **Complete** validates the listed parts against the upload as read at
//!   revision `R` and publishes them in one guarded batch pinned to `R`.
//!   The stored receipt makes a retry return the same ETag without
//!   publishing again.
//! - **Abort** closes the upload; its part extents go to garbage
//!   collection.
//!
//! Conditional headers are refused with `501 NotImplemented`, never
//! ignored. Checksums: Create accepts `x-amz-checksum-algorithm` (type
//! absent or `FULL_OBJECT`) because default SDK transfers send it; every
//! part is verified against the checksum it carries (header or aws-chunked
//! trailer). No checksum of the whole multipart object is computed or
//! reported, so GET/HEAD return none, UploadPart does not echo one (clients
//! then list no part checksums in Complete), and Complete refuses a
//! client-supplied object checksum or a `COMPOSITE` type with `501`.

use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use sha2::{Digest, Sha256};
use velmora::rng::{FillRandom, SystemRng};
use velmora_s3_proto::mutation::{
    parse_complete, CommitResult, MultipartChecksum, PartEvidence, UploadMetadata,
};
use velmora_s3_proto::{
    verify, Authority, ChecksumAlgorithm, Credential, ErrorCode, Headers, Limits, Policy, Target,
    UploadValidator, VerifiedRequest,
};
use zeroize::Zeroizing;

use crate::config::{BridgeConfig, Maintenance};
use crate::crypto::{seal_extent, unwrap_bdk, unwrap_secret};
use crate::ingress::{read_upload, upload_lengths, IngressError, UploadReadError};
use crate::ports::{
    BlobMeta, BlobStore, Bridge, Catalog, Clock, Guard, JobSink, Kek, NntpConnector, UploadTarget,
};
use crate::recovery::{generation_key, write_generation};
use crate::types::{
    BridgeError, Bucket, CompleteUpload, ExtentId, ExtentPlacement, ExtentRow, ExtentState,
    GenerationId, GenerationRow, GenerationState, Job, KeyStatus, OutboxStage, Perm, RespBody,
    S3Request, S3Response, SafetyState, UploadId, UploadPartRow, UploadRow, UploadState,
    JOB_VERSION,
};

/// Smallest non-final part.
pub const MIN_PART_BYTES: u64 = 5 * 1024 * 1024;
/// Highest part number, and the most parts one Complete may list.
pub const MAX_PARTS: u16 = 10_000;
/// Largest accepted CompleteMultipartUpload body.
pub const MAX_COMPLETE_BODY_BYTES: u64 = 2 * 1024 * 1024;
/// How often Complete reads, validates and tries to publish before it
/// answers `503 SlowDown`.
const COMPLETE_ATTEMPTS: u32 = 3;
/// `KeyMode::Random`.
const KEY_MODE_RANDOM: u8 = 1;

/// Headers the edge adds. They are never signed and their values are not
/// always printable ASCII, so they are dropped before header validation.
/// Dropping a header can only fail a signature, never satisfy one.
fn edge_header(name: &str) -> bool {
    name.starts_with("cf-")
        || name.starts_with("x-forwarded-")
        || matches!(name, "cdn-loop" | "x-real-ip" | "true-client-ip")
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a call failed. Carries a class only, never request data.
enum Fail {
    S3(ErrorCode),
    Ingress(IngressError),
    /// Catalogue, blob, crypto or RNG failure: `500 InternalError`.
    Internal,
}

impl From<ErrorCode> for Fail {
    fn from(e: ErrorCode) -> Self {
        Fail::S3(e)
    }
}

impl From<IngressError> for Fail {
    fn from(e: IngressError) -> Self {
        Fail::Ingress(e)
    }
}

impl From<UploadReadError> for Fail {
    fn from(e: UploadReadError) -> Self {
        match e {
            UploadReadError::Ingress(e) => Fail::Ingress(e),
            UploadReadError::Proto(e) => Fail::S3(e),
        }
    }
}

impl From<BridgeError> for Fail {
    fn from(_: BridgeError) -> Self {
        Fail::Internal
    }
}

type Outcome<T> = Result<T, Fail>;

fn message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::AccessDenied => "Access Denied",
        ErrorCode::SignatureDoesNotMatch => {
            "The request signature we calculated does not match the signature you provided."
        }
        ErrorCode::RequestTimeTooSkewed => {
            "The difference between the request time and the current time is too large."
        }
        ErrorCode::InvalidArgument => "Invalid Argument",
        ErrorCode::InvalidDigest => "The Content-MD5 or checksum value you specified is not valid.",
        ErrorCode::BadDigest => {
            "The Content-MD5 or checksum value you specified did not match what we received."
        }
        ErrorCode::IncompleteBody => {
            "You did not provide the number of bytes specified by the Content-Length HTTP header."
        }
        ErrorCode::EntityTooLarge => "Your proposed upload exceeds the maximum allowed size.",
        ErrorCode::MalformedXML => "The XML you provided was not well-formed.",
        ErrorCode::NoSuchUpload => {
            "The specified upload does not exist. The upload ID may be invalid, or the upload \
             may have been aborted or completed."
        }
        ErrorCode::InvalidPart => {
            "One or more of the specified parts could not be found, or its entity tag does not \
             match the part that was uploaded."
        }
        ErrorCode::InvalidPartOrder => {
            "The list of parts was not in ascending order. The parts list must be specified in \
             order by part number."
        }
        ErrorCode::EntityTooSmall => {
            "Your proposed upload is smaller than the minimum allowed object size."
        }
        ErrorCode::NotImplemented => {
            "A header or operation you provided implies functionality that is not implemented."
        }
        ErrorCode::SlowDown => "Please reduce your request rate.",
        ErrorCode::InternalError => "We encountered an internal error. Please try again.",
        _ => "The request is not valid.",
    }
}

fn s3_error(code: ErrorCode) -> S3Response {
    let mut resp = S3Response::error(code.status(), &format!("{code:?}"), message(code));
    if code == ErrorCode::SlowDown {
        resp.headers.push(("retry-after".into(), "1".into()));
    }
    resp
}

impl Fail {
    fn response(self) -> S3Response {
        match self {
            Fail::S3(code) => s3_error(code),
            Fail::Ingress(e) => e.response(),
            Fail::Internal => s3_error(ErrorCode::InternalError),
        }
    }
}

fn respond(outcome: Outcome<S3Response>) -> S3Response {
    outcome.unwrap_or_else(Fail::response)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

/// The raw MD5 behind a part ETag this service issued (`"<32 hex>"`).
fn part_md5(etag: &str) -> Option<[u8; 16]> {
    let digits = bare_etag(etag).as_bytes();
    if digits.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (digits[2 * i] as char).to_digit(16)?;
        let lo = (digits[2 * i + 1] as char).to_digit(16)?;
        *slot = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

/// An ETag without its surrounding quotes; clients send either form.
fn bare_etag(etag: &str) -> &str {
    etag.strip_prefix('"')
        .and_then(|e| e.strip_suffix('"'))
        .unwrap_or(etag)
}

fn xml_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

fn random<const N: usize>() -> Outcome<[u8; N]> {
    let mut out = [0u8; N];
    SystemRng.fill_bytes(&mut out).map_err(|_| Fail::Internal)?;
    Ok(out)
}

fn from_proto(resp: velmora_s3_proto::Response) -> S3Response {
    S3Response {
        status: resp.status,
        headers: resp.headers,
        body: if resp.body.is_empty() {
            RespBody::Empty
        } else {
            RespBody::Bytes(resp.body)
        },
    }
}

fn policy(cfg: &BridgeConfig) -> Outcome<Policy> {
    Policy::new(
        cfg.s3_host.clone(),
        cfg.region.clone(),
        Limits {
            target_bytes: 8 * 1024,
            control_xml_bytes: MAX_COMPLETE_BODY_BYTES as usize,
            header_bytes: 32 * 1024,
            header_count: 128,
            query_pairs: 32,
            upload_bytes: cfg.max_extent_bytes,
            clock_skew_seconds: 900,
            presign_seconds: 604_800,
        },
    )
    .map_err(|_| Fail::Internal)
}

/// The single value of a query parameter. `None` when absent; repeated or
/// non-UTF-8 is `InvalidRequest`.
fn query_one<'a>(target: &'a Target, name: &str) -> Outcome<Option<&'a str>> {
    let mut values = target
        .query()
        .iter()
        .filter(|(k, _)| k.as_slice() == name.as_bytes());
    let Some((_, first)) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ErrorCode::InvalidRequest.into());
    }
    std::str::from_utf8(first)
        .map(Some)
        .map_err(|_| ErrorCode::InvalidRequest.into())
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// The one access key a request named, if it is active, and whether it may
/// write to the addressed bucket.
#[derive(Default)]
struct OneKey {
    key: Option<KeyMaterial>,
    /// Name of the bucket this key holds an `rw` grant on (the addressed
    /// one, or none).
    writable_bucket: Option<String>,
}

struct KeyMaterial {
    access_key_id: String,
    principal: String,
    secret: Zeroizing<Vec<u8>>,
}

impl Authority for OneKey {
    fn credential(&self, access_key: &str) -> Option<Credential<'_>> {
        let key = self.key.as_ref()?;
        (key.access_key_id == access_key).then(|| Credential {
            secret: &key.secret,
            principal: &key.principal,
        })
    }

    /// Every multipart call mutates, so it needs `rw` on the bucket.
    fn authorize(&self, principal: &str, _method: &str, target: &Target) -> bool {
        self.key.as_ref().is_some_and(|k| k.principal == principal)
            && self.writable_bucket.as_deref() == Some(target.bucket.as_str())
    }
}

/// The access key id a request presents, before any verification:
/// `Credential=<id>/…` of the `Authorization` header or the presigned
/// `X-Amz-Credential`. `verify` parses the same fields strictly.
fn presented_access_key(target: &Target, headers: &Headers) -> Option<String> {
    let credential = match headers.get("authorization") {
        Some(value) => value
            .strip_prefix("AWS4-HMAC-SHA256 ")?
            .split(',')
            .find_map(|field| field.trim().strip_prefix("Credential="))?,
        None => query_one(target, "X-Amz-Credential").ok().flatten()?,
    };
    let id = credential.split('/').next()?;
    (!id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| id.to_string())
}

/// A request whose signature verified for an `rw` key of `bucket`.
struct Authed {
    policy: Policy,
    target: Target,
    headers: Headers,
    verified: VerifiedRequest,
    bucket: Bucket,
    /// Decoded object key.
    key: String,
}

async fn authenticate<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: &S3Request,
) -> Outcome<Authed>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    if bridge.cfg.maintenance == Maintenance::Restore {
        return Err(ErrorCode::SlowDown.into());
    }
    let policy = policy(&bridge.cfg)?;
    let target = Target::parse(&req.raw_target, &policy)?;
    let fields: Vec<(&str, &str)> = req
        .headers
        .iter()
        .filter(|(n, _)| !edge_header(n))
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let headers = Headers::new(&fields, &policy)?;

    let mut authority = OneKey::default();
    let mut bucket = None;
    if let Some(akid) = presented_access_key(&target, &headers) {
        // Unknown and disabled keys look the same: no credential.
        let row = bridge.catalog.access_key(&akid).await?;
        if let Some(row) = row.filter(|r| r.status == KeyStatus::Active) {
            let secret = unwrap_secret(
                &bridge.kek,
                row.kek_version,
                &row.access_key_id,
                &row.secret_wrapped,
            )?;
            bucket = bridge.catalog.bucket_by_name(&target.bucket).await?;
            let perm = match &bucket {
                Some(b) => bridge.catalog.grant(&akid, &b.id).await?,
                None => None,
            };
            authority.writable_bucket = (perm == Some(Perm::Rw)).then(|| target.bucket.clone());
            authority.key = Some(KeyMaterial {
                access_key_id: row.access_key_id,
                principal: row.principal,
                secret,
            });
        }
    }
    // Ingress refuses untrusted transport before any handler runs.
    let verified = verify(
        req.method.as_str(),
        &target,
        &headers,
        true,
        bridge.clock.now().secs().0,
        &policy,
        &authority,
    )?;
    // `authorize` passed, so the bucket exists and the grant is `rw`.
    let bucket = bucket.ok_or(ErrorCode::AccessDenied)?;
    let key = target
        .key
        .clone()
        .filter(|k| !k.is_empty())
        .ok_or(ErrorCode::InvalidRequest)?;
    Ok(Authed {
        policy,
        target,
        headers,
        verified,
        bucket,
        key,
    })
}

/// Conditional mutations are refused, never ignored: publishing does not
/// evaluate them atomically yet.
fn refuse_conditional(headers: &Headers) -> Outcome<()> {
    const CONDITIONAL: [&str; 4] = [
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
    ];
    if CONDITIONAL.iter().any(|h| headers.get(h).is_some()) {
        return Err(ErrorCode::NotImplemented.into());
    }
    Ok(())
}

/// The `uploadId` of the request. Anything that is not an id this service
/// could have issued is an unknown upload.
fn upload_id(target: &Target) -> Outcome<UploadId> {
    let raw = query_one(target, "uploadId")?.ok_or(ErrorCode::InvalidRequest)?;
    if raw.len() != 32
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ErrorCode::NoSuchUpload.into());
    }
    Ok(UploadId::new(raw))
}

fn part_number(target: &Target) -> Outcome<u16> {
    let raw = query_one(target, "partNumber")?.ok_or(ErrorCode::InvalidRequest)?;
    if raw.is_empty() || raw.len() > 5 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ErrorCode::InvalidArgument.into());
    }
    match raw.parse::<u16>() {
        Ok(n) if (1..=MAX_PARTS).contains(&n) => Ok(n),
        _ => Err(ErrorCode::InvalidArgument.into()),
    }
}

/// Charges the budget, reads exactly the declared body and checks it
/// against the signed payload hash, `Content-MD5` and any checksum header.
async fn read_verified_body<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    a: &Authed,
    req: S3Request,
    max: u64,
) -> Outcome<Vec<u8>>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let lengths = upload_lengths(&req.headers, max)?;
    let mut validator = UploadValidator::new(&a.headers, &a.verified, &a.policy)?;
    let charge = bridge.budget.charge_body(lengths.decoded).await?;
    let body = read_upload(req.body, lengths, &charge, &mut validator).await?;
    validator.finish()?;
    // Only the small, validated control document outlives the charge.
    drop(charge);
    Ok(body)
}

// ---------------------------------------------------------------------------
// CreateMultipartUpload
// ---------------------------------------------------------------------------

pub(super) async fn create<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
    _bucket: &str,
    _key: &str,
) -> S3Response {
    respond(create_inner(bridge, req).await)
}

async fn create_inner<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> Outcome<S3Response>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let a = authenticate(bridge, &req).await?;
    refuse_conditional(&a.headers)?;
    // Parts are verified against their own checksums; a whole-object
    // checksum is never computed, so only the FULL_OBJECT shape (whose
    // absence a client tolerates) is accepted, never COMPOSITE.
    if a.headers
        .get("x-amz-checksum-type")
        .is_some_and(|t| t != "FULL_OBJECT")
    {
        return Err(ErrorCode::NotImplemented.into());
    }
    let metadata = UploadMetadata::from_headers(&a.headers)?;
    let (user, content): (BTreeMap<String, String>, BTreeMap<String, String>) = metadata
        .headers
        .into_iter()
        .partition(|(name, _)| name.starts_with("x-amz-meta-"));
    let json = |m: &BTreeMap<String, String>| serde_json::to_string(m).map_err(|_| Fail::Internal);

    let id = UploadId::mint(random()?);
    bridge
        .catalog
        .create_upload(&UploadRow {
            id: id.clone(),
            bucket_id: a.bucket.id.clone(),
            key: a.key.clone(),
            content_json: json(&content)?,
            user_meta_json: json(&user)?,
            state: UploadState::Open,
            revision: 0,
            completed_generation_id: None,
            complete_digest: None,
            result_etag: None,
            initiated_at: bridge.clock.now(),
        })
        .await?;

    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<InitiateMultipartUploadResult \
         xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><Key>{}</Key>\
         <UploadId>{}</UploadId></InitiateMultipartUploadResult>",
        xml_text(&a.target.bucket),
        xml_text(&a.key),
        id.as_str()
    );
    Ok(S3Response {
        status: 200,
        headers: vec![("content-type".into(), "application/xml".into())],
        body: RespBody::Bytes(body.into_bytes()),
    })
}

// ---------------------------------------------------------------------------
// UploadPart
// ---------------------------------------------------------------------------

pub(super) async fn upload_part<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
    _bucket: &str,
    _key: &str,
) -> S3Response {
    respond(upload_part_inner(bridge, req).await)
}

async fn upload_part_inner<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> Outcome<S3Response>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let a = authenticate(bridge, &req).await?;
    refuse_conditional(&a.headers)?;
    // UploadPartCopy is a different operation.
    if a.headers.get("x-amz-copy-source").is_some()
        || a.headers.get("x-amz-copy-source-range").is_some()
    {
        return Err(ErrorCode::NotImplemented.into());
    }
    let number = part_number(&a.target)?;
    let id = upload_id(&a.target)?;
    let target = UploadTarget {
        bucket: &a.bucket.id,
        key: &a.key,
        id: &id,
    };
    // Refuse an unknown or closed upload before the body is read or
    // anything is stored. The guarded batch below decides for real.
    match bridge.catalog.upload(&target).await? {
        Some((upload, _)) if upload.state == UploadState::Open => {}
        _ => return Err(ErrorCode::NoSuchUpload.into()),
    }

    // Plaintext and ciphertext live together while sealing: the charge
    // covers both and is held until the ciphertext has been handed over.
    // For aws-chunked bodies every length below is the decoded one.
    let lengths = upload_lengths(&req.headers, bridge.cfg.max_extent_bytes)?;
    let declared = lengths.decoded;
    let mut validator = UploadValidator::new(&a.headers, &a.verified, &a.policy)?;
    let charge = bridge.budget.charge_body(declared).await?;
    let body = read_upload(req.body, lengths, &charge, &mut validator).await?;
    validator.finish()?;

    let bdk = unwrap_bdk(
        &bridge.kek,
        a.bucket.kek_version,
        &a.bucket.id,
        &a.bucket.bdk_wrapped,
    )?;
    // A fresh id per seal: the key wrap binds the id, never a version.
    let extent_id = ExtentId::mint(random()?);
    let sealed = seal_extent(&bdk, &a.bucket.id, &extent_id, &body, &mut SystemRng)?;
    drop(body);
    let now = bridge.clock.now();
    let etag = format!("\"{}\"", hex(&sealed.plain_md5));
    let extent = ExtentRow {
        id: extent_id.clone(),
        bucket_id: a.bucket.id.clone(),
        generation_id: None,
        state: ExtentState::Staged,
        seq: None,
        plain_offset: None,
        plain_size: declared,
        cipher_size: sealed.ciphertext.len() as u64,
        media_header: sealed.media_header.to_vec(),
        key_mode: KEY_MODE_RANDOM,
        wrapped_file_key: Some(sealed.wrapped_file_key.to_vec()),
        plain_md5: sealed.plain_md5,
        plain_sha256: sealed.plain_sha256,
        cipher_sha256: sealed.cipher_sha256,
        safety_state: SafetyState::Held,
        article_count: None,
        plan_rev: 0,
        last_verified_at: None,
        release_evidence: None,
        released_at: None,
        created_at: now,
    };
    let safety_key = extent_id.safety_key();
    bridge
        .safety
        .put(
            &safety_key,
            sealed.ciphertext,
            &BlobMeta {
                bucket: &a.bucket.id,
                extent: &extent_id,
                cipher_sha256: &extent.cipher_sha256,
            },
        )
        .await?;
    drop(charge);

    let part = UploadPartRow {
        upload_id: id.clone(),
        part_number: number,
        extent_id,
        size: declared,
        etag: etag.clone(),
        uploaded_at: now,
    };
    match bridge
        .catalog
        .put_upload_part(&target, &part, &extent, now)
        .await?
    {
        Guard::Applied(()) => Ok(S3Response {
            status: 200,
            headers: vec![("etag".into(), etag)],
            body: RespBody::Empty,
        }),
        Guard::Lost => {
            // The upload was completed or aborted meanwhile. The batch
            // wrote nothing, so the blob just stored is an orphan no
            // catalogue row names. It is left for garbage collection,
            // which is the only path that deletes from the safety store.
            Err(ErrorCode::NoSuchUpload.into())
        }
    }
}

// ---------------------------------------------------------------------------
// CompleteMultipartUpload
// ---------------------------------------------------------------------------

/// SHA-256 of the canonical `(part_number, etag)` list of a Complete
/// request: one `<number>:<etag without quotes>\n` line per part.
fn receipt_digest(listed: &[PartEvidence]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in listed {
        h.update(p.number.to_string().as_bytes());
        h.update(b":");
        h.update(bare_etag(&p.etag).as_bytes());
        h.update(b"\n");
    }
    h.finalize().into()
}

/// The object a validated part list describes.
struct Publication {
    placements: Vec<ExtentPlacement>,
    size: u64,
    /// `"<md5 of the concatenated part MD5s>-<parts>"`.
    etag: String,
}

/// Checks the listed parts (already ascending) against the stored ones:
/// each must exist with the same ETag, and every part but the last must be
/// at least [`MIN_PART_BYTES`].
fn plan(listed: &[PartEvidence], stored: &[UploadPartRow]) -> Outcome<Publication> {
    let mut placements = Vec::with_capacity(listed.len());
    let mut md5s = Vec::with_capacity(listed.len() * 16);
    let mut size = 0u64;
    let mut too_small = false;
    for (i, want) in listed.iter().enumerate() {
        let have = stored
            .binary_search_by_key(&want.number, |p| p.part_number)
            .map(|at| &stored[at])
            .map_err(|_| ErrorCode::InvalidPart)?;
        if bare_etag(&want.etag) != bare_etag(&have.etag) {
            return Err(ErrorCode::InvalidPart.into());
        }
        // A missing or mismatched part anywhere in the list is reported
        // before a size problem.
        too_small |= i + 1 < listed.len() && have.size < MIN_PART_BYTES;
        md5s.extend_from_slice(&part_md5(&have.etag).ok_or(Fail::Internal)?);
        placements.push(ExtentPlacement {
            extent_id: have.extent_id.clone(),
            seq: u32::try_from(i).map_err(|_| Fail::Internal)?,
            plain_offset: size,
        });
        size = size.checked_add(have.size).ok_or(Fail::Internal)?;
    }
    if too_small {
        return Err(ErrorCode::EntityTooSmall.into());
    }
    let etag = format!("\"{}-{}\"", hex(&md5::compute(&md5s).0), listed.len());
    Ok(Publication {
        placements,
        size,
        etag,
    })
}

pub(super) async fn complete<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
    _bucket: &str,
    _key: &str,
) -> S3Response {
    respond(complete_inner(bridge, req).await)
}

fn complete_response(a: &Authed, etag: String, modified_ms: i64) -> Outcome<S3Response> {
    let result = CommitResult {
        bucket: a.target.bucket.clone(),
        key: a.key.clone(),
        etag,
        checksum: None,
        modified_ms,
    };
    Ok(from_proto(result.complete_response(&a.target, &a.policy)?))
}

async fn complete_inner<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> Outcome<S3Response>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let a = authenticate(bridge, &req).await?;
    // Before the body is read or anything is published.
    refuse_conditional(&a.headers)?;
    // A whole-object checksum cannot be checked: none is computed.
    if ChecksumAlgorithm::ALL
        .iter()
        .any(|c| a.headers.get(c.header()).is_some())
        || a.headers.get("x-amz-checksum-type").is_some()
    {
        return Err(ErrorCode::NotImplemented.into());
    }
    let id = upload_id(&a.target)?;
    let target = UploadTarget {
        bucket: &a.bucket.id,
        key: &a.key,
        id: &id,
    };
    let max = MAX_COMPLETE_BODY_BYTES.min(bridge.cfg.max_extent_bytes);
    let body = read_verified_body(bridge, &a, req, max).await?;
    let listed = parse_complete(&body, &a.policy, MAX_PARTS, MultipartChecksum::None).map_err(
        |e| match e {
            // A document that lists no part at all is not a part list,
            // whether its root is empty or self-closing.
            ErrorCode::InvalidPart | ErrorCode::InvalidRequest
                if !body.windows(5).any(|w| w == b"<Part") =>
            {
                ErrorCode::MalformedXML
            }
            e => e,
        },
    )?;
    drop(body);
    let digest = receipt_digest(&listed);

    // Revision of the previous attempt, if its batch lost the guard.
    let mut lost_at: Option<u64> = None;
    for _ in 0..COMPLETE_ATTEMPTS {
        let Some((upload, parts)) = bridge.catalog.upload(&target).await? else {
            return Err(ErrorCode::NoSuchUpload.into());
        };
        match upload.state {
            UploadState::Open => {}
            UploadState::Aborted => return Err(ErrorCode::NoSuchUpload.into()),
            UploadState::Completed => {
                // A retry of the Complete that won: answer from the
                // receipt and publish nothing, so a later overwrite of the
                // key is never rolled back.
                if upload.complete_digest != Some(digest) {
                    return Err(ErrorCode::NoSuchUpload.into());
                }
                let etag = upload.result_etag.ok_or(Fail::Internal)?;
                return complete_response(&a, etag, bridge.clock.now().0);
            }
        }
        if lost_at == Some(upload.revision) {
            // Nothing changed the upload, so the batch was not refused by
            // a race: the catalogue would not adopt the listed parts.
            return Err(ErrorCode::InvalidPart.into());
        }
        let publication = plan(&listed, &parts)?;
        let now = bridge.clock.now();
        let generation = GenerationRow {
            id: GenerationId::mint(now, random()?),
            bucket_id: a.bucket.id.clone(),
            key: a.key.clone(),
            state: GenerationState::Live,
            size: publication.size,
            etag: publication.etag.clone(),
            checksum_json: None,
            content_json: upload.content_json,
            user_meta_json: upload.user_meta_json,
            extent_count: u32::try_from(publication.placements.len())
                .map_err(|_| Fail::Internal)?,
            created_at: now,
            retired_at: None,
        };
        let commit = CompleteUpload {
            generation,
            placements: publication.placements,
            now,
        };
        // The recovery record is durable before the publication batch.
        // It describes the staged extents as this generation will hold
        // them; the batch applies only if the upload is unchanged.
        let mut staged: HashMap<ExtentId, ExtentRow> = bridge
            .catalog
            .upload_extents(&target)
            .await?
            .into_iter()
            .map(|e| (e.id.clone(), e))
            .collect();
        let mut extents = Vec::with_capacity(commit.placements.len());
        for p in &commit.placements {
            let Some(mut row) = staged.remove(&p.extent_id) else {
                break;
            };
            row.seq = Some(p.seq);
            row.plain_offset = Some(p.plain_offset);
            extents.push(row);
        }
        drop(staged);
        if extents.len() != commit.placements.len() {
            // An UploadPart replaced a listed part after the upload was
            // read. The batch would lose its guard: take the same path.
            lost_at = Some(upload.revision);
            continue;
        }
        write_generation(
            &bridge.safety,
            &bridge.kek,
            &a.bucket,
            &commit.generation,
            &extents,
        )
        .await?;
        drop(extents);
        match bridge
            .catalog
            .complete_upload(&target, upload.revision, &digest, &commit)
            .await?
        {
            Guard::Applied(()) => {
                // The outbox rows are the durable obligation; a lost
                // notification is picked up by the dispatcher.
                for p in &commit.placements {
                    let job = Job::Extent {
                        v: JOB_VERSION,
                        extent: p.extent_id.clone(),
                        generation: commit.generation.id.clone(),
                        stage: OutboxStage::Post,
                    };
                    let _ = bridge.jobs.send(&job, 0).await;
                }
                return complete_response(&a, publication.etag, now.0);
            }
            Guard::Lost => {
                // Nothing was published under this id, so its record
                // must not publish it in a replay either. Best effort: a
                // record left behind replays as a PUT that failed.
                let _ = bridge
                    .safety
                    .delete(&generation_key(&commit.generation.id))
                    .await;
                lost_at = Some(upload.revision);
            }
        }
    }
    Err(ErrorCode::SlowDown.into())
}

// ---------------------------------------------------------------------------
// AbortMultipartUpload
// ---------------------------------------------------------------------------

pub(super) async fn abort<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
    _bucket: &str,
    _key: &str,
) -> S3Response {
    respond(abort_inner(bridge, req).await)
}

async fn abort_inner<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> Outcome<S3Response>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let a = authenticate(bridge, &req).await?;
    refuse_conditional(&a.headers)?;
    let id = upload_id(&a.target)?;
    let target = UploadTarget {
        bucket: &a.bucket.id,
        key: &a.key,
        id: &id,
    };
    let no_content = || S3Response {
        status: 204,
        headers: Vec::new(),
        body: RespBody::Empty,
    };
    // A lost guard means the upload is not open (any more): answer from
    // its state. `Open` after a loss cannot last, so one more try decides.
    for _ in 0..2 {
        if let Guard::Applied(()) = bridge
            .catalog
            .abort_upload(&target, bridge.clock.now())
            .await?
        {
            return Ok(no_content());
        }
        match bridge.catalog.upload(&target).await? {
            Some((upload, _)) => match upload.state {
                UploadState::Aborted => return Ok(no_content()),
                UploadState::Completed => return Err(ErrorCode::NoSuchUpload.into()),
                UploadState::Open => {}
            },
            None => return Err(ErrorCode::NoSuchUpload.into()),
        }
    }
    Err(ErrorCode::SlowDown.into())
}
