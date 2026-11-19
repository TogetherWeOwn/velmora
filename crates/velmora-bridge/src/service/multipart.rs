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
//!   part. A body above one extent is stored as slices, like a PutObject
//!   of that length, and the part is the list of their extents. Nothing
//!   is posted before Complete.
//! - **Complete** validates the listed parts against the upload as read at
//!   revision `R` and publishes their extents, in part order and body
//!   order, in one guarded batch pinned to `R`. An upload that holds
//!   more extents than one object may have is refused and stays open.
//!   An upload of more extents than one recovery record holds in one
//!   document is read a run of part numbers at a time and recorded in
//!   segments ([`SegmentWriter`]); its answer is a `200` whose document
//!   may follow its headers, as S3 answers a Complete.
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
use std::future::Future;
use std::rc::Rc;

use futures_util::future::LocalBoxFuture;
use sha2::{Digest, Sha256};
use velmora::rng::{FillRandom, SystemRng};
use velmora_s3_proto::mutation::{
    copy_part_response, parse_complete, CommitResult, MultipartChecksum, PartEvidence,
    UploadMetadata,
};
use velmora_s3_proto::{
    verify, Authority, ChecksumAlgorithm, Credential, ErrorCode, Headers, Limits, Policy, Target,
    UploadValidator, VerifiedRequest,
};
use zeroize::Zeroizing;

use crate::config::{BridgeConfig, Maintenance};
use crate::crypto::{seal_extent, unwrap_bdk, unwrap_secret};
use crate::ingress::{
    body_is_empty, declared_length, read_upload, upload_lengths, Charge, IngressError,
    UploadLengths, UploadReadError,
};
use crate::intents::WRITER_MAX_AGE_MS;
use crate::keepalive::{Deferred, XML_DECLARATION};
use crate::ports::{
    BlobMeta, BlobStore, Bridge, Catalog, Clock, Guard, JobSink, Kek, NntpConnector,
    PublishOutcome, UploadTarget,
};
use crate::recovery::{id_after, set_id, write_generation, Recorded, SegmentWriter, MAX_SEGMENTS};
use crate::service::common::{
    check_precondition, discard_refused, discard_unless_present, hold_precondition, precondition,
    restore_gate, writes_refused,
};
use crate::service::slices::{store_slices, SliceError, SliceSink};
use crate::types::{
    Body, BridgeError, Bucket, CompleteUpload, ExtentId, ExtentPlacement, ExtentRow, ExtentState,
    GenerationRow, GenerationState, Job, KeyStatus, OutboxStage, PartExtent, Perm, Precondition,
    RespBody, S3Request, S3Response, SafetyState, UploadId, UploadPartRow, UploadRow, UploadState,
    WriteId, JOB_VERSION,
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
/// Queue messages of one `send_many`.
const JOB_BATCH: usize = 100;

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
    /// An answer a shared helper already rendered.
    Response(S3Response),
}

impl From<ErrorCode> for Fail {
    fn from(e: ErrorCode) -> Self {
        Fail::S3(e)
    }
}

impl From<S3Response> for Fail {
    fn from(resp: S3Response) -> Self {
        Fail::Response(resp)
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
        ErrorCode::PreconditionFailed => {
            "At least one of the pre-conditions you specified did not hold."
        }
        ErrorCode::NoSuchKey => "The specified key does not exist.",
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
            Fail::Response(resp) => resp,
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
            upload_bytes: cfg.max_put_bytes,
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
    // A replay that was started and did not end: see `restore_gate`.
    if bridge.catalog.restore_pending().await? {
        return Err(ErrorCode::SlowDown.into());
    }
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
    // UploadPartCopy is this request with a source header and no body.
    let copy = a.headers.get("x-amz-copy-source").is_some();
    if !copy && a.headers.get("x-amz-copy-source-range").is_some() {
        return Err(ErrorCode::InvalidRequest.into());
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
    let (body, charge) = if copy {
        copied_part(bridge, &a, &req.headers, req.body).await?
    } else {
        // A part may be as long as a PutObject. Above one extent it is
        // stored as slices, never read whole.
        let lengths = upload_lengths(&req.headers, bridge.cfg.max_put_bytes)?;
        if lengths.decoded > bridge.cfg.max_extent_bytes {
            return sliced_part(bridge, &a, &target, number, req.body, lengths).await;
        }
        let mut validator = UploadValidator::new(&a.headers, &a.verified, &a.policy)?;
        let charge = bridge.budget.charge_body(lengths.decoded).await?;
        let body = read_upload(req.body, lengths, &charge, &mut validator).await?;
        validator.finish()?;
        (body, charge)
    };
    let declared = body.len() as u64;

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
        Guard::Applied(()) if copy => Ok(from_proto(copy_part_response(&etag, now.0)?)),
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

/// A part body above one extent. It is stored as a PutObject of that
/// length is (`slices.rs`): slice by slice while the rest is still on
/// the wire, each slice a staged extent with an intent row written
/// before its blob. The part is the list of those extents in body order,
/// and its ETag is the MD5 of the whole body.
///
/// No recovery record names a staged part, so the stamp is what tells a
/// restored catalogue from this one: it is raised after the part is
/// committed and before the answer, and a part whose raise failed is not
/// acknowledged. The client sends it again, and that replaces it.
async fn sliced_part<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    a: &Authed,
    target: &UploadTarget<'_>,
    number: u16,
    body: Body,
    lengths: UploadLengths,
) -> Outcome<S3Response>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let slice_bytes = bridge.cfg.slice_bytes;
    let count =
        usize::try_from(lengths.decoded.div_ceil(slice_bytes)).map_err(|_| Fail::Internal)?;
    // Complete refuses an upload that holds more extents than an object
    // may have. A part that would take it there is refused here, before
    // its body is read, so the client learns it at this part and not
    // after it has sent them all. Parts in flight are not counted.
    let limit = bridge.cfg.max_object_extents;
    let held = bridge
        .catalog
        .upload_extents_held(target.id, number)
        .await?;
    if held.saturating_add(count as u64) > u64::from(limit) {
        return Err(too_many_extents(limit).into());
    }
    let mut validator = UploadValidator::new(&a.headers, &a.verified, &a.policy)?;
    // One slice of plaintext and one of ciphertext are held at a time,
    // whatever the length of the part. Nothing is read before this.
    let charge = bridge.budget.charge_body(slice_bytes).await?;

    let started = bridge.clock.now();
    let write = WriteId::mint(random()?);
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        ids.push(ExtentId::mint(random()?));
    }
    let bdk = unwrap_bdk(
        &bridge.kek,
        a.bucket.kek_version,
        &a.bucket.id,
        &a.bucket.bdk_wrapped,
    )?;
    // Every slice has its row before its blob exists: whatever happens
    // to this request from here on, the catalogue names what it stored.
    match bridge.catalog.open_intents(&write, &ids, started).await? {
        Guard::Applied(()) => {}
        // A replay started after this request passed the gate.
        Guard::Lost => {
            restore_gate(bridge).await?;
            return Err(writes_refused().into());
        }
    }
    // From here on a failure gives the rows up. No record of the write
    // exists anywhere, so the sweep need not wait for them. A row that is
    // given up no longer passes the guard of the batch below: a batch
    // whose answer was lost cannot apply after this.
    let give_up = || async {
        let _ = bridge.catalog.abandon_intents(&write).await;
    };

    let mut rng = SystemRng;
    let sink = SliceSink {
        safety: &bridge.safety,
        bdk: &bdk,
        bucket: &a.bucket.id,
        ids: &ids,
        slice_bytes,
        rng: &mut rng,
    };
    let stored = match store_slices(sink, body, lengths, &charge, &mut validator).await {
        Ok(stored) => stored,
        Err(e) => {
            give_up().await;
            return Err(match e {
                SliceError::Ingress(e) => Fail::Ingress(e),
                SliceError::Proto(e) => Fail::S3(e),
                SliceError::Store => Fail::Internal,
            });
        }
    };
    // The signature of the last chunk, the trailer, the digests and the
    // length are only known here: until this passes the slices are those
    // of a body nobody vouched for.
    let decoded = match validator.finish() {
        Ok(decoded) => decoded,
        Err(e) => {
            give_up().await;
            return Err(e.into());
        }
    };
    drop(charge);
    if stored.len() != count {
        give_up().await;
        return Err(Fail::Internal);
    }

    let now = bridge.clock.now();
    // The ETag of a part is the MD5 of its whole body, whatever the
    // number of extents it is stored in.
    let etag = format!("\"{}\"", hex(decoded.md5()));
    let extents: Vec<ExtentRow> = ids
        .iter()
        .zip(stored)
        .map(|(id, slice)| ExtentRow {
            id: id.clone(),
            bucket_id: a.bucket.id.clone(),
            generation_id: None,
            state: ExtentState::Staged,
            seq: None,
            plain_offset: None,
            plain_size: slice.plain_size,
            cipher_size: slice.cipher_size,
            media_header: slice.sealed.media_header.to_vec(),
            key_mode: KEY_MODE_RANDOM,
            wrapped_file_key: Some(slice.sealed.wrapped_file_key.to_vec()),
            plain_md5: slice.sealed.plain_md5,
            plain_sha256: slice.sealed.plain_sha256,
            cipher_sha256: slice.sealed.cipher_sha256,
            safety_state: SafetyState::Held,
            article_count: None,
            plan_rev: 0,
            last_verified_at: None,
            release_evidence: None,
            released_at: None,
            created_at: now,
        })
        .collect();
    let Some(first) = ids.first() else {
        give_up().await;
        return Err(Fail::Internal);
    };
    let part = UploadPartRow {
        upload_id: target.id.clone(),
        part_number: number,
        extent_id: first.clone(),
        size: lengths.decoded,
        etag: etag.clone(),
        uploaded_at: now,
    };
    // A write this old stops here. The sweep takes `open` rows only
    // long after this age, and the batch refuses rows it took.
    if now.0.saturating_sub(started.0) > WRITER_MAX_AGE_MS {
        give_up().await;
        return Err(ErrorCode::SlowDown.into());
    }
    match bridge
        .catalog
        .put_upload_part_sliced(target, &part, &extents, &write, now)
        .await
    {
        Ok(Guard::Applied(())) => {}
        Ok(Guard::Lost) => {
            // The batch wrote nothing. The upload was completed or
            // aborted meanwhile, a replay began, or the rows are no
            // longer this request's. The slices are left to the sweep.
            give_up().await;
            restore_gate(bridge).await?;
            return Err(match bridge.catalog.upload(target).await? {
                Some((upload, _)) if upload.state == UploadState::Open => ErrorCode::SlowDown,
                _ => ErrorCode::NoSuchUpload,
            }
            .into());
        }
        Err(_) => {
            // Unknown whether the batch applied. If it did, the rows
            // are gone and this changes nothing; if not, it cannot
            // apply any more.
            give_up().await;
            return Err(Fail::Internal);
        }
    }
    // Before the answer: a catalogue restored to a point before this
    // commit is then behind its stamp, the sweep refuses there, and the
    // slices stay. Without the raise the part is not acknowledged.
    if bridge.raise_stamp().await.is_err() {
        restore_gate(bridge).await?;
        return Err(ErrorCode::SlowDown.into());
    }
    Ok(S3Response {
        status: 200,
        headers: vec![("etag".into(), etag)],
        body: RespBody::Empty,
    })
}

/// `x-amz-copy-source-range`: `bytes=first-last`, both ends given and
/// inside an object of `size` bytes. Returns the start and the length.
fn copy_range(value: &str, size: u64) -> Outcome<(u64, u64)> {
    let number = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u64>().ok())
            .flatten()
    };
    value
        .strip_prefix("bytes=")
        .and_then(|range| range.split_once('-'))
        .and_then(|(first, last)| Some((number(first)?, number(last)?)))
        .filter(|(first, last)| first <= last && *last < size)
        .map(|(first, last)| (first, last - first + 1))
        .ok_or_else(|| ErrorCode::InvalidArgument.into())
}

/// The bytes UploadPartCopy names: a range of a live object in the same
/// bucket (see `copy.rs`), or all of it. They are read the way a GET
/// reads them, authenticated extent by extent, and the caller seals them
/// as a new extent of this upload. A part is one extent, so the range
/// is capped like an uploaded part.
///
/// The source's extents are not referenced, whatever the range: a part
/// row would then keep an extent of another object in service, which the
/// part garbage collection does not account for.
async fn copied_part<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    a: &Authed,
    raw: &[(String, String)],
    sent: crate::types::Body,
) -> Outcome<(Vec<u8>, Charge)>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    // A copy has no body; one that was sent would be silently dropped.
    // It can come without a declared length, so the stream is asked too.
    if declared_length(raw)?.is_some_and(|len| len != 0) || !body_is_empty(sent).await {
        return Err(ErrorCode::InvalidRequest.into());
    }
    // Nor bytes a checksum value could be checked against.
    if ChecksumAlgorithm::ALL
        .iter()
        .any(|alg| a.headers.get(alg.header()).is_some())
    {
        return Err(ErrorCode::InvalidRequest.into());
    }
    let key = super::copy::source_key(&a.headers, &a.policy, &a.bucket)?;
    let (source, extents) = super::copy::source_object(bridge, &a.headers, &a.bucket, &key).await?;
    let (start, len) = match a.headers.get("x-amz-copy-source-range") {
        Some(range) => copy_range(range, source.size)?,
        None => (0, source.size),
    };
    if len > bridge.cfg.max_extent_bytes {
        return Err(ErrorCode::EntityTooLarge.into());
    }
    // The read holds what it needs piece by piece and hands back the
    // charge for the plaintext. Charging for the seal before the read
    // would leave a full-size extent no room to be read in.
    let (body, mut charge) = super::get::read_range(bridge, &a.bucket, extents, start, len).await?;
    // Plaintext and ciphertext live together while sealing.
    charge.absorb(bridge.budget.charge(len).await?);
    Ok((body, charge))
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

/// One listed part as the upload holds it.
struct ListedPart {
    number: u16,
    /// The first extent of the part.
    first: ExtentId,
    size: u64,
}

/// The object a validated part list describes.
struct Publication {
    parts: Vec<ListedPart>,
    size: u64,
    /// `"<md5 of the concatenated part MD5s>-<parts>"`.
    etag: String,
}

/// Checks the listed parts (already ascending) against the stored ones:
/// each must exist with the same ETag, and every part but the last must be
/// at least [`MIN_PART_BYTES`].
fn plan(listed: &[PartEvidence], stored: &[UploadPartRow]) -> Outcome<Publication> {
    let mut parts = Vec::with_capacity(listed.len());
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
        parts.push(ListedPart {
            number: have.part_number,
            first: have.extent_id.clone(),
            size: have.size,
        });
        size = size.checked_add(have.size).ok_or(Fail::Internal)?;
    }
    if too_small {
        return Err(ErrorCode::EntityTooSmall.into());
    }
    let etag = format!("\"{}-{}\"", hex(&md5::compute(&md5s).0), listed.len());
    Ok(Publication { parts, size, etag })
}

/// The extents of the listed `parts` as the generation will hold them:
/// in part order and, within a part, in body order, the first of them
/// at `seq` and `offset`, which are moved past the last. `staged` is
/// ordered by part number and piece; what it holds of other parts is
/// left out. `None` when it does not hold exactly the parts that were
/// listed: a part was replaced after the upload was read.
fn place(
    parts: &[ListedPart],
    staged: Vec<PartExtent>,
    seq: &mut u32,
    offset: &mut u64,
) -> Option<Vec<ExtentRow>> {
    let mut by_part: HashMap<u16, Vec<ExtentRow>> = HashMap::new();
    for PartExtent {
        part_number,
        piece,
        extent,
    } in staged
    {
        let rows = by_part.entry(part_number).or_default();
        if usize::try_from(piece).ok() != Some(rows.len()) {
            return None;
        }
        rows.push(extent);
    }
    let mut out = Vec::new();
    for part in parts {
        let rows = by_part.remove(&part.number)?;
        if rows.first().map(|e| &e.id) != Some(&part.first) {
            return None;
        }
        let start = *offset;
        for mut row in rows {
            row.seq = Some(*seq);
            row.plain_offset = Some(*offset);
            *seq = seq.checked_add(1)?;
            *offset = offset.checked_add(row.plain_size)?;
            out.push(row);
        }
        if *offset - start != part.size {
            return None;
        }
    }
    Some(out)
}

pub(super) async fn complete<C, B, N, J, K, T>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
    _bucket: &str,
    _key: &str,
) -> S3Response
where
    C: Catalog + 'static,
    B: BlobStore + 'static,
    N: NntpConnector + 'static,
    J: JobSink + 'static,
    K: Kek + 'static,
    T: Clock + 'static,
{
    respond(complete_inner(bridge, req).await)
}

/// The answer to a Complete of an upload that holds more than `limit`
/// extents. Nothing was published and the upload is still open.
fn too_many_extents(limit: u32) -> S3Response {
    S3Response::error(
        400,
        "EntityTooLarge",
        &format!(
            "The upload holds more than {limit} stored extents, the most one object may have. \
             A part above one extent is stored as several. Use a smaller part size."
        ),
    )
}

/// The answer of a Complete whose condition does not hold: `refusal`,
/// unless the upload was completed in the meantime by the same request
/// sent twice. Then the object the condition met may be the one this
/// upload published, and the answer is the receipt, as for any retry of
/// a Complete that won.
async fn refused_unless_completed<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    target: &UploadTarget<'_>,
    digest: &[u8; 32],
    a: &Authed,
    refusal: S3Response,
) -> Outcome<S3Response>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    if let Some((upload, _)) = bridge.catalog.upload(target).await? {
        if upload.state == UploadState::Completed && upload.complete_digest == Some(*digest) {
            let etag = upload.result_etag.ok_or(Fail::Internal)?;
            return complete_response(a, etag, bridge.clock.now().0);
        }
    }
    Err(refusal.into())
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

/// Part numbers one read of a paged Complete covers.
const WINDOW_PARTS: u16 = 256;
/// Most extent rows such a read brings: every part of the run in as many
/// slices as one body may have.
const WINDOW_ROWS: u32 = WINDOW_PARTS as u32 * crate::config::MAX_WRITE_SLICES as u32;

/// What a Complete asks, once its body is read.
struct Completion {
    a: Authed,
    condition: Option<Precondition>,
    id: UploadId,
    listed: Vec<PartEvidence>,
    digest: [u8; 32],
}

impl Completion {
    fn target(&self) -> UploadTarget<'_> {
        UploadTarget {
            bucket: &self.a.bucket.id,
            key: &self.a.key,
            id: &self.id,
        }
    }
}

/// An open upload as one attempt read it, with its listed parts checked.
struct Opened {
    upload: UploadRow,
    publication: Publication,
    /// How many extents the upload holds, listed or not. 0 when no
    /// object of this deployment has a segmented record: then nothing
    /// asks.
    held: u64,
}

/// What an attempt found before it wrote anything.
enum Look {
    /// The request is answered: by the receipt of the Complete that won.
    Answer(S3Response),
    Open(Box<Opened>),
}

/// Reads the upload and checks the request against it. Writes nothing.
/// `lost_at` is the revision of the attempt before, if its batch lost
/// the guard.
async fn look<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    c: &Completion,
    lost_at: Option<u64>,
) -> Outcome<Look>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let (a, target) = (&c.a, c.target());
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
            if upload.complete_digest != Some(c.digest) {
                return Err(ErrorCode::NoSuchUpload.into());
            }
            let etag = upload.result_etag.ok_or(Fail::Internal)?;
            return complete_response(a, etag, bridge.clock.now().0).map(Look::Answer);
        }
    }
    if lost_at == Some(upload.revision) {
        // Nothing changed the upload, so the batch was not refused by
        // a race: the catalogue would not adopt the listed parts.
        return Err(ErrorCode::InvalidPart.into());
    }
    // A condition that does not hold now is answered before anything
    // is written for this attempt, the floor of the key included.
    if let Some(condition) = &c.condition {
        if let Err(refusal) = check_precondition(bridge, &a.bucket.id, &a.key, condition).await {
            return refused_unless_completed(bridge, &target, &c.digest, a, refusal)
                .await
                .map(Look::Answer);
        }
    }
    let publication = plan(&c.listed, &parts)?;
    drop(parts);
    // An upload that holds more than an object may have, in listed
    // parts or not, is refused before anything is recorded, and stays
    // open: the client aborts it, or sends parts again in bodies of at
    // most one extent until it holds fewer. With a limit no segmented
    // record is under, the one read of the extents says so itself.
    let (limit, cut) = (bridge.cfg.max_object_extents, bridge.cfg.record_cut);
    let mut held = 0;
    if limit > cut.after {
        held = bridge.catalog.upload_extents_held(&c.id, 0).await?;
        if held > u64::from(limit) {
            return Err(too_many_extents(limit).into());
        }
        // No reader takes a head of more segments, so no segment of
        // such a record is stored. A configuration that was checked
        // never comes here.
        if held > u64::from(cut.after) && !cut.fits(held) {
            let most = u32::try_from(MAX_SEGMENTS)
                .unwrap_or(u32::MAX)
                .saturating_mul(cut.per);
            return Err(too_many_extents(most.min(limit)).into());
        }
    }
    Ok(Look::Open(Box::new(Opened {
        upload,
        publication,
        held,
    })))
}

/// The record of one attempt, before it is stored as a whole.
enum Draft<'a, B, K> {
    /// Every extent, for a record in one document.
    Single(Vec<ExtentRow>),
    /// The segments are stored; the head is not.
    Segmented(SegmentWriter<'a, B, K>),
}

/// The listed extents of one attempt, placed.
struct Placed<'a, B, K> {
    placements: Vec<ExtentPlacement>,
    /// A part of several extents is among them.
    sliced: bool,
    draft: Draft<'a, B, K>,
}

/// Reads the extents of the listed parts and places them. `None` when
/// the upload no longer holds the parts as they were listed: an
/// UploadPart replaced one after the upload was read.
///
/// An upload of at most [`Cut::after`](crate::recovery::Cut) extents is
/// read at once. A larger one is read a run of [`WINDOW_PARTS`] part
/// numbers at a time, and from the extent that makes the object larger
/// than one document holds, the rows go into segments as they come, so
/// what is held is one run of rows, one segment and the placements.
/// Only a request that holds the charge of that work (`charged`) stores
/// segments; another is answered `503 SlowDown` before the first.
async fn gather<'a, C, B, N, J, K, T>(
    bridge: &'a Bridge<C, B, N, J, K, T>,
    c: &'a Completion,
    publication: &Publication,
    held: u64,
    charged: bool,
) -> Outcome<Option<Placed<'a, B, K>>>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let target = c.target();
    let (limit, cut) = (bridge.cfg.max_object_extents, bridge.cfg.record_cut);
    let placement = |e: &ExtentRow| -> Outcome<ExtentPlacement> {
        Ok(ExtentPlacement {
            extent_id: e.id.clone(),
            seq: e.seq.ok_or(Fail::Internal)?,
            plain_offset: e.plain_offset.ok_or(Fail::Internal)?,
        })
    };
    let (mut seq, mut offset) = (0u32, 0u64);
    if held <= u64::from(cut.after) {
        // One record in one document names every extent.
        let most = limit.min(cut.after);
        let staged = bridge
            .catalog
            .upload_extents(&target, most.saturating_add(1))
            .await?;
        if u32::try_from(staged.len()).map_or(true, |n| n > most) {
            if most == limit {
                return Err(too_many_extents(limit).into());
            }
            // The upload grew past one document since it was counted:
            // an UploadPart came in between. The next attempt counts
            // again.
            return Ok(None);
        }
        let sliced = staged.iter().any(|p| p.piece > 0);
        let Some(extents) = place(&publication.parts, staged, &mut seq, &mut offset) else {
            return Ok(None);
        };
        let placements = extents.iter().map(placement).collect::<Outcome<Vec<_>>>()?;
        return Ok(Some(Placed {
            placements,
            sliced,
            draft: Draft::Single(extents),
        }));
    }

    let mut placements: Vec<ExtentPlacement> = Vec::new();
    let mut sliced = false;
    // Rows wait here until there are more than one document holds.
    let mut waiting: Vec<ExtentRow> = Vec::new();
    let mut writer: Option<SegmentWriter<'a, B, K>> = None;
    let mut parts = publication.parts.as_slice();
    while let Some(first) = parts.first().map(|p| p.number) {
        let last = first.saturating_add(WINDOW_PARTS - 1);
        let run = parts.partition_point(|p| p.number <= last);
        let (listed, rest) = parts.split_at(run);
        parts = rest;
        let staged = bridge
            .catalog
            .upload_extents_between(&target, first, last, WINDOW_ROWS + 1)
            .await?;
        if u32::try_from(staged.len()).map_or(true, |n| n > WINDOW_ROWS) {
            // No part is stored in more slices than one body may have.
            return Err(Fail::Internal);
        }
        sliced |= staged.iter().any(|p| p.piece > 0);
        let Some(rows) = place(listed, staged, &mut seq, &mut offset) else {
            return Ok(None);
        };
        if seq > limit {
            // Only when parts were added since the count.
            return Err(too_many_extents(limit).into());
        }
        for row in &rows {
            placements.push(placement(row)?);
        }
        waiting.extend(rows);
        if writer.is_none() && seq > cut.after {
            if !charged {
                // The request began on an upload within one document,
                // so it holds no charge and its answer is not kept
                // alive. A listed part was since stored again with the
                // same ETag in more extents (the slice size changed
                // between the two versions that took them). Sent again,
                // the Complete is counted as what it is.
                return Err(ErrorCode::SlowDown.into());
            }
            writer = Some(SegmentWriter::new(
                &bridge.safety,
                &bridge.kek,
                &bridge.cfg.records,
                &c.a.bucket,
                set_id(bridge.clock.now(), random()?),
                cut.per,
            )?);
        }
        if let Some(writer) = writer.as_mut() {
            for row in waiting.drain(..) {
                writer.push(&row).await?;
            }
        }
        // The host runs its timers here: the window after which the
        // answer is streamed, and the keepalive of that stream. Calls
        // that are answered at once, one after the other, may leave it
        // no turn for them (measured in a local workerd: no timer ran
        // while this loop read 131,072 extents).
        if let Some(sleep) = bridge.budget.sleeper() {
            sleep(0).await;
        }
    }
    let draft = match writer {
        Some(writer) => Draft::Segmented(writer),
        // The listed parts are few enough for one document, whatever
        // else the upload holds.
        None => Draft::Single(waiting),
    };
    Ok(Some(Placed {
        placements,
        sliced,
        draft,
    }))
}

/// Runs `work`, which holds a charge, in the table of the isolate
/// ([`Bridge::works`]), and marks it there every
/// [`JOB_BEAT_MS`](crate::jobtable::JOB_BEAT_MS) on a timer of this
/// invocation.
///
/// The work runs under the invocation's `waitUntil`, which the runtime
/// ends at most 30 s after the client left. What ran under it is then
/// neither polled again nor dropped, so in the frame of the invocation
/// the charge would be held for as long as the isolate lives. In the
/// table its mark goes stale instead, and the next request of the
/// isolate drops it ([`Bridge::reap_work`]): the charge and the memory
/// it stands for go together.
///
/// `gone` is the document when the work was dropped while this
/// invocation still ran: its timer was a minute late, or the work did
/// not end in [`JOB_WAIT_MS`](crate::jobtable::JOB_WAIT_MS).
///
/// A host without timers has nothing to mark with: its work runs in
/// the frame of the invocation.
fn tabled<C, B, N, J, K, T>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    work: impl Future<Output = Vec<u8>> + 'static,
    gone: impl FnOnce() -> Vec<u8> + 'static,
) -> LocalBoxFuture<'static, Vec<u8>>
where
    C: Catalog + 'static,
    B: BlobStore + 'static,
    N: NntpConnector + 'static,
    J: JobSink + 'static,
    K: Kek + 'static,
    T: Clock + 'static,
{
    let Some(sleep) = bridge.budget.sleeper().cloned() else {
        return Box::pin(work);
    };
    let started = bridge.clock.now();
    let running = bridge.works.run(started, work);
    let bridge = Rc::clone(bridge);
    Box::pin(async move {
        let beat = || sleep(crate::jobtable::JOB_BEAT_MS as u32);
        match running.marked(started, || bridge.clock.now(), beat).await {
            crate::jobtable::Ran::Done(doc) => doc,
            _ => gone(),
        }
    })
}

/// The document of an answer, as a deferred body sends it after the
/// XML declaration.
fn document(resp: S3Response) -> Vec<u8> {
    let body = match resp.body {
        RespBody::Bytes(body) => body,
        _ => Vec::new(),
    };
    let rest = body.strip_prefix(XML_DECLARATION).unwrap_or(&body);
    let start = rest
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(rest.len());
    rest[start..].to_vec()
}

async fn complete_inner<C, B, N, J, K, T>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
) -> Outcome<S3Response>
where
    C: Catalog + 'static,
    B: BlobStore + 'static,
    N: NntpConnector + 'static,
    J: JobSink + 'static,
    K: Kek + 'static,
    T: Clock + 'static,
{
    let a = authenticate(bridge, &req).await?;
    // Before the body is read or anything is published: `If-None-Match:
    // *` or `If-Match` is a condition on the key, held to by the batch
    // that publishes. Any other conditional header is refused.
    let condition = precondition(&a.headers)?;
    // A whole-object checksum cannot be checked: none is computed.
    if ChecksumAlgorithm::ALL
        .iter()
        .any(|c| a.headers.get(c.header()).is_some())
        || a.headers.get("x-amz-checksum-type").is_some()
    {
        return Err(ErrorCode::NotImplemented.into());
    }
    let id = upload_id(&a.target)?;
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
    let completion = Completion {
        a,
        condition,
        id,
        listed,
        digest,
    };

    // Everything the request can be refused for without a write is
    // answered here, with its status.
    let first = match look(bridge, &completion, None).await? {
        Look::Answer(resp) => return Ok(resp),
        Look::Open(opened) => *opened,
    };
    if first.held <= u64::from(bridge.cfg.record_cut.after) {
        return publish(bridge, &completion, first, false).await;
    }
    // A segmented record: the extents are read and stored a run at a
    // time, which can outlast a client's read timeout. So the answer is
    // a `200` whose document follows when the work is done, kept alive
    // with whitespace (`crate::keepalive`), and a failure from here on
    // is an `<Error>` document in it, as S3 itself answers a Complete.
    // The memory of the work is charged as one fixed sum; without room
    // for it the client is told to come back. What may hold the room
    // is the work of an invocation that ended while this one waited:
    // nothing else may have come to drop it, so look once more.
    let bytes = crate::config::COMPLETE_CHARGE_BYTES;
    let charge = match bridge.budget.charge_ahead(bytes).await {
        Ok(charge) => charge,
        Err(e) => {
            bridge.reap_work();
            bridge.budget.try_charge(bytes).ok_or(e)?
        }
    };
    let work = {
        let bridge = Rc::clone(bridge);
        async move {
            let _charge = charge;
            document(respond(publish(&bridge, &completion, first, true).await))
        }
    };
    // Work that was dropped: the upload is published or it is not, and
    // a Complete sent again answers from the receipt or publishes.
    let fallback = || document(s3_error(ErrorCode::InternalError));
    let work = tabled(bridge, work, fallback);
    Ok(S3Response {
        status: 200,
        headers: vec![("content-type".to_string(), "application/xml".to_string())],
        body: RespBody::Deferred(Deferred::new(work, fallback)),
    })
}

/// Records and publishes the upload, from `first` on: up to
/// [`COMPLETE_ATTEMPTS`] attempts, each on the upload as it reads it.
/// A request that began on an upload within one document holds no
/// charge (`charged` is false), also when the upload has grown past it
/// by a later attempt: the parts it lists are the ones it began with
/// (their ETags), so its record is one document as long as each is
/// stored in the extents it had. [`gather`] refuses the one case that
/// is left.
async fn publish<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    c: &Completion,
    first: Opened,
    charged: bool,
) -> Outcome<S3Response>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let (a, target, digest) = (&c.a, c.target(), &c.digest);
    let condition = c.condition.as_ref();
    let mut first = Some(first);
    // Revision of the previous attempt, if its batch lost the guard.
    let mut lost_at: Option<u64> = None;
    for _ in 0..COMPLETE_ATTEMPTS {
        let Opened {
            upload,
            publication,
            held,
        } = match first.take() {
            Some(opened) => opened,
            None => match look(bridge, c, lost_at).await? {
                Look::Answer(resp) => return Ok(resp),
                Look::Open(opened) => *opened,
            },
        };
        let Some(placed) = gather(bridge, c, &publication, held, charged).await? else {
            // An UploadPart replaced a listed part after the upload was
            // read. The batch would lose its guard: take the same path.
            lost_at = Some(upload.revision);
            continue;
        };
        let Placed {
            placements,
            sliced,
            draft,
        } = placed;
        // A part stored in slices may be here without its stamp: its
        // request answered `503`, or `500` after a commit it could not
        // confirm, and the client took the part from ListParts. Its write intents are in any catalogue saved while
        // it was stored, and in one restored from there the sweep would
        // take the slices of this object. So the stamp is raised before
        // the record exists, and without it nothing is published.
        if sliced && bridge.raise_stamp().await.is_err() {
            restore_gate(bridge).await?;
            return Err(ErrorCode::SlowDown.into());
        }
        if matches!(draft, Draft::Segmented(_)) {
            // The read took many calls. An upload that moved in the
            // meantime (a part came, or an abort) gets no head: the
            // batch would refuse it. The next attempt answers from what
            // the upload is by then.
            match bridge.catalog.upload(&target).await? {
                Some((now, _))
                    if now.state == UploadState::Open && now.revision == upload.revision => {}
                _ => continue,
            }
        }
        let now = bridge.clock.now();
        // The id sorts after everything already on the key, so the order
        // of ids on a key is the order of its commits; the batch checks
        // it again, against whatever commits in between.
        let newest = bridge.catalog.newest_id(&a.bucket.id, &a.key).await?;
        let generation = GenerationRow {
            id: id_after(now, newest.as_ref(), random()?),
            bucket_id: a.bucket.id.clone(),
            key: a.key.clone(),
            state: GenerationState::Live,
            size: publication.size,
            etag: publication.etag.clone(),
            checksum_json: None,
            content_json: upload.content_json,
            user_meta_json: upload.user_meta_json,
            extent_count: u32::try_from(placements.len()).map_err(|_| Fail::Internal)?,
            created_at: now,
            retired_at: None,
        };
        // The recovery record is durable before the publication batch.
        // It describes the staged extents as this generation will hold
        // them; the batch applies only if the upload is unchanged.
        let commit = CompleteUpload {
            generation,
            placements,
            now,
        };
        // A condition that does not hold ends the request with `412`
        // or `404`, before a record exists under this id. The upload is
        // not touched: it stays open with its parts, to be completed
        // again or aborted.
        if let Err(refusal) = hold_precondition(
            bridge,
            &a.bucket.id,
            &a.key,
            &commit.generation.id,
            condition,
        )
        .await
        {
            return refused_unless_completed(bridge, &target, digest, a, refusal).await;
        }
        let record: Recorded = match draft {
            Draft::Single(extents) => {
                write_generation(
                    &bridge.catalog,
                    &bridge.safety,
                    &bridge.kek,
                    &bridge.cfg.records,
                    &a.bucket,
                    &commit.generation,
                    &extents,
                )
                .await?
            }
            // The last segment, then the head: only now is there a
            // record of this attempt.
            Draft::Segmented(writer) => writer.finish(&bridge.catalog, &commit.generation).await?,
        };
        match bridge
            .catalog
            .complete_upload(&target, upload.revision, digest, &commit, condition, record)
            .await?
        {
            PublishOutcome::Applied => {
                // The outbox rows are the durable obligation, written
                // by the batch for every extent. One message batch
                // starts the first of them; the dispatcher brings the
                // rest, and whatever a lost notification leaves.
                let jobs: Vec<Job> = commit
                    .placements
                    .iter()
                    .take(JOB_BATCH)
                    .map(|p| Job::Extent {
                        v: JOB_VERSION,
                        extent: p.extent_id.clone(),
                        generation: commit.generation.id.clone(),
                        stage: OutboxStage::Post,
                    })
                    .collect();
                let _ = bridge.jobs.send_many(&jobs).await;
                return complete_response(a, publication.etag, now.0);
            }
            PublishOutcome::Refused(record) => {
                // Nothing was published under this id, so its record
                // must not publish it in a replay either. Best effort: a
                // record left behind replays as a PUT that failed, and
                // under everything that follows it on the key, which
                // the floor raised for it holds to a later id. Of a
                // segmented record the head is the record: its segments
                // stay, and nothing reads them without it.
                let discarded = discard_unless_present(bridge, &commit.generation, record).await;
                // Refused as well when a replay started after this
                // request passed the gate.
                if bridge.catalog.restore_pending().await? {
                    return Err(ErrorCode::SlowDown.into());
                }
                if let Some(condition) = condition {
                    // A conditional Complete says `412` or `404` only
                    // when no record of it is left: with one, a replay
                    // could publish what the answer says was refused.
                    // The same for a record that was kept because a row
                    // exists under its id: a replay may have published it.
                    if !discarded? {
                        return Err(Fail::Internal);
                    }
                    // The batch does not say which guard refused it. If
                    // the condition fails now, that is the answer, so
                    // the upload is not blamed below for what the key
                    // did.
                    if let Err(refusal) =
                        check_precondition(bridge, &a.bucket.id, &a.key, condition).await
                    {
                        return refused_unless_completed(bridge, &target, digest, a, refusal).await;
                    }
                }
                // Otherwise refused for the id (the key took a newer one
                // since it was read) or for the upload. Only the second
                // is judged by the revision on the next turn.
                let newest = bridge.catalog.newest_id(&a.bucket.id, &a.key).await?;
                // The floor is this id itself unless something newer
                // came: only a higher one outran it.
                let outrun = newest.is_some_and(|n| n > commit.generation.id);
                lost_at = (!outrun).then_some(upload.revision);
            }
            PublishOutcome::Fenced(record) => {
                // The catalogue failed, then showed that nothing was
                // published. Without its record this attempt cannot come
                // back in a replay, also after the client aborts.
                let _ = discard_refused(bridge, &commit.generation, record).await;
                return Err(Fail::Internal);
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
