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

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

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
use crate::ports::{
    BlobMeta, BlobStore, Bridge, Catalog, Clock, Guard, JobSink, Kek, NntpConnector,
    PublishOutcome, UploadTarget,
};
use crate::recovery::{id_after, write_generation};
use crate::service::common::{
    auth_refused, check_precondition, discard_refused, discard_unless_present, header_refused,
    hold_precondition, host_refused, precondition, restore_gate, send_post_jobs, signed_host,
    writes_refused, REGION_ALIASES,
};
use crate::service::slices::{store_slices, SliceError, SliceSink};
use crate::types::{
    Body, BridgeError, Bucket, CompleteUpload, ExtentId, ExtentPlacement, ExtentRow, ExtentState,
    GenerationRow, GenerationState, KeyStatus, PartExtent, Perm, RespBody, S3Request, S3Response,
    SafetyState, UploadId, UploadPartRow, UploadRow, UploadState, WriteId,
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
        ErrorCode::NoSuchBucket => "The specified bucket does not exist.",
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

/// The policy for requests signed for `host` (see `common::signed_host`).
fn policy(cfg: &BridgeConfig, host: &str) -> Outcome<Policy> {
    Policy::new(
        host.to_owned(),
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
    .and_then(|policy| policy.with_region_aliases(&REGION_ALIASES))
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
    /// The key holds a grant on the addressed bucket, of either kind.
    granted: bool,
    /// Set when `authorize` refused a bucket this key has no grant on.
    /// The verifier asks `authorize` only once the signature has
    /// verified, so this is only ever set for an authenticated caller.
    no_bucket: Cell<bool>,
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
        if !self.key.as_ref().is_some_and(|k| k.principal == principal) {
            return false;
        }
        if !self.granted {
            self.no_bucket.set(true);
        }
        self.writable_bucket.as_deref() == Some(target.bucket.as_str())
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
    let policy = policy(&bridge.cfg, signed_host(&bridge.cfg, req))?;
    let target = Target::parse(&req.raw_target, &policy);
    let fields: Vec<(&str, &str)> = req
        .headers
        .iter()
        .filter(|(n, _)| !crate::entry::dropped_header(n))
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let headers = Headers::new(&fields, &policy);
    // The named refusals of `common::authenticate`, in the same order:
    // the host before the path is judged.
    if let Ok(headers) = &headers {
        if let Some(resp) = host_refused(headers, &bridge.cfg) {
            return Err(resp.into());
        }
    }
    let target = target?;
    let headers = headers?;
    headers
        .check_features()
        .map_err(|refusal| header_refused(&refusal))?;

    let mut authority = OneKey::default();
    let mut bucket = None;
    // The entry point admits one kind of key (`crate::entry`): a key of
    // the other kind is looked up as if it did not exist.
    let entry = crate::entry::Entry::of(&req.headers);
    if let Some(akid) = presented_access_key(&target, &headers).filter(|akid| entry.admits(akid)) {
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
            authority.granted = perm.is_some();
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
    )
    .map_err(|code| {
        if code == ErrorCode::AccessDenied && authority.no_bucket.get() {
            // As `common::authenticate`: the signature verified, and to
            // this key no bucket of this name exists.
            Fail::S3(ErrorCode::NoSuchBucket)
        } else {
            Fail::Response(auth_refused(code, &policy, &headers, &target))
        }
    })?;
    // `authorize` passed, so the bucket exists and the grant is `rw`.
    let bucket = bucket.ok_or(ErrorCode::NoSuchBucket)?;
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
    // The state alone: reading the parts here would cost a row per part
    // already uploaded, on every part.
    if bridge.catalog.upload_state(&target).await? != Some(UploadState::Open) {
        return Err(ErrorCode::NoSuchUpload.into());
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
            return Err(match bridge.catalog.upload_state(target).await? {
                Some(UploadState::Open) => ErrorCode::SlowDown,
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
    let source = super::copy::source_generation(bridge, &a.headers, &a.bucket, &key).await?;
    let (start, len) = match a.headers.get("x-amz-copy-source-range") {
        Some(range) => copy_range(range, source.size)?,
        None => (0, source.size),
    };
    if len > bridge.cfg.max_extent_bytes {
        return Err(ErrorCode::EntityTooLarge.into());
    }
    // The extents of the range alone, by the generation the conditions
    // were judged on: a source of any size costs the rows of one part.
    // An empty source has no byte to ask for; its one empty extent
    // begins at 0, where a range of one byte looks.
    let end = start.checked_add(len.max(1)).ok_or(Fail::Internal)?;
    let extents = bridge.catalog.extents_in(&source.id, start, end).await?;
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

/// The extents of the listed parts as the generation will hold them: in
/// part order and, within a part, in body order. `staged` is ordered by
/// part number and piece. `None` when it does not hold exactly the parts
/// that were listed: a part was replaced after the upload was read.
fn place(parts: &[ListedPart], staged: Vec<PartExtent>) -> Option<Vec<ExtentRow>> {
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
    let mut offset = 0u64;
    for part in parts {
        let rows = by_part.remove(&part.number)?;
        if rows.first().map(|e| &e.id) != Some(&part.first) {
            return None;
        }
        let start = offset;
        for mut row in rows {
            row.seq = Some(u32::try_from(out.len()).ok()?);
            row.plain_offset = Some(offset);
            offset = offset.checked_add(row.plain_size)?;
            out.push(row);
        }
        if offset - start != part.size {
            return None;
        }
    }
    Some(out)
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
                // key is never rolled back. A declared size is not
                // checked again: the same part list was held to it when
                // it won, and a replay publishes nothing to guard.
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
        // A condition that does not hold now is answered before anything
        // is written for this attempt, the floor of the key included.
        if let Some(condition) = &condition {
            if let Err(refusal) = check_precondition(bridge, &a.bucket.id, &a.key, condition).await
            {
                return refused_unless_completed(bridge, &target, &digest, &a, refusal).await;
            }
        }
        let publication = plan(&listed, &parts)?;
        drop(parts);
        // The size the client says the object has is its guard against a
        // part that went missing: an object of another size is not
        // published. The header is checked as a decimal before this.
        if let Some(declared) = a.headers.get("x-amz-mp-object-size") {
            if declared.parse::<u64>().ok() != Some(publication.size) {
                let message = format!(
                    "The x-amz-mp-object-size header declares {declared} bytes, but the \
                     listed parts hold {} bytes. This request published nothing.",
                    publication.size
                );
                return Err(S3Response::error_with(
                    400,
                    "InvalidRequest",
                    &message,
                    &[("Header", "x-amz-mp-object-size")],
                )
                .into());
            }
        }
        // One record names every extent of the object and one batch
        // publishes them. An upload that holds more than an object may
        // have, in listed parts or not, is refused before either, and
        // stays open: the client aborts it, or sends parts again in
        // bodies of at most one extent until it holds fewer.
        let limit = bridge.cfg.max_object_extents;
        let staged = bridge
            .catalog
            .upload_extents(&target, limit.saturating_add(1))
            .await?;
        if u32::try_from(staged.len()).map_or(true, |n| n > limit) {
            return Err(too_many_extents(limit).into());
        }
        let sliced = staged.iter().any(|p| p.piece > 0);
        let Some(extents) = place(&publication.parts, staged) else {
            // An UploadPart replaced a listed part after the upload was
            // read. The batch would lose its guard: take the same path.
            lost_at = Some(upload.revision);
            continue;
        };
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
        let mut placements = Vec::with_capacity(extents.len());
        for e in &extents {
            placements.push(ExtentPlacement {
                extent_id: e.id.clone(),
                seq: e.seq.ok_or(Fail::Internal)?,
                plain_offset: e.plain_offset.ok_or(Fail::Internal)?,
            });
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
            condition.as_ref(),
        )
        .await
        {
            return refused_unless_completed(bridge, &target, &digest, &a, refusal).await;
        }
        let record = write_generation(
            &bridge.catalog,
            &bridge.safety,
            &bridge.kek,
            &bridge.cfg.records,
            &a.bucket,
            &commit.generation,
            &extents,
        )
        .await?;
        drop(extents);
        match bridge
            .catalog
            .complete_upload(
                &target,
                upload.revision,
                &digest,
                &commit,
                condition.as_ref(),
                record,
            )
            .await?
        {
            PublishOutcome::Applied => {
                let rows = commit
                    .placements
                    .iter()
                    .map(|p| p.extent_id.clone())
                    .collect();
                send_post_jobs(bridge, &commit.generation.id, rows, commit.now).await;
                return complete_response(&a, publication.etag, now.0);
            }
            PublishOutcome::Refused(record) => {
                // Nothing was published under this id, so its record
                // must not publish it in a replay either. Best effort: a
                // record left behind replays as a PUT that failed, and
                // under everything that follows it on the key, which
                // the floor raised for it holds to a later id.
                let discarded = discard_unless_present(bridge, &commit.generation, record).await;
                // Refused as well when a replay started after this
                // request passed the gate.
                if bridge.catalog.restore_pending().await? {
                    return Err(ErrorCode::SlowDown.into());
                }
                if let Some(condition) = &condition {
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
                        return refused_unless_completed(bridge, &target, &digest, &a, refusal)
                            .await;
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
