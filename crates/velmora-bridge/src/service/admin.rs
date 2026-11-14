//! `/_admin/*` routes and S3 CreateBucket.
//!
//! Every route checks the admin bearer token first, in constant time, so
//! an unauthenticated caller learns nothing about which routes exist.
//!
//! | Route | Answer |
//! |---|---|
//! | `POST /_admin/buckets` `{name, disposable}` | `200`; `403` for a non-disposable bucket while real data is not allowed; `409` name taken |
//! | `POST /_admin/keys` `{buckets, perm}` | `200` with the secret, once |
//! | `GET /_admin/objects/<bucket>/<key>` | `200` per-extent state |
//! | `POST /_admin/evict/<bucket>/<key>[?include_safety=1]` | `200`; `403` for `include_safety` on a non-disposable bucket |
//! | `POST /_admin/drill/<bucket>/<key>` | `200` read-back from Usenet only |
//! | `GET /_admin/status` | `200` |
//! | `POST /_admin/dev/guard-selftest` | `200` in dev, `404` otherwise |
//!
//! Secrets: the access key secret exists in the `POST /_admin/keys`
//! response body and nowhere else. No error body carries request data,
//! key material or backend error text.

use std::rc::Rc;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use velmora::rng::{fill_alphabet, FillRandom, SystemRng};
use zeroize::Zeroizing;

use crate::articles::article_spans;
use crate::config::{Maintenance, REAL_DATA_READY};
use crate::crypto::{open_range, unwrap_bdk, wrap_bdk, wrap_secret, DataKey};
use crate::fetch::{read_articles, ProviderSession};
use crate::ingress::{self, check_admin_bearer, IngressError};
use crate::ports::{
    BlobStore, Bridge, Catalog, Clock, Guard, JobSink, Kek, NntpConnector, PermitClass,
};
use crate::post::Stop;
use crate::recovery::delete_blob;
use crate::types::{
    AccessKeyRow, ArticleRow, ArticleState, Body, BridgeError, Bucket, BucketId, ExtentRow,
    KeyStatus, Method, OutboxStage, Perm, RespBody, S3Request, S3Response, SafetyState,
};

/// Largest admin request body.
const MAX_BODY_BYTES: u64 = 64 * 1024;
/// Buckets one access key can be granted in one request.
const MAX_GRANTS: usize = 32;
/// Extents whose cache presence one status request looks up.
const MAX_CACHE_PROBES: usize = 200;
/// `owner` and `principal` of everything the admin API creates.
const ADMIN_PRINCIPAL: &str = "admin";

const KEY_ID_PREFIX: &str = "AKVL";
const KEY_ID_RANDOM_LEN: usize = 16;
const KEY_ID_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const SECRET_LEN: usize = 40;
const SECRET_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

type Admin<V> = core::result::Result<V, S3Response>;

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

fn json_response(status: u16, value: &Value) -> S3Response {
    S3Response {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: RespBody::Bytes(value.to_string().into_bytes()),
    }
}

fn ok(value: &Value) -> S3Response {
    json_response(200, value)
}

/// `code` and `message` are static text: never request data.
fn fail(status: u16, code: &'static str, message: &'static str) -> S3Response {
    json_response(status, &json!({ "error": code, "message": message }))
}

fn not_found() -> S3Response {
    fail(404, "NotFound", "No such admin route.")
}

fn no_bucket() -> S3Response {
    fail(404, "NoSuchBucket", "The bucket does not exist.")
}

fn no_key() -> S3Response {
    fail(404, "NoSuchKey", "The object does not exist.")
}

fn busy() -> S3Response {
    fail(503, "SlowDown", "Busy; retry shortly.")
}

/// A backend failure, as its class only: the text of a database or
/// provider error can carry data.
fn internal(e: &BridgeError) -> S3Response {
    let class = match e {
        BridgeError::Sql(_) | BridgeError::GuardFailed => "catalog",
        BridgeError::Blob(_) => "blob",
        BridgeError::Nntp(_) => "nntp",
        BridgeError::Queue(_) => "queue",
        BridgeError::Crypto(_) => "crypto",
        _ => "internal",
    };
    json_response(
        500,
        &json!({ "error": "InternalError", "message": "The request failed.", "class": class }),
    )
}

fn ingress(e: IngressError) -> S3Response {
    json_response(
        e.status(),
        &json!({ "error": e.code(), "message": "The request was refused." }),
    )
}

/// Shorthand for `map_err(|e| internal(&e))`.
trait OrInternal<V> {
    fn or_internal(self) -> Admin<V>;
}

impl<V> OrInternal<V> for crate::types::Result<V> {
    fn or_internal(self) -> Admin<V> {
        self.map_err(|e| internal(&e))
    }
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/// Reads a small JSON body, charged to the byte budget before the read.
async fn read_json<C, B, N, J, K, T, D>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> Admin<D>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
    D: DeserializeOwned,
{
    let declared = match ingress::declared_length(&req.headers).map_err(ingress)? {
        Some(n) => n,
        None => match &req.body {
            Body::Empty => 0,
            Body::Stream {
                declared_len: Some(n),
                ..
            } => *n,
            Body::Stream { .. } => return Err(ingress(IngressError::MissingContentLength)),
        },
    };
    if declared > MAX_BODY_BYTES {
        return Err(ingress(IngressError::EntityTooLarge));
    }
    let charge = bridge.budget.charge(declared).await.map_err(ingress)?;
    let bytes = ingress::read_capped(req.body, declared, &charge)
        .await
        .map_err(ingress)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| fail(400, "MalformedJSON", "The body is not the expected JSON."))
}

/// `<bucket>/<key>` from the raw path. The key is percent-decoded; the
/// bucket name is used as written.
fn object_target(rest: &str) -> Admin<(&str, String)> {
    let bad = || fail(400, "InvalidArgument", "Expected <bucket>/<key>.");
    let (bucket, raw_key) = rest.split_once('/').ok_or_else(bad)?;
    let key = super::decode_name(raw_key)
        .and_then(|k| String::from_utf8(k).ok())
        .ok_or_else(bad)?;
    if bucket.is_empty() || key.is_empty() {
        return Err(bad());
    }
    Ok((bucket, key))
}

/// Whether the query carries `name=1` or `name=true`.
fn flag(raw_target: &str, name: &str) -> bool {
    let query = raw_target.split_once('?').map_or("", |(_, q)| q);
    query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .any(|(n, v)| n == name && matches!(v, "1" | "true"))
}

/// S3 bucket naming, without dots: 3–63 of `a-z0-9-`, starting and ending
/// with a letter or digit. This also keeps `_admin` out of the namespace.
fn valid_bucket_name(name: &str) -> bool {
    let b = name.as_bytes();
    let edge = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (3..=63).contains(&b.len())
        && b.iter().all(|c| edge(c) || *c == b'-')
        && b.first().is_some_and(edge)
        && b.last().is_some_and(edge)
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub(super) async fn handle<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
    rest: &str,
) -> S3Response {
    if let Err(e) = check_admin_bearer(&req, bridge.cfg.admin_token.expose()) {
        return e.response();
    }
    match route(bridge, req, rest).await {
        Ok(r) | Err(r) => r,
    }
}

async fn route<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
    rest: &str,
) -> Admin<S3Response> {
    let method = req.method.clone();
    let get = method == Method::Get;
    let post = method == Method::Post;
    let wrong_method = || fail(405, "MethodNotAllowed", "Wrong method for this route.");

    if let Some(dev) = rest.strip_prefix("/dev/") {
        // Outside development these routes do not exist.
        if !bridge.cfg.is_dev() {
            return Err(not_found());
        }
        return match dev {
            "guard-selftest" if !post => Err(wrong_method()),
            "guard-selftest" => {
                let rolled_back = bridge.catalog.guard_selftest().await.or_internal()?;
                Ok(ok(&json!({ "rolled_back": rolled_back })))
            }
            _ => Err(not_found()),
        };
    }

    if let Some(target) = rest.strip_prefix("/objects/") {
        if !get {
            return Err(wrong_method());
        }
        let (bucket, key) = object_target(target)?;
        return object_status(bridge, bucket, &key).await;
    }
    if let Some(target) = rest.strip_prefix("/evict/") {
        if !post {
            return Err(wrong_method());
        }
        mutable(bridge)?;
        let (bucket, key) = object_target(target)?;
        let include_safety = flag(&req.raw_target, "include_safety");
        return evict(bridge, bucket, &key, include_safety).await;
    }
    if let Some(target) = rest.strip_prefix("/drill/") {
        if !post {
            return Err(wrong_method());
        }
        mutable(bridge)?;
        let (bucket, key) = object_target(target)?;
        return drill(bridge, bucket, &key).await;
    }

    match rest {
        "/status" if get => status(bridge).await,
        "/buckets" if post => {
            mutable(bridge)?;
            let body: CreateBucketBody = read_json(bridge, req).await?;
            let bucket = create_bucket(bridge, &body.name, body.disposable).await?;
            Ok(ok(&json!({
                "name": bucket.name,
                "disposable": bucket.disposable,
                "created_at": bucket.created_at,
            })))
        }
        "/keys" if post => {
            mutable(bridge)?;
            let body: CreateKeyBody = read_json(bridge, req).await?;
            create_key(bridge, &body).await
        }
        "/status" | "/buckets" | "/keys" => Err(wrong_method()),
        _ => Err(not_found()),
    }
}

/// Refuses a mutation while the catalogue is being restored.
fn mutable<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
) -> Admin<()> {
    match bridge.cfg.maintenance {
        Maintenance::Off => Ok(()),
        Maintenance::Restore => Err(fail(
            503,
            "ServiceUnavailable",
            "Maintenance: no changes are accepted.",
        )),
    }
}

// ---------------------------------------------------------------------------
// Buckets
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBucketBody {
    name: String,
    /// Required: a caller must say what kind of bucket it wants.
    disposable: bool,
}

async fn create_bucket<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    name: &str,
    disposable: bool,
) -> Admin<Bucket> {
    if !valid_bucket_name(name) {
        return Err(fail(
            400,
            "InvalidBucketName",
            "Use 3-63 lower-case letters, digits and hyphens.",
        ));
    }
    // Until catalogue recovery is proven, only data that may be lost is
    // accepted.
    if !disposable && !REAL_DATA_READY {
        return Err(fail(
            403,
            "RealDataNotReady",
            "Only disposable buckets can be created yet.",
        ));
    }
    let mut rng = SystemRng;
    let mut rand = [0u8; 8];
    rng.fill_bytes(&mut rand)
        .map_err(|_| internal(&BridgeError::Crypto("rng")))?;
    let id = BucketId::mint(rand);
    let bdk = DataKey::generate(&mut rng).or_internal()?;
    let (kek_version, wrapped) = wrap_bdk(&bridge.kek, &id, &bdk, &mut rng).or_internal()?;
    let bucket = Bucket {
        id,
        name: name.to_string(),
        owner: ADMIN_PRINCIPAL.to_string(),
        bdk_wrapped: wrapped.to_vec(),
        kek_version,
        disposable,
        created_at: bridge.clock.now(),
    };
    match bridge.catalog.create_bucket(&bucket).await.or_internal()? {
        Guard::Applied(()) => Ok(bucket),
        Guard::Lost => Err(fail(
            409,
            "BucketAlreadyExists",
            "The bucket name is taken.",
        )),
    }
}

/// S3 `PUT /<bucket>`: admin only, so it needs the admin bearer token. It
/// creates a non-disposable bucket, which is refused until real data is
/// allowed. Errors are S3 XML.
pub(super) async fn create_bucket_s3<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
    bucket: &str,
) -> S3Response {
    if check_admin_bearer(&req, bridge.cfg.admin_token.expose()).is_err() {
        return IngressError::AccessDenied.response();
    }
    if mutable(bridge).is_err() {
        return S3Response::error(503, "ServiceUnavailable", "Maintenance.");
    }
    match create_bucket(bridge, bucket, false).await {
        Ok(_) => S3Response {
            status: 200,
            headers: vec![("location".to_string(), format!("/{bucket}"))],
            body: RespBody::Empty,
        },
        Err(r) => match r.status {
            400 => S3Response::error(400, "InvalidBucketName", "The bucket name is not valid."),
            403 => IngressError::AccessDenied.response(),
            409 => S3Response::error(409, "BucketAlreadyExists", "The bucket name is taken."),
            _ => S3Response::error(500, "InternalError", "The request failed."),
        },
    }
}

// ---------------------------------------------------------------------------
// Access keys
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateKeyBody {
    buckets: Vec<String>,
    perm: String,
}

async fn create_key<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    body: &CreateKeyBody,
) -> Admin<S3Response> {
    let perm =
        Perm::parse(&body.perm).ok_or_else(|| fail(400, "InvalidArgument", "perm is rw or ro."))?;
    if body.buckets.is_empty() || body.buckets.len() > MAX_GRANTS {
        return Err(fail(400, "InvalidArgument", "Name 1 to 32 buckets."));
    }
    // Every bucket must exist before anything is written.
    let mut grants: Vec<BucketId> = Vec::with_capacity(body.buckets.len());
    for name in &body.buckets {
        let bucket = bridge.catalog.bucket_by_name(name).await.or_internal()?;
        let id = bucket.ok_or_else(no_bucket)?.id;
        if !grants.contains(&id) {
            grants.push(id);
        }
    }

    let rng_failed = |_| internal(&BridgeError::Crypto("rng"));
    let mut rng = SystemRng;
    let mut id_tail = [0u8; KEY_ID_RANDOM_LEN];
    fill_alphabet(&mut rng, &mut id_tail, KEY_ID_ALPHABET).map_err(rng_failed)?;
    let mut access_key_id = String::from(KEY_ID_PREFIX);
    access_key_id.extend(id_tail.iter().map(|b| char::from(*b)));

    // The only plaintext copies of the secret: this buffer (wiped on
    // drop) and the response body.
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    fill_alphabet(&mut rng, &mut secret[..], SECRET_ALPHABET).map_err(rng_failed)?;
    let (kek_version, secret_wrapped) =
        wrap_secret(&bridge.kek, &access_key_id, &secret[..], &mut rng).or_internal()?;

    let row = AccessKeyRow {
        access_key_id: access_key_id.clone(),
        principal: ADMIN_PRINCIPAL.to_string(),
        secret_wrapped,
        kek_version,
        status: KeyStatus::Active,
        created_at: bridge.clock.now(),
    };
    bridge.catalog.create_access_key(&row).await.or_internal()?;
    // A grant that fails leaves a key row with some of its grants. That
    // key cannot be used: its secret exists only in this buffer and is
    // returned only after every grant is stored. The catalogue has no call
    // to disable or delete a key, so the row stays.
    for bucket in &grants {
        bridge
            .catalog
            .put_grant(&access_key_id, bucket, perm)
            .await
            .or_internal()?;
    }

    // Written by hand so the secret is not copied through a JSON tree.
    // Both values are ASCII letters and digits: nothing to escape.
    let mut out = Vec::with_capacity(64 + access_key_id.len() + SECRET_LEN);
    out.extend_from_slice(b"{\"access_key_id\":\"");
    out.extend_from_slice(access_key_id.as_bytes());
    out.extend_from_slice(b"\",\"secret\":\"");
    out.extend_from_slice(&secret[..]);
    out.extend_from_slice(b"\",\"perm\":\"");
    out.extend_from_slice(perm.as_str().as_bytes());
    out.extend_from_slice(b"\"}");
    Ok(S3Response {
        status: 200,
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("cache-control".to_string(), "no-store".to_string()),
        ],
        body: RespBody::Bytes(out),
    })
}

// ---------------------------------------------------------------------------
// Object status
// ---------------------------------------------------------------------------

async fn bucket_named<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    name: &str,
) -> Admin<Bucket> {
    bridge
        .catalog
        .bucket_by_name(name)
        .await
        .or_internal()?
        .ok_or_else(no_bucket)
}

async fn object_status<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &str,
    key: &str,
) -> Admin<S3Response> {
    let bucket = bucket_named(bridge, bucket).await?;
    let status = bridge
        .catalog
        .object_status(&bucket.id, key)
        .await
        .or_internal()?
        .ok_or_else(no_key)?;
    let mut extents = Vec::with_capacity(status.extents.len());
    for (i, x) in status.extents.iter().enumerate() {
        let cache = if i >= MAX_CACHE_PROBES {
            "unchecked"
        } else if bridge
            .cache
            .head(&x.extent_id.cache_key())
            .await
            .or_internal()?
            .is_some()
        {
            "present"
        } else {
            "absent"
        };
        let backbones: Vec<Value> = x
            .backbones
            .iter()
            .map(|b| {
                json!({
                    "backbone": b.backbone,
                    "provider": b.provider_id,
                    "counts": b.counts,
                    "ok": b.articles_ok,
                    "total": b.articles_total,
                    "at": b.verified_at,
                    "result": b.result,
                    "plan_rev": b.plan_rev,
                })
            })
            .collect();
        extents.push(json!({
            "extent_id": x.extent_id.as_str(),
            "seq": x.seq,
            "stage": x.stage,
            "attempts": x.attempts,
            "safety_state": x.safety_state,
            "last_error": x.last_error,
            "cache": cache,
            "backbones": backbones,
        }));
    }
    let g = &status.generation;
    Ok(ok(&json!({
        "generation": g.id.as_str(),
        "state": g.state,
        "size": g.size,
        "etag": g.etag,
        "created_at": g.created_at,
        "extents": extents,
    })))
}

// ---------------------------------------------------------------------------
// Evict
// ---------------------------------------------------------------------------

/// Deletes an object's cache copies. With `include_safety`, and only in a
/// disposable bucket, it also gives up the pinned copy of every extent
/// that is past the post stage and that a backbone currently holds in
/// full: the catalogue is told first, then the blob goes.
async fn evict<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &str,
    key: &str,
    include_safety: bool,
) -> Admin<S3Response> {
    let bucket = bucket_named(bridge, bucket).await?;
    if include_safety && !bucket.disposable {
        return Err(fail(
            403,
            "SafetyEvictRefused",
            "Only a disposable bucket can give up its pinned copies.",
        ));
    }
    let status = bridge
        .catalog
        .object_status(&bucket.id, key)
        .await
        .or_internal()?
        .ok_or_else(no_key)?;

    // Only a read-back from a backbone that is still configured is
    // evidence, as in the verify stage. Labels compare trimmed and in
    // lower case.
    let label = |b: &str| b.trim().to_lowercase();
    let configured: Vec<String> = bridge
        .cfg
        .providers
        .iter()
        .filter(|p| p.read && p.enabled)
        .map(|p| label(&p.backbone))
        .collect();
    let on_usenet = |x: &crate::types::ExtentStatus| {
        x.backbones
            .iter()
            .any(|b| b.counts && configured.contains(&label(&b.backbone)))
    };

    let (mut evicted, mut safety_deleted, mut safety_kept) = (0u32, 0u32, 0u32);
    for x in &status.extents {
        delete_blob(&bridge.cache, &x.extent_id.cache_key())
            .await
            .or_internal()?;
        evicted += 1;
        if !include_safety {
            continue;
        }
        let gone = match x.safety_state {
            SafetyState::Held => {
                // The post stage reads the pinned copy; without a full
                // copy on a backbone the pinned one is the only one.
                let posted = !matches!(x.stage, None | Some(OutboxStage::Post));
                posted
                    && on_usenet(x)
                    && bridge
                        .catalog
                        .set_safety_state(&x.extent_id, SafetyState::Held, SafetyState::Deleted)
                        .await
                        .or_internal()?
            }
            // A release job is between its decision and its delete.
            SafetyState::Releasing => false,
            // Already given up: the delete only removes a leftover.
            SafetyState::Released | SafetyState::Deleted => true,
        };
        if gone {
            delete_blob(&bridge.safety, &x.extent_id.safety_key())
                .await
                .or_internal()?;
            safety_deleted += 1;
        } else {
            safety_kept += 1;
        }
    }
    Ok(ok(&json!({
        "evicted": evicted,
        "safety_deleted": safety_deleted,
        "safety_kept": safety_kept,
    })))
}

// ---------------------------------------------------------------------------
// Drill
// ---------------------------------------------------------------------------

enum Drilled {
    /// The verified ciphertext and the provider that completed it.
    Read(Vec<u8>, String),
    Busy,
    Unavailable,
}

/// Reads one extent's ciphertext from Usenet only. Neither blob store is
/// read or written.
async fn drill_extent<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    extent: &ExtentRow,
    plan: &[ArticleRow],
) -> crate::types::Result<Drilled> {
    let Ok(size) = usize::try_from(extent.cipher_size) else {
        return Ok(Drilled::Unavailable);
    };
    let spans = article_spans(extent.cipher_size);
    let planned = !plan.is_empty()
        && plan.len() == spans.len()
        && (0u32..).zip(plan).zip(&spans).all(|((idx, row), span)| {
            row.idx == idx
                && row.cipher_offset == span.start
                && row.cipher_len == span.len
                && row.state == ArticleState::Posted
        });
    if !planned {
        return Ok(Drilled::Unavailable);
    }

    let mut cipher = vec![0u8; size];
    let mut have = vec![false; plan.len()];
    let mut busy = false;
    let mut last_provider = String::new();
    let holder = format!("drill:{}", extent.id);
    for provider in bridge.cfg.providers.iter().filter(|p| p.read && p.enabled) {
        let wanted: Vec<&ArticleRow> = plan.iter().filter(|a| !have[a.idx as usize]).collect();
        if wanted.is_empty() {
            break;
        }
        let Some(mut session) = ProviderSession::open(
            &bridge.catalog,
            &bridge.nntp,
            &bridge.clock,
            provider,
            PermitClass::Background,
            &holder,
        )
        .await?
        else {
            busy = true;
            continue;
        };
        let read = read_articles(&mut session, None, &wanted, |row, payload| {
            // Offsets and lengths were checked against the plan above.
            let start = row.cipher_offset as usize;
            cipher[start..start + payload.len()].copy_from_slice(&payload);
            have[row.idx as usize] = true;
        })
        .await;
        session.close().await;
        match read {
            Ok(tally) if tally.ok > 0 => last_provider.clone_from(&provider.id),
            Ok(_) => {}
            Err(Stop::NoPermit | Stop::Cooling(_) | Stop::Fail(..) | Stop::Session(_)) => {
                busy = true;
            }
            Err(Stop::Fenced | Stop::Catalog) => {
                return Err(BridgeError::Sql("catalogue failed during a drill".into()));
            }
        }
    }
    if have.contains(&false) {
        return Ok(if busy {
            Drilled::Busy
        } else {
            Drilled::Unavailable
        });
    }
    let digest: [u8; 32] = Sha256::digest(&cipher).into();
    if digest != extent.cipher_sha256 {
        return Ok(Drilled::Unavailable);
    }
    Ok(Drilled::Read(cipher, last_provider))
}

/// Proves an object can be rebuilt from Usenet alone: every article is
/// read, checked, decrypted and compared with the catalogued digests.
async fn drill<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &str,
    key: &str,
) -> Admin<S3Response> {
    let bucket = bucket_named(bridge, bucket).await?;
    let (generation, extents) = bridge
        .catalog
        .live_object(&bucket.id, key)
        .await
        .or_internal()?
        .ok_or_else(no_key)?;
    let bdk = unwrap_bdk(
        &bridge.kek,
        bucket.kek_version,
        &bucket.id,
        &bucket.bdk_wrapped,
    )
    .or_internal()?;

    let mut whole = Sha256::new();
    let mut articles = 0u64;
    let mut matched = true;
    let mut provider = String::new();
    for extent in &extents {
        // Ciphertext and plaintext of one extent are held together.
        let bytes = extent.cipher_size.saturating_add(extent.plain_size);
        let _charge = bridge.budget.charge(bytes).await.map_err(|_| busy())?;
        let plan = bridge.catalog.articles(&extent.id).await.or_internal()?;
        let (cipher, used) = match drill_extent(bridge, extent, &plan).await.or_internal()? {
            Drilled::Read(cipher, used) => (cipher, used),
            Drilled::Busy => return Err(busy()),
            Drilled::Unavailable => {
                matched = false;
                break;
            }
        };
        articles += plan.len() as u64;
        provider = used;
        let Ok(plain_len) = usize::try_from(extent.plain_size) else {
            matched = false;
            break;
        };
        let mut plain = Zeroizing::new(vec![0u8; plain_len]);
        let opened = open_range(&bdk, &bucket.id, extent, 0, &cipher, 0, &mut plain);
        let digest: [u8; 32] = Sha256::digest(&plain[..]).into();
        if !matches!(opened, Ok(n) if n == plain_len) || digest != extent.plain_sha256 {
            matched = false;
            break;
        }
        whole.update(&plain[..]);
    }
    let plaintext_sha256 = matched.then(|| hex(&whole.finalize()));
    Ok(ok(&json!({
        "source": "nntp",
        "provider": provider,
        "articles": articles,
        "extents": extents.len(),
        "size": generation.size,
        "plaintext_sha256": plaintext_sha256,
        "match": matched,
    })))
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

async fn status<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
) -> Admin<S3Response> {
    let stats = bridge.catalog.outbox_stats().await.or_internal()?;
    let now = bridge.clock.now();
    let load = bridge.catalog.provider_load(now).await.or_internal()?;
    // Identity is `id` and `backbone` only: never a host or a login.
    let providers: Vec<Value> = bridge
        .cfg
        .providers
        .iter()
        .map(|p| {
            let l = load.iter().find(|l| l.provider_id == p.id);
            json!({
                "id": p.id,
                "backbone": p.backbone,
                "priority": p.priority,
                "enabled": p.enabled,
                "held": l.map_or(0, |l| l.held),
                "failures": l.map_or(0, |l| l.failures),
                "cooling": l.is_some_and(|l| l.cooldown_until > now),
                "cooldown_until": l.map_or(0, |l| l.cooldown_until.0),
            })
        })
        .collect();
    let mut outbox = serde_json::Map::new();
    for (stage, n) in &stats.by_stage {
        outbox.insert(stage.as_str().to_string(), json!(n));
    }
    let cfg = &bridge.cfg;
    Ok(ok(&json!({
        "environment": if cfg.is_dev() { "dev" } else { "prod" },
        "maintenance": match cfg.maintenance {
            Maintenance::Off => "off",
            Maintenance::Restore => "restore",
        },
        "gc_mode": match cfg.gc_mode {
            crate::config::GcMode::Off => "off",
            crate::config::GcMode::Disposable => "disposable",
        },
        "real_data_ready": REAL_DATA_READY,
        "required_backbones": cfg.required_backbones,
        // Figures of the isolate that answers; another isolate has its own.
        "inflight_peak_bytes": bridge.budget.peak(),
        "inflight_bytes": bridge.budget.in_use(),
        "inflight_budget_bytes": bridge.budget.capacity(),
        "outbox": outbox,
        "dead": stats.dead,
        "last_dispatch_at": stats.last_dispatch_at,
        "providers": providers,
    })))
}
