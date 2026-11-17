//! `/_admin/*` routes and S3 CreateBucket.
//!
//! Every route checks the admin bearer token first, in constant time, so
//! an unauthenticated caller learns nothing about which routes exist.
//! Every answer, an error too, carries `cache-control: no-store`.
//!
//! | Route | Answer |
//! |---|---|
//! | `POST /_admin/buckets` `{name, disposable}` | `200` (a non-disposable bucket only with `"disposable": false`; `403` for one if `REAL_DATA_READY` is unset); `409` name taken |
//! | `POST /_admin/keys` `{buckets, perm}` | `200` with the secret, once |
//! | `GET /_admin/keys[?after=<id>]` | `200`: ids, status, created time and grants, never a secret; `next` while more follow |
//! | `POST /_admin/keys/<access_key_id>/grants` `{bucket, perm}` | `200` `{access_key_id, bucket, perm}`, widening (`ro` to `rw`) or repeating an earlier grant on that bucket; `409` `GrantNarrowingRefused` for `rw` to `ro`; `404` unknown key or bucket; `400` bad `perm` |
//! | `DELETE /_admin/keys/<access_key_id>` | `204` revoked; `404` unknown (so a second call is `404`) |
//! | `DELETE /_admin/keys/<access_key_id>/grants` | `405`: grants are not removed one by one |
//! | `GET /_admin/objects/<bucket>/<key>` | `200` per-extent state |
//! | `POST /_admin/evict/<bucket>/<key>[?include_safety=1]` | `200`; `403` for `include_safety` on a non-disposable bucket |
//! | `POST /_admin/drill/<bucket>/<key>` | `200` read-back from Usenet only |
//! | `GET /_admin/status` | `200` |
//! | `POST /_admin/restore` `{since_ms[, margin_ms]}` or `{cursor}` | `200` with the counts of one replay step and `next`; `409` unless `MAINTENANCE=restore` |
//! | `POST /_admin/pack-plans[?limit=<n>]` | `200` `{looked, packed, end}`: one step of packing the article plans that are still rows; `409` unless `PACKED_PLANS=on` |
//! | `POST /_admin/dev/guard-selftest` | `200` in dev, `404` otherwise |
//!
//! Secrets: the access key secret exists in the `POST /_admin/keys`
//! response body and nowhere else. No error body carries request data,
//! key material or backend error text.
//!
//! Revocation: `DELETE /_admin/keys/<id>` first stores the recovery
//! record `m/rk/<id>` in `SAFETY`, then deletes the key row (and with it
//! the wrapped secret) and its grants in one batch. Every request looks
//! the key up in the catalogue, so the next one, presigned or not, finds
//! no key. A catalogue export made before the revocation still holds the
//! row: the first step of a restore (`since_ms`) deletes every key that
//! has a revocation record before it replays anything; until then, under
//! `MAINTENANCE=restore`, authentication checks the record itself
//! (`service::common`). Revocation is
//! accepted under maintenance and during a replay, which never touch
//! keys.
//!
//! Grants: `POST /_admin/keys/<id>/grants` lets a client that holds one
//! key and creates buckets grant that key on a new bucket. The write is
//! one statement that stores the grant only while the key row and the
//! bucket row both exist, so a revocation or a bucket deletion that
//! commits around it never leaves an orphaned grant. A grant is never
//! narrowed (`rw` to `ro` answers `409`): the only reduction of a key's
//! access is revocation, which has a recovery record and so survives a
//! restore, where a narrowed grant would silently be wide again. Grants,
//! like keys, are catalogue rows only, never recovery records: a
//! catalogue restored from an export older than a grant does not have
//! it (as it does not have a key minted after the export), a widening
//! (`ro` to `rw`) made after the export is lost the same way, and a
//! replay brings neither back.

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
use crate::fetch::{read_articles, request_holder, ProviderSession};
use crate::ingress::{self, check_admin_bearer, IngressError};
use crate::ports::{
    BlobStore, Bridge, Catalog, Clock, GrantPut, Guard, JobSink, Kek, NntpConnector, PermitClass,
};
use crate::post::Stop;
use crate::recovery::{
    delete_blob, revoked_key_id, valid_key_id, write_key_revocation, REVOKED_KEY_PREFIX,
};
use crate::replay::ReplayCursor;
use crate::types::{
    AccessKeyRow, ArticleRow, ArticleState, Body, BridgeError, Bucket, BucketId, ExtentRow,
    KeyStatus, Method, OutboxStage, Perm, ProviderLoad, RespBody, S3Request, S3Response,
    SafetyState,
};

/// Largest admin request body.
const MAX_BODY_BYTES: u64 = 64 * 1024;
/// Buckets one access key can be granted in one request.
const MAX_GRANTS: usize = 32;
/// Extents whose cache presence one status request looks up.
const MAX_CACHE_PROBES: usize = 200;
/// Keys one `GET /_admin/keys` lists.
const KEY_PAGE: u32 = 500;
/// Revocation records one listing call reads during a restore.
const REVOCATION_PAGE: u32 = 500;
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

fn no_access_key() -> S3Response {
    fail(404, "NoSuchAccessKey", "The access key does not exist.")
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

/// The value of `name` in the query, if it is there.
fn query_param<'a>(raw_target: &'a str, name: &str) -> Option<&'a str> {
    let query = raw_target.split_once('?').map_or("", |(_, q)| q);
    query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find_map(|(n, v)| (n == name).then_some(v))
}

/// Most extents one `POST /_admin/pack-plans` looks at.
const MAX_PACK_LIMIT: u32 = 500;

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
    let mut resp = match check_admin_bearer(&req, bridge.cfg.admin_token.expose()) {
        Err(e) => e.response(),
        Ok(_) => match route(bridge, req, rest).await {
            Ok(r) | Err(r) => r,
        },
    };
    // No admin answer, error or not, belongs in a cache. The Worker's
    // own refusals before this point get it from `ingress::front`.
    ingress::no_store(&mut resp);
    resp
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
        mutable(bridge).await?;
        let (bucket, key) = object_target(target)?;
        let include_safety = flag(&req.raw_target, "include_safety");
        return evict(bridge, bucket, &key, include_safety).await;
    }
    if let Some(akid) = rest.strip_prefix("/keys/") {
        if let Some(akid) = akid.strip_suffix("/grants") {
            if !post {
                return Err(wrong_method());
            }
            mutable(bridge).await?;
            // An id that could not have been minted names no key; it
            // never reaches the catalogue.
            if !valid_key_id(akid) {
                return Err(no_access_key());
            }
            let body: GrantBody = read_json(bridge, req).await?;
            return put_grant(bridge, akid, &body).await;
        }
        if method != Method::Delete {
            return Err(wrong_method());
        }
        return revoke_key(bridge, akid).await;
    }
    if let Some(target) = rest.strip_prefix("/drill/") {
        if !post {
            return Err(wrong_method());
        }
        mutable(bridge).await?;
        let (bucket, key) = object_target(target)?;
        return drill(bridge, bucket, &key).await;
    }

    match rest {
        "/status" if get => status(bridge).await,
        "/buckets" if post => {
            mutable(bridge).await?;
            let body: CreateBucketBody = read_json(bridge, req).await?;
            let bucket = create_bucket(bridge, &body.name, body.disposable).await?;
            Ok(ok(&json!({
                "name": bucket.name,
                "disposable": bucket.disposable,
                "created_at": bucket.created_at,
            })))
        }
        "/keys" if post => {
            mutable(bridge).await?;
            let body: CreateKeyBody = read_json(bridge, req).await?;
            create_key(bridge, &body).await
        }
        "/keys" if get => list_keys(bridge, &req.raw_target).await,
        "/pack-plans" if post => {
            mutable(bridge).await?;
            // Not before every Worker reads a packed plan.
            if !bridge.cfg.packed_plans {
                return Err(fail(
                    409,
                    "PackedPlansOff",
                    "Article plans are packed only while PACKED_PLANS is on.",
                ));
            }
            let limit = query_param(&req.raw_target, "limit")
                .map(|v| v.parse::<u32>())
                .transpose()
                .map_err(|_| fail(400, "InvalidArgument", "limit must be a number."))?
                .unwrap_or(crate::jobs::PACK_LIMIT)
                .clamp(1, MAX_PACK_LIMIT);
            let report = bridge.catalog.pack_plans(limit).await.or_internal()?;
            Ok(ok(&json!(report)))
        }
        "/restore" if post => {
            // The one mutation maintenance allows, and only maintenance.
            if bridge.cfg.maintenance != Maintenance::Restore {
                return Err(fail(
                    409,
                    "NotInMaintenance",
                    "A restore runs only while MAINTENANCE=restore.",
                ));
            }
            let body: RestoreBody = read_json(bridge, req).await?;
            restore(bridge, body).await
        }
        "/status" | "/buckets" | "/keys" | "/restore" | "/pack-plans" => Err(wrong_method()),
        _ => Err(not_found()),
    }
}

/// Refuses a mutation while the catalogue is being restored: under
/// maintenance, and until a replay that was started has ended.
async fn mutable<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
) -> Admin<()> {
    if bridge.cfg.maintenance == Maintenance::Restore {
        return Err(fail(
            503,
            "ServiceUnavailable",
            "Maintenance: no changes are accepted.",
        ));
    }
    if bridge.catalog.restore_pending().await.or_internal()? {
        return Err(fail(
            503,
            "ServiceUnavailable",
            "A replay of the recovery records is not finished: no changes are accepted.",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

/// Records minted this long before the restore point are replayed too: a
/// request mints its generation id before it commits, so a record older
/// than a catalogue export can belong to a commit newer than it.
const RESTORE_MARGIN_MS: i64 = 60 * 60 * 1000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreBody {
    /// First call: the restore point (the time of the catalogue export
    /// that was loaded; `0` replays every record).
    since_ms: Option<i64>,
    margin_ms: Option<i64>,
    /// Later calls: `next` of the previous response.
    cursor: Option<ReplayCursor>,
}

/// One bounded replay step. The caller repeats it with `next` until
/// `next` is null.
async fn restore<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    body: RestoreBody,
) -> Admin<S3Response> {
    let bad = || fail(400, "InvalidArgument", "Send since_ms or cursor.");
    let earlier = || {
        fail(
            409,
            "OperationAborted",
            "This cursor is of an earlier replay. The replay that was started last is not finished.",
        )
    };
    let cursor = match (body.cursor, body.since_ms) {
        (Some(cursor), None) if body.margin_ms.is_none() => {
            // The catalogue knows how far the replay has come. A cursor
            // that is ahead of it (made up, or of another restore
            // point) would end the replay with records left out.
            let progress = bridge
                .catalog
                .restore_progress(crate::types::UnixMs(cursor.run_ms))
                .await
                .or_internal()?
                .ok_or_else(earlier)?;
            if !cursor.follows(&progress) {
                return Err(fail(
                    400,
                    "InvalidArgument",
                    "This cursor is ahead of the replay. Send `next` of the last response.",
                ));
            }
            cursor
        }
        (None, Some(since)) if since >= 0 => {
            let margin = body.margin_ms.unwrap_or(RESTORE_MARGIN_MS);
            if margin < 0 {
                return Err(bad());
            }
            let from = crate::types::UnixMs(since.saturating_sub(margin).max(0));
            // Before anything else: the catalogue may come from an
            // export that still holds keys revoked since.
            forget_revoked_keys(bridge).await.or_internal()?;
            // From here until the last step, the catalogue refuses
            // writes, whatever MAINTENANCE says.
            let run = bridge
                .catalog
                .restore_begin(from, bridge.clock.now())
                .await
                .or_internal()?
                .map_err(|unfinished| {
                    // The catalogue holds the records up to that point
                    // at most, whatever was restored since.
                    json_response(
                        409,
                        &json!({
                            "error": "OperationAborted",
                            "message": "A replay from an earlier restore point is not finished. Start no later than it: send the since_ms of unfinished_since_ms with margin_ms 0, or an earlier since_ms.",
                            "unfinished_since_ms": unfinished.0,
                        }),
                    )
                })?;
            ReplayCursor {
                run_ms: run.0,
                ..ReplayCursor::start(from)
            }
        }
        _ => return Err(bad()),
    };
    let run = crate::types::UnixMs(cursor.run_ms);
    let report = bridge.replay_step(cursor).await.or_internal()?;
    match &report.next {
        // Recorded before the caller gets it: the next call may start
        // from here and no further.
        Some(next) => bridge
            .catalog
            .restore_advance(run, &next.mark())
            .await
            .or_internal()?,
        // Only the replay that is recorded as under way is ended: the
        // last step of an older cursor must not open the catalogue for
        // writes while a replay that was started after it still runs.
        None => {
            let rolled_back = || {
                fail(
                    409,
                    "OperationAborted",
                    "The catalogue was rolled back after this replay started. Start a new replay with since_ms.",
                )
            };
            // Not if the catalogue is behind a stamp that was raised
            // after this replay started: it was rolled back since, and
            // this replay does not hold what was written before that.
            let (stamp, seen) = bridge
                .stamp_level(run)
                .await
                .or_internal()?
                .ok_or_else(rolled_back)?;
            // The catalogue holds every record again: its stamp counter
            // is brought level with the newest stamp object.
            if !bridge
                .catalog
                .restore_finish(
                    run,
                    bridge.clock.now(),
                    stamp,
                    seen,
                    &bridge.cfg.catalogue_id,
                )
                .await
                .or_internal()?
            {
                return Err(earlier());
            }
            // The last step of a replay that had ended before, sent
            // again: it changed nothing. If the catalogue was rolled
            // back since, that replay does not cover it.
            if bridge.stamp_row().await.or_internal()?.rolled_back {
                return Err(rolled_back());
            }
        }
    }
    let value = serde_json::to_value(&report)
        .map_err(|_| fail(500, "InternalError", "The report could not be encoded."))?;
    Ok(ok(&value))
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
    // With the gate closed, only data that may be lost is accepted.
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
/// creates a non-disposable bucket (refused only if `REAL_DATA_READY` is
/// unset). Errors are S3 XML.
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
    if mutable(bridge).await.is_err() {
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

/// S3 `DELETE /<bucket>`: admin only, like [`create_bucket_s3`], so it
/// needs the admin bearer token. The bucket and its grants go only while
/// nothing of the bucket is on record ([`Catalog::delete_bucket`]); any
/// other bucket is `409 BucketNotEmpty`. Errors are S3 XML.
///
/// Unlike the other admin mutations it is accepted under
/// `MAINTENANCE=restore`, once no replay is unfinished: an operator who
/// has to remove a stale bucket between two replays does it while no
/// client can write into that bucket. It is refused while a replay is
/// under way, or due because the restore was armed or the rollback stamp
/// found the catalogue set back, here and again in the catalogue batch:
/// the records not yet read may name the bucket. A restored catalogue
/// that is neither armed nor found out yet is not known to be one: there
/// a bucket that looks empty goes with its grants, and the replay makes
/// it again from its records, without the grants.
pub(super) async fn delete_bucket_s3<
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
    let failed = || S3Response::error(500, "InternalError", "The request failed.");
    match bridge.catalog.restore_pending().await {
        Ok(false) => {}
        Ok(true) => {
            return S3Response::error(
                503,
                "ServiceUnavailable",
                "A replay of the recovery records is not finished.",
            )
        }
        Err(_) => return failed(),
    }
    let found = match bridge.catalog.bucket_by_name(bucket).await {
        Ok(Some(found)) => found,
        Ok(None) => {
            return S3Response::error(404, "NoSuchBucket", "The specified bucket does not exist.")
        }
        Err(_) => return failed(),
    };
    match bridge.catalog.delete_bucket(&found).await {
        Ok(Guard::Applied(())) => S3Response {
            status: 204,
            headers: Vec::new(),
            body: RespBody::Empty,
        },
        // In use, or deleted by another request in between; a retry of
        // the latter is `NoSuchBucket`.
        Ok(Guard::Lost) => super::bucket::bucket_not_empty(),
        Err(_) => failed(),
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
    // returned only after every grant is stored. The row stays until
    // `DELETE /_admin/keys/<id>` removes it (`GET /_admin/keys` lists it).
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

/// `GET /_admin/keys[?after=<id>]`: one page of keys in id order. No
/// column of the secret is read.
async fn list_keys<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    raw_target: &str,
) -> Admin<S3Response> {
    let bad = || fail(400, "InvalidArgument", "after is an access key id.");
    let query = raw_target.split_once('?').map_or("", |(_, q)| q);
    let mut after = String::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some(("after", v)) if valid_key_id(v) => v.clone_into(&mut after),
            _ => return Err(bad()),
        }
    }
    let keys = bridge
        .catalog
        .list_access_keys(&after, KEY_PAGE)
        .await
        .or_internal()?;
    let next = (keys.len() >= KEY_PAGE as usize)
        .then(|| keys.last().map(|k| k.access_key_id.clone()))
        .flatten();
    let keys: Vec<Value> = keys
        .iter()
        .map(|k| {
            json!({
                "access_key_id": k.access_key_id,
                "status": k.status.as_str(),
                "created_at": k.created_at.0,
                "grants": k.grants.iter().map(|(bucket, perm)| json!({
                    "bucket": bucket,
                    "perm": perm.as_str(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut resp = ok(&json!({ "keys": keys, "next": next }));
    resp.headers
        .push(("cache-control".to_string(), "no-store".to_string()));
    Ok(resp)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantBody {
    bucket: String,
    perm: String,
}

/// `POST /_admin/keys/<id>/grants`: sets the key's permission on one
/// more bucket, or widens or repeats its grant on one it has; never
/// narrows it. The key id was checked by the router. The catalogue writes the grant only while the key and the
/// bucket both exist ([`Catalog::put_grant_if_present`]).
async fn put_grant<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    akid: &str,
    body: &GrantBody,
) -> Admin<S3Response> {
    let perm =
        Perm::parse(&body.perm).ok_or_else(|| fail(400, "InvalidArgument", "perm is rw or ro."))?;
    let bucket = bridge
        .catalog
        .bucket_by_name(&body.bucket)
        .await
        .or_internal()?
        .ok_or_else(no_bucket)?;
    match bridge
        .catalog
        .put_grant_if_present(akid, &bucket.id, perm)
        .await
        .or_internal()?
    {
        GrantPut::Applied => {}
        // A restore from an export older than the call would silently
        // widen it again; revocation is the one reduction that survives.
        GrantPut::Narrowing => {
            return Err(fail(
                409,
                "GrantNarrowingRefused",
                "A grant is never narrowed: revoke the key and mint a new one.",
            ));
        }
        // The key or the bucket is gone (or never was); say which.
        GrantPut::Lost => {
            return Err(
                if bridge.catalog.access_key_exists(akid).await.or_internal()? {
                    no_bucket()
                } else {
                    no_access_key()
                },
            );
        }
    }
    let mut resp = ok(&json!({
        "access_key_id": akid,
        "bucket": bucket.name,
        "perm": perm.as_str(),
    }));
    resp.headers
        .push(("cache-control".to_string(), "no-store".to_string()));
    Ok(resp)
}

/// `DELETE /_admin/keys/<id>`: the record first, then the rows. A
/// failure between the two leaves the key usable and the record stored;
/// the call is repeated and then finds the key again.
async fn revoke_key<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    akid: &str,
) -> Admin<S3Response> {
    // An id that could not have been minted names no key; it reaches
    // neither the catalogue nor a blob name.
    if !valid_key_id(akid) {
        return Err(no_access_key());
    }
    if !bridge.catalog.access_key_exists(akid).await.or_internal()? {
        return Err(no_access_key());
    }
    write_key_revocation(&bridge.safety, &bridge.kek, akid, bridge.clock.now())
        .await
        .or_internal()?;
    bridge
        .catalog
        .delete_access_keys(&[akid.to_string()])
        .await
        .or_internal()?;
    Ok(S3Response {
        status: 204,
        headers: vec![("cache-control".to_string(), "no-store".to_string())],
        body: RespBody::Bytes(Vec::new()),
    })
}

/// Deletes every key that has a revocation record, a page of records
/// per catalogue batch. Idempotent: a key that is not there is skipped.
async fn forget_revoked_keys<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Bridge<C, B, N, J, K, T>,
) -> crate::types::Result<u64> {
    let mut after = REVOKED_KEY_PREFIX.to_string();
    let mut forgotten = 0;
    loop {
        let names = bridge
            .safety
            .list(REVOKED_KEY_PREFIX, &after, REVOCATION_PAGE)
            .await?;
        // A name that is no key id cannot name a catalogue row.
        let ids: Vec<String> = names
            .iter()
            .filter_map(|n| revoked_key_id(n))
            .map(str::to_string)
            .collect();
        forgotten += bridge.catalog.delete_access_keys(&ids).await?;
        match names.last() {
            Some(last) if names.len() >= REVOCATION_PAGE as usize => last.clone_into(&mut after),
            _ => return Ok(forgotten),
        }
    }
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
                    "kind": b.kind,
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

    // Only a read-back from a backbone that counts toward a release is
    // evidence, as in the verify stage: a `STAT` pass is not one. Labels
    // compare trimmed and in lower case.
    let label = |b: &str| b.trim().to_lowercase();
    let configured = crate::verify::release_labels(&bridge.cfg.providers);
    // With too few backbones that count, no pinned copy is given up.
    let paused = bridge.cfg.release_paused().is_some();
    let on_usenet = |x: &crate::types::ExtentStatus| {
        !paused
            && x.backbones.iter().any(|b| {
                b.counts
                    && b.kind == crate::types::VerifyKind::Body
                    && configured.contains(&label(&b.backbone))
            })
    };

    let (mut evicted, mut safety_deleted, mut safety_kept) = (0u32, 0u32, 0u32);
    for x in &status.extents {
        // Read before any delete: a cold read that fills the cache while
        // this runs changes it, and its copy then stays counted.
        let seq = bridge.catalog.hot_seq(&x.extent_id).await.or_internal()?;
        delete_blob(&bridge.cache, &x.extent_id.cache_key())
            .await
            .or_internal()?;
        evicted += 1;
        // The deleted copies leave the hot-tier count.
        let forget = |seq: u64, safety: bool| async move {
            let done = bridge.catalog.hot_forget(&x.extent_id, seq, safety, true);
            done.await.or_internal().map(|_| ())
        };
        if !include_safety {
            forget(seq, false).await?;
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
            // A release job is between its decision and its end.
            SafetyState::Releasing => false,
            // No longer pinned: the copy is only cache (a released one
            // still serves reads until it is evicted).
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
        // Giving up a held copy changed the state, which bumped the
        // token once: that bump is this request's own.
        let own_bump = u64::from(gone && x.safety_state == SafetyState::Held);
        forget(seq + own_bump, gone).await?;
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
    let holder = request_holder("drill")?;
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
            // A drill runs inside a request, as a read does: the short
            // permit and the short calls of one.
            PermitClass::Read,
            &holder,
        )
        .await?
        .map(|s| s.with_timer(bridge.budget.sleeper())) else {
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
            Err(
                Stop::NoPermit
                | Stop::Refused
                | Stop::Cooling(_)
                | Stop::Fail(..)
                | Stop::Session(_),
            ) => {
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
    let replaying = bridge.catalog.restore_pending().await.or_internal()?;
    // A stamp row of another catalogue id is said, not failed on: this
    // is where the operator looks for it.
    let (rolled_back, id_mismatch) = match bridge.stamp_row().await {
        Ok(row) => (Some(row.rolled_back), false),
        Err(e) if crate::stamp::is_catalogue_id_error(&e) => (None, true),
        Err(e) => return Err(internal(&e)),
    };
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
                // Whether the provider lets its backbone count toward a
                // release (one `false` speaks for the whole backbone).
                "release": p.release,
                "max_conns": p.max_conns,
                // `null` = no address limit: `max_conns` alone.
                "max_ips": p.max_ips,
                // How connections leave: through one of the provider's
                // proxies (never around them), or directly.
                "route": if p.proxies.is_empty() { "direct" } else { "proxy" },
                "held": l.map_or(0, |l| l.held),
                "holders": l.map_or(0, |l| l.holders),
                "failures": l.map_or(0, |l| l.failures),
                "cooling": l.is_some_and(|l| l.cooldown_until > now),
                "cooldown_until": l.map_or(0, |l| l.cooldown_until.0),
                // `false` from the first strike until a good session;
                // `reason` says why the last strike was one (a code,
                // never the provider's words).
                "healthy": l.is_none_or(ProviderLoad::healthy),
                "reason": l.and_then(|l| l.fault),
            })
        })
        .collect();
    let mut outbox = serde_json::Map::new();
    for (stage, n) in &stats.by_stage {
        outbox.insert(stage.as_str().to_string(), json!(n));
    }
    let hot = bridge.catalog.hot_stats().await.or_internal()?;
    let intents = bridge
        .catalog
        .intent_stats(crate::intents::open_before(now))
        .await
        .or_internal()?;
    let cfg = &bridge.cfg;
    Ok(ok(&json!({
        // Slices of large PUTs that never became an object. `kept` rows
        // sit beside a generation record and are never deleted by the
        // sweep; `waiting` writes are past the grace period and are
        // leaked safety bytes until the sweep (`sweep`) removes them.
        "write_intents": {
            "sweep": if cfg.intent_sweep { "on" } else { "off" },
            "open_writes": intents.open_writes,
            "waiting_writes": intents.waiting_writes,
            "oldest_waiting_at": intents.oldest_waiting_at.map(|t| t.0),
            "kept_writes": intents.kept_writes,
            "kept_slices": intents.kept_slices,
            "oldest_kept_at": intents.oldest_kept_at.map(|t| t.0),
            "anomalies": intents.anomalies,
        },
        // R2 as a hot tier. Pinned bytes are safety copies not yet
        // released; they are never evicted and are outside the cap.
        "hot": {
            "pinned_bytes": hot.pinned_bytes,
            "pinned_extents": hot.pinned_extents,
            "evictable_bytes": hot.evictable_bytes,
            "evictable_extents": hot.evictable_extents,
            "cap_bytes": cfg.hot_cap_bytes,
            "low_watermark_bytes": crate::jobs::low_watermark(cfg.hot_cap_bytes),
        },
        "environment": if cfg.is_dev() { "dev" } else { "prod" },
        "maintenance": match cfg.maintenance {
            Maintenance::Off => "off",
            Maintenance::Restore => "restore",
        },
        // A replay was started and did not end, or the catalogue was
        // found behind its rollback stamp: writes are refused.
        "replay_unfinished": replaying,
        // `null` = not known: see `catalogue_id_mismatch`.
        "catalogue_rolled_back": rolled_back,
        // `CATALOGUE_ID` is not the id this catalogue's stamp was raised
        // under: no stamp is raised and no job runs until it is put right.
        "catalogue_id_mismatch": id_mismatch,
        "gc_mode": match cfg.gc_mode {
            crate::config::GcMode::Off => "off",
            crate::config::GcMode::Disposable => "disposable",
        },
        "real_data_ready": REAL_DATA_READY,
        "required_backbones": cfg.required_backbones,
        // Empty unless the configuration needs attention. While a
        // "release paused" line is here, nothing is released.
        "config_warnings": cfg.release_paused().into_iter().collect::<Vec<_>>(),
        // Figures of the isolate that answers; another isolate has its own.
        "inflight_peak_bytes": bridge.budget.peak(),
        "inflight_bytes": bridge.budget.in_use(),
        "inflight_budget_bytes": bridge.budget.capacity(),
        "job_budget_bytes": bridge.budget.job_capacity(),
        "outbox": outbox,
        "dead": stats.dead,
        "last_dispatch_at": stats.last_dispatch_at,
        "providers": providers,
    })))
}
