//! DeleteObject and DeleteObjects: retire the live generation of a key.
//! Idempotent, so a key that does not exist is deleted too (`204`, or a
//! `Deleted` entry).
//!
//! There is one delete of a key: the gate against a replay, the ids of
//! the key, the tombstone record, then the guarded catalogue batch.
//! DeleteObject runs it for the key in the path ([`delete_key`]).
//! DeleteObjects runs the same steps for the keys of its body, a chunk
//! of keys at a time ([`delete_chunk`]): each step is one catalogue call
//! for the whole chunk instead of one per key, and the tombstone of
//! every key is on record before the batch that deletes it. A key whose
//! turn in the chunk did not settle it (another request is at work on
//! it) goes on alone, on the path of a DeleteObject. A DeleteObjects
//! request of N keys leaves what N DeleteObject requests leave.
//!
//! A DeleteObject with `If-Match` takes [`delete_key_if`]: it deletes
//! only the object the condition names, which the batch that deletes
//! checks itself, and answers `412` or `404` otherwise. DeleteObjects
//! takes no condition, in a header or per key: `501`.

use std::collections::HashMap;
use std::rc::Rc;

use futures_util::stream::{self, StreamExt};
use velmora::rng::{FillRandom, SystemRng};
use velmora_s3_proto::mutation::{delete_result, parse_delete, DeleteOutcome};
use velmora_s3_proto::{storable_key, ChecksumAlgorithm, ErrorCode, UploadValidator};

use super::common::{
    authenticate, check_precondition, conditional_gate, internal, mutation_gate, policy_with,
    restore_gate, s3_error, writes_refused,
};
use crate::ingress::{read_upload, upload_lengths, UploadReadError};
use crate::keepalive::Deferred;
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::recovery::{tombstone_id, write_tombstone, write_tombstones, NewTombstone};
use crate::types::{Bucket, GenerationId, Precondition, RespBody, S3Request, S3Response, UnixMs};

/// Most keys one DeleteObjects request may name (the S3 limit).
pub const MAX_DELETE_KEYS: usize = 1000;
pub use crate::ingress::MAX_DELETE_BODY_BYTES;
/// Most keys of one DeleteObjects request that share their catalogue
/// calls: about seven statements a key in the batch that deletes.
const DELETE_CHUNK_KEYS: usize = 50;
/// Most bytes of key text in such a chunk, whatever the number of keys.
/// A key is bound several times in a batch; this keeps one batch of the
/// longest keys in the low hundreds of kilobytes.
const DELETE_CHUNK_KEY_BYTES: usize = 32 * 1024;
/// Chunks of one DeleteObjects request that are at work at the same
/// time. Their keys are different ones, so they do not wait for each
/// other; while one waits for the catalogue, the tombstones of the
/// others are on their way to the store.
const DELETE_CHUNKS: usize = 4;
/// Keys of one chunk that go on alone at the same time, when the batch
/// of the chunk deleted nothing. Each is a handful of catalogue and
/// store calls in sequence.
const DELETE_CONCURRENCY: usize = 6;

/// Why one key was not deleted.
#[derive(Clone, Copy)]
enum DeleteError {
    /// Catalogue, store or RNG failure.
    Internal,
    /// A replay of the recovery records is under way, or started while
    /// the delete ran: nothing was deleted.
    Refused,
    /// The key took a newer id every time the delete was tried.
    Busy,
}

impl DeleteError {
    fn response(&self) -> S3Response {
        match self {
            DeleteError::Internal => internal(),
            DeleteError::Refused => writes_refused(),
            DeleteError::Busy => s3_error(ErrorCode::SlowDown),
        }
    }

    /// The same two answers as an entry of a `DeleteResult`.
    fn outcome(&self) -> DeleteOutcome {
        match self {
            DeleteError::Internal => DeleteOutcome::Failed {
                code: "InternalError",
                message: "We encountered an internal error. Please try again.",
            },
            DeleteError::Refused => DeleteOutcome::Failed {
                code: "ServiceUnavailable",
                message: "Writes are refused until the catalogue has been restored. \
                          Please try again later.",
            },
            DeleteError::Busy => DeleteOutcome::Failed {
                code: "SlowDown",
                message: "Please reduce your request rate.",
            },
        }
    }
}

pub(super) async fn delete_object<
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
    match delete(bridge, req).await {
        Ok(resp) | Err(resp) => resp,
    }
}

async fn delete<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> Result<S3Response, S3Response> {
    let authed = authenticate(bridge, &req).await?;
    let (bucket, key) = authed.object()?;
    match conditional_gate(&bridge.cfg, &authed.headers, bucket)? {
        None => delete_key(bridge, bucket, key)
            .await
            .map_err(|e| e.response())?,
        // A delete is conditional on the object it deletes only.
        Some(Precondition::Absent) => return Err(S3Response::not_implemented()),
        Some(condition) => delete_key_if(bridge, bucket, key, &condition).await?,
    }
    Ok(S3Response {
        status: 204,
        headers: Vec::new(),
        body: RespBody::Empty,
    })
}

/// Deletes `key` of `bucket` for a request that is authorized to write
/// the bucket and passed [`mutation_gate`]. `Ok` = the delete is the
/// newest thing that happened to the key: nothing is live on it, and
/// every write that comes takes an id after the tombstone.
///
/// A delete that finds a newer id on the key than its tombstone (a
/// write that began, or was published, after the tombstone was chosen)
/// changes nothing and starts again above that id. Its tombstone would
/// not cover that write in a replay, and a write that is held to the
/// object this delete removes (`If-Match`) must not be published beside
/// it: neither here nor by a replay of its record.
async fn delete_key<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    key: &str,
) -> Result<(), DeleteError> {
    delete_key_in(bridge, bucket, key, DELETE_ATTEMPTS).await
}

/// [`delete_key`] with `attempts` attempts left.
async fn delete_key_in<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    key: &str,
    attempts: usize,
) -> Result<(), DeleteError> {
    for _ in 0..attempts {
        if delete_key_once(bridge, bucket, key).await? {
            return Ok(());
        }
    }
    Err(DeleteError::Busy)
}

/// One attempt of [`delete_key`]. `false` = the key took a newer id
/// than the tombstone of this attempt, and nothing was changed.
async fn delete_key_once<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    key: &str,
) -> Result<bool, DeleteError> {
    let failed = |_| DeleteError::Internal;
    if bridge.catalog.restore_pending().await.map_err(failed)? {
        return Err(DeleteError::Refused);
    }
    // The generation row alone: a delete needs the id, and the extents
    // of a large object are many rows.
    let live = bridge
        .catalog
        .live_generation(&bucket.id, key)
        .await
        .map_err(failed)?;
    let seen = match live {
        Some(live) => live.id,
        // Nothing live. A write that was not published may still have
        // its record (its batch failed, or the record could not be
        // removed): a replay would publish it, over this delete. The
        // floor of the key says so, and then the delete leaves a
        // tombstone as if the object were live. Otherwise there is
        // nothing to delete and nothing to record.
        None => match bridge
            .catalog
            .unpublished_floor(&bucket.id, key)
            .await
            .map_err(failed)?
        {
            Some(floor) => floor,
            None => return Ok(true),
        },
    };
    // The newest id on the key: the live generation, or a floor above
    // it, left by the record of a write or a delete that did not commit.
    // The tombstone sorts after that record too, so a replay cannot
    // apply it over this delete.
    let newest = bridge
        .catalog
        .newest_id(&bucket.id, key)
        .await
        .map_err(failed)?
        .map_or(seen.clone(), |n| n.max(seen.clone()));
    let now = bridge.clock.now();
    let mut rand = [0u8; 8];
    SystemRng
        .fill_bytes(&mut rand)
        .map_err(|_| DeleteError::Internal)?;
    // The tombstone is durable before the catalogue batch, so an
    // acknowledged delete stays deleted in a restored catalogue. It
    // covers every generation older than itself. The floor of the key
    // is raised to the tombstone before the record is stored: when the
    // batch below finds nothing left to delete (another delete was
    // faster), the record stays, and every later write sorts after it.
    let tombstone = tombstone_id(now, &newest, rand);
    write_tombstone(
        &bridge.catalog,
        &bridge.safety,
        &bridge.sealer(),
        &bridge.cfg.records,
        &bucket.id,
        key,
        &tombstone,
        now,
    )
    .await
    .map_err(failed)?;
    commit_delete(bridge, bucket, key, &tombstone, now).await
}

/// The end of one attempt: the batch that deletes `key` under its
/// `tombstone`, which is on record, and what it means when the batch
/// changed nothing. `false` as [`delete_key_once`].
async fn commit_delete<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    key: &str,
    tombstone: &GenerationId,
    now: UnixMs,
) -> Result<bool, DeleteError> {
    let failed = |_| DeleteError::Internal;
    let deleted = bridge
        .catalog
        .delete_object_before(&bucket.id, key, tombstone, now)
        .await
        .map_err(failed)?;
    if deleted {
        return Ok(true);
    }
    // Nothing was changed. A replay started after this request passed
    // the gate: the delete was not done.
    if bridge.catalog.restore_pending().await.map_err(failed)? {
        return Err(DeleteError::Refused);
    }
    // Or the key has an id above the tombstone, of a write that is
    // published or on its way: the next attempt sorts after it.
    let newest = bridge
        .catalog
        .newest_id(&bucket.id, key)
        .await
        .map_err(failed)?;
    if newest.is_some_and(|n| n > *tombstone) {
        return Ok(false);
    }
    // Or nothing older than the tombstone was live any more (another
    // delete was faster), and the delete holds.
    let live = bridge
        .catalog
        .live_generation(&bucket.id, key)
        .await
        .map_err(failed)?;
    match live {
        Some(live) if live.id < *tombstone => Err(DeleteError::Refused),
        _ => Ok(true),
    }
}

/// The first attempt of [`delete_key`] for every key of `keys` (each
/// key once), with one catalogue call a step for all of them, and the
/// later attempts of the keys that need one. The answers are in the
/// order of `keys`.
///
/// Every key goes through the steps of [`delete_key_once`] in their
/// order: the gate, its ids, its floor, its tombstone record, the mark
/// on the floor, the batch. A step before the batch that is one call
/// here fails for all keys that take it, as it fails for the key of a
/// DeleteObject: they answer `InternalError` and nothing further is done
/// for them. The batch deletes all keys that have a live object, or
/// none. When it deletes none (one of them is held up by a newer id,
/// another delete or a replay), each key takes the rest of its attempt
/// alone, under the tombstone it has, and its later attempts. When the
/// batch is not answered, each key takes the rest of its attempt alone
/// and no later one ([`after_unanswered`]).
async fn delete_chunk<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    keys: &[&str],
) -> Vec<Result<(), DeleteError>> {
    let all = |e: DeleteError| keys.iter().map(|_| Err(e)).collect::<Vec<_>>();
    match bridge.catalog.restore_pending().await {
        Ok(false) => {}
        Ok(true) => return all(DeleteError::Refused),
        Err(_) => return all(DeleteError::Internal),
    }
    let Ok(heads) = bridge.catalog.key_heads(&bucket.id, keys).await else {
        return all(DeleteError::Internal);
    };
    if heads.len() != keys.len() {
        return all(DeleteError::Internal);
    }
    // `Ok` until a step says otherwise.
    let mut done: Vec<Result<(), DeleteError>> = vec![Ok(()); keys.len()];
    // The keys that need a tombstone: the place of each in `keys`,
    // whether it has a live object, and its tombstone.
    let mut places = Vec::new();
    let mut tombstones = Vec::new();
    for (place, (key, head)) in keys.iter().zip(heads).enumerate() {
        // Nothing live and no record a replay would publish: nothing to
        // delete and nothing to record (see `delete_key_once`).
        if head.live.is_none() && !head.unpublished {
            continue;
        }
        let live = head.live.is_some();
        // The live generation, or a floor above it.
        let Some(newest) = head.live.max(head.floor) else {
            done[place] = Err(DeleteError::Internal);
            continue;
        };
        let now = bridge.clock.now();
        let mut rand = [0u8; 8];
        if SystemRng.fill_bytes(&mut rand).is_err() {
            done[place] = Err(DeleteError::Internal);
            continue;
        }
        places.push((place, live));
        tombstones.push(NewTombstone {
            key,
            id: tombstone_id(now, &newest, rand),
            now,
        });
    }
    // Every tombstone is durable before the batch below.
    let stored = match write_tombstones(
        &bridge.catalog,
        &bridge.safety,
        &bridge.sealer(),
        &bridge.cfg.records,
        &bucket.id,
        &tombstones,
    )
    .await
    {
        Ok(stored) if stored.len() == tombstones.len() => stored,
        _ => {
            for (place, _) in places {
                done[place] = Err(DeleteError::Internal);
            }
            return done;
        }
    };
    // The keys whose tombstone is on record. Those with a live object
    // share the batch that deletes. A key without one has a tombstone
    // for the record of a write that was not published: its own batch
    // finds nothing to delete, which would undo the batch of all, so it
    // takes the end of its attempt alone.
    let mut batch = Vec::new();
    let mut alone = Vec::new();
    for (((place, live), tombstone), stored) in places.into_iter().zip(&tombstones).zip(stored) {
        match stored {
            Ok(()) if live => batch.push((place, tombstone)),
            Ok(()) => alone.push((place, tombstone, false)),
            Err(_) => done[place] = Err(DeleteError::Internal),
        }
    }
    if !batch.is_empty() {
        // Each key under the clock reading of its tombstone, as in
        // `delete_key_once`: the floor the delete leaves stays in the
        // millisecond of the tombstone.
        let deletes: Vec<(&str, &GenerationId, UnixMs)> =
            batch.iter().map(|(_, t)| (t.key, &t.id, t.now)).collect();
        match bridge
            .catalog
            .delete_objects_before(&bucket.id, &deletes)
            .await
        {
            Ok(true) => {}
            // Nothing was deleted: one key is held up (a newer id,
            // another delete, a replay). Each on its own from here.
            Ok(false) => alone.extend(batch.into_iter().map(|(p, t)| (p, t, false))),
            // No answer: the batch failed, or it was applied. The
            // tombstones are on record, so each key still gets its own
            // try under the tombstone it has, but no later attempt (see
            // below).
            Err(_) => alone.extend(batch.into_iter().map(|(p, t)| (p, t, true))),
        }
    }
    let alone: Vec<(usize, Result<(), DeleteError>)> = stream::iter(alone)
        .map(|(place, tombstone, unanswered)| async move {
            let key = tombstone.key;
            let result =
                match commit_delete(bridge, bucket, key, &tombstone.id, tombstone.now).await {
                    Ok(true) => Ok(()),
                    Ok(false) if unanswered => after_unanswered(bridge, bucket, key).await,
                    Ok(false) => delete_key_in(bridge, bucket, key, DELETE_ATTEMPTS - 1).await,
                    Err(e) => Err(e),
                };
            (place, result)
        })
        .buffered(DELETE_CONCURRENCY)
        .collect()
        .await;
    for (place, result) in alone {
        done[place] = result;
    }
    done
}

/// The answer for a key whose chunk batch was not answered, when its
/// own batch under the same tombstone changed nothing and the key has an
/// id above the tombstone.
///
/// That id is the floor the chunk batch left when it was applied, or a
/// write that came after. A later attempt would store a tombstone above
/// it, and where the chunk batch was applied that deletes an object
/// that was written after this delete was done: a write that held
/// `If-None-Match: *` and was told so would be gone. So there is no
/// later attempt. The key is answered as deleted when nothing is live
/// on it and no record of an unpublished write is left for a replay;
/// otherwise the outcome is not known, as for a DeleteObject whose
/// batch was not answered.
async fn after_unanswered<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    key: &str,
) -> Result<(), DeleteError> {
    match bridge
        .catalog
        .key_heads(&bucket.id, &[key])
        .await
        .as_deref()
    {
        Ok([head]) if head.live.is_none() && !head.unpublished => Ok(()),
        _ => Err(DeleteError::Internal),
    }
}

/// Cuts `keys` into the chunks [`delete_chunk`] takes, in order.
fn delete_chunks<'k, 'a>(keys: &'k [&'a str]) -> Vec<&'k [&'a str]> {
    let mut chunks = Vec::new();
    let (mut start, mut bytes) = (0, 0);
    for (i, key) in keys.iter().enumerate() {
        if i > start
            && (i - start == DELETE_CHUNK_KEYS || bytes + key.len() > DELETE_CHUNK_KEY_BYTES)
        {
            chunks.push(&keys[start..i]);
            (start, bytes) = (i, 0);
        }
        bytes += key.len();
    }
    if start < keys.len() {
        chunks.push(&keys[start..]);
    }
    chunks
}

/// How often a delete is tried before it answers `SlowDown`.
const DELETE_ATTEMPTS: usize = 4;

/// How often a conditional delete is tried before it answers
/// `SlowDown`: again whenever the key changed between the look at its
/// live object and the batch, each time judged against what is live then.
const CONDITIONAL_ATTEMPTS: u32 = 4;

/// Deletes `key` if its live object meets `condition` (`If-Match`), for
/// a request that is authorized to write the bucket and passed the gate.
/// `Ok` = this request deleted the object the condition names.
///
/// Unlike [`delete_key`] it is not idempotent: without a live object
/// the answer is `404 NoSuchKey`, with another one `412`.
///
/// The tombstone is a record a replay applies whatever became of the
/// request, and it is never removed. So it is stored only once the floor
/// of the key stands at its id and the condition held after that: from
/// then on nothing is published on the key under an id the tombstone
/// covers, and all it can delete in a replay is the object the condition
/// named, or one that was gone before it. A request that answers `412`
/// or `404` stored no tombstone under the id it judged with; one from an
/// earlier turn covers only what a later write or delete had already
/// taken the place of.
async fn delete_key_if<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    key: &str,
    condition: &Precondition,
) -> Result<(), S3Response> {
    for _ in 0..CONDITIONAL_ATTEMPTS {
        restore_gate(bridge).await?;
        // Without any id on the key there is no object, and no floor to
        // raise: the condition fails on that alone.
        check_precondition(bridge, &bucket.id, key, condition).await?;
        let Some(newest) = bridge
            .catalog
            .newest_id(&bucket.id, key)
            .await
            .map_err(|_| internal())?
        else {
            continue;
        };
        let now = bridge.clock.now();
        let mut rand = [0u8; 8];
        SystemRng.fill_bytes(&mut rand).map_err(|_| internal())?;
        let tombstone = tombstone_id(now, &newest, rand);
        bridge
            .catalog
            .raise_floor(&bucket.id, key, &tombstone, false)
            .await
            .map_err(|_| internal())?;
        check_precondition(bridge, &bucket.id, key, condition).await?;
        write_tombstone(
            &bridge.catalog,
            &bridge.safety,
            &bridge.sealer(),
            &bridge.cfg.records,
            &bucket.id,
            key,
            &tombstone,
            now,
        )
        .await
        .map_err(|_| internal())?;
        if bridge
            .catalog
            .delete_object_if(&bucket.id, key, &tombstone, condition, now)
            .await
            .map_err(|_| internal())?
        {
            return Ok(());
        }
        // Nothing was deleted: the key changed after the look above, or
        // a replay began. The next turn says which.
    }
    Err(s3_error(ErrorCode::SlowDown))
}

// ---------------------------------------------------------------------------
// DeleteObjects
// ---------------------------------------------------------------------------

pub(super) async fn delete_objects<
    C: Catalog + 'static,
    B: BlobStore + 'static,
    N: NntpConnector + 'static,
    J: JobSink + 'static,
    K: Kek + 'static,
    T: Clock + 'static,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
    _bucket: &str,
) -> S3Response {
    match delete_many(bridge, req).await {
        Ok(resp) | Err(resp) => resp,
    }
}

/// S3 requires an integrity check on the body: `Content-MD5`, or a
/// checksum in a header or in the aws-chunked trailer. The validator
/// then holds the body to whichever one the request names.
fn names_integrity_check(headers: &velmora_s3_proto::Headers) -> bool {
    headers.get("content-md5").is_some()
        || headers.get("x-amz-trailer").is_some()
        || ChecksumAlgorithm::ALL
            .into_iter()
            .any(|a| headers.get(a.header()).is_some())
}

/// Everything that can fail the request with a status code comes before
/// the answer: authentication, the gates, the body and its document.
/// The deletes are the work of the [`Deferred`] body that answers.
async fn delete_many<
    C: Catalog + 'static,
    B: BlobStore + 'static,
    N: NntpConnector + 'static,
    J: JobSink + 'static,
    K: Kek + 'static,
    T: Clock + 'static,
>(
    bridge: &Rc<Bridge<C, B, N, J, K, T>>,
    req: S3Request,
) -> Result<S3Response, S3Response> {
    // POST: `authenticate` requires a read-write grant on the bucket.
    let authed = authenticate(bridge, &req).await?;
    let Some(bucket) = &authed.bucket else {
        return Err(s3_error(ErrorCode::InvalidRequest));
    };
    mutation_gate(&bridge.cfg, &authed.headers, bucket)?;
    restore_gate(bridge).await?;
    if !names_integrity_check(&authed.headers) {
        return Err(S3Response::error(
            400,
            "InvalidRequest",
            "Missing required header for this request: Content-MD5.",
        ));
    }

    // The limits of this document, not those of an object body.
    let xml_policy = policy_with(
        &bridge.cfg,
        &bridge.cfg.s3_host,
        MAX_DELETE_BODY_BYTES as usize,
        MAX_DELETE_BODY_BYTES,
    )?;
    let lengths = upload_lengths(&req.headers, MAX_DELETE_BODY_BYTES).map_err(|e| e.response())?;
    let mut validator =
        UploadValidator::new(&authed.headers, &authed.verified, &xml_policy).map_err(s3_error)?;
    let charge = bridge
        .budget
        .charge_body(lengths.decoded)
        .await
        .map_err(|e| e.response())?;
    let body = read_upload(req.body, lengths, &charge, &mut validator)
        .await
        .map_err(|e| match e {
            UploadReadError::Ingress(e) => e.response(),
            UploadReadError::Proto(e) => s3_error(e),
        })?;
    let verified = validator.finish().map_err(s3_error)?;
    if authed.headers.get("content-md5").is_none() && verified.checksum().is_none() {
        return Err(s3_error(ErrorCode::InvalidRequest));
    }

    let request = parse_delete(&body, &xml_policy, MAX_DELETE_KEYS).map_err(s3_error)?;
    drop(body);
    // Only the list of keys outlives the charge: the document and the
    // tree read from it are gone.
    drop(charge);

    // Nothing from here on fails the request: every failure is the
    // answer for a key. So the answer is a `200` whose document may be
    // sent after its headers (see `crate::keepalive`).
    let keys = Rc::new(request.keys);
    let quiet = request.quiet;
    let work = {
        let (bridge, bucket, keys) = (Rc::clone(bridge), bucket.clone(), Rc::clone(&keys));
        async move {
            let outcomes = delete_keys(&bridge, &bucket, &keys).await;
            delete_document(&keys, &outcomes, quiet)
        }
    };
    // Work that ends without its document (it was dropped) is answered
    // as if every key had failed: a delete is idempotent, and a client
    // tries the keys again.
    let fallback = move || {
        let outcomes = vec![DeleteError::Internal.outcome(); keys.len()];
        delete_document(&keys, &outcomes, quiet)
    };
    Ok(S3Response {
        status: 200,
        headers: vec![("content-type".to_string(), "application/xml".to_string())],
        body: RespBody::Deferred(Deferred::new(work, fallback)),
    })
}

/// The answer for every key of `keys`, in their order.
async fn delete_keys<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    keys: &[String],
) -> Vec<DeleteOutcome> {
    // Every key is deleted as a DeleteObject deletes it, once: a key
    // that is named again gets the answer of its first mention, so the
    // request leaves the records of one delete per key, and no two
    // deletes of this request are at work on one key. The answers come
    // back in request order.
    let mut first: HashMap<&str, usize> = HashMap::new();
    let mut distinct: Vec<&str> = Vec::new();
    let slots: Vec<usize> = keys
        .iter()
        .map(|key| {
            *first.entry(key.as_str()).or_insert_with(|| {
                distinct.push(key.as_str());
                distinct.len() - 1
            })
        })
        .collect();
    // No request can have stored a key that is not storable.
    let mut done: Vec<DeleteOutcome> = vec![
        DeleteOutcome::Failed {
            code: "InvalidArgument",
            message: "The key is not valid.",
        };
        distinct.len()
    ];
    let (places, storable): (Vec<usize>, Vec<&str>) = distinct
        .iter()
        .enumerate()
        .filter(|(_, key)| storable_key(key))
        .map(|(place, key)| (place, *key))
        .unzip();
    let deleted: Vec<Vec<Result<(), DeleteError>>> = stream::iter(delete_chunks(&storable))
        .map(|chunk| delete_chunk(bridge, bucket, chunk))
        .buffered(DELETE_CHUNKS)
        .collect()
        .await;
    for (place, result) in places.into_iter().zip(deleted.into_iter().flatten()) {
        done[place] = match result {
            Ok(()) => DeleteOutcome::Deleted,
            Err(e) => e.outcome(),
        };
    }
    slots.into_iter().map(|i| done[i].clone()).collect()
}

/// The `DeleteResult` document. It cannot fail any more: when the
/// answers do not match the keys, every key is answered `InternalError`.
fn delete_document(keys: &[String], outcomes: &[DeleteOutcome], quiet: bool) -> Vec<u8> {
    match delete_result(keys, outcomes, quiet) {
        Ok(resp) => resp.body,
        Err(_) => {
            let failed = vec![DeleteError::Internal.outcome(); keys.len()];
            delete_result(keys, &failed, quiet)
                .map(|resp| resp.body)
                .unwrap_or_default()
        }
    }
}
