//! DeleteObject and DeleteObjects: retire the live generation of a key.
//! Idempotent, so a key that does not exist is deleted too (`204`, or a
//! `Deleted` entry).
//!
//! There is one delete path, [`delete_key`]. DeleteObject runs it for the
//! key in the path, DeleteObjects for every key in its body: the same
//! gate against a replay, the same tombstone record before the catalogue
//! batch, the same guarded batch. A DeleteObjects request of N keys
//! leaves what N DeleteObject requests leave.
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
    authenticate, check_precondition, conditional_gate, from_proto, internal, mutation_gate,
    policy_with, restore_gate, s3_error, writes_refused,
};
use crate::ingress::{read_upload, upload_lengths, UploadReadError};
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::recovery::{tombstone_id, write_tombstone};
use crate::types::{Bucket, Precondition, RespBody, S3Request, S3Response};

/// Most keys one DeleteObjects request may name (the S3 limit).
pub const MAX_DELETE_KEYS: usize = 1000;
pub use crate::ingress::MAX_DELETE_BODY_BYTES;
/// Keys of one DeleteObjects request that are deleted at the same time.
/// Each delete is a handful of catalogue and store calls in sequence, so
/// this is also the number of connections the request holds open.
const DELETE_CONCURRENCY: usize = 6;

/// Why one key was not deleted.
enum DeleteError {
    /// Catalogue, store or RNG failure.
    Internal,
    /// A replay of the recovery records is under way, or started while
    /// the delete ran: nothing was deleted.
    Refused,
}

impl DeleteError {
    fn response(&self) -> S3Response {
        match self {
            DeleteError::Internal => internal(),
            DeleteError::Refused => writes_refused(),
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
/// the bucket and passed [`mutation_gate`]. `Ok` = the key has no live
/// generation older than this delete (also when it had none at all).
async fn delete_key<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    bucket: &Bucket,
    key: &str,
) -> Result<(), DeleteError> {
    let failed = |_| DeleteError::Internal;
    if bridge.catalog.restore_pending().await.map_err(failed)? {
        return Err(DeleteError::Refused);
    }
    let live = bridge
        .catalog
        .live_object(&bucket.id, key)
        .await
        .map_err(failed)?;
    let seen = match live {
        Some((live, _)) => live.id,
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
            None => return Ok(()),
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
    // covers every generation older than itself; a generation published
    // after it (a racing PUT) survives, here and in a replay. The floor
    // of the key is raised to the tombstone before the record is stored:
    // when the batch below finds nothing left to delete (another delete
    // was faster), the record stays, and every later write sorts after it.
    let tombstone = tombstone_id(now, &newest, rand);
    write_tombstone(
        &bridge.catalog,
        &bridge.safety,
        &bridge.kek,
        &bucket.id,
        key,
        &tombstone,
        now,
    )
    .await
    .map_err(failed)?;
    let deleted = bridge
        .catalog
        .delete_object_before(&bucket.id, key, &tombstone, now)
        .await
        .map_err(failed)?;
    if deleted {
        return Ok(());
    }
    // Nothing was changed. Either nothing older than the tombstone is
    // live any more (another delete was faster, or a PUT that sorts
    // after the tombstone), and the delete holds. Or a replay started
    // after this request passed the gate: then the object is still
    // live under its older id, and the delete was not done.
    let live = bridge
        .catalog
        .live_object(&bucket.id, key)
        .await
        .map_err(failed)?;
    match live {
        Some((live, _)) if live.id < tombstone => Err(DeleteError::Refused),
        _ => Ok(()),
    }
}

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
            &bridge.kek,
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

async fn delete_many<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
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

    // Every key takes the path of a DeleteObject on it, once: a key that
    // is named again gets the answer of its first mention, so the request
    // leaves the records of one delete per key. The answers come back in
    // request order.
    let mut first: HashMap<&str, usize> = HashMap::new();
    let mut distinct: Vec<&str> = Vec::new();
    let slots: Vec<usize> = request
        .keys
        .iter()
        .map(|key| {
            *first.entry(key.as_str()).or_insert_with(|| {
                distinct.push(key.as_str());
                distinct.len() - 1
            })
        })
        .collect();
    let done: Vec<DeleteOutcome> = stream::iter(distinct)
        .map(|key| async move {
            if !storable_key(key) {
                // No request can have stored such a key.
                return DeleteOutcome::Failed {
                    code: "InvalidArgument",
                    message: "The key is not valid.",
                };
            }
            match delete_key(bridge, bucket, key).await {
                Ok(()) => DeleteOutcome::Deleted,
                Err(e) => e.outcome(),
            }
        })
        .buffered(DELETE_CONCURRENCY)
        .collect()
        .await;
    let outcomes: Vec<DeleteOutcome> = slots.into_iter().map(|i| done[i].clone()).collect();
    delete_result(&request.keys, &outcomes, request.quiet)
        .map(from_proto)
        .map_err(s3_error)
}
