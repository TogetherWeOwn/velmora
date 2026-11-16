//! DeleteObject and DeleteObjects: retire the live generation of a key.
//! Idempotent, so a key that does not exist is deleted too (`204`, or a
//! `Deleted` entry).
//!
//! There is one delete path, [`delete_key`]. DeleteObject runs it for the
//! key in the path, DeleteObjects for every key in its body: the same
//! gate against a replay, the same tombstone record before the catalogue
//! batch, the same guarded batch. A DeleteObjects request of N keys
//! leaves what N DeleteObject requests leave.

use std::collections::HashMap;
use std::rc::Rc;

use futures_util::stream::{self, StreamExt};
use velmora::rng::{FillRandom, SystemRng};
use velmora_s3_proto::mutation::{delete_result, parse_delete, DeleteOutcome};
use velmora_s3_proto::{storable_key, ChecksumAlgorithm, ErrorCode, UploadValidator};

use super::common::{
    authenticate, from_proto, internal, mutation_gate, policy_with, restore_gate, s3_error,
    writes_refused,
};
use crate::ingress::{read_upload, upload_lengths, UploadReadError};
use crate::ports::{BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector};
use crate::recovery::{tombstone_id, write_tombstone};
use crate::types::{Bucket, RespBody, S3Request, S3Response};

/// Most keys one DeleteObjects request may name (the S3 limit).
pub const MAX_DELETE_KEYS: usize = 1000;
/// Largest accepted DeleteObjects body: 1000 keys of 1024 bytes, each
/// byte possibly a character reference, stay below it in practice; a
/// larger document is refused before it is read.
pub const MAX_DELETE_BODY_BYTES: u64 = 2 * 1024 * 1024;
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
    mutation_gate(&bridge.cfg, &authed.headers, bucket)?;
    delete_key(bridge, bucket, key)
        .await
        .map_err(|e| e.response())?;
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

    let lengths = upload_lengths(&req.headers, MAX_DELETE_BODY_BYTES).map_err(|e| e.response())?;
    let mut validator = UploadValidator::new(&authed.headers, &authed.verified, &authed.policy)
        .map_err(s3_error)?;
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
    // Only the small, validated control document outlives the charge.
    drop(charge);
    if authed.headers.get("content-md5").is_none() && verified.checksum().is_none() {
        return Err(s3_error(ErrorCode::InvalidRequest));
    }

    let xml_policy = policy_with(&bridge.cfg, MAX_DELETE_BODY_BYTES as usize)?;
    let request = parse_delete(&body, &xml_policy, MAX_DELETE_KEYS).map_err(s3_error)?;
    drop(body);

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
