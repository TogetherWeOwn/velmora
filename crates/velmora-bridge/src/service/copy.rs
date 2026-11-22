//! CopyObject: a new generation that references the extents of its source.
//!
//! Nothing is read, re-encrypted or posted. The copy is one catalogue
//! batch, guarded on the source still being the live object it was when
//! its conditions were checked. From then on the extents are in service
//! for as long as either generation is live.
//!
//! Served only when `SERVER_SIDE_COPY` is on (see `BridgeConfig`).
//!
//! `If-None-Match: *` and `If-Match` are conditions on the destination
//! key, as for a PutObject, and judged by the same batch. The
//! `x-amz-copy-source-if-*` headers are conditions on the source.
//!
//! Not served, each `501 NotImplemented`:
//! - a source in another bucket. Its file keys are wrapped under that
//!   bucket's data key, so the copy would need a second wrapped key per
//!   extent;
//! - a source `versionId`. There is no versioning;
//! - a checksum algorithm other than the one stored with the source.

use velmora::rng::{FillRandom, SystemRng};
use velmora_s3_proto::mutation::{CommitResult, UploadMetadata};
use velmora_s3_proto::{
    ChecksumAlgorithm, Conditions, ErrorCode, Headers, ObjectMetadata, Policy, Target,
};

use super::common::{
    check_precondition, discard_before_retry, hold_precondition, internal, metadata_json,
    restore_gate, s3_error, stored_checksum, stored_headers, unavailable, Authed,
};
use crate::config::SINGLE_RECORD_EXTENTS;
use crate::ports::{
    BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector, PublishOutcome,
};
use crate::recovery::{id_after, write_generation};
use crate::types::{
    Body, Bucket, CopyGeneration, ExtentRow, GenerationRow, GenerationState, Precondition,
    S3Response,
};

/// Times the copy is re-planned when the source changes under it.
const ATTEMPTS: usize = 3;

/// The key `x-amz-copy-source` names, in the request's own bucket.
///
/// The value is `/bucket/key` or `bucket/key`, percent-encoded like a
/// request path, so it is parsed by the same rules.
pub(super) fn source_key(
    headers: &Headers,
    policy: &Policy,
    bucket: &Bucket,
) -> Result<String, S3Response> {
    let value = headers
        .get("x-amz-copy-source")
        .ok_or_else(|| s3_error(ErrorCode::InvalidRequest))?;
    let raw = if value.starts_with('/') {
        value.to_owned()
    } else {
        format!("/{value}")
    };
    let source = Target::parse(&raw, policy).map_err(s3_error)?;
    if let Some((name, _)) = source.query().first() {
        return Err(if name == b"versionId" {
            S3Response::not_implemented()
        } else {
            s3_error(ErrorCode::InvalidArgument)
        });
    }
    let key = source
        .key
        .filter(|k| !k.is_empty())
        .ok_or_else(|| s3_error(ErrorCode::InvalidArgument))?;
    // The caller holds write on the destination bucket, which includes
    // read. Any other bucket is refused without a lookup, so the answer
    // says nothing about which buckets exist.
    if source.bucket != bucket.name {
        return Err(S3Response::error(
            501,
            "NotImplemented",
            "Copying from another bucket is not implemented.",
        ));
    }
    Ok(key)
}

/// Judges the `x-amz-copy-source-if-*` conditions of a copy on the
/// generation it reads from.
fn check_source(headers: &Headers, generation: &GenerationRow) -> Result<(), S3Response> {
    let metadata = ObjectMetadata::new(
        generation.id.as_str().to_owned(),
        generation.size,
        generation.etag.clone(),
        generation.created_at.secs().0,
        stored_headers(generation).ok_or_else(internal)?,
        stored_checksum(generation),
    )
    .map_err(|_| internal())?;
    Conditions::from_copy_source(headers)
        .check_copy_source(&metadata)
        .map_err(s3_error)
}

/// The live generation a copy reads from, after its
/// `x-amz-copy-source-if-*` conditions held: the generation row alone.
/// UploadPartCopy reads the extents of its range by the id of this
/// generation, as a GET does.
pub(super) async fn source_generation<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    headers: &Headers,
    bucket: &Bucket,
    key: &str,
) -> Result<GenerationRow, S3Response>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let Some(generation) = bridge
        .catalog
        .live_generation(&bucket.id, key)
        .await
        .map_err(|_| internal())?
    else {
        return Err(s3_error(ErrorCode::NoSuchKey));
    };
    check_source(headers, &generation)?;
    Ok(generation)
}

/// The answer to a CopyObject whose source has more extents than one
/// copy takes ([`SINGLE_RECORD_EXTENTS`]). S3 refuses a CopyObject of
/// more than 5 GB the same way, and clients copy a large object in
/// parts.
fn source_too_large() -> S3Response {
    S3Response::error(
        400,
        "InvalidRequest",
        "The specified copy source is larger than the maximum allowable size for a copy \
         source. Copy it in parts with UploadPartCopy.",
    )
}

/// The live object a CopyObject shares its extents with, every extent
/// row of it, after the `x-amz-copy-source-if-*` conditions held.
///
/// A copy names every extent of its source in one recovery record and
/// loads every row for that, so a source of more than
/// [`SINGLE_RECORD_EXTENTS`] extents is refused, and it is refused on
/// its generation row, before any extent row is read. The key can get
/// another generation between the two reads, so what was loaded is
/// judged again, on its conditions and on its count; only in that
/// window are the rows of a source above the limit read before it is
/// refused.
async fn source_object<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    headers: &Headers,
    bucket: &Bucket,
    key: &str,
) -> Result<(GenerationRow, Vec<ExtentRow>), S3Response>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let seen = source_generation(bridge, headers, bucket, key).await?;
    if seen.extent_count > SINGLE_RECORD_EXTENTS {
        return Err(source_too_large());
    }
    let Some((generation, extents)) = bridge
        .catalog
        .live_object(&bucket.id, key)
        .await
        .map_err(|_| internal())?
    else {
        return Err(s3_error(ErrorCode::NoSuchKey));
    };
    if generation.id != seen.id {
        check_source(headers, &generation)?;
    }
    let count = u32::try_from(extents.len()).unwrap_or(u32::MAX);
    if generation.extent_count.max(count) > SINGLE_RECORD_EXTENTS {
        return Err(source_too_large());
    }
    Ok((generation, extents))
}

/// `PUT /bucket/key` with `x-amz-copy-source`. The caller authenticated
/// the request and passed the mutation gates.
pub(super) async fn copy_object<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    authed: &Authed,
    declared: Option<u64>,
    body: Body,
    condition: Option<Precondition>,
) -> Result<S3Response, S3Response>
where
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
{
    let (bucket, key) = authed.object()?;
    if !bridge.cfg.server_side_copy {
        return Err(S3Response::error(
            501,
            "NotImplemented",
            "Server-side copy is not enabled.",
        ));
    }
    // A copy has no body; one that was sent would be silently dropped.
    // It can come without a declared length, so the stream is asked too.
    if declared.is_some_and(|len| len != 0) || !crate::ingress::body_is_empty(body).await {
        return Err(s3_error(ErrorCode::InvalidRequest));
    }
    if authed.headers.get("x-amz-copy-source-range").is_some() {
        return Err(s3_error(ErrorCode::InvalidRequest));
    }
    // No bytes arrive, so there is nothing a checksum value could be
    // checked against.
    if ChecksumAlgorithm::ALL
        .iter()
        .any(|a| authed.headers.get(a.header()).is_some())
    {
        return Err(s3_error(ErrorCode::InvalidRequest));
    }
    let wanted = authed
        .headers
        .get("x-amz-checksum-algorithm")
        .or_else(|| authed.headers.get("x-amz-sdk-checksum-algorithm"))
        .map(|name| {
            ChecksumAlgorithm::from_name(name).ok_or_else(|| s3_error(ErrorCode::InvalidRequest))
        })
        .transpose()?;
    let replacement = UploadMetadata::from_headers(&authed.headers).map_err(s3_error)?;
    let replace = match authed.headers.get("x-amz-metadata-directive") {
        None | Some("COPY") => false,
        Some("REPLACE") => true,
        Some(_) => return Err(s3_error(ErrorCode::InvalidArgument)),
    };
    let source = source_key(&authed.headers, &authed.policy, bucket)?;
    if source == key && !replace {
        return Err(S3Response::error(
            400,
            "InvalidRequest",
            "This copy request is illegal because it is trying to copy an object to itself \
             without changing the object's metadata.",
        ));
    }

    for _ in 0..ATTEMPTS {
        // A condition on the destination that does not hold now is
        // answered before anything is written for the copy, the floor of
        // the key included.
        if let Some(condition) = &condition {
            check_precondition(bridge, &bucket.id, key, condition).await?;
        }
        let (from, extents) = source_object(bridge, &authed.headers, bucket, &source).await?;
        // The copy keeps the checksum stored with the source. Computing
        // another one would mean reading every byte.
        if wanted.is_some_and(|a| stored_checksum(&from).map(|c| c.algorithm()) != Some(a)) {
            return Err(S3Response::error(
                501,
                "NotImplemented",
                "A copy keeps the checksum of its source; computing another is not implemented.",
            ));
        }
        // The newest id on the destination key, its live generation or
        // its floor, so that the copy's id sorts after it. The batch
        // holds the copy to that. The floor also covers the attempt that
        // lost: should its record have survived, it sorts before this
        // one. The id of the source does not matter: a replay applies
        // the two records in either order (`sql/replay.rs`), and a copy
        // onto its own source finds it as the newest id of the key.
        let newest = bridge
            .catalog
            .newest_id(&bucket.id, key)
            .await
            .map_err(|_| internal())?;
        let now = bridge.clock.now();
        let mut rand = [0u8; 8];
        SystemRng.fill_bytes(&mut rand).map_err(|_| internal())?;
        let (content_json, user_meta_json) = if replace {
            metadata_json(&replacement)
        } else {
            (from.content_json.clone(), from.user_meta_json.clone())
        };
        let generation = GenerationRow {
            id: id_after(now, newest.as_ref(), rand),
            bucket_id: bucket.id.clone(),
            key: key.to_owned(),
            state: GenerationState::Live,
            size: from.size,
            etag: from.etag.clone(),
            // The bytes are the source's, whatever the directive says.
            checksum_json: from.checksum_json.clone(),
            content_json,
            user_meta_json,
            extent_count: from.extent_count,
            created_at: now,
            retired_at: None,
        };
        let result = CommitResult {
            bucket: bucket.name.clone(),
            key: key.to_owned(),
            etag: generation.etag.clone(),
            checksum: stored_checksum(&generation),
            modified_ms: now.0,
        };
        // A condition on the destination that does not hold ends the
        // copy here, before a record exists under this id.
        hold_precondition(bridge, &bucket.id, key, &generation.id, condition.as_ref()).await?;
        // The recovery record is durable before the catalogue batch, as
        // for a PUT. It describes every extent in full, so a replay can
        // rebuild the copy when the source it shares them with is gone.
        // The extents have the same places in the copy as in the source.
        let record = write_generation(
            &bridge.catalog,
            &bridge.safety,
            &bridge.sealer(),
            &bridge.cfg.records,
            bucket,
            &generation,
            &extents,
        )
        .await
        .map_err(|_| internal())?;
        drop(extents);
        let copy = CopyGeneration {
            generation,
            source: from.id,
            source_key: source.clone(),
            now,
        };
        let refused = match bridge
            .catalog
            .copy_generation(&copy, condition.as_ref(), record)
            .await
            .map_err(|_| internal())?
        {
            PublishOutcome::Applied => {
                return result
                    .copy_response()
                    .map(super::common::from_proto)
                    .map_err(|_| internal());
            }
            PublishOutcome::Refused(record) | PublishOutcome::Fenced(record) => record,
        };
        // The source was overwritten or deleted since it was read, the
        // destination got a generation this id does not sort after, or
        // the condition on the destination no longer holds.
        // Nothing was published under this id, so its record must not
        // publish it in a replay either. A record that cannot be removed
        // ends the request: no copy was made, and the caller is told so.
        discard_before_retry(bridge, &copy.generation, refused, condition.is_some()).await?;
        // Refused as well when a replay started after this request
        // passed the gate.
        restore_gate(bridge).await?;
        // Plan again against what is live now.
    }
    Err(unavailable())
}
