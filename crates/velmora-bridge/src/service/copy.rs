//! CopyObject: a new generation that references the extents of its source.
//!
//! Nothing is read, re-encrypted or posted. The copy is one catalogue
//! batch, guarded on the source still being the live object it was when
//! its conditions were checked. From then on the extents are in service
//! for as long as either generation is live.
//!
//! Served only when `SERVER_SIDE_COPY` is on (see `BridgeConfig`).
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
    internal, metadata_json, s3_error, stored_checksum, stored_headers, unavailable, Authed,
};
use crate::ports::{BlobStore, Bridge, Catalog, Clock, Guard, JobSink, Kek, NntpConnector};
use crate::recovery::{copy_id, generation_key, write_generation};
use crate::types::{
    Body, Bucket, CopyGeneration, ExtentRow, GenerationRow, GenerationState, S3Response,
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

/// The live object a copy reads from, after its
/// `x-amz-copy-source-if-*` conditions held.
pub(super) async fn source_object<C, B, N, J, K, T>(
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
    let Some((generation, extents)) = bridge
        .catalog
        .live_object(&bucket.id, key)
        .await
        .map_err(|_| internal())?
    else {
        return Err(s3_error(ErrorCode::NoSuchKey));
    };
    let metadata = ObjectMetadata::new(
        generation.id.as_str().to_owned(),
        generation.size,
        generation.etag.clone(),
        generation.created_at.secs().0,
        stored_headers(&generation).ok_or_else(internal)?,
        stored_checksum(&generation),
    )
    .map_err(|_| internal())?;
    Conditions::from_copy_source(headers)
        .check_copy_source(&metadata)
        .map_err(s3_error)?;
    Ok((generation, extents))
}

/// `PUT /bucket/key` with `x-amz-copy-source`. The caller authenticated
/// the request and passed the mutation gates.
pub(super) async fn copy_object<C, B, N, J, K, T>(
    bridge: &Bridge<C, B, N, J, K, T>,
    authed: &Authed,
    declared: Option<u64>,
    body: Body,
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
        let now = bridge.clock.now();
        let mut rand = [0u8; 8];
        SystemRng.fill_bytes(&mut rand).map_err(|_| internal())?;
        let (content_json, user_meta_json) = if replace {
            metadata_json(&replacement)
        } else {
            (from.content_json.clone(), from.user_meta_json.clone())
        };
        let generation = GenerationRow {
            id: copy_id(now, &from.id, rand),
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
        // The recovery record is durable before the catalogue batch, as
        // for a PUT. It describes every extent in full, so a replay can
        // rebuild the copy when the source it shares them with is gone.
        // The extents have the same places in the copy as in the source.
        write_generation(&bridge.safety, &bridge.kek, bucket, &generation, &extents)
            .await
            .map_err(|_| internal())?;
        drop(extents);
        let record = generation_key(&generation.id);
        let committed = bridge
            .catalog
            .copy_generation(&CopyGeneration {
                generation,
                source: from.id,
                source_key: source.clone(),
                now,
            })
            .await
            .map_err(|_| internal())?;
        if committed == Guard::Applied(()) {
            return result
                .copy_response()
                .map(super::common::from_proto)
                .map_err(|_| internal());
        }
        // The source was overwritten or deleted since it was read, so
        // nothing was published under this id and its record must not
        // publish it in a replay either. Best effort, as for Complete.
        let _ = bridge.safety.delete(&record).await;
        // Plan again against what is live now.
    }
    Err(unavailable())
}
