//! PutObject: one request body sealed as one extent.
//!
//! Order: authenticate from headers, refuse what the slice cannot honour,
//! check the declared length, charge the byte budget, then read. The body
//! is acknowledged only after the safety copy is stored and the catalogue
//! batch that publishes the generation has committed.

use std::rc::Rc;

use velmora::rng::{FillRandom, SystemRng};
use velmora_s3_proto::mutation::{CommitResult, UploadMetadata};
use velmora_s3_proto::{ErrorCode, StoredChecksum, UploadValidator};

use super::common::{
    authenticate, checksum_json, from_proto, internal, metadata_json, mutation_gate, s3_error,
};
use crate::crypto::{seal_extent, unwrap_bdk};
use crate::ingress::{read_upload, upload_lengths, UploadReadError};
use crate::ports::{
    BlobMeta, BlobStore, Bridge, Catalog, Clock, JobSink, Kek, NntpConnector, PublishOutcome,
};
use crate::recovery::{discard_generation, id_after, write_generation};
use crate::types::{
    CommitGeneration, ExtentId, ExtentRow, ExtentState, GenerationId, GenerationRow,
    GenerationState, Job, OutboxStage, S3Request, S3Response, SafetyState, JOB_VERSION,
};

/// How often a PUT is published before it answers `SlowDown`: once
/// under the id it minted, then under ids minted after whatever was
/// newer on the key.
const COMMIT_ATTEMPTS: u32 = 4;

/// Key mode of a per-extent random file key.
const KEY_MODE_RANDOM: u8 = 1;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) async fn put_object<
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
    match put(bridge, req).await {
        Ok(resp) | Err(resp) => resp,
    }
}

async fn put<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> Result<S3Response, S3Response> {
    let authed = authenticate(bridge, &req).await?;
    let (bucket, key) = authed.object()?;
    mutation_gate(&bridge.cfg, &authed.headers, bucket)?;
    // CopyObject is this request shape with a source header and no body.
    if authed.headers.get("x-amz-copy-source").is_some() {
        let declared = crate::ingress::declared_length(&req.headers).map_err(|e| e.response())?;
        return super::copy::copy_object(bridge, &authed, declared, req.body).await;
    }
    let metadata = UploadMetadata::from_headers(&authed.headers).map_err(s3_error)?;
    // For aws-chunked bodies every length below is the decoded one.
    let lengths =
        upload_lengths(&req.headers, bridge.cfg.max_extent_bytes).map_err(|e| e.response())?;
    let len = lengths.decoded;
    let mut validator = UploadValidator::new(&authed.headers, &authed.verified, &authed.policy)
        .map_err(s3_error)?;

    // Nothing of the body is buffered before this charge is held.
    let charge = bridge
        .budget
        .charge_body(len)
        .await
        .map_err(|e| e.response())?;
    let body = read_upload(req.body, lengths, &charge, &mut validator)
        .await
        .map_err(|e| match e {
            UploadReadError::Ingress(e) => e.response(),
            UploadReadError::Proto(e) => s3_error(e),
        })?;
    let decoded = validator.finish().map_err(s3_error)?;

    let now = bridge.clock.now();
    let mut rng = SystemRng;
    let mut extent_rand = [0u8; 13];
    let mut generation_rand = [0u8; 8];
    rng.fill_bytes(&mut extent_rand).map_err(|_| internal())?;
    rng.fill_bytes(&mut generation_rand)
        .map_err(|_| internal())?;
    let extent_id = ExtentId::mint(extent_rand);
    let generation_id = GenerationId::mint(now, generation_rand);

    let bdk = unwrap_bdk(
        &bridge.kek,
        bucket.kek_version,
        &bucket.id,
        &bucket.bdk_wrapped,
    )
    .map_err(|_| internal())?;
    let sealed =
        seal_extent(&bdk, &bucket.id, &extent_id, &body, &mut rng).map_err(|_| internal())?;
    drop(body);

    let etag = format!("\"{}\"", hex(&sealed.plain_md5));
    let checksum = decoded.checksum().cloned();
    let (content_json, user_meta_json) = metadata_json(&metadata);
    let extent = ExtentRow {
        id: extent_id.clone(),
        bucket_id: bucket.id.clone(),
        generation_id: Some(generation_id.clone()),
        state: ExtentState::Committed,
        seq: Some(0),
        plain_offset: Some(0),
        plain_size: len,
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
    let generation = GenerationRow {
        id: generation_id.clone(),
        bucket_id: bucket.id.clone(),
        key: key.to_owned(),
        state: GenerationState::Live,
        size: len,
        etag: etag.clone(),
        checksum_json: checksum.as_ref().map(|(a, v)| checksum_json(*a, v)),
        content_json,
        user_meta_json,
        extent_count: 1,
        created_at: now,
        retired_at: None,
    };

    // The safety copy is durable before the catalogue names it. If the
    // commit below fails, the blob is an unreferenced orphan, never a
    // catalogue row without bytes.
    bridge
        .safety
        .put(
            &extent_id.safety_key(),
            sealed.ciphertext,
            &BlobMeta {
                bucket: &bucket.id,
                extent: &extent_id,
                cipher_sha256: &sealed.cipher_sha256,
            },
        )
        .await
        .map_err(|_| internal())?;
    // The recovery record is durable before the catalogue batch: an
    // acknowledged PUT can be replayed into a restored catalogue. If this
    // write fails, nothing is published.
    let mut commit = CommitGeneration {
        generation,
        extents: vec![extent],
        now,
    };
    let mut attempts = 0;
    let generation_id = loop {
        let record = write_generation(
            &bridge.safety,
            &bridge.kek,
            bucket,
            &commit.generation,
            &commit.extents,
        )
        .await
        .map_err(|_| internal())?;
        let refused = match bridge
            .catalog
            .commit_generation(&commit, record)
            .await
            .map_err(|_| internal())?
        {
            PublishOutcome::Applied => break commit.generation.id.clone(),
            PublishOutcome::Refused(record) => record,
        };
        // The key already carries a newer id: a commit that landed after
        // this id was minted, or one minted by a clock ahead of this
        // one. Publishing under the older id would let a replay of the
        // records put the other one on top. Nothing was published, so
        // the record goes, and the PUT is tried again under an id that
        // sorts after everything on the key.
        discard_generation(&bridge.safety, &refused)
            .await
            .map_err(|_| internal())?;
        attempts += 1;
        if attempts == COMMIT_ATTEMPTS {
            return Err(s3_error(ErrorCode::SlowDown));
        }
        let newest = bridge
            .catalog
            .newest_id(&bucket.id, key)
            .await
            .map_err(|_| internal())?;
        rng.fill_bytes(&mut generation_rand)
            .map_err(|_| internal())?;
        let id = id_after(bridge.clock.now(), newest.as_ref(), generation_rand);
        for e in &mut commit.extents {
            e.generation_id = Some(id.clone());
        }
        commit.generation.id = id;
    };
    drop(charge);

    // The commit wrote the posting obligation; the queue message is only a
    // wake-up. If it is lost the dispatcher finds the outbox row.
    let _ = bridge
        .jobs
        .send(
            &Job::Extent {
                v: JOB_VERSION,
                extent: extent_id,
                generation: generation_id,
                stage: OutboxStage::Post,
            },
            0,
        )
        .await;

    let checksum = match checksum {
        Some((algorithm, value)) => {
            Some(StoredChecksum::full(algorithm, value).map_err(|_| internal())?)
        }
        None => None,
    };
    Ok(from_proto(
        CommitResult {
            bucket: bucket.name.clone(),
            key: key.to_owned(),
            etag,
            checksum,
            modified_ms: now.0,
        }
        .put_response(),
    ))
}
