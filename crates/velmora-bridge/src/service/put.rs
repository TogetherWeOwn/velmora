//! PutObject: one request body sealed as one extent, or, above
//! `max_extent_bytes`, as slices that are each an extent.
//!
//! Order: authenticate from headers, refuse what the slice cannot honour,
//! check the declared length, charge the byte budget, then read. The body
//! is acknowledged only after the safety copy is stored and the catalogue
//! batch that publishes the generation has committed.
//!
//! A body of at most one extent is sealed and handed to the safety store
//! while it arrives (`store_streamed`), so only a window of it is in
//! memory. Its final sealed chunk is withheld until the validator
//! accepted the whole body: a refused body never becomes a whole blob.
//! The digests in the catalogue are the validator's, of the plaintext,
//! and the sealer's, of the ciphertext, and the store's own account of
//! what it holds is compared with the sealer's before a row names the
//! blob.
//!
//! A sliced body is stored while it arrives, so its slices exist before
//! the body is known to be valid. Each has a `write_intents` row from
//! before its blob is stored, nothing is published before the validator
//! accepted the whole body, and the batch that publishes deletes the
//! rows. A request that fails or dies leaves rows that name every blob
//! it wrote, for the sweep ([`crate::intents`]). This handler never
//! deletes a slice.

use std::rc::Rc;

use velmora::rng::{FillRandom, SystemRng};
use velmora_s3_proto::mutation::{CommitResult, UploadMetadata};
use velmora_s3_proto::{ErrorCode, StoredChecksum, UploadValidator};

use super::common::{
    authenticate_observed, catalog_error, check_precondition_observed, checksum_json,
    conditional_gate, discard_before_retry, from_proto, hold_precondition, internal, local_error,
    local_fault, metadata_json, restore_gate_observed, s3_error, send_post_jobs, store_streamed,
    writes_refused,
};
use super::slices::{store_slices, SliceError, SliceSink};
use crate::crypto::unwrap_bdk;
use crate::ingress::{upload_lengths, SealedUpload, UploadLengths, UploadReadError};
use crate::intents::WRITER_MAX_AGE_MS;
use crate::metrics::{FailureStage as Stage, Fault, RequestObservation};
use crate::ports::{
    BlobStore, Bridge, Catalog, Clock, Guard, JobSink, Kek, NntpConnector, PublishOutcome,
    StreamMeta,
};
use crate::recovery::{id_after, write_generation};
use crate::types::{
    Body, Bucket, CommitGeneration, ExtentId, ExtentRow, ExtentState, GenerationId, GenerationRow,
    GenerationState, Precondition, S3Request, S3Response, SafetyState, WriteId,
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
    observed: &mut RequestObservation,
) -> S3Response {
    match put(bridge, req, observed).await {
        Ok(resp) | Err(resp) => resp,
    }
}

async fn put<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
    observed: &mut RequestObservation,
) -> Result<S3Response, S3Response> {
    let authed = authenticate_observed(bridge, &req, observed).await?;
    let (bucket, key) = authed.object()?;
    // `If-None-Match: *` or `If-Match`, held to by the batch that
    // publishes; any other conditional header is refused here.
    let condition = conditional_gate(&bridge.cfg, &authed.headers, bucket)?;
    restore_gate_observed(bridge, observed).await?;
    // CopyObject is this request shape with a source header and no body.
    if authed.headers.get("x-amz-copy-source").is_some() {
        let declared = crate::ingress::declared_length(&req.headers).map_err(|e| e.response())?;
        return super::copy::copy_object(bridge, &authed, declared, req.body, condition, observed)
            .await;
    }
    // A condition that does not hold now is answered before the body is
    // read. One that holds now proves nothing yet: it is judged again
    // where the write is published.
    if let Some(condition) = &condition {
        check_precondition_observed(bridge, &bucket.id, key, condition, observed).await?;
    }
    let metadata = UploadMetadata::from_headers(&authed.headers).map_err(s3_error)?;
    // For aws-chunked bodies every length below is the decoded one.
    let lengths =
        upload_lengths(&req.headers, bridge.cfg.max_put_bytes).map_err(|e| e.response())?;
    let len = lengths.decoded;
    observed.record_size(len);
    let validator = UploadValidator::new(&authed.headers, &authed.verified, &authed.policy)
        .map_err(s3_error)?;
    if len > bridge.cfg.max_extent_bytes {
        let upload = SlicedUpload {
            bucket,
            key,
            metadata,
            lengths,
            validator,
            condition,
        };
        return put_sliced(bridge, req.body, upload, observed).await;
    }

    let mut rng = SystemRng;
    let mut extent_rand = [0u8; 13];
    rng.fill_bytes(&mut extent_rand)
        .map_err(|_| local_fault(observed, "Rng"))?;
    let extent_id = ExtentId::mint(extent_rand);
    let bdk = unwrap_bdk(
        &bridge.kek,
        bucket.kek_version,
        &bucket.id,
        &bucket.bdk_wrapped,
    )
    .map_err(|e| local_error(observed, &e))?;

    // Nothing of the body is read before this charge is held. The body
    // is sealed and stored while it arrives: the safety copy is whole
    // only if the validator accepted the body, and it is durable before
    // the catalogue names it. If the commit below fails, the blob is an
    // unreferenced orphan, never a catalogue row without bytes.
    let charge = bridge
        .budget
        .charge_stream(len)
        .await
        .inspect_err(observed.on_error(Stage::Budget))
        .map_err(|e| e.response())?;
    let SealedUpload { decoded, sealed } = store_streamed(
        &bridge.safety,
        req.body,
        lengths,
        validator,
        &bdk,
        StreamMeta {
            bucket: &bucket.id,
            extent: &extent_id,
        },
        &charge,
        observed,
    )
    .await
    .map_err(|e| match e {
        UploadReadError::Ingress(e) => e.response(),
        UploadReadError::Proto(e) => s3_error(e),
    })?;
    // Nothing of the body is held any more.
    drop(charge);

    let now = bridge.clock.now();
    let mut generation_rand = [0u8; 8];
    rng.fill_bytes(&mut generation_rand)
        .map_err(|_| local_fault(observed, "Rng"))?;
    let generation_id = GenerationId::mint(now, generation_rand);

    let etag = format!("\"{}\"", hex(decoded.md5()));
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
        cipher_size: sealed.cipher_size,
        media_header: sealed.media_header.to_vec(),
        key_mode: KEY_MODE_RANDOM,
        wrapped_file_key: Some(sealed.wrapped_file_key.to_vec()),
        plain_md5: *decoded.md5(),
        plain_sha256: *decoded.sha256(),
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
        // A conditional PUT that lost the key to another write, or to a
        // delete, ends here with `412` or `404`: before a record exists
        // under this id, and after the record of an earlier attempt was
        // removed. The safety copy stays behind unreferenced, as it does
        // for any PUT that is not published.
        hold_precondition(
            bridge,
            &bucket.id,
            key,
            &commit.generation.id,
            condition.as_ref(),
            observed,
        )
        .await?;
        let record = write_generation(
            &bridge.catalog,
            &bridge.safety,
            &bridge.kek,
            &bridge.cfg.records,
            bucket,
            &commit.generation,
            &commit.extents,
        )
        .await
        .map_err(|error| {
            observed.mark_error(Stage::storage(&error), &error);
            catalog_error(error)
        })?;
        let refused = match bridge
            .catalog
            .commit_generation(&commit, condition.as_ref(), record)
            .await
            .inspect_err(observed.on_error(Stage::Commit))
            .map_err(catalog_error)?
        {
            PublishOutcome::Applied => break commit.generation.id.clone(),
            PublishOutcome::Refused(record) | PublishOutcome::Fenced(record) => record,
            PublishOutcome::FencedOverloaded(_) => {
                observed.mark_fault(Stage::Commit, Fault::named("FencedOverloaded"));
                return Err(s3_error(ErrorCode::SlowDown));
            }
        };
        // The key already carries a newer id: a commit that landed after
        // this id was minted, or one minted by a clock ahead of this
        // one. Publishing under the older id would let a replay of the
        // records put the other one on top. Or the condition of the PUT
        // no longer held. Nothing was published, so the record goes, and
        // the PUT is tried again under an id that sorts after everything
        // on the key; its condition is judged again first.
        discard_before_retry(
            bridge,
            &commit.generation,
            refused,
            condition.is_some(),
            observed,
        )
        .await?;
        // Refused as well when a replay started after this request
        // passed the gate.
        restore_gate_observed(bridge, observed).await?;
        attempts += 1;
        if attempts == COMMIT_ATTEMPTS {
            observed.mark_fault(Stage::Commit, Fault::named("AttemptsExhausted"));
            return Err(s3_error(ErrorCode::SlowDown));
        }
        let newest = bridge
            .catalog
            .newest_id(&bucket.id, key)
            .await
            .inspect_err(observed.on_error(Stage::Lookup))
            .map_err(catalog_error)?;
        rng.fill_bytes(&mut generation_rand)
            .map_err(|_| local_fault(observed, "Rng"))?;
        let id = id_after(bridge.clock.now(), newest.as_ref(), generation_rand);
        for e in &mut commit.extents {
            e.generation_id = Some(id.clone());
        }
        commit.generation.id = id;
    };

    send_post_jobs(bridge, &generation_id, vec![extent_id], commit.now).await;

    let checksum = match checksum {
        Some((algorithm, value)) => Some(
            StoredChecksum::full(algorithm, value)
                .map_err(|_| local_fault(observed, "Checksum"))?,
        ),
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

/// A body above one extent, after authentication and the length check.
struct SlicedUpload<'a> {
    bucket: &'a Bucket,
    key: &'a str,
    metadata: UploadMetadata,
    lengths: UploadLengths,
    validator: UploadValidator,
    condition: Option<Precondition>,
}

/// The request gave up at a point where no recovery record of the write
/// exists: its rows are marked so that the sweep need not wait for them.
/// Best effort; rows left `open` are swept after the grace period.
async fn give_up<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    write: &WriteId,
) {
    let _ = bridge.catalog.abandon_intents(write).await;
}

async fn put_sliced<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
    bridge: &Bridge<C, B, N, J, K, T>,
    body: Body,
    upload: SlicedUpload<'_>,
    observed: &mut RequestObservation,
) -> Result<S3Response, S3Response> {
    let SlicedUpload {
        bucket,
        key,
        metadata,
        lengths,
        mut validator,
        condition,
    } = upload;
    let len = lengths.decoded;
    let slice_bytes = bridge.cfg.slice_bytes;
    let count = usize::try_from(len.div_ceil(slice_bytes))
        .map_err(|_| local_fault(observed, "Overflow"))?;

    // One slice of plaintext and one of ciphertext are held at a time,
    // whatever the length of the body. Nothing is read before this.
    let charge = bridge
        .budget
        .charge_body(slice_bytes)
        .await
        .inspect_err(observed.on_error(Stage::Budget))
        .map_err(|e| e.response())?;

    let started = bridge.clock.now();
    let mut rng = SystemRng;
    let mut write_rand = [0u8; 16];
    rng.fill_bytes(&mut write_rand)
        .map_err(|_| local_fault(observed, "Rng"))?;
    let write = WriteId::mint(write_rand);
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let mut extent_rand = [0u8; 13];
        rng.fill_bytes(&mut extent_rand)
            .map_err(|_| local_fault(observed, "Rng"))?;
        ids.push(ExtentId::mint(extent_rand));
    }
    let bdk = unwrap_bdk(
        &bridge.kek,
        bucket.kek_version,
        &bucket.id,
        &bucket.bdk_wrapped,
    )
    .map_err(|e| local_error(observed, &e))?;

    // Every slice has its row before its blob exists: whatever happens
    // to this request from here on, the catalogue names what it stored.
    match bridge.catalog.open_intents(&write, &ids, started).await {
        Ok(Guard::Applied(())) => {}
        // A replay started after this request passed the gate.
        Ok(Guard::Lost) => {
            restore_gate_observed(bridge, observed).await?;
            return Err(writes_refused());
        }
        Err(error) => {
            observed.mark_error(Stage::Commit, &error);
            return Err(catalog_error(error));
        }
    }

    let sink = SliceSink {
        safety: &bridge.safety,
        bdk: &bdk,
        bucket: &bucket.id,
        ids: &ids,
        slice_bytes,
        rng: &mut rng,
    };
    let stored = match store_slices(sink, body, lengths, &charge, &mut validator).await {
        Ok(stored) => stored,
        Err(e) => {
            give_up(bridge, &write).await;
            return Err(match e {
                SliceError::Ingress(e) => e.response(),
                SliceError::Proto(e) => s3_error(e),
                SliceError::Internal => local_fault(observed, "SliceInternal"),
                SliceError::Store(fault) => {
                    observed.mark_fault(Stage::R2, fault);
                    internal()
                }
            });
        }
    };
    // The signature of the last chunk, the trailer, the digests and the
    // length are only known here: until this passes the slices are those
    // of a body nobody vouched for.
    let decoded = match validator.finish() {
        Ok(decoded) => decoded,
        Err(e) => {
            give_up(bridge, &write).await;
            return Err(s3_error(e));
        }
    };
    if stored.len() != count {
        give_up(bridge, &write).await;
        return Err(local_fault(observed, "SliceCount"));
    }

    let now = bridge.clock.now();
    let mut generation_rand = [0u8; 8];
    if rng.fill_bytes(&mut generation_rand).is_err() {
        give_up(bridge, &write).await;
        return Err(local_fault(observed, "Rng"));
    }
    let generation_id = GenerationId::mint(now, generation_rand);
    // The ETag of a PutObject is the MD5 of its whole body, whatever the
    // number of extents it is stored in.
    let etag = format!("\"{}\"", hex(decoded.md5()));
    let checksum = decoded.checksum().cloned();
    let (content_json, user_meta_json) = metadata_json(&metadata);

    let mut extents = Vec::with_capacity(count);
    let mut offset = 0u64;
    for (seq, (id, slice)) in ids.iter().zip(stored).enumerate() {
        extents.push(ExtentRow {
            id: id.clone(),
            bucket_id: bucket.id.clone(),
            generation_id: Some(generation_id.clone()),
            state: ExtentState::Committed,
            seq: u32::try_from(seq).ok(),
            plain_offset: Some(offset),
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
        });
        offset = offset.saturating_add(slice.plain_size);
    }
    let generation = GenerationRow {
        id: generation_id,
        bucket_id: bucket.id.clone(),
        key: key.to_owned(),
        state: GenerationState::Live,
        size: len,
        etag: etag.clone(),
        checksum_json: checksum.as_ref().map(|(a, v)| checksum_json(*a, v)),
        content_json,
        user_meta_json,
        extent_count: u32::try_from(count).map_err(|_| local_fault(observed, "Overflow"))?,
        created_at: now,
        retired_at: None,
    };

    let mut commit = CommitGeneration {
        generation,
        extents,
        now,
    };
    let mut attempts = 0;
    loop {
        // A write this old stops before it writes a record. The sweep
        // takes `open` rows only long after this age, so a writer that
        // passed here still has its rows when it publishes.
        if bridge.clock.now().0.saturating_sub(started.0) > WRITER_MAX_AGE_MS {
            give_up(bridge, &write).await;
            return Err(s3_error(ErrorCode::SlowDown));
        }
        // The id of the record goes on the rows before the record is
        // written: a record of this write is always found from them.
        match bridge
            .catalog
            .intents_generation(&write, &commit.generation.id, count)
            .await
        {
            Ok(Guard::Applied(())) => {}
            // The rows are no longer this request's to publish: the
            // sweep took them, or a replay began. No record was written
            // under this id, and none is left of an earlier one.
            Ok(Guard::Lost) => {
                give_up(bridge, &write).await;
                restore_gate_observed(bridge, observed).await?;
                observed.mark_fault(Stage::Commit, Fault::named("IntentsLost"));
                return Err(internal());
            }
            Err(error) => {
                give_up(bridge, &write).await;
                observed.mark_error(Stage::Commit, &error);
                return Err(catalog_error(error));
            }
        }
        // The stamp is raised with the id on the rows and before the
        // record exists. A catalogue restored to any point before this
        // raise is then behind its stamp, and the sweep refuses; one
        // restored to a later point names the record on its rows, and
        // the sweep keeps the slices. A raise after the commit alone
        // would leave the restore into the upload of a write whose raise
        // failed: rows without an id, and no stamp that says so.
        if let Err(error) = bridge.raise_stamp().await {
            give_up(bridge, &write).await;
            restore_gate_observed(bridge, observed).await?;
            observed.mark_error(Stage::stamp(&error), &error);
            return Err(s3_error(ErrorCode::SlowDown));
        }
        // A conditional PUT whose condition does not hold ends here. No
        // record exists: none was written under this id, and the one of
        // an earlier attempt was removed.
        if let Err(resp) = hold_precondition(
            bridge,
            &bucket.id,
            key,
            &commit.generation.id,
            condition.as_ref(),
            observed,
        )
        .await
        {
            give_up(bridge, &write).await;
            return Err(resp);
        }
        // From the record on, a failure without an answer leaves the
        // rows `open`: the record may exist, and only the sweep's look
        // at `SAFETY` after the grace period decides what the slices
        // are. They are marked abandoned only where the record is known
        // to be gone.
        let record = write_generation(
            &bridge.catalog,
            &bridge.safety,
            &bridge.kek,
            &bridge.cfg.records,
            bucket,
            &commit.generation,
            &commit.extents,
        )
        .await
        .map_err(|error| {
            observed.mark_error(Stage::storage(&error), &error);
            catalog_error(error)
        })?;
        let refused = match bridge
            .catalog
            .commit_sliced(&commit, &write, condition.as_ref(), record)
            .await
            .inspect_err(observed.on_error(Stage::Commit))
            .map_err(catalog_error)?
        {
            PublishOutcome::Applied => break,
            PublishOutcome::Refused(record) | PublishOutcome::Fenced(record) => record,
            PublishOutcome::FencedOverloaded(_) => {
                observed.mark_fault(Stage::Commit, Fault::named("FencedOverloaded"));
                return Err(s3_error(ErrorCode::SlowDown));
            }
        };
        // A newer id on the key, a condition that no longer holds, a
        // replay, or rows the sweep took.
        // Nothing was published, so the record goes.
        // The slices are not given up where the record may be left.
        discard_before_retry(
            bridge,
            &commit.generation,
            refused,
            condition.is_some(),
            observed,
        )
        .await?;
        if let Err(resp) = restore_gate_observed(bridge, observed).await {
            give_up(bridge, &write).await;
            return Err(resp);
        }
        attempts += 1;
        if attempts == COMMIT_ATTEMPTS {
            give_up(bridge, &write).await;
            observed.mark_fault(Stage::Commit, Fault::named("AttemptsExhausted"));
            return Err(s3_error(ErrorCode::SlowDown));
        }
        // No record exists here, so a failure below gives the slices up.
        let next = async {
            let newest = bridge
                .catalog
                .newest_id(&bucket.id, key)
                .await
                .inspect_err(observed.on_error(Stage::Lookup))
                .map_err(catalog_error)?;
            rng.fill_bytes(&mut generation_rand)
                .map_err(|_| local_fault(observed, "Rng"))?;
            Ok::<_, S3Response>(id_after(
                bridge.clock.now(),
                newest.as_ref(),
                generation_rand,
            ))
        };
        let id = match next.await {
            Ok(id) => id,
            Err(response) => {
                give_up(bridge, &write).await;
                return Err(response);
            }
        };
        for e in &mut commit.extents {
            e.generation_id = Some(id.clone());
        }
        commit.generation.id = id;
    }
    // Once more with the commit confirmed, before the answer: a restore
    // to a point before this commit is then found as such, and closes
    // the write gate. A raise that fails does not undo the commit.
    let _ = bridge.raise_stamp().await;
    drop(charge);

    let rows = commit.extents.iter().map(|e| e.id.clone()).collect();
    send_post_jobs(bridge, &commit.generation.id, rows, commit.now).await;

    let checksum = match checksum {
        Some((algorithm, value)) => Some(
            StoredChecksum::full(algorithm, value)
                .map_err(|_| local_fault(observed, "Checksum"))?,
        ),
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
