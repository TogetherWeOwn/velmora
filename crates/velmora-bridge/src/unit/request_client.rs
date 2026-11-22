//! The Worker's side of the request calls (`docs/units.md`, "Requests";
//! package L1-5).
//!
//! [`RequestClient`] has one typed method per [`RequestCall`], with the
//! argument and return types of the [`Catalog`] method it stands for, so
//! a request catalogue forwards each S3 handler's call to it unchanged.
//! Each method sends one `request` call through a [`UnitPort`] and reads
//! the `ok` answer back into the method's type. Any other answer is an
//! error ([`REQUEST_REFUSED`], or the catalogue error a `failed` answer
//! names), and the first such answer is kept ([`RequestClient::refusal`])
//! for the Worker to turn into the request's answer (the table in
//! `docs/units.md`).
//!
//! [`Catalog`]: crate::ports::Catalog

use std::cell::RefCell;

use serde::de::DeserializeOwned;

use super::identity::{CallKind, Seqs};
use super::request::{Published, RecordWire, RequestCall};
use super::{UnitAnswer, UnitCall, UnitName, UnitOp};
use crate::ports::{KeyHead, PublishOutcome, UploadTarget};
use crate::recovery::Recorded;
use crate::replay::ReplayProbe;
use crate::tenant_catalog::UnitPort;
use crate::types::*;

/// The unit answered a request call with anything but `ok` (or `failed`):
/// the answer is in [`RequestClient::refusal`].
pub const REQUEST_REFUSED: &str = "unit: request refused";

/// The request calls of one request, to one unit, with the numbers of
/// the tenant head the Worker verified.
pub struct RequestClient<P: UnitPort> {
    port: P,
    name: UnitName,
    seqs: Seqs,
    refusal: RefCell<Option<UnitAnswer>>,
}

impl<P: UnitPort> RequestClient<P> {
    pub fn new(port: P, name: UnitName, seqs: Seqs) -> Self {
        RequestClient {
            port,
            name,
            seqs,
            refusal: RefCell::new(None),
        }
    }

    /// The first answer that was not `ok` or `failed` since this client
    /// was made.
    pub fn refusal(&self) -> Option<UnitAnswer> {
        self.refusal.borrow().clone()
    }

    pub fn port(&self) -> &P {
        &self.port
    }

    /// One request call; its `ok` body read back as `T`.
    pub async fn call<T: DeserializeOwned>(&self, call: RequestCall) -> Result<T> {
        let answer = self.send(call).await?;
        self.read(answer)
    }

    /// One request call, and the unit's answer: an error only when no
    /// answer came (the call may or may not have run).
    async fn send(&self, call: RequestCall) -> Result<UnitAnswer> {
        let c = UnitCall {
            name: self.name.clone(),
            kind: CallKind::Request,
            seqs: Some(self.seqs),
            authenticated: true,
            listed: true,
            op: UnitOp::Request {
                call: Box::new(call),
            },
        };
        self.port.call(&c).await
    }

    fn read<T: DeserializeOwned>(&self, answer: UnitAnswer) -> Result<T> {
        match answer {
            UnitAnswer::Ok { body, .. } => serde_json::from_value(body)
                .map_err(|_| BridgeError::Sql("unit: request answer does not decode".into())),
            UnitAnswer::Failed { class } => Err(match class.as_str() {
                "guard" => BridgeError::GuardFailed,
                "invalid" => BridgeError::Invalid("unit: invalid"),
                _ => BridgeError::Sql(format!("unit: {class}")),
            }),
            other => {
                let mut kept = self.refusal.borrow_mut();
                if kept.is_none() {
                    *kept = Some(other);
                }
                Err(BridgeError::Invalid(REQUEST_REFUSED))
            }
        }
    }

    async fn publish(&self, call: RequestCall, record: Recorded) -> Result<PublishOutcome> {
        let published: Published = self.call(call).await?;
        Ok(published.outcome(record))
    }

    pub async fn access_key(&self, akid: &str) -> Result<Option<AccessKeyRow>> {
        self.call(RequestCall::access_key { akid: akid.into() })
            .await
    }
    pub async fn grant(&self, akid: &str, bucket: &BucketId) -> Result<Option<Perm>> {
        self.call(RequestCall::grant {
            akid: akid.into(),
            bucket: bucket.clone(),
        })
        .await
    }
    pub async fn bucket_by_name(&self, name: &str) -> Result<Option<Bucket>> {
        self.call(RequestCall::bucket_by_name { name: name.into() })
            .await
    }
    pub async fn buckets_for(&self, akid: &str) -> Result<Vec<Bucket>> {
        self.call(RequestCall::buckets_for { akid: akid.into() })
            .await
    }
    pub async fn bucket_in_use(&self, bucket: &BucketId) -> Result<bool> {
        self.call(RequestCall::bucket_in_use {
            bucket: bucket.clone(),
        })
        .await
    }
    pub async fn live_object(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<(GenerationRow, Vec<ExtentRow>)>> {
        self.call(RequestCall::live_object {
            bucket: bucket.clone(),
            key: key.into(),
        })
        .await
    }
    pub async fn live_generation(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<GenerationRow>> {
        self.call(RequestCall::live_generation {
            bucket: bucket.clone(),
            key: key.into(),
        })
        .await
    }
    pub async fn generation_by_id(
        &self,
        bucket: &BucketId,
        generation: &GenerationId,
    ) -> Result<Option<(Bucket, GenerationRow)>> {
        self.call(RequestCall::generation_by_id {
            bucket: bucket.clone(),
            generation: generation.clone(),
        })
        .await
    }
    pub async fn extents_in(
        &self,
        generation: &GenerationId,
        start: u64,
        end: u64,
    ) -> Result<Vec<ExtentRow>> {
        self.call(RequestCall::extents_in {
            generation: generation.clone(),
            start,
            end,
        })
        .await
    }
    pub async fn newest_id(&self, bucket: &BucketId, key: &str) -> Result<Option<GenerationId>> {
        self.call(RequestCall::newest_id {
            bucket: bucket.clone(),
            key: key.into(),
        })
        .await
    }
    pub async fn unpublished_floor(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<GenerationId>> {
        self.call(RequestCall::unpublished_floor {
            bucket: bucket.clone(),
            key: key.into(),
        })
        .await
    }
    pub async fn key_heads(&self, bucket: &BucketId, keys: &[&str]) -> Result<Vec<KeyHead>> {
        self.call(RequestCall::key_heads {
            bucket: bucket.clone(),
            keys: keys.iter().map(|k| k.to_string()).collect(),
        })
        .await
    }
    pub async fn list(&self, bucket: &BucketId, q: &ListQuery) -> Result<ListPage> {
        self.call(RequestCall::list {
            bucket: bucket.clone(),
            q: q.clone(),
        })
        .await
    }
    pub async fn list_heads(&self, bucket: &BucketId, q: &ListQuery) -> Result<Vec<ListEntry>> {
        self.call(RequestCall::list_heads {
            bucket: bucket.clone(),
            q: q.clone(),
        })
        .await
    }
    pub async fn object_status(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<ObjectStatus>> {
        self.call(RequestCall::object_status {
            bucket: bucket.clone(),
            key: key.into(),
        })
        .await
    }
    pub async fn replay_probe(&self, g: &GenerationRow) -> Result<ReplayProbe> {
        self.call(RequestCall::replay_probe { g: g.clone() }).await
    }
    pub async fn restore_pending(&self) -> Result<bool> {
        self.call(RequestCall::restore_pending {}).await
    }
    pub async fn articles(&self, extent: &ExtentId) -> Result<Vec<ArticleRow>> {
        self.call(RequestCall::articles {
            extent: extent.clone(),
        })
        .await
    }
    pub async fn touch_read(
        &self,
        extent: &ExtentId,
        now: UnixMs,
        min_gap_ms: i64,
        from_cache: bool,
    ) -> Result<UnixMs> {
        self.call(RequestCall::touch_read {
            extent: extent.clone(),
            now,
            min_gap_ms,
            from_cache,
        })
        .await
    }
    pub async fn record_cache_fill(&self, extent: &ExtentId, now: UnixMs) -> Result<()> {
        self.call(RequestCall::record_cache_fill {
            extent: extent.clone(),
            now,
        })
        .await
    }
    pub async fn upload(
        &self,
        t: &UploadTarget<'_>,
    ) -> Result<Option<(UploadRow, Vec<UploadPartRow>)>> {
        self.call(RequestCall::upload {
            bucket: t.bucket.clone(),
            key: t.key.into(),
            upload: t.id.clone(),
        })
        .await
    }
    pub async fn list_uploads(
        &self,
        bucket: &BucketId,
        q: &UploadListQuery,
    ) -> Result<Vec<OpenUpload>> {
        self.call(RequestCall::list_uploads {
            bucket: bucket.clone(),
            q: q.clone(),
        })
        .await
    }
    pub async fn upload_extents(
        &self,
        t: &UploadTarget<'_>,
        limit: u32,
    ) -> Result<Vec<PartExtent>> {
        self.call(RequestCall::upload_extents {
            bucket: t.bucket.clone(),
            key: t.key.into(),
            upload: t.id.clone(),
            limit,
        })
        .await
    }
    pub async fn upload_extents_held(&self, upload: &UploadId, except: u16) -> Result<u64> {
        self.call(RequestCall::upload_extents_held {
            upload: upload.clone(),
            except,
        })
        .await
    }
    pub async fn outbox_stats(&self) -> Result<OutboxStats> {
        self.call(RequestCall::outbox_stats {}).await
    }
    pub async fn intent_stats(&self, open_before: UnixMs) -> Result<IntentStats> {
        self.call(RequestCall::intent_stats { open_before }).await
    }
    pub async fn usage_counters(&self) -> Result<UsageCounters> {
        self.call(RequestCall::usage_counters {}).await
    }
    pub async fn usage_snapshot(&self, hours: u32) -> Result<UsageSnapshot> {
        self.call(RequestCall::usage_snapshot { hours }).await
    }
    pub async fn usage_buckets(&self, after: &str, limit: u32) -> Result<(bool, Vec<BucketUsage>)> {
        self.call(RequestCall::usage_buckets {
            after: after.into(),
            limit,
        })
        .await
    }
    pub async fn usage_recounts(&self) -> Result<(RecountState, Option<UsageRecount>)> {
        self.call(RequestCall::usage_recounts {}).await
    }
    pub async fn hot_stats(&self) -> Result<HotStats> {
        self.call(RequestCall::hot_stats {}).await
    }
    pub async fn hot_seq(&self, extent: &ExtentId) -> Result<u64> {
        self.call(RequestCall::hot_seq {
            extent: extent.clone(),
        })
        .await
    }
    pub async fn commit_generation(
        &self,
        c: &CommitGeneration,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        let call = RequestCall::commit_generation {
            c: c.clone(),
            condition: condition.cloned(),
            record: RecordWire::of(&record),
        };
        self.publish(call, record).await
    }
    pub async fn commit_sliced(
        &self,
        c: &CommitGeneration,
        write: &WriteId,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        let call = RequestCall::commit_sliced {
            c: c.clone(),
            write: write.clone(),
            condition: condition.cloned(),
            record: RecordWire::of(&record),
        };
        self.publish(call, record).await
    }
    pub async fn copy_generation(
        &self,
        c: &CopyGeneration,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        let call = RequestCall::copy_generation {
            c: c.clone(),
            condition: condition.cloned(),
            record: RecordWire::of(&record),
        };
        self.publish(call, record).await
    }
    pub async fn open_intents(
        &self,
        write: &WriteId,
        extents: &[ExtentId],
        now: UnixMs,
    ) -> Result<crate::ports::Guard<()>> {
        self.call(RequestCall::open_intents {
            write: write.clone(),
            extents: extents.to_vec(),
            now,
        })
        .await
    }
    pub async fn intents_generation(
        &self,
        write: &WriteId,
        generation: &GenerationId,
        slices: usize,
    ) -> Result<crate::ports::Guard<()>> {
        let slices =
            u32::try_from(slices).map_err(|_| BridgeError::Invalid("unit: too many slices"))?;
        self.call(RequestCall::intents_generation {
            write: write.clone(),
            generation: generation.clone(),
            slices,
        })
        .await
    }
    pub async fn abandon_intents(&self, write: &WriteId) -> Result<()> {
        self.call(RequestCall::abandon_intents {
            write: write.clone(),
        })
        .await
    }
    pub async fn raise_floor(
        &self,
        bucket: &BucketId,
        key: &str,
        id: &GenerationId,
        generation: bool,
    ) -> Result<()> {
        self.call(RequestCall::raise_floor {
            bucket: bucket.clone(),
            key: key.into(),
            id: id.clone(),
            generation,
        })
        .await
    }
    pub async fn settle_floor(
        &self,
        bucket: &BucketId,
        key: &str,
        id: &GenerationId,
    ) -> Result<()> {
        self.call(RequestCall::settle_floor {
            bucket: bucket.clone(),
            key: key.into(),
            id: id.clone(),
        })
        .await
    }
    pub async fn raise_floors(
        &self,
        bucket: &BucketId,
        ids: &[(&str, &GenerationId)],
    ) -> Result<()> {
        self.call(RequestCall::raise_floors {
            bucket: bucket.clone(),
            ids: owned_ids(ids),
        })
        .await
    }
    pub async fn settle_floors(
        &self,
        bucket: &BucketId,
        ids: &[(&str, &GenerationId)],
    ) -> Result<()> {
        self.call(RequestCall::settle_floors {
            bucket: bucket.clone(),
            ids: owned_ids(ids),
        })
        .await
    }
    pub async fn delete_object_before(
        &self,
        bucket: &BucketId,
        key: &str,
        before: &GenerationId,
        now: UnixMs,
    ) -> Result<bool> {
        self.call(RequestCall::delete_object_before {
            bucket: bucket.clone(),
            key: key.into(),
            before: before.clone(),
            now,
        })
        .await
    }
    pub async fn delete_object_if(
        &self,
        bucket: &BucketId,
        key: &str,
        before: &GenerationId,
        condition: &Precondition,
        now: UnixMs,
    ) -> Result<bool> {
        self.call(RequestCall::delete_object_if {
            bucket: bucket.clone(),
            key: key.into(),
            before: before.clone(),
            condition: condition.clone(),
            now,
        })
        .await
    }
    pub async fn delete_objects_before(
        &self,
        bucket: &BucketId,
        deletes: &[(&str, &GenerationId, UnixMs)],
    ) -> Result<bool> {
        self.call(RequestCall::delete_objects_before {
            bucket: bucket.clone(),
            deletes: deletes
                .iter()
                .map(|(k, g, t)| (k.to_string(), (*g).clone(), *t))
                .collect(),
        })
        .await
    }
    pub async fn create_upload(&self, u: &UploadRow) -> Result<()> {
        self.call(RequestCall::create_upload { u: u.clone() }).await
    }
    pub async fn put_upload_part(
        &self,
        t: &UploadTarget<'_>,
        part: &UploadPartRow,
        extent: &ExtentRow,
        now: UnixMs,
    ) -> Result<crate::ports::Guard<()>> {
        self.call(RequestCall::put_upload_part {
            bucket: t.bucket.clone(),
            key: t.key.into(),
            upload: t.id.clone(),
            part: part.clone(),
            extent: extent.clone(),
            now,
        })
        .await
    }
    pub async fn put_upload_part_sliced(
        &self,
        t: &UploadTarget<'_>,
        part: &UploadPartRow,
        extents: &[ExtentRow],
        write: &WriteId,
        now: UnixMs,
    ) -> Result<crate::ports::Guard<()>> {
        self.call(RequestCall::put_upload_part_sliced {
            bucket: t.bucket.clone(),
            key: t.key.into(),
            upload: t.id.clone(),
            part: part.clone(),
            extents: extents.to_vec(),
            write: write.clone(),
            now,
        })
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_upload(
        &self,
        t: &UploadTarget<'_>,
        revision: u64,
        digest: &[u8; 32],
        c: &CompleteUpload,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        let call = RequestCall::complete_upload {
            bucket: t.bucket.clone(),
            key: t.key.into(),
            upload: t.id.clone(),
            revision,
            digest: *digest,
            c: c.clone(),
            condition: condition.cloned(),
            record: RecordWire::of(&record),
        };
        match self.send(call).await {
            Ok(answer) => Ok(self.read::<Published>(answer)?.outcome(record)),
            // No answer: the Complete may have applied, or may still.
            // Moving the upload to its next revision settles it, as
            // tenant 0's catalogue does: if that applies, the Complete had
            // not and never will, and its record may go.
            Err(lost) => {
                let fenced = self
                    .call::<bool>(RequestCall::fence_upload {
                        bucket: t.bucket.clone(),
                        key: t.key.into(),
                        upload: t.id.clone(),
                        revision,
                    })
                    .await;
                match fenced {
                    Ok(true) => Ok(PublishOutcome::Fenced(record.refused_on_unit())),
                    // Still unknown, or it had applied: the record stays.
                    Ok(false) | Err(_) => Err(lost),
                }
            }
        }
    }
    pub async fn abort_upload(
        &self,
        t: &UploadTarget<'_>,
        now: UnixMs,
    ) -> Result<crate::ports::Guard<()>> {
        self.call(RequestCall::abort_upload {
            bucket: t.bucket.clone(),
            key: t.key.into(),
            upload: t.id.clone(),
            now,
        })
        .await
    }
}

fn owned_ids(ids: &[(&str, &GenerationId)]) -> Vec<(String, GenerationId)> {
    ids.iter()
        .map(|(k, g)| (k.to_string(), (*g).clone()))
        .collect()
}
