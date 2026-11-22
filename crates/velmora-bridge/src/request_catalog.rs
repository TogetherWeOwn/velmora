//! The request catalogue of a managed tenant (lane L6, package L6-6;
//! tenancy ADR §2.7, AM-64, AM-71): the `Catalog` that `Bridge::handle`
//! serves a managed tenant's S3 request over, so the tenant runs tenant
//! 0's handler code.
//!
//! - **The S3 request path's methods** go to the tenant's unit as request
//!   calls ([`RequestClient`], L1-5), through a [`UnitPort`] that the
//!   composition root builds over the router and the unit client
//!   (`root::request::RequestPort`; `UnitClient::call` is the only retry
//!   layer). None is sent before the signature verified: they answer
//!   [`ERR_BEFORE_SIGNATURE`] until [`Catalog::signature_verified`].
//! - **`access_key`** is answered from the unit's `key_row`, read before
//!   the signature (unauthenticated, read-only, allowed under `restore`):
//!   the row of the key the request claims, and no other.
//! - **The tenant's state** from that `key_row` is applied once the
//!   signature verified, before any other call: `active` serves
//!   everything; `suspended` with `read_only` serves GET and HEAD; any
//!   other state refuses the request (`403 AccountProblem`), the unit's
//!   own rule for each call.
//! - **Permits and provider health** stay on the shared catalogue, as on
//!   the job path. Every other method (bucket and key administration,
//!   jobs, replay, restore) is not on a unit's request path and is
//!   refused ([`ERR_NOT_ON_REQUEST_PATH`]).

#![allow(clippy::too_many_arguments)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use serde::Deserialize;

use crate::crypto::scheme2::{unwrap_bdk_v2, TenantId as KeyTenant};
use crate::crypto::DataKey;
use crate::keys::record::TkRing;
use crate::keys::tk::LoadedRing;
use crate::plan::{PackReport, StoredPlan};
use crate::ports::*;
use crate::recovery::Recorded;
use crate::replay::*;
use crate::tenant::TenantScope;
use crate::tenant_catalog::UnitPort;
use crate::types::*;
use crate::unit::call::HoldMode;
use crate::unit::request_client::RequestClient;
use crate::unit::{CallKind, TenantState, UnitAnswer, UnitCall, UnitOp};

/// A request call before the signature verified: never sent.
pub const ERR_BEFORE_SIGNATURE: BridgeError =
    BridgeError::Invalid("unit request: before the signature verified");
/// A catalogue method that is not on a unit's request path.
pub const ERR_NOT_ON_REQUEST_PATH: BridgeError =
    BridgeError::NotImplemented("not on a unit's request path");
/// The tenant's state refuses the request (`403 AccountProblem`).
pub const ERR_ACCOUNT_PROBLEM: BridgeError =
    BridgeError::Invalid("unit request: the tenant's state refuses it");
/// Whether `e` is [`ERR_ACCOUNT_PROBLEM`]: `authenticate` answers it
/// `403 AccountProblem` (any other failure of the hook is `503`).
pub fn is_account_problem(e: &BridgeError) -> bool {
    matches!((e, &ERR_ACCOUNT_PROBLEM), (BridgeError::Invalid(a), BridgeError::Invalid(b)) if a == b)
}

/// The key's row changed between the `key_row` read under an expired
/// lease and its authenticated read (AM-63): `403 InvalidAccessKeyId`.
pub const ERR_KEY_CHANGED: BridgeError =
    BridgeError::Invalid("unit request: the key changed after the signature check");

/// Whether `e` is [`ERR_KEY_CHANGED`].
pub fn is_key_changed(e: &BridgeError) -> bool {
    matches!((e, &ERR_KEY_CHANGED), (BridgeError::Invalid(a), BridgeError::Invalid(b)) if a == b)
}

/// A `key_row` answer that does not decode.
pub const ERR_KEY_ROW: BridgeError = BridgeError::Invalid("unit request: key_row unreadable");

fn not_here(_method: &'static str) -> BridgeError {
    ERR_NOT_ON_REQUEST_PATH
}

/// The unit's `key_row` answer (AM-63, AM-64), as the Worker reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRow {
    /// The claimed key's row; `None`: no such key (or not one this unit
    /// serves).
    pub key: Option<AccessKeyRow>,
    pub tenant_state: TenantState,
    pub tenant_mode: Option<HoldMode>,
    /// Answered under an expired lease (AM-63): for the signature check
    /// alone; the first authenticated call renews.
    pub lease_expired: bool,
}

#[derive(Deserialize)]
struct KeyRowWire {
    key: Option<KeyWire>,
    state: StateWire,
    #[serde(default)]
    lease_expired: bool,
}

#[derive(Deserialize)]
struct KeyWire {
    access_key_id: String,
    principal: String,
    secret_wrapped: String,
    kek_version: u32,
    status: String,
    created_at: i64,
}

#[derive(Deserialize)]
struct StateWire {
    tenant_state: String,
    tenant_mode: Option<String>,
}

impl KeyRow {
    /// The `ok` body of a `key_row` call. A key of another id than
    /// `access_key_id`, or one in a status this build does not know, is
    /// no key.
    pub fn from_body(body: &serde_json::Value, access_key_id: &str) -> Result<KeyRow> {
        use base64::Engine as _;
        let wire = KeyRowWire::deserialize(body).map_err(|_| ERR_KEY_ROW)?;
        let tenant_state = TenantState::parse(&wire.state.tenant_state).ok_or(ERR_KEY_ROW)?;
        let tenant_mode = match wire.state.tenant_mode.as_deref() {
            None => None,
            Some(m) => Some(HoldMode::parse(m).ok_or(ERR_KEY_ROW)?),
        };
        let key = match wire.key {
            Some(k) if k.access_key_id == access_key_id => {
                let secret_wrapped = base64::engine::general_purpose::STANDARD
                    .decode(k.secret_wrapped.as_bytes())
                    .map_err(|_| ERR_KEY_ROW)?;
                KeyStatus::parse(&k.status).map(|status| AccessKeyRow {
                    access_key_id: k.access_key_id,
                    principal: k.principal,
                    secret_wrapped,
                    kek_version: k.kek_version,
                    status,
                    created_at: UnixMs(k.created_at),
                })
            }
            _ => None,
        };
        Ok(KeyRow {
            key,
            tenant_state,
            tenant_mode,
            lease_expired: wire.lease_expired,
        })
    }

    /// Whether the tenant's state serves a request: the unit's rule for a
    /// call (`active` everything; `suspended` with `read_only` reads).
    pub fn serves(&self, read: bool) -> bool {
        match self.tenant_state {
            TenantState::Active => true,
            TenantState::Suspended => read && self.tenant_mode == Some(HoldMode::ReadOnly),
            _ => false,
        }
    }
}

/// The tenant's key ring, for the bucket keys (the port loads it through
/// the composition root, `Root::tenant_keys`: it fails closed without key
/// locations or a live key version).
#[allow(async_fn_in_trait)]
pub trait TenantRing {
    async fn tenant_ring(&self, tenant: &KeyTenant) -> Result<LoadedRing>;
}

/// No tenant key for the bucket row's version.
pub const ERR_NO_BUCKET_KEY: BridgeError =
    BridgeError::Crypto("unit request: no tenant key for the bucket");

/// The catalogue of one managed tenant's request (see the module).
pub struct RequestCatalog<P: UnitPort, S: Catalog> {
    client: RequestClient<P>,
    shared: S,
    scope: TenantScope,
    access_key_id: String,
    key_row: KeyRow,
    /// Set by [`Catalog::signature_verified`]; shared with the port, which
    /// sends request calls authenticated from then on.
    verified: Rc<Cell<bool>>,
    /// The tenant's key ring, loaded on the first bucket key.
    ring: RefCell<Option<Rc<LoadedRing>>>,
}

impl<P: UnitPort + TenantRing, S: Catalog> RequestCatalog<P, S> {
    /// `scope` is the managed tenant's (never tenant 0's). `verified` is
    /// the flag the port reads (false until the signature verified).
    /// `key_row` is the unit's answer for `access_key_id`.
    pub fn new(
        client: RequestClient<P>,
        shared: S,
        scope: TenantScope,
        access_key_id: &str,
        key_row: KeyRow,
        verified: Rc<Cell<bool>>,
    ) -> Self {
        verified.set(false);
        RequestCatalog {
            client,
            shared,
            scope,
            access_key_id: access_key_id.to_owned(),
            key_row,
            verified,
            ring: RefCell::new(None),
        }
    }

    /// The request client (its refusal and the publications it refused).
    pub fn client(&self) -> &RequestClient<P> {
        &self.client
    }

    /// The `key_row` this request read.
    pub fn key_row(&self) -> &KeyRow {
        &self.key_row
    }

    fn verified(&self) -> Result<()> {
        match self.verified.get() {
            true => Ok(()),
            false => Err(ERR_BEFORE_SIGNATURE),
        }
    }

    /// The tenant's key ring, loaded once per request through the port.
    /// Only after the signature verified.
    async fn ring(&self) -> Result<Rc<LoadedRing>> {
        self.verified()?;
        let held = self.ring.borrow().clone();
        match held {
            Some(ring) => Ok(ring),
            None => {
                let tenant = KeyTenant::parse(self.scope.tenant_id())?;
                let ring = Rc::new(self.client.port().tenant_ring(&tenant).await?);
                *self.ring.borrow_mut() = Some(Rc::clone(&ring));
                Ok(ring)
            }
        }
    }

    /// The data key of a bucket of this tenant: its wrap under the tenant
    /// key whose version the row names (scheme 2). Only after the
    /// signature verified.
    async fn tenant_bucket_key(&self, bucket: &Bucket) -> Result<DataKey> {
        let tenant = KeyTenant::parse(self.scope.tenant_id())?;
        let ring = self.ring().await?;
        let tk = ring.key(bucket.kek_version).ok_or(ERR_NO_BUCKET_KEY)?;
        unwrap_bdk_v2(
            tk,
            &tenant,
            bucket.kek_version,
            &bucket.id,
            &bucket.bdk_wrapped,
        )
    }

    /// The `key_row` once more, authenticated (after the signature).
    async fn reread_key_row(&self) -> Result<KeyRow> {
        let call = UnitCall {
            name: self.client.name().clone(),
            kind: CallKind::Request,
            seqs: Some(self.client.seqs()),
            authenticated: true,
            listed: true,
            op: UnitOp::KeyRow {
                access_key_id: self.access_key_id.clone(),
                presigned: None,
            },
        };
        match self.client.port().call(&call).await? {
            UnitAnswer::Ok { body, .. } => KeyRow::from_body(&body, &self.access_key_id),
            // The unit refuses an authenticated read of a tenant whose
            // state serves nothing: 403 after the signature (ADR §2.8).
            UnitAnswer::Refused {
                reason: crate::unit::Refused::AccountProblem,
                ..
            } => Err(ERR_ACCOUNT_PROBLEM),
            _ => Err(ERR_KEY_ROW),
        }
    }

    fn seeded_key(&self, akid: &str) -> Result<Option<AccessKeyRow>> {
        Ok(match akid == self.access_key_id {
            true => self.key_row.key.clone(),
            false => None,
        })
    }
}

impl<P: UnitPort + TenantRing, S: Catalog> Catalog for RequestCatalog<P, S> {
    fn request_scope(&self) -> Option<&TenantScope> {
        Some(&self.scope)
    }

    async fn record_ring(&self) -> Option<Result<Rc<LoadedRing>>> {
        Some(self.ring().await)
    }

    async fn bucket_key(&self, bucket: &Bucket) -> Option<Result<DataKey>> {
        Some(self.tenant_bucket_key(bucket).await)
    }

    async fn signature_verified(&self, read: bool) -> Result<()> {
        if !self.key_row.lease_expired {
            if !self.key_row.serves(read) {
                return Err(ERR_ACCOUNT_PROBLEM);
            }
            self.verified.set(true);
            return Ok(());
        }

        // AM-63: the expired row checked the signature only. The signed
        // re-read must be fresh, and only its tenant state can authorize.
        self.verified.set(true);
        let result = match self.reread_key_row().await {
            Ok(row) if row.lease_expired => Err(ERR_KEY_ROW),
            Ok(row) if !row.serves(read) => Err(ERR_ACCOUNT_PROBLEM),
            Ok(row) if row.key.is_some() && row.key == self.key_row.key => Ok(()),
            Ok(_) => Err(ERR_KEY_CHANGED),
            Err(e) => Err(e),
        };
        if result.is_err() {
            self.verified.set(false);
        }
        result
    }

    async fn upload_state(&self, t: &UploadTarget<'_>) -> Result<Option<UploadState>> {
        self.verified()?;
        self.client.upload_state(t).await
    }
    async fn unmark_sent(&self, jobs: &[Job], mark: UnixMs) -> Result<u64> {
        self.verified()?;
        self.client.unmark_sent(jobs, mark).await
    }
    async fn gc_orphans_due(&self, now: UnixMs) -> Result<bool> {
        let _ = (now,);
        Err(not_here("gc_orphans_due"))
    }
    async fn gc_orphans(
        &self,
        now: UnixMs,
        cutoff: UnixMs,
        scan: u32,
        limit: u32,
    ) -> Result<Vec<GcRow>> {
        let _ = (now, cutoff, scan, limit);
        Err(not_here("gc_orphans"))
    }
    async fn gc_orphan_claim(
        &self,
        rows: &[GcRow],
        now: UnixMs,
        cutoff: UnixMs,
    ) -> (Vec<bool>, Result<()>) {
        let _ = (rows, now, cutoff);
        (Vec::new(), Err(not_here("gc_orphan_claim")))
    }
    async fn gc_orphan_done(&self, id: i64, now: UnixMs) -> Result<()> {
        let _ = (id, now);
        Err(not_here("gc_orphan_done"))
    }
    async fn create_bucket(&self, b: &Bucket) -> Result<Guard<()>> {
        let _ = (b,);
        Err(not_here("create_bucket"))
    }
    async fn create_access_key(&self, k: &AccessKeyRow) -> Result<()> {
        let _ = (k,);
        Err(not_here("create_access_key"))
    }
    async fn put_grant(&self, akid: &str, bucket: &BucketId, perm: Perm) -> Result<()> {
        let _ = (akid, bucket, perm);
        Err(not_here("put_grant"))
    }
    async fn put_grant_if_present(
        &self,
        akid: &str,
        bucket: &BucketId,
        perm: Perm,
    ) -> Result<GrantPut> {
        let _ = (akid, bucket, perm);
        Err(not_here("put_grant_if_present"))
    }
    async fn bucket_by_name(&self, name: &str) -> Result<Option<Bucket>> {
        self.verified()?;
        self.client.bucket_by_name(name).await
    }
    async fn bucket_in_use(&self, bucket: &BucketId) -> Result<bool> {
        self.verified()?;
        self.client.bucket_in_use(bucket).await
    }
    async fn delete_bucket(&self, bucket: &Bucket) -> Result<Guard<()>> {
        let _ = (bucket,);
        Err(not_here("delete_bucket"))
    }
    async fn buckets_for(&self, akid: &str) -> Result<Vec<Bucket>> {
        self.verified()?;
        self.client.buckets_for(akid).await
    }
    async fn access_key(&self, akid: &str) -> Result<Option<AccessKeyRow>> {
        self.seeded_key(akid)
    }
    async fn grant(&self, akid: &str, bucket: &BucketId) -> Result<Option<Perm>> {
        self.verified()?;
        self.client.grant(akid, bucket).await
    }
    async fn access_key_exists(&self, akid: &str) -> Result<bool> {
        let _ = (akid,);
        Err(not_here("access_key_exists"))
    }
    async fn list_access_keys(&self, after: &str, limit: u32) -> Result<Vec<AccessKeySummary>> {
        let _ = (after, limit);
        Err(not_here("list_access_keys"))
    }
    async fn delete_access_keys(&self, akids: &[String]) -> Result<u64> {
        let _ = (akids,);
        Err(not_here("delete_access_keys"))
    }
    async fn live_object(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<(GenerationRow, Vec<ExtentRow>)>> {
        self.verified()?;
        self.client.live_object(bucket, key).await
    }
    async fn live_generation(&self, bucket: &BucketId, key: &str) -> Result<Option<GenerationRow>> {
        self.verified()?;
        self.client.live_generation(bucket, key).await
    }
    async fn generation_by_id(
        &self,
        bucket: &BucketId,
        generation: &GenerationId,
    ) -> Result<Option<(Bucket, GenerationRow)>> {
        self.verified()?;
        self.client.generation_by_id(bucket, generation).await
    }
    async fn extents_in(
        &self,
        generation: &GenerationId,
        start: u64,
        end: u64,
    ) -> Result<Vec<ExtentRow>> {
        self.verified()?;
        self.client.extents_in(generation, start, end).await
    }
    async fn commit_generation(
        &self,
        c: &CommitGeneration,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        self.verified()?;
        self.client.commit_generation(c, condition, record).await
    }
    async fn commit_sliced(
        &self,
        c: &CommitGeneration,
        write: &WriteId,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        self.verified()?;
        self.client.commit_sliced(c, write, condition, record).await
    }
    async fn open_intents(
        &self,
        write: &WriteId,
        extents: &[ExtentId],
        now: UnixMs,
    ) -> Result<Guard<()>> {
        self.verified()?;
        self.client.open_intents(write, extents, now).await
    }
    async fn intents_generation(
        &self,
        write: &WriteId,
        generation: &GenerationId,
        slices: usize,
    ) -> Result<Guard<()>> {
        self.verified()?;
        self.client
            .intents_generation(write, generation, slices)
            .await
    }
    async fn abandon_intents(&self, write: &WriteId) -> Result<()> {
        self.verified()?;
        self.client.abandon_intents(write).await
    }
    async fn due_intents(&self, open_before: UnixMs, limit: u32) -> Result<Vec<WriteId>> {
        let _ = (open_before, limit);
        Err(not_here("due_intents"))
    }
    async fn fence_intents(
        &self,
        write: &WriteId,
        open_before: UnixMs,
        stamp: Option<u64>,
    ) -> Result<IntentFence> {
        let _ = (write, open_before, stamp);
        Err(not_here("fence_intents"))
    }
    async fn hold_intent_fence(
        &self,
        write: &WriteId,
        slices: usize,
        stamp: Option<u64>,
    ) -> Result<bool> {
        let _ = (write, slices, stamp);
        Err(not_here("hold_intent_fence"))
    }
    async fn keep_intents(&self, write: &WriteId) -> Result<()> {
        let _ = (write,);
        Err(not_here("keep_intents"))
    }
    async fn drop_intents(&self, write: &WriteId) -> Result<()> {
        let _ = (write,);
        Err(not_here("drop_intents"))
    }
    async fn intent_stats(&self, open_before: UnixMs) -> Result<IntentStats> {
        self.verified()?;
        self.client.intent_stats(open_before).await
    }
    async fn newest_id(&self, bucket: &BucketId, key: &str) -> Result<Option<GenerationId>> {
        self.verified()?;
        self.client.newest_id(bucket, key).await
    }
    async fn raise_floor(
        &self,
        bucket: &BucketId,
        key: &str,
        id: &GenerationId,
        generation: bool,
    ) -> Result<()> {
        self.verified()?;
        self.client.raise_floor(bucket, key, id, generation).await
    }
    async fn settle_floor(&self, bucket: &BucketId, key: &str, id: &GenerationId) -> Result<()> {
        self.verified()?;
        self.client.settle_floor(bucket, key, id).await
    }
    async fn unpublished_floor(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<GenerationId>> {
        self.verified()?;
        self.client.unpublished_floor(bucket, key).await
    }
    async fn copy_generation(
        &self,
        c: &CopyGeneration,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        self.verified()?;
        self.client.copy_generation(c, condition, record).await
    }
    async fn delete_object_before(
        &self,
        bucket: &BucketId,
        key: &str,
        before: &GenerationId,
        now: UnixMs,
    ) -> Result<bool> {
        self.verified()?;
        self.client
            .delete_object_before(bucket, key, before, now)
            .await
    }
    async fn delete_object_if(
        &self,
        bucket: &BucketId,
        key: &str,
        before: &GenerationId,
        condition: &Precondition,
        now: UnixMs,
    ) -> Result<bool> {
        self.verified()?;
        self.client
            .delete_object_if(bucket, key, before, condition, now)
            .await
    }
    async fn key_heads(&self, bucket: &BucketId, keys: &[&str]) -> Result<Vec<KeyHead>> {
        self.verified()?;
        self.client.key_heads(bucket, keys).await
    }
    async fn raise_floors(&self, bucket: &BucketId, ids: &[(&str, &GenerationId)]) -> Result<()> {
        self.verified()?;
        self.client.raise_floors(bucket, ids).await
    }
    async fn settle_floors(&self, bucket: &BucketId, ids: &[(&str, &GenerationId)]) -> Result<()> {
        self.verified()?;
        self.client.settle_floors(bucket, ids).await
    }
    async fn delete_objects_before(
        &self,
        bucket: &BucketId,
        deletes: &[(&str, &GenerationId, UnixMs)],
    ) -> Result<bool> {
        self.verified()?;
        self.client.delete_objects_before(bucket, deletes).await
    }
    async fn list(&self, bucket: &BucketId, q: &ListQuery) -> Result<ListPage> {
        self.verified()?;
        self.client.list(bucket, q).await
    }
    async fn list_heads(&self, bucket: &BucketId, q: &ListQuery) -> Result<Vec<ListEntry>> {
        self.verified()?;
        self.client.list_heads(bucket, q).await
    }
    async fn object_status(&self, bucket: &BucketId, key: &str) -> Result<Option<ObjectStatus>> {
        self.verified()?;
        self.client.object_status(bucket, key).await
    }
    async fn set_safety_state(
        &self,
        extent: &ExtentId,
        from: SafetyState,
        to: SafetyState,
    ) -> Result<bool> {
        let _ = (extent, from, to);
        Err(not_here("set_safety_state"))
    }
    async fn create_upload(&self, u: &UploadRow) -> Result<()> {
        self.verified()?;
        self.client.create_upload(u).await
    }
    async fn upload(
        &self,
        t: &UploadTarget<'_>,
    ) -> Result<Option<(UploadRow, Vec<UploadPartRow>)>> {
        self.verified()?;
        self.client.upload(t).await
    }
    async fn list_uploads(
        &self,
        bucket: &BucketId,
        q: &UploadListQuery,
    ) -> Result<Vec<OpenUpload>> {
        self.verified()?;
        self.client.list_uploads(bucket, q).await
    }
    async fn put_upload_part(
        &self,
        t: &UploadTarget<'_>,
        part: &UploadPartRow,
        extent: &ExtentRow,
        now: UnixMs,
    ) -> Result<Guard<()>> {
        self.verified()?;
        self.client.put_upload_part(t, part, extent, now).await
    }
    async fn put_upload_part_sliced(
        &self,
        t: &UploadTarget<'_>,
        part: &UploadPartRow,
        extents: &[ExtentRow],
        write: &WriteId,
        now: UnixMs,
    ) -> Result<Guard<()>> {
        self.verified()?;
        self.client
            .put_upload_part_sliced(t, part, extents, write, now)
            .await
    }
    async fn complete_upload(
        &self,
        t: &UploadTarget<'_>,
        revision: u64,
        digest: &[u8; 32],
        c: &CompleteUpload,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        self.verified()?;
        self.client
            .complete_upload(t, revision, digest, c, condition, record)
            .await
    }
    async fn upload_extents(&self, t: &UploadTarget<'_>, limit: u32) -> Result<Vec<PartExtent>> {
        self.verified()?;
        self.client.upload_extents(t, limit).await
    }
    async fn upload_extents_held(&self, upload: &UploadId, except: u16) -> Result<u64> {
        self.verified()?;
        self.client.upload_extents_held(upload, except).await
    }
    async fn abort_upload(&self, t: &UploadTarget<'_>, now: UnixMs) -> Result<Guard<()>> {
        self.verified()?;
        self.client.abort_upload(t, now).await
    }
    async fn claim(
        &self,
        extent: &ExtentId,
        generation: &GenerationId,
        stage: OutboxStage,
        owner: &str,
        now: UnixMs,
    ) -> Result<Option<Lease>> {
        let _ = (extent, generation, stage, owner, now);
        Err(not_here("claim"))
    }
    async fn renew(&self, l: &Lease, now: UnixMs) -> Result<bool> {
        let _ = (l, now);
        Err(not_here("renew"))
    }
    async fn advance(
        &self,
        l: &Lease,
        to: OutboxStage,
        next_at: UnixMs,
        now: UnixMs,
    ) -> Result<bool> {
        let _ = (l, to, next_at, now);
        Err(not_here("advance"))
    }
    async fn fail(
        &self,
        l: &Lease,
        class: FailClass,
        next_at: UnixMs,
        now: UnixMs,
    ) -> Result<bool> {
        let _ = (l, class, next_at, now);
        Err(not_here("fail"))
    }
    async fn set_cursor(&self, l: &Lease, cursor: u32, now: UnixMs) -> Result<bool> {
        let _ = (l, cursor, now);
        Err(not_here("set_cursor"))
    }
    async fn defer(&self, l: &Lease, next_at: UnixMs, now: UnixMs) -> Result<bool> {
        let _ = (l, next_at, now);
        Err(not_here("defer"))
    }
    async fn defer_at(&self, l: &Lease, cursor: u32, next_at: UnixMs, now: UnixMs) -> Result<bool> {
        let _ = (l, cursor, next_at, now);
        Err(not_here("defer_at"))
    }
    async fn job_extent(
        &self,
        extent: &ExtentId,
        generation: &GenerationId,
    ) -> Result<Option<JobExtent>> {
        let _ = (extent, generation);
        Err(not_here("job_extent"))
    }
    async fn plan_articles(
        &self,
        l: &Lease,
        rows: &[ArticleRow],
    ) -> Result<Option<Vec<ArticleRow>>> {
        let _ = (l, rows);
        Err(not_here("plan_articles"))
    }
    async fn plan_packed(
        &self,
        l: &Lease,
        cipher_size: u64,
        plan: &[u8],
        parity: Option<&[u8]>,
    ) -> Result<Option<StoredPlan>> {
        let _ = (l, cipher_size, plan, parity);
        Err(not_here("plan_packed"))
    }
    async fn articles(&self, extent: &ExtentId) -> Result<Vec<ArticleRow>> {
        self.verified()?;
        self.client.articles(extent).await
    }
    async fn stored_plan(&self, extent: &ExtentId) -> Result<StoredPlan> {
        let _ = (extent,);
        Err(not_here("stored_plan"))
    }
    async fn mark_posted(&self, l: &Lease, idx: u32, provider: &str, now: UnixMs) -> Result<bool> {
        let _ = (l, idx, provider, now);
        Err(not_here("mark_posted"))
    }
    async fn mark_posted_many(
        &self,
        l: &Lease,
        posted: &[(u32, &str)],
        now: UnixMs,
    ) -> Result<bool> {
        let _ = (l, posted, now);
        Err(not_here("mark_posted_many"))
    }
    async fn mark_reposted_many(&self, l: &Lease, idxs: &[u32], now: UnixMs) -> Result<bool> {
        let _ = (l, idxs, now);
        Err(not_here("mark_reposted_many"))
    }
    async fn renew_all(
        &self,
        l: &Lease,
        permits: &[Permit],
        now: UnixMs,
    ) -> Result<(bool, Vec<bool>)> {
        let _ = (l, permits, now);
        Err(not_here("renew_all"))
    }
    async fn record_verification(&self, l: &Lease, v: &VerificationRow) -> Result<bool> {
        let _ = (l, v);
        Err(not_here("record_verification"))
    }
    async fn backbone_status(&self, extent: &ExtentId) -> Result<Vec<BackboneStatus>> {
        let _ = (extent,);
        Err(not_here("backbone_status"))
    }
    async fn body_checks(&self, extent: &ExtentId) -> Result<Vec<BackboneStatus>> {
        let _ = (extent,);
        Err(not_here("body_checks"))
    }
    async fn begin_release(
        &self,
        l: &Lease,
        required: u32,
        counting: &[String],
        evidence_json: &str,
        now: UnixMs,
    ) -> Result<Guard<()>> {
        let _ = (l, required, counting, evidence_json, now);
        Err(not_here("begin_release"))
    }
    async fn begin_release_light(
        &self,
        l: &Lease,
        required: u32,
        counting: &[String],
        evidence_json: &str,
        now: UnixMs,
        need_full: bool,
    ) -> Result<Guard<()>> {
        let _ = (l, required, counting, evidence_json, now, need_full);
        Err(not_here("begin_release_light"))
    }
    async fn escalate_verify(&self, e: &VerifyEscalation, plan_rev: u32) -> Result<()> {
        let _ = (e, plan_rev);
        Err(not_here("escalate_verify"))
    }
    async fn verify_raised(
        &self,
        extent: &ExtentId,
        backbone: &str,
        plan_rev: u32,
    ) -> Result<bool> {
        let _ = (extent, backbone, plan_rev);
        Err(not_here("verify_raised"))
    }
    async fn verify_escalations(&self, at: UnixMs) -> Result<Vec<VerifyEscalation>> {
        let _ = (at,);
        Err(not_here("verify_escalations"))
    }
    async fn finish_release(&self, l: &Lease, now: UnixMs) -> Result<bool> {
        let _ = (l, now);
        Err(not_here("finish_release"))
    }
    async fn due(&self, now: UnixMs, resend: Resend, limit: u32) -> Result<Vec<DueRow>> {
        let _ = (now, resend, limit);
        Err(not_here("due"))
    }
    async fn mark_sent(&self, extents: &[ExtentId], now: UnixMs) -> Result<u64> {
        let _ = (extents, now);
        Err(not_here("mark_sent"))
    }
    async fn bury_exhausted(&self, max_attempts: u32, now: UnixMs) -> Result<u64> {
        let _ = (max_attempts, now);
        Err(not_here("bury_exhausted"))
    }
    async fn record_dispatch(&self, now: UnixMs) -> Result<()> {
        let _ = (now,);
        Err(not_here("record_dispatch"))
    }
    async fn outbox_stats(&self) -> Result<OutboxStats> {
        self.verified()?;
        self.client.outbox_stats().await
    }
    async fn guard_selftest(&self) -> Result<bool> {
        Err(not_here("guard_selftest"))
    }
    async fn gc_due(&self, now: UnixMs, limit: u32, disposable_only: bool) -> Result<Vec<GcRow>> {
        let _ = (now, limit, disposable_only);
        Err(not_here("gc_due"))
    }
    async fn gc_begin(&self, row: &GcRow, now: UnixMs) -> Result<GcStep> {
        let _ = (row, now);
        Err(not_here("gc_begin"))
    }
    async fn gc_done(&self, id: i64, now: UnixMs) -> Result<()> {
        let _ = (id, now);
        Err(not_here("gc_done"))
    }
    async fn replay_probe(&self, g: &GenerationRow) -> Result<ReplayProbe> {
        self.verified()?;
        self.client.replay_probe(g).await
    }
    async fn replay_extents(
        &self,
        bucket: &Bucket,
        extents: &[ReplayExtent],
        now: UnixMs,
    ) -> Result<Vec<ExtentId>> {
        let _ = (bucket, extents, now);
        Err(not_here("replay_extents"))
    }
    async fn held_extents(&self, after: &str, limit: u32) -> Result<Vec<ExtentId>> {
        let _ = (after, limit);
        Err(not_here("held_extents"))
    }
    async fn restore_begin(
        &self,
        since: UnixMs,
        now: UnixMs,
    ) -> Result<std::result::Result<UnixMs, UnixMs>> {
        let _ = (since, now);
        Err(not_here("restore_begin"))
    }
    async fn restore_finish(
        &self,
        run: UnixMs,
        now: UnixMs,
        stamp: u64,
        seen: Option<u64>,
        catalogue: &str,
    ) -> Result<bool> {
        let _ = (run, now, stamp, seen, catalogue);
        Err(not_here("restore_finish"))
    }
    async fn restore_pending(&self) -> Result<bool> {
        self.verified()?;
        self.client.restore_pending().await
    }
    async fn stamp(&self, catalogue: &str) -> Result<crate::stamp::StampRow> {
        let _ = (catalogue,);
        Err(not_here("stamp"))
    }
    async fn stamp_advance(&self, from: Option<u64>, catalogue: &str) -> Result<bool> {
        let _ = (from, catalogue);
        Err(not_here("stamp_advance"))
    }
    async fn stamp_rolled_back(
        &self,
        seen: Option<u64>,
        now: UnixMs,
        catalogue: &str,
    ) -> Result<bool> {
        let _ = (seen, now, catalogue);
        Err(not_here("stamp_rolled_back"))
    }
    async fn restore_progress(&self, run: UnixMs) -> Result<Option<RestoreProgress>> {
        let _ = (run,);
        Err(not_here("restore_progress"))
    }
    async fn restore_advance(&self, run: UnixMs, next: &ReplayMark) -> Result<()> {
        let _ = (run, next);
        Err(not_here("restore_advance"))
    }
    async fn replay_tombstone(
        &self,
        bucket: &BucketId,
        key: &str,
        id: &GenerationId,
        now: UnixMs,
    ) -> Result<bool> {
        let _ = (bucket, key, id, now);
        Err(not_here("replay_tombstone"))
    }
    async fn replay_damaged(&self, limit: u32) -> Result<(u64, Vec<GenerationId>)> {
        let _ = (limit,);
        Err(not_here("replay_damaged"))
    }
    async fn replay_publish(
        &self,
        g: &GenerationRow,
        placements: &[ExtentPlacement],
        now: UnixMs,
    ) -> Result<ReplayPublish> {
        let _ = (g, placements, now);
        Err(not_here("replay_publish"))
    }
    async fn replay_twin(
        &self,
        g: &GenerationRow,
        placements: &[ExtentPlacement],
    ) -> Result<Option<GenerationId>> {
        let _ = (g, placements);
        Err(not_here("replay_twin"))
    }
    async fn seed_permits(&self, providers: &[ProviderConfig]) -> Result<()> {
        self.shared.seed_permits(providers).await
    }
    async fn acquire_permit(
        &self,
        p: &ProviderConfig,
        class: PermitClass,
        holder: &str,
        now: UnixMs,
    ) -> Result<Option<Permit>> {
        self.shared.acquire_permit(p, class, holder, now).await
    }
    async fn renew_permit(&self, p: &Permit, now: UnixMs) -> Result<bool> {
        self.shared.renew_permit(p, now).await
    }
    async fn release_permit(&self, p: &Permit) -> Result<()> {
        self.shared.release_permit(p).await
    }
    async fn provider_load(&self, now: UnixMs) -> Result<Vec<ProviderLoad>> {
        self.shared.provider_load(now).await
    }
    async fn provider_status(&self, now: UnixMs) -> Result<Vec<ProviderLoad>> {
        self.shared.provider_status(now).await
    }
    async fn provider_failed(
        &self,
        provider: &str,
        fault: ProviderFault,
        now: UnixMs,
    ) -> Result<()> {
        self.shared.provider_failed(provider, fault, now).await
    }
    async fn provider_recovered(&self, provider: &str, now: UnixMs) -> Result<()> {
        self.shared.provider_recovered(provider, now).await
    }
    async fn providers_to_probe(
        &self,
        now: UnixMs,
        quiet_since: UnixMs,
        login_quiet_since: UnixMs,
    ) -> Result<Vec<String>> {
        self.shared
            .providers_to_probe(now, quiet_since, login_quiet_since)
            .await
    }
    async fn redrive_underverified(
        &self,
        backbones: &[String],
        required: u32,
        limit: u32,
        now: UnixMs,
    ) -> Result<u64> {
        let _ = (backbones, required, limit, now);
        Err(not_here("redrive_underverified"))
    }
    async fn revive_referenced(&self, limit: u32, now: UnixMs) -> Result<u64> {
        let _ = (limit, now);
        Err(not_here("revive_referenced"))
    }
    async fn pack_plans(&self, limit: u32) -> Result<PackReport> {
        let _ = (limit,);
        Err(not_here("pack_plans"))
    }
    async fn usage_counters(&self) -> Result<UsageCounters> {
        self.verified()?;
        self.client.usage_counters().await
    }
    async fn usage_snapshot(&self, hours: u32) -> Result<UsageSnapshot> {
        self.verified()?;
        self.client.usage_snapshot(hours).await
    }
    async fn usage_buckets(&self, after: &str, limit: u32) -> Result<(bool, Vec<BucketUsage>)> {
        self.verified()?;
        self.client.usage_buckets(after, limit).await
    }
    async fn usage_recount_start(
        &self,
        now: UnixMs,
        adopt: bool,
        restart: bool,
        only_on: bool,
    ) -> Result<bool> {
        let _ = (now, adopt, restart, only_on);
        Err(not_here("usage_recount_start"))
    }
    async fn usage_recount_step(&self, chunk: u32, now: UnixMs) -> Result<RecountStep> {
        let _ = (chunk, now);
        Err(not_here("usage_recount_step"))
    }
    async fn usage_recounts(&self) -> Result<(RecountState, Option<UsageRecount>)> {
        self.verified()?;
        self.client.usage_recounts().await
    }
    async fn usage_off(&self) -> Result<()> {
        Err(not_here("usage_off"))
    }
    async fn hot_stats(&self) -> Result<HotStats> {
        self.verified()?;
        self.client.hot_stats().await
    }
    async fn evictable_bytes(&self) -> Result<u64> {
        Err(not_here("evictable_bytes"))
    }
    async fn evict_candidates(&self, limit: u32) -> Result<Vec<EvictCandidate>> {
        let _ = (limit,);
        Err(not_here("evict_candidates"))
    }
    async fn begin_evict(&self, x: &EvictCandidate) -> Result<bool> {
        let _ = (x,);
        Err(not_here("begin_evict"))
    }
    async fn finish_evict(&self, x: &EvictCandidate) -> Result<bool> {
        let _ = (x,);
        Err(not_here("finish_evict"))
    }
    async fn record_cache_fill(&self, extent: &ExtentId, now: UnixMs) -> Result<()> {
        self.verified()?;
        self.client.record_cache_fill(extent, now).await
    }
    async fn touch_read(
        &self,
        extent: &ExtentId,
        now: UnixMs,
        min_gap_ms: i64,
        from_cache: bool,
    ) -> Result<UnixMs> {
        self.verified()?;
        self.client
            .touch_read(extent, now, min_gap_ms, from_cache)
            .await
    }
    async fn hot_check_due(&self, now: UnixMs, every_ms: i64) -> Result<bool> {
        let _ = (now, every_ms);
        Err(not_here("hot_check_due"))
    }
    async fn hot_checked(&self, now: UnixMs) -> Result<()> {
        let _ = (now,);
        Err(not_here("hot_checked"))
    }
    async fn hot_drain_set(&self, left: u64) -> Result<()> {
        let _ = (left,);
        Err(not_here("hot_drain_set"))
    }
    async fn hot_drain_claim(&self, left: u64) -> Result<bool> {
        let _ = (left,);
        Err(not_here("hot_drain_claim"))
    }
    async fn hot_seq(&self, extent: &ExtentId) -> Result<u64> {
        self.verified()?;
        self.client.hot_seq(extent).await
    }
    async fn hot_forget(
        &self,
        extent: &ExtentId,
        seq: u64,
        safety: bool,
        cache: bool,
    ) -> Result<bool> {
        let _ = (extent, seq, safety, cache);
        Err(not_here("hot_forget"))
    }
}
