//! Shared harness for the S3 handler tests: a bridge over the SQL
//! catalogue (in-memory SQLite) and in-memory blob stores, an independent
//! SigV4 signer, and response helpers.

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use futures_util::stream::{self, StreamExt};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use velmora::rng::SystemRng;
use velmora_bridge::config::{BridgeConfig, Environment, GcMode, Maintenance};
use velmora_bridge::crypto::{wrap_bdk, wrap_secret, DataKey};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::plan::{PackReport, StoredPlan};
use velmora_bridge::recovery::Recorded;
use velmora_bridge::recovery::Unpublished;
use velmora_bridge::replay::{
    ReplayExtent, ReplayMark, ReplayProbe, ReplayPublish, RestoreProgress,
};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::tenant_catalog::UnitPort;
use velmora_bridge::testkit::{FakeJobs, FixedClock, MemBlobStore, RusqliteSql, TestKek};
use velmora_bridge::unit::request_client::RequestClient;
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Seqs, SyncHead, TenantId, TenantState, Unit, UnitAnswer,
    UnitCall, UnitName, UnitOp, UnitSql,
};
use velmora_bridge::*;

pub const T0: UnixMs = UnixMs(1_800_000_000_000);
pub const HOST: &str = "s3.test";
pub const REGION: &str = "auto";
pub const AKID: &str = "AKIDTESTKEY000000001";
pub const MIB: usize = 1024 * 1024;

/// A secret access key drawn fresh for each test thread, so no test
/// depends on a fixed credential.
pub fn secret() -> &'static str {
    thread_local! {
        static SECRET: &'static str = {
            let mut bytes = [0u8; 20];
            velmora::rng::FillRandom::fill_bytes(&mut SystemRng, &mut bytes).expect("os randomness");
            Box::leak(hex(&bytes).into_boxed_str())
        };
    }
    SECRET.with(|s| *s)
}

/// The rig's catalogue. On tenant 0 it is the SQL catalogue itself. With
/// `VELMORA_UNIT_REQUESTS` set, the rig's database is a born unit's, and
/// every catalogue method of the S3 request path goes to the unit as a
/// request call (`unit::request`), through JSON, as the Worker's request
/// catalogue sends it: the handler suites then run on a unit. Setup
/// (buckets, keys, grants), job methods and the tests' own reads of other
/// tables go to the same database directly.
pub struct TestCatalog {
    pub cat: SqlCatalog<Shared>,
    pub unit: Option<UnitRoute>,
}

/// The rig's database, shared by the catalogue and the unit.
#[derive(Clone)]
pub struct Shared(pub Rc<FailSql>);

impl std::ops::Deref for Shared {
    type Target = FailSql;
    fn deref(&self) -> &FailSql {
        &self.0
    }
}

impl Sql for Shared {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.0.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.0.exec(sql, params).await
    }
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        self.0.batch(stmts).await
    }
}

impl UnitSql for Shared {
    fn atomically(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.0.inner.atomically(f)
    }
    fn apply_script(&self, script: &str) -> Result<()> {
        self.0.inner.apply_script(script)
    }
    fn database_size(&self) -> Result<u64> {
        self.0.inner.database_size()
    }
}

/// The unit of a rig in unit mode, and the request calls to it.
pub struct UnitRoute {
    pub unit: Rc<Unit<Shared>>,
    pub client: RequestClient<LocalUnit>,
}

/// The way to the rig's unit: each call and answer crosses as JSON.
pub struct LocalUnit {
    pub unit: Rc<Unit<Shared>>,
    pub calls: Cell<u64>,
}

/// A unit call meets the rig's faults as one call: the tripwire counts
/// and trips it whole (`Fail`: not run; `Lost`: run, answer lost;
/// `Stall`: held before it runs), and a publication fault of the
/// database is that of the call that publishes (`Applied`: committed,
/// answer lost). The statements inside it run in one transaction and
/// cannot be stalled or interleaved; a statement fault inside it (a
/// failed write, batch or matching statement) fails the whole call and
/// keeps nothing of it.
impl UnitPort for LocalUnit {
    async fn call(&self, call: &UnitCall) -> Result<UnitAnswer> {
        self.calls.set(self.calls.get() + 1);
        let sql = self.unit.sql();
        let wire = serde_json::to_string(call).unwrap();
        let call: UnitCall = serde_json::from_str(&wire).expect("a call reads back");
        let publishes = matches!(
            &call.op,
            UnitOp::Request { call } if matches!(
                call.name(),
                "commit_generation" | "commit_sliced" | "copy_generation" | "complete_upload"
            )
        );
        sql.over_budget()?;
        let lost = match publishes.then(|| sql.fail_publish.take()).flatten() {
            None => false,
            Some(PublishFault::NotApplied) => return Err(sql_down()),
            Some(PublishFault::Down) => {
                sql.fail_next_batch.set(true);
                return Err(sql_down());
            }
            Some(PublishFault::Overloaded(n)) => {
                sql.overloaded.set(n);
                return Err(sql_down());
            }
            Some(PublishFault::Applied) => true,
            Some(f @ PublishFault::RefusedOverloaded(_)) => {
                // Run in full, refused by its guard inside the call.
                sql.fail_publish.set(Some(f));
                false
            }
        };
        let run = async {
            sql.in_unit.set(true);
            let answer = self.unit.handle(&call, T0);
            sql.in_unit.set(false);
            if std::env::var_os("VELMORA_UNIT_TRACE").is_some()
                && !matches!(answer, UnitAnswer::Ok { .. })
            {
                // The method's name and the answer only: an op can carry
                // wrapped secrets.
                let what = match &call.op {
                    UnitOp::Request { call } => call.name(),
                    _ => "worker or read call",
                };
                eprintln!("unit: {what} -> {answer:?}");
            }
            Ok(answer)
        };
        let answer = sql.trip.guard(sql_down, run).await?;
        if lost {
            return Err(sql_down());
        }
        let wire = serde_json::to_string(&answer).unwrap();
        Ok(serde_json::from_str(&wire).expect("an answer reads back"))
    }
}

/// Whether the rigs of this run serve through a unit.
pub fn on_unit() -> bool {
    std::env::var_os("VELMORA_UNIT_REQUESTS").is_some_and(|v| !v.is_empty() && v != "0")
}

/// A test of tenant 0's D1 catalogue itself, not of the request path:
/// in unit mode it says why and is not run.
pub fn tenant_zero_only(why: &str) -> bool {
    if on_unit() {
        eprintln!("tenant 0 only, not in unit mode: {why}");
    }
    on_unit()
}

/// The unit's name in unit mode: one of tenant 0's, whose key scheme
/// (1, the KEK's) is the one the rig wraps with. The request path is the
/// same for every tenant; only the wraps a unit takes differ (rule 13).
pub fn unit_name() -> UnitName {
    UnitName::new(TenantId::zero(), 1)
}

/// The unit's numbers in unit mode.
pub const UNIT_SEQS: Seqs = Seqs {
    state_seq: 3,
    keys_seq: 0,
};

impl TestCatalog {
    /// The catalogue over `sql`: on tenant 0, or (unit mode) on a unit
    /// born over it, open and `active`.
    pub fn new(sql: FailSql, unit: bool) -> TestCatalog {
        let shared = Shared(Rc::new(sql));
        if !unit {
            return TestCatalog {
                cat: SqlCatalog::new(shared),
                unit: None,
            };
        }
        let unit = Rc::new(Unit::new(shared.clone(), unit_name(), ""));
        let worker = |op| {
            unit.handle(
                &UnitCall {
                    name: unit_name(),
                    kind: CallKind::Worker,
                    seqs: Some(UNIT_SEQS),
                    authenticated: true,
                    listed: true,
                    op,
                },
                T0,
            )
        };
        let born = worker(UnitOp::Provision {
            token: BirthToken {
                name: unit_name(),
                jurisdiction: String::new(),
                record_seq: UNIT_SEQS.state_seq,
                schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
                key_scheme: 1,
                kind: BirthKind::Birth,
            },
            sealed: vec![1],
        });
        assert!(matches!(born, UnitAnswer::Ok { .. }), "{born:?}");
        let synced = worker(UnitOp::Sync {
            head: SyncHead {
                seqs: UNIT_SEQS,
                tenant_state: TenantState::Active,
                tenant_mode: None,
                restoring_since: None,
                lift: None,
            },
        });
        assert!(matches!(synced, UnitAnswer::Ok { .. }), "{synced:?}");
        // Rule 12 (the unit lease, u0002): the Worker's renewal at T0, so
        // the unit serves for T; every unit call of the rig runs at T0.
        let renewed = worker(UnitOp::Renew {
            proof_start: T0,
            proven: velmora_bridge::unit_lease::lease::Proven {
                state_seq: UNIT_SEQS.state_seq,
                keys_seq: UNIT_SEQS.keys_seq,
                stamp_counter: None,
                revoked: 0,
            },
            revocations: Vec::new(),
        });
        assert!(matches!(renewed, UnitAnswer::Ok { .. }), "{renewed:?}");
        let client = RequestClient::new(
            LocalUnit {
                unit: Rc::clone(&unit),
                calls: Cell::new(0),
            },
            unit_name(),
            UNIT_SEQS,
        );
        TestCatalog {
            cat: SqlCatalog::new(shared),
            unit: Some(UnitRoute { unit, client }),
        }
    }

    /// The request calls the unit answered, in unit mode.
    pub fn unit_calls(&self) -> Option<u64> {
        self.unit.as_ref().map(|u| u.client.port().calls.get())
    }
}

impl std::ops::Deref for TestCatalog {
    type Target = SqlCatalog<Shared>;
    fn deref(&self) -> &SqlCatalog<Shared> {
        &self.cat
    }
}

impl Catalog for TestCatalog {
    async fn create_bucket(&self, b: &Bucket) -> Result<Guard<()>> {
        self.cat.create_bucket(b).await
    }
    async fn create_access_key(&self, k: &AccessKeyRow) -> Result<()> {
        self.cat.create_access_key(k).await
    }
    async fn put_grant(&self, akid: &str, bucket: &BucketId, perm: Perm) -> Result<()> {
        self.cat.put_grant(akid, bucket, perm).await
    }
    async fn put_grant_if_present(
        &self,
        akid: &str,
        bucket: &BucketId,
        perm: Perm,
    ) -> Result<GrantPut> {
        self.cat.put_grant_if_present(akid, bucket, perm).await
    }
    async fn bucket_by_name(&self, name: &str) -> Result<Option<Bucket>> {
        match &self.unit {
            Some(route) => route.client.bucket_by_name(name).await,
            None => self.cat.bucket_by_name(name).await,
        }
    }
    async fn bucket_in_use(&self, bucket: &BucketId) -> Result<bool> {
        match &self.unit {
            Some(route) => route.client.bucket_in_use(bucket).await,
            None => self.cat.bucket_in_use(bucket).await,
        }
    }
    async fn delete_bucket(&self, bucket: &Bucket) -> Result<Guard<()>> {
        self.cat.delete_bucket(bucket).await
    }
    async fn buckets_for(&self, akid: &str) -> Result<Vec<Bucket>> {
        match &self.unit {
            Some(route) => route.client.buckets_for(akid).await,
            None => self.cat.buckets_for(akid).await,
        }
    }
    async fn access_key(&self, akid: &str) -> Result<Option<AccessKeyRow>> {
        match &self.unit {
            Some(route) => route.client.access_key(akid).await,
            None => self.cat.access_key(akid).await,
        }
    }
    async fn grant(&self, akid: &str, bucket: &BucketId) -> Result<Option<Perm>> {
        match &self.unit {
            Some(route) => route.client.grant(akid, bucket).await,
            None => self.cat.grant(akid, bucket).await,
        }
    }
    async fn access_key_exists(&self, akid: &str) -> Result<bool> {
        self.cat.access_key_exists(akid).await
    }
    async fn list_access_keys(&self, after: &str, limit: u32) -> Result<Vec<AccessKeySummary>> {
        self.cat.list_access_keys(after, limit).await
    }
    async fn delete_access_keys(&self, akids: &[String]) -> Result<u64> {
        self.cat.delete_access_keys(akids).await
    }
    async fn live_object(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<(GenerationRow, Vec<ExtentRow>)>> {
        match &self.unit {
            Some(route) => route.client.live_object(bucket, key).await,
            None => self.cat.live_object(bucket, key).await,
        }
    }
    async fn live_generation(&self, bucket: &BucketId, key: &str) -> Result<Option<GenerationRow>> {
        match &self.unit {
            Some(route) => route.client.live_generation(bucket, key).await,
            None => self.cat.live_generation(bucket, key).await,
        }
    }
    async fn generation_by_id(
        &self,
        bucket: &BucketId,
        generation: &GenerationId,
    ) -> Result<Option<(Bucket, GenerationRow)>> {
        match &self.unit {
            Some(route) => route.client.generation_by_id(bucket, generation).await,
            None => self.cat.generation_by_id(bucket, generation).await,
        }
    }
    async fn extents_in(
        &self,
        generation: &GenerationId,
        start: u64,
        end: u64,
    ) -> Result<Vec<ExtentRow>> {
        match &self.unit {
            Some(route) => route.client.extents_in(generation, start, end).await,
            None => self.cat.extents_in(generation, start, end).await,
        }
    }
    async fn commit_generation(
        &self,
        c: &CommitGeneration,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        match &self.unit {
            Some(route) => route.client.commit_generation(c, condition, record).await,
            None => self.cat.commit_generation(c, condition, record).await,
        }
    }
    async fn commit_sliced(
        &self,
        c: &CommitGeneration,
        write: &WriteId,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        match &self.unit {
            Some(route) => {
                route
                    .client
                    .commit_sliced(c, write, condition, record)
                    .await
            }
            None => self.cat.commit_sliced(c, write, condition, record).await,
        }
    }
    async fn open_intents(
        &self,
        write: &WriteId,
        extents: &[ExtentId],
        now: UnixMs,
    ) -> Result<Guard<()>> {
        match &self.unit {
            Some(route) => route.client.open_intents(write, extents, now).await,
            None => self.cat.open_intents(write, extents, now).await,
        }
    }
    async fn intents_generation(
        &self,
        write: &WriteId,
        generation: &GenerationId,
        slices: usize,
    ) -> Result<Guard<()>> {
        match &self.unit {
            Some(route) => {
                route
                    .client
                    .intents_generation(write, generation, slices)
                    .await
            }
            None => self.cat.intents_generation(write, generation, slices).await,
        }
    }
    async fn abandon_intents(&self, write: &WriteId) -> Result<()> {
        match &self.unit {
            Some(route) => route.client.abandon_intents(write).await,
            None => self.cat.abandon_intents(write).await,
        }
    }
    async fn due_intents(&self, open_before: UnixMs, limit: u32) -> Result<Vec<WriteId>> {
        self.cat.due_intents(open_before, limit).await
    }
    async fn fence_intents(
        &self,
        write: &WriteId,
        open_before: UnixMs,
        stamp: Option<u64>,
    ) -> Result<IntentFence> {
        self.cat.fence_intents(write, open_before, stamp).await
    }
    async fn hold_intent_fence(
        &self,
        write: &WriteId,
        slices: usize,
        stamp: Option<u64>,
    ) -> Result<bool> {
        self.cat.hold_intent_fence(write, slices, stamp).await
    }
    async fn keep_intents(&self, write: &WriteId) -> Result<()> {
        self.cat.keep_intents(write).await
    }
    async fn drop_intents(&self, write: &WriteId) -> Result<()> {
        self.cat.drop_intents(write).await
    }
    async fn intent_stats(&self, open_before: UnixMs) -> Result<IntentStats> {
        match &self.unit {
            Some(route) => route.client.intent_stats(open_before).await,
            None => self.cat.intent_stats(open_before).await,
        }
    }
    async fn newest_id(&self, bucket: &BucketId, key: &str) -> Result<Option<GenerationId>> {
        match &self.unit {
            Some(route) => route.client.newest_id(bucket, key).await,
            None => self.cat.newest_id(bucket, key).await,
        }
    }
    async fn raise_floor(
        &self,
        bucket: &BucketId,
        key: &str,
        id: &GenerationId,
        generation: bool,
    ) -> Result<()> {
        match &self.unit {
            Some(route) => route.client.raise_floor(bucket, key, id, generation).await,
            None => self.cat.raise_floor(bucket, key, id, generation).await,
        }
    }
    async fn settle_floor(&self, bucket: &BucketId, key: &str, id: &GenerationId) -> Result<()> {
        match &self.unit {
            Some(route) => route.client.settle_floor(bucket, key, id).await,
            None => self.cat.settle_floor(bucket, key, id).await,
        }
    }
    async fn unpublished_floor(
        &self,
        bucket: &BucketId,
        key: &str,
    ) -> Result<Option<GenerationId>> {
        match &self.unit {
            Some(route) => route.client.unpublished_floor(bucket, key).await,
            None => self.cat.unpublished_floor(bucket, key).await,
        }
    }
    async fn copy_generation(
        &self,
        c: &CopyGeneration,
        condition: Option<&Precondition>,
        record: Recorded,
    ) -> Result<PublishOutcome> {
        match &self.unit {
            Some(route) => route.client.copy_generation(c, condition, record).await,
            None => self.cat.copy_generation(c, condition, record).await,
        }
    }
    async fn delete_object_before(
        &self,
        bucket: &BucketId,
        key: &str,
        before: &GenerationId,
        now: UnixMs,
    ) -> Result<bool> {
        match &self.unit {
            Some(route) => {
                route
                    .client
                    .delete_object_before(bucket, key, before, now)
                    .await
            }
            None => {
                self.cat
                    .delete_object_before(bucket, key, before, now)
                    .await
            }
        }
    }
    async fn delete_object_if(
        &self,
        bucket: &BucketId,
        key: &str,
        before: &GenerationId,
        condition: &Precondition,
        now: UnixMs,
    ) -> Result<bool> {
        match &self.unit {
            Some(route) => {
                route
                    .client
                    .delete_object_if(bucket, key, before, condition, now)
                    .await
            }
            None => {
                self.cat
                    .delete_object_if(bucket, key, before, condition, now)
                    .await
            }
        }
    }
    async fn key_heads(&self, bucket: &BucketId, keys: &[&str]) -> Result<Vec<KeyHead>> {
        match &self.unit {
            Some(route) => route.client.key_heads(bucket, keys).await,
            None => self.cat.key_heads(bucket, keys).await,
        }
    }
    async fn raise_floors(&self, bucket: &BucketId, ids: &[(&str, &GenerationId)]) -> Result<()> {
        match &self.unit {
            Some(route) => route.client.raise_floors(bucket, ids).await,
            None => self.cat.raise_floors(bucket, ids).await,
        }
    }
    async fn settle_floors(&self, bucket: &BucketId, ids: &[(&str, &GenerationId)]) -> Result<()> {
        match &self.unit {
            Some(route) => route.client.settle_floors(bucket, ids).await,
            None => self.cat.settle_floors(bucket, ids).await,
        }
    }
    async fn delete_objects_before(
        &self,
        bucket: &BucketId,
        deletes: &[(&str, &GenerationId, UnixMs)],
    ) -> Result<bool> {
        match &self.unit {
            Some(route) => route.client.delete_objects_before(bucket, deletes).await,
            None => self.cat.delete_objects_before(bucket, deletes).await,
        }
    }
    async fn list(&self, bucket: &BucketId, q: &ListQuery) -> Result<ListPage> {
        match &self.unit {
            Some(route) => route.client.list(bucket, q).await,
            None => self.cat.list(bucket, q).await,
        }
    }
    async fn list_heads(&self, bucket: &BucketId, q: &ListQuery) -> Result<Vec<ListEntry>> {
        match &self.unit {
            Some(route) => route.client.list_heads(bucket, q).await,
            None => self.cat.list_heads(bucket, q).await,
        }
    }
    async fn object_status(&self, bucket: &BucketId, key: &str) -> Result<Option<ObjectStatus>> {
        match &self.unit {
            Some(route) => route.client.object_status(bucket, key).await,
            None => self.cat.object_status(bucket, key).await,
        }
    }
    async fn set_safety_state(
        &self,
        extent: &ExtentId,
        from: SafetyState,
        to: SafetyState,
    ) -> Result<bool> {
        self.cat.set_safety_state(extent, from, to).await
    }
    async fn create_upload(&self, u: &UploadRow) -> Result<()> {
        match &self.unit {
            Some(route) => route.client.create_upload(u).await,
            None => self.cat.create_upload(u).await,
        }
    }
    async fn upload(
        &self,
        t: &UploadTarget<'_>,
    ) -> Result<Option<(UploadRow, Vec<UploadPartRow>)>> {
        match &self.unit {
            Some(route) => route.client.upload(t).await,
            None => self.cat.upload(t).await,
        }
    }
    async fn upload_state(&self, t: &UploadTarget<'_>) -> Result<Option<UploadState>> {
        self.cat.upload_state(t).await
    }
    async fn list_uploads(
        &self,
        bucket: &BucketId,
        q: &UploadListQuery,
    ) -> Result<Vec<OpenUpload>> {
        match &self.unit {
            Some(route) => route.client.list_uploads(bucket, q).await,
            None => self.cat.list_uploads(bucket, q).await,
        }
    }
    async fn put_upload_part(
        &self,
        t: &UploadTarget<'_>,
        part: &UploadPartRow,
        extent: &ExtentRow,
        now: UnixMs,
    ) -> Result<Guard<()>> {
        match &self.unit {
            Some(route) => route.client.put_upload_part(t, part, extent, now).await,
            None => self.cat.put_upload_part(t, part, extent, now).await,
        }
    }
    async fn put_upload_part_sliced(
        &self,
        t: &UploadTarget<'_>,
        part: &UploadPartRow,
        extents: &[ExtentRow],
        write: &WriteId,
        now: UnixMs,
    ) -> Result<Guard<()>> {
        match &self.unit {
            Some(route) => {
                route
                    .client
                    .put_upload_part_sliced(t, part, extents, write, now)
                    .await
            }
            None => {
                self.cat
                    .put_upload_part_sliced(t, part, extents, write, now)
                    .await
            }
        }
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
        match &self.unit {
            Some(route) => {
                route
                    .client
                    .complete_upload(t, revision, digest, c, condition, record)
                    .await
            }
            None => {
                self.cat
                    .complete_upload(t, revision, digest, c, condition, record)
                    .await
            }
        }
    }
    async fn upload_extents(&self, t: &UploadTarget<'_>, limit: u32) -> Result<Vec<PartExtent>> {
        match &self.unit {
            Some(route) => route.client.upload_extents(t, limit).await,
            None => self.cat.upload_extents(t, limit).await,
        }
    }
    async fn upload_extents_held(&self, upload: &UploadId, except: u16) -> Result<u64> {
        match &self.unit {
            Some(route) => route.client.upload_extents_held(upload, except).await,
            None => self.cat.upload_extents_held(upload, except).await,
        }
    }
    async fn abort_upload(&self, t: &UploadTarget<'_>, now: UnixMs) -> Result<Guard<()>> {
        match &self.unit {
            Some(route) => route.client.abort_upload(t, now).await,
            None => self.cat.abort_upload(t, now).await,
        }
    }
    async fn claim(
        &self,
        extent: &ExtentId,
        generation: &GenerationId,
        stage: OutboxStage,
        owner: &str,
        now: UnixMs,
    ) -> Result<Option<Lease>> {
        self.cat.claim(extent, generation, stage, owner, now).await
    }
    async fn renew(&self, l: &Lease, now: UnixMs) -> Result<bool> {
        self.cat.renew(l, now).await
    }
    async fn advance(
        &self,
        l: &Lease,
        to: OutboxStage,
        next_at: UnixMs,
        now: UnixMs,
    ) -> Result<bool> {
        self.cat.advance(l, to, next_at, now).await
    }
    async fn fail(
        &self,
        l: &Lease,
        class: FailClass,
        next_at: UnixMs,
        now: UnixMs,
    ) -> Result<bool> {
        self.cat.fail(l, class, next_at, now).await
    }
    async fn set_cursor(&self, l: &Lease, cursor: u32, now: UnixMs) -> Result<bool> {
        self.cat.set_cursor(l, cursor, now).await
    }
    async fn defer(&self, l: &Lease, next_at: UnixMs, now: UnixMs) -> Result<bool> {
        self.cat.defer(l, next_at, now).await
    }
    async fn defer_at(&self, l: &Lease, cursor: u32, next_at: UnixMs, now: UnixMs) -> Result<bool> {
        self.cat.defer_at(l, cursor, next_at, now).await
    }
    async fn job_extent(
        &self,
        extent: &ExtentId,
        generation: &GenerationId,
    ) -> Result<Option<JobExtent>> {
        self.cat.job_extent(extent, generation).await
    }
    async fn plan_articles(
        &self,
        l: &Lease,
        rows: &[ArticleRow],
    ) -> Result<Option<Vec<ArticleRow>>> {
        self.cat.plan_articles(l, rows).await
    }
    async fn plan_packed(
        &self,
        l: &Lease,
        cipher_size: u64,
        plan: &[u8],
        parity: Option<&[u8]>,
    ) -> Result<Option<StoredPlan>> {
        self.cat.plan_packed(l, cipher_size, plan, parity).await
    }
    async fn articles(&self, extent: &ExtentId) -> Result<Vec<ArticleRow>> {
        match &self.unit {
            Some(route) => route.client.articles(extent).await,
            None => self.cat.articles(extent).await,
        }
    }
    async fn stored_plan(&self, extent: &ExtentId) -> Result<StoredPlan> {
        self.cat.stored_plan(extent).await
    }
    async fn mark_posted(&self, l: &Lease, idx: u32, provider: &str, now: UnixMs) -> Result<bool> {
        self.cat.mark_posted(l, idx, provider, now).await
    }
    async fn mark_posted_many(
        &self,
        l: &Lease,
        posted: &[(u32, &str)],
        now: UnixMs,
    ) -> Result<bool> {
        self.cat.mark_posted_many(l, posted, now).await
    }
    async fn mark_reposted_many(&self, l: &Lease, idxs: &[u32], now: UnixMs) -> Result<bool> {
        self.cat.mark_reposted_many(l, idxs, now).await
    }
    async fn renew_all(
        &self,
        l: &Lease,
        permits: &[Permit],
        now: UnixMs,
    ) -> Result<(bool, Vec<bool>)> {
        self.cat.renew_all(l, permits, now).await
    }
    async fn record_verification(&self, l: &Lease, v: &VerificationRow) -> Result<bool> {
        self.cat.record_verification(l, v).await
    }
    async fn backbone_status(&self, extent: &ExtentId) -> Result<Vec<BackboneStatus>> {
        self.cat.backbone_status(extent).await
    }
    async fn body_checks(&self, extent: &ExtentId) -> Result<Vec<BackboneStatus>> {
        self.cat.body_checks(extent).await
    }
    async fn begin_release(
        &self,
        l: &Lease,
        required: u32,
        counting: &[String],
        evidence_json: &str,
        now: UnixMs,
    ) -> Result<Guard<()>> {
        self.cat
            .begin_release(l, required, counting, evidence_json, now)
            .await
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
        self.cat
            .begin_release_light(l, required, counting, evidence_json, now, need_full)
            .await
    }
    async fn escalate_verify(&self, e: &VerifyEscalation, plan_rev: u32) -> Result<()> {
        self.cat.escalate_verify(e, plan_rev).await
    }
    async fn verify_raised(
        &self,
        extent: &ExtentId,
        backbone: &str,
        plan_rev: u32,
    ) -> Result<bool> {
        self.cat.verify_raised(extent, backbone, plan_rev).await
    }
    async fn verify_escalations(&self, at: UnixMs) -> Result<Vec<VerifyEscalation>> {
        self.cat.verify_escalations(at).await
    }
    async fn finish_release(&self, l: &Lease, now: UnixMs) -> Result<bool> {
        self.cat.finish_release(l, now).await
    }
    async fn due(&self, now: UnixMs, resend: Resend, limit: u32) -> Result<Vec<DueRow>> {
        self.cat.due(now, resend, limit).await
    }
    async fn mark_sent(&self, extents: &[ExtentId], now: UnixMs) -> Result<u64> {
        self.cat.mark_sent(extents, now).await
    }
    async fn unmark_sent(&self, jobs: &[Job], mark: UnixMs) -> Result<u64> {
        self.cat.unmark_sent(jobs, mark).await
    }
    async fn bury_exhausted(&self, max_attempts: u32, now: UnixMs) -> Result<u64> {
        self.cat.bury_exhausted(max_attempts, now).await
    }
    async fn record_dispatch(&self, now: UnixMs) -> Result<()> {
        self.cat.record_dispatch(now).await
    }
    async fn outbox_stats(&self) -> Result<OutboxStats> {
        match &self.unit {
            Some(route) => route.client.outbox_stats().await,
            None => self.cat.outbox_stats().await,
        }
    }
    async fn guard_selftest(&self) -> Result<bool> {
        self.cat.guard_selftest().await
    }
    async fn gc_due(&self, now: UnixMs, limit: u32, disposable_only: bool) -> Result<Vec<GcRow>> {
        self.cat.gc_due(now, limit, disposable_only).await
    }
    async fn gc_begin(&self, row: &GcRow, now: UnixMs) -> Result<GcStep> {
        self.cat.gc_begin(row, now).await
    }
    async fn gc_done(&self, id: i64, now: UnixMs) -> Result<()> {
        self.cat.gc_done(id, now).await
    }
    async fn replay_probe(&self, g: &GenerationRow) -> Result<ReplayProbe> {
        match &self.unit {
            Some(route) => route.client.replay_probe(g).await,
            None => self.cat.replay_probe(g).await,
        }
    }
    async fn replay_extents(
        &self,
        bucket: &Bucket,
        extents: &[ReplayExtent],
        now: UnixMs,
    ) -> Result<Vec<ExtentId>> {
        self.cat.replay_extents(bucket, extents, now).await
    }
    async fn held_extents(&self, after: &str, limit: u32) -> Result<Vec<ExtentId>> {
        self.cat.held_extents(after, limit).await
    }
    async fn restore_begin(
        &self,
        since: UnixMs,
        now: UnixMs,
    ) -> Result<std::result::Result<UnixMs, UnixMs>> {
        self.cat.restore_begin(since, now).await
    }
    async fn restore_finish(
        &self,
        run: UnixMs,
        now: UnixMs,
        stamp: u64,
        seen: Option<u64>,
        catalogue: &str,
    ) -> Result<bool> {
        self.cat
            .restore_finish(run, now, stamp, seen, catalogue)
            .await
    }
    async fn restore_pending(&self) -> Result<bool> {
        match &self.unit {
            Some(route) => route.client.restore_pending().await,
            None => self.cat.restore_pending().await,
        }
    }
    async fn stamp(&self, catalogue: &str) -> Result<crate::stamp::StampRow> {
        self.cat.stamp(catalogue).await
    }
    async fn stamp_advance(&self, from: Option<u64>, catalogue: &str) -> Result<bool> {
        self.cat.stamp_advance(from, catalogue).await
    }
    async fn stamp_rolled_back(
        &self,
        seen: Option<u64>,
        now: UnixMs,
        catalogue: &str,
    ) -> Result<bool> {
        self.cat.stamp_rolled_back(seen, now, catalogue).await
    }
    async fn restore_progress(&self, run: UnixMs) -> Result<Option<RestoreProgress>> {
        self.cat.restore_progress(run).await
    }
    async fn restore_advance(&self, run: UnixMs, next: &ReplayMark) -> Result<()> {
        self.cat.restore_advance(run, next).await
    }
    async fn replay_tombstone(
        &self,
        bucket: &BucketId,
        key: &str,
        id: &GenerationId,
        now: UnixMs,
    ) -> Result<bool> {
        self.cat.replay_tombstone(bucket, key, id, now).await
    }
    async fn replay_damaged(&self, limit: u32) -> Result<(u64, Vec<GenerationId>)> {
        self.cat.replay_damaged(limit).await
    }
    async fn replay_publish(
        &self,
        g: &GenerationRow,
        placements: &[ExtentPlacement],
        now: UnixMs,
    ) -> Result<ReplayPublish> {
        self.cat.replay_publish(g, placements, now).await
    }
    async fn replay_twin(
        &self,
        g: &GenerationRow,
        placements: &[ExtentPlacement],
    ) -> Result<Option<GenerationId>> {
        self.cat.replay_twin(g, placements).await
    }
    async fn seed_permits(&self, providers: &[ProviderConfig]) -> Result<()> {
        self.cat.seed_permits(providers).await
    }
    async fn acquire_permit(
        &self,
        p: &ProviderConfig,
        class: PermitClass,
        holder: &str,
        now: UnixMs,
    ) -> Result<Option<Permit>> {
        self.cat.acquire_permit(p, class, holder, now).await
    }
    async fn renew_permit(&self, p: &Permit, now: UnixMs) -> Result<bool> {
        self.cat.renew_permit(p, now).await
    }
    async fn release_permit(&self, p: &Permit) -> Result<()> {
        self.cat.release_permit(p).await
    }
    fn forget_permit(&self, _p: &Permit) {
        self.cat.forget_permit(_p)
    }
    async fn provider_load(&self, now: UnixMs) -> Result<Vec<ProviderLoad>> {
        self.cat.provider_load(now).await
    }
    async fn provider_status(&self, now: UnixMs) -> Result<Vec<ProviderLoad>> {
        self.cat.provider_status(now).await
    }
    async fn provider_failed(
        &self,
        provider: &str,
        fault: ProviderFault,
        now: UnixMs,
    ) -> Result<()> {
        self.cat.provider_failed(provider, fault, now).await
    }
    async fn provider_recovered(&self, provider: &str, now: UnixMs) -> Result<()> {
        self.cat.provider_recovered(provider, now).await
    }
    async fn providers_to_probe(
        &self,
        now: UnixMs,
        quiet_since: UnixMs,
        login_quiet_since: UnixMs,
    ) -> Result<Vec<String>> {
        self.cat
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
        self.cat
            .redrive_underverified(backbones, required, limit, now)
            .await
    }
    async fn revive_referenced(&self, limit: u32, now: UnixMs) -> Result<u64> {
        self.cat.revive_referenced(limit, now).await
    }
    async fn pack_plans(&self, limit: u32) -> Result<PackReport> {
        self.cat.pack_plans(limit).await
    }
    async fn usage_counters(&self) -> Result<UsageCounters> {
        match &self.unit {
            Some(route) => route.client.usage_counters().await,
            None => self.cat.usage_counters().await,
        }
    }
    async fn usage_snapshot(&self, hours: u32) -> Result<UsageSnapshot> {
        match &self.unit {
            Some(route) => route.client.usage_snapshot(hours).await,
            None => self.cat.usage_snapshot(hours).await,
        }
    }
    async fn usage_buckets(&self, after: &str, limit: u32) -> Result<(bool, Vec<BucketUsage>)> {
        match &self.unit {
            Some(route) => route.client.usage_buckets(after, limit).await,
            None => self.cat.usage_buckets(after, limit).await,
        }
    }
    async fn usage_recount_start(
        &self,
        now: UnixMs,
        adopt: bool,
        restart: bool,
        only_on: bool,
    ) -> Result<bool> {
        self.cat
            .usage_recount_start(now, adopt, restart, only_on)
            .await
    }
    async fn usage_recount_step(&self, chunk: u32, now: UnixMs) -> Result<RecountStep> {
        self.cat.usage_recount_step(chunk, now).await
    }
    async fn usage_recounts(&self) -> Result<(RecountState, Option<UsageRecount>)> {
        match &self.unit {
            Some(route) => route.client.usage_recounts().await,
            None => self.cat.usage_recounts().await,
        }
    }
    async fn usage_off(&self) -> Result<()> {
        self.cat.usage_off().await
    }
    async fn hot_stats(&self) -> Result<HotStats> {
        match &self.unit {
            Some(route) => route.client.hot_stats().await,
            None => self.cat.hot_stats().await,
        }
    }
    async fn evictable_bytes(&self) -> Result<u64> {
        self.cat.evictable_bytes().await
    }
    async fn evict_candidates(&self, limit: u32) -> Result<Vec<EvictCandidate>> {
        self.cat.evict_candidates(limit).await
    }
    async fn begin_evict(&self, x: &EvictCandidate) -> Result<bool> {
        self.cat.begin_evict(x).await
    }
    async fn finish_evict(&self, x: &EvictCandidate) -> Result<bool> {
        self.cat.finish_evict(x).await
    }
    async fn record_cache_fill(&self, extent: &ExtentId, now: UnixMs) -> Result<()> {
        match &self.unit {
            Some(route) => route.client.record_cache_fill(extent, now).await,
            None => self.cat.record_cache_fill(extent, now).await,
        }
    }
    async fn touch_read(
        &self,
        extent: &ExtentId,
        now: UnixMs,
        min_gap_ms: i64,
        from_cache: bool,
    ) -> Result<UnixMs> {
        match &self.unit {
            Some(route) => {
                route
                    .client
                    .touch_read(extent, now, min_gap_ms, from_cache)
                    .await
            }
            None => {
                self.cat
                    .touch_read(extent, now, min_gap_ms, from_cache)
                    .await
            }
        }
    }
    async fn hot_check_due(&self, now: UnixMs, every_ms: i64) -> Result<bool> {
        self.cat.hot_check_due(now, every_ms).await
    }
    async fn hot_checked(&self, now: UnixMs) -> Result<()> {
        self.cat.hot_checked(now).await
    }
    async fn hot_drain_set(&self, left: u64) -> Result<()> {
        self.cat.hot_drain_set(left).await
    }
    async fn hot_drain_claim(&self, left: u64) -> Result<bool> {
        self.cat.hot_drain_claim(left).await
    }
    async fn hot_seq(&self, extent: &ExtentId) -> Result<u64> {
        match &self.unit {
            Some(route) => route.client.hot_seq(extent).await,
            None => self.cat.hot_seq(extent).await,
        }
    }
    async fn hot_forget(
        &self,
        extent: &ExtentId,
        seq: u64,
        safety: bool,
        cache: bool,
    ) -> Result<bool> {
        self.cat.hot_forget(extent, seq, safety, cache).await
    }
}
pub type TestBridge<N> = Bridge<TestCatalog, Blobs, N, Jobs, TestKek, FixedClock>;

// ---------------------------------------------------------------------------
// A connector for tests that must never reach Usenet
// ---------------------------------------------------------------------------

pub struct NoNntp;
pub enum NoSession {}

impl NntpSession for NoSession {
    async fn post(&mut self, _: &str, _: &[u8]) -> Result<velmora::nntp::PostOutcome> {
        match *self {}
    }
    async fn stat(&mut self, _: &str) -> Result<bool> {
        match *self {}
    }
    async fn body(&mut self, _: &str, _: &mut Vec<u8>) -> Result<BodyOutcome> {
        match *self {}
    }
    async fn quit(self) {
        match self {}
    }
}

impl NntpConnector for NoNntp {
    type Session = NoSession;
    async fn connect(&self, _: &ProviderConfig, _: &Permit) -> Result<NoSession> {
        panic!("this test must not open an NNTP session");
    }
}

/// A job sink that records sends and can be made to fail.
#[derive(Default)]
pub struct Jobs {
    pub inner: FakeJobs,
    pub fail: Cell<bool>,
}

impl JobSink for Jobs {
    async fn send(&self, job: &Job, delay_secs: u32) -> Result<()> {
        if self.fail.get() {
            return Err(BridgeError::Queue("queue down".into()));
        }
        self.inner.send(job, delay_secs).await
    }
    async fn send_many(&self, jobs: &[Job]) -> Result<()> {
        if self.fail.get() {
            return Err(BridgeError::Queue("queue down".into()));
        }
        self.inner.send_many(jobs).await
    }
}

/// What happens at one call of a store or of the database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trip {
    /// The call never answers: the request stops here. Dropping its
    /// future is a handler that was killed at this point;
    /// [`Tripwire::release`] lets it go on.
    Stall,
    /// The call fails and did nothing.
    Fail,
    /// The call is carried out and then fails: no answer.
    Lost,
}

/// Counts the calls of the safety store and of the database of a rig,
/// and trips one of them.
#[derive(Clone, Default)]
pub struct Tripwire(Rc<TripState>);

#[derive(Default)]
struct TripState {
    armed: Cell<Option<(u64, Trip)>>,
    held: Cell<bool>,
    calls: Cell<u64>,
    /// State of the generator behind [`Tripwire::jitter`].
    jitter: Cell<Option<u64>>,
}

impl Tripwire {
    /// Trips the call that comes after `skip` more calls.
    pub fn arm(&self, skip: u64, trip: Trip) {
        self.0.armed.set(Some((skip, trip)));
    }

    pub fn disarm(&self) {
        self.0.armed.set(None);
        self.0.held.set(false);
    }

    /// Whether the wire tripped (it disarms itself when it does).
    pub fn tripped(&self) -> bool {
        self.0.armed.get().is_none()
    }

    /// Lets a stalled call go on.
    pub fn release(&self) {
        self.0.held.set(false);
    }

    /// From now on every call first lets the other requests of the test
    /// run, zero to three times, as `seed` decides: requests that are
    /// polled together then take their store and database calls in an
    /// order that differs from seed to seed and repeats for one seed.
    pub fn jitter(&self, seed: u64) {
        // Never zero: the generator would stay there.
        self.0
            .jitter
            .set(Some(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1));
    }

    /// Calls seen so far.
    pub fn calls(&self) -> u64 {
        self.0.calls.get()
    }

    /// `Some` = the caller fails, before (`Fail`) or after (`Lost`)
    /// doing its work.
    async fn cross(&self) -> Option<Trip> {
        self.0.calls.set(self.0.calls.get() + 1);
        if let Some(mut x) = self.0.jitter.get() {
            // xorshift64
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0.jitter.set(Some(x));
            for _ in 0..(x >> 32) % 4 {
                tokio::task::yield_now().await;
            }
        }
        match self.0.armed.get() {
            None => None,
            Some((0, trip)) => {
                self.0.armed.set(None);
                if trip != Trip::Stall {
                    return Some(trip);
                }
                self.0.held.set(true);
                std::future::poll_fn(|_| {
                    if self.0.held.get() {
                        std::task::Poll::Pending
                    } else {
                        std::task::Poll::Ready(())
                    }
                })
                .await;
                None
            }
            Some((n, trip)) => {
                self.0.armed.set(Some((n - 1, trip)));
                None
            }
        }
    }

    /// Runs one call of a store under the wire.
    async fn guard<V>(
        &self,
        down: fn() -> BridgeError,
        call: impl std::future::Future<Output = Result<V>>,
    ) -> Result<V> {
        match self.cross().await {
            None => call.await,
            Some(Trip::Lost) => {
                call.await?;
                Err(down())
            }
            Some(_) => Err(down()),
        }
    }
}

fn blob_down() -> BridgeError {
    BridgeError::Blob("store down".into())
}

fn sql_down() -> BridgeError {
    BridgeError::Sql("no answer".into())
}

/// A blob store whose writes can be made to fail.
#[derive(Default)]
pub struct Blobs {
    pub inner: MemBlobStore,
    /// Every call crosses it first.
    pub trip: Tripwire,
    pub fail_put: Cell<bool>,
    /// Puts of keys with this prefix fail.
    pub fail_put_prefix: RefCell<Option<String>>,
    /// Every put that was sent, also one that failed: its key and the
    /// SHA-256 of its bytes.
    pub puts: RefCell<Vec<(String, [u8; 32])>>,
    /// The next list call waits until `list_held` is cleared again.
    pub hold_list: Cell<bool>,
    /// A list call is waiting.
    pub list_held: Cell<bool>,
    /// With `hold_list`: the held call reads its keys before it waits,
    /// not after.
    pub list_first: Cell<bool>,
    /// Every list call fails.
    pub fail_list: Cell<bool>,
    /// This many deletes of a recovery record fail.
    pub fail_record_deletes: Cell<u32>,
    /// Deleting this key fails.
    pub fail_delete: RefCell<Option<String>>,
    /// The next this many deletes fail.
    pub fail_deletes: Cell<u32>,
    /// Called once, with the key, at the start of the next delete.
    pub before_delete: Hook,
    /// Called once, with the key, at the start of the next put.
    pub before_put: Hook,
    /// A put of a key with this prefix waits until this is cleared.
    pub hold_put_prefix: RefCell<Option<String>>,
    /// A put is waiting.
    pub held: Cell<bool>,
}

/// How long a held call waits, in turns of the executor.
pub const HOLD_TURNS: u32 = 100_000;

/// Something that happens in the middle of an operation on a store.
pub type Hook = RefCell<Option<Box<dyn FnOnce(&str)>>>;

fn fire(hook: &Hook, key: &str) {
    let hook = hook.borrow_mut().take();
    if let Some(hook) = hook {
        hook(key);
    }
}

impl std::ops::Deref for Blobs {
    type Target = MemBlobStore;
    fn deref(&self) -> &MemBlobStore {
        &self.inner
    }
}

impl BlobStore for Blobs {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.puts
            .borrow_mut()
            .push((key.to_string(), Sha256::digest(&bytes).into()));
        fire(&self.before_put, key);
        let holds = |key: &str| {
            let prefix = self.hold_put_prefix.borrow();
            prefix.as_deref().is_some_and(|p| key.starts_with(p))
        };
        while holds(key) {
            self.held.set(true);
            tokio::task::yield_now().await;
        }
        let refused = self
            .fail_put_prefix
            .borrow()
            .as_deref()
            .is_some_and(|p| key.starts_with(p));
        if self.fail_put.get() || refused {
            return Err(BridgeError::Blob("store down".into()));
        }
        self.trip
            .guard(blob_down, self.inner.put(key, bytes, meta))
            .await
    }
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.trip.guard(blob_down, self.inner.get(key, span)).await
    }
    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.trip.guard(blob_down, self.inner.head(key)).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        fire(&self.before_delete, key);
        if self.fail_delete.borrow().as_deref() == Some(key) {
            return Err(BridgeError::Blob("store down".into()));
        }
        if self.fail_deletes.get() > 0 {
            self.fail_deletes.set(self.fail_deletes.get() - 1);
            return Err(BridgeError::Blob("store down".into()));
        }
        self.trip.guard(blob_down, self.inner.delete(key)).await
    }
    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        // The faults of `delete` hold for the delete of a record too.
        if self.fail_delete.borrow().as_deref() == Some(refused.key().as_str()) {
            return Err(BridgeError::Blob("store down".into()));
        }
        if self.fail_deletes.get() > 0 {
            self.fail_deletes.set(self.fail_deletes.get() - 1);
            return Err(BridgeError::Blob("store down".into()));
        }
        let left = self.fail_record_deletes.get();
        if left > 0 {
            self.fail_record_deletes.set(left - 1);
            return Err(BridgeError::Blob("store down".into()));
        }
        self.trip
            .guard(blob_down, self.inner.delete_record(refused))
            .await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        if self.fail_list.get() {
            return Err(BridgeError::Blob("list failed".into()));
        }
        if !self.hold_list.take() {
            return self
                .trip
                .guard(blob_down, self.inner.list(prefix, start_after, limit))
                .await;
        }
        let early = match self.list_first.take() {
            true => Some(self.inner.list(prefix, start_after, limit).await),
            false => None,
        };
        self.list_held.set(true);
        // Bounded: a test that never lets go fails instead of hanging.
        for _ in 0..HOLD_TURNS {
            if !self.list_held.get() {
                return match early {
                    Some(keys) => keys,
                    None => self.inner.list(prefix, start_after, limit).await,
                };
            }
            tokio::task::yield_now().await;
        }
        panic!("the held list call was never let go");
    }
}

/// A database whose writes can be made to fail; reads keep working.
pub struct FailSql {
    pub inner: RusqliteSql,
    pub fail_writes: Cell<bool>,
    /// Fails the next batch that publishes a generation, once.
    pub fail_publish: Cell<Option<PublishFault>>,
    pub fail_next_batch: Cell<bool>,
    /// Fails every statement (read or write) whose text contains the
    /// string, after letting the given number of them through.
    pub fail_matching: RefCell<Option<(&'static str, u32)>>,
    /// Runs the given SQL once, just before a read whose text contains
    /// the string, after letting the given number of such reads through:
    /// what another request commits between two reads of this one.
    pub before_matching: RefCell<Option<(&'static str, u32, String)>>,
    /// Fails this many batches, the next ones: a commit that does not
    /// go through while single statements still do.
    pub fail_batches: Cell<u32>,
    /// Answers this many statements, the next ones of any kind, the way
    /// D1 does after a large batch that did not commit ([`OVERLOADED`]).
    /// In unit mode: this many unit calls.
    pub overloaded: Cell<u32>,
    /// Every call crosses it first. In unit mode a unit call crosses it
    /// once, and the statements inside the call do not.
    pub trip: Tripwire,
    /// Set while a unit call runs (unit mode).
    pub in_unit: Cell<bool>,
}

/// How a publication batch fails: D1 may answer with an error before it
/// wrote anything, or after it committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishFault {
    NotApplied,
    Applied,
    /// Not applied, and the batch after it fails as well.
    Down,
    /// Not applied, and D1 answers the given number of statements after
    /// it, reads included, with [`OVERLOADED`].
    Overloaded(u32),
    /// Run in full and refused by a guard at its end, and then as
    /// `Overloaded`: what D1 did after a large refused batch.
    RefusedOverloaded(u32),
}

/// What D1 answers while a database is over its budget of the last ten
/// seconds. A batch that is refused is charged in full, so the first
/// statement after a large one can get this.
pub const OVERLOADED: &str =
    "D1_ERROR: D1 DB is overloaded. Too many resources consumed within a 10 second window.";

impl FailSql {
    fn refused(&self, sql: &str) -> bool {
        let mut rule = self.fail_matching.borrow_mut();
        match rule.as_mut() {
            Some((text, pass)) if sql.contains(*text) => {
                let refuse = *pass == 0;
                *pass = pass.saturating_sub(1);
                refuse
            }
            _ => false,
        }
    }

    /// Commits what was set to happen before this read, if it is the one.
    fn interleave(&self, sql: &str) {
        let mut rule = self.before_matching.borrow_mut();
        let due = match rule.as_mut() {
            Some((text, pass, _)) if sql.contains(*text) => {
                let due = *pass == 0;
                *pass = pass.saturating_sub(1);
                due
            }
            _ => false,
        };
        if due {
            let (_, _, other) = rule.take().unwrap();
            self.inner.with_conn(|c| c.execute_batch(&other).unwrap());
        }
    }

    /// Whether this statement is one of those answered "overloaded".
    fn over_budget(&self) -> Result<()> {
        if self.in_unit.get() {
            return Ok(());
        }
        match self.overloaded.get() {
            0 => Ok(()),
            n => {
                self.overloaded.set(n - 1);
                Err(BridgeError::Sql(OVERLOADED.into()))
            }
        }
    }
}

impl std::ops::Deref for FailSql {
    type Target = RusqliteSql;
    fn deref(&self) -> &RusqliteSql {
        &self.inner
    }
}

impl Sql for FailSql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.over_budget()?;
        if self.refused(sql) {
            return Err(BridgeError::Sql("database down".into()));
        }
        self.interleave(sql);
        if self.in_unit.get() {
            return self.inner.query(sql, params).await;
        }
        self.trip
            .guard(sql_down, self.inner.query(sql, params))
            .await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.over_budget()?;
        if self.fail_writes.get() || self.refused(sql) {
            return Err(BridgeError::Sql("database down".into()));
        }
        if self.in_unit.get() {
            return self.inner.exec(sql, params).await;
        }
        self.trip
            .guard(sql_down, self.inner.exec(sql, params))
            .await
    }
    async fn batch(&self, mut stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        self.over_budget()?;
        if self.fail_writes.get() {
            return Err(BridgeError::Sql("database down".into()));
        }
        if self.fail_batches.get() > 0 {
            self.fail_batches.set(self.fail_batches.get() - 1);
            return Err(BridgeError::Sql("database down".into()));
        }
        if self.fail_next_batch.take() {
            return Err(BridgeError::Sql("no answer".into()));
        }
        let publishes = stmts
            .iter()
            .any(|(sql, _)| sql.starts_with("INSERT INTO generations"));
        if publishes {
            match self.fail_publish.take() {
                Some(PublishFault::NotApplied) => {
                    return Err(BridgeError::Sql("no answer".into()));
                }
                Some(PublishFault::Down) => {
                    self.fail_next_batch.set(true);
                    return Err(BridgeError::Sql("no answer".into()));
                }
                Some(PublishFault::Applied) => {
                    self.inner.batch(stmts).await?;
                    return Err(BridgeError::Sql("no answer".into()));
                }
                Some(PublishFault::Overloaded(n)) => {
                    self.overloaded.set(n);
                    return Err(BridgeError::Sql("no answer".into()));
                }
                Some(PublishFault::RefusedOverloaded(n)) => {
                    self.overloaded.set(n);
                    stmts.push(("INSERT INTO tx_guard(ok) VALUES (0)", vec![]));
                    return self.inner.batch(stmts).await;
                }
                None => {}
            }
        }
        if self.in_unit.get() {
            return self.inner.batch(stmts).await;
        }
        self.trip.guard(sql_down, self.inner.batch(stmts)).await
    }
}

// ---------------------------------------------------------------------------
// Rig
// ---------------------------------------------------------------------------

pub fn config(providers: Vec<ProviderConfig>) -> BridgeConfig {
    BridgeConfig {
        environment: Environment::Dev,
        s3_host: HOST.to_string(),
        region: REGION.to_string(),
        max_extent_bytes: 16 * 1024 * 1024,
        max_put_bytes: 16 * 1024 * 1024,
        slice_bytes: 8 * 1024 * 1024,
        max_object_extents: 10_000,
        intent_sweep: false,
        records: velmora_bridge::recovery::Layout::flat(),
        packed_plans: false,
        parity: false,
        required_backbones: 1,
        safety_min_age_secs: 0,
        verify_delay_secs: 30,
        post_sockets: 4,
        cold_sockets: 4,
        propagation_grace_secs: 21_600,
        newsgroups: vec!["alt.binaries.test".to_string()],
        kek_active: 1,
        inflight_budget_bytes: 48 * 1024 * 1024,
        job_budget_bytes: 48 * 1024 * 1024,
        gc_mode: GcMode::Disposable,
        hot_cap_bytes: velmora_bridge::config::DEFAULT_HOT_CAP_BYTES,
        maintenance: Maintenance::Off,
        server_side_copy: true,
        get_fanout_bytes: None,
        catalogue_id: "main".to_string(),
        dev_trust_http: false,
        verify: Default::default(),
        providers,
        admin_token: Secret::new("admin-token-fixture-admin-token-fixture".to_string()),
        admin_read_token: None,
        admin_host: None,
        metrics_sample: 10,
    }
}

pub struct Rig<N: NntpConnector + 'static = NoNntp> {
    pub bridge: Rc<TestBridge<N>>,
}

pub fn rig() -> Rig {
    rig_with(NoNntp, config(Vec::new()))
}

pub fn rig_with<N: NntpConnector + 'static>(nntp: N, cfg: BridgeConfig) -> Rig<N> {
    let budget = ByteBudget::new(cfg.inflight_budget_bytes);
    rig_with_budget(nntp, cfg, budget)
}

/// A rig whose byte budget is `budget` (for example one with a sleeper).
pub fn rig_with_budget<N: NntpConnector + 'static>(
    nntp: N,
    cfg: BridgeConfig,
    budget: ByteBudget,
) -> Rig<N> {
    rig_on(nntp, cfg, budget, on_unit())
}

/// A rig that serves through a unit whatever `VELMORA_UNIT_REQUESTS`
/// says.
pub fn unit_rig() -> Rig {
    let cfg = config(Vec::new());
    let budget = ByteBudget::new(cfg.inflight_budget_bytes);
    rig_on(NoNntp, cfg, budget, true)
}

/// A rig on tenant 0's catalogue (`unit = false`) or on a unit.
pub fn rig_on<N: NntpConnector + 'static>(
    nntp: N,
    cfg: BridgeConfig,
    budget: ByteBudget,
    unit: bool,
) -> Rig<N> {
    // One wire over the safety store and the database: a request is a
    // single sequence of calls to the two.
    let trip = Tripwire::default();
    Rig {
        bridge: Rc::new(Bridge {
            catalog: TestCatalog::new(
                FailSql {
                    trip: trip.clone(),
                    // A unit applies its own schema at its birth.
                    inner: if unit {
                        RusqliteSql::open_in_memory().unwrap()
                    } else {
                        RusqliteSql::with_schema().unwrap()
                    },
                    fail_writes: Cell::new(false),
                    fail_publish: Cell::new(None),
                    fail_next_batch: Cell::new(false),
                    fail_matching: RefCell::new(None),
                    before_matching: RefCell::new(None),
                    fail_batches: Cell::new(0),
                    overloaded: Cell::new(0),
                    in_unit: Cell::new(false),
                },
                unit,
            ),
            safety: Blobs {
                trip,
                ..Blobs::default()
            },
            cache: Blobs::default(),
            nntp,
            jobs: Jobs::default(),
            kek: TestKek::new(),
            clock: FixedClock::new(T0),
            budget,
            cfg,
        }),
    }
}

impl<N: NntpConnector + 'static> Rig<N> {
    /// Creates a bucket with a fresh data key.
    pub async fn bucket(&self, name: &str, disposable: bool) -> Bucket {
        let mut rng = SystemRng;
        let seed = sha256(name.as_bytes());
        let id = BucketId::mint(seed[..8].try_into().unwrap());
        let bdk = DataKey::generate(&mut rng).unwrap();
        let (kek_version, wrapped) = wrap_bdk(&self.bridge.kek, &id, &bdk, &mut rng).unwrap();
        let bucket = Bucket {
            id,
            name: name.to_string(),
            owner: "owner".to_string(),
            bdk_wrapped: wrapped.to_vec(),
            kek_version,
            disposable,
            created_at: T0,
        };
        assert_eq!(
            self.bridge.catalog.create_bucket(&bucket).await.unwrap(),
            Guard::Applied(())
        );
        bucket
    }

    /// Stores an access key and returns its signer.
    pub async fn key(&self, akid: &str, secret: &str, status: KeyStatus) -> Signer {
        let (kek_version, secret_wrapped) =
            wrap_secret(&self.bridge.kek, akid, secret.as_bytes(), &mut SystemRng).unwrap();
        self.bridge
            .catalog
            .create_access_key(&AccessKeyRow {
                access_key_id: akid.to_string(),
                principal: format!("principal-{akid}"),
                secret_wrapped,
                kek_version,
                status,
                created_at: T0,
            })
            .await
            .unwrap();
        Signer::new(akid, secret)
    }

    pub async fn grant(&self, akid: &str, bucket: &Bucket, perm: Perm) {
        self.bridge
            .catalog
            .put_grant(akid, &bucket.id, perm)
            .await
            .unwrap();
    }

    /// One disposable bucket and one read-write key on it.
    pub async fn standard(&self, bucket: &str) -> (Bucket, Signer) {
        let b = self.bucket(bucket, true).await;
        let signer = self.key(AKID, secret(), KeyStatus::Active).await;
        self.grant(AKID, &b, Perm::Rw).await;
        (b, signer)
    }

    pub fn now(&self) -> UnixMs {
        self.bridge.clock.now()
    }

    /// The wire over the safety store and the database.
    pub fn trip(&self) -> &Tripwire {
        &self.bridge.safety.trip
    }

    pub async fn send(&self, req: Req) -> Resp {
        let resp = Rc::clone(&self.bridge).handle(req.into_request()).await;
        Resp::collect(resp).await
    }

    /// Signs with `signer` at the rig's clock and sends.
    pub async fn call(
        &self,
        signer: &Signer,
        method: Method,
        raw_path: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Resp {
        self.send(signer.sign(self.now(), method, raw_path, query, headers, body.to_vec()))
            .await
    }

    pub async fn put(&self, signer: &Signer, bucket: &str, key: &str, body: &[u8]) -> Resp {
        self.call(signer, Method::Put, &path(bucket, key), &[], &[], body)
            .await
    }

    pub async fn head(&self, signer: &Signer, bucket: &str, key: &str) -> Resp {
        self.call(signer, Method::Head, &path(bucket, key), &[], &[], b"")
            .await
    }

    /// Sends `req` with a body that records whether it was ever polled.
    pub async fn send_watched(&self, req: Req) -> (Resp, bool) {
        let polled = Rc::new(Cell::new(false));
        let flag = Rc::clone(&polled);
        let declared_len = req
            .headers
            .iter()
            .find(|(n, _)| n == "content-length")
            .and_then(|(_, v)| v.parse().ok());
        let body = req.body;
        let request = S3Request {
            method: req.method,
            raw_target: req.target,
            headers: req.headers,
            body: Body::Stream {
                declared_len,
                stream: stream::once(async move {
                    flag.set(true);
                    Ok(body)
                })
                .boxed_local(),
            },
        };
        let resp = Rc::clone(&self.bridge).handle(request).await;
        (Resp::collect(resp).await, polled.get())
    }

    /// The live generation and extents of a key, straight from the
    /// catalogue.
    pub async fn live(
        &self,
        bucket: &Bucket,
        key: &str,
    ) -> Option<(GenerationRow, Vec<ExtentRow>)> {
        self.bridge
            .catalog
            .live_object(&bucket.id, key)
            .await
            .unwrap()
    }

    /// Rows in a catalogue table.
    pub fn count(&self, table: &str) -> i64 {
        self.bridge.catalog.sql.with_conn(|c| {
            c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        })
    }
}

// ---------------------------------------------------------------------------
// SigV4 header signing (independent of the server's verifier)
// ---------------------------------------------------------------------------

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Deterministic bytes that do not repeat on a chunk boundary.
pub fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[seed as usize % 4] ^ seed)
        .collect()
}

/// Percent-encodes everything outside the RFC 3986 unreserved set
/// (uppercase hex); `/` is kept in paths.
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::new();
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `/bucket/key` with the key percent-encoded as SDKs send it.
pub fn path(bucket: &str, key: &str) -> String {
    format!("/{bucket}/{}", uri_encode(key, true))
}

/// Days since 1970-01-01 to (year, month, day).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[derive(Clone)]
pub struct Signer {
    pub akid: String,
    pub secret: String,
    pub region: String,
}

/// One request before it is handed to the bridge.
pub struct Req {
    pub method: Method,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.retain(|(n, _)| n != name);
        self.headers.push((name.to_string(), value.to_string()));
    }

    pub fn into_request(self) -> S3Request {
        let declared_len = self
            .headers
            .iter()
            .find(|(n, _)| n == "content-length")
            .and_then(|(_, v)| v.parse().ok());
        let body = if self.body.is_empty() && declared_len.is_none() {
            Body::Empty
        } else {
            Body::Stream {
                declared_len,
                stream: stream::iter(
                    self.body
                        .chunks(64 * 1024)
                        .map(|c| Ok(c.to_vec()))
                        .collect::<Vec<_>>(),
                )
                .boxed_local(),
            }
        };
        S3Request {
            method: self.method,
            raw_target: self.target,
            headers: self.headers,
            body,
        }
    }
}

impl Signer {
    pub fn new(akid: &str, secret: &str) -> Self {
        Signer {
            akid: akid.to_string(),
            secret: secret.to_string(),
            region: REGION.to_string(),
        }
    }

    /// Header-signs `method raw_path?query`. `raw_path` is sent and signed
    /// exactly as given; query pairs are given decoded. Every header in
    /// `extra` is signed. PUT always declares its length.
    pub fn sign(
        &self,
        now: UnixMs,
        method: Method,
        raw_path: &str,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Req {
        self.sign_as(now, method, raw_path, query, extra, body, None)
            .0
    }

    /// The timestamp, the credential scope and the signing key at `now`:
    /// what a chunk-signature chain is built from.
    pub fn scope(&self, now: UnixMs) -> (String, String, Vec<u8>) {
        let secs = now.0.div_euclid(1000);
        let (y, mo, d) = civil(secs.div_euclid(86_400));
        let t = secs.rem_euclid(86_400);
        let date = format!("{y:04}{mo:02}{d:02}");
        let stamp = format!("{date}T{:02}{:02}{:02}Z", t / 3600, t % 3600 / 60, t % 60);
        let mut key = hmac(format!("AWS4{}", self.secret).as_bytes(), date.as_bytes());
        for part in [self.region.as_str(), "s3", "aws4_request"] {
            key = hmac(&key, part.as_bytes());
        }
        (
            stamp,
            format!("{date}/{}/s3/aws4_request", self.region),
            key,
        )
    }

    /// [`Self::sign`] with an explicit `x-amz-content-sha256`
    /// (`UNSIGNED-PAYLOAD` or a `STREAMING-*` value): the body is not
    /// hashed and no `Content-Length` is added. Returns the request and
    /// its signature, the seed of a chunk-signature chain.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_as(
        &self,
        now: UnixMs,
        method: Method,
        raw_path: &str,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        body: Vec<u8>,
        payload: Option<&str>,
    ) -> (Req, String) {
        let mut q: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
            .collect();
        q.sort();
        let canonical_query = q
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let target = if q.is_empty() {
            raw_path.to_string()
        } else {
            format!("{raw_path}?{canonical_query}")
        };

        let (stamp, scope, key) = self.scope(now);
        let explicit = payload.is_some();
        let payload = payload.map_or_else(|| hex(&sha256(&body)), str::to_string);
        let mut signed: BTreeMap<String, String> = BTreeMap::new();
        signed.insert("host".into(), HOST.into());
        signed.insert("x-amz-content-sha256".into(), payload.clone());
        signed.insert("x-amz-date".into(), stamp.clone());
        for (k, v) in extra {
            signed.insert(k.to_ascii_lowercase(), v.trim().to_string());
        }
        let canonical_headers: String = signed.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let names = signed.keys().cloned().collect::<Vec<_>>().join(";");
        let canonical = format!(
            "{}\n{raw_path}\n{canonical_query}\n{canonical_headers}\n{names}\n{payload}",
            method.as_str()
        );
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
            hex(&sha256(canonical.as_bytes()))
        );
        let signature = hex(&hmac(&key, to_sign.as_bytes()));

        let mut headers: Vec<(String, String)> = signed.into_iter().collect();
        headers.push((
            "authorization".into(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
                self.akid
            ),
        ));
        if !explicit && (method == Method::Put || !body.is_empty()) {
            headers.push(("content-length".into(), body.len().to_string()));
        }
        (
            Req {
                method,
                target,
                headers,
                body,
            },
            signature,
        )
    }

    /// A signed aws-chunked body chained from `seed` (the signature of
    /// its request), with an optional signed trailer.
    pub fn signed_chunks(
        &self,
        now: UnixMs,
        seed: &str,
        data: &[u8],
        chunk: usize,
        trailer: Option<(&str, String)>,
    ) -> Vec<u8> {
        let (stamp, scope, key) = self.scope(now);
        let empty = hex(&sha256(b""));
        let mut previous = seed.to_owned();
        let mut out = Vec::with_capacity(data.len() + data.len() / chunk * 96 + 512);
        for c in data.chunks(chunk).chain([&b""[..]]) {
            let sts = format!(
                "AWS4-HMAC-SHA256-PAYLOAD\n{stamp}\n{scope}\n{previous}\n{empty}\n{}",
                hex(&sha256(c))
            );
            previous = hex(&hmac(&key, sts.as_bytes()));
            out.extend_from_slice(
                format!("{:x};chunk-signature={previous}\r\n", c.len()).as_bytes(),
            );
            if !c.is_empty() {
                out.extend_from_slice(c);
                out.extend_from_slice(b"\r\n");
            }
        }
        if let Some((name, value)) = trailer {
            let sts = format!(
                "AWS4-HMAC-SHA256-TRAILER\n{stamp}\n{scope}\n{previous}\n{}",
                hex(&sha256(format!("{name}:{value}\n").as_bytes()))
            );
            let sig = hex(&hmac(&key, sts.as_bytes()));
            out.extend_from_slice(
                format!("{name}:{value}\r\nx-amz-trailer-signature:{sig}\r\n").as_bytes(),
            );
        }
        out.extend_from_slice(b"\r\n");
        out
    }
}

/// An unsigned aws-chunked body, the way aws-cli sends it. `trailer` is
/// one `name:value` line, or empty.
pub fn unsigned_chunks(data: &[u8], chunk: usize, trailer: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / chunk * 16 + 256);
    for c in data.chunks(chunk) {
        out.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        out.extend_from_slice(c);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n");
    if !trailer.is_empty() {
        out.extend_from_slice(format!("{trailer}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// CRC-32C of `data`, base64: the value of `x-amz-checksum-crc32c`.
pub fn crc32c_b64(data: &[u8]) -> String {
    use base64::Engine as _;
    let mut table = [0u32; 256];
    for (i, t) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0x82F6_3B78
            } else {
                c >> 1
            };
        }
        *t = c;
    }
    let mut c = !0u32;
    for b in data {
        c = table[((c ^ u32::from(*b)) & 0xff) as usize] ^ (c >> 8);
    }
    base64::engine::general_purpose::STANDARD.encode((!c).to_be_bytes())
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Set when a streamed body ended with an error.
    pub stream_error: Option<String>,
}

impl Resp {
    pub async fn collect(resp: S3Response) -> Resp {
        let mut body = Vec::new();
        let mut stream_error = None;
        match resp.body {
            RespBody::Empty => {}
            RespBody::Bytes(b) => body = b,
            // The buffered form: the document once it is done.
            RespBody::Deferred(d) => match d.settle(Box::pin(std::future::pending())).await {
                Ok(doc) => body = doc,
                Err(_) => unreachable!("the window never elapses"),
            },
            RespBody::Stream(mut s) => {
                while let Some(item) = s.next().await {
                    match item {
                        Ok(chunk) => body.extend_from_slice(&chunk),
                        Err(e) => {
                            stream_error = Some(e.to_string());
                            break;
                        }
                    }
                }
            }
            RespBody::Fanout(_) => panic!("a body in sub-ranges is collected by its own test"),
        }
        Resp {
            status: resp.status,
            headers: resp.headers,
            body,
            stream_error,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The `<Code>` of an S3 error body.
    pub fn code(&self) -> String {
        self.values("Code").into_iter().next().unwrap_or_default()
    }

    /// The `<Message>` of an S3 error body.
    pub fn message(&self) -> String {
        self.values("Message")
            .into_iter()
            .next()
            .unwrap_or_default()
    }

    /// The text of every `<tag>…</tag>` in the body, in order.
    pub fn values(&self, tag: &str) -> Vec<String> {
        let text = self.text();
        let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
        let mut out = Vec::new();
        let mut rest = text.as_str();
        while let Some(i) = rest.find(&open) {
            rest = &rest[i + open.len()..];
            let Some(j) = rest.find(&close) else { break };
            out.push(rest[..j].to_string());
            rest = &rest[j + close.len()..];
        }
        out
    }

    #[track_caller]
    pub fn expect(&self, status: u16) -> &Self {
        assert_eq!(self.status, status, "body: {}", self.text());
        self
    }

    #[track_caller]
    pub fn expect_error(&self, status: u16, code: &str) -> &Self {
        assert_eq!(
            (self.status, self.code().as_str()),
            (status, code),
            "body: {}",
            self.text()
        );
        self
    }

    /// The answer to a write while the catalogue is being restored. It
    /// does not say that an object cannot be read: no object was read.
    #[track_caller]
    pub fn expect_writes_refused(&self) -> &Self {
        self.expect_error(503, "ServiceUnavailable");
        assert_eq!(
            self.message(),
            "Writes are refused until the catalogue has been restored. Please try again later."
        );
        assert_eq!(self.header("retry-after"), Some("30"));
        self
    }
}
