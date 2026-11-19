//! Native test doubles for the ports (feature `testkit`; frozen with the
//! contract). Single-threaded by design, like the Worker: use them on a
//! current-thread runtime.
//!
//! - [`RusqliteSql`]: `Sql` over an in-memory SQLite with the D1 schema;
//!   `batch` is one transaction that rolls back entirely on any failure.
//! - [`MemBlobStore`]: `BlobStore` in memory, with stored metadata; `put`
//!   refuses bytes whose SHA-256 differs from `cipher_sha256`, as R2 does.
//! - [`FixedClock`]: settable `Clock`.
//! - [`FakeJobs`]: records sends; `drop_next(n)` loses the next `n`.
//! - [`TestKek`]: fixed, non-secret KEKs.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use rusqlite::types::{Value, ValueRef};
use rusqlite::{params_from_iter, Connection};
use sha2::{Digest, Sha256};

use crate::meter::Meter;
pub use crate::meter::{Tally, WriteOp, WriteReport};
use crate::ports::{
    BlobMeta, BlobStore, Catalog, Clock, Guard, JobSink, Kek, PublishOutcome, Row, Sql, SqlValue,
    UploadTarget, MAX_QUEUE_DELAY_SECS, MAX_SQL_PARAMS, MAX_SQL_VALUE_BYTES,
};
use crate::recovery::{is_protected_key, tombstone_id, Recorded, Unpublished, ERR_RECORD_DELETE};
use crate::types::{
    BridgeError, BucketId, ByteSpan, CommitGeneration, CompleteUpload, CopyGeneration, ExtentId,
    Job, KekBytes, Precondition, Result, UnixMs,
};

/// The D1 schema, applied by [`RusqliteSql::with_schema`].
pub const MIGRATION_0001: &str =
    include_str!("../../../workers/s3-bridge/migrations/0001_init.sql");

/// Provider health and pool-shared connection limits.
pub const MIGRATION_0002: &str =
    include_str!("../../../workers/s3-bridge/migrations/0002_provider_health.sql");

/// The index behind the re-drive of under-verified extents.
pub const MIGRATION_0003: &str =
    include_str!("../../../workers/s3-bridge/migrations/0003_extents_held.sql");

/// Hot-tier accounting: evictable bytes, last read, eviction fence.
pub const MIGRATION_0004: &str =
    include_str!("../../../workers/s3-bridge/migrations/0004_hot_tier.sql");
/// Extent references per generation (copies share extents).
pub const MIGRATION_0005: &str =
    include_str!("../../../workers/s3-bridge/migrations/0005_generation_extents.sql");
/// The class of a held permit (background job or read).
pub const MIGRATION_0006: &str =
    include_str!("../../../workers/s3-bridge/migrations/0006_permit_class.sql");

/// The floor of each key: the newest id a recovery record was stored
/// under.
pub const MIGRATION_0007: &str =
    include_str!("../../../workers/s3-bridge/migrations/0007_key_floors.sql");

/// The mark of an unfinished catalogue replay.
pub const MIGRATION_0008: &str =
    include_str!("../../../workers/s3-bridge/migrations/0008_restore_state.sql");
/// Each article's own yEnc name (standalone single-part articles).
pub const MIGRATION_0009: &str =
    include_str!("../../../workers/s3-bridge/migrations/0009_article_yenc_name.sql");

/// The rollback stamp counter.
pub const MIGRATION_0010: &str =
    include_str!("../../../workers/s3-bridge/migrations/0010_rollback_stamp.sql");
/// The slices of a multi-extent write, recorded before they are stored.
pub const MIGRATION_0011: &str =
    include_str!("../../../workers/s3-bridge/migrations/0011_write_intents.sql");

/// Why a provider's last failed session failed.
pub const MIGRATION_0012: &str =
    include_str!("../../../workers/s3-bridge/migrations/0012_provider_health_reason.sql");
/// How a verification row checked the articles (`body` or `stat`).
pub const MIGRATION_0013: &str =
    include_str!("../../../workers/s3-bridge/migrations/0013_verification_kind.sql");
/// When an article was last posted again (`articles.reposted_at`).
pub const MIGRATION_0014: &str =
    include_str!("../../../workers/s3-bridge/migrations/0014_article_reposted_at.sql");
/// The dispatcher's mark of a sent outbox row (`outbox.sent_at`).
pub const MIGRATION_0015: &str =
    include_str!("../../../workers/s3-bridge/migrations/0015_outbox_sent_at.sql");
/// The article plan packed on the extent's row (`extents.plan`).
pub const MIGRATION_0016: &str =
    include_str!("../../../workers/s3-bridge/migrations/0016_packed_plan.sql");
/// Article rows of a packed plan may be deleted while in service.
pub const MIGRATION_0017: &str =
    include_str!("../../../workers/s3-bridge/migrations/0017_packed_plan_rows.sql");
/// The slices of a multipart part stored as several extents
/// (`upload_part_extents`).
pub const MIGRATION_0018: &str =
    include_str!("../../../workers/s3-bridge/migrations/0018_upload_part_extents.sql");
/// The light check of the verify stage (`verifications.mode`,
/// `verify_escalations`).
pub const MIGRATION_0019: &str =
    include_str!("../../../workers/s3-bridge/migrations/0019_verify_mode.sql");

// ---------------------------------------------------------------------------
// RusqliteSql
// ---------------------------------------------------------------------------

/// `Sql` over SQLite. Foreign keys are enforced, as on D1.
pub struct RusqliteSql {
    conn: RefCell<Connection>,
    /// Counts rows written the way D1 bills them, once switched on.
    meter: RefCell<Option<Meter>>,
}

fn to_value(v: &SqlValue) -> Value {
    match v {
        SqlValue::Null => Value::Null,
        SqlValue::Int(i) => Value::Integer(*i),
        SqlValue::Text(s) => Value::Text(s.clone()),
        SqlValue::Blob(b) => Value::Blob(b.clone()),
    }
}

fn from_ref(v: ValueRef<'_>) -> Result<SqlValue> {
    Ok(match v {
        ValueRef::Null => SqlValue::Null,
        ValueRef::Integer(i) => SqlValue::Int(i),
        ValueRef::Text(t) => SqlValue::Text(
            String::from_utf8(t.to_vec()).map_err(|_| BridgeError::Sql("non-utf8 text".into()))?,
        ),
        ValueRef::Blob(b) => SqlValue::Blob(b.to_vec()),
        // The schema has no REAL columns; D1 would return a JS number.
        ValueRef::Real(_) => return Err(BridgeError::Sql("unexpected REAL column".into())),
    })
}

/// Maps a SQLite error the way the D1 adapter must: the `tx_guard` CHECK
/// is `GuardFailed`, everything else is `Sql`.
fn map_err(e: rusqlite::Error) -> BridgeError {
    let msg = e.to_string();
    if crate::ports::is_tx_guard_violation(&msg) {
        BridgeError::GuardFailed
    } else {
        BridgeError::Sql(msg)
    }
}

/// D1 rejects statements with more than `MAX_SQL_PARAMS` bound values.
fn check_params(params: &[SqlValue]) -> Result<()> {
    if params.len() > MAX_SQL_PARAMS {
        return Err(BridgeError::Sql(format!(
            "too many bound parameters: {} > {MAX_SQL_PARAMS}",
            params.len()
        )));
    }
    // D1 refuses a bound value above `MAX_SQL_VALUE_BYTES` as well.
    let size = |v: &SqlValue| match v {
        SqlValue::Text(t) => t.len(),
        SqlValue::Blob(b) => b.len(),
        SqlValue::Null | SqlValue::Int(_) => 0,
    };
    if let Some(n) = params.iter().map(size).find(|n| *n > MAX_SQL_VALUE_BYTES) {
        return Err(BridgeError::Sql(format!(
            "bound value too large: {n} > {MAX_SQL_VALUE_BYTES}"
        )));
    }
    Ok(())
}

/// Steps one statement to completion like D1 `run()`: `RETURNING` and
/// `SELECT` are accepted and their rows discarded. Returns rows changed.
fn run_to_completion(conn: &Connection, sql: &str, params: &[SqlValue]) -> Result<u64> {
    check_params(params)?;
    let before = conn.total_changes();
    let mut stmt = conn.prepare(sql).map_err(map_err)?;
    let mut rows = stmt
        .query(params_from_iter(params.iter().map(to_value)))
        .map_err(map_err)?;
    while rows.next().map_err(map_err)?.is_some() {}
    drop(rows);
    Ok(conn.total_changes().saturating_sub(before))
}

impl RusqliteSql {
    /// Empty in-memory database with foreign keys on.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(map_err)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(map_err)?;
        Ok(RusqliteSql {
            conn: RefCell::new(conn),
            meter: RefCell::new(None),
        })
    }

    /// Starts counting rows written as D1 bills them (see
    /// [`crate::meter`]). Switch it on after the schema is applied.
    pub fn meter_writes(&self) -> Result<()> {
        let meter = Meter::install(&mut self.conn.borrow_mut()).map_err(map_err)?;
        *self.meter.borrow_mut() = Some(meter);
        Ok(())
    }

    /// Rows written since the meter was switched on or last reset. Empty
    /// when the meter is off.
    pub fn writes(&self) -> WriteReport {
        self.meter
            .borrow()
            .as_ref()
            .map(Meter::report)
            .unwrap_or_default()
    }

    /// Zeroes the meter (and re-reads the schema at the next write).
    pub fn reset_writes(&self) {
        if let Some(m) = self.meter.borrow_mut().as_mut() {
            m.reset();
        }
    }

    /// In-memory database with every migration applied, in order.
    pub fn with_schema() -> Result<Self> {
        let db = Self::open_in_memory()?;
        db.apply(MIGRATION_0001)?;
        db.apply(MIGRATION_0002)?;
        db.apply(MIGRATION_0003)?;
        db.apply(MIGRATION_0004)?;
        db.apply(MIGRATION_0005)?;
        db.apply(MIGRATION_0006)?;
        db.apply(MIGRATION_0007)?;
        db.apply(MIGRATION_0008)?;
        db.apply(MIGRATION_0009)?;
        db.apply(MIGRATION_0010)?;
        db.apply(MIGRATION_0011)?;
        db.apply(MIGRATION_0012)?;
        db.apply(MIGRATION_0013)?;
        db.apply(MIGRATION_0014)?;
        db.apply(MIGRATION_0015)?;
        db.apply(MIGRATION_0016)?;
        db.apply(MIGRATION_0017)?;
        db.apply(MIGRATION_0018)?;
        db.apply(MIGRATION_0019)?;
        Ok(db)
    }

    /// Runs a multi-statement script (a migration).
    pub fn apply(&self, script: &str) -> Result<()> {
        self.conn.borrow().execute_batch(script).map_err(map_err)
    }

    /// Direct access for assertions.
    pub fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> R) -> R {
        f(&self.conn.borrow())
    }
}

impl Sql for RusqliteSql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        check_params(params)?;
        let conn = self.conn.borrow();
        // Whatever a failed statement left behind was rolled back.
        if let Some(m) = self.meter.borrow_mut().as_mut() {
            m.discard();
        }
        let mut stmt = conn.prepare(sql).map_err(map_err)?;
        let cols = stmt.column_count();
        let mut rows = stmt
            .query(params_from_iter(params.iter().map(to_value)))
            .map_err(map_err)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(map_err)? {
            let mut r = Vec::with_capacity(cols);
            for i in 0..cols {
                r.push(from_ref(row.get_ref(i).map_err(map_err)?)?);
            }
            out.push(r);
        }
        drop(rows);
        drop(stmt);
        // A statement with RETURNING writes too.
        if let Some(m) = self.meter.borrow_mut().as_mut() {
            let priced = m.price(&conn).map_err(map_err)?;
            m.commit(sql, priced);
        }
        Ok(out)
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        let conn = self.conn.borrow();
        let mut meter = self.meter.borrow_mut();
        // What a failed query left behind was rolled back.
        if let Some(m) = meter.as_mut() {
            m.discard();
        }
        let changed = match run_to_completion(&conn, sql, params) {
            Ok(n) => n,
            Err(e) => {
                if let Some(m) = meter.as_mut() {
                    m.discard();
                }
                return Err(e);
            }
        };
        if let Some(m) = meter.as_mut() {
            let priced = m.price(&conn).map_err(map_err)?;
            m.commit(sql, priced);
        }
        Ok(changed)
    }

    /// One transaction: the first failing statement (a guard CHECK or any
    /// other error) rolls back every statement of the batch.
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        let mut conn = self.conn.borrow_mut();
        let mut meter = self.meter.borrow_mut();
        // What a failed query left behind was rolled back.
        if let Some(m) = meter.as_mut() {
            m.discard();
        }
        let tx = conn.transaction().map_err(map_err)?;
        let mut changed = Vec::with_capacity(stmts.len());
        let mut priced = Vec::new();
        for (sql, params) in &stmts {
            // On error `tx` drops here, which rolls back; nothing of the
            // batch was written, so nothing of it is metered.
            match run_to_completion(&tx, sql, params) {
                Ok(n) => changed.push(n),
                Err(e) => {
                    if let Some(m) = meter.as_mut() {
                        m.discard();
                    }
                    return Err(e);
                }
            }
            if let Some(m) = meter.as_mut() {
                priced.push((*sql, m.price(&tx).map_err(map_err)?));
            }
        }
        tx.commit().map_err(map_err)?;
        if let Some(m) = meter.as_mut() {
            for (sql, p) in priced {
                m.commit(sql, p);
            }
        }
        Ok(changed)
    }
}

// ---------------------------------------------------------------------------
// MemBlobStore
// ---------------------------------------------------------------------------

/// One stored blob and its custom metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredBlob {
    pub bytes: Vec<u8>,
    pub bucket: BucketId,
    pub extent: ExtentId,
    pub cipher_sha256: [u8; 32],
}

/// In-memory `BlobStore`. A span past the end is an error (callers always
/// derive spans from catalogue sizes).
///
/// `put` checks the bytes against `meta.cipher_sha256` the way the R2
/// adapter asks R2 to: on a mismatch it fails with `BridgeError::Blob` and
/// stores nothing (an existing blob under the key is left untouched).
#[derive(Default)]
pub struct MemBlobStore {
    blobs: RefCell<BTreeMap<String, StoredBlob>>,
    gets: Cell<u64>,
    refuse_puts: Cell<bool>,
}

impl MemBlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, key: &str) -> bool {
        self.blobs.borrow().contains_key(key)
    }

    /// While set, every `put` fails and stores nothing.
    pub fn refuse_puts(&self, refuse: bool) {
        self.refuse_puts.set(refuse);
    }

    /// `get` calls so far.
    pub fn gets(&self) -> u64 {
        self.gets.get()
    }

    pub fn keys(&self) -> Vec<String> {
        self.blobs.borrow().keys().cloned().collect()
    }

    pub fn stored(&self, key: &str) -> Option<StoredBlob> {
        self.blobs.borrow().get(key).cloned()
    }

    /// Loses a blob behind the store's back, a recovery record as well:
    /// the store itself never deletes one. `false` = it was not there.
    pub fn lose(&self, key: &str) -> bool {
        self.blobs.borrow_mut().remove(key).is_some()
    }

    /// Overwrites stored bytes (tamper tests).
    pub fn corrupt(&self, key: &str, f: impl FnOnce(&mut Vec<u8>)) -> bool {
        match self.blobs.borrow_mut().get_mut(key) {
            Some(b) => {
                f(&mut b.bytes);
                true
            }
            None => false,
        }
    }
}

impl BlobStore for MemBlobStore {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if digest != *meta.cipher_sha256 {
            return Err(BridgeError::Blob("mem: put digest mismatch".into()));
        }
        if self.refuse_puts.get() {
            return Err(BridgeError::Blob("mem: put refused".into()));
        }
        self.blobs.borrow_mut().insert(
            key.to_string(),
            StoredBlob {
                bytes,
                bucket: meta.bucket.clone(),
                extent: meta.extent.clone(),
                cipher_sha256: *meta.cipher_sha256,
            },
        );
        Ok(())
    }

    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.gets.set(self.gets.get() + 1);
        let blobs = self.blobs.borrow();
        let Some(blob) = blobs.get(key) else {
            return Ok(None);
        };
        match span {
            None => Ok(Some(blob.bytes.clone())),
            Some(s) => {
                let len = blob.bytes.len() as u64;
                if s.start > len || s.end() > len {
                    return Err(BridgeError::Blob("range past end".into()));
                }
                // Both bounds are <= len, which is a usize.
                Ok(Some(
                    blob.bytes[s.start as usize..s.end() as usize].to_vec(),
                ))
            }
        }
    }

    async fn head(&self, key: &str) -> Result<Option<u64>> {
        Ok(self.blobs.borrow().get(key).map(|b| b.bytes.len() as u64))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        if is_protected_key(key) {
            return Err(ERR_RECORD_DELETE);
        }
        self.blobs.borrow_mut().remove(key);
        Ok(())
    }

    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.blobs.borrow_mut().remove(&refused.key());
        Ok(())
    }

    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        let mut keys: Vec<String> = self
            .blobs
            .borrow()
            .keys()
            .filter(|k| k.starts_with(prefix) && k.as_str() > start_after)
            .cloned()
            .collect();
        keys.sort();
        keys.truncate(limit as usize);
        Ok(keys)
    }
}

// ---------------------------------------------------------------------------
// FixedClock
// ---------------------------------------------------------------------------

/// A clock that moves only when told to. A clone shows the same time.
#[derive(Clone)]
pub struct FixedClock {
    now: Rc<Cell<UnixMs>>,
}

impl FixedClock {
    pub fn new(now: UnixMs) -> Self {
        FixedClock {
            now: Rc::new(Cell::new(now)),
        }
    }

    pub fn set(&self, now: UnixMs) {
        self.now.set(now);
    }

    pub fn advance_ms(&self, ms: i64) {
        self.now.set(self.now.get().plus_ms(ms));
    }

    pub fn advance_secs(&self, secs: u32) {
        self.now.set(self.now.get().plus_secs(secs));
    }
}

impl Clock for FixedClock {
    fn now(&self) -> UnixMs {
        self.now.get()
    }
}

// ---------------------------------------------------------------------------
// FakeJobs
// ---------------------------------------------------------------------------

/// One recorded send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentJob {
    pub job: Job,
    pub delay_secs: u32,
}

/// Records every job sent. `drop_next(n)` makes the next `n` jobs vanish
/// while reporting success (a lost notification).
#[derive(Default)]
pub struct FakeJobs {
    sent: RefCell<Vec<SentJob>>,
    drop_next: Cell<u32>,
    dropped: Cell<u32>,
    calls: Cell<u32>,
    fail_after: Cell<Option<u32>>,
    backlog: Cell<crate::types::Backlog>,
}

/// `send_many` bound (Queues `sendBatch`).
pub const MAX_SEND_MANY: usize = 100;

impl FakeJobs {
    pub fn new() -> Self {
        Self::default()
    }

    /// What [`JobSink::backlog`] answers from now on. Unknown until set.
    pub fn set_backlog(&self, backlog: crate::types::Backlog) {
        self.backlog.set(backlog);
    }

    pub fn drop_next(&self, n: u32) {
        self.drop_next.set(n);
    }

    /// Jobs lost by `drop_next` so far.
    pub fn dropped(&self) -> u32 {
        self.dropped.get()
    }

    /// The next `n` calls succeed and every call after them fails, until
    /// `None` is set.
    pub fn fail_after(&self, n: Option<u32>) {
        self.fail_after.set(n);
    }

    fn refused(&self) -> Result<()> {
        match self.fail_after.get() {
            None => Ok(()),
            Some(0) => Err(BridgeError::Queue("send refused".into())),
            Some(n) => {
                self.fail_after.set(Some(n - 1));
                Ok(())
            }
        }
    }

    /// Calls of `send` and `send_many` so far, lost ones included.
    pub fn calls(&self) -> u32 {
        self.calls.get()
    }

    pub fn sent(&self) -> Vec<SentJob> {
        self.sent.borrow().clone()
    }

    /// Returns and clears the recorded sends.
    pub fn take(&self) -> Vec<SentJob> {
        std::mem::take(&mut *self.sent.borrow_mut())
    }

    fn record(&self, job: &Job, delay_secs: u32) {
        if self.drop_next.get() > 0 {
            self.drop_next.set(self.drop_next.get() - 1);
            self.dropped.set(self.dropped.get() + 1);
            return;
        }
        self.sent.borrow_mut().push(SentJob {
            job: job.clone(),
            delay_secs,
        });
    }
}

impl JobSink for FakeJobs {
    async fn send(&self, job: &Job, delay_secs: u32) -> Result<()> {
        self.calls.set(self.calls.get() + 1);
        self.refused()?;
        if delay_secs > MAX_QUEUE_DELAY_SECS {
            return Err(BridgeError::Queue("delay over 12 hours".into()));
        }
        self.record(job, delay_secs);
        Ok(())
    }

    async fn send_many(&self, jobs: &[Job]) -> Result<()> {
        self.calls.set(self.calls.get() + 1);
        self.refused()?;
        if jobs.len() > MAX_SEND_MANY {
            return Err(BridgeError::Queue("send_many over 100 jobs".into()));
        }
        for job in jobs {
            self.record(job, 0);
        }
        Ok(())
    }

    async fn backlog(&self) -> crate::types::Backlog {
        self.backlog.get()
    }
}

// ---------------------------------------------------------------------------
// TestKek
// ---------------------------------------------------------------------------

/// Fixed test KEKs. Never use outside tests.
pub struct TestKek {
    active: u32,
    keys: BTreeMap<u32, KekBytes>,
}

impl TestKek {
    /// Version 1 = `[0x11; 32]`, active.
    pub fn new() -> Self {
        Self::with_versions(1, &[(1, [0x11; 32])])
    }

    /// Panics if `active` is not among `versions` (test setup error).
    pub fn with_versions(active: u32, versions: &[(u32, [u8; 32])]) -> Self {
        let keys: BTreeMap<u32, KekBytes> = versions
            .iter()
            .map(|(v, k)| (*v, KekBytes::new(*k)))
            .collect();
        assert!(keys.contains_key(&active), "active KEK version missing");
        TestKek { active, keys }
    }
}

impl Default for TestKek {
    fn default() -> Self {
        Self::new()
    }
}

impl Kek for TestKek {
    fn active(&self) -> (u32, &KekBytes) {
        (self.active, &self.keys[&self.active])
    }

    fn version(&self, v: u32) -> Option<&KekBytes> {
        self.keys.get(&v)
    }
}

// ---------------------------------------------------------------------------
// Publishing without a record
// ---------------------------------------------------------------------------

/// Catalogue tests publish rows that no request recorded. These
/// make the proof the catalogue asks for ([`Recorded::for_test`]) and
/// answer as a guarded batch does.
#[allow(async_fn_in_trait)]
pub trait PublishUnrecorded: Catalog {
    async fn publish(&self, c: &CommitGeneration) -> Result<Guard<()>> {
        self.publish_if(c, None).await
    }

    /// [`Self::publish`] under the condition of a conditional write.
    async fn publish_if(
        &self,
        c: &CommitGeneration,
        condition: Option<&Precondition>,
    ) -> Result<Guard<()>> {
        let record = Recorded::for_test(&c.generation.id);
        Ok(match self.commit_generation(c, condition, record).await? {
            PublishOutcome::Applied => Guard::Applied(()),
            PublishOutcome::Refused(_) | PublishOutcome::Fenced(_) => Guard::Lost,
        })
    }

    async fn publish_copy(&self, c: &CopyGeneration) -> Result<Guard<()>> {
        self.publish_copy_if(c, None).await
    }

    async fn publish_copy_if(
        &self,
        c: &CopyGeneration,
        condition: Option<&Precondition>,
    ) -> Result<Guard<()>> {
        let record = Recorded::for_test(&c.generation.id);
        Ok(match self.copy_generation(c, condition, record).await? {
            PublishOutcome::Applied => Guard::Applied(()),
            PublishOutcome::Refused(_) | PublishOutcome::Fenced(_) => Guard::Lost,
        })
    }

    async fn publish_upload(
        &self,
        t: &UploadTarget<'_>,
        revision: u64,
        digest: &[u8; 32],
        c: &CompleteUpload,
    ) -> Result<Guard<()>> {
        self.publish_upload_if(t, revision, digest, c, None).await
    }

    async fn publish_upload_if(
        &self,
        t: &UploadTarget<'_>,
        revision: u64,
        digest: &[u8; 32],
        c: &CompleteUpload,
        condition: Option<&Precondition>,
    ) -> Result<Guard<()>> {
        let record = Recorded::for_test(&c.generation.id);
        Ok(
            match self
                .complete_upload(t, revision, digest, c, condition, record)
                .await?
            {
                PublishOutcome::Applied => Guard::Applied(()),
                PublishOutcome::Refused(_) | PublishOutcome::Fenced(_) => Guard::Lost,
            },
        )
    }

    /// DeleteObject without its tombstone record: retires what is live
    /// under an id minted after the newest one on the key.
    /// `false` = nothing was retired.
    async fn delete_now(&self, bucket: &BucketId, key: &str, now: UnixMs) -> Result<bool> {
        let Some(newest) = self.newest_id(bucket, key).await? else {
            return Ok(false);
        };
        let tombstone = tombstone_id(now, &newest, [0xff; 8]);
        self.delete_object_before(bucket, key, &tombstone, now)
            .await
    }
}

impl<C: Catalog> PublishUnrecorded for C {}
