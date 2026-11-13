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

use rusqlite::types::{Value, ValueRef};
use rusqlite::{params_from_iter, Connection};
use sha2::{Digest, Sha256};

use crate::ports::{
    BlobMeta, BlobStore, Clock, JobSink, Kek, Row, Sql, SqlValue, MAX_QUEUE_DELAY_SECS,
    MAX_SQL_PARAMS,
};
use crate::types::{BridgeError, BucketId, ByteSpan, ExtentId, Job, KekBytes, Result, UnixMs};

/// The D1 schema, applied by [`RusqliteSql::with_schema`].
pub const MIGRATION_0001: &str =
    include_str!("../../../workers/s3-bridge/migrations/0001_init.sql");

// ---------------------------------------------------------------------------
// RusqliteSql
// ---------------------------------------------------------------------------

/// `Sql` over SQLite. Foreign keys are enforced, as on D1.
pub struct RusqliteSql {
    conn: RefCell<Connection>,
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
        })
    }

    /// In-memory database with `0001_init.sql` applied.
    pub fn with_schema() -> Result<Self> {
        let db = Self::open_in_memory()?;
        db.apply(MIGRATION_0001)?;
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
        Ok(out)
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        run_to_completion(&self.conn.borrow(), sql, params)
    }

    /// One transaction: the first failing statement (a guard CHECK or any
    /// other error) rolls back every statement of the batch.
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(map_err)?;
        let mut changed = Vec::with_capacity(stmts.len());
        for (sql, params) in &stmts {
            // On error `tx` drops here, which rolls back.
            changed.push(run_to_completion(&tx, sql, params)?);
        }
        tx.commit().map_err(map_err)?;
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
}

impl MemBlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, key: &str) -> bool {
        self.blobs.borrow().contains_key(key)
    }

    pub fn keys(&self) -> Vec<String> {
        self.blobs.borrow().keys().cloned().collect()
    }

    pub fn stored(&self, key: &str) -> Option<StoredBlob> {
        self.blobs.borrow().get(key).cloned()
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
        self.blobs.borrow_mut().remove(key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FixedClock
// ---------------------------------------------------------------------------

/// A clock that moves only when told to.
pub struct FixedClock {
    now: Cell<UnixMs>,
}

impl FixedClock {
    pub fn new(now: UnixMs) -> Self {
        FixedClock {
            now: Cell::new(now),
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
}

/// `send_many` bound (Queues `sendBatch`).
pub const MAX_SEND_MANY: usize = 100;

impl FakeJobs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn drop_next(&self, n: u32) {
        self.drop_next.set(n);
    }

    /// Jobs lost by `drop_next` so far.
    pub fn dropped(&self) -> u32 {
        self.dropped.get()
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
        if delay_secs > MAX_QUEUE_DELAY_SECS {
            return Err(BridgeError::Queue("delay over 12 hours".into()));
        }
        self.record(job, delay_secs);
        Ok(())
    }

    async fn send_many(&self, jobs: &[Job]) -> Result<()> {
        if jobs.len() > MAX_SEND_MANY {
            return Err(BridgeError::Queue("send_many over 100 jobs".into()));
        }
        for job in jobs {
            self.record(job, 0);
        }
        Ok(())
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
