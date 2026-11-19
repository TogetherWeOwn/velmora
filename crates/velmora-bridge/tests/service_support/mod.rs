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
use velmora_bridge::recovery::Unpublished;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{FakeJobs, FixedClock, MemBlobStore, RusqliteSql, TestKek};
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

pub type TestCatalog = SqlCatalog<FailSql>;
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
    fail_next_batch: Cell<bool>,
    /// Fails every statement (read or write) whose text contains the
    /// string, after letting the given number of them through.
    pub fail_matching: RefCell<Option<(&'static str, u32)>>,
    /// Fails this many batches, the next ones: a commit that does not
    /// go through while single statements still do.
    pub fail_batches: Cell<u32>,
    /// Answers this many statements, the next ones of any kind, the way
    /// D1 does after a large batch that did not commit ([`OVERLOADED`]).
    pub overloaded: Cell<u32>,
    /// Every call crosses it first.
    pub trip: Tripwire,
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

    /// Whether this statement is one of those answered "overloaded".
    fn over_budget(&self) -> Result<()> {
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
        self.trip
            .guard(sql_down, self.inner.query(sql, params))
            .await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.over_budget()?;
        if self.fail_writes.get() || self.refused(sql) {
            return Err(BridgeError::Sql("database down".into()));
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
    // One wire over the safety store and the database: a request is a
    // single sequence of calls to the two.
    let trip = Tripwire::default();
    Rig {
        bridge: Rc::new(Bridge {
            catalog: SqlCatalog::new(FailSql {
                trip: trip.clone(),
                inner: RusqliteSql::with_schema().unwrap(),
                fail_writes: Cell::new(false),
                fail_publish: Cell::new(None),
                fail_next_batch: Cell::new(false),
                fail_matching: RefCell::new(None),
                fail_batches: Cell::new(0),
                overloaded: Cell::new(0),
            }),
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
