//! `run_job`, the GC job and the cron dispatcher, over the SQL catalogue
//! (SQLite with the production schema) and the in-process NNTP server.
//!
//! Objects are committed straight through the catalogue, so each test
//! starts from exactly what a finished PUT leaves behind: a live
//! generation, a pinned ciphertext and an outbox row at `post`.

mod nntp_support;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use nntp_support::{TcpConnector, PASS, USER};
use sha2::Digest as _;
use velmora::rng::SystemRng;
use velmora_bridge::config::{Environment, GcMode, Maintenance};
use velmora_bridge::crypto::{seal_extent, unwrap_bdk, wrap_bdk, DataKey};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::jobs::{DISPATCH_LIMIT, GC_BATCH, MAX_ATTEMPTS};
use velmora_bridge::recovery::{article_key, read_article_plan, write_article_plan, Unpublished};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::{
    FakeJobs, FixedClock, MemBlobStore, PublishUnrecorded, RusqliteSql, TestKek,
};
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

const T0: UnixMs = UnixMs(1_800_000_000_000);
const BUDGET: u64 = 48 * 1024 * 1024;
const VERIFY_DELAY_SECS: u32 = 30;

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// One SQLite database shared by the bridge and the test.
struct Shared(Rc<RusqliteSql>);

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

struct SharedClock(Rc<FixedClock>);

impl Clock for SharedClock {
    fn now(&self) -> UnixMs {
        self.0.now()
    }
}

/// A blob store that panics on any call while `forbid` is set.
struct GuardedBlob {
    inner: MemBlobStore,
    forbid: Rc<Cell<bool>>,
    /// A key whose delete fails.
    broken: RefCell<Option<String>>,
    /// Puts of keys with this prefix fail.
    no_put: RefCell<Option<String>>,
}

impl GuardedBlob {
    fn check(&self) {
        assert!(!self.forbid.get(), "blob store touched");
    }
}

impl BlobStore for GuardedBlob {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.check();
        if self
            .no_put
            .borrow()
            .as_deref()
            .is_some_and(|p| key.starts_with(p))
        {
            return Err(BridgeError::Blob("put failed".to_string()));
        }
        self.inner.put(key, bytes, meta).await
    }
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.check();
        self.inner.get(key, span).await
    }
    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.check();
        self.inner.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.check();
        if self.broken.borrow().as_deref() == Some(key) {
            return Err(BridgeError::Blob("delete failed".to_string()));
        }
        self.inner.delete(key).await
    }
    async fn delete_record(&self, refused: Unpublished) -> Result<()> {
        self.check();
        self.inner.delete_record(refused).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.check();
        self.inner.list(prefix, start_after, limit).await
    }
}

/// The TCP connector, plus two test hooks: it panics while `forbid` is
/// set, and with a `target` it lets a second worker take that extent's
/// lease while the first is opening its connection.
struct Connector {
    inner: TcpConnector,
    forbid: Rc<Cell<bool>>,
    thief: SqlCatalog<Shared>,
    clock: Rc<FixedClock>,
    target: RefCell<Option<(ExtentId, GenerationId, OutboxStage)>>,
    stolen: RefCell<Option<Lease>>,
}

impl NntpConnector for Connector {
    type Session = <TcpConnector as NntpConnector>::Session;

    async fn connect(&self, p: &ProviderConfig, permit: &Permit) -> Result<Self::Session> {
        assert!(!self.forbid.get(), "NNTP connection opened");
        let target = self.target.borrow_mut().take();
        if let Some((extent, generation, stage)) = target {
            // The running job stalls past its lease and another takes it.
            self.clock.advance_secs(601);
            let lease = self
                .thief
                .claim(&extent, &generation, stage, "thief", self.clock.now())
                .await?
                .expect("an expired lease can be claimed");
            *self.stolen.borrow_mut() = Some(lease);
        }
        self.inner.connect(p, permit).await
    }
}

type TestBridge =
    Bridge<SqlCatalog<Shared>, GuardedBlob, Connector, FakeJobs, TestKek, SharedClock>;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fx {
    bridge: TestBridge,
    sql: Rc<RusqliteSql>,
    clock: Rc<FixedClock>,
    server: TestNntpServer,
    forbid_io: Rc<Cell<bool>>,
    seed: Cell<u8>,
}

/// A committed single-extent object.
struct Obj {
    extent: ExtentId,
    generation: GenerationId,
    plain: Vec<u8>,
}

impl Obj {
    fn job(&self, stage: OutboxStage) -> Job {
        Job::Extent {
            v: JOB_VERSION,
            extent: self.extent.clone(),
            generation: self.generation.clone(),
            stage,
        }
    }
}

fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.to_string())
}

impl Fx {
    async fn new() -> Fx {
        Fx::with(GcMode::Disposable, Maintenance::Off).await
    }

    async fn with(gc_mode: GcMode, maintenance: Maintenance) -> Fx {
        let mut config = ServerConfig::for_test();
        config.articles = Vec::new();
        config.missing_ids.clear();
        config.users.insert(
            USER.to_string(),
            UserConfig {
                password: PASS.to_string(),
                max_connections: 2,
            },
        );
        let server = TestNntpServer::spawn(config).await;
        let providers = vec![ProviderConfig {
            id: "p0".to_string(),
            host: server.addr().ip().to_string(),
            port: server.addr().port(),
            tls: false,
            user: USER.to_string(),
            pass: PASS.to_string(),
            backbone: "bb0".to_string(),
            post: true,
            read: true,
            max_conns: 2,
            priority: 0,
            retention_days: None,
            pool: None,
            pool_max_conns: None,
            enabled: true,
        }];
        let cfg = BridgeConfig {
            environment: Environment::Dev,
            s3_host: "s3.test".to_string(),
            region: "auto".to_string(),
            max_extent_bytes: 16 * 1024 * 1024,
            required_backbones: 1,
            safety_min_age_secs: 0,
            verify_delay_secs: VERIFY_DELAY_SECS,
            newsgroups: vec!["alt.binaries.test".to_string()],
            kek_active: 1,
            inflight_budget_bytes: BUDGET,
            gc_mode,
            hot_cap_bytes: velmora_bridge::config::DEFAULT_HOT_CAP_BYTES,
            maintenance,
            server_side_copy: false,
            dev_trust_http: false,
            providers,
            admin_token: Secret::new("admin-token-fixture-admin-token-fixture".to_string()),
        };
        let sql = Rc::new(RusqliteSql::with_schema().unwrap());
        let clock = Rc::new(FixedClock::new(T0));
        let forbid_io = Rc::new(Cell::new(false));
        let blob = || GuardedBlob {
            inner: MemBlobStore::new(),
            forbid: Rc::clone(&forbid_io),
            broken: RefCell::new(None),
            no_put: RefCell::new(None),
        };
        let bridge = Bridge {
            catalog: SqlCatalog::new(Shared(Rc::clone(&sql))),
            safety: blob(),
            cache: blob(),
            nntp: Connector {
                inner: TcpConnector::default(),
                forbid: Rc::clone(&forbid_io),
                thief: SqlCatalog::new(Shared(Rc::clone(&sql))),
                clock: Rc::clone(&clock),
                target: RefCell::new(None),
                stolen: RefCell::new(None),
            },
            jobs: FakeJobs::new(),
            kek: TestKek::new(),
            clock: SharedClock(Rc::clone(&clock)),
            budget: ByteBudget::new(BUDGET),
            cfg,
        };
        Fx {
            bridge,
            sql,
            clock,
            server,
            forbid_io,
            seed: Cell::new(1),
        }
    }

    fn next(&self) -> u8 {
        let n = self.seed.get();
        self.seed.set(n + 1);
        n
    }

    async fn bucket(&self, name: &str, disposable: bool) -> Bucket {
        let id = BucketId::mint([self.next(); 8]);
        let bdk = DataKey::generate(&mut SystemRng).unwrap();
        let (kek_version, wrapped) = wrap_bdk(&self.bridge.kek, &id, &bdk, &mut SystemRng).unwrap();
        let bucket = Bucket {
            id,
            name: name.to_string(),
            owner: "owner".to_string(),
            bdk_wrapped: wrapped.to_vec(),
            kek_version,
            disposable,
            created_at: T0,
        };
        let created = self.bridge.catalog.create_bucket(&bucket).await.unwrap();
        assert_eq!(created, Guard::Applied(()));
        bucket
    }

    /// What a finished PUT leaves: the sealed extent in both blob stores
    /// and one committed generation. No queue message is sent.
    async fn put(&self, bucket: &Bucket, key: &str, plain: &[u8]) -> Obj {
        let n = self.next();
        let now = self.clock.now();
        let bdk = unwrap_bdk(
            &self.bridge.kek,
            bucket.kek_version,
            &bucket.id,
            &bucket.bdk_wrapped,
        )
        .unwrap();
        let extent_id = ExtentId::mint([n; 13]);
        let sealed = seal_extent(&bdk, &bucket.id, &extent_id, plain, &mut SystemRng).unwrap();
        let generation = GenerationRow {
            id: GenerationId::mint(now, [n; 8]),
            bucket_id: bucket.id.clone(),
            key: key.to_string(),
            state: GenerationState::Live,
            size: plain.len() as u64,
            etag: "\"etag\"".to_string(),
            checksum_json: None,
            content_json: "{}".to_string(),
            user_meta_json: "{}".to_string(),
            extent_count: 1,
            created_at: now,
            retired_at: None,
        };
        let extent = ExtentRow {
            id: extent_id.clone(),
            bucket_id: bucket.id.clone(),
            generation_id: Some(generation.id.clone()),
            state: ExtentState::Committed,
            seq: Some(0),
            plain_offset: Some(0),
            plain_size: plain.len() as u64,
            cipher_size: sealed.ciphertext.len() as u64,
            media_header: sealed.media_header.to_vec(),
            key_mode: 1,
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
        let meta = BlobMeta {
            bucket: &bucket.id,
            extent: &extent_id,
            cipher_sha256: &sealed.cipher_sha256,
        };
        self.bridge
            .safety
            .put(&extent_id.safety_key(), sealed.ciphertext.clone(), &meta)
            .await
            .unwrap();
        self.bridge
            .cache
            .put(&extent_id.cache_key(), sealed.ciphertext.clone(), &meta)
            .await
            .unwrap();
        self.bridge
            .catalog
            .publish(&CommitGeneration {
                generation: generation.clone(),
                extents: vec![extent],
                now,
            })
            .await
            .unwrap();
        Obj {
            extent: extent_id,
            generation: generation.id,
            plain: plain.to_vec(),
        }
    }

    /// First column of the first row, as text.
    async fn scalar(&self, sql: &str, params: &[SqlValue]) -> String {
        let rows = self.sql.query(sql, params).await.unwrap();
        match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Text(s)) => s.clone(),
            Some(SqlValue::Int(n)) => n.to_string(),
            Some(SqlValue::Null) | None => "NULL".to_string(),
            Some(other) => panic!("unexpected {other:?}"),
        }
    }

    async fn outbox(&self, o: &Obj, column: &str) -> String {
        let sql = format!("SELECT {column} FROM outbox WHERE extent_id = ?1");
        self.scalar(&sql, &[text(o.extent.as_str())]).await
    }

    async fn extent(&self, o: &Obj, column: &str) -> String {
        let sql = format!("SELECT {column} FROM extents WHERE id = ?1");
        self.scalar(&sql, &[text(o.extent.as_str())]).await
    }

    /// Closed GC rows of an object's extent.
    async fn gc_done(&self, o: &Obj) -> String {
        let sql = "SELECT COUNT(*) FROM gc WHERE extent_id = ?1 AND done_at IS NOT NULL";
        self.scalar(sql, &[text(o.extent.as_str())]).await
    }

    /// Everything a job may write, for "nothing changed" checks.
    async fn dump(&self) -> Vec<Row> {
        let mut out = Vec::new();
        for sql in [
            "SELECT * FROM outbox ORDER BY extent_id",
            "SELECT * FROM articles ORDER BY extent_id, idx",
            "SELECT * FROM verifications ORDER BY extent_id, backbone, verified_at",
            "SELECT id, safety_state, article_count, plan_rev, release_evidence, released_at \
             FROM extents ORDER BY id",
            "SELECT * FROM gc ORDER BY id",
        ] {
            out.extend(self.sql.query(sql, &[]).await.unwrap());
        }
        out
    }

    fn has_safety(&self, o: &Obj) -> bool {
        self.bridge.safety.inner.contains(&o.extent.safety_key())
    }

    fn has_cache(&self, o: &Obj) -> bool {
        self.bridge.cache.inner.contains(&o.extent.cache_key())
    }

    /// Delivers queued jobs in due order, moving the clock to each due
    /// time, until the queue is empty. Returns the number of deliveries.
    async fn pump(&self) -> u32 {
        let mut queue: Vec<(UnixMs, Job)> = Vec::new();
        let mut runs = 0;
        loop {
            let now = self.clock.now();
            for sent in self.bridge.jobs.take() {
                queue.push((now.plus_secs(sent.delay_secs), sent.job));
            }
            if queue.is_empty() {
                return runs;
            }
            queue.sort_by_key(|(due, _)| *due);
            let (due, job) = queue.remove(0);
            if due > self.clock.now() {
                self.clock.set(due);
            }
            runs += 1;
            assert!(runs < 200, "the queue does not drain");
            if let JobOutcome::Retry { delay_secs } = self.bridge.run_job(&job).await {
                queue.push((self.clock.now().plus_secs(delay_secs), job));
            }
        }
    }
}

/// Three articles' worth of plaintext.
fn plaintext() -> Vec<u8> {
    nntp_support::marked_plaintext(2 * 1024 * 1024 + 4321)
}

// ---------------------------------------------------------------------------
// run_job
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_verify_release_over_fake_nntp() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "a/big.bin", &plaintext()).await;
    assert_eq!(fx.outbox(&o, "stage").await, "post");
    assert!(fx.has_safety(&o));
    let seeded = BlobMeta {
        bucket: &bucket.id,
        extent: &o.extent,
        cipher_sha256: &sha2::Sha256::digest(b"record").into(),
    };
    let record = b"record".to_vec();
    fx.bridge
        .safety
        .put("m/g_seeded", record, &seeded)
        .await
        .unwrap();

    fx.bridge
        .jobs
        .send(&o.job(OutboxStage::Post), 0)
        .await
        .unwrap();
    let runs = fx.pump().await;

    // One delivery per stage; one backbone, so one verify job.
    assert_eq!(runs, 3);
    assert_eq!(fx.outbox(&o, "stage").await, "done");
    assert_eq!(fx.outbox(&o, "last_error").await, "NULL");
    assert_eq!(fx.extent(&o, "safety_state").await, "released");
    assert_eq!(fx.extent(&o, "article_count").await, "3");
    assert_ne!(fx.extent(&o, "release_evidence").await, "NULL");
    assert_eq!(fx.server.posted_count().await, 3);
    let posted = "SELECT COUNT(*) FROM articles WHERE state = 'posted'";
    assert_eq!(fx.scalar(posted, &[]).await, "3");

    // The release deletes nothing: the copy stays in R2, now evictable.
    assert!(fx.has_safety(&o));
    assert_eq!(
        fx.extent(&o, "hot_safety_bytes").await,
        fx.extent(&o, "cipher_size").await
    );
    assert!(fx.has_cache(&o));
    // The recovery records stay beside it.
    assert_eq!(
        fx.bridge.safety.inner.keys(),
        [
            article_key(&o.extent),
            "m/g_seeded".to_string(),
            o.extent.safety_key()
        ]
    );
    let status = fx.bridge.catalog.backbone_status(&o.extent).await.unwrap();
    assert_eq!(status.len(), 1);
    assert!(status[0].counts && status[0].articles_ok == 3);

    // Every job gave its memory and its connection slot back.
    assert_eq!(fx.bridge.budget.in_use(), 0);
    assert!(fx.bridge.budget.peak() >= o.plain.len() as u64);
    assert_eq!(fx.bridge.nntp.inner.live(), 0);
    assert!(fx.bridge.nntp.inner.peak() <= 2);
    let held = "SELECT COUNT(*) FROM provider_permits WHERE holder IS NOT NULL";
    assert_eq!(fx.scalar(held, &[]).await, "0");
}

/// The article plan record is stored before the first POST: while it
/// cannot be written nothing is posted, and the record that is written
/// later holds the plan the catalogue has.
#[tokio::test]
async fn no_post_before_the_article_plan_record() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "a/big.bin", &plaintext()).await;
    *fx.bridge.safety.no_put.borrow_mut() = Some("m/art/".to_string());

    let outcome = fx.bridge.run_job(&o.job(OutboxStage::Post)).await;
    assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
    assert_eq!(fx.server.posted_count().await, 0);
    assert_eq!(fx.outbox(&o, "stage").await, "post");
    assert!(!fx.bridge.safety.inner.contains(&article_key(&o.extent)));
    // The plan itself is in the catalogue: the retry reuses it.
    assert_eq!(fx.extent(&o, "article_count").await, "3");
    let planned = fx.bridge.catalog.articles(&o.extent).await.unwrap();

    *fx.bridge.safety.no_put.borrow_mut() = None;
    fx.make_due(&o).await;
    assert_eq!(
        fx.bridge.run_job(&o.job(OutboxStage::Post)).await,
        JobOutcome::Ack
    );
    assert_eq!(fx.server.posted_count().await, 3);
    let record = read_article_plan(&fx.bridge.safety, &fx.bridge.kek, &o.extent)
        .await
        .unwrap()
        .expect("the record exists");
    // The record names the revision the catalogue gave the plan.
    assert_eq!(fx.extent(&o, "plan_rev").await, "1");
    assert_eq!(record.plan_rev, 1);
    let rows = record.rows(ArticleState::Planned).unwrap();
    assert_eq!(rows.len(), 3);
    for (row, was) in rows.iter().zip(&planned) {
        assert_eq!(
            (
                &row.message_id,
                row.cipher_offset,
                row.cipher_len,
                row.payload_sha256
            ),
            (
                &was.message_id,
                was.cipher_offset,
                was.cipher_len,
                was.payload_sha256
            )
        );
    }

    // A record that no longer opens is replaced by the next write.
    let name = article_key(&o.extent);
    assert!(fx.bridge.safety.inner.corrupt(&name, |b| b[8] ^= 1));
    assert!(
        read_article_plan(&fx.bridge.safety, &fx.bridge.kek, &o.extent)
            .await
            .is_err()
    );
    let (_, extents) = fx
        .bridge
        .catalog
        .live_object(&bucket.id, "a/big.bin")
        .await
        .unwrap()
        .unwrap();
    write_article_plan(&fx.bridge.safety, &fx.bridge.kek, &extents[0], &planned)
        .await
        .unwrap();
    let again = read_article_plan(&fx.bridge.safety, &fx.bridge.kek, &o.extent)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.rows(ArticleState::Planned).unwrap().len(), 3);
}

// ---------------------------------------------------------------------------
// Provider pool, on the SQL catalogue
// ---------------------------------------------------------------------------

impl Fx {
    /// Makes the object's outbox row claimable now.
    async fn make_due(&self, o: &Obj) {
        let sql = "UPDATE outbox SET next_at = 0, lease_until = NULL WHERE extent_id = ?1";
        self.sql
            .exec(sql, &[text(o.extent.as_str())])
            .await
            .unwrap();
    }

    /// Connection slots handed out so far, over all providers.
    async fn uses(&self) -> u64 {
        let load = self.bridge.catalog.provider_load(self.clock.now());
        load.await.unwrap().iter().map(|l| l.uses).sum()
    }

    async fn health(&self, column: &str) -> String {
        let sql = format!("SELECT {column} FROM provider_health WHERE provider_id = 'p0'");
        self.scalar(&sql, &[]).await
    }
}

/// Three post jobs that cannot connect start a cooldown in
/// `provider_health`. While it lasts a job waits without an attempt and
/// without a connection slot; after it, a good session clears the record.
#[tokio::test]
async fn provider_cooldown_on_the_sql_catalogue() {
    let mut fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "a/cool.bin", &plaintext()).await;
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = dead.local_addr().unwrap().port();
    let port = core::mem::replace(&mut fx.bridge.cfg.providers[0].port, dead);

    for run in 0..3 {
        fx.make_due(&o).await;
        let outcome = fx.bridge.run_job(&o.job(OutboxStage::Post)).await;
        assert!(matches!(outcome, JobOutcome::Retry { .. }));
        if run < 2 {
            assert_eq!(fx.health("cooldown_until").await, "0");
            fx.clock.advance_secs(3600);
        }
    }
    assert_eq!(fx.outbox(&o, "attempts").await, "3");
    let until = fx.clock.now().plus_secs(60);
    assert_eq!(fx.health("cooldown_until").await, until.0.to_string());
    assert_eq!(fx.health("cooldowns").await, "1");

    // Cooling: the job is put off to the end of the cooldown.
    let before = fx.uses().await;
    fx.clock.advance_secs(20);
    fx.make_due(&o).await;
    let outcome = fx.bridge.run_job(&o.job(OutboxStage::Post)).await;
    assert_eq!(outcome, JobOutcome::Retry { delay_secs: 40 });
    assert_eq!(fx.outbox(&o, "attempts").await, "3");
    assert_eq!(fx.outbox(&o, "next_at").await, until.0.to_string());
    assert_eq!(fx.uses().await, before);

    // Repaired: the first good session after the cooldown clears it.
    fx.bridge.cfg.providers[0].port = port;
    fx.clock.set(until);
    fx.bridge
        .jobs
        .send(&o.job(OutboxStage::Post), 0)
        .await
        .unwrap();
    fx.pump().await;
    assert_eq!(fx.outbox(&o, "stage").await, "done");
    assert_eq!(fx.health("failures").await, "0");
    assert_eq!(fx.health("cooldowns").await, "0");
    assert_eq!(fx.health("cooldown_until").await, "0");
}

/// Two accounts of one pool share `pool_max_conns` in `provider_permits`:
/// while the other account holds the pool's background slot, a post job
/// waits without an attempt; once the slot is free it posts.
#[tokio::test]
async fn pool_limit_on_the_sql_catalogue() {
    let mut fx = Fx::new().await;
    let mut twin = fx.bridge.cfg.providers[0].clone();
    twin.id = "p1".to_string();
    twin.post = false;
    fx.bridge.cfg.providers.push(twin);
    for p in &mut fx.bridge.cfg.providers {
        p.pool = Some("bundle".to_string());
        // One background slot and one kept for reads.
        p.pool_max_conns = Some(2);
    }
    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "a/pool.bin", &plaintext()).await;

    let twin = &fx.bridge.cfg.providers[1];
    let catalog = &fx.bridge.catalog;
    let permit = catalog.acquire_permit(twin, PermitClass::Background, "other", fx.clock.now());
    let permit = permit.await.unwrap().expect("the pool's background slot");

    let outcome = fx.bridge.run_job(&o.job(OutboxStage::Post)).await;
    assert!(matches!(outcome, JobOutcome::Retry { .. }));
    assert_eq!(fx.outbox(&o, "stage").await, "post");
    assert_eq!(fx.outbox(&o, "attempts").await, "0");
    assert_eq!(fx.outbox(&o, "last_error").await, "NULL");
    assert_eq!(fx.server.posted_count().await, 0);
    assert_eq!(fx.bridge.nntp.inner.connects(), 0);

    catalog.release_permit(&permit).await.unwrap();
    fx.make_due(&o).await;
    let outcome = fx.bridge.run_job(&o.job(OutboxStage::Post)).await;
    assert_eq!(outcome, JobOutcome::Ack);
    assert_eq!(fx.outbox(&o, "stage").await, "verify");
    assert_eq!(fx.server.posted_count().await, 3);
    let pooled = "SELECT COUNT(*) FROM provider_permits WHERE pool = 'bundle'";
    assert_ne!(fx.scalar(pooled, &[]).await, "0");
}

#[tokio::test]
async fn duplicate_and_stale_jobs_are_noops() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    let post = o.job(OutboxStage::Post);

    assert_eq!(fx.bridge.run_job(&post).await, JobOutcome::Ack);
    assert_eq!(fx.outbox(&o, "stage").await, "verify");
    fx.bridge.jobs.take();
    let before = fx.dump().await;
    let connects = fx.bridge.nntp.inner.connects();

    // From here on any NNTP or blob call fails the test.
    fx.forbid_io.set(true);
    let other = Obj {
        extent: ExtentId::mint([0xee; 13]),
        generation: GenerationId::mint(T0, [0xee; 8]),
        plain: Vec::new(),
    };
    let stale = [
        // A second delivery of the post message.
        post.clone(),
        // The verify message, before the row is due.
        o.job(OutboxStage::Verify),
        // A stage the row has not reached.
        o.job(OutboxStage::Release),
        // Stages no job runs.
        o.job(OutboxStage::Done),
        o.job(OutboxStage::Dead),
        o.job(OutboxStage::Cancelled),
        // An extent that does not exist, and a generation that is not
        // this extent's.
        other.job(OutboxStage::Post),
        Job::Extent {
            v: JOB_VERSION,
            extent: o.extent.clone(),
            generation: other.generation.clone(),
            stage: OutboxStage::Verify,
        },
        // A message format this build does not know.
        Job::Extent {
            v: JOB_VERSION + 1,
            extent: o.extent.clone(),
            generation: o.generation.clone(),
            stage: OutboxStage::Verify,
        },
        Job::Gc { v: JOB_VERSION + 1 },
    ];
    for job in &stale {
        assert_eq!(fx.bridge.run_job(job).await, JobOutcome::Ack, "{job:?}");
    }
    assert_eq!(
        fx.dump().await,
        before,
        "a no-op job wrote to the catalogue"
    );
    assert!(fx.bridge.jobs.sent().is_empty());
    assert_eq!(fx.bridge.nntp.inner.connects(), connects);
    assert_eq!(fx.server.posted_count().await, 3);

    // Two deliveries of one message at once: one runs, one is a no-op.
    fx.forbid_io.set(false);
    fx.clock.advance_secs(VERIFY_DELAY_SECS);
    let verify = o.job(OutboxStage::Verify);
    let (a, b) =
        futures_util::future::join(fx.bridge.run_job(&verify), fx.bridge.run_job(&verify)).await;
    assert_eq!((a, b), (JobOutcome::Ack, JobOutcome::Ack));
    assert_eq!(fx.outbox(&o, "stage").await, "release");
    let verifications = "SELECT COUNT(*) FROM verifications";
    assert_eq!(fx.scalar(verifications, &[]).await, "1");
}

#[tokio::test]
async fn stale_lease_is_fenced() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "k", &plaintext()).await;

    // The job outlives its lease while it connects; a second worker
    // claims the row in that gap.
    *fx.bridge.nntp.target.borrow_mut() =
        Some((o.extent.clone(), o.generation.clone(), OutboxStage::Post));
    let outcome = fx.bridge.run_job(&o.job(OutboxStage::Post)).await;
    assert_eq!(outcome, JobOutcome::Ack, "a fenced job stops and acks");
    let thief = fx.bridge.nntp.stolen.borrow_mut().take().expect("stolen");

    // The stale job changed nothing the new holder owns.
    assert_eq!(fx.outbox(&o, "stage").await, "post");
    assert_eq!(fx.outbox(&o, "lease_owner").await, "thief");
    assert_eq!(fx.outbox(&o, "lease_token").await, thief.token.to_string());
    assert_eq!(fx.outbox(&o, "attempts").await, "2");
    assert_eq!(fx.outbox(&o, "last_error").await, "NULL");
    let posted = "SELECT COUNT(*) FROM articles WHERE state = 'posted'";
    assert_eq!(fx.scalar(posted, &[]).await, "0");
    assert!(fx.has_safety(&o));
    assert!(
        fx.bridge.jobs.sent().is_empty(),
        "a fenced job must not announce the next stage"
    );
    assert_eq!(fx.bridge.budget.in_use(), 0);
    assert_eq!(fx.bridge.nntp.inner.live(), 0);

    // The new holder's lease still works, and its job finishes the stage.
    let now = fx.clock.now();
    assert!(fx.bridge.catalog.renew(&thief, now).await.unwrap());
    let row = fx
        .bridge
        .catalog
        .job_extent(&o.extent, &o.generation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fx.bridge.post_stage(&thief, &row).await, JobOutcome::Ack);
    assert_eq!(fx.outbox(&o, "stage").await, "verify");
    // Both workers used the one stored plan: no article exists twice.
    assert_eq!(fx.server.posted_count().await, 3);
}

#[tokio::test]
async fn job_waits_for_memory_without_spending_an_attempt() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "k", &plaintext()).await;

    let all = fx.bridge.budget.try_charge(BUDGET).expect("empty budget");
    let outcome = fx.bridge.run_job(&o.job(OutboxStage::Post)).await;
    let JobOutcome::Retry { delay_secs } = outcome else {
        panic!("expected a retry, got {outcome:?}");
    };
    assert!((15..=60).contains(&delay_secs));
    assert_eq!(fx.outbox(&o, "stage").await, "post");
    assert_eq!(fx.outbox(&o, "attempts").await, "0");
    assert_eq!(fx.outbox(&o, "lease_until").await, "NULL");
    assert_eq!(fx.bridge.nntp.inner.connects(), 0);

    drop(all);
    fx.clock.advance_secs(delay_secs);
    assert_eq!(
        fx.bridge.run_job(&o.job(OutboxStage::Post)).await,
        JobOutcome::Ack
    );
    assert_eq!(fx.outbox(&o, "stage").await, "verify");
}

#[tokio::test]
async fn restore_maintenance_stops_jobs_and_dispatch() {
    let fx = Fx::with(GcMode::Disposable, Maintenance::Restore).await;
    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "k", b"one").await;
    fx.put(&bucket, "k", b"two").await;
    let before = fx.dump().await;

    fx.forbid_io.set(true);
    assert_eq!(
        fx.bridge.run_job(&o.job(OutboxStage::Post)).await,
        JobOutcome::Ack
    );
    assert_eq!(
        fx.bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert_eq!(
        fx.bridge.dispatch().await.unwrap(),
        DispatchReport::default()
    );
    assert_eq!(fx.dump().await, before);
    assert!(fx.bridge.jobs.sent().is_empty());
    let stats = fx.bridge.catalog.outbox_stats().await.unwrap();
    assert_eq!(stats.last_dispatch_at, None);
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dispatch_recovers_lost_notification() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "a/lost.bin", &plaintext()).await;

    // The PUT committed, but its queue message never arrived.
    fx.bridge.jobs.drop_next(1);
    fx.bridge
        .jobs
        .send(&o.job(OutboxStage::Post), 0)
        .await
        .unwrap();
    assert_eq!(fx.bridge.jobs.dropped(), 1);
    assert_eq!(fx.pump().await, 0);
    assert_eq!(fx.outbox(&o, "stage").await, "post");
    assert_eq!(fx.outbox(&o, "attempts").await, "0");

    // The next cron tick finds the row and sends the message again.
    fx.clock.advance_secs(300);
    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!(report.enqueued, 1);
    assert!(report.permits_seeded);
    assert_eq!(fx.bridge.jobs.sent()[0].job, o.job(OutboxStage::Post));
    let stats = fx.bridge.catalog.outbox_stats().await.unwrap();
    assert_eq!(stats.last_dispatch_at, Some(fx.clock.now()));

    fx.pump().await;
    assert_eq!(fx.outbox(&o, "stage").await, "done");
    assert_eq!(fx.extent(&o, "safety_state").await, "released");

    // Nothing is due any more: a tick sends nothing.
    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!((report.enqueued, report.gc_enqueued), (0, false));
    assert!(fx.bridge.jobs.sent().is_empty());
}

#[tokio::test]
async fn dispatch_recovers_a_message_lost_between_stages() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "k", &plaintext()).await;

    // The post job's hand-over to verify is lost.
    fx.bridge.jobs.drop_next(1);
    assert_eq!(
        fx.bridge.run_job(&o.job(OutboxStage::Post)).await,
        JobOutcome::Ack
    );
    assert_eq!(fx.bridge.jobs.dropped(), 1);
    assert_eq!(fx.outbox(&o, "stage").await, "verify");

    // Too early: the verify row is not due, so the tick sends nothing.
    assert_eq!(fx.bridge.dispatch().await.unwrap().enqueued, 0);
    fx.clock.advance_secs(300);
    assert_eq!(fx.bridge.dispatch().await.unwrap().enqueued, 1);
    assert_eq!(fx.bridge.jobs.sent()[0].job, o.job(OutboxStage::Verify));
    fx.pump().await;
    assert_eq!(fx.outbox(&o, "stage").await, "done");
}

#[tokio::test]
async fn dispatch_is_bounded() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    let total = DISPATCH_LIMIT as usize + 30;
    let mut objects = Vec::new();
    for i in 0..total {
        objects.push(fx.put(&bucket, &format!("k{i}"), b"tiny").await);
    }

    // One row has used up its attempts, one is held by a running job.
    let spent = &objects[0];
    fx.sql
        .exec(
            "UPDATE outbox SET attempts = ?2 WHERE extent_id = ?1",
            &[
                text(spent.extent.as_str()),
                SqlValue::Int(i64::from(MAX_ATTEMPTS) + 1),
            ],
        )
        .await
        .unwrap();
    let running = &objects[1];
    let now = fx.clock.now();
    let lease = fx
        .bridge
        .catalog
        .claim(
            &running.extent,
            &running.generation,
            OutboxStage::Post,
            "w",
            now,
        )
        .await
        .unwrap();
    assert!(lease.is_some());

    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!(report.enqueued, DISPATCH_LIMIT);
    assert_eq!(report.buried, 1);
    let sent = fx.bridge.jobs.take();
    assert_eq!(sent.len(), DISPATCH_LIMIT as usize, "one batch, no more");
    assert_eq!(fx.outbox(spent, "stage").await, "dead");
    for skipped in [spent, running] {
        assert!(sent.iter().all(|s| s.job != skipped.job(OutboxStage::Post)));
    }
    // The dispatcher claims nothing: every row is as due as before.
    let leased = "SELECT COUNT(*) FROM outbox WHERE lease_until IS NOT NULL";
    assert_eq!(fx.scalar(leased, &[]).await, "1");
    let tried = "SELECT COUNT(*) FROM outbox WHERE attempts > 0 AND stage = 'post'";
    assert_eq!(fx.scalar(tried, &[]).await, "1");
    assert_eq!(fx.bridge.dispatch().await.unwrap().enqueued, DISPATCH_LIMIT);

    let stats = fx.bridge.catalog.outbox_stats().await.unwrap();
    assert_eq!(stats.dead, 1);
}

#[tokio::test]
async fn dispatch_does_no_blob_or_nntp_io() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    // A due outbox row and due GC rows (the overwritten generation).
    fx.put(&bucket, "k", b"one").await;
    let o = fx.put(&bucket, "k", b"two").await;
    let before = fx.dump().await;
    let slots = "SELECT COUNT(*) FROM provider_permits";
    assert_eq!(fx.scalar(slots, &[]).await, "0");

    fx.forbid_io.set(true);
    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!(
        report,
        DispatchReport {
            enqueued: 1,
            gc_enqueued: true,
            evict_enqueued: false,
            buried: 0,
            permits_seeded: true,
            redriven: 0,
            redrive_failed: false,
            evict_failed: false,
        }
    );
    let sent: Vec<Job> = fx.bridge.jobs.take().into_iter().map(|s| s.job).collect();
    assert_eq!(
        sent,
        vec![o.job(OutboxStage::Post), Job::Gc { v: JOB_VERSION }]
    );
    assert_eq!(
        fx.dump().await,
        before,
        "the dispatcher only reads and sends"
    );
    assert_eq!(fx.scalar(slots, &[]).await, "2", "one slot per connection");
    assert_eq!(fx.bridge.budget.peak(), 0);
}

// ---------------------------------------------------------------------------
// GC
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gc_off_deletes_nothing() {
    let fx = Fx::with(GcMode::Off, Maintenance::Off).await;
    let bucket = fx.bucket("scratch", true).await;
    let old = fx.put(&bucket, "k", b"one").await;
    fx.put(&bucket, "k", b"two").await;
    let before = fx.dump().await;
    let due = fx
        .bridge
        .catalog
        .gc_due(fx.clock.now(), 50, true)
        .await
        .unwrap();
    assert_eq!(due.len(), 2, "the overwrite queued GC rows");

    let report = fx.bridge.dispatch().await.unwrap();
    assert!(!report.gc_enqueued);
    assert!(fx
        .bridge
        .jobs
        .take()
        .iter()
        .all(|s| s.job != Job::Gc { v: JOB_VERSION }));

    // Even a GC message that does arrive does nothing.
    fx.forbid_io.set(true);
    assert_eq!(
        fx.bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert_eq!(fx.dump().await, before);
    assert!(fx.has_safety(&old) && fx.has_cache(&old));
    assert!(fx.bridge.jobs.sent().is_empty());
}

#[tokio::test]
async fn gc_disposable_skips_real_buckets() {
    let fx = Fx::new().await;
    let scratch = fx.bucket("scratch", true).await;
    let real = fx.bucket("real", false).await;
    let scratch_old = fx.put(&scratch, "k", b"one").await;
    let scratch_new = fx.put(&scratch, "k", b"two").await;
    let real_old = fx.put(&real, "k", b"one").await;
    let real_new = fx.put(&real, "k", b"two").await;
    // A live object nobody overwrote.
    let untouched = fx.put(&scratch, "other", b"three").await;

    assert!(fx.bridge.dispatch().await.unwrap().gc_enqueued);
    fx.bridge.jobs.take();
    assert_eq!(
        fx.bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );

    // Only the retired generation of the disposable bucket lost its blobs.
    assert!(!fx.has_safety(&scratch_old) && !fx.has_cache(&scratch_old));
    for kept in [&scratch_new, &real_old, &real_new, &untouched] {
        assert!(fx.has_safety(kept) && fx.has_cache(kept));
    }
    assert_eq!(fx.extent(&scratch_old, "safety_state").await, "deleted");
    assert_eq!(fx.extent(&real_old, "safety_state").await, "held");
    assert_eq!(fx.gc_done(&scratch_old).await, "2");
    assert_eq!(fx.gc_done(&real_old).await, "0");

    // The real bucket's rows stay due, and stay untouched on every run.
    assert_eq!(
        fx.bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert!(fx.has_safety(&real_old) && fx.has_cache(&real_old));
    assert_eq!(fx.gc_done(&real_old).await, "0");
    assert!(!fx.bridge.dispatch().await.unwrap().gc_enqueued);
}

#[tokio::test]
async fn gc_job_caps_actions() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    // 30 overwrites: 60 blob deletes are due at once.
    let mut old = Vec::new();
    for i in 0..30 {
        let key = format!("k{i}");
        old.push(fx.put(&bucket, &key, b"one").await);
        fx.put(&bucket, &key, b"two").await;
    }
    let done = "SELECT COUNT(*) FROM gc WHERE done_at IS NOT NULL";
    let blobs = |fx: &Fx| {
        old.iter()
            .map(|o| usize::from(fx.has_safety(o)) + usize::from(fx.has_cache(o)))
            .sum::<usize>()
    };
    assert_eq!(blobs(&fx), 60);

    assert_eq!(
        fx.bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert_eq!(fx.scalar(done, &[]).await, GC_BATCH.to_string());
    assert_eq!(blobs(&fx), 60 - GC_BATCH as usize);
    // It asks for one more run instead of working on.
    let sent = fx.bridge.jobs.take();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].job, Job::Gc { v: JOB_VERSION });

    assert_eq!(
        fx.bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert_eq!(fx.scalar(done, &[]).await, "60");
    assert_eq!(blobs(&fx), 0);
    assert!(
        fx.bridge.jobs.sent().is_empty(),
        "nothing left: no re-enqueue"
    );
    // Blobs of live generations were never candidates.
    assert_eq!(fx.bridge.safety.inner.keys().len(), 30);
    assert_eq!(fx.bridge.cache.inner.keys().len(), 30);
}

#[tokio::test]
async fn gc_failing_row_does_not_block_the_batch() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    let mut old = Vec::new();
    for i in 0..3 {
        let key = format!("k{i}");
        old.push(fx.put(&bucket, &key, b"one").await);
        fx.put(&bucket, &key, b"two").await;
    }
    let open = "SELECT COUNT(*) FROM gc WHERE done_at IS NULL AND action LIKE 'delete_%'";
    assert_eq!(fx.scalar(open, &[]).await, "6");
    // The first extent's cache object cannot be deleted right now.
    let stuck = old[0].extent.cache_key();
    *fx.bridge.cache.broken.borrow_mut() = Some(stuck.clone());

    let gc = Job::Gc { v: JOB_VERSION };
    assert!(matches!(
        fx.bridge.run_job(&gc).await,
        JobOutcome::Retry { .. }
    ));
    // Every other row was handled; the failing one is still due.
    assert_eq!(fx.scalar(open, &[]).await, "1");
    assert!(fx.has_cache(&old[0]) && !fx.has_safety(&old[0]));
    for o in &old[1..] {
        assert!(!fx.has_cache(o) && !fx.has_safety(o));
    }

    // Once the store recovers, the retry finishes the row.
    *fx.bridge.cache.broken.borrow_mut() = None;
    assert_eq!(fx.bridge.run_job(&gc).await, JobOutcome::Ack);
    assert_eq!(fx.scalar(open, &[]).await, "0");
    assert!(!fx.has_cache(&old[0]));
}

// ---------------------------------------------------------------------------
// Re-drive
// ---------------------------------------------------------------------------

/// An object stored while one backbone was configured stops at `done` with
/// its safety copy held. Once a second backbone is configured, the
/// dispatcher sends it back to verify, and the copy is released on the
/// evidence of both.
#[tokio::test]
async fn dispatch_redrives_done_extents_when_a_backbone_is_added() {
    let mut fx = Fx::new().await;
    fx.bridge.cfg.required_backbones = 2;
    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.bridge
        .jobs
        .send(&o.job(OutboxStage::Post), 0)
        .await
        .unwrap();
    fx.pump().await;
    assert_eq!(fx.outbox(&o, "stage").await, "done");
    assert_eq!(fx.extent(&o, "safety_state").await, "held");
    assert!(fx.has_safety(&o));

    // One backbone can never satisfy two: the tick leaves the row alone
    // instead of verifying it again on every run.
    fx.clock.advance_secs(300);
    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!((report.redriven, report.enqueued), (0, 0));
    assert_eq!(fx.outbox(&o, "stage").await, "done");

    // A second backbone that has the articles by peering.
    let mut config = ServerConfig::for_test();
    config.articles = Vec::new();
    config.missing_ids.clear();
    config.users.insert(
        USER.to_string(),
        UserConfig {
            password: PASS.to_string(),
            max_connections: 2,
        },
    );
    let second = TestNntpServer::spawn(config).await;
    let peer = |server: &TestNntpServer| {
        let addr = server.addr();
        nntp_support::nntp_config(
            &addr.ip().to_string(),
            addr.port(),
            "otheruser",
            "otherpass",
        )
    };
    let mut src = nntp_support::dial(&peer(&fx.server)).await.unwrap();
    let mut dst = nntp_support::dial(&peer(&second)).await.unwrap();
    for row in fx.bridge.catalog.articles(&o.extent).await.unwrap() {
        let mut article = Vec::new();
        src.article_to(&row.message_id, &mut article).await.unwrap();
        dst.post_article(&row.message_id, &article).await.unwrap();
    }
    src.quit().await;
    dst.quit().await;
    let mut p1 = fx.bridge.cfg.providers[0].clone();
    p1.id = "p1".to_string();
    p1.port = second.addr().port();
    p1.backbone = "bb1".to_string();
    p1.post = false;
    fx.bridge.cfg.providers.push(p1);

    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!((report.redriven, report.enqueued), (1, 1));
    assert_eq!(fx.bridge.jobs.sent()[0].job, o.job(OutboxStage::Verify));
    assert_eq!(fx.outbox(&o, "stage").await, "verify");
    fx.pump().await;
    assert_eq!(fx.outbox(&o, "stage").await, "done");
    assert_eq!(fx.extent(&o, "safety_state").await, "released");
    assert!(fx.has_safety(&o));
    let status = fx.bridge.catalog.backbone_status(&o.extent).await.unwrap();
    assert_eq!(status.iter().filter(|s| s.counts).count(), 2);
    // Nothing was posted twice.
    assert_eq!(fx.server.posted_count().await, 3);

    // Released: the next tick has nothing to re-drive.
    fx.clock.advance_secs(300);
    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!((report.redriven, report.enqueued), (0, 0));
}

/// An NNTP server with the test account and no articles.
async fn empty_server() -> TestNntpServer {
    let mut config = ServerConfig::for_test();
    config.articles = Vec::new();
    config.missing_ids.clear();
    config.users.insert(
        USER.to_string(),
        UserConfig {
            password: PASS.to_string(),
            max_connections: 2,
        },
    );
    TestNntpServer::spawn(config).await
}

/// Three backbones, two required, and the third never receives the
/// extent. Two good copies are enough: the third is recorded as missing
/// and the safety copy is released, once. The extent must not go round
/// between verify and release for ever.
#[tokio::test]
async fn release_with_a_backbone_that_never_has_the_extent() {
    let mut fx = Fx::new().await;
    fx.bridge.cfg.required_backbones = 2;
    // bb1 is a second account on the server that has the articles.
    let mut p1 = fx.bridge.cfg.providers[0].clone();
    p1.id = "p1".to_string();
    p1.backbone = "bb1".to_string();
    p1.post = false;
    let third = empty_server().await;
    let mut p2 = p1.clone();
    p2.id = "p2".to_string();
    p2.backbone = "bb2".to_string();
    p2.port = third.addr().port();
    fx.bridge.cfg.providers.extend([p1, p2]);

    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.bridge
        .jobs
        .send(&o.job(OutboxStage::Post), 0)
        .await
        .unwrap();
    // Post, three verify reads with bb2's four waits, one release.
    let runs = fx.pump().await;
    assert!(runs <= 12, "{runs} deliveries");

    assert_eq!(fx.outbox(&o, "stage").await, "done");
    assert_eq!(fx.extent(&o, "safety_state").await, "released");
    assert!(fx.has_safety(&o));
    let evidence = fx.extent(&o, "release_evidence").await;
    let evidence: serde_json::Value = serde_json::from_str(&evidence).unwrap();
    assert_eq!(evidence.as_array().unwrap().len(), 2);
    let status = fx.bridge.catalog.backbone_status(&o.extent).await.unwrap();
    let of = |b: &str| status.iter().find(|s| s.backbone == b).unwrap();
    assert!(of("bb0").counts && of("bb1").counts);
    assert!(!of("bb2").counts);
    assert_eq!(of("bb2").result, VerifyResult::Missing);
    assert_eq!(third.posted_count().await, 0);

    // Released: a later tick finds nothing to send or to re-drive.
    fx.clock.advance_secs(300);
    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!((report.redriven, report.enqueued), (0, 0));
    assert_eq!(fx.pump().await, 0);
    assert_eq!(fx.outbox(&o, "stage").await, "done");
}

/// A re-drive that fails is reported and the due rows still go out.
#[tokio::test(flavor = "current_thread")]
async fn dispatch_survives_a_failed_redrive() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch", true).await;
    let o = fx.put(&bucket, "k", &plaintext()).await;
    fx.make_due(&o).await;
    fx.sql.exec("DROP TABLE scan_cursors", &[]).await.unwrap();

    let report = fx.bridge.dispatch().await.unwrap();
    assert!(report.redrive_failed);
    assert_eq!((report.redriven, report.enqueued), (0, 1));
    assert_eq!(fx.bridge.jobs.sent()[0].job, o.job(OutboxStage::Post));
}
