//! The job path over a unit (package W2-jobs): post, verify, release, the
//! dispatcher and GC run unchanged, with `TenantCatalog` as their
//! catalogue. Its job methods are calls to a managed tenant's unit, sent
//! as JSON as they cross `fetch`; provider permits and health stay in the
//! shared database. The unit here is the native one; `workers/unit-suite`
//! runs this file against a Durable Object too.

mod nntp_support;

use std::cell::Cell;
use std::rc::Rc;

use nntp_support::{TcpConnector, PASS, USER};
use velmora::rng::SystemRng;
use velmora_bridge::config::{Environment, GcMode, Maintenance};
use velmora_bridge::crypto::{seal_extent, unwrap_bdk, wrap_bdk, DataKey};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::tenant_catalog::{
    TenantCatalog, UnitPort, NOT_ON_UNIT, UNIT_CLOSED, UNIT_REFUSED, UNIT_STALE, UNIT_STALE_JOB,
    UNIT_SYNC_NEEDED,
};
use velmora_bridge::testkit::{
    FakeJobs, FixedClock, MemBlobStore, PublishUnrecorded, RusqliteSql, TestKek,
};
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Seqs, SyncHead, TenantId, TenantState, Unit, UnitAnswer,
    UnitCall, UnitName, UnitOp, UnitSql,
};
use velmora_bridge::unit_lease::alarm::AlarmRules;
use velmora_bridge::unit_lease::lease::{LeaseRules, Proven};
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

const T0: UnixMs = UnixMs(1_800_000_000_000);
const BUDGET: u64 = 48 * 1024 * 1024;

fn tenant() -> TenantId {
    TenantId::parse("t_00000000000000a7").unwrap()
}

fn own() -> UnitName {
    UnitName::new(tenant(), 0)
}

/// The scope the consumer gives a job of this tenant (`jobmsg::admit_for`).
fn scope() -> velmora_bridge::TenantScope {
    velmora_bridge::TenantScope::managed(&tenant()).unwrap()
}

// ---------------------------------------------------------------------------
// The unit and the way to it
// ---------------------------------------------------------------------------

/// One SQLite database, shared by the unit and the test's own reads.
#[derive(Clone)]
struct Db(Rc<RusqliteSql>);

impl Sql for Db {
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

impl UnitSql for Db {
    fn atomically(&self, f: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.0.atomically(f)
    }
    fn apply_script(&self, script: &str) -> Result<()> {
        self.0.apply_script(script)
    }
    fn database_size(&self) -> Result<u64> {
        self.0.database_size()
    }
}

/// The unit, reached as through `fetch`: the call and the answer cross
/// as JSON.
struct Local {
    unit: Rc<Unit<Db>>,
    clock: Rc<FixedClock>,
    calls: Rc<Cell<u32>>,
}

impl UnitPort for Local {
    async fn call(&self, call: &UnitCall) -> Result<UnitAnswer> {
        self.calls.set(self.calls.get() + 1);
        let wire = serde_json::to_string(call).unwrap();
        let call: UnitCall = serde_json::from_str(&wire).expect("a call reads back");
        let answer = self.unit.handle(&call, self.clock.now());
        let wire = serde_json::to_string(&answer).unwrap();
        Ok(serde_json::from_str(&wire).expect("an answer reads back"))
    }
}

struct SharedClock(Rc<FixedClock>);

impl Clock for SharedClock {
    fn now(&self) -> UnixMs {
        self.0.now()
    }
}

type UnitBridge = Bridge<
    TenantCatalog<Local, SqlCatalog<RusqliteSql>>,
    MemBlobStore,
    TcpConnector,
    FakeJobs,
    TestKek,
    SharedClock,
>;

struct Fx {
    bridge: UnitBridge,
    unit: Rc<Unit<Db>>,
    /// The unit's catalogue for the test's own setup and reads.
    cat: SqlCatalog<Db>,
    db: Db,
    clock: Rc<FixedClock>,
    server: TestNntpServer,
    calls: Rc<Cell<u32>>,
    seed: Cell<u32>,
}

struct Obj {
    extent: ExtentId,
    generation: GenerationId,
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

fn worker(unit: &Unit<Db>, op: UnitOp, now: UnixMs) -> UnitAnswer {
    unit.handle(
        &UnitCall {
            name: own(),
            kind: CallKind::Worker,
            seqs: Some(Seqs {
                state_seq: 3,
                keys_seq: 0,
            }),
            authenticated: true,
            listed: true,
            op,
        },
        now,
    )
}

fn sync(unit: &Unit<Db>, state_seq: u64, restoring: Option<u64>, now: UnixMs) {
    let a = worker(
        unit,
        UnitOp::Sync {
            head: SyncHead {
                seqs: Seqs {
                    state_seq,
                    keys_seq: 0,
                },
                tenant_state: TenantState::Active,
                tenant_mode: None,
                restoring_since: restoring,
                lift: None,
            },
        },
        now,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
}

/// The Worker's renewal at `now` (rule 12).
fn renew(unit: &Unit<Db>, now: UnixMs) {
    let a = worker(
        unit,
        UnitOp::Renew {
            proof_start: now,
            proven: Proven {
                state_seq: 3,
                keys_seq: 0,
                stamp_counter: None,
                revoked: 0,
            },
            revocations: Vec::new(),
        },
        now,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "renew: {a:?}");
}

impl Fx {
    async fn new() -> Fx {
        Fx::with(GcMode::Disposable, 3).await
    }

    /// `job_seq`: the `state_seq` the jobs carry (the unit is at 3).
    async fn with(gc_mode: GcMode, job_seq: u64) -> Fx {
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
            hosts: Vec::new(),
            host_select: Default::default(),
            port: server.addr().port(),
            tls: false,
            user: USER.to_string(),
            pass: PASS.to_string(),
            backbone: "bb0".to_string(),
            post: true,
            read: true,
            max_conns: 2,
            max_ips: None,
            drill_conns: 0,
            priority: 0,
            retention_days: None,
            pool: None,
            pool_max_conns: None,
            proxies: Vec::new(),
            enabled: true,
            release: true,
        }];
        let cfg = BridgeConfig {
            admin_read_token: None,
            admin_host: None,
            metrics_sample: 10,
            environment: Environment::Dev,
            s3_host: "s3.test".to_string(),
            region: "auto".to_string(),
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
            inflight_budget_bytes: BUDGET,
            job_budget_bytes: BUDGET,
            gc_mode,
            hot_cap_bytes: velmora_bridge::config::DEFAULT_HOT_CAP_BYTES,
            maintenance: Maintenance::Off,
            server_side_copy: false,
            get_fanout_bytes: None,
            // Tenant 0's id: `for_unit` below makes the unit's.
            catalogue_id: "main".to_string(),
            dev_trust_http: false,
            verify: Default::default(),
            providers,
            admin_token: Secret::new("admin-token-fixture-admin-token-fixture".to_string()),
        }
        // The unit's job configuration, as the consumer makes it.
        .for_unit(&own())
        .unwrap();
        assert_eq!(cfg.catalogue_id, format!("{}.0", tenant()));
        let clock = Rc::new(FixedClock::new(T0));
        let db = Db(Rc::new(RusqliteSql::open_in_memory().unwrap()));
        // A lease that outlasts the test's clock: these tests are about
        // the job path; `unit_lease_wiring.rs` holds the lease's rules.
        let unit = Rc::new(Unit::new(db.clone(), own(), "").with_rules(
            LeaseRules {
                term_ms: 30 * 24 * 3_600_000,
                ..LeaseRules::DEFAULT
            },
            AlarmRules::DEFAULT,
        ));
        let token = BirthToken {
            name: own(),
            jurisdiction: String::new(),
            record_seq: 3,
            schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
            key_scheme: 2,
            kind: BirthKind::Birth,
        };
        let born = worker(
            &unit,
            UnitOp::Provision {
                token,
                sealed: vec![1],
            },
            T0,
        );
        assert!(matches!(born, UnitAnswer::Ok { .. }), "{born:?}");
        sync(&unit, 3, None, T0);
        renew(&unit, T0);
        let calls = Rc::new(Cell::new(0));
        let port = Local {
            unit: Rc::clone(&unit),
            clock: Rc::clone(&clock),
            calls: Rc::clone(&calls),
        };
        // The shared database: permits and provider health of every
        // tenant.
        let shared = SqlCatalog::new(RusqliteSql::with_schema().unwrap());
        let catalog = TenantCatalog::new(
            port,
            shared,
            own(),
            Seqs {
                state_seq: job_seq,
                keys_seq: 0,
            },
        );
        let bridge = Bridge {
            catalog,
            safety: MemBlobStore::new(),
            cache: MemBlobStore::new(),
            nntp: TcpConnector::default(),
            jobs: FakeJobs::new(),
            kek: TestKek::new(),
            clock: SharedClock(Rc::clone(&clock)),
            budget: ByteBudget::new(BUDGET),
            cfg,
        };
        Fx {
            bridge,
            cat: SqlCatalog::new(db.clone()),
            unit,
            db,
            clock,
            server,
            calls,
            seed: Cell::new(1),
        }
    }

    fn next<const N: usize>(&self) -> [u8; N] {
        let n = self.seed.get();
        self.seed.set(n + 1);
        let mut id = [n as u8; N];
        id[..4].copy_from_slice(&n.to_be_bytes());
        id
    }

    async fn bucket(&self, name: &str) -> Bucket {
        let id = BucketId::mint(self.next());
        let bdk = DataKey::generate(&mut SystemRng).unwrap();
        let (kek_version, wrapped) = wrap_bdk(&self.bridge.kek, &id, &bdk, &mut SystemRng).unwrap();
        let bucket = Bucket {
            id,
            name: name.to_string(),
            owner: "owner".to_string(),
            bdk_wrapped: wrapped.to_vec(),
            kek_version,
            disposable: true,
            created_at: T0,
        };
        // A managed tenant's unit holds only scheme-2 BDK wraps (rule 13).
        // The scheme-2 wrap is the key lane's and not on this branch: the
        // unit gets this wrap's bytes under the scheme-2 version byte, and
        // the test keeps the scheme-1 wrap for its own seal. The job path
        // never opens a BDK.
        let mut held = bucket.clone();
        held.bdk_wrapped[0] = 0x02;
        assert_eq!(
            self.cat.create_bucket(&held).await.unwrap(),
            Guard::Applied(())
        );
        bucket
    }

    /// What a finished PUT leaves in the unit and the blob stores.
    async fn put(&self, bucket: &Bucket, key: &str, plain: &[u8]) -> Obj {
        let n: [u8; 13] = self.next();
        let now = self.clock.now();
        let bdk = unwrap_bdk(
            &self.bridge.kek,
            bucket.kek_version,
            &bucket.id,
            &bucket.bdk_wrapped,
        )
        .unwrap();
        let extent_id = ExtentId::mint(n);
        let sealed = seal_extent(&bdk, &bucket.id, &extent_id, plain, &mut SystemRng).unwrap();
        let generation = GenerationRow {
            id: GenerationId::mint(now, n[..8].try_into().unwrap()),
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
            .put(
                &scope().safety_key(&extent_id),
                sealed.ciphertext.clone(),
                &meta,
            )
            .await
            .unwrap();
        self.bridge
            .cache
            .put(
                &scope().cache_key(&extent_id),
                sealed.ciphertext.clone(),
                &meta,
            )
            .await
            .unwrap();
        self.cat
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
        }
    }

    async fn scalar(&self, sql: &str, params: &[SqlValue]) -> String {
        let rows = self.db.query(sql, params).await.unwrap();
        match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Text(s)) => s.clone(),
            Some(SqlValue::Int(n)) => n.to_string(),
            Some(SqlValue::Null) | None => "NULL".to_string(),
            Some(other) => panic!("unexpected {other:?}"),
        }
    }

    async fn outbox(&self, o: &Obj, column: &str) -> String {
        let sql = format!("SELECT {column} FROM outbox WHERE extent_id = ?1");
        self.scalar(&sql, &[SqlValue::Text(o.extent.as_str().into())])
            .await
    }

    async fn extent(&self, o: &Obj, column: &str) -> String {
        let sql = format!("SELECT {column} FROM extents WHERE id = ?1");
        self.scalar(&sql, &[SqlValue::Text(o.extent.as_str().into())])
            .await
    }

    /// Delivers queued jobs in due order until the queue is empty.
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
            if let JobOutcome::Retry { delay_secs } = self.bridge.run_job(&scope(), &job).await {
                queue.push((self.clock.now().plus_secs(delay_secs), job));
            }
        }
    }
}

fn plaintext() -> Vec<u8> {
    nntp_support::marked_plaintext(2 * 1024 * 1024 + 4321)
}

// ---------------------------------------------------------------------------
// The lifecycle on a unit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn post_verify_release_run_on_the_units_catalogue() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "a/big.bin", &plaintext()).await;
    assert_eq!(fx.outbox(&o, "stage").await, "post");
    fx.bridge
        .jobs
        .send(&o.job(OutboxStage::Post), 0)
        .await
        .unwrap();
    let runs = fx.pump().await;
    assert_eq!(runs, 3, "one delivery per stage");
    assert_eq!(fx.outbox(&o, "stage").await, "done");
    assert_eq!(fx.outbox(&o, "last_error").await, "NULL");
    assert_eq!(fx.extent(&o, "safety_state").await, "released");
    assert_eq!(fx.extent(&o, "article_count").await, "3");
    assert_ne!(fx.extent(&o, "release_evidence").await, "NULL");
    assert_eq!(fx.server.posted_count().await, 3);
    let posted = "SELECT COUNT(*) FROM articles WHERE state = 'posted'";
    assert_eq!(fx.scalar(posted, &[]).await, "3");
    let verified = "SELECT COUNT(*) FROM verifications WHERE result = 'ok'";
    assert_eq!(fx.scalar(verified, &[]).await, "1");
    // Every catalogue step went to the unit; the permits stayed shared.
    assert!(fx.calls.get() > 10, "{} unit calls", fx.calls.get());
    let held = "SELECT COUNT(*) FROM provider_permits";
    assert_eq!(fx.scalar(held, &[]).await, "0", "no permit in the unit");
    let shared_slots = fx
        .bridge
        .catalog
        .shared()
        .sql
        .query("SELECT COUNT(*), COUNT(holder) FROM provider_permits", &[])
        .await
        .unwrap();
    assert_eq!(shared_slots[0], vec![SqlValue::Int(2), SqlValue::Int(0)]);
    assert_eq!(fx.bridge.budget.in_use(), 0);
}

#[tokio::test]
async fn eviction_drops_a_released_extents_copies_through_the_unit() {
    let mut fx = Fx::new().await;
    // Every evictable byte is over the cap.
    fx.bridge.cfg.hot_cap_bytes = 0;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "a/big.bin", &plaintext()).await;
    fx.bridge
        .jobs
        .send(&o.job(OutboxStage::Post), 0)
        .await
        .unwrap();
    fx.pump().await;
    assert_eq!(fx.extent(&o, "safety_state").await, "released");
    let cipher: u64 = fx.extent(&o, "cipher_size").await.parse().unwrap();
    assert_eq!(fx.bridge.evict_batch(&scope(), 0).await.unwrap(), cipher);
    assert!(!fx.bridge.safety.contains(&scope().safety_key(&o.extent)));
    assert!(!fx.bridge.cache.contains(&scope().cache_key(&o.extent)));
    assert_eq!(fx.extent(&o, "hot_safety_bytes").await, "0");
    assert_eq!(fx.extent(&o, "hot_cache_bytes").await, "0");
}

#[tokio::test]
async fn the_dispatcher_finds_a_lost_message_in_the_unit() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "a/lost.bin", &plaintext()).await;
    // The PUT committed, but its queue message never arrived.
    fx.clock.advance_secs(300);
    let report = fx.bridge.dispatch().await.unwrap();
    assert_eq!(report.enqueued, 1);
    // The usage recount's state reads back through the unit while idle.
    assert!(!report.recount_failed, "{report:?}");
    let (state, _) = fx.bridge.catalog.usage_recounts().await.unwrap();
    assert!(!state.running);
    assert_eq!(fx.bridge.jobs.sent()[0].job, o.job(OutboxStage::Post));
    fx.pump().await;
    assert_eq!(fx.outbox(&o, "stage").await, "done");
    assert_eq!(fx.extent(&o, "safety_state").await, "released");
}

#[tokio::test]
async fn gc_takes_an_overwritten_extent_on_the_unit() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let old = fx.put(&bucket, "k", b"one").await;
    let new = fx.put(&bucket, "k", b"two").await;
    let due = fx.cat.gc_due(fx.clock.now(), 50, true).await.unwrap();
    assert_eq!(due.len(), 2, "the overwrite queued GC rows");
    // The dispatcher (its stamp raise included) sends the GC job.
    assert!(fx.bridge.dispatch().await.unwrap().gc_enqueued);
    fx.bridge.jobs.take();
    assert_eq!(
        fx.bridge
            .run_job(&scope(), &Job::Gc { v: JOB_VERSION })
            .await,
        JobOutcome::Ack
    );
    let done = "SELECT COUNT(*) FROM gc WHERE extent_id = ?1 AND done_at IS NOT NULL";
    let id = [SqlValue::Text(old.extent.as_str().into())];
    assert_eq!(fx.scalar(done, &id).await, "2");
    assert_eq!(fx.extent(&old, "safety_state").await, "deleted");
    assert!(!fx.bridge.safety.contains(&scope().safety_key(&old.extent)));
    assert!(!fx.bridge.cache.contains(&scope().cache_key(&old.extent)));
    // The live object keeps its copies.
    assert!(fx.bridge.safety.contains(&scope().safety_key(&new.extent)));
}

// ---------------------------------------------------------------------------
// What the unit refuses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_job_with_lower_numbers_changes_nothing_and_gets_the_units_numbers() {
    // The unit holds seq 3; the job carries 2.
    let fx = Fx::with(GcMode::Disposable, 2).await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "a/x.bin", &plaintext()).await;
    // The unit answers its own numbers and does nothing (AM-50).
    let err = fx
        .bridge
        .catalog
        .job_extent(&o.extent, &o.generation)
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::Invalid(UNIT_STALE)), "{err:?}");
    let unit_seqs = Seqs {
        state_seq: 3,
        keys_seq: 0,
    };
    assert_eq!(fx.bridge.catalog.stale_seqs(), Some(unit_seqs));
    assert_eq!(fx.bridge.catalog.latest_seqs(), Some(unit_seqs));
    fx.bridge.run_job(&scope(), &o.job(OutboxStage::Post)).await;
    // The consumer can tell why: the unit's refusal is kept.
    assert_eq!(fx.bridge.catalog.refusal(), Some(UNIT_STALE));
    assert_eq!(fx.outbox(&o, "stage").await, "post");
    assert_eq!(fx.outbox(&o, "attempts").await, "0");
    assert_eq!(fx.server.posted_count().await, 0);
    // Run once more with the unit's numbers: it goes through.
    let again = TenantCatalog::new(
        Local {
            unit: Rc::clone(&fx.unit),
            clock: Rc::clone(&fx.clock),
            calls: Rc::default(),
        },
        SqlCatalog::new(RusqliteSql::with_schema().unwrap()),
        own(),
        fx.bridge.catalog.stale_seqs().unwrap(),
    );
    again.job_extent(&o.extent, &o.generation).await.unwrap();
    assert_eq!(again.refusal(), None);
    assert_eq!(again.stale_seqs(), None);
    assert_eq!(again.latest_seqs(), Some(unit_seqs));
}

#[tokio::test]
async fn a_job_with_no_numbers_is_refused_and_is_not_stale() {
    let fx = Fx::new().await;
    let call = UnitCall {
        name: own(),
        kind: CallKind::Job,
        seqs: None,
        authenticated: true,
        listed: false,
        op: UnitOp::Job {
            call: velmora_bridge::unit::jobcall::JobCall::evictable_bytes {},
        },
    };
    assert_eq!(
        fx.unit.handle(&call, fx.clock.now()),
        UnitAnswer::Refused {
            reason: velmora_bridge::unit::Refused::Identity(
                velmora_bridge::unit::identity::Refusal::StaleJob
            ),
            alarm: false,
        }
    );
    // Through the job catalogue it is UNIT_STALE_JOB, never UNIT_STALE:
    // the consumer pages for it instead of running it again (AM-50).
    struct NoNumbers(Local);
    impl UnitPort for NoNumbers {
        async fn call(&self, call: &UnitCall) -> Result<UnitAnswer> {
            let mut c = call.clone();
            c.seqs = None;
            self.0.call(&c).await
        }
    }
    let cat = TenantCatalog::new(
        NoNumbers(Local {
            unit: Rc::clone(&fx.unit),
            clock: Rc::clone(&fx.clock),
            calls: Rc::default(),
        }),
        SqlCatalog::new(RusqliteSql::with_schema().unwrap()),
        own(),
        Seqs {
            state_seq: 3,
            keys_seq: 0,
        },
    );
    let err = cat.evictable_bytes().await.unwrap_err();
    assert!(
        matches!(err, BridgeError::Invalid(UNIT_STALE_JOB)),
        "{err:?}"
    );
    assert_eq!(cat.stale_seqs(), None);
}

#[tokio::test]
async fn job_calls_say_no_record_lists_the_unit() {
    // AM-50 (L6-7c): the consumer decides an unborn unit from the
    // tenant's head, so a job call never carries `listed`.
    struct Seen(Local, Rc<Cell<Option<bool>>>);
    impl UnitPort for Seen {
        async fn call(&self, call: &UnitCall) -> Result<UnitAnswer> {
            self.1.set(Some(call.listed));
            self.0.call(call).await
        }
    }
    let fx = Fx::new().await;
    let seen = Rc::new(Cell::new(None));
    let cat = TenantCatalog::new(
        Seen(
            Local {
                unit: Rc::clone(&fx.unit),
                clock: Rc::clone(&fx.clock),
                calls: Rc::default(),
            },
            Rc::clone(&seen),
        ),
        SqlCatalog::new(RusqliteSql::with_schema().unwrap()),
        own(),
        Seqs {
            state_seq: 3,
            keys_seq: 0,
        },
    );
    cat.evictable_bytes().await.unwrap();
    assert_eq!(seen.get(), Some(false));
}

#[tokio::test]
async fn a_closed_unit_takes_no_job() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "a/x.bin", &plaintext()).await;
    // A restore entry closes the unit; the job's numbers are now below
    // too, so take a catalogue whose numbers match the closed unit.
    sync(&fx.unit, 4, Some(4), fx.clock.now());
    let closed = TenantCatalog::new(
        Local {
            unit: Rc::clone(&fx.unit),
            clock: Rc::clone(&fx.clock),
            calls: Rc::default(),
        },
        SqlCatalog::new(RusqliteSql::with_schema().unwrap()),
        own(),
        Seqs {
            state_seq: 4,
            keys_seq: 0,
        },
    );
    let err = closed
        .job_extent(&o.extent, &o.generation)
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::Invalid(UNIT_CLOSED)), "{err:?}");
    assert_eq!(fx.outbox(&o, "stage").await, "post");
}

#[tokio::test]
async fn the_request_path_is_not_served_through_the_job_catalogue() {
    let fx = Fx::new().await;
    let err = fx
        .bridge
        .catalog
        .bucket_by_name("scratch")
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::NotImplemented(NOT_ON_UNIT)));
    // A job call made as a request is refused by the unit.
    let call = UnitCall {
        name: own(),
        kind: CallKind::Request,
        seqs: Some(Seqs {
            state_seq: 3,
            keys_seq: 0,
        }),
        authenticated: true,
        listed: true,
        op: UnitOp::Job {
            call: velmora_bridge::unit::jobcall::JobCall::evictable_bytes {},
        },
    };
    assert!(matches!(
        fx.unit.handle(&call, fx.clock.now()),
        UnitAnswer::Refused {
            reason: velmora_bridge::unit::Refused::Unauthenticated,
            ..
        }
    ));
}

#[tokio::test]
async fn a_job_with_higher_numbers_needs_a_sync() {
    let fx = Fx::with(GcMode::Disposable, 4).await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "a/x.bin", b"x").await;
    let err = fx
        .bridge
        .catalog
        .job_extent(&o.extent, &o.generation)
        .await
        .unwrap_err();
    assert!(
        matches!(err, BridgeError::Invalid(UNIT_SYNC_NEEDED)),
        "{err:?}"
    );
    assert_eq!(fx.bridge.catalog.refusal(), Some(UNIT_SYNC_NEEDED));
}

#[tokio::test]
async fn a_stamp_under_another_id_than_the_units_is_refused() {
    let fx = Fx::new().await;
    let err = fx.bridge.catalog.stamp("main").await.unwrap_err();
    assert!(
        velmora_bridge::stamp::is_catalogue_id_error(&err),
        "{err:?}"
    );
    let own = format!("{}.0", tenant());
    fx.bridge.catalog.stamp(&own).await.unwrap();
}

#[tokio::test]
async fn jobs_run_for_a_suspended_tenant_and_not_for_a_shred() {
    let fx = Fx::new().await;
    let bucket = fx.bucket("scratch").await;
    let o = fx.put(&bucket, "a/x.bin", b"x").await;
    let state = |s: TenantState, mode: Option<velmora_bridge::unit::call::HoldMode>| {
        let a = worker(
            &fx.unit,
            UnitOp::Sync {
                head: SyncHead {
                    seqs: Seqs {
                        state_seq: 3,
                        keys_seq: 0,
                    },
                    tenant_state: s,
                    tenant_mode: mode,
                    restoring_since: None,
                    lift: None,
                },
            },
            fx.clock.now(),
        );
        assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    };
    for (s, mode) in [
        (
            TenantState::Suspended,
            Some(velmora_bridge::unit::call::HoldMode::Locked),
        ),
        (TenantState::Deleting, None),
    ] {
        state(s, mode);
        assert!(fx
            .bridge
            .catalog
            .job_extent(&o.extent, &o.generation)
            .await
            .unwrap()
            .is_some());
    }
    state(TenantState::Shredding, None);
    let err = fx
        .bridge
        .catalog
        .job_extent(&o.extent, &o.generation)
        .await
        .unwrap_err();
    assert!(matches!(err, BridgeError::Invalid(UNIT_REFUSED)), "{err:?}");
}

#[tokio::test]
async fn a_job_call_without_authentication_is_refused() {
    let fx = Fx::new().await;
    let call = UnitCall {
        name: own(),
        kind: CallKind::Job,
        seqs: Some(Seqs {
            state_seq: 3,
            keys_seq: 0,
        }),
        authenticated: false,
        listed: true,
        op: UnitOp::Job {
            call: velmora_bridge::unit::jobcall::JobCall::evictable_bytes {},
        },
    };
    assert!(matches!(
        fx.unit.handle(&call, fx.clock.now()),
        UnitAnswer::Refused {
            reason: velmora_bridge::unit::Refused::Unauthenticated,
            ..
        }
    ));
}

/// A unit's sweep asks only its tenant's layout whether a generation is
/// recorded: a record under tenant 0's flat name never counts for it.
#[tokio::test]
async fn a_units_generation_record_is_looked_for_in_its_own_layout_only() {
    use velmora_bridge::recovery::{generation_recorded, Layout};
    let store = MemBlobStore::new();
    let id = GenerationId::new("g_00000000000000000000000001");
    let (bucket, extent) = (BucketId::new("b_0000000000000001"), ExtentId::new("x_0"));
    let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest([1u8]).into();
    let meta = BlobMeta {
        bucket: &bucket,
        extent: &extent,
        cipher_sha256: &digest,
    };
    store
        .put(&Layout::flat().generation_key(&id), vec![1], &meta)
        .await
        .unwrap();
    assert!(!generation_recorded(&store, &scope(), &id).await.unwrap());
    assert!(
        generation_recorded(&store, &TenantScope::tenant_zero(), &id)
            .await
            .unwrap()
    );
    store
        .put(&Layout::of(&scope()).generation_key(&id), vec![1], &meta)
        .await
        .unwrap();
    assert!(generation_recorded(&store, &scope(), &id).await.unwrap());
}
