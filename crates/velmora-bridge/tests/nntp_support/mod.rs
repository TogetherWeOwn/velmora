//! Shared rig for the NNTP stage tests: the in-process fake server, a TCP
//! connector that counts live sessions, and a small in-memory `Catalog`
//! that models leases, article plans, verifications and provider permits.
//!
//! The in-memory catalogue exists so the stages are tested against the
//! `Catalog` trait alone; the SQL catalogue has its own tests.

#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use velmora::media::{FileKey, Profile, Sealer};
use velmora::nntp::{NntpClient, NntpConfig, PostOutcome};
use velmora::rng::SystemRng;
use velmora::transports::NativeTlsTransport;
use velmora_bridge::config::{Environment, GcMode, Maintenance};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::testkit::{FakeJobs, FixedClock, MemBlobStore, TestKek};
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

pub const T0: UnixMs = UnixMs(1_800_000_000_000);
pub const LEASE_SECS: u32 = 600;
pub const PERMIT_SECS: u32 = 120;
pub const USER: &str = "testuser";
pub const PASS: &str = "testpass";

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// ---------------------------------------------------------------------------
// Connector
// ---------------------------------------------------------------------------

/// Dials the provider's host and port in plaintext and counts sessions.
#[derive(Default)]
pub struct TcpConnector {
    live: Rc<Cell<u32>>,
    peak: Rc<Cell<u32>>,
    connects: Cell<u32>,
}

impl TcpConnector {
    /// Most sessions ever open at once.
    pub fn peak(&self) -> u32 {
        self.peak.get()
    }
    pub fn live(&self) -> u32 {
        self.live.get()
    }
    /// Sessions opened so far.
    pub fn connects(&self) -> u32 {
        self.connects.get()
    }
}

pub fn nntp_config(host: &str, port: u16, user: &str, pass: &str) -> NntpConfig {
    NntpConfig {
        host: host.to_string(),
        port,
        tls: false,
        allow_insecure_plaintext: true,
        username: Some(user.to_string()),
        password: Some(pass.to_string()),
        timeout: Duration::from_secs(5),
        max_article_bytes: 1024 * 1024,
        ..NntpConfig::default()
    }
}

pub async fn dial(cfg: &NntpConfig) -> Result<NntpClient<NativeTlsTransport>> {
    let transport = velmora::transports::tokio_tls::connect(cfg)
        .await
        .map_err(velmora::Error::Io)?;
    Ok(NntpClient::connect(transport, cfg).await?)
}

pub struct CountedSession {
    inner: Option<NntpClient<NativeTlsTransport>>,
    live: Rc<Cell<u32>>,
}

impl Drop for CountedSession {
    fn drop(&mut self) {
        self.live.set(self.live.get() - 1);
    }
}

impl CountedSession {
    fn client(&mut self) -> &mut NntpClient<NativeTlsTransport> {
        self.inner.as_mut().expect("session in use after quit")
    }
}

impl NntpSession for CountedSession {
    async fn post(&mut self, message_id: &str, article: &[u8]) -> Result<PostOutcome> {
        NntpSession::post(self.client(), message_id, article).await
    }
    async fn stat(&mut self, message_id: &str) -> Result<bool> {
        NntpSession::stat(self.client(), message_id).await
    }
    async fn body(&mut self, message_id: &str, out: &mut Vec<u8>) -> Result<BodyOutcome> {
        NntpSession::body(self.client(), message_id, out).await
    }
    async fn quit(mut self) {
        if let Some(client) = self.inner.take() {
            NntpSession::quit(client).await;
        }
    }
}

impl NntpConnector for TcpConnector {
    type Session = CountedSession;

    async fn connect(&self, p: &ProviderConfig, _permit: &Permit) -> Result<CountedSession> {
        let client = dial(&nntp_config(&p.host, p.port, &p.user, &p.pass)).await?;
        self.connects.set(self.connects.get() + 1);
        self.live.set(self.live.get() + 1);
        self.peak.set(self.peak.get().max(self.live.get()));
        Ok(CountedSession {
            inner: Some(client),
            live: Rc::clone(&self.live),
        })
    }
}

// ---------------------------------------------------------------------------
// In-memory catalogue
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct OutboxRow {
    pub generation: GenerationId,
    pub stage: OutboxStage,
    pub attempts: u32,
    pub next_at: UnixMs,
    pub token: u64,
    pub lease_until: Option<UnixMs>,
    pub cursor: u32,
    pub last_error: Option<FailClass>,
}

pub struct Entry {
    pub job: JobExtent,
    pub outbox: OutboxRow,
    pub articles: Vec<ArticleRow>,
    pub verifications: Vec<VerificationRow>,
}

#[derive(Clone, Default)]
struct Slot {
    token: u64,
    until: i64,
}

#[derive(Default)]
pub struct MemCatalog {
    pub entries: RefCell<BTreeMap<ExtentId, Entry>>,
    slots: RefCell<BTreeMap<String, Vec<Slot>>>,
    /// The next `n` `mark_posted` calls fail before writing (a job that
    /// dies between the POST and the catalogue write).
    pub fail_mark_posted: Cell<u32>,
    /// Most permits ever held at once, per provider.
    pub permit_peak: RefCell<BTreeMap<String, u32>>,
    pub permit_refusals: Cell<u32>,
}

impl MemCatalog {
    pub fn insert(&self, job: JobExtent, generation: GenerationId) {
        let outbox = OutboxRow {
            generation,
            stage: OutboxStage::Post,
            attempts: 0,
            next_at: T0,
            token: 0,
            lease_until: None,
            cursor: 0,
            last_error: None,
        };
        self.entries.borrow_mut().insert(
            job.extent.id.clone(),
            Entry {
                job,
                outbox,
                articles: Vec::new(),
                verifications: Vec::new(),
            },
        );
    }

    pub fn outbox(&self, extent: &ExtentId) -> OutboxRow {
        self.entries.borrow()[extent].outbox.clone()
    }

    pub fn extent(&self, extent: &ExtentId) -> ExtentRow {
        self.entries.borrow()[extent].job.extent.clone()
    }

    pub fn verifications(&self, extent: &ExtentId) -> Vec<VerificationRow> {
        self.entries.borrow()[extent].verifications.clone()
    }

    pub fn edit(&self, extent: &ExtentId, f: impl FnOnce(&mut Entry)) {
        f(self.entries.borrow_mut().get_mut(extent).expect("extent"));
    }

    /// Runs `f` on the entry only while the lease still holds.
    fn fenced<R>(&self, l: &Lease, f: impl FnOnce(&mut Entry) -> R) -> Option<R> {
        let mut entries = self.entries.borrow_mut();
        let e = entries.get_mut(&l.extent)?;
        let o = &e.outbox;
        (o.generation == l.generation && o.stage == l.stage && o.token == l.token).then(|| f(e))
    }

    fn statuses(e: &Entry) -> Vec<BackboneStatus> {
        let extent = &e.job.extent;
        let mut latest: BTreeMap<&str, &VerificationRow> = BTreeMap::new();
        for v in e
            .verifications
            .iter()
            .filter(|v| v.plan_rev == extent.plan_rev)
        {
            // Later rows win, including at the same timestamp.
            match latest.get(v.backbone.as_str()) {
                Some(old) if old.verified_at > v.verified_at => {}
                _ => {
                    latest.insert(&v.backbone, v);
                }
            }
        }
        latest
            .values()
            .map(|v| BackboneStatus {
                backbone: v.backbone.clone(),
                provider_id: v.provider_id.clone(),
                verified_at: v.verified_at,
                plan_rev: v.plan_rev,
                articles_ok: v.articles_ok,
                articles_total: v.articles_total,
                result: v.result,
                counts: v.result == VerifyResult::Ok
                    && v.articles_ok == v.articles_total
                    && Some(v.articles_total) == extent.article_count,
            })
            .collect()
    }
}

fn unused<T>() -> Result<T> {
    Err(BridgeError::NotImplemented("not modelled by the stage rig"))
}

impl Catalog for MemCatalog {
    async fn claim(
        &self,
        extent: &ExtentId,
        generation: &GenerationId,
        stage: OutboxStage,
        _owner: &str,
        now: UnixMs,
    ) -> Result<Option<Lease>> {
        let mut entries = self.entries.borrow_mut();
        let Some(e) = entries.get_mut(extent) else {
            return Ok(None);
        };
        let o = &mut e.outbox;
        let free = o.lease_until.is_none_or(|until| until < now);
        if &o.generation != generation || o.stage != stage || o.next_at > now || !free {
            return Ok(None);
        }
        o.token += 1;
        o.attempts += 1;
        o.lease_until = Some(now.plus_secs(LEASE_SECS));
        Ok(Some(Lease {
            extent: extent.clone(),
            generation: generation.clone(),
            stage,
            token: o.token,
            attempts: o.attempts,
            cursor: o.cursor,
        }))
    }

    async fn renew(&self, l: &Lease, now: UnixMs) -> Result<bool> {
        Ok(self
            .fenced(l, |e| {
                e.outbox.lease_until = Some(now.plus_secs(LEASE_SECS))
            })
            .is_some())
    }

    async fn advance(
        &self,
        l: &Lease,
        to: OutboxStage,
        next_at: UnixMs,
        _: UnixMs,
    ) -> Result<bool> {
        Ok(self
            .fenced(l, |e| {
                e.outbox.stage = to;
                e.outbox.next_at = next_at;
                e.outbox.lease_until = None;
            })
            .is_some())
    }

    async fn fail(&self, l: &Lease, class: FailClass, next_at: UnixMs, _: UnixMs) -> Result<bool> {
        Ok(self
            .fenced(l, |e| {
                e.outbox.last_error = Some(class);
                e.outbox.next_at = next_at;
                e.outbox.lease_until = None;
            })
            .is_some())
    }

    async fn set_cursor(&self, l: &Lease, cursor: u32, _: UnixMs) -> Result<bool> {
        Ok(self.fenced(l, |e| e.outbox.cursor = cursor).is_some())
    }

    async fn defer(&self, l: &Lease, next_at: UnixMs, _: UnixMs) -> Result<bool> {
        Ok(self
            .fenced(l, |e| {
                e.outbox.attempts -= 1;
                e.outbox.next_at = next_at;
                e.outbox.lease_until = None;
            })
            .is_some())
    }

    async fn job_extent(&self, extent: &ExtentId, _: &GenerationId) -> Result<Option<JobExtent>> {
        Ok(self.entries.borrow().get(extent).map(|e| e.job.clone()))
    }

    async fn plan_articles(
        &self,
        l: &Lease,
        rows: &[ArticleRow],
    ) -> Result<Option<Vec<ArticleRow>>> {
        Ok(self.fenced(l, |e| {
            if e.articles.is_empty() {
                e.articles = rows.to_vec();
                e.job.extent.article_count = Some(rows.len() as u32);
                e.job.extent.plan_rev = 1;
            }
            e.articles.clone()
        }))
    }

    async fn articles(&self, extent: &ExtentId) -> Result<Vec<ArticleRow>> {
        let entries = self.entries.borrow();
        Ok(entries
            .get(extent)
            .map(|e| e.articles.clone())
            .unwrap_or_default())
    }

    async fn mark_posted(&self, l: &Lease, idx: u32, provider: &str, now: UnixMs) -> Result<bool> {
        if self.fail_mark_posted.get() > 0 {
            self.fail_mark_posted.set(self.fail_mark_posted.get() - 1);
            return Err(BridgeError::Sql("injected mark_posted failure".into()));
        }
        Ok(self
            .fenced(l, |e| {
                let a = &mut e.articles[idx as usize];
                a.state = ArticleState::Posted;
                a.provider_id = Some(provider.to_string());
                a.posted_at = Some(now);
            })
            .is_some())
    }

    async fn record_verification(&self, l: &Lease, v: &VerificationRow) -> Result<bool> {
        Ok(self
            .fenced(l, |e| {
                e.verifications.push(v.clone());
                if v.result == VerifyResult::Ok {
                    e.job.extent.last_verified_at = Some(v.verified_at);
                }
            })
            .is_some())
    }

    async fn backbone_status(&self, extent: &ExtentId) -> Result<Vec<BackboneStatus>> {
        let entries = self.entries.borrow();
        Ok(entries.get(extent).map(Self::statuses).unwrap_or_default())
    }

    async fn begin_release(
        &self,
        l: &Lease,
        required: u32,
        evidence_json: &str,
        _: UnixMs,
    ) -> Result<Guard<()>> {
        let applied = self.fenced(l, |e| {
            let counting = Self::statuses(e).iter().filter(|s| s.counts).count();
            if counting < required as usize {
                return false;
            }
            e.job.extent.safety_state = SafetyState::Releasing;
            e.job.extent.release_evidence = Some(evidence_json.to_string());
            true
        });
        Ok(if applied == Some(true) {
            Guard::Applied(())
        } else {
            Guard::Lost
        })
    }

    async fn finish_release(&self, l: &Lease, now: UnixMs) -> Result<bool> {
        Ok(self
            .fenced(l, |e| {
                e.job.extent.safety_state = SafetyState::Released;
                e.job.extent.released_at = Some(now);
                e.outbox.stage = OutboxStage::Done;
                e.outbox.lease_until = None;
            })
            .is_some())
    }

    async fn seed_permits(&self, providers: &[ProviderConfig]) -> Result<()> {
        let mut slots = self.slots.borrow_mut();
        for p in providers {
            slots
                .entry(p.id.clone())
                .or_insert_with(|| vec![Slot::default(); p.max_conns as usize]);
        }
        Ok(())
    }

    async fn acquire_permit(
        &self,
        p: &ProviderConfig,
        class: PermitClass,
        _holder: &str,
        now: UnixMs,
    ) -> Result<Option<Permit>> {
        self.seed_permits(core::slice::from_ref(p)).await?;
        let reserve = u32::from(p.max_conns >= 2);
        let limit = match class {
            PermitClass::Background => p.max_conns - reserve,
            PermitClass::Read => p.max_conns,
        };
        let mut slots = self.slots.borrow_mut();
        let slots = slots.get_mut(&p.id).expect("seeded");
        let free = (0..limit as usize).find(|&i| slots[i].until < now.0);
        let Some(i) = free else {
            self.permit_refusals.set(self.permit_refusals.get() + 1);
            return Ok(None);
        };
        slots[i].token += 1;
        slots[i].until = now.plus_secs(PERMIT_SECS).0;
        let held = slots.iter().filter(|s| s.until >= now.0).count() as u32;
        let mut peak = self.permit_peak.borrow_mut();
        let peak = peak.entry(p.id.clone()).or_default();
        *peak = (*peak).max(held);
        Ok(Some(Permit {
            provider: p.id.clone(),
            slot: i as u32,
            token: slots[i].token,
        }))
    }

    async fn renew_permit(&self, p: &Permit, now: UnixMs) -> Result<bool> {
        let mut slots = self.slots.borrow_mut();
        let slot = &mut slots.get_mut(&p.provider).expect("seeded")[p.slot as usize];
        if slot.token != p.token {
            return Ok(false);
        }
        slot.until = now.plus_secs(PERMIT_SECS).0;
        Ok(true)
    }

    async fn release_permit(&self, p: &Permit) -> Result<()> {
        let mut slots = self.slots.borrow_mut();
        let slot = &mut slots.get_mut(&p.provider).expect("seeded")[p.slot as usize];
        if slot.token == p.token {
            slot.until = 0;
        }
        Ok(())
    }

    // Not used by the post, verify, release or cold-read paths.
    async fn create_bucket(&self, _: &Bucket) -> Result<Guard<()>> {
        unused()
    }
    async fn create_access_key(&self, _: &AccessKeyRow) -> Result<()> {
        unused()
    }
    async fn put_grant(&self, _: &str, _: &BucketId, _: Perm) -> Result<()> {
        unused()
    }
    async fn bucket_by_name(&self, _: &str) -> Result<Option<Bucket>> {
        unused()
    }
    async fn buckets_for(&self, _: &str) -> Result<Vec<Bucket>> {
        unused()
    }
    async fn access_key(&self, _: &str) -> Result<Option<AccessKeyRow>> {
        unused()
    }
    async fn grant(&self, _: &str, _: &BucketId) -> Result<Option<Perm>> {
        unused()
    }
    async fn live_object(
        &self,
        _: &BucketId,
        _: &str,
    ) -> Result<Option<(GenerationRow, Vec<ExtentRow>)>> {
        unused()
    }
    async fn commit_generation(&self, _: &CommitGeneration) -> Result<()> {
        unused()
    }
    async fn delete_object(&self, _: &BucketId, _: &str, _: UnixMs) -> Result<()> {
        unused()
    }
    async fn list(&self, _: &BucketId, _: &ListQuery) -> Result<ListPage> {
        unused()
    }
    async fn object_status(&self, _: &BucketId, _: &str) -> Result<Option<ObjectStatus>> {
        unused()
    }
    async fn set_safety_state(&self, _: &ExtentId, _: SafetyState, _: SafetyState) -> Result<bool> {
        unused()
    }
    async fn create_upload(&self, _: &UploadRow) -> Result<()> {
        unused()
    }
    async fn upload(
        &self,
        _: &UploadTarget<'_>,
    ) -> Result<Option<(UploadRow, Vec<UploadPartRow>)>> {
        unused()
    }
    async fn put_upload_part(
        &self,
        _: &UploadTarget<'_>,
        _: &UploadPartRow,
        _: &ExtentRow,
        _: UnixMs,
    ) -> Result<Guard<()>> {
        unused()
    }
    async fn complete_upload(
        &self,
        _: &UploadTarget<'_>,
        _: u64,
        _: &[u8; 32],
        _: &CompleteUpload,
    ) -> Result<Guard<()>> {
        unused()
    }
    async fn abort_upload(&self, _: &UploadTarget<'_>, _: UnixMs) -> Result<Guard<()>> {
        unused()
    }
    async fn due(&self, _: UnixMs, _: u32) -> Result<Vec<DueRow>> {
        unused()
    }
    async fn bury_exhausted(&self, _: u32, _: UnixMs) -> Result<u64> {
        unused()
    }
    async fn record_dispatch(&self, _: UnixMs) -> Result<()> {
        unused()
    }
    async fn outbox_stats(&self) -> Result<OutboxStats> {
        unused()
    }
    async fn guard_selftest(&self) -> Result<bool> {
        unused()
    }
    async fn gc_due(&self, _: UnixMs, _: u32, _: bool) -> Result<Vec<GcRow>> {
        unused()
    }
    async fn gc_begin(&self, _: &GcRow, _: UnixMs) -> Result<GcStep> {
        unused()
    }
    async fn gc_done(&self, _: i64, _: UnixMs) -> Result<()> {
        unused()
    }
}

// ---------------------------------------------------------------------------
// Rig
// ---------------------------------------------------------------------------

pub type TestBridge = Bridge<MemCatalog, MemBlobStore, TcpConnector, FakeJobs, TestKek, FixedClock>;

/// One fake provider: its own server (its own spool) and backbone name.
pub struct Spec {
    pub backbone: &'static str,
    pub post: bool,
    pub max_conns: u32,
}

pub struct Rig {
    /// One server per provider, in provider order (`p0`, `p1`, …).
    pub servers: Vec<TestNntpServer>,
    pub bridge: TestBridge,
}

/// A recognisable plaintext: any leak into an article is easy to find.
pub const MARKER: &[u8] = b"PLAINTEXT-MARKER";

/// A bucket name that cannot appear in an article by chance.
pub const BUCKET_NAME: &str = "private-bucket-name";

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn marked_plaintext(len: usize) -> Vec<u8> {
    MARKER.iter().copied().cycle().take(len).collect()
}

pub async fn rig(specs: &[Spec]) -> Rig {
    let mut servers = Vec::new();
    let mut providers = Vec::new();
    for (i, spec) in specs.iter().enumerate() {
        let mut config = ServerConfig::for_test();
        config.articles = Vec::new();
        config.missing_ids.clear();
        config.users.insert(
            USER.to_string(),
            UserConfig {
                password: PASS.to_string(),
                max_connections: spec.max_conns as usize,
            },
        );
        let server = TestNntpServer::spawn(config).await;
        providers.push(ProviderConfig {
            id: format!("p{i}"),
            host: server.addr().ip().to_string(),
            port: server.addr().port(),
            tls: false,
            user: USER.to_string(),
            pass: PASS.to_string(),
            backbone: spec.backbone.to_string(),
            post: spec.post,
            read: true,
            max_conns: spec.max_conns,
        });
        servers.push(server);
    }
    let cfg = BridgeConfig {
        environment: Environment::Dev,
        s3_host: "s3.test".to_string(),
        region: "auto".to_string(),
        max_extent_bytes: 16 * 1024 * 1024,
        required_backbones: 1,
        safety_min_age_secs: 0,
        verify_delay_secs: 30,
        newsgroups: vec!["alt.binaries.test".to_string()],
        kek_active: 1,
        inflight_budget_bytes: 48 * 1024 * 1024,
        gc_mode: GcMode::Disposable,
        maintenance: Maintenance::Off,
        dev_trust_http: false,
        providers,
        admin_token: Secret::new("admin-token-fixture-admin-token-fixture".to_string()),
    };
    let bridge = Bridge {
        catalog: MemCatalog::default(),
        safety: MemBlobStore::new(),
        cache: MemBlobStore::new(),
        nntp: TcpConnector::default(),
        jobs: FakeJobs::new(),
        kek: TestKek::new(),
        clock: FixedClock::new(T0),
        budget: ByteBudget::new(48 * 1024 * 1024),
        cfg,
    };
    Rig { servers, bridge }
}

/// A single provider that posts and reads, two connections.
pub async fn simple_rig() -> Rig {
    rig(&[Spec {
        backbone: "bb0",
        post: true,
        max_conns: 2,
    }])
    .await
}

/// A seeded extent: its ids and the sealed ciphertext held in the safety
/// store.
pub struct Seeded {
    pub extent: ExtentId,
    pub generation: GenerationId,
    pub cipher: Vec<u8>,
}

impl Rig {
    pub fn server(&self) -> &TestNntpServer {
        &self.servers[0]
    }

    /// Seals `plain` as one media stream, stores it in the safety store and
    /// adds the extent with an outbox row at the post stage.
    pub async fn seed(&self, n: u8, plain: &[u8]) -> Seeded {
        let key = FileKey::generate(&mut SystemRng).unwrap();
        let sealer = Sealer::random(&Profile::drive(), &key, &mut SystemRng).unwrap();
        let cipher = sealer.seal_to_vec(plain).unwrap();
        let bucket = Bucket {
            id: BucketId::mint([7; 8]),
            name: BUCKET_NAME.to_string(),
            owner: "owner".to_string(),
            bdk_wrapped: vec![0; 73],
            kek_version: 1,
            disposable: true,
            created_at: T0,
        };
        let generation = GenerationId::mint(T0, [n; 8]);
        let extent = ExtentRow {
            id: ExtentId::mint([n; 13]),
            bucket_id: bucket.id.clone(),
            generation_id: Some(generation.clone()),
            state: ExtentState::Committed,
            seq: Some(0),
            plain_offset: Some(0),
            plain_size: plain.len() as u64,
            cipher_size: cipher.len() as u64,
            media_header: cipher[..48].to_vec(),
            key_mode: 1,
            wrapped_file_key: Some(vec![0; 73]),
            plain_md5: sha256(plain)[..16].try_into().unwrap(),
            plain_sha256: sha256(plain),
            cipher_sha256: sha256(&cipher),
            safety_state: SafetyState::Held,
            article_count: None,
            plan_rev: 0,
            last_verified_at: None,
            release_evidence: None,
            released_at: None,
            created_at: T0,
        };
        let meta = BlobMeta {
            bucket: &bucket.id,
            extent: &extent.id,
            cipher_sha256: &extent.cipher_sha256,
        };
        self.bridge
            .safety
            .put(&extent.id.safety_key(), cipher.clone(), &meta)
            .await
            .unwrap();
        let id = extent.id.clone();
        self.bridge.catalog.insert(
            JobExtent {
                extent,
                bucket,
                generation_state: GenerationState::Live,
            },
            generation.clone(),
        );
        Seeded {
            extent: id,
            generation,
            cipher,
        }
    }

    pub async fn try_claim(&self, s: &Seeded, stage: OutboxStage) -> Option<Lease> {
        let now = self.bridge.clock.now();
        self.bridge
            .catalog
            .claim(&s.extent, &s.generation, stage, "test", now)
            .await
            .unwrap()
    }

    pub async fn claim(&self, s: &Seeded, stage: OutboxStage) -> Lease {
        self.try_claim(s, stage).await.expect("row is claimable")
    }

    pub async fn job(&self, s: &Seeded) -> JobExtent {
        let job = self
            .bridge
            .catalog
            .job_extent(&s.extent, &s.generation)
            .await;
        job.unwrap().expect("extent")
    }

    /// Claims the post stage and runs it once.
    pub async fn run_post(&self, s: &Seeded) -> JobOutcome {
        let lease = self.claim(s, OutboxStage::Post).await;
        let job = self.job(s).await;
        self.bridge.post_stage(&lease, &job).await
    }

    pub async fn plan(&self, s: &Seeded) -> Vec<ArticleRow> {
        self.bridge.catalog.articles(&s.extent).await.unwrap()
    }

    /// A direct client on server `i`, outside the permit gate (a second
    /// login, so it never competes for the provider's connection cap).
    pub async fn raw_client(&self, i: usize) -> NntpClient<NativeTlsTransport> {
        let addr = self.servers[i].addr();
        dial(&nntp_config(
            &addr.ip().to_string(),
            addr.port(),
            "otheruser",
            "otherpass",
        ))
        .await
        .unwrap()
    }
}
