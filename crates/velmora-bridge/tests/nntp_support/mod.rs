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
use velmora::article::assemble_article;
use velmora::media::{FileKey, Profile, Sealer};
use velmora::nntp::{NntpClient, NntpConfig, PostOutcome};
use velmora::rng::SystemRng;
use velmora::transports::NativeTlsTransport;
use velmora::yenc::{encode_segment, SegmentParams};
use velmora_bridge::config::{Environment, GcMode, Maintenance};
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::testkit::{FakeJobs, FixedClock, MemBlobStore, TestKek};
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

pub const T0: UnixMs = UnixMs(1_800_000_000_000);
pub use velmora_bridge::LEASE_SECS;
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
    slow: Rc<RefCell<Option<Slow>>>,
    park: Rc<RefCell<Option<Rc<Cell<bool>>>>>,
}

/// Calls that take time on the test clock, and when each one started.
struct Slow {
    clock: FixedClock,
    ms: i64,
    calls: Vec<(&'static str, UnixMs)>,
}

fn begin(slow: &RefCell<Option<Slow>>, what: &'static str) {
    if let Some(slow) = slow.borrow_mut().as_mut() {
        slow.calls.push((what, slow.clock.now()));
    }
}

fn end(slow: &RefCell<Option<Slow>>) {
    if let Some(slow) = slow.borrow().as_ref() {
        slow.clock.advance_ms(slow.ms);
    }
}

impl TcpConnector {
    /// From now on every connect, lookup, read and POST takes `ms` on
    /// `clock`.
    pub fn slow(&self, clock: &FixedClock, ms: i64) {
        *self.slow.borrow_mut() = Some(Slow {
            clock: clock.clone(),
            ms,
            calls: Vec::new(),
        });
    }
    /// The next POST to be answered does not return to the job until the
    /// flag is set: the call stays in flight for as long as a test wants.
    pub fn park_next_post(&self) -> Rc<Cell<bool>> {
        let release = Rc::new(Cell::new(false));
        *self.park.borrow_mut() = Some(Rc::clone(&release));
        release
    }
    /// The slow calls so far: what, and the time each started.
    pub fn calls(&self) -> Vec<(&'static str, UnixMs)> {
        let slow = self.slow.borrow();
        slow.as_ref().map(|s| s.calls.clone()).unwrap_or_default()
    }
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
    slow: Rc<RefCell<Option<Slow>>>,
    park: Rc<RefCell<Option<Rc<Cell<bool>>>>>,
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
        begin(&self.slow, "post");
        let posted = NntpSession::post(self.client(), message_id, article).await;
        let parked = self.park.borrow_mut().take();
        if let Some(release) = parked {
            while !release.get() {
                tokio::task::yield_now().await;
            }
        }
        end(&self.slow);
        posted
    }
    async fn stat(&mut self, message_id: &str) -> Result<bool> {
        begin(&self.slow, "stat");
        let found = NntpSession::stat(self.client(), message_id).await;
        end(&self.slow);
        found
    }
    async fn body(&mut self, message_id: &str, out: &mut Vec<u8>) -> Result<BodyOutcome> {
        begin(&self.slow, "body");
        let found = NntpSession::body(self.client(), message_id, out).await;
        end(&self.slow);
        found
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
        begin(&self.slow, "connect");
        let client = dial(&nntp_config(&p.host, p.port, &p.user, &p.pass)).await;
        end(&self.slow);
        let client = client?;
        self.connects.set(self.connects.get() + 1);
        self.live.set(self.live.get() + 1);
        self.peak.set(self.peak.get().max(self.live.get()));
        Ok(CountedSession {
            inner: Some(client),
            live: Rc::clone(&self.live),
            slow: Rc::clone(&self.slow),
            park: Rc::clone(&self.park),
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
    /// The pool the slot was last taken under.
    pool: Option<String>,
    /// Who took the slot last.
    holder: String,
    /// Whether a background job took it.
    background: bool,
}

/// A provider's strikes, as `provider_health` keeps them.
#[derive(Clone, Copy, Default)]
struct Health {
    failures: u32,
    cooldowns: u32,
    until: i64,
}

/// A takeover injected at the catalogue write that marks one article
/// index posted (alone or in a batch).
#[derive(Clone, Copy, Debug)]
pub enum Fault {
    /// Another job takes the lease before the write: the write is fenced.
    StealLeaseBefore(u32),
    /// Another job takes the lease right after the write.
    StealLeaseAfter(u32),
    /// The permit slot is taken over right after the write.
    RevokePermitAfter(u32),
}

#[derive(Default)]
pub struct MemCatalog {
    pub entries: RefCell<BTreeMap<ExtentId, Entry>>,
    slots: RefCell<BTreeMap<String, Vec<Slot>>>,
    health: RefCell<BTreeMap<String, Health>>,
    /// The next `n` `mark_posted` calls fail before writing (a job that
    /// dies between the POST and the catalogue write).
    pub fail_mark_posted: Cell<u32>,
    pub fault: Cell<Option<Fault>>,
    /// `renew_all` calls so far (one per renewal tick of a post job).
    pub renewals: Cell<u32>,
    /// The time of each `renew_all`.
    pub renewed_at: RefCell<Vec<UnixMs>>,
    /// Permit renewals never come back.
    pub renew_hangs: Cell<bool>,
    /// Every permit renewal takes this long on the clock.
    pub renew_takes: RefCell<Option<(FixedClock, i64)>>,
    /// The time of each permit renewal that held.
    pub permit_renewed_at: RefCell<Vec<UnixMs>>,
    /// `mark_posted_many` calls so far.
    pub mark_batches: Cell<u32>,
    /// Most permits ever held at once, per provider.
    pub permit_peak: RefCell<BTreeMap<String, u32>>,
    /// Most holders ever live at once, per provider.
    pub holder_peak: RefCell<BTreeMap<String, u32>>,
    /// Every slot handed out: the provider and the holder's name.
    pub granted: RefCell<Vec<(String, String)>>,
    pub permit_refusals: Cell<u32>,
    /// Permits another holder gives back right after the next refusal.
    pub free_after_refusal: RefCell<Vec<Permit>>,
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

    /// Every held slot passes to someone else: its holder's permit is dead.
    pub fn revoke_permits(&self) {
        for slot in self.slots.borrow_mut().values_mut().flatten() {
            slot.token += 1;
            slot.holder = "someone else".into();
        }
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
        let fault = self.fault.get();
        let steal = |e: &mut Entry| {
            e.outbox.token += 1;
            e.outbox.lease_until = Some(now.plus_secs(LEASE_SECS));
        };
        if matches!(fault, Some(Fault::StealLeaseBefore(i)) if i == idx) {
            self.fault.set(None);
            self.edit(&l.extent, steal);
        }
        let written = self
            .fenced(l, |e| {
                let a = &mut e.articles[idx as usize];
                a.state = ArticleState::Posted;
                a.provider_id = Some(provider.to_string());
                a.posted_at = Some(now);
            })
            .is_some();
        match fault {
            Some(Fault::StealLeaseAfter(i)) if i == idx => {
                self.fault.set(None);
                self.edit(&l.extent, steal);
            }
            Some(Fault::RevokePermitAfter(i)) if i == idx => {
                self.fault.set(None);
                for slot in self.slots.borrow_mut().values_mut().flatten() {
                    slot.token += 1;
                }
            }
            _ => {}
        }
        Ok(written)
    }

    async fn record_verification(&self, l: &Lease, v: &VerificationRow) -> Result<bool> {
        // One row per extent, backbone and instant, as in the real table.
        let stored = self.fenced(l, |e| {
            let taken =
                |o: &VerificationRow| o.backbone == v.backbone && o.verified_at == v.verified_at;
            if e.verifications.iter().any(taken) {
                return false;
            }
            e.verifications.push(v.clone());
            if v.result == VerifyResult::Ok {
                e.job.extent.last_verified_at = Some(v.verified_at);
            }
            true
        });
        match stored {
            Some(false) => Err(BridgeError::Sql("duplicate verification row".into())),
            other => Ok(other.is_some()),
        }
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

    // The hot tier is tested on the SQL catalogue; here nothing is ever
    // evictable.
    async fn hot_stats(&self) -> Result<HotStats> {
        Ok(HotStats::default())
    }
    async fn evictable_bytes(&self) -> Result<u64> {
        Ok(0)
    }
    async fn evict_candidates(&self, _: u32) -> Result<Vec<EvictCandidate>> {
        Ok(Vec::new())
    }
    async fn begin_evict(&self, _: &EvictCandidate) -> Result<bool> {
        Ok(false)
    }
    async fn finish_evict(&self, _: &EvictCandidate) -> Result<bool> {
        Ok(false)
    }
    async fn record_cache_fill(&self, _: &ExtentId, _: UnixMs) -> Result<()> {
        Ok(())
    }
    async fn touch_read(&self, _: &ExtentId, now: UnixMs, _: i64, _: bool) -> Result<UnixMs> {
        Ok(now)
    }
    async fn hot_check_due(&self, _: UnixMs, _: i64) -> Result<bool> {
        Ok(false)
    }
    async fn hot_checked(&self, _: UnixMs) -> Result<()> {
        Ok(())
    }
    async fn hot_drain_set(&self, _: u64) -> Result<()> {
        Ok(())
    }
    async fn hot_drain_claim(&self, _: u64) -> Result<bool> {
        Ok(false)
    }
    async fn hot_seq(&self, _: &ExtentId) -> Result<u64> {
        Ok(0)
    }
    async fn hot_forget(&self, _: &ExtentId, _: u64, _: bool, _: bool) -> Result<bool> {
        Ok(true)
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
        holder: &str,
        now: UnixMs,
    ) -> Result<Option<Permit>> {
        self.seed_permits(core::slice::from_ref(p)).await?;
        let background = class == PermitClass::Background;
        let limit = |max: u32| max - u32::from(background && max >= 2);
        let conns = match class {
            PermitClass::Background => p.background_conns(),
            PermitClass::Read => p.max_conns,
        };
        let mut all = self.slots.borrow_mut();
        // Held slots of the whole pool count against its shared limit.
        let pool_full = match (&p.pool, p.pool_max_conns) {
            (Some(pool), Some(max)) => {
                let held = all
                    .values()
                    .flatten()
                    .filter(|s| s.pool.as_ref() == Some(pool) && s.until >= now.0)
                    .count();
                held >= limit(max) as usize
            }
            _ => false,
        };
        let slots = all.get_mut(&p.id).expect("seeded");
        // As in `sql::permits`: expired slots are freed first, a holder
        // with a live slot adds no address, and background holders have
        // a limit of their own.
        if p.max_ips.is_some() {
            for slot in slots.iter_mut().filter(|s| s.until < now.0) {
                slot.until = 0;
            }
        }
        let holders = |jobs_only: bool| -> std::collections::BTreeSet<&str> {
            slots
                .iter()
                .filter(|s| s.until >= now.0 && (s.background || !jobs_only))
                .map(|s| s.holder.as_str())
                .collect()
        };
        let (live, jobs) = (holders(false), holders(true));
        let address =
            live.contains(holder) || p.max_ips.is_none_or(|max| live.len() < max as usize);
        let job_address = !background
            || jobs.contains(holder)
            || p.background_ips()
                .is_none_or(|max| jobs.len() < max as usize);
        let no_address = !(address && job_address);
        let free = (0..conns as usize).find(|&i| slots[i].until < now.0);
        let Some(i) = free.filter(|_| !pool_full && !no_address) else {
            self.permit_refusals.set(self.permit_refusals.get() + 1);
            for freed in self.free_after_refusal.borrow_mut().drain(..) {
                let slot = &mut all.get_mut(&freed.provider).expect("seeded")[freed.slot as usize];
                if slot.token == freed.token {
                    slot.until = 0;
                }
            }
            return Ok(None);
        };
        slots[i].token += 1;
        slots[i].until = now.plus_secs(class.permit_secs()).0;
        slots[i].pool.clone_from(&p.pool);
        slots[i].holder = holder.to_string();
        slots[i].background = background;
        self.granted
            .borrow_mut()
            .push((p.id.clone(), holder.to_string()));
        let held = slots.iter().filter(|s| s.until >= now.0).count() as u32;
        let mut peak = self.permit_peak.borrow_mut();
        let peak = peak.entry(p.id.clone()).or_default();
        *peak = (*peak).max(held);
        let holders: std::collections::BTreeSet<&str> = slots
            .iter()
            .filter(|s| s.until >= now.0)
            .map(|s| s.holder.as_str())
            .collect();
        let mut peak = self.holder_peak.borrow_mut();
        let peak = peak.entry(p.id.clone()).or_default();
        *peak = (*peak).max(holders.len() as u32);
        Ok(Some(Permit {
            provider: p.id.clone(),
            slot: i as u32,
            token: slots[i].token,
            class,
        }))
    }

    async fn mark_posted_many(
        &self,
        l: &Lease,
        posted: &[(u32, &str)],
        now: UnixMs,
    ) -> Result<bool> {
        self.mark_batches.set(self.mark_batches.get() + 1);
        if self.fail_mark_posted.get() > 0 {
            self.fail_mark_posted.set(self.fail_mark_posted.get() - 1);
            return Err(BridgeError::Sql("injected mark_posted failure".into()));
        }
        let fault = self.fault.get();
        let has = |i: u32| posted.iter().any(|(idx, _)| *idx == i);
        let steal = |e: &mut Entry| {
            e.outbox.token += 1;
            e.outbox.lease_until = Some(now.plus_secs(LEASE_SECS));
        };
        if matches!(fault, Some(Fault::StealLeaseBefore(i)) if has(i)) {
            self.fault.set(None);
            self.edit(&l.extent, steal);
        }
        // All or nothing, like the fenced SQL batch.
        let written = self
            .fenced(l, |e| {
                for (idx, provider) in posted {
                    let a = &mut e.articles[*idx as usize];
                    a.state = ArticleState::Posted;
                    a.provider_id = Some(provider.to_string());
                    a.posted_at = Some(now);
                }
            })
            .is_some();
        match fault {
            Some(Fault::StealLeaseAfter(i)) if has(i) => {
                self.fault.set(None);
                self.edit(&l.extent, steal);
            }
            Some(Fault::RevokePermitAfter(i)) if has(i) => {
                self.fault.set(None);
                for slot in self.slots.borrow_mut().values_mut().flatten() {
                    slot.token += 1;
                }
            }
            _ => {}
        }
        Ok(written)
    }

    async fn renew_all(
        &self,
        l: &Lease,
        permits: &[Permit],
        now: UnixMs,
    ) -> Result<(bool, Vec<bool>)> {
        self.renewals.set(self.renewals.get() + 1);
        self.renewed_at.borrow_mut().push(now);
        let lease = self.renew(l, now).await?;
        let mut held = Vec::new();
        for p in permits {
            held.push(self.renew_permit(p, now).await?);
        }
        Ok((lease, held))
    }

    async fn renew_permit(&self, p: &Permit, now: UnixMs) -> Result<bool> {
        if self.renew_hangs.get() {
            std::future::pending::<()>().await;
        }
        let mut slots = self.slots.borrow_mut();
        let slot = &mut slots.get_mut(&p.provider).expect("seeded")[p.slot as usize];
        // A freed or expired slot is not extended, as in `sql::permits`.
        if slot.token != p.token || slot.until < now.0 {
            return Ok(false);
        }
        self.permit_renewed_at.borrow_mut().push(now);
        if let Some((clock, ms)) = self.renew_takes.borrow().as_ref() {
            clock.advance_ms(*ms);
        }
        // By the class the slot was taken for, as in `sql::permits`.
        let class = match slot.background {
            true => PermitClass::Background,
            false => PermitClass::Read,
        };
        slot.until = now.plus_secs(class.permit_secs()).0;
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
    async fn copy_generation(&self, _: &velmora_bridge::CopyGeneration) -> Result<Guard<()>> {
        unused()
    }
    async fn delete_object(&self, _: &BucketId, _: &str, _: UnixMs) -> Result<()> {
        unused()
    }
    async fn delete_object_before(
        &self,
        _: &BucketId,
        _: &str,
        _: &GenerationId,
        _: UnixMs,
    ) -> Result<bool> {
        unused()
    }
    async fn upload_extents(&self, _: &UploadTarget<'_>) -> Result<Vec<ExtentRow>> {
        unused()
    }
    async fn replay_probe(&self, _: &GenerationRow) -> Result<velmora_bridge::replay::ReplayProbe> {
        unused()
    }
    async fn replay_extents(
        &self,
        _: &Bucket,
        _: &[velmora_bridge::replay::ReplayExtent],
        _: UnixMs,
    ) -> Result<()> {
        unused()
    }
    async fn replay_damaged(&self, _: u32) -> Result<(u64, Vec<GenerationId>)> {
        unused()
    }
    async fn replay_publish(
        &self,
        _: &GenerationRow,
        _: &[velmora_bridge::ExtentPlacement],
        _: UnixMs,
    ) -> Result<Guard<()>> {
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
    async fn provider_load(&self, now: UnixMs) -> Result<Vec<ProviderLoad>> {
        let slots = self.slots.borrow();
        let health = self.health.borrow();
        let ids: std::collections::BTreeSet<&String> = slots.keys().chain(health.keys()).collect();
        Ok(ids
            .into_iter()
            .map(|id| {
                let s = slots.get(id).map(Vec::as_slice).unwrap_or_default();
                let h = health.get(id).copied().unwrap_or_default();
                ProviderLoad {
                    provider_id: id.clone(),
                    held: s.iter().filter(|s| s.until >= now.0).count() as u32,
                    holders: s
                        .iter()
                        .filter(|s| s.until >= now.0)
                        .map(|s| s.holder.as_str())
                        .collect::<std::collections::BTreeSet<_>>()
                        .len() as u32,
                    background_holders: s
                        .iter()
                        .filter(|s| s.until >= now.0 && s.background)
                        .map(|s| s.holder.as_str())
                        .collect::<std::collections::BTreeSet<_>>()
                        .len() as u32,
                    uses: s.iter().map(|s| s.token).sum(),
                    failures: h.failures,
                    cooldowns: h.cooldowns,
                    cooldown_until: UnixMs(h.until),
                }
            })
            .collect())
    }

    async fn provider_failed(&self, provider: &str, now: UnixMs) -> Result<()> {
        let mut health = self.health.borrow_mut();
        let h = health.entry(provider.to_string()).or_default();
        if h.until > now.0 {
            return Ok(());
        }
        if h.failures + 1 >= 3 || h.cooldowns > 0 {
            h.until = now.0 + (60_000i64 << h.cooldowns).min(900_000);
            h.cooldowns = (h.cooldowns + 1).min(4);
            h.failures = 0;
        } else {
            h.failures += 1;
        }
        Ok(())
    }

    async fn provider_recovered(&self, provider: &str, now: UnixMs) -> Result<()> {
        if let Some(h) = self.health.borrow_mut().get_mut(provider) {
            if h.until <= now.0 {
                *h = Health::default();
            }
        }
        Ok(())
    }

    async fn redrive_underverified(&self, _: &[String], _: u32, _: u32, _: UnixMs) -> Result<u64> {
        unused()
    }
    async fn revive_referenced(&self, _: u32, _: UnixMs) -> Result<u64> {
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
            max_ips: None,
            priority: 0,
            retention_days: None,
            pool: None,
            pool_max_conns: None,
            enabled: true,
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
        post_sockets: 4,
        propagation_grace_secs: 21_600,
        newsgroups: vec!["alt.binaries.test".to_string()],
        kek_active: 1,
        inflight_budget_bytes: 48 * 1024 * 1024,
        gc_mode: GcMode::Disposable,
        hot_cap_bytes: velmora_bridge::config::DEFAULT_HOT_CAP_BYTES,
        maintenance: Maintenance::Off,
        server_side_copy: true,
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

/// A well-formed article for `row` under its stored headers. With `flip`
/// one payload bit is wrong: the yEnc checksum still matches, the planned
/// SHA-256 does not.
pub fn render(plan: &[ArticleRow], row: &ArticleRow, cipher: &[u8], flip: bool) -> Vec<u8> {
    let start = row.cipher_offset as usize;
    let mut payload = cipher[start..start + row.cipher_len as usize].to_vec();
    if flip {
        payload[10] ^= 1;
    }
    let params = SegmentParams {
        name: "planted".to_string(),
        part: row.idx + 1,
        total: plan.len() as u32,
        begin: row.cipher_offset + 1,
        end: row.cipher_offset + row.cipher_len,
        file_size: cipher.len() as u64,
    };
    let mut body = Vec::new();
    encode_segment(&mut body, &params, &payload).unwrap();
    assemble_article(&row.headers, &body).unwrap()
}

/// Two backbones: `p0` posts and reads, `p1` only reads.
pub async fn two_backbone_rig() -> Rig {
    let mut rig = rig(&[
        Spec {
            backbone: "bb0",
            post: true,
            max_conns: 2,
        },
        Spec {
            backbone: "bb1",
            post: false,
            max_conns: 2,
        },
    ])
    .await;
    rig.bridge.cfg.required_backbones = 2;
    rig
}

/// Two providers on the same backbone: one copy, however many accounts.
pub async fn shared_backbone_rig() -> Rig {
    let mut rig = rig(&[
        Spec {
            backbone: "bb0",
            post: true,
            max_conns: 2,
        },
        Spec {
            backbone: "bb0",
            post: false,
            max_conns: 2,
        },
    ])
    .await;
    rig.bridge.cfg.required_backbones = 2;
    rig
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

    /// Claims the post stage and runs it; as soon as server `server`
    /// holds `stored` articles, `then` runs in the middle of the job.
    pub async fn run_post_and(
        &self,
        s: &Seeded,
        server: usize,
        stored: usize,
        then: impl AsyncFnOnce(),
    ) -> JobOutcome {
        let lease = self.claim(s, OutboxStage::Post).await;
        let job = self.job(s).await;
        // A job that ends before `stored` articles are there is returned
        // as it is: `then` does not run and nothing waits for ever.
        let done = Cell::new(false);
        let post = async {
            let outcome = self.bridge.post_stage(&lease, &job).await;
            done.set(true);
            outcome
        };
        let mid = async {
            // Bounded: a job that neither ends nor stores `stored`
            // articles fails the test instead of hanging it.
            let started = std::time::Instant::now();
            while self.servers[server].posted_count().await < stored {
                if done.get() {
                    return;
                }
                assert!(
                    started.elapsed().as_secs() < 120,
                    "the job neither ended nor stored {stored} articles"
                );
                tokio::task::yield_now().await;
            }
            then().await;
        };
        tokio::join!(post, mid).0
    }

    /// Claims `stage` and runs it once.
    pub async fn run(&self, s: &Seeded, stage: OutboxStage) -> JobOutcome {
        let lease = self.claim(s, stage).await;
        let job = self.job(s).await;
        match stage {
            OutboxStage::Post => self.bridge.post_stage(&lease, &job).await,
            OutboxStage::Verify => self.bridge.verify_stage(&lease, &job).await,
            OutboxStage::Release => self.bridge.release_stage(&lease, &job).await,
            other => panic!("no stage function for {other:?}"),
        }
    }

    /// Posts the extent and moves the clock to the start of verification.
    pub async fn post(&self, s: &Seeded) -> Vec<ArticleRow> {
        assert_eq!(self.run_post(s).await, JobOutcome::Ack);
        self.bridge
            .clock
            .advance_secs(self.bridge.cfg.verify_delay_secs);
        self.bridge.jobs.take();
        self.plan(s).await
    }

    /// Plans the extent, plants a well-formed article with the wrong
    /// payload under the planned message-id of article `idx`, then posts
    /// the rest. The provider keeps the planted copy (the stage's own POST
    /// of that id is answered as a duplicate).
    pub async fn post_with_planted_article(&self, s: &Seeded, idx: usize) -> Vec<ArticleRow> {
        self.server().set_posting_allowed(false).await;
        assert_ne!(self.run_post(s).await, JobOutcome::Ack);
        self.server().set_posting_allowed(true).await;
        let plan = self.plan(s).await;
        let row = &plan[idx];
        let article = render(&plan, row, &s.cipher, true);
        let mut client = self.raw_client(0).await;
        client
            .post_article(&row.message_id, &article)
            .await
            .unwrap();
        client.quit().await;
        self.bridge.clock.advance_secs(60);
        self.post(s).await
    }

    /// Copies every planned article from server `from` to server `to`
    /// (what peering between backbones does).
    pub async fn propagate(&self, s: &Seeded, from: usize, to: usize) {
        let mut src = self.raw_client(from).await;
        let mut dst = self.raw_client(to).await;
        for row in self.plan(s).await {
            let mut article = Vec::new();
            src.article_to(&row.message_id, &mut article).await.unwrap();
            dst.post_article(&row.message_id, &article).await.unwrap();
        }
        src.quit().await;
        dst.quit().await;
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
