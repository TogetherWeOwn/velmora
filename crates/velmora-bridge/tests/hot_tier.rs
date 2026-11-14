//! The hot tier: R2 as a bounded cache in front of Usenet, on the SQL
//! catalogue (SQLite with the production schema) and the in-process NNTP
//! server.
//!
//! - A release keeps the safety copy and makes it evictable.
//! - Over the cap, the eviction job drops least recently read evictable
//!   extents down to the low watermark, and nothing else.
//! - A pinned extent (unverified or too young) is never evicted.
//! - An evicted extent is still readable: a cold read refills the cache.

mod nntp_support;
mod service_support;

use std::future::Future;
use std::pin::pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use nntp_support::{TcpConnector, PASS, USER};
use service_support::*;
use velmora_bridge::config::{BridgeConfig, GcMode, Maintenance};
use velmora_bridge::jobs::{low_watermark, EVICT_BATCH, EVICT_CHECK_SECS};
use velmora_bridge::service::READ_STAMP_MS;
use velmora_bridge::sql::HOT_INDEX_ONLY;
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

const BUCKET: &str = "bkt-hot";
/// Plaintext size of every test object, so that all extents weigh the same.
const LEN: usize = 40_000;
const WEEK_SECS: u32 = 604_800;

/// Starts a drain: the job totals the tier itself.
const EVICT: Job = Job::Evict {
    v: JOB_VERSION,
    remaining: 0,
};

/// A later step of a drain that still has `remaining` bytes to evict.
fn resume(remaining: u64) -> Job {
    Job::Evict {
        v: JOB_VERSION,
        remaining,
    }
}

/// Runs a future that never has to wait (catalogue, in-memory stores) to
/// its end, from a place that cannot await: a fault hook.
fn at_once<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("the future had to wait"),
    }
}

struct Hot {
    rig: Rig<TcpConnector>,
    #[allow(dead_code)] // keeps the server alive
    server: TestNntpServer,
    bucket: Bucket,
    signer: Signer,
}

/// A rig with one backbone, no minimum age, garbage collection off and a
/// cap of zero (everything evictable is over the cap) unless `tune` says
/// otherwise.
async fn hot_with(tune: impl FnOnce(&mut BridgeConfig)) -> Hot {
    let mut server_cfg = ServerConfig::for_test();
    server_cfg.articles = Vec::new();
    server_cfg.missing_ids.clear();
    server_cfg.users.insert(
        USER.to_string(),
        UserConfig {
            password: PASS.to_string(),
            max_connections: 4,
        },
    );
    let server = TestNntpServer::spawn(server_cfg).await;
    let mut cfg = config(vec![ProviderConfig {
        id: "p0".to_string(),
        host: server.addr().ip().to_string(),
        port: server.addr().port(),
        tls: false,
        user: USER.to_string(),
        pass: PASS.to_string(),
        backbone: "alpha".to_string(),
        post: true,
        read: true,
        max_conns: 2,
        priority: 0,
        retention_days: None,
        pool: None,
        pool_max_conns: None,
        enabled: true,
    }]);
    cfg.gc_mode = GcMode::Off;
    cfg.hot_cap_bytes = 0;
    tune(&mut cfg);
    let rig = rig_with(TcpConnector::default(), cfg);
    rig.bridge
        .catalog
        .seed_permits(&rig.bridge.cfg.providers)
        .await
        .unwrap();
    let (bucket, signer) = rig.standard(BUCKET).await;
    Hot {
        rig,
        server,
        bucket,
        signer,
    }
}

async fn hot() -> Hot {
    hot_with(|_| {}).await
}

impl Hot {
    fn bridge(&self) -> &TestBridge<TcpConnector> {
        &self.rig.bridge
    }

    fn cfg_mut(&mut self) -> &mut BridgeConfig {
        &mut Rc::get_mut(&mut self.rig.bridge)
            .expect("no request in flight")
            .cfg
    }

    fn set_cap(&mut self, bytes: u64) {
        self.cfg_mut().hot_cap_bytes = bytes;
    }

    /// Makes the dispatcher's hot-tier check due on its next run.
    fn check_due(&self) {
        self.bridge().catalog.sql.with_conn(|c| {
            c.execute("DELETE FROM meta WHERE k = 'hot_checked_at'", [])
                .unwrap()
        });
    }

    /// As a release leaves an extent, without posting it.
    fn mark_released(&self, extent: &ExtentRow) {
        self.sql(
            "UPDATE extents SET safety_state = 'released', hot_safety_bytes = cipher_size, \
               last_read_at = created_at, evict_seq = evict_seq + 1 WHERE id = ?1",
            extent,
        );
    }

    /// Writes a cache fill behind the catalogue's back: a blob that is
    /// not counted.
    async fn uncounted_fill(&self, extent: &ExtentRow) {
        let bridge = self.bridge();
        let from = bridge.safety.stored(&extent.id.safety_key());
        let meta = BlobMeta {
            bucket: &self.bucket.id,
            extent: &extent.id,
            cipher_sha256: &extent.cipher_sha256,
        };
        let key = extent.id.cache_key();
        let bytes = from.expect("the safety copy is the source").bytes;
        bridge.cache.inner.put(&key, bytes, &meta).await.unwrap();
    }

    /// The eviction jobs now in the queue, which they leave.
    fn sent_evictions(&self) -> Vec<Job> {
        let sent = self.bridge().jobs.inner.take();
        let jobs = sent.into_iter().map(|s| s.job);
        jobs.filter(|job| matches!(job, Job::Evict { .. }))
            .collect()
    }

    fn body(key: &str) -> Vec<u8> {
        pattern(key.len() as u8 ^ key.as_bytes()[key.len() - 1], LEN)
    }

    /// PUTs an object and returns its extent. The posting job the PUT sent
    /// stays in the queue.
    async fn put(&self, key: &str) -> ExtentRow {
        self.rig
            .put(&self.signer, BUCKET, key, &Self::body(key))
            .await
            .expect(200);
        let (_, extents) = self.rig.live(&self.bucket, key).await.unwrap();
        assert_eq!(extents.len(), 1);
        extents.into_iter().next().unwrap()
    }

    /// Drops every queued job: the extents they name stay where they are.
    fn discard_jobs(&self) {
        self.bridge().jobs.inner.take();
    }

    /// Runs queued jobs that `wanted` accepts, in due order, moving the
    /// clock to each due time, until none is left. Others are dropped.
    /// Returns the number of deliveries.
    async fn pump_if(&self, wanted: impl Fn(&Job) -> bool) -> u32 {
        let clock = &self.bridge().clock;
        let mut queue: Vec<(UnixMs, Job)> = Vec::new();
        let mut runs = 0;
        loop {
            let now = clock.now();
            for sent in self.bridge().jobs.inner.take() {
                if wanted(&sent.job) {
                    queue.push((now.plus_secs(sent.delay_secs), sent.job));
                }
            }
            if queue.is_empty() {
                return runs;
            }
            queue.sort_by_key(|(due, _)| *due);
            let (due, job) = queue.remove(0);
            if due > clock.now() {
                clock.set(due);
            }
            runs += 1;
            assert!(runs < 500, "the queue does not drain");
            if let JobOutcome::Retry { delay_secs } = self.bridge().run_job(&job).await {
                queue.push((clock.now().plus_secs(delay_secs), job));
            }
        }
    }

    async fn pump(&self) -> u32 {
        self.pump_if(|_| true).await
    }

    /// PUT, post, verify and release: the extent ends evictable.
    async fn released(&self, key: &str) -> ExtentRow {
        let extent = self.put(key).await;
        self.pump().await;
        assert_eq!(self.text(&extent, "safety_state"), "released");
        extent
    }

    /// Runs one job and expects it to be acknowledged.
    async fn run(&self, job: &Job) {
        assert_eq!(self.bridge().run_job(job).await, JobOutcome::Ack);
    }

    /// The dispatcher's report, with its hot-tier check due; only the
    /// eviction job it sent is run.
    async fn dispatch_and_evict(&self) -> (DispatchReport, u32) {
        self.check_due();
        let report = self.bridge().dispatch().await.unwrap();
        let runs = self.pump_if(|job| matches!(job, Job::Evict { .. })).await;
        (report, runs)
    }

    async fn get(&self, key: &str) -> Resp {
        self.rig
            .call(&self.signer, Method::Get, &path(BUCKET, key), &[], &[], b"")
            .await
    }

    async fn get_ok(&self, key: &str) {
        let resp = self.get(key).await;
        resp.expect(200);
        assert!(resp.stream_error.is_none(), "{:?}", resp.stream_error);
        assert!(
            resp.body == Self::body(key),
            "GET {key} returned other bytes"
        );
    }

    fn num(&self, extent: &ExtentRow, column: &str) -> Option<i64> {
        let sql = format!("SELECT {column} FROM extents WHERE id = ?1");
        self.bridge().catalog.sql.with_conn(|c| {
            c.query_row(&sql, [extent.id.as_str()], |r| r.get(0))
                .unwrap()
        })
    }

    fn text(&self, extent: &ExtentRow, column: &str) -> String {
        let sql = format!("SELECT {column} FROM extents WHERE id = ?1");
        self.bridge().catalog.sql.with_conn(|c| {
            c.query_row(&sql, [extent.id.as_str()], |r| r.get(0))
                .unwrap()
        })
    }

    fn sql(&self, sql: &str, extent: &ExtentRow) {
        let n = self
            .bridge()
            .catalog
            .sql
            .with_conn(|c| c.execute(sql, [extent.id.as_str()]).unwrap());
        assert_eq!(n, 1, "{sql}");
    }

    fn has_safety(&self, extent: &ExtentRow) -> bool {
        self.bridge().safety.contains(&extent.id.safety_key())
    }

    fn has_cache(&self, extent: &ExtentRow) -> bool {
        self.bridge().cache.contains(&extent.id.cache_key())
    }

    async fn evictable(&self) -> u64 {
        self.bridge().catalog.evictable_bytes().await.unwrap()
    }

    async fn stats(&self) -> HotStats {
        self.bridge().catalog.hot_stats().await.unwrap()
    }

    /// The extent as the eviction job would list it right now, whether or
    /// not it is evictable.
    fn as_candidate(&self, extent: &ExtentRow, safety_bytes: u64) -> EvictCandidate {
        let state = self.text(extent, "safety_state");
        EvictCandidate {
            extent: extent.id.clone(),
            safety_bytes,
            cache_bytes: self.num(extent, "hot_cache_bytes").unwrap() as u64,
            seq: self.num(extent, "evict_seq").unwrap() as u64,
            pinned: state == "held" || state == "releasing",
        }
    }

    /// Whether the catalogue grants an eviction that claims the safety
    /// copy, to a job that lists the extent truthfully or to one that
    /// wrongly believes it is not pinned.
    async fn grants_safety(&self, extent: &ExtentRow) -> bool {
        let catalog = &self.bridge().catalog;
        let safety_bytes = extent.cipher_size;
        let honest = self.as_candidate(extent, safety_bytes);
        let wrong = EvictCandidate {
            pinned: false,
            ..honest.clone()
        };
        let mut granted = false;
        for x in [honest, wrong] {
            granted |= catalog.begin_evict(&x).await.unwrap() && !x.pinned;
        }
        granted
    }

    async fn admin_status(&self) -> serde_json::Value {
        let token = self.bridge().cfg.admin_token.expose().to_string();
        let resp = self
            .rig
            .send(Req {
                method: Method::Get,
                target: "/_admin/status".to_string(),
                headers: vec![("authorization".to_string(), format!("Bearer {token}"))],
                body: Vec::new(),
            })
            .await;
        resp.expect(200);
        serde_json::from_slice(&resp.body).unwrap()
    }
}

// ---------------------------------------------------------------------------
// Release
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn release_keeps_the_copy_and_makes_it_evictable() {
    let hot = hot_with(|cfg| cfg.hot_cap_bytes = u64::MAX / 4).await;
    let held = hot.put("held").await;
    hot.discard_jobs();
    let cipher = held.cipher_size;
    assert_eq!(
        hot.stats().await,
        HotStats {
            pinned_bytes: cipher,
            pinned_extents: 1,
            evictable_bytes: 0,
            evictable_extents: 0,
        }
    );

    hot.bridge().clock.advance_secs(60);
    let x = hot.released("released").await;

    // Nothing was deleted, and the copy still serves reads without Usenet.
    assert!(hot.has_safety(&x));
    assert_eq!(hot.num(&x, "hot_safety_bytes"), Some(cipher as i64));
    assert_eq!(hot.num(&x, "hot_cache_bytes"), Some(0));
    // A never-read extent takes its place in the order by upload time.
    assert_eq!(hot.num(&x, "last_read_at"), Some(x.created_at.0));
    let connects = hot.bridge().nntp.connects();
    hot.get_ok("released").await;
    assert_eq!(hot.bridge().nntp.connects(), connects);

    assert_eq!(
        hot.stats().await,
        HotStats {
            pinned_bytes: cipher,
            pinned_extents: 1,
            evictable_bytes: cipher,
            evictable_extents: 1,
        }
    );
    assert_eq!(hot.num(&held, "hot_safety_bytes"), Some(0));
}

// ---------------------------------------------------------------------------
// Eviction
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn over_the_cap_the_least_recently_read_go_down_to_the_low_watermark() {
    // Garbage collection is off in this rig: eviction does not depend on it.
    let mut hot = hot().await;
    assert_eq!(hot.bridge().cfg.gc_mode, GcMode::Off);
    let clock = |secs| hot.bridge().clock.advance_secs(secs);

    // The oldest extent of all is pinned: its job never runs.
    let pinned = hot.put("pinned").await;
    hot.discard_jobs();
    let cipher = pinned.cipher_size;

    let mut xs = Vec::new();
    for key in ["k0", "k1", "k2", "k3", "k4", "k5"] {
        clock(60);
        xs.push(hot.released(key).await);
    }
    // The two oldest are read two hours later: they become the newest.
    clock(7200);
    hot.get_ok("k0").await;
    hot.get_ok("k1").await;
    assert_eq!(hot.num(&xs[0], "last_read_at"), Some(hot.rig.now().0));

    // A recovery manifest shares the safety store. Eviction must not see it.
    let manifest = BlobMeta {
        bucket: &hot.bucket.id,
        extent: &pinned.id,
        cipher_sha256: &pinned.cipher_sha256,
    };
    let stored = hot.bridge().safety.stored(&pinned.id.safety_key());
    let bytes = stored.unwrap().bytes;
    for store in [&hot.bridge().safety, &hot.bridge().cache] {
        store
            .put("m/manifest", bytes.clone(), &manifest)
            .await
            .unwrap();
    }

    // Six evictable extents against a cap of five: two must go to get
    // under the low watermark of four and a half.
    assert_eq!(hot.evictable().await, 6 * cipher);
    hot.set_cap(5 * cipher);
    let low = low_watermark(5 * cipher);
    assert!(4 * cipher <= low && low < 5 * cipher);
    let extents = hot.rig.count("extents");

    let (report, runs) = hot.dispatch_and_evict().await;
    assert!(report.evict_enqueued);
    assert_eq!(runs, 1);

    let gone: Vec<bool> = xs.iter().map(|x| !hot.has_safety(x)).collect();
    assert_eq!(gone, [false, false, true, true, false, false]);
    assert_eq!(hot.evictable().await, 4 * cipher);
    for x in &xs[2..4] {
        assert_eq!(hot.num(x, "hot_safety_bytes"), Some(0));
        // Only R2 bytes went: the catalogue still describes the extent.
        assert_eq!(hot.text(x, "safety_state"), "released");
    }
    assert_eq!(hot.rig.count("extents"), extents);
    assert_eq!(hot.rig.count("articles"), 6);
    assert!(hot.has_safety(&pinned));
    assert!(hot.bridge().safety.contains("m/manifest"));
    assert!(hot.bridge().cache.contains("m/manifest"));

    let status = hot.admin_status().await;
    assert_eq!(status["hot"]["pinned_bytes"], cipher);
    assert_eq!(status["hot"]["pinned_extents"], 1);
    assert_eq!(status["hot"]["evictable_bytes"], 4 * cipher);
    assert_eq!(status["hot"]["evictable_extents"], 4);
    assert_eq!(status["hot"]["cap_bytes"], 5 * cipher);
    assert_eq!(status["hot"]["low_watermark_bytes"], low);

    // Under the cap again: the next run sends nothing.
    let (report, runs) = hot.dispatch_and_evict().await;
    assert!(!report.evict_enqueued);
    assert_eq!(runs, 0);
    assert_eq!(hot.evictable().await, 4 * cipher);

    // The evicted objects are still there for a reader.
    hot.get_ok("k2").await;
    hot.get_ok("k4").await;
}

#[tokio::test(flavor = "current_thread")]
async fn nothing_is_evicted_at_or_under_the_cap() {
    let mut hot = hot().await;
    let mut xs = Vec::new();
    for key in ["a", "b", "c"] {
        hot.bridge().clock.advance_secs(60);
        xs.push(hot.released(key).await);
    }
    let cipher = xs[0].cipher_size;
    // Exactly at the cap is not over it.
    hot.set_cap(3 * cipher);

    let (report, runs) = hot.dispatch_and_evict().await;
    assert!(!report.evict_enqueued);
    assert_eq!(runs, 0);
    // An eviction job that arrives anyway (a duplicate, a late one) finds
    // nothing to do.
    hot.run(&EVICT).await;
    assert!(xs.iter().all(|x| hot.has_safety(x)));
    assert_eq!(hot.evictable().await, 3 * cipher);
    assert!(hot.bridge().jobs.inner.take().is_empty());

    // A drain that is already under way does not total the tier again:
    // it evicts what the step before it left, oldest first, and stops.
    hot.set_cap(100 * cipher);
    hot.run(&resume(1)).await;
    let kept: Vec<bool> = xs.iter().map(|x| hot.has_safety(x)).collect();
    assert_eq!(kept, [false, true, true]);
    assert_eq!(hot.evictable().await, 2 * cipher);
    assert!(hot.sent_evictions().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn pinned_extents_are_never_evicted_however_far_over_the_cap() {
    // Cap zero: anything evictable would go at once.
    let hot = hot_with(|cfg| cfg.safety_min_age_secs = WEEK_SECS).await;

    // Never posted, so not verified anywhere.
    let unverified = hot.put("unverified").await;
    hot.discard_jobs();
    // Posted and verified, but younger than the minimum age.
    let young = hot.put("young").await;
    hot.pump().await;
    assert_eq!(hot.text(&young, "safety_state"), "held");
    assert_ne!(hot.num(&young, "last_verified_at"), None);
    let cipher = young.cipher_size;

    let untouched = |hot: &Hot| {
        assert!(hot.has_safety(&unverified));
        assert!(hot.has_safety(&young));
    };
    assert_eq!(hot.evictable().await, 0);
    assert_eq!(hot.stats().await.pinned_bytes, 2 * cipher);
    let (report, runs) = hot.dispatch_and_evict().await;
    assert!(!report.evict_enqueued);
    assert_eq!(runs, 0);
    hot.run(&EVICT).await;
    hot.run(&resume(10 * cipher)).await;
    untouched(&hot);

    // Even with a byte count that claims otherwise, in either pinned
    // state, the catalogue neither lists nor grants a pinned safety copy.
    for state in ["held", "releasing"] {
        for x in [&unverified, &young] {
            hot.sql(
                &format!(
                    "UPDATE extents SET safety_state = '{state}', \
                       hot_safety_bytes = cipher_size WHERE id = ?1"
                ),
                x,
            );
        }
        let catalog = &hot.bridge().catalog;
        assert_eq!(hot.evictable().await, 0);
        assert!(catalog.evict_candidates(10).await.unwrap().is_empty());
        for x in [&unverified, &young] {
            let seq = hot.num(x, "evict_seq");
            assert!(!hot.grants_safety(x).await);
            assert_eq!(hot.num(x, "evict_seq"), seq);
        }
        hot.run(&EVICT).await;
        hot.run(&resume(10 * cipher)).await;
        untouched(&hot);

        // With a cache fill beside it, the fill is evictable and goes;
        // the pinned safety copy does not, and stays pinned.
        hot.uncounted_fill(&young).await;
        hot.sql(
            "UPDATE extents SET hot_cache_bytes = cipher_size WHERE id = ?1",
            &young,
        );
        assert_eq!(hot.evictable().await, cipher);
        assert_eq!(hot.stats().await.pinned_bytes, 2 * cipher);
        let listed = catalog.evict_candidates(10).await.unwrap();
        assert_eq!(listed, [hot.as_candidate(&young, cipher)]);
        assert!(listed[0].pinned);
        assert!(!hot.grants_safety(&young).await);
        hot.run(&EVICT).await;
        assert!(!hot.has_cache(&young));
        assert_eq!(hot.num(&young, "hot_cache_bytes"), Some(0));
        // The forged safety count of a pinned extent is not the job's to
        // clear, and is never summed.
        assert_eq!(hot.num(&young, "hot_safety_bytes"), Some(cipher as i64));
        assert_eq!(hot.evictable().await, 0);
        untouched(&hot);
        hot.get_ok("young").await;
    }
    for x in [&unverified, &young] {
        hot.sql(
            "UPDATE extents SET safety_state = 'held', hot_safety_bytes = 0 WHERE id = ?1",
            x,
        );
    }

    // A week later the verified one is released, after a fresh read-back,
    // and only then can it go. The unverified one stays.
    hot.bridge().clock.advance_secs(WEEK_SECS);
    hot.bridge().dispatch().await.unwrap();
    hot.pump_if(|job| matches!(job, Job::Extent { extent, .. } if *extent == young.id))
        .await;
    assert_eq!(hot.text(&young, "safety_state"), "released");
    assert!(hot.has_safety(&young));

    let (report, runs) = hot.dispatch_and_evict().await;
    assert!(report.evict_enqueued);
    assert_eq!(runs, 1);
    assert!(!hot.has_safety(&young));
    assert!(hot.has_safety(&unverified));
    assert_eq!(
        hot.stats().await,
        HotStats {
            pinned_bytes: cipher,
            pinned_extents: 1,
            evictable_bytes: 0,
            evictable_extents: 0,
        }
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_evicted_extent_is_read_cold_and_the_cache_refill_is_evictable() {
    let hot = hot().await;
    let x = hot.released("cold").await;
    let cipher = x.cipher_size;

    assert_eq!(hot.bridge().evict_batch(0).await.unwrap(), cipher);
    assert!(!hot.has_safety(&x) && !hot.has_cache(&x));
    assert_eq!(hot.evictable().await, 0);

    // The GET goes to Usenet, returns the right bytes and refills the cache.
    hot.bridge().clock.advance_secs(120);
    let connects = hot.bridge().nntp.connects();
    hot.get_ok("cold").await;
    assert_eq!(hot.bridge().nntp.connects(), connects + 1);
    assert!(hot.has_cache(&x) && !hot.has_safety(&x));
    assert_eq!(hot.num(&x, "hot_cache_bytes"), Some(cipher as i64));
    assert_eq!(hot.num(&x, "hot_safety_bytes"), Some(0));
    assert_eq!(hot.num(&x, "last_read_at"), Some(hot.rig.now().0));
    assert_eq!(hot.evictable().await, cipher);
    // The refill serves the next read.
    hot.get_ok("cold").await;
    assert_eq!(hot.bridge().nntp.connects(), connects + 1);

    // The refill is evictable at once, and the cycle repeats.
    assert_eq!(hot.bridge().evict_batch(0).await.unwrap(), cipher);
    assert!(!hot.has_cache(&x));
    assert_eq!(hot.evictable().await, 0);
    hot.get_ok("cold").await;
    assert_eq!(hot.bridge().nntp.connects(), connects + 2);
    assert_eq!(hot.evictable().await, cipher);
}

/// One job handles a bounded number of extents and hands the rest on.
#[tokio::test(flavor = "current_thread")]
async fn a_large_drain_runs_in_bounded_steps() {
    let hot = hot().await;
    let n = EVICT_BATCH as usize + 10;
    let mut xs = Vec::new();
    for i in 0..n {
        let x = hot.put(&format!("bulk-{i:03}")).await;
        // The release itself is tested above.
        hot.mark_released(&x);
        xs.push(x);
    }
    hot.discard_jobs();
    let cipher = xs[0].cipher_size;
    assert_eq!(hot.evictable().await, n as u64 * cipher);

    hot.run(&EVICT).await;
    let left = xs.iter().filter(|x| hot.has_safety(x)).count();
    assert_eq!(left, 10);
    assert_eq!(hot.evictable().await, 10 * cipher);
    // The step hands on what is left to evict, so the next one does not
    // have to total the tier: it runs even when the total cannot be had.
    let sent = hot.sent_evictions();
    assert_eq!(sent, [resume(10 * cipher)]);
    hot.bridge()
        .catalog
        .sql
        .fail_matching
        .replace(Some(("SUM(", 0)));
    assert!(matches!(
        hot.bridge().run_job(&EVICT).await,
        JobOutcome::Retry { .. }
    ));
    hot.run(&sent[0]).await;
    hot.bridge().catalog.sql.fail_matching.replace(None);
    assert!(hot.sent_evictions().is_empty());
    assert!(xs.iter().all(|x| !hot.has_safety(x)));
    assert_eq!(hot.evictable().await, 0);
    assert_eq!(hot.rig.count("extents"), n as i64);
}

// ---------------------------------------------------------------------------
// Races
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn two_eviction_jobs_cannot_both_take_an_extent() {
    let hot = hot().await;
    let x = hot.released("raced").await;
    let cipher = x.cipher_size;
    let catalog = &hot.bridge().catalog;

    // Both jobs list the extent; only one may begin.
    let listed = catalog.evict_candidates(10).await.unwrap();
    assert_eq!(listed, [hot.as_candidate(&x, cipher)]);
    assert!(catalog.begin_evict(&listed[0]).await.unwrap());
    assert!(!catalog.begin_evict(&listed[0]).await.unwrap());

    // The loser stops without deleting. A job that crashed after its
    // begin leaves the extent listed and counted, so a later job takes it.
    assert_eq!(hot.evictable().await, cipher);
    let again = catalog.evict_candidates(10).await.unwrap();
    assert_eq!(again[0].seq, listed[0].seq + 1);

    assert!(catalog.finish_evict(&listed[0]).await.unwrap());
    // Finishing twice, or beginning again from the old listing, changes
    // nothing: the count cannot go below zero.
    assert!(!catalog.finish_evict(&listed[0]).await.unwrap());
    assert!(!catalog.begin_evict(&listed[0]).await.unwrap());
    assert_eq!(hot.num(&x, "hot_safety_bytes"), Some(0));
    assert_eq!(hot.evictable().await, 0);
    assert!(catalog.evict_candidates(10).await.unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn a_release_racing_an_eviction_never_loses_the_pinned_copy() {
    let hot = hot().await;
    let x = hot.put("racing").await;
    let cipher = x.cipher_size;
    let catalog = &hot.bridge().catalog;
    let job = |stage| Job::Extent {
        v: JOB_VERSION,
        extent: x.id.clone(),
        generation: x.generation_id.clone().unwrap(),
        stage,
    };

    // Before every step of the pipeline an eviction job runs, and an
    // eviction that believes the extent is evictable asks to begin.
    let attempt = || hot.grants_safety(&x);
    hot.discard_jobs();
    for stage in [OutboxStage::Post, OutboxStage::Verify] {
        hot.run(&EVICT).await;
        assert!(!attempt().await);
        hot.bridge().clock.advance_secs(60);
        hot.run(&job(stage)).await;
        assert!(hot.has_safety(&x), "after {stage}");
    }
    assert_eq!(hot.text(&x, "safety_state"), "held");
    hot.run(&EVICT).await;
    assert!(!attempt().await);

    // The release has decided but not finished.
    hot.sql(
        "UPDATE extents SET safety_state = 'releasing' WHERE id = ?1",
        &x,
    );
    hot.run(&EVICT).await;
    assert!(!attempt().await);
    assert!(hot.has_safety(&x));
    hot.sql("UPDATE extents SET safety_state = 'held' WHERE id = ?1", &x);

    // A listing taken before the release is stale after it, whatever it
    // claimed about the extent.
    let stale = hot.as_candidate(&x, cipher);
    hot.discard_jobs();
    hot.run(&job(OutboxStage::Release)).await;
    assert_eq!(hot.text(&x, "safety_state"), "released");
    assert!(hot.has_safety(&x));
    for pinned in [true, false] {
        let stale = EvictCandidate {
            pinned,
            ..stale.clone()
        };
        assert!(!catalog.begin_evict(&stale).await.unwrap());
    }
    assert!(hot.has_safety(&x));

    // Released and listed afresh, it goes.
    hot.run(&EVICT).await;
    assert!(!hot.has_safety(&x));
    hot.get_ok("racing").await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_cache_fill_during_an_eviction_stays_counted() {
    let hot = hot().await;
    let x = hot.released("refilled").await;
    let cipher = x.cipher_size;
    let catalog = &hot.bridge().catalog;

    let listed = catalog.evict_candidates(10).await.unwrap();
    assert!(catalog.begin_evict(&listed[0]).await.unwrap());
    hot.bridge()
        .safety
        .delete(&x.id.safety_key())
        .await
        .unwrap();
    // A reader misses, reads from Usenet and fills the cache before the
    // eviction finishes.
    hot.get_ok("refilled").await;
    assert!(hot.has_cache(&x));

    // The eviction must not zero the count of a copy that exists.
    assert!(!catalog.finish_evict(&listed[0]).await.unwrap());
    assert_eq!(hot.num(&x, "hot_cache_bytes"), Some(cipher as i64));
    assert!(hot.evictable().await >= cipher);

    // The next eviction takes what is left and the count is exact again.
    hot.run(&EVICT).await;
    assert!(!hot.has_cache(&x));
    assert_eq!(hot.evictable().await, 0);
    assert_eq!(hot.num(&x, "hot_safety_bytes"), Some(0));
}

// ---------------------------------------------------------------------------
// Last read
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn last_read_is_written_at_most_once_an_hour() {
    let hot = hot_with(|cfg| cfg.hot_cap_bytes = u64::MAX / 4).await;
    let x = hot.released("read").await;
    let clock = &hot.bridge().clock;
    let stamp = |hot: &Hot| hot.num(&x, "last_read_at").unwrap();
    let minutes = |n: u32| clock.advance_secs(n * 60);

    // The release starts the stamp at the upload time.
    let uploaded = x.created_at.0;
    assert_eq!(stamp(&hot), uploaded);
    clock.set(UnixMs(uploaded));

    minutes(10);
    hot.get_ok("read").await;
    minutes(49);
    hot.get_ok("read").await;
    assert_eq!(stamp(&hot), uploaded, "stamped twice within the hour");

    minutes(1);
    hot.get_ok("read").await;
    let first = hot.rig.now().0;
    assert_eq!(first - uploaded, READ_STAMP_MS);
    assert_eq!(stamp(&hot), first);

    for _ in 0..5 {
        minutes(11);
        hot.get_ok("read").await;
        assert_eq!(stamp(&hot), first);
    }
    minutes(5);
    hot.get_ok("read").await;
    assert_eq!(stamp(&hot), first + READ_STAMP_MS);

    // The catalogue holds the gap on its own, for a second isolate that
    // has not seen the stamp: it answers with the stamp it keeps.
    let catalog = &hot.bridge().catalog;
    let now = hot.rig.now().plus_secs(1800);
    let kept = catalog
        .touch_read(&x.id, now, READ_STAMP_MS, false)
        .await
        .unwrap();
    assert_eq!(kept.0, first + READ_STAMP_MS);
    assert_eq!(stamp(&hot), first + READ_STAMP_MS);
    let later = now.plus_secs(1800);
    let kept = catalog.touch_read(&x.id, later, READ_STAMP_MS, false).await;
    assert_eq!(kept.unwrap(), later);
    assert_eq!(stamp(&hot), later.0);
}

// ---------------------------------------------------------------------------
// Other deletes keep the count right
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn garbage_collection_and_admin_evict_end_the_count() {
    let hot = hot_with(|cfg| {
        cfg.gc_mode = GcMode::Disposable;
        cfg.hot_cap_bytes = u64::MAX / 4;
    })
    .await;
    let token = hot.bridge().cfg.admin_token.expose().to_string();

    // Admin evict deletes both copies of a released extent.
    let a = hot.released("admin").await;
    assert_eq!(hot.evictable().await, a.cipher_size);
    let resp = hot
        .rig
        .send(Req {
            method: Method::Post,
            target: format!("/_admin/evict/{BUCKET}/admin?include_safety=1"),
            headers: vec![("authorization".to_string(), format!("Bearer {token}"))],
            body: Vec::new(),
        })
        .await;
    resp.expect(200);
    assert!(!hot.has_safety(&a));
    assert_eq!(hot.evictable().await, 0);

    // A cold read that fills the cache while an admin evict is between
    // its deletes and its bookkeeping stays counted.
    let catalog = &hot.bridge().catalog;
    let seq = catalog.hot_seq(&a.id).await.unwrap();
    hot.get_ok("admin").await;
    assert!(hot.has_cache(&a));
    assert!(!catalog.hot_forget(&a.id, seq, true, true).await.unwrap());
    assert_eq!(hot.evictable().await, a.cipher_size);
    let seq = catalog.hot_seq(&a.id).await.unwrap();
    hot.bridge().cache.delete(&a.id.cache_key()).await.unwrap();
    assert!(catalog.hot_forget(&a.id, seq, false, true).await.unwrap());
    assert!(!catalog.hot_forget(&a.id, seq, false, true).await.unwrap());
    assert_eq!(hot.evictable().await, 0);

    // A deleted object's copies leave through garbage collection.
    let b = hot.released("deleted").await;
    assert_eq!(hot.evictable().await, b.cipher_size);
    hot.rig
        .call(
            &hot.signer,
            Method::Delete,
            &path(BUCKET, "deleted"),
            &[],
            &[],
            b"",
        )
        .await
        .expect(204);
    hot.bridge().clock.advance_secs(40 * 86_400);
    hot.run(&Job::Gc { v: JOB_VERSION }).await;
    assert!(!hot.has_safety(&b));
    assert_eq!(hot.num(&b, "hot_safety_bytes"), Some(0));
    assert_eq!(hot.evictable().await, 0);
    assert_eq!(hot.stats().await, HotStats::default());
}

// ---------------------------------------------------------------------------
// Cost
// ---------------------------------------------------------------------------

/// The statements the dispatcher and the eviction job run every time are
/// answered from a partial covering index: no table scan, no sort.
#[tokio::test(flavor = "current_thread")]
async fn periodic_statements_read_only_their_index() {
    let hot = hot().await;
    for (sql, index) in HOT_INDEX_ONLY {
        let plan: Vec<String> = hot.bridge().catalog.sql.with_conn(|c| {
            let sql = format!("EXPLAIN QUERY PLAN {}", sql.replace("?1", "10"));
            let mut stmt = c.prepare(&sql).unwrap();
            let rows = stmt.query_map((), |r| r.get::<_, String>(3)).unwrap();
            rows.map(|r| r.unwrap()).collect()
        });
        let plan = plan.join(" | ");
        assert!(
            plan.contains(&format!("USING COVERING INDEX {index}")),
            "{sql}\n{plan}"
        );
        assert!(!plan.contains("TEMP B-TREE"), "{sql}\n{plan}");
    }
}

// ---------------------------------------------------------------------------
// Cache fills and their count
// ---------------------------------------------------------------------------

const COUNT_FILL: &str = "SET hot_cache_bytes = cipher_size, last_read_at";

/// A fill is counted before it is written and again after. Whichever of
/// the two counts is lost, no cache blob is left that the catalogue does
/// not count.
#[tokio::test(flavor = "current_thread")]
async fn a_cache_fill_is_never_written_uncounted() {
    let hot = hot().await;
    let x = hot.released("filled").await;
    let cipher = x.cipher_size as i64;
    let sql = &hot.bridge().catalog.sql;
    let evict = || async {
        hot.run(&EVICT).await;
        assert!(!hot.has_cache(&x) && !hot.has_safety(&x));
        assert_eq!(hot.evictable().await, 0);
    };
    evict().await;

    // The count before the write fails: nothing is written. The bytes
    // are verified all the same, so the read succeeds.
    sql.fail_matching.replace(Some((COUNT_FILL, 0)));
    hot.get_ok("filled").await;
    assert!(!hot.has_cache(&x));
    assert_eq!(hot.num(&x, "hot_cache_bytes"), Some(0));

    // The write happens and the count after it never runs (the request
    // was cancelled, or the catalogue failed): the copy is counted.
    sql.fail_matching.replace(Some((COUNT_FILL, 1)));
    hot.get_ok("filled").await;
    assert_eq!(sql.fail_matching.take(), Some((COUNT_FILL, 0)));
    assert!(hot.has_cache(&x));
    assert_eq!(hot.num(&x, "hot_cache_bytes"), Some(cipher));
    evict().await;

    // An eviction runs between the first count and the write, and ends
    // the count. The count after the write restores it.
    let bridge = hot.rig.bridge.clone();
    let cache = &hot.bridge().cache;
    cache.before_put.replace(Some(Box::new(move |_| {
        let cache_bytes = bridge.cfg.hot_cap_bytes + cipher as u64;
        assert_eq!(at_once(bridge.evict_batch(0)).unwrap(), cache_bytes);
    })));
    hot.get_ok("filled").await;
    assert!(cache.before_put.borrow().is_none());
    assert!(hot.has_cache(&x));
    assert_eq!(hot.num(&x, "hot_cache_bytes"), Some(cipher));
    evict().await;

    // The write itself fails after the first count: the count stands for
    // a copy that does not exist, and the next eviction corrects it.
    hot.bridge().cache.fail_put.set(true);
    hot.get("filled").await;
    hot.bridge().cache.fail_put.set(false);
    assert!(!hot.has_cache(&x));
    assert_eq!(hot.num(&x, "hot_cache_bytes"), Some(cipher));
    evict().await;
    assert_eq!(hot.num(&x, "hot_cache_bytes"), Some(0));
    hot.get_ok("filled").await;
}

/// A cache blob the catalogue does not count (written before the counts
/// existed, or by an older Worker) does not stay outside the cap.
#[tokio::test(flavor = "current_thread")]
async fn an_uncounted_cache_blob_is_evicted_or_counted_again() {
    let hot = hot().await;
    let clock = &hot.bridge().clock;

    // Beside a counted safety copy: the eviction deletes both keys,
    // whatever the counts say.
    let both = hot.released("both").await;
    let cipher = both.cipher_size;
    hot.uncounted_fill(&both).await;
    assert_eq!(hot.num(&both, "hot_cache_bytes"), Some(0));
    assert_eq!(hot.evictable().await, cipher);
    assert_eq!(hot.bridge().evict_batch(0).await.unwrap(), cipher);
    assert!(!hot.has_cache(&both) && !hot.has_safety(&both));

    // Alone, with nothing counted: no eviction lists the extent.
    let alone = hot.released("alone").await;
    hot.uncounted_fill(&alone).await;
    let safety = &hot.bridge().safety;
    safety.delete(&alone.id.safety_key()).await.unwrap();
    hot.sql(
        "UPDATE extents SET hot_safety_bytes = 0 WHERE id = ?1",
        &alone,
    );
    assert_eq!(hot.evictable().await, 0);
    hot.run(&EVICT).await;
    assert!(hot.has_cache(&alone));

    // A read served from it counts it, with the hourly stamp.
    let seq = hot.num(&alone, "evict_seq").unwrap();
    clock.advance_ms(READ_STAMP_MS);
    let connects = hot.bridge().nntp.connects();
    hot.get_ok("alone").await;
    assert_eq!(hot.bridge().nntp.connects(), connects);
    assert_eq!(hot.num(&alone, "hot_cache_bytes"), Some(cipher as i64));
    assert_eq!(hot.num(&alone, "last_read_at"), Some(hot.rig.now().0));
    // A listing from before does not survive the new count.
    assert_eq!(hot.num(&alone, "evict_seq"), Some(seq + 1));
    assert_eq!(hot.evictable().await, cipher);
    // A read from an already counted fill is a stamp and nothing more.
    clock.advance_ms(READ_STAMP_MS);
    hot.get_ok("alone").await;
    assert_eq!(hot.num(&alone, "evict_seq"), Some(seq + 1));

    hot.run(&EVICT).await;
    assert!(!hot.has_cache(&alone));
    assert_eq!(hot.evictable().await, 0);

    // A read served from the safety copy counts no cache fill.
    let warm = hot.released("warm").await;
    clock.advance_ms(READ_STAMP_MS);
    hot.get_ok("warm").await;
    assert_eq!(hot.num(&warm, "last_read_at"), Some(hot.rig.now().0));
    assert_eq!(hot.num(&warm, "hot_cache_bytes"), Some(0));
}

// ---------------------------------------------------------------------------
// The job when things go wrong
// ---------------------------------------------------------------------------

/// Three released extents, oldest first.
async fn three(hot: &Hot) -> Vec<ExtentRow> {
    let mut xs = Vec::new();
    for key in ["e0", "e1", "e2"] {
        hot.bridge().clock.advance_secs(60);
        xs.push(hot.released(key).await);
    }
    xs
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_delete_is_retried_and_does_not_hold_up_the_rest() {
    let hot = hot().await;
    let xs = three(&hot).await;
    let cipher = xs[0].cipher_size;
    let safety = &hot.bridge().safety;

    safety.fail_delete.replace(Some(xs[0].id.safety_key()));
    let outcome = hot.bridge().run_job(&EVICT).await;
    assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
    // The extent whose delete failed is intact and still counted; the
    // ones behind it went.
    assert!(hot.has_safety(&xs[0]));
    assert_eq!(hot.num(&xs[0], "hot_safety_bytes"), Some(cipher as i64));
    assert!(!hot.has_safety(&xs[1]) && !hot.has_safety(&xs[2]));
    assert_eq!(hot.evictable().await, cipher);
    assert!(hot.sent_evictions().is_empty());

    // The retry finishes the job.
    safety.fail_delete.replace(None);
    hot.run(&EVICT).await;
    assert!(!hot.has_safety(&xs[0]));
    assert_eq!(hot.evictable().await, 0);
    for key in ["e0", "e1", "e2"] {
        hot.get_ok(key).await;
    }
}

/// A read refills the extent between the job's deletes and its
/// bookkeeping. The job no longer knows how much is left to evict, so it
/// stops: it evicts nothing more and hands nothing on.
#[tokio::test(flavor = "current_thread")]
async fn a_drain_stops_when_an_extent_changes_under_it() {
    let hot = hot().await;
    let xs = three(&hot).await;
    let cipher = xs[0].cipher_size;

    let bridge = hot.rig.bridge.clone();
    let filled = xs[0].id.clone();
    hot.bridge()
        .safety
        .before_delete
        .replace(Some(Box::new(move |key| {
            assert_eq!(key, filled.safety_key());
            let now = bridge.clock.now();
            at_once(bridge.catalog.record_cache_fill(&filled, now)).unwrap();
        })));
    hot.uncounted_fill(&xs[0]).await;
    hot.run(&EVICT).await;

    // The fill that raced the eviction is still counted.
    assert_eq!(hot.num(&xs[0], "hot_cache_bytes"), Some(cipher as i64));
    assert!(hot.has_safety(&xs[1]) && hot.has_safety(&xs[2]));
    assert!(hot.sent_evictions().is_empty());
    assert_eq!(hot.evictable().await, 4 * cipher);

    // The count is above what R2 holds until the next drain, which the
    // dispatcher starts because the tier is still over the cap.
    let (report, runs) = hot.dispatch_and_evict().await;
    assert!(report.evict_enqueued);
    assert_eq!(runs, 1);
    assert_eq!(hot.evictable().await, 0);
    assert!(xs.iter().all(|x| !hot.has_safety(x) && !hot.has_cache(x)));
}

/// Two drains at once, the second one running in full in the middle of
/// the first: together they evict what one would have, and no more.
#[tokio::test(flavor = "current_thread")]
async fn two_drains_at_once_do_not_evict_past_the_low_watermark() {
    let mut hot = hot().await;
    let mut xs = three(&hot).await;
    hot.bridge().clock.advance_secs(60);
    xs.push(hot.released("e3").await);
    let cipher = xs[0].cipher_size;
    // Four extents against a cap of three: two go.
    hot.set_cap(3 * cipher);
    assert!(low_watermark(3 * cipher) < 3 * cipher);
    assert!(low_watermark(3 * cipher) >= 2 * cipher);

    let bridge = hot.rig.bridge.clone();
    hot.bridge()
        .safety
        .before_delete
        .replace(Some(Box::new(move |_| {
            let outcome = at_once(bridge.run_job(&EVICT));
            assert_eq!(outcome, JobOutcome::Ack);
        })));
    hot.run(&EVICT).await;

    let gone: Vec<bool> = xs.iter().map(|x| !hot.has_safety(x)).collect();
    assert_eq!(gone, [true, true, false, false]);
    assert_eq!(hot.evictable().await, 2 * cipher);
    for x in &xs {
        let left = if hot.has_safety(x) { cipher as i64 } else { 0 };
        assert_eq!(hot.num(x, "hot_safety_bytes"), Some(left));
    }
    assert!(hot.sent_evictions().is_empty());
    for key in ["e0", "e1", "e2", "e3"] {
        hot.get_ok(key).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn nothing_is_evicted_during_a_restore() {
    let mut hot = hot().await;
    let xs = three(&hot).await;
    let cipher = xs[0].cipher_size;
    hot.cfg_mut().maintenance = Maintenance::Restore;

    for job in [EVICT, resume(3 * cipher)] {
        hot.run(&job).await;
        assert!(xs.iter().all(|x| hot.has_safety(x)));
        assert_eq!(hot.evictable().await, 3 * cipher);
        assert!(hot.sent_evictions().is_empty());
    }

    hot.cfg_mut().maintenance = Maintenance::Off;
    hot.run(&EVICT).await;
    assert_eq!(hot.evictable().await, 0);
}

// ---------------------------------------------------------------------------
// The dispatcher's check
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn the_dispatcher_totals_the_tier_at_most_every_half_hour() {
    async fn dispatch(hot: &Hot) -> (bool, Vec<Job>) {
        let report = hot.bridge().dispatch().await.unwrap();
        assert!(!report.evict_failed);
        (report.evict_enqueued, hot.sent_evictions())
    }
    let mut hot = hot_with(|cfg| cfg.hot_cap_bytes = u64::MAX / 4).await;
    three(&hot).await;

    // The first run checks: under the cap, nothing to do.
    assert_eq!(dispatch(&hot).await, (false, vec![]));
    // From now the tier is over the cap, but the next check is not due:
    // the runs in between do not total it (they work even when the total
    // cannot be had).
    hot.set_cap(0);
    let clock = |secs| hot.bridge().clock.advance_secs(secs);
    let sql = &hot.bridge().catalog.sql;
    sql.fail_matching.replace(Some(("SUM(", 0)));
    for _ in 0..3 {
        clock(EVICT_CHECK_SECS / 3 - 1);
        assert_eq!(dispatch(&hot).await, (false, vec![]));
    }
    sql.fail_matching.replace(None);

    // Half an hour after the last check the next one runs and starts a
    // drain; the run after that does not check again.
    clock(3);
    assert_eq!(dispatch(&hot).await, (true, vec![EVICT]));
    clock(60);
    assert_eq!(dispatch(&hot).await, (false, vec![]));
}

/// A hot-tier check that fails is reported and does not stop the rest of
/// the dispatcher's run; it is due again on the next run.
#[tokio::test(flavor = "current_thread")]
async fn a_failed_check_does_not_abort_the_dispatcher() {
    let hot = hot().await;
    three(&hot).await;
    let sql = &hot.bridge().catalog.sql;
    let last_dispatch = || async {
        let stats = hot.bridge().catalog.outbox_stats().await.unwrap();
        stats.last_dispatch_at
    };

    // The total cannot be had.
    hot.bridge().clock.advance_secs(60);
    sql.fail_matching.replace(Some(("SUM(", 0)));
    let report = hot.bridge().dispatch().await.unwrap();
    sql.fail_matching.replace(None);
    assert!(report.evict_failed && !report.evict_enqueued);
    assert_eq!(last_dispatch().await, Some(hot.rig.now()));
    assert!(hot.sent_evictions().is_empty());

    // The queue refuses the eviction job.
    hot.bridge().clock.advance_secs(60);
    hot.bridge().jobs.fail.set(true);
    let report = hot.bridge().dispatch().await.unwrap();
    hot.bridge().jobs.fail.set(false);
    assert!(report.evict_failed && !report.evict_enqueued);
    assert_eq!(last_dispatch().await, Some(hot.rig.now()));

    // Neither failure used up the half hour: the very next run checks.
    hot.bridge().clock.advance_secs(60);
    let report = hot.bridge().dispatch().await.unwrap();
    assert!(!report.evict_failed && report.evict_enqueued);
    assert_eq!(hot.sent_evictions(), [EVICT]);
}

// ---------------------------------------------------------------------------
// Garbage collection racing a fill
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_fill_racing_the_collection_of_its_cache_blob_stays_counted() {
    let hot = hot_with(|cfg| {
        cfg.gc_mode = GcMode::Disposable;
        cfg.hot_cap_bytes = u64::MAX / 4;
    })
    .await;
    let x = hot.released("collected").await;
    let cipher = x.cipher_size as i64;
    let bridge = hot.bridge();
    let catalog = &bridge.catalog;

    // The extent has a counted cache fill, and its object is deleted.
    hot.uncounted_fill(&x).await;
    catalog
        .record_cache_fill(&x.id, hot.rig.now())
        .await
        .unwrap();
    let target = path(BUCKET, "collected");
    let delete = hot
        .rig
        .call(&hot.signer, Method::Delete, &target, &[], &[], b"");
    delete.await.expect(204);
    bridge.clock.advance_secs(40 * 86_400);
    let now = hot.rig.now();
    let due = catalog.gc_due(now, 10, true).await.unwrap();
    let row = due.iter().find(|r| r.action == GcAction::DeleteCache);
    let row = row.expect("a cache delete is due");
    assert_eq!(row.extent_id, x.id);

    // Collection stops counting the fill before it deletes the blob.
    let step = catalog.gc_begin(row, now).await.unwrap();
    assert!(matches!(step, GcStep::DeleteBlob { .. }), "{step:?}");
    assert_eq!(hot.num(&x, "hot_cache_bytes"), Some(0));
    assert!(hot.has_cache(&x));

    // A reader that still held the object fills the cache right then,
    // on either side of the delete: its copy is counted.
    let seq = hot.num(&x, "evict_seq");
    catalog.record_cache_fill(&x.id, now).await.unwrap();
    assert_ne!(hot.num(&x, "evict_seq"), seq);
    bridge.cache.delete(&x.id.cache_key()).await.unwrap();
    hot.uncounted_fill(&x).await;
    catalog.gc_done(row.id, now).await.unwrap();
    assert!(hot.has_cache(&x));
    assert_eq!(hot.num(&x, "hot_cache_bytes"), Some(cipher));

    // The rest of the collection ends the safety copy's count and leaves
    // the cache count to the eviction job, which takes the stray fill.
    hot.run(&Job::Gc { v: JOB_VERSION }).await;
    assert!(!hot.has_safety(&x));
    assert_eq!(hot.num(&x, "hot_safety_bytes"), Some(0));
    assert_eq!(hot.num(&x, "hot_cache_bytes"), Some(cipher));
    assert_eq!(bridge.evict_batch(1).await.unwrap(), cipher as u64);
    assert!(!hot.has_cache(&x));
    assert_eq!(hot.stats().await, HotStats::default());
}

// ---------------------------------------------------------------------------
// The fence
// ---------------------------------------------------------------------------

/// Every statement that sets an extent's `safety_state` must bump
/// `evict_seq` in the same statement. Without that, an eviction that
/// listed an extent as released could begin after the extent went back
/// to `held` or `releasing` and delete a pinned copy.
#[test]
fn every_safety_state_change_bumps_the_fence() {
    fn sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    sources(&src, &mut files);
    assert!(files.len() > 10);

    let mut checked = 0;
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        // Line continuations and layout must not hide a clause.
        let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let flat = flat.replace("\\ ", "").replace("\", \"", "");
        for (at, _) in flat.match_indices("UPDATE extents") {
            let rest = &flat[at..];
            let set = &rest[..rest.find(" WHERE ").unwrap_or(rest.len())];
            if !set.contains("safety_state =") {
                continue;
            }
            checked += 1;
            assert!(
                set.contains("evict_seq = evict_seq + 1"),
                "{}: sets safety_state without bumping evict_seq:\n{set}",
                file.display()
            );
        }
        // Extents are created pinned, never as evictable.
        for (at, _) in flat.match_indices("INSERT INTO extents") {
            let rest = &flat[at..(at + 900).min(flat.len())];
            assert!(!rest.contains("'released'"), "{}", file.display());
        }
    }
    // The release (begin and finish), the generic state change and
    // garbage collection.
    assert!(checked >= 4, "only {checked} statements found");
}

/// The same, observed: after any state change, a listing taken before it
/// is refused, in particular one taken while the extent was evictable.
#[tokio::test(flavor = "current_thread")]
async fn a_listing_does_not_survive_a_state_change() {
    use SafetyState::*;
    let hot = hot().await;
    let x = hot.released("fenced").await;
    let cipher = x.cipher_size;
    let catalog = &hot.bridge().catalog;

    let mut from = Released;
    for to in [Held, Releasing, Held, Released, Deleted, Held] {
        let listed = hot.as_candidate(&x, cipher);
        let wrong = EvictCandidate {
            pinned: !listed.pinned,
            ..listed.clone()
        };
        let moved = catalog.set_safety_state(&x.id, from, to).await.unwrap();
        assert!(moved, "{from:?} -> {to:?}");
        for stale in [listed, wrong] {
            assert!(
                !catalog.begin_evict(&stale).await.unwrap(),
                "{from:?} -> {to:?}: {stale:?}"
            );
        }
        from = to;
    }
    assert!(hot.has_safety(&x));

    // Back in `held`, the copy is pinned whatever was counted before.
    assert_eq!(hot.evictable().await, 0);
    hot.run(&EVICT).await;
    hot.run(&resume(cipher)).await;
    assert!(hot.has_safety(&x));
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

/// The migration runs on a catalogue that already has extents, and leaves
/// them as they are in R2: held copies pinned, nothing evictable.
#[tokio::test(flavor = "current_thread")]
async fn the_migration_applies_to_a_catalogue_with_extents() {
    use velmora_bridge::testkit::*;
    let db = RusqliteSql::open_in_memory().unwrap();
    for script in [MIGRATION_0001, MIGRATION_0002, MIGRATION_0003] {
        db.apply(script).unwrap();
    }
    db.with_conn(|c| {
        c.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        let states = ["held", "releasing", "released", "deleted"];
        for (i, state) in states.into_iter().enumerate() {
            c.execute(
                "INSERT INTO extents (id, bucket_id, state, plain_size, cipher_size, \
                   media_header, plain_md5, plain_sha256, cipher_sha256, safety_state, \
                   created_at) \
                 VALUES (?1, 'b', 'committed', 100, ?2, x'00', x'00', x'00', x'00', ?3, ?4)",
                (
                    format!("x_{i}"),
                    1000 * (i as i64 + 1),
                    state,
                    5000 + i as i64,
                ),
            )
            .unwrap();
        }
    });
    db.apply(MIGRATION_0005).unwrap();

    let new_columns: Vec<(i64, i64, Option<i64>, i64)> = db.with_conn(|c| {
        let mut stmt = c
            .prepare(
                "SELECT hot_safety_bytes, hot_cache_bytes, last_read_at, evict_seq \
                 FROM extents ORDER BY id",
            )
            .unwrap();
        let rows = stmt.query_map((), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)));
        rows.unwrap().map(|r| r.unwrap()).collect()
    });
    assert_eq!(new_columns, [(0, 0, None, 0); 4]);

    let catalog = velmora_bridge::sql::SqlCatalog::new(db);
    assert_eq!(
        catalog.hot_stats().await.unwrap(),
        HotStats {
            pinned_bytes: 1000 + 2000,
            pinned_extents: 2,
            evictable_bytes: 0,
            evictable_extents: 0,
        }
    );
    assert!(catalog.evict_candidates(10).await.unwrap().is_empty());

    // An old extent takes part from its first cache fill on.
    let old = ExtentId::new("x_2".to_string());
    catalog.record_cache_fill(&old, UnixMs(9000)).await.unwrap();
    let listed = catalog.evict_candidates(10).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!((listed[0].cache_bytes, listed[0].pinned), (3000, false));
    assert!(catalog.begin_evict(&listed[0]).await.unwrap());
    assert!(catalog.finish_evict(&listed[0]).await.unwrap());
    assert_eq!(catalog.evictable_bytes().await.unwrap(), 0);
}
