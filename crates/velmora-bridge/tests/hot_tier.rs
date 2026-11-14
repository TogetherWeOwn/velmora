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

use std::rc::Rc;

use nntp_support::{TcpConnector, PASS, USER};
use service_support::*;
use velmora_bridge::config::{BridgeConfig, GcMode};
use velmora_bridge::jobs::{low_watermark, EVICT_BATCH};
use velmora_bridge::service::READ_STAMP_MS;
use velmora_bridge::sql::HOT_INDEX_ONLY;
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

const BUCKET: &str = "bkt-hot";
/// Plaintext size of every test object, so that all extents weigh the same.
const LEN: usize = 40_000;
const WEEK_SECS: u32 = 604_800;

const EVICT: Job = Job::Evict {
    v: JOB_VERSION,
    resume: false,
};
const EVICT_RESUME: Job = Job::Evict {
    v: JOB_VERSION,
    resume: true,
};

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

    fn set_cap(&mut self, bytes: u64) {
        Rc::get_mut(&mut self.rig.bridge)
            .expect("no request in flight")
            .cfg
            .hot_cap_bytes = bytes;
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

    /// The dispatcher's report; only the eviction job it sent is run.
    async fn dispatch_and_evict(&self) -> (DispatchReport, u32) {
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
        EvictCandidate {
            extent: extent.id.clone(),
            safety_bytes,
            cache_bytes: self.num(extent, "hot_cache_bytes").unwrap() as u64,
            seq: self.num(extent, "evict_seq").unwrap() as u64,
        }
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

    // Far under the cap not even the continuation of a drain acts.
    hot.set_cap(100 * cipher);
    hot.run(&EVICT_RESUME).await;
    assert!(xs.iter().all(|x| hot.has_safety(x)));

    // Between the low watermark and the cap only a drain that is already
    // under way goes on, and it stops at the low watermark.
    hot.set_cap(3 * cipher);
    hot.run(&EVICT_RESUME).await;
    let kept: Vec<bool> = xs.iter().map(|x| hot.has_safety(x)).collect();
    assert_eq!(kept, [false, true, true]);
    hot.run(&EVICT_RESUME).await;
    assert_eq!(hot.evictable().await, 2 * cipher);
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
    hot.run(&EVICT_RESUME).await;
    untouched(&hot);

    // Even with byte counts that claim otherwise, in either pinned state,
    // the catalogue neither lists nor grants a pinned extent.
    for state in ["held", "releasing"] {
        for x in [&unverified, &young] {
            hot.sql(
                &format!(
                    "UPDATE extents SET safety_state = '{state}', \
                       hot_safety_bytes = cipher_size, hot_cache_bytes = cipher_size \
                     WHERE id = ?1"
                ),
                x,
            );
        }
        let catalog = &hot.bridge().catalog;
        assert_eq!(hot.evictable().await, 0);
        assert!(catalog.evict_candidates(10).await.unwrap().is_empty());
        for x in [&unverified, &young] {
            let forged = hot.as_candidate(x, cipher);
            assert!(!catalog.begin_evict(&forged).await.unwrap());
            assert_eq!(hot.num(x, "evict_seq"), Some(forged.seq as i64));
        }
        hot.run(&EVICT).await;
        hot.run(&EVICT_RESUME).await;
        untouched(&hot);
    }
    for x in [&unverified, &young] {
        hot.sql(
            "UPDATE extents SET safety_state = 'held', hot_safety_bytes = 0, \
               hot_cache_bytes = 0 WHERE id = ?1",
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

    assert_eq!(hot.bridge().evict_batch(false).await.unwrap(), cipher);
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
    assert_eq!(hot.bridge().evict_batch(false).await.unwrap(), cipher);
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
        // As a release leaves it; the release itself is tested above.
        hot.sql(
            "UPDATE extents SET safety_state = 'released', hot_safety_bytes = cipher_size, \
               last_read_at = created_at WHERE id = ?1",
            &x,
        );
        xs.push(x);
    }
    hot.discard_jobs();
    let cipher = xs[0].cipher_size;
    assert_eq!(hot.evictable().await, n as u64 * cipher);

    hot.run(&EVICT).await;
    let left = xs.iter().filter(|x| hot.has_safety(x)).count();
    assert_eq!(left, 10);
    assert_eq!(hot.evictable().await, 10 * cipher);
    let sent: Vec<Job> = hot
        .bridge()
        .jobs
        .inner
        .sent()
        .into_iter()
        .map(|s| s.job)
        .collect();
    assert_eq!(sent, [EVICT_RESUME]);

    assert_eq!(hot.pump().await, 1);
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
    let attempt = || {
        let forged = hot.as_candidate(&x, cipher);
        async move { catalog.begin_evict(&forged).await.unwrap() }
    };
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

    // A listing taken before the release is stale after it.
    let stale = hot.as_candidate(&x, cipher);
    hot.discard_jobs();
    hot.run(&job(OutboxStage::Release)).await;
    assert_eq!(hot.text(&x, "safety_state"), "released");
    assert!(hot.has_safety(&x));
    assert!(!catalog.begin_evict(&stale).await.unwrap());
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
    let kept = catalog.touch_read(&x.id, now, READ_STAMP_MS).await.unwrap();
    assert_eq!(kept.0, first + READ_STAMP_MS);
    assert_eq!(stamp(&hot), first + READ_STAMP_MS);
    let later = now.plus_secs(1800);
    let kept = catalog.touch_read(&x.id, later, READ_STAMP_MS).await;
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
