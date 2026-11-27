//! Scrub and repair (`velmora_bridge::scrub`) against two in-process NNTP
//! servers, one per backbone, and the SQL catalogue: released extents are
//! read back from Usenet alone, a loss is confirmed before it is
//! repaired, the repair goes through the verify and release stages
//! again, and what cannot be repaired is said.

mod nntp_support;
mod service_support;

use std::cell::RefCell;

use nntp_support::{dial, nntp_config, TcpConnector, PASS, USER};
use service_support::*;
use velmora_bridge::scrub::repair_bound_secs;
use velmora_bridge::*;
use velmora_test_nntp::{ServerConfig, TestNntpServer, UserConfig};

type ScrubRig = Rig<TcpConnector>;

const BUCKET: &str = "bkt-scrub";
const DAY_SECS: u32 = 86_400;
/// Two articles: the first is 721,120 bytes of payload.
const PLAIN: usize = 1_000_000;

thread_local! {
    static ALERTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn note_alert(line: &str) {
    ALERTS.with(|a| a.borrow_mut().push(line.to_string()));
}

fn alerts() -> Vec<String> {
    ALERTS.with(|a| a.borrow().clone())
}

struct World {
    rig: ScrubRig,
    servers: [TestNntpServer; 2],
    signer: Signer,
    bucket: Bucket,
}

struct Obj {
    extent: ExtentId,
    generation: GenerationId,
    plain: Vec<u8>,
}

fn provider(id: &str, backbone: &str, server: &TestNntpServer) -> ProviderConfig {
    ProviderConfig {
        id: id.to_string(),
        host: server.addr().ip().to_string(),
        hosts: Vec::new(),
        host_select: Default::default(),
        port: server.addr().port(),
        tls: false,
        user: USER.to_string(),
        pass: PASS.to_string(),
        backbone: backbone.to_string(),
        post: true,
        read: true,
        max_conns: 3,
        max_ips: None,
        drill_conns: 2,
        priority: 0,
        retention_days: None,
        pool: None,
        pool_max_conns: None,
        proxies: Vec::new(),
        enabled: true,
        release: true,
    }
}

async fn server() -> TestNntpServer {
    let mut cfg = ServerConfig::for_test();
    cfg.articles = Vec::new();
    cfg.missing_ids.clear();
    cfg.users.insert(
        USER.to_string(),
        UserConfig {
            password: PASS.to_string(),
            max_connections: 16,
        },
    );
    TestNntpServer::spawn(cfg).await
}

async fn world_with(tune: impl FnOnce(&mut velmora_bridge::config::BridgeConfig)) -> World {
    world_on(false, tune).await
}

async fn world_on(
    sqlite_only: bool,
    tune: impl FnOnce(&mut velmora_bridge::config::BridgeConfig),
) -> World {
    velmora_bridge::trace::log_alerts(note_alert);
    ALERTS.with(|a| a.borrow_mut().clear());
    let servers = [server().await, server().await];
    let mut cfg = config(vec![
        provider("p0", "alpha", &servers[0]),
        provider("p1", "beta", &servers[1]),
    ]);
    cfg.required_backbones = 2;
    cfg.scrub.on = true;
    tune(&mut cfg);
    let rig = if sqlite_only {
        rig_with(TcpConnector::default(), cfg)
    } else {
        rig_with_selected(TcpConnector::default(), cfg)
    };
    rig.bridge
        .catalog
        .seed_permits(&rig.bridge.cfg.providers)
        .await
        .unwrap();
    let (bucket, signer) = rig.standard(BUCKET).await;
    World {
        rig,
        servers,
        signer,
        bucket,
    }
}

/// [`world`], with a byte budget that has `sleeper`.
async fn world_sleeping(sleeper: velmora_bridge::ingress::Sleeper) -> World {
    velmora_bridge::trace::log_alerts(note_alert);
    ALERTS.with(|a| a.borrow_mut().clear());
    let servers = [server().await, server().await];
    let mut cfg = config(vec![
        provider("p0", "alpha", &servers[0]),
        provider("p1", "beta", &servers[1]),
    ]);
    cfg.required_backbones = 2;
    cfg.scrub.on = true;
    let budget =
        velmora_bridge::ingress::ByteBudget::new(cfg.inflight_budget_bytes).with_sleeper(sleeper);
    let rig = rig_with_budget_selected(TcpConnector::default(), cfg, budget);
    rig.bridge
        .catalog
        .seed_permits(&rig.bridge.cfg.providers)
        .await
        .unwrap();
    let (bucket, signer) = rig.standard(BUCKET).await;
    World {
        rig,
        servers,
        signer,
        bucket,
    }
}

async fn world() -> World {
    world_with(|_| {}).await
}

impl World {
    fn bridge(&self) -> &TestBridge<TcpConnector> {
        &self.rig.bridge
    }

    fn advance_secs(&self, secs: u32) {
        self.bridge().clock.advance_secs(secs);
    }

    /// Uploads `key`, posts it, copies every article to the backbone
    /// that lacks it, and runs verify and release: the extent ends
    /// released on both backbones.
    async fn released(&self, key: &str, seed: u8) -> Obj {
        let o = self.released_unenrolled(key, seed).await;
        self.align_clocks(&o).await;
        o
    }

    async fn released_unenrolled(&self, key: &str, seed: u8) -> Obj {
        self.released_sized(key, seed, PLAIN).await
    }

    async fn released_sized(&self, key: &str, seed: u8, len: usize) -> Obj {
        let plain = pattern(seed, len);
        self.rig
            .put(&self.signer, BUCKET, key, &plain)
            .await
            .expect(200);
        let (generation, extents) = self.rig.live(&self.bucket, key).await.unwrap();
        assert_eq!(extents.len(), 1);
        let o = Obj {
            extent: extents[0].id.clone(),
            generation: generation.id,
            plain,
        };
        self.run(&o, OutboxStage::Post).await;
        self.mirror(&o).await;
        self.drive(&o).await;
        assert_eq!(self.safety_state(&o).await, "released");
        o
    }

    /// [`Self::released`], with the articles copied to `extra` servers
    /// too before verify.
    async fn released_on(&self, extra: &[&TestNntpServer], key: &str, seed: u8) -> Obj {
        let plain = pattern(seed, PLAIN);
        self.rig
            .put(&self.signer, BUCKET, key, &plain)
            .await
            .expect(200);
        let (generation, extents) = self.rig.live(&self.bucket, key).await.unwrap();
        let o = Obj {
            extent: extents[0].id.clone(),
            generation: generation.id,
            plain,
        };
        self.run(&o, OutboxStage::Post).await;
        self.mirror(&o).await;
        for server in extra {
            let addr = server.addr();
            let mut dst = dial(&nntp_config(
                &addr.ip().to_string(),
                addr.port(),
                USER,
                PASS,
            ))
            .await
            .unwrap();
            for row in self.plan(&o).await {
                let mut src = self.client(0).await;
                let mut article = Vec::new();
                src.article_to(&row.message_id, &mut article).await.unwrap();
                dst.post_article(&row.message_id, &article).await.unwrap();
                src.quit().await;
            }
            dst.quit().await;
        }
        self.drive(&o).await;
        assert_eq!(self.safety_state(&o).await, "released");
        self.align_clocks(&o).await;
        o
    }

    // Older repair tests bring all STAT clocks due at once. Separate tests
    // below exercise enrollment, staggering, and independently due clocks.
    async fn align_clocks(&self, o: &Obj) {
        let c = &self.bridge().catalog;
        let now = self.bridge().clock.now();
        let token = c.scrub_take(now, now.plus_secs(60)).await.unwrap().unwrap();
        let cfg = &self.bridge().cfg;
        let names: Vec<String> = cfg
            .providers
            .iter()
            .filter(|p| p.enabled && p.read && p.release)
            .map(|p| p.backbone.clone())
            .collect();
        c.scrub_enroll(token, &names, now, [30 * 86_400_000, 90 * 86_400_000])
            .await
            .unwrap();
        c.scrub_free(token, now).await.unwrap();
        c.sql
            .inner
            .fixture_exec(
                "UPDATE scrub_copies SET stat_at = ?2, full_at = ?3, stat_phase_at = ?2, full_phase_at = ?3 WHERE extent_id = ?1",
                &[
                    SqlValue::Text(o.extent.as_str().to_owned()),
                    SqlValue::Int(now.plus_secs(30 * DAY_SECS).0),
                    SqlValue::Int(now.plus_secs(90 * DAY_SECS).0),
                ],
            )
            .await
            .unwrap();
    }

    async fn set_clocks(&self, o: &Obj, backbone: &str, stat_at: UnixMs, full_at: UnixMs) {
        self.bridge().catalog.sql.inner.fixture_exec(
            "UPDATE scrub_copies SET stat_at = ?3, full_at = ?4, stat_phase_at = ?3, full_phase_at = ?4 WHERE extent_id = ?1 AND backbone = ?2",
            &[SqlValue::Text(o.extent.as_str().to_owned()), SqlValue::Text(backbone.to_owned()), SqlValue::Int(stat_at.0), SqlValue::Int(full_at.0)],
        ).await.unwrap();
    }

    async fn full_checks_now(&self, o: &Obj) {
        let now = self.bridge().clock.now();
        for name in ["alpha", "beta"] {
            self.set_clocks(o, name, now.plus_secs(30 * DAY_SECS), now)
                .await;
        }
    }

    async fn clocks(&self, o: &Obj, backbone: &str) -> (UnixMs, UnixMs) {
        let result = self
            .bridge()
            .catalog
            .sql
            .inner
            .fixture_query(
                "SELECT stat_at, full_at FROM scrub_copies WHERE extent_id = ?1 AND backbone = ?2",
                &[
                    SqlValue::Text(o.extent.as_str().to_owned()),
                    SqlValue::Text(backbone.to_owned()),
                ],
            )
            .await
            .unwrap();
        let [SqlValue::Int(stat), SqlValue::Int(full)] = result[0][..] else {
            panic!("missing copy clocks for {backbone}");
        };
        (UnixMs(stat), UnixMs(full))
    }

    /// Runs the object's jobs until its outbox row is `done`.
    async fn drive(&self, o: &Obj) {
        for _ in 0..12 {
            let stage = self.stage(o).await;
            if stage == "done" {
                return;
            }
            self.advance_secs(60);
            self.run(o, OutboxStage::parse(&stage).expect("a stage"))
                .await;
        }
        panic!("the object never reached done: {}", self.stage(o).await);
    }

    async fn run(&self, o: &Obj, stage: OutboxStage) -> JobOutcome {
        let job = Job::Extent {
            v: JOB_VERSION,
            extent: o.extent.clone(),
            generation: o.generation.clone(),
            stage,
        };
        let outcome = self.bridge().run_job(&job).await;
        self.bridge().jobs.inner.take();
        outcome
    }

    async fn plan(&self, o: &Obj) -> Vec<ArticleRow> {
        self.bridge().catalog.articles(&o.extent).await.unwrap()
    }

    /// The data articles and then any parity articles of the object.
    async fn all_articles(&self, o: &Obj) -> Vec<ArticleRow> {
        let stored = self.bridge().catalog.stored_plan(&o.extent).await.unwrap();
        let size: u64 = self
            .scalar("SELECT cipher_size FROM extents WHERE id = ?1", &o.extent)
            .await
            .parse()
            .unwrap();
        let parity = stored.parity_plan(&o.extent, size).unwrap();
        let mut rows = stored.rows;
        rows.extend(parity.into_iter().flat_map(|p| p.articles));
        rows
    }

    /// Copies every article of the object, parity included, to the
    /// server that lacks it, as propagation between backbones would.
    async fn mirror(&self, o: &Obj) {
        for row in self.all_articles(o).await {
            let id = row.message_id.as_str();
            let from = match self.servers[0].is_stored(id).await {
                true => 0,
                false => 1,
            };
            let to = 1 - from;
            if self.servers[to].is_stored(id).await {
                continue;
            }
            let mut src = self.client(from).await;
            let mut dst = self.client(to).await;
            let mut article = Vec::new();
            src.article_to(id, &mut article).await.unwrap();
            dst.post_article(id, &article).await.unwrap();
            src.quit().await;
            dst.quit().await;
        }
    }

    async fn client(
        &self,
        i: usize,
    ) -> velmora::nntp::NntpClient<velmora::transports::tokio_tls::NativeTlsTransport> {
        let addr = self.servers[i].addr();
        dial(&nntp_config(
            &addr.ip().to_string(),
            addr.port(),
            USER,
            PASS,
        ))
        .await
        .unwrap()
    }

    async fn hide(&self, server: usize, o: &Obj, idx: usize) {
        let plan = self.plan(o).await;
        self.servers[server].hide(&plan[idx].message_id).await;
    }

    async fn scalar(&self, sql: &str, extent: &ExtentId) -> String {
        let rows = self
            .bridge()
            .catalog
            .sql
            .inner
            .fixture_query(sql, &[SqlValue::Text(extent.as_str().to_string())])
            .await
            .unwrap();
        match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Text(s)) => s.clone(),
            Some(SqlValue::Int(n)) => n.to_string(),
            Some(SqlValue::Null) | None => "NULL".to_string(),
            Some(other) => panic!("unexpected {other:?}"),
        }
    }

    async fn scrub_failures(&self, o: &Obj) -> Vec<String> {
        let rows = self.bridge().catalog.sql.inner.fixture_query(
            "SELECT backbone FROM verifications WHERE extent_id = ?1 AND provider_id = 'scrub' ORDER BY backbone",
            &[SqlValue::Text(o.extent.as_str().into())],
        ).await.unwrap();
        rows.into_iter()
            .map(|row| match &row[..] {
                [SqlValue::Text(backbone)] => backbone.clone(),
                _ => panic!("unexpected verification row"),
            })
            .collect()
    }

    async fn stage(&self, o: &Obj) -> String {
        self.scalar("SELECT stage FROM outbox WHERE extent_id = ?1", &o.extent)
            .await
    }

    async fn safety_state(&self, o: &Obj) -> String {
        self.scalar("SELECT safety_state FROM extents WHERE id = ?1", &o.extent)
            .await
    }

    async fn result(&self, o: &Obj) -> String {
        self.scalar("SELECT scrub_result FROM extents WHERE id = ?1", &o.extent)
            .await
    }

    async fn next_at(&self, o: &Obj) -> Option<i64> {
        self.scalar("SELECT scrub_next_at FROM extents WHERE id = ?1", &o.extent)
            .await
            .parse()
            .ok()
    }

    async fn scrubbed_at(&self, o: &Obj) -> Option<i64> {
        self.scalar(
            "SELECT last_scrubbed_at FROM extents WHERE id = ?1",
            &o.extent,
        )
        .await
        .parse()
        .ok()
    }

    async fn scrub(&self) -> ScrubRun {
        self.bridge()
            .scrub_run()
            .await
            .unwrap()
            .expect("the run took the lease")
    }

    async fn state(&self) -> ScrubState {
        self.bridge().catalog.scrub_state().await.unwrap()
    }

    fn has_safety(&self, o: &Obj) -> bool {
        self.bridge().safety.contains(&o.extent.safety_key())
    }

    /// The POSTs sent so far in this test (every one, logged as it starts).
    fn posts(&self) -> u32 {
        nntp_support::post_starts().len() as u32
    }

    /// Reads the object back through S3 and compares it.
    async fn read_back(&self, key: &str, o: &Obj) {
        let got = self
            .rig
            .call(&self.signer, Method::Get, &path(BUCKET, key), &[], &[], b"")
            .await;
        got.expect(200);
        assert_eq!(got.body, o.plain, "the object reads back as uploaded");
    }
}

/// A released extent is not checked before either copy clock is due.
#[tokio::test(flavor = "current_thread")]
async fn nothing_is_read_before_the_first_copy_deadline() {
    let w = world().await;
    let o = w.released("a", 1).await;
    w.advance_secs(29 * DAY_SECS);
    let run = w.scrub().await;
    assert_eq!((run.checked, run.ended), (0, ScrubEnd::Idle));
    assert_eq!(w.result(&o).await, "NULL");
}

/// On a healthy monthly STAT pass only the STAT clocks move. Nothing is
/// posted and nothing is written to a blob store.
#[tokio::test(flavor = "current_thread")]
async fn a_healthy_stat_pass_moves_only_the_stat_clocks() {
    let w = world().await;
    let o = w.released("a", 1).await;
    w.advance_secs(31 * DAY_SECS);
    let posts = w.posts();
    let safety_puts = w.bridge().safety.puts.borrow().len();
    let cache_puts = w.bridge().cache.puts.borrow().len();
    let now = w.bridge().clock.now();
    let (stat, full) = w.clocks(&o, "alpha").await;

    let run = w.scrub().await;

    assert_eq!(
        (run.checked, run.ok, run.suspect, run.repaired),
        (1, 1, 0, 0)
    );
    assert_eq!(run.ended, ScrubEnd::Idle);
    assert_eq!(
        run.bytes_read, 0,
        "the monthly STAT pass does not read BODY"
    );
    assert_eq!(w.result(&o).await, "ok");
    assert_eq!(w.scrubbed_at(&o).await, Some(now.0));
    for backbone in ["alpha", "beta"] {
        assert_eq!(
            w.clocks(&o, backbone).await,
            (stat.plus_secs(30 * DAY_SECS), full)
        );
    }
    assert_eq!(w.posts(), posts, "a check posts nothing");
    assert_eq!(w.bridge().safety.puts.borrow().len(), safety_puts);
    assert_eq!(w.bridge().cache.puts.borrow().len(), cache_puts);
    assert_eq!(w.safety_state(&o).await, "released");
    let state = w.state().await;
    assert_eq!((state.runs, state.checked, state.ok), (1, 1, 1));
    assert_eq!(state.lease_until, None, "the run gave the lease back");
    assert!(alerts().is_empty(), "{:?}", alerts());

    // A late check retains its scheduled phase, rather than drifting.
    w.advance_secs(28 * DAY_SECS);
    assert_eq!(w.scrub().await.checked, 0);
    w.advance_secs(DAY_SECS);
    assert_eq!(w.scrub().await.ok, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn mixed_due_kinds_advance_only_their_own_backbone_and_interval() {
    let w = world_with(|cfg| {
        cfg.scrub.interval_days = 7;
        cfg.scrub.full_interval_days = 19;
    })
    .await;
    let o = w.released("mixed", 5).await;
    let now = w.bridge().clock.now();
    let later = now.plus_secs(100 * DAY_SECS);
    w.set_clocks(&o, "alpha", now, later).await;
    w.set_clocks(&o, "beta", later, now).await;
    // An alpha BODY would fail; only alpha STAT and beta BODY are due.
    w.servers[0].set_body_gone(true).await;
    let run = w.scrub().await;
    assert_eq!((run.checked, run.ok, run.suspect), (1, 1, 0));
    assert!(run.bytes_read > PLAIN as u64);
    assert_eq!(
        w.clocks(&o, "alpha").await,
        (now.plus_secs(7 * DAY_SECS), later)
    );
    assert_eq!(
        w.clocks(&o, "beta").await,
        (later, now.plus_secs(19 * DAY_SECS))
    );
    w.advance_secs(7 * DAY_SECS - 1);
    assert_eq!(w.scrub().await.checked, 0);
    w.advance_secs(1);
    assert_eq!(w.scrub().await.bytes_read, 0);
    w.advance_secs(12 * DAY_SECS);
    assert!(w.scrub().await.bytes_read > PLAIN as u64);
}

#[tokio::test(flavor = "current_thread")]
async fn beta_corruption_survives_stat_and_alpha_full_but_not_beta_full() {
    let w = world().await;
    let o = w.released("beta-corrupt", 6).await;
    let id = &w.plan(&o).await[0].message_id;
    assert!(w.servers[1].replace_posted_body(id, b"not yEnc\r\n").await);
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    let now = w.bridge().clock.now();
    let beta_full = now.plus_secs(DAY_SECS);
    let later = now.plus_secs(100 * DAY_SECS);
    w.set_clocks(&o, "alpha", later, now).await;
    w.set_clocks(&o, "beta", now, beta_full).await;

    let first = w.scrub().await;
    assert_eq!((first.ok, first.suspect), (1, 0));
    assert_eq!(w.clocks(&o, "alpha").await.1, now.plus_secs(90 * DAY_SECS));
    assert_eq!(w.clocks(&o, "beta").await.1, beta_full);
    w.advance_secs(DAY_SECS);
    assert_eq!(w.scrub().await.suspect, 1);
    w.advance_secs(w.bridge().cfg.scrub.confirm_secs);
    assert_eq!(w.scrub().await.repaired, 1);
    assert_eq!(w.stage(&o).await, "verify");
    assert!(w.has_safety(&o));
    assert_eq!(w.clocks(&o, "alpha").await.1, now.plus_secs(90 * DAY_SECS));
    assert!(alerts()
        .iter()
        .any(|a| a.contains("source=usenet") && a.contains("lacking=[beta]")));
}

#[tokio::test(flavor = "current_thread")]
async fn enrollment_spreads_first_checks_and_preserves_existing_clocks() {
    let w = world().await;
    let a = w.released_unenrolled("new-a", 8).await;
    let b = w.released_unenrolled("new-b", 9).await;
    let now = w.bridge().clock.now();
    assert_eq!(w.scrub().await.checked, 0);
    let a_alpha = w.clocks(&a, "alpha").await;
    let b_alpha = w.clocks(&b, "alpha").await;
    assert_ne!(a_alpha, b_alpha);
    for o in [&a, &b] {
        for name in ["alpha", "beta"] {
            let (stat, full) = w.clocks(o, name).await;
            assert!((now..now.plus_secs(30 * DAY_SECS)).contains(&stat));
            assert!((now..now.plus_secs(90 * DAY_SECS)).contains(&full));
        }
    }
    let c = &w.bridge().catalog;
    let token = c.scrub_take(now, now.plus_secs(60)).await.unwrap().unwrap();
    assert!(c
        .scrub_repin(token, &a.extent, (now, now.plus_secs(3600)), &[])
        .await
        .unwrap());
    c.scrub_enroll(
        token,
        &["alpha".into(), "beta".into(), "gamma".into()],
        now,
        [30 * 86_400_000, 90 * 86_400_000],
    )
    .await
    .unwrap();
    assert_eq!(w.clocks(&a, "alpha").await, a_alpha);
    assert!(w.clocks(&a, "gamma").await.1 >= now);
}

#[tokio::test(flavor = "current_thread")]
async fn a_copy_pass_cannot_clear_or_confirm_another_backbones_loss() {
    let w = world().await;
    let o = w.released("independent-confirm", 10).await;
    let now = w.bridge().clock.now();
    let later = now.plus_secs(100 * DAY_SECS);
    w.set_clocks(&o, "alpha", now, later).await;
    w.set_clocks(&o, "beta", now.plus_secs(1800), later).await;
    w.hide(0, &o, 0).await;
    assert_eq!(w.scrub().await.suspect, 1);
    w.advance_secs(1800);
    assert_eq!(w.scrub().await.ok, 0);
    assert_eq!(w.result(&o).await, "suspect");

    w.advance_secs(1800);
    w.set_clocks(&o, "beta", w.bridge().clock.now(), later)
        .await;
    w.hide(1, &o, 1).await;
    assert_eq!(w.scrub().await.repaired, 1);
    assert_eq!(w.scrub_failures(&o).await, ["alpha", "beta"]);
    assert_eq!(
        w.scalar(
            "SELECT stat_loss_at FROM scrub_copies WHERE extent_id = ?1 AND backbone = 'beta'",
            &o.extent
        )
        .await,
        "NULL",
        "re-pin handed beta's loss to the verify job"
    );
}

async fn light_verify_waits_for_alpha_full_read(alpha_failed_earlier: bool) {
    let w = world_with(|cfg| {
        cfg.verify.mode = velmora_bridge::config::VerifyMode::Light;
        cfg.verify.sample_ppm = 0;
    })
    .await;
    let o = w.released("mixed-loss", 19).await;
    let plan = w.plan(&o).await;
    let alpha_corrupt = &plan[1].message_id;
    let mut original = Vec::new();
    let mut client = w.client(0).await;
    client
        .article_to(alpha_corrupt, &mut original)
        .await
        .unwrap();
    client.quit().await;
    let headers = original.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let body = &original[headers + 4..];
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    assert!(
        w.servers[0]
            .replace_posted_body(alpha_corrupt, b"not yEnc\r\n")
            .await
    );

    let now = w.bridge().clock.now();
    let confirm = w.bridge().cfg.scrub.confirm_secs;
    let later = now.plus_secs(100 * DAY_SECS);
    if alpha_failed_earlier {
        w.set_clocks(&o, "alpha", later, now).await;
        assert_eq!(w.scrub().await.suspect, 1);
        // A persisted failure must count even when its full retry is not due.
        w.set_clocks(&o, "alpha", later, later).await;
    } else {
        w.set_clocks(&o, "alpha", later, now.plus_secs(confirm))
            .await;
    }
    w.set_clocks(&o, "beta", now, later).await;
    w.hide(1, &o, 0).await;
    assert_eq!(w.scrub().await.suspect, 1);
    w.advance_secs(confirm);
    assert_eq!(
        w.scrub().await.repaired,
        1,
        "mixed read reconstructs from both backbones"
    );
    assert_eq!(w.stage(&o).await, "verify");
    w.servers[1].unhide(&plan[0].message_id).await;
    for _ in 0..3 {
        let stage = w.stage(&o).await;
        if stage == "done" || stage == "dead" {
            break;
        }
        w.advance_secs(3600);
        w.run(&o, OutboxStage::parse(&stage).unwrap()).await;
    }
    assert_eq!(
        w.safety_state(&o).await,
        "held",
        "alpha STAT cannot clear its failed full read"
    );
    assert!(w.has_safety(&o));
    assert!(w.servers[0].replace_posted_body(alpha_corrupt, body).await);
    for _ in 0..12 {
        let stage = w.stage(&o).await;
        if stage == "done" || stage == "dead" {
            break;
        }
        w.advance_secs(3600);
        w.run(&o, OutboxStage::parse(&stage).unwrap()).await;
    }
    assert_eq!(w.stage(&o).await, "done");
    assert_eq!(w.safety_state(&o).await, "released");
}

#[tokio::test(flavor = "current_thread")]
async fn light_verify_cannot_release_after_an_unconfirmed_full_failure_in_the_repair_visit() {
    light_verify_waits_for_alpha_full_read(false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn light_verify_cannot_release_with_a_full_failure_from_an_earlier_visit() {
    light_verify_waits_for_alpha_full_read(true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn clean_checks_clear_only_the_observed_backbones_incident() {
    let w = world().await;
    let o = w.released("independent-incident", 11).await;
    let now = w.bridge().clock.now();
    let later = now.plus_secs(DAY_SECS);
    w.set_clocks(&o, "alpha", now, later).await;
    w.set_clocks(&o, "beta", later, later).await;
    w.bridge().catalog.sql.inner.fixture_exec(
        r#"UPDATE scrub_state SET last_incident = '["alpha","beta"]', incident_clean_by = '[["alpha",7],["beta",7]]'"#,
        &[],
    ).await.unwrap();
    assert_eq!(w.scrub().await.ok, 1);
    let state = w.state().await;
    assert_eq!(state.blocked(), ["beta"]);
    assert_eq!(state.incident_clean_by, [("beta".into(), 7)]);
}

#[tokio::test(flavor = "current_thread")]
async fn enrollment_preserves_a_legacy_pending_loss_as_full_work() {
    let w = world().await;
    let o = w.released_unenrolled("legacy-loss", 12).await;
    let now = w.bridge().clock.now();
    w.bridge().catalog.sql.inner.fixture_exec(
        "UPDATE extents SET scrub_result='suspect', last_scrubbed_at=?2, scrub_next_at=?2 WHERE id=?1",
        &[SqlValue::Text(o.extent.as_str().into()), SqlValue::Int(now.0)],
    ).await.unwrap();
    w.servers[1].set_body_gone(true).await;
    let run = w.scrub().await;
    assert_eq!(
        (run.suspect, run.repaired),
        (1, 0),
        "retry the legacy loss without assuming its backbone"
    );
    assert_eq!(w.clocks(&o, "beta").await.1, now.plus_secs(3600));
}

#[tokio::test(flavor = "current_thread")]
async fn a_stat_pass_cannot_clear_a_body_incident() {
    let w = world().await;
    let mut objects = Vec::new();
    for i in 0..8 {
        objects.push(w.released(&format!("body-incident-{i}"), i).await);
    }
    for o in &objects {
        w.full_checks_now(o).await;
    }
    w.servers[1].set_body_gone(true).await;
    assert_eq!(w.scrub().await.incident.as_deref(), Some("beta"));

    let now = w.bridge().clock.now();
    for o in &objects {
        let full = w.clocks(o, "beta").await.1;
        w.set_clocks(o, "beta", now, full).await;
    }
    w.scrub().await;
    assert_eq!(
        w.state().await.blocked(),
        ["beta"],
        "STAT is not BODY recovery evidence"
    );
    w.servers[1].set_body_gone(false).await;
    w.advance_secs(3600);
    assert_eq!(w.scrub().await.ok, 8);
    assert!(w.state().await.blocked().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn a_successful_retry_resumes_the_original_phase() {
    let w = world().await;
    let o = w.released("phase-retry", 13).await;
    let now = w.bridge().clock.now();
    w.set_clocks(&o, "beta", now, now.plus_secs(90 * DAY_SECS))
        .await;
    w.hide(1, &o, 0).await;
    assert_eq!(w.scrub().await.suspect, 1);
    w.servers[1].unhide(&w.plan(&o).await[0].message_id).await;
    w.advance_secs(3600);
    assert_eq!(w.scrub().await.ok, 1);
    assert_eq!(w.clocks(&o, "beta").await.0, now.plus_secs(30 * DAY_SECS));
}

#[tokio::test(flavor = "current_thread")]
async fn a_changed_interval_starts_at_the_latest_regular_deadline() {
    let mut w = world().await;
    let o = w.released("new-interval", 14).await;
    let now = w.bridge().clock.now();
    let later = now.plus_secs(300 * DAY_SECS);
    w.set_clocks(&o, "alpha", later, later).await;
    w.set_clocks(&o, "beta", later, now).await;
    assert_eq!(w.scrub().await.ok, 1);
    assert_eq!(w.clocks(&o, "beta").await.1, now.plus_secs(90 * DAY_SECS));
    std::rc::Rc::get_mut(&mut w.rig.bridge)
        .unwrap()
        .cfg
        .scrub
        .full_interval_days = 91;
    w.advance_secs(90 * DAY_SECS);
    assert_eq!(w.scrub().await.ok, 1);
    assert_eq!(w.clocks(&o, "beta").await.1, now.plus_secs(181 * DAY_SECS));
}

#[tokio::test(flavor = "current_thread")]
async fn a_single_body_failure_does_not_upgrade_a_stat_incident() {
    let w = world().await;
    let o = w.released("stat-incident", 15).await;
    w.full_checks_now(&o).await;
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            r#"UPDATE scrub_state SET last_incident = '["beta"]', incident_clean = 7"#,
            &[],
        )
        .await
        .unwrap();
    w.servers[1].set_body_gone(true).await;
    assert_eq!(w.scrub().await.suspect, 1);
    let state = w.state().await;
    assert_eq!(state.blocked(), ["beta"]);
    assert!(state.incident_body_by.is_empty());
    assert_eq!(state.incident_clean, 0);
}

/// An article lost on one backbone: seen once it is only `suspect`;
/// seen again after the confirm interval the extent is re-pinned, the
/// verify stage posts the article to that backbone again under its
/// message-id, and the release needs both backbones again.
#[tokio::test(flavor = "current_thread")]
async fn a_loss_on_one_backbone_is_confirmed_then_reposted_there_and_released_on_two() {
    let w = world().await;
    let o = w.released("a", 2).await;
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 1).await;

    let first = w.scrub().await;
    assert_eq!((first.checked, first.suspect, first.repaired), (1, 1, 0));
    assert_eq!(w.result(&o).await, "suspect");
    assert_eq!(w.safety_state(&o).await, "released", "nothing repaired yet");
    // Not looked at again before the confirm interval.
    w.advance_secs(3599);
    assert_eq!(w.scrub().await.checked, 0);
    w.advance_secs(1);

    let second = w.scrub().await;
    assert_eq!((second.checked, second.repaired), (1, 1));
    assert_eq!(w.result(&o).await, "repairing");
    assert_eq!(w.safety_state(&o).await, "held");
    assert_eq!(w.stage(&o).await, "verify");
    assert!(w.has_safety(&o), "the safety copy is back");
    assert!(alerts().iter().any(|a| a.starts_with("scrub-repair ")
        && a.contains("source=usenet")
        && a.contains("lacking=[beta]")));
    let state = w.state().await;
    assert_eq!((state.suspect, state.repaired), (1, 1));

    // The pipeline: verify posts the article to beta again and reads it
    // back; the release then needs both backbones.
    let plan = w.plan(&o).await;
    let posts = w.posts();
    assert!(w.servers[1].is_hidden(&plan[1].message_id).await);
    w.drive(&o).await;
    assert_eq!(w.safety_state(&o).await, "released");
    assert!(
        !w.servers[1].is_hidden(&plan[1].message_id).await,
        "the repost under the stored message-id put it back on beta"
    );
    assert_eq!(w.posts(), posts + 1, "one POST: the lost article");
    let evidence = w
        .scalar(
            "SELECT release_evidence FROM extents WHERE id = ?1",
            &o.extent,
        )
        .await;
    assert!(
        evidence.contains("alpha") && evidence.contains("beta"),
        "{evidence}"
    );

    // At its repair bound the extent is released: checked as any, ok.
    let bound = repair_bound_secs(w.bridge().cfg.safety_min_age_secs, 3600);
    w.advance_secs(u32::try_from(bound).unwrap());
    let after = w.scrub().await;
    assert_eq!((after.checked, after.ok), (1, 1));
    assert_eq!(w.result(&o).await, "ok");
    w.read_back("a", &o).await;
}

/// A loss that is gone when it is looked at again (a provider that
/// answered `430` for a while) is never repaired.
#[tokio::test(flavor = "current_thread")]
async fn a_loss_that_heals_before_it_is_confirmed_is_not_repaired() {
    let w = world().await;
    let o = w.released("a", 3).await;
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 0).await;
    assert_eq!(w.scrub().await.suspect, 1);
    let plan = w.plan(&o).await;
    w.servers[0].unhide(&plan[0].message_id).await;
    w.advance_secs(3600);
    let run = w.scrub().await;
    assert_eq!((run.ok, run.repaired), (1, 0));
    assert_eq!(w.result(&o).await, "ok");
    assert_eq!(w.safety_state(&o).await, "released");
}

/// Lost on every backbone, with neither the safety copy nor Usenet to
/// read it from: the cache copy is checked against the digest and used.
#[tokio::test(flavor = "current_thread")]
async fn a_loss_on_every_backbone_is_repaired_from_the_cache_copy() {
    let w = world().await;
    let o = w.released("a", 4).await;
    let cipher = w
        .bridge()
        .safety
        .stored(&o.extent.safety_key())
        .unwrap()
        .bytes;
    // The safety copy was evicted; a read had filled the cache.
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;

    assert_eq!(w.scrub().await.suspect, 1);
    // The read that fills the cache comes after the first sighting:
    // at the sighting the scrub writes a fill that is the only R2 copy
    // to the safety store itself (`scrub-protect`).
    w.bridge()
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    w.advance_secs(3600);
    let run = w.scrub().await;
    assert_eq!(run.repaired, 1);
    assert!(w.has_safety(&o));
    assert!(alerts().iter().any(|a| a.contains("source=cache")));
    assert!(alerts().iter().any(|a| a.contains("lacking=[alpha,beta]")));

    w.drive(&o).await;
    assert_eq!(w.safety_state(&o).await, "released");
    let plan = w.plan(&o).await;
    for s in &w.servers {
        assert!(!s.is_hidden(&plan[0].message_id).await);
    }
}

/// Lost on every backbone, and no intact copy in R2: `unrecoverable`,
/// an alert line every time, and a counter. A corrupt cache copy is not
/// used.
#[tokio::test(flavor = "current_thread")]
async fn a_loss_with_no_intact_copy_anywhere_is_unrecoverable_and_alerted() {
    let w = world().await;
    let o = w.released("a", 5).await;
    let cipher = w
        .bridge()
        .safety
        .stored(&o.extent.safety_key())
        .unwrap()
        .bytes;
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    w.bridge()
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    // The cache copy rotted.
    assert!(w
        .bridge()
        .cache
        .corrupt(&o.extent.cache_key(), |b| b[10] ^= 1));
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 1).await;
    w.hide(1, &o, 1).await;
    let posts = w.posts();

    assert_eq!(w.scrub().await.suspect, 1);
    w.advance_secs(3600);
    let run = w.scrub().await;
    assert_eq!((run.unrecoverable, run.repaired), (1, 0));
    assert_eq!(w.result(&o).await, "unrecoverable");
    assert_eq!(w.safety_state(&o).await, "released");
    assert!(!w.has_safety(&o), "nothing unverified is written");
    assert_eq!(w.posts(), posts, "nothing is posted");
    let state = w.state().await;
    assert_eq!(state.unrecoverable, 1);
    assert_eq!(state.last_unrecoverable_at, Some(w.bridge().clock.now()));
    let lines: Vec<String> = alerts()
        .into_iter()
        .filter(|a| a.starts_with("scrub-unrecoverable "))
        .collect();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains(o.extent.as_str()));

    // Checked again at the confirm interval: a backbone that comes back
    // ends it.
    let plan = w.plan(&o).await;
    w.servers[1].unhide(&plan[1].message_id).await;
    w.advance_secs(3600);
    let back = w.scrub().await;
    assert_eq!(back.repaired, 1, "beta has it again: repaired from Usenet");
}

/// A busy backbone cannot complete its check or block later healthy work.
#[tokio::test(flavor = "current_thread")]
async fn a_provider_without_a_free_slot_defers_only_its_own_check() {
    let w = world_on(true, |cfg| {
        for p in &mut cfg.providers {
            p.max_conns = 1;
            p.drill_conns = 0;
        }
    })
    .await;
    let o = w.released("a", 6).await;
    let healthy = w.released("b", 7).await;
    w.advance_secs(31 * DAY_SECS);
    let now = w.bridge().clock.now();
    let later = now.plus_secs(30 * DAY_SECS);
    w.set_clocks(&healthy, "beta", later, later).await;
    // Another job holds beta's only slot.
    let beta = w.bridge().cfg.providers[1].clone();
    let held = w
        .bridge()
        .catalog
        .acquire_permit(
            &beta,
            PermitClass::Background,
            "job:other",
            w.bridge().clock.now(),
        )
        .await
        .unwrap();
    assert!(held.is_some());
    let db = w.bridge().catalog.sql.inner.sqlite();
    db.meter_writes().unwrap();
    let before = db.writes();
    let beta_due = w.clocks(&o, "beta").await;

    let run = w.scrub().await;
    assert_eq!((run.checked, run.ended), (1, ScrubEnd::Idle));
    assert_eq!(
        db.writes().since(&before).table("provider_permits"),
        2,
        "one alpha session, no shared pool with beta"
    );
    assert_eq!(w.result(&healthy).await, "ok");
    assert_eq!(w.result(&o).await, "NULL");
    assert_eq!(w.next_at(&o).await, None);
    let now = w.bridge().clock.now();
    assert!(
        w.clocks(&o, "alpha").await.0 > now,
        "alpha completed independently"
    );
    assert_eq!(w.clocks(&o, "beta").await, beta_due);
    // A run with only this partial result still completes alpha's check.
    w.set_clocks(&o, "alpha", now, later).await;
    w.set_clocks(&o, "beta", now, later).await;
    assert_eq!(w.scrub().await.checked, 0);
    assert!(w.clocks(&o, "alpha").await.0 > now);
    assert!(!alerts()
        .iter()
        .any(|alert| alert.starts_with("scrub-no-progress")));
}

#[tokio::test(flavor = "current_thread")]
async fn an_unreachable_backbone_backlog_cannot_spend_the_run_quota() {
    let mut w = world_with(|cfg| cfg.scrub.extents_per_run = 8).await;
    let mut backlog = Vec::new();
    for i in 0..9 {
        backlog.push(w.released(&format!("beta-{i}"), i).await);
    }
    let healthy = w.released("alpha-only", 10).await;
    let due = w.bridge().clock.now();
    let later = due.plus_secs(100 * DAY_SECS);
    for o in &backlog {
        w.set_clocks(o, "alpha", later, later).await;
        w.set_clocks(o, "beta", due, later).await;
    }
    w.set_clocks(&healthy, "beta", later, later).await;
    w.advance_secs(1);
    w.set_clocks(&healthy, "alpha", w.bridge().clock.now(), later)
        .await;
    // Drop the listener at the address the configured beta provider uses.
    drop(std::mem::replace(&mut w.servers[1], server().await));

    let run = w.scrub().await;
    assert_eq!((run.checked, run.ok, run.ended), (1, 1, ScrubEnd::Idle));
    assert_eq!(w.result(&healthy).await, "ok");
    for o in &backlog {
        assert_eq!(w.clocks(o, "beta").await, (due, later));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn held_copy_checks_wait_for_the_repair_watch() {
    let w = world_with(|cfg| cfg.scrub.extents_per_run = 1).await;
    let held = w.released("held", 10).await;
    let healthy = w.released("healthy", 11).await;
    let now = w.bridge().clock.now();
    let watch = now.plus_secs(10 * 3600);
    let later = now.plus_secs(100 * DAY_SECS);
    let c = &w.bridge().catalog;
    let token = c.scrub_take(now, now.plus_secs(60)).await.unwrap().unwrap();
    assert!(c
        .scrub_repin(token, &held.extent, (now, watch), &[])
        .await
        .unwrap());
    assert!(c.scrub_free(token, now).await.unwrap());
    w.set_clocks(&held, "alpha", now, later).await;
    w.advance_secs(1);
    w.set_clocks(&healthy, "alpha", w.bridge().clock.now(), later)
        .await;

    let run = w.scrub().await;
    assert_eq!((run.checked, run.ok), (1, 1));
    assert_eq!(w.clocks(&held, "alpha").await, (watch, later));
    assert_eq!(w.safety_state(&held).await, "held");
    w.advance_secs(10 * 3600 - 1);
    w.scrub().await;
    let next_watch = UnixMs(w.next_at(&held).await.unwrap());
    assert!(next_watch > watch);
    assert_eq!(w.clocks(&held, "alpha").await, (next_watch, later));
}

/// The breaker: 8 extents of 8 lacking articles on one backbone is a
/// backbone event, not lost articles. The run stops, nothing is
/// repaired, and no loss there is repaired until a run that could have
/// tripped it again does not.
#[tokio::test(flavor = "current_thread")]
async fn a_backbone_that_lacks_many_extents_trips_the_breaker_and_re_pins_trickle() {
    let w = world().await;
    let mut objs = Vec::new();
    for i in 0..9u8 {
        objs.push(w.released(&format!("k{i}"), 10 + i).await);
    }
    w.advance_secs(31 * DAY_SECS);
    for o in &objs {
        w.hide(1, o, 0).await;
    }

    let first = w.scrub().await;
    assert_eq!(first.ended, ScrubEnd::Incident);
    assert_eq!((first.checked, first.suspect, first.repaired), (8, 8, 0));
    assert_eq!(first.incident.as_deref(), Some("beta"));
    assert!(alerts().iter().any(|a| a == "scrub-incident beta 8/8"));
    let state = w.state().await;
    assert_eq!(state.incidents, 1);
    assert_eq!(state.blocked(), ["beta"]);

    // Confirmed an hour later, but beta is still under the incident: one
    // re-pin a run at most (BLOCKED_REPINS_PER_RUN), the rest stay.
    w.advance_secs(3600);
    let second = w.scrub().await;
    assert_eq!(
        second.repaired,
        velmora_bridge::scrub::BLOCKED_REPINS_PER_RUN
    );
    let mut held = 0;
    for o in &objs {
        held += u32::from(w.safety_state(o).await == "held");
    }
    assert_eq!(held, 1);

    // Beta comes back: 8 clean checks in a row clear the incident.
    for o in &objs {
        let plan = w.plan(o).await;
        w.servers[1].unhide(&plan[0].message_id).await;
    }
    w.advance_secs(3600);
    let third = w.scrub().await;
    // The one re-pinned in the second run is not due until its bound.
    assert_eq!((third.checked, third.ok, third.repaired), (8, 8, 0));
    assert_eq!(w.state().await.last_incident, None);
    assert!(w.state().await.blocked().is_empty());
}

/// A run checks at most `SCRUB_EXTENTS_PER_RUN` extents, the one
/// verified longest ago first; the next run goes on with the rest.
#[tokio::test(flavor = "current_thread")]
async fn a_run_checks_its_quota_oldest_verified_first() {
    let w = world_with(|cfg| cfg.scrub.extents_per_run = 2).await;
    let a = w.released("a", 20).await;
    w.advance_secs(DAY_SECS);
    let b = w.released("b", 21).await;
    w.advance_secs(DAY_SECS);
    let c = w.released("c", 22).await;
    w.advance_secs(40 * DAY_SECS);

    let run = w.scrub().await;
    assert_eq!((run.checked, run.ended), (2, ScrubEnd::Quota));
    assert_eq!(w.result(&a).await, "ok");
    assert_eq!(w.result(&b).await, "ok");
    assert_eq!(w.result(&c).await, "NULL");
    let next = w.scrub().await;
    assert_eq!(next.checked, 1);
    assert_eq!(w.result(&c).await, "ok");
}

/// One run at a time: a run while another holds the lease does nothing,
/// and the dispatcher sends a run only while the lease is free.
#[tokio::test(flavor = "current_thread")]
async fn one_run_at_a_time_and_the_dispatcher_sends_one_only_while_the_lease_is_free() {
    let w = world().await;
    let _ = w.released("a", 30).await;
    w.advance_secs(31 * DAY_SECS);
    let now = w.bridge().clock.now();
    let token = w
        .bridge()
        .catalog
        .scrub_take(now, now.plus_secs(600))
        .await
        .unwrap();
    assert!(token.is_some());
    assert_eq!(w.bridge().scrub_run().await.unwrap(), None);

    let report = w.bridge().dispatch().await.unwrap();
    assert!(!report.scrub_enqueued);
    assert!(!w
        .bridge()
        .jobs
        .inner
        .take()
        .iter()
        .any(|j| matches!(j.job, Job::Scrub { .. })));

    w.advance_secs(601);
    let report = w.bridge().dispatch().await.unwrap();
    assert!(report.scrub_enqueued);
    let sent = w.bridge().jobs.inner.take();
    assert_eq!(
        sent.iter()
            .filter(|j| matches!(j.job, Job::Scrub { .. }))
            .count(),
        1
    );
    // The job runs the scrub.
    assert_eq!(
        w.bridge().run_job(&Job::Scrub { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert_eq!(w.state().await.checked, 1);
}

/// `SCRUB=off` (the default): no run is sent, and a run job that arrives
/// does nothing.
#[tokio::test(flavor = "current_thread")]
async fn with_the_scrub_off_nothing_is_sent_and_no_extent_is_checked() {
    let w = world_with(|cfg| cfg.scrub.on = false).await;
    let o = w.released("a", 31).await;
    w.advance_secs(31 * DAY_SECS);
    let report = w.bridge().dispatch().await.unwrap();
    assert!(!report.scrub_enqueued);
    assert!(!w
        .bridge()
        .jobs
        .inner
        .take()
        .iter()
        .any(|j| matches!(j.job, Job::Scrub { .. })));
    assert_eq!(
        w.bridge().run_job(&Job::Scrub { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert_eq!(w.result(&o).await, "NULL");
    assert_eq!(w.state().await.runs, 0);
}

/// A repair that does not end (here: nothing runs the verify stage) is
/// looked at when it should have ended: `stalled`, with an alert, and a
/// safety copy that went missing meanwhile is written again from Usenet.
#[tokio::test(flavor = "current_thread")]
async fn a_repair_that_does_not_end_is_reported_stalled_and_its_safety_copy_kept() {
    let w = world().await;
    let o = w.released("a", 40).await;
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 0).await;
    w.scrub().await;
    w.advance_secs(3600);
    assert_eq!(w.scrub().await.repaired, 1);
    assert_eq!(w.safety_state(&o).await, "held");

    // An eviction that began before the re-pin took the copy.
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    let bound = repair_bound_secs(w.bridge().cfg.safety_min_age_secs, 3600);
    w.advance_secs(u32::try_from(bound).unwrap() - 1);
    let early = w.scrub().await;
    assert_eq!(
        (early.checked, early.stalled),
        (0, 0),
        "not due before the bound"
    );
    w.advance_secs(1);
    let run = w.scrub().await;
    assert_eq!(run.stalled, 1);
    assert_eq!(w.result(&o).await, "stalled");
    assert!(w.has_safety(&o), "written again from Usenet");
    assert!(alerts()
        .iter()
        .any(|a| a.starts_with("scrub-stalled ") && a.contains("written again")));

    // The pipeline then finishes the repair.
    w.drive(&o).await;
    assert_eq!(w.safety_state(&o).await, "released");
}

/// An extent of an object that was deleted is never read again and never
/// brought back: it is skipped, with nothing written to a blob store.
#[tokio::test(flavor = "current_thread")]
async fn an_extent_of_a_deleted_object_is_skipped_and_not_re_pinned() {
    let w = world().await;
    let o = w.released("a", 50).await;
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 0).await;
    assert_eq!(w.scrub().await.suspect, 1);
    w.rig
        .call(&w.signer, Method::Delete, &path(BUCKET, "a"), &[], &[], b"")
        .await
        .expect(204);
    w.advance_secs(3600);
    let puts = w.bridge().safety.puts.borrow().len();
    let run = w.scrub().await;
    assert_eq!((run.checked, run.repaired, run.bytes_read), (0, 0, 0));
    assert_eq!(w.result(&o).await, "skipped");
    assert_eq!(w.safety_state(&o).await, "released");
    assert_eq!(
        w.bridge().safety.puts.borrow().len(),
        puts,
        "no copy written"
    );
    // Not even selected again at the confirmation interval.
    w.advance_secs(3600);
    let catalog = &w.bridge().catalog;
    let labels = ["alpha".into(), "beta".into()];
    let now = w.bridge().clock.now();
    assert!(catalog.scrub_due(&labels, now, 8).await.unwrap().is_empty());

    // Once GC has marked it deleted, remove its indexed schedules.
    catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET safety_state = 'deleted' WHERE id = ?1",
            &[SqlValue::Text(o.extent.as_str().into())],
        )
        .await
        .unwrap();
    w.advance_secs(30 * DAY_SECS);
    assert_eq!(w.scrub().await.checked, 0);
    assert_eq!(
        w.scalar(
            "SELECT COUNT(*) FROM scrub_copies WHERE extent_id = ?1",
            &o.extent
        )
        .await,
        "0"
    );
}

/// A 20,000-row ready backlog still reads just one page and its PK joins.
#[tokio::test(flavor = "current_thread")]
async fn due_work_is_bounded_even_when_twenty_thousand_copies_are_due() {
    let w = world().await;
    let c = &w.bridge().catalog;
    let db = &c.sql.inner;
    let seed = db.fixture(
        "WITH RECURSIVE n(x) AS (VALUES (1) UNION ALL SELECT x+1 FROM n WHERE x < 20000) \
         INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at) \
         SELECT printf('fixture-%05d', x), ?1, 'committed', 1, 65, zeroblob(48), zeroblob(16), zeroblob(32), zeroblob(32), 'released', 0 FROM n",
        "INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at) \
         SELECT 'fixture-' || lpad(CAST(x AS text), 5, '0'), ?1, 'committed', 1, 65, \
           decode(repeat('00', 48), 'hex'), decode(repeat('00', 16), 'hex'), \
           decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), 'released', 0 \
         FROM generate_series(1, 20000) x",
    );
    db.fixture_exec(seed, &[SqlValue::Text(w.bucket.id.as_str().to_owned())])
        .await
        .unwrap();
    c.sql
        .inner
        .fixture_exec(
            "INSERT INTO scrub_copies(extent_id,backbone,stat_at,full_at,stat_phase_at,full_phase_at) \
         SELECT id, 'alpha', 0, 100, 0, 100 FROM extents",
            &[],
        )
        .await
        .unwrap();
    if db.dialect() == Dialect::Sqlite {
        let sqlite = db.sqlite();
        sqlite.reset_read_stats();
    }
    let due = c
        .scrub_due(&["alpha".into()], UnixMs(0), u32::MAX)
        .await
        .unwrap();
    assert_eq!(due.len(), 8);
    assert_eq!(due[0].extent.id.as_str(), "fixture-00001");
    assert_eq!(due[7].extent.id.as_str(), "fixture-00008");
    if db.dialect() == Dialect::Sqlite {
        let sqlite = db.sqlite();
        let reads = sqlite.read_stats();
        assert_eq!((reads.queries, reads.rows), (2, 8));
        assert!(
            reads.vm_steps < 1000,
            "an index page, not a scan: {reads:?}"
        );
    }
    #[cfg(feature = "testkit-pg")]
    if let Some(pg) = db.postgres() {
        let client = pg.client().await.unwrap();
        client
            .batch_execute(
                "UPDATE extents SET scrub_enrolled = 1 WHERE id < 'fixture-00201'; \
             UPDATE extents SET scrub_next_at = 0 WHERE id < 'fixture-00201'; \
             UPDATE extents SET safety_state = 'held' WHERE id >= 'fixture-00401'; \
             ANALYZE extents; ANALYZE scrub_copies;",
            )
            .await
            .unwrap();
        let binds: [&[&(dyn tokio_postgres::types::ToSql + Sync)]; 4] = [
            &[&"alpha", &0i64, &8i64],
            &[&0i64, &8i64],
            &[&"", &128i64],
            &[&"", &128i64],
        ];
        for ((query, args), index) in velmora_bridge::sql::scrub_range_queries(Dialect::Postgres)
            .into_iter()
            .zip(binds)
            .zip([
                "scrub_copies_due",
                "extents_scrub_watch",
                "extents_scrub_pending",
                "extents_scrub_enrolled",
            ])
        {
            let query = velmora_bridge::pg::normalize_statement(query).unwrap();
            let rows = client
                .query(&format!("EXPLAIN {query}"), args)
                .await
                .unwrap();
            let plan = rows
                .iter()
                .map(|r| r.get::<_, String>(0))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                plan.contains(index) && plan.contains("Index Cond:"),
                "{plan}"
            );
            assert!(!plan.contains("Seq Scan"), "{plan}");
        }
    }
}

/// What a healthy check costs the catalogue in rows written, as D1
/// bills them: one result row per extent, each STAT clock and its index
/// entry per copy, and per run the lease, its totals and provider slots.
/// The slots are a per-run cost: the sessions are kept from one extent
/// to the next, so a run of more extents does not take more of them.
#[tokio::test(flavor = "current_thread")]
async fn a_healthy_check_writes_its_result_and_the_run_its_slots() {
    let w = world_on(true, |_| {}).await;
    let mut objs = Vec::new();
    for i in 0..4u8 {
        objs.push(w.released(&format!("k{i}"), 60 + i).await);
    }
    w.advance_secs(31 * DAY_SECS);
    let db = w.bridge().catalog.sql.inner.sqlite();
    db.meter_writes().unwrap();
    let before = db.writes();
    let run = w.scrub().await;
    assert_eq!(run.ok, 4);
    let spent = db.writes().since(&before);
    let extents = spent.table("extents");
    let state = spent.table("scrub_state");
    let slots = spent.table("provider_permits") + spent.table("provider_health");
    println!(
        "rows written by a run of 4 healthy extents: {} (extents {extents}, scrub_state {state}, slots {slots})",
        spent.billed()
    );
    for (table, tally) in &spent.by_table {
        println!("  {table:?}: {}", tally.billed());
    }
    assert_eq!(extents, 4, "one summary row per extent");
    assert_eq!(state, 2, "the lease taken, the totals added");
    let copies = spent.table("scrub_copies");
    assert_eq!(copies, 4 * 2 * 2, "each STAT clock and its index entry");
    // Everything else is the run's provider slots, kept across extents.
    assert_eq!(spent.billed(), extents + copies + state + slots);
    let one = {
        let w = world_on(true, |_| {}).await;
        let _ = w.released("a", 70).await;
        w.advance_secs(31 * DAY_SECS);
        let db = w.bridge().catalog.sql.inner.sqlite();
        db.meter_writes().unwrap();
        let before = db.writes();
        assert_eq!(w.scrub().await.ok, 1);
        let spent = db.writes().since(&before);
        spent.table("provider_permits") + spent.table("provider_health")
    };
    assert_eq!(slots, one, "a run of 4 takes the slots a run of 1 does");
}

#[tokio::test(flavor = "current_thread")]
async fn write_meter_separates_enrollment_from_independent_copy_checks() {
    let w = world_on(true, |_| {}).await;
    let o = w.released_unenrolled("meter", 71).await;
    let c = &w.bridge().catalog;
    let now = w.bridge().clock.now();
    let interval = i64::from(DAY_SECS) * 1000;
    let db = c.sql.inner.sqlite();
    db.meter_writes().unwrap();
    let token = c.scrub_take(now, now.plus_secs(60)).await.unwrap().unwrap();
    let before = db.writes();
    c.scrub_enroll(
        token,
        &["alpha".into(), "beta".into()],
        now,
        [30 * interval, 90 * interval],
    )
    .await
    .unwrap();
    let spent = db.writes().since(&before);
    let enrollment = spent.table("extents") + spent.table("scrub_copies");
    println!("rows written per initial enrollment: {enrollment} (excluding run state)");
    assert_eq!(enrollment, 6);
    assert!(c.scrub_free(token, now).await.unwrap());
    let later = now.plus_secs(100 * DAY_SECS);
    w.set_clocks(&o, "beta", later, later).await;
    // A BODY pass also moves `last_verified_at` (H6): one row more.
    for (stat, full, kind, expected) in [(now, later, "STAT", 3), (later, now, "BODY", 4)] {
        w.set_clocks(&o, "alpha", stat, full).await;
        let before = db.writes();
        assert_eq!(w.scrub().await.ok, 1);
        let spent = db.writes().since(&before);
        let rows = spent.table("extents") + spent.table("scrub_copies");
        let overhead = spent.billed() - rows;
        println!("rows written per one-copy {kind} visit: {rows} (+{overhead} per run)");
        assert_eq!(rows, expected);
    }
}

/// While an incident on a backbone stands, a confirmed loss there is not
/// re-pinned beyond one a run, and a loss with no intact copy anywhere is
/// still said to be unrecoverable.
#[tokio::test(flavor = "current_thread")]
async fn under_an_incident_one_re_pin_a_run_and_unrecoverable_is_still_said() {
    let w = world().await;
    let kept = w.released("a", 80).await;
    let also = w.released("c", 82).await;
    let lost = w.released("b", 81).await;
    assert!(w.bridge().safety.lose(&lost.extent.safety_key()));
    w.advance_secs(31 * DAY_SECS);
    for o in [&kept, &also, &lost] {
        w.hide(0, o, 0).await;
        w.hide(1, o, 0).await;
    }
    assert_eq!(w.scrub().await.suspect, 3);
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec("UPDATE scrub_state SET last_incident = 'beta'", &[])
        .await
        .unwrap();
    w.advance_secs(3600);
    let run = w.scrub().await;
    assert_eq!((run.repaired, run.unrecoverable, run.suspect), (1, 1, 1));
    let held = [w.safety_state(&kept).await, w.safety_state(&also).await];
    assert_eq!(held.iter().filter(|s| *s == "held").count(), 1);
    assert_eq!(w.result(&lost).await, "unrecoverable");
    // The run checked fewer extents than a trip needs: the incident stands.
    assert_eq!(w.state().await.blocked(), ["beta"]);
}

/// A provider whose drill connections are all the reader may take: the
/// `STAT` session takes a background slot, so the reader is never short
/// of its own.
#[tokio::test(flavor = "current_thread")]
async fn the_stat_session_never_takes_a_drill_slot_the_reader_needs() {
    let w = world_with(|cfg| {
        for p in &mut cfg.providers {
            p.drill_conns = 1;
        }
        cfg.scrub.sockets = 1;
    })
    .await;
    let o = w.released("a", 90).await;
    let b = w.released("b", 92).await;
    w.advance_secs(31 * DAY_SECS);
    // `a` is due for STAT, `b` for a full read in the same run.
    w.full_checks_now(&b).await;
    let run = w.scrub().await;
    assert_eq!((run.checked, run.ok, run.ended), (2, 2, ScrubEnd::Idle));
    assert!(run.bytes_read > 0, "the full read ran");
    assert_eq!(w.result(&o).await, "ok");
    assert_eq!(w.result(&b).await, "ok");
}

/// A re-pinned extent whose watch found no intact copy anywhere stays
/// watched: once Usenet has it again, its safety copy is written back.
#[tokio::test(flavor = "current_thread")]
async fn a_watched_repair_without_any_copy_is_watched_again_and_restored() {
    let w = world().await;
    let o = w.released("a", 91).await;
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 0).await;
    w.scrub().await;
    w.advance_secs(3600);
    assert_eq!(w.scrub().await.repaired, 1);
    // The copy goes, and so does the article on the other backbone.
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    w.hide(0, &o, 0).await;
    let bound = repair_bound_secs(w.bridge().cfg.safety_min_age_secs, 3600);
    w.advance_secs(u32::try_from(bound).unwrap());
    assert_eq!(w.scrub().await.unrecoverable, 1);
    assert_eq!(w.result(&o).await, "unrecoverable");
    assert_eq!(w.safety_state(&o).await, "held");
    // Usenet has it again: the next look writes the copy back.
    let plan = w.plan(&o).await;
    w.servers[0].unhide(&plan[0].message_id).await;
    w.advance_secs(3600);
    let run = w.scrub().await;
    assert_eq!(run.stalled, 1);
    assert!(w.has_safety(&o), "written back from Usenet");
    assert_eq!(w.result(&o).await, "stalled");
}

/// A provider past its retention answers 430 for what it no longer keeps:
/// that is no loss of its backbone. Presence is asked of a provider that
/// retains the articles, as verify asks.
#[tokio::test(flavor = "current_thread")]
async fn a_provider_past_its_retention_is_not_asked_for_presence() {
    let short = server().await;
    let w = world_with(|cfg| {
        // First in its backbone's order, keeps 30 days, and has nothing.
        let mut p = provider("p0b", "alpha", &short);
        p.retention_days = Some(30);
        p.post = false;
        cfg.providers[0].priority = 1;
        cfg.providers.insert(0, p);
    })
    .await;
    // Posted, then on all three servers, then verified and released.
    let plain = pattern(92, PLAIN);
    w.rig.put(&w.signer, BUCKET, "a", &plain).await.expect(200);
    let (generation, extents) = w.rig.live(&w.bucket, "a").await.unwrap();
    let o = Obj {
        extent: extents[0].id.clone(),
        generation: generation.id,
        plain,
    };
    w.run(&o, OutboxStage::Post).await;
    w.mirror(&o).await;
    let addr = short.addr();
    let mut dst = dial(&nntp_config(
        &addr.ip().to_string(),
        addr.port(),
        USER,
        PASS,
    ))
    .await
    .unwrap();
    for row in w.plan(&o).await {
        let mut src = w.client(0).await;
        let mut article = Vec::new();
        src.article_to(&row.message_id, &mut article).await.unwrap();
        dst.post_article(&row.message_id, &article).await.unwrap();
        src.quit().await;
    }
    dst.quit().await;
    w.drive(&o).await;
    assert_eq!(w.safety_state(&o).await, "released");
    w.align_clocks(&o).await;
    // Past its 30 days the short account no longer has them.
    w.advance_secs(31 * DAY_SECS);
    for row in w.plan(&o).await {
        short.hide(&row.message_id).await;
    }
    let run = w.scrub().await;
    assert_eq!((run.checked, run.ok, run.suspect), (1, 1, 0));
    assert_eq!(w.result(&o).await, "ok");
}

/// A trip on a second backbone keeps the first one's block: no loss on
/// either is repaired until a clean run.
#[tokio::test(flavor = "current_thread")]
async fn incidents_on_two_backbones_block_both() {
    let w = world().await;
    let mut objs = Vec::new();
    for i in 0..8u8 {
        objs.push(w.released(&format!("k{i}"), 100 + i).await);
    }
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec("UPDATE scrub_state SET last_incident = '[\"alpha\"]'", &[])
        .await
        .unwrap();
    w.advance_secs(31 * DAY_SECS);
    for o in &objs {
        w.hide(1, o, 0).await;
    }
    let run = w.scrub().await;
    assert_eq!(run.incident.as_deref(), Some("beta"));
    assert_eq!(w.state().await.blocked(), ["alpha", "beta"]);
}

/// Every write of a run names its lease's token: one whose lease was
/// taken over writes nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_run_whose_lease_was_taken_writes_nothing() {
    let w = world().await;
    let o = w.released("a", 110).await;
    let c = &w.bridge().catalog;
    let now = w.bridge().clock.now();
    let old = c.scrub_take(now, now.plus_secs(10)).await.unwrap().unwrap();
    w.advance_secs(11);
    let now = w.bridge().clock.now();
    let new = c
        .scrub_take(now, now.plus_secs(600))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(old, new);
    let next = now.plus_secs(60);
    assert!(!c
        .scrub_record(old, &o.extent, ScrubResult::Ok, now, Some(next))
        .await
        .unwrap());
    assert!(!c.scrub_drop(old, &o.extent).await.unwrap());
    assert!(!c.scrub_defer(old, &o.extent, next).await.unwrap());
    assert!(!c
        .scrub_repin(old, &o.extent, (now, next), &[])
        .await
        .unwrap());
    assert!(!c.scrub_end(old, &ScrubRun::default(), now).await.unwrap());
    assert_eq!(w.result(&o).await, "NULL");
    assert_eq!(w.safety_state(&o).await, "released");
    assert_eq!(w.state().await.runs, 0);
    // The run that holds it writes.
    assert!(c
        .scrub_record(new, &o.extent, ScrubResult::Ok, now, Some(next))
        .await
        .unwrap());
}

/// The re-pin's guard: only a released extent whose posting is done and
/// that a live object holds.
#[tokio::test(flavor = "current_thread")]
async fn the_re_pin_is_refused_unless_released_done_and_live() {
    let w = world().await;
    let c = &w.bridge().catalog;
    let now = w.bridge().clock.now();
    let token = c
        .scrub_take(now, now.plus_secs(600))
        .await
        .unwrap()
        .unwrap();
    let at = (now, now.plus_secs(60));
    // Held: not yet released.
    let plain = pattern(111, PLAIN);
    w.rig
        .put(&w.signer, BUCKET, "held", &plain)
        .await
        .expect(200);
    let held = w.rig.live(&w.bucket, "held").await.unwrap().1.remove(0);
    assert!(!c.scrub_repin(token, &held.id, at, &[]).await.unwrap());
    // Released, but its outbox row is not `done`.
    let o = w.released_unenrolled("a", 112).await;
    c.sql
        .inner
        .fixture_exec(
            "UPDATE outbox SET stage = 'verify' WHERE extent_id = ?1",
            &[SqlValue::Text(o.extent.as_str().to_string())],
        )
        .await
        .unwrap();
    assert!(!c.scrub_repin(token, &o.extent, at, &[]).await.unwrap());
    // Released and done, but no live object holds it.
    let gone = w.released_unenrolled("b", 113).await;
    w.rig
        .call(&w.signer, Method::Delete, &path(BUCKET, "b"), &[], &[], b"")
        .await
        .expect(204);
    assert!(!c.scrub_repin(token, &gone.extent, at, &[]).await.unwrap());
    // Released, done and live: re-pinned.
    let ok = w.released_unenrolled("c", 114).await;
    assert!(c.scrub_repin(token, &ok.extent, at, &[]).await.unwrap());
    assert_eq!(w.safety_state(&ok).await, "held");
    assert_eq!(w.stage(&ok).await, "verify");
}

/// At most `SCRUB_REPAIRS_PER_RUN` re-pins in a run: the rest stay
/// `suspect` and come back at the confirm interval.
#[tokio::test(flavor = "current_thread")]
async fn a_run_re_pins_at_most_its_cap() {
    let w = world_with(|cfg| cfg.scrub.repairs_per_run = 1).await;
    let a = w.released("a", 120).await;
    let b = w.released("b", 121).await;
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &a, 0).await;
    w.hide(1, &b, 0).await;
    assert_eq!(w.scrub().await.suspect, 2);
    w.advance_secs(3600);
    let run = w.scrub().await;
    assert_eq!((run.repaired, run.suspect), (1, 1));
    let states = [w.safety_state(&a).await, w.safety_state(&b).await];
    assert_eq!(states.iter().filter(|s| *s == "held").count(), 1);
}

/// An eviction that began before the re-pin does not delete the safety
/// copy the re-pin put back: the delete asks again first.
#[tokio::test(flavor = "current_thread")]
async fn an_eviction_begun_before_the_re_pin_keeps_the_safety_copy() {
    let w = world().await;
    let o = w.released("a", 130).await;
    let c = &w.bridge().catalog;
    let listed = c.evict_candidates(100).await.unwrap();
    let mine = listed.into_iter().find(|x| x.extent == o.extent).unwrap();
    assert!(!mine.pinned);
    assert!(c.begin_evict(&mine).await.unwrap(), "the eviction begins");
    assert_eq!(
        c.evict_safety_still_ok(&mine, Some(&["alpha".to_owned(), "beta".to_owned()]))
            .await
            .unwrap(),
        EvictCheck::Delete,
        "not yet re-pinned"
    );
    let now = w.bridge().clock.now();
    let token = c
        .scrub_take(now, now.plus_secs(600))
        .await
        .unwrap()
        .unwrap();
    assert!(c
        .scrub_repin(token, &o.extent, (now, now.plus_secs(60)), &[])
        .await
        .unwrap());
    assert_eq!(
        c.evict_safety_still_ok(&mine, Some(&["alpha".to_owned(), "beta".to_owned()]))
            .await
            .unwrap(),
        EvictCheck::Moved,
        "re-pinned since the begin: the safety copy stays"
    );
    // A listing from before the re-pin cannot begin either.
    assert!(!c.begin_evict(&mine).await.unwrap());
}

/// Bodies no provider serves while every backbone answers `STAT`: the
/// re-pin records a failed full read on every backbone, so even the
/// light check reads them in full and releases nothing on `STAT` alone.
#[tokio::test(flavor = "current_thread")]
async fn bodies_no_provider_serves_are_never_released_on_stat_alone() {
    let w = world_with(|cfg| {
        cfg.verify.mode = velmora_bridge::config::VerifyMode::Light;
        cfg.verify.sample_ppm = 0;
    })
    .await;
    let o = w.released("a", 140).await;
    w.full_checks_now(&o).await;
    for s in &w.servers {
        s.set_body_gone(true).await;
    }
    assert_eq!(w.scrub().await.suspect, 1);
    w.advance_secs(3600);
    assert_eq!(
        w.scrub().await.repaired,
        1,
        "from the safety copy still in R2"
    );
    let failed = w
        .scalar(
            "SELECT COUNT(*) FROM verifications WHERE extent_id = ?1 AND provider_id = 'scrub' \
               AND kind = 'body' AND result = 'missing'",
            &o.extent,
        )
        .await;
    assert_eq!(failed, "2");
    for _ in 0..12 {
        let stage = w.stage(&o).await;
        if stage == "done" || stage == "dead" {
            break;
        }
        w.advance_secs(3600);
        w.run(&o, OutboxStage::parse(&stage).unwrap()).await;
    }
    assert_eq!(
        w.safety_state(&o).await,
        "held",
        "never released on STAT alone"
    );
    assert!(w.has_safety(&o));
}

/// A loss on a backbone no provider posts to: verify cannot put it back
/// there, so the operator is told; the extent is still re-pinned, since
/// `STAT` and a read assembled across providers do not prove that the
/// backbones left hold it whole.
#[tokio::test(flavor = "current_thread")]
async fn a_loss_nobody_can_post_is_re_pinned_and_said() {
    let third = server().await;
    let w = world_with(|cfg| {
        cfg.providers[1].post = false;
        let mut gamma = provider("p2", "gamma", &third);
        gamma.post = false;
        cfg.providers.push(gamma);
    })
    .await;
    let o = w.released_on(&[&third], "a", 150).await;
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 0).await;
    assert_eq!(w.scrub().await.suspect, 1);
    w.advance_secs(3600);
    let run = w.scrub().await;
    assert_eq!(run.repaired, 1);
    assert_eq!(w.safety_state(&o).await, "held");
    assert!(alerts()
        .iter()
        .any(|a| a.starts_with("scrub-unpostable ") && a.contains("lacking=[beta]")));
}

/// A check that still finds a loss on a backbone under an incident sets
/// the count of clean checks back: short runs do not clear an incident
/// that lasts.
#[tokio::test(flavor = "current_thread")]
async fn a_lasting_incident_is_not_cleared_by_short_runs() {
    let w = world().await;
    let a = w.released("a", 170).await;
    let b = w.released("b", 171).await;
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE scrub_state SET last_incident = '[\"beta\"]', incident_clean = 7",
            &[],
        )
        .await
        .unwrap();
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &a, 0).await;
    let run = w.scrub().await;
    assert_eq!(run.checked, 2);
    let state = w.state().await;
    assert_eq!(state.blocked(), ["beta"], "a or b still lacks there");
    assert!(state.incident_clean <= 1, "{}", state.incident_clean);
    // Clean checks in a row clear it.
    let plan = w.plan(&a).await;
    w.servers[1].unhide(&plan[0].message_id).await;
    for i in 0..8u8 {
        let _ = w.released(&format!("c{i}"), 172 + i).await;
    }
    w.advance_secs(31 * DAY_SECS);
    let _ = w.scrub().await;
    assert!(w.state().await.blocked().is_empty());
    let _ = b;
}

/// A provider without drill connections whose one background slot the
/// run's `STAT` session holds: the read gets it, and the run goes on.
#[tokio::test(flavor = "current_thread")]
async fn the_read_gets_the_slot_the_stat_session_held() {
    let w = world_with(|cfg| {
        for p in &mut cfg.providers {
            p.drill_conns = 0;
            p.max_conns = 2;
        }
        cfg.scrub.sockets = 1;
    })
    .await;
    let o = w.released("a", 190).await;
    let p = w.released("b", 191).await;
    let q = w.released("c", 192).await;
    w.advance_secs(31 * DAY_SECS);
    // STAT, then a full read, then STAT again, on the same constrained
    // providers: each needs the slot the one before it kept.
    let now = w.bridge().clock.now();
    let far = now.plus_secs(60 * DAY_SECS);
    for name in ["alpha", "beta"] {
        w.set_clocks(&o, name, now.plus_ms(-3000), far).await;
        w.set_clocks(&p, name, far, now.plus_ms(-2000)).await;
        w.set_clocks(&q, name, now.plus_ms(-1000), far).await;
    }
    let run = w.scrub().await;
    assert_eq!((run.checked, run.ok, run.ended), (3, 3, ScrubEnd::Idle));
    assert!(run.bytes_read > 0, "the full read ran");
    for x in [&o, &p, &q] {
        assert_eq!(w.result(x).await, "ok");
    }
}

/// All scheduler listings use bounded ranges on their actual indexes.
#[tokio::test(flavor = "current_thread")]
async fn scheduler_queries_use_indexed_ranges_without_sorting() {
    let w = world_on(true, |_| {}).await;
    use SqlValue::{Int, Text};
    let cases = [
        (
            "scrub_copies_due",
            vec![Text("alpha".into()), Int(0), Int(8)],
        ),
        ("extents_scrub_watch", vec![Int(0), Int(8)]),
        ("extents_scrub_pending", vec![Text(String::new()), Int(128)]),
        (
            "extents_scrub_enrolled",
            vec![Text(String::new()), Int(128)],
        ),
    ];
    for (query, (index, bind)) in velmora_bridge::sql::scrub_range_queries(Dialect::Sqlite)
        .into_iter()
        .zip(cases)
    {
        let sql = format!("EXPLAIN QUERY PLAN {query}");
        let plan = w
            .bridge()
            .catalog
            .sql
            .inner
            .fixture_query(&sql, &bind)
            .await
            .unwrap();
        let text = format!("{plan:?}");
        assert!(text.contains("SEARCH ") && text.contains(index), "{text}");
        assert!(
            !text.contains("TEMP B-TREE") && !text.contains("SCAN "),
            "{text}"
        );
    }
}

/// Two backbones whose providers share one pool of slots: the run's kept
/// `STAT` session of one is given up for the other, so the run is not
/// stopped by its own sessions.
#[tokio::test(flavor = "current_thread")]
async fn backbones_that_share_a_pool_are_both_asked() {
    let w = world_with(|cfg| {
        for p in &mut cfg.providers {
            p.pool = Some("shared".to_string());
            p.pool_max_conns = Some(2);
        }
        cfg.scrub.sockets = 2;
    })
    .await;
    let a = w.released("a", 160).await;
    let b = w.released("b", 161).await;
    w.advance_secs(31 * DAY_SECS);
    let run = w.scrub().await;
    assert_eq!((run.checked, run.ok, run.ended), (2, 2, ScrubEnd::Idle));
    assert_eq!(w.result(&a).await, "ok");
    assert_eq!(w.result(&b).await, "ok");
}

/// A re-pinned extent whose object was deleted meanwhile is left to
/// garbage collection: the watch writes no copy back for it.
#[tokio::test(flavor = "current_thread")]
async fn the_watch_leaves_an_extent_of_a_deleted_object_alone() {
    let w = world().await;
    let o = w.released("a", 162).await;
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 0).await;
    w.scrub().await;
    w.advance_secs(3600);
    assert_eq!(w.scrub().await.repaired, 1);
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    w.rig
        .call(&w.signer, Method::Delete, &path(BUCKET, "a"), &[], &[], b"")
        .await
        .expect(204);
    let puts = w.bridge().safety.puts.borrow().len();
    let bound = repair_bound_secs(w.bridge().cfg.safety_min_age_secs, 3600);
    w.advance_secs(u32::try_from(bound).unwrap());
    let run = w.scrub().await;
    assert_eq!((run.stalled, run.unrecoverable, run.bytes_read), (0, 0, 0));
    assert_eq!(
        w.bridge().safety.puts.borrow().len(),
        puts,
        "no copy written"
    );
    assert_eq!(w.next_at(&o).await, None, "off the due list");
}

/// The re-pin's guard asks for `released` itself: a held extent whose
/// posting is done and that a live object holds is not re-pinned.
#[tokio::test(flavor = "current_thread")]
async fn a_held_extent_whose_posting_is_done_is_not_re_pinned() {
    let w = world().await;
    let o = w.released("a", 200).await;
    let c = &w.bridge().catalog;
    c.sql
        .inner
        .fixture_exec(
            "UPDATE extents SET safety_state = 'held', evict_seq = evict_seq + 1 WHERE id = ?1",
            &[SqlValue::Text(o.extent.as_str().to_string())],
        )
        .await
        .unwrap();
    assert_eq!(w.stage(&o).await, "done");
    let now = w.bridge().clock.now();
    let token = c
        .scrub_take(now, now.plus_secs(600))
        .await
        .unwrap()
        .unwrap();
    assert!(!c
        .scrub_repin(token, &o.extent, (now, now.plus_secs(60)), &[])
        .await
        .unwrap());
}

/// The re-pin counts the copy it puts back as pinned bytes of the
/// extent: an extent whose released copy was evicted (count 0) has it
/// counted again.
#[tokio::test(flavor = "current_thread")]
async fn the_re_pin_counts_the_copy_it_puts_back() {
    let w = world().await;
    let o = w.released("a", 201).await;
    let c = &w.bridge().catalog;
    c.sql
        .inner
        .fixture_exec(
            "UPDATE extents SET hot_safety_bytes = 0 WHERE id = ?1",
            &[SqlValue::Text(o.extent.as_str().to_string())],
        )
        .await
        .unwrap();
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 0).await;
    w.scrub().await;
    w.advance_secs(3600);
    assert_eq!(w.scrub().await.repaired, 1);
    let counted = w
        .scalar(
            "SELECT hot_safety_bytes = cipher_size FROM extents WHERE id = ?1",
            &o.extent,
        )
        .await;
    assert_eq!(counted, "1");
}

/// A copy that cannot be written back after the re-pin is tried again,
/// and said when it still is not there; the extent stays pinned for the
/// watch.
#[tokio::test(flavor = "current_thread")]
async fn a_copy_that_cannot_be_written_back_is_tried_again_and_said() {
    let w = world().await;
    let o = w.released("a", 202).await;
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 0).await;
    w.scrub().await;
    w.advance_secs(3600);
    *w.bridge().safety.fail_put_prefix.borrow_mut() = Some("x/".to_string());
    let puts = w.bridge().safety.puts.borrow().len();
    assert_eq!(w.scrub().await.repaired, 1);
    assert_eq!(
        w.bridge().safety.puts.borrow().len(),
        puts + 2,
        "tried twice"
    );
    assert!(alerts()
        .iter()
        .any(|a| a.starts_with("scrub-repair-copy-missing ")));
    assert_eq!(w.safety_state(&o).await, "held");
    // Looked at again after the confirm interval, not at the bound.
    assert_eq!(
        w.next_at(&o).await,
        Some(w.bridge().clock.now().0 + 3_600_000)
    );
    *w.bridge().safety.fail_put_prefix.borrow_mut() = None;
    let repinned_at = w.scrubbed_at(&o).await.unwrap();
    w.advance_secs(3600);
    // The early look writes the copy; the repair has not stalled, and is
    // due again at its own bound.
    let early = w.scrub().await;
    assert_eq!(early.stalled, 0);
    assert!(w.has_safety(&o), "written by the watch");
    assert_eq!(w.result(&o).await, "repairing");
    let bound = repair_bound_secs(w.bridge().cfg.safety_min_age_secs, 3600) as i64;
    assert_eq!(w.next_at(&o).await, Some(repinned_at + bound * 1000));
}

/// The scrub's reader never takes the read slot a request's cold read is
/// kept: with that slot held by a request, the run still reads.
#[tokio::test(flavor = "current_thread")]
async fn the_scrub_never_takes_the_read_reserve() {
    let w = world_with(|cfg| {
        for p in &mut cfg.providers {
            p.drill_conns = 0;
            p.max_conns = 2;
        }
        cfg.scrub.sockets = 1;
    })
    .await;
    let o = w.released("a", 203).await;
    w.advance_secs(31 * DAY_SECS);
    // A full read too, not only STAT.
    let now = w.bridge().clock.now();
    for name in ["alpha", "beta"] {
        w.set_clocks(&o, name, now, now).await;
    }
    for p in w.bridge().cfg.providers.clone() {
        let held = w
            .bridge()
            .catalog
            .acquire_permit(&p, PermitClass::Read, "get:someone", now)
            .await
            .unwrap();
        assert!(held.is_some(), "the read reserve of {}", p.id);
    }
    // Any take of a read slot fails from here on: the run must take none.
    *w.bridge().catalog.sql.fail_matching.borrow_mut() = Some(("ORDER BY slot DESC", 0));
    let run = w.scrub().await;
    *w.bridge().catalog.sql.fail_matching.borrow_mut() = None;
    assert_eq!((run.checked, run.ok, run.ended), (1, 1, ScrubEnd::Idle));
    assert!(
        run.bytes_read > 0,
        "the full read ran without the read reserve"
    );
    assert_eq!(w.result(&o).await, "ok");
}

/// The eviction job, begun before a re-pin, deletes the cache copy but not
/// the safety copy the re-pin keeps.
#[tokio::test(flavor = "current_thread")]
async fn the_eviction_job_keeps_the_safety_copy_of_an_extent_re_pinned_under_it() {
    let w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 204).await;
    assert!(w.has_safety(&o));
    // Right before the eviction asks whether the copy may still go, the
    // scrub re-pins the extent.
    *w.bridge().catalog.sql.before_matching.borrow_mut() = Some((
        "FROM extents WHERE id = ?1 AND evict_seq = ?2",
        0,
        format!(
            "UPDATE extents SET safety_state = 'held', evict_seq = evict_seq + 1 WHERE id = '{}'",
            o.extent.as_str()
        ),
    ));
    w.bridge().evict_batch(0).await.unwrap();
    assert!(
        w.bridge().catalog.sql.before_matching.borrow().is_none(),
        "the eviction asked"
    );
    assert!(w.has_safety(&o), "the safety copy stays");
}

/// A BODY interruption defers the first extent without changing the due
/// clocks. After both backbones fail, the rest of their backlog waits for
/// the next run rather than repeating the same probes.
#[tokio::test(flavor = "current_thread")]
async fn a_read_that_breaks_off_leaves_its_backbone_due_for_the_next_run() {
    let w = world().await;
    let a = w.released("a", 205).await;
    let b = w.released("b", 206).await;
    let first_due = w.bridge().clock.now();
    w.full_checks_now(&a).await;
    w.advance_secs(1);
    w.full_checks_now(&b).await;
    for s in &w.servers {
        s.drop_next_bodies(1000).await;
    }
    let run = w.scrub().await;
    assert_eq!((run.checked, run.ended), (0, ScrubEnd::Idle));
    assert_eq!(w.result(&a).await, "deferred");
    assert_eq!(w.result(&b).await, "NULL");
    for (s, backbone) in w.servers.iter().zip(["alpha", "beta"]) {
        assert_eq!(w.clocks(&a, backbone).await.1, first_due);
        assert_eq!(w.clocks(&b, backbone).await.1, first_due.plus_secs(1));
        s.drop_next_bodies(0).await;
    }
    let again = w.scrub().await;
    assert_eq!(again.ok, 2);
}

/// The extent at which the breaker trips is classified like any other
/// confirmed loss: with no intact copy anywhere it is `unrecoverable`,
/// not left `suspect`.
#[tokio::test(flavor = "current_thread")]
async fn the_extent_that_trips_the_breaker_is_still_found_unrecoverable() {
    let w = world().await;
    let mut objs = Vec::new();
    for i in 0..8u8 {
        let o = w.released(&format!("k{i}"), 210 + i).await;
        assert!(w.bridge().safety.lose(&o.extent.safety_key()));
        objs.push(o);
    }
    w.advance_secs(31 * DAY_SECS);
    for o in &objs {
        w.hide(0, o, 0).await;
        w.hide(1, o, 0).await;
    }
    assert_eq!(w.scrub().await.ended, ScrubEnd::Incident);
    w.advance_secs(3600);
    let run = w.scrub().await;
    assert_eq!(run.ended, ScrubEnd::Incident);
    assert_eq!(run.unrecoverable, 8);
    for o in &objs {
        assert_eq!(w.result(o).await, "unrecoverable");
    }
}

/// A trip is stored at once: a run whose end is never written still
/// leaves the next one blocked.
#[tokio::test(flavor = "current_thread")]
async fn a_trip_is_stored_when_it_happens() {
    let w = world().await;
    let mut objs = Vec::new();
    for i in 0..8u8 {
        objs.push(w.released(&format!("k{i}"), 220 + i).await);
    }
    w.advance_secs(31 * DAY_SECS);
    for o in &objs {
        w.hide(1, o, 0).await;
    }
    *w.bridge().catalog.sql.fail_matching.borrow_mut() =
        Some(("UPDATE scrub_state SET lease_until = NULL", 0));
    assert_eq!(w.scrub().await.ended, ScrubEnd::Incident);
    *w.bridge().catalog.sql.fail_matching.borrow_mut() = None;
    let state = w.state().await;
    assert_eq!(state.runs, 0, "the end was not written");
    assert_eq!(state.blocked(), ["beta"]);
}

/// From the cache copy (the last copy), the safety copy is written before
/// the re-pin and kept even if the guard refuses the re-pin.
#[tokio::test(flavor = "current_thread")]
async fn a_cache_sourced_copy_is_written_first_and_kept_when_refused() {
    let w = world().await;
    let o = w.released("a", 230).await;
    let cipher = w
        .bridge()
        .safety
        .stored(&o.extent.safety_key())
        .unwrap()
        .bytes;
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;
    w.scrub().await;
    // The read that fills the cache comes after the first sighting:
    // at the sighting the scrub writes a fill that is the only R2 copy
    // to the safety store itself (`scrub-protect`).
    w.bridge()
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    // The guard will refuse: the outbox row is not `done`.
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE outbox SET stage = 'verify' WHERE extent_id = ?1",
            &[SqlValue::Text(o.extent.as_str().to_string())],
        )
        .await
        .unwrap();
    w.advance_secs(3600);
    let puts = w.bridge().safety.puts.borrow().len();
    let run = w.scrub().await;
    assert_eq!(run.repaired, 0);
    assert_eq!(
        w.bridge().safety.puts.borrow().len(),
        puts + 1,
        "written first"
    );
    assert!(w.has_safety(&o), "kept even though the re-pin was refused");
    assert_eq!(w.result(&o).await, "suspect");
}

#[tokio::test(flavor = "current_thread")]
async fn a_transient_safety_read_then_lease_loss_does_not_delete_the_copy() {
    let w = world().await;
    let o = w.released("a", 231).await;
    let bridge = w.bridge();
    let safety = &bridge.safety;
    let safety_key = o.extent.safety_key();
    let cipher = safety.stored(&safety_key).unwrap().bytes;
    let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    bridge
        .cache
        .put(&o.extent.cache_key(), cipher.clone(), &meta)
        .await
        .unwrap();
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;
    assert_eq!(w.scrub().await.repaired, 0);
    w.advance_secs(bridge.cfg.scrub.confirm_secs);

    // Fail the next safety GET, then pause the cache-sourced PUT so
    // another run can take the scrub lease.
    safety.fail_next_get.set(true);
    safety.hold_put_prefix.replace(Some(safety_key.clone()));
    let run = w.scrub();
    tokio::pin!(run);
    let take_lease = async {
        while !safety.held.get() {
            tokio::task::yield_now().await;
        }
        assert!(!safety.fail_next_get.get(), "the safety GET failed");
        bridge
            .clock
            .advance_ms(velmora_bridge::jobtable::JOB_MAX_AGE_MS + 1);
        let now = bridge.clock.now();
        bridge
            .catalog
            .scrub_take(now, now.plus_secs(60))
            .await
            .unwrap()
            .expect("another run took over the expired lease");
        safety.hold_put_prefix.replace(None);
    };
    tokio::select! {
        () = take_lease => {}
        _ = &mut run => panic!("scrub finished without writing the cached copy"),
    }
    assert_eq!(run.await.repaired, 0);
    assert_eq!(w.safety_state(&o).await, "released");
    let stored = safety
        .stored(&safety_key)
        .expect("the safety copy must survive a refused re-pin after a transient GET error");
    assert!(stored.bytes == cipher, "the safety copy must stay intact");
}

#[tokio::test(flavor = "current_thread")]
async fn cache_repair_does_not_leave_a_copy_after_gc_collects_the_extent() {
    let w = world_with(|cfg| cfg.gc_mode = velmora_bridge::config::GcMode::Disposable).await;
    let o = w.released("a", 232).await;
    let bridge = w.bridge();
    let safety = &bridge.safety;
    let safety_key = o.extent.safety_key();
    let cipher = safety.stored(&safety_key).unwrap().bytes;
    assert!(safety.lose(&safety_key));
    let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;
    assert_eq!(w.scrub().await.repaired, 0);
    // The read that fills the cache comes after the first sighting:
    // at the sighting the scrub writes a fill that is the only R2 copy
    // to the safety store itself (`scrub-protect`).
    bridge
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    w.advance_secs(bridge.cfg.scrub.confirm_secs);

    safety.hold_put_prefix.replace(Some(safety_key));
    let run = w.scrub();
    tokio::pin!(run);
    let collect = async {
        while !safety.held.get() {
            tokio::task::yield_now().await;
        }
        w.rig
            .call(&w.signer, Method::Delete, &path(BUCKET, "a"), &[], &[], b"")
            .await
            .expect(204);
        assert_eq!(
            bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
            JobOutcome::Ack
        );
        assert_eq!(w.safety_state(&o).await, "deleted");
        safety.hold_put_prefix.replace(None);
    };
    tokio::select! {
        () = collect => {}
        _ = &mut run => panic!("scrub finished without writing the cached copy"),
    }
    assert_eq!(run.await.repaired, 0);
    assert!(w.has_safety(&o), "scrub leaves cleanup to GC");
    assert_eq!(
        bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert!(!w.has_safety(&o), "GC also collects the replacement");
}

#[tokio::test(flavor = "current_thread")]
async fn cache_repair_after_gc_blob_delete_leaves_a_fresh_gc_obligation() {
    cache_repair_during_gc(None, 1).await;
}

#[tokio::test(flavor = "current_thread")]
async fn refused_cache_repair_retries_a_failed_gc_enqueue() {
    cache_repair_during_gc(Some(Trip::Fail), 1).await;
}

#[tokio::test(flavor = "current_thread")]
async fn refused_cache_repair_gc_drains_both_rows_after_an_enqueue_reply_is_lost() {
    cache_repair_during_gc(Some(Trip::Lost), 2).await;
}

async fn cache_repair_during_gc(enqueue_fault: Option<Trip>, expected_obligations: usize) {
    let w = world_with(|cfg| cfg.gc_mode = velmora_bridge::config::GcMode::Disposable).await;
    let o = w.released("a", 233).await;
    let bridge = w.bridge();
    let safety = &bridge.safety;
    let key = o.extent.safety_key();
    let cipher = safety.stored(&key).unwrap().bytes;
    let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    bridge
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;
    assert_eq!(w.scrub().await.repaired, 0);
    w.advance_secs(bridge.cfg.scrub.confirm_secs);

    safety.fail_next_get.set(true);
    safety.hold_put_prefix.replace(Some(key.clone()));
    let run = w.scrub();
    tokio::pin!(run);
    let delete_before_put = async {
        while !safety.held.get() {
            tokio::task::yield_now().await;
        }
        assert!(!safety.fail_next_get.get(), "the safety GET failed");
        w.rig
            .call(&w.signer, Method::Delete, &path(BUCKET, "a"), &[], &[], b"")
            .await
            .expect(204);
        let now = bridge.clock.now();
        let old = bridge
            .catalog
            .gc_due(now, 10, true)
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.action == GcAction::DeleteSafety)
            .unwrap();
        assert!(matches!(
            bridge.catalog.gc_begin(&old, now).await.unwrap(),
            GcStep::DeleteBlob { store: BlobStoreKind::Safety, key: gc_key } if gc_key == key
        ));
        safety.delete(&key).await.unwrap();
        if let Some(fault) = enqueue_fault {
            // Let the R2 PUT and guarded re-pin batch run; trip the
            // first enqueue either before it commits or on its reply.
            w.rig.trip().arm(2, fault);
        }
        safety.hold_put_prefix.replace(None);
        old
    };
    let old = tokio::select! {
        old = delete_before_put => old,
        _ = &mut run => panic!("scrub finished without writing the cached copy"),
    };
    assert_eq!(run.await.repaired, 0);
    assert!(
        w.has_safety(&o),
        "scrub must not delete after a transient GET error"
    );
    assert_eq!(
        w.safety_state(&o).await,
        "released",
        "old GC still in flight"
    );
    let now = bridge.clock.now();
    bridge.catalog.gc_done(old.id, now).await.unwrap();
    assert!(
        w.has_safety(&o),
        "the old GC delete preceded the replacement"
    );
    let due = bridge.catalog.gc_due(now, 10, true).await.unwrap();
    assert!(!due.iter().any(|row| row.id == old.id), "old row is closed");
    assert_eq!(
        due.iter()
            .filter(|row| row.extent_id == o.extent && row.action == GcAction::DeleteSafety)
            .count(),
        expected_obligations,
        "the old completion must not close the replacement's GC obligation(s)"
    );
    assert_eq!(
        bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert!(
        !w.has_safety(&o),
        "a later GC pass collects the replacement"
    );
    assert_eq!(
        w.rig
            .count("gc WHERE action = 'delete_safety' AND done_at IS NULL"),
        0,
        "GC completes every safety obligation, including a duplicate"
    );
}

/// A clean check carries the count of clean checks across runs: at 8 in a
/// row the incident clears, however short the runs.
#[tokio::test(flavor = "current_thread")]
async fn clean_checks_count_across_runs() {
    let w = world().await;
    let _ = w.released("a", 240).await;
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE scrub_state SET last_incident = '[\"beta\"]', incident_clean = 7",
            &[],
        )
        .await
        .unwrap();
    w.advance_secs(31 * DAY_SECS);
    assert_eq!(w.scrub().await.ok, 1);
    assert!(w.state().await.blocked().is_empty(), "7 + 1 clean checks");
}

/// A run that fails before its first extent gives the lease back and
/// leaves the incidents as they were.
#[tokio::test(flavor = "current_thread")]
async fn a_run_that_fails_at_its_start_keeps_the_incidents() {
    let w = world().await;
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec("UPDATE scrub_state SET last_incident = '[\"beta\"]'", &[])
        .await
        .unwrap();
    *w.bridge().catalog.sql.fail_matching.borrow_mut() =
        Some(("SELECT lease_token, lease_until", 0));
    assert!(w.bridge().scrub_run().await.is_err());
    *w.bridge().catalog.sql.fail_matching.borrow_mut() = None;
    let state = w.state().await;
    assert_eq!(state.blocked(), ["beta"]);
    assert_eq!(state.lease_until, None, "the lease is free");
}

/// A backbone that answers `STAT` for every article but whose provider
/// does not serve one whole is a loss there too: after the re-pin it gets
/// a failed full read, so no release counts it on `STAT` alone.
#[tokio::test(flavor = "current_thread")]
async fn a_backbone_that_does_not_serve_what_it_says_it_holds_is_read_in_full() {
    let w = world().await;
    let o = w.released("a", 250).await;
    w.full_checks_now(&o).await;
    // Alpha serves no body (but answers STAT); beta serves them all.
    w.servers[0].set_body_gone(true).await;
    let first = w.scrub().await;
    assert_eq!(first.suspect, 1, "a loss, not ok");
    w.advance_secs(3600);
    assert_eq!(w.scrub().await.repaired, 1);
    assert_eq!(w.scrub_failures(&o).await, ["alpha"]);
    assert!(alerts().iter().any(|a| a.contains("lacking=[alpha]")));
}

/// A loss seen once (`suspect`) whose second look breaks off stays
/// confirmed: the read that broke off records nothing over it, the next
/// look that finds the loss re-pins the extent, and looks that keep
/// breaking off are said once the last look that ended is two confirm
/// intervals old.
#[tokio::test(flavor = "current_thread")]
async fn a_confirmed_loss_stays_confirmed_through_a_read_that_breaks_off() {
    let w = world().await;
    let o = w.released("a", 251).await;
    // No copy in R2: the repair has to come from Usenet.
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 1).await;
    assert_eq!(w.scrub().await.suspect, 1);
    let seen = w.scrubbed_at(&o).await;
    let deferred = |id: &str| {
        alerts()
            .iter()
            .filter(|a| a.starts_with("scrub-deferred ") && a.contains(id))
            .count()
    };

    // The second look breaks off (no body served anywhere).
    w.advance_secs(3600);
    for s in &w.servers {
        s.drop_next_bodies(1000).await;
    }
    let broken = w.scrub().await;
    assert_eq!(broken.repaired, 0);
    assert_eq!(w.result(&o).await, "suspect", "the loss stays on record");
    assert_eq!(w.scrubbed_at(&o).await, seen, "the last look that ended");
    assert_eq!(deferred(o.extent.as_str()), 0, "once is not said");

    // Again, more than two confirm intervals after the look that ended.
    w.advance_secs(3700);
    w.scrub().await;
    assert_eq!(w.result(&o).await, "suspect");
    assert_eq!(
        deferred(o.extent.as_str()),
        1,
        "looks that keep breaking off"
    );

    // The next look that reads it confirms the loss and re-pins.
    for s in &w.servers {
        s.drop_next_bodies(0).await;
    }
    w.advance_secs(3600);
    let run = w.scrub().await;
    assert_eq!(run.repaired, 1, "confirmed by the look before the break");
    assert_eq!(w.result(&o).await, "repairing");
    assert_eq!(w.safety_state(&o).await, "held");
    assert!(w.has_safety(&o), "the copy is back, read from alpha");
}

// ---------------------------------------------------------------------------
// Review fixes: parity repair, blob-lifetime races, a bad plan, H6 stamp
// ---------------------------------------------------------------------------

/// Plaintext of three data articles: their extent gets a parity article.
const PARITY_PLAIN: usize = 1_500_000;

/// Lost on every backbone, within the extent's parity, with no copy in
/// R2: the repair read rebuilds the lost article from parity. The extent
/// is re-pinned from the rebuilt bytes, not said to be unrecoverable.
#[tokio::test(flavor = "current_thread")]
async fn a_loss_on_every_backbone_within_its_parity_is_rebuilt_not_lost() {
    let w = world_with(|cfg| {
        cfg.packed_plans = true;
        cfg.parity = true;
    })
    .await;
    let o = w.released_sized("a", 241, PARITY_PLAIN).await;
    w.align_clocks(&o).await;
    let all = w.all_articles(&o).await;
    let data = w.plan(&o).await.len();
    assert!(all.len() > data, "the extent has parity articles");
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    assert!(!w.bridge().cache.contains(&o.extent.cache_key()));
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 1).await;
    w.hide(1, &o, 1).await;

    assert_eq!(w.scrub().await.suspect, 1);
    w.advance_secs(3600);
    let run = w.scrub().await;
    assert_eq!((run.repaired, run.unrecoverable), (1, 0), "{:?}", alerts());
    assert_eq!(w.result(&o).await, "repairing");
    assert_eq!(w.safety_state(&o).await, "held");
    assert!(w.has_safety(&o), "the rebuilt copy is pinned in R2");
    assert!(
        alerts()
            .iter()
            .any(|a| a.starts_with("scrub-repair ") && a.contains("source=parity")),
        "{:?}",
        alerts()
    );
    assert!(!alerts()
        .iter()
        .any(|a| a.starts_with("scrub-unrecoverable ")));
}

/// The repair watch of a re-pinned parity extent whose safety copy is
/// gone rebuilds it from parity too.
#[tokio::test(flavor = "current_thread")]
async fn the_repair_watch_rebuilds_a_missing_copy_from_parity() {
    let w = world_with(|cfg| {
        cfg.packed_plans = true;
        cfg.parity = true;
    })
    .await;
    let o = w.released_sized("a", 247, PARITY_PLAIN).await;
    w.align_clocks(&o).await;
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 1).await;
    w.hide(1, &o, 1).await;
    w.scrub().await;
    w.advance_secs(3600);
    // The re-pin cannot write its copy: the watch looks again early.
    *w.bridge().safety.fail_put_prefix.borrow_mut() = Some("x/".to_string());
    assert_eq!(w.scrub().await.repaired, 1);
    assert!(!w.has_safety(&o));
    *w.bridge().safety.fail_put_prefix.borrow_mut() = None;
    w.advance_secs(3600);
    let early = w.scrub().await;
    assert_eq!(
        (early.unrecoverable, early.stalled),
        (0, 0),
        "{:?}",
        alerts()
    );
    assert!(
        w.has_safety(&o),
        "rebuilt from parity and written by the watch"
    );
    assert_eq!(w.result(&o).await, "repairing");
}

/// The eviction job is paused right after its catalogue check, at the
/// delete of the safety copy. The scrub then confirms a loss on every
/// backbone and re-pins the extent from that copy, its last intact one.
/// The delete that follows must not take the copy of the re-pinned
/// extent. (Before the fix the check passed, and the copy was deleted
/// after the re-pin.)
#[tokio::test(flavor = "current_thread")]
async fn an_eviction_paused_after_its_check_cannot_delete_a_copy_the_scrub_re_pins() {
    use std::cell::Cell;
    use std::rc::Rc;
    let w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 242).await;
    assert!(w.has_safety(&o));
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;
    assert_eq!(w.scrub().await.suspect, 1);
    w.advance_secs(3600);

    let paused = Rc::new(Cell::new(false));
    let go = Rc::new(Cell::new(false));
    {
        let (paused, go, key) = (paused.clone(), go.clone(), o.extent.safety_key());
        *w.bridge().safety.before_delete_async.borrow_mut() = Some(Box::new(move |k: String| {
            Box::pin(async move {
                if k == key {
                    paused.set(true);
                    while !go.get() {
                        tokio::task::yield_now().await;
                    }
                }
            })
        }));
    }
    let evict = w.bridge().evict_batch(0);
    tokio::pin!(evict);
    let at_delete = async {
        while !paused.get() {
            tokio::task::yield_now().await;
        }
    };
    let mid_delete = tokio::select! {
        r = &mut evict => {
            r.unwrap();
            false
        }
        () = at_delete => true,
    };
    // The eviction is past its check (paused at the delete), or it is
    // over and kept the copy.
    let run = w.scrub().await;
    assert_eq!(run.repaired, 1);
    assert!(alerts().iter().any(|a| a.contains("source=safety")));
    go.set(true);
    if mid_delete {
        evict.await.unwrap();
    }
    assert_eq!(w.safety_state(&o).await, "held");
    assert!(
        w.has_safety(&o),
        "the re-pinned extent keeps its last intact copy"
    );
}

/// An eviction past its check before any loss was on record ends within
/// one queue invocation. A loss first seen after that check is not
/// re-pinned before such an eviction can still be deleting: the scrub
/// waits two invocation lifetimes from the first sighting, whatever the
/// confirm interval (short here, as in dev).
#[tokio::test(flavor = "current_thread")]
async fn a_loss_first_seen_under_a_running_eviction_is_not_re_pinned_before_it_ends() {
    use std::cell::Cell;
    use std::rc::Rc;
    use velmora_bridge::jobtable::JOB_MAX_AGE_MS;
    let w = world_with(|cfg| {
        cfg.hot_cap_bytes = 1;
        cfg.scrub.confirm_secs = 60;
    })
    .await;
    let o = w.released("a", 248).await;
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;

    let paused = Rc::new(Cell::new(false));
    let go = Rc::new(Cell::new(false));
    {
        let (paused, go) = (paused.clone(), go.clone());
        *w.bridge().safety.before_delete_async.borrow_mut() = Some(Box::new(move |_| {
            Box::pin(async move {
                paused.set(true);
                while !go.get() {
                    tokio::task::yield_now().await;
                }
            })
        }));
    }
    let evict = w.bridge().evict_batch(0);
    tokio::pin!(evict);
    let at_delete = async {
        while !paused.get() {
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        _ = &mut evict => panic!("no loss was on record: the eviction deletes the copy"),
        () = at_delete => {}
    }
    assert_eq!(w.scrub().await.suspect, 1, "first sighting");
    w.advance_secs(60);
    let second = w.scrub().await;
    assert_eq!(
        (second.suspect, second.repaired),
        (1, 0),
        "confirmed, but an eviction from before the first sighting may still delete"
    );
    go.set(true);
    evict.await.unwrap();
    assert!(!w.has_safety(&o), "the eviction took the copy, as it may");
    // Once that eviction is surely over, the loss is handled as found:
    // no copy is left anywhere, which is said.
    w.bridge().clock.advance_ms(2 * JOB_MAX_AGE_MS);
    let later = w.scrub().await;
    assert_eq!((later.repaired, later.unrecoverable), (0, 1));
}

/// A re-pin from Usenet writes the safety copy after its catalogue
/// write. The object is deleted and garbage collection finishes while
/// that PUT is in flight; the copy that then lands must be collected by
/// a later GC pass, also when the PUT's reply is lost.
async fn usenet_repair_put_after_gc(lost_reply: bool, defer_fails: bool) {
    let w = world_with(|cfg| cfg.gc_mode = velmora_bridge::config::GcMode::Disposable).await;
    let o = w.released("a", 243).await;
    let bridge = w.bridge();
    let safety = &bridge.safety;
    let key = o.extent.safety_key();
    assert!(safety.lose(&key));
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 0).await;
    assert_eq!(w.scrub().await.suspect, 1);
    w.advance_secs(3600);

    safety.hold_put_prefix.replace(Some(key.clone()));
    let run = w.scrub();
    tokio::pin!(run);
    let collect = async {
        while !safety.held.get() {
            tokio::task::yield_now().await;
        }
        assert_eq!(w.safety_state(&o).await, "held", "re-pinned before the PUT");
        w.rig
            .call(&w.signer, Method::Delete, &path(BUCKET, "a"), &[], &[], b"")
            .await
            .expect(204);
        assert_eq!(
            bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
            JobOutcome::Ack
        );
        assert_eq!(w.safety_state(&o).await, "deleted", "GC ran to its end");
        if lost_reply {
            // Both PUTs of the re-pin land and lose their replies.
            let wire = w.rig.trip().clone();
            *safety.before_put.borrow_mut() = Some(Box::new(move |_| wire.arm(0, Trip::Lost)));
            w.rig.trip().arm(0, Trip::Lost);
        }
        if defer_fails {
            // The watch's early look cannot be scheduled.
            *bridge.catalog.sql.fail_matching.borrow_mut() = Some(("SET scrub_next_at = ?3", 0));
        }
        safety.hold_put_prefix.replace(None);
    };
    tokio::select! {
        () = collect => {}
        _ = &mut run => panic!("scrub finished without writing the copy"),
    }
    let run = run.await;
    *bridge.catalog.sql.fail_matching.borrow_mut() = None;
    assert_eq!(run.repaired, 1);
    if defer_fails {
        assert_eq!(run.ended, ScrubEnd::Stopped, "the reschedule failed");
    }
    assert!(w.has_safety(&o), "the PUT landed after GC");
    assert_eq!(
        bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert!(
        !w.has_safety(&o),
        "a later GC pass collects the copy written after the first one"
    );
    assert_eq!(
        w.rig
            .count("gc WHERE action = 'delete_safety' AND done_at IS NULL"),
        0
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_usenet_repair_copy_written_after_gc_is_collected() {
    usenet_repair_put_after_gc(false, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_usenet_repair_copy_whose_put_reply_is_lost_after_gc_is_collected() {
    usenet_repair_put_after_gc(true, false).await;
}

/// The cleanup row is written before the watch is rescheduled: a failed
/// reschedule cannot leave the copy behind.
#[tokio::test(flavor = "current_thread")]
async fn a_lost_repair_put_is_collected_even_if_the_watch_cannot_be_rescheduled() {
    usenet_repair_put_after_gc(true, true).await;
}

/// The repair watch writes a missing safety copy again after its
/// liveness check. GC that finishes before that PUT lands must not leave
/// the copy behind.
#[tokio::test(flavor = "current_thread")]
async fn a_watch_rewrite_that_lands_after_gc_is_collected() {
    let w = world_with(|cfg| cfg.gc_mode = velmora_bridge::config::GcMode::Disposable).await;
    let o = w.released("a", 244).await;
    let bridge = w.bridge();
    let safety = &bridge.safety;
    let key = o.extent.safety_key();
    assert!(safety.lose(&key));
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 0).await;
    w.scrub().await;
    w.advance_secs(3600);
    *safety.fail_put_prefix.borrow_mut() = Some("x/".to_string());
    assert_eq!(w.scrub().await.repaired, 1);
    *safety.fail_put_prefix.borrow_mut() = None;
    w.advance_secs(3600);

    safety.hold_put_prefix.replace(Some(key.clone()));
    let run = w.scrub();
    tokio::pin!(run);
    let collect = async {
        while !safety.held.get() {
            tokio::task::yield_now().await;
        }
        w.rig
            .call(&w.signer, Method::Delete, &path(BUCKET, "a"), &[], &[], b"")
            .await
            .expect(204);
        assert_eq!(
            bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
            JobOutcome::Ack
        );
        assert_eq!(w.safety_state(&o).await, "deleted", "GC ran to its end");
        safety.hold_put_prefix.replace(None);
    };
    tokio::select! {
        () = collect => {}
        _ = &mut run => panic!("the watch finished without writing the copy"),
    }
    run.await;
    assert!(w.has_safety(&o), "the watch's PUT landed after GC");
    assert_eq!(
        bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert!(!w.has_safety(&o), "a later GC pass collects it");
}

/// A plan whose parity addendum cannot be read: that extent is said and
/// deferred, its loss evidence kept and no pass recorded, and the run
/// goes on to the next due extent.
#[tokio::test(flavor = "current_thread")]
async fn a_malformed_plan_defers_its_extent_and_the_run_goes_on() {
    let w = world_with(|cfg| cfg.packed_plans = true).await;
    let a = w.released("a", 245).await;
    let b = w.released("b", 246).await;
    w.advance_secs(31 * DAY_SECS);
    let now = w.bridge().clock.now();
    let far = now.plus_secs(60 * DAY_SECS);
    for name in ["alpha", "beta"] {
        w.set_clocks(&a, name, now.plus_ms(-2000), far).await;
        w.set_clocks(&b, name, now.plus_ms(-1000), far).await;
    }
    let c = &w.bridge().catalog.sql.inner;
    c.fixture_exec(
        "UPDATE scrub_copies SET stat_loss_at = ?2 WHERE extent_id = ?1 AND backbone = 'alpha'",
        &[
            SqlValue::Text(a.extent.as_str().to_owned()),
            SqlValue::Int(now.0 - 7_200_000),
        ],
    )
    .await
    .unwrap();
    c.fixture_exec(
        "UPDATE extents SET parity = ?2 WHERE id = ?1",
        &[
            SqlValue::Text(a.extent.as_str().to_owned()),
            SqlValue::Blob(vec![0xff; 7]),
        ],
    )
    .await
    .unwrap();
    let result_before = w.result(&a).await;

    let run = w.scrub().await;
    assert_ne!(
        run.ended,
        ScrubEnd::Stopped,
        "one bad plan does not stop the run"
    );
    assert_eq!((run.checked, run.ok), (1, 1), "b is checked");
    assert_eq!(w.result(&b).await, "ok");
    assert!(alerts()
        .iter()
        .any(|l| l.starts_with("scrub-bad-plan ") && l.contains(a.extent.as_str())));
    // a: deferred, its loss kept, no pass recorded.
    assert_eq!(w.result(&a).await, result_before);
    let loss = w
        .scalar(
            "SELECT stat_loss_at FROM scrub_copies WHERE extent_id = ?1 AND backbone = 'alpha'",
            &a.extent,
        )
        .await;
    assert_eq!(loss, (now.0 - 7_200_000).to_string());
    let (stat, _) = w.clocks(&a, "alpha").await;
    assert!(
        stat > now,
        "a is due again later, not at the head of the list"
    );
    assert!(stat < now.plus_secs(DAY_SECS), "deferred, not passed");
}

/// H6: a successful scheduled BODY check moves `last_verified_at`
/// forward, never back; a STAT pass and a failed BODY check do not.
#[tokio::test(flavor = "current_thread")]
async fn a_scheduled_body_pass_advances_last_verified_at() {
    let w = world().await;
    let o = w.released("a", 249).await;
    let stamp = || async {
        w.scalar(
            "SELECT last_verified_at FROM extents WHERE id = ?1",
            &o.extent,
        )
        .await
    };
    let released = stamp().await;
    assert_ne!(released, "NULL", "verify stamped the release read");
    // A STAT pass: nothing read, nothing stamped.
    w.advance_secs(31 * DAY_SECS);
    assert_eq!(w.scrub().await.ok, 1);
    assert_eq!(stamp().await, released);
    // A BODY pass on both backbones.
    w.advance_secs(60);
    w.full_checks_now(&o).await;
    let now = w.bridge().clock.now();
    let run = w.scrub().await;
    assert_eq!(run.ok, 1);
    assert!(run.bytes_read > 0);
    assert_eq!(stamp().await, now.0.to_string());
    // Never back: a stamp ahead stays.
    let ahead = now.0 + 86_400_000;
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET last_verified_at = ?2 WHERE id = ?1",
            &[
                SqlValue::Text(o.extent.as_str().to_owned()),
                SqlValue::Int(ahead),
            ],
        )
        .await
        .unwrap();
    w.advance_secs(60);
    w.full_checks_now(&o).await;
    assert_eq!(w.scrub().await.ok, 1);
    assert_eq!(stamp().await, ahead.to_string());
    // Failed BODY checks stamp nothing.
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET last_verified_at = ?2 WHERE id = ?1",
            &[
                SqlValue::Text(o.extent.as_str().to_owned()),
                SqlValue::Int(now.0),
            ],
        )
        .await
        .unwrap();
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;
    w.advance_secs(60);
    w.full_checks_now(&o).await;
    let failed = w.scrub().await;
    assert_eq!(failed.suspect, 1);
    assert_eq!(stamp().await, now.0.to_string());
}

/// With the scrub on, an extent with a loss on record is not listed for
/// eviction: both copies stay, counted. One whose loss is recorded after
/// the listing, right before the deletes, keeps both copies too: the
/// cache fill can be the only R2 copy left (its safety copy already
/// evicted), and the repair of that loss may need it. With the scrub off
/// the old rule holds: both go.
#[tokio::test(flavor = "current_thread")]
async fn eviction_keeps_and_counts_the_copies_of_an_extent_with_a_loss_on_record() {
    // (scrub on, loss recorded only after the listing, safety copy already evicted)
    for (scrub, late, cache_only) in [
        (true, false, false),
        (true, true, false),
        (true, true, true),
        (false, false, false),
    ] {
        let w = world_with(|cfg| {
            cfg.hot_cap_bytes = 1;
            cfg.scrub.on = scrub;
        })
        .await;
        let o = w.released("a", 250).await;
        let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
        let cipher = w
            .bridge()
            .safety
            .stored(&o.extent.safety_key())
            .unwrap()
            .bytes;
        let meta = BlobMeta {
            bucket: &extent.bucket_id,
            extent: &extent.id,
            cipher_sha256: &extent.cipher_sha256,
        };
        w.bridge()
            .cache
            .put(&o.extent.cache_key(), cipher, &meta)
            .await
            .unwrap();
        let c = &w.bridge().catalog;
        c.record_cache_fill(&o.extent, w.bridge().clock.now())
            .await
            .unwrap();
        if cache_only {
            assert!(w.bridge().safety.lose(&o.extent.safety_key()));
            c.sql
                .inner
                .fixture_exec(
                    "UPDATE extents SET hot_safety_bytes = 0 WHERE id = ?1",
                    &[SqlValue::Text(o.extent.as_str().to_owned())],
                )
                .await
                .unwrap();
        }
        let loss = format!(
            "UPDATE scrub_copies SET full_loss_at = {} WHERE extent_id = '{}' AND backbone = 'beta'",
            w.bridge().clock.now().0,
            o.extent.as_str()
        );
        if late {
            *c.sql.before_matching.borrow_mut() =
                Some(("FROM extents WHERE id = ?1 AND evict_seq = ?2", 0, loss));
        } else {
            c.sql.inner.fixture_script(&loss).unwrap();
        }
        w.bridge().evict_batch(0).await.unwrap();
        assert!(
            c.sql.before_matching.borrow().is_none(),
            "the loss was recorded"
        );
        let counts = w
            .scalar(
                "SELECT hot_safety_bytes || ':' || hot_cache_bytes FROM extents WHERE id = ?1",
                &o.extent,
            )
            .await;
        let size = extent.cipher_size;
        let (safety, cache, expected) = match (scrub, cache_only) {
            (true, false) => (true, true, format!("{size}:{size}")),
            (true, true) => (false, true, format!("0:{size}")),
            (false, _) => (false, false, "0:0".to_owned()),
        };
        assert_eq!(
            w.has_safety(&o),
            safety,
            "safety copy, scrub={scrub} late={late} cache_only={cache_only}"
        );
        assert_eq!(
            w.bridge().cache.contains(&o.extent.cache_key()),
            cache,
            "cache fill, scrub={scrub} late={late} cache_only={cache_only}"
        );
        assert_eq!(counts, expected, "scrub={scrub} late={late}");
    }
}

/// A full eviction batch of extents with a loss on record (as when a
/// backbone outage leaves many extents suspect) is at the head of the
/// eviction order. The extent behind them is evicted by the same drain,
/// their copies stay, and their read stamps (what the adaptive cap
/// measures) are not touched.
#[tokio::test(flavor = "current_thread")]
async fn kept_copies_at_the_head_of_the_order_do_not_stall_eviction() {
    use velmora_bridge::jobs::EVICT_BATCH;
    let w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let mut kept = Vec::new();
    for i in 0..EVICT_BATCH {
        kept.push(w.released_sized(&format!("k{i}"), i as u8, 1000).await);
    }
    let free = w.released_sized("free", 251, 1000).await;
    w.align_clocks(&free).await;
    let c = &w.bridge().catalog.sql.inner;
    let now = w.bridge().clock.now();
    for (i, o) in kept.iter().enumerate() {
        let id = SqlValue::Text(o.extent.as_str().to_owned());
        c.fixture_exec(
            "UPDATE scrub_copies SET stat_loss_at = ?2 WHERE extent_id = ?1",
            &[id.clone(), SqlValue::Int(now.0)],
        )
        .await
        .unwrap();
        c.fixture_exec(
            "UPDATE extents SET last_read_at = ?2 WHERE id = ?1",
            &[id, SqlValue::Int(1 + i as i64)],
        )
        .await
        .unwrap();
    }
    c.fixture_exec(
        "UPDATE extents SET last_read_at = ?2 WHERE id = ?1",
        &[
            SqlValue::Text(free.extent.as_str().to_owned()),
            SqlValue::Int(1_000),
        ],
    )
    .await
    .unwrap();
    w.bridge().jobs.inner.take();

    w.bridge().evict_batch(0).await.unwrap();
    assert!(!w.has_safety(&free), "the extent behind them is evicted");
    assert!(
        !w.bridge()
            .jobs
            .inner
            .take()
            .iter()
            .any(|s| matches!(s.job, Job::Evict { .. })),
        "nothing more is listed: no continuation over the same rows"
    );
    for (i, o) in kept.iter().enumerate() {
        assert!(w.has_safety(o), "a copy with a loss on record stays");
        let read = w
            .scalar("SELECT last_read_at FROM extents WHERE id = ?1", &o.extent)
            .await;
        assert_eq!(read, (1 + i).to_string(), "its read stamp is untouched");
    }
}

/// Re-pins `o` from Usenet (beta lacks article 0) without its safety
/// copy: the PUT is refused, so its watch looks again early.
async fn repinned_without_its_copy(w: &World, o: &Obj) {
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, o, 0).await;
    w.scrub().await;
    w.advance_secs(3600);
    *w.bridge().safety.fail_put_prefix.borrow_mut() = Some("x/".to_string());
    assert_eq!(w.scrub().await.repaired, 1);
    *w.bridge().safety.fail_put_prefix.borrow_mut() = None;
    assert!(!w.has_safety(o));
    assert_eq!(w.safety_state(o).await, "held");
}

/// The watch's safety GET fails while Usenet and the cache have nothing:
/// that is no proof the copy is gone. Not `unrecoverable`; looked at
/// again, and said once the stores answer.
#[tokio::test(flavor = "current_thread")]
async fn a_failed_safety_read_in_the_watch_is_not_called_unrecoverable() {
    let w = world().await;
    let o = w.released("a", 252).await;
    repinned_without_its_copy(&w, &o).await;
    w.hide(0, &o, 0).await;
    w.advance_secs(3600);
    w.bridge().safety.fail_next_get.set(true);
    let run = w.scrub().await;
    assert!(
        !w.bridge().safety.fail_next_get.get(),
        "the watch read the safety store"
    );
    assert_eq!(run.unrecoverable, 0, "{:?}", alerts());
    assert!(!alerts()
        .iter()
        .any(|a| a.starts_with("scrub-unrecoverable ")));
    assert_eq!(
        w.next_at(&o).await,
        Some(w.bridge().clock.now().0 + 3_600_000),
        "looked at again after the confirm interval"
    );
    // With every store answering, nothing intact anywhere is said.
    w.advance_secs(3600);
    assert_eq!(w.scrub().await.unrecoverable, 1);
}

/// The watch's Usenet read breaks off, and the cache holds an intact
/// copy: the safety copy is written from the cache, not deferred.
#[tokio::test(flavor = "current_thread")]
async fn an_interrupted_watch_read_restores_the_copy_from_the_cache() {
    let w = world().await;
    let o = w.released("a", 253).await;
    let cipher = w
        .bridge()
        .safety
        .stored(&o.extent.safety_key())
        .unwrap()
        .bytes;
    repinned_without_its_copy(&w, &o).await;
    let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    w.bridge()
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    w.advance_secs(3600);
    for s in &w.servers {
        s.drop_next_bodies(1000).await;
    }
    let run = w.scrub().await;
    for s in &w.servers {
        s.drop_next_bodies(0).await;
    }
    assert_eq!((run.unrecoverable, run.stalled), (0, 0));
    assert!(w.has_safety(&o), "written from the cache");
    assert_eq!(w.result(&o).await, "repairing");
}

/// A cache-sourced repair PUT that lands while GC finishes, and whose
/// reply is lost: the copy is collected by a later GC pass.
#[tokio::test(flavor = "current_thread")]
async fn a_cache_repair_put_with_a_lost_reply_after_gc_is_collected() {
    let w = world_with(|cfg| cfg.gc_mode = velmora_bridge::config::GcMode::Disposable).await;
    let o = w.released("a", 254).await;
    let bridge = w.bridge();
    let safety = &bridge.safety;
    let key = o.extent.safety_key();
    let cipher = safety.stored(&key).unwrap().bytes;
    assert!(safety.lose(&key));
    let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;
    assert_eq!(w.scrub().await.suspect, 1);
    // The read that fills the cache comes after the first sighting:
    // at the sighting the scrub writes a fill that is the only R2 copy
    // to the safety store itself (`scrub-protect`).
    bridge
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    w.advance_secs(3600);

    safety.hold_put_prefix.replace(Some(key.clone()));
    let run = w.scrub();
    tokio::pin!(run);
    let collect = async {
        while !safety.held.get() {
            tokio::task::yield_now().await;
        }
        w.rig
            .call(&w.signer, Method::Delete, &path(BUCKET, "a"), &[], &[], b"")
            .await
            .expect(204);
        assert_eq!(
            bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
            JobOutcome::Ack
        );
        assert_eq!(w.safety_state(&o).await, "deleted", "GC ran to its end");
        w.rig.trip().arm(0, Trip::Lost);
        safety.hold_put_prefix.replace(None);
    };
    tokio::select! {
        () = collect => {}
        _ = &mut run => panic!("scrub finished without writing the cached copy"),
    }
    assert_eq!(run.await.repaired, 0);
    assert!(w.has_safety(&o), "the PUT landed; its reply was lost");
    assert_eq!(
        bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert!(!w.has_safety(&o), "a later GC pass collects it");
}

/// A loss recorded on a backbone that no longer counts is never checked
/// again, so it must not keep an extent out of eviction: only losses on
/// the backbones that count now fence it.
#[tokio::test(flavor = "current_thread")]
async fn a_loss_on_a_backbone_that_no_longer_counts_does_not_keep_the_copies() {
    for (backbone, kept) in [("beta", false), ("alpha", true)] {
        // beta reads, but no longer counts toward a release.
        let w = world_with(|cfg| {
            cfg.hot_cap_bytes = 1;
            cfg.required_backbones = 1;
            cfg.providers[1].release = false;
        })
        .await;
        let o = w.released("a", 255).await;
        assert!(w.has_safety(&o));
        let now = w.bridge().clock.now().0;
        // The loss beta's copy had while it still counted, or a loss on alpha.
        w.bridge()
            .catalog
            .sql
            .inner
            .fixture_exec(
                "INSERT INTO scrub_copies(extent_id, backbone, stat_at, full_at, stat_phase_at, \
                 full_phase_at, stat_loss_at) VALUES (?1, 'beta', ?2, ?2, ?2, ?2, ?2) \
                 ON CONFLICT(extent_id, backbone) DO NOTHING",
                &[
                    SqlValue::Text(o.extent.as_str().to_owned()),
                    SqlValue::Int(now),
                ],
            )
            .await
            .unwrap();
        w.bridge()
            .catalog
            .sql
            .inner
            .fixture_exec(
                "UPDATE scrub_copies SET stat_loss_at = ?2 WHERE extent_id = ?1 AND backbone = ?3",
                &[
                    SqlValue::Text(o.extent.as_str().to_owned()),
                    SqlValue::Int(now),
                    SqlValue::Text(backbone.to_owned()),
                ],
            )
            .await
            .unwrap();
        w.bridge().evict_batch(0).await.unwrap();
        assert_eq!(
            w.has_safety(&o),
            kept,
            "a loss on {backbone} keeps the copy: {kept}"
        );
    }
}

/// A copy check reads the provider pool while the run keeps a session
/// from the check before. A pool read that outlasts that session's slot
/// does not keep the socket past it: the session is ended (its slot
/// freed) while the read is still pending, and the same read then goes
/// on and the check completes. The rig's budget gets a sleeper on the
/// test clock for this.
#[tokio::test(flavor = "current_thread")]
async fn a_slow_pool_read_ends_the_retained_sessions_before_their_slots_run_out() {
    use std::cell::RefCell;
    use std::rc::Rc;
    let clock: Rc<RefCell<Option<velmora_bridge::testkit::FixedClock>>> = Rc::default();
    let sleeper: velmora_bridge::ingress::Sleeper = {
        let clock = clock.clone();
        Rc::new(move |ms| {
            let clock = clock.borrow().clone().expect("the rig's clock");
            let until = clock.now().0 + i64::from(ms);
            Box::pin(async move {
                while clock.now().0 < until {
                    tokio::task::yield_now().await;
                }
            })
        })
    };
    let w = world_sleeping(sleeper).await;
    *clock.borrow_mut() = Some(w.bridge().clock.clone());
    let o = w.released("a", 4).await;
    w.advance_secs(31 * DAY_SECS);
    let held = || async {
        let rows = w
            .bridge()
            .catalog
            .sql
            .inner
            .fixture_query(
                "SELECT COUNT(*) FROM provider_permits WHERE lease_until <> 0 AND holder IS NOT NULL",
                &[],
            )
            .await
            .unwrap();
        match rows[0][0] {
            SqlValue::Int(n) => n.to_string(),
            ref other => panic!("{other:?}"),
        }
    };
    let sql = &w.bridge().catalog.sql;
    // The pool read of the second copy check (beta), with alpha's session kept.
    sql.stall_query_matching
        .set(Some(("SUM(held), SUM(uses)", 1)));
    let run = w.scrub();
    tokio::pin!(run);
    let drive = async {
        while !sql.selected_query.tripped() || sql.stall_query_matching.get().is_some() {
            tokio::task::yield_now().await;
        }
        assert_ne!(
            held().await,
            "0",
            "alpha's session is kept into beta's check"
        );
        // The pool read outlasts the slot of the kept session.
        w.advance_secs(PERMIT_SECS + 60);
        // Bounded by time, not executor turns: ending the session is
        // catalogue I/O, which on PostgreSQL takes real round trips.
        // The whole wait is bounded, a stalled count read with it.
        let ended = async {
            while held().await != "0" {
                tokio::task::yield_now().await;
            }
        };
        tokio::time::timeout(HOLD_TIMEOUT, ended)
            .await
            .expect("the kept session is ended while the pool read is pending");
        sql.selected_query.release();
    };
    tokio::select! {
        () = drive => {}
        _ = &mut run => panic!("the run ended with its pool read stalled"),
    }
    let run = run.await;
    assert_eq!((run.checked, run.ok), (1, 1), "the same read went on");
    assert_eq!(w.result(&o).await, "ok");
}

// ---------------------------------------------------------------------------
// Second re-review: releasability, write-ahead PUT intents, bad packed
// plans, bounded eviction windows, lost re-pin replies
// ---------------------------------------------------------------------------

fn cfg_mut(w: &mut World) -> &mut velmora_bridge::config::BridgeConfig {
    &mut std::rc::Rc::get_mut(&mut w.rig.bridge)
        .expect("no request in flight")
        .cfg
}

/// A backbone that held a released extent stops counting: the extent is
/// no longer releasable under the backbones that count now (one of the
/// two required), so eviction must not delete its last R2 copy, with no
/// loss on record anywhere and with the scrub off as well.
#[tokio::test(flavor = "current_thread")]
async fn eviction_keeps_the_last_copy_of_an_extent_not_releasable_under_the_counting_backbones() {
    for scrub in [true, false] {
        let mut w = world_with(|cfg| {
            cfg.hot_cap_bytes = 1;
            cfg.scrub.on = scrub;
        })
        .await;
        let o = w.released("a", 9).await;
        cfg_mut(&mut w).providers[1].release = false;
        w.bridge().evict_batch(0).await.unwrap();
        assert!(w.has_safety(&o), "scrub={scrub}: the last copy stays");
        // Both backbones counting again: it may go.
        cfg_mut(&mut w).providers[1].release = true;
        w.bridge().evict_batch(0).await.unwrap();
        assert!(
            !w.has_safety(&o),
            "scrub={scrub}: releasable again, evicted"
        );
    }
}

/// The protection clears by itself: with beta retired and gamma counting
/// in its place, the scrub's next look re-verifies the extent (re-pinned,
/// posted to gamma, released on alpha and gamma), and eviction may then
/// take its R2 copy.
#[tokio::test(flavor = "current_thread")]
async fn a_retired_backbone_is_replaced_by_a_scrub_re_verify_and_eviction_then_proceeds() {
    let gamma = server().await;
    let mut w = world_with(|cfg| {
        cfg.hot_cap_bytes = 1;
        let mut p = provider("p2", "gamma", &gamma);
        p.enabled = false;
        cfg.providers.push(p);
    })
    .await;
    let o = w.released("a", 10).await;
    {
        let cfg = cfg_mut(&mut w);
        cfg.providers[1].release = false;
        cfg.providers[2].enabled = true;
    }
    w.bridge().evict_batch(0).await.unwrap();
    assert!(w.has_safety(&o), "not releasable under alpha and gamma yet");
    w.advance_secs(31 * DAY_SECS);
    let run = w.scrub().await;
    assert_eq!(run.repaired, 1, "{:?}", alerts());
    assert!(alerts()
        .iter()
        .any(|a| a.starts_with("scrub-reverify ") && a.contains("unproven=[gamma]")));
    assert_eq!(w.safety_state(&o).await, "held");
    w.drive(&o).await;
    assert_eq!(w.safety_state(&o).await, "released");
    let evidence = w
        .scalar(
            "SELECT release_evidence FROM extents WHERE id = ?1",
            &o.extent,
        )
        .await;
    assert!(evidence.contains("gamma"), "{evidence}");
    for row in w.plan(&o).await {
        assert!(gamma.is_stored(&row.message_id).await, "posted to gamma");
    }
    w.bridge().evict_batch(0).await.unwrap();
    assert!(!w.has_safety(&o), "releasable again: evicted");
}

/// A cache-sourced repair whose run stops between the PUT and its
/// catalogue update (the re-pin batch never runs), after GC collected
/// the extent: the write-ahead intent is reconciled by a later run, once
/// the PUT can no longer land, and GC collects the copy.
#[tokio::test(flavor = "current_thread")]
async fn a_repair_put_cancelled_before_its_catalogue_update_is_collected_later() {
    let w = world_with(|cfg| cfg.gc_mode = velmora_bridge::config::GcMode::Disposable).await;
    let o = w.released("a", 11).await;
    let bridge = w.bridge();
    let safety = &bridge.safety;
    let key = o.extent.safety_key();
    let cipher = safety.stored(&key).unwrap().bytes;
    assert!(safety.lose(&key));
    let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;
    assert_eq!(w.scrub().await.suspect, 1);
    // The read that fills the cache comes after the first sighting:
    // at the sighting the scrub writes a fill that is the only R2 copy
    // to the safety store itself (`scrub-protect`).
    bridge
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    w.advance_secs(3600);

    let id: &'static str = Box::leak(o.extent.as_str().to_owned().into_boxed_str());
    safety.hold_put_prefix.replace(Some(key.clone()));
    let mut run = Box::pin(w.scrub());
    let collect = async {
        while !safety.held.get() {
            tokio::task::yield_now().await;
        }
        w.rig
            .call(&w.signer, Method::Delete, &path(BUCKET, "a"), &[], &[], b"")
            .await
            .expect(204);
        assert_eq!(
            bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
            JobOutcome::Ack
        );
        assert_eq!(w.safety_state(&o).await, "deleted", "GC ran to its end");
        // The re-pin batch that follows the PUT never answers.
        bridge.catalog.sql.stall_batch_key.set(Some(id));
        safety.hold_put_prefix.replace(None);
        while bridge.catalog.sql.stall_batch_key.get().is_some() {
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        () = collect => {}
        _ = &mut run => panic!("the run ended with its re-pin stalled"),
    }
    // The invocation is cancelled there: the PUT landed, nothing after it ran.
    drop(run);
    bridge.catalog.sql.selected_batch.disarm();
    assert!(w.has_safety(&o), "the PUT landed");
    assert_eq!(
        bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert!(w.has_safety(&o), "no cleanup was queued before the cancel");
    // Once the cancelled invocation can no longer write, a run reconciles.
    bridge
        .clock
        .advance_ms(velmora_bridge::jobtable::JOB_MAX_AGE_MS + 1);
    w.scrub().await;
    assert_eq!(
        bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert!(
        !w.has_safety(&o),
        "the reconciled intent collected the copy"
    );
    assert_eq!(
        w.rig.count("scan_cursors WHERE k LIKE 'scrub-put:%'"),
        0,
        "the intent is gone"
    );
}

/// A packed data plan that cannot be decoded: its extent is said and
/// deferred, its evidence kept, and the run goes on, on the scheduled
/// path and on the repair watch's.
#[tokio::test(flavor = "current_thread")]
async fn a_corrupt_packed_plan_defers_its_extent_and_the_run_goes_on() {
    // Scheduled checks.
    let w = world_with(|cfg| cfg.packed_plans = true).await;
    let a = w.released("a", 12).await;
    let b = w.released("b", 13).await;
    w.advance_secs(31 * DAY_SECS);
    let now = w.bridge().clock.now();
    let far = now.plus_secs(60 * DAY_SECS);
    for name in ["alpha", "beta"] {
        w.set_clocks(&a, name, now.plus_ms(-2000), far).await;
        w.set_clocks(&b, name, now.plus_ms(-1000), far).await;
    }
    let packed = w
        .scalar(
            "SELECT COUNT(*) FROM extents WHERE id = ?1 AND plan IS NOT NULL",
            &a.extent,
        )
        .await;
    assert_eq!(packed, "1", "the plan is stored packed");
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET plan = ?2 WHERE id = ?1",
            &[
                SqlValue::Text(a.extent.as_str().to_owned()),
                SqlValue::Blob(vec![0xee; 9]),
            ],
        )
        .await
        .unwrap();
    let run = w.scrub().await;
    assert_ne!(run.ended, ScrubEnd::Stopped);
    assert_eq!((run.checked, run.ok), (1, 1), "b is checked");
    assert!(alerts()
        .iter()
        .any(|l| l.starts_with("scrub-bad-plan ") && l.contains(a.extent.as_str())));
    let (stat, _) = w.clocks(&a, "alpha").await;
    assert!(stat > now && stat < now.plus_secs(DAY_SECS), "deferred");

    // The repair watch of a re-pinned extent.
    let w = world_with(|cfg| cfg.packed_plans = true).await;
    let a = w.released("a", 14).await;
    let b = w.released("b", 15).await;
    repinned_without_its_copy(&w, &a).await;
    let result = w.result(&a).await;
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET plan = ?2 WHERE id = ?1",
            &[
                SqlValue::Text(a.extent.as_str().to_owned()),
                SqlValue::Blob(vec![0xee; 9]),
            ],
        )
        .await
        .unwrap();
    w.advance_secs(3600);
    let now = w.bridge().clock.now();
    for name in ["alpha", "beta"] {
        w.set_clocks(&b, name, now.plus_ms(-1000), now.plus_secs(60 * DAY_SECS))
            .await;
    }
    let run = w.scrub().await;
    assert_ne!(run.ended, ScrubEnd::Stopped);
    assert_eq!(w.result(&b).await, "ok", "b is checked");
    assert_eq!(w.result(&a).await, result, "the repair stays on record");
    assert_eq!(
        w.next_at(&a).await,
        Some(now.0 + 3_600_000),
        "looked at again"
    );
}

/// 20,000 extents with a loss on record (protected) sit at the head of
/// the eviction order, ahead of one that may go. Each drain step reads
/// one bounded window, and the steps reach that extent.
#[tokio::test(flavor = "current_thread")]
async fn eviction_steps_stay_bounded_past_a_long_protected_prefix() {
    use velmora_bridge::jobs::EVICT_WINDOW;
    let w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 16).await;
    let c = &w.bridge().catalog;
    let db = &c.sql.inner;
    let evidence = r#"[{"backbone":"alpha","kind":"body","plan_rev":0},{"backbone":"beta","kind":"stat","plan_rev":0}]"#;
    let seed = db.fixture(
        "WITH RECURSIVE n(x) AS (VALUES (1) UNION ALL SELECT x+1 FROM n WHERE x < 20000) \
         INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at,hot_safety_bytes,last_read_at,release_evidence) \
         SELECT printf('fixture-%05d', x), ?1, 'committed', 1, 65, zeroblob(48), zeroblob(16), zeroblob(32), zeroblob(32), 'released', 0, 65, x, ?2 FROM n",
        "INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at,hot_safety_bytes,last_read_at,release_evidence) \
         SELECT 'fixture-' || lpad(CAST(x AS text), 5, '0'), ?1, 'committed', 1, 65, \
           decode(repeat('00', 48), 'hex'), decode(repeat('00', 16), 'hex'), \
           decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), 'released', 0, 65, x, ?2 \
         FROM generate_series(1, 20000) x",
    );
    db.fixture_exec(
        seed,
        &[
            SqlValue::Text(w.bucket.id.as_str().to_owned()),
            SqlValue::Text(evidence.to_owned()),
        ],
    )
    .await
    .unwrap();
    db.fixture_exec(
        "INSERT INTO scrub_copies(extent_id,backbone,stat_at,full_at,stat_phase_at,full_phase_at,stat_loss_at) \
         SELECT id, 'alpha', 0, 100, 0, 100, 1 FROM extents WHERE id LIKE 'fixture-%'",
        &[],
    )
    .await
    .unwrap();
    db.fixture_exec(
        "UPDATE extents SET last_read_at = 30000 WHERE id = ?1",
        &[SqlValue::Text(o.extent.as_str().to_owned())],
    )
    .await
    .unwrap();
    #[cfg(feature = "testkit-pg")]
    if let Some(pg) = db.postgres() {
        let client = pg.client().await.unwrap();
        client
            .batch_execute("ANALYZE extents; ANALYZE scrub_copies;")
            .await
            .unwrap();
    }
    w.bridge().jobs.inner.take();
    let mut steps = 0;
    let mut remaining = 0;
    loop {
        if db.dialect() == Dialect::Sqlite {
            db.sqlite().reset_read_stats();
        }
        w.bridge().evict_batch(remaining).await.unwrap();
        steps += 1;
        if db.dialect() == Dialect::Sqlite {
            let reads = db.sqlite().read_stats();
            assert!(
                reads.vm_steps < 300_000,
                "a step reads one window, not the prefix: {reads:?}"
            );
        }
        let next = w
            .bridge()
            .jobs
            .inner
            .take()
            .into_iter()
            .find_map(|s| match s.job {
                Job::Evict { remaining, .. } => Some(remaining),
                _ => None,
            });
        match next {
            Some(r) => remaining = r,
            None => break,
        }
        assert!(steps <= 20_000 / EVICT_WINDOW as usize + 2, "the steps end");
    }
    assert!(!w.has_safety(&o), "reached and evicted after {steps} steps");
    assert!(steps >= 20_000 / EVICT_WINDOW as usize, "one window a step");
    // PostgreSQL: the window's index scan stops at the window.
    #[cfg(feature = "testkit-pg")]
    if let Some(pg) = db.postgres() {
        let client = pg.client().await.unwrap();
        let query =
            velmora_bridge::pg::normalize_statement(velmora_bridge::sql::HOT_EVICT_WINDOWS[2])
                .unwrap();
        let explain = client
            .prepare_typed(
                &format!("EXPLAIN (ANALYZE, FORMAT TEXT) {query}"),
                &[
                    tokio_postgres::types::Type::INT8,
                    tokio_postgres::types::Type::TEXT,
                    tokio_postgres::types::Type::INT8,
                ],
            )
            .await
            .unwrap();
        let labels = r#"["alpha","beta"]"#;
        let rows = client
            .query(&explain, &[&i64::from(EVICT_WINDOW), &labels, &2i64])
            .await
            .unwrap();
        let plan = rows
            .iter()
            .map(|r| r.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(plan.contains("extents_evictable"), "{plan}");
        assert!(!plan.contains("Seq Scan"), "{plan}");
        let scan = plan
            .lines()
            .find(|l| l.contains("Index") && l.contains("extents_evictable"))
            .unwrap();
        let actual = scan.split("actual").nth(1).unwrap();
        let read: u64 = actual
            .split("rows=")
            .nth(1)
            .unwrap()
            .split(|ch: char| !ch.is_ascii_digit())
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(read <= u64::from(EVICT_WINDOW), "{plan}");
    }
}

/// The SQLite windows read `extents_evictable` in order with key lookups
/// in `scrub_copies`: no sort, no scan.
#[tokio::test(flavor = "current_thread")]
async fn the_eviction_windows_read_their_index_in_order() {
    let w = world_on(true, |_| {}).await;
    let labels = r#"'["alpha","beta"]'"#;
    let windows = [
        velmora_bridge::sql::HOT_EVICT_WINDOWS[0]
            .replace("?3", "2")
            .replace("?2", labels)
            .replace("?1", "200"),
        velmora_bridge::sql::HOT_EVICT_WINDOWS[1]
            .replace("?5", "2")
            .replace("?4", labels)
            .replace("?3", "'x'")
            .replace("?2", "7")
            .replace("?1", "200"),
    ];
    for sql in &windows {
        let plan: Vec<String> = w.bridge().catalog.sql.with_conn(|c| {
            let sql = format!("EXPLAIN QUERY PLAN {sql}");
            let mut stmt = c.prepare(&sql).unwrap();
            let rows = stmt.query_map((), |r| r.get::<_, String>(3)).unwrap();
            rows.map(|r| r.unwrap()).collect()
        });
        let plan = plan.join(" | ");
        assert!(plan.contains("INDEX extents_evictable"), "{plan}");
        assert!(!plan.contains("TEMP B-TREE FOR ORDER BY"), "{plan}");
        assert!(
            !plan.contains("SCAN s"),
            "a key lookup in scrub_copies: {plan}"
        );
    }
}

/// A Usenet-sourced re-pin whose batch committed but whose reply was
/// lost: a point read finds it re-pinned, and the safety copy is written
/// as after any re-pin, not left missing until the repair bound.
#[tokio::test(flavor = "current_thread")]
async fn a_re_pin_whose_reply_is_lost_still_writes_the_safety_copy() {
    let w = world().await;
    let o = w.released("a", 17).await;
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 0).await;
    assert_eq!(w.scrub().await.suspect, 1);
    w.advance_secs(3600);
    // The re-pin batch (the statement that pins the extent again).
    w.bridge()
        .catalog
        .sql
        .lose_batch_matching
        .set(Some("SET safety_state = 'held', evict_seq = evict_seq + 1"));
    let run = w.scrub().await;
    assert!(
        w.bridge().catalog.sql.lose_batch_matching.get().is_none(),
        "the re-pin's reply was lost"
    );
    assert_eq!(run.repaired, 1);
    assert_eq!(w.safety_state(&o).await, "held");
    assert!(w.has_safety(&o), "the copy is written as after any re-pin");
}

/// Expired PUT intents are reconciled oldest first: newer intents of
/// extents whose ids sort lower cannot keep an expired one out of the
/// page.
#[tokio::test(flavor = "current_thread")]
async fn an_expired_put_intent_is_not_held_up_by_newer_ones() {
    let w = world().await;
    let c = &w.bridge().catalog;
    let now = w.bridge().clock.now();
    for i in 0..20 {
        c.scrub_put_intent(&ExtentId::new(format!("a{i:02}")), now.plus_secs(3600))
            .await
            .unwrap();
    }
    c.scrub_put_intent(&ExtentId::new("zz-expired"), now.plus_ms(-1))
        .await
        .unwrap();
    let due = c.scrub_put_intents_due(now, 8).await.unwrap();
    let shown = format!("{due:?}");
    assert!(shown.contains("zz-expired"), "{shown}");
    assert!(
        !shown.contains("a00"),
        "an intent not yet expired waits: {shown}"
    );
}

/// A re-verify that waits on the extent's own deadline (no copy check
/// due) keeps a deadline whatever stops it: past the run's re-pins, or a
/// plan that cannot be decoded. It is never left without one.
#[tokio::test(flavor = "current_thread")]
async fn a_deferred_re_verify_keeps_its_deadline() {
    let mut w = world_with(|cfg| {
        cfg.packed_plans = true;
        cfg.scrub.repairs_per_run = 0;
    })
    .await;
    let o = w.released("a", 18).await;
    cfg_mut(&mut w).providers[1].release = false;
    // A passing check: not releasable under alpha alone, no re-pin left.
    w.advance_secs(31 * DAY_SECS);
    w.scrub().await;
    let deferred = w.next_at(&o).await.expect("a deadline");
    // Its own deadline comes, with no copy check due, and the plan
    // cannot be decoded.
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET plan = ?2 WHERE id = ?1",
            &[
                SqlValue::Text(o.extent.as_str().to_owned()),
                SqlValue::Blob(vec![0xee; 9]),
            ],
        )
        .await
        .unwrap();
    w.bridge().clock.set(UnixMs(deferred));
    w.scrub().await;
    let next = w.next_at(&o).await;
    assert!(
        next.is_some_and(|n| n > deferred),
        "still has a deadline ahead: {next:?}"
    );
}

/// With the scrub on, the cache fill of a pinned extent under a scrub
/// repair stays: its safety copy could not be written, and the repair
/// watch writes it from that fill.
#[tokio::test(flavor = "current_thread")]
async fn the_cache_fill_of_an_extent_under_repair_is_not_evicted() {
    let w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 19).await;
    let cipher = w
        .bridge()
        .safety
        .stored(&o.extent.safety_key())
        .unwrap()
        .bytes;
    repinned_without_its_copy(&w, &o).await;
    let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    w.bridge()
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    w.bridge()
        .catalog
        .record_cache_fill(&o.extent, w.bridge().clock.now())
        .await
        .unwrap();
    w.bridge().evict_batch(0).await.unwrap();
    assert!(
        w.bridge().cache.contains(&o.extent.cache_key()),
        "the only R2 copy of an extent under repair stays"
    );
}

/// A backlog of expired PUT intents is reconciled a bounded page a run,
/// whatever the configured re-pins: the run's own work is not held up.
#[tokio::test(flavor = "current_thread")]
async fn a_backlog_of_put_intents_is_reconciled_a_bounded_page_a_run() {
    let w = world_with(|cfg| cfg.scrub.repairs_per_run = 10_000).await;
    let c = &w.bridge().catalog;
    let now = w.bridge().clock.now();
    for i in 0..300 {
        c.scrub_put_intent(&ExtentId::new(format!("x{i:03}")), now.plus_ms(-1))
            .await
            .unwrap();
    }
    w.scrub().await;
    let left = w.rig.count("scan_cursors WHERE k LIKE 'scrub-put:%'");
    assert_eq!(left, 300 - i64::from(velmora_bridge::scrub::RECONCILE_MAX));
    w.scrub().await;
    assert_eq!(w.rig.count("scan_cursors WHERE k LIKE 'scrub-put:%'"), 0);
}

// ---------------------------------------------------------------------------
// Round 4: one release rule for eviction and the scrub
// ---------------------------------------------------------------------------

/// Sets an extent's release evidence to `entries` (backbone, kind) for its
/// current plan.
async fn set_evidence(w: &World, o: &Obj, entries: &[(&str, &str)]) {
    let json = entries
        .iter()
        .map(|(b, k)| format!(r#"{{"backbone":"{b}","kind":"{k}","plan_rev":PLANREV}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let rev = w
        .scalar("SELECT plan_rev FROM extents WHERE id = ?1", &o.extent)
        .await;
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET release_evidence = ?2 WHERE id = ?1",
            &[
                SqlValue::Text(o.extent.as_str().to_owned()),
                SqlValue::Text(format!("[{}]", json.replace("PLANREV", &rev))),
            ],
        )
        .await
        .unwrap();
}

/// Retiring the only backbone with a full pass: two counting backbones
/// still hold presence passes, but the release rule wants a full pass on
/// a counting backbone (`VERIFY_MODE=body`, and a sampled extent under
/// the light check). Eviction keeps the last copy, and the scrub
/// re-verifies.
#[tokio::test(flavor = "current_thread")]
async fn retiring_the_only_backbone_with_a_full_pass_keeps_the_last_copy() {
    use velmora_bridge::config::VerifyMode;
    for (mode, full) in [(VerifyMode::Body, "body"), (VerifyMode::Light, "sampled")] {
        let gamma = server().await;
        let mut w = world_with(|cfg| {
            cfg.hot_cap_bytes = 1;
            cfg.providers.push(provider("p2", "gamma", &gamma));
        })
        .await;
        let o = w.released_on(&[&gamma], "a", 20).await;
        set_evidence(
            &w,
            &o,
            &[("alpha", full), ("beta", "stat"), ("gamma", "stat")],
        )
        .await;
        {
            let cfg = cfg_mut(&mut w);
            cfg.verify.mode = mode;
            cfg.providers[0].release = false;
        }
        w.bridge().evict_batch(0).await.unwrap();
        assert!(
            w.has_safety(&o),
            "{mode:?}: no full pass on a counting backbone"
        );
        // The scrub's next passing look re-verifies it.
        w.advance_secs(31 * DAY_SECS);
        w.scrub().await;
        assert!(
            alerts()
                .iter()
                .any(|a| a.starts_with("scrub-reverify ") && a.contains(o.extent.as_str())),
            "{mode:?}: {:?}",
            alerts()
        );
    }
}

/// Release evidence that cannot be read strictly (an object instead of an
/// array, a plan revision that is not a number, a missing kind) is no
/// release on SQLite and PostgreSQL alike: those extents keep their copy,
/// and the window goes on to the next extent, which is evicted.
#[tokio::test(flavor = "current_thread")]
async fn malformed_release_evidence_is_no_release_and_the_window_goes_on() {
    let w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let bad = [
        r#"{"backbone":"alpha","kind":"body","plan_rev":0}"#.to_owned(),
        r#"[{"backbone":"alpha","kind":"body","plan_rev":"x"},{"backbone":"beta","kind":"stat","plan_rev":"x"}]"#
            .to_owned(),
        r#"[{"backbone":"alpha","plan_rev":0},{"backbone":"beta","plan_rev":0}]"#.to_owned(),
    ];
    let mut kept = Vec::new();
    for (i, evidence) in bad.iter().enumerate() {
        let o = w.released(&format!("bad{i}"), 21 + i as u8).await;
        w.bridge()
            .catalog
            .sql
            .inner
            .fixture_exec(
                "UPDATE extents SET release_evidence = ?2, plan_rev = 0, last_read_at = ?3 \
                 WHERE id = ?1",
                &[
                    SqlValue::Text(o.extent.as_str().to_owned()),
                    SqlValue::Text(evidence.clone()),
                    SqlValue::Int(1 + i as i64),
                ],
            )
            .await
            .unwrap();
        kept.push(o);
    }
    let good = w.released("good", 30).await;
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET last_read_at = 100 WHERE id = ?1",
            &[SqlValue::Text(good.extent.as_str().to_owned())],
        )
        .await
        .unwrap();
    w.bridge().evict_batch(0).await.unwrap();
    for o in &kept {
        assert!(w.has_safety(o), "malformed evidence is no release");
    }
    assert!(!w.has_safety(&good), "the window went on past them");
}

/// A re-pinned extent whose safety copy could not be written and whose
/// cache fill is intact: eviction keeps that fill with the scrub turned
/// off as well, since the fence reads the safety copy, not the switch.
#[tokio::test(flavor = "current_thread")]
async fn a_pending_repairs_cache_fill_stays_with_the_scrub_off() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 31).await;
    let cipher = w
        .bridge()
        .safety
        .stored(&o.extent.safety_key())
        .unwrap()
        .bytes;
    repinned_without_its_copy(&w, &o).await;
    let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    w.bridge()
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    w.bridge()
        .catalog
        .record_cache_fill(&o.extent, w.bridge().clock.now())
        .await
        .unwrap();
    cfg_mut(&mut w).scrub.on = false;
    w.bridge().evict_batch(0).await.unwrap();
    assert!(!w.has_safety(&o), "the safety copy is missing");
    assert!(
        w.bridge().cache.contains(&o.extent.cache_key()),
        "the only R2 copy stays with the scrub off"
    );
}

/// Every re-verify that does not end in a re-pin keeps a retry one
/// confirm interval ahead, also when no regular check is due: a cache
/// copy that could not be written as the safety copy, and a read that
/// broke off.
#[tokio::test(flavor = "current_thread")]
async fn an_incomplete_re_verify_always_keeps_a_retry() {
    for case in ["put-refused", "interrupted"] {
        let mut w = world().await;
        let o = w.released("a", 32).await;
        let cipher = w
            .bridge()
            .safety
            .stored(&o.extent.safety_key())
            .unwrap()
            .bytes;
        cfg_mut(&mut w).providers[1].release = false;
        match case {
            "put-refused" => {
                assert!(w.bridge().safety.lose(&o.extent.safety_key()));
                let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
                let meta = BlobMeta {
                    bucket: &extent.bucket_id,
                    extent: &extent.id,
                    cipher_sha256: &extent.cipher_sha256,
                };
                w.bridge()
                    .cache
                    .put(&o.extent.cache_key(), cipher, &meta)
                    .await
                    .unwrap();
                for s in &w.servers {
                    s.set_body_gone(true).await;
                }
                w.bridge().safety.refuse_puts(true);
            }
            _ => {
                // No R2 copy either: the read that breaks off is all.
                assert!(w.bridge().safety.lose(&o.extent.safety_key()));
                for s in &w.servers {
                    s.drop_next_bodies(1000).await;
                }
            }
        }
        w.advance_secs(31 * DAY_SECS);
        let run = w.scrub().await;
        assert_eq!(run.repaired, 0, "{case}");
        let now = w.bridge().clock.now().0;
        assert_eq!(
            w.next_at(&o).await,
            Some(now + 3_600_000),
            "{case}: a retry"
        );
        // The retry itself, with no regular check due, fails the same way
        // and keeps the next one.
        w.advance_secs(3600);
        w.scrub().await;
        let now = w.bridge().clock.now().0;
        assert_eq!(
            w.next_at(&o).await,
            Some(now + 3_600_000),
            "{case}: the watch-only retry keeps one too"
        );
    }
}

/// With `EVICTION=paused` no drain starts and a queued step does nothing,
/// even over the cap.
#[tokio::test(flavor = "current_thread")]
async fn a_paused_eviction_deletes_nothing() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 33).await;
    cfg_mut(&mut w).eviction_paused = true;
    w.bridge().evict_batch(0).await.unwrap();
    w.bridge().evict_batch(123).await.unwrap();
    assert!(w.has_safety(&o), "paused: nothing deleted");
    cfg_mut(&mut w).eviction_paused = false;
    w.bridge().evict_batch(0).await.unwrap();
    assert!(!w.has_safety(&o), "resumed: evicted");
}

/// With the scrub on, an extent eviction keeps for want of a release whose
/// only R2 copy is a cache fill (which the cache bucket's lifecycle rule
/// may expire) gets a scrub deadline at once, and the re-verify then
/// writes a safety copy, with no regular check due.
#[tokio::test(flavor = "current_thread")]
async fn a_kept_cache_only_extent_gets_a_safety_copy_back_soon() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 34).await;
    let cipher = w
        .bridge()
        .safety
        .stored(&o.extent.safety_key())
        .unwrap()
        .bytes;
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    let extent = w.rig.live(&w.bucket, "a").await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    w.bridge()
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    let c = &w.bridge().catalog;
    c.record_cache_fill(&o.extent, w.bridge().clock.now())
        .await
        .unwrap();
    c.sql
        .inner
        .fixture_exec(
            "UPDATE extents SET hot_safety_bytes = 0 WHERE id = ?1",
            &[SqlValue::Text(o.extent.as_str().to_owned())],
        )
        .await
        .unwrap();
    cfg_mut(&mut w).providers[1].release = false;
    w.bridge().evict_batch(0).await.unwrap();
    assert!(w.bridge().cache.contains(&o.extent.cache_key()), "kept");
    assert!(w.next_at(&o).await.is_some(), "the scrub looks at it soon");
    w.scrub().await;
    assert!(w.has_safety(&o), "the re-verify wrote a safety copy");
}

/// Puts an intact cache fill of `o` in place and counts it.
async fn cache_fill(w: &World, o: &Obj, name: &str, cipher: Vec<u8>) {
    let extent = w.rig.live(&w.bucket, name).await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    w.bridge()
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    w.bridge()
        .catalog
        .record_cache_fill(&o.extent, w.bridge().clock.now())
        .await
        .unwrap();
}

/// A pinned extent's cache fill that eviction keeps (no safety copy in
/// place) does not end the drain: the extents behind it in the order
/// still go.
#[tokio::test(flavor = "current_thread")]
async fn a_kept_cache_fill_does_not_end_the_drain() {
    let w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let a = w.released("a", 41).await;
    let b = w.released("b", 42).await;
    let cipher = w
        .bridge()
        .safety
        .stored(&a.extent.safety_key())
        .unwrap()
        .bytes;
    repinned_without_its_copy(&w, &a).await;
    cache_fill(&w, &a, "a", cipher).await;
    // `b` was read after `a`: it comes after it in the order.
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET last_read_at = ?2 WHERE id = ?1",
            &[
                SqlValue::Text(b.extent.as_str().to_owned()),
                SqlValue::Int(w.bridge().clock.now().0 + 1_000),
            ],
        )
        .await
        .unwrap();
    assert!(w.has_safety(&b));
    w.bridge().evict_batch(0).await.unwrap();
    assert!(
        w.bridge().cache.contains(&a.extent.cache_key()),
        "kept: the only R2 copy"
    );
    assert!(!w.has_safety(&b), "the drain went on past the kept fill");
}

/// A Usenet repair whose safety PUTs fail leaves no object with other
/// bytes under the safety key: eviction would take it for the copy and
/// delete a later intact cache fill.
#[tokio::test(flavor = "current_thread")]
async fn a_wrong_safety_object_is_not_taken_for_the_copy() {
    let w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 43).await;
    let key = o.extent.safety_key();
    let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
    assert!(w.bridge().safety.corrupt(&key, |b| b[10] ^= 1));
    w.advance_secs(31 * DAY_SECS);
    w.hide(1, &o, 0).await;
    w.scrub().await;
    w.advance_secs(3600);
    *w.bridge().safety.fail_put_prefix.borrow_mut() = Some("x/".to_string());
    assert_eq!(w.scrub().await.repaired, 1);
    *w.bridge().safety.fail_put_prefix.borrow_mut() = None;
    assert_eq!(w.safety_state(&o).await, "held");
    assert!(!w.has_safety(&o), "the object with other bytes is gone");
    assert!(alerts()
        .iter()
        .any(|a| a.starts_with("scrub-bad-safety-copy ") && a.contains(o.extent.as_str())));
    cache_fill(&w, &o, "a", cipher).await;
    w.bridge().evict_batch(0).await.unwrap();
    assert!(
        w.bridge().cache.contains(&o.extent.cache_key()),
        "the intact cache fill stays"
    );
}

/// A refill between the begin and the pre-delete check (the sequence
/// moved) ends the drain, as a refused claim does: what it still has to
/// evict is no longer known. A loss alone is passed over.
#[tokio::test(flavor = "current_thread")]
async fn a_moved_sequence_at_the_pre_delete_check_ends_the_drain() {
    let w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let a = w.released("a", 44).await;
    let b = w.released("b", 45).await;
    let c = &w.bridge().catalog;
    c.sql
        .inner
        .fixture_exec(
            "UPDATE extents SET last_read_at = ?2 WHERE id = ?1",
            &[
                SqlValue::Text(b.extent.as_str().to_owned()),
                SqlValue::Int(w.bridge().clock.now().0 + 1_000),
            ],
        )
        .await
        .unwrap();
    *c.sql.before_matching.borrow_mut() = Some((
        "FROM extents WHERE id = ?1 AND evict_seq = ?2",
        0,
        format!(
            "UPDATE extents SET hot_cache_bytes = cipher_size, evict_seq = evict_seq + 1 \
             WHERE id = '{}'",
            a.extent.as_str()
        ),
    ));
    w.bridge().evict_batch(0).await.unwrap();
    assert!(c.sql.before_matching.borrow().is_none(), "the check ran");
    assert!(w.has_safety(&a), "moved: nothing deleted");
    assert!(w.has_safety(&b), "the drain ended at the moved extent");
}

/// The scrub deletes a released extent's safety object whose bytes are
/// not the extent's, and only then says so; the deleted object is no
/// longer counted. A delete that fails is said as such, and nothing
/// changes.
#[tokio::test(flavor = "current_thread")]
async fn a_deleted_wrong_safety_object_is_uncounted_and_a_failed_delete_is_said() {
    for fails in [true, false] {
        let w = world().await;
        let o = w.released("a", 46).await;
        let key = o.extent.safety_key();
        assert!(w.bridge().safety.corrupt(&key, |b| b[10] ^= 1));
        if fails {
            *w.bridge().safety.fail_delete.borrow_mut() = Some(key.clone());
        }
        w.advance_secs(31 * DAY_SECS);
        w.hide(0, &o, 1).await;
        w.hide(1, &o, 1).await;
        w.scrub().await;
        w.advance_secs(3600);
        w.scrub().await;
        let counted = w
            .scalar(
                "SELECT hot_safety_bytes FROM extents WHERE id = ?1",
                &o.extent,
            )
            .await;
        let lines: Vec<String> = alerts()
            .into_iter()
            .filter(|a| a.starts_with("scrub-bad-safety-copy ") && a.contains(o.extent.as_str()))
            .collect();
        assert!(!lines.is_empty(), "fails={fails}: {lines:?}");
        assert_eq!(w.safety_state(&o).await, "released", "fails={fails}");
        if fails {
            assert!(
                lines.iter().all(|l| l.ends_with("the delete failed")),
                "{lines:?}"
            );
            assert!(w.bridge().safety.contains(&key));
            assert_ne!(counted, "0", "still there: still counted");
        } else {
            assert!(lines.iter().all(|l| l.ends_with("; deleted")), "{lines:?}");
            assert!(!w.bridge().safety.contains(&key));
            assert_eq!(counted, "0", "gone: no longer counted");
            assert_eq!(w.result(&o).await, "unrecoverable");
        }
    }
}

/// Writes the extent's own bytes under its safety key, as a checked put.
async fn put_safety_copy(w: &World, o: &Obj, name: &str, cipher: Vec<u8>) {
    let extent = w.rig.live(&w.bucket, name).await.unwrap().1.remove(0);
    let meta = BlobMeta {
        bucket: &extent.bucket_id,
        extent: &extent.id,
        cipher_sha256: &extent.cipher_sha256,
    };
    w.bridge()
        .safety
        .put(&o.extent.safety_key(), cipher, &meta)
        .await
        .unwrap();
}

/// A pinned extent's cache fill goes only while its safety copy is in
/// place: a blob the store checked as the extent's bytes. A blob that is
/// only there (other bytes, never checked) is not the copy.
#[tokio::test(flavor = "current_thread")]
async fn a_pinned_fill_stays_while_the_safety_blob_is_not_the_extents() {
    let w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 47).await;
    let key = o.extent.safety_key();
    let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
    repinned_without_its_copy(&w, &o).await;
    put_safety_copy(&w, &o, "a", cipher.clone()).await;
    assert!(w.bridge().safety.corrupt(&key, |b| b[10] ^= 1));
    cache_fill(&w, &o, "a", cipher).await;
    w.bridge().evict_batch(0).await.unwrap();
    assert!(
        w.bridge().cache.contains(&o.extent.cache_key()),
        "other bytes under the safety key: the fill stays"
    );
}

/// The scrub moves the sequence before it deletes a safety object: an
/// eviction that claimed the pinned row and found the copy in place, but
/// whose claim moved before the delete, deletes nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_pinned_fill_eviction_checks_its_claim_after_the_safety_check() {
    let w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 48).await;
    let cipher = w
        .bridge()
        .safety
        .stored(&o.extent.safety_key())
        .unwrap()
        .bytes;
    repinned_without_its_copy(&w, &o).await;
    put_safety_copy(&w, &o, "a", cipher.clone()).await;
    cache_fill(&w, &o, "a", cipher).await;
    let c = &w.bridge().catalog;
    // What the scrub does before it deletes a safety object.
    *c.sql.before_matching.borrow_mut() = Some((
        "FROM extents WHERE id = ?1 AND evict_seq = ?2",
        0,
        format!(
            "UPDATE extents SET evict_seq = evict_seq + 1 WHERE id = '{}'",
            o.extent.as_str()
        ),
    ));
    w.bridge().evict_batch(0).await.unwrap();
    assert!(
        w.bridge().cache.contains(&o.extent.cache_key()),
        "the claim moved: nothing deleted"
    );
    assert!(
        c.sql.before_matching.borrow().is_none(),
        "the claim was checked"
    );
}

/// A released extent eviction keeps for want of a release, whose only R2
/// copy is a cache fill 29.9 days old: the fill is written to the safety
/// store when eviction keeps it, so the cache's 30-day lifecycle rule
/// cannot take the last R2 copy. With the scrub on and off alike.
#[tokio::test(flavor = "current_thread")]
async fn a_kept_fill_near_the_cache_expiry_is_promoted_to_the_safety_store() {
    for scrub in [true, false] {
        let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
        let o = w.released("a", 49).await;
        let key = o.extent.safety_key();
        let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
        assert!(w.bridge().safety.lose(&key));
        w.bridge()
            .catalog
            .sql
            .inner
            .fixture_exec(
                "UPDATE extents SET hot_safety_bytes = 0 WHERE id = ?1",
                &[SqlValue::Text(o.extent.as_str().to_owned())],
            )
            .await
            .unwrap();
        cache_fill(&w, &o, "a", cipher.clone()).await;
        // The fill is 29.9 days old when eviction looks at it.
        w.advance_secs(29 * DAY_SECS + 77_760);
        cfg_mut(&mut w).scrub.on = scrub;
        cfg_mut(&mut w).providers[1].release = false;
        w.bridge().evict_batch(0).await.unwrap();
        assert!(w.bridge().cache.contains(&o.extent.cache_key()), "kept");
        // Day 30: the cache's lifecycle rule takes the fill.
        w.advance_secs(8_640);
        assert!(w.bridge().cache.lose(&o.extent.cache_key()));
        let stored = w.bridge().safety.stored(&key);
        assert_eq!(
            stored.map(|b| b.bytes),
            Some(cipher),
            "scrub={scrub}: the safety copy holds the extent's bytes"
        );
        assert_eq!(
            w.scalar(
                "SELECT hot_safety_bytes FROM extents WHERE id = ?1",
                &o.extent
            )
            .await,
            w.scalar("SELECT cipher_size FROM extents WHERE id = ?1", &o.extent)
                .await,
            "scrub={scrub}: counted"
        );
    }
}

/// The retry of a re-verify is on record before the re-verify writes or
/// records anything: an invocation that ends during its cache-to-safety
/// write (after the copy checks were recorded) leaves the retry behind.
#[tokio::test(flavor = "current_thread")]
async fn a_re_verify_retry_is_on_record_before_its_safety_write() {
    let mut w = world().await;
    let o = w.released("a", 50).await;
    let key = o.extent.safety_key();
    let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
    cfg_mut(&mut w).providers[1].release = false;
    assert!(w.bridge().safety.lose(&key));
    cache_fill(&w, &o, "a", cipher).await;
    for s in &w.servers {
        s.set_body_gone(true).await;
    }
    w.advance_secs(31 * DAY_SECS);
    let safety = &w.bridge().safety;
    safety.hold_put_prefix.replace(Some(key.clone()));
    let mut run = Box::pin(w.bridge().scrub_run());
    let held = async {
        while !safety.held.get() {
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        () = held => {}
        _ = &mut run => panic!("the run ended before its safety write"),
    }
    // The invocation ends there.
    drop(run);
    safety.hold_put_prefix.replace(None);
    let now = w.bridge().clock.now().0;
    assert_eq!(
        w.next_at(&o).await,
        Some(now + 3_600_000),
        "the retry stands"
    );
}

/// `/_admin/evict` applies eviction's last-copy rule and its pause: a
/// cache fill that is an unreleasable extent's only R2 copy stays, and
/// nothing is deleted while `EVICTION=paused`.
#[tokio::test(flavor = "current_thread")]
async fn admin_evict_keeps_a_last_copy_and_honours_the_pause() {
    let mut w = world().await;
    let o = w.released("a", 51).await;
    let key = o.extent.safety_key();
    let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
    assert!(w.bridge().safety.lose(&key));
    cache_fill(&w, &o, "a", cipher).await;
    let token = w.bridge().cfg.admin_token.expose().to_string();
    let evict = || Req {
        method: Method::Post,
        target: format!("/_admin/evict/{BUCKET}/a"),
        headers: vec![("authorization".to_string(), format!("Bearer {token}"))],
        body: Vec::new(),
    };
    cfg_mut(&mut w).eviction_paused = true;
    let paused = w.rig.send(evict()).await;
    assert!(
        w.bridge().cache.contains(&o.extent.cache_key()),
        "paused: nothing deleted"
    );
    assert_eq!(paused.status, 503);
    cfg_mut(&mut w).eviction_paused = false;
    cfg_mut(&mut w).providers[1].release = false;
    let kept = w.rig.send(evict()).await;
    assert!(
        w.bridge().cache.contains(&o.extent.cache_key()),
        "the only R2 copy of an unreleasable extent stays"
    );
    assert_eq!(kept.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&kept.body).unwrap();
    assert_eq!(body["cache_kept"], 1);
    cfg_mut(&mut w).providers[1].release = true;
    w.rig.send(evict()).await.expect(200);
    assert!(
        !w.bridge().cache.contains(&o.extent.cache_key()),
        "releasable: the fill goes"
    );
}

/// Makes `o` a released extent whose only R2 copy is a counted cache fill.
async fn cache_only(w: &World, o: &Obj, name: &str) {
    let key = o.extent.safety_key();
    let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
    assert!(w.bridge().safety.lose(&key));
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET hot_safety_bytes = 0 WHERE id = ?1",
            &[SqlValue::Text(o.extent.as_str().to_owned())],
        )
        .await
        .unwrap();
    cache_fill(w, o, name, cipher).await;
}

/// Runs every queued eviction step, the ones they queue too.
async fn drain_steps(w: &World) {
    loop {
        let steps: Vec<Job> = w
            .bridge()
            .jobs
            .inner
            .take()
            .into_iter()
            .map(|s| s.job)
            .filter(|j| matches!(j, Job::Evict { .. }))
            .collect();
        if steps.is_empty() {
            return;
        }
        for step in steps {
            w.bridge().run_job(&step).await;
        }
    }
}

/// More kept cache-only fills in one window than a step writes: the drain
/// goes on from the first one not written, and every one gets its safety
/// copy, however the drain's target falls.
#[tokio::test(flavor = "current_thread")]
async fn every_kept_fill_of_a_window_is_promoted_before_the_drain_moves_past_it() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let mut objs = Vec::new();
    for i in 0..9u8 {
        let name = format!("k{i}");
        let o = w.released(&name, 60 + i).await;
        cache_only(&w, &o, &name).await;
        objs.push(o);
    }
    cfg_mut(&mut w).providers[1].release = false;
    w.bridge().jobs.inner.take();
    w.bridge().evict_batch(0).await.unwrap();
    drain_steps(&w).await;
    for (i, o) in objs.iter().enumerate() {
        assert!(w.has_safety(o), "k{i}: promoted");
    }
}

/// `deleted` names a safety copy given up (a restore without one, a
/// drill), not an extent out of service: a live extent in that state with
/// no release evidence keeps its cache fill, in the drain and in
/// `/_admin/evict`, and no safety copy is written for it.
#[tokio::test(flavor = "current_thread")]
async fn a_live_extent_without_its_safety_copy_keeps_its_fill_unwritten() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 70).await;
    cache_only(&w, &o, "a").await;
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET safety_state = 'deleted', release_evidence = NULL, \
             evict_seq = evict_seq + 1 WHERE id = ?1",
            &[SqlValue::Text(o.extent.as_str().to_owned())],
        )
        .await
        .unwrap();
    cfg_mut(&mut w).providers[1].release = false;
    w.bridge().evict_batch(0).await.unwrap();
    assert!(
        w.bridge().cache.contains(&o.extent.cache_key()),
        "the drain keeps the fill"
    );
    assert!(!w.has_safety(&o), "no safety copy is written for it");
    let token = w.bridge().cfg.admin_token.expose().to_string();
    let r = w
        .rig
        .send(Req {
            method: Method::Post,
            target: format!("/_admin/evict/{BUCKET}/a"),
            headers: vec![("authorization".to_string(), format!("Bearer {token}"))],
            body: Vec::new(),
        })
        .await;
    assert!(
        w.bridge().cache.contains(&o.extent.cache_key()),
        "/_admin/evict keeps the fill"
    );
    assert_eq!(r.status, 200);
}

/// `/_admin/evict` decides each extent's last-copy rule right before its
/// deletes: a loss the scrub records after the request began keeps the
/// fill that is the extent's only R2 copy.
#[tokio::test(flavor = "current_thread")]
async fn admin_evict_sees_a_loss_recorded_during_the_request() {
    let w = world().await;
    let o = w.released("a", 73).await;
    cache_only(&w, &o, "a").await;
    *w.bridge().catalog.sql.before_matching.borrow_mut() = Some((
        "SELECT evict_seq",
        0,
        format!(
            "UPDATE scrub_copies SET full_loss_at = {} WHERE extent_id = '{}' AND backbone = 'beta'",
            w.bridge().clock.now().0,
            o.extent.as_str()
        ),
    ));
    let token = w.bridge().cfg.admin_token.expose().to_string();
    let r = w
        .rig
        .send(Req {
            method: Method::Post,
            target: format!("/_admin/evict/{BUCKET}/a"),
            headers: vec![("authorization".to_string(), format!("Bearer {token}"))],
            body: Vec::new(),
        })
        .await;
    assert!(
        w.bridge().cache.contains(&o.extent.cache_key()),
        "the loss on record keeps the only R2 copy"
    );
    assert_eq!(r.status, 200);
    assert!(
        w.bridge().catalog.sql.before_matching.borrow().is_none(),
        "the loss was recorded during the request"
    );
}

/// Kept fills with nothing to write (the fill is gone from the cache, as
/// the lifecycle rule takes it while it is still counted) do not take a
/// step's share: with nine of them at the head (unstamped legacy rows), the
/// drain still reaches the extent behind them.
#[tokio::test(flavor = "current_thread")]
async fn kept_fills_with_nothing_to_write_do_not_hold_the_drain() {
    let w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    for i in 0..9u8 {
        let name = format!("k{i}");
        let o = w.released(&name, 80 + i).await;
        cache_only(&w, &o, &name).await;
        set_evidence(&w, &o, &[("alpha", "body")]).await;
        assert!(w.bridge().cache.lose(&o.extent.cache_key()));
        w.bridge()
            .catalog
            .sql
            .inner
            .fixture_exec(
                "UPDATE extents SET last_read_at = NULL WHERE id = ?1",
                &[SqlValue::Text(o.extent.as_str().to_owned())],
            )
            .await
            .unwrap();
    }
    let last = w.released("z", 90).await;
    w.bridge().jobs.inner.take();
    w.bridge().evict_batch(0).await.unwrap();
    for _ in 0..20 {
        let steps: Vec<Job> = w
            .bridge()
            .jobs
            .inner
            .take()
            .into_iter()
            .map(|s| s.job)
            .filter(|j| matches!(j, Job::Evict { .. }))
            .collect();
        if steps.is_empty() {
            break;
        }
        for step in steps {
            w.bridge().run_job(&step).await;
        }
    }
    assert!(!w.has_safety(&last), "the extent behind them was evicted");
}

/// An eviction step that ends between a promotion's write and its
/// collection guard, after the object was deleted and collected: a later
/// eviction step reconciles the write-ahead intent, with the scrub off,
/// and the copy is collected.
#[tokio::test(flavor = "current_thread")]
async fn an_interrupted_promotion_is_collected_by_a_later_step() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 71).await;
    cache_only(&w, &o, "a").await;
    cfg_mut(&mut w).scrub.on = false;
    cfg_mut(&mut w).providers[1].release = false;
    let bridge = w.bridge();
    let safety = &bridge.safety;
    let key = o.extent.safety_key();
    safety.hold_put_prefix.replace(Some(key.clone()));
    let mut step = Box::pin(bridge.evict_batch(0));
    let meanwhile = async {
        while !safety.held.get() {
            tokio::task::yield_now().await;
        }
        w.rig
            .call(&w.signer, Method::Delete, &path(BUCKET, "a"), &[], &[], b"")
            .await
            .expect(204);
        assert_eq!(
            bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
            JobOutcome::Ack
        );
        // The guard after the write never answers.
        bridge
            .catalog
            .sql
            .stall_exec_matching
            .set(Some("'delete_safety', ?2 FROM extents e"));
        safety.hold_put_prefix.replace(None);
        while bridge.catalog.sql.stall_exec_matching.get().is_some() {
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        () = meanwhile => {}
        _ = &mut step => panic!("the step ended before its guard"),
    }
    drop(step);
    bridge.catalog.sql.selected_exec.disarm();
    assert!(w.has_safety(&o), "the write landed");
    bridge
        .clock
        .advance_ms(velmora_bridge::jobtable::JOB_MAX_AGE_MS + 1);
    bridge.evict_batch(0).await.unwrap();
    assert_eq!(
        bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert!(
        !w.has_safety(&o),
        "the reconciled intent collected the copy"
    );
}

/// As above, with the tier under its cap afterwards: no eviction step runs,
/// and the dispatcher's eviction check reconciles the intent.
#[tokio::test(flavor = "current_thread")]
async fn an_interrupted_promotion_is_collected_by_the_dispatcher_under_the_cap() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 71).await;
    cache_only(&w, &o, "a").await;
    cfg_mut(&mut w).scrub.on = false;
    cfg_mut(&mut w).providers[1].release = false;
    let bridge = w.bridge();
    let safety = &bridge.safety;
    let key = o.extent.safety_key();
    safety.hold_put_prefix.replace(Some(key.clone()));
    let mut step = Box::pin(bridge.evict_batch(0));
    let meanwhile = async {
        while !safety.held.get() {
            tokio::task::yield_now().await;
        }
        w.rig
            .call(&w.signer, Method::Delete, &path(BUCKET, "a"), &[], &[], b"")
            .await
            .expect(204);
        assert_eq!(
            bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
            JobOutcome::Ack
        );
        // The guard after the write never answers.
        bridge
            .catalog
            .sql
            .stall_exec_matching
            .set(Some("'delete_safety', ?2 FROM extents e"));
        safety.hold_put_prefix.replace(None);
        while bridge.catalog.sql.stall_exec_matching.get().is_some() {
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        () = meanwhile => {}
        _ = &mut step => panic!("the step ended before its guard"),
    }
    drop(step);
    bridge.catalog.sql.selected_exec.disarm();
    assert!(w.has_safety(&o), "the write landed");
    bridge
        .clock
        .advance_ms(velmora_bridge::jobtable::JOB_MAX_AGE_MS + 1);
    // The tier is under its cap now: no drain runs, the dispatcher's check
    // still reconciles.
    cfg_mut(&mut w).hot_cap_bytes = u64::MAX / 4;
    let bridge = w.bridge();
    bridge
        .clock
        .advance_ms(i64::from(velmora_bridge::jobs::EVICT_CHECK_SECS) * 1000);
    bridge.dispatch().await.unwrap();
    assert_eq!(
        bridge.run_job(&Job::Gc { v: JOB_VERSION }).await,
        JobOutcome::Ack
    );
    assert!(
        !w.has_safety(&o),
        "the reconciled intent collected the copy"
    );
}

/// A promotion takes its share of the jobs' memory first. With none to
/// spare nothing is written, the step does not move past the fill, and a
/// later step writes it.
#[tokio::test(flavor = "current_thread")]
async fn a_promotion_waits_for_the_jobs_memory() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 72).await;
    cache_only(&w, &o, "a").await;
    cfg_mut(&mut w).providers[1].release = false;
    let bridge = w.bridge();
    let all = bridge
        .budget
        .charge_job(bridge.budget.job_capacity())
        .await
        .unwrap();
    bridge.jobs.inner.take();
    bridge.evict_batch(0).await.unwrap();
    assert!(!w.has_safety(&o), "no memory to spare: nothing written");
    let next: Vec<_> = bridge.jobs.inner.take();
    assert!(
        next.iter()
            .any(|s| matches!(s.job, Job::Evict { .. }) && s.delay_secs > 0),
        "a later step is queued: {:?}",
        next.iter()
            .map(|s| (&s.job, s.delay_secs))
            .collect::<Vec<_>>()
    );
    drop(all);
    for s in next {
        bridge.run_job(&s.job).await;
    }
    assert!(w.has_safety(&o), "written by the later step");
}

/// A kept fill the cache's lifecycle rule took is no longer counted, or
/// its bytes would make the drain take other copies: for a released
/// extent kept for want of a release, and for one whose safety copy was
/// given up (`deleted`).
#[tokio::test(flavor = "current_thread")]
async fn a_kept_fill_the_lifecycle_took_is_no_longer_counted() {
    for state in ["released", "deleted"] {
        let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
        let o = w.released("a", 74).await;
        cache_only(&w, &o, "a").await;
        if state == "deleted" {
            w.bridge()
                .catalog
                .sql
                .inner
                .fixture_exec(
                    "UPDATE extents SET safety_state = 'deleted', release_evidence = NULL, \
                     evict_seq = evict_seq + 1 WHERE id = ?1",
                    &[SqlValue::Text(o.extent.as_str().to_owned())],
                )
                .await
                .unwrap();
        }
        cfg_mut(&mut w).providers[1].release = false;
        assert!(w.bridge().cache.lose(&o.extent.cache_key()));
        w.bridge().evict_batch(0).await.unwrap();
        assert_eq!(
            w.scalar(
                "SELECT hot_cache_bytes FROM extents WHERE id = ?1",
                &o.extent
            )
            .await,
            "0",
            "{state}: the fill that is gone is not counted"
        );
    }
}

/// The same for a kept extent that has its safety copy: its fill that the
/// lifecycle rule took is no longer counted either.
#[tokio::test(flavor = "current_thread")]
async fn a_gone_fill_of_a_kept_extent_with_its_safety_copy_is_no_longer_counted() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 75).await;
    let cipher = w
        .bridge()
        .safety
        .stored(&o.extent.safety_key())
        .unwrap()
        .bytes;
    cache_fill(&w, &o, "a", cipher).await;
    cfg_mut(&mut w).providers[1].release = false;
    assert!(w.bridge().cache.lose(&o.extent.cache_key()));
    w.bridge().evict_batch(0).await.unwrap();
    assert!(w.has_safety(&o), "kept");
    assert_eq!(
        w.scalar(
            "SELECT hot_cache_bytes FROM extents WHERE id = ?1",
            &o.extent
        )
        .await,
        "0"
    );
}

/// Bytes of a gone fill are not part of what the drain has to free: when
/// they were all of the tier's excess, the drain leaves an evictable copy
/// alone.
#[tokio::test(flavor = "current_thread")]
async fn a_gone_fill_does_not_make_the_drain_take_another_copy() {
    let mut w = world().await;
    let kept = w.released("a", 76).await;
    cache_only(&w, &kept, "a").await;
    set_evidence(&w, &kept, &[("alpha", "body")]).await;
    let other = w.released("b", 77).await;
    let size: u64 = w
        .scalar(
            "SELECT cipher_size FROM extents WHERE id = ?1",
            &other.extent,
        )
        .await
        .parse()
        .unwrap();
    // Over the cap only by the fill that is no longer there.
    cfg_mut(&mut w).hot_cap_bytes = 2 * size - 1;
    assert!(w.bridge().cache.lose(&kept.extent.cache_key()));
    w.bridge().evict_batch(0).await.unwrap();
    assert!(w.has_safety(&other), "the evictable copy stays");
}

/// Kept fills still to be written when the drain has nothing left to free
/// (gone fills took its whole excess): the next step writes them, though
/// it starts as a new drain and the tier, with the copies written so far,
/// is no longer over its cap.
#[tokio::test(flavor = "current_thread")]
async fn kept_fills_are_promoted_after_the_excess_runs_out() {
    let mut w = world().await;
    // Nine fills the lifecycle rule took, ahead of nine to write.
    let mut gone = Vec::new();
    for i in 0..9u8 {
        let name = format!("g{i}");
        let o = w.released(&name, 91 + i).await;
        cache_only(&w, &o, &name).await;
        set_evidence(&w, &o, &[("alpha", "body")]).await;
        gone.push(o);
    }
    let mut objs = Vec::new();
    for i in 0..9u8 {
        let name = format!("k{i}");
        let o = w.released(&name, 110 + i).await;
        cache_only(&w, &o, &name).await;
        set_evidence(&w, &o, &[("alpha", "body")]).await;
        w.bridge()
            .catalog
            .sql
            .inner
            .fixture_exec(
                "UPDATE extents SET last_read_at = last_read_at + 1000 WHERE id = ?1",
                &[SqlValue::Text(o.extent.as_str().to_owned())],
            )
            .await
            .unwrap();
        objs.push(o);
    }
    let size: u64 = w
        .scalar(
            "SELECT cipher_size FROM extents WHERE id = ?1",
            &gone[0].extent,
        )
        .await
        .parse()
        .unwrap();
    // 18 fills counted, over the cap; once the gone ones are not counted,
    // the nine fills and the eight copies written in a step are under it.
    cfg_mut(&mut w).hot_cap_bytes = 18 * size - 1;
    for o in &gone {
        assert!(w.bridge().cache.lose(&o.extent.cache_key()));
    }
    w.bridge().jobs.inner.take();
    w.bridge().evict_batch(0).await.unwrap();
    drain_steps(&w).await;
    for (i, o) in objs.iter().enumerate() {
        assert!(w.has_safety(o), "k{i}: promoted");
    }
}

/// A step HEADs only the kept fills it gets to: with twenty to write and
/// a share of eight, the first step stops within its first batch of HEADs.
#[tokio::test(flavor = "current_thread")]
async fn a_step_heads_only_the_kept_fills_it_gets_to() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    for i in 0..20u8 {
        let name = format!("k{i}");
        let o = w.released(&name, 120 + i).await;
        cache_only(&w, &o, &name).await;
    }
    cfg_mut(&mut w).providers[1].release = false;
    let cache = &w.bridge().cache;
    let before = cache.heads.get();
    w.bridge().evict_batch(0).await.unwrap();
    let heads = cache.heads.get() - before;
    assert!(heads <= 16, "{heads} cache HEADs for a share of 8");
}

/// A drain over the cap that finds a promotion marker writes those fills,
/// then evicts from the head of the order: the oldest copy goes first.
#[tokio::test(flavor = "current_thread")]
async fn a_drain_after_a_promotion_marker_evicts_the_oldest_copy_first() {
    let mut w = world().await;
    let old = w.released("a", 130).await;
    let new = w.released("b", 131).await;
    let c = &w.bridge().catalog;
    let read = |o: &Obj, at: i64| {
        let id = o.extent.as_str().to_owned();
        async move {
            c.sql
                .inner
                .fixture_exec(
                    "UPDATE extents SET last_read_at = ?2 WHERE id = ?1",
                    &[SqlValue::Text(id), SqlValue::Int(at)],
                )
                .await
                .unwrap();
        }
    };
    let now = w.bridge().clock.now().0;
    read(&old, now - 2_000).await;
    read(&new, now - 1_000).await;
    // A marker left past the oldest copy.
    c.set_evict_cursor(&EvictCursor::Promote(Box::new(EvictCursor::After(
        now - 2_000,
        old.extent.as_str().to_owned(),
    ))))
    .await
    .unwrap();
    let size: u64 = w
        .scalar("SELECT cipher_size FROM extents WHERE id = ?1", &old.extent)
        .await
        .parse()
        .unwrap();
    // Over the cap by less than one copy.
    cfg_mut(&mut w).hot_cap_bytes = 2 * size - 1;
    w.bridge().jobs.inner.take();
    w.bridge().evict_batch(0).await.unwrap();
    drain_steps(&w).await;
    assert!(!w.has_safety(&old), "the oldest copy went");
    assert!(w.has_safety(&new), "the newer one stays");
}

/// A promotion step that came during a pause leaves its marker: once
/// eviction resumes, the dispatcher's check starts a step for it though
/// the tier is under its cap.
#[tokio::test(flavor = "current_thread")]
async fn the_dispatcher_resumes_promotions_a_pause_deferred() {
    let mut w = world().await;
    let o = w.released("a", 132).await;
    cache_only(&w, &o, "a").await;
    cfg_mut(&mut w).providers[1].release = false;
    w.bridge()
        .catalog
        .set_evict_cursor(&EvictCursor::Promote(Box::new(EvictCursor::Start)))
        .await
        .unwrap();
    cfg_mut(&mut w).eviction_paused = true;
    w.bridge().jobs.inner.take();
    assert_eq!(w.bridge().evict_batch(0).await.unwrap(), 0);
    cfg_mut(&mut w).eviction_paused = false;
    cfg_mut(&mut w).hot_cap_bytes = u64::MAX / 4;
    let bridge = w.bridge();
    bridge
        .clock
        .advance_ms(i64::from(velmora_bridge::jobs::EVICT_CHECK_SECS) * 1000);
    bridge.dispatch().await.unwrap();
    drain_steps(&w).await;
    assert!(w.has_safety(&o), "the deferred fill was written");
}

/// A step that fails part way through its kept fills (here a cache HEAD)
/// leaves a promotion marker behind it, and the dispatcher's check writes
/// the fills later, with the tier under its cap.
#[tokio::test(flavor = "current_thread")]
async fn a_step_that_fails_mid_promotion_leaves_its_fills_to_a_later_one() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 133).await;
    cache_only(&w, &o, "a").await;
    cfg_mut(&mut w).providers[1].release = false;
    w.bridge().cache.trip.arm(0, Trip::Fail);
    assert!(w.bridge().evict_batch(0).await.is_err(), "the HEAD failed");
    w.bridge().cache.trip.disarm();
    assert!(!w.has_safety(&o));
    cfg_mut(&mut w).hot_cap_bytes = u64::MAX / 4;
    let bridge = w.bridge();
    bridge
        .clock
        .advance_ms(i64::from(velmora_bridge::jobs::EVICT_CHECK_SECS) * 1000);
    bridge.jobs.inner.take();
    let report = bridge.dispatch().await.unwrap();
    assert!(report.evict_enqueued, "a step for the marker is reported");
    drain_steps(&w).await;
    assert!(w.has_safety(&o), "written by the later step");
}

/// A continuation that fails after the first step wrote part of a
/// window's kept fills, whose claim the failure used up (a second
/// delivery does nothing): the marker it left lets the dispatcher's check
/// finish the rest.
#[tokio::test(flavor = "current_thread")]
async fn a_failed_continuation_after_partial_promotion_is_finished_later() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let mut objs = Vec::new();
    for i in 0..12u8 {
        let name = format!("k{i}");
        let o = w.released(&name, 140 + i).await;
        cache_only(&w, &o, &name).await;
        objs.push(o);
    }
    cfg_mut(&mut w).providers[1].release = false;
    w.bridge().jobs.inner.take();
    w.bridge().evict_batch(0).await.unwrap();
    let written = objs.iter().filter(|o| w.has_safety(o)).count();
    assert_eq!(written, 8, "the first step wrote its share");
    let next: Vec<Job> = w
        .bridge()
        .jobs
        .inner
        .take()
        .into_iter()
        .map(|s| s.job)
        .collect();
    let Some(step @ Job::Evict { remaining, .. }) = next.first().cloned() else {
        panic!("a continuation was queued: {next:?}")
    };
    assert!(remaining > 0, "a drain step, not a new drain");
    // The continuation fails at its cache checks, after its claim.
    w.bridge().cache.trip.arm(0, Trip::Fail);
    assert!(w.bridge().evict_batch(remaining).await.is_err());
    w.bridge().cache.trip.disarm();
    // A second delivery finds its claim used.
    w.bridge().run_job(&step).await;
    assert_eq!(
        objs.iter().filter(|o| w.has_safety(o)).count(),
        8,
        "nothing more yet"
    );
    cfg_mut(&mut w).hot_cap_bytes = u64::MAX / 4;
    let bridge = w.bridge();
    bridge
        .clock
        .advance_ms(i64::from(velmora_bridge::jobs::EVICT_CHECK_SECS) * 1000);
    bridge.jobs.inner.take();
    assert!(bridge.dispatch().await.unwrap().evict_enqueued);
    drain_steps(&w).await;
    for (i, o) in objs.iter().enumerate() {
        assert!(w.has_safety(o), "k{i}: written");
    }
}

/// Runs the dispatcher's eviction check (due once per `EVICT_CHECK_SECS`)
/// and every eviction step it queues.
async fn evict_check_now(w: &World) {
    let bridge = w.bridge();
    bridge
        .clock
        .advance_ms(i64::from(velmora_bridge::jobs::EVICT_CHECK_SECS) * 1000);
    bridge.jobs.inner.take();
    bridge.dispatch().await.unwrap();
    drain_steps(w).await;
}

/// A loss the scrub records keeps the extent from eviction, and under
/// the cap no drain lists it: the fill that is its only R2 copy (29.9
/// days old here) is written to the safety store at the sighting, so the
/// cache's 30-day rule cannot take the last R2 copy.
#[tokio::test(flavor = "current_thread")]
async fn a_lost_extents_only_fill_under_the_cap_is_written_at_the_sighting() {
    let w = world().await;
    let o = w.released("a", 150).await;
    let key = o.extent.safety_key();
    let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
    // The fill is written a day after the release; its checks fall due
    // when it is 29.9 days old.
    w.advance_secs(95_040);
    cache_only(&w, &o, "a").await;
    w.advance_secs(29 * DAY_SECS + 77_760);
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;
    // The sighting; the repair waits for its confirmation.
    assert_eq!(w.scrub().await.suspect, 1);
    // Day 30: the cache's lifecycle rule takes the fill.
    w.advance_secs(8_640);
    assert!(w.bridge().cache.lose(&o.extent.cache_key()));
    assert_eq!(
        w.bridge().safety.stored(&key).map(|b| b.bytes),
        Some(cipher),
        "the safety store holds the bytes"
    );
    assert!(alerts()
        .iter()
        .any(|a| a.starts_with("scrub-protect ") && a.contains(o.extent.as_str())));
}

/// A rule change that retires a counting backbone, with the tier under
/// its cap and the fill 29.9 days old: the dispatcher's check sweeps the
/// whole eviction order and writes the fill to the safety store. With the
/// scrub on and off.
#[tokio::test(flavor = "current_thread")]
async fn a_rule_change_under_the_cap_sweeps_the_kept_fills_to_safety() {
    for scrub in [true, false] {
        let mut w = world().await;
        cfg_mut(&mut w).scrub.on = scrub;
        let o = w.released("a", 151).await;
        let key = o.extent.safety_key();
        let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
        cache_only(&w, &o, "a").await;
        // The rule the dispatcher first runs under is recorded.
        evict_check_now(&w).await;
        w.advance_secs(29 * DAY_SECS + 77_760);
        cfg_mut(&mut w).providers[1].release = false;
        evict_check_now(&w).await;
        w.advance_secs(8_640);
        assert!(w.bridge().cache.lose(&o.extent.cache_key()));
        assert_eq!(
            w.bridge().safety.stored(&key).map(|b| b.bytes),
            Some(cipher),
            "scrub={scrub}: the sweep wrote the fill"
        );
        assert!(
            alerts().iter().any(|a| a.starts_with("evict-sweep-done ")),
            "scrub={scrub}: the sweep's end is said"
        );
    }
}

/// Over the cap, a drain frees what it must from the head of the order
/// and stops; a fill read a moment ago sits at the tail, past where any
/// drain gets. After a rule change (here `VERIFY_MODE` from `light` to
/// `body`, which leaves only the tail's STAT-only release unreleasable)
/// the sweep reaches it all the same.
#[tokio::test(flavor = "current_thread")]
async fn a_rule_change_reaches_a_hot_fill_at_the_tail() {
    let mut w = world().await;
    let tail = w.released("t", 156).await;
    let key = tail.extent.safety_key();
    let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
    cache_only(&w, &tail, "t").await;
    set_evidence(&w, &tail, &[("alpha", "stat"), ("beta", "stat")]).await;
    let size: u64 = w
        .scalar(
            "SELECT cipher_size FROM extents WHERE id = ?1",
            &tail.extent,
        )
        .await
        .parse()
        .unwrap();
    // A hundred older copies ahead of it, released on a full read.
    let db = &w.bridge().catalog.sql.inner;
    let evidence = r#"[{"backbone":"alpha","kind":"body","plan_rev":0},{"backbone":"beta","kind":"stat","plan_rev":0}]"#;
    let seed = db.fixture(
        "WITH RECURSIVE n(x) AS (VALUES (1) UNION ALL SELECT x+1 FROM n WHERE x < 100) \
         INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at,hot_safety_bytes,last_read_at,release_evidence) \
         SELECT printf('fixture-%05d', x), ?1, 'committed', 1, ?3, zeroblob(48), zeroblob(16), zeroblob(32), zeroblob(32), 'released', 0, ?3, x, ?2 FROM n",
        "INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at,hot_safety_bytes,last_read_at,release_evidence) \
         SELECT 'fixture-' || lpad(CAST(x AS text), 5, '0'), ?1, 'committed', 1, ?3, \
           decode(repeat('00', 48), 'hex'), decode(repeat('00', 16), 'hex'), \
           decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), 'released', 0, ?3, x, ?2 \
         FROM generate_series(1, 100) x",
    );
    db.fixture_exec(
        seed,
        &[
            SqlValue::Text(w.bucket.id.as_str().to_owned()),
            SqlValue::Text(evidence.to_owned()),
            SqlValue::Int(size as i64),
        ],
    )
    .await
    .unwrap();
    cfg_mut(&mut w).verify.mode = velmora_bridge::config::VerifyMode::Light;
    cfg_mut(&mut w).hot_cap_bytes = u64::MAX / 4;
    evict_check_now(&w).await;
    // Over the cap by about ten copies: a drain frees them from the head.
    cfg_mut(&mut w).hot_cap_bytes = 101 * size - 1;
    cfg_mut(&mut w).verify.mode = velmora_bridge::config::VerifyMode::Body;
    evict_check_now(&w).await;
    assert_eq!(
        w.bridge().safety.stored(&key).map(|b| b.bytes),
        Some(cipher),
        "the tail's fill was written"
    );
}

/// A count that outlived its copy (a finish that lost its compare-and-set
/// after the deletes leaves `hot_safety_bytes` with no `x/` object): a
/// sweep looks rather than trusts it, and writes the kept fill.
#[tokio::test(flavor = "current_thread")]
async fn a_sweep_writes_a_kept_fill_whose_safety_count_outlived_its_copy() {
    let mut w = world().await;
    let o = w.released("a", 157).await;
    let key = o.extent.safety_key();
    let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
    cache_fill(&w, &o, "a", cipher.clone()).await;
    // The copy is gone; its count stands.
    assert!(w.bridge().safety.lose(&key));
    assert_ne!(
        w.scalar(
            "SELECT hot_safety_bytes FROM extents WHERE id = ?1",
            &o.extent
        )
        .await,
        "0"
    );
    evict_check_now(&w).await;
    cfg_mut(&mut w).providers[1].release = false;
    evict_check_now(&w).await;
    assert_eq!(
        w.bridge().safety.stored(&key).map(|b| b.bytes),
        Some(cipher),
        "the sweep wrote the fill"
    );
}

/// A marker's step (a sweep, or fills left to write) evicts nothing and
/// does not total the tier: that aggregate over the whole eviction order
/// would run on every step of a sweep.
#[tokio::test(flavor = "current_thread")]
async fn a_marker_step_does_not_total_the_tier() {
    let mut w = world_with(|cfg| cfg.hot_cap_bytes = 1).await;
    let o = w.released("a", 158).await;
    cache_only(&w, &o, "a").await;
    cfg_mut(&mut w).providers[1].release = false;
    let c = &w.bridge().catalog;
    c.set_evict_cursor(&EvictCursor::Promote(Box::new(EvictCursor::Start)))
        .await
        .unwrap();
    *c.sql.fail_matching.borrow_mut() = Some(("), 0), COUNT(*) FROM extents WHERE", 0));
    w.bridge().jobs.inner.take();
    let step = w.bridge().evict_batch(0).await;
    *c.sql.fail_matching.borrow_mut() = None;
    step.expect("no tier total in a marker's step");
    assert!(w.has_safety(&o), "the marked fill was written");
}

/// A catalogue with no rule on record (the first check after this
/// release) sweeps the whole eviction order: an unreleasable cache-only
/// fill present then is written to the safety store, without relying on
/// any count made before.
#[tokio::test(flavor = "current_thread")]
async fn the_first_check_sweeps_and_writes_an_unreleasable_fill() {
    let mut w = world().await;
    let o = w.released("a", 159).await;
    let key = o.extent.safety_key();
    let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
    cache_only(&w, &o, "a").await;
    cfg_mut(&mut w).providers[1].release = false;
    assert_eq!(w.bridge().catalog.evict_rule_seen().await.unwrap(), None);
    evict_check_now(&w).await;
    assert_eq!(
        w.bridge().safety.stored(&key).map(|b| b.bytes),
        Some(cipher),
        "the first sweep wrote the fill"
    );
    assert_eq!(
        w.bridge().catalog.evict_rule_seen().await.unwrap(),
        Some(w.bridge().rule_fingerprint()),
        "and recorded the rule it covered"
    );
}

/// A sweep step covers a whole window: rows that may go do not end it
/// early, as they end a drain's step at a batch. 450 releasable rows take
/// three windows of 200, not nine batches of 50.
#[tokio::test(flavor = "current_thread")]
async fn a_sweep_step_covers_a_whole_window() {
    let w = world().await;
    let o = w.released("a", 160).await;
    let db = &w.bridge().catalog.sql.inner;
    let evidence = r#"[{"backbone":"alpha","kind":"body","plan_rev":0},{"backbone":"beta","kind":"stat","plan_rev":0}]"#;
    let seed = db.fixture(
        "WITH RECURSIVE n(x) AS (VALUES (1) UNION ALL SELECT x+1 FROM n WHERE x < 450) \
         INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at,hot_safety_bytes,last_read_at,release_evidence) \
         SELECT printf('fixture-%05d', x), ?1, 'committed', 1, 65, zeroblob(48), zeroblob(16), zeroblob(32), zeroblob(32), 'released', 0, 65, x, ?2 FROM n",
        "INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,cipher_sha256,safety_state,created_at,hot_safety_bytes,last_read_at,release_evidence) \
         SELECT 'fixture-' || lpad(CAST(x AS text), 5, '0'), ?1, 'committed', 1, 65, \
           decode(repeat('00', 48), 'hex'), decode(repeat('00', 16), 'hex'), \
           decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'), 'released', 0, 65, x, ?2 \
         FROM generate_series(1, 450) x",
    );
    db.fixture_exec(
        seed,
        &[
            SqlValue::Text(w.bucket.id.as_str().to_owned()),
            SqlValue::Text(evidence.to_owned()),
        ],
    )
    .await
    .unwrap();
    let _ = o;
    let bridge = w.bridge();
    bridge
        .clock
        .advance_ms(i64::from(velmora_bridge::jobs::EVICT_CHECK_SECS) * 1000);
    bridge.jobs.inner.take();
    bridge.dispatch().await.unwrap();
    let mut steps = 0;
    while bridge.catalog.evict_rule_seen().await.unwrap().is_none() {
        let queued: Vec<Job> = bridge
            .jobs
            .inner
            .take()
            .into_iter()
            .map(|s| s.job)
            .filter(|j| matches!(j, Job::Evict { .. }))
            .collect();
        assert!(!queued.is_empty(), "the sweep stalled after {steps} steps");
        for step in queued {
            bridge.run_job(&step).await;
            steps += 1;
        }
        assert!(steps <= 20, "the sweep did not end");
    }
    assert!(steps <= 4, "{steps} steps for 451 rows");
}

/// `SCRUB` decides whether a loss on record keeps a row from a sweep's
/// promotion. An unreleasable extent with a loss on record, whose fill
/// the scrub never managed to write, is promoted by the sweep that
/// turning `SCRUB` off starts, with the tier under its cap.
#[tokio::test(flavor = "current_thread")]
async fn turning_the_scrub_off_sweeps_a_lost_extents_fill_to_safety() {
    let mut w = world().await;
    let o = w.released("a", 161).await;
    let key = o.extent.safety_key();
    let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
    cache_only(&w, &o, "a").await;
    cfg_mut(&mut w).providers[1].release = false;
    // A loss on record on alpha; the scrub's writes of the fill failed.
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE scrub_copies SET full_loss_at = ?2 WHERE extent_id = ?1 AND backbone = 'alpha'",
            &[
                SqlValue::Text(o.extent.as_str().to_owned()),
                SqlValue::Int(w.bridge().clock.now().0),
            ],
        )
        .await
        .unwrap();
    // The sweep under `SCRUB=on` leaves the lost row to the scrub.
    evict_check_now(&w).await;
    assert!(!w.has_safety(&o));
    cfg_mut(&mut w).scrub.on = false;
    evict_check_now(&w).await;
    assert_eq!(
        w.bridge().safety.stored(&key).map(|b| b.bytes),
        Some(cipher),
        "the sweep after the toggle wrote the fill"
    );
}

/// Makes `o` a released extent with no R2 copy at all (Usenet only).
async fn usenet_only(w: &World, o: &Obj) {
    assert!(w.bridge().safety.lose(&o.extent.safety_key()));
    w.bridge()
        .catalog
        .sql
        .inner
        .fixture_exec(
            "UPDATE extents SET hot_safety_bytes = 0 WHERE id = ?1",
            &[SqlValue::Text(o.extent.as_str().to_owned())],
        )
        .await
        .unwrap();
}

/// A GET that reads the object from Usenet and fills the cache.
async fn read_cold(w: &World, o: &Obj, name: &str) {
    let r = w
        .rig
        .call(&w.signer, Method::Get, &path(BUCKET, name), &[], &[], b"")
        .await;
    r.expect(200);
    assert_eq!(r.body, o.plain, "the object reads back");
    assert!(w.bridge().cache.contains(&o.extent.cache_key()), "filled");
}

/// A cold fill of an extent that is not releasable under the rule now,
/// with no safety copy, writes the same verified bytes to the safety
/// store too: the cache's lifecycle rule cannot take its only R2 copy.
#[tokio::test(flavor = "current_thread")]
async fn a_cold_fill_of_an_unreleasable_extent_writes_its_safety_copy() {
    let mut w = world().await;
    let o = w.released("a", 162).await;
    let key = o.extent.safety_key();
    let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
    usenet_only(&w, &o).await;
    cfg_mut(&mut w).providers[1].release = false;
    read_cold(&w, &o, "a").await;
    assert_eq!(
        w.bridge().safety.stored(&key).map(|b| b.bytes),
        Some(cipher),
        "the fill's bytes are its safety copy too"
    );
    assert_ne!(
        w.scalar(
            "SELECT hot_safety_bytes FROM extents WHERE id = ?1",
            &o.extent
        )
        .await,
        "0",
        "and counted"
    );
}

/// The safety write of such a fill fails: the read still answers, and a
/// sweep is put on record, which the dispatcher runs under the cap and
/// which writes the fill.
#[tokio::test(flavor = "current_thread")]
async fn a_failed_fill_time_safety_write_leaves_a_sweep_that_writes_it() {
    let mut w = world().await;
    let o = w.released("a", 163).await;
    let key = o.extent.safety_key();
    let cipher = w.bridge().safety.stored(&key).unwrap().bytes;
    usenet_only(&w, &o).await;
    cfg_mut(&mut w).providers[1].release = false;
    // The rule's first sweep is done; the tier is far under its cap.
    evict_check_now(&w).await;
    *w.bridge().safety.fail_put_prefix.borrow_mut() = Some("x/".to_string());
    read_cold(&w, &o, "a").await;
    *w.bridge().safety.fail_put_prefix.borrow_mut() = None;
    assert!(!w.has_safety(&o), "the write failed");
    evict_check_now(&w).await;
    assert_eq!(
        w.bridge().safety.stored(&key).map(|b| b.bytes),
        Some(cipher),
        "the sweep wrote the fill"
    );
}

/// A releasable extent's cold fill writes nothing to the safety store: no
/// cost for the common case.
#[tokio::test(flavor = "current_thread")]
async fn a_releasable_extents_cold_fill_writes_no_safety_copy() {
    let w = world().await;
    let o = w.released("a", 164).await;
    usenet_only(&w, &o).await;
    let safety_puts = w.bridge().safety.puts.borrow().len();
    read_cold(&w, &o, "a").await;
    assert!(!w.has_safety(&o));
    assert_eq!(w.bridge().safety.puts.borrow().len(), safety_puts);
}
