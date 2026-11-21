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
    let rig = rig_with(TcpConnector::default(), cfg);
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
        let plain = pattern(seed, PLAIN);
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
        o
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

    /// Copies every article of the object to the server that lacks it,
    /// as propagation between backbones would.
    async fn mirror(&self, o: &Obj) {
        for row in self.plan(o).await {
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
            .query(sql, &[SqlValue::Text(extent.as_str().to_string())])
            .await
            .unwrap();
        match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Text(s)) => s.clone(),
            Some(SqlValue::Int(n)) => n.to_string(),
            Some(SqlValue::Null) | None => "NULL".to_string(),
            Some(other) => panic!("unexpected {other:?}"),
        }
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

/// The first check of a released extent is due 30 days after its last
/// verification, not before.
#[tokio::test(flavor = "current_thread")]
async fn nothing_is_due_before_thirty_days_after_the_last_verification() {
    let w = world().await;
    let o = w.released("a", 1).await;
    w.advance_secs(29 * DAY_SECS);
    let run = w.scrub().await;
    assert_eq!((run.checked, run.ended), (0, ScrubEnd::Idle));
    assert_eq!(w.result(&o).await, "NULL");
}

/// A healthy extent is read back whole from Usenet, recorded `ok`, and is
/// due again after `SCRUB_INTERVAL_DAYS`. Nothing is posted and nothing
/// is written to a blob store.
#[tokio::test(flavor = "current_thread")]
async fn a_healthy_extent_is_read_back_recorded_ok_and_due_again_after_the_interval() {
    let w = world().await;
    let o = w.released("a", 1).await;
    w.advance_secs(31 * DAY_SECS);
    let posts = w.posts();
    let safety_puts = w.bridge().safety.puts.borrow().len();
    let cache_puts = w.bridge().cache.puts.borrow().len();
    let now = w.bridge().clock.now();

    let run = w.scrub().await;

    assert_eq!(
        (run.checked, run.ok, run.suspect, run.repaired),
        (1, 1, 0, 0)
    );
    assert_eq!(run.ended, ScrubEnd::Idle);
    assert!(run.bytes_read > PLAIN as u64);
    assert_eq!(w.result(&o).await, "ok");
    assert_eq!(w.scrubbed_at(&o).await, Some(now.0));
    assert_eq!(w.next_at(&o).await, Some(now.0 + 30 * 86_400_000));
    assert_eq!(w.posts(), posts, "a check posts nothing");
    assert_eq!(w.bridge().safety.puts.borrow().len(), safety_puts);
    assert_eq!(w.bridge().cache.puts.borrow().len(), cache_puts);
    assert_eq!(w.safety_state(&o).await, "released");
    let state = w.state().await;
    assert_eq!((state.runs, state.checked, state.ok), (1, 1, 1));
    assert_eq!(state.lease_until, None, "the run gave the lease back");
    assert!(alerts().is_empty(), "{:?}", alerts());

    // Checked again only once the interval is over.
    w.advance_secs(29 * DAY_SECS);
    assert_eq!(w.scrub().await.checked, 0);
    w.advance_secs(DAY_SECS);
    assert_eq!(w.scrub().await.ok, 1);
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
    w.bridge()
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;

    assert_eq!(w.scrub().await.suspect, 1);
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

/// No free slot for the check: the run ends and records nothing for the
/// extent, which stays due.
#[tokio::test(flavor = "current_thread")]
async fn a_provider_without_a_free_slot_ends_the_run_and_nothing_is_recorded() {
    let w = world_with(|cfg| {
        for p in &mut cfg.providers {
            p.max_conns = 1;
            p.drill_conns = 0;
        }
    })
    .await;
    let o = w.released("a", 6).await;
    w.advance_secs(31 * DAY_SECS);
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

    let run = w.scrub().await;
    assert_eq!((run.checked, run.ended), (0, ScrubEnd::Busy));
    assert_eq!(w.result(&o).await, "NULL");
    assert_eq!(w.next_at(&o).await, None);
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
    // Not looked at again before the interval.
    w.advance_secs(3600);
    assert_eq!(w.scrub().await.checked, 0);
}

/// The due list is read from its index, a page at a time.
#[tokio::test(flavor = "current_thread")]
async fn the_due_list_is_read_from_its_index() {
    let w = world().await;
    let plan = w
        .bridge()
        .catalog
        .sql
        .query(
            "EXPLAIN QUERY PLAN SELECT id FROM extents INDEXED BY extents_scrub_due \
              WHERE (safety_state = 'released' OR scrub_next_at IS NOT NULL) \
                AND COALESCE(scrub_next_at, \
                  COALESCE(last_verified_at, released_at, created_at) + 2592000000) <= ?1 \
              ORDER BY COALESCE(scrub_next_at, \
                  COALESCE(last_verified_at, released_at, created_at) + 2592000000) LIMIT 8",
            &[SqlValue::Int(0)],
        )
        .await
        .unwrap();
    let text = format!("{plan:?}");
    assert!(text.contains("extents_scrub_due"), "{text}");
    assert!(
        !text.contains("TEMP B-TREE"),
        "no sort outside the index: {text}"
    );
}

/// What a healthy check costs the catalogue in rows written, as D1
/// bills them: the result (the row and its due-index entry) per extent,
/// and per run the lease, its totals and the provider slots of the run.
/// The slots are a per-run cost: the sessions are kept from one extent
/// to the next, so a run of more extents does not take more of them.
#[tokio::test(flavor = "current_thread")]
async fn a_healthy_check_writes_its_result_and_the_run_its_slots() {
    let w = world().await;
    let mut objs = Vec::new();
    for i in 0..4u8 {
        objs.push(w.released(&format!("k{i}"), 60 + i).await);
    }
    w.advance_secs(31 * DAY_SECS);
    let db = &w.bridge().catalog.sql.inner;
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
    assert_eq!(extents, 4 * 2, "the result and its index entry, per extent");
    assert_eq!(state, 2, "the lease taken, the totals added");
    // Everything else is the run's provider slots, kept across extents.
    assert_eq!(spent.billed(), extents + state + slots);
    let one = {
        let w = world().await;
        let _ = w.released("a", 70).await;
        w.advance_secs(31 * DAY_SECS);
        let db = &w.bridge().catalog.sql.inner;
        db.meter_writes().unwrap();
        let before = db.writes();
        assert_eq!(w.scrub().await.ok, 1);
        let spent = db.writes().since(&before);
        spent.table("provider_permits") + spent.table("provider_health")
    };
    assert_eq!(slots, one, "a run of 4 takes the slots a run of 1 does");
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
        .exec("UPDATE scrub_state SET last_incident = 'beta'", &[])
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
    w.advance_secs(31 * DAY_SECS);
    let run = w.scrub().await;
    assert_eq!((run.checked, run.ok, run.ended), (1, 1, ScrubEnd::Idle));
    assert_eq!(w.result(&o).await, "ok");
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
        .exec("UPDATE scrub_state SET last_incident = '[\"alpha\"]'", &[])
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
        .scrub_record(old, &o.extent, ScrubResult::Ok, now, next)
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
        .scrub_record(new, &o.extent, ScrubResult::Ok, now, next)
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
    let o = w.released("a", 112).await;
    c.sql
        .exec(
            "UPDATE outbox SET stage = 'verify' WHERE extent_id = ?1",
            &[SqlValue::Text(o.extent.as_str().to_string())],
        )
        .await
        .unwrap();
    assert!(!c.scrub_repin(token, &o.extent, at, &[]).await.unwrap());
    // Released and done, but no live object holds it.
    let gone = w.released("b", 113).await;
    w.rig
        .call(&w.signer, Method::Delete, &path(BUCKET, "b"), &[], &[], b"")
        .await
        .expect(204);
    assert!(!c.scrub_repin(token, &gone.extent, at, &[]).await.unwrap());
    // Released, done and live: re-pinned.
    let ok = w.released("c", 114).await;
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
    assert!(
        c.evict_safety_still_ok(&mine).await.unwrap(),
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
    assert!(
        !c.evict_safety_still_ok(&mine).await.unwrap(),
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
    w.advance_secs(31 * DAY_SECS);
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
        .exec(
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
    w.advance_secs(31 * DAY_SECS);
    // The second extent's `STAT` needs the slot the read of the first
    // kept: the read's sessions are ended for it.
    let run = w.scrub().await;
    assert_eq!((run.checked, run.ok, run.ended), (2, 2, ScrubEnd::Idle));
    assert_eq!(w.result(&o).await, "ok");
    assert_eq!(w.result(&p).await, "ok");
}

/// The due query as it runs is read from its index.
#[tokio::test(flavor = "current_thread")]
async fn the_due_query_as_it_runs_uses_its_index() {
    let w = world().await;
    let sql = format!(
        "EXPLAIN QUERY PLAN {}",
        velmora_bridge::sql::scrub_due_sql()
    );
    let plan = w
        .bridge()
        .catalog
        .sql
        .query(&sql, &[SqlValue::Int(0), SqlValue::Int(8)])
        .await
        .unwrap();
    let text = format!("{plan:?}");
    assert!(text.contains("extents_scrub_due"), "{text}");
    assert!(!text.contains("TEMP B-TREE"), "{text}");
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
        .exec(
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
        .exec(
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
    let now = w.bridge().clock.now();
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
        "SELECT COUNT(*) FROM extents WHERE id = ?1 AND evict_seq = ?2",
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

/// A read that breaks off while every backbone says it holds every
/// article is recorded `deferred`, looked at again after the confirm
/// interval, and the run goes on with the next extent.
#[tokio::test(flavor = "current_thread")]
async fn a_read_that_breaks_off_is_deferred_and_the_run_goes_on() {
    let w = world().await;
    let a = w.released("a", 205).await;
    let b = w.released("b", 206).await;
    w.advance_secs(31 * DAY_SECS);
    for s in &w.servers {
        s.drop_next_bodies(1000).await;
    }
    let run = w.scrub().await;
    for s in &w.servers {
        s.drop_next_bodies(0).await;
    }
    let results = [w.result(&a).await, w.result(&b).await];
    assert_ne!(run.ended, ScrubEnd::Busy, "{results:?}");
    assert!(
        results.iter().all(|r| r == "deferred"),
        "both looked at, neither recorded as a loss: {results:?}"
    );
    w.advance_secs(3600);
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
/// the re-pin; a re-pin the guard refuses takes that copy back.
#[tokio::test(flavor = "current_thread")]
async fn a_cache_sourced_copy_is_written_first_and_taken_back_when_refused() {
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
    w.bridge()
        .cache
        .put(&o.extent.cache_key(), cipher, &meta)
        .await
        .unwrap();
    w.advance_secs(31 * DAY_SECS);
    w.hide(0, &o, 0).await;
    w.hide(1, &o, 0).await;
    w.scrub().await;
    // The guard will refuse: the outbox row is not `done`.
    w.bridge()
        .catalog
        .sql
        .exec(
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
    assert!(!w.has_safety(&o), "taken back: the re-pin was refused");
    assert_eq!(w.result(&o).await, "suspect");
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
        .exec(
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
        .exec("UPDATE scrub_state SET last_incident = '[\"beta\"]'", &[])
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
    w.advance_secs(31 * DAY_SECS);
    // Alpha serves no body (but answers STAT); beta serves them all.
    w.servers[0].set_body_gone(true).await;
    let first = w.scrub().await;
    assert_eq!(first.suspect, 1, "a loss, not ok");
    w.advance_secs(3600);
    assert_eq!(w.scrub().await.repaired, 1);
    let failed = w
        .scalar(
            "SELECT group_concat(backbone) FROM verifications WHERE extent_id = ?1 \
               AND provider_id = 'scrub'",
            &o.extent,
        )
        .await;
    assert_eq!(failed, "alpha");
    assert!(alerts().iter().any(|a| a.contains("lacking=[alpha]")));
}
