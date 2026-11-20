//! The release invariant, in every combination of the verify mode and
//! parity: the safety copy of an extent is released only when every
//! article of its plan, the parity articles included, was verified on two
//! backbones, is still there on both when the release asks, and the
//! minimum age is over. Run against the in-process NNTP server.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::config::{VerifyConfig, VerifyMode};
use velmora_bridge::parity::ParityPlan;
use velmora_bridge::verify::sample_backbone;
use velmora_bridge::*;

/// Ten data articles, and so two parity articles when parity is on.
const TEN: usize = 6_500_000;
const DATA: u32 = 10;
const PARITY: u32 = 2;
/// Longer than every wait for a missing article and every round of
/// verify of a test together: the minimum age is never over by accident.
const MIN_AGE_SECS: u32 = 30 * 24 * 3600;
/// Longer than the waits for a missing article: nothing is posted again.
const LONG_GRACE_SECS: u32 = 86_400;
const EVERY_EXTENT: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Check {
    /// `VERIFY_MODE=body`.
    Body,
    /// `light`, outside the sample, every provider with a size command.
    LightSize,
    /// `light`, outside the sample, no size command: `STAT` alone.
    LightStat,
    /// `light`, every extent in the sample.
    LightSampled,
}

const CHECKS: [Check; 4] = [
    Check::Body,
    Check::LightSize,
    Check::LightStat,
    Check::LightSampled,
];

/// Two backbones that count, both needed for a release; the first posts.
async fn rig_of(check: Check, parity: bool) -> Rig {
    let spec = |backbone, post| Spec {
        backbone,
        post,
        max_conns: 4,
    };
    let mut rig = rig(&[spec("bb0", true), spec("bb1", false)]).await;
    let cfg = &mut rig.bridge.cfg;
    cfg.providers[1].priority = 1;
    cfg.required_backbones = 2;
    cfg.packed_plans = true;
    cfg.parity = parity;
    cfg.safety_min_age_secs = MIN_AGE_SECS;
    cfg.propagation_grace_secs = LONG_GRACE_SECS;
    let light = |sample_ppm, sizes: &[(&str, SizeCommand)]| VerifyConfig {
        mode: VerifyMode::Light,
        sample_ppm,
        escalate_secs: 3600,
        size_commands: sizes.iter().map(|(p, c)| (p.to_string(), *c)).collect(),
    };
    cfg.verify = match check {
        Check::Body => VerifyConfig::default(),
        Check::LightSize => light(0, &[("p0", SizeCommand::Head), ("p1", SizeCommand::Hdr)]),
        Check::LightStat => light(0, &[]),
        Check::LightSampled => light(EVERY_EXTENT, &[]),
    };
    assert_eq!(VerifyConfig::default().mode, VerifyMode::Body);
    if check == Check::LightSize {
        for server in &rig.servers {
            server.set_reported_size(Some(0)).await;
        }
    }
    rig
}

impl Rig {
    /// Posts an extent to the first backbone. Every article of its
    /// plan: the data articles, then the parity articles.
    async fn posted(&self, n: u8, parity: bool) -> (Seeded, Vec<ArticleRow>) {
        let s = self.seed(n, &marked_plaintext(TEN)).await;
        let mut all = self.post(&s).await;
        assert_eq!(all.len(), DATA as usize);
        let stored = self.bridge.catalog.stored_plan(&s.extent).await.unwrap();
        let addendum: Option<ParityPlan> = stored
            .parity_plan(&s.extent, s.cipher.len() as u64)
            .unwrap();
        assert_eq!(addendum.is_some(), parity);
        if let Some(addendum) = addendum {
            assert_eq!(addendum.articles.len(), PARITY as usize);
            all.extend(addendum.articles);
        }
        assert_eq!(self.servers[0].posted_count().await, all.len());
        assert_eq!(self.servers[1].posted_count().await, 0);
        (s, all)
    }

    /// Copies `rows` from the first server to the second.
    async fn copy_to_second(&self, rows: &[ArticleRow]) {
        let mut src = self.raw_client(0).await;
        let mut dst = self.raw_client(1).await;
        for row in rows {
            let mut article = Vec::new();
            src.article_to(&row.message_id, &mut article).await.unwrap();
            dst.post_article(&row.message_id, &article).await.unwrap();
        }
        src.quit().await;
        dst.quit().await;
    }

    fn stage(&self, s: &Seeded) -> OutboxStage {
        self.bridge.catalog.outbox(&s.extent).stage
    }

    /// The safety copy is there, held, and nothing says it was released.
    fn held(&self, s: &Seeded) -> bool {
        let extent = self.bridge.catalog.extent(&s.extent);
        self.bridge.safety.contains(&s.extent.safety_key())
            && extent.safety_state == SafetyState::Held
            && extent.release_evidence.is_none()
            && extent.released_at.is_none()
    }

    /// Moves the clock to the time the row of `s` is due.
    fn wait_until_due(&self, s: &Seeded) {
        let due = self.bridge.catalog.outbox(&s.extent).next_at;
        let ahead_ms = (due.0 - self.bridge.clock.now().0).max(0);
        let secs = u32::try_from(ahead_ms.div_euclid(1000) + 1).unwrap();
        self.bridge.clock.advance_secs(secs);
    }

    /// Runs verify, each time the row is due, until the extent is at the
    /// release stage. A verify that never gets there fails the test.
    async fn verify_until_release(&self, s: &Seeded, what: &str) {
        for _ in 0..16 {
            self.wait_until_due(s);
            let _ = self.run(s, OutboxStage::Verify).await;
            assert!(self.held(s), "{what}");
            if self.stage(s) == OutboxStage::Release {
                return;
            }
            assert_eq!(self.stage(s), OutboxStage::Verify, "{what}");
        }
        panic!("{what}: verify never passed");
    }

    /// The release evidence of `s`.
    fn evidence(&self, s: &Seeded) -> Vec<serde_json::Value> {
        let extent = self.bridge.catalog.extent(&s.extent);
        let json: serde_json::Value =
            serde_json::from_str(extent.release_evidence.as_deref().unwrap()).unwrap();
        json.as_array().unwrap().clone()
    }
}

/// One walk through the life of an extent under `check`, with parity or
/// without. At every step before the last the safety copy is held.
async fn walk(check: Check, parity: bool, n: u8) {
    let what = format!("{check:?}, parity {parity}");
    let rig = rig_of(check, parity).await;
    let (s, all) = rig.posted(n, parity).await;
    let total = DATA + if parity { PARITY } else { 0 };
    assert_eq!(all.len(), total as usize, "{what}");
    // The last article of the plan: a parity article where there is one.
    let (late, rest) = all.split_last().unwrap();
    assert_eq!(late.idx, total - 1);

    // 1. On one backbone only: nothing passes, whatever the first one
    //    answers.
    for _ in 0..3 {
        rig.wait_until_due(&s);
        assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
        assert_eq!(rig.stage(&s), OutboxStage::Verify, "{what}");
        assert!(rig.try_claim(&s, OutboxStage::Release).await.is_none());
        assert!(rig.held(&s), "{what}: one backbone");
    }

    // 2. The second backbone has every article but one. Through every
    //    wait for a missing article, and the rounds after them, verify
    //    does not pass and no release job can start.
    rig.copy_to_second(rest).await;
    for _ in 0..8 {
        rig.wait_until_due(&s);
        assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
        assert_eq!(rig.stage(&s), OutboxStage::Verify, "{what}");
        assert!(rig.try_claim(&s, OutboxStage::Release).await.is_none());
        assert!(rig.held(&s), "{what}: one article short");
    }

    // 3. Every article on both: verify passes. The release is due only
    //    when the minimum age is over, and a release job that runs
    //    before that releases nothing.
    rig.copy_to_second(std::slice::from_ref(late)).await;
    rig.verify_until_release(&s, &what).await;
    let posted = all.iter().filter_map(ArticleRow::last_posted_at).max();
    let ready = posted.unwrap().plus_secs(MIN_AGE_SECS);
    assert!(
        rig.bridge.clock.now() < ready,
        "{what}: the test ran too long"
    );
    assert_eq!(rig.bridge.catalog.outbox(&s.extent).next_at, ready);
    assert!(rig.try_claim(&s, OutboxStage::Release).await.is_none());
    // A job that arrives early all the same (a row moved by hand).
    let now = rig.bridge.clock.now();
    rig.bridge
        .catalog
        .edit(&s.extent, |e| e.outbox.next_at = now);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.stage(&s), OutboxStage::Release, "{what}");
    assert_eq!(rig.bridge.catalog.outbox(&s.extent).next_at, ready);
    assert!(rig.held(&s), "{what}: before the minimum age");

    // 4. The minimum age is over, and the second backbone has lost the
    //    article again: the release goes back to verify.
    rig.wait_until_due(&s);
    assert!(rig.bridge.clock.now() >= ready);
    rig.servers[1].hide(&late.message_id).await;
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.stage(&s), OutboxStage::Verify, "{what}");
    assert!(rig.held(&s), "{what}: an article gone at the release");
    rig.wait_until_due(&s);
    assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert!(rig.held(&s), "{what}: an article gone at verify");

    // 5. It is back: verified again on both, then released.
    rig.servers[1].unhide(&late.message_id).await;
    rig.verify_until_release(&s, &what).await;
    rig.wait_until_due(&s);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    let extent = rig.bridge.catalog.extent(&s.extent);
    assert_eq!(extent.safety_state, SafetyState::Released, "{what}");

    // The evidence: both backbones, each over every article of the
    // plan, and the full check where the mode asks for one.
    let evidence = rig.evidence(&s);
    for name in ["bb0", "bb1"] {
        let stat = |e: &&serde_json::Value| e["backbone"] == name && e["kind"] == "stat";
        assert_eq!(evidence.iter().filter(stat).count(), 1, "{what}: {name}");
    }
    for entry in &evidence {
        assert_eq!(entry["ok"], total, "{what}: {entry}");
        assert_eq!(entry["total"], total, "{what}: {entry}");
        match parity {
            true => assert_eq!(entry["parity"], PARITY, "{what}: {entry}"),
            false => assert!(entry.get("parity").is_none(), "{what}: {entry}"),
        }
    }
    let kinds = |kind: &str| evidence.iter().filter(|e| e["kind"] == kind).count();
    match check {
        Check::Body => assert!(kinds("body") >= 1, "{what}: {evidence:?}"),
        Check::LightSampled => {
            let drawn = sample_backbone(rig.bridge.kek.active().1, &s.extent, 2);
            let full = |e: &&serde_json::Value| e["kind"] == "sampled" || e["kind"] == "body";
            let read: Vec<_> = evidence.iter().filter(full).collect();
            assert!(!read.is_empty(), "{what}: {evidence:?}");
            let name = ["bb0", "bb1"][drawn];
            assert!(read.iter().any(|e| e["backbone"] == name), "{what}");
        }
        Check::LightSize => assert_eq!(kinds("size"), 2, "{what}: {evidence:?}"),
        Check::LightStat => assert_eq!(evidence.len(), 2, "{what}: {evidence:?}"),
    }
    // Every row that passed is a pass of the whole plan.
    for v in rig.bridge.catalog.verifications(&s.extent) {
        assert_eq!(v.articles_total, total, "{what}");
    }

    // Readable from the providers alone.
    let cold = rig.bridge.fetch_cold(&extent).await.unwrap();
    assert_eq!(cold, fetch::ColdFetch::Filled(s.cipher.clone()), "{what}");
}

/// The invariant under `VERIFY_MODE=body` and under `light` (size,
/// `STAT`, sampled), each without parity.
#[tokio::test]
async fn nothing_is_released_before_two_backbones_and_the_minimum_age() {
    for (n, check) in (1u8..).zip(CHECKS) {
        walk(check, false, n).await;
    }
}

/// The same with parity: a parity article is one of the articles every
/// step counts.
#[tokio::test]
async fn nothing_is_released_before_two_backbones_and_the_minimum_age_with_parity() {
    for (n, check) in (11u8..).zip(CHECKS) {
        walk(check, true, n).await;
    }
}

/// Under the light check every backbone is asked for the parity articles
/// too: with its size command at verify, with `STAT` at the release.
#[tokio::test]
async fn the_light_check_asks_every_backbone_for_the_parity_articles() {
    let mut rig = rig_of(Check::LightSize, true).await;
    rig.bridge.cfg.safety_min_age_secs = 0;
    let (s, all) = rig.posted(21, true).await;
    rig.copy_to_second(&all).await;
    let n = all.len();
    assert_eq!(n, (DATA + PARITY) as usize);
    let calls = |rig: &Rig| {
        let calls = rig.bridge.nntp.calls();
        let of = |what| calls.iter().filter(|c| c.0 == what).count();
        (of("body"), of("stat"), of("size"))
    };

    rig.bridge.nntp.slow(&rig.bridge.clock, 1);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(calls(&rig), (0, 0, 2 * n));
    let rows = rig.bridge.catalog.verifications(&s.extent);
    assert_eq!(rows.len(), 2);
    for v in &rows {
        assert_eq!(
            (v.kind, v.result, v.articles_ok, v.articles_total),
            (VerifyKind::Size, VerifyResult::Ok, n as u32, n as u32)
        );
    }
    rig.bridge.clock.advance_secs(1);
    rig.bridge.nntp.slow(&rig.bridge.clock, 1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(calls(&rig), (0, 2 * n, 0));
    let extent = rig.bridge.catalog.extent(&s.extent);
    assert_eq!(extent.safety_state, SafetyState::Released);
}

/// Under the light check a pass that was recorded over the data articles
/// alone (a Worker from before parity was verified) releases nothing,
/// for an extent outside the sample too: the release sends the extent
/// back to verify, which asks for every article.
#[tokio::test]
async fn light_passes_without_the_parity_articles_release_nothing() {
    for check in [Check::LightSize, Check::LightStat, Check::LightSampled] {
        let mut rig = rig_of(check, true).await;
        rig.bridge.cfg.safety_min_age_secs = 0;
        let (s, all) = rig.posted(31, true).await;
        rig.copy_to_second(&all).await;
        assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
        assert_eq!(rig.stage(&s), OutboxStage::Release);
        rig.bridge.catalog.edit(&s.extent, |e| {
            for v in &mut e.verifications {
                v.articles_ok = DATA;
                v.articles_total = DATA;
            }
        });

        rig.bridge.clock.advance_secs(1);
        assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
        assert_eq!(rig.stage(&s), OutboxStage::Verify, "{check:?}");
        assert!(rig.held(&s), "{check:?}");

        rig.verify_until_release(&s, "after the short passes").await;
        rig.wait_until_due(&s);
        assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
        let extent = rig.bridge.catalog.extent(&s.extent);
        assert_eq!(extent.safety_state, SafetyState::Released, "{check:?}");
        for entry in rig.evidence(&s) {
            assert_eq!(entry["total"], DATA + PARITY, "{check:?}: {entry}");
        }
    }
}

/// A sampled extent whose parity article has other bytes on the backbone
/// that is read in full: the read is corrupt, the backbone is raised to
/// full reads, and nothing is released while it stays so.
#[tokio::test]
async fn a_corrupt_parity_article_in_the_sample_releases_nothing() {
    let rig = rig_of(Check::LightSampled, true).await;
    let s = rig.seed(41, &marked_plaintext(TEN)).await;
    // The addendum is stored by a first job that cannot post; another
    // payload is then planted under the id of a parity article.
    rig.server().set_posting_allowed(false).await;
    assert_ne!(rig.run_post(&s).await, JobOutcome::Ack);
    rig.server().set_posting_allowed(true).await;
    let stored = rig.bridge.catalog.stored_plan(&s.extent).await.unwrap();
    let addendum = stored
        .parity_plan(&s.extent, s.cipher.len() as u64)
        .unwrap()
        .expect("the extent has parity");
    let row = &addendum.articles[1];
    let other = vec![0x5a; row.cipher_len as usize];
    let mut planted = row.clone();
    planted.cipher_offset = 0;
    let article = render(&[planted.clone()], &planted, &other, false);
    let mut client = rig.raw_client(0).await;
    client
        .post_article(&row.message_id, &article)
        .await
        .unwrap();
    client.quit().await;
    rig.bridge.clock.advance_secs(60);
    let mut all = rig.post(&s).await;
    all.extend(addendum.articles.iter().cloned());
    // Both backbones carry the same articles, the wrong one too.
    rig.copy_to_second(&all).await;

    let drawn = sample_backbone(rig.bridge.kek.active().1, &s.extent, 2);
    let name = ["bb0", "bb1"][drawn];
    for _ in 0..6 {
        rig.wait_until_due(&s);
        assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
        assert_eq!(rig.stage(&s), OutboxStage::Verify);
        assert!(rig.try_claim(&s, OutboxStage::Release).await.is_none());
        assert!(rig.held(&s));
    }
    let rows = rig.bridge.catalog.verifications(&s.extent);
    let corrupt = |v: &VerificationRow| {
        v.backbone == name
            && v.kind.is_full()
            && v.result == VerifyResult::Corrupt
            && v.articles_total == DATA + PARITY
    };
    assert!(rows.iter().any(corrupt), "{rows:?}");
    let raised = rig.bridge.catalog.escalations.borrow().clone();
    assert!(raised.iter().any(|e| e.backbone == name), "{raised:?}");
}

/// The guard of the catalogue itself, behind the job's own rule: a
/// backbone whose latest full read covered the data articles alone holds
/// no copy, whatever `STAT` says afterwards, under the guard of `body`
/// and under the light guard. Read in full with the parity articles, it
/// counts again.
#[tokio::test]
async fn the_guard_refuses_a_full_read_of_the_data_alone() {
    for (n, light) in [(51u8, false), (52u8, true)] {
        let rig = rig_of(Check::Body, true).await;
        let (s, _) = rig.posted(n, true).await;
        let catalog = &rig.bridge.catalog;
        catalog.edit(&s.extent, |e| {
            e.outbox.stage = OutboxStage::Release;
            e.outbox.lease_until = None;
        });
        rig.wait_until_due(&s);
        let lease = rig.claim(&s, OutboxStage::Release).await;
        let plan_rev = catalog.extent(&s.extent).plan_rev;
        let t0 = rig.bridge.clock.now();
        let pass = |i: usize, ms: i64, kind: VerifyKind, articles: u32| VerificationRow {
            extent_id: s.extent.clone(),
            backbone: format!("bb{i}"),
            provider_id: format!("p{i}"),
            verified_at: UnixMs(t0.0 + ms),
            plan_rev,
            articles_ok: articles,
            articles_total: articles,
            result: VerifyResult::Ok,
            kind,
        };
        let all = DATA + PARITY;
        let record = |row: VerificationRow| {
            let lease = &lease;
            async move { assert!(catalog.record_verification(lease, &row).await.unwrap()) }
        };
        let release = |ms: i64| {
            let lease = &lease;
            async move {
                let counting = ["bb0".to_string(), "bb1".to_string()];
                let now = UnixMs(t0.0 + ms);
                let guard = match light {
                    false => catalog.begin_release(lease, 2, &counting, "[]", now).await,
                    true => {
                        catalog
                            .begin_release_light(lease, 2, &counting, "[]", now, false)
                            .await
                    }
                };
                guard.unwrap()
            }
        };

        record(pass(0, 1, VerifyKind::Body, all)).await;
        // As a version from before parity reads: the data alone.
        record(pass(1, 2, VerifyKind::Body, DATA)).await;
        // Nor does it say the extent was verified.
        assert_eq!(
            catalog.extent(&s.extent).last_verified_at,
            Some(UnixMs(t0.0 + 1))
        );
        for i in [0, 1] {
            record(pass(i, 3, VerifyKind::Stat, all)).await;
        }
        assert_eq!(release(4).await, Guard::Lost, "light={light}");
        assert!(rig.held(&s), "light={light}");
        assert_eq!(rig.stage(&s), OutboxStage::Release, "light={light}");

        // Read in full, parity included: the backbone holds a copy again.
        record(pass(1, 5, VerifyKind::Body, all)).await;
        record(pass(1, 6, VerifyKind::Stat, all)).await;
        assert_eq!(release(7).await, Guard::Applied(()), "light={light}");
        let extent = catalog.extent(&s.extent);
        assert_eq!(extent.safety_state, SafetyState::Releasing, "light={light}");
        assert_eq!(extent.last_verified_at, Some(UnixMs(t0.0 + 5)));
    }
}
