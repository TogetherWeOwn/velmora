//! The release is one write, and the release invariant holds through it
//! under every verify mode: the safety copy of an extent is released
//! only when every article was verified on two backbones, is still there
//! on both when the release asks, and the minimum age is over. Until
//! that write the extent is `held` and its row is not done; the write
//! leaves it `released` with its evidence and the row done, and no step
//! in between. Run against the in-process NNTP server.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::config::{VerifyConfig, VerifyMode};
use velmora_bridge::verify::sample_backbone;
use velmora_bridge::*;

/// Ten articles.
const TEN: usize = 6_500_000;
const DATA: u32 = 10;
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
async fn rig_of(check: Check) -> Rig {
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
    /// Posts an extent to the first backbone. Its articles.
    async fn posted(&self, n: u8) -> (Seeded, Vec<ArticleRow>) {
        let s = self.seed(n, &marked_plaintext(TEN)).await;
        let all = self.post(&s).await;
        assert_eq!(all.len(), DATA as usize);
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

    /// The safety copy is there, held, its row not done, and nothing
    /// says it was released.
    fn held(&self, s: &Seeded) -> bool {
        let extent = self.bridge.catalog.extent(&s.extent);
        self.bridge.safety.contains(&s.extent.safety_key())
            && self.stage(s) != OutboxStage::Done
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

/// One walk through the life of an extent under `check`. At every step
/// before the last the safety copy is held.
async fn walk(check: Check, n: u8) {
    let what = format!("{check:?}");
    let rig = rig_of(check).await;
    let (s, all) = rig.posted(n).await;
    let total = DATA;
    assert_eq!(all.len(), total as usize, "{what}");
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
    // One write: released, with the evidence and the time, and the row
    // done. Nothing is left for a second step.
    let extent = rig.bridge.catalog.extent(&s.extent);
    assert_eq!(extent.safety_state, SafetyState::Released, "{what}");
    assert_eq!(extent.released_at, Some(rig.bridge.clock.now()), "{what}");
    assert_eq!(rig.stage(&s), OutboxStage::Done, "{what}");
    assert!(rig.try_claim(&s, OutboxStage::Release).await.is_none());

    // The evidence: both backbones, each over every article, and the
    // full check where the mode asks for one.
    let evidence = rig.evidence(&s);
    for name in ["bb0", "bb1"] {
        let stat = |e: &&serde_json::Value| e["backbone"] == name && e["kind"] == "stat";
        assert_eq!(evidence.iter().filter(stat).count(), 1, "{what}: {name}");
    }
    for entry in &evidence {
        assert_eq!(entry["ok"], total, "{what}: {entry}");
        assert_eq!(entry["total"], total, "{what}: {entry}");
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
    // Every row on record is over every article.
    for v in rig.bridge.catalog.verifications(&s.extent) {
        assert_eq!(v.articles_total, total, "{what}");
    }

    // Readable from the providers alone.
    let cold = rig.bridge.fetch_cold(&extent).await.unwrap();
    assert_eq!(cold, fetch::ColdFetch::Filled(s.cipher.clone()), "{what}");
}

/// The invariant under `VERIFY_MODE=body` and under `light` (size,
/// `STAT`, sampled), with the release in one write.
#[tokio::test]
async fn nothing_is_released_before_two_backbones_and_the_minimum_age() {
    for (n, check) in (1u8..).zip(CHECKS) {
        walk(check, n).await;
    }
}

/// A release the job itself refuses (an article is gone when it asks)
/// writes nothing: the extent stays `held`, without evidence, and goes
/// back to verify, under `light` and under `body`.
#[tokio::test]
async fn a_refused_release_leaves_the_extent_as_it_was() {
    for check in CHECKS {
        let mut rig = rig_of(check).await;
        rig.bridge.cfg.safety_min_age_secs = 0;
        let (s, all) = rig.posted(21).await;
        rig.copy_to_second(&all).await;
        rig.verify_until_release(&s, "verify").await;
        // Gone from the second backbone when the release asks.
        rig.servers[1].hide(&all[3].message_id).await;
        rig.wait_until_due(&s);
        let before = rig.bridge.catalog.extent(&s.extent);
        assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
        let after = rig.bridge.catalog.extent(&s.extent);
        assert!(rig.held(&s), "{check:?}");
        assert_eq!(after.safety_state, before.safety_state, "{check:?}");
        assert_eq!(after.release_evidence, None, "{check:?}");
        assert_eq!(rig.stage(&s), OutboxStage::Verify, "{check:?}");
    }
}

/// A release the guard refuses writes nothing, under the light guard and
/// under the guard of `body`: no pass recorded under this claim, then a
/// lease that ran out. The same call in time is the one write.
#[tokio::test]
async fn a_release_the_guard_refuses_writes_nothing() {
    for (n, check) in (31u8..).zip(CHECKS) {
        let mut rig = rig_of(check).await;
        rig.bridge.cfg.safety_min_age_secs = 0;
        let (s, all) = rig.posted(n).await;
        rig.copy_to_second(&all).await;
        rig.verify_until_release(&s, "verify").await;
        rig.wait_until_due(&s);
        let lease = rig.claim(&s, OutboxStage::Release).await;
        let catalog = &rig.bridge.catalog;
        let counting = ["bb0".to_string(), "bb1".to_string()];
        let release = |now: UnixMs| {
            let (lease, counting) = (&lease, &counting);
            async move {
                let done = match check {
                    Check::Body => catalog.release(lease, 2, counting, "[]", now).await,
                    _ => {
                        let need_full = check == Check::LightSampled;
                        catalog
                            .release_light(lease, 2, counting, "[]", now, need_full)
                            .await
                    }
                };
                done.unwrap()
            }
        };
        let unchanged = |what: &str| {
            assert!(rig.held(&s), "{check:?}: {what}");
            assert_eq!(rig.stage(&s), OutboxStage::Release, "{check:?}: {what}");
        };
        let now = rig.bridge.clock.now();

        // Every pass on record is older than this claim.
        assert_eq!(release(now).await, Guard::Lost, "{check:?}");
        unchanged("no pass under this claim");

        // The passes count now; the lease has run out.
        catalog.edit(&s.extent, |e| e.outbox.claimed_at = UnixMs(0));
        let until = catalog.outbox(&s.extent).lease_until.expect("leased");
        assert_eq!(release(UnixMs(until.0 + 1)).await, Guard::Lost, "{check:?}");
        unchanged("the lease ran out");

        // In time: released, with the evidence, and the row done.
        assert_eq!(release(until).await, Guard::Applied(()), "{check:?}");
        let extent = catalog.extent(&s.extent);
        assert_eq!(extent.safety_state, SafetyState::Released, "{check:?}");
        assert_eq!(extent.release_evidence.as_deref(), Some("[]"), "{check:?}");
        assert_eq!(extent.released_at, Some(until), "{check:?}");
        assert_eq!(rig.stage(&s), OutboxStage::Done, "{check:?}");
        // A second release finds nothing to do.
        assert_eq!(release(until).await, Guard::Lost, "{check:?}");
    }
}
