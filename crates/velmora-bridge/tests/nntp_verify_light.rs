//! The light check of the verify stage (`VERIFY_MODE=light`) against the
//! in-process NNTP server: presence and size on every backbone, a full
//! read for a sample, and what a failed sample read does.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::config::{VerifyConfig, VerifyMode};
use velmora_bridge::fetch::size_bounds;
use velmora_bridge::post::{stored_size, stored_sizes};
use velmora_bridge::verify::{in_sample, sample_backbone, MISSING_BACKOFF_SECS, REVERIFY_SECS};
use velmora_bridge::*;

const PLAIN_LEN: usize = 1_500_000;
/// Longer than all the waits for a missing article: nothing is reposted.
const LONG_GRACE_SECS: u32 = 86_400;
const ALL: u32 = 1_000_000;
const ESCALATE_SECS: u32 = 3_600;

fn retry_delay(outcome: &JobOutcome) -> u32 {
    match outcome {
        JobOutcome::Retry { delay_secs } => *delay_secs,
        JobOutcome::Ack => panic!("expected a retry, got an ack"),
    }
}

/// Two backbones under the light check, `ppm` of the extents sampled.
async fn light_rig(ppm: u32, sizes: &[(&str, SizeCommand)]) -> Rig {
    let mut rig = two_backbone_rig().await;
    rig.bridge.cfg.propagation_grace_secs = LONG_GRACE_SECS;
    rig.bridge.cfg.verify = VerifyConfig {
        mode: VerifyMode::Light,
        sample_ppm: ppm,
        escalate_secs: ESCALATE_SECS,
        size_commands: sizes.iter().map(|(p, c)| (p.to_string(), *c)).collect(),
    };
    rig
}

impl Rig {
    /// Posts an extent of three articles and copies it to the second
    /// backbone.
    async fn on_two(&self, n: u8) -> (Seeded, Vec<ArticleRow>) {
        let s = self.seed(n, &marked_plaintext(PLAIN_LEN)).await;
        let plan = self.post(&s).await;
        self.propagate(&s, 0, 1).await;
        assert_eq!(plan.len(), 3);
        (s, plan)
    }

    fn stage(&self, s: &Seeded) -> OutboxStage {
        self.bridge.catalog.outbox(&s.extent).stage
    }

    fn state(&self, s: &Seeded) -> SafetyState {
        self.bridge.catalog.extent(&s.extent).safety_state
    }

    /// The rows on record: backbone, kind, result.
    fn checks(&self, s: &Seeded) -> Vec<(String, VerifyKind, VerifyResult)> {
        let rows = self.bridge.catalog.verifications(&s.extent);
        rows.iter()
            .map(|r| (r.backbone.clone(), r.kind, r.result))
            .collect()
    }

    /// The release evidence: backbone, kind and size command per entry.
    fn evidence(&self, s: &Seeded) -> Vec<(String, String, Option<String>)> {
        let extent = self.bridge.catalog.extent(&s.extent);
        let json: serde_json::Value =
            serde_json::from_str(extent.release_evidence.as_deref().unwrap()).unwrap();
        let text = |v: &serde_json::Value| v.as_str().map(str::to_string);
        json.as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    text(&e["backbone"]).unwrap(),
                    text(&e["kind"]).unwrap(),
                    text(&e["size_command"]),
                )
            })
            .collect()
    }

    /// The calls of the last job by kind: `(BODY, STAT, size)`.
    fn calls(&self) -> (usize, usize, usize) {
        let calls = self.bridge.nntp.calls();
        let of = |what| calls.iter().filter(|c| c.0 == what).count();
        (of("body"), of("stat"), of("size"))
    }

    /// Runs one job with the call log started.
    async fn logged(&self, s: &Seeded, stage: OutboxStage) -> JobOutcome {
        self.bridge.nntp.slow(&self.bridge.clock, 1);
        self.run(s, stage).await
    }

    /// Verifies and releases: both jobs acknowledge.
    async fn verify_and_release(&self, s: &Seeded) {
        assert_eq!(self.run(s, OutboxStage::Verify).await, JobOutcome::Ack);
        assert_eq!(self.stage(s), OutboxStage::Release);
        self.bridge.clock.advance_secs(1);
        assert_eq!(self.run(s, OutboxStage::Release).await, JobOutcome::Ack);
    }

    /// Moves the clock to the time the row of `s` is due.
    fn wait_until_due(&self, s: &Seeded) {
        let due = self.bridge.catalog.outbox(&s.extent).next_at;
        let ahead_ms = (due.0 - self.bridge.clock.now().0).max(0);
        self.bridge
            .clock
            .advance_secs((ahead_ms as u32).div_ceil(1000));
    }

    /// The backbone index a sampled extent is read in full on.
    fn sample_index(&self, s: &Seeded) -> usize {
        sample_backbone(self.bridge.kek.active().1, &s.extent, 2)
    }
}

fn row(
    backbone: &str,
    kind: VerifyKind,
    result: VerifyResult,
) -> (String, VerifyKind, VerifyResult) {
    (backbone.to_string(), kind, result)
}

fn ok(backbone: &str, kind: VerifyKind) -> (String, VerifyKind, VerifyResult) {
    row(backbone, kind, VerifyResult::Ok)
}

fn entry(backbone: &str, kind: &str, command: Option<&str>) -> (String, String, Option<String>) {
    (
        backbone.to_string(),
        kind.to_string(),
        command.map(str::to_string),
    )
}

/// Outside the sample no article is read: every backbone is asked for
/// every article with its size command, the release job asks again with
/// `STAT`, and the evidence says what each backbone was asked with.
#[tokio::test]
async fn an_extent_outside_the_sample_is_released_on_size_and_presence() {
    let sizes = [("p0", SizeCommand::Head), ("p1", SizeCommand::Hdr)];
    let rig = light_rig(0, &sizes).await;
    for server in &rig.servers {
        server.set_reported_size(Some(0)).await;
    }
    let (s, plan) = rig.on_two(1).await;
    let n = plan.len();

    assert_eq!(rig.logged(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.calls(), (0, 0, 2 * n));
    assert_eq!(
        rig.checks(&s),
        [ok("bb0", VerifyKind::Size), ok("bb1", VerifyKind::Size)]
    );
    assert_eq!(rig.stage(&s), OutboxStage::Release);
    assert_eq!(rig.state(&s), SafetyState::Held);

    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.logged(&s, OutboxStage::Release).await, JobOutcome::Ack);
    // The release keeps its `STAT` of every article on every backbone.
    assert_eq!(rig.calls(), (0, 2 * n, 0));
    assert_eq!(rig.state(&s), SafetyState::Released);
    assert_eq!(
        rig.evidence(&s),
        [
            entry("bb0", "stat", None),
            entry("bb1", "stat", None),
            entry("bb0", "size", Some("head")),
            entry("bb1", "size", Some("hdr")),
        ]
    );
    // Still readable from the providers alone.
    let extent = rig.bridge.catalog.extent(&s.extent);
    let cold = rig.bridge.fetch_cold(&extent).await.unwrap();
    assert_eq!(cold, fetch::ColdFetch::Filled(s.cipher.clone()));
}

/// A provider without a size command, and one whose answer has no size,
/// are recorded as the `STAT` pass they are: the evidence never says
/// `size` for a size nobody saw.
#[tokio::test]
async fn a_pass_without_a_size_is_recorded_as_stat() {
    // `p0` has no command; `p1` is asked with `HEAD` and has no `Bytes:`.
    let rig = light_rig(0, &[("p1", SizeCommand::Head)]).await;
    let (s, plan) = rig.on_two(2).await;
    let n = plan.len();

    assert_eq!(rig.logged(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.calls(), (0, n, n));
    assert_eq!(
        rig.checks(&s),
        [ok("bb0", VerifyKind::Stat), ok("bb1", VerifyKind::Stat)]
    );
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
    assert_eq!(
        rig.evidence(&s),
        [entry("bb0", "stat", None), entry("bb1", "stat", None)]
    );
}

/// A size no posted article of the plan can have blocks the release: the
/// backbone holds no copy, whatever it answers afterwards, until it has
/// been read in full.
#[tokio::test]
async fn a_size_that_does_not_fit_blocks_the_release() {
    let sizes = [("p0", SizeCommand::Head), ("p1", SizeCommand::Head)];
    let rig = light_rig(0, &sizes).await;
    rig.servers[0].set_reported_size(Some(0)).await;
    // The second backbone stores articles cut short.
    rig.servers[1].set_reported_size(Some(-200_000)).await;
    let (s, plan) = rig.on_two(3).await;
    let n = plan.len();

    let wait = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(wait, REVERIFY_SECS);
    assert_eq!(
        rig.checks(&s),
        [
            ok("bb0", VerifyKind::Size),
            row("bb1", VerifyKind::Size, VerifyResult::Corrupt),
        ]
    );
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.stage, OutboxStage::Verify);
    assert_eq!(outbox.last_error, Some(FailClass::Corrupt));
    assert_eq!(rig.state(&s), SafetyState::Held);
    // A size like this one does not raise the sample: no full read
    // failed.
    assert!(rig.bridge.catalog.escalations.borrow().is_empty());

    // A release job that got hold of the row releases nothing either:
    // the size that fits now does not undo the one that did not.
    rig.servers[1].set_reported_size(Some(0)).await;
    rig.bridge.clock.advance_secs(wait);
    let now = rig.bridge.clock.now();
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.outbox.stage = OutboxStage::Release;
        e.outbox.next_at = now;
    });
    rig.run(&s, OutboxStage::Release).await;
    assert_eq!(rig.state(&s), SafetyState::Held);
    assert!(rig.bridge.safety.contains(&s.extent.safety_key()));
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.outbox.stage = OutboxStage::Verify;
        e.outbox.next_at = now;
    });

    // Verify reads that backbone in full, and only that one.
    rig.bridge.clock.advance_secs(REVERIFY_SECS);
    assert_eq!(rig.logged(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.calls(), (n, 0, n));
    assert_eq!(
        rig.checks(&s)[2..],
        [ok("bb0", VerifyKind::Size), ok("bb1", VerifyKind::Body)]
    );
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
}

/// A size above the largest the article can have is as wrong as one
/// below the smallest.
#[tokio::test]
async fn a_size_that_is_too_large_does_not_fit_either() {
    let sizes = [("p0", SizeCommand::Hdr), ("p1", SizeCommand::Hdr)];
    let rig = light_rig(0, &sizes).await;
    rig.servers[0].set_reported_size(Some(200_000)).await;
    rig.servers[1].set_reported_size(Some(0)).await;
    let (s, _) = rig.on_two(4).await;

    assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(
        rig.checks(&s),
        [
            row("bb0", VerifyKind::Size, VerifyResult::Corrupt),
            ok("bb1", VerifyKind::Size),
        ]
    );
    assert_eq!(rig.state(&s), SafetyState::Held);
}

/// The two-backbone rule is the same under the light check: an article
/// one backbone does not have keeps the safety copy, at verify and at
/// release.
#[tokio::test]
async fn an_article_missing_on_one_backbone_blocks_the_release() {
    let rig = light_rig(0, &[]).await;

    // Missing when verify asks.
    let (early, plan) = rig.on_two(5).await;
    rig.servers[1].hide(&plan[1].message_id).await;
    assert_eq!(
        retry_delay(&rig.run(&early, OutboxStage::Verify).await),
        MISSING_BACKOFF_SECS[0]
    );
    assert_eq!(rig.stage(&early), OutboxStage::Verify);
    assert_eq!(rig.state(&early), SafetyState::Held);

    // Missing when the release asks: verify had passed on both.
    let (late, plan) = rig.on_two(6).await;
    assert_eq!(rig.run(&late, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.stage(&late), OutboxStage::Release);
    rig.servers[1].hide(&plan[2].message_id).await;
    rig.bridge.clock.advance_secs(1);
    assert_eq!(
        rig.logged(&late, OutboxStage::Release).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls().0, 0);
    assert_eq!(rig.stage(&late), OutboxStage::Verify);
    assert_eq!(rig.state(&late), SafetyState::Held);
    assert!(rig.bridge.safety.contains(&late.extent.safety_key()));
    // Verify records the loss after its waits, as under `body`.
    rig.wait_until_due(&late);
    assert_eq!(
        retry_delay(&rig.run(&late, OutboxStage::Verify).await),
        MISSING_BACKOFF_SECS[0]
    );
    assert_eq!(rig.state(&late), SafetyState::Held);
}

/// With three backbones that count, one that lacked the extent when
/// verify ran does not count at the release because it answers `STAT`
/// then: it was never checked. The extent goes back to verify.
#[tokio::test]
async fn a_backbone_verify_did_not_pass_does_not_count_at_release() {
    let spec = |backbone, post| Spec {
        backbone,
        post,
        max_conns: 2,
    };
    let mut rig = rig(&[spec("bb0", true), spec("bb1", false), spec("bb2", false)]).await;
    rig.bridge.cfg.required_backbones = 2;
    rig.bridge.cfg.propagation_grace_secs = 0;
    rig.bridge.cfg.verify = VerifyConfig {
        mode: VerifyMode::Light,
        sample_ppm: 0,
        escalate_secs: ESCALATE_SECS,
        size_commands: Vec::new(),
    };
    let (s, plan) = rig.on_two(20).await;
    let mut outcome = rig.run(&s, OutboxStage::Verify).await;
    while outcome != JobOutcome::Ack {
        rig.wait_until_due(&s);
        outcome = rig.run(&s, OutboxStage::Verify).await;
    }
    assert_eq!(rig.stage(&s), OutboxStage::Release);
    let on_record = rig.checks(&s);
    assert_eq!(
        on_record.last().unwrap(),
        &row("bb2", VerifyKind::Stat, VerifyResult::Missing)
    );

    // The third backbone gets the extent; the second loses an article.
    rig.propagate(&s, 0, 2).await;
    rig.servers[1].hide(&plan[1].message_id).await;
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.logged(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.stage(&s), OutboxStage::Verify);
    assert_eq!(rig.state(&s), SafetyState::Held);
    assert!(rig.bridge.safety.contains(&s.extent.safety_key()));
}

/// Three backbones under the light check, two of them needed.
async fn three_backbone_rig(specs: [(&'static str, bool); 3]) -> Rig {
    let spec = |(backbone, post)| Spec {
        backbone,
        post,
        max_conns: 2,
    };
    let mut rig = rig(&specs.map(spec)).await;
    rig.bridge.cfg.required_backbones = 2;
    rig.bridge.cfg.propagation_grace_secs = 0;
    rig.bridge.cfg.verify = VerifyConfig {
        mode: VerifyMode::Light,
        sample_ppm: 0,
        escalate_secs: ESCALATE_SECS,
        size_commands: Vec::new(),
    };
    rig
}

/// Puts `backbone` under full reads from now on, as a failed sample of
/// another extent would.
async fn raise(rig: &Rig, backbone: &str) -> VerifyEscalation {
    let now = rig.bridge.clock.now();
    let raised = VerifyEscalation {
        backbone: backbone.to_string(),
        until: now.plus_secs(ESCALATE_SECS),
        raised_at: now,
        extent_id: ExtentId::mint([0xee; 13]),
        result: VerifyResult::Corrupt,
    };
    rig.bridge.catalog.escalate_verify(&raised).await.unwrap();
    raised
}

/// The release records no pass for a backbone verify did not pass: its
/// answer to `STAT` now must not become the last word on it, or a
/// release that is tried again would count it. A failure found by the
/// release is recorded all the same.
#[tokio::test]
async fn the_release_records_nothing_for_a_backbone_verify_did_not_pass() {
    let rig = three_backbone_rig([("bb0", true), ("bb1", false), ("bb2", false)]).await;
    let (s, _) = rig.on_two(21).await;
    let mut outcome = rig.run(&s, OutboxStage::Verify).await;
    while outcome != JobOutcome::Ack {
        rig.wait_until_due(&s);
        outcome = rig.run(&s, OutboxStage::Verify).await;
    }
    assert_eq!(rig.stage(&s), OutboxStage::Release);
    let missing = row("bb2", VerifyKind::Stat, VerifyResult::Missing);
    assert_eq!(rig.checks(&s).last().unwrap(), &missing);

    // The third backbone gets the extent: the release asks it and it
    // answers, but the two that verify passed are the release.
    rig.propagate(&s, 0, 2).await;
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
    let rows = rig.checks(&s);
    let of_third: Vec<_> = rows.iter().filter(|r| r.0 == "bb2").collect();
    assert_eq!(of_third, [&missing]);
    assert!(rig.evidence(&s).iter().all(|e| e.0 != "bb2"));
}

/// A backbone under full reads that lacks the extent does not hold the
/// release for good while enough others have it: one of them is read in
/// full instead, and the extent is released on those.
#[tokio::test]
async fn another_backbone_is_read_in_full_when_the_one_named_lacks_the_extent() {
    let rig = three_backbone_rig([("bb0", true), ("bb1", false), ("bb2", false)]).await;
    raise(&rig, "bb2").await;
    rig.bridge.clock.advance_secs(1);
    // Stored while the third backbone is under full reads, and never
    // copied to it.
    let (s, plan) = rig.on_two(22).await;
    for _ in 0..12 {
        rig.logged(&s, OutboxStage::Verify).await;
        if rig.stage(&s) == OutboxStage::Release {
            break;
        }
        rig.wait_until_due(&s);
    }
    assert_eq!(rig.stage(&s), OutboxStage::Release);
    let rows = rig.checks(&s);
    assert!(rows.contains(&ok("bb0", VerifyKind::Sampled)));
    assert!(rows.contains(&row("bb2", VerifyKind::Sampled, VerifyResult::Missing)));
    // One full read stands in, not one per backbone.
    assert!(!rows.contains(&ok("bb1", VerifyKind::Sampled)));
    assert_eq!(rig.calls().0, 2 * plan.len());

    // An article is gone for a moment when the release asks: back to
    // verify. The full read on record still stands there, though the
    // latest row of its backbone is now a presence pass.
    rig.servers[1].hide(&plan[0].message_id).await;
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.stage(&s), OutboxStage::Verify);
    rig.servers[1].unhide(&plan[0].message_id).await;
    for _ in 0..12 {
        rig.wait_until_due(&s);
        rig.logged(&s, OutboxStage::Verify).await;
        if rig.stage(&s) == OutboxStage::Release {
            break;
        }
    }
    assert_eq!(rig.stage(&s), OutboxStage::Release);
    let rows = rig.checks(&s);
    let full = |r: &&(String, VerifyKind, VerifyResult)| r.0 == "bb0" && r.1.is_full();
    assert_eq!(rows.iter().filter(full).count(), 1);
    let last = rows.iter().rev().find(|r| r.0 == "bb0").unwrap();
    assert_eq!(last, &ok("bb0", VerifyKind::Stat));

    rig.wait_until_due(&s);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
    let evidence = rig.evidence(&s);
    assert!(evidence.contains(&entry("bb0", "sampled", None)));
    assert!(evidence.iter().all(|e| e.0 != "bb2"));
}

/// Two providers on one backbone may answer differently. A full read
/// that finds an article missing is held against the `STAT` of the same
/// provider: what another provider of the backbone says of the article
/// neither makes the first one a provider that answers for bytes it
/// lacks nor clears it of that.
#[tokio::test]
async fn a_failed_full_read_is_held_against_the_stat_of_the_same_provider() {
    let rig = three_backbone_rig([("bb0", true), ("bb1", false), ("bb1", false)]).await;
    let raised = raise(&rig, "bb1").await;
    rig.bridge.clock.advance_secs(1);
    let (s, plan) = rig.on_two(23).await;
    rig.propagate(&s, 0, 2).await;
    // The first provider of the backbone lacks one article, for `BODY`
    // and for `STAT`. The second lists them all and serves no body.
    rig.servers[1].hide(&plan[0].message_id).await;
    rig.servers[2].set_body_gone(true).await;

    let missing = |rig: &Rig| {
        let rows = rig.bridge.catalog.verifications(&s.extent);
        let row = rows.into_iter().find(|r| r.result == VerifyResult::Missing);
        row.map(|r| (r.backbone, r.provider_id))
    };
    for _ in 0..12 {
        assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
        if missing(&rig).is_some() {
            break;
        }
        rig.wait_until_due(&s);
    }
    let (backbone, _) = missing(&rig).expect("a missing row");
    assert_eq!(backbone, "bb1");
    let now = rig.bridge.catalog.escalations.borrow().clone();
    // Each read that finds the article missing is held against `STAT`
    // at once, before the waits, so what counts is which providers were
    // read in any of the rounds.
    match rig.bridge.nntp.connects_to("p2") {
        // Only the first provider was read and nothing was raised: the
        // row is the one from before, though the other provider answers
        // `STAT` for the article.
        0 => assert_eq!(now, [raised]),
        // The second was read and raised the backbone, though the other
        // provider says with `STAT` that the article is not there.
        _ => assert_eq!(
            (&now[0].extent_id, now[0].result),
            (&s.extent, VerifyResult::Missing)
        ),
    }
}

/// One backbone is not two under the light check either.
#[tokio::test]
async fn one_backbone_releases_nothing_under_the_light_check() {
    let rig = light_rig(0, &[]).await;
    // Never copied to the second backbone.
    let s = rig.seed(7, &marked_plaintext(PLAIN_LEN)).await;
    rig.post(&s).await;

    assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.stage(&s), OutboxStage::Verify);
    assert_eq!(rig.state(&s), SafetyState::Held);
}

/// The release waits for the minimum age under the light check as well.
#[tokio::test]
async fn the_minimum_age_holds_under_the_light_check() {
    let mut rig = light_rig(0, &[]).await;
    rig.bridge.cfg.safety_min_age_secs = 7_200;
    let (s, _) = rig.on_two(8).await;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.stage(&s), OutboxStage::Release);
    let due = rig.bridge.catalog.outbox(&s.extent).next_at;
    assert!(due >= rig.bridge.clock.now().plus_secs(7_000));
    // A job that runs early releases nothing.
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.outbox.next_at = rig.bridge.clock.now();
    });
    rig.run(&s, OutboxStage::Release).await;
    assert_eq!(rig.state(&s), SafetyState::Held);
    assert_eq!(rig.stage(&s), OutboxStage::Release);

    rig.bridge.clock.advance_secs(7_300);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
}

/// A sampled extent is read in full on the backbone its id draws, and
/// the evidence says `sampled`.
#[tokio::test]
async fn a_sampled_extent_is_read_in_full_on_one_backbone() {
    let rig = light_rig(ALL, &[]).await;
    let (s, plan) = rig.on_two(9).await;
    let n = plan.len();
    let drawn = rig.sample_index(&s);
    let other = 1 - drawn;
    // The other backbone could not pass a full read: it is not asked for
    // one.
    rig.servers[other].set_body_gone(true).await;

    assert_eq!(rig.logged(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    // One backbone read, the other asked for presence.
    assert_eq!(rig.calls(), (n, n, 0));
    let names = ["bb0", "bb1"];
    let mut want = [ok("bb0", VerifyKind::Stat), ok("bb1", VerifyKind::Stat)];
    want[drawn].1 = VerifyKind::Sampled;
    assert_eq!(rig.checks(&s), want);

    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
    assert_eq!(
        rig.evidence(&s),
        [
            entry("bb0", "stat", None),
            entry("bb1", "stat", None),
            entry(names[drawn], "sampled", None),
        ]
    );
}

/// A sampled read that finds a corrupt article raises the sample to
/// every extent on that backbone for a while: extents outside the sample
/// are read in full there, and released only with that read on record.
#[tokio::test]
async fn a_corrupt_sample_raises_the_backbone_to_full_reads() {
    let mut rig = light_rig(ALL, &[]).await;
    let bad = rig.seed(10, &marked_plaintext(PLAIN_LEN)).await;
    rig.post_with_planted_article(&bad, 1).await;
    rig.propagate(&bad, 0, 1).await;
    let drawn = rig.sample_index(&bad);
    let name = ["bb0", "bb1"][drawn];
    let now = rig.bridge.clock.now();

    assert_eq!(
        retry_delay(&rig.run(&bad, OutboxStage::Verify).await),
        REVERIFY_SECS
    );
    assert_eq!(
        rig.checks(&bad)[drawn],
        row(name, VerifyKind::Sampled, VerifyResult::Corrupt)
    );
    assert_eq!(rig.state(&bad), SafetyState::Held);
    let raised = rig.bridge.catalog.escalations.borrow().clone();
    let expected = VerifyEscalation {
        backbone: name.to_string(),
        until: now.plus_secs(ESCALATE_SECS),
        raised_at: now,
        extent_id: bad.extent.clone(),
        result: VerifyResult::Corrupt,
    };
    assert!(raised.contains(&expected));
    // The other backbone has a copy of the same corrupt article and is
    // read in full to stand in for the one drawn, in this round or the
    // next. It fails too and is raised too: the record does not say
    // which articles failed, so this is not told from damage of its own.
    rig.wait_until_due(&bad);
    rig.run(&bad, OutboxStage::Verify).await;
    let mut names: Vec<String> = Vec::new();
    for e in rig.bridge.catalog.escalations.borrow().iter() {
        assert_eq!(
            (&e.extent_id, e.result),
            (&bad.extent, VerifyResult::Corrupt)
        );
        names.push(e.backbone.clone());
    }
    names.sort();
    assert_eq!(names, ["bb0", "bb1"]);
    // An extent raises a backbone once. Its bytes were bad when posted
    // and stay bad: every later round fails the same reads, during the
    // escalations and after them, and moves neither end.
    let raised = rig.bridge.catalog.escalations.borrow().clone();
    for _ in 0..6 {
        rig.bridge.clock.advance_secs(ESCALATE_SECS / 4);
        rig.wait_until_due(&bad);
        assert_ne!(rig.run(&bad, OutboxStage::Verify).await, JobOutcome::Ack);
        assert_eq!(*rig.bridge.catalog.escalations.borrow(), raised);
    }
    assert_eq!(rig.state(&bad), SafetyState::Held);
    // The rest follows the one that was drawn, from its first read.
    *rig.bridge.catalog.escalations.borrow_mut() = vec![expected];

    // From here on nothing is in the sample by its id.
    rig.bridge.cfg.verify.sample_ppm = 0;
    let (s, plan) = rig.on_two(11).await;
    let n = plan.len();
    assert_eq!(rig.logged(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.calls().0, n);
    let mut want = [ok("bb0", VerifyKind::Stat), ok("bb1", VerifyKind::Stat)];
    want[drawn].1 = VerifyKind::Sampled;
    assert_eq!(rig.checks(&s), want);
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
    assert!(rig.evidence(&s).contains(&entry(name, "sampled", None)));

    // An extent stored before the period ended is read in full there
    // even when its job runs after it: a backlog does not let it by.
    rig.bridge.clock.advance_secs(ESCALATE_SECS);
    let (late, plan) = rig.on_two(14).await;
    assert_eq!(
        rig.logged(&late, OutboxStage::Verify).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls().0, plan.len());
    assert_eq!(rig.checks(&late), want);

    // Extents stored after the period are not read in full again.
    let (after, _) = rig.on_two(12).await;
    let now = rig.bridge.clock.now();
    let catalog = &rig.bridge.catalog;
    catalog.edit(&after.extent, |e| e.job.extent.created_at = now);
    assert_eq!(
        rig.logged(&after, OutboxStage::Verify).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls().0, 0);
    assert_eq!(
        rig.checks(&after),
        [ok("bb0", VerifyKind::Stat), ok("bb1", VerifyKind::Stat)]
    );
}

/// A backbone that answers `STAT` for articles whose bytes it does not
/// serve is what the sample is for: the full read finds them missing,
/// `STAT` says they are there, and the backbone is raised to full reads.
#[tokio::test]
async fn a_sample_that_cannot_be_read_where_stat_passes_escalates() {
    let rig = light_rig(ALL, &[]).await;
    let (s, _) = rig.on_two(13).await;
    let drawn = rig.sample_index(&s);
    let name = ["bb0", "bb1"][drawn];
    rig.servers[drawn].set_body_gone(true).await;

    // The backbone is raised by the first read that finds this, before
    // the waits for a missing article: they take hours, and all that
    // time the provider would answer `STAT` for other extents.
    let now = rig.bridge.clock.now();
    let expected = VerifyEscalation {
        backbone: name.to_string(),
        until: now.plus_secs(ESCALATE_SECS),
        raised_at: now,
        extent_id: s.extent.clone(),
        result: VerifyResult::Missing,
    };
    let want = vec![expected];
    // The waits themselves are those of `body`, and the reads that come
    // after them find nothing new: the end stays where it was put.
    for wait in MISSING_BACKOFF_SECS {
        assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), wait);
        assert_eq!(*rig.bridge.catalog.escalations.borrow(), want);
        // Not recorded yet: the backbone is read again after the wait.
        assert!(rig.checks(&s).iter().all(|r| r.0 != name));
        rig.bridge.clock.advance_secs(wait);
    }
    assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert!(rig
        .checks(&s)
        .contains(&row(name, VerifyKind::Sampled, VerifyResult::Missing)));
    assert_eq!(*rig.bridge.catalog.escalations.borrow(), want);
    // Nor does a read after the escalation has ended raise it again:
    // this extent has had its say on the backbone.
    rig.bridge.clock.advance_secs(ESCALATE_SECS);
    rig.wait_until_due(&s);
    assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(*rig.bridge.catalog.escalations.borrow(), want);
    assert_eq!(rig.state(&s), SafetyState::Held);
    assert_eq!(rig.stage(&s), OutboxStage::Verify);
}

/// An article that is simply not there is not a provider answering for
/// bytes it lacks: every check finds it, so the sample is not raised.
#[tokio::test]
async fn a_sample_missing_for_stat_too_does_not_escalate() {
    let rig = light_rig(ALL, &[]).await;
    let (s, plan) = rig.on_two(14).await;
    let drawn = rig.sample_index(&s);
    rig.servers[drawn].hide(&plan[0].message_id).await;

    for wait in MISSING_BACKOFF_SECS {
        assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), wait);
        rig.bridge.clock.advance_secs(wait);
    }
    assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let missing = rig.checks(&s);
    assert!(missing.iter().any(|r| r.2 == VerifyResult::Missing));
    assert!(rig.bridge.catalog.escalations.borrow().is_empty());
    assert_eq!(rig.state(&s), SafetyState::Held);
}

/// An extent that passed the light check before a backbone was raised to
/// full reads is not released on that pass: it goes back to verify and
/// is read in full there.
#[tokio::test]
async fn an_escalation_reaches_extents_that_wait_for_their_release() {
    let rig = light_rig(0, &[]).await;
    let (s, plan) = rig.on_two(15).await;
    let n = plan.len();
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.stage(&s), OutboxStage::Release);

    let now = rig.bridge.clock.now();
    let raised = VerifyEscalation {
        backbone: "bb1".to_string(),
        until: now.plus_secs(ESCALATE_SECS),
        raised_at: now,
        extent_id: ExtentId::mint([0xee; 13]),
        result: VerifyResult::Corrupt,
    };
    rig.bridge.catalog.escalate_verify(&raised).await.unwrap();
    // An earlier end does not shorten it.
    let shorter = VerifyEscalation {
        until: now.plus_secs(60),
        ..raised.clone()
    };
    rig.bridge.catalog.escalate_verify(&shorter).await.unwrap();
    assert_eq!(*rig.bridge.catalog.escalations.borrow(), [raised]);

    // The release comes late, after the period is over: the extent was
    // stored before its end, so it is still held to it.
    rig.bridge.clock.advance_secs(ESCALATE_SECS + 60);
    assert_eq!(rig.logged(&s, OutboxStage::Release).await, JobOutcome::Ack);
    // Nothing was asked: there is no full check on record.
    assert_eq!(rig.calls(), (0, 0, 0));
    assert_eq!(rig.stage(&s), OutboxStage::Verify);
    assert_eq!(rig.state(&s), SafetyState::Held);

    assert_eq!(rig.logged(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.calls().0, n);
    assert_eq!(
        rig.checks(&s)[2..],
        [ok("bb0", VerifyKind::Stat), ok("bb1", VerifyKind::Sampled)]
    );
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
}

/// While a backbone is under full reads it holds a copy only with its
/// own full read on record: the full read of another backbone does not
/// stand in for it.
#[tokio::test]
async fn a_backbone_under_full_reads_needs_its_own_full_read() {
    let mut rig = light_rig(0, &[]).await;
    // Verified under `body`: the first backbone read in full, the second
    // asked with `STAT`.
    rig.bridge.cfg.verify.mode = VerifyMode::Body;
    let (s, _) = rig.on_two(16).await;
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(
        rig.checks(&s),
        [ok("bb0", VerifyKind::Body), ok("bb1", VerifyKind::Stat)]
    );

    rig.bridge.cfg.verify.mode = VerifyMode::Light;
    let now = rig.bridge.clock.now();
    let raised = VerifyEscalation {
        backbone: "bb1".to_string(),
        until: now.plus_secs(ESCALATE_SECS),
        raised_at: now,
        extent_id: ExtentId::mint([0xee; 13]),
        result: VerifyResult::Corrupt,
    };
    rig.bridge.catalog.escalate_verify(&raised).await.unwrap();
    rig.bridge.clock.advance_secs(1);
    rig.run(&s, OutboxStage::Release).await;
    assert_eq!(rig.state(&s), SafetyState::Held);
    assert!(rig.bridge.safety.contains(&s.extent.safety_key()));
    assert_eq!(rig.stage(&s), OutboxStage::Verify);

    // Read in full there, it is released.
    rig.wait_until_due(&s);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let rows = rig.checks(&s);
    assert_eq!(rows[rows.len() - 1], ok("bb1", VerifyKind::Sampled));
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
}

/// A rollout from `body` to `light` and back, with extents in between
/// the stages. Each job follows the mode of the Worker it runs in.
#[tokio::test]
async fn the_two_modes_side_by_side() {
    let mut rig = light_rig(0, &[]).await;

    // Verified under `light`, released by a Worker under `body`: there
    // is no full check on record, so nothing is released. The extent
    // goes back to verify, is read in full, and is released then.
    let (s, plan) = rig.on_two(20).await;
    let n = plan.len();
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    rig.bridge.cfg.verify.mode = VerifyMode::Body;
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.logged(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.calls(), (0, 0, 0));
    assert_eq!(rig.stage(&s), OutboxStage::Verify);
    assert_eq!(rig.state(&s), SafetyState::Held);
    assert_eq!(rig.logged(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.calls().0, n);
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
    assert_eq!(
        rig.evidence(&s),
        [
            entry("bb0", "stat", None),
            entry("bb1", "stat", None),
            entry("bb0", "body", None),
        ]
    );

    // Verified under `body`, released under `light`: the full check on
    // record stays valid and stays in the evidence, whether the extent
    // is in the sample or not.
    for (seed, ppm) in [(21, 0), (22, ALL)] {
        rig.bridge.cfg.verify.mode = VerifyMode::Body;
        let (s, _) = rig.on_two(seed).await;
        assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
        rig.bridge.cfg.verify.mode = VerifyMode::Light;
        rig.bridge.cfg.verify.sample_ppm = ppm;
        rig.bridge.clock.advance_secs(1);
        assert_eq!(rig.logged(&s, OutboxStage::Release).await, JobOutcome::Ack);
        assert_eq!(rig.calls(), (0, 2 * n, 0));
        assert_eq!(rig.state(&s), SafetyState::Released, "ppm = {ppm}");
        assert!(rig.evidence(&s).contains(&entry("bb0", "body", None)));
    }

    // Sampled under `light`, released under `body`: a sampled read is a
    // full read.
    rig.bridge.cfg.verify.sample_ppm = ALL;
    let (s, _) = rig.on_two(23).await;
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    rig.bridge.cfg.verify.mode = VerifyMode::Body;
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
    let sampled = rig.evidence(&s);
    assert_eq!(sampled.iter().filter(|e| e.1 == "sampled").count(), 1);

    // A row put off under one mode is picked up under the other: a walk
    // that stopped at the second backbone under `body` goes on under
    // `light`.
    rig.bridge.cfg.verify.mode = VerifyMode::Body;
    rig.bridge.cfg.verify.sample_ppm = 0;
    let (s, plan) = rig.on_two(24).await;
    rig.servers[1].hide(&plan[0].message_id).await;
    assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.checks(&s), [ok("bb0", VerifyKind::Body)]);
    rig.servers[1].unhide(&plan[0].message_id).await;
    rig.bridge.cfg.verify.mode = VerifyMode::Light;
    rig.bridge.clock.advance_secs(MISSING_BACKOFF_SECS[0]);
    rig.verify_and_release(&s).await;
    assert_eq!(rig.state(&s), SafetyState::Released);
}

/// `body` is what a configuration that says nothing gets, and under it
/// nothing of the light check runs.
#[tokio::test]
async fn the_default_is_the_full_read_of_every_extent() {
    let mut rig = two_backbone_rig().await;
    assert_eq!(rig.bridge.cfg.verify, VerifyConfig::default());
    assert_eq!(VerifyConfig::default().mode, VerifyMode::Body);
    // A size command and a sample rate change nothing under `body`.
    rig.bridge.cfg.verify.size_commands = vec![("p0".to_string(), SizeCommand::Head)];
    rig.bridge.cfg.verify.sample_ppm = 0;
    let (s, plan) = rig.on_two(30).await;
    let n = plan.len();

    assert_eq!(rig.logged(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.calls(), (n, n, 0));
    assert_eq!(
        rig.checks(&s),
        [ok("bb0", VerifyKind::Body), ok("bb1", VerifyKind::Stat)]
    );
    // And nothing is asked for together, at verify or at release.
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
    assert!(!events().contains(&"ask_many"));
}

/// Under the light check the articles of an extent are asked for in one
/// call per provider, at verify and at release, and a call that breaks
/// costs nothing but the round trip: its articles are asked one by one.
#[tokio::test]
async fn the_light_check_asks_for_an_extent_together() {
    let rig = light_rig(0, &[("p0", SizeCommand::Head)]).await;
    rig.servers[0].set_reported_size(Some(0)).await;
    let together = || events().iter().filter(|e| **e == "ask_many").count();
    let (s, plan) = rig.on_two(41).await;
    let n = plan.len();

    assert_eq!(rig.logged(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.calls(), (0, n, n));
    assert_eq!(together(), 2);
    assert_eq!(
        rig.checks(&s),
        [ok("bb0", VerifyKind::Size), ok("bb1", VerifyKind::Stat)]
    );
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.state(&s), SafetyState::Released);
    assert_eq!(together(), 4);

    // The connection of the second backbone closes on the first `STAT`
    // of the call: every article is then asked on its own, on a new
    // connection, and the answer is the same.
    let (s, plan) = rig.on_two(42).await;
    let n = plan.len();
    rig.servers[1].drop_next_stats(1).await;
    assert_eq!(rig.logged(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(together(), 6);
    // The `STAT`s of the call that broke, and one for each article.
    assert_eq!(rig.calls(), (0, 2 * n, n));
    assert_eq!(
        rig.checks(&s),
        [ok("bb0", VerifyKind::Size), ok("bb1", VerifyKind::Stat)]
    );

    // An article missing in the middle of a call is missing, and the
    // others are not.
    let (s, plan) = rig.on_two(43).await;
    rig.servers[1].hide(&plan[1].message_id).await;
    let wait = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(wait, MISSING_BACKOFF_SECS[0]);
    assert_eq!(rig.checks(&s), [ok("bb0", VerifyKind::Size)]);
    assert_eq!(rig.stage(&s), OutboxStage::Verify);
    assert_eq!(rig.state(&s), SafetyState::Held);
}

fn extent_id(n: u32) -> ExtentId {
    let mut rand = [0u8; 13];
    rand[..4].copy_from_slice(&n.to_be_bytes());
    rand[4..8].copy_from_slice(&n.wrapping_mul(2_654_435_761).to_be_bytes());
    ExtentId::mint(rand)
}

/// The sample follows from the extent id and the key alone: the same
/// answer every time, at the configured rate, and another set under
/// another key.
#[test]
fn the_sample_is_deterministic_and_at_the_configured_rate() {
    let kek = KekBytes::new([0x11; 32]);
    let other = KekBytes::new([0x22; 32]);
    const N: u32 = 100_000;
    let ids: Vec<ExtentId> = (0..N).map(extent_id).collect();
    let drawn = |kek: &KekBytes, ppm: u32| -> Vec<bool> {
        ids.iter().map(|id| in_sample(kek, id, ppm)).collect()
    };
    let count = |v: &[bool]| v.iter().filter(|b| **b).count();

    // 2 %: 2000 of 100 000 expected, standard deviation 44.
    let two = drawn(&kek, 20_000);
    assert!((1_750..=2_250).contains(&count(&two)), "{}", count(&two));
    // A retry, the release job, another isolate: the same extents.
    assert_eq!(drawn(&kek, 20_000), two);
    // None and all.
    assert_eq!(count(&drawn(&kek, 0)), 0);
    assert_eq!(count(&drawn(&kek, ALL)), N as usize);
    // A higher rate adds extents and drops none.
    let five = drawn(&kek, 50_000);
    assert!((4_600..=5_400).contains(&count(&five)), "{}", count(&five));
    assert!(two.iter().zip(&five).all(|(a, b)| !*a || *b));
    // Another key draws another sample of the same size: the ids alone
    // do not tell which extents are read.
    let foreign = drawn(&other, 20_000);
    assert!((1_750..=2_250).contains(&count(&foreign)));
    let both = two.iter().zip(&foreign).filter(|(a, b)| **a && **b).count();
    assert!(both < 120, "{both} extents in both samples");

    // The backbone a sampled extent is read on: stable, in range, and
    // every backbone gets its share.
    let on: Vec<usize> = ids.iter().map(|id| sample_backbone(&kek, id, 2)).collect();
    let again: Vec<usize> = ids.iter().map(|id| sample_backbone(&kek, id, 2)).collect();
    assert_eq!(on, again);
    let second = on.iter().filter(|i| **i == 1).count();
    assert!(on.iter().all(|i| *i < 2));
    assert!((49_000..=51_000).contains(&second), "{second}");
    assert!(ids.iter().all(|id| sample_backbone(&kek, id, 1) == 0));
    assert!(ids.iter().all(|id| sample_backbone(&kek, id, 3) < 3));
    // Whether an extent is sampled says nothing about where.
    let sampled_on_second = two.iter().zip(&on).filter(|(s, i)| **s && **i == 1).count();
    assert!((800..=1_200).contains(&sampled_on_second));
}

/// What the size is compared with: the range the stored article of a row
/// can have, from its payload length.
#[test]
fn size_bounds_cover_real_articles_and_little_else() {
    let article = |cipher_len: u64| ArticleRow {
        extent_id: ExtentId::mint([1; 13]),
        idx: 0,
        message_id: "m@example.invalid".to_string(),
        newsgroup: "alt.binaries.test".to_string(),
        headers: vec![b'h'; 300],
        cipher_offset: 0,
        cipher_len,
        payload_sha256: [0; 32],
        state: ArticleState::Posted,
        provider_id: Some("p0".to_string()),
        posted_at: None,
        reposted_at: None,
        yenc_name: None,
    };
    // Measured on two providers: the payload length, the bytes of the
    // `BODY` answer, and the size the injecting server stamped.
    for (cipher_len, body, stamped) in [
        (1_064, 1_172, 1_883),
        (100_080, 103_269, 103_988),
        (721_120, 744_175, 744_918),
    ] {
        let (least, most) = size_bounds(&article(cipher_len));
        assert!(least <= body && body <= most, "{cipher_len}: body");
        assert!(least <= stamped && stamped <= most, "{cipher_len}: stamped");
        // The payload without its encoding is too small, and so is an
        // article that lost one line in a hundred.
        if cipher_len > 50_000 {
            assert!(cipher_len < least);
            assert!(body - body / 100 < least);
        }
        // Twice the article is too large.
        if cipher_len > 50_000 {
            assert!(2 * body > most);
        }
        // The slack above the largest plain article is the headers.
        assert!(most - body < 8_192 + 300 + 256 + cipher_len / 20);
    }
    let (least, most) = size_bounds(&article(0));
    assert!(least == 0 && most >= 8_192);
}

/// The size commands against a server: one that reports a size, one that
/// does not know the command, and an article that is not there.
#[tokio::test]
async fn size_commands_against_a_server() {
    let rig = simple_rig().await;
    let s = rig.seed(40, &marked_plaintext(PLAIN_LEN)).await;
    let plan = rig.post(&s).await;
    let id = plan[0].message_id.as_str();
    let (least, most) = size_bounds(&plan[0]);
    let mut client = rig.raw_client(0).await;
    let commands = [SizeCommand::Head, SizeCommand::Hdr, SizeCommand::Over];

    // No size on offer: `HEAD` has no `Bytes:` header, `HDR` and `OVER`
    // are not known and the article is asked for with `STAT`.
    for how in commands {
        let found = stored_size(&mut client, id, how).await.unwrap();
        assert_eq!(found, SizeOutcome::Present(None), "{how:?}");
        let gone = stored_size(&mut client, "gone@example.invalid", how).await;
        assert_eq!(gone.unwrap(), SizeOutcome::Missing, "{how:?}");
    }

    rig.server().set_reported_size(Some(0)).await;
    let mut sizes = Vec::new();
    for how in commands {
        match stored_size(&mut client, id, how).await.unwrap() {
            SizeOutcome::Present(Some(size)) => sizes.push(size),
            other => panic!("{how:?}: {other:?}"),
        }
        let gone = stored_size(&mut client, "gone@example.invalid", how).await;
        assert_eq!(gone.unwrap(), SizeOutcome::Missing, "{how:?}");
    }
    assert_eq!(sizes, [sizes[0]; 3]);
    assert!(least <= sizes[0] && sizes[0] <= most, "{sizes:?}");

    // A size that came with the article is told apart from the
    // provider's own count.
    rig.server().set_size_carried(true).await;
    let carried = stored_size(&mut client, id, SizeCommand::Head).await;
    assert_eq!(carried.unwrap(), SizeOutcome::Carried(sizes[0]));
    rig.server().set_size_carried(false).await;

    // An `OVER` answer with no line for the article says nothing, not
    // even that the article is there: `STAT` is asked.
    rig.server().set_over_empty(true).await;
    let found = stored_size(&mut client, id, SizeCommand::Over).await;
    assert_eq!(found.unwrap(), SizeOutcome::Present(None));
    let gone = stored_size(&mut client, "gone@example.invalid", SizeCommand::Over).await;
    assert_eq!(gone.unwrap(), SizeOutcome::Missing);
    rig.server().set_over_empty(false).await;
    // The session is still in step after every answer.
    assert!(NntpSession::stat(&mut client, id).await.unwrap());

    // Asked for together, the answers are those of one by one, in
    // order, whatever the command and whatever the server has on offer.
    let ids = [id, "gone@example.invalid", id, plan[1].message_id.as_str()];
    for setting in 0..4 {
        rig.server()
            .set_reported_size((setting > 0).then_some(0))
            .await;
        rig.server().set_size_carried(setting == 2).await;
        rig.server().set_over_empty(setting == 3).await;
        for how in [None, Some(SizeCommand::Head), Some(SizeCommand::Hdr)]
            .into_iter()
            .chain([Some(SizeCommand::Over)])
        {
            let mut one_by_one = Vec::new();
            for id in ids {
                one_by_one.push(match how {
                    Some(how) => stored_size(&mut client, id, how).await.unwrap(),
                    None => match NntpSession::stat(&mut client, id).await.unwrap() {
                        true => SizeOutcome::Present(None),
                        false => SizeOutcome::Missing,
                    },
                });
            }
            let together = stored_sizes(&mut client, &ids, how).await.unwrap();
            assert_eq!(together, one_by_one, "{setting} {how:?}");
            assert_eq!(together[1], SizeOutcome::Missing);
            assert_ne!(together[0], SizeOutcome::Missing);
        }
    }
    assert!(stored_sizes(&mut client, &[], None)
        .await
        .unwrap()
        .is_empty());
    // The session is still in step.
    assert!(NntpSession::stat(&mut client, id).await.unwrap());

    // A message-id that could carry a second command is refused before
    // anything is sent, alone or among others.
    for bad in ["", "a b@x", "a>\r\nQUIT", "<a@x>"] {
        let refused = stored_size(&mut client, bad, SizeCommand::Head).await;
        assert!(refused.is_err(), "{bad:?}");
        for how in [None, Some(SizeCommand::Head)] {
            let refused = stored_sizes(&mut client, &[id, bad], how).await;
            assert!(refused.is_err(), "{bad:?}");
        }
    }
    assert!(NntpSession::stat(&mut client, id).await.unwrap());
    client.quit().await;
}
