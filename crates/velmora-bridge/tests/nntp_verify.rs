//! Verify and release stages against the in-process NNTP server.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::config::Environment;
use velmora_bridge::verify::{MISSING_BACKOFF_SECS, REVERIFY_SECS};
use velmora_bridge::*;

const PLAIN_LEN: usize = 1_500_000;

/// The generic retry delay of a failed job: `60 s * 2^(attempts-1)`.
fn backoff(attempts: u32) -> u32 {
    60 << (attempts - 1)
}

fn retry_delay(outcome: &JobOutcome) -> u32 {
    match outcome {
        JobOutcome::Retry { delay_secs } => *delay_secs,
        JobOutcome::Ack => panic!("expected a retry, got an ack"),
    }
}

impl Rig {
    async fn posted(&self, n: u8) -> (Seeded, Vec<ArticleRow>) {
        let s = self.seed(n, &marked_plaintext(PLAIN_LEN)).await;
        let plan = self.post(&s).await;
        (s, plan)
    }

    /// Posts, copies the articles to the second backbone, and verifies
    /// both: the extent is at the release stage.
    async fn verified_on_two(&self, n: u8) -> (Seeded, Vec<ArticleRow>) {
        let (s, plan) = self.posted(n).await;
        self.propagate(&s, 0, 1).await;
        assert_eq!(self.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
        assert_eq!(self.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
        assert_eq!(self.outbox(&s).stage, OutboxStage::Release);
        assert_eq!(self.outbox(&s).cursor, 0);
        self.bridge.jobs.take();
        self.bridge.clock.advance_secs(1);
        (s, plan)
    }

    fn outbox(&self, s: &Seeded) -> OutboxRow {
        self.bridge.catalog.outbox(&s.extent)
    }

    fn rows(&self, s: &Seeded) -> Vec<VerificationRow> {
        self.bridge.catalog.verifications(&s.extent)
    }

    fn safety_held(&self, s: &Seeded) -> bool {
        self.bridge.safety.contains(&s.extent.safety_key())
            && self.bridge.catalog.extent(&s.extent).safety_state == SafetyState::Held
    }

    fn sent_stages(&self) -> Vec<(OutboxStage, u32)> {
        let sent = self.bridge.jobs.take();
        sent.iter()
            .map(|j| match &j.job {
                Job::Extent { stage, .. } => (*stage, j.delay_secs),
                other => panic!("unexpected job {other:?}"),
            })
            .collect()
    }
}

#[tokio::test]
async fn verify_records_a_complete_pass_and_hands_over_to_release() {
    let rig = simple_rig().await;
    let (s, _) = rig.posted(1).await;
    let now = rig.bridge.clock.now();

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);

    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].result, VerifyResult::Ok);
    assert_eq!((rows[0].articles_ok, rows[0].articles_total), (3, 3));
    assert_eq!(
        (rows[0].backbone.as_str(), rows[0].provider_id.as_str()),
        ("bb0", "p0")
    );
    assert_eq!(rows[0].plan_rev, 1);
    assert_eq!(rows[0].verified_at, now);
    let outbox = rig.outbox(&s);
    assert_eq!(outbox.stage, OutboxStage::Release);
    assert_eq!(outbox.next_at, now);
    assert_eq!(outbox.cursor, 0);
    assert_eq!(rig.sent_stages(), [(OutboxStage::Release, 0)]);
    // Verification reads; it never changes the safety copy.
    assert!(rig.safety_held(&s));
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A missing article is read again after 2 min, 10 min, 1 h and 6 h. Only
/// then is the backbone recorded as `missing`.
#[tokio::test]
async fn missing_is_retried_before_recorded() {
    let rig = simple_rig().await;
    let (s, plan) = rig.posted(2).await;
    rig.server().hide(&plan[1].message_id).await;

    assert_eq!(MISSING_BACKOFF_SECS, [120, 600, 3600, 21_600]);
    for (step, wait) in (1u32..).zip(MISSING_BACKOFF_SECS) {
        let now = rig.bridge.clock.now();
        assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), wait);
        let outbox = rig.outbox(&s);
        assert_eq!(outbox.stage, OutboxStage::Verify);
        assert_eq!(outbox.last_error, Some(FailClass::MissingPending));
        assert_eq!(outbox.next_at, now.plus_secs(wait));
        assert_eq!(outbox.cursor, step);
        assert!(rig.rows(&s).is_empty(), "nothing recorded at step {step}");
        // Not claimable before the wait is over.
        assert!(rig.try_claim(&s, OutboxStage::Verify).await.is_none());
        rig.bridge.clock.advance_secs(wait);
    }

    // The waits are used up: the result is recorded.
    assert_eq!(
        retry_delay(&rig.run(&s, OutboxStage::Verify).await),
        REVERIFY_SECS
    );
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].result, VerifyResult::Missing);
    assert_eq!((rows[0].articles_ok, rows[0].articles_total), (2, 3));
    let outbox = rig.outbox(&s);
    assert_eq!(outbox.stage, OutboxStage::Verify);
    assert_eq!(outbox.cursor, 0);
    assert!(rig.safety_held(&s));
    // Nothing was re-posted.
    assert_eq!(rig.server().posted_count().await, 3);

    // The article shows up: the next round passes and cancels the miss.
    rig.server().unhide(&plan[1].message_id).await;
    rig.bridge.clock.advance_secs(REVERIFY_SECS);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.rows(&s).last().unwrap().result, VerifyResult::Ok);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
}

/// An article that appears during the waits is never recorded as missing.
#[tokio::test]
async fn late_article_passes_without_a_missing_row() {
    let rig = simple_rig().await;
    let (s, plan) = rig.posted(3).await;
    rig.server().hide(&plan[2].message_id).await;

    assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), 120);
    rig.bridge.clock.advance_secs(120);
    assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), 600);
    rig.server().unhide(&plan[2].message_id).await;
    rig.bridge.clock.advance_secs(600);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);

    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].result, VerifyResult::Ok);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert_eq!(rig.outbox(&s).cursor, 0);
}

/// A present but wrong article is recorded as `corrupt` at once and the
/// extent never reaches release.
#[tokio::test]
async fn corrupt_article_is_recorded_as_corrupt() {
    let rig = simple_rig().await;
    let s = rig.seed(4, &marked_plaintext(PLAIN_LEN)).await;
    rig.post_with_planted_article(&s, 1).await;

    assert_eq!(
        retry_delay(&rig.run(&s, OutboxStage::Verify).await),
        REVERIFY_SECS
    );
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].result, VerifyResult::Corrupt);
    assert_eq!((rows[0].articles_ok, rows[0].articles_total), (2, 3));
    let outbox = rig.outbox(&s);
    assert_eq!(outbox.stage, OutboxStage::Verify);
    assert_eq!(outbox.last_error, Some(FailClass::Corrupt));
    assert!(rig.safety_held(&s));
}

/// A broken connection is replaced inside the job; when the reconnects run
/// out, nothing is recorded (only complete passes are).
#[tokio::test]
async fn transport_failure_records_nothing() {
    let rig = simple_rig().await;
    let (s, _) = rig.posted(5).await;

    rig.server().drop_next_bodies(3).await;
    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(delay, backoff(rig.outbox(&s).attempts));
    assert!(rig.rows(&s).is_empty());
    assert_eq!(rig.outbox(&s).last_error, Some(FailClass::NntpError));
    assert_eq!(rig.bridge.nntp.live(), 0);

    rig.server().drop_next_bodies(1).await;
    rig.bridge.clock.advance_secs(delay);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.rows(&s).len(), 1);
    assert_eq!(rig.rows(&s)[0].result, VerifyResult::Ok);
}

/// One backbone per job; the cursor carries the position between jobs and
/// moving on spends no attempt.
#[tokio::test]
async fn verify_walks_one_backbone_per_job() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.posted(6).await;
    rig.propagate(&s, 0, 1).await;
    let now = rig.bridge.clock.now();
    let attempts = rig.outbox(&s).attempts;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.rows(&s).len(), 1);
    assert_eq!(rig.rows(&s)[0].backbone, "bb0");
    let outbox = rig.outbox(&s);
    assert_eq!(outbox.stage, OutboxStage::Verify);
    assert_eq!(outbox.cursor, 8);
    assert_eq!(outbox.next_at, now);
    assert_eq!(outbox.attempts, attempts);
    assert_eq!(rig.sent_stages(), [(OutboxStage::Verify, 0)]);

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[1].backbone.as_str(), rows[1].provider_id.as_str()),
        ("bb1", "p1")
    );
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert_eq!(rig.sent_stages(), [(OutboxStage::Release, 0)]);
}

/// The second backbone never gets the articles: no release, and the safety
/// copy stays.
#[tokio::test]
async fn unverified_second_backbone_blocks_release() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.posted(7).await;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    for wait in MISSING_BACKOFF_SECS {
        assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), wait);
        rig.bridge.clock.advance_secs(wait);
    }
    assert_eq!(
        retry_delay(&rig.run(&s, OutboxStage::Verify).await),
        REVERIFY_SECS
    );
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[1].backbone.as_str(), rows[1].result),
        ("bb1", VerifyResult::Missing)
    );
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    assert!(rig.safety_held(&s));
}

/// One backbone where two are required: verification completes, the safety
/// copy is kept, and no release job exists.
#[tokio::test]
async fn too_few_backbones_keep_the_safety_copy() {
    let mut rig = simple_rig().await;
    rig.bridge.cfg.required_backbones = 2;
    let (s, _) = rig.posted(8).await;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.rows(&s)[0].result, VerifyResult::Ok);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Done);
    assert!(rig.sent_stages().is_empty());
    assert!(rig.safety_held(&s));
}

/// The release waits for the safety copy's minimum age.
#[tokio::test]
async fn release_waits_for_the_minimum_age() {
    let mut rig = simple_rig().await;
    let week = 7 * 24 * 3600;
    rig.bridge.cfg.safety_min_age_secs = week;
    let (s, _) = rig.posted(9).await;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let outbox = rig.outbox(&s);
    assert_eq!(outbox.stage, OutboxStage::Release);
    assert_eq!(outbox.next_at, T0.plus_secs(week));
    // Too far out for a queue delay: the dispatcher sends it when due.
    assert!(rig.sent_stages().is_empty());

    // A release job that runs early anyway defers itself.
    rig.bridge
        .catalog
        .edit(&s.extent, |e| e.outbox.next_at = T0);
    let connects = rig.bridge.nntp.connects();
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).next_at, T0.plus_secs(week));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert_eq!(rig.bridge.nntp.connects(), connects);
    assert!(rig.safety_held(&s));

    rig.bridge.clock.set(T0.plus_secs(week));
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.bridge.safety.contains(&s.extent.safety_key()));
    assert_eq!(
        rig.bridge.catalog.extent(&s.extent).safety_state,
        SafetyState::Released
    );
}

#[tokio::test]
async fn release_unpins_the_safety_copy_on_fresh_evidence() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.verified_on_two(10).await;
    rig.bridge.clock.advance_secs(3600);
    let now = rig.bridge.clock.now();

    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);

    assert!(rig.bridge.safety.contains(&s.extent.safety_key()));
    let extent = rig.bridge.catalog.extent(&s.extent);
    assert_eq!(extent.safety_state, SafetyState::Released);
    assert_eq!(extent.released_at, Some(now));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Done);
    // Two rows from verify, two fresh ones from this job; the evidence
    // names only the fresh ones.
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 4);
    let evidence: serde_json::Value =
        serde_json::from_str(extent.release_evidence.as_deref().unwrap()).unwrap();
    let evidence = evidence.as_array().unwrap();
    assert_eq!(evidence.len(), 2);
    for (entry, backbone) in evidence.iter().zip(["bb0", "bb1"]) {
        assert_eq!(entry["backbone"], backbone);
        assert_eq!(entry["verified_at"], now.0);
        assert_eq!(
            (entry["ok"].as_u64(), entry["total"].as_u64()),
            (Some(3), Some(3))
        );
        assert_eq!(entry["plan_rev"], 1);
    }
    // The extent is still readable from Usenet alone.
    let cold = rig.bridge.fetch_cold(&extent).await.unwrap();
    assert_eq!(cold, fetch::ColdFetch::Filled(s.cipher.clone()));
}

/// An earlier pass is not enough: the release reads every backbone again.
/// An article that has gone missing since keeps the safety copy and sends
/// the extent back to verify, which records the loss after its waits.
#[tokio::test]
async fn release_needs_fresh_evidence() {
    let rig = two_backbone_rig().await;
    let (s, plan) = rig.verified_on_two(11).await;
    rig.servers[1].hide(&plan[0].message_id).await;
    let now = rig.bridge.clock.now();

    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.safety_held(&s));
    assert_eq!(rig.bridge.catalog.extent(&s.extent).release_evidence, None);
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Verify, 0));
    assert_eq!(outbox.next_at, now);
    assert_eq!(rig.sent_stages(), [(OutboxStage::Verify, 0)]);

    // Verify walks its waits and then records the second backbone's loss.
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    for wait in MISSING_BACKOFF_SECS {
        assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), wait);
        rig.bridge.clock.advance_secs(wait);
    }
    let last = rig.run(&s, OutboxStage::Verify).await;
    assert_eq!(retry_delay(&last), REVERIFY_SECS);
    let status = rig.bridge.catalog.backbone_status(&s.extent).await.unwrap();
    let bb1 = status.iter().find(|b| b.backbone == "bb1").unwrap();
    assert_eq!((bb1.result, bb1.counts), (VerifyResult::Missing, false));
    assert!(rig.safety_held(&s));

    // The article comes back: verify passes and the release goes through.
    rig.servers[1].unhide(&plan[0].message_id).await;
    rig.bridge.clock.advance_secs(REVERIFY_SECS);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.bridge.safety.contains(&s.extent.safety_key()));
    assert_eq!(
        rig.bridge.catalog.extent(&s.extent).safety_state,
        SafetyState::Released
    );
}

/// A corrupt article found at release time is recorded, which cancels the
/// backbone's earlier pass, and the safety copy stays.
#[tokio::test]
async fn newer_failure_cancels_pass() {
    let rig = two_backbone_rig().await;
    let (s, plan) = rig.verified_on_two(12).await;
    // The second backbone's copy of article 2 is replaced by a wrong one.
    let id = &plan[2].message_id;
    rig.servers[1].hide(id).await;
    let mut client = rig.raw_client(1).await;
    let planted = render(&plan, &plan[2], &s.cipher, true);
    client.post_article(id, &planted).await.unwrap();
    client.quit().await;

    let now = rig.bridge.clock.now();
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.safety_held(&s));
    // Back to verify, which re-checks after the long wait.
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Verify, 0));
    assert_eq!(outbox.next_at, now.plus_secs(REVERIFY_SECS));
    let status = rig.bridge.catalog.backbone_status(&s.extent).await.unwrap();
    let bb1 = status.iter().find(|b| b.backbone == "bb1").unwrap();
    assert_eq!(bb1.result, VerifyResult::Corrupt);
    assert!(!bb1.counts);
}

/// Two accounts on one backbone are one copy: they never add up to the
/// two backbones a release needs.
#[tokio::test]
async fn same_backbone_counts_once() {
    let rig = shared_backbone_rig().await;
    let (s, _) = rig.posted(18).await;
    rig.propagate(&s, 0, 1).await;

    // One job covers the backbone; the second account is not a second pass.
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.rows(&s).len(), 1);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Done);
    assert!(rig.sent_stages().is_empty());
    assert!(rig.safety_held(&s));

    // Even a release job that runs anyway deletes nothing.
    let to_release = |e: &mut Entry| e.outbox.stage = OutboxStage::Release;
    rig.bridge.catalog.edit(&s.extent, to_release);
    rig.bridge.clock.advance_secs(1);
    let outcome = rig.run(&s, OutboxStage::Release).await;
    assert_eq!(retry_delay(&outcome), REVERIFY_SECS);
    assert!(rig.safety_held(&s));
    assert_eq!(rig.bridge.catalog.extent(&s.extent).release_evidence, None);
}

/// Two spellings of one backbone label are still one backbone.
#[tokio::test]
async fn backbone_labels_ignore_case_and_spaces() {
    let mut rig = two_backbone_rig().await;
    rig.bridge.cfg.providers[0].backbone = "Shared".into();
    rig.bridge.cfg.providers[1].backbone = " shared ".into();
    let (s, _) = rig.posted(20).await;
    rig.propagate(&s, 0, 1).await;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].backbone, "shared");
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Done);
    assert!(rig.safety_held(&s));
}

/// A result left behind by a backbone that is no longer configured does
/// not count towards a release.
#[tokio::test]
async fn removed_backbone_does_not_count() {
    let mut rig = two_backbone_rig().await;
    let (s, _) = rig.posted(19).await;
    rig.propagate(&s, 0, 1).await;
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);

    // The second backbone is dropped from the configuration.
    rig.bridge.cfg.providers.truncate(1);
    let to_verify = |e: &mut Entry| e.outbox.stage = OutboxStage::Verify;
    rig.bridge.catalog.edit(&s.extent, to_verify);
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Done);
    assert!(rig.safety_held(&s));
}

/// A job died between the release decision and its last step: the next job
/// finishes the release without reading anything.
#[tokio::test]
async fn interrupted_release_is_finished() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.verified_on_two(13).await;
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.job.extent.safety_state = SafetyState::Releasing;
    });
    let connects = rig.bridge.nntp.connects();

    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.bridge.nntp.connects(), connects);
    assert!(rig.bridge.safety.contains(&s.extent.safety_key()));
    assert_eq!(
        rig.bridge.catalog.extent(&s.extent).safety_state,
        SafetyState::Released
    );
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Done);
}

/// Outside development, one backbone is never enough to release.
#[tokio::test]
async fn single_backbone_never_releases_outside_dev() {
    let mut rig = simple_rig().await;
    rig.bridge.cfg.environment = Environment::Prod;
    let (s, _) = rig.posted(14).await;
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);

    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Done);
    assert!(rig.safety_held(&s));
}

/// A deleted generation belongs to garbage collection.
#[tokio::test]
async fn deleted_generation_cancels_the_release() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.verified_on_two(15).await;
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.job.generation_state = GenerationState::Deleted;
    });

    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Cancelled);
    assert!(rig.safety_held(&s));
}

/// A job whose lease was taken over reads nothing and records nothing.
#[tokio::test]
async fn stale_lease_records_nothing() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.verified_on_two(16).await;
    let rows = rig.rows(&s).len();
    let job = rig.job(&s).await;

    let stale = rig.claim(&s, OutboxStage::Release).await;
    rig.bridge.clock.advance_secs(LEASE_SECS + 1);
    let _current = rig.claim(&s, OutboxStage::Release).await;

    assert_eq!(
        rig.bridge.release_stage(&stale, &job).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.rows(&s).len(), rows);
    assert!(rig.safety_held(&s));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// No free slot: the job is deferred, no attempt is spent, nothing is read.
#[tokio::test]
async fn verify_without_a_slot_is_deferred() {
    let rig = simple_rig().await;
    let (s, _) = rig.posted(17).await;
    let provider = rig.bridge.cfg.providers[0].clone();
    let now = rig.bridge.clock.now();
    let class = PermitClass::Background;
    let held = rig
        .bridge
        .catalog
        .acquire_permit(&provider, class, "t", now);
    let held = held.await.unwrap().expect("free slot");
    let attempts = rig.outbox(&s).attempts;
    let connects = rig.bridge.nntp.connects();

    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert!((15..=60).contains(&delay), "delay {delay}");
    assert_eq!(rig.outbox(&s).attempts, attempts);
    assert_eq!(rig.bridge.nntp.connects(), connects);
    assert!(rig.rows(&s).is_empty());

    rig.bridge.catalog.release_permit(&held).await.unwrap();
    rig.bridge.clock.advance_secs(60);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
}
