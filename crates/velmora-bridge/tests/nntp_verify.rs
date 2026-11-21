//! Verify and release stages against the in-process NNTP server.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::config::Environment;
use velmora_bridge::ingress::ByteBudget;
use velmora_bridge::verify::{MISSING_BACKOFF_SECS, REVERIFY_SECS};
use velmora_bridge::*;

const PLAIN_LEN: usize = 1_500_000;
/// A propagation grace longer than all the waits for a missing article
/// together: nothing is ever posted again.
const LONG_GRACE_SECS: u32 = 86_400;
/// `Lease::cursor` of the second backbone after a repost.
const SECOND_REPOSTED: u32 = 15;

/// The generic retry delay of a failed job: `60 s * 2^(attempts-1)`.
fn backoff(attempts: u32) -> u32 {
    60 << (attempts - 1)
}

/// The rows as they were before any repost was stamped on them.
fn without_repost_stamps(mut plan: Vec<ArticleRow>) -> Vec<ArticleRow> {
    plan.iter_mut().for_each(|a| a.reposted_at = None);
    plan
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

    /// The wake-ups sent: the stage, the queue delay and the time each
    /// one waits for.
    fn sent_wakes(&self) -> Vec<(OutboxStage, u32, UnixMs)> {
        let sent = self.bridge.jobs.take();
        sent.iter()
            .map(|j| match &j.job {
                Job::Wake { stage, at, .. } => (*stage, j.delay_secs, *at),
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
    let mut rig = simple_rig().await;
    rig.bridge.cfg.propagation_grace_secs = LONG_GRACE_SECS;
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

/// The same for a `STAT`: a connection that breaks before the answer says
/// nothing about the article. No pass is recorded for that backbone and
/// nothing is released on it.
#[tokio::test]
async fn stat_transport_failure_records_nothing() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.posted(31).await;
    rig.propagate(&s, 0, 1).await;

    rig.servers[1].drop_next_stats(3).await;
    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(delay, backoff(rig.outbox(&s).attempts));
    assert_eq!(checks(&rig, &s), [ok("bb0", VerifyKind::Body)]);
    let outbox = rig.outbox(&s);
    assert_eq!(outbox.stage, OutboxStage::Verify);
    assert_eq!(outbox.last_error, Some(FailClass::NntpError));
    // The failed job says where it got to: the next one starts at the
    // second backbone.
    assert_eq!(outbox.cursor, 8);
    assert!(rig.safety_held(&s));

    // One more break is replaced inside the job, and the answer counts.
    // The first backbone is not read again.
    rig.servers[1].drop_next_stats(1).await;
    rig.bridge.clock.advance_secs(delay);
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(reads(&rig).0, 0);
    assert_eq!(
        checks(&rig, &s),
        [ok("bb0", VerifyKind::Body), ok("bb1", VerifyKind::Stat)]
    );
}

/// One job reads every backbone under one claim: no job in between, no
/// attempt spent, and the resume point is never written on the way.
#[tokio::test]
async fn verify_reads_every_backbone_in_one_job() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.posted(6).await;
    rig.propagate(&s, 0, 1).await;
    let attempts = rig.outbox(&s).attempts;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[0].backbone.as_str(), rows[0].provider_id.as_str()),
        ("bb0", "p0")
    );
    assert_eq!(
        (rows[1].backbone.as_str(), rows[1].provider_id.as_str()),
        ("bb1", "p1")
    );
    let outbox = rig.outbox(&s);
    assert_eq!(outbox.stage, OutboxStage::Release);
    assert_eq!(outbox.cursor, 0);
    // One claim for the whole round.
    assert_eq!(outbox.attempts, attempts + 1);
    assert_eq!(rig.sent_stages(), [(OutboxStage::Release, 0)]);
}

/// A row left at the second backbone, by a job that stopped there or by
/// a Worker that read one backbone per job: the next job starts at the
/// second backbone and does not read the first one again.
#[tokio::test]
async fn verify_resumes_at_the_backbone_the_row_names() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.posted(6).await;
    rig.propagate(&s, 0, 1).await;
    // As the one-backbone job left it: the first backbone's pass on
    // record and the row at the second.
    let lease = rig.claim(&s, OutboxStage::Verify).await;
    let now = rig.bridge.clock.now();
    let pass = VerificationRow {
        extent_id: s.extent.clone(),
        backbone: "bb0".into(),
        provider_id: "p0".into(),
        verified_at: now,
        plan_rev: 1,
        articles_ok: 3,
        articles_total: 3,
        result: VerifyResult::Ok,
        kind: VerifyKind::Body,
    };
    let catalog = &rig.bridge.catalog;
    assert!(catalog.record_verification(&lease, &pass).await.unwrap());
    assert!(catalog.defer_at(&lease, 8, now, now).await.unwrap());
    assert_eq!(rig.outbox(&s).cursor, 8);
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(
        checks(&rig, &s),
        [ok("bb0", VerifyKind::Body), ok("bb1", VerifyKind::Stat)]
    );
    // The first backbone is not read again.
    assert_eq!(reads(&rig), (0, 3));
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Release, 0));
}

/// The second backbone never gets the articles: no release, and the safety
/// copy stays.
#[tokio::test]
async fn unverified_second_backbone_blocks_release() {
    let mut rig = two_backbone_rig().await;
    rig.bridge.cfg.propagation_grace_secs = LONG_GRACE_SECS;
    let (s, _) = rig.posted(7).await;

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
    // Too far out for one queue delay: a wake-up carries the wait on.
    assert_eq!(
        rig.sent_wakes(),
        [(
            OutboxStage::Release,
            MAX_QUEUE_DELAY_SECS,
            T0.plus_secs(week)
        )]
    );

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

/// The minimum age counts from the post, not from the upload: an extent
/// stored twice the minimum age before it was posted is not released
/// until the articles themselves are that old.
#[tokio::test]
async fn the_minimum_age_counts_from_the_post_not_from_the_upload() {
    let mut rig = simple_rig().await;
    let day = 24 * 3600;
    rig.bridge.cfg.safety_min_age_secs = day;
    let s = rig.seed(40, &marked_plaintext(PLAIN_LEN)).await;
    assert_eq!(rig.bridge.catalog.extent(&s.extent).created_at, T0);
    // A posting backlog: the extent waits two days for its post.
    rig.bridge.clock.advance_secs(2 * day);
    let plan = rig.post(&s).await;
    let posted = plan.iter().filter_map(|a| a.posted_at).max().unwrap();
    assert!(posted >= T0.plus_secs(2 * day));
    let ready = posted.plus_secs(day);

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let outbox = rig.outbox(&s);
    assert_eq!(outbox.stage, OutboxStage::Release);
    assert_eq!(outbox.next_at, ready);
    assert_eq!(
        rig.sent_wakes(),
        [(OutboxStage::Release, MAX_QUEUE_DELAY_SECS, ready)]
    );

    // A release job that runs early defers itself and reads nothing, up
    // to the last millisecond.
    for early in [rig.bridge.clock.now(), UnixMs(ready.0 - 1)] {
        rig.bridge.clock.set(early);
        rig.bridge
            .catalog
            .edit(&s.extent, |e| e.outbox.next_at = early);
        let connects = rig.bridge.nntp.connects();
        assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
        assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
        assert_eq!(rig.outbox(&s).next_at, ready);
        assert_eq!(rig.bridge.nntp.connects(), connects);
        assert!(rig.safety_held(&s));
    }

    rig.bridge.clock.set(ready);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(
        rig.bridge.catalog.extent(&s.extent).safety_state,
        SafetyState::Released
    );
}

/// An extent posted before it was stored (a clock that stepped back)
/// still waits the minimum age from when it was stored: nothing is
/// released earlier than it was before the post time counted.
#[tokio::test]
async fn the_minimum_age_never_ends_before_it_would_from_the_upload() {
    let mut rig = simple_rig().await;
    let day = 24 * 3600;
    rig.bridge.cfg.safety_min_age_secs = day;
    let (s, _) = rig.posted(41).await;
    let later = rig.bridge.clock.now().plus_secs(3600);
    rig.bridge
        .catalog
        .edit(&s.extent, |e| e.job.extent.created_at = later);

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).next_at, later.plus_secs(day));
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
    // Two rows from verify, two fresh ones from this job. The evidence
    // names the fresh ones, then the full check on record from verify.
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 4);
    let evidence: serde_json::Value =
        serde_json::from_str(extent.release_evidence.as_deref().unwrap()).unwrap();
    let evidence = evidence.as_array().unwrap();
    assert_eq!(evidence.len(), 3);
    let expected = [
        ("bb0", "stat", now),
        ("bb1", "stat", now),
        ("bb0", "body", rows[0].verified_at),
    ];
    assert!(rows[0].verified_at < now);
    for (entry, (backbone, kind, at)) in evidence.iter().zip(expected) {
        assert_eq!(entry["backbone"], backbone);
        assert_eq!(entry["kind"], kind);
        assert_eq!(entry["verified_at"], at.0);
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

/// An earlier pass is not enough: the release asks every backbone again.
/// An article that has gone missing since (`STAT` answers 430) keeps the
/// safety copy and sends the extent back to verify, which records the
/// loss after its waits.
#[tokio::test]
async fn release_needs_fresh_evidence() {
    let mut rig = two_backbone_rig().await;
    rig.bridge.cfg.propagation_grace_secs = LONG_GRACE_SECS;
    let (s, plan) = rig.verified_on_two(11).await;
    rig.servers[1].hide(&plan[0].message_id).await;
    let now = rig.bridge.clock.now();

    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.safety_held(&s));
    assert_eq!(rig.bridge.catalog.extent(&s.extent).release_evidence, None);
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Verify, 0));
    // Verify starts after its usual wait, not at once.
    let wait = rig.bridge.cfg.verify_delay_secs;
    assert!(wait > 0);
    assert_eq!(outbox.next_at, now.plus_secs(wait));
    assert_eq!(rig.sent_stages(), [(OutboxStage::Verify, wait)]);
    rig.bridge.clock.advance_secs(wait);

    // Verify walks its waits and then records the second backbone's loss.
    rig.bridge.clock.advance_secs(1);
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
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.bridge.safety.contains(&s.extent.safety_key()));
    assert_eq!(
        rig.bridge.catalog.extent(&s.extent).safety_state,
        SafetyState::Released
    );
}

/// A failure recorded after the full check cancels it: the release finds
/// no full check on record, asks no provider anything, and sends the
/// extent back to verify, which reads it in full again.
#[tokio::test]
async fn newer_failure_cancels_pass() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.verified_on_two(12).await;
    let failed_at = rig.bridge.clock.now();
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.verifications.push(VerificationRow {
            extent_id: s.extent.clone(),
            backbone: "bb0".into(),
            provider_id: "p0".into(),
            verified_at: failed_at,
            plan_rev: 1,
            articles_ok: 2,
            articles_total: 3,
            result: VerifyResult::Corrupt,
            kind: VerifyKind::Body,
        });
    });
    let last = rig.bridge.catalog.body_checks(&s.extent).await.unwrap();
    assert!(last.iter().all(|b| !b.counts), "{last:?}");
    rig.bridge.clock.advance_secs(1);
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);

    let now = rig.bridge.clock.now();
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.safety_held(&s));
    assert_eq!(rig.bridge.catalog.extent(&s.extent).release_evidence, None);
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Verify, 0));
    assert_eq!(outbox.next_at, now);
    assert_eq!(rig.sent_stages(), [(OutboxStage::Verify, 0)]);
    assert!(rig.bridge.nntp.calls().is_empty());
    assert_eq!(rig.rows(&s).len(), 3);

    // Verify reads the first backbone in full again; then the release
    // goes through.
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(checks(&rig, &s)[3], ok("bb0", VerifyKind::Body));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(
        rig.bridge.catalog.extent(&s.extent).safety_state,
        SafetyState::Released
    );
}

/// A provider list with fewer backbones that count than a release needs:
/// the release job releases nothing and reads nothing, and the safety
/// copy stays held. The rows that would have passed stay as they are,
/// and the row waits in its stage without an attempt spent, so the
/// release goes through once the list is put right.
#[tokio::test]
async fn too_few_counting_backbones_release_nothing() {
    let mut rig = two_backbone_rig().await;
    let (s, _) = rig.verified_on_two(34).await;
    rig.bridge.cfg.providers[1].release = false;
    assert!(rig.bridge.cfg.release_paused().is_some());
    let before = checks(&rig, &s);
    let connects = rig.bridge.nntp.connects();
    let attempts = rig.outbox(&s).attempts;

    for _ in 0..3 {
        let now = rig.bridge.clock.now();
        assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
        assert!(rig.safety_held(&s));
        assert_eq!(rig.bridge.catalog.extent(&s.extent).release_evidence, None);
        let outbox = rig.outbox(&s);
        assert_eq!(
            (outbox.stage, outbox.attempts, outbox.next_at),
            (OutboxStage::Release, attempts, now.plus_secs(REVERIFY_SECS))
        );
        assert_eq!(checks(&rig, &s), before);
        assert_eq!(rig.bridge.nntp.connects(), connects);
        rig.bridge.clock.advance_secs(REVERIFY_SECS);
    }

    // The list is put right: the same row is released on its next run.
    rig.bridge.cfg.providers[1].release = true;
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(!rig.safety_held(&s));
    assert!(rig
        .bridge
        .catalog
        .extent(&s.extent)
        .release_evidence
        .is_some());
}

/// No backbone counts at all: the upload is not checked, nothing fails
/// over and over, and the safety copy stays held.
#[tokio::test]
async fn no_counting_backbone_holds_the_copy_without_retries() {
    let mut rig = two_backbone_rig().await;
    let (s, _) = rig.posted(35).await;
    rig.propagate(&s, 0, 1).await;
    for p in &mut rig.bridge.cfg.providers {
        p.release = false;
    }
    let connects = rig.bridge.nntp.connects();

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Done);
    assert_eq!(rig.bridge.nntp.connects(), connects);
    assert!(rig.rows(&s).is_empty());
    assert!(rig.safety_held(&s));
}

/// The backbones, results and kinds of an extent's verification rows.
fn checks(rig: &Rig, s: &Seeded) -> Vec<(String, VerifyKind, VerifyResult)> {
    let rows = rig.rows(s);
    rows.iter()
        .map(|r| (r.backbone.clone(), r.kind, r.result))
        .collect()
}

fn ok(backbone: &str, kind: VerifyKind) -> (String, VerifyKind, VerifyResult) {
    (backbone.to_string(), kind, VerifyResult::Ok)
}

/// Three backbones, all reading; `p0` posts.
async fn three_backbone_rig() -> Rig {
    let spec = |backbone, post| Spec {
        backbone,
        post,
        max_conns: 2,
    };
    let specs = [spec("bb0", true), spec("bb1", false), spec("bb2", false)];
    let mut rig = rig(&specs).await;
    rig.bridge.cfg.required_backbones = 2;
    rig
}

/// The upload check: every article read in full on the first backbone
/// that counts, and only its presence asked on the next. A `BODY` on the
/// second backbone would fail here; nothing is read from it.
#[tokio::test]
async fn verify_reads_one_backbone_in_full_and_stats_the_next() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.posted(30).await;
    rig.propagate(&s, 0, 1).await;
    rig.servers[1].set_body_gone(true).await;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(
        checks(&rig, &s),
        [ok("bb0", VerifyKind::Body), ok("bb1", VerifyKind::Stat)]
    );
    let rows = rig.rows(&s);
    assert_eq!((rows[1].articles_ok, rows[1].articles_total), (3, 3));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);

    // At release both are asked for presence only; the full check is
    // the one on record.
    rig.bridge.jobs.take();
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(
        checks(&rig, &s)[2..],
        [ok("bb0", VerifyKind::Stat), ok("bb1", VerifyKind::Stat)]
    );
    let extent = rig.bridge.catalog.extent(&s.extent);
    assert_eq!(extent.safety_state, SafetyState::Released);
    let evidence: serde_json::Value =
        serde_json::from_str(extent.release_evidence.as_deref().unwrap()).unwrap();
    let kinds: Vec<_> = evidence
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["backbone"].as_str().unwrap(), e["kind"].as_str().unwrap()))
        .collect();
    assert_eq!(kinds, [("bb0", "stat"), ("bb1", "stat"), ("bb0", "body")]);
}

/// The calls a job made to the providers since the log was started, by
/// kind: `(BODY, STAT)`.
fn reads(rig: &Rig) -> (usize, usize) {
    let calls = rig.bridge.nntp.calls();
    let of = |what| calls.iter().filter(|c| c.0 == what).count();
    (of("body"), of("stat"))
}

/// The full `BODY` read happens once, at verify, on one backbone. The
/// release job reads no `BODY` at all: it asks every backbone that counts
/// for every article with `STAT`.
#[tokio::test]
async fn release_reads_no_body_and_stats_every_backbone() {
    let rig = two_backbone_rig().await;
    let (s, plan) = rig.posted(40).await;
    rig.propagate(&s, 0, 1).await;
    let n = plan.len();
    assert_eq!(n, 3);

    rig.bridge.nntp.slow(&rig.bridge.clock, 1);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    // Verify: every article read in full once, and asked for once.
    assert_eq!(reads(&rig), (n, n));

    rig.bridge.clock.advance_secs(1);
    rig.bridge.nntp.slow(&rig.bridge.clock, 1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    // Release: no `BODY`, one `STAT` per article and backbone.
    assert_eq!(reads(&rig), (0, 2 * n));
    assert_eq!(
        rig.bridge.catalog.extent(&s.extent).safety_state,
        SafetyState::Released
    );
}

/// No release on `STAT` alone for a plan that was never read in full: a
/// plan that changed after verify has no full check on record. The
/// release job asks no provider anything and sends the extent back to
/// verify, which reads the new plan in full; only then is it released.
#[tokio::test]
async fn a_changed_plan_is_read_in_full_before_any_release() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.verified_on_two(41).await;
    assert_eq!(rig.rows(&s)[0].plan_rev, 1);
    // The same articles under a new plan revision.
    rig.bridge
        .catalog
        .edit(&s.extent, |e| e.job.extent.plan_rev = 2);
    let on_record = rig.bridge.catalog.body_checks(&s.extent).await.unwrap();
    assert!(on_record.is_empty(), "{on_record:?}");

    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    let now = rig.bridge.clock.now();
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.safety_held(&s));
    assert_eq!(rig.bridge.catalog.extent(&s.extent).release_evidence, None);
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Verify, 0));
    assert_eq!(outbox.next_at, now);
    assert_eq!(rig.sent_stages(), [(OutboxStage::Verify, 0)]);
    assert!(rig.bridge.nntp.calls().is_empty());
    assert_eq!(rig.rows(&s).len(), 2);

    // Verify reads the new plan in full, and the release follows.
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let rows = rig.rows(&s);
    assert_eq!((rows[2].plan_rev, rows[2].kind), (2, VerifyKind::Body));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert_eq!(reads(&rig), (3, 3));
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(reads(&rig), (3, 9));
    let extent = rig.bridge.catalog.extent(&s.extent);
    assert_eq!(extent.safety_state, SafetyState::Released);
    let evidence = extent.release_evidence.unwrap();
    assert!(!evidence.contains("\"plan_rev\":1"), "{evidence}");
}

/// The full check counts only on a backbone that still answers for every
/// article. With three backbones, the one read in full at verify lacks an
/// article at release: the `STAT` passes of the other two release
/// nothing, and verify reads again.
#[tokio::test]
async fn stat_passes_do_not_release_without_the_backbone_read_in_full() {
    let mut rig = three_backbone_rig().await;
    rig.bridge.cfg.propagation_grace_secs = LONG_GRACE_SECS;
    let (s, plan) = rig.posted(42).await;
    rig.propagate(&s, 0, 1).await;
    rig.propagate(&s, 0, 2).await;
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.rows(&s).len(), 3);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    rig.bridge.jobs.take();
    rig.bridge.clock.advance_secs(1);
    rig.servers[0].hide(&plan[1].message_id).await;

    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    // The 430 is asked once more, as in every check.
    assert_eq!(reads(&rig), (0, 10));
    assert!(rig.safety_held(&s));
    assert_eq!(rig.bridge.catalog.extent(&s.extent).release_evidence, None);
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Verify, 0));
    let wait = rig.bridge.cfg.verify_delay_secs;
    assert_eq!(rig.sent_stages(), [(OutboxStage::Verify, wait)]);
    // Nothing recorded: verify owns the waits and the record.
    assert_eq!(rig.rows(&s).len(), 3);
}

/// A backbone whose full read failed at verify holds no copy at release,
/// whatever it answers to `STAT`. With three backbones: the first was
/// read and found corrupt, the second was read in full, the third lost
/// an article since. The first and the second both answer `STAT`: that is
/// one copy, and nothing is released.
#[tokio::test]
async fn a_stat_answer_does_not_count_where_the_full_read_failed() {
    let mut rig = three_backbone_rig().await;
    rig.bridge.cfg.propagation_grace_secs = LONG_GRACE_SECS;
    let (s, plan) = rig.posted(44).await;
    rig.propagate(&s, 0, 1).await;
    rig.propagate(&s, 0, 2).await;
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.rows(&s).len(), 3);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    rig.bridge.jobs.take();
    // As verify leaves it when the first backbone served wrong bytes and
    // the second was read in full.
    let (first, second) = {
        let rows = rig.rows(&s);
        (rows[0].backbone.clone(), rows[1].backbone.clone())
    };
    rig.bridge.catalog.edit(&s.extent, |e| {
        for v in &mut e.verifications {
            if v.backbone == first {
                assert_eq!(v.kind, VerifyKind::Body);
                v.result = VerifyResult::Corrupt;
                v.articles_ok -= 1;
            } else if v.backbone == second {
                v.kind = VerifyKind::Body;
            }
        }
    });
    rig.bridge.clock.advance_secs(1);
    rig.servers[2].hide(&plan[1].message_id).await;

    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(reads(&rig), (0, 10));
    assert!(rig.safety_held(&s));
    assert_eq!(rig.bridge.catalog.extent(&s.extent).release_evidence, None);
    let wait = rig.bridge.cfg.verify_delay_secs;
    assert!(wait > 0);
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Verify, 0));
    assert_eq!(outbox.next_at, rig.bridge.clock.now().plus_secs(wait));
    assert_eq!(rig.sent_stages(), [(OutboxStage::Verify, wait)]);
    assert_eq!(rig.rows(&s).len(), 3);

    // Every backbone answers, and still the first holds no copy: the
    // second and the third are the two.
    rig.servers[2].unhide(&plan[1].message_id).await;
    rig.bridge.clock.advance_secs(wait);
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.outbox.stage = OutboxStage::Release;
    });
    rig.bridge.jobs.take();
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(!rig.safety_held(&s));
    let evidence = rig.bridge.catalog.extent(&s.extent).release_evidence;
    let evidence: serde_json::Value = serde_json::from_str(&evidence.unwrap()).unwrap();
    let backbones: Vec<&str> = evidence
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["backbone"].as_str().unwrap())
        .collect();
    assert!(!backbones.contains(&first.as_str()), "{backbones:?}");
    assert_eq!(backbones.len(), 3, "{backbones:?}");
}

/// A backbone whose full read failed recovers: verify reads it with
/// `BODY` again, also after an earlier backbone has passed the full
/// check, and the release then takes it. With `STAT` there the release
/// would refuse it every time and the extent would go round for ever.
#[tokio::test]
async fn verify_reads_in_full_again_where_the_full_read_failed() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.verified_on_two(45).await;
    // As a round leaves it in which neither backbone had the articles
    // yet, before the round that passed.
    let stat = rig.rows(&s)[1].clone();
    assert_eq!(
        (stat.backbone.as_str(), stat.kind),
        ("bb1", VerifyKind::Stat)
    );
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.verifications.push(VerificationRow {
            verified_at: UnixMs(stat.verified_at.0 - 1),
            articles_ok: 0,
            result: VerifyResult::Missing,
            kind: VerifyKind::Body,
            ..stat.clone()
        });
    });

    // The release does not take the `STAT` answer of that backbone.
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.safety_held(&s));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    rig.bridge
        .clock
        .advance_secs(rig.bridge.cfg.verify_delay_secs);

    // Verify: both in full this time.
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(reads(&rig), (6, 0));
    let all = checks(&rig, &s);
    assert_eq!(all[all.len() - 1], ok("bb1", VerifyKind::Body));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(
        rig.bridge.catalog.extent(&s.extent).safety_state,
        SafetyState::Released
    );
    // And from then on `STAT` is enough there again.
    assert_eq!(reads(&rig), (6, 6));
}

/// An article missing at release (`STAT` answers 430) takes the usual
/// repair path: back to verify, which posts it to the backbone that
/// lacks it once the propagation grace is over.
#[tokio::test]
async fn an_article_missing_at_release_is_reposted_by_verify() {
    let mut rig = two_posting_backbones().await;
    rig.bridge.cfg.propagation_grace_secs = 0;
    let (s, plan) = rig.verified_on_two(43).await;
    rig.servers[1].hide(&plan[2].message_id).await;
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    let posts = || {
        let calls = rig.bridge.nntp.calls();
        calls.iter().filter(|c| c.0 == "post").count()
    };

    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    // The 430 is asked once more, as in every check.
    assert_eq!(reads(&rig), (0, 7));
    assert!(rig.safety_held(&s));
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Verify, 0));
    let wait = rig.bridge.cfg.verify_delay_secs;
    assert_eq!(rig.sent_stages(), [(OutboxStage::Verify, wait)]);
    assert_eq!(posts(), 0);

    // Verify: the first backbone in full, then the second, where the one
    // missing article is posted again.
    rig.bridge.clock.advance_secs(wait);
    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(delay, rig.bridge.cfg.verify_delay_secs);
    assert_eq!(reads(&rig).0, 3);
    assert_eq!(posts(), 1);
    assert_eq!(rig.outbox(&s).cursor, SECOND_REPOSTED);
    assert!(rig.safety_held(&s));
}

/// A server that answers `STAT` for articles whose `BODY` is gone: the
/// full check is a `BODY`, so the first backbone never passes on `STAT`,
/// and the full check falls to the backbone after it.
#[tokio::test]
async fn stat_true_body_missing_is_missing_at_verify() {
    let mut rig = two_backbone_rig().await;
    rig.bridge.cfg.propagation_grace_secs = LONG_GRACE_SECS;
    let (s, _) = rig.posted(31).await;
    rig.propagate(&s, 0, 1).await;
    rig.servers[0].set_body_gone(true).await;

    for wait in MISSING_BACKOFF_SECS {
        assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), wait);
        assert!(rig.rows(&s).is_empty());
        rig.bridge.clock.advance_secs(wait);
    }
    // The waits are used up: the loss is recorded and the walk moves on.
    // No backbone has passed the full check yet: the second is read in
    // full, and one backbone is still not two.
    assert_eq!(
        retry_delay(&rig.run(&s, OutboxStage::Verify).await),
        REVERIFY_SECS
    );
    let missing = ("bb0".to_string(), VerifyKind::Body, VerifyResult::Missing);
    assert_eq!(rig.rows(&s)[0].articles_ok, 0);
    assert_eq!(checks(&rig, &s), [missing, ok("bb1", VerifyKind::Body)]);
    // The round is over: the next one starts at the first backbone.
    assert_eq!(rig.outbox(&s).cursor, 0);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    assert!(rig.safety_held(&s));
}

/// What the release no longer sees, by the operator's decision: a
/// backbone that stopped serving the bodies after verify read them, and
/// still answers `STAT`. The full check is the one on record, so the
/// release goes through. Before, the release read every `BODY` again and
/// this kept the safety copy.
#[tokio::test]
async fn a_body_gone_after_verify_is_not_seen_by_the_release() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.verified_on_two(32).await;
    rig.servers[0].set_body_gone(true).await;

    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(
        rig.bridge.catalog.extent(&s.extent).safety_state,
        SafetyState::Released
    );
    // The safety copy stays in the store, evictable, and serves reads.
    assert!(rig.bridge.safety.contains(&s.extent.safety_key()));
}

/// `STAT` passes alone release nothing, however many backbones give
/// them. With no `BODY` pass on record (the rows of verify turned into
/// `STAT` passes), the catalogue refuses fresh `STAT` passes on both
/// backbones, and a release job asks no provider and goes back to verify.
#[tokio::test]
async fn stat_passes_alone_never_release() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.verified_on_two(33).await;
    rig.bridge.catalog.edit(&s.extent, |e| {
        for row in &mut e.verifications {
            row.kind = VerifyKind::Stat;
        }
    });
    let lease = rig.claim(&s, OutboxStage::Release).await;
    let now = rig.bridge.clock.now();
    for backbone in ["bb0", "bb1"] {
        let row = VerificationRow {
            extent_id: s.extent.clone(),
            backbone: backbone.into(),
            provider_id: "p".into(),
            verified_at: now,
            plan_rev: 1,
            articles_ok: 3,
            articles_total: 3,
            result: VerifyResult::Ok,
            kind: VerifyKind::Stat,
        };
        assert!(rig
            .bridge
            .catalog
            .record_verification(&lease, &row)
            .await
            .unwrap());
    }
    let counting = ["bb0".to_string(), "bb1".to_string()];
    let guard = rig
        .bridge
        .catalog
        .begin_release(&lease, 2, &counting, "[]", now)
        .await
        .unwrap();
    assert_eq!(guard, Guard::Lost);
    assert!(rig.safety_held(&s));

    // The release job itself: nothing asked, back to verify.
    rig.bridge
        .catalog
        .edit(&s.extent, |e| e.outbox.lease_until = None);
    rig.bridge.clock.advance_secs(1);
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.bridge.nntp.calls().is_empty());
    assert!(rig.safety_held(&s));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    assert_eq!(rig.bridge.catalog.extent(&s.extent).release_evidence, None);
}

/// The full check on record with fresh `STAT` passes: the catalogue's
/// guard lets the release through, and not before both backbones have
/// answered under this claim.
#[tokio::test]
async fn the_guard_takes_fresh_stat_passes_with_the_full_check_on_record() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.verified_on_two(39).await;
    let lease = rig.claim(&s, OutboxStage::Release).await;
    let now = rig.bridge.clock.now();
    let counting = ["bb0".to_string(), "bb1".to_string()];
    let begin = || async {
        let catalog = &rig.bridge.catalog;
        let guard = catalog.begin_release(&lease, 2, &counting, "[]", now);
        guard.await.unwrap()
    };
    assert_eq!(begin().await, Guard::Lost, "nothing asked under the claim");
    for (backbone, expected) in [("bb1", Guard::Lost), ("bb0", Guard::Applied(()))] {
        let row = VerificationRow {
            extent_id: s.extent.clone(),
            backbone: backbone.into(),
            provider_id: "p".into(),
            verified_at: now,
            plan_rev: 1,
            articles_ok: 3,
            articles_total: 3,
            result: VerifyResult::Ok,
            kind: VerifyKind::Stat,
        };
        let catalog = &rig.bridge.catalog;
        assert!(catalog.record_verification(&lease, &row).await.unwrap());
        assert_eq!(begin().await, expected, "after {backbone}");
    }
}

/// A verify round that ends with passes on every backbone and none of
/// them the full check does not hand over to release, and does not park
/// the extent either: it reads again from the start.
#[tokio::test]
async fn verify_with_only_stat_passes_reads_again() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.posted(37).await;
    rig.propagate(&s, 0, 1).await;
    let now = rig.bridge.clock.now();
    rig.bridge.catalog.edit(&s.extent, |e| {
        for backbone in ["bb0", "bb1"] {
            e.verifications.push(VerificationRow {
                extent_id: s.extent.clone(),
                backbone: backbone.into(),
                provider_id: "p".into(),
                verified_at: now,
                plan_rev: 1,
                articles_ok: 3,
                articles_total: 3,
                result: VerifyResult::Ok,
                kind: VerifyKind::Stat,
            });
        }
        // Past the last backbone: the round is over.
        e.outbox.cursor = 16;
    });

    let outcome = rig.run(&s, OutboxStage::Verify).await;
    assert_eq!(retry_delay(&outcome), REVERIFY_SECS);
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Verify, 0));
    assert_eq!(outbox.last_error, Some(FailClass::Internal));
    assert!(rig.sent_stages().is_empty());
    assert!(rig.safety_held(&s));

    // The next round starts with the full check and releases.
    rig.bridge.clock.advance_secs(REVERIFY_SECS);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(checks(&rig, &s)[2], ok("bb0", VerifyKind::Body));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
}

/// Only a full check on an earlier backbone lets a later one be asked for
/// presence alone: after a `STAT` pass, the next backbone is read in full.
#[tokio::test]
async fn a_stat_pass_before_it_does_not_spare_a_backbone_the_full_check() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.posted(38).await;
    rig.propagate(&s, 0, 1).await;
    let now = rig.bridge.clock.now();
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.verifications.push(VerificationRow {
            extent_id: s.extent.clone(),
            backbone: "bb0".into(),
            provider_id: "p0".into(),
            verified_at: now,
            plan_rev: 1,
            articles_ok: 3,
            articles_total: 3,
            result: VerifyResult::Ok,
            kind: VerifyKind::Stat,
        });
        // The second backbone is next.
        e.outbox.cursor = 8;
    });

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(
        checks(&rig, &s),
        [ok("bb0", VerifyKind::Stat), ok("bb1", VerifyKind::Body)]
    );
}

/// The release rule on its own.
#[test]
fn release_rule() {
    use VerifyKind::{Body, Stat};
    let counting = ["a".to_string(), "b".to_string(), "c".to_string()];
    let rule = |passes: &[(&str, VerifyKind)], required| {
        verify::releasable(passes.iter().copied(), &counting, required)
    };
    // The full check on one backbone, presence on another.
    assert!(rule(&[("a", Body), ("b", Stat)], 2));
    assert!(rule(&[("b", Stat), ("c", Body)], 2));
    assert!(rule(&[("a", Body), ("b", Body)], 2));
    assert!(rule(&[("a", Body)], 1));
    // `STAT` alone is never the full check, on any number of backbones.
    assert!(!rule(&[("a", Stat), ("b", Stat), ("c", Stat)], 2));
    assert!(!rule(&[("a", Stat)], 1));
    // Both checks on one backbone are one copy.
    assert!(!rule(&[("a", Body), ("a", Stat)], 2));
    assert!(!rule(&[("a", Body), ("A ", Stat), (" a", Body)], 2));
    // A backbone that does not count gives neither the full check...
    assert!(!rule(&[("x", Body), ("a", Stat), ("b", Stat)], 2));
    assert!(!rule(&[("x", Body)], 1));
    // ...nor a second copy.
    assert!(!rule(&[("a", Body), ("x", Stat)], 2));
    assert!(!rule(&[("a", Body), ("x", Body)], 2));
    // Too few, nothing, and a requirement of nothing.
    assert!(!rule(&[("a", Body), ("b", Stat)], 3));
    assert!(!rule(&[], 1));
    assert!(!rule(&[("a", Body), ("b", Stat)], 0));
    // Labels are compared the way backbones are grouped.
    assert!(rule(&[(" A", Body), ("B ", Stat)], 2));
    assert!(!verify::releasable([("a", Body), ("b", Stat)], &[], 2));
}

/// A backbone marked `release: false` is neither checked nor counted:
/// the two that count carry the release, in their own order.
#[tokio::test]
async fn a_backbone_that_does_not_count_is_not_checked() {
    let mut rig = three_backbone_rig().await;
    rig.bridge.cfg.providers[0].release = false;
    let (s, _) = rig.posted(34).await;
    rig.propagate(&s, 0, 1).await;
    rig.propagate(&s, 0, 2).await;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let both = [ok("bb1", VerifyKind::Body), ok("bb2", VerifyKind::Stat)];
    assert_eq!(checks(&rig, &s), both);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);

    rig.bridge.jobs.take();
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(
        checks(&rig, &s)[2..],
        [ok("bb1", VerifyKind::Stat), ok("bb2", VerifyKind::Stat)]
    );
    let extent = rig.bridge.catalog.extent(&s.extent);
    assert_eq!(extent.safety_state, SafetyState::Released);
    assert!(!extent.release_evidence.unwrap().contains("bb0"));
}

/// The backbone that holds the articles does not count, and the one that
/// counts is alone: no release from verify, and none from a release job
/// that runs anyway. Which of the two is marked makes no difference.
#[tokio::test]
async fn one_counting_backbone_is_not_two() {
    for marked in [0, 1] {
        let mut rig = two_backbone_rig().await;
        rig.bridge.cfg.providers[marked].release = false;
        let (s, _) = rig.posted(35).await;
        rig.propagate(&s, 0, 1).await;
        let counted = format!("bb{}", 1 - marked);

        assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
        assert_eq!(checks(&rig, &s), [ok(&counted, VerifyKind::Body)]);
        assert_eq!(rig.outbox(&s).stage, OutboxStage::Done);
        assert!(rig.sent_stages().is_empty());
        assert!(rig.safety_held(&s));

        let to_release = |e: &mut Entry| e.outbox.stage = OutboxStage::Release;
        rig.bridge.catalog.edit(&s.extent, to_release);
        rig.bridge.clock.advance_secs(1);
        assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
        assert_eq!(
            rig.outbox(&s).stage,
            OutboxStage::Release,
            "marked = {marked}"
        );
        assert_eq!(checks(&rig, &s), [ok(&counted, VerifyKind::Body)]);
        assert!(rig.safety_held(&s));
        assert_eq!(rig.bridge.catalog.extent(&s.extent).release_evidence, None);
    }
}

/// With three backbones that count, only the first is read in full, and
/// only at verify: the release asks all three for presence.
#[tokio::test]
async fn every_backbone_after_the_full_check_is_stat() {
    let rig = three_backbone_rig().await;
    let (s, _) = rig.posted(36).await;
    rig.propagate(&s, 0, 1).await;
    rig.propagate(&s, 0, 2).await;
    for _ in 0..3 {
        if rig.outbox(&s).stage == OutboxStage::Verify {
            assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
        }
    }
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    let seen = checks(&rig, &s);
    assert_eq!(seen[0], ok("bb0", VerifyKind::Body));
    assert!(seen[1..].iter().all(|c| c.1 == VerifyKind::Stat));

    rig.bridge.jobs.take();
    rig.bridge.clock.advance_secs(1);
    let before = seen.len();
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(
        checks(&rig, &s)[before..],
        [
            ok("bb0", VerifyKind::Stat),
            ok("bb1", VerifyKind::Stat),
            ok("bb2", VerifyKind::Stat)
        ]
    );
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

    // Even a release job that runs anyway deletes nothing: the release
    // is paused, and the job ends without reading.
    let to_release = |e: &mut Entry| e.outbox.stage = OutboxStage::Release;
    rig.bridge.catalog.edit(&s.extent, to_release);
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert_eq!(rig.rows(&s).len(), 1);
    assert!(rig.safety_held(&s));
    assert_eq!(rig.bridge.catalog.extent(&s.extent).release_evidence, None);
}

/// The first account of a backbone refuses the login for the account
/// itself: the verify reads the backbone through its other account in
/// the same job, and the first takes a strike. With every account of
/// the backbone refusing, the job waits without spending an attempt.
#[tokio::test]
async fn verify_reads_a_backbone_through_its_next_account_when_one_is_refused() {
    let mut rig = shared_backbone_rig().await;
    rig.bridge.cfg.providers[0].priority = 0;
    rig.bridge.cfg.providers[1].priority = 1;
    let (s, _) = rig.posted(19).await;
    rig.propagate(&s, 0, 1).await;
    let mut held = Vec::new();
    for i in [0, 1] {
        let addr = rig.servers[i].addr();
        let cfg = nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
        held.push([dial(&cfg).await.unwrap(), dial(&cfg).await.unwrap()]);
    }
    let refuse = Some("502 Account suspended");
    rig.servers[0].set_limit_reply(refuse).await;
    rig.servers[1].set_limit_reply(refuse).await;

    // Both refuse: nothing was read, nothing is spent.
    let attempts = rig.outbox(&s).attempts;
    let outcome = rig.run(&s, OutboxStage::Verify).await;
    assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
    let outbox = rig.outbox(&s);
    assert_eq!(
        (outbox.attempts, outbox.stage),
        (attempts, OutboxStage::Verify)
    );
    assert!(rig.rows(&s).is_empty());

    // The second account is free again: it answers for the backbone.
    for client in held.pop().unwrap() {
        client.quit().await;
    }
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.outbox.next_at = UnixMs(0);
        e.outbox.lease_until = None;
    });
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].provider_id.as_str(), rows[0].result),
        ("p1", VerifyResult::Ok)
    );
    let now = rig.bridge.clock.now();
    let load = rig.bridge.catalog.provider_load(now).await.unwrap();
    let p0 = load.iter().find(|l| l.provider_id == "p0").unwrap();
    assert_eq!(
        (p0.failures, p0.fault),
        (2, Some(ProviderFault::LoginRefused))
    );
    for client in held.pop().unwrap() {
        client.quit().await;
    }
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

/// A verify job renews neither its lease nor its slot for calls that all
/// start within 20 s of the claim and of the slot being taken: each of
/// those wrote the expiry a renewal would write, each renewal is two
/// catalogue writes, and a slot taken less than 20 s ago outlasts any
/// one call with time to spare.
#[tokio::test]
async fn verify_renews_nothing_for_a_quick_pass() {
    let rig = simple_rig().await;
    let (s, plan) = rig.posted(40).await;
    assert!(plan.len() > 1);
    let clock = rig.bridge.clock.clone();
    rig.bridge.nntp.slow(&clock, 1_000);
    rig.bridge.catalog.permit_renewed_at.borrow_mut().clear();
    rig.bridge.catalog.lease_renewed_at.borrow_mut().clear();
    let start = clock.now();

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);

    let calls = rig.bridge.nntp.calls();
    assert_eq!(calls.len(), 1 + plan.len());
    assert!(calls.iter().all(|(_, at)| at.0 - start.0 < 20_000));
    assert_eq!(*rig.bridge.catalog.permit_renewed_at.borrow(), []);
    assert_eq!(*rig.bridge.catalog.lease_renewed_at.borrow(), []);
    assert_eq!(rig.rows(&s)[0].result, VerifyResult::Ok);
}

/// A slow pass renews before the first call that would start 20 s or
/// more after the claim, and again 20 s after each renewal: no call
/// starts on an older one, and the lease is renewed whenever the slot
/// is.
#[tokio::test]
async fn verify_renews_when_the_claim_or_the_last_renewal_is_old() {
    let rig = simple_rig().await;
    let (s, plan) = rig.posted(41).await;
    assert_eq!(plan.len(), 3);
    let clock = rig.bridge.clock.clone();
    let call_ms = 8_000;
    rig.bridge.nntp.slow(&clock, call_ms);
    rig.bridge.catalog.permit_renewed_at.borrow_mut().clear();
    rig.bridge.catalog.lease_renewed_at.borrow_mut().clear();
    let start = clock.now();

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);

    // Claimed at 0: connect at 0, BODY at 8 s and 16 s, renewal, BODY
    // at 24 s.
    let renewed = rig.bridge.catalog.permit_renewed_at.borrow().clone();
    assert_eq!(renewed, [start.plus_ms(3 * call_ms)]);
    assert_eq!(*rig.bridge.catalog.lease_renewed_at.borrow(), renewed);
    let calls = rig.bridge.nntp.calls();
    assert_eq!(calls.len(), 1 + plan.len());
    // The claim and the slot hold from `start` as a renewal at it would.
    let held: Vec<UnixMs> = [start].into_iter().chain(renewed).collect();
    for (what, at) in &calls {
        let age = held.iter().filter(|r| r.0 <= at.0).map(|r| at.0 - r.0);
        let age = age.min().expect("held before the call");
        assert!(age < 20_000, "{what} on a renewal {age} ms old");
    }
}

/// A claim that is 20 s old when the job gets to its first call stands
/// for nothing: the job renews before the call, and a row taken over in
/// between stops it there, before any socket is opened.
#[tokio::test]
async fn verify_renews_first_on_a_claim_that_is_old() {
    let rig = simple_rig().await;
    let (s, plan) = rig.posted(44).await;
    let clock = rig.bridge.clock.clone();
    rig.bridge.nntp.slow(&clock, 1_000);
    rig.bridge.catalog.permit_renewed_at.borrow_mut().clear();
    rig.bridge.catalog.lease_renewed_at.borrow_mut().clear();

    let job = rig.job(&s).await;
    let lease = rig.claim(&s, OutboxStage::Verify).await;
    clock.advance_secs(20);
    let start = clock.now();
    assert_eq!(rig.bridge.verify_stage(&lease, &job).await, JobOutcome::Ack);
    assert_eq!(rig.bridge.nntp.calls().len(), 1 + plan.len());
    assert_eq!(*rig.bridge.catalog.lease_renewed_at.borrow(), [start]);
    assert_eq!(*rig.bridge.catalog.permit_renewed_at.borrow(), [start]);

    // The same with the row taken over while the claim aged.
    let (s, _) = rig.posted(45).await;
    rig.bridge.nntp.slow(&clock, 1_000);
    rig.bridge.catalog.lease_renewed_at.borrow_mut().clear();
    let job = rig.job(&s).await;
    let lease = rig.claim(&s, OutboxStage::Verify).await;
    clock.advance_secs(20);
    rig.bridge.catalog.take_over(&s.extent);
    let at = clock.now();
    rig.bridge.verify_stage(&lease, &job).await;
    assert!(rig.bridge.nntp.calls().is_empty());
    assert_eq!(*rig.bridge.catalog.lease_renewed_at.borrow(), [at]);
    assert!(rig.rows(&s).is_empty());
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

impl Rig {
    /// Runs the verify stage on a fresh claim and calls `then` once the
    /// job has made `after` calls to the provider. A stage that ends
    /// before that fails the test instead of leaving it waiting.
    async fn verify_interrupted(
        &self,
        s: &Seeded,
        after: usize,
        then: impl FnOnce(),
    ) -> JobOutcome {
        let job = self.job(s).await;
        let lease = self.claim(s, OutboxStage::Verify).await;
        let done = std::cell::Cell::new(false);
        let stage = async {
            let outcome = self.bridge.verify_stage(&lease, &job).await;
            done.set(true);
            outcome
        };
        let interrupt = async {
            while self.bridge.nntp.calls().len() < after {
                assert!(!done.get(), "the stage ended before call {after}");
                tokio::task::yield_now().await;
            }
            then();
        };
        tokio::join!(stage, interrupt).0
    }

    /// Runs the verify stage and takes the row over once the job has
    /// made `after` calls to the provider.
    async fn verify_taken_over(&self, s: &Seeded, after: usize) -> JobOutcome {
        self.verify_interrupted(s, after, || self.bridge.catalog.take_over(&s.extent))
            .await
    }
}

/// The row is taken over while the job reads on a renewal it does not
/// repeat yet. The renewal that comes due finds the lease gone: the job
/// stops there, reads no further and records nothing.
#[tokio::test]
async fn verify_stops_at_the_renewal_that_finds_its_lease_gone() {
    let rig = simple_rig().await;
    let (s, plan) = rig.posted(42).await;
    assert_eq!(plan.len(), 3);
    let clock = rig.bridge.clock.clone();
    rig.bridge.nntp.slow(&clock, 8_000);
    rig.bridge.catalog.lease_renewed_at.borrow_mut().clear();
    let start = clock.now();

    // Taken over once the first BODY is out: connect, BODY.
    rig.verify_taken_over(&s, 2).await;

    // Claimed at 0: connect at 0, BODY at 8 s and 16 s; the renewal due
    // at 24 s stops it.
    let calls: Vec<&str> = rig.bridge.nntp.calls().iter().map(|c| c.0).collect();
    assert_eq!(calls, ["connect", "body", "body"]);
    assert_eq!(
        *rig.bridge.catalog.lease_renewed_at.borrow(),
        [start.plus_ms(24_000)]
    );
    assert!(rig.rows(&s).is_empty());
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A pass that ends before another renewal is due may read every article
/// on a lease that was taken over meanwhile. What it read is not
/// recorded: every write carries the lease and is refused.
#[tokio::test]
async fn a_pass_read_on_a_lease_lost_meanwhile_records_nothing() {
    let rig = simple_rig().await;
    let (s, plan) = rig.posted(43).await;
    let clock = rig.bridge.clock.clone();
    rig.bridge.nntp.slow(&clock, 1_000);
    rig.bridge.catalog.lease_renewed_at.borrow_mut().clear();

    rig.verify_taken_over(&s, 2).await;

    assert_eq!(rig.bridge.nntp.calls().len(), 1 + plan.len());
    assert_eq!(rig.bridge.catalog.lease_renewed_at.borrow().len(), 0);
    assert!(rig.rows(&s).is_empty());
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A slot lost while the job reads is found at the renewal that comes
/// due: the job stops there and is deferred, and nothing is recorded.
#[tokio::test]
async fn verify_stops_at_the_renewal_that_finds_its_slot_gone() {
    let rig = simple_rig().await;
    let (s, plan) = rig.posted(44).await;
    assert_eq!(plan.len(), 3);
    let clock = rig.bridge.clock.clone();
    rig.bridge.nntp.slow(&clock, 8_000);
    let lose_slot = || rig.bridge.catalog.drop_permits();

    let outcome = rig.verify_interrupted(&s, 2, lose_slot).await;

    assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
    let calls: Vec<&str> = rig.bridge.nntp.calls().iter().map(|c| c.0).collect();
    assert_eq!(calls, ["connect", "body", "body"]);
    assert!(rig.rows(&s).is_empty());
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

/// A later backbone has no free slot: the job is put off without an
/// attempt spent, and the same write says where it got to. The job that
/// comes back asks the second backbone only.
#[tokio::test]
async fn a_put_off_job_resumes_at_the_backbone_it_reached() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.posted(46).await;
    rig.propagate(&s, 0, 1).await;
    let now = rig.bridge.clock.now();
    let class = PermitClass::Background;
    let mut held = Vec::new();
    let second = &rig.bridge.cfg.providers[1];
    while let Some(permit) = rig
        .bridge
        .catalog
        .acquire_permit(second, class, "t", now)
        .await
        .unwrap()
    {
        held.push(permit);
    }
    assert!(!held.is_empty());
    let attempts = rig.outbox(&s).attempts;

    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert!((15..=60).contains(&delay), "delay {delay}");
    assert_eq!(checks(&rig, &s), [ok("bb0", VerifyKind::Body)]);
    let outbox = rig.outbox(&s);
    assert_eq!(
        (outbox.stage, outbox.cursor, outbox.attempts),
        (OutboxStage::Verify, 8, attempts)
    );
    assert_eq!(outbox.next_at, now.plus_secs(delay));

    for permit in held {
        rig.bridge.catalog.release_permit(&permit).await.unwrap();
    }
    rig.bridge.clock.advance_secs(60);
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(reads(&rig), (0, 3));
    assert_eq!(
        checks(&rig, &s),
        [ok("bb0", VerifyKind::Body), ok("bb1", VerifyKind::Stat)]
    );
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Release, 0));
}

/// A backbone has no free slot, and the host has a timer: the job waits
/// for one under its claim. The slots here are those of a holder that
/// is gone: they free when their permits expire, half a permit lifetime
/// after the claim, and the job goes on in the same run. Nothing is put
/// off, and the queue delivers the job once.
#[tokio::test]
async fn a_job_waits_under_its_claim_for_a_slot_that_comes_free() {
    let mut rig = two_backbone_rig().await;
    rig.with_timer();
    let (s, _) = rig.posted(48).await;
    rig.propagate(&s, 0, 1).await;
    let now = rig.bridge.clock.now();
    let half = i64::from(PERMIT_SECS) * 500;
    rig.take_slots(1, now.plus_ms(-half)).await;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);

    let waited = rig.bridge.clock.now().0 - now.0;
    assert!((half..jobs::SLOT_WAIT_MS).contains(&waited), "{waited}");
    assert_eq!(
        checks(&rig, &s),
        [ok("bb0", VerifyKind::Body), ok("bb1", VerifyKind::Stat)]
    );
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Release, 0));
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// The slots stay taken (their holder is at work and renews them): the
/// job waits one permit lifetime from its claim and no longer, then is
/// put off as a job without a timer is at once. The row's attempts are
/// what they were before the claim, and the row says where the job got
/// to.
#[tokio::test]
async fn a_job_that_waited_in_vain_is_put_off_without_an_attempt() {
    let mut rig = two_backbone_rig().await;
    rig.with_timer();
    let (s, _) = rig.posted(49).await;
    rig.propagate(&s, 0, 1).await;
    let now = rig.bridge.clock.now();
    // Held past the end of the wait, as after a renewal.
    let held = rig.take_slots(1, now.plus_secs(30)).await;
    let attempts = rig.outbox(&s).attempts;

    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);

    assert!((15..=60).contains(&delay), "delay {delay}");
    let ended = rig.bridge.clock.now();
    let poll = i64::from(jobs::SLOT_POLL_MS);
    let waited = ended.0 - now.0;
    assert!(
        (jobs::SLOT_WAIT_MS..jobs::SLOT_WAIT_MS + poll).contains(&waited),
        "{waited}"
    );
    assert_eq!(checks(&rig, &s), [ok("bb0", VerifyKind::Body)]);
    let outbox = rig.outbox(&s);
    assert_eq!(
        (outbox.stage, outbox.cursor, outbox.attempts),
        (OutboxStage::Verify, 8, attempts)
    );
    assert_eq!(outbox.next_at, ended.plus_secs(delay));
    assert_eq!(rig.bridge.nntp.live(), 0);

    // The job that comes back finds the slot and asks that backbone only.
    for permit in held {
        rig.bridge.catalog.release_permit(&permit).await.unwrap();
    }
    rig.bridge.clock.advance_secs(60);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(
        checks(&rig, &s),
        [ok("bb0", VerifyKind::Body), ok("bb1", VerifyKind::Stat)]
    );
}

/// A lease lost while a later backbone is read: the first backbone's
/// result, written under the lease, stays; nothing more is written, and
/// the new holder's row is as its claim found it.
#[tokio::test]
async fn a_lease_lost_on_a_later_backbone_writes_nothing_more() {
    let rig = two_backbone_rig().await;
    let (s, plan) = rig.posted(47).await;
    rig.propagate(&s, 0, 1).await;
    rig.bridge.nntp.slow(&rig.bridge.clock, 1_000);

    // Taken over once the second backbone is being asked: connect and
    // one BODY per article, connect, STAT.
    let after = 1 + plan.len() + 2;
    assert_eq!(rig.verify_taken_over(&s, after).await, JobOutcome::Ack);

    assert_eq!(checks(&rig, &s), [ok("bb0", VerifyKind::Body)]);
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Verify, 0));
    assert!(rig.sent_stages().is_empty());
    assert!(rig.safety_held(&s));
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// Two backbones that both post and read. `p1` is a backup, so the post
/// stage puts every article on `p0` only; `bb1` gets them by propagation.
async fn two_posting_backbones() -> Rig {
    let both = |backbone| Spec {
        backbone,
        post: true,
        max_conns: 3,
    };
    let mut rig = rig(&[both("bb0"), both("bb1")]).await;
    rig.bridge.cfg.providers[1].priority = 1;
    rig.bridge.cfg.required_backbones = 2;
    rig
}

impl Rig {
    /// Posts, verifies the first backbone, and walks the waits for the
    /// second one up to the end of the propagation grace. Nothing is
    /// posted again on the way.
    async fn waited_out_the_grace(&self, n: u8) -> (Seeded, Vec<ArticleRow>) {
        let (s, plan) = self.posted(n).await;
        let posted_at = plan.iter().filter_map(|a| a.posted_at).max().unwrap();
        let grace_ends = posted_at.plus_secs(self.bridge.cfg.propagation_grace_secs);
        // The first job reads the first backbone and goes on to the second
        // one; every later job starts at the second.
        for wait in MISSING_BACKOFF_SECS {
            let left = (grace_ends.0 - self.bridge.clock.now().0) / 1000;
            if left <= 0 {
                break;
            }
            // The last wait ends with the grace, not after it.
            let wait = wait.min(u32::try_from(left).unwrap());
            assert_eq!(retry_delay(&self.run(&s, OutboxStage::Verify).await), wait);
            self.bridge.clock.advance_secs(wait);
        }
        assert_eq!(self.bridge.clock.now(), grace_ends);
        assert_eq!(self.servers[1].posted_count().await, 0);
        assert_eq!(self.rows(&s).len(), 1);
        (s, plan)
    }

    /// Copies one article from the first server to the second.
    async fn propagate_one(&self, row: &ArticleRow) {
        let mut src = self.raw_client(0).await;
        let mut dst = self.raw_client(1).await;
        let mut article = Vec::new();
        src.article_to(&row.message_id, &mut article).await.unwrap();
        dst.post_article(&row.message_id, &article).await.unwrap();
        src.quit().await;
        dst.quit().await;
    }
}

/// The second backbone still lacks articles when the propagation grace is
/// over: exactly those are posted straight to its provider, under the
/// stored message-ids, and the next read passes.
#[tokio::test]
async fn missing_after_the_grace_is_posted_to_the_backbone_that_lacks_it() {
    let rig = two_posting_backbones().await;
    let (s, plan) = rig.waited_out_the_grace(30).await;
    // One article did arrive on its own.
    rig.propagate_one(&plan[0]).await;

    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(delay, rig.bridge.cfg.verify_delay_secs);
    let outbox = rig.outbox(&s);
    assert_eq!(
        (outbox.stage, outbox.cursor),
        (OutboxStage::Verify, SECOND_REPOSTED)
    );
    // Not recorded as missing, and the other two articles are there now.
    assert_eq!(rig.rows(&s).len(), 1);
    let ids = rig.servers[1].posted_ids().await;
    assert_eq!(ids.len(), 3);
    for row in &plan {
        assert!(ids.contains(&format!("<{}>", row.message_id)));
    }
    // The first provider stays the recorded one.
    assert_eq!(without_repost_stamps(rig.plan(&s).await), plan);
    assert_eq!(rig.servers[0].posted_count().await, 3);
    assert_eq!(rig.bridge.nntp.live(), 0);

    rig.bridge.clock.advance_secs(delay);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let rows = rig.rows(&s);
    assert_eq!(
        (rows[1].backbone.as_str(), rows[1].result),
        ("bb1", VerifyResult::Ok)
    );
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(
        rig.bridge.catalog.extent(&s.extent).safety_state,
        SafetyState::Released
    );
}

/// A repost starts the minimum age again: the safety copy outlasts a soak
/// of the reposted articles, however old the first post is. Without it a
/// release could follow the repost within minutes, on a `STAT` of the
/// backbone that only just got the articles.
#[tokio::test]
async fn a_repost_moves_the_release_later() {
    let mut rig = two_posting_backbones().await;
    let day = 24 * 3600;
    rig.bridge.cfg.safety_min_age_secs = day;
    let (s, plan) = rig.waited_out_the_grace(36).await;
    let posted = plan.iter().filter_map(|a| a.posted_at).max().unwrap();
    assert!(plan.iter().all(|a| a.reposted_at.is_none()));
    rig.propagate_one(&plan[0]).await;

    let reposted = rig.bridge.clock.now();
    // Hours after the first post, which is when the extent was stored.
    assert_eq!(
        reposted,
        posted.plus_secs(rig.bridge.cfg.propagation_grace_secs)
    );
    assert!(reposted > T0.plus_secs(3600));
    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(rig.outbox(&s).cursor, SECOND_REPOSTED);
    // Only the articles that were posted again are stamped, and nothing
    // else of the rows changes.
    let now = rig.plan(&s).await;
    let stamps: Vec<_> = now.iter().map(|a| a.reposted_at).collect();
    assert_eq!(stamps, [None, Some(reposted), Some(reposted)]);
    assert_eq!(without_repost_stamps(now), plan);

    rig.bridge.clock.advance_secs(delay);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let ready = reposted.plus_secs(day);
    let outbox = rig.outbox(&s);
    assert_eq!(outbox.stage, OutboxStage::Release);
    assert_eq!(outbox.next_at, ready);

    // Not released before then, even by a release job that runs early.
    rig.bridge.clock.set(UnixMs(ready.0 - 1));
    rig.bridge
        .catalog
        .edit(&s.extent, |e| e.outbox.next_at = T0);
    let connects = rig.bridge.nntp.connects();
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).next_at, ready);
    assert_eq!(rig.bridge.nntp.connects(), connects);
    assert!(rig.safety_held(&s));

    rig.bridge.clock.set(ready);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(
        rig.bridge.catalog.extent(&s.extent).safety_state,
        SafetyState::Released
    );
}

/// The stamp of a repost is the time the provider took the article, not
/// only the time the job set out to send it: the minimum age starts
/// when the last POST of the repost has been answered.
#[tokio::test]
async fn a_repost_is_stamped_when_the_provider_has_taken_it() {
    let mut rig = two_posting_backbones().await;
    let day = 24 * 3600;
    rig.bridge.cfg.safety_min_age_secs = day;
    let (s, _) = rig.waited_out_the_grace(38).await;
    // Every call to a provider takes two seconds from here on.
    rig.bridge.nntp.slow(&rig.bridge.clock, 2000);

    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(rig.outbox(&s).cursor, SECOND_REPOSTED);
    let calls = rig.bridge.nntp.calls();
    let posts = calls.iter().filter(|c| c.0 == "post").map(|c| c.1);
    let answered = posts.max().expect("a POST").plus_ms(2000);
    let plan = rig.plan(&s).await;
    for row in &plan {
        assert!(row.reposted_at >= Some(answered), "{:?}", row.reposted_at);
    }
    let newest = plan.iter().filter_map(|a| a.reposted_at).max().unwrap();

    rig.bridge.clock.advance_secs(delay);
    while rig.outbox(&s).stage == OutboxStage::Verify {
        assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    }
    let outbox = rig.outbox(&s);
    assert_eq!(outbox.stage, OutboxStage::Release);
    assert_eq!(outbox.next_at, newest.plus_secs(day));
}

/// The repost is stamped before anything is sent: when the stamp cannot
/// be written, nothing is posted, so no repost exists that the minimum
/// age does not know of.
#[tokio::test]
async fn nothing_is_reposted_without_its_stamp() {
    let rig = two_posting_backbones().await;
    let (s, plan) = rig.waited_out_the_grace(37).await;
    rig.bridge.catalog.fail_mark_reposted.set(1);

    assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.servers[1].posted_count().await, 0);
    assert_eq!(rig.plan(&s).await, plan);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    assert_ne!(rig.outbox(&s).cursor, SECOND_REPOSTED);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A repost that is larger than the whole budget runs alone, next to the
/// charge its own verify job already holds: it is not put off for ever.
#[tokio::test]
async fn a_repost_larger_than_the_budget_still_runs() {
    let mut rig = two_posting_backbones().await;
    rig.bridge.budget = ByteBudget::new(4 * 1024 * 1024);
    let (s, plan) = rig.waited_out_the_grace(31).await;
    // What the dispatcher charges for a verify job.
    let stage = rig.bridge.budget.try_charge(2 * 1024 * 1024).unwrap();

    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(delay, rig.bridge.cfg.verify_delay_secs);
    assert_eq!(rig.outbox(&s).cursor, SECOND_REPOSTED);
    assert_eq!(rig.servers[1].posted_count().await, plan.len());
    drop(stage);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

/// A verify run reads from a provider and reposts on it: one invocation,
/// so one address. On an account that allows one address the repost goes
/// through, and every slot of the run carries the same name.
#[tokio::test]
async fn verify_and_its_repost_are_one_address() {
    let mut rig = two_posting_backbones().await;
    for p in &mut rig.bridge.cfg.providers {
        p.max_ips = Some(1);
    }
    let (s, plan) = rig.waited_out_the_grace(36).await;
    rig.bridge.catalog.granted.borrow_mut().clear();
    rig.bridge.catalog.holder_peak.borrow_mut().clear();

    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);

    assert_eq!(delay, rig.bridge.cfg.verify_delay_secs);
    assert_eq!(rig.outbox(&s).cursor, SECOND_REPOSTED);
    assert_eq!(rig.servers[1].posted_count().await, plan.len());
    let granted = rig.bridge.catalog.granted.borrow();
    // The check that found the articles missing, and the repost.
    let on_second = granted.iter().filter(|(p, _)| p == "p1").count();
    assert!(on_second >= 2, "{granted:?}");
    let names: std::collections::BTreeSet<&str> =
        granted.iter().map(|(_, holder)| holder.as_str()).collect();
    assert_eq!(names.len(), 1, "{granted:?}");
    assert!(names.iter().all(|name| name.starts_with("job:")));
}

/// The repost is accepted, and the backbone still answers 430 for the
/// articles on the read that follows. They are not posted a second time
/// in the round: the backbone is recorded as `missing`.
#[tokio::test]
async fn an_accepted_repost_that_stays_missing_is_not_posted_again() {
    let rig = two_posting_backbones().await;
    let (s, plan) = rig.waited_out_the_grace(34).await;

    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(rig.outbox(&s).cursor, SECOND_REPOSTED);
    assert_eq!(rig.servers[1].posted_count().await, plan.len());
    assert_eq!(rig.rows(&s).len(), 1);

    // The provider took the articles and does not serve them.
    let ids = plan.iter().map(|a| a.message_id.clone());
    rig.servers[1].set_hidden(ids).await;
    rig.bridge.clock.advance_secs(delay);
    // From here on every call to a provider is logged.
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    let last = rig.run(&s, OutboxStage::Verify).await;

    assert_eq!(retry_delay(&last), REVERIFY_SECS);
    let calls = rig.bridge.nntp.calls();
    assert!(!calls.is_empty());
    assert!(
        calls.iter().all(|c| c.0 != "post"),
        "posted a second time: {calls:?}"
    );
    assert_eq!(rig.servers[1].posted_count().await, plan.len());
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[1].backbone.as_str(), rows[1].result),
        ("bb1", VerifyResult::Missing)
    );
    assert_eq!(rig.outbox(&s).cursor, 0);
    assert!(rig.safety_held(&s));
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// The posting provider answers 240 to a POST and throws the article
/// away. Verify finds it missing on the backbone it was posted to, and
/// once the grace is over posts exactly that article there again, under
/// its stored message-id: once per round, until a read finds it.
#[tokio::test]
async fn an_article_the_posting_provider_lost_is_posted_there_again() {
    let mut rig = rig(&[Spec {
        backbone: "bb0",
        post: true,
        max_conns: 3,
    }])
    .await;
    rig.bridge.cfg.required_backbones = 1;
    let s = rig.seed(35, &marked_plaintext(PLAIN_LEN)).await;
    rig.servers[0].discard_next_posts(1).await;
    let plan = rig.post(&s).await;
    // Recorded as posted, all of them; the provider has one fewer.
    assert!(plan.iter().all(|a| a.state == ArticleState::Posted));
    assert_eq!(plan.len(), 3);
    assert_eq!(rig.servers[0].posted_count().await, 2);

    // Until the grace is over the backbone is only read.
    let posted_at = plan.iter().filter_map(|a| a.posted_at).max().unwrap();
    let grace_ends = posted_at.plus_secs(rig.bridge.cfg.propagation_grace_secs);
    while rig.bridge.clock.now() < grace_ends {
        let wait = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
        rig.bridge.clock.advance_secs(wait);
    }
    assert_eq!(rig.servers[0].posted_count().await, 2);
    assert!(rig.rows(&s).is_empty());

    // From here on every call to the provider is logged.
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    let posts = || {
        let calls = rig.bridge.nntp.calls();
        calls.iter().filter(|c| c.0 == "post").count()
    };
    // Round one: the provider throws the repost away as well.
    rig.servers[0].discard_next_posts(1).await;
    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(delay, rig.bridge.cfg.verify_delay_secs);
    assert_eq!(posts(), 1);
    rig.bridge.clock.advance_secs(delay);
    let last = rig.run(&s, OutboxStage::Verify).await;
    assert_eq!(retry_delay(&last), REVERIFY_SECS);
    assert_eq!(posts(), 1, "posted twice in one round");
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].backbone.as_str(), rows[0].result),
        ("bb0", VerifyResult::Missing)
    );
    assert_eq!(rig.outbox(&s).cursor, 0);
    assert!(rig.safety_held(&s));

    // Round two: one more repost, and this one is kept.
    rig.bridge.clock.advance_secs(REVERIFY_SECS);
    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(posts(), 2);
    assert_eq!(rig.servers[0].posted_count().await, 3);
    rig.bridge.clock.advance_secs(delay);
    rig.run(&s, OutboxStage::Verify).await;
    assert_eq!(posts(), 2);
    let rows = rig.rows(&s);
    assert_eq!(rows.last().unwrap().result, VerifyResult::Ok);
    // The same message-ids throughout, and the rows as they were.
    assert_eq!(without_repost_stamps(rig.plan(&s).await), plan);
    let ids = rig.servers[0].posted_ids().await;
    for row in &plan {
        assert!(ids.contains(&format!("<{}>", row.message_id)));
    }
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// An obligation that was cancelled after its repost and revived starts
/// over at the post stage with its cursor at zero. The articles are on
/// the backbone by then: nothing is posted again, by either stage. The
/// post stage goes straight on to verify without a provider slot, so it
/// does so even while other jobs hold every one of them.
#[tokio::test]
async fn a_revived_extent_is_not_posted_again() {
    let rig = two_posting_backbones().await;
    let (s, plan) = rig.waited_out_the_grace(36).await;
    retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(rig.outbox(&s).cursor, SECOND_REPOSTED);
    assert_eq!(rig.servers[1].posted_count().await, plan.len());

    // What reviving a cancelled row does.
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.outbox.stage = OutboxStage::Post;
        e.outbox.cursor = 0;
        e.outbox.attempts = 0;
    });
    rig.bridge.clock.advance_secs(3600);
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    // Another job holds every background slot of both posting providers.
    let now = rig.bridge.clock.now();
    let mut held = Vec::new();
    for provider in &rig.bridge.cfg.providers {
        while let Some(permit) = rig
            .bridge
            .catalog
            .acquire_permit(provider, PermitClass::Background, "other", now)
            .await
            .unwrap()
        {
            held.push(permit);
        }
    }
    assert!(held.len() >= 2);
    assert_eq!(rig.run(&s, OutboxStage::Post).await, JobOutcome::Ack);
    // The post stage needed no provider at all.
    assert!(rig.bridge.nntp.calls().is_empty());
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    for permit in held {
        rig.bridge.catalog.release_permit(&permit).await.unwrap();
    }
    rig.bridge.clock.advance_secs(3600);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert!(rig.bridge.nntp.calls().iter().all(|c| c.0 != "post"));
    assert_eq!(without_repost_stamps(rig.plan(&s).await), plan);
    assert_eq!(rig.servers[0].posted_count().await, plan.len());
    assert_eq!(rig.servers[1].posted_count().await, plan.len());
}

/// With no grace at all the first read that finds articles missing posts
/// them.
#[tokio::test]
async fn no_grace_reposts_at_once() {
    let mut rig = two_posting_backbones().await;
    rig.bridge.cfg.propagation_grace_secs = 0;
    let (s, _) = rig.posted(31).await;

    // One job: the first backbone passes, the second is posted to.
    assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), 30);
    assert_eq!(rig.rows(&s).len(), 1);
    assert_eq!(rig.servers[1].posted_count().await, 3);
    assert_eq!(rig.outbox(&s).cursor, SECOND_REPOSTED);
}

/// The repost is tried once per round. A backbone that still lacks the
/// articles on the next read is recorded as `missing`; the next round
/// tries again.
#[tokio::test]
async fn refused_repost_is_recorded_as_missing_and_tried_next_round() {
    let rig = two_posting_backbones().await;
    let (s, _) = rig.waited_out_the_grace(32).await;
    rig.servers[1].set_posting_allowed(false).await;

    let last = rig.run(&s, OutboxStage::Verify).await;
    assert_eq!(retry_delay(&last), REVERIFY_SECS);
    let rows = rig.rows(&s);
    assert_eq!(
        (rows[1].backbone.as_str(), rows[1].result),
        ("bb1", VerifyResult::Missing)
    );
    assert_eq!(rig.servers[1].posted_count().await, 0);
    assert_eq!(rig.outbox(&s).cursor, 0);
    assert!(rig.safety_held(&s));
    assert_eq!(rig.bridge.nntp.live(), 0);

    // The next round: the provider posts again.
    rig.servers[1].set_posting_allowed(true).await;
    rig.bridge.clock.advance_secs(REVERIFY_SECS);
    assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), 30);
    assert_eq!(rig.servers[1].posted_count().await, 3);
    rig.bridge.clock.advance_secs(30);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
}

/// A repost comes from the safety copy: without it nothing is posted and
/// the backbone is recorded as it is.
#[tokio::test]
async fn repost_needs_the_safety_copy() {
    let rig = two_posting_backbones().await;
    let (s, _) = rig.waited_out_the_grace(33).await;
    rig.bridge
        .safety
        .delete(&s.extent.safety_key())
        .await
        .unwrap();

    let last = rig.run(&s, OutboxStage::Verify).await;
    assert_eq!(retry_delay(&last), REVERIFY_SECS);
    assert_eq!(rig.rows(&s)[1].result, VerifyResult::Missing);
    assert_eq!(rig.servers[1].posted_count().await, 0);
}

/// A backbone whose providers only read is never posted to.
#[tokio::test]
async fn read_only_backbone_is_not_reposted() {
    let rig = two_backbone_rig().await;
    let (s, _) = rig.waited_out_the_grace(34).await;

    let last = rig.run(&s, OutboxStage::Verify).await;
    assert_eq!(retry_delay(&last), REVERIFY_SECS);
    assert_eq!(rig.rows(&s)[1].result, VerifyResult::Missing);
    assert_eq!(rig.servers[1].posted_count().await, 0);
}

/// A job whose lease was taken over posts nothing and moves nothing.
#[tokio::test]
async fn stale_lease_reposts_nothing() {
    let rig = two_posting_backbones().await;
    let (s, _) = rig.waited_out_the_grace(35).await;

    let stale = rig.claim(&s, OutboxStage::Verify).await;
    rig.bridge.clock.advance_secs(LEASE_SECS + 1);
    let holder = rig.claim(&s, OutboxStage::Verify).await;
    let job = rig.job(&s).await;
    assert_eq!(rig.bridge.verify_stage(&stale, &job).await, JobOutcome::Ack);

    assert_eq!(rig.servers[1].posted_count().await, 0);
    let outbox = rig.outbox(&s);
    assert_eq!(outbox.token, holder.token);
    assert_eq!(outbox.cursor, holder.cursor);
    assert_eq!(rig.rows(&s).len(), 1);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// No memory for the extent right now: the repost waits, without spending
/// an attempt or a retry step.
#[tokio::test]
async fn repost_waits_for_memory() {
    let rig = two_posting_backbones().await;
    let (s, _) = rig.waited_out_the_grace(36).await;
    let before = rig.outbox(&s);
    let room = rig.bridge.budget.capacity();
    let held = rig.bridge.budget.charge(room).await.unwrap();

    let outcome = rig.run(&s, OutboxStage::Verify).await;
    assert!(matches!(outcome, JobOutcome::Retry { delay_secs } if (15..=60).contains(&delay_secs)));
    assert_eq!(rig.servers[1].posted_count().await, 0);
    let outbox = rig.outbox(&s);
    assert_eq!(
        (outbox.cursor, outbox.attempts),
        (before.cursor, before.attempts)
    );
    drop(held);
}
