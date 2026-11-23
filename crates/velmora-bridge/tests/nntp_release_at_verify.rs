//! The release by the verify job (`RELEASE_AT_VERIFY`) against the
//! in-process NNTP server: a verify round that passed, once the minimum
//! age is over, releases the extent on the checks it has just made, and
//! nothing is released that a release job would not release.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::config::{Environment, VerifyConfig, VerifyMode};
use velmora_bridge::verify::{MISSING_BACKOFF_SECS, REVERIFY_SECS};
use velmora_bridge::*;

const PLAIN_LEN: usize = 1_500_000;
/// A propagation grace longer than all the waits for a missing article
/// together: nothing is ever posted again.
const LONG_GRACE_SECS: u32 = 86_400;
const DAY_SECS: u32 = 86_400;
/// `Lease::cursor` of the second backbone, and of it after a repost.
const SECOND: u32 = 8;
const SECOND_REPOSTED: u32 = 15;

fn retry_delay(outcome: &JobOutcome) -> u32 {
    match outcome {
        JobOutcome::Retry { delay_secs } => *delay_secs,
        JobOutcome::Ack => panic!("expected a retry, got an ack"),
    }
}

/// [`two_backbone_rig`] with the release by the verify job on.
async fn rig_on() -> Rig {
    let mut rig = two_backbone_rig().await;
    rig.bridge.cfg.release_at_verify = true;
    rig
}

/// Two backbones that both post and read; the post stage uses `p0` only.
async fn two_posting_backbones() -> Rig {
    let both = |backbone| Spec {
        backbone,
        post: true,
        max_conns: 3,
    };
    let mut rig = rig(&[both("bb0"), both("bb1")]).await;
    rig.bridge.cfg.providers[1].priority = 1;
    rig.bridge.cfg.required_backbones = 2;
    rig.bridge.cfg.release_at_verify = true;
    rig
}

/// Two backbones under the light check, `ppm` of the extents sampled.
async fn light_rig(ppm: u32, sizes: &[(&str, SizeCommand)]) -> Rig {
    let mut rig = rig_on().await;
    rig.bridge.cfg.propagation_grace_secs = LONG_GRACE_SECS;
    rig.bridge.cfg.verify = VerifyConfig {
        mode: VerifyMode::Light,
        sample_ppm: ppm,
        escalate_secs: 3_600,
        size_commands: sizes.iter().map(|(p, c)| (p.to_string(), *c)).collect(),
    };
    rig
}

impl Rig {
    async fn posted(&self, n: u8) -> (Seeded, Vec<ArticleRow>) {
        let s = self.seed(n, &marked_plaintext(PLAIN_LEN)).await;
        let plan = self.post(&s).await;
        assert_eq!(plan.len(), 3);
        (s, plan)
    }

    /// Posts an extent of three articles and copies it to the second
    /// backbone.
    async fn on_two(&self, n: u8) -> (Seeded, Vec<ArticleRow>) {
        let (s, plan) = self.posted(n).await;
        self.propagate(&s, 0, 1).await;
        (s, plan)
    }

    fn outbox(&self, s: &Seeded) -> OutboxRow {
        self.bridge.catalog.outbox(&s.extent)
    }

    fn rows(&self, s: &Seeded) -> Vec<VerificationRow> {
        self.bridge.catalog.verifications(&s.extent)
    }

    fn state(&self, s: &Seeded) -> SafetyState {
        self.bridge.catalog.extent(&s.extent).safety_state
    }

    /// Pinned, in the catalogue and in the store, and no evidence of a
    /// release written.
    fn held(&self, s: &Seeded) -> bool {
        let extent = self.bridge.catalog.extent(&s.extent);
        self.bridge.safety.contains(&s.extent.safety_key())
            && extent.safety_state == SafetyState::Held
            && extent.release_evidence.is_none()
            && extent.released_at.is_none()
    }

    /// Released, with the row done and the copy still in the store.
    fn released(&self, s: &Seeded) -> bool {
        self.bridge.safety.contains(&s.extent.safety_key())
            && self.state(s) == SafetyState::Released
            && self.outbox(s).stage == OutboxStage::Done
    }

    /// The rows on record: backbone, kind, result.
    fn checks(&self, s: &Seeded) -> Vec<(String, VerifyKind, VerifyResult)> {
        let rows = self.rows(s);
        rows.iter()
            .map(|r| (r.backbone.clone(), r.kind, r.result))
            .collect()
    }

    /// The release evidence: backbone, kind, time and size command.
    fn evidence(&self, s: &Seeded) -> Vec<(String, String, UnixMs, Option<String>)> {
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
                    UnixMs(e["verified_at"].as_i64().unwrap()),
                    text(&e["size_command"]),
                )
            })
            .collect()
    }

    /// The evidence without the times.
    fn evidence_kinds(&self, s: &Seeded) -> Vec<(String, String, Option<String>)> {
        let all = self.evidence(s);
        all.into_iter().map(|(b, k, _, c)| (b, k, c)).collect()
    }

    /// The calls of the last logged job by kind: `(BODY, STAT, size)`.
    fn calls(&self) -> (usize, usize, usize) {
        let calls = self.bridge.nntp.calls();
        let of = |what| calls.iter().filter(|c| c.0 == what).count();
        (of("body"), of("stat"), of("size"))
    }

    /// Runs one job with the call log started; a call takes `ms`.
    async fn logged(&self, s: &Seeded, stage: OutboxStage, ms: i64) -> JobOutcome {
        self.bridge.nntp.slow(&self.bridge.clock, ms);
        self.run(s, stage).await
    }

    /// The jobs sent since the last look: stage and delay.
    fn sent(&self) -> Vec<(OutboxStage, u32)> {
        let sent = self.bridge.jobs.take();
        sent.iter()
            .map(|j| match &j.job {
                Job::Extent { stage, .. } | Job::Wake { stage, .. } => (*stage, j.delay_secs),
                other => panic!("unexpected job {other:?}"),
            })
            .collect()
    }

    /// As a verify job that read the first backbone and was put off at
    /// the second left the row: the first backbone's full check on
    /// record, from a claim that is over.
    async fn first_backbone_verified(&self, s: &Seeded) -> VerificationRow {
        let lease = self.claim(s, OutboxStage::Verify).await;
        let now = self.bridge.clock.now();
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
        let catalog = &self.bridge.catalog;
        assert!(catalog
            .record_verification(&lease, &pass)
            .await
            .unwrap()
            .held());
        assert!(catalog.defer_at(&lease, SECOND, now, now).await.unwrap());
        assert_eq!(self.outbox(s).cursor, SECOND);
        self.bridge.clock.advance_secs(1);
        pass
    }

    /// Posts, verifies the first backbone, and walks the waits for the
    /// second one up to the end of the propagation grace.
    async fn waited_out_the_grace(&self, n: u8) -> (Seeded, Vec<ArticleRow>) {
        let (s, plan) = self.posted(n).await;
        let posted_at = plan.iter().filter_map(|a| a.posted_at).max().unwrap();
        let grace_ends = posted_at.plus_secs(self.bridge.cfg.propagation_grace_secs);
        for wait in MISSING_BACKOFF_SECS {
            let left = (grace_ends.0 - self.bridge.clock.now().0) / 1000;
            if left <= 0 {
                break;
            }
            let wait = wait.min(u32::try_from(left).unwrap());
            assert_eq!(retry_delay(&self.run(&s, OutboxStage::Verify).await), wait);
            assert!(self.held(&s));
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

fn ok(backbone: &str, kind: VerifyKind) -> (String, VerifyKind, VerifyResult) {
    (backbone.to_string(), kind, VerifyResult::Ok)
}

fn entry(backbone: &str, kind: &str, command: Option<&str>) -> (String, String, Option<String>) {
    (
        backbone.to_string(),
        kind.to_string(),
        command.map(str::to_string),
    )
}

/// With no minimum age left to wait for, the verify job that passed
/// releases the extent: one job, each backbone asked once, and the
/// evidence is the checks of that job.
#[tokio::test]
async fn verify_releases_on_the_checks_it_has_just_made() {
    let rig = rig_on().await;
    let (s, plan) = rig.on_two(1).await;
    let n = plan.len();
    let claimed = rig.bridge.clock.now();

    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 1).await,
        JobOutcome::Ack
    );

    // One full read and one presence check, and no second round.
    assert_eq!(rig.calls(), (n, n, 0));
    assert_eq!(
        rig.checks(&s),
        [ok("bb0", VerifyKind::Body), ok("bb1", VerifyKind::Stat)]
    );
    assert!(rig.released(&s));
    let extent = rig.bridge.catalog.extent(&s.extent);
    assert!(extent.released_at.unwrap() >= claimed);
    // No release job is sent for: the row is done.
    assert_eq!(rig.sent(), []);
    assert_eq!(rig.outbox(&s).lease_until, None);
    // The evidence names each check once, with the time it was made:
    // both under the claim of the job that released.
    let rows = rig.rows(&s);
    assert_eq!(
        rig.evidence(&s),
        [
            ("bb0".into(), "body".into(), rows[0].verified_at, None),
            ("bb1".into(), "stat".into(), rows[1].verified_at, None),
        ]
    );
    assert!(rows.iter().all(|r| r.verified_at >= claimed));
    assert_eq!(rig.bridge.nntp.live(), 0);
    // Still readable from the providers alone.
    let cold = rig.bridge.fetch_cold(&extent).await.unwrap();
    assert_eq!(cold, fetch::ColdFetch::Filled(s.cipher.clone()));
}

/// Off (the default) the verify job releases nothing, whatever the
/// minimum age: the release is a job of its own.
#[tokio::test]
async fn off_the_release_stays_a_job_of_its_own() {
    let mut rig = rig_on().await;
    rig.bridge.cfg.release_at_verify = false;
    let (s, _) = rig.on_two(2).await;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert!(rig.held(&s));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert_eq!(rig.sent(), [(OutboxStage::Release, 0)]);
}

/// An article the second backbone never gets: no verify job releases
/// anything, through all the waits and the rounds after them.
#[tokio::test]
async fn one_backbone_is_never_a_release() {
    let mut rig = rig_on().await;
    rig.bridge.cfg.propagation_grace_secs = LONG_GRACE_SECS;
    let (s, plan) = rig.on_two(3).await;
    rig.servers[1].hide(&plan[1].message_id).await;

    for _round in 0..2 {
        for wait in MISSING_BACKOFF_SECS {
            assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), wait);
            assert!(rig.held(&s));
            rig.bridge.clock.advance_secs(wait);
        }
        let last = rig.run(&s, OutboxStage::Verify).await;
        assert_eq!(retry_delay(&last), REVERIFY_SECS);
        assert!(rig.held(&s));
        assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
        rig.bridge.clock.advance_secs(REVERIFY_SECS);
    }
    let rows = rig.rows(&s);
    assert!(rows
        .iter()
        .any(|r| r.backbone == "bb1" && r.result == VerifyResult::Missing));
    assert!(!rows
        .iter()
        .any(|r| r.backbone == "bb1" && r.result == VerifyResult::Ok));
}

/// Before the minimum age is over the verify job releases nothing: the
/// release is a job of its own, due when the age is over, and it asks
/// every backbone again.
#[tokio::test]
async fn before_the_minimum_age_the_release_job_asks_again() {
    let mut rig = rig_on().await;
    rig.bridge.cfg.safety_min_age_secs = DAY_SECS;
    let (s, plan) = rig.on_two(4).await;
    let n = plan.len();
    let posted = plan.iter().filter_map(|a| a.posted_at).max().unwrap();
    let ready = posted.plus_secs(DAY_SECS);

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert!(rig.held(&s));
    let outbox = rig.outbox(&s);
    assert_eq!(
        (outbox.stage, outbox.next_at),
        (OutboxStage::Release, ready)
    );
    assert_eq!(rig.rows(&s).len(), 2);

    // A release job that runs early releases nothing and asks nothing.
    rig.bridge.clock.set(UnixMs(ready.0 - 1));
    rig.bridge
        .catalog
        .edit(&s.extent, |e| e.outbox.next_at = T0);
    assert_eq!(
        rig.logged(&s, OutboxStage::Release, 0).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls(), (0, 0, 0));
    assert!(rig.held(&s));

    rig.bridge.clock.set(ready);
    assert_eq!(
        rig.logged(&s, OutboxStage::Release, 0).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls(), (0, 2 * n, 0));
    assert!(rig.released(&s));
    assert_eq!(
        rig.evidence_kinds(&s),
        [
            entry("bb0", "stat", None),
            entry("bb1", "stat", None),
            entry("bb0", "body", None),
        ]
    );
}

/// A verify job that runs when the minimum age is already over (a round
/// that had to wait, a retry) releases on its own checks, whatever the
/// minimum age is set to.
#[tokio::test]
async fn a_verify_after_the_minimum_age_releases() {
    let mut rig = rig_on().await;
    rig.bridge.cfg.safety_min_age_secs = DAY_SECS;
    let (s, plan) = rig.on_two(5).await;
    let n = plan.len();
    let posted = plan.iter().filter_map(|a| a.posted_at).max().unwrap();
    rig.bridge.clock.set(posted.plus_secs(DAY_SECS));

    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 0).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls(), (n, n, 0));
    assert!(rig.released(&s));
    assert_eq!(
        rig.evidence_kinds(&s),
        [entry("bb0", "body", None), entry("bb1", "stat", None)]
    );
}

/// The minimum age ends while the verify job reads. A check counts as
/// presence for the release only if all of it was made once the age
/// was over: one whose questions began before, and whose row is
/// recorded after, holds answers from before. Both backbones are asked
/// again here.
#[tokio::test]
async fn a_check_that_began_before_the_minimum_age_was_over_is_asked_again() {
    let mut rig = rig_on().await;
    let (s, plan) = rig.on_two(6).await;
    let n = plan.len();
    assert_eq!(n, 3);
    let posted = plan.iter().filter_map(|a| a.posted_at).max().unwrap();
    // The age is over one second into the job.
    let start = rig.bridge.clock.now();
    let age_ms = start.0 + 1000 - posted.0;
    assert_eq!(age_ms % 1000, 0);
    rig.bridge.cfg.safety_min_age_secs = u32::try_from(age_ms / 1000).unwrap();
    let ready = UnixMs(start.0 + 1000);

    // Every call takes 150 ms, the connect too: the first backbone is
    // done at 600 ms, and the second has had two answers of three when
    // the age is over.
    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 150).await,
        JobOutcome::Ack
    );
    let rows = rig.rows(&s);
    assert_eq!(
        rig.checks(&s),
        [
            ok("bb0", VerifyKind::Body),
            ok("bb1", VerifyKind::Stat),
            ok("bb0", VerifyKind::Stat),
            ok("bb1", VerifyKind::Stat),
        ]
    );
    let log = rig.bridge.nntp.calls();
    let asked: Vec<UnixMs> = log.iter().filter(|c| c.0 == "stat").map(|c| c.1).collect();
    assert_eq!(rows[0].verified_at, UnixMs(start.0 + 600));
    // Two questions before the age was over, the row after it: the
    // time of the row alone would count the check.
    assert!(asked[1] < ready && asked[2] >= ready);
    assert_eq!(rows[1].verified_at, UnixMs(start.0 + 1200));
    // Both backbones were asked a second time, all of it after.
    assert_eq!(rig.calls(), (n, 3 * n, 0));
    assert!(asked[n..].iter().all(|at| *at >= ready));
    assert!(rig.released(&s));
    assert_eq!(
        rig.evidence(&s),
        [
            ("bb0".into(), "stat".into(), rows[2].verified_at, None),
            ("bb1".into(), "stat".into(), rows[3].verified_at, None),
            ("bb0".into(), "body".into(), rows[0].verified_at, None),
        ]
    );
}

/// The same at the boundary: the age is over at the instant the second
/// backbone's check begins. That check is presence. The first one,
/// recorded at that same instant but made before it, is not.
#[tokio::test]
async fn a_check_that_began_once_the_minimum_age_was_over_is_presence() {
    let mut rig = rig_on().await;
    let (s, plan) = rig.on_two(7).await;
    let n = plan.len();
    let posted = plan.iter().filter_map(|a| a.posted_at).max().unwrap();
    // Every call takes one second, the connect too: the first backbone
    // is done `n + 1` seconds into the job, and the age is over then.
    let start = rig.bridge.clock.now();
    let check_ms = 1000 * (i64::try_from(n).unwrap() + 1);
    let age_ms = start.0 + check_ms - posted.0;
    assert_eq!(age_ms % 1000, 0);
    rig.bridge.cfg.safety_min_age_secs = u32::try_from(age_ms / 1000).unwrap();
    let ready = UnixMs(start.0 + check_ms);

    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 1000).await,
        JobOutcome::Ack
    );
    let rows = rig.rows(&s);
    assert_eq!(
        rig.checks(&s),
        [
            ok("bb0", VerifyKind::Body),
            ok("bb1", VerifyKind::Stat),
            ok("bb0", VerifyKind::Stat),
        ]
    );
    assert_eq!(rows[0].verified_at, ready);
    assert_eq!(rows[1].verified_at, UnixMs(ready.0 + check_ms));
    // The first backbone was asked a second time, the second was not.
    assert_eq!(rig.calls(), (n, 2 * n, 0));
    assert!(rig.released(&s));
    assert_eq!(
        rig.evidence(&s),
        [
            ("bb0".into(), "stat".into(), rows[2].verified_at, None),
            ("bb1".into(), "stat".into(), rows[1].verified_at, None),
            ("bb0".into(), "body".into(), rows[0].verified_at, None),
        ]
    );
}

/// Review regression: a `STAT` that is asked again because the full read
/// of its backbone began before the minimum age was over, and that ends
/// in the millisecond that full read ended. The catalogue keeps the
/// `body` pass at that instant in its place, so the answer is not on
/// record. The job must not release on it, nor list it as evidence: the
/// release stage asks again from a later millisecond, and releases on
/// passes it has on record under its own claim.
#[tokio::test]
async fn a_stat_in_the_millisecond_of_the_full_read_is_asked_again_later() {
    let mut rig = rig_on().await;
    let (s, plan) = rig.on_two(8).await;
    let n = plan.len();
    let posted = plan.iter().filter_map(|a| a.posted_at).max().unwrap();
    // The full read of the first backbone (connect and three `BODY`s,
    // 300 ms each) ends 1200 ms into the job; the age is over at 1000.
    // Every call after it takes no time.
    let start = rig.bridge.clock.now();
    let age_ms = start.0 + 1000 - posted.0;
    assert_eq!(age_ms % 1000, 0);
    rig.bridge.cfg.safety_min_age_secs = u32::try_from(age_ms / 1000).unwrap();
    let ready = UnixMs(start.0 + 1000);
    let read_ends = UnixMs(start.0 + 1200);
    rig.bridge.nntp.slow_for(&rig.bridge.clock, 300, n + 1);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);

    // The `STAT` of the first backbone was asked, after the age, and
    // ended at `read_ends`: the full read stays on record there.
    let log = rig.bridge.nntp.calls();
    let asked: Vec<UnixMs> = log.iter().filter(|c| c.0 == "stat").map(|c| c.1).collect();
    assert_eq!(asked.len(), 2 * n);
    assert!(asked.iter().all(|at| *at == read_ends && *at >= ready));
    assert_eq!(
        rig.checks(&s),
        [ok("bb0", VerifyKind::Body), ok("bb1", VerifyKind::Stat)]
    );
    assert!(rig.rows(&s).iter().all(|r| r.verified_at == read_ends));
    // Nothing released, no evidence written; the release stage is due
    // a millisecond later.
    assert!(rig.held(&s));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert_eq!(rig.outbox(&s).next_at, read_ends.plus_ms(1));
    assert_eq!(rig.sent(), [(OutboxStage::Release, 1)]);

    // The release job asks both backbones under its own claim.
    rig.bridge.clock.advance_secs(1);
    let at = rig.bridge.clock.now();
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.released(&s));
    assert_eq!(
        rig.evidence(&s),
        [
            ("bb0".into(), "stat".into(), at, None),
            ("bb1".into(), "stat".into(), at, None),
            ("bb0".into(), "body".into(), read_ends, None),
        ]
    );
}

/// A verify job that resumes at the second backbone has not asked the
/// first one itself: the pass on record is from an earlier job. It asks
/// that backbone with `STAT` before it releases, as a release job would.
#[tokio::test]
async fn a_backbone_this_job_did_not_ask_is_asked_before_the_release() {
    let rig = rig_on().await;
    let (s, plan) = rig.on_two(7).await;
    let n = plan.len();
    let earlier = rig.first_backbone_verified(&s).await;
    let claimed = rig.bridge.clock.now();
    assert!(earlier.verified_at < claimed);

    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 0).await,
        JobOutcome::Ack
    );

    // The second backbone as its verify, then the first for presence.
    assert_eq!(rig.calls(), (0, 2 * n, 0));
    assert_eq!(
        rig.checks(&s),
        [
            ok("bb0", VerifyKind::Body),
            ok("bb1", VerifyKind::Stat),
            ok("bb0", VerifyKind::Stat),
        ]
    );
    assert!(rig.released(&s));
    // Presence from this claim only; the full check from the record.
    assert_eq!(
        rig.evidence(&s),
        [
            ("bb0".into(), "stat".into(), claimed, None),
            ("bb1".into(), "stat".into(), claimed, None),
            ("bb0".into(), "body".into(), earlier.verified_at, None),
        ]
    );
}

/// A verify job that gets no slot for the question it has yet to ask
/// makes its round only once: the row goes to the release stage, whose
/// job asks every backbone when there is a slot. Nothing is released
/// on the way.
#[tokio::test]
async fn without_a_slot_for_its_last_question_the_release_stage_asks() {
    let rig = rig_on().await;
    let (s, plan) = rig.on_two(8).await;
    let n = plan.len();
    rig.first_backbone_verified(&s).await;
    // Another job holds every slot of the first backbone's provider.
    let now = rig.bridge.clock.now();
    let first = &rig.bridge.cfg.providers[0];
    assert_eq!(first.backbone, "bb0");
    let catalog = &rig.bridge.catalog;
    let mut held = Vec::new();
    let class = PermitClass::Background;
    while let Some(permit) = catalog
        .acquire_permit(first, class, "other", now)
        .await
        .unwrap()
    {
        held.push(permit);
    }
    assert!(!held.is_empty());

    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 0).await,
        JobOutcome::Ack
    );
    // The second backbone as its verify, and no answer from the first.
    assert_eq!(rig.calls(), (0, n, 0));
    assert_eq!(rig.rows(&s).len(), 2);
    assert!(rig.held(&s));
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.next_at), (OutboxStage::Release, now));
    assert_eq!(rig.sent(), [(OutboxStage::Release, 0)]);

    for permit in held {
        catalog.release_permit(&permit).await.unwrap();
    }
    rig.bridge.clock.advance_secs(1);
    assert_eq!(
        rig.logged(&s, OutboxStage::Release, 0).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls(), (0, 2 * n, 0));
    assert!(rig.released(&s));
}

#[tokio::test]
async fn failed_extra_stat_hands_off_to_release_after_reconnects() {
    let rig = rig_on().await;
    let (s, _) = rig.on_two(8).await;
    rig.first_backbone_verified(&s).await;
    rig.servers[0].drop_next_stats(3).await;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.rows(&s).len(), 2, "only the verify round was recorded");
    assert!(rig.held(&s));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert_eq!(rig.sent(), [(OutboxStage::Release, 0)]);

    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.released(&s));
}

/// The catalogue has the last word: a row taken over between the last
/// check and the release is not released by the job that lost it, and
/// the copy stays held for the job that has it now.
#[tokio::test]
async fn a_release_the_catalogue_refuses_keeps_the_copy() {
    let rig = rig_on().await;
    let (s, plan) = rig.on_two(18).await;
    let n = plan.len();
    rig.bridge.catalog.take_over_at_release.set(true);

    rig.logged(&s, OutboxStage::Verify, 0).await;
    // The round was made and recorded, and the release was asked for.
    assert_eq!(rig.calls(), (n, n, 0));
    assert_eq!(rig.rows(&s).len(), 2);
    assert!(!rig.bridge.catalog.take_over_at_release.get());
    assert!(rig.held(&s));
    assert_eq!(rig.bridge.catalog.extent(&s.extent).release_evidence, None);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    assert_eq!(rig.sent(), []);
}

/// The catalogue refuses with the lease intact (the copy is not `held`
/// by the time of the write): nothing is released and no evidence is
/// written, the job fails with the row still at `verify`, and it is
/// tried again.
#[tokio::test]
async fn a_release_refused_under_an_intact_lease_is_tried_again() {
    let rig = rig_on().await;
    let (s, plan) = rig.on_two(18).await;
    let n = plan.len();
    rig.bridge.catalog.releasing_at_release.set(true);

    let outcome = rig.logged(&s, OutboxStage::Verify, 0).await;
    assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
    // The round was made and recorded, and the release was asked for.
    assert_eq!(rig.calls(), (n, n, 0));
    assert_eq!(rig.rows(&s).len(), 2);
    assert!(!rig.bridge.catalog.releasing_at_release.get());
    let extent = rig.bridge.catalog.extent(&s.extent);
    assert_eq!(extent.safety_state, SafetyState::Releasing);
    assert_eq!(extent.release_evidence, None);
    assert_eq!(extent.released_at, None);
    assert!(rig.bridge.safety.contains(&s.extent.safety_key()));
    let row = rig.outbox(&s);
    assert_eq!(row.stage, OutboxStage::Verify);
    assert_eq!(row.last_error, Some(FailClass::Internal));
    assert_eq!(row.lease_until, None);
    assert_eq!(rig.sent(), []);
}

/// The backbone an earlier job passed has lost an article since: the
/// verify job that resumes finds it missing, releases nothing, records
/// nothing for it and starts verify again, which owns the waits.
#[tokio::test]
async fn an_article_gone_since_an_earlier_job_keeps_the_copy() {
    let mut rig = rig_on().await;
    rig.bridge.cfg.propagation_grace_secs = LONG_GRACE_SECS;
    let (s, plan) = rig.on_two(8).await;
    rig.first_backbone_verified(&s).await;
    rig.servers[0].hide(&plan[2].message_id).await;
    let now = rig.bridge.clock.now();

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);

    assert!(rig.held(&s));
    assert_eq!(
        rig.checks(&s),
        [ok("bb0", VerifyKind::Body), ok("bb1", VerifyKind::Stat)]
    );
    // Verify again, from the first backbone, after its usual wait and
    // without an attempt spent.
    let wait = rig.bridge.cfg.verify_delay_secs;
    assert!(wait > 0);
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Verify, 0));
    assert_eq!(outbox.next_at, now.plus_secs(wait));
    assert_eq!(rig.sent(), [(OutboxStage::Verify, wait)]);

    // That round reads the first backbone in full and waits for it.
    rig.bridge.clock.advance_secs(wait);
    for wait in MISSING_BACKOFF_SECS {
        assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), wait);
        assert!(rig.held(&s));
        rig.bridge.clock.advance_secs(wait);
    }
    let last = rig.run(&s, OutboxStage::Verify).await;
    assert_eq!(retry_delay(&last), REVERIFY_SECS);
    assert!(rig.held(&s));
    let status = rig.bridge.catalog.backbone_status(&s.extent).await.unwrap();
    let bb0 = status.iter().find(|b| b.backbone == "bb0").unwrap();
    assert_eq!((bb0.result, bb0.counts), (VerifyResult::Missing, false));

    // The article comes back: the round passes and releases.
    rig.servers[0].unhide(&plan[2].message_id).await;
    rig.bridge.clock.advance_secs(REVERIFY_SECS);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert!(rig.released(&s));
}

/// A repost: the job that posts again stops, and the release waits for
/// the check of the reposted backbone made after it. With no minimum
/// age the job that makes that check releases, and asks the backbone it
/// did not read itself.
#[tokio::test]
async fn a_repost_is_checked_before_the_release() {
    let rig = two_posting_backbones().await;
    let (s, plan) = rig.waited_out_the_grace(9).await;
    rig.propagate_one(&plan[0]).await;
    let reposted = rig.bridge.clock.now();

    // The job that posts again releases nothing and records nothing.
    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(delay, rig.bridge.cfg.verify_delay_secs);
    assert_eq!(rig.outbox(&s).cursor, SECOND_REPOSTED);
    assert_eq!(rig.servers[1].posted_count().await, 3);
    assert!(rig.held(&s));
    assert_eq!(rig.rows(&s).len(), 1);
    let stamps: Vec<_> = rig.plan(&s).await.iter().map(|a| a.reposted_at).collect();
    assert_eq!(stamps, [None, Some(reposted), Some(reposted)]);

    rig.bridge.clock.advance_secs(delay);
    let claimed = rig.bridge.clock.now();
    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 0).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls(), (0, 2 * plan.len(), 0));
    assert!(rig.released(&s));
    // Every check the release rests on was made after the repost.
    let evidence = rig.evidence(&s);
    assert_eq!(
        evidence[..2],
        [
            ("bb0".into(), "stat".into(), claimed, None),
            ("bb1".into(), "stat".into(), claimed, None),
        ]
    );
    assert!(claimed > reposted);
}

/// A repost starts the minimum age again, for the verify job as for the
/// release job: the job that checks the reposted backbone releases
/// nothing before the age of the repost is over.
#[tokio::test]
async fn a_repost_moves_the_release_later() {
    let mut rig = two_posting_backbones().await;
    // The minimum age of the first post is over when the grace ends.
    let age = rig.bridge.cfg.propagation_grace_secs;
    assert!(age > 3600);
    rig.bridge.cfg.safety_min_age_secs = age;
    let (s, plan) = rig.waited_out_the_grace(10).await;
    rig.propagate_one(&plan[0]).await;
    let reposted = rig.bridge.clock.now();
    let posted = plan.iter().filter_map(|a| a.posted_at).max().unwrap();
    assert_eq!(reposted, posted.plus_secs(age));

    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(rig.outbox(&s).cursor, SECOND_REPOSTED);
    rig.bridge.clock.advance_secs(delay);

    // The round passes, but the age of the repost is not over.
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert!(rig.held(&s));
    let ready = reposted.plus_secs(age);
    let outbox = rig.outbox(&s);
    assert_eq!(
        (outbox.stage, outbox.next_at),
        (OutboxStage::Release, ready)
    );

    rig.bridge.clock.set(ready);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.released(&s));
}

/// Three backbones, two needed: one that lacks the extent is recorded as
/// missing by the job that then releases on the other two. It does not
/// hold the release up, and it is no part of the evidence.
#[tokio::test]
async fn a_backbone_that_lacks_the_extent_is_no_part_of_the_release() {
    let spec = |backbone, post| Spec {
        backbone,
        post,
        max_conns: 2,
    };
    let mut rig = rig(&[spec("bb0", true), spec("bb1", false), spec("bb2", false)]).await;
    rig.bridge.cfg.required_backbones = 2;
    rig.bridge.cfg.release_at_verify = true;
    rig.bridge.cfg.propagation_grace_secs = LONG_GRACE_SECS;
    let (s, _) = rig.on_two(11).await;

    // The first job passes two backbones and waits for the third.
    for wait in MISSING_BACKOFF_SECS {
        assert_eq!(retry_delay(&rig.run(&s, OutboxStage::Verify).await), wait);
        assert!(rig.held(&s));
        rig.bridge.clock.advance_secs(wait);
    }
    // The last one records the third as missing and releases on the
    // first two, each asked by this job.
    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 0).await,
        JobOutcome::Ack
    );
    assert!(rig.released(&s));
    assert_eq!(
        rig.checks(&s),
        [
            ok("bb0", VerifyKind::Body),
            ok("bb1", VerifyKind::Stat),
            ("bb2".into(), VerifyKind::Stat, VerifyResult::Missing),
            ok("bb0", VerifyKind::Stat),
            ok("bb1", VerifyKind::Stat),
        ]
    );
    assert_eq!(
        rig.evidence_kinds(&s),
        [
            entry("bb0", "stat", None),
            entry("bb1", "stat", None),
            entry("bb0", "body", None),
        ]
    );
}

/// The release by a verify job is one write to the catalogue: the copy
/// is never `releasing` under its row, so there is no step for another
/// job to finish. A copy found `releasing` all the same is none of the
/// verify job's: it leaves the row to the release stage, which reopens
/// the interrupted decision and checks both backbones before releasing.
#[tokio::test]
async fn a_copy_found_releasing_is_left_to_the_release_stage() {
    let rig = rig_on().await;
    let (s, plan) = rig.on_two(12).await;
    let n = plan.len();
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.job.extent.safety_state = SafetyState::Releasing;
    });

    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 0).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls(), (n, n, 0));
    assert_eq!(rig.state(&s), SafetyState::Releasing);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert_eq!(rig.sent(), [(OutboxStage::Release, 0)]);

    rig.bridge.clock.advance_secs(1);
    assert_eq!(
        rig.logged(&s, OutboxStage::Release, 0).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls(), (0, 2 * n, 0));
    assert!(rig.released(&s));
}

/// What a release job answers without a check is still its answer: a
/// deleted generation, one backbone outside development. The verify
/// job releases nothing there and leaves the row to the release stage.
#[tokio::test]
async fn what_the_release_stage_decides_is_left_to_it() {
    // A deleted generation is cancelled by the release stage.
    let rig = rig_on().await;
    let (s, _) = rig.on_two(13).await;
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.job.generation_state = GenerationState::Deleted;
    });
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert!(rig.held(&s));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Cancelled);
    assert!(rig.held(&s));

    // One backbone is never enough outside development.
    let mut rig = simple_rig().await;
    rig.bridge.cfg.release_at_verify = true;
    rig.bridge.cfg.environment = Environment::Prod;
    let (s, _) = rig.posted(14).await;
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert!(rig.held(&s));
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Done);
    assert!(rig.held(&s));
}

/// In development one required backbone releases, by the verify job too.
#[tokio::test]
async fn one_required_backbone_releases_in_development() {
    let mut rig = simple_rig().await;
    rig.bridge.cfg.release_at_verify = true;
    assert_eq!(rig.bridge.cfg.environment, Environment::Dev);
    assert_eq!(rig.bridge.cfg.required_backbones, 1);
    let (s, _) = rig.posted(15).await;

    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert!(rig.released(&s));
    assert_eq!(rig.evidence_kinds(&s), [entry("bb0", "body", None)]);
}

/// A job whose lease was taken over while it read releases nothing: the
/// guard of the catalogue is fenced by the lease, for a verify job as
/// for a release job.
#[tokio::test]
async fn a_lease_taken_over_releases_nothing() {
    let rig = rig_on().await;
    let (s, _) = rig.on_two(16).await;
    let lease = rig.claim(&s, OutboxStage::Verify).await;
    let job = rig.job(&s).await;
    rig.bridge.catalog.take_over(&s.extent);

    // The first write under the lost lease is refused and the job ends:
    // the row is the new holder's.
    assert_eq!(rig.bridge.verify_stage(&lease, &job).await, JobOutcome::Ack);
    assert!(rig.held(&s));
    assert_eq!(rig.rows(&s), []);
}

/// The guard of the catalogue, asked with a verify lease: a pass from
/// an earlier claim is not presence, so one backbone asked under this
/// claim releases nothing, and two do, in one step. The two steps of a
/// release job are not open to a verify lease.
#[tokio::test]
async fn the_guard_counts_only_passes_of_the_claim_that_releases() {
    let rig = rig_on().await;
    let (s, _) = rig.on_two(17).await;
    let earlier = rig.first_backbone_verified(&s).await;
    let lease = rig.claim(&s, OutboxStage::Verify).await;
    let now = rig.bridge.clock.now();
    let catalog = &rig.bridge.catalog;
    let labels = ["bb0".to_string(), "bb1".to_string()];
    let stat = |backbone: &str, provider: &str| VerificationRow {
        backbone: backbone.into(),
        provider_id: provider.into(),
        verified_at: now,
        kind: VerifyKind::Stat,
        ..earlier.clone()
    };

    // The second backbone under this claim, the first only before it.
    let second = stat("bb1", "p1");
    assert!(catalog
        .record_verification(&lease, &second)
        .await
        .unwrap()
        .held());
    let released = catalog.release_at_verify(&lease, 2, &labels, "[]", now, None);
    assert_eq!(released.await.unwrap(), Guard::Lost);
    assert!(rig.held(&s));

    // Both under this claim, and the full check on record.
    let first = stat("bb0", "p0");
    assert!(catalog
        .record_verification(&lease, &first)
        .await
        .unwrap()
        .held());
    let begun = catalog.begin_release(&lease, 2, &labels, "[]", now).await;
    assert!(matches!(begun, Err(BridgeError::Invalid(_))));
    assert!(rig.held(&s));
    let released = catalog.release_at_verify(&lease, 2, &labels, "[]", now, None);
    assert_eq!(released.await.unwrap(), Guard::Applied(()));
    assert!(rig.released(&s));
    assert_eq!(rig.bridge.catalog.extent(&s.extent).released_at, Some(now));
}

/// Under the light check an extent outside the sample is released by
/// the verify job on its size checks: no article is read, and none is
/// asked for twice.
#[tokio::test]
async fn the_light_check_releases_on_its_size_checks() {
    let sizes = [("p0", SizeCommand::Head), ("p1", SizeCommand::Hdr)];
    let rig = light_rig(0, &sizes).await;
    for server in &rig.servers {
        server.set_reported_size(Some(0)).await;
    }
    let (s, plan) = rig.on_two(20).await;
    let n = plan.len();

    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 1).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls(), (0, 0, 2 * n));
    assert_eq!(
        rig.checks(&s),
        [ok("bb0", VerifyKind::Size), ok("bb1", VerifyKind::Size)]
    );
    assert!(rig.released(&s));
    // Each check once, with the command its provider was asked with.
    assert_eq!(
        rig.evidence_kinds(&s),
        [
            entry("bb0", "size", Some("head")),
            entry("bb1", "size", Some("hdr")),
        ]
    );
    let extent = rig.bridge.catalog.extent(&s.extent);
    let cold = rig.bridge.fetch_cold(&extent).await.unwrap();
    assert_eq!(cold, fetch::ColdFetch::Filled(s.cipher.clone()));
}

/// A sampled extent is released by the verify job with its full read as
/// the full check.
#[tokio::test]
async fn a_sampled_extent_is_released_with_its_full_read() {
    let rig = light_rig(1_000_000, &[]).await;
    let (s, plan) = rig.on_two(21).await;
    let n = plan.len();
    let drawn = verify::sample_backbone(rig.bridge.kek.active().1, &s.extent, 2);
    rig.servers[1 - drawn].set_body_gone(true).await;

    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 1).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls(), (n, n, 0));
    assert!(rig.released(&s));
    let mut want = [entry("bb0", "stat", None), entry("bb1", "stat", None)];
    want[drawn].1 = "sampled".into();
    assert_eq!(rig.evidence_kinds(&s), want);
}

/// Under the light check too, a check that began before the minimum
/// age was over is not presence: both backbones are asked again, with
/// `STAT`, and the size checks stay the record of what verify found.
#[tokio::test]
async fn the_light_check_asks_again_what_began_before_the_minimum_age() {
    let sizes = [("p0", SizeCommand::Head), ("p1", SizeCommand::Head)];
    let mut rig = light_rig(0, &sizes).await;
    for server in &rig.servers {
        server.set_reported_size(Some(0)).await;
    }
    let (s, plan) = rig.on_two(25).await;
    let n = plan.len();
    let posted = plan.iter().filter_map(|a| a.posted_at).max().unwrap();
    // The age is over one second into the job; a call takes 150 ms.
    let start = rig.bridge.clock.now();
    let age_ms = start.0 + 1000 - posted.0;
    assert_eq!(age_ms % 1000, 0);
    rig.bridge.cfg.safety_min_age_secs = u32::try_from(age_ms / 1000).unwrap();
    let ready = UnixMs(start.0 + 1000);

    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 150).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls(), (0, 2 * n, 2 * n));
    let log = rig.bridge.nntp.calls();
    let stats = log.iter().filter(|c| c.0 == "stat");
    assert!(stats.into_iter().all(|c| c.1 >= ready));
    assert_eq!(
        rig.checks(&s),
        [
            ok("bb0", VerifyKind::Size),
            ok("bb1", VerifyKind::Size),
            ok("bb0", VerifyKind::Stat),
            ok("bb1", VerifyKind::Stat),
        ]
    );
    assert!(rig.released(&s));
    assert_eq!(
        rig.evidence_kinds(&s),
        [
            entry("bb0", "stat", None),
            entry("bb1", "stat", None),
            entry("bb0", "size", Some("head")),
            entry("bb1", "size", Some("head")),
        ]
    );
}

/// A size that does not fit, or an article one backbone lacks, blocks
/// the release by the verify job as it blocks the release job.
#[tokio::test]
async fn the_light_check_releases_nothing_on_one_backbone() {
    let sizes = [("p0", SizeCommand::Head), ("p1", SizeCommand::Head)];
    let rig = light_rig(0, &sizes).await;
    rig.servers[0].set_reported_size(Some(0)).await;
    // The second backbone stores articles cut short.
    rig.servers[1].set_reported_size(Some(-200_000)).await;
    let (cut, _) = rig.on_two(22).await;
    let wait = retry_delay(&rig.run(&cut, OutboxStage::Verify).await);
    assert_eq!(wait, REVERIFY_SECS);
    assert!(rig.held(&cut));
    assert_eq!(rig.outbox(&cut).stage, OutboxStage::Verify);

    rig.servers[1].set_reported_size(Some(0)).await;
    let (lacking, plan) = rig.on_two(23).await;
    rig.servers[1].hide(&plan[1].message_id).await;
    assert_eq!(
        retry_delay(&rig.run(&lacking, OutboxStage::Verify).await),
        MISSING_BACKOFF_SECS[0]
    );
    assert!(rig.held(&lacking));
    assert_eq!(rig.outbox(&lacking).stage, OutboxStage::Verify);
}

/// Under the light check a backbone an earlier job passed is asked by
/// the job that releases, and one that then lacks an article sends the
/// extent back to verify.
#[tokio::test]
async fn the_light_check_asks_a_backbone_it_did_not_ask_itself() {
    let rig = light_rig(0, &[]).await;
    let (s, plan) = rig.on_two(24).await;
    let n = plan.len();
    // An earlier job passed the first backbone with `STAT`.
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
        kind: VerifyKind::Stat,
    };
    let catalog = &rig.bridge.catalog;
    assert!(catalog
        .record_verification(&lease, &pass)
        .await
        .unwrap()
        .held());
    assert!(catalog.defer_at(&lease, SECOND, now, now).await.unwrap());
    rig.bridge.clock.advance_secs(1);
    rig.servers[0].hide(&plan[0].message_id).await;

    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 0).await,
        JobOutcome::Ack
    );
    // Both backbones asked for presence, and nothing read.
    let (bodies, stats, sizes) = rig.calls();
    assert_eq!((bodies, sizes), (0, 0));
    assert!(stats >= 2 * n);
    assert!(rig.held(&s));
    // Nothing recorded for the backbone that lacks the article.
    assert_eq!(
        rig.checks(&s),
        [ok("bb0", VerifyKind::Stat), ok("bb1", VerifyKind::Stat)]
    );
    let outbox = rig.outbox(&s);
    assert_eq!((outbox.stage, outbox.cursor), (OutboxStage::Verify, 0));

    // The article is back: the next round asks both and releases.
    rig.servers[0].unhide(&plan[0].message_id).await;
    rig.bridge
        .clock
        .advance_secs(rig.bridge.cfg.verify_delay_secs);
    assert_eq!(
        rig.logged(&s, OutboxStage::Verify, 0).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.calls(), (0, 2 * n, 0));
    assert!(rig.released(&s));
}
