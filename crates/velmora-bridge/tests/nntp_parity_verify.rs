//! Verify and release stages for an extent with parity articles: they
//! are checked, counted, posted again and waited for like its data
//! articles, and nothing is released without them.

mod nntp_support;

use nntp_support::*;
use velmora::yenc::decode_part_to;
use velmora_bridge::parity::ParityPlan;
use velmora_bridge::verify::MISSING_BACKOFF_SECS;
use velmora_bridge::*;

/// Ten data articles, and so two parity articles.
const TEN: usize = 6_500_000;
const DATA: u32 = 10;
const PARITY: u32 = 2;
const ALL: u32 = DATA + PARITY;
/// A propagation grace longer than all the waits for a missing article
/// together: nothing is ever posted again.
const LONG_GRACE_SECS: u32 = 86_400;
/// `Lease::cursor` of the second backbone after a repost.
const SECOND_REPOSTED: u32 = 15;

fn retry_delay(outcome: &JobOutcome) -> u32 {
    match outcome {
        JobOutcome::Retry { delay_secs } => *delay_secs,
        JobOutcome::Ack => panic!("expected a retry, got an ack"),
    }
}

/// Two backbones that count, both needed for a release. The first one
/// takes the posts; the second posts too when `second_posts`.
async fn parity_rig(second_posts: bool) -> Rig {
    let spec = |backbone, post| Spec {
        backbone,
        post,
        max_conns: 4,
    };
    let mut rig = rig(&[spec("bb0", true), spec("bb1", second_posts)]).await;
    rig.bridge.cfg.providers[1].priority = 1;
    rig.bridge.cfg.required_backbones = 2;
    rig.bridge.cfg.packed_plans = true;
    rig.bridge.cfg.parity = true;
    rig
}

impl Rig {
    /// Posts a ten-article extent with its parity: all of it is on the
    /// first backbone, none of it on the second.
    async fn posted(&self, n: u8) -> (Seeded, ParityPlan) {
        let s = self.seed(n, &marked_plaintext(TEN)).await;
        let plan = self.post(&s).await;
        assert_eq!(plan.len(), DATA as usize);
        let parity = self.parity_of(&s).await;
        assert_eq!(parity.articles.len(), PARITY as usize);
        assert_eq!(self.servers[0].posted_count().await, ALL as usize);
        assert_eq!(self.servers[1].posted_count().await, 0);
        (s, parity)
    }

    /// What the stored addendum of the extent expands to.
    async fn parity_of(&self, s: &Seeded) -> ParityPlan {
        let stored = self.bridge.catalog.stored_plan(&s.extent).await.unwrap();
        stored
            .parity_plan(&s.extent, s.cipher.len() as u64)
            .unwrap()
            .expect("the extent has parity")
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

    /// Posts, copies every article to the second backbone, and verifies
    /// both: the extent is at the release stage.
    async fn verified_on_two(&self, n: u8) -> (Seeded, ParityPlan) {
        let (s, parity) = self.posted(n).await;
        self.propagate(&s, 0, 1).await;
        for row in &parity.articles {
            self.propagate_one(row).await;
        }
        assert_eq!(self.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
        assert_eq!(self.outbox(&s).stage, OutboxStage::Release);
        self.bridge.jobs.take();
        self.bridge.clock.advance_secs(1);
        (s, parity)
    }

    fn outbox(&self, s: &Seeded) -> OutboxRow {
        self.bridge.catalog.outbox(&s.extent)
    }

    fn rows(&self, s: &Seeded) -> Vec<VerificationRow> {
        self.bridge.catalog.verifications(&s.extent)
    }

    fn safety_held(&self, s: &Seeded) -> bool {
        let extent = self.bridge.catalog.extent(&s.extent);
        self.bridge.safety.contains(&s.extent.safety_key())
            && extent.safety_state == SafetyState::Held
            && extent.release_evidence.is_none()
    }

    fn released(&self, s: &Seeded) -> bool {
        self.bridge.catalog.extent(&s.extent).safety_state == SafetyState::Released
    }
}

/// What a pass recorded: backbone, kind, result, articles found, total.
fn summary(v: &VerificationRow) -> (&str, VerifyKind, VerifyResult, u32, u32) {
    (
        v.backbone.as_str(),
        v.kind,
        v.result,
        v.articles_ok,
        v.articles_total,
    )
}

/// A backbone holds the extent only with every parity article: while the
/// second one lacks one, verify does not pass it and a release goes back
/// to verify. With the article there the extent is released, and the
/// evidence counts the parity articles.
#[tokio::test]
async fn release_waits_for_every_parity_article_on_the_second_backbone() {
    let mut rig = parity_rig(false).await;
    rig.bridge.cfg.propagation_grace_secs = LONG_GRACE_SECS;
    let (s, parity) = rig.posted(1).await;
    // Every data article and one parity article reach the second
    // backbone.
    rig.propagate(&s, 0, 1).await;
    rig.propagate_one(&parity.articles[0]).await;
    let late = &parity.articles[1];

    // The first backbone is read in full, parity included. The second
    // lacks an article: no result yet, and no release.
    let wait = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(wait, MISSING_BACKOFF_SECS[0]);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 1);
    let ok = VerifyResult::Ok;
    assert_eq!(summary(&rows[0]), ("bb0", VerifyKind::Body, ok, ALL, ALL));
    assert!(rig.safety_held(&s));

    rig.propagate_one(late).await;
    rig.bridge.clock.advance_secs(wait);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 2);
    assert_eq!(summary(&rows[1]), ("bb1", VerifyKind::Stat, ok, ALL, ALL));

    // The article is gone from the second backbone again when the
    // release asks: nothing is released and nothing recorded.
    rig.servers[1].hide(&late.message_id).await;
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    assert_eq!(rig.rows(&s).len(), 2);
    assert!(rig.safety_held(&s));

    rig.servers[1].unhide(&late.message_id).await;
    rig.bridge
        .clock
        .advance_secs(rig.bridge.cfg.verify_delay_secs);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.released(&s));

    let extent = rig.bridge.catalog.extent(&s.extent);
    let evidence: serde_json::Value =
        serde_json::from_str(extent.release_evidence.as_deref().unwrap()).unwrap();
    let evidence = evidence.as_array().unwrap();
    let kinds: Vec<_> = evidence
        .iter()
        .map(|e| (e["backbone"].as_str().unwrap(), e["kind"].as_str().unwrap()))
        .collect();
    assert_eq!(kinds, [("bb0", "stat"), ("bb1", "stat"), ("bb0", "body")]);
    for entry in evidence {
        assert_eq!(entry["ok"], ALL);
        assert_eq!(entry["total"], ALL);
        assert_eq!(entry["parity"], PARITY);
        assert_eq!(entry["plan_rev"], 1);
    }
}

/// The evidence of an extent without parity is what it was: no entry
/// has a parity count.
#[tokio::test]
async fn evidence_without_parity_has_no_parity_count() {
    let mut rig = parity_rig(false).await;
    rig.bridge.cfg.parity = false;
    let s = rig.seed(2, &marked_plaintext(1_500_000)).await;
    let plan = rig.post(&s).await;
    rig.propagate(&s, 0, 1).await;
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.released(&s));

    let total = plan.len() as u32;
    assert!(rig.rows(&s).iter().all(|v| v.articles_total == total));
    let extent = rig.bridge.catalog.extent(&s.extent);
    let evidence: serde_json::Value =
        serde_json::from_str(extent.release_evidence.as_deref().unwrap()).unwrap();
    let evidence = evidence.as_array().unwrap();
    assert_eq!(evidence.len(), 3);
    for entry in evidence {
        // The fields of an entry, as before (in the order of the map).
        let fields: Vec<&str> = entry
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected = [
            "backbone",
            "provider",
            "verified_at",
            "kind",
            "ok",
            "total",
            "plan_rev",
        ];
        expected.sort_unstable();
        assert_eq!(fields, expected);
        assert_eq!(entry["total"], total);
    }
}

/// Passes over the data articles alone, as a version from before parity
/// records them, release nothing: the release finds no full check of the
/// whole plan on record and sends the extent back to verify, which reads
/// every article.
#[tokio::test]
async fn passes_without_the_parity_articles_release_nothing() {
    let rig = parity_rig(false).await;
    let (s, _) = rig.verified_on_two(3).await;
    rig.bridge.catalog.edit(&s.extent, |e| {
        for v in &mut e.verifications {
            v.articles_ok = DATA;
            v.articles_total = DATA;
        }
    });

    let connects = rig.bridge.nntp.connects();
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    assert_eq!(rig.bridge.nntp.connects(), connects);
    assert!(rig.safety_held(&s));

    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let rows = rig.rows(&s);
    let ok = VerifyResult::Ok;
    assert_eq!(summary(&rows[2]), ("bb0", VerifyKind::Body, ok, ALL, ALL));
    assert_eq!(summary(&rows[3]), ("bb1", VerifyKind::Stat, ok, ALL, ALL));
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.released(&s));
}

/// The catalogue's own guard refuses a release on passes that left the
/// parity articles out, whatever the job found.
#[tokio::test]
async fn the_guard_counts_the_parity_articles() {
    let rig = parity_rig(false).await;
    let (s, _) = rig.verified_on_two(4).await;
    let lease = rig.claim(&s, OutboxStage::Release).await;
    let now = rig.bridge.clock.now();
    let labels = ["bb0".to_string(), "bb1".to_string()];
    let pass = |backbone: &str, at: UnixMs, total: u32| VerificationRow {
        extent_id: s.extent.clone(),
        backbone: backbone.to_string(),
        provider_id: "p".to_string(),
        verified_at: at,
        plan_rev: 1,
        articles_ok: total,
        articles_total: total,
        result: VerifyResult::Ok,
        kind: VerifyKind::Stat,
    };
    let catalog = &rig.bridge.catalog;
    for (at, total, granted) in [(now, DATA, false), (now.plus_ms(1), ALL, true)] {
        for backbone in ["bb0", "bb1"] {
            let row = pass(backbone, at, total);
            assert!(catalog.record_verification(&lease, &row).await.unwrap());
        }
        let begun = catalog.begin_release(&lease, 2, &labels, "[]", at).await;
        assert_eq!(begun.unwrap() == Guard::Applied(()), granted, "{total}");
    }
}

/// The second backbone still lacks a parity article when the propagation
/// grace is over: it is posted straight to that backbone's provider from
/// the safety copy, under its stored message-id, and the next read
/// passes. The minimum age counts from that post.
#[tokio::test]
async fn a_missing_parity_article_is_posted_to_the_backbone_that_lacks_it() {
    let mut rig = parity_rig(true).await;
    let day = 24 * 3600;
    rig.bridge.cfg.safety_min_age_secs = day;
    let (s, parity) = rig.posted(5).await;
    rig.propagate(&s, 0, 1).await;
    rig.propagate_one(&parity.articles[0]).await;
    let lost = &parity.articles[1];
    assert_eq!(lost.idx, ALL - 1);
    let grace_ends = lost
        .posted_at
        .unwrap()
        .plus_secs(rig.bridge.cfg.propagation_grace_secs);

    // Until the grace is over the backbone is only read again.
    while rig.bridge.clock.now() < grace_ends {
        let wait = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
        rig.bridge.clock.advance_secs(wait);
        assert_eq!(rig.servers[1].posted_count().await, ALL as usize - 1);
    }
    assert_eq!(rig.bridge.clock.now(), grace_ends);
    assert_eq!(rig.rows(&s).len(), 1);

    let reposted = rig.bridge.clock.now();
    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(delay, rig.bridge.cfg.verify_delay_secs);
    let outbox = rig.outbox(&s);
    assert_eq!(
        (outbox.stage, outbox.cursor),
        (OutboxStage::Verify, SECOND_REPOSTED)
    );
    // Exactly the one article, with the shard the addendum describes.
    assert_eq!(rig.servers[1].posted_count().await, ALL as usize);
    assert_eq!(rig.servers[0].posted_count().await, ALL as usize);
    let mut client = rig.raw_client(1).await;
    let mut article = Vec::new();
    client
        .article_to(&lost.message_id, &mut article)
        .await
        .unwrap();
    client.quit().await;
    let mut payload = vec![0u8; lost.cipher_len as usize];
    decode_part_to(&lost.message_id, &article, &mut payload).unwrap();
    assert_eq!(sha256(&payload), lost.payload_sha256);
    {
        let entries = rig.bridge.catalog.entries.borrow();
        // Stamped before the POST and again when it was accepted.
        let stamped = &entries[&s.extent].parity_reposted;
        assert!(!stamped.is_empty() && stamped.iter().all(|idx| *idx == lost.idx));
    }
    // The addendum is the one that was stored: nothing was drawn again.
    assert_eq!(rig.parity_of(&s).await.rows, parity.rows);
    assert_eq!(rig.bridge.nntp.live(), 0);

    rig.bridge.clock.advance_secs(delay);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let rows = rig.rows(&s);
    let ok = VerifyResult::Ok;
    assert_eq!(summary(&rows[1]), ("bb1", VerifyKind::Stat, ok, ALL, ALL));
    let ready = reposted.plus_secs(day);
    let outbox = rig.outbox(&s);
    assert_eq!(
        (outbox.stage, outbox.next_at),
        (OutboxStage::Release, ready)
    );

    // Not released before the minimum age after the repost is over.
    rig.bridge.clock.set(UnixMs(ready.0 - 1));
    rig.bridge
        .catalog
        .edit(&s.extent, |e| e.outbox.next_at = T0);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.safety_held(&s));
    rig.bridge.clock.set(ready);
    assert_eq!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
    assert!(rig.released(&s));
}

/// Parity articles that were never posted (a version from before parity
/// posted the plan, data only) are found missing at verify and posted
/// then, while the safety copy is held.
#[tokio::test]
async fn parity_that_was_never_posted_is_posted_at_verify() {
    let mut rig = parity_rig(true).await;
    rig.bridge.cfg.propagation_grace_secs = 0;
    rig.bridge.cfg.required_backbones = 1;
    rig.bridge.cfg.providers.truncate(1);
    let (s, parity) = rig.posted(6).await;
    for row in &parity.articles {
        rig.servers[0].hide(&row.message_id).await;
    }

    let delay = retry_delay(&rig.run(&s, OutboxStage::Verify).await);
    assert_eq!(delay, rig.bridge.cfg.verify_delay_secs);
    assert!(rig.rows(&s).is_empty());
    for row in &parity.articles {
        assert!(!rig.servers[0].is_hidden(&row.message_id).await);
    }
    assert_eq!(rig.servers[0].posted_count().await, ALL as usize);

    rig.bridge.clock.advance_secs(delay);
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let rows = rig.rows(&s);
    let ok = VerifyResult::Ok;
    assert_eq!(rows.len(), 1);
    assert_eq!(summary(&rows[0]), ("bb0", VerifyKind::Body, ok, ALL, ALL));
}

/// A parity article whose payload is not the one the addendum describes
/// is corrupt, like a data article: the backbone does not hold the
/// extent.
#[tokio::test]
async fn a_corrupt_parity_article_is_recorded_as_corrupt() {
    let mut rig = parity_rig(false).await;
    rig.bridge.cfg.required_backbones = 1;
    rig.bridge.cfg.providers.truncate(1);
    let s = rig.seed(7, &marked_plaintext(TEN)).await;
    // The provider holds another payload under the id of a parity
    // article: the addendum is stored by a first job that cannot post.
    rig.server().set_posting_allowed(false).await;
    assert_ne!(rig.run_post(&s).await, JobOutcome::Ack);
    rig.server().set_posting_allowed(true).await;
    let parity = rig.parity_of(&s).await;
    let row = &parity.articles[0];
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
    rig.post(&s).await;

    assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let rows = rig.rows(&s);
    assert_eq!(rows.len(), 1);
    let corrupt = VerifyResult::Corrupt;
    assert_eq!(
        summary(&rows[0]),
        ("bb0", VerifyKind::Body, corrupt, ALL - 1, ALL)
    );
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Verify);
    assert!(rig.safety_held(&s));
}

/// An addendum that cannot be read fails the verify job and the release
/// job: no article is asked for, nothing is recorded, nothing released.
/// So does a plan that has lost the addendum its row counts.
#[tokio::test]
async fn an_unreadable_addendum_fails_verify_and_release() {
    let damage: [fn(&mut Entry); 3] = [
        |e| e.parity.as_mut().unwrap()[30] ^= 0x01,
        |e| e.parity.as_mut().unwrap().truncate(40),
        |e| e.parity = None,
    ];
    for (n, damage) in damage.into_iter().enumerate() {
        let rig = parity_rig(false).await;

        // At verify.
        let (s, _) = rig.posted(10 + n as u8).await;
        rig.bridge.catalog.edit(&s.extent, damage);
        let connects = rig.bridge.nntp.connects();
        assert_ne!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
        let outbox = rig.outbox(&s);
        assert_eq!(outbox.stage, OutboxStage::Verify);
        assert_eq!(outbox.last_error, Some(FailClass::Corrupt));
        assert!(rig.rows(&s).is_empty());
        assert_eq!(rig.bridge.nntp.connects(), connects);
        assert!(rig.safety_held(&s));

        // At release, with every pass on record.
        let rig = parity_rig(false).await;
        let (s, _) = rig.verified_on_two(20 + n as u8).await;
        rig.bridge.catalog.edit(&s.extent, damage);
        let connects = rig.bridge.nntp.connects();
        assert_ne!(rig.run(&s, OutboxStage::Release).await, JobOutcome::Ack);
        let outbox = rig.outbox(&s);
        assert_eq!(outbox.stage, OutboxStage::Release);
        assert_eq!(outbox.last_error, Some(FailClass::Corrupt));
        assert_eq!(rig.rows(&s).len(), 2);
        assert_eq!(rig.bridge.nntp.connects(), connects);
        assert!(rig.safety_held(&s));
    }
}
