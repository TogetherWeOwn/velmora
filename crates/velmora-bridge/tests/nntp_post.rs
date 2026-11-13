//! Post stage against the in-process NNTP server: the stored plan is what
//! gets posted, and every retry path re-sends the same message-id.

mod nntp_support;

use nntp_support::*;
use velmora::yenc::decode_part_to;
use velmora_bridge::*;

/// Three articles: one full, one full, one short.
const PLAIN_LEN: usize = 1_500_000;

fn bracketed(plan: &[ArticleRow]) -> Vec<String> {
    plan.iter().map(|a| format!("<{}>", a.message_id)).collect()
}

fn ids(plan: &[ArticleRow]) -> Vec<String> {
    plan.iter().map(|a| a.message_id.clone()).collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn retry_delay(outcome: &JobOutcome) -> u32 {
    match outcome {
        JobOutcome::Retry { delay_secs } => *delay_secs,
        JobOutcome::Ack => panic!("expected a retry, got an ack"),
    }
}

#[tokio::test]
async fn posts_the_stored_plan_and_no_plaintext() {
    let rig = simple_rig().await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let plan = rig.plan(&s).await;
    assert_eq!(plan.len(), 3);
    assert!(plan.iter().all(|a| a.state == ArticleState::Posted));
    assert!(plan.iter().all(|a| a.provider_id.as_deref() == Some("p0")));
    // Exactly the planned message-ids reached the server, once each.
    assert_eq!(rig.server().posted_ids().await, bracketed(&plan));

    let mut client = rig.raw_client(0).await;
    for row in &plan {
        let mut article = Vec::new();
        client
            .article_to(&row.message_id, &mut article)
            .await
            .unwrap();
        assert!(
            !contains(&article, MARKER),
            "plaintext in article {}",
            row.idx
        );
        let mut payload = vec![0u8; row.cipher_len as usize];
        let part = decode_part_to(&row.message_id, &article, &mut payload).unwrap();
        assert_eq!(part.written as u64, row.cipher_len);
        assert_eq!(part.offset, row.cipher_offset);
        assert_eq!(part.file_size, s.cipher.len() as u64);
        let start = row.cipher_offset as usize;
        assert_eq!(payload, s.cipher[start..start + payload.len()]);
        assert!(
            !contains(&payload, MARKER),
            "plaintext in payload {}",
            row.idx
        );
        assert_eq!(sha256(&payload), row.payload_sha256);
    }
    client.quit().await;

    // Handed to the verify stage after the configured delay.
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.stage, OutboxStage::Verify);
    assert_eq!(outbox.next_at, T0.plus_secs(30));
    let sent = rig.bridge.jobs.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].delay_secs, 30);
    assert!(matches!(
        &sent[0].job,
        Job::Extent { stage: OutboxStage::Verify, extent, .. } if extent == &s.extent
    ));
    // The slot is free again and the session is closed.
    assert_eq!(rig.bridge.nntp.live(), 0);
    assert_eq!(rig.bridge.nntp.connects(), 1);
}

/// Articles carry only the obfuscated headers: no catalogue identifier and
/// no plaintext digest appears anywhere in a posted article.
#[tokio::test]
async fn posted_articles_carry_no_identifying_metadata() {
    let rig = simple_rig().await;
    let s = rig.seed(9, &marked_plaintext(PLAIN_LEN)).await;
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let job = rig.job(&s).await;
    let extent = &job.extent;
    let mut secrets: Vec<Vec<u8>> = vec![
        BUCKET_NAME.into(),
        job.bucket.id.as_str().into(),
        job.bucket.owner.clone().into(),
        extent.id.as_str().into(),
        s.generation.as_str().into(),
    ];
    for digest in [&extent.plain_md5[..], &extent.plain_sha256[..]] {
        secrets.push(digest.to_vec());
        secrets.push(hex(digest).into());
        secrets.push(hex(digest).to_uppercase().into());
    }

    let mut client = rig.raw_client(0).await;
    for row in rig.plan(&s).await {
        let mut article = Vec::new();
        client
            .article_to(&row.message_id, &mut article)
            .await
            .unwrap();
        for secret in &secrets {
            assert!(
                !contains(&article, secret),
                "article {} leaks metadata",
                row.idx
            );
            assert!(!contains(&row.headers, secret));
        }
        // The stored headers are the posted headers.
        let headers = String::from_utf8(row.headers.clone()).unwrap();
        let subject = headers.lines().find(|l| l.starts_with("Subject:")).unwrap();
        assert!(contains(&article, subject.as_bytes()));
    }
    client.quit().await;
}

/// The job dies after the POST and before the catalogue write. Its
/// successor re-sends the same message-id, the server answers "duplicate",
/// and the article is confirmed: no second copy, no new id.
#[tokio::test]
async fn crash_after_post_reposts_the_same_id() {
    let rig = simple_rig().await;
    let s = rig.seed(2, &marked_plaintext(PLAIN_LEN)).await;

    rig.bridge.catalog.fail_mark_posted.set(1);
    assert_eq!(retry_delay(&rig.run_post(&s).await), 60);
    let planned = rig.plan(&s).await;
    assert!(planned.iter().all(|a| a.state == ArticleState::Planned));
    assert_eq!(rig.server().posted_ids().await, bracketed(&planned)[..1]);
    // The dead job's lease still fences the row.
    assert!(rig.try_claim(&s, OutboxStage::Post).await.is_none());

    rig.bridge.clock.advance_secs(LEASE_SECS + 1);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let plan = rig.plan(&s).await;
    assert_eq!(ids(&plan), ids(&planned));
    assert!(plan.iter().all(|a| a.state == ArticleState::Posted));
    assert_eq!(rig.server().posted_ids().await, bracketed(&plan));
    assert_eq!(
        rig.bridge.catalog.outbox(&s.extent).stage,
        OutboxStage::Verify
    );
}

/// The server says "duplicate" but cannot show the article yet. The job
/// fails as `dup-unconfirmed` and comes back with the same message-id.
#[tokio::test]
async fn dup_unconfirmed_keeps_message_id() {
    let rig = simple_rig().await;
    let s = rig.seed(3, &marked_plaintext(PLAIN_LEN)).await;

    rig.bridge.catalog.fail_mark_posted.set(1);
    rig.run_post(&s).await;
    let planned = rig.plan(&s).await;

    rig.server().set_stat_lag(true).await;
    rig.bridge.clock.advance_secs(LEASE_SECS + 1);
    let now = rig.bridge.clock.now();
    // Second attempt: 60 s doubled once.
    assert_eq!(retry_delay(&rig.run_post(&s).await), 120);
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.stage, OutboxStage::Post);
    assert_eq!(outbox.last_error, Some(FailClass::DupUnconfirmed));
    assert_eq!(outbox.next_at, now.plus_secs(120));
    assert_eq!(outbox.lease_until, None);
    let plan = rig.plan(&s).await;
    assert_eq!(ids(&plan), ids(&planned));
    assert_eq!(plan[0].state, ArticleState::Planned);
    assert_eq!(rig.server().posted_count().await, 1);

    rig.server().set_stat_lag(false).await;
    rig.bridge.clock.advance_secs(120);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let plan = rig.plan(&s).await;
    assert_eq!(ids(&plan), ids(&planned));
    assert_eq!(rig.server().posted_ids().await, bracketed(&plan));
}

/// A provider that refuses posting leaves the job retryable, with the plan
/// intact.
#[tokio::test]
async fn posting_refused_is_retried_not_dead() {
    let rig = simple_rig().await;
    let s = rig.seed(4, &marked_plaintext(PLAIN_LEN)).await;

    rig.server().set_posting_allowed(false).await;
    assert_eq!(retry_delay(&rig.run_post(&s).await), 60);
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.stage, OutboxStage::Post);
    assert_eq!(outbox.last_error, Some(FailClass::PostRefused));
    assert_eq!(outbox.next_at, T0.plus_secs(60));
    let planned = rig.plan(&s).await;
    assert_eq!(planned.len(), 3);
    assert_eq!(rig.server().posted_count().await, 0);
    assert_eq!(rig.bridge.nntp.live(), 0);

    rig.server().set_posting_allowed(true).await;
    rig.bridge.clock.advance_secs(60);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    assert_eq!(rig.server().posted_ids().await, bracketed(&planned));
}

/// The connection dies after the article is sent and before the reply.
/// The stage reconnects and re-sends the same article inside the same job.
#[tokio::test]
async fn post_reconnects_after_drop() {
    let rig = simple_rig().await;
    let s = rig.seed(5, &marked_plaintext(PLAIN_LEN)).await;

    rig.server().drop_next_posts(1).await;
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let plan = rig.plan(&s).await;
    assert!(plan.iter().all(|a| a.state == ArticleState::Posted));
    assert_eq!(rig.server().posted_ids().await, bracketed(&plan));
    assert_eq!(rig.bridge.nntp.connects(), 2);
    assert_eq!(rig.bridge.nntp.peak(), 1);
}

/// Reconnects are bounded: after the last attempt the job fails as an NNTP
/// error and a later job finishes with the same message-ids.
#[tokio::test]
async fn post_reconnects_are_bounded() {
    let rig = simple_rig().await;
    let s = rig.seed(6, &marked_plaintext(PLAIN_LEN)).await;

    rig.server().drop_next_posts(3).await;
    assert_eq!(retry_delay(&rig.run_post(&s).await), 60);
    assert_eq!(rig.bridge.nntp.connects(), 3);
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.last_error, Some(FailClass::NntpError));
    let planned = rig.plan(&s).await;
    assert!(planned.iter().all(|a| a.state == ArticleState::Planned));

    rig.bridge.clock.advance_secs(60);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    assert_eq!(rig.server().posted_ids().await, bracketed(&planned));
}

/// A job whose lease was taken over writes nothing and posts nothing.
#[tokio::test]
async fn stale_lease_stops_before_any_post() {
    let rig = simple_rig().await;
    let s = rig.seed(7, &marked_plaintext(PLAIN_LEN)).await;

    let stale = rig.claim(&s, OutboxStage::Post).await;
    rig.bridge.clock.advance_secs(LEASE_SECS + 1);
    let current = rig.claim(&s, OutboxStage::Post).await;
    let job = rig.job(&s).await;

    assert_eq!(rig.bridge.post_stage(&stale, &job).await, JobOutcome::Ack);
    assert!(rig.plan(&s).await.is_empty());
    assert_eq!(rig.server().posted_count().await, 0);
    assert_eq!(rig.bridge.nntp.connects(), 0);
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.token, current.token);
    assert_eq!(outbox.stage, OutboxStage::Post);

    // The current holder is unaffected.
    assert_eq!(rig.bridge.post_stage(&current, &job).await, JobOutcome::Ack);
    assert_eq!(rig.server().posted_count().await, 3);
}

/// The lease is taken over while the stage is posting: the next article
/// is never sent.
#[tokio::test]
async fn lease_lost_mid_stage_stops_posting() {
    let rig = simple_rig().await;
    let s = rig.seed(8, &marked_plaintext(PLAIN_LEN)).await;

    rig.bridge
        .catalog
        .fault
        .set(Some(Fault::StealLeaseAfterMark(0)));
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let plan = rig.plan(&s).await;
    assert_eq!(rig.server().posted_ids().await, bracketed(&plan)[..1]);
    assert_eq!(plan[0].state, ArticleState::Posted);
    assert!(plan[1..].iter().all(|a| a.state == ArticleState::Planned));
    assert_eq!(rig.bridge.nntp.connects(), 1);
    assert_eq!(rig.bridge.nntp.live(), 0);
    // Nothing was advanced or enqueued by the stale job.
    assert_eq!(
        rig.bridge.catalog.outbox(&s.extent).stage,
        OutboxStage::Post
    );
    assert!(rig.bridge.jobs.sent().is_empty());
}

/// The lease is lost between a POST and its catalogue write: the write is
/// refused, the job stops, and the successor confirms the same article.
#[tokio::test]
async fn fenced_mark_posted_stops_and_successor_confirms() {
    let rig = simple_rig().await;
    let s = rig.seed(22, &marked_plaintext(PLAIN_LEN)).await;

    rig.bridge
        .catalog
        .fault
        .set(Some(Fault::StealLeaseBeforeMark(1)));
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let planned = rig.plan(&s).await;
    assert_eq!(planned[1].state, ArticleState::Planned);
    assert_eq!(planned[2].state, ArticleState::Planned);
    assert_eq!(rig.server().posted_ids().await, bracketed(&planned)[..2]);

    rig.bridge.clock.advance_secs(LEASE_SECS + 1);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let plan = rig.plan(&s).await;
    assert_eq!(ids(&plan), ids(&planned));
    assert!(plan.iter().all(|a| a.state == ArticleState::Posted));
    assert_eq!(rig.server().posted_ids().await, bracketed(&plan));
}

/// The lease is lost after the last article: the stale job does not move
/// the row to the next stage.
#[tokio::test]
async fn fenced_advance_leaves_the_stage_alone() {
    let rig = simple_rig().await;
    let s = rig.seed(23, &marked_plaintext(PLAIN_LEN)).await;

    rig.bridge
        .catalog
        .fault
        .set(Some(Fault::StealLeaseAfterMark(2)));
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    assert_eq!(
        rig.bridge.catalog.outbox(&s.extent).stage,
        OutboxStage::Post
    );
    assert!(rig.bridge.jobs.sent().is_empty());
}

/// The permit slot is taken over mid-stage: the socket is dropped and the
/// job is deferred, with nothing more posted on the lost slot.
#[tokio::test]
async fn lost_permit_stops_posting() {
    let rig = simple_rig().await;
    let s = rig.seed(24, &marked_plaintext(PLAIN_LEN)).await;

    rig.bridge
        .catalog
        .fault
        .set(Some(Fault::RevokePermitAfterMark(0)));
    let delay = retry_delay(&rig.run_post(&s).await);
    assert!((15..=60).contains(&delay), "delay {delay}");
    assert_eq!(rig.server().posted_count().await, 1);
    assert_eq!(rig.bridge.nntp.live(), 0);
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.attempts, 0);
    assert_eq!(outbox.stage, OutboxStage::Post);
}

/// A repost is byte-identical to the first post: the provider lost the
/// article (so the repost is stored again) and the stored bytes match.
#[tokio::test]
async fn repost_is_byte_identical() {
    let rig = simple_rig().await;
    let s = rig.seed(25, &marked_plaintext(PLAIN_LEN)).await;

    rig.bridge.catalog.fail_mark_posted.set(1);
    rig.run_post(&s).await;
    let id = rig.plan(&s).await[0].message_id.clone();
    let mut client = rig.raw_client(0).await;
    let mut first = Vec::new();
    client.article_to(&id, &mut first).await.unwrap();

    rig.server().hide(&id).await;
    rig.bridge.clock.advance_secs(LEASE_SECS + 1);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let mut second = Vec::new();
    client.article_to(&id, &mut second).await.unwrap();
    client.quit().await;
    assert!(!first.is_empty());
    assert_eq!(first, second);
    assert_eq!(rig.server().posted_count().await, 3);
}

/// Overlapping jobs never hold more provider connections than the slots
/// allow; a job without a slot is deferred without spending an attempt.
#[tokio::test]
async fn permits_never_exceed_max_conns() {
    let rig = rig(&[Spec {
        backbone: "bb0",
        post: true,
        max_conns: 3,
    }])
    .await;
    let mut seeded = Vec::new();
    for n in 10..14 {
        seeded.push(rig.seed(n, &marked_plaintext(PLAIN_LEN)).await);
    }

    let (a, b, c, d) = tokio::join!(
        rig.run_post(&seeded[0]),
        rig.run_post(&seeded[1]),
        rig.run_post(&seeded[2]),
        rig.run_post(&seeded[3]),
    );
    let outcomes = [a, b, c, d];
    // One slot stays reserved for reads: two background jobs at a time.
    assert_eq!(
        outcomes.iter().filter(|o| **o == JobOutcome::Ack).count(),
        2
    );
    assert_eq!(rig.bridge.nntp.peak(), 2);
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p0"], 2);
    assert_eq!(rig.bridge.catalog.permit_refusals.get(), 2);
    assert_eq!(rig.bridge.nntp.connects(), 2);

    for (s, outcome) in seeded.iter().zip(&outcomes) {
        if *outcome == JobOutcome::Ack {
            continue;
        }
        let delay = retry_delay(outcome);
        assert!((15..=60).contains(&delay), "delay {delay}");
        let outbox = rig.bridge.catalog.outbox(&s.extent);
        assert_eq!(outbox.stage, OutboxStage::Post);
        assert_eq!(outbox.attempts, 0, "no attempt spent");
        assert_eq!(outbox.next_at, T0.plus_secs(delay));
        assert_eq!(outbox.last_error, None);
    }

    rig.bridge.clock.advance_secs(60);
    for (s, outcome) in seeded.iter().zip(&outcomes) {
        if *outcome != JobOutcome::Ack {
            assert_eq!(rig.run_post(s).await, JobOutcome::Ack);
        }
    }
    assert_eq!(rig.server().posted_count().await, 12);
    assert_eq!(rig.bridge.nntp.peak(), 2);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// The provider's own "too many connections" is treated as "no slot".
#[tokio::test]
async fn provider_connection_cap_defers_the_job() {
    let rig = simple_rig().await;
    let s = rig.seed(20, &marked_plaintext(PLAIN_LEN)).await;
    let addr = rig.server().addr();
    let cfg = nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
    // Something else already holds both of the account's connections.
    let held = (dial(&cfg).await.unwrap(), dial(&cfg).await.unwrap());

    let delay = retry_delay(&rig.run_post(&s).await);
    assert!((15..=60).contains(&delay), "delay {delay}");
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.attempts, 0);
    assert_eq!(outbox.last_error, None);
    assert_eq!(rig.server().posted_count().await, 0);

    held.0.quit().await;
    held.1.quit().await;
    rig.bridge.clock.advance_secs(60);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    assert_eq!(rig.server().posted_count().await, 3);
}

/// Safety bytes that do not match the catalogue are never posted.
#[tokio::test]
async fn mismatched_safety_bytes_are_not_posted() {
    let rig = simple_rig().await;
    let s = rig.seed(21, &marked_plaintext(PLAIN_LEN)).await;
    rig.bridge
        .safety
        .corrupt(&s.extent.safety_key(), |b| b[100] ^= 1);

    retry_delay(&rig.run_post(&s).await);
    assert_eq!(
        rig.bridge.catalog.outbox(&s.extent).last_error,
        Some(FailClass::Corrupt)
    );
    assert!(rig.plan(&s).await.is_empty());
    assert_eq!(rig.server().posted_count().await, 0);
    assert_eq!(rig.bridge.nntp.connects(), 0);
}
