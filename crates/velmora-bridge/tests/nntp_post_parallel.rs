//! Post stage with several sockets and several providers at once: every
//! article is posted once, the permit gate bounds the sockets, and a
//! stale lease writes nothing however many sockets are posting.

mod nntp_support;

use std::cell::RefCell;
use std::collections::BTreeSet;

use nntp_support::*;
use velmora_bridge::*;

/// Ten articles.
const PLAIN_LEN: usize = 6_500_000;

fn spec(backbone: &'static str, max_conns: u32) -> Spec {
    Spec {
        backbone,
        post: true,
        max_conns,
    }
}

fn id_set(plan: &[ArticleRow]) -> BTreeSet<String> {
    plan.iter().map(|a| format!("<{}>", a.message_id)).collect()
}

async fn stored(rig: &Rig, server: usize) -> BTreeSet<String> {
    let ids = rig.servers[server].posted_ids().await;
    let set: BTreeSet<String> = ids.iter().cloned().collect();
    assert_eq!(set.len(), ids.len(), "an article was stored twice");
    set
}

fn all_posted_by(plan: &[ArticleRow], provider: &str) -> bool {
    plan.iter()
        .all(|a| a.state == ArticleState::Posted && a.provider_id.as_deref() == Some(provider))
}

/// One job, four sockets: every article is posted once, on four permits,
/// with one renewal and one catalogue write for the lot.
#[tokio::test]
async fn posts_on_several_sockets_at_once() {
    // Five slots: one stays reserved for reads.
    let rig = rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let plan = rig.plan(&s).await;
    assert_eq!(plan.len(), 10);
    assert!(all_posted_by(&plan, "p0"));
    assert_eq!(stored(&rig, 0).await, id_set(&plan));
    assert_eq!(rig.bridge.nntp.connects(), 4);
    assert_eq!(rig.bridge.nntp.peak(), 4);
    assert_eq!(rig.bridge.nntp.live(), 0);
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p0"], 4);
    assert_eq!(rig.bridge.catalog.renewals.get(), 1);
    assert_eq!(rig.bridge.catalog.mark_batches.get(), 1);
    assert_eq!(
        rig.bridge.catalog.outbox(&s.extent).stage,
        OutboxStage::Verify
    );
    // Every slot is free again.
    assert_eq!(
        rig.run_post(&rig.seed(2, &[7; 1000]).await).await,
        JobOutcome::Ack
    );
}

/// `POST_SOCKETS` bounds the sockets of a job, and a job never opens more
/// sockets than it has articles.
#[tokio::test]
async fn sockets_follow_the_setting_and_the_work() {
    let mut rig = rig(&[spec("bb0", 9)]).await;
    rig.bridge.cfg.post_sockets = 2;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    assert_eq!(rig.bridge.nntp.peak(), 2);

    rig.bridge.cfg.post_sockets = 8;
    let one = rig.seed(2, &[7; 1000]).await;
    assert_eq!(rig.run_post(&one).await, JobOutcome::Ack);
    assert_eq!(rig.bridge.nntp.connects(), 3);
    assert_eq!(rig.bridge.nntp.peak(), 2);
}

/// Overlapping jobs with several sockets each never hold more permits or
/// connections than the provider allows; a job that gets fewer slots than
/// it wants posts with what it got, and one that gets none is deferred.
#[tokio::test]
async fn permits_bound_the_sockets_of_overlapping_jobs() {
    // Six slots, five for background work.
    let rig = rig(&[spec("bb0", 6)]).await;
    let mut seeded = Vec::new();
    for n in 1..=3 {
        seeded.push(rig.seed(n, &marked_plaintext(PLAIN_LEN)).await);
    }

    let (a, b, c) = tokio::join!(
        rig.run_post(&seeded[0]),
        rig.run_post(&seeded[1]),
        rig.run_post(&seeded[2]),
    );
    // Four sockets, one socket, none.
    assert_eq!([a, b], [JobOutcome::Ack, JobOutcome::Ack]);
    assert!(matches!(c, JobOutcome::Retry { delay_secs } if (15..=60).contains(&delay_secs)));
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p0"], 5);
    assert_eq!(rig.bridge.nntp.peak(), 5);
    assert_eq!(rig.bridge.nntp.connects(), 5);
    assert_eq!(rig.bridge.nntp.live(), 0);
    assert_eq!(rig.bridge.catalog.outbox(&seeded[2].extent).attempts, 0);
    assert_eq!(rig.servers[0].posted_count().await, 20);
}

/// The lease runs out while four sockets are posting and another job
/// takes the row. The stale job stops, marks nothing and advances
/// nothing; the new holder posts under the same message-ids and no
/// article is stored twice.
#[tokio::test]
async fn expired_lease_with_several_sockets_writes_nothing() {
    let rig = rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    let thief = RefCell::new(None);
    let outcome = rig
        .run_post_and(&s, 0, 1, async || {
            rig.bridge.clock.advance_secs(LEASE_SECS + 1);
            *thief.borrow_mut() = rig.try_claim(&s, OutboxStage::Post).await;
        })
        .await;
    assert_eq!(outcome, JobOutcome::Ack);
    let thief = thief.into_inner().expect("the expired lease is claimable");

    let plan = rig.plan(&s).await;
    // Only articles already on the wire at the takeover were finished.
    let before = rig.servers[0].posted_count().await;
    assert!(before < plan.len(), "stored {before}");
    assert!(plan.iter().all(|a| a.state == ArticleState::Planned));
    assert_eq!(rig.bridge.catalog.mark_batches.get(), 0);
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.stage, OutboxStage::Post);
    assert_eq!(outbox.token, thief.token);
    assert!(rig.bridge.jobs.sent().is_empty());
    assert_eq!(rig.bridge.nntp.live(), 0);

    let job = rig.job(&s).await;
    assert_eq!(rig.bridge.post_stage(&thief, &job).await, JobOutcome::Ack);
    let done = rig.plan(&s).await;
    assert!(all_posted_by(&done, "p0"));
    assert_eq!(id_set(&done), id_set(&plan));
    assert_eq!(stored(&rig, 0).await, id_set(&plan));
}

/// The lease is taken over (no time passes, so no renewal notices) while
/// the sockets post on. The one write that would record the articles is
/// refused as a whole.
#[tokio::test]
async fn stolen_lease_refuses_the_whole_batch() {
    let rig = rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    let outcome = rig
        .run_post_and(&s, 0, 2, async || {
            rig.bridge.catalog.edit(&s.extent, |e| e.outbox.token += 1);
        })
        .await;
    assert_eq!(outcome, JobOutcome::Ack);
    let plan = rig.plan(&s).await;
    assert!(plan.iter().all(|a| a.state == ArticleState::Planned));
    assert_eq!(rig.bridge.catalog.mark_batches.get(), 1);
    assert_eq!(
        rig.bridge.catalog.outbox(&s.extent).stage,
        OutboxStage::Post
    );
    assert!(rig.bridge.jobs.sent().is_empty());
}

/// The reply to one POST never arrives on one of four sockets. That
/// socket reconnects, finds the article with `STAT` and goes on; the
/// other sockets are not disturbed and nothing is stored twice.
#[tokio::test]
async fn lost_reply_on_one_socket_is_looked_up() {
    let rig = rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    rig.servers[0].drop_next_posts(1).await;
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let plan = rig.plan(&s).await;
    assert!(all_posted_by(&plan, "p0"));
    assert_eq!(stored(&rig, 0).await, id_set(&plan));
    // Four sockets and one reconnect.
    assert_eq!(rig.bridge.nntp.connects(), 5);
    assert_eq!(rig.bridge.nntp.peak(), 4);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// One socket of the job is refused by the provider's own connection
/// limit: the others finish the work and the job succeeds.
#[tokio::test]
async fn a_socket_without_a_provider_slot_leaves_the_rest_working() {
    let rig = rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;
    let addr = rig.servers[0].addr();
    let cfg = nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
    // Something else holds two of the account's five connections.
    let held = (dial(&cfg).await.unwrap(), dial(&cfg).await.unwrap());

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let plan = rig.plan(&s).await;
    assert!(all_posted_by(&plan, "p0"));
    assert_eq!(stored(&rig, 0).await, id_set(&plan));
    assert_eq!(rig.bridge.nntp.connects(), 3);
    held.0.quit().await;
    held.1.quit().await;
}

/// Two providers of one tier, each on its own backbone.
async fn spread_rig() -> Rig {
    rig(&[spec("bb0", 5), spec("bb1", 5)]).await
}

/// Every article is on exactly one of the two servers, and recorded
/// against the provider that has it.
async fn assert_posted_once(rig: &Rig, plan: &[ArticleRow]) {
    let on = [stored(rig, 0).await, stored(rig, 1).await];
    assert!(on[0].is_disjoint(&on[1]), "an article was posted twice");
    for row in plan {
        assert_eq!(row.state, ArticleState::Posted);
        let at = usize::from(row.provider_id.as_deref() == Some("p1"));
        assert!(on[at].contains(&format!("<{}>", row.message_id)));
    }
    assert_eq!(on[0].len() + on[1].len(), plan.len());
}

/// The sockets of a job spread over the providers of a tier and share
/// one queue: each article is posted once, to whichever provider's
/// socket was free.
#[tokio::test]
async fn articles_spread_over_the_providers_of_a_tier() {
    let rig = spread_rig().await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let plan = rig.plan(&s).await;
    assert_eq!(plan.len(), 10);
    assert_posted_once(&rig, &plan).await;
    assert!(rig.servers[0].posted_count().await > 0);
    assert!(rig.servers[1].posted_count().await > 0);
    // Four sockets in all, two on each provider.
    assert_eq!(rig.bridge.nntp.connects(), 4);
    assert_eq!(rig.bridge.nntp.peak(), 4);
    assert_eq!(rig.bridge.nntp.live(), 0);
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p0"], 2);
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p1"], 2);
    assert_eq!(rig.bridge.catalog.renewals.get(), 1);
    assert_eq!(rig.bridge.catalog.mark_batches.get(), 1);
    assert_eq!(
        rig.bridge.catalog.outbox(&s.extent).stage,
        OutboxStage::Verify
    );
}

/// Three providers and four sockets: every provider gets a socket.
#[tokio::test]
async fn sockets_go_round_the_providers() {
    let rig = rig(&[spec("bb0", 5), spec("bb1", 5), spec("bb2", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let peak = rig.bridge.catalog.permit_peak.borrow().clone();
    assert_eq!([peak["p0"], peak["p1"], peak["p2"]], [2, 1, 1]);
    let mut all = BTreeSet::new();
    for server in 0..3 {
        all.extend(stored(&rig, server).await);
    }
    let plan = rig.plan(&s).await;
    assert_eq!(all, id_set(&plan));
    assert_eq!(
        rig.servers[0].posted_count().await
            + rig.servers[1].posted_count().await
            + rig.servers[2].posted_count().await,
        10
    );
}

/// A job dies after posting and before recording. Its successor posts
/// the same message-ids: a provider that has an article answers
/// "duplicate" and stores nothing twice, and every article is recorded
/// once.
#[tokio::test]
async fn spread_post_is_idempotent_after_a_crash() {
    let rig = spread_rig().await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    rig.bridge.catalog.fail_mark_posted.set(1);
    assert!(matches!(rig.run_post(&s).await, JobOutcome::Retry { .. }));
    let planned = rig.plan(&s).await;
    assert!(planned.iter().all(|a| a.state == ArticleState::Planned));
    assert_eq!(
        rig.servers[0].posted_count().await + rig.servers[1].posted_count().await,
        10
    );

    rig.bridge.clock.advance_secs(LEASE_SECS + 1);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let plan = rig.plan(&s).await;
    assert_eq!(id_set(&plan), id_set(&planned));
    let on = [stored(&rig, 0).await, stored(&rig, 1).await];
    for row in &plan {
        assert_eq!(row.state, ArticleState::Posted);
        let at = usize::from(row.provider_id.as_deref() == Some("p1"));
        assert!(on[at].contains(&format!("<{}>", row.message_id)));
    }
}

/// A provider that refuses to post gives its articles back to the queue:
/// the other provider of the tier posts them all and the job succeeds.
#[tokio::test]
async fn a_refusing_provider_leaves_the_work_to_the_others() {
    let rig = spread_rig().await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    rig.servers[1].set_posting_allowed(false).await;
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let plan = rig.plan(&s).await;
    assert!(all_posted_by(&plan, "p0"));
    assert_eq!(stored(&rig, 0).await, id_set(&plan));
    assert_eq!(rig.servers[1].posted_count().await, 0);
    assert_eq!(rig.bridge.catalog.outbox(&s.extent).attempts, 1);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A provider without a free slot is passed over: the others take every
/// socket of the job.
#[tokio::test]
async fn a_provider_without_a_slot_is_passed_over() {
    let rig = spread_rig().await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;
    let p1 = &rig.bridge.cfg.providers[1];
    let now = rig.bridge.clock.now();
    let class = PermitClass::Background;
    while let Some(_held) = rig
        .bridge
        .catalog
        .acquire_permit(p1, class, "other", now)
        .await
        .unwrap()
    {}

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let plan = rig.plan(&s).await;
    assert!(all_posted_by(&plan, "p0"));
    assert_eq!(rig.servers[1].posted_count().await, 0);
    assert_eq!(rig.bridge.nntp.peak(), 4);
}

/// A lower tier is a backup, not more sockets: while the first tier
/// works, nothing is posted to it. When the first tier refuses, the
/// backup posts the lot.
#[tokio::test]
async fn a_lower_tier_is_only_a_backup() {
    let mut rig = spread_rig().await;
    rig.bridge.cfg.providers[1].priority = 1;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    assert_eq!(rig.servers[0].posted_count().await, 10);
    assert_eq!(rig.servers[1].posted_count().await, 0);

    rig.servers[0].set_posting_allowed(false).await;
    let s = rig.seed(2, &marked_plaintext(PLAIN_LEN)).await;
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let plan = rig.plan(&s).await;
    assert!(all_posted_by(&plan, "p1"));
    assert_eq!(rig.servers[1].posted_count().await, 10);
}

/// The lease is lost while two providers are being posted to: nothing is
/// recorded for either.
#[tokio::test]
async fn spread_post_with_a_stale_lease_writes_nothing() {
    let rig = spread_rig().await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    let thief = RefCell::new(None);
    let outcome = rig
        .run_post_and(&s, 1, 1, async || {
            rig.bridge.clock.advance_secs(LEASE_SECS + 1);
            *thief.borrow_mut() = rig.try_claim(&s, OutboxStage::Post).await;
        })
        .await;
    assert_eq!(outcome, JobOutcome::Ack);
    let thief = thief.into_inner().expect("the expired lease is claimable");
    let plan = rig.plan(&s).await;
    assert!(plan.iter().all(|a| a.state == ArticleState::Planned));
    assert_eq!(rig.bridge.catalog.mark_batches.get(), 0);
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(
        (outbox.stage, outbox.token),
        (OutboxStage::Post, thief.token)
    );
    assert!(rig.bridge.jobs.sent().is_empty());
}

/// A job with one article opens one socket. When the provider it picked
/// refuses the post, the other provider of the same tier gets it, in the
/// same run, whichever of the two refuses.
#[tokio::test]
async fn one_article_reaches_the_other_provider_of_the_tier() {
    for refusing in [0, 1] {
        let rig = spread_rig().await;
        let s = rig.seed(1, &[7; 1000]).await;
        rig.servers[refusing].set_posting_allowed(false).await;

        assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
        let plan = rig.plan(&s).await;
        assert_eq!(plan.len(), 1);
        assert!(all_posted_by(&plan, &format!("p{}", 1 - refusing)));
        assert_eq!(rig.servers[refusing].posted_count().await, 0);
        assert_eq!(stored(&rig, 1 - refusing).await, id_set(&plan));
        assert_eq!(rig.bridge.nntp.live(), 0);
    }
}

/// More providers in the tier than sockets in the job: the providers
/// that got no socket in the first round are asked when the first fail.
#[tokio::test]
async fn providers_beyond_the_socket_limit_are_asked_too() {
    let mut rig = rig(&[spec("bb0", 5), spec("bb1", 5), spec("bb2", 5)]).await;
    rig.bridge.cfg.post_sockets = 2;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;
    // Whichever two come first, at least one of them refuses.
    rig.servers[0].set_posting_allowed(false).await;
    rig.servers[1].set_posting_allowed(false).await;

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let plan = rig.plan(&s).await;
    assert!(all_posted_by(&plan, "p2"));
    assert_eq!(stored(&rig, 2).await, id_set(&plan));
    assert!(rig.bridge.nntp.peak() <= 2);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// One provider of the tier is at its account limit (its login is
/// refused), the other refuses the post. The busy one may still do the
/// work later: the job waits for it without spending an attempt, and
/// does not fall to the backup tier.
#[tokio::test]
async fn a_login_refused_for_the_limit_defers_the_job() {
    let mut rig = rig(&[spec("bb0", 5), spec("bb1", 5), spec("bb2", 5)]).await;
    rig.bridge.cfg.providers[2].priority = 1;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;
    let addr = rig.servers[0].addr();
    let cfg = nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
    // Something else holds every connection of the first account.
    let mut held = Vec::new();
    for _ in 0..5 {
        held.push(dial(&cfg).await.unwrap());
    }
    rig.servers[1].set_posting_allowed(false).await;

    let outcome = rig.run_post(&s).await;
    assert!(matches!(outcome, JobOutcome::Retry { delay_secs } if delay_secs < 120));
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!((outbox.stage, outbox.attempts), (OutboxStage::Post, 0));
    assert_eq!(outbox.last_error, None);
    for server in &rig.servers {
        assert_eq!(server.posted_count().await, 0);
    }
    assert_eq!(rig.bridge.nntp.live(), 0);

    // The account has room again: the same job finishes on it.
    for client in held {
        client.quit().await;
    }
    rig.bridge.clock.advance_secs(120);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    assert!(all_posted_by(&rig.plan(&s).await, "p0"));
    assert_eq!(rig.servers[2].posted_count().await, 0);
}

/// Every call to the provider is slow, each well inside its own time
/// limit, and together they take longer than a permit lasts. The lease
/// and the permits are renewed between the calls of one article, not
/// only between articles: no connect, lookup or POST starts on a renewal
/// older than the timer.
#[tokio::test]
async fn slow_calls_never_start_on_an_old_renewal() {
    let mut rig = rig(&[spec("bb0", 5)]).await;
    rig.bridge.cfg.post_sockets = 1;
    let s = rig.seed(1, &marked_plaintext(1_400_000)).await;
    // The first reply is lost: that article is looked up after a reconnect.
    rig.servers[0].drop_next_posts(1).await;
    rig.bridge.nntp.slow(&rig.bridge.clock, 55_000);

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let calls = rig.bridge.nntp.calls();
    let renewed = rig.bridge.catalog.renewed_at.borrow().clone();
    for what in ["connect", "stat", "post"] {
        assert!(calls.iter().any(|c| c.0 == what), "no {what} was made");
    }
    // In all they took longer than a permit lasts.
    assert!(calls.len() as i64 * 55_000 > i64::from(PERMIT_SECS) * 1000);
    for (what, at) in calls {
        let fresh = renewed.iter().any(|r| (0..20_000).contains(&(at.0 - r.0)));
        assert!(fresh, "{what} at {} started on an old renewal", at.0 - T0.0);
    }
    let plan = rig.plan(&s).await;
    assert!(all_posted_by(&plan, "p0"));
    assert_eq!(stored(&rig, 0).await, id_set(&plan));
}
