//! Post stage with several sockets and several providers at once: every
//! article is posted once, the permit gate bounds the sockets, and a
//! stale lease writes nothing however many sockets are posting.

mod nntp_support;

use std::cell::{Cell, RefCell};
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

/// One socket, and the provider it goes to refuses the login because its
/// account is full: the other provider of the tier does the work in the
/// same run, whichever of the two is full.
#[tokio::test]
async fn a_full_account_leaves_the_work_to_the_rest_of_the_tier() {
    for full in [0, 1] {
        let mut rig = spread_rig().await;
        rig.bridge.cfg.post_sockets = 1;
        let s = rig.seed(1, &marked_plaintext(1_400_000)).await;
        let addr = rig.servers[full].addr();
        let cfg = nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(dial(&cfg).await.unwrap());
        }

        let connects = || events().iter().filter(|e| **e == "connect").count();
        let before = connects();
        assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
        let plan = rig.plan(&s).await;
        assert!(all_posted_by(&plan, &format!("p{}", 1 - full)));
        assert_eq!(rig.servers[full].posted_count().await, 0);
        // The first provider in order is asked first. When it is the full
        // one: one login there, refused and not tried again, and one on
        // the other.
        assert_eq!(connects() - before, if full == 0 { 2 } else { 1 });
        assert_eq!(rig.bridge.nntp.live(), 0);
        for client in held {
            client.quit().await;
        }
    }
}

/// A provider that had no slot when the job began gets one while the
/// other is refusing, is asked, and refuses too. Now every provider of
/// the tier was asked and failed, none is busy any more: the backup tier
/// posts the lot instead of the job waiting.
#[tokio::test]
async fn a_provider_that_was_busy_and_then_failed_does_not_hold_the_job() {
    let mut rig = rig(&[spec("bb0", 5), spec("bb1", 5), spec("bb2", 5)]).await;
    rig.bridge.cfg.providers[2].priority = 1;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;
    rig.servers[0].set_posting_allowed(false).await;
    rig.servers[1].set_posting_allowed(false).await;
    // Another job holds every slot of the first provider.
    let p0 = &rig.bridge.cfg.providers[0];
    let now = rig.bridge.clock.now();
    let mut held = Vec::new();
    while let Some(permit) = rig
        .bridge
        .catalog
        .acquire_permit(p0, PermitClass::Background, "other", now)
        .await
        .unwrap()
    {
        held.push(permit);
    }
    // It gives them back just after this job was turned away.
    rig.bridge
        .catalog
        .free_after_refusal
        .borrow_mut()
        .extend(held);

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let plan = rig.plan(&s).await;
    assert!(all_posted_by(&plan, "p2"));
    assert_eq!(rig.servers[2].posted_count().await, 10);
}

/// The reply to a POST is lost, and after the reconnect the provider
/// neither shows the article yet nor takes it again. The article may be
/// on its way to the other backbones all the same, so the backup
/// provider is asked for it before it is sent there.
#[tokio::test]
async fn a_lost_reply_is_remembered_across_providers() {
    let mut rig = spread_rig().await;
    rig.bridge.cfg.providers[1].priority = 1;
    rig.bridge.cfg.post_sockets = 1;
    let s = rig.seed(1, &marked_plaintext(400_000)).await;
    rig.servers[0].drop_next_posts(1).await;
    rig.servers[0].set_stat_lag(true).await;
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);

    let refuse = async || rig.servers[0].set_posting_allowed(false).await;
    assert_eq!(rig.run_post_and(&s, 0, 1, refuse).await, JobOutcome::Ack);

    let calls: Vec<&str> = rig.bridge.nntp.calls().iter().map(|c| c.0).collect();
    assert_eq!(
        calls,
        ["connect", "post", "connect", "stat", "post", "connect", "stat", "post"]
    );
    let plan = rig.plan(&s).await;
    assert_eq!(plan.len(), 1);
    assert!(all_posted_by(&plan, "p1"));
}

/// The catalogue fails while a job records its first article. The job
/// stops, and what the provider had accepted by then is still recorded
/// on the way out, under the same fenced lease.
#[tokio::test]
async fn accepted_articles_are_recorded_after_a_catalogue_failure() {
    let mut rig = rig(&[spec("bb0", 5)]).await;
    rig.bridge.cfg.post_sockets = 1;
    let s = rig.seed(1, &marked_plaintext(1_400_000)).await;
    // Slow calls: the job records what it has between two articles.
    rig.bridge.nntp.slow(&rig.bridge.clock, 25_000);
    rig.bridge.catalog.fail_mark_posted.set(1);

    assert!(matches!(rig.run_post(&s).await, JobOutcome::Retry { .. }));

    let plan = rig.plan(&s).await;
    assert!(plan.len() >= 2);
    let posted = plan.iter().filter(|a| a.state == ArticleState::Posted);
    assert_eq!(posted.count(), 1);
    assert_eq!(rig.servers[0].posted_count().await, 1);
    assert_eq!(rig.bridge.catalog.mark_batches.get(), 2);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// The same, with the lease lost instead: nothing is recorded, on the
/// way out either.
#[tokio::test]
async fn a_stale_lease_records_nothing_on_the_way_out() {
    let mut rig = rig(&[spec("bb0", 5)]).await;
    rig.bridge.cfg.post_sockets = 1;
    let s = rig.seed(1, &marked_plaintext(1_400_000)).await;
    rig.bridge.nntp.slow(&rig.bridge.clock, 25_000);
    rig.bridge
        .catalog
        .fault
        .set(Some(Fault::StealLeaseBefore(0)));

    rig.run_post(&s).await;

    let plan = rig.plan(&s).await;
    assert!(plan.iter().all(|a| a.state == ArticleState::Planned));
    assert_eq!(rig.servers[0].posted_count().await, 1);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// Every slot of the first tier is taken: the job gives its lease back
/// before it loads the extent, and no plan is written.
#[tokio::test]
async fn a_job_without_a_slot_does_not_load_the_extent() {
    let mut rig = rig(&[spec("bb0", 5), spec("bb1", 5)]).await;
    rig.bridge.cfg.providers[1].priority = 1;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;
    let p0 = &rig.bridge.cfg.providers[0];
    let now = rig.bridge.clock.now();
    let mut held = Vec::new();
    while let Some(permit) = rig
        .bridge
        .catalog
        .acquire_permit(p0, PermitClass::Background, "other", now)
        .await
        .unwrap()
    {
        held.push(permit);
    }
    let reads = rig.bridge.safety.gets();

    assert!(matches!(rig.run_post(&s).await, JobOutcome::Retry { .. }));

    assert_eq!(rig.bridge.safety.gets(), reads);
    assert!(rig.plan(&s).await.is_empty());
    assert_eq!(rig.bridge.nntp.connects(), 0);
    // The backup tier was not touched, and the job holds nothing.
    assert_eq!(rig.servers[1].posted_count().await, 0);
    for permit in held {
        rig.bridge.catalog.release_permit(&permit).await.unwrap();
    }
    // The job was put off, not failed: it runs when it is due again.
    assert_eq!(rig.bridge.catalog.outbox(&s.extent).attempts, 0);
    rig.bridge.clock.advance_secs(600);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    assert!(all_posted_by(&rig.plan(&s).await, "p0"));
}

/// Two sockets. While one has a POST in flight, the permits are taken
/// over and the other socket's renewal finds them gone. The first socket
/// makes no call after its POST returns, and the article that POST
/// delivered is recorded: marking is fenced by the lease, not the permit.
#[tokio::test]
async fn a_socket_that_lost_its_permit_mid_post_stops_and_is_recorded() {
    let mut rig = rig(&[spec("bb0", 5)]).await;
    rig.bridge.cfg.post_sockets = 2;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    // The first POST to be answered stays in flight.
    let release = rig.bridge.nntp.park_next_post();
    let calls_then = Cell::new(0);
    let renewed_in_flight = Cell::new(false);

    let revoke = async || {
        let renewals = rig.bridge.catalog.renewals.get();
        rig.bridge.catalog.revoke_permits();
        // Old enough for the other socket to renew before its next call.
        rig.bridge.clock.advance_secs(30);
        calls_then.set(rig.bridge.nntp.calls().len());
        // Bounded: a job that never renews fails the test, not hangs it.
        for _ in 0..1_000_000 {
            if rig.bridge.catalog.renewals.get() != renewals {
                renewed_in_flight.set(true);
                break;
            }
            tokio::task::yield_now().await;
        }
        release.set(true);
    };
    let outcome = rig.run_post_and(&s, 0, 2, revoke).await;

    // Put off for a slot, not failed.
    assert!(matches!(outcome, JobOutcome::Retry { .. }));
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!((outbox.stage, outbox.attempts), (OutboxStage::Post, 0));
    assert!(release.get(), "the permits were never taken over");
    assert!(
        renewed_in_flight.get(),
        "no renewal while the POST was in flight"
    );
    // No call began after the takeover, on either socket.
    let calls = rig.bridge.nntp.calls();
    assert_eq!(calls.len(), calls_then.get(), "{calls:?}");
    // Every article a provider took is recorded, the parked one included.
    let plan = rig.plan(&s).await;
    let on_server = stored(&rig, 0).await;
    assert!(on_server.len() >= 2 && on_server.len() < plan.len());
    let posted: BTreeSet<String> = plan
        .iter()
        .filter(|a| a.state == ArticleState::Posted)
        .map(|a| format!("<{}>", a.message_id))
        .collect();
    assert_eq!(posted, on_server);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// An account that allows one source address and six connections: one
/// job is one address, and it posts on as many sockets as `POST_SOCKETS`
/// and the connection limit give it.
#[tokio::test]
async fn one_address_carries_every_socket_of_a_job() {
    let mut rig = rig(&[spec("bb0", 6)]).await;
    rig.bridge.cfg.providers[0].max_ips = Some(1);
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    assert!(all_posted_by(&rig.plan(&s).await, "p0"));
    assert_eq!(rig.bridge.nntp.connects(), 4);
    assert_eq!(rig.bridge.nntp.peak(), 4);
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p0"], 4);
    assert_eq!(rig.bridge.catalog.holder_peak.borrow()["p0"], 1);

    // More sockets than the account has connections: all six. No read
    // can connect from a second address, so none is kept back for one.
    rig.bridge.cfg.post_sockets = 8;
    let s = rig.seed(2, &marked_plaintext(PLAIN_LEN)).await;
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    assert_eq!(rig.bridge.nntp.peak(), 6);
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p0"], 6);
    assert_eq!(rig.bridge.catalog.holder_peak.borrow()["p0"], 1);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// Three jobs at once on an account with one address: one of them posts,
/// on all its sockets, and the others are put off without an attempt,
/// although the account has connections to spare. They run once the
/// address is free.
#[tokio::test]
async fn overlapping_jobs_share_addresses_not_only_connections() {
    let mut rig = rig(&[spec("bb0", 12)]).await;
    rig.bridge.cfg.providers[0].max_ips = Some(1);
    let mut seeded = Vec::new();
    for n in 1..=3 {
        seeded.push(rig.seed(n, &marked_plaintext(PLAIN_LEN)).await);
    }

    let outcomes = tokio::join!(
        rig.run_post(&seeded[0]),
        rig.run_post(&seeded[1]),
        rig.run_post(&seeded[2]),
    );
    let outcomes = [outcomes.0, outcomes.1, outcomes.2];
    assert_eq!(outcomes[0], JobOutcome::Ack);
    for (outcome, s) in outcomes.iter().zip(&seeded).skip(1) {
        assert!(
            matches!(outcome, JobOutcome::Retry { delay_secs } if (15..=60).contains(delay_secs))
        );
        let outbox = rig.bridge.catalog.outbox(&s.extent);
        assert_eq!((outbox.stage, outbox.attempts), (OutboxStage::Post, 0));
        assert_eq!(outbox.last_error, None);
    }
    assert_eq!(rig.bridge.catalog.holder_peak.borrow()["p0"], 1);
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p0"], 4);
    assert_eq!(rig.bridge.nntp.peak(), 4);
    assert_eq!(rig.bridge.nntp.connects(), 4);
    assert_eq!(rig.servers[0].posted_count().await, 10);

    rig.bridge.clock.advance_secs(60);
    assert_eq!(rig.run_post(&seeded[1]).await, JobOutcome::Ack);
    assert_eq!(rig.servers[0].posted_count().await, 20);
}

/// With three addresses, two go to jobs and one stays for reads: two
/// jobs post at once on four sockets each, and the third waits.
#[tokio::test]
async fn jobs_leave_an_address_for_reads() {
    let mut rig = rig(&[spec("bb0", 16)]).await;
    rig.bridge.cfg.providers[0].max_ips = Some(3);
    let mut seeded = Vec::new();
    for n in 1..=3 {
        seeded.push(rig.seed(n, &marked_plaintext(PLAIN_LEN)).await);
    }

    let (a, b, c) = tokio::join!(
        rig.run_post(&seeded[0]),
        rig.run_post(&seeded[1]),
        rig.run_post(&seeded[2]),
    );
    assert_eq!([a, b], [JobOutcome::Ack, JobOutcome::Ack]);
    assert!(matches!(c, JobOutcome::Retry { .. }));
    assert_eq!(rig.bridge.catalog.outbox(&seeded[2].extent).attempts, 0);
    assert_eq!(rig.bridge.catalog.holder_peak.borrow()["p0"], 2);
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p0"], 8);
    assert_eq!(rig.bridge.nntp.peak(), 8);
}

/// The one address of an account passes to someone else while a job is
/// posting on two sockets. The job stops at its next renewal: it does
/// not dial again and takes no slot back, which would make it a second
/// address.
#[tokio::test]
async fn a_job_that_lost_its_address_stops() {
    let mut rig = rig(&[spec("bb0", 6)]).await;
    rig.bridge.cfg.providers[0].max_ips = Some(1);
    rig.bridge.cfg.post_sockets = 2;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    let release = rig.bridge.nntp.park_next_post();
    let calls_then = Cell::new(0);

    let revoke = async || {
        let renewals = rig.bridge.catalog.renewals.get();
        rig.bridge.catalog.revoke_permits();
        rig.bridge.clock.advance_secs(30);
        calls_then.set(rig.bridge.nntp.calls().len());
        for _ in 0..1_000_000 {
            if rig.bridge.catalog.renewals.get() != renewals {
                break;
            }
            tokio::task::yield_now().await;
        }
        release.set(true);
    };
    let outcome = rig.run_post_and(&s, 0, 2, revoke).await;

    assert!(matches!(outcome, JobOutcome::Retry { .. }));
    assert!(release.get(), "the permits were never taken over");
    assert_eq!(rig.bridge.catalog.outbox(&s.extent).attempts, 0);
    let calls = rig.bridge.nntp.calls();
    assert_eq!(calls.len(), calls_then.get(), "{calls:?}");
    assert_eq!(rig.bridge.nntp.connects(), 2);
    assert_eq!(rig.bridge.nntp.live(), 0);
    // The address is still the other holder's: the job has no slot.
    let load = rig
        .bridge
        .catalog
        .provider_load(rig.bridge.clock.now())
        .await
        .unwrap();
    assert_eq!((load[0].held, load[0].holders), (2, 1));
    assert!(rig.plan(&s).await.iter().any(|a| a.posted_at.is_none()));

    // The next run of the same job and stage is another invocation, so
    // another address: it has a name of its own, and waits for the
    // address like anybody else.
    let first = rig.bridge.catalog.granted.borrow().clone();
    rig.bridge.clock.advance_secs(600);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let granted = rig.bridge.catalog.granted.borrow();
    let names = |all: &[(String, String)]| -> BTreeSet<String> {
        all.iter().map(|(_, holder)| holder.clone()).collect()
    };
    let (before, after) = (names(&first), names(&granted[first.len()..]));
    assert_eq!((before.len(), after.len()), (1, 1), "{granted:?}");
    assert!(before.is_disjoint(&after), "{granted:?}");
    let job = format!("job:{}:", s.extent);
    assert!(before.union(&after).all(|name| name.starts_with(&job)));
}

/// A job asks for its slots in passes, all requests of a pass at once: a
/// provider it has no slot from yet is asked for one, then the rest are
/// asked for together. No request is made twice.
#[tokio::test]
async fn a_job_asks_for_its_slots_together() {
    let two = rig(&[spec("bb0", 5), spec("bb0", 5)]).await;
    two.bridge.catalog.acquire_takes_a_turn.set(true);
    let s = two.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    assert_eq!(two.run_post(&s).await, JobOutcome::Ack);

    // One for each provider, then the other two together.
    assert_eq!(two.bridge.catalog.acquire_peak.get(), 2);
    let asked = events().iter().filter(|e| **e == "acquire").count();
    assert_eq!(asked, 4);
    let peak = two.bridge.catalog.permit_peak.borrow().clone();
    assert_eq!((peak["p0"], peak["p1"]), (2, 2));
    assert_eq!(two.bridge.catalog.permit_refusals.get(), 0);

    // One provider (one of its five slots stays reserved for reads): one
    // request, then three at once.
    let one = rig(&[spec("bb0", 5)]).await;
    one.bridge.catalog.acquire_takes_a_turn.set(true);
    let s = one.seed(2, &marked_plaintext(PLAIN_LEN)).await;
    assert_eq!(one.run_post(&s).await, JobOutcome::Ack);
    assert_eq!(one.bridge.catalog.acquire_peak.get(), 3);
    assert_eq!(one.bridge.catalog.permit_peak.borrow()["p0"], 4);
}

/// The sockets connect while the extent is read and planned, and nothing
/// is posted before the plan is stored.
#[tokio::test]
async fn sockets_connect_while_the_extent_loads() {
    let rig = rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let events = events();
    let plan = events.iter().position(|e| *e == "plan").expect("planned");
    let connects: Vec<usize> = (0..events.len())
        .filter(|i| events[*i] == "connect")
        .collect();
    assert_eq!(connects.len(), 4);
    assert!(connects.iter().all(|at| *at < plan), "{events:?}");
    let posts: Vec<usize> = (0..events.len()).filter(|i| events[*i] == "post").collect();
    assert_eq!(posts.len(), 10);
    assert!(posts.iter().all(|at| *at > plan), "{events:?}");
    // The renewal the sockets connected under is the round's first.
    assert_eq!(rig.bridge.catalog.renewals.get(), 1);
    assert_eq!(rig.bridge.nntp.connects(), 4);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A post job leaves one record of its phases for the log: counts and
/// milliseconds, and nothing that names the extent.
#[tokio::test]
async fn a_post_job_leaves_its_timings() {
    let rig = rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;
    let job = Job::Extent {
        v: JOB_VERSION,
        extent: s.extent.clone(),
        generation: s.generation.clone(),
        stage: OutboxStage::Post,
    };

    assert_eq!(rig.bridge.run_job(&job).await, JobOutcome::Ack);

    let now = rig.bridge.clock.now();
    let trace = trace::take(&s.extent, now).expect("a record");
    assert_eq!((trace.sockets, trace.articles), (4, 10));
    let line = trace.to_string();
    assert!(!line.contains(s.extent.as_str()), "{line}");
    assert!(line.contains("sockets=4 articles=10"), "{line}");
    // Taken once.
    assert_eq!(trace::take(&s.extent, now), None);
}
