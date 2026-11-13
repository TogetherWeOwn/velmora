//! The provider pool against in-process NNTP servers, one per provider:
//! priority, spread inside a tier, retention, cooldown and posting
//! failover.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::fetch::ColdFetch;
use velmora_bridge::*;

const PLAIN_LEN: usize = 1_500_000;
const DAY_SECS: u32 = 86_400;

/// `n` providers that post and read, each its own backbone and server.
async fn pool_rig(n: usize) -> Rig {
    const NAMES: [&str; 3] = ["bb0", "bb1", "bb2"];
    let specs: Vec<Spec> = (0..n)
        .map(|i| Spec {
            backbone: NAMES[i],
            post: true,
            max_conns: 2,
        })
        .collect();
    rig(&specs).await
}

/// A local port nothing listens on.
fn dead_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

impl Rig {
    fn set_priorities(&mut self, priorities: &[u8]) {
        for (p, priority) in self.bridge.cfg.providers.iter_mut().zip(priorities) {
            p.priority = *priority;
        }
    }

    /// Posts through `p0`, copies the articles to every server in `to`
    /// and removes the safety copy: Usenet is the only source left.
    async fn posted_on(&self, n: u8, to: &[usize]) -> (Seeded, Vec<ArticleRow>) {
        let s = self.seed(n, &marked_plaintext(PLAIN_LEN)).await;
        let plan = self.post(&s).await;
        assert!(plan.iter().all(|a| a.provider_id.as_deref() == Some("p0")));
        for &i in to {
            self.propagate(&s, 0, i).await;
        }
        self.bridge
            .safety
            .delete(&s.extent.safety_key())
            .await
            .unwrap();
        (s, plan)
    }

    async fn fetch(&self, s: &Seeded) -> ColdFetch {
        let extent = self.bridge.catalog.extent(&s.extent);
        self.bridge.fetch_cold(&extent).await.unwrap()
    }

    async fn load(&self, i: usize) -> ProviderLoad {
        let id = format!("p{i}");
        let now = self.bridge.clock.now();
        let all = self.bridge.catalog.provider_load(now).await.unwrap();
        let found = all.into_iter().find(|l| l.provider_id == id);
        found.unwrap_or(ProviderLoad {
            provider_id: id,
            held: 0,
            uses: 0,
            failures: 0,
            cooldowns: 0,
            cooldown_until: UnixMs(0),
        })
    }

    /// Connection slots handed out for provider `i` so far.
    async fn uses(&self, i: usize) -> u64 {
        self.load(i).await.uses
    }

    async fn cooling(&self, i: usize) -> bool {
        self.load(i).await.cooldown_until > self.bridge.clock.now()
    }

    /// Points provider `i` at a port nothing listens on; returns the port
    /// it had.
    fn unplug(&mut self, i: usize) -> u16 {
        core::mem::replace(&mut self.bridge.cfg.providers[i].port, dead_port())
    }
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// The lower `priority` number is asked first, whatever the list order;
/// the other provider is not contacted while the first one serves.
#[tokio::test]
async fn reads_follow_priority() {
    let mut rig = pool_rig(2).await;
    let (s, _) = rig.posted_on(1, &[1]).await;

    rig.set_priorities(&[1, 0]);
    let before = (rig.uses(0).await, rig.uses(1).await);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.uses(0).await, before.0);
    assert_eq!(rig.uses(1).await, before.1 + 1);

    rig.set_priorities(&[0, 1]);
    let before = (rig.uses(0).await, rig.uses(1).await);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.uses(0).await, before.0 + 1);
    assert_eq!(rig.uses(1).await, before.1);

    // A disabled provider is never asked, first priority or not.
    rig.bridge.cfg.providers[0].enabled = false;
    let before = rig.uses(0).await;
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.uses(0).await, before);
}

/// Inside a tier the provider with more free slots goes first, and equal
/// providers take turns.
#[tokio::test]
async fn reads_spread_inside_a_tier() {
    let rig = pool_rig(3).await;
    let (s, _) = rig.posted_on(2, &[1, 2]).await;
    let now = rig.bridge.clock.now();
    let catalog = &rig.bridge.catalog;

    // p0 and p1 each have a connection in use: p2 is the freest.
    let mut busy = Vec::new();
    for i in [0, 1] {
        let p = &rig.bridge.cfg.providers[i];
        let permit = catalog.acquire_permit(p, PermitClass::Read, "t", now);
        busy.push(permit.await.unwrap().expect("free slot"));
    }
    let before = rig.uses(2).await;
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.uses(2).await, before + 1);
    for permit in &busy {
        catalog.release_permit(permit).await.unwrap();
    }

    // All idle: nine reads are shared out evenly.
    let before = [rig.uses(0).await, rig.uses(1).await, rig.uses(2).await];
    for _ in 0..9 {
        assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    }
    let after = [rig.uses(0).await, rig.uses(1).await, rig.uses(2).await];
    let total: u64 = (0..3).map(|i| after[i] - before[i]).sum();
    assert_eq!(total, 9);
    let most = (0..3).map(|i| after[i]).max().unwrap();
    let least = (0..3).map(|i| after[i]).min().unwrap();
    assert!(most - least <= 1, "uneven: {before:?} -> {after:?}");
}

/// An article the first provider lacks comes from the next one; the
/// first provider is not marked unhealthy for a `430`.
#[tokio::test]
async fn article_missing_on_one_provider_is_read_from_the_next() {
    let mut rig = pool_rig(2).await;
    rig.set_priorities(&[0, 1]);
    let (s, plan) = rig.posted_on(3, &[1]).await;
    rig.servers[0].hide(&plan[1].message_id).await;

    let before = (rig.uses(0).await, rig.uses(1).await);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.uses(0).await, before.0 + 1);
    assert_eq!(rig.uses(1).await, before.1 + 1);
    assert_eq!(rig.load(0).await.failures, 0);

    // Gone from both: the extent cannot be completed.
    rig.servers[1].hide(&plan[1].message_id).await;
    assert_eq!(rig.fetch(&s).await, ColdFetch::Unavailable);
    assert_eq!(rig.load(0).await.failures, 0);
    assert_eq!(rig.load(1).await.failures, 0);
}

/// A provider is not asked for an article older than its retention.
#[tokio::test]
async fn reads_skip_a_provider_past_its_retention() {
    let mut rig = pool_rig(2).await;
    rig.set_priorities(&[0, 1]);
    rig.bridge.cfg.providers[0].retention_days = Some(10);
    let (s, _) = rig.posted_on(4, &[1]).await;

    // Nine days old: p0 still serves it.
    rig.bridge.clock.advance_secs(9 * DAY_SECS);
    let before = (rig.uses(0).await, rig.uses(1).await);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(
        (rig.uses(0).await, rig.uses(1).await),
        (before.0 + 1, before.1)
    );

    // Eleven days old: p0 is skipped without a connection.
    rig.bridge.clock.advance_secs(2 * DAY_SECS);
    let before = (rig.uses(0).await, rig.uses(1).await);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(
        (rig.uses(0).await, rig.uses(1).await),
        (before.0, before.1 + 1)
    );

    // Verification reads the long-retention provider too.
    rig.bridge.cfg.providers[1].backbone = "bb0".to_string();
    let lease = rig.claim(&s, OutboxStage::Verify).await;
    let job = rig.job(&s).await;
    let before = (rig.uses(0).await, rig.uses(1).await);
    rig.bridge.verify_stage(&lease, &job).await;
    assert_eq!(
        (rig.uses(0).await, rig.uses(1).await),
        (before.0, before.1 + 1)
    );
    let seen = rig.bridge.catalog.verifications(&s.extent);
    assert_eq!(seen.last().unwrap().provider_id, "p1");
}

// ---------------------------------------------------------------------------
// Cooldown
// ---------------------------------------------------------------------------

/// Three sessions in a row that cannot connect put the provider in a
/// cooldown: it is skipped until the cooldown ends, the wait doubles when
/// it fails again, and one good session clears the record.
#[tokio::test]
async fn provider_cools_down_after_repeated_failures_and_recovers() {
    let mut rig = pool_rig(2).await;
    rig.set_priorities(&[0, 1]);
    let (s, _) = rig.posted_on(5, &[1]).await;
    let port = rig.unplug(0);

    // Each read tries p0 first, fails over to p1 and still succeeds.
    for strike in 1..=3u32 {
        assert!(!rig.cooling(0).await);
        let before = rig.uses(0).await;
        assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
        assert_eq!(rig.uses(0).await, before + 1, "strike {strike}");
    }
    let start = rig.bridge.clock.now();
    let load = rig.load(0).await;
    assert_eq!(load.cooldown_until, start.plus_secs(60));
    assert_eq!(rig.load(1).await.failures, 0);

    // Cooling: p0 is not asked at all.
    let before = rig.uses(0).await;
    rig.bridge.clock.advance_secs(59);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.uses(0).await, before);

    // Back after a minute, still broken: one failure, two minutes.
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.uses(0).await, before + 1);
    let now = rig.bridge.clock.now();
    assert_eq!(rig.load(0).await.cooldown_until, now.plus_secs(120));

    // Repaired: after the cooldown it serves again and the record clears.
    rig.bridge.cfg.providers[0].port = port;
    rig.bridge.clock.advance_secs(120);
    let before = (rig.uses(0).await, rig.uses(1).await);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(
        (rig.uses(0).await, rig.uses(1).await),
        (before.0 + 1, before.1)
    );
    let load = rig.load(0).await;
    assert_eq!(
        (load.failures, load.cooldowns, load.cooldown_until),
        (0, 0, UnixMs(0))
    );
}

/// While the only provider that has an article cools down, the read is
/// "try again", never "the data is gone".
#[tokio::test]
async fn read_while_the_only_source_cools_is_retryable() {
    let mut rig = pool_rig(2).await;
    rig.set_priorities(&[0, 1]);
    // p1 never got the articles.
    let (s, _) = rig.posted_on(6, &[]).await;
    let port = rig.unplug(0);
    for _ in 0..3 {
        assert_eq!(rig.fetch(&s).await, ColdFetch::Interrupted);
    }
    assert!(rig.cooling(0).await);
    let before = rig.uses(0).await;
    assert_eq!(rig.fetch(&s).await, ColdFetch::Interrupted);
    assert_eq!(rig.uses(0).await, before);

    rig.bridge.cfg.providers[0].port = port;
    rig.bridge.clock.advance_secs(60);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
}

/// A cooling provider that no longer retains the missing article is not
/// worth waiting for: the answer is "unavailable", not "retry".
#[tokio::test]
async fn cooling_provider_past_its_retention_is_not_waited_for() {
    let mut rig = pool_rig(2).await;
    rig.set_priorities(&[0, 1]);
    let (s, plan) = rig.posted_on(12, &[1]).await;
    rig.servers[1].hide(&plan[0].message_id).await;
    rig.bridge.cfg.providers[0].retention_days = Some(10);
    rig.bridge.clock.advance_secs(11 * DAY_SECS);
    let now = rig.bridge.clock.now();
    for _ in 0..3 {
        let failed = rig.bridge.catalog.provider_failed("p0", now);
        failed.await.unwrap();
    }
    assert!(rig.cooling(0).await);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Unavailable);

    // Inside its retention the same cooling provider is worth a retry.
    rig.bridge.cfg.providers[0].retention_days = Some(12);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Interrupted);
}

// ---------------------------------------------------------------------------
// Posting
// ---------------------------------------------------------------------------

/// Posting goes to the first `post` provider by priority.
#[tokio::test]
async fn posting_follows_priority() {
    let mut rig = pool_rig(2).await;
    rig.set_priorities(&[1, 0]);
    let s = rig.seed(7, &marked_plaintext(PLAIN_LEN)).await;
    let plan = rig.post(&s).await;
    assert!(plan.iter().all(|a| a.provider_id.as_deref() == Some("p1")));
    assert_eq!(rig.servers[1].posted_count().await, plan.len());
    assert_eq!(rig.servers[0].posted_count().await, 0);
}

/// Posting spreads inside a tier like reading does: a provider whose
/// slots are all in use is passed over for another one of the same tier.
#[tokio::test]
async fn posting_spreads_inside_a_tier() {
    let rig = pool_rig(2).await;
    let now = rig.bridge.clock.now();
    let catalog = &rig.bridge.catalog;
    let p0 = &rig.bridge.cfg.providers[0];
    for _ in 0..2 {
        let permit = catalog.acquire_permit(p0, PermitClass::Read, "t", now);
        permit.await.unwrap().expect("free slot");
    }
    let s = rig.seed(8, &marked_plaintext(PLAIN_LEN)).await;
    let plan = rig.post(&s).await;
    assert!(plan.iter().all(|a| a.provider_id.as_deref() == Some("p1")));
    assert_eq!(rig.servers[0].posted_count().await, 0);
}

/// The pool's snapshot ranks a provider first, but the permit gate
/// refuses it (its free slot is reserved for reads): the post goes to
/// the next provider of the tier.
#[tokio::test]
async fn post_passes_over_a_tier_member_without_a_permit() {
    let mut rig = pool_rig(2).await;
    rig.bridge.cfg.providers[0].max_conns = 3;
    // One connection and so no read reserve: p1 has one free slot too.
    rig.bridge.cfg.providers[1].max_conns = 1;
    let now = rig.bridge.clock.now();
    let catalog = &rig.bridge.catalog;
    let (p0, p1) = (&rig.bridge.cfg.providers[0], &rig.bridge.cfg.providers[1]);
    // p1 has been used more, so p0 wins the tie on free slots.
    for _ in 0..4 {
        let permit = catalog.acquire_permit(p1, PermitClass::Read, "t", now);
        let permit = permit.await.unwrap().expect("free slot");
        catalog.release_permit(&permit).await.unwrap();
    }
    // p0: both background slots held, one slot left for reads only.
    for _ in 0..2 {
        let permit = catalog.acquire_permit(p0, PermitClass::Background, "t", now);
        permit.await.unwrap().expect("free slot");
    }

    let s = rig.seed(9, &marked_plaintext(PLAIN_LEN)).await;
    let plan = rig.post(&s).await;
    assert!(plan.iter().all(|a| a.provider_id.as_deref() == Some("p1")));
    assert_eq!(rig.servers[1].posted_count().await, plan.len());
    assert_eq!(rig.servers[0].posted_count().await, 0);
}

/// A lower tier is a backup, not overflow: while the tier above is only
/// busy, the job waits and nothing is posted further down.
#[tokio::test]
async fn post_does_not_drop_a_tier_when_the_top_one_is_busy() {
    let mut rig = pool_rig(2).await;
    rig.set_priorities(&[0, 1]);
    let now = rig.bridge.clock.now();
    let p0 = &rig.bridge.cfg.providers[0];
    for _ in 0..2 {
        let permit = rig
            .bridge
            .catalog
            .acquire_permit(p0, PermitClass::Read, "t", now);
        permit.await.unwrap().expect("free slot");
    }
    let s = rig.seed(10, &marked_plaintext(PLAIN_LEN)).await;
    let attempts = rig.bridge.catalog.outbox(&s.extent).attempts;
    assert!(matches!(rig.run_post(&s).await, JobOutcome::Retry { .. }));
    assert_eq!(rig.bridge.catalog.outbox(&s.extent).attempts, attempts);
    assert_eq!(rig.servers[0].posted_count().await, 0);
    assert_eq!(rig.servers[1].posted_count().await, 0);
}

/// Every provider that could post is cooling: the job waits for the
/// cooldown without spending an attempt and without a connection.
#[tokio::test]
async fn post_waits_while_every_poster_cools() {
    let mut rig = pool_rig(1).await;
    let port = rig.unplug(0);
    let s = rig.seed(11, &marked_plaintext(PLAIN_LEN)).await;
    // Three failed runs, an hour apart: the third starts the cooldown.
    for run in 0..3 {
        assert!(!rig.cooling(0).await);
        assert!(matches!(rig.run_post(&s).await, JobOutcome::Retry { .. }));
        if run < 2 {
            rig.bridge.clock.advance_secs(3600);
        }
    }
    assert!(rig.cooling(0).await);
    let until = rig.load(0).await.cooldown_until;
    rig.bridge.clock.set(until.plus_ms(-30_000));
    rig.bridge.catalog.edit(&s.extent, |e| {
        e.outbox.next_at = UnixMs(0);
        e.outbox.lease_until = None;
    });
    let attempts = rig.bridge.catalog.outbox(&s.extent).attempts;
    let uses = rig.uses(0).await;
    assert_eq!(rig.run_post(&s).await, JobOutcome::Retry { delay_secs: 30 });
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.attempts, attempts);
    assert_eq!(outbox.next_at, until);
    assert_eq!(rig.uses(0).await, uses);

    // Repaired and cooled down: the post goes through.
    rig.bridge.cfg.providers[0].port = port;
    rig.bridge.clock.set(until);
    rig.bridge
        .catalog
        .edit(&s.extent, |e| e.outbox.lease_until = None);
    let plan = rig.post(&s).await;
    assert!(plan.iter().all(|a| a.state == ArticleState::Posted));
    assert!(!rig.cooling(0).await);
}
