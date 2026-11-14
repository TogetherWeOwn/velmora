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
    async fn posted_on(&mut self, n: u8, to: &[usize]) -> (Seeded, Vec<ArticleRow>) {
        let s = self.seed(n, &marked_plaintext(PLAIN_LEN)).await;
        // For the post alone every other provider is a backup, so that
        // `p0` takes every article whatever tiers the test has set.
        let tiers: Vec<u8> = self
            .bridge
            .cfg
            .providers
            .iter()
            .map(|p| p.priority)
            .collect();
        for p in self.bridge.cfg.providers.iter_mut().skip(1) {
            p.priority = u8::MAX;
        }
        let plan = self.post(&s).await;
        self.set_priorities(&tiers);
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
            holders: 0,
            background_holders: 0,
            uses: 0,
            failures: 0,
            cooldowns: 0,
            cooldown_until: UnixMs(0),
            fault: None,
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
    let mut rig = pool_rig(3).await;
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

/// An article older than every reader's stated retention is still asked
/// for before the read gives up: the stated retention is an estimate.
#[tokio::test]
async fn article_past_every_retention_is_still_asked_for() {
    let mut rig = pool_rig(2).await;
    rig.bridge.cfg.providers[0].retention_days = Some(10);
    rig.bridge.cfg.providers[1].retention_days = Some(5);
    let (s, _) = rig.posted_on(21, &[]).await;
    rig.bridge.clock.advance_secs(11 * DAY_SECS);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
}

/// The provider answers the login with `482` because the account is at
/// its connection limit. That is "no slot", not a fault: the read reports
/// "busy", the post waits without spending an attempt, nothing goes to a
/// lower tier and the provider takes no strike.
#[tokio::test]
async fn login_refused_over_the_limit_is_no_slot_not_a_fault() {
    let mut rig = pool_rig(2).await;
    rig.set_priorities(&[0, 1]);
    let (s, _) = rig.posted_on(22, &[]).await;
    let to_post = rig.seed(23, &marked_plaintext(PLAIN_LEN)).await;

    // Someone else holds both of the account's connections on p0.
    rig.servers[0].set_limit_reply_482(true).await;
    let addr = rig.servers[0].addr();
    let cfg = nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
    let held = [dial(&cfg).await.unwrap(), dial(&cfg).await.unwrap()];

    assert_eq!(rig.fetch(&s).await, ColdFetch::Busy);
    let attempts = rig.bridge.catalog.outbox(&to_post.extent).attempts;
    assert!(matches!(
        rig.run_post(&to_post).await,
        JobOutcome::Retry { .. }
    ));
    let outbox = rig.bridge.catalog.outbox(&to_post.extent);
    assert_eq!(outbox.attempts, attempts);
    assert_eq!(rig.servers[1].posted_count().await, 0);
    let load = rig.load(0).await;
    assert_eq!((load.failures, load.cooldown_until), (0, UnixMs(0)));

    for client in held {
        client.quit().await;
    }
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
}

/// The replies providers give when the account is connected from as many
/// source addresses as it may be. Each is "no slot", like a full
/// account: the read reports "busy", the post waits without spending an
/// attempt, nothing goes to a lower tier and the provider takes no
/// strike, however often it happens.
#[tokio::test]
async fn login_refused_for_the_address_limit_is_no_slot_not_a_fault() {
    for reply in [
        "502 max number of simultaneous IPs (3) reached",
        "502 (max number of simultaneous IP addresses reached: 4)",
        "482 Already connected from different IP",
        "481 Exceeded maximum number of connections per user",
        "481 exceeded MAXIMUM number of connections (20)",
        "482 Too many connected hosts",
        "502 Too many sessions for user",
        "502 Session limit reached",
        "502 Too many connects",
        // The limit is what counts, not the reply code.
        "400 Too many connections",
    ] {
        let mut rig = pool_rig(2).await;
        rig.set_priorities(&[0, 1]);
        let (s, _) = rig.posted_on(22, &[]).await;
        let to_post = rig.seed(23, &marked_plaintext(PLAIN_LEN)).await;

        // The account is in use from elsewhere: p0 refuses every login.
        rig.servers[0].set_limit_reply(Some(reply)).await;
        let addr = rig.servers[0].addr();
        let cfg = nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
        let held = [dial(&cfg).await.unwrap(), dial(&cfg).await.unwrap()];

        // More often than the strikes that start a cooldown.
        for _ in 0..5 {
            assert_eq!(rig.fetch(&s).await, ColdFetch::Busy, "{reply}");
            let outcome = rig.run_post(&to_post).await;
            assert!(matches!(outcome, JobOutcome::Retry { .. }), "{reply}");
            rig.bridge.clock.advance_secs(120);
        }
        let outbox = rig.bridge.catalog.outbox(&to_post.extent);
        assert_eq!((outbox.attempts, &outbox.last_error), (0, &None), "{reply}");
        assert_eq!(rig.servers[1].posted_count().await, 0, "{reply}");
        let load = rig.load(0).await;
        assert_eq!(
            (load.failures, load.cooldowns, load.cooldown_until),
            (0, 0, UnixMs(0)),
            "{reply}"
        );
        assert_eq!(rig.bridge.nntp.live(), 0, "{reply}");

        for client in held {
            client.quit().await;
        }
        assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
        assert_eq!(rig.run_post(&to_post).await, JobOutcome::Ack);
    }
}

/// The provider refuses the login for the account itself: access denied,
/// a used-up quota, a suspended account, a login it no longer takes.
/// Waiting for a slot would never end, so this is a fault, not "no
/// slot": the read goes to the next provider, the post goes to the next
/// tier **in the same job**, and the provider takes a strike with the
/// reason `login_refused` and then cools down.
#[tokio::test]
async fn login_refused_for_the_account_is_a_strike_and_the_work_moves_on() {
    for reply in [
        "502 Access denied: quota exceeded, see your account page",
        "502 Account suspended",
        "502",
        "482 Authentication rejected",
        "481 Authentication failed",
        // A limit, but not one of connections: no slot will come free.
        "502 Download limit exceeded",
        // They mention a connection; what they refuse is the account.
        "502 Quota exceeded, closing connection",
        "481 Invalid login; max attempts exceeded, connection closed",
        "502 Block exhausted (unlimited connections plan)",
    ] {
        let mut rig = pool_rig(2).await;
        rig.set_priorities(&[0, 1]);
        let (s, _) = rig.posted_on(22, &[1]).await;
        let to_post = rig.seed(23, &marked_plaintext(PLAIN_LEN)).await;
        let had = rig.servers[1].posted_count().await;

        // p0 answers every login with `reply`.
        rig.servers[0].set_limit_reply(Some(reply)).await;
        let addr = rig.servers[0].addr();
        let cfg = nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
        let held = [dial(&cfg).await.unwrap(), dial(&cfg).await.unwrap()];

        // The post: p0 is the whole first tier and refuses, so the job
        // posts on the backup tier at once and is done.
        assert_eq!(rig.run_post(&to_post).await, JobOutcome::Ack, "{reply}");
        let plan = rig.bridge.catalog.articles(&to_post.extent).await.unwrap();
        assert!(!plan.is_empty(), "{reply}");
        for row in &plan {
            assert_eq!(row.state, ArticleState::Posted, "{reply}");
            assert_eq!(row.provider_id.as_deref(), Some("p1"), "{reply}");
        }
        assert_eq!(
            rig.servers[1].posted_count().await,
            had + plan.len(),
            "{reply}"
        );
        let load = rig.load(0).await;
        assert_eq!(
            (load.failures, load.fault, load.healthy()),
            (1, Some(ProviderFault::LoginRefused), false),
            "{reply}"
        );

        // The read: p0 is asked first and refuses, p1 has the articles.
        // The refusal is final for this read: one login, not a second
        // try on a new connection.
        let asked = rig.bridge.nntp.dials_to("p0");
        assert_eq!(
            rig.fetch(&s).await,
            ColdFetch::Filled(s.cipher.clone()),
            "{reply}"
        );
        assert_eq!(rig.bridge.nntp.dials_to("p0"), asked + 1, "{reply}");
        assert_eq!(rig.load(0).await.failures, 2, "{reply}");

        // The third strike starts the cooldown: p0 is left out.
        assert_eq!(
            rig.fetch(&s).await,
            ColdFetch::Filled(s.cipher.clone()),
            "{reply}"
        );
        let now = rig.bridge.clock.now();
        let load = rig.load(0).await;
        assert!(load.cooldown_until > now, "{reply}");
        assert_eq!(load.fault, Some(ProviderFault::LoginRefused), "{reply}");
        let asked = rig.bridge.nntp.dials_to("p0");
        assert_eq!(
            rig.fetch(&s).await,
            ColdFetch::Filled(s.cipher.clone()),
            "{reply}"
        );
        assert_eq!(rig.bridge.nntp.dials_to("p0"), asked, "{reply}");
        assert_eq!(rig.bridge.nntp.live(), 0, "{reply}");

        // The account is in order again: one good session after the
        // cooldown clears the strikes and the reason.
        rig.servers[0].set_limit_reply(None).await;
        for client in held {
            client.quit().await;
        }
        rig.bridge.clock.advance_secs(61);
        assert_eq!(
            rig.fetch(&s).await,
            ColdFetch::Filled(s.cipher.clone()),
            "{reply}"
        );
        let load = rig.load(0).await;
        assert_eq!((load.healthy(), load.fault), (true, None), "{reply}");
    }
}

/// A tier with a provider that refuses the login for its account and a
/// healthy one that is only out of slots still waits for the healthy
/// one: a lower tier is a backup for failure, not overflow.
#[tokio::test]
async fn a_refused_account_next_to_a_busy_provider_still_waits_for_the_tier() {
    let mut rig = pool_rig(3).await;
    rig.set_priorities(&[0, 0, 1]);
    let to_post = rig.seed(23, &marked_plaintext(PLAIN_LEN)).await;

    rig.servers[0]
        .set_limit_reply(Some("502 Account suspended"))
        .await;
    let held: Vec<_> = {
        let mut held = Vec::new();
        // p0 refuses for the account, p1 for its connection limit.
        for server in &rig.servers[..2] {
            let addr = server.addr();
            let cfg = nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
            held.push(dial(&cfg).await.unwrap());
            held.push(dial(&cfg).await.unwrap());
        }
        held
    };

    let outcome = rig.run_post(&to_post).await;
    assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
    assert_eq!(rig.bridge.catalog.outbox(&to_post.extent).attempts, 0);
    assert_eq!(rig.servers[2].posted_count().await, 0);
    let (refused, busy) = (rig.load(0).await, rig.load(1).await);
    assert_eq!(
        (refused.failures, refused.fault),
        (1, Some(ProviderFault::LoginRefused))
    );
    assert_eq!((busy.failures, busy.fault), (0, None));
    for client in held {
        client.quit().await;
    }
}

/// The only provider that has the articles refuses the login for its
/// account. Each read costs it one login until it cools down, and then
/// none: a read does not try a provider that cools for a refused login,
/// as it does one that cools for a failure that may be over.
#[tokio::test]
async fn reads_leave_a_provider_that_cools_for_a_refused_login_alone() {
    let rig = {
        let mut rig = pool_rig(1).await;
        let (s, _) = rig.posted_on(31, &[]).await;
        (rig, s)
    };
    let (rig, s) = rig;
    rig.servers[0]
        .set_limit_reply(Some("502 Account suspended"))
        .await;
    let addr = rig.servers[0].addr();
    let cfg = nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
    let held = [dial(&cfg).await.unwrap(), dial(&cfg).await.unwrap()];

    for strike in 1..=3 {
        assert!(!rig.cooling(0).await);
        let asked = rig.bridge.nntp.dials_to("p0");
        assert_eq!(rig.fetch(&s).await, ColdFetch::Interrupted);
        assert_eq!(rig.bridge.nntp.dials_to("p0"), asked + 1, "strike {strike}");
    }
    assert!(rig.cooling(0).await);
    let asked = rig.bridge.nntp.dials_to("p0");
    for _ in 0..10 {
        assert_eq!(rig.fetch(&s).await, ColdFetch::Interrupted);
    }
    assert_eq!(rig.bridge.nntp.dials_to("p0"), asked);
    for client in held {
        client.quit().await;
    }

    // The same with the account in order and only the record differing:
    // the reason decides, not the server.
    for (fault, probed) in [
        (ProviderFault::LoginRefused, false),
        (ProviderFault::ConnectRefused, true),
        (ProviderFault::SessionFailed, true),
    ] {
        let mut rig = pool_rig(1).await;
        let (s, _) = rig.posted_on(32, &[]).await;
        let now = rig.bridge.clock.now();
        for _ in 0..3 {
            let failed = rig.bridge.catalog.provider_failed("p0", fault, now);
            failed.await.unwrap();
        }
        assert!(rig.cooling(0).await);
        let asked = rig.bridge.nntp.dials_to("p0");
        let got = rig.fetch(&s).await;
        let dials = rig.bridge.nntp.dials_to("p0") - asked;
        if probed {
            assert_eq!((got, dials), (ColdFetch::Filled(s.cipher.clone()), 1));
        } else {
            assert_eq!((got, dials), (ColdFetch::Interrupted, 0), "{fault:?}");
        }
    }
}

/// A provider whose addresses are all in use is asked last in its tier,
/// however many connections it has free: the read goes to the other
/// provider at once instead of being refused a slot first.
#[tokio::test]
async fn a_provider_with_no_address_left_is_asked_last() {
    let mut rig = pool_rig(2).await;
    let (s, _) = rig.posted_on(2, &[1]).await;
    rig.bridge.cfg.providers[0].max_conns = 8;
    rig.bridge.cfg.providers[0].max_ips = Some(1);
    let now = rig.bridge.clock.now();
    let catalog = &rig.bridge.catalog;
    // p0 has seven connections free and its one address in use; p1 has
    // one connection free.
    let mut busy = Vec::new();
    for i in [0, 1] {
        let p = &rig.bridge.cfg.providers[i];
        let permit = catalog.acquire_permit(p, PermitClass::Read, "t", now);
        busy.push(permit.await.unwrap().expect("free slot"));
    }
    let (refused, before) = (catalog.permit_refusals.get(), rig.uses(1).await);

    for n in 1..=3 {
        assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
        assert_eq!(rig.uses(1).await, before + n);
    }
    assert_eq!(catalog.permit_refusals.get(), refused);

    // The address is free again: p0, with more room, goes first.
    catalog.release_permit(&busy[0]).await.unwrap();
    let before = rig.uses(0).await;
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.uses(0).await, before + 1);
}

/// A `481` that does not name a connection limit is a refused login: it
/// counts against the provider, and after three of them it cools down.
#[tokio::test]
async fn a_481_without_a_connection_limit_is_a_failed_login() {
    for reply in ["481 Authentication failed", "481 Too many bad logins"] {
        let mut rig = pool_rig(2).await;
        rig.set_priorities(&[0, 1]);
        let (s, _) = rig.posted_on(24, &[1]).await;
        rig.servers[0].set_limit_reply(Some(reply)).await;
        let addr = rig.servers[0].addr();
        let cfg = nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
        let _held = [dial(&cfg).await.unwrap(), dial(&cfg).await.unwrap()];

        for strike in 1..=3u32 {
            assert!(!rig.cooling(0).await, "{reply}");
            // The read is served by the provider below.
            assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
            let load = rig.load(0).await;
            assert_eq!(load.failures + 3 * load.cooldowns, strike, "{reply}");
        }
        assert!(rig.cooling(0).await, "{reply}");
    }
}

/// Two cold reads at once are two requests, so two addresses: on an
/// account that allows one, the second is told "busy" although a
/// connection is free. Without the limit both are served.
#[tokio::test]
async fn two_reads_at_once_are_two_addresses() {
    for max_ips in [Some(1), None] {
        let mut rig = pool_rig(1).await;
        let (s, _) = rig.posted_on(25, &[]).await;
        rig.bridge.cfg.providers[0].max_conns = 4;
        rig.bridge.cfg.providers[0].max_ips = max_ips;
        rig.bridge.catalog.granted.borrow_mut().clear();

        let (first, second) = tokio::join!(rig.fetch(&s), rig.fetch(&s));

        let filled = ColdFetch::Filled(s.cipher.clone());
        let busy = [&first, &second]
            .iter()
            .filter(|got| ***got == ColdFetch::Busy)
            .count();
        let served = [&first, &second]
            .iter()
            .filter(|got| ***got == filled)
            .count();
        let expected = if max_ips.is_some() { (1, 1) } else { (2, 0) };
        assert_eq!((served, busy), expected, "max_ips {max_ips:?}");
        // Each request that got a slot has a name of its own.
        let granted = rig.bridge.catalog.granted.borrow();
        let names: std::collections::BTreeSet<&str> =
            granted.iter().map(|(_, holder)| holder.as_str()).collect();
        assert_eq!(names.len(), served, "{granted:?}");
        assert!(names.iter().all(|name| name.starts_with("get:")));
        assert_eq!(rig.bridge.nntp.live(), 0);
    }
}

/// Jobs have one address fewer than reads. While a job is on a provider
/// that allows two, the next job is sent to the other provider of the
/// tier without being refused a slot first, and a read still starts
/// with the provider that has more room.
#[tokio::test]
async fn a_provider_with_no_address_left_for_jobs_is_asked_last_by_jobs() {
    let mut rig = pool_rig(2).await;
    let (s, _) = rig.posted_on(3, &[1]).await;
    rig.bridge.cfg.providers[0].max_conns = 8;
    rig.bridge.cfg.providers[0].max_ips = Some(2);
    // One socket a job, so that a refusal can only be for the address.
    rig.bridge.cfg.post_sockets = 1;
    let now = rig.bridge.clock.now();
    let catalog = &rig.bridge.catalog;
    let p0 = &rig.bridge.cfg.providers[0];
    let job = catalog.acquire_permit(p0, PermitClass::Background, "job:other", now);
    job.await.unwrap().expect("free slot");
    let load = rig.load(0).await;
    assert_eq!((load.holders, load.background_holders), (1, 1));
    let refused = catalog.permit_refusals.get();
    let on_first = rig.servers[0].posted_count().await;

    let before = rig.uses(0).await;
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.uses(0).await, before + 1);

    let to_post = rig.seed(4, &marked_plaintext(PLAIN_LEN)).await;
    let plan = rig.post(&to_post).await;
    assert!(plan.iter().all(|a| a.provider_id.as_deref() == Some("p1")));
    assert_eq!(rig.servers[0].posted_count().await, on_first);
    assert_eq!(catalog.permit_refusals.get(), refused);
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

/// Every reader is cooling: the read still gets one attempt, on the
/// provider that is due back first, instead of failing unasked.
#[tokio::test]
async fn read_tries_the_soonest_cooling_provider_when_all_cool() {
    let mut rig = pool_rig(2).await;
    let (s, _) = rig.posted_on(24, &[]).await;
    let now = rig.bridge.clock.now();
    // p1 trips twice (60 s, then 120 s from +60 s); p0 once at +100 s.
    let catalog = &rig.bridge.catalog;
    for at in [0, 0, 0, 60] {
        let failed = catalog.provider_failed("p1", ProviderFault::SessionFailed, now.plus_secs(at));
        failed.await.unwrap();
    }
    rig.bridge.clock.set(now.plus_secs(100));
    for _ in 0..3 {
        let failed =
            catalog.provider_failed("p0", ProviderFault::SessionFailed, now.plus_secs(100));
        failed.await.unwrap();
    }
    assert!(rig.cooling(0).await && rig.cooling(1).await);
    assert!(rig.load(0).await.cooldown_until < rig.load(1).await.cooldown_until);

    let before = (rig.uses(0).await, rig.uses(1).await);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(
        (rig.uses(0).await, rig.uses(1).await),
        (before.0 + 1, before.1)
    );
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
        let failed = rig
            .bridge
            .catalog
            .provider_failed("p0", ProviderFault::SessionFailed, now);
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

/// The first provider refuses the post: the same articles, under the
/// message-ids planned before the failure, go to the next provider.
#[tokio::test]
async fn post_fails_over_with_the_same_message_ids() {
    let mut rig = pool_rig(2).await;
    rig.set_priorities(&[0, 1]);
    let s = rig.seed(8, &marked_plaintext(PLAIN_LEN)).await;

    // Nobody accepts: the plan is stored, the job fails and will retry.
    rig.servers[0].set_posting_allowed(false).await;
    rig.servers[1].set_posting_allowed(false).await;
    assert!(matches!(rig.run_post(&s).await, JobOutcome::Retry { .. }));
    let planned = rig.plan(&s).await;
    assert!(planned.len() >= 2);
    assert!(planned.iter().all(|a| a.state == ArticleState::Planned));
    let ids = |rows: &[ArticleRow]| -> Vec<String> {
        rows.iter().map(|a| a.message_id.clone()).collect()
    };

    // p1 accepts again; p0 still refuses.
    rig.servers[1].set_posting_allowed(true).await;
    rig.bridge.clock.advance_secs(3600);
    let plan = rig.post(&s).await;
    assert_eq!(ids(&plan), ids(&planned));
    for (after, before) in plan.iter().zip(&planned) {
        assert_eq!(after.headers, before.headers);
        assert_eq!(after.state, ArticleState::Posted);
        assert_eq!(after.provider_id.as_deref(), Some("p1"));
    }
    let wanted: Vec<&str> = plan.iter().map(|a| a.message_id.as_str()).collect();
    assert_eq!(rig.servers[1].posted_count_for(&wanted).await, plan.len());
    assert_eq!(rig.servers[1].posted_count().await, plan.len());
    assert_eq!(rig.servers[0].posted_count().await, 0);
    // A refused post says nothing about the provider's health.
    assert_eq!(rig.load(0).await.failures, 0);
}

/// The first run leaves every article planned: p0 loses each reply (and
/// its lookup finds nothing), p1 refuses. Then every planned article
/// reaches p1 from elsewhere, byte for byte. Returns the plan.
async fn planned_then_peered_to_p1(rig: &mut Rig, s: &Seeded) -> Vec<ArticleRow> {
    rig.set_priorities(&[0, 1]);
    rig.servers[1].set_posting_allowed(false).await;
    rig.servers[0].set_stat_lag(true).await;
    rig.servers[0].drop_next_posts(usize::MAX / 2).await;
    assert!(matches!(rig.run_post(s).await, JobOutcome::Retry { .. }));
    rig.servers[0].drop_next_posts(0).await;
    rig.servers[0].set_stat_lag(false).await;
    let planned = rig.plan(s).await;
    assert!(planned.iter().all(|a| a.state == ArticleState::Planned));

    let mut peer = rig.raw_client(1).await;
    rig.servers[1].set_posting_allowed(true).await;
    for row in &planned {
        let article = render(&planned, row, &s.cipher, false);
        peer.post_article(&row.message_id, &article).await.unwrap();
    }
    peer.quit().await;
    assert_eq!(rig.servers[1].posted_count().await, planned.len());
    planned
}

/// The second provider already holds the articles (the first provider
/// took them and they peered across) and the first one now refuses to
/// post: the second answers "duplicate", which is confirmed, and each
/// article is recorded once.
#[tokio::test]
async fn duplicate_on_the_failover_provider_confirms() {
    let mut rig = pool_rig(2).await;
    let s = rig.seed(9, &marked_plaintext(PLAIN_LEN)).await;
    let planned = planned_then_peered_to_p1(&mut rig, &s).await;
    let on_p0 = rig.servers[0].posted_count().await;

    rig.servers[0].set_posting_allowed(false).await;
    rig.bridge.clock.advance_secs(3600);
    let plan = rig.post(&s).await;
    for (after, before) in plan.iter().zip(&planned) {
        assert_eq!(after.message_id, before.message_id);
        assert_eq!(after.state, ArticleState::Posted);
        assert_eq!(after.provider_id.as_deref(), Some("p1"));
    }
    // Nothing was stored a second time, under any id.
    assert_eq!(rig.servers[1].posted_count().await, planned.len());
    assert_eq!(rig.servers[0].posted_count().await, on_p0);
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.stage, OutboxStage::Verify);
}

/// The first provider's connection fails, so whether it took the
/// articles is unknown. Before posting on the next provider the job
/// looks the message-ids up there: they are present (peered across), so
/// nothing is posted again. The second provider would refuse a POST.
#[tokio::test]
async fn failover_after_an_unknown_post_looks_the_article_up_first() {
    let mut rig = pool_rig(2).await;
    let s = rig.seed(13, &marked_plaintext(PLAIN_LEN)).await;
    let planned = planned_then_peered_to_p1(&mut rig, &s).await;
    let on_p0 = rig.servers[0].posted_count().await;

    rig.servers[1].set_posting_allowed(false).await;
    rig.unplug(0);
    rig.bridge.clock.advance_secs(3600);
    let plan = rig.post(&s).await;
    for (after, before) in plan.iter().zip(&planned) {
        assert_eq!(after.message_id, before.message_id);
        assert_eq!(after.headers, before.headers);
        assert_eq!(after.state, ArticleState::Posted);
        assert_eq!(after.provider_id.as_deref(), Some("p1"));
    }
    assert_eq!(rig.servers[1].posted_count().await, planned.len());
    assert_eq!(rig.servers[0].posted_count().await, on_p0);
    // The unreachable provider took a strike for each failed session.
    assert_eq!(rig.load(0).await.failures, 2);
}

/// A provider that fails half-way hands only the remaining articles to
/// the next one: no article is posted to both.
#[tokio::test]
async fn failover_posts_only_what_is_still_planned() {
    let mut rig = pool_rig(2).await;
    rig.set_priorities(&[0, 1]);
    let s = rig.seed(10, &marked_plaintext(PLAIN_LEN)).await;
    // Plan first, so the article count is known.
    rig.servers[0].set_posting_allowed(false).await;
    rig.servers[1].set_posting_allowed(false).await;
    assert!(matches!(rig.run_post(&s).await, JobOutcome::Retry { .. }));
    let planned = rig.plan(&s).await;
    assert!(planned.len() >= 2);

    // p0 takes exactly one article and then refuses.
    let first = &planned[0];
    let mut peer = rig.raw_client(0).await;
    rig.servers[0].set_posting_allowed(true).await;
    let article = render(&planned, first, &s.cipher, false);
    peer.post_article(&first.message_id, &article)
        .await
        .unwrap();
    peer.quit().await;
    rig.servers[0].set_posting_allowed(false).await;
    rig.servers[1].set_posting_allowed(true).await;

    rig.bridge.clock.advance_secs(3600);
    let plan = rig.post(&s).await;
    assert!(plan.iter().all(|a| a.state == ArticleState::Posted));
    assert_eq!(rig.servers[0].posted_count().await, 1);
    let on_p1 = rig.servers[1].posted_count().await;
    let by_p1 = plan
        .iter()
        .filter(|a| a.provider_id.as_deref() == Some("p1"))
        .count();
    assert_eq!(on_p1, by_p1);
    assert!(on_p1 == plan.len() || on_p1 == plan.len() - 1);
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

/// One provider of the top tier refuses the post and the other is only
/// busy: the job waits for the busy one instead of using the backup tier.
#[tokio::test]
async fn failover_stays_in_a_tier_that_is_only_busy() {
    let mut rig = pool_rig(3).await;
    rig.set_priorities(&[0, 0, 1]);
    rig.servers[0].set_posting_allowed(false).await;
    let now = rig.bridge.clock.now();
    let p1 = &rig.bridge.cfg.providers[1];
    for _ in 0..2 {
        let permit = rig
            .bridge
            .catalog
            .acquire_permit(p1, PermitClass::Read, "t", now);
        permit.await.unwrap().expect("free slot");
    }
    let s = rig.seed(12, &marked_plaintext(PLAIN_LEN)).await;
    let attempts = rig.bridge.catalog.outbox(&s.extent).attempts;
    assert!(matches!(rig.run_post(&s).await, JobOutcome::Retry { .. }));
    assert_eq!(rig.bridge.catalog.outbox(&s.extent).attempts, attempts);
    for server in &rig.servers {
        assert_eq!(server.posted_count().await, 0);
    }
    assert!(rig.uses(0).await > 0, "p0 was not tried");
    assert_eq!(rig.uses(2).await, 0);
}

/// Holds both of provider `i`'s connections and makes it answer every
/// further login with `reply`.
async fn refuse_logins(
    rig: &Rig,
    i: usize,
    reply: &'static str,
) -> [velmora::nntp::NntpClient<velmora::transports::NativeTlsTransport>; 2] {
    rig.servers[i].set_limit_reply(Some(reply)).await;
    let addr = rig.servers[i].addr();
    let cfg = nntp_config(&addr.ip().to_string(), addr.port(), USER, PASS);
    [dial(&cfg).await.unwrap(), dial(&cfg).await.unwrap()]
}

impl Rig {
    /// Runs the post job again, whenever it was due.
    async fn rerun_post(&self, s: &Seeded) -> JobOutcome {
        self.bridge.catalog.edit(&s.extent, |e| {
            e.outbox.next_at = UnixMs(0);
            e.outbox.lease_until = None;
        });
        self.run_post(s).await
    }
}

/// The only poster refuses the login for its account for days. The job
/// waits, never spends an attempt and so never ends up dead; the
/// provider sees one login per try once it is known to refuse, and none
/// while it cools down. When the account is in order again the job
/// posts.
#[tokio::test]
async fn a_lasting_refusal_never_spends_an_attempt() {
    let mut rig = pool_rig(1).await;
    let s = rig.seed(41, &marked_plaintext(PLAIN_LEN)).await;
    // Room for three sockets of a job (one slot stays with the reads).
    rig.bridge.cfg.providers[0].max_conns = 4;
    let held = refuse_logins(&rig, 0, "502 Account suspended").await;

    // The first run opens every socket of the job; the provider refuses
    // them all. From then on a run tries with one.
    let nntp = &rig.bridge.nntp;
    let mut dials = Vec::new();
    for _ in 0..3 {
        assert!(!rig.cooling(0).await);
        let before = nntp.dials_to("p0");
        let outcome = rig.rerun_post(&s).await;
        assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
        dials.push(nntp.dials_to("p0") - before);
    }
    assert_eq!(dials, [3, 1, 1]);
    assert!(rig.cooling(0).await);
    assert_eq!(nntp.live(), 0);

    // Far more runs than a job has attempts, over more than a week.
    let before = nntp.dials_to("p0");
    let mut probes = 0;
    for _ in 0..200 {
        probes += usize::from(!rig.cooling(0).await);
        let outcome = rig.rerun_post(&s).await;
        assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
        rig.bridge.clock.advance_secs(3600);
    }
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!((outbox.attempts, &outbox.last_error), (0, &None));
    // One login per ended cooldown, and the cooldowns grow to six hours.
    assert_eq!(nntp.dials_to("p0") - before, probes);
    assert!((30..45).contains(&probes), "{probes}");
    assert_eq!(rig.load(0).await.fault, Some(ProviderFault::LoginRefused));

    // The account is in order again.
    rig.servers[0].set_limit_reply(None).await;
    for client in held {
        client.quit().await;
    }
    rig.bridge.clock.advance_secs(6 * 3600);
    assert_eq!(rig.rerun_post(&s).await, JobOutcome::Ack);
    let plan = rig.bridge.catalog.articles(&s.extent).await.unwrap();
    assert!(plan.iter().all(|a| a.state == ArticleState::Posted));
    let load = rig.load(0).await;
    assert_eq!((load.healthy(), load.fault), (true, None));
}

/// Every tier refuses the login for its account: the job waits without
/// spending an attempt. A real failure next to a refusal is still a
/// failed run and costs one.
#[tokio::test]
async fn only_a_real_failure_next_to_a_refusal_spends_an_attempt() {
    let mut rig = pool_rig(2).await;
    rig.set_priorities(&[0, 1]);
    let s = rig.seed(42, &marked_plaintext(PLAIN_LEN)).await;
    let mut held = Vec::new();
    for i in [0, 1] {
        held.extend(refuse_logins(&rig, i, "502 Account suspended").await);
    }
    let outcome = rig.rerun_post(&s).await;
    assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!((outbox.attempts, &outbox.last_error), (0, &None));
    for i in [0, 1] {
        let load = rig.load(i).await;
        assert_eq!(
            (load.failures, load.fault),
            (1, Some(ProviderFault::LoginRefused))
        );
    }

    // p1 cannot be reached at all: that run failed.
    rig.unplug(1);
    let outcome = rig.rerun_post(&s).await;
    assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.attempts, 1);
    assert!(outbox.last_error.is_some());
    assert_eq!(rig.load(1).await.fault, Some(ProviderFault::SessionFailed));
    for client in held {
        client.quit().await;
    }
}

/// The job is logged in on a provider and a further login there is
/// refused, in words that name no limit. A provider that just let the
/// job in is not refusing the account: the job has reached the number
/// of connections it gets. It posts on the sockets it has, the provider
/// takes no strike and nothing goes to the backup tier.
#[tokio::test]
async fn a_refusal_next_to_a_logged_in_socket_is_the_connection_limit() {
    for reply in ["502 Please try again later", "481 Not now", "502"] {
        let mut rig = pool_rig(2).await;
        rig.set_priorities(&[0, 1]);
        let s = rig.seed(43, &marked_plaintext(PLAIN_LEN)).await;
        // The catalogue has three slots for a job; the server gives two.
        rig.bridge.cfg.providers[0].max_conns = 4;
        rig.servers[0].set_limit_reply(Some(reply)).await;

        assert_eq!(rig.run_post(&s).await, JobOutcome::Ack, "{reply}");
        assert_eq!(rig.bridge.nntp.dials_to("p0"), 3, "{reply}");
        let plan = rig.bridge.catalog.articles(&s.extent).await.unwrap();
        assert!(plan.len() >= 3, "{reply}");
        for row in &plan {
            assert_eq!(row.state, ArticleState::Posted, "{reply}");
            assert_eq!(row.provider_id.as_deref(), Some("p0"), "{reply}");
        }
        assert_eq!(rig.servers[1].posted_count().await, 0, "{reply}");
        let load = rig.load(0).await;
        assert_eq!((load.failures, load.fault), (0, None), "{reply}");
        assert_eq!(rig.bridge.nntp.live(), 0, "{reply}");
    }

    // Not a strike even for a moment: a provider one strike away from a
    // cooldown does not start one.
    let mut rig = pool_rig(2).await;
    rig.set_priorities(&[0, 1]);
    let s = rig.seed(44, &marked_plaintext(PLAIN_LEN)).await;
    rig.bridge.cfg.providers[0].max_conns = 4;
    rig.servers[0].set_limit_reply(Some("502")).await;
    let now = rig.bridge.clock.now();
    for _ in 0..2 {
        let failed = rig
            .bridge
            .catalog
            .provider_failed("p0", ProviderFault::SessionFailed, now);
        failed.await.unwrap();
    }
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    assert_eq!(rig.servers[1].posted_count().await, 0);
    let load = rig.load(0).await;
    assert_eq!((load.healthy(), load.cooldowns), (true, 0));
}

/// The same on the tier a job falls to, whose sockets connect inside the
/// posting round: the first tier cannot be reached, the backup lets two
/// of the job's three sockets in and refuses the third. The two post
/// everything, the third's article included, and the backup takes no
/// strike.
#[tokio::test]
async fn a_refusal_inside_the_round_next_to_a_logged_in_socket_is_the_limit() {
    let mut rig = pool_rig(3).await;
    rig.set_priorities(&[0, 1, 2]);
    let s = rig.seed(45, &marked_plaintext(PLAIN_LEN)).await;
    rig.unplug(0);
    rig.bridge.cfg.providers[1].max_conns = 4;
    rig.servers[1]
        .set_limit_reply(Some("502 Please try again later"))
        .await;

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    assert_eq!(rig.bridge.nntp.dials_to("p1"), 3);
    let plan = rig.bridge.catalog.articles(&s.extent).await.unwrap();
    assert!(plan.len() >= 3);
    for row in &plan {
        assert_eq!(row.state, ArticleState::Posted);
        assert_eq!(row.provider_id.as_deref(), Some("p1"));
    }
    assert_eq!(rig.servers[2].posted_count().await, 0);
    let load = rig.load(1).await;
    assert_eq!((load.failures, load.fault), (0, None));
    assert_eq!(rig.bridge.nntp.live(), 0);
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
