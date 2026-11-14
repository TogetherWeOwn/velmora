//! `SqlCatalog` provider permits over SQLite with the D1 schema.

use std::collections::BTreeSet;

use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::*;

const T0: UnixMs = UnixMs(1_762_992_000_123);
const TTL_MS: i64 = 120_000;

fn provider(id: &str, max_conns: u32) -> ProviderConfig {
    let json = format!(
        "{{\"id\":\"{id}\",\"host\":\"news.example.invalid\",\"port\":563,\"tls\":true,\
         \"user\":\"u\",\"pass\":\"p\",\"backbone\":\"bb\",\"post\":true,\"read\":true,\
         \"max_conns\":{max_conns}}}"
    );
    serde_json::from_str(&json).unwrap()
}

fn catalog() -> SqlCatalog<RusqliteSql> {
    SqlCatalog::new(RusqliteSql::with_schema().unwrap())
}

async fn count(c: &SqlCatalog<RusqliteSql>, sql: &str) -> i64 {
    match c.sql.query(sql, &[]).await.unwrap()[0][0] {
        SqlValue::Int(n) => n,
        ref other => panic!("not an integer: {other:?}"),
    }
}

/// Slots held at `now`.
async fn held(c: &SqlCatalog<RusqliteSql>, now: UnixMs) -> i64 {
    let sql = format!(
        "SELECT COUNT(*) FROM provider_permits WHERE lease_until >= {}",
        now.0
    );
    count(c, &sql).await
}

async fn acquire(
    c: &SqlCatalog<RusqliteSql>,
    p: &ProviderConfig,
    class: PermitClass,
    now: UnixMs,
) -> Option<Permit> {
    c.acquire_permit(p, class, "holder", now).await.unwrap()
}

#[tokio::test]
async fn seeding_is_idempotent_and_per_provider() {
    let c = catalog();
    let providers = [provider("p1", 3), provider("p2", 1), provider("p0", 0)];
    c.seed_permits(&providers).await.unwrap();
    let p1 = acquire(&c, &providers[0], PermitClass::Read, T0)
        .await
        .unwrap();
    // Seeding again neither frees a held slot nor adds one.
    c.seed_permits(&providers).await.unwrap();
    assert_eq!(count(&c, "SELECT COUNT(*) FROM provider_permits").await, 4);
    assert_eq!(held(&c, T0).await, 1);
    assert!(c.renew_permit(&p1, T0).await.unwrap());
    // A provider with no connections allowed never yields a permit.
    assert!(acquire(&c, &providers[2], PermitClass::Read, T0)
        .await
        .is_none());
    assert!(acquire(&c, &providers[2], PermitClass::Background, T0)
        .await
        .is_none());
    assert_eq!(count(&c, "SELECT COUNT(*) FROM provider_permits").await, 4);
}

/// Overlapping background jobs and cold reads against one provider: the
/// number of held permits never passes `max_conns`, and background jobs
/// never take the slot reserved for reads.
#[tokio::test]
async fn permits_never_exceed_max_conns() {
    for max_conns in [1u32, 2, 3, 5] {
        let c = catalog();
        let p = provider("p1", max_conns);
        let other = provider("p2", 1);
        let background_cap = if max_conns >= 2 { max_conns - 1 } else { 1 };
        let mut live: Vec<(Permit, PermitClass)> = Vec::new();
        let mut peak = 0;
        // A fixed, mixed schedule: acquire in bursts, release some, repeat.
        // No seeding call: the first acquire creates the slots.
        for round in 0..40u32 {
            let now = T0.plus_ms(i64::from(round));
            let class = if round % 3 == 0 {
                PermitClass::Read
            } else {
                PermitClass::Background
            };
            if let Some(permit) = acquire(&c, &p, class, now).await {
                assert!(permit.slot < max_conns);
                assert_eq!(permit.provider, "p1");
                live.push((permit, class));
            } else {
                let background = live
                    .iter()
                    .filter(|(_, k)| *k == PermitClass::Background)
                    .count();
                match class {
                    PermitClass::Read => assert_eq!(live.len(), max_conns as usize),
                    // Refused although a slot may be free: it is the read reserve.
                    PermitClass::Background => assert!(
                        live.len() == max_conns as usize
                            || live.iter().filter(|(p, _)| p.slot < background_cap).count()
                                == background_cap as usize,
                        "background refused with {background} of {background_cap} in use"
                    ),
                }
            }
            let slots: BTreeSet<u32> = live.iter().map(|(p, _)| p.slot).collect();
            assert_eq!(slots.len(), live.len(), "one slot handed out twice");
            assert!(live.len() <= max_conns as usize);
            assert_eq!(held(&c, now).await, live.len() as i64);
            for (permit, class) in &live {
                if *class == PermitClass::Background {
                    assert!(
                        permit.slot < background_cap,
                        "background took the read reserve"
                    );
                }
            }
            peak = peak.max(live.len());
            if round % 4 == 3 {
                let (permit, _) = live.remove(0);
                c.release_permit(&permit).await.unwrap();
            }
        }
        assert_eq!(
            peak, max_conns as usize,
            "the schedule never filled the provider"
        );
        assert_eq!(
            count(&c, "SELECT COUNT(*) FROM provider_permits").await,
            i64::from(max_conns)
        );
        // Another provider's slots are its own.
        assert!(acquire(&c, &other, PermitClass::Read, T0).await.is_some());
    }
}

#[tokio::test]
async fn background_leaves_one_slot_for_reads() {
    let c = catalog();
    let p = provider("p1", 2);
    let job = acquire(&c, &p, PermitClass::Background, T0).await.unwrap();
    assert_eq!(job.slot, 0);
    assert!(acquire(&c, &p, PermitClass::Background, T0).await.is_none());
    let read = acquire(&c, &p, PermitClass::Read, T0).await.unwrap();
    assert_eq!(read.slot, 1);
    assert!(acquire(&c, &p, PermitClass::Read, T0).await.is_none());
    // A read may also use a slot background jobs can use.
    c.release_permit(&job).await.unwrap();
    assert_eq!(
        acquire(&c, &p, PermitClass::Read, T0).await.unwrap().slot,
        0
    );

    // With a single connection there is no reserve.
    let single = provider("solo", 1);
    assert!(acquire(&c, &single, PermitClass::Background, T0)
        .await
        .is_some());
    assert!(acquire(&c, &single, PermitClass::Read, T0).await.is_none());
}

/// A holder that crashed (or stalled past the TTL) loses its slot at
/// expiry. Whatever it does afterwards changes nothing.
#[tokio::test]
async fn expired_permit_is_reclaimed_and_fenced() {
    let c = catalog();
    let p = provider("p1", 1);
    let stale = acquire(&c, &p, PermitClass::Read, T0).await.unwrap();
    assert_eq!((stale.slot, stale.token), (0, 1));

    // Held through the whole TTL, including its last millisecond.
    let expiry = T0.plus_ms(TTL_MS);
    assert!(acquire(&c, &p, PermitClass::Read, expiry).await.is_none());
    // A renewal extends it from the renewal time.
    assert!(c.renew_permit(&stale, T0.plus_ms(1000)).await.unwrap());
    let expiry = T0.plus_ms(1000 + TTL_MS);
    assert!(acquire(&c, &p, PermitClass::Read, expiry).await.is_none());

    // Expired but not yet taken over: the holder may not extend it. It
    // must drop its connection instead.
    let after = expiry.plus_ms(1);
    assert!(!c.renew_permit(&stale, after).await.unwrap());

    let owner = acquire(&c, &p, PermitClass::Read, after).await.unwrap();
    assert_eq!((owner.slot, owner.token), (0, 2));
    // The stale holder can neither renew nor free the slot it lost.
    assert!(!c.renew_permit(&stale, after).await.unwrap());
    c.release_permit(&stale).await.unwrap();
    assert_eq!(held(&c, after).await, 1);
    assert!(acquire(&c, &p, PermitClass::Read, after).await.is_none());
    assert!(c.renew_permit(&owner, after).await.unwrap());

    // The owner's release frees it at once, and its permit is then spent.
    c.release_permit(&owner).await.unwrap();
    assert_eq!(held(&c, after).await, 0);
    assert!(!c.renew_permit(&owner, after).await.unwrap());
    let next = acquire(&c, &p, PermitClass::Read, after).await.unwrap();
    assert_eq!(next.token, 3);
    // Releasing twice, or after someone else acquired, is harmless.
    c.release_permit(&owner).await.unwrap();
    assert_eq!(held(&c, after).await, 1);
}

/// A full provider stays full while another provider has free slots.
#[tokio::test]
async fn a_full_provider_cannot_borrow_from_another() {
    let c = catalog();
    let (p1, p2) = (provider("p1", 2), provider("p2", 2));
    c.seed_permits(&[p1.clone(), p2.clone()]).await.unwrap();
    let a = acquire(&c, &p1, PermitClass::Read, T0).await.unwrap();
    let b = acquire(&c, &p1, PermitClass::Read, T0).await.unwrap();
    assert!(acquire(&c, &p1, PermitClass::Read, T0).await.is_none());
    assert!(acquire(&c, &p1, PermitClass::Background, T0)
        .await
        .is_none());
    assert_eq!((a.token, b.token), (1, 1));
    assert!(c.renew_permit(&a, T0).await.unwrap());
    assert!(c.renew_permit(&b, T0).await.unwrap());
    assert_eq!(held(&c, T0).await, 2);
}

/// Lowering `max_conns` takes effect at once: surplus slots stay in the
/// table but are never handed out.
#[tokio::test]
async fn lowered_max_conns_is_obeyed() {
    let c = catalog();
    let wide = provider("p1", 4);
    c.seed_permits(std::slice::from_ref(&wide)).await.unwrap();
    let narrow = provider("p1", 2);
    c.seed_permits(std::slice::from_ref(&narrow)).await.unwrap();
    let mut got = Vec::new();
    while let Some(p) = acquire(&c, &narrow, PermitClass::Read, T0).await {
        got.push(p.slot);
    }
    assert_eq!(got, vec![1, 0]);
}

// ---------------------------------------------------------------------------
// Pools: accounts that share one connection limit
// ---------------------------------------------------------------------------

fn pooled(id: &str, max_conns: u32, pool: &str, pool_max_conns: u32) -> ProviderConfig {
    let mut p = provider(id, max_conns);
    p.pool = Some(pool.into());
    p.pool_max_conns = Some(pool_max_conns);
    p
}

/// Three accounts of one pool under an interleaved schedule: no account
/// passes its own `max_conns`, the accounts together never pass
/// `pool_max_conns`, and background jobs leave the pool's read slot free.
#[tokio::test]
async fn pool_shared_permits_never_exceed_the_pool_limit() {
    const POOL_MAX: u32 = 4;
    let c = catalog();
    let accounts = [
        pooled("a", 3, "bundle", POOL_MAX),
        pooled("b", 3, "bundle", POOL_MAX),
        pooled("c", 2, "bundle", POOL_MAX),
    ];
    // Outside the pool: unaffected by it.
    let alone = provider("z", 2);
    let mut live: Vec<(Permit, PermitClass)> = Vec::new();
    let mut pool_peak = 0;
    let mut refused = 0;
    for round in 0..120u32 {
        let now = T0.plus_ms(i64::from(round));
        let account = &accounts[(round % 3) as usize];
        let class = if round % 4 == 0 {
            PermitClass::Read
        } else {
            PermitClass::Background
        };
        match acquire(&c, account, class, now).await {
            Some(permit) => live.push((permit, class)),
            None => refused += 1,
        }
        if round % 5 == 4 {
            let (permit, _) = live.remove(0);
            c.release_permit(&permit).await.unwrap();
        }
        let in_pool = live.len() as u32;
        pool_peak = pool_peak.max(in_pool);
        assert!(in_pool <= POOL_MAX, "round {round}: {in_pool} held");
        assert_eq!(held(&c, now).await, i64::from(in_pool));
        for (member, account) in accounts.iter().enumerate() {
            let own = live
                .iter()
                .filter(|(p, _)| p.provider == account.id)
                .count() as u32;
            assert!(own <= account.max_conns, "round {round}: member {member}");
        }
        let background = live
            .iter()
            .filter(|(_, class)| *class == PermitClass::Background)
            .count() as u32;
        assert!(background < POOL_MAX, "round {round}: no read slot left");
        let slots: BTreeSet<(String, u32)> = live
            .iter()
            .map(|(p, _)| (p.provider.clone(), p.slot))
            .collect();
        assert_eq!(slots.len(), live.len(), "a slot is held twice");
    }
    assert_eq!(pool_peak, POOL_MAX);
    assert!(refused > 0);

    // The pool is full; a provider outside it still gets its slots.
    while acquire(&c, &accounts[0], PermitClass::Read, T0.plus_ms(200))
        .await
        .is_some()
    {}
    assert!(acquire(&c, &alone, PermitClass::Read, T0.plus_ms(200))
        .await
        .is_some());
}

/// An expired slot of one account frees room for another account of the
/// pool, and two pools do not count against each other.
#[tokio::test]
async fn pool_limit_counts_live_slots_of_its_own_pool_only() {
    let c = catalog();
    let a = pooled("a", 2, "one", 2);
    let b = pooled("b", 2, "one", 2);
    let other = pooled("c", 2, "two", 2);
    for _ in 0..2 {
        assert!(acquire(&c, &a, PermitClass::Read, T0).await.is_some());
    }
    assert!(acquire(&c, &b, PermitClass::Read, T0).await.is_none());
    assert!(acquire(&c, &other, PermitClass::Read, T0).await.is_some());
    // Both of `a`'s slots expire unreleased.
    let later = T0.plus_ms(TTL_MS + 1);
    assert!(acquire(&c, &b, PermitClass::Read, later).await.is_some());
    assert!(acquire(&c, &b, PermitClass::Read, later).await.is_some());
    assert!(acquire(&c, &a, PermitClass::Read, later).await.is_none());
}

// ---------------------------------------------------------------------------
// Health and cooldown
// ---------------------------------------------------------------------------

async fn load_of(c: &SqlCatalog<RusqliteSql>, id: &str, now: UnixMs) -> Option<ProviderLoad> {
    let all = c.provider_load(now).await.unwrap();
    all.into_iter().find(|l| l.provider_id == id)
}

const MINUTE_MS: i64 = 60_000;

/// Three failed sessions in a row start a one-minute cooldown. Each
/// further failure after a cooldown doubles it, up to fifteen minutes.
/// One good session clears everything.
#[tokio::test]
async fn cooldown_starts_after_repeated_failures_and_doubles() {
    let c = catalog();
    assert_eq!(load_of(&c, "p1", T0).await, None);

    c.provider_failed("p1", T0).await.unwrap();
    c.provider_failed("p1", T0.plus_ms(1)).await.unwrap();
    let before = load_of(&c, "p1", T0.plus_ms(1)).await.unwrap();
    assert_eq!((before.failures, before.cooldown_until), (2, UnixMs(0)));

    let mut now = T0.plus_ms(2);
    c.provider_failed("p1", now).await.unwrap();
    let tripped = load_of(&c, "p1", now).await.unwrap();
    assert_eq!(tripped.cooldown_until, now.plus_ms(MINUTE_MS));
    assert_eq!((tripped.failures, tripped.cooldowns), (0, 1));

    // Reports that arrive while it cools change nothing: jobs that fail
    // together do not stack cooldowns.
    c.provider_failed("p1", now.plus_ms(10)).await.unwrap();
    c.provider_recovered("p1", now.plus_ms(10)).await.unwrap();
    assert_eq!(load_of(&c, "p1", now).await.unwrap(), tripped);

    // After a cooldown one more failure is enough, and the wait doubles.
    for minutes in [2, 4, 8, 15, 15] {
        now = load_of(&c, "p1", now).await.unwrap().cooldown_until;
        c.provider_failed("p1", now).await.unwrap();
        let l = load_of(&c, "p1", now).await.unwrap();
        assert_eq!(l.cooldown_until, now.plus_ms(minutes * MINUTE_MS));
    }

    // Recovery: back to a clean slate, three strikes again.
    now = load_of(&c, "p1", now).await.unwrap().cooldown_until;
    c.provider_recovered("p1", now).await.unwrap();
    let clean = load_of(&c, "p1", now).await.unwrap();
    assert_eq!(
        (clean.failures, clean.cooldowns, clean.cooldown_until),
        (0, 0, UnixMs(0))
    );
    c.provider_failed("p1", now).await.unwrap();
    c.provider_failed("p1", now).await.unwrap();
    assert_eq!(load_of(&c, "p1", now).await.unwrap().cooldown_until.0, 0);
    // Other providers are untouched.
    assert_eq!(load_of(&c, "p2", now).await, None);
}

/// The load snapshot joins held slots, hand-outs so far and health.
#[tokio::test]
async fn provider_load_reports_slots_and_health_per_provider() {
    let c = catalog();
    let p1 = provider("p1", 3);
    let p2 = provider("p2", 2);
    let first = acquire(&c, &p1, PermitClass::Read, T0).await.unwrap();
    acquire(&c, &p1, PermitClass::Read, T0).await.unwrap();
    acquire(&c, &p2, PermitClass::Read, T0).await.unwrap();
    c.release_permit(&first).await.unwrap();
    c.provider_failed("p2", T0).await.unwrap();

    let l1 = load_of(&c, "p1", T0).await.unwrap();
    assert_eq!((l1.held, l1.failures), (1, 0));
    let l2 = load_of(&c, "p2", T0).await.unwrap();
    assert_eq!((l2.held, l2.failures), (1, 1));
    // `uses` grows with every hand-out, held or not.
    assert!(l1.uses > l2.uses);
    // Expired slots are not held.
    let later = T0.plus_ms(TTL_MS + 1);
    assert_eq!(load_of(&c, "p1", later).await.unwrap().held, 0);
}

// ---------------------------------------------------------------------------
// Source addresses (`max_ips`)
// ---------------------------------------------------------------------------

fn capped(id: &str, max_conns: u32, max_ips: u32) -> ProviderConfig {
    let mut p = provider(id, max_conns);
    p.max_ips = Some(max_ips);
    p
}

async fn acquire_as(
    c: &SqlCatalog<RusqliteSql>,
    p: &ProviderConfig,
    class: PermitClass,
    holder: &str,
    now: UnixMs,
) -> Option<Permit> {
    c.acquire_permit(p, class, holder, now).await.unwrap()
}

/// The live slots of a provider at `now`: `(slot, holder, background)`.
async fn live_slots(
    c: &SqlCatalog<RusqliteSql>,
    id: &str,
    now: UnixMs,
) -> Vec<(u32, String, bool)> {
    let sql = format!(
        "SELECT slot, holder, background FROM provider_permits \
         WHERE provider_id = '{id}' AND lease_until >= {} ORDER BY slot",
        now.0
    );
    let rows = c.sql.query(&sql, &[]).await.unwrap();
    rows.into_iter()
        .map(|row| match (&row[0], &row[1], &row[2]) {
            (SqlValue::Int(slot), SqlValue::Text(holder), SqlValue::Int(job)) => {
                (*slot as u32, holder.clone(), *job == 1)
            }
            other => panic!("a live slot without a holder: {other:?}"),
        })
        .collect()
}

fn holders_of(live: &[(u32, String, bool)]) -> BTreeSet<&str> {
    live.iter().map(|(_, h, _)| h.as_str()).collect()
}

/// The holders with a slot that a background job took.
fn jobs_of(live: &[(u32, String, bool)]) -> BTreeSet<&str> {
    let jobs = live.iter().filter(|(_, _, job)| *job);
    jobs.map(|(_, h, _)| h.as_str()).collect()
}

/// One job on an account that allows one address takes slots up to the
/// connection limit, and nobody else gets one meanwhile, although slots
/// are free.
#[tokio::test]
async fn one_holder_takes_several_slots_and_a_second_holder_none() {
    let c = catalog();
    let p = capped("p1", 6, 1);
    for n in 0..4 {
        let got = acquire_as(&c, &p, PermitClass::Background, "job-a", T0).await;
        assert_eq!(got.map(|permit| permit.slot), Some(n));
    }
    for class in [PermitClass::Background, PermitClass::Read] {
        assert!(acquire_as(&c, &p, class, "job-b", T0).await.is_none());
    }
    assert_eq!(held(&c, T0).await, 4);
    assert_eq!(holders_of(&live_slots(&c, "p1", T0).await).len(), 1);
}

/// The connection that background jobs leave to reads. An account with
/// one address has none: a read cannot connect next to the job, so the
/// job takes every connection. With two addresses or no limit, the last
/// connection is the reads'.
#[tokio::test]
async fn no_connection_is_kept_back_on_an_account_with_one_address() {
    let c = catalog();
    for (id, max_ips, for_jobs) in [("p1", Some(1), 6), ("p2", Some(2), 5), ("p3", None, 5)] {
        let mut p = provider(id, 6);
        p.max_ips = max_ips;
        assert_eq!(p.background_conns(), for_jobs, "{id}");
        let mut got = 0;
        while acquire_as(&c, &p, PermitClass::Background, "job-a", T0)
            .await
            .is_some()
        {
            got += 1;
        }
        assert_eq!(got, for_jobs, "{id}");
        // What is left is for a read.
        let read = acquire_as(&c, &p, PermitClass::Read, "job-a", T0).await;
        assert_eq!(read.is_some(), for_jobs < 6, "{id}");
    }
    // One connection is one connection, whatever the address limit.
    assert_eq!(capped("p4", 1, 4).background_conns(), 1);
}

/// A long mixed schedule of acquires, renewals, releases and expiries by
/// six holders. After every step the provider has no more live slots than
/// `max_conns` and no more holders than `max_ips`, and every acquire is
/// granted exactly when the rule says so: the caller holds a live slot
/// there or an address is free for its class, and a slot is free.
#[tokio::test]
async fn addresses_and_connections_stay_under_their_limits() {
    for (max_conns, max_ips) in [(1u32, 1u32), (4, 1), (6, 2), (6, 3), (3, 5), (8, 4)] {
        let c = catalog();
        let p = capped("p1", max_conns, max_ips);
        let reserve = |max: u32| u32::from(max >= 2);
        let mut permits: Vec<Permit> = Vec::new();
        let mut now = T0;
        let (mut peak_slots, mut peak_holders, mut shared) = (0, 0, false);
        // A fixed pseudo-random schedule (an LCG), the same on every run.
        let mut seed = u64::from(max_conns * 31 + max_ips);
        let mut next = |bound: u64| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % bound
        };
        for step in 0..600 {
            match next(10) {
                0..=5 => {
                    let holder = format!("h{}", next(6));
                    let class = match next(3) {
                        0 => PermitClass::Read,
                        _ => PermitClass::Background,
                    };
                    let job = class == PermitClass::Background;
                    // Jobs leave a connection, except on one address.
                    let conns = match job && max_ips != 1 {
                        true => max_conns - reserve(max_conns),
                        false => max_conns,
                    };
                    let before = live_slots(&c, "p1", now).await;
                    let known = holders_of(&before).contains(holder.as_str());
                    let room = (holders_of(&before).len() as u32) < max_ips;
                    // Jobs leave an address too, counted over jobs only.
                    let job_room = !job
                        || jobs_of(&before).contains(holder.as_str())
                        || (jobs_of(&before).len() as u32) < max_ips - reserve(max_ips);
                    let address = (known || room) && job_room;
                    let slot = (0..conns).any(|s| !before.iter().any(|(live, ..)| *live == s));
                    let got = acquire_as(&c, &p, class, &holder, now).await;
                    assert_eq!(
                        got.is_some(),
                        address && slot,
                        "step {step}: {holder} {class:?} with {before:?} \
                         (max_conns {max_conns}, max_ips {max_ips})"
                    );
                    permits.extend(got);
                }
                6 | 7 if !permits.is_empty() => {
                    let at = next(permits.len() as u64) as usize;
                    c.release_permit(&permits.swap_remove(at)).await.unwrap();
                }
                8 if !permits.is_empty() => {
                    let at = next(permits.len() as u64) as usize;
                    // A renewal of an expired or re-taken slot is refused.
                    // So is one that is late: it carries a time at which
                    // the slot was live, and comes after an acquire that
                    // found it expired.
                    let stale = now.plus_ms(-(next(200_000) as i64));
                    let at_time = if next(2) == 0 { now } else { stale };
                    if !c.renew_permit(&permits[at], at_time).await.unwrap() {
                        permits.swap_remove(at);
                    }
                }
                _ => now = now.plus_ms(next(50_000) as i64),
            }
            let live = live_slots(&c, "p1", now).await;
            assert!(live.len() <= max_conns as usize, "step {step}: {live:?}");
            let holders = holders_of(&live).len();
            assert!(holders <= max_ips as usize, "step {step}: {live:?}");
            let jobs = jobs_of(&live).len() as u32;
            assert!(jobs <= max_ips - reserve(max_ips), "step {step}: {live:?}");
            peak_slots = peak_slots.max(live.len());
            peak_holders = peak_holders.max(holders);
            shared |= live.len() > holders;
        }
        // The schedule reached both limits, and a holder had several slots.
        assert_eq!(peak_slots, max_conns as usize, "max_conns {max_conns}");
        assert_eq!(
            peak_holders,
            max_ips.min(max_conns) as usize,
            "max_ips {max_ips}"
        );
        assert_eq!(shared, max_conns > 1, "max_conns {max_conns}");
    }
}

/// A holder that dies keeps its address until its slots expire, and not
/// a millisecond longer. Once another holder has the address, the first
/// one can neither renew its slots nor take new ones.
#[tokio::test]
async fn an_expired_holder_frees_its_address_and_cannot_come_back() {
    let c = catalog();
    let p = capped("p1", 6, 1);
    let a0 = acquire_as(&c, &p, PermitClass::Read, "a", T0)
        .await
        .unwrap();
    let a1 = acquire_as(&c, &p, PermitClass::Read, "a", T0)
        .await
        .unwrap();
    // Held up to and including the last millisecond of the permit.
    for now in [T0, T0.plus_ms(TTL_MS)] {
        assert!(acquire_as(&c, &p, PermitClass::Read, "b", now)
            .await
            .is_none());
    }
    let later = T0.plus_ms(TTL_MS + 1);
    let b = acquire_as(&c, &p, PermitClass::Read, "b", later)
        .await
        .unwrap();
    // `a` is out. `b` took one of its two slots; the other one, which
    // nobody took, cannot be renewed either: that would make `a` a
    // second holder.
    assert!([a0.slot, a1.slot].contains(&b.slot));
    for lost in [&a0, &a1] {
        assert!(!c.renew_permit(lost, later).await.unwrap());
    }
    assert!(acquire_as(&c, &p, PermitClass::Read, "a", later)
        .await
        .is_none());
    assert_eq!(holders_of(&live_slots(&c, "p1", later).await).len(), 1);
    // A late release by `a` frees nothing of `b`.
    for lost in [&a0, &a1] {
        c.release_permit(lost).await.unwrap();
    }
    assert!(c.renew_permit(&b, later).await.unwrap());
    assert!(acquire_as(&c, &p, PermitClass::Read, "a", later)
        .await
        .is_none());
}

/// The address is held while any one slot of the holder is live: a
/// holder that let one slot expire still counts, and may take more.
#[tokio::test]
async fn a_holder_with_one_live_slot_keeps_its_address() {
    let c = catalog();
    let p = capped("p1", 6, 1);
    acquire_as(&c, &p, PermitClass::Read, "a", T0)
        .await
        .unwrap();
    let kept = acquire_as(&c, &p, PermitClass::Read, "a", T0)
        .await
        .unwrap();
    assert!(c.renew_permit(&kept, T0.plus_ms(100_000)).await.unwrap());

    let later = T0.plus_ms(TTL_MS + 1);
    assert_eq!(live_slots(&c, "p1", later).await.len(), 1);
    assert!(acquire_as(&c, &p, PermitClass::Read, "b", later)
        .await
        .is_none());
    assert!(acquire_as(&c, &p, PermitClass::Read, "a", later)
        .await
        .is_some());
}

/// Giving back the last slot frees the address at once; giving back one
/// of several does not.
#[tokio::test]
async fn releasing_the_last_slot_frees_the_address() {
    let c = catalog();
    let p = capped("p1", 6, 1);
    let a0 = acquire_as(&c, &p, PermitClass::Read, "a", T0)
        .await
        .unwrap();
    let a1 = acquire_as(&c, &p, PermitClass::Read, "a", T0)
        .await
        .unwrap();
    c.release_permit(&a0).await.unwrap();
    assert!(acquire_as(&c, &p, PermitClass::Read, "b", T0)
        .await
        .is_none());
    c.release_permit(&a1).await.unwrap();
    assert!(acquire_as(&c, &p, PermitClass::Read, "b", T0)
        .await
        .is_some());
}

/// Background jobs leave one address to reads when the account allows
/// two or more, as they leave one connection.
#[tokio::test]
async fn background_jobs_leave_an_address_for_reads() {
    let c = catalog();
    let p = capped("p1", 8, 3);
    for job in ["job-a", "job-b"] {
        assert!(acquire_as(&c, &p, PermitClass::Background, job, T0)
            .await
            .is_some());
    }
    assert!(acquire_as(&c, &p, PermitClass::Background, "job-c", T0)
        .await
        .is_none());
    // A job that has its address takes more slots all the same.
    assert!(acquire_as(&c, &p, PermitClass::Background, "job-b", T0)
        .await
        .is_some());
    assert!(acquire_as(&c, &p, PermitClass::Read, "get-c", T0)
        .await
        .is_some());
    assert!(acquire_as(&c, &p, PermitClass::Read, "get-d", T0)
        .await
        .is_none());

    // With one address there is nothing to set aside.
    let single = capped("p2", 8, 1);
    assert!(
        acquire_as(&c, &single, PermitClass::Background, "job-a", T0)
            .await
            .is_some()
    );
}

/// The address that jobs leave free is for reads, and a read that uses
/// it takes nothing from the jobs: with two addresses, one read in
/// flight and one job run side by side. A second job waits, read or no
/// read, and a second read gets in only while no job has the other
/// address.
#[tokio::test]
async fn a_read_in_flight_does_not_take_the_address_of_the_jobs() {
    let c = catalog();
    let p = capped("p1", 8, 2);
    let read = acquire_as(&c, &p, PermitClass::Read, "get-a", T0)
        .await
        .unwrap();
    let job = acquire_as(&c, &p, PermitClass::Background, "job-a", T0)
        .await
        .unwrap();
    let live = live_slots(&c, "p1", T0).await;
    assert_eq!((holders_of(&live).len(), jobs_of(&live).len()), (2, 1));
    // Both addresses are in use.
    for (class, holder) in [
        (PermitClass::Background, "job-b"),
        (PermitClass::Read, "get-b"),
    ] {
        assert!(acquire_as(&c, &p, class, holder, T0).await.is_none());
    }
    // Without the read, the second job still waits: the free address is
    // not the jobs'. A read takes it.
    c.release_permit(&read).await.unwrap();
    assert!(acquire_as(&c, &p, PermitClass::Background, "job-b", T0)
        .await
        .is_none());
    assert!(acquire_as(&c, &p, PermitClass::Read, "get-b", T0)
        .await
        .is_some());
    // Without the job, reads may have both addresses, and then a job
    // waits for one of them.
    c.release_permit(&job).await.unwrap();
    assert!(acquire_as(&c, &p, PermitClass::Read, "get-c", T0)
        .await
        .is_some());
    assert!(acquire_as(&c, &p, PermitClass::Background, "job-b", T0)
        .await
        .is_none());
}

/// A holder counts as a job only through a slot that it took as one. A
/// read that is on the provider cannot take a slot as a job past the
/// jobs' limit, and a slot that a read takes over is a read's.
#[tokio::test]
async fn the_class_is_recorded_per_slot() {
    let c = catalog();
    let p = capped("p1", 8, 2);
    assert!(acquire_as(&c, &p, PermitClass::Background, "job-a", T0)
        .await
        .is_some());
    assert!(acquire_as(&c, &p, PermitClass::Read, "get-a", T0)
        .await
        .is_some());
    // `get-a` has its address, and the jobs have all of theirs.
    assert!(acquire_as(&c, &p, PermitClass::Background, "get-a", T0)
        .await
        .is_none());
    assert!(acquire_as(&c, &p, PermitClass::Read, "job-a", T0)
        .await
        .is_some());

    // The job's slot expires and a read takes it over: no job is left.
    let p = capped("p2", 2, 2);
    assert!(acquire_as(&c, &p, PermitClass::Background, "job-a", T0)
        .await
        .is_some());
    assert_eq!(jobs_of(&live_slots(&c, "p2", T0).await).len(), 1);
    let later = T0.plus_ms(TTL_MS + 1);
    for holder in ["get-a", "get-b"] {
        assert!(acquire_as(&c, &p, PermitClass::Read, holder, later)
            .await
            .is_some());
    }
    let live = live_slots(&c, "p2", later).await;
    assert_eq!((holders_of(&live).len(), jobs_of(&live).len()), (2, 0));
}

/// A renewal carries the time its caller read before the round trip. If
/// it arrives after the slot expired and another holder was let in, it
/// must not bring the old holder back: that would be an address too
/// many. The acquire that let the new holder in freed the expired slots.
#[tokio::test]
async fn a_late_renewal_cannot_revive_an_expired_holder() {
    let c = catalog();
    let p = capped("p1", 6, 1);
    let a0 = acquire_as(&c, &p, PermitClass::Read, "a", T0)
        .await
        .unwrap();
    let a1 = acquire_as(&c, &p, PermitClass::Read, "a", T0)
        .await
        .unwrap();
    // `a` reads the clock while its slots are live, and stalls.
    let read_by_a = T0.plus_ms(TTL_MS);
    let later = T0.plus_ms(TTL_MS + 1);
    let b = acquire_as(&c, &p, PermitClass::Background, "b", later)
        .await
        .unwrap();
    // `b` took one slot of `a`. The other is free too, not just expired.
    for lost in [&a0, &a1] {
        assert!(!c.renew_permit(lost, read_by_a).await.unwrap());
    }
    let live = live_slots(&c, "p1", later).await;
    assert_eq!(holders_of(&live), BTreeSet::from(["b"]));
    assert!(c.renew_permit(&b, later).await.unwrap());

    // Without an address limit nothing depends on it, and a slot that
    // nobody took can still be renewed late.
    let open = provider("p2", 2);
    acquire_as(&c, &open, PermitClass::Read, "a", T0)
        .await
        .unwrap();
    let kept = acquire_as(&c, &open, PermitClass::Read, "a", T0)
        .await
        .unwrap();
    assert!(acquire_as(&c, &open, PermitClass::Read, "b", later)
        .await
        .is_some());
    assert!(c.renew_permit(&kept, read_by_a).await.unwrap());
}

/// Each provider counts its own holders: a job that is on one provider
/// is no address on another, and the same job is one address on each.
#[tokio::test]
async fn addresses_are_counted_per_provider() {
    let c = catalog();
    let (p1, p2) = (capped("p1", 4, 1), capped("p2", 4, 1));
    assert!(acquire_as(&c, &p1, PermitClass::Read, "a", T0)
        .await
        .is_some());
    // `a` has no slot on p2 yet: its slot on p1 does not let it in there
    // past another holder, and does not keep another holder out.
    assert!(acquire_as(&c, &p2, PermitClass::Read, "b", T0)
        .await
        .is_some());
    assert!(acquire_as(&c, &p2, PermitClass::Read, "a", T0)
        .await
        .is_none());
    assert!(acquire_as(&c, &p1, PermitClass::Read, "b", T0)
        .await
        .is_none());
}

/// Without `max_ips` nothing counts holders: as many as there are slots.
#[tokio::test]
async fn without_max_ips_only_connections_count() {
    let c = catalog();
    let p = provider("p1", 4);
    assert_eq!(p.max_ips, None);
    for n in 0..4 {
        let holder = format!("h{n}");
        assert!(acquire_as(&c, &p, PermitClass::Read, &holder, T0)
            .await
            .is_some());
    }
    assert!(acquire_as(&c, &p, PermitClass::Read, "h0", T0)
        .await
        .is_none());
    let load = load_of(&c, "p1", T0).await.unwrap();
    assert_eq!((load.held, load.holders), (4, 4));
}

/// The load snapshot counts the holders of live slots, each once.
#[tokio::test]
async fn provider_load_counts_live_holders() {
    let c = catalog();
    let p = capped("p1", 6, 3);
    let a = acquire_as(&c, &p, PermitClass::Read, "a", T0)
        .await
        .unwrap();
    acquire_as(&c, &p, PermitClass::Read, "a", T0)
        .await
        .unwrap();
    let b = acquire_as(&c, &p, PermitClass::Background, "b", T0)
        .await
        .unwrap();
    acquire_as(&c, &p, PermitClass::Background, "b", T0)
        .await
        .unwrap();
    let load = load_of(&c, "p1", T0).await.unwrap();
    assert_eq!((load.held, load.holders), (4, 2));
    // `b` is one background holder, on two slots.
    assert_eq!(load.background_holders, 1);

    c.release_permit(&b).await.unwrap();
    let later = T0.plus_ms(60_000);
    assert!(c.renew_permit(&a, later).await.unwrap());
    let load = load_of(&c, "p1", later).await.unwrap();
    assert_eq!((load.held, load.holders), (3, 2));
    // Expired slots have no holder.
    let expired = T0.plus_ms(TTL_MS + 1);
    let load = load_of(&c, "p1", expired).await.unwrap();
    assert_eq!((load.held, load.holders), (1, 1));
    assert_eq!(load.background_holders, 0);
    let load = load_of(&c, "p1", later.plus_ms(TTL_MS + 1)).await.unwrap();
    assert_eq!((load.held, load.holders), (0, 0));
}

/// A `Sql` that counts the statements it is sent.
struct Counting {
    db: RusqliteSql,
    queries: std::cell::Cell<u32>,
    others: std::cell::Cell<u32>,
}

impl Sql for Counting {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.queries.set(self.queries.get() + 1);
        self.db.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.others.set(self.others.get() + 1);
        self.db.exec(sql, params).await
    }
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        self.others.set(self.others.get() + 1);
        self.db.batch(stmts).await
    }
}

/// The address count, the pool count and the take are one statement:
/// D1 runs a statement alone, so two acquires cannot both see room and
/// both take a slot. A count in a statement of its own could.
#[tokio::test]
async fn an_acquire_under_every_limit_is_one_statement() {
    let c = SqlCatalog::new(Counting {
        db: RusqliteSql::with_schema().unwrap(),
        queries: std::cell::Cell::new(0),
        others: std::cell::Cell::new(0),
    });
    let mut p = capped("p1", 4, 2);
    p.pool = Some("bundle".into());
    p.pool_max_conns = Some(4);
    c.seed_permits(core::slice::from_ref(&p)).await.unwrap();
    let sent = || (c.sql.queries.get(), c.sql.others.get());
    let seeded = sent();

    // One statement decides. The one before it only frees expired slots.
    let granted = c.acquire_permit(&p, PermitClass::Read, "a", T0).await;
    assert!(granted.unwrap().is_some());
    assert_eq!(sent(), (seeded.0 + 1, seeded.1 + 1));
    c.acquire_permit(&p, PermitClass::Read, "b", T0)
        .await
        .unwrap()
        .unwrap();
    // Refused for the address limit: one statement, and no write of the
    // slots (nothing has expired, and the seeding insert adds none).
    let before = sent();
    let refused = c.acquire_permit(&p, PermitClass::Read, "c", T0).await;
    assert!(refused.unwrap().is_none());
    assert_eq!(sent(), (before.0 + 1, before.1 + 2));
    let slots = c
        .sql
        .db
        .query("SELECT COUNT(*) FROM provider_permits", &[])
        .await
        .unwrap();
    assert_eq!(slots[0][0], SqlValue::Int(4));

    // No address limit: the take alone.
    p.id = "p2".into();
    p.max_ips = None;
    c.seed_permits(core::slice::from_ref(&p)).await.unwrap();
    let before = sent();
    let granted = c.acquire_permit(&p, PermitClass::Read, "c", T0).await;
    assert!(granted.unwrap().is_some());
    assert_eq!(sent(), (before.0 + 1, before.1));
}
