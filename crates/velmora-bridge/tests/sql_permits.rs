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
