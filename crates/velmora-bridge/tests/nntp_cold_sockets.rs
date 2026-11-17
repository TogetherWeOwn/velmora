//! Cold reads over several connections: the articles of an extent are
//! read on whichever socket is free and still land in their places, an
//! article one provider cannot supply comes from the next, and a provider
//! that breaks off does not fail a read another provider can complete.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::fetch::ColdFetch;
use velmora_bridge::*;

/// Nine articles.
const PLAIN_LEN: usize = 6_000_000;

async fn rig_of(conns: &[u32], sockets: u32) -> Rig {
    let specs: Vec<Spec> = conns
        .iter()
        .enumerate()
        .map(|(i, &max_conns)| Spec {
            backbone: ["bb0", "bb1", "bb2"][i],
            post: i == 0,
            max_conns,
        })
        .collect();
    let mut rig = rig(&specs).await;
    rig.bridge.cfg.cold_sockets = sockets;
    rig
}

impl Rig {
    /// Posts an extent of `len` plaintext bytes to `p0` and removes the
    /// safety copy: Usenet is the only source left.
    async fn posted_cold(&self, n: u8, len: usize) -> (Seeded, Vec<ArticleRow>) {
        let s = self.seed(n, &marked_plaintext(len)).await;
        let plan = self.post(&s).await;
        self.bridge
            .safety
            .delete(&s.extent.safety_key())
            .await
            .unwrap();
        (s, plan)
    }

    /// Copies `rows` from `p0` to provider `to`, as peering would.
    async fn peer(&self, to: usize, rows: &[&ArticleRow]) {
        let mut src = self.raw_client(0).await;
        let mut dst = self.raw_client(to).await;
        for row in rows {
            let mut article = Vec::new();
            src.article_to(&row.message_id, &mut article).await.unwrap();
            dst.post_article(&row.message_id, &article).await.unwrap();
        }
        src.quit().await;
        dst.quit().await;
    }

    async fn fetch(&self, s: &Seeded) -> ColdFetch {
        let extent = self.bridge.catalog.extent(&s.extent);
        self.bridge.fetch_cold(&extent).await.unwrap()
    }

    fn cached(&self, s: &Seeded) -> Option<Vec<u8>> {
        self.bridge
            .cache
            .stored(&s.extent.cache_key())
            .map(|b| b.bytes)
    }
}

/// Four sockets read nine articles; whatever order they finish in, the
/// extent is the one that was posted, and it is in the cache.
#[tokio::test]
async fn several_sockets_fill_the_extent_in_order() {
    let rig = rig_of(&[6], 4).await;
    let (s, plan) = rig.posted_cold(1, PLAIN_LEN).await;
    assert_eq!(plan.len(), 9);
    let before = rig.bridge.nntp.connects();

    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.cached(&s), Some(s.cipher.clone()));
    assert_eq!(rig.bridge.nntp.connects() - before, 4);
    assert_eq!(rig.bridge.nntp.peak(), 4);
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p0"], 4);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A read never opens more sockets than the extent has articles, nor
/// more than the provider has slots.
#[tokio::test]
async fn sockets_are_bounded_by_articles_and_slots() {
    let rig = rig_of(&[8], 8).await;
    // Three articles.
    let (s, plan) = rig.posted_cold(2, 1_500_000).await;
    assert_eq!(plan.len(), 3);
    let before = rig.bridge.nntp.connects();
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.bridge.nntp.connects() - before, 3);

    let rig = rig_of(&[2], 8).await;
    let (s, _) = rig.posted_cold(3, PLAIN_LEN).await;
    let before = rig.bridge.nntp.connects();
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.bridge.nntp.connects() - before, 2);
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p0"], 2);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// The sockets spread over the providers of one tier.
#[tokio::test]
async fn sockets_spread_over_the_providers_of_a_tier() {
    let rig = rig_of(&[4, 4], 4).await;
    let (s, plan) = rig.posted_cold(4, PLAIN_LEN).await;
    rig.peer(1, &plan.iter().collect::<Vec<_>>()).await;

    let before = |id| rig.bridge.nntp.connects_to(id);
    let (p0, p1) = (before("p0"), before("p1"));
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.bridge.nntp.connects_to("p0") - p0, 2);
    assert_eq!(rig.bridge.nntp.connects_to("p1") - p1, 2);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A provider of a lower tier is asked only for what the tier above
/// could not supply.
#[tokio::test]
async fn a_lower_tier_only_reads_what_the_tier_above_lacks() {
    let mut rig = rig_of(&[4, 4], 4).await;
    rig.bridge.cfg.providers[1].priority = 1;
    let (s, plan) = rig.posted_cold(5, PLAIN_LEN).await;
    rig.peer(1, &plan.iter().collect::<Vec<_>>()).await;

    let p1 = rig.bridge.nntp.connects_to("p1");
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.bridge.nntp.connects_to("p1"), p1, "p1 was not needed");

    // Two articles go missing on p0: p1 supplies exactly those.
    let (s, plan) = rig.posted_cold(6, PLAIN_LEN).await;
    rig.peer(1, &[&plan[2], &plan[7]]).await;
    rig.servers[0].hide(&plan[2].message_id).await;
    rig.servers[0].hide(&plan[7].message_id).await;
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert!(rig.bridge.nntp.connects_to("p1") > p1);
    assert_eq!(rig.cached(&s), Some(s.cipher.clone()));
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A reader that goes on to the next extent with connections to a lower
/// tier, which the extent before needed, does not read on over them:
/// the better tier has the next extent, and it reads all of it.
#[tokio::test]
async fn a_lower_tier_kept_from_the_extent_before_reads_nothing_the_tier_above_has() {
    let mut rig = rig_of(&[4, 4], 4).await;
    rig.bridge.cfg.providers[1].priority = 1;
    // The first is on p1 only, the second on both.
    let (first, plan) = rig.posted_cold(7, PLAIN_LEN).await;
    rig.peer(1, &plan.iter().collect::<Vec<_>>()).await;
    for row in &plan {
        rig.servers[0].hide(&row.message_id).await;
    }
    let (second, plan) = rig.posted_cold(8, PLAIN_LEN).await;
    rig.peer(1, &plan.iter().collect::<Vec<_>>()).await;

    let extents = [
        rig.bridge.catalog.extent(&first.extent),
        rig.bridge.catalog.extent(&second.extent),
    ];
    let (read, stats) = rig.bridge.fetch_cold_run(&extents).await.unwrap();
    assert_eq!(
        read,
        [
            ColdFetch::Filled(first.cipher.clone()),
            ColdFetch::Filled(second.cipher.clone())
        ]
    );
    let articles = |id: &str| {
        stats
            .share
            .iter()
            .find(|s| s.0 == id)
            .map_or(0, |s| s.1 as usize)
    };
    assert_eq!(articles("p1"), plan.len(), "the first extent only");
    assert_eq!(articles("p0"), plan.len(), "all of the second");
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// The extent was read and verified: a cache that does not take the
/// copy does not fail the read.
#[tokio::test]
async fn a_cache_that_refuses_the_copy_does_not_fail_the_read() {
    let rig = rig_of(&[4], 4).await;
    let (s, _) = rig.posted_cold(9, PLAIN_LEN).await;
    rig.bridge.cache.refuse_puts(true);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.cached(&s), None);
    assert_eq!(rig.bridge.nntp.live(), 0);
    rig.bridge.cache.refuse_puts(false);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.cached(&s), Some(s.cipher.clone()));
}

/// An article that one provider has with other bytes, and one it does
/// not have, come from the other provider; without them there, the
/// extent is not returned and not cached.
#[tokio::test]
async fn a_missing_or_corrupt_article_comes_from_another_provider() {
    let rig = rig_of(&[4, 4], 4).await;
    let s = rig.seed(7, &marked_plaintext(PLAIN_LEN)).await;
    // p0 holds a corrupt article 3.
    let plan = rig.post_with_planted_article(&s, 3).await;
    rig.bridge
        .safety
        .delete(&s.extent.safety_key())
        .await
        .unwrap();
    rig.servers[0].hide(&plan[5].message_id).await;
    let others: Vec<&ArticleRow> = plan.iter().filter(|r| r.idx != 3 && r.idx != 5).collect();
    rig.peer(1, &others).await;

    assert_eq!(rig.fetch(&s).await, ColdFetch::Unavailable);
    assert_eq!(rig.cached(&s), None);

    // p1 gets a good article 3 of its own and article 5 by peering.
    let good = render(&plan, &plan[3], &s.cipher, false);
    let mut dst = rig.raw_client(1).await;
    dst.post_article(&plan[3].message_id, &good).await.unwrap();
    dst.quit().await;
    rig.servers[0].unhide(&plan[5].message_id).await;
    rig.peer(1, &[&plan[5]]).await;
    rig.servers[0].hide(&plan[5].message_id).await;

    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.cached(&s), Some(s.cipher.clone()));
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A connection that dies mid-body does not fail the read: the article
/// is read again, on a new connection or on another socket.
#[tokio::test]
async fn a_dropped_connection_does_not_fail_the_read() {
    let rig = rig_of(&[4], 4).await;
    let (s, _) = rig.posted_cold(8, PLAIN_LEN).await;
    rig.server().drop_next_bodies(2).await;

    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.bridge.nntp.peak(), 4);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A provider whose every connection breaks off does not fail a read
/// that another provider can complete.
#[tokio::test]
async fn a_provider_that_breaks_off_is_replaced_by_another() {
    let rig = rig_of(&[4, 4], 4).await;
    let (s, plan) = rig.posted_cold(9, PLAIN_LEN).await;
    rig.peer(1, &plan.iter().collect::<Vec<_>>()).await;
    rig.servers[0].drop_next_bodies(1_000).await;

    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.cached(&s), Some(s.cipher.clone()));
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// When no provider can complete the extent, the read ends as
/// retryable: nothing is returned, nothing is cached, every slot is
/// free again, and the next read succeeds.
#[tokio::test]
async fn a_read_no_provider_completes_is_interrupted_and_caches_nothing() {
    let rig = rig_of(&[4], 4).await;
    let (s, _) = rig.posted_cold(10, PLAIN_LEN).await;
    rig.server().drop_next_bodies(1_000).await;

    assert_eq!(rig.fetch(&s).await, ColdFetch::Interrupted);
    assert_eq!(rig.cached(&s), None);
    assert_eq!(rig.bridge.nntp.live(), 0);
    let now = rig.bridge.clock.now();
    let load = rig.bridge.catalog.provider_load(now).await.unwrap();
    assert!(load.iter().all(|l| l.held == 0), "a slot is still held");

    rig.server().drop_next_bodies(0).await;
    rig.bridge.clock.advance_secs(3_600);
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
}

/// Two reads at once share a provider's slots: neither takes more than
/// the provider has, and a read that got none is told to come back.
#[tokio::test]
async fn overlapping_reads_never_exceed_the_slots() {
    let rig = rig_of(&[4], 4).await;
    let (a, _) = rig.posted_cold(11, PLAIN_LEN).await;
    let (b, _) = rig.posted_cold(12, PLAIN_LEN).await;

    let (ra, rb) = tokio::join!(rig.fetch(&a), rig.fetch(&b));
    for (s, r) in [(&a, &ra), (&b, &rb)] {
        assert!(
            *r == ColdFetch::Filled(s.cipher.clone()) || *r == ColdFetch::Busy,
            "a read ended as neither filled nor busy"
        );
    }
    assert!(ra != ColdFetch::Busy || rb != ColdFetch::Busy);
    assert_eq!(rig.bridge.nntp.peak(), 4);
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p0"], 4);
    assert_eq!(rig.bridge.nntp.live(), 0);
}
