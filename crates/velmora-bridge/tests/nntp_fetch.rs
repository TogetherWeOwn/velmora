//! Cold reads against the in-process NNTP server: every article is read
//! with one `BODY`, verified, and only a complete verified extent is
//! cached and returned.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::fetch::ColdFetch;
use velmora_bridge::*;

const PLAIN_LEN: usize = 1_500_000;

impl Rig {
    /// Posts the extent, then removes the safety copy: Usenet is the only
    /// source left.
    async fn posted_cold(&self, n: u8) -> (Seeded, Vec<ArticleRow>) {
        let s = self.seed(n, &marked_plaintext(PLAIN_LEN)).await;
        let plan = self.post(&s).await;
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

    fn cached(&self, s: &Seeded) -> Option<Vec<u8>> {
        self.bridge
            .cache
            .stored(&s.extent.cache_key())
            .map(|b| b.bytes)
    }
}

#[tokio::test]
async fn cold_read_returns_verified_bytes_and_fills_the_cache() {
    let rig = simple_rig().await;
    let (s, _) = rig.posted_cold(1).await;
    let before = rig.bridge.nntp.connects();

    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    // The complete extent is in the cache; the safety store is untouched.
    assert_eq!(rig.cached(&s), Some(s.cipher.clone()));
    assert!(!rig.bridge.safety.contains(&s.extent.safety_key()));
    assert_eq!(rig.bridge.nntp.connects() - before, 1);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A `430` is a one-line reply: the same session serves the next article.
#[tokio::test]
async fn body_430_keeps_session() {
    let rig = simple_rig().await;
    let (s, plan) = rig.posted_cold(2).await;
    rig.server().hide(&plan[1].message_id).await;

    // On the session port itself.
    let mut client = rig.raw_client(0).await;
    let mut out = Vec::new();
    let missing = NntpSession::body(&mut client, &plan[1].message_id, &mut out).await;
    assert_eq!(missing.unwrap(), BodyOutcome::Missing);
    let found = NntpSession::body(&mut client, &plan[2].message_id, &mut out).await;
    assert_eq!(found.unwrap(), BodyOutcome::Found);
    assert!(!out.is_empty());
    NntpSession::quit(client).await;

    // Through the read path: one session for the whole pass and the retry,
    // and an incomplete extent is neither returned nor cached.
    let before = rig.bridge.nntp.connects();
    assert_eq!(rig.fetch(&s).await, ColdFetch::Unavailable);
    assert_eq!(rig.bridge.nntp.connects() - before, 1);
    assert_eq!(rig.cached(&s), None);

    rig.server().unhide(&plan[1].message_id).await;
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
}

/// A connection that dies mid-body is replaced and the read resumes at the
/// same article.
#[tokio::test]
async fn read_reconnects_after_drop() {
    let rig = simple_rig().await;
    let (s, _) = rig.posted_cold(3).await;

    rig.server().drop_next_bodies(1).await;
    let before = rig.bridge.nntp.connects();
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.bridge.nntp.connects() - before, 2);
    assert_eq!(rig.bridge.nntp.peak(), 1);
}

/// Reconnects are bounded, and a truncated body is never used.
#[tokio::test]
async fn read_reconnects_are_bounded() {
    let rig = simple_rig().await;
    let (s, _) = rig.posted_cold(4).await;

    rig.server().drop_next_bodies(3).await;
    let before = rig.bridge.nntp.connects();
    assert_eq!(rig.fetch(&s).await, ColdFetch::Unavailable);
    assert_eq!(rig.bridge.nntp.connects() - before, 3);
    assert_eq!(rig.cached(&s), None);
    assert_eq!(rig.bridge.nntp.live(), 0);

    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
}

/// An article that decodes cleanly but is not the planned payload fails
/// its SHA-256 check: nothing is returned and nothing is cached.
#[tokio::test]
async fn corrupt_article_is_never_returned() {
    let rig = simple_rig().await;
    let s = rig.seed(5, &marked_plaintext(PLAIN_LEN)).await;
    rig.post_with_planted_article(&s, 1).await;
    rig.bridge
        .safety
        .delete(&s.extent.safety_key())
        .await
        .unwrap();

    assert_eq!(rig.fetch(&s).await, ColdFetch::Unavailable);
    assert_eq!(rig.cached(&s), None);
}

/// Each article comes from the first provider that serves it intact.
#[tokio::test]
async fn cold_read_falls_back_per_article() {
    let rig = two_backbone_rig().await;
    let s = rig.seed(6, &marked_plaintext(PLAIN_LEN)).await;
    // p0 holds a corrupt article 1; p1 gets good copies of 0 and 2 by
    // peering and a good article 1 of its own.
    let plan = rig.post_with_planted_article(&s, 1).await;
    let mut src = rig.raw_client(0).await;
    let mut dst = rig.raw_client(1).await;
    for row in [&plan[0], &plan[2]] {
        let mut article = Vec::new();
        src.article_to(&row.message_id, &mut article).await.unwrap();
        dst.post_article(&row.message_id, &article).await.unwrap();
    }
    src.quit().await;
    dst.quit().await;
    rig.bridge
        .safety
        .delete(&s.extent.safety_key())
        .await
        .unwrap();
    // Without article 1 on p1 the extent cannot be completed.
    assert_eq!(rig.fetch(&s).await, ColdFetch::Unavailable);
    assert_eq!(rig.cached(&s), None);

    // A good copy of article 1 on p1; article 0 disappears from p0.
    let row = &plan[1];
    let good = render(&plan, row, &s.cipher, false);
    let mut dst = rig.raw_client(1).await;
    dst.post_article(&row.message_id, &good).await.unwrap();
    dst.quit().await;
    rig.servers[0].hide(&plan[0].message_id).await;

    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
    assert_eq!(rig.cached(&s), Some(s.cipher.clone()));
}

/// No free slot: no socket, and the caller is told to come back.
#[tokio::test]
async fn cold_read_without_a_slot_is_busy() {
    let rig = simple_rig().await;
    let (s, _) = rig.posted_cold(7).await;
    let provider = rig.bridge.cfg.providers[0].clone();
    let now = rig.bridge.clock.now();
    let mut held = Vec::new();
    for _ in 0..provider.max_conns {
        let permit = rig
            .bridge
            .catalog
            .acquire_permit(&provider, PermitClass::Read, "t", now);
        held.push(permit.await.unwrap().expect("free slot"));
    }

    let before = rig.bridge.nntp.connects();
    assert_eq!(rig.fetch(&s).await, ColdFetch::Busy);
    assert_eq!(rig.bridge.nntp.connects(), before);
    assert_eq!(rig.cached(&s), None);

    for permit in &held {
        rig.bridge.catalog.release_permit(permit).await.unwrap();
    }
    assert_eq!(rig.fetch(&s).await, ColdFetch::Filled(s.cipher.clone()));
}

/// Overlapping cold reads never hold more connections than the provider
/// allows; reads may use every slot.
#[tokio::test]
async fn permits_never_exceed_max_conns() {
    let rig = simple_rig().await;
    let mut seeded = Vec::new();
    for n in 10..14 {
        seeded.push(rig.posted_cold(n).await.0);
    }
    let base = rig.bridge.nntp.connects();

    let (a, b, c, d) = tokio::join!(
        rig.fetch(&seeded[0]),
        rig.fetch(&seeded[1]),
        rig.fetch(&seeded[2]),
        rig.fetch(&seeded[3]),
    );
    let results = [a, b, c, d];
    assert_eq!(results.iter().filter(|r| **r == ColdFetch::Busy).count(), 2);
    for (s, r) in seeded.iter().zip(&results) {
        if *r != ColdFetch::Busy {
            assert_eq!(*r, ColdFetch::Filled(s.cipher.clone()));
        }
    }
    assert_eq!(rig.bridge.nntp.peak(), 2);
    assert_eq!(rig.bridge.nntp.connects() - base, 2);
    assert_eq!(rig.bridge.catalog.permit_peak.borrow()["p0"], 2);
    assert_eq!(rig.bridge.nntp.live(), 0);
}
