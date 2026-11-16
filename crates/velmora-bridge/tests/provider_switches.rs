//! The per-provider `post` and `read` switches. A provider with
//! `read: false` is an account whose downloads cost (a block account): no
//! stage may read from it. One with `post: false` is never posted to.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::fetch::ColdFetch;
use velmora_bridge::*;

const PLAIN_LEN: usize = 1_500_000;

/// `p0` posts and never reads (backbone `bb0`); `p1` reads and never
/// posts (backbone `bb1`). Peering is the test's `propagate`.
async fn post_only_and_read_only() -> Rig {
    let mut rig = rig(&[
        Spec {
            backbone: "bb0",
            post: true,
            max_conns: 2,
        },
        Spec {
            backbone: "bb1",
            post: false,
            max_conns: 2,
        },
    ])
    .await;
    rig.bridge.cfg.providers[0].read = false;
    rig
}

#[tokio::test]
async fn a_post_only_provider_is_posted_to_and_never_read() {
    let rig = post_only_and_read_only().await;
    let s = rig.seed(1, &marked_plaintext(PLAIN_LEN)).await;

    // Post: only the provider that posts.
    let plan = rig.post(&s).await;
    assert!(rig.bridge.nntp.connects_to("p0") >= 1);
    assert_eq!(rig.bridge.nntp.connects_to("p1"), 0);
    assert_eq!(rig.servers[0].posted_count().await, plan.len());
    assert_eq!(rig.servers[1].posted_count().await, 0);
    let posted = rig.bridge.nntp.connects_to("p0");

    // Verify: the posting backbone is not read, so it is no copy; the
    // backbone the articles reached is read and counts.
    rig.propagate(&s, 0, 1).await;
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    assert_eq!(rig.bridge.nntp.connects_to("p0"), posted);
    let rows = rig.bridge.catalog.verifications(&s.extent);
    assert!(!rows.is_empty());
    assert!(rows
        .iter()
        .all(|r| r.backbone == "bb1" && r.provider_id == "p1"));
    assert!(rows.iter().all(|r| r.result == VerifyResult::Ok));
    assert_eq!(
        rig.bridge.catalog.outbox(&s.extent).stage,
        OutboxStage::Release
    );

    // Cold read with no safety copy and no cache: from the reader only.
    rig.bridge
        .safety
        .delete(&s.extent.safety_key())
        .await
        .unwrap();
    let extent = rig.bridge.catalog.extent(&s.extent);
    assert_eq!(
        rig.bridge.fetch_cold(&extent).await.unwrap(),
        ColdFetch::Filled(s.cipher.clone())
    );
    assert_eq!(rig.bridge.nntp.connects_to("p0"), posted);
    assert!(rig.bridge.nntp.connects_to("p1") >= 2);
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// With no reader left that has the articles, a cold read gives up rather
/// than ask the provider that only posts, though it holds them.
#[tokio::test]
async fn a_cold_read_never_falls_back_to_a_post_only_provider() {
    let rig = post_only_and_read_only().await;
    let s = rig.seed(2, &marked_plaintext(PLAIN_LEN)).await;
    rig.post(&s).await;
    let posted = rig.bridge.nntp.connects_to("p0");
    rig.bridge
        .safety
        .delete(&s.extent.safety_key())
        .await
        .unwrap();

    let extent = rig.bridge.catalog.extent(&s.extent);
    assert_eq!(
        rig.bridge.fetch_cold(&extent).await.unwrap(),
        ColdFetch::Unavailable
    );
    assert_eq!(rig.bridge.nntp.connects_to("p0"), posted);
}
