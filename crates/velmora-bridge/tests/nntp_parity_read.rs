//! Cold reads of extents with parity over two providers: parity is read
//! only for articles that are lost where they were asked for, a reader
//! that could not be asked is never taken for one that lost them, and a
//! rebuild holds its room in the byte budget or does not start.

mod nntp_support;

use nntp_support::*;
use velmora::rng::SystemRng;
use velmora::yenc::decode_part_to;
use velmora_bridge::fetch::{cold_rebuild_bytes, ColdFetch, ColdStats};
use velmora_bridge::parity;
use velmora_bridge::*;

/// Three data articles and one parity article.
const THREE: usize = 1_500_000;
/// Ten data articles and two parity articles.
const TEN: usize = 6_500_000;

/// An extent that is only on Usenet, with what the rig reads it from.
struct Stripe {
    rig: Rig,
    s: Seeded,
    data: Vec<ArticleRow>,
    parity: Vec<ArticleRow>,
}

/// `p0` posts an extent of `len` plaintext bytes with its parity, every
/// provider after it has all of it by peering, and the safety copy is
/// gone. Every call to a provider is noted from here on.
async fn posted(n: u8, len: usize, providers: usize) -> Stripe {
    let specs: Vec<Spec> = ["bb0", "bb1"][..providers]
        .iter()
        .enumerate()
        .map(|(i, backbone)| Spec {
            backbone,
            post: i == 0,
            max_conns: 2,
        })
        .collect();
    let mut rig = rig(&specs).await;
    rig.bridge.cfg.packed_plans = true;
    rig.bridge.cfg.parity = true;
    let s = rig.seed(n, &marked_plaintext(len)).await;
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let stored = rig.bridge.catalog.stored_plan(&s.extent).await.unwrap();
    let parity = stored
        .parity_plan(&s.extent, s.cipher.len() as u64)
        .unwrap()
        .expect("the extent has parity")
        .articles;
    let data = stored.rows;
    for to in 1..providers {
        let mut src = rig.raw_client(0).await;
        let mut dst = rig.raw_client(to).await;
        for row in data.iter().chain(&parity) {
            let mut article = Vec::new();
            src.article_to(&row.message_id, &mut article).await.unwrap();
            dst.post_article(&row.message_id, &article).await.unwrap();
        }
        src.quit().await;
        dst.quit().await;
    }
    rig.bridge
        .safety
        .delete(&s.extent.safety_key())
        .await
        .unwrap();
    rig.bridge.nntp.slow(&rig.bridge.clock, 0);
    Stripe {
        rig,
        s,
        data,
        parity,
    }
}

impl Stripe {
    /// One read of the extent by a reader of its own: how it ended and
    /// what the reader counted.
    async fn read(&self) -> (ColdFetch, ColdStats) {
        let extent = self.rig.bridge.catalog.extent(&self.s.extent);
        let (mut read, stats) = self.rig.bridge.fetch_cold_run(&[extent]).await.unwrap();
        (read.remove(0), stats)
    }

    /// Calls of one kind to the providers so far.
    fn calls(&self, what: &str) -> usize {
        let calls = self.rig.bridge.nntp.calls();
        calls.iter().filter(|call| call.0 == what).count()
    }

    /// Articles the providers hold, all of them together.
    async fn held(&self) -> usize {
        let mut held = 0;
        for server in &self.rig.servers {
            held += server.posted_count().await;
        }
        held
    }

    /// Takes every connection slot of provider `i`: a read gets none.
    async fn occupy(&self, i: usize) {
        let provider = self.rig.bridge.cfg.providers[i].clone();
        let now = self.rig.bridge.clock.now();
        for _ in 0..provider.max_conns {
            let permit = self.rig.bridge.catalog.acquire_permit(
                &provider,
                PermitClass::Read,
                "elsewhere",
                now,
            );
            permit.await.unwrap().expect("free slot");
        }
    }

    /// Provider `i` failed often enough to be left alone for a while.
    async fn cool(&self, i: usize) {
        let id = format!("p{i}");
        let catalog = &self.rig.bridge.catalog;
        let now = self.rig.bridge.clock.now();
        for _ in 0..10 {
            catalog
                .provider_failed(&id, ProviderFault::SessionFailed, now)
                .await
                .unwrap();
        }
        let load = catalog.provider_load(now).await.unwrap();
        let load = load.into_iter().find(|l| l.provider_id == id).unwrap();
        assert!(load.cooldown_until > now, "{id} is not cooling");
    }
}

fn verified(stats: &ColdStats) -> u32 {
    stats.share.iter().map(|share| share.1).sum()
}

/// An article that one provider lost and the other has is read from the
/// other: no parity article is asked for, and nothing is rebuilt. Each
/// provider lost one here, so whichever is asked first lacks one.
#[tokio::test]
async fn an_article_another_provider_has_costs_no_parity_read() {
    let st = posted(1, TEN, 2).await;
    st.rig.servers[0].hide(&st.data[4].message_id).await;
    st.rig.servers[1].hide(&st.data[7].message_id).await;

    let (read, stats) = st.read().await;

    assert_eq!(read, ColdFetch::Filled(st.s.cipher.clone()));
    assert_eq!((stats.rebuilt, stats.unrecoverable), (0, 0));
    // Both providers have every parity article: one that was asked for
    // would have been verified and counted. Ten were, the data articles.
    assert_eq!(verified(&stats), 10);
    // A `BODY` for each, and two more for the one the first provider
    // lacks: it is asked twice before the article counts as missing
    // there.
    assert_eq!(st.calls("body"), 12);
}

/// More articles are lost on the provider that answered than the parity
/// rebuilds, and the other provider has no free slot: the read is worth
/// another try, and is not called unrecoverable.
#[tokio::test]
async fn a_loss_beyond_parity_is_not_final_while_a_provider_is_busy() {
    let st = posted(2, THREE, 2).await;
    st.rig.servers[0].hide(&st.data[0].message_id).await;
    st.rig.servers[0].hide(&st.data[2].message_id).await;
    st.occupy(1).await;

    let (read, stats) = st.read().await;

    assert_eq!(read, ColdFetch::Busy);
    assert_eq!((stats.rebuilt, stats.unrecoverable), (0, 0));
    // Two are lost and there is one parity article: none was asked for.
    assert_eq!(verified(&stats), 1);
}

/// The same while the other provider is left alone after failures.
#[tokio::test]
async fn a_loss_beyond_parity_is_not_final_while_a_provider_is_cooling() {
    let st = posted(3, THREE, 2).await;
    st.rig.servers[0].hide(&st.data[0].message_id).await;
    st.rig.servers[0].hide(&st.data[2].message_id).await;
    st.cool(1).await;

    let (read, stats) = st.read().await;

    assert_eq!(read, ColdFetch::Interrupted);
    assert_eq!((stats.rebuilt, stats.unrecoverable), (0, 0));
}

/// With both providers answering, the same loss on both is final.
#[tokio::test]
async fn a_loss_beyond_parity_on_every_provider_is_unrecoverable() {
    let st = posted(4, THREE, 2).await;
    for server in &st.rig.servers {
        server.hide(&st.data[0].message_id).await;
        server.hide(&st.data[2].message_id).await;
    }

    let (read, stats) = st.read().await;

    assert_eq!(read, ColdFetch::Unrecoverable);
    assert_eq!((stats.rebuilt, stats.unrecoverable), (0, 1));
    assert_eq!(stats.extents, 0);
}

/// A loss within the parity is rebuilt from the provider that answered
/// while the other has no free slot. The rebuild posts nothing and
/// leaves the catalogue as it was.
#[tokio::test]
async fn a_loss_within_parity_is_rebuilt_while_a_provider_is_busy() {
    let st = posted(5, THREE, 2).await;
    st.rig.servers[0].hide(&st.data[1].message_id).await;
    st.occupy(1).await;
    let held = st.held().await;
    let catalog = &st.rig.bridge.catalog;
    let before = (
        catalog.mark_batches.get(),
        catalog.stored_plan(&st.s.extent).await.unwrap(),
        catalog.extent(&st.s.extent),
    );

    let (read, stats) = st.read().await;

    assert_eq!(read, ColdFetch::Filled(st.s.cipher.clone()));
    assert_eq!((stats.rebuilt, stats.unrecoverable), (1, 0));
    assert_eq!(stats.extents, 1);
    // Two data articles and the parity article.
    assert_eq!(verified(&stats), 3);
    assert_eq!(st.calls("post"), 0);
    assert_eq!(st.held().await, held);
    let after = (
        catalog.mark_batches.get(),
        catalog.stored_plan(&st.s.extent).await.unwrap(),
        catalog.extent(&st.s.extent),
    );
    assert!(before == after, "the read changed the catalogue");
}

/// The same while the other provider is left alone after failures.
#[tokio::test]
async fn a_loss_within_parity_is_rebuilt_while_a_provider_is_cooling() {
    let st = posted(6, THREE, 2).await;
    st.rig.servers[0].hide(&st.data[1].message_id).await;
    st.cool(1).await;

    let (read, stats) = st.read().await;

    assert_eq!(read, ColdFetch::Filled(st.s.cipher.clone()));
    assert_eq!((stats.rebuilt, stats.unrecoverable), (1, 0));
}

/// A provider with no free slot may have the parity article too: a
/// rebuild that could not get it leaves the read as it was, to be tried
/// again.
#[tokio::test]
async fn a_rebuild_short_of_parity_is_not_final_while_a_provider_is_busy() {
    let st = posted(7, THREE, 2).await;
    st.rig.servers[0].hide(&st.data[1].message_id).await;
    st.rig.servers[0].hide(&st.parity[0].message_id).await;
    st.occupy(1).await;

    let (read, stats) = st.read().await;

    assert_eq!(read, ColdFetch::Busy);
    assert_eq!((stats.rebuilt, stats.unrecoverable), (0, 0));
}

/// An extent that no provider can be asked for is not counted as
/// unrecoverable: nothing is known to be lost.
#[tokio::test]
async fn an_extent_nobody_answered_for_is_not_counted_unrecoverable() {
    let mut st = posted(8, THREE, 1).await;
    st.rig.bridge.cfg.providers[0].read = false;

    let (read, stats) = st.read().await;

    assert_eq!(read, ColdFetch::Unavailable);
    assert_eq!((stats.rebuilt, stats.unrecoverable), (0, 0));
    assert_eq!(st.calls("body"), 0);
}

/// A rebuild that finds no room in the byte budget does not start: the
/// read is busy, holds nothing, and succeeds once there is room. Only as
/// many parity articles are charged as articles are lost.
#[tokio::test]
async fn a_rebuild_without_room_is_busy_and_holds_nothing() {
    let st = posted(9, TEN, 1).await;
    st.rig.servers[0].hide(&st.data[3].message_id).await;
    let shard = st.parity[0].cipher_len;
    // One lost of ten, with two parity articles: one is read.
    let need = cold_rebuild_bytes(shard, 1);
    assert_eq!(need, 5 * shard + 4);
    let budget = &st.rig.bridge.budget;
    let taken = budget.try_charge(budget.capacity() - need + 1).unwrap();

    let (read, stats) = st.read().await;

    assert_eq!(read, ColdFetch::Busy);
    assert_eq!((stats.rebuilt, stats.unrecoverable), (0, 0));
    assert_eq!(budget.in_use(), taken.bytes());
    // No parity article was read without the room for the rebuild.
    assert_eq!(verified(&stats), 9);

    // With exactly the room for it.
    drop(taken);
    let taken = budget.try_charge(budget.capacity() - need).unwrap();
    let (read, stats) = st.read().await;
    assert_eq!(read, ColdFetch::Filled(st.s.cipher.clone()));
    assert_eq!((stats.rebuilt, verified(&stats)), (1, 10));
    assert_eq!(budget.in_use(), taken.bytes());
    assert_eq!(budget.peak(), budget.capacity());
}

/// A parity article that no provider has intact leaves its place to the
/// next: the rebuild holds no more than as many as articles are lost.
#[tokio::test]
async fn a_parity_article_that_is_lost_leaves_its_place_to_the_next() {
    let st = posted(10, TEN, 1).await;
    st.rig.servers[0].hide(&st.data[3].message_id).await;
    st.rig.servers[0].hide(&st.parity[0].message_id).await;
    let need = cold_rebuild_bytes(st.parity[0].cipher_len, 1);
    let budget = &st.rig.bridge.budget;
    let taken = budget.try_charge(budget.capacity() - need).unwrap();

    let (read, stats) = st.read().await;

    assert_eq!(read, ColdFetch::Filled(st.s.cipher.clone()));
    assert_eq!((stats.rebuilt, verified(&stats)), (1, 10));
    assert_eq!(budget.in_use(), taken.bytes());
}

/// The parity articles are what the addendum says, byte for byte, but
/// were made with another row of the code than it names: what the codec
/// rebuilds is not the lost article. Nothing of it is used.
#[tokio::test]
async fn a_rebuilt_article_that_is_not_the_planned_one_is_not_used() {
    let st = posted(11, THREE, 1).await;
    let rig = &st.rig;
    let old = &st.parity[0];
    // The shard as it was posted, for row 0.
    let mut client = rig.raw_client(0).await;
    let mut article = Vec::new();
    client
        .article_to(&old.message_id, &mut article)
        .await
        .unwrap();
    let mut shard = vec![0u8; old.cipher_len as usize];
    let part = decode_part_to(&old.message_id, &article, &mut shard).unwrap();
    assert_eq!(part.written as u64, old.cipher_len);
    // An addendum that names it as row 5.
    rig.bridge.catalog.edit(&st.s.extent, |e| {
        let packed = e.packed.clone().unwrap();
        let other = parity::build(
            &mut SystemRng,
            T0.secs().0,
            &["alt.binaries.test"],
            &st.s.extent,
            st.s.cipher.len() as u64,
            &packed,
            &[(5, sha256(&shard))],
        );
        e.parity = Some(other.unwrap());
    });
    let stored = rig.bridge.catalog.stored_plan(&st.s.extent).await.unwrap();
    let renamed = stored
        .parity_plan(&st.s.extent, st.s.cipher.len() as u64)
        .unwrap()
        .unwrap()
        .articles;
    let row = &renamed[0];
    let mut bytes = vec![0u8; (row.cipher_offset + row.cipher_len) as usize];
    bytes[row.cipher_offset as usize..].copy_from_slice(&shard);
    let all: Vec<ArticleRow> = st.data.iter().chain(&renamed).cloned().collect();
    let planted = render(&all, row, &bytes, false);
    client
        .post_article(&row.message_id, &planted)
        .await
        .unwrap();
    client.quit().await;

    // Nothing is lost: the parity is not looked at.
    let (read, _) = st.read().await;
    assert_eq!(read, ColdFetch::Filled(st.s.cipher.clone()));

    rig.servers[0].hide(&st.data[1].message_id).await;
    let (read, stats) = st.read().await;

    assert_eq!(read, ColdFetch::Unrecoverable);
    assert_eq!((stats.rebuilt, stats.unrecoverable), (0, 1));
    // The parity article was read and passed its own SHA-256.
    assert_eq!(verified(&stats), 3);
    assert_eq!(rig.bridge.budget.in_use(), 0);
}

/// The preferred provider gives fewer connections than the reader asks
/// for, and lacks a data article; the provider of the next tier is asked
/// for it and lacks it too, and has no parity for it. The connections
/// of the preferred provider were ended for that, so its slots are free:
/// the parity article is read from it and the article rebuilt.
#[tokio::test]
async fn parity_is_read_from_a_provider_whose_slots_a_tier_switch_freed() {
    let mut st = posted(12, THREE, 2).await;
    // More sockets than `p0` has slots, and `p1` only asked after it.
    st.rig.bridge.cfg.cold_sockets = 4;
    st.rig.bridge.cfg.providers[1].priority = 1;
    st.rig.servers[0].hide(&st.data[1].message_id).await;
    st.rig.servers[1].hide(&st.data[1].message_id).await;
    st.rig.servers[1].hide(&st.parity[0].message_id).await;

    let (read, stats) = st.read().await;

    assert!(read == ColdFetch::Filled(st.s.cipher.clone()), "{stats:?}");
    assert_eq!((stats.rebuilt, stats.unrecoverable), (1, 0));
}
