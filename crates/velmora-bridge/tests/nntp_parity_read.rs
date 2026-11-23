//! Cold reads of extents with parity over two providers: parity is read
//! only for articles that are lost where they were asked for, a reader
//! that could not be asked is never taken for one that lost them, and a
//! rebuild holds its room in the byte budget or does not start.

mod nntp_support;
mod service_support;

use nntp_support::*;
use std::cell::Cell;
use std::rc::Rc;
use velmora::rng::SystemRng;
use velmora::yenc::decode_part_to;
use velmora_bridge::fetch::{
    cold_rebuild_bytes, cold_step_bytes, ColdFetch, ColdStats, COLD_WAIT_MS,
};
use velmora_bridge::ingress::{ByteBudget, Sleeper, CHARGE_POLL_MS};
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

const GET_KEY: &str = "extent.bin";

struct ColdGet {
    nntp: Rig,
    svc: service_support::Rig<TcpConnector>,
    bucket: Bucket,
    signer: service_support::Signer,
    extent: ExtentRow,
}

impl ColdGet {
    async fn get(&self) -> service_support::Resp {
        self.svc
            .call(
                &self.signer,
                Method::Get,
                &service_support::path(&self.bucket.name, GET_KEY),
                &[],
                &[],
                b"",
            )
            .await
    }
}

async fn posted_for_get(
    body: &[u8],
    with_parity: bool,
    pooled: bool,
    sleeper: Option<Sleeper>,
) -> ColdGet {
    let specs = [
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
    ];
    let nntp = rig(&specs[..if pooled { 2 } else { 1 }]).await;
    let mut providers = nntp.bridge.cfg.providers.clone();
    if pooled {
        for p in &mut providers {
            p.pool = Some("shared".into());
            p.pool_max_conns = Some(1);
        }
    }
    let mut cfg = service_support::config(providers);
    cfg.cold_sockets = 2;
    cfg.packed_plans = with_parity;
    cfg.parity = with_parity;
    let mut budget = ByteBudget::new(cfg.inflight_budget_bytes);
    if let Some(sleeper) = sleeper {
        budget = budget.with_sleeper(sleeper);
    }
    let svc = service_support::rig_with_budget(TcpConnector::default(), cfg, budget);
    let bridge = &svc.bridge;
    bridge
        .catalog
        .seed_permits(&bridge.cfg.providers)
        .await
        .unwrap();
    let (bucket, signer) = svc.standard("cold-read").await;
    svc.put(&signer, &bucket.name, GET_KEY, body)
        .await
        .expect(200);
    let (generation, extents) = svc.live(&bucket, GET_KEY).await.unwrap();
    let extent = extents.into_iter().next().unwrap();
    let lease = bridge
        .catalog
        .claim(
            &extent.id,
            &generation.id,
            OutboxStage::Post,
            "post",
            svc.now(),
        )
        .await
        .unwrap()
        .unwrap();
    let job = bridge
        .catalog
        .job_extent(&extent.id, &generation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bridge.post_stage(&lease, &job).await, JobOutcome::Ack);
    bridge.cache.delete(&extent.id.cache_key()).await.unwrap();
    bridge.safety.delete(&extent.id.safety_key()).await.unwrap();
    bridge.nntp.slow(&bridge.clock, 0);
    ColdGet {
        nntp,
        svc,
        bucket,
        signer,
        extent,
    }
}

/// Exercise the S3 GET with one permit shared by two same-tier read
/// providers. The second provider has either one required parity article
/// or one required data article.
async fn shared_pool_cold_get(with_parity: bool) {
    let body = marked_plaintext(if with_parity { TEN } else { THREE });
    let cold = posted_for_get(&body, with_parity, true, None).await;
    let (nntp, bridge, extent) = (&cold.nntp, &cold.svc.bridge, &cold.extent);
    let stored = bridge.catalog.stored_plan(&extent.id).await.unwrap();
    let parity = stored.parity_plan(&extent.id, extent.cipher_size).unwrap();
    let mut src = nntp.raw_client(0).await;
    let mut dst = nntp.raw_client(1).await;
    for row in &stored.rows {
        let mut article = Vec::new();
        src.article_to(&row.message_id, &mut article).await.unwrap();
        dst.post_article(&row.message_id, &article).await.unwrap();
    }
    if let Some(parity) = parity {
        assert_eq!(parity.articles.len(), 2);
        let row = &parity.articles[1];
        let mut article = Vec::new();
        src.article_to(&row.message_id, &mut article).await.unwrap();
        dst.post_article(&row.message_id, &article).await.unwrap();
        nntp.servers[0].hide(&row.message_id).await;
        for row in &stored.rows[..2] {
            for server in &nntp.servers {
                server.hide(&row.message_id).await;
            }
        }
    } else {
        // Both providers are needed, regardless of which one is first
        // in the catalogue's order after the post.
        nntp.servers[0].hide(&stored.rows[0].message_id).await;
        nntp.servers[1].hide(&stored.rows[1].message_id).await;
    }
    src.quit().await;
    dst.quit().await;

    let response = cold.get().await;
    response.expect(200);
    assert!(
        response.body == body,
        "cold GET did not return the original bytes"
    );
    assert_eq!(bridge.nntp.peak(), 1);
    assert!(bridge.nntp.connects_to("p1") > 0);
}

#[tokio::test]
async fn cold_get_rebuilds_with_parity_split_over_one_shared_pool_slot() {
    shared_pool_cold_get(true).await;
}

#[tokio::test]
async fn cold_get_reads_data_from_the_waiting_provider_of_a_shared_pool() {
    shared_pool_cold_get(false).await;
}

/// A competitor takes the rebuild's room during the retry's cache
/// check. The extent alone fits, but the retry must wait for both rather
/// than download without enough room again.
#[tokio::test]
async fn cold_get_downloads_only_once_more_when_retry_rebuild_room_is_taken() {
    cold_get_with_retry_rebuild_room_taken(false).await;
}

#[tokio::test]
async fn cold_get_does_not_retry_when_rebuild_room_arrives_after_deadline() {
    cold_get_with_retry_rebuild_room_taken(true).await;
}

async fn cold_get_with_retry_rebuild_room_taken(expired: bool) {
    let polls = Rc::new(Cell::new(0u32));
    let released = Rc::new(Cell::new(0u32));
    let sleeper: Sleeper = {
        let (polls, released) = (polls.clone(), released.clone());
        Rc::new(move |ms| {
            if ms > CHARGE_POLL_MS {
                return Box::pin(std::future::pending());
            }
            let poll = polls.get() + 1;
            polls.set(poll);
            let released = released.clone();
            Box::pin(async move {
                while released.get() < poll {
                    tokio::task::yield_now().await;
                }
            })
        })
    };
    let body = marked_plaintext(THREE);
    let cold = posted_for_get(&body, true, false, Some(sleeper)).await;
    let bridge = &cold.svc.bridge;
    let extent = &cold.extent;
    let stored = bridge.catalog.stored_plan(&extent.id).await.unwrap();
    let parity = stored
        .parity_plan(&extent.id, extent.cipher_size)
        .unwrap()
        .unwrap();
    cold.nntp.server().hide(&stored.rows[1].message_id).await;

    let budget = &bridge.budget;
    let step = cold_step_bytes(extent.cipher_size, bridge.cfg.cold_sockets);
    let rebuild = cold_rebuild_bytes(parity.articles[0].cipher_len, 1);
    let base = budget.capacity() - step - rebuild;
    let block_first = budget.try_charge(base + 1).unwrap();
    let trip = &bridge.cache.trip;
    let competitor = async {
        while polls.get() == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            budget.in_use(),
            base + 1,
            "the read waits without its charge"
        );
        drop(block_first);
        let _base = budget.try_charge(base).unwrap();
        trip.arm(0, service_support::Trip::Stall);
        released.set(1);
        while !trip.tripped() {
            tokio::task::yield_now().await;
        }
        let taken = budget
            .try_charge(rebuild)
            .expect("retry has not reserved rebuild room across warm");
        trip.release();
        while polls.get() < 2 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            budget.in_use(),
            base + rebuild,
            "the retry waits without its charge"
        );
        if expired {
            bridge.clock.advance_ms(i64::from(COLD_WAIT_MS) + 1);
        }
        drop(taken);
        released.set(u32::MAX);
    };
    let (response, ()) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        futures_util::future::join(cold.get(), competitor),
    )
    .await
    .expect("the cold GET and competitor finish");

    let bodies = bridge
        .nntp
        .calls()
        .iter()
        .filter(|call| call.0 == "body")
        .count();
    // Each pass makes four data requests (including the second ask for
    // the lost article); only a second pass fetches a parity article.
    if expired {
        assert_eq!(
            (response.status, response.code().as_str()),
            (503, "SlowDown")
        );
        assert_eq!(bodies, 4, "a full download started past the deadline");
    } else {
        response.expect(200);
        assert!(response.body == body);
        assert_eq!(bodies, 4 + 5, "a third full download was made");
    }
    assert_eq!(budget.in_use(), 0);
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

#[tokio::test]
async fn review_orphan_losses_are_not_final_while_a_provider_is_cooling() {
    let mut st = posted(14, THREE, 2).await;
    for provider in &mut st.rig.bridge.cfg.providers {
        provider.retention_days = Some(1);
    }
    st.rig.bridge.clock.advance_secs(2 * 86_400);
    for idx in [0, 2] {
        st.rig.servers[0].hide(&st.data[idx].message_id).await;
    }
    st.cool(1).await;

    let (read, stats) = st.read().await;
    assert_eq!(read, ColdFetch::Interrupted);
    assert_eq!(stats.unrecoverable, 0);

    st.rig.bridge.clock.advance_secs(86_400);
    for idx in [0, 2] {
        st.rig.servers[1].hide(&st.data[idx].message_id).await;
    }
    let (read, stats) = st.read().await;
    assert_eq!(read, ColdFetch::Unrecoverable);
    assert_eq!(stats.unrecoverable, 1);
}

#[tokio::test]
async fn review_orphan_losses_are_interrupted_while_a_provider_is_busy() {
    let mut st = posted(16, THREE, 2).await;
    for provider in &mut st.rig.bridge.cfg.providers {
        provider.retention_days = Some(1);
    }
    st.rig.bridge.clock.advance_secs(2 * 86_400);
    for idx in [0, 2] {
        st.rig.servers[0].hide(&st.data[idx].message_id).await;
    }
    st.occupy(1).await;

    let (read, stats) = st.read().await;
    assert_eq!(read, ColdFetch::Interrupted);
    assert_eq!(stats.unrecoverable, 0);
}

#[tokio::test]
async fn review_orphan_parity_loss_is_not_final_while_a_provider_is_cooling() {
    let mut st = posted(15, THREE, 2).await;
    st.rig.bridge.cfg.providers[0].retention_days = Some(3);
    st.rig.bridge.cfg.providers[1].retention_days = Some(1);
    st.rig.bridge.clock.advance_secs(2 * 86_400);
    // The parity rows inherit the first data row's stamp. Age only that
    // row (which both readers still have), so the missing data row is
    // within p0's retention and only the missing parity needs the orphan pass.
    st.rig.bridge.catalog.edit(&st.s.extent, |e| {
        e.articles[0].posted_at = Some(UnixMs(T0.0 - 2 * 86_400_000));
    });
    st.rig.servers[0].hide(&st.data[1].message_id).await;
    st.rig.servers[0].hide(&st.parity[0].message_id).await;
    st.cool(1).await;

    let (read, stats) = st.read().await;
    assert_eq!(read, ColdFetch::Interrupted);
    assert_eq!(stats.unrecoverable, 0);

    st.rig.bridge.clock.advance_secs(3_600);
    st.rig.servers[1].hide(&st.parity[0].message_id).await;
    let (read, stats) = st.read().await;
    assert_eq!(read, ColdFetch::Unrecoverable);
    assert_eq!(stats.unrecoverable, 1);
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

#[tokio::test]
async fn a_broken_session_frees_the_shared_slot_for_a_waiting_provider() {
    let mut st = posted(13, THREE, 2).await;
    st.rig.bridge.cfg.cold_sockets = 2;
    for p in &mut st.rig.bridge.cfg.providers {
        p.pool = Some("shared".into());
        p.pool_max_conns = Some(1);
    }
    // p1 has used fewer slots (p0 posted the extent), so gets the
    // shared slot first. Its session keeps breaking off.
    st.rig.servers[1].drop_next_bodies(100).await;

    let (read, stats) = st.read().await;

    assert!(read == ColdFetch::Filled(st.s.cipher.clone()), "{stats:?}");
    assert!(stats.broken > 0);
    assert_eq!(stats.rebuilt, 0);
}
