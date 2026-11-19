//! Post stage with the parity switch on: the parity articles of an
//! extent are planned and stored with its plan, posted with its data
//! articles, and are enough to rebuild data articles that are lost.

mod nntp_support;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use nntp_support::*;
use velmora::rng::SystemRng;
use velmora::rs::{reconstruct, DataShard, ParityShard};
use velmora::yenc::decode_part_to;
use velmora_bridge::parity::{self, ParityPlan};
use velmora_bridge::recovery::{read_article_plan, Layout};
use velmora_bridge::*;

const MIB: usize = 1024 * 1024;
/// 24 articles: a full extent.
const FULL: usize = 16 * MIB;
/// 12 articles.
const HALF: usize = 8 * MIB;
/// Ten articles.
const TEN: usize = 6_500_000;

fn spec(backbone: &'static str, max_conns: u32) -> Spec {
    Spec {
        backbone,
        post: true,
        max_conns,
    }
}

/// Providers that post, with packed plans and parity on.
async fn parity_rig(specs: &[Spec]) -> Rig {
    let mut rig = rig(specs).await;
    rig.bridge.cfg.packed_plans = true;
    rig.bridge.cfg.parity = true;
    rig
}

/// The stored addendum of the extent, as it is.
fn addendum(rig: &Rig, s: &Seeded) -> Option<Vec<u8>> {
    rig.bridge.catalog.entries.borrow()[&s.extent]
        .parity
        .clone()
}

/// What the stored addendum of the extent expands to.
async fn parity_of(rig: &Rig, s: &Seeded) -> ParityPlan {
    let stored = rig.bridge.catalog.stored_plan(&s.extent).await.unwrap();
    stored
        .parity_plan(&s.extent, s.cipher.len() as u64)
        .unwrap()
        .expect("the extent has parity")
}

/// Per parity article that is recorded as posted, by `idx`: the provider.
fn parity_posted(rig: &Rig, s: &Seeded) -> BTreeMap<u32, String> {
    rig.bridge.catalog.entries.borrow()[&s.extent]
        .parity_posted
        .clone()
}

fn id_set<'a>(rows: impl IntoIterator<Item = &'a ArticleRow>) -> BTreeSet<String> {
    rows.into_iter()
        .map(|a| format!("<{}>", a.message_id))
        .collect()
}

/// The articles server `server` holds, none of them twice.
async fn stored(rig: &Rig, server: usize) -> BTreeSet<String> {
    let ids = rig.servers[server].posted_ids().await;
    let set: BTreeSet<String> = ids.iter().cloned().collect();
    assert_eq!(set.len(), ids.len(), "an article was stored twice");
    set
}

/// The payload of `row` as server `server` holds it.
async fn payload_on(rig: &Rig, server: usize, row: &ArticleRow) -> Vec<u8> {
    let mut client = rig.raw_client(server).await;
    let mut article = Vec::new();
    client
        .article_to(&row.message_id, &mut article)
        .await
        .unwrap();
    client.quit().await;
    let mut payload = vec![0u8; row.cipher_len as usize];
    let part = decode_part_to(&row.message_id, &article, &mut payload).unwrap();
    assert_eq!(part.written as u64, row.cipher_len);
    // A standalone article, like a data article: nothing on the wire
    // says it is parity, or of which extent.
    assert!(!part.multipart);
    assert_eq!(part.file_size, row.cipher_len);
    payload
}

/// Rebuilds the data articles `lost` of the extent from what server 0
/// holds: every other data article, and the parity articles.
async fn rebuilt(
    rig: &Rig,
    plan: &[ArticleRow],
    parity: &ParityPlan,
    lost: &[usize],
) -> Vec<Vec<u8>> {
    let mut held = Vec::new();
    for (at, row) in plan.iter().enumerate() {
        match lost.contains(&at) {
            true => held.push(None),
            false => held.push(Some(payload_on(rig, 0, row).await)),
        }
    }
    let data: Vec<DataShard> = held
        .iter()
        .zip(plan)
        .map(|(payload, row)| match payload {
            Some(payload) => DataShard::Present(payload),
            None => DataShard::Lost {
                len: row.cipher_len as usize,
            },
        })
        .collect();
    let mut shards = Vec::new();
    for row in &parity.articles {
        shards.push(payload_on(rig, 0, row).await);
    }
    let shards: Vec<ParityShard> = parity
        .rows
        .iter()
        .zip(&shards)
        .map(|(row, bytes)| ParityShard { row: *row, bytes })
        .collect();
    reconstruct(&data, &shards).unwrap()
}

fn slice_of<'a>(s: &'a Seeded, row: &ArticleRow) -> &'a [u8] {
    let start = row.cipher_offset as usize;
    &s.cipher[start..start + row.cipher_len as usize]
}

/// A full extent: 24 data articles and 4 parity articles are posted,
/// once each. Every parity article on the server is the shard its
/// addendum describes, and any four data articles that are lost are
/// rebuilt from the rest.
#[tokio::test]
async fn a_full_extent_is_posted_with_four_parity_articles() {
    let rig = parity_rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(FULL)).await;

    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    let plan = rig.plan(&s).await;
    assert_eq!(plan.len(), 24);
    assert!(plan.iter().all(|a| a.state == ArticleState::Posted));
    let parity = parity_of(&rig, &s).await;
    assert_eq!(parity.rows, [0, 1, 2, 3]);
    assert_eq!(rig.job(&s).await.parity_count, Some(4));
    // One write records the plan as posted, parity included.
    assert_eq!(rig.bridge.catalog.mark_batches.get(), 1);
    let by = parity_posted(&rig, &s);
    assert_eq!(by.keys().copied().collect::<Vec<u32>>(), [24, 25, 26, 27]);
    assert!(by.values().all(|p| p == "p0"));
    assert_eq!(
        rig.bridge.catalog.outbox(&s.extent).stage,
        OutboxStage::Verify
    );

    // 28 articles, no id twice, none shared between data and parity.
    let ids = id_set(plan.iter().chain(&parity.articles));
    assert_eq!(ids.len(), 28);
    assert_eq!(stored(&rig, 0).await, ids);
    assert_eq!(rig.server().posted_count().await, 28);

    let longest = plan.iter().map(|a| a.cipher_len).max().unwrap();
    for (slot, row) in parity.articles.iter().enumerate() {
        assert_eq!(row.idx as usize, 24 + slot);
        assert_eq!(row.cipher_len, longest + longest % 2);
        assert_eq!(row.cipher_len, u64::from(parity.shard_len));
        assert_eq!(row.state, ArticleState::Posted);
        let payload = payload_on(&rig, 0, row).await;
        assert_eq!(sha256(&payload), row.payload_sha256, "parity {slot}");
        assert!(!payload.windows(MARKER.len()).any(|w| w == MARKER));
    }

    for lost in [[0, 1, 2, 3], [20, 21, 22, 23], [0, 7, 13, 23]] {
        let back = rebuilt(&rig, &plan, &parity, &lost).await;
        assert_eq!(back.len(), 4);
        for (at, payload) in lost.iter().zip(&back) {
            assert_eq!(sha256(payload), plan[*at].payload_sha256, "data {at}");
            assert_eq!(payload, slice_of(&s, &plan[*at]), "data {at}");
        }
    }
}

/// One parity article per six data articles, rounded up, and at least
/// one: twelve data articles get two, a single one gets one.
#[tokio::test]
async fn smaller_extents_get_their_share_of_parity() {
    let rig = parity_rig(&[spec("bb0", 5)]).await;
    for (n, plain, data, extra) in [(1, HALF, 12, 2), (2, 1000, 1, 1)] {
        let before = rig.server().posted_count().await;
        let s = rig.seed(n, &marked_plaintext(plain)).await;
        assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

        let plan = rig.plan(&s).await;
        let parity = parity_of(&rig, &s).await;
        assert_eq!((plan.len(), parity.articles.len()), (data, extra));
        let posted = rig.server().posted_count().await - before;
        assert_eq!(posted, data + extra);
        // Any `extra` data articles are rebuilt.
        let lost: Vec<usize> = (0..extra).map(|i| data - 1 - i * (data / extra)).collect();
        let mut lost_sorted = lost.clone();
        lost_sorted.sort_unstable();
        let back = rebuilt(&rig, &plan, &parity, &lost_sorted).await;
        for (at, payload) in lost_sorted.iter().zip(&back) {
            assert_eq!(payload, slice_of(&s, &plan[*at]), "data {at}");
        }
    }
}

/// The addendum is stored with the plan, in the catalogue and in the
/// recovery record, before the first article is sent.
#[tokio::test]
async fn the_addendum_is_stored_before_the_first_post() {
    let rig = parity_rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(TEN)).await;

    let mut seen = None;
    let outcome = rig
        .run_post_and(&s, 0, 1, async || {
            let record = read_article_plan(
                &rig.bridge.safety,
                &rig.bridge.kek,
                &s.extent,
                &Layout::flat(),
            )
            .await
            .unwrap()
            .record
            .expect("the plan record is stored");
            seen = Some((addendum(&rig, &s), record.parity));
        })
        .await;
    assert_eq!(outcome, JobOutcome::Ack);

    let stored = addendum(&rig, &s).expect("an addendum");
    let (in_catalogue, in_record) = seen.expect("the job was seen posting");
    assert_eq!(in_catalogue.as_ref(), Some(&stored));
    assert_eq!(in_record.as_ref(), Some(&stored));
    // The plan and its addendum are one write, and it comes before any
    // POST.
    let events = events();
    let planned: Vec<usize> = (0..events.len())
        .filter(|at| events[*at] == "plan")
        .collect();
    let first_post = events.iter().position(|e| *e == "post").unwrap();
    assert_eq!(planned.len(), 1);
    assert!(planned[0] < first_post);
}

/// A job that is refused every post leaves the plan and its addendum
/// behind. The job after it computes the same shards, finds them in the
/// stored addendum and posts them under the stored identifiers.
#[tokio::test]
async fn a_retry_posts_the_parity_of_the_stored_addendum() {
    let rig = parity_rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(TEN)).await;

    rig.server().set_posting_allowed(false).await;
    assert_ne!(rig.run_post(&s).await, JobOutcome::Ack);
    assert_eq!(rig.server().posted_count().await, 0);
    let first = addendum(&rig, &s).expect("an addendum");
    let planned = parity_of(&rig, &s).await;
    assert!(planned
        .articles
        .iter()
        .all(|a| a.state == ArticleState::Planned));

    rig.server().set_posting_allowed(true).await;
    rig.bridge.clock.advance_secs(60);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    assert_eq!(addendum(&rig, &s), Some(first));
    let plan = rig.plan(&s).await;
    let parity = parity_of(&rig, &s).await;
    assert_eq!(parity.rows, planned.rows);
    assert_eq!(id_set(&parity.articles), id_set(&planned.articles));
    assert_eq!(
        stored(&rig, 0).await,
        id_set(plan.iter().chain(&parity.articles))
    );
    for row in &parity.articles {
        assert_eq!(sha256(&payload_on(&rig, 0, row).await), row.payload_sha256);
    }
}

/// The job dies after the POSTs and before the write that records them.
/// Its successor finds every article, parity too, on the server under
/// the stored identifiers: nothing is posted twice and nothing new.
#[tokio::test]
async fn a_crash_after_the_posts_sends_no_second_parity() {
    let rig = parity_rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(TEN)).await;

    rig.bridge.catalog.fail_mark_posted.set(2);
    assert_ne!(rig.run_post(&s).await, JobOutcome::Ack);
    let first = addendum(&rig, &s).expect("an addendum");
    let planned = parity_of(&rig, &s).await;
    let on_server = stored(&rig, 0).await;
    assert_eq!(on_server.len(), 12);
    assert!(parity_posted(&rig, &s).is_empty());
    let mut before = Vec::new();
    for row in &planned.articles {
        before.push(payload_on(&rig, 0, row).await);
    }

    rig.bridge.clock.advance_secs(LEASE_SECS + 1);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);

    assert_eq!(addendum(&rig, &s), Some(first));
    assert_eq!(stored(&rig, 0).await, on_server);
    let parity = parity_of(&rig, &s).await;
    assert_eq!(parity.articles.len(), 2);
    assert_eq!(parity_posted(&rig, &s).len(), 2);
    for (row, before) in parity.articles.iter().zip(&before) {
        assert_eq!(row.state, ArticleState::Posted);
        assert_eq!(&payload_on(&rig, 0, row).await, before);
    }
}

/// A stored addendum whose hash is not that of the shard the ciphertext
/// gives fails the job as corrupt, before anything is sent: neither an
/// addendum that no longer matches its digest, nor one that is whole
/// and describes other shards.
#[tokio::test]
async fn a_stored_addendum_of_other_shards_fails_the_job() {
    for whole in [false, true] {
        let rig = parity_rig(&[spec("bb0", 5)]).await;
        let s = rig.seed(1, &marked_plaintext(TEN)).await;
        rig.server().set_posting_allowed(false).await;
        assert_ne!(rig.run_post(&s).await, JobOutcome::Ack);
        rig.server().set_posting_allowed(true).await;

        let good = parity_of(&rig, &s).await;
        let mut hashes: Vec<(u16, [u8; 32])> = good
            .rows
            .iter()
            .zip(&good.articles)
            .map(|(row, a)| (*row, a.payload_sha256))
            .collect();
        hashes[1].1[0] ^= 1;
        rig.bridge.catalog.edit(&s.extent, |e| {
            let packed = e.packed.clone().unwrap();
            e.parity = Some(match whole {
                // A well-formed addendum of this plan, for another shard.
                true => parity::build(
                    &mut SystemRng,
                    T0.secs().0,
                    &["alt.binaries.test"],
                    &s.extent,
                    s.cipher.len() as u64,
                    &packed,
                    &hashes,
                )
                .unwrap(),
                // The stored one with one bit of a hash changed.
                false => {
                    let mut bad = e.parity.clone().unwrap();
                    let last = bad.len() - 1;
                    bad[last] ^= 1;
                    bad
                }
            });
        });

        rig.bridge.clock.advance_secs(60);
        assert_ne!(rig.run_post(&s).await, JobOutcome::Ack);
        let outbox = rig.bridge.catalog.outbox(&s.extent);
        assert_eq!(outbox.stage, OutboxStage::Post);
        assert_eq!(outbox.last_error, Some(FailClass::Corrupt), "whole {whole}");
        assert_eq!(rig.server().posted_count().await, 0, "whole {whole}");
        let plan = rig.plan(&s).await;
        assert!(plan.iter().all(|a| a.state == ArticleState::Planned));
    }
}

/// The same after part of the plan was posted: the job that finds the
/// addendum changed posts nothing more.
#[tokio::test]
async fn a_changed_addendum_stops_a_plan_that_is_half_posted() {
    let rig = parity_rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(TEN)).await;
    rig.bridge.catalog.fail_mark_posted.set(2);
    assert_ne!(rig.run_post(&s).await, JobOutcome::Ack);
    let on_server = stored(&rig, 0).await;
    assert_eq!(on_server.len(), 12);

    rig.bridge.catalog.edit(&s.extent, |e| {
        let bad = e.parity.as_mut().unwrap();
        let last = bad.len() - 1;
        bad[last] ^= 1;
    });
    rig.bridge.clock.advance_secs(LEASE_SECS + 1);
    assert_ne!(rig.run_post(&s).await, JobOutcome::Ack);

    let outbox = rig.bridge.catalog.outbox(&s.extent);
    assert_eq!(outbox.last_error, Some(FailClass::Corrupt));
    assert_eq!(stored(&rig, 0).await, on_server);
    let plan = rig.plan(&s).await;
    assert!(plan.iter().all(|a| a.state == ArticleState::Planned));
}

/// With the switch off a packed plan has no addendum and no parity
/// article is posted; an extent that was planned with it on keeps its
/// parity when the switch goes off.
#[tokio::test]
async fn the_switch_governs_new_plans_only() {
    let mut rig = parity_rig(&[spec("bb0", 5)]).await;
    rig.bridge.cfg.parity = false;
    let off = rig.seed(1, &marked_plaintext(TEN)).await;
    assert_eq!(rig.run_post(&off).await, JobOutcome::Ack);
    assert_eq!(addendum(&rig, &off), None);
    assert_eq!(rig.job(&off).await.parity_count, None);
    assert_eq!(stored(&rig, 0).await, id_set(&rig.plan(&off).await));
    assert_eq!(rig.server().posted_count().await, 10);

    // Planned with the switch on, posted after it went off.
    rig.bridge.cfg.parity = true;
    let on = rig.seed(2, &marked_plaintext(TEN)).await;
    rig.server().set_posting_allowed(false).await;
    assert_ne!(rig.run_post(&on).await, JobOutcome::Ack);
    rig.server().set_posting_allowed(true).await;
    rig.bridge.cfg.parity = false;
    rig.bridge.clock.advance_secs(60);
    assert_eq!(rig.run_post(&on).await, JobOutcome::Ack);
    assert_eq!(parity_of(&rig, &on).await.articles.len(), 2);
    assert_eq!(parity_posted(&rig, &on).len(), 2);
    assert_eq!(rig.server().posted_count().await, 22);
}

/// Parity is stored beside a packed plan only: with plans kept as rows
/// the switch does nothing.
#[tokio::test]
async fn a_plan_of_rows_gets_no_parity() {
    let mut rig = parity_rig(&[spec("bb0", 5)]).await;
    rig.bridge.cfg.packed_plans = false;
    let s = rig.seed(1, &marked_plaintext(TEN)).await;
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    assert_eq!(addendum(&rig, &s), None);
    assert_eq!(rig.server().posted_count().await, 10);
}

/// How many data articles each provider is recorded for.
fn data_by(plan: &[ArticleRow]) -> BTreeMap<String, usize> {
    let mut by = BTreeMap::new();
    for a in plan {
        *by.entry(a.provider_id.clone().unwrap()).or_default() += 1;
    }
    by
}

/// Two providers with sockets in the round: the parity articles go to
/// the one that took fewer data articles, so that losing either
/// provider's articles does not lose data and parity together.
#[tokio::test]
async fn parity_goes_to_the_provider_with_fewer_data_articles() {
    // Four sockets: three on the first provider, one on the second (a
    // slot of each stays reserved for reads).
    let rig = parity_rig(&[spec("bb0", 4), spec("bb1", 2)]).await;
    let s = rig.seed(1, &marked_plaintext(FULL)).await;

    let run = tokio::time::timeout(Duration::from_secs(120), rig.run_post(&s));
    assert_eq!(run.await.expect("the job ends"), JobOutcome::Ack);

    let plan = rig.plan(&s).await;
    let parity = parity_of(&rig, &s).await;
    let data = data_by(&plan);
    assert_eq!(rig.bridge.nntp.connects_to("p0"), 3);
    assert_eq!(rig.bridge.nntp.connects_to("p1"), 1);
    assert!(data["p1"] < data["p0"], "{data:?}");
    let by = parity_posted(&rig, &s);
    assert_eq!(by.len(), 4);
    assert!(by.values().all(|p| p == "p1"), "{by:?}");
    assert_eq!(stored(&rig, 1).await.len(), data["p1"] + 4);
    assert_eq!(stored(&rig, 0).await.len(), data["p0"]);
    // Each article is on one server, and all of them are somewhere.
    let mut all = stored(&rig, 0).await;
    all.extend(stored(&rig, 1).await);
    assert_eq!(all, id_set(plan.iter().chain(&parity.articles)));
    assert_eq!(all.len(), 28);
}

/// The preferred provider stops taking posts in the middle of the
/// parity: the sockets of the other provider, which held back for it,
/// post the rest. The job does not wait for a provider that is gone.
#[tokio::test]
async fn parity_falls_to_the_other_provider_when_the_preferred_one_fails() {
    let rig = parity_rig(&[spec("bb0", 4), spec("bb1", 2)]).await;
    let s = rig.seed(1, &marked_plaintext(FULL)).await;
    // The plan first, so that the parity articles are known.
    rig.servers[0].set_posting_allowed(false).await;
    rig.servers[1].set_posting_allowed(false).await;
    assert_ne!(rig.run_post(&s).await, JobOutcome::Ack);
    rig.servers[0].set_posting_allowed(true).await;
    rig.servers[1].set_posting_allowed(true).await;
    let parity = parity_of(&rig, &s).await;
    let parity_ids = id_set(&parity.articles);
    rig.bridge.clock.advance_secs(3600);

    let lease = rig.claim(&s, OutboxStage::Post).await;
    let job = rig.job(&s).await;
    let post = rig.bridge.post_stage(&lease, &job);
    let fail = async {
        // As soon as the second server holds a parity article it takes
        // no more.
        loop {
            let held = stored(&rig, 1).await;
            if held.intersection(&parity_ids).next().is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
        rig.servers[1].set_posting_allowed(false).await;
    };
    let both = async { tokio::join!(post, fail).0 };
    let outcome = tokio::time::timeout(Duration::from_secs(120), both).await;
    assert_eq!(outcome.expect("the job ends"), JobOutcome::Ack);

    let plan = rig.plan(&s).await;
    assert!(plan.iter().all(|a| a.state == ArticleState::Posted));
    let by = parity_posted(&rig, &s);
    assert_eq!(by.len(), 4);
    // The second provider took the parity it was sent before it failed;
    // the first took the rest.
    let on_second = stored(&rig, 1).await;
    let on_first = stored(&rig, 0).await;
    let first_parity = on_first.intersection(&parity_ids).count();
    let second_parity = on_second.intersection(&parity_ids).count();
    assert!(second_parity >= 1 && first_parity >= 1, "{by:?}");
    assert_eq!(first_parity + second_parity, 4);
    assert_eq!(by.values().filter(|p| *p == "p0").count(), first_parity);
    let mut all = on_first;
    all.extend(on_second);
    assert_eq!(all, id_set(plan.iter().chain(&parity.articles)));
}

/// A parity article a provider lost is posted again from the safety
/// copy, under its stored identifiers: the shard is computed again and
/// is the one the addendum describes.
#[tokio::test]
async fn a_lost_parity_article_is_posted_again() {
    let rig = parity_rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(TEN)).await;
    let plan = rig.post(&s).await;
    let parity = parity_of(&rig, &s).await;
    let lost = &parity.articles[1];
    assert_eq!(lost.idx, 11);
    rig.server().hide(&lost.message_id).await;
    let kept = rig.server().posted_count().await;

    let lease = rig.claim(&s, OutboxStage::Verify).await;
    let job = rig.job(&s).await;
    // A data article and a parity article in one go.
    rig.server().hide(&plan[3].message_id).await;
    let done = rig.bridge.repost_run(&lease, &job, &[3, 11]).await;
    assert_eq!(done, Ok(true));

    assert!(!rig.server().is_hidden(&lost.message_id).await);
    assert!(!rig.server().is_hidden(&plan[3].message_id).await);
    assert_eq!(rig.server().posted_count().await, kept);
    assert_eq!(
        sha256(&payload_on(&rig, 0, lost).await),
        lost.payload_sha256
    );
    assert_eq!(payload_on(&rig, 0, &plan[3]).await, slice_of(&s, &plan[3]));
    // Stamped as posted again: the safety copy waits from here.
    let entries = rig.bridge.catalog.entries.borrow();
    let entry = &entries[&s.extent];
    assert!(entry.parity_reposted.contains(&11));
    assert!(entry.articles[3].reposted_at.is_some());
    assert_eq!(addendum(&rig, &s), entry.parity.clone());
}

/// A repost never sends a shard the addendum does not describe: with
/// the stored addendum changed it fails as corrupt and sends nothing.
#[tokio::test]
async fn a_repost_of_parity_checks_the_shard() {
    let rig = parity_rig(&[spec("bb0", 5)]).await;
    let s = rig.seed(1, &marked_plaintext(TEN)).await;
    rig.post(&s).await;
    let good = parity_of(&rig, &s).await;
    let mut hashes: Vec<(u16, [u8; 32])> = good
        .rows
        .iter()
        .zip(&good.articles)
        .map(|(row, a)| (*row, a.payload_sha256))
        .collect();
    hashes[0].1[5] ^= 0x10;
    rig.bridge.catalog.edit(&s.extent, |e| {
        let packed = e.packed.clone().unwrap();
        let other = parity::build(
            &mut SystemRng,
            T0.secs().0,
            &["alt.binaries.test"],
            &s.extent,
            s.cipher.len() as u64,
            &packed,
            &hashes,
        );
        e.parity = Some(other.unwrap());
    });
    let before = stored(&rig, 0).await;

    let lease = rig.claim(&s, OutboxStage::Verify).await;
    let job = rig.job(&s).await;
    let done = rig.bridge.repost_run(&lease, &job, &[11]).await;
    assert_eq!(done, Err(Some(FailClass::Corrupt)));
    assert_eq!(stored(&rig, 0).await, before);
    // A repost of data articles alone does not compute the shards.
    let done = rig.bridge.repost_run(&lease, &job, &[2]).await;
    assert_eq!(done, Ok(true));
    assert_eq!(stored(&rig, 0).await, before);
}
