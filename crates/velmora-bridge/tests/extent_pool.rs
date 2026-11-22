//! The extent buffers a posting isolate keeps between post jobs
//! (`ByteBudget::with_extent_pool`): a spare is charged while it waits,
//! is taken over by the next job whose extent it fits, is let go when a
//! charge needs its room, and changes nothing that is posted.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::articles::article_spans;
use velmora_bridge::ingress::{ByteBudget, EXTENT_POOL_MIN_BYTES};
use velmora_bridge::post::bench_render_article;
use velmora_bridge::*;

const MIB: u64 = 1024 * 1024;

#[test]
fn spare_count_uses_the_post_job_charge_including_parity() {
    use velmora_bridge::jobs::extent_pool_buffers;

    // With parity and 8 sockets, two ~32.13 MiB jobs fit in 90 MiB.
    assert_eq!(extent_pool_buffers(90 * MIB, 16 * MIB, 8, true), 2);
    assert_eq!(extent_pool_buffers(90 * MIB, 16 * MIB, 8, false), 3);
    // 84 MiB would fit three plaintext-sized charges but not three ciphertext ones.
    assert_eq!(extent_pool_buffers(84 * MIB, 16 * MIB, 8, false), 2);
    // Shipped config: 90 MiB budget, 16 MiB extents, 6 sockets, parity off.
    assert_eq!(extent_pool_buffers(90 * MIB, 16 * MIB, 6, false), 3);
}

#[tokio::test]
async fn an_oversized_catalogue_extent_settles_as_corrupt_before_taking_a_buffer() {
    let mut rig = rig(&[Spec {
        backbone: "bb0",
        post: true,
        max_conns: 1,
    }])
    .await;
    rig.bridge.budget = budget(1);
    let s = rig.seed(1, b"sealed extent").await;
    rig.bridge
        .catalog
        .entries
        .borrow_mut()
        .get_mut(&s.extent)
        .unwrap()
        .job
        .extent
        .cipher_size = 2 << 30;
    let job = Job::Extent {
        v: JOB_VERSION,
        extent: s.extent.clone(),
        generation: s.generation,
        stage: OutboxStage::Post,
    };
    assert!(matches!(
        rig.bridge.run_job(&job).await,
        JobOutcome::Retry { .. }
    ));
    assert_eq!(
        rig.bridge.catalog.outbox(&s.extent).last_error,
        Some(FailClass::Corrupt)
    );
    assert_eq!(rig.bridge.safety.gets(), 0, "no safety body read");
    assert_eq!(rig.bridge.budget.peak(), 0, "no extent buffer charge");
    assert_eq!(
        rig.bridge.budget.spare_bytes(),
        0,
        "no spare capacity retained"
    );
}

#[tokio::test]
async fn lowering_the_upload_limit_does_not_strand_an_existing_extent() {
    let mut rig = rig(&[Spec {
        backbone: "bb0",
        post: true,
        max_conns: 1,
    }])
    .await;
    rig.bridge.budget = budget(1);
    let s = rig.seed(1, &marked_plaintext(5 * MIB as usize)).await;
    rig.bridge.cfg.max_extent_bytes = 4 * MIB;
    let job = Job::Extent {
        v: JOB_VERSION,
        extent: s.extent.clone(),
        generation: s.generation,
        stage: OutboxStage::Post,
    };
    assert_eq!(rig.bridge.run_job(&job).await, JobOutcome::Ack);
    assert_eq!(
        rig.bridge.catalog.outbox(&s.extent).stage,
        OutboxStage::Verify
    );
    assert!(rig.server().posted_count().await > 0);
}

#[tokio::test]
async fn a_wrong_safety_object_size_settles_as_corrupt_before_reading() {
    let rig = rig(&[Spec {
        backbone: "bb0",
        post: true,
        max_conns: 1,
    }])
    .await;
    let s = rig.seed(1, b"sealed extent").await;
    assert!(rig
        .bridge
        .safety
        .corrupt(&s.extent.safety_key(), |bytes| bytes.push(0)));
    assert!(matches!(rig.run_post(&s).await, JobOutcome::Retry { .. }));
    assert_eq!(
        rig.bridge.catalog.outbox(&s.extent).last_error,
        Some(FailClass::Corrupt)
    );
    assert_eq!(rig.bridge.safety.gets(), 0, "no safety body read");
    assert_eq!(rig.server().posted_count().await, 0);
}

/// A job budget as production has it: 48 MiB for requests, 90 for jobs.
fn budget(spares: usize) -> ByteBudget {
    ByteBudget::new(48 * MIB)
        .with_job_capacity(90 * MIB)
        .with_extent_pool(spares)
}

/// Charges a post job of `bytes` for an extent of `len` bytes, fills its
/// buffer with `len` bytes and drops the charge. The buffer's address.
async fn one_job(budget: &ByteBudget, bytes: u64, len: u64) -> usize {
    let charge = budget.charge_job_extent(bytes, len).await.unwrap();
    let at = {
        let mut buffer = charge.lend(len as usize);
        buffer.resize(len as usize, 7);
        buffer.as_ptr() as usize
    };
    drop(charge);
    at
}

#[tokio::test]
async fn a_spare_is_charged_while_it_waits_and_taken_over_by_the_next_job() {
    let budget = budget(3);
    let at = one_job(&budget, 25 * MIB, 16 * MIB).await;
    assert_eq!((budget.spares(), budget.spare_bytes()), (1, 16 * MIB));
    // The spare is still counted: nothing is held that is not charged.
    assert_eq!(budget.in_use(), 16 * MIB);
    assert_eq!(budget.jobs_in_use(), 16 * MIB);

    let charge = budget.charge_job_extent(25 * MIB, 16 * MIB).await.unwrap();
    // The job's charge counts the buffer it took over once, not twice.
    assert_eq!(charge.bytes(), 25 * MIB);
    assert_eq!(budget.in_use(), 25 * MIB);
    assert_eq!(budget.spares(), 0);
    {
        let buffer = charge.lend(16 * MIB as usize);
        assert_eq!(buffer.as_ptr() as usize, at, "the same memory");
        assert!(buffer.is_empty(), "nothing of the last extent is left");
    }
    drop(charge);
    assert_eq!((budget.spares(), budget.in_use()), (1, 16 * MIB));
    assert_eq!(budget.peak(), 25 * MIB);
}

#[tokio::test]
async fn a_charge_that_needs_the_room_of_a_spare_lets_it_go() {
    let budget = budget(3);
    one_job(&budget, 25 * MIB, 16 * MIB).await;
    let job = budget.try_charge_job(70 * MIB).unwrap();
    assert_eq!(budget.in_use(), 86 * MIB);
    // 20 MiB of requests weigh 37.5 MiB of jobs: no room even without
    // the spare, so it is kept.
    assert!(budget.try_charge(20 * MIB).is_none());
    assert_eq!(budget.spares(), 1);
    // 10 MiB weigh 18.75: room once the spare is gone.
    let request = budget.try_charge(10 * MIB).unwrap();
    assert_eq!((budget.spares(), budget.spare_bytes()), (0, 0));
    assert_eq!(budget.in_use(), 80 * MIB);
    drop((job, request));
    assert_eq!(budget.in_use(), 0);
}

#[tokio::test]
async fn a_larger_spare_is_charged_at_its_size_and_a_much_larger_one_is_not_taken() {
    let budget = budget(3);
    let at = one_job(&budget, 25 * MIB, 16 * MIB).await;

    // 14 MiB fit 16 with less than a quarter over: taken, at 16.
    let charge = budget.charge_job_extent(23 * MIB, 14 * MIB).await.unwrap();
    assert_eq!(charge.bytes(), 25 * MIB);
    assert_eq!(budget.in_use(), 25 * MIB);
    assert_eq!(charge.lend(14 * MIB as usize).as_ptr() as usize, at);
    drop(charge);
    assert_eq!(budget.spare_bytes(), 16 * MIB);

    // 8 MiB would leave half of it unused: a buffer of its own.
    let charge = budget.charge_job_extent(17 * MIB, 8 * MIB).await.unwrap();
    assert_eq!(charge.bytes(), 17 * MIB);
    assert_eq!(budget.in_use(), 33 * MIB);
    assert_ne!(charge.lend(8 * MIB as usize).as_ptr() as usize, at);
    drop(charge);
    // Both are kept now, each charged at its size.
    assert_eq!((budget.spares(), budget.spare_bytes()), (2, 24 * MIB));
}

/// When what a larger spare holds beyond the extent is all that keeps a
/// charge out, the spare is let go instead and the job gets a buffer of
/// its own: the pool never refuses a charge that fits without it.
#[tokio::test]
async fn a_spare_too_large_to_fit_is_let_go_rather_than_keep_the_job_out() {
    let budget = budget(3);
    one_job(&budget, 25 * MIB, 16 * MIB).await;
    let held = budget.try_charge_job(66 * MIB).unwrap();
    assert_eq!(budget.in_use(), 82 * MIB);
    // 14 MiB in the 16 MiB spare would charge 25 MiB: 91 of 90. Without
    // it, 23 MiB fit (89).
    let charge = budget.charge_job_extent(23 * MIB, 14 * MIB).await.unwrap();
    assert_eq!(charge.bytes(), 23 * MIB);
    assert_eq!((budget.spares(), budget.in_use()), (0, 89 * MIB));
    charge.lend(14 * MIB as usize);
    drop((held, charge));
    // Its own buffer is the spare now, charged at its size.
    assert_eq!((budget.spares(), budget.in_use()), (1, 14 * MIB));
}

#[tokio::test]
async fn the_pool_keeps_its_newest_buffers_up_to_its_size() {
    let budget = budget(1);
    // Two jobs at once, so each has a buffer of its own.
    let first = budget.charge_job_extent(25 * MIB, 16 * MIB).await.unwrap();
    let second = budget.charge_job_extent(25 * MIB, 16 * MIB).await.unwrap();
    first.lend(16 * MIB as usize);
    let newest = second.lend(16 * MIB as usize).as_ptr() as usize;
    drop(first);
    drop(second);
    assert_eq!((budget.spares(), budget.in_use()), (1, 16 * MIB));
    let charge = budget.charge_job_extent(25 * MIB, 16 * MIB).await.unwrap();
    assert_eq!(charge.lend(16 * MIB as usize).as_ptr() as usize, newest);
}

#[tokio::test]
async fn nothing_is_kept_without_a_pool_below_its_least_size_or_past_its_charge() {
    // No pool: the budget is as it was.
    let none = ByteBudget::new(48 * MIB).with_job_capacity(90 * MIB);
    one_job(&none, 25 * MIB, 16 * MIB).await;
    assert_eq!((none.spares(), none.in_use()), (0, 0));

    let budget = budget(3);
    // A small extent leaves no gap of note: not kept.
    let small = EXTENT_POOL_MIN_BYTES - 1;
    one_job(&budget, small + 9 * MIB, small).await;
    assert_eq!((budget.spares(), budget.in_use()), (0, 0));
    // A job charge that does not count an extent keeps nothing.
    let charge = budget.try_charge_job(25 * MIB).unwrap();
    charge.lend(16 * MIB as usize);
    drop(charge);
    assert_eq!((budget.spares(), budget.in_use()), (0, 0));
    // A buffer that grew past what was charged for it is not kept.
    let charge = budget.charge_job_extent(25 * MIB, 16 * MIB).await.unwrap();
    charge.lend(16 * MIB as usize).resize(17 * MIB as usize, 0);
    drop(charge);
    assert_eq!((budget.spares(), budget.in_use()), (0, 0));
}

/// Every article that server 0 holds of the extent, against the article
/// rendered from the safety copy and the stored plan alone: each data
/// article from its range of the ciphertext, each parity article from the
/// shards computed again here. Returns how many were compared.
async fn check_posted(rig: &Rig, s: &Seeded) -> usize {
    let plan = rig.plan(s).await;
    let cipher = rig
        .bridge
        .safety
        .get(&s.extent.safety_key(), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cipher, s.cipher);
    let stored = rig.bridge.catalog.stored_plan(&s.extent).await.unwrap();
    let parity = stored
        .parity_plan(&s.extent, cipher.len() as u64)
        .unwrap()
        .expect("the extent has parity");
    let data: Vec<&[u8]> = article_spans(cipher.len() as u64)
        .iter()
        .map(|span| &cipher[span.start as usize..span.end() as usize])
        .collect();
    let shards = velmora::rs::encode(&data, &parity.rows).unwrap();
    let mut want: Vec<(&ArticleRow, &[u8])> = plan
        .iter()
        .map(|row| {
            let start = row.cipher_offset as usize;
            (row, &cipher[start..start + row.cipher_len as usize])
        })
        .collect();
    want.extend(parity.articles.iter().zip(shards.iter().map(Vec::as_slice)));
    let mut client = rig.raw_client(0).await;
    for (row, payload) in &want {
        let rendered =
            bench_render_article(row, plan.len() as u32, cipher.len() as u64, payload).unwrap();
        let mut held = Vec::new();
        client.article_to(&row.message_id, &mut held).await.unwrap();
        assert!(held == rendered, "article {} differs", row.idx);
    }
    client.quit().await;
    want.len()
}

/// Post jobs through the queue path (`run_job`, which charges them), one
/// after another in one isolate, with parity: a full extent, another
/// full one (it takes over the first one's buffer), one of 14 MiB (the
/// same buffer, charged at its size) and one of 8 MiB (a buffer of its
/// own). With the pool and without it, every article posted is the one
/// the safety copy and the stored plan render, byte for byte, and the
/// pool holds nothing it has not charged.
#[tokio::test]
async fn posted_articles_are_byte_identical_with_and_without_the_pool() {
    const PLAIN: [usize; 4] = [16 << 20, 16 << 20, 14 << 20, 8 << 20];
    for spares in [0, 3] {
        let mut rig = rig(&[Spec {
            backbone: "bb0",
            post: true,
            max_conns: 7,
        }])
        .await;
        rig.bridge.cfg.packed_plans = true;
        rig.bridge.cfg.parity = true;
        rig.bridge.cfg.post_sockets = 6;
        rig.bridge.budget = budget(spares);
        let mut compared = 0;
        let mut seeded = Vec::new();
        for (n, plain) in PLAIN.iter().enumerate() {
            let s = rig.seed(n as u8 + 1, &marked_plaintext(*plain)).await;
            let job = Job::Extent {
                v: JOB_VERSION,
                extent: s.extent.clone(),
                generation: s.generation.clone(),
                stage: OutboxStage::Post,
            };
            assert_eq!(rig.bridge.run_job(&job).await, JobOutcome::Ack);
            compared += check_posted(&rig, &s).await;
            let budget = &rig.bridge.budget;
            // Between jobs only the spares are held, and they are counted.
            assert_eq!(budget.in_use(), budget.spare_bytes(), "after job {n}");
            match spares {
                0 => assert_eq!(budget.spares(), 0),
                _ => assert!(budget.spares() >= 1),
            }
            seeded.push(s);
        }
        // 24 + 4, 24 + 4, 21 + 4 and 12 + 2 articles.
        assert_eq!(compared, 95);
        assert_eq!(rig.server().posted_count().await, 95);
        if spares > 0 {
            // A 16 MiB buffer and the 8 MiB one.
            let full = seeded[0].cipher.len() as u64;
            let half = seeded[3].cipher.len() as u64;
            assert_eq!(rig.bridge.budget.spare_bytes(), full + half);
        }
        assert!(rig.bridge.budget.peak() <= 90 * MIB);
    }
}
