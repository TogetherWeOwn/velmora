//! One-extent PUT wake-ups, verified against the real SQL catalogue.

mod nntp_support;
mod service_support;

use std::future::Future;
use std::task::{Context, Waker};

use nntp_support::TcpConnector;
use service_support::*;
use velmora_bridge::*;

const BUCKET: &str = "put-wake";

fn post_job(extent: &ExtentId, generation: &GenerationId) -> Job {
    Job::Extent {
        v: JOB_VERSION,
        extent: extent.clone(),
        generation: generation.clone(),
        stage: OutboxStage::Post,
    }
}

#[tokio::test]
async fn the_fast_wake_up_leaves_while_the_publication_batch_is_pending() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    let trip = &rig.bridge.catalog.sql.publish_trip;
    let send = &rig.bridge.jobs.send_trip;
    trip.arm(0, Trip::Stall);
    send.arm(0, Trip::Stall);
    let mut put = std::pin::pin!(rig.put(&signer, BUCKET, "k", b"body"));
    let cx = &mut Context::from_waker(Waker::noop());
    assert!(put.as_mut().poll(cx).is_pending());
    assert!(trip.tripped(), "commit starts without waiting for the send");
    assert!(send.tripped(), "send starts without waiting for the commit");
    send.release();
    assert!(put.as_mut().poll(cx).is_pending());
    assert_eq!(rig.count("outbox"), 0);
    let sent = rig.bridge.jobs.inner.sent();
    assert_eq!(sent.len(), 1, "send while the commit is pending");
    assert_eq!(sent[0].delay_secs, 1);
    let commit_now = rig.now();
    trip.release();
    put.await.expect(200);

    let (generation, extents) = rig.live(&bucket, "k").await.unwrap();
    assert_eq!(sent[0].job, post_job(&extents[0].id, &generation.id));
    assert_eq!(rig.bridge.jobs.inner.sent().len(), 1);
    let sent_at = rig.bridge.catalog.sql.with_conn(|c| {
        c.query_row("SELECT sent_at FROM outbox", [], |row| row.get::<_, i64>(0))
            .unwrap()
    });
    assert_eq!(sent_at, commit_now.0);
}

#[tokio::test]
async fn two_failed_sends_leave_the_post_due_immediately() {
    let rig = rig();
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.bridge.jobs.fail.set(true);
    rig.put(&signer, BUCKET, "k", b"body").await.expect(200);

    assert_eq!(*rig.bridge.jobs.send_delays.borrow(), [1, 0]);
    assert!(rig.bridge.jobs.inner.sent().is_empty());
    assert_eq!(rig.count("outbox WHERE sent_at IS NULL"), 1);
    let (generation, extents) = rig.live(&bucket, "k").await.unwrap();
    let due = rig
        .bridge
        .catalog
        .due(rig.now(), Resend::after(jobs::RESEND_SECS), 10)
        .await
        .unwrap();
    assert_eq!(
        due,
        [DueRow {
            extent_id: extents[0].id.clone(),
            generation_id: generation.id,
            stage: OutboxStage::Post,
        }]
    );
}

#[tokio::test]
async fn the_late_wake_up_is_sent_at_500_ms_but_not_at_499_ms() {
    for (elapsed, delays) in [(499, &[1][..]), (500, &[1, 0][..])] {
        let provider = nntp_support::simple_rig().await;
        let rig = rig_with(
            TcpConnector::default(),
            config(provider.bridge.cfg.providers.clone()),
        );
        let (bucket, signer) = rig.standard(BUCKET).await;
        let trip = &rig.bridge.catalog.sql.publish_trip;
        trip.arm(0, Trip::Stall);
        let mut put = std::pin::pin!(rig.put(&signer, BUCKET, "k", b"body"));
        assert!(put
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        assert!(trip.tripped());
        rig.bridge.clock.advance_ms(elapsed);
        trip.release();
        put.await.expect(200);
        let (generation, extents) = rig.live(&bucket, "k").await.unwrap();

        let sent = rig.bridge.jobs.inner.take();
        assert_eq!(
            sent.iter().map(|s| s.delay_secs).collect::<Vec<_>>(),
            delays,
            "commit took {elapsed} ms"
        );
        // The late message is deliverable first. The early one is a no-op
        // if the late one has already moved the row out of Post.
        for wake in sent.iter().rev() {
            assert_eq!(wake.job, post_job(&extents[0].id, &generation.id));
            rig.bridge.clock.advance_secs(wake.delay_secs);
            assert_eq!(rig.bridge.run_job(&wake.job).await, JobOutcome::Ack);
        }
        // One token increment for the claim, one for advancing to Verify.
        assert_eq!(
            rig.count("outbox WHERE stage = 'verify' AND lease_token = 2"),
            1
        );
        assert_eq!(provider.server().posted_ids().await.len(), 1);
    }
}

#[tokio::test]
async fn a_refused_attempt_cannot_claim_the_final_generation() {
    let provider = nntp_support::simple_rig().await;
    let rig = rig_with(
        TcpConnector::default(),
        config(provider.bridge.cfg.providers.clone()),
    );
    let (bucket, signer) = rig.standard(BUCKET).await;
    rig.bridge.clock.advance_secs(2);
    rig.put(&signer, BUCKET, "k", b"newer").await.expect(200);
    let (newer, _) = rig.live(&bucket, "k").await.unwrap();
    assert_eq!(rig.bridge.jobs.inner.take().len(), 1);

    rig.bridge.clock.set(T0);
    rig.put(&signer, BUCKET, "k", b"retried").await.expect(200);
    let (final_gen, extents) = rig.live(&bucket, "k").await.unwrap();
    let extent = &extents[0].id;
    let sent = rig.bridge.jobs.inner.take();
    assert_eq!(sent.len(), 2);
    assert_eq!((sent[0].delay_secs, sent[1].delay_secs), (1, 1));
    let Job::Extent {
        generation: refused,
        ..
    } = &sent[0].job
    else {
        panic!("expected a wake-up for the refused generation");
    };
    assert_eq!(sent[0].job, post_job(extent, refused));
    assert!(refused < &newer.id && newer.id < final_gen.id);
    assert_eq!(sent[1].job, post_job(extent, &final_gen.id));
    assert_eq!(rig.count("generations"), 2);
    assert_eq!(
        rig.count("outbox WHERE stage = 'post' AND sent_at IS NOT NULL"),
        1
    );

    rig.bridge.clock.advance_secs(1);
    assert!(rig
        .bridge
        .catalog
        .claim(extent, refused, OutboxStage::Post, "test", rig.now())
        .await
        .unwrap()
        .is_none());
    assert_eq!(rig.bridge.run_job(&sent[0].job).await, JobOutcome::Ack);
    assert_eq!(
        rig.count("outbox WHERE stage = 'post' AND lease_token = 0"),
        1
    );
    assert!(provider.server().posted_ids().await.is_empty());

    assert_eq!(rig.bridge.run_job(&sent[1].job).await, JobOutcome::Ack);
    assert_eq!(rig.count("outbox WHERE stage = 'post'"), 0);
    assert_eq!(
        rig.count("outbox WHERE stage = 'verify' AND lease_token = 2"),
        1
    );
    assert_eq!(provider.server().posted_ids().await.len(), 1);
}
