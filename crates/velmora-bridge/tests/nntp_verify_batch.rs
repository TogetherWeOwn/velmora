//! Verify jobs that share NNTP sessions across a batch.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::fetch::SessionShelf;
use velmora_bridge::*;

type VerifyShelf = SessionShelf<<TcpConnector as NntpConnector>::Session>;

async fn rig_on() -> Rig {
    let mut rig = two_backbone_rig().await;
    rig.bridge.cfg.release_at_verify = true;
    rig
}

impl Rig {
    async fn on_two(&self, n: u8) -> Seeded {
        let s = self.seed(n, &marked_plaintext(1_500_000)).await;
        assert_eq!(self.post(&s).await.len(), 3);
        self.propagate(&s, 0, 1).await;
        s
    }

    async fn verify_in(&self, s: &Seeded, shelf: Option<&VerifyShelf>) -> JobOutcome {
        let lease = self.claim(s, OutboxStage::Verify).await;
        let job = self.job(s).await;
        match shelf {
            Some(shelf) => self.bridge.verify_stage_in(&lease, &job, Some(shelf)).await,
            None => self.bridge.verify_stage(&lease, &job).await,
        }
    }

    async fn close_shelf(&self, shelf: &VerifyShelf) {
        shelf.close(&self.bridge.catalog, &self.bridge.clock).await;
    }

    fn outbox(&self, s: &Seeded) -> OutboxRow {
        self.bridge.catalog.outbox(&s.extent)
    }

    fn released(&self, s: &Seeded) -> bool {
        self.bridge.safety.contains(&s.extent.safety_key())
            && self.bridge.catalog.extent(&s.extent).safety_state == SafetyState::Released
            && self.outbox(s).stage == OutboxStage::Done
    }

    fn held(&self, s: &Seeded) -> bool {
        let extent = self.bridge.catalog.extent(&s.extent);
        self.bridge.safety.contains(&s.extent.safety_key())
            && extent.safety_state == SafetyState::Held
            && extent.release_evidence.is_none()
            && extent.released_at.is_none()
    }

    fn verify_connections(&self) -> [usize; 2] {
        ["p0", "p1"].map(|id| self.bridge.nntp.connects_to(id))
    }
}

/// Four extents share two connections, and closing the shelf frees both slots.
#[tokio::test]
async fn a_batch_verifies_every_extent_over_one_connection_per_backbone() {
    let rig = rig_on().await;
    for (start, shelf, expected) in [(1, Some(VerifyShelf::new().unwrap()), 1), (5, None, 4)] {
        let mut extents = Vec::new();
        for n in start..start + 4 {
            extents.push(rig.on_two(n).await);
        }
        let before = rig.verify_connections();
        for s in &extents {
            assert_eq!(rig.verify_in(s, shelf.as_ref()).await, JobOutcome::Ack);
            assert!(rig.released(s));
        }
        if let Some(shelf) = &shelf {
            assert_eq!(shelf.parked(), 2);
            assert_eq!(shelf.reused(), 6);
            rig.close_shelf(shelf).await;
            assert_eq!(shelf.parked(), 0);
            assert_eq!(rig.bridge.nntp.live(), 0);
            let loads = rig
                .bridge
                .catalog
                .provider_load(rig.bridge.clock.now())
                .await
                .unwrap();
            assert_eq!(loads.iter().map(|load| load.held).sum::<u32>(), 0);
        }
        assert_eq!(
            rig.verify_connections(),
            before.map(|count| count + expected)
        );
    }
}

/// Losing the middle claim leaves its extent held while the other jobs release theirs.
#[tokio::test]
async fn an_extent_whose_lease_is_lost_inside_a_batch_is_skipped_alone() {
    let rig = rig_on().await;
    let first = rig.on_two(1).await;
    let lost = rig.on_two(2).await;
    let last = rig.on_two(3).await;
    let shelf = VerifyShelf::new().unwrap();

    assert_eq!(rig.verify_in(&first, Some(&shelf)).await, JobOutcome::Ack);
    let lease = rig.claim(&lost, OutboxStage::Verify).await;
    let job = rig.job(&lost).await;
    rig.bridge.catalog.take_over(&lost.extent);
    assert_eq!(
        rig.bridge.verify_stage_in(&lease, &job, Some(&shelf)).await,
        JobOutcome::Ack
    );
    assert_eq!(rig.verify_in(&last, Some(&shelf)).await, JobOutcome::Ack);
    rig.close_shelf(&shelf).await;

    assert!(rig.held(&lost));
    assert_eq!(rig.outbox(&lost).stage, OutboxStage::Verify);
    assert!(rig.bridge.catalog.verifications(&lost.extent).is_empty());
    for s in [first, last] {
        assert!(rig.released(&s));
        let rows = rig.bridge.catalog.verifications(&s.extent);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.extent_id == s.extent));
    }
}

/// Each job renews its own claim, even when it uses the previous job's connections.
#[tokio::test]
async fn each_job_of_a_batch_renews_its_own_lease() {
    let rig = rig_on().await;
    let first = rig.on_two(1).await;
    let second = rig.on_two(2).await;
    let shelf = VerifyShelf::new().unwrap();
    let clock = &rig.bridge.clock;
    let renewals = &rig.bridge.catalog.lease_renewed_at;

    let first_lease = rig.claim(&first, OutboxStage::Verify).await;
    renewals.borrow_mut().clear();
    clock.advance_secs(21);
    assert_eq!(
        rig.bridge
            .verify_stage_in(&first_lease, &rig.job(&first).await, Some(&shelf))
            .await,
        JobOutcome::Ack
    );
    assert_eq!(*renewals.borrow(), [clock.now(); 2]);
    assert!(rig.released(&first));
    let before = rig.outbox(&first);

    let second_lease = rig.claim(&second, OutboxStage::Verify).await;
    assert_ne!(first_lease.extent, second_lease.extent);
    renewals.borrow_mut().clear();
    clock.advance_secs(21);
    assert_eq!(
        rig.bridge
            .verify_stage_in(&second_lease, &rig.job(&second).await, Some(&shelf))
            .await,
        JobOutcome::Ack
    );
    assert_eq!(*renewals.borrow(), [clock.now(); 2]);
    assert_eq!(shelf.reused(), 2);
    assert!(rig.released(&second));
    let row = rig.outbox(&second);
    assert_eq!(
        (row.token, row.claimed_at),
        (second_lease.token, second_lease.claimed_at)
    );
    let after = rig.outbox(&first);
    assert_eq!(
        (
            after.stage,
            after.token,
            after.claimed_at,
            after.lease_until
        ),
        (
            before.stage,
            before.token,
            before.claimed_at,
            before.lease_until
        )
    );
    rig.close_shelf(&shelf).await;
}

/// A job opens fresh connections after the parked sessions pass their reuse limit.
#[tokio::test]
async fn a_kept_session_older_than_the_reuse_bound_is_closed_and_a_new_one_opened() {
    let rig = rig_on().await;
    let first = rig.on_two(1).await;
    let second = rig.on_two(2).await;
    let shelf = VerifyShelf::new().unwrap();
    let before = rig.verify_connections();

    assert_eq!(rig.verify_in(&first, Some(&shelf)).await, JobOutcome::Ack);
    assert_eq!(shelf.parked(), 2);
    rig.bridge.clock.advance_ms(60_000 + 1_000);
    assert_eq!(rig.verify_in(&second, Some(&shelf)).await, JobOutcome::Ack);
    assert_eq!(rig.verify_connections(), before.map(|count| count + 2));
    assert_eq!(shelf.reused(), 0);
    assert_eq!(shelf.parked(), 2);
    assert_eq!(rig.bridge.nntp.live(), 2);
    assert!(rig.released(&first));
    assert!(rig.released(&second));
    rig.close_shelf(&shelf).await;
}

/// A pass that loses its slot closes its session, so the next job dials again.
#[tokio::test]
async fn a_session_whose_pass_failed_is_not_kept() {
    let rig = rig_on().await;
    let first = rig.on_two(1).await;
    let second = rig.on_two(2).await;
    let shelf = VerifyShelf::new().unwrap();
    let bridge = &rig.bridge;
    let before = rig.verify_connections();
    bridge.nntp.slow(&bridge.clock, 8_000);

    let done = std::cell::Cell::new(false);
    let verify = async {
        let outcome = rig.verify_in(&first, Some(&shelf)).await;
        done.set(true);
        outcome
    };
    let interrupt = async {
        // Revoke the slot during the first BODY, before renewal is due.
        while bridge.nntp.calls().len() < 2 {
            assert!(!done.get(), "verify ended before its first BODY");
            tokio::task::yield_now().await;
        }
        bridge.catalog.drop_permits();
    };
    let (outcome, ()) = tokio::join!(verify, interrupt);
    assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
    let calls: Vec<_> = bridge
        .nntp
        .calls()
        .into_iter()
        .map(|(call, _)| call)
        .collect();
    assert_eq!(calls, ["connect", "body", "body"]);
    assert_eq!(rig.verify_connections(), [before[0] + 1, before[1]]);
    assert_eq!(shelf.parked(), 0);
    assert_eq!(bridge.nntp.live(), 0);
    assert!(rig.held(&first));

    // Let the revoked permit expire so it can be acquired again.
    bridge.clock.advance_secs(ports::PERMIT_SECS + 1);
    bridge.nntp.slow(&bridge.clock, 0);
    assert_eq!(rig.verify_in(&second, Some(&shelf)).await, JobOutcome::Ack);
    assert_eq!(rig.verify_connections(), [before[0] + 2, before[1] + 1]);
    assert_eq!(shelf.reused(), 0);
    assert!(rig.released(&second));
    rig.close_shelf(&shelf).await;
}

/// The first blocked job polls for a slot, and the next job retries immediately.
#[tokio::test]
async fn only_one_job_of_a_batch_waits_for_a_slot() {
    let mut rig = rig_on().await;
    rig.with_timer();
    let first = rig.on_two(1).await;
    let second = rig.on_two(2).await;
    let shelf = VerifyShelf::new().unwrap();
    let bridge = &rig.bridge;
    let now = bridge.clock.now();
    let held = rig.take_slots(0, now.plus_secs(30)).await;
    let (_, asks) = bridge.catalog.slot_asks();
    let attempts = [&first, &second].map(|s| rig.outbox(s).attempts);

    let outcome = rig.verify_in(&first, Some(&shelf)).await;
    assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
    let end = bridge.clock.now();
    let poll = i64::from(jobs::SLOT_POLL_MS);
    assert!((jobs::SLOT_WAIT_MS..jobs::SLOT_WAIT_MS + poll).contains(&(end.0 - now.0)));
    let (loads_after_first, asks_after_first) = bridge.catalog.slot_asks();
    assert!(asks_after_first > asks + 1);

    let outcome = rig.verify_in(&second, Some(&shelf)).await;
    assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
    assert_eq!(bridge.clock.now(), end);
    assert_eq!(
        bridge.catalog.slot_asks(),
        (loads_after_first + 1, asks_after_first + 1)
    );
    for (s, attempts) in [&first, &second].into_iter().zip(attempts) {
        assert!(rig.held(s));
        let row = rig.outbox(s);
        assert_eq!((row.stage, row.attempts), (OutboxStage::Verify, attempts));
    }

    for permit in held {
        bridge.catalog.release_permit(&permit).await.unwrap();
    }
    rig.close_shelf(&shelf).await;
}

/// Slots held now, per provider id.
async fn held(rig: &Rig, id: &str) -> u32 {
    let now = rig.bridge.clock.now();
    let loads = rig.bridge.catalog.provider_load(now).await.unwrap();
    loads
        .iter()
        .filter(|l| l.provider_id == id)
        .map(|l| l.held)
        .sum()
}

/// A shelf keeps at most two sessions: the third backbone's session
/// closes the oldest one, socket and slot.
#[tokio::test]
async fn a_full_shelf_closes_its_oldest_session() {
    let one = |backbone, post| Spec {
        backbone,
        post,
        max_conns: 2,
    };
    let mut rig = rig(&[one("bb0", true), one("bb1", false), one("bb2", false)]).await;
    rig.bridge.cfg.required_backbones = 2;
    rig.bridge.cfg.release_at_verify = true;
    let s = rig.seed(1, &marked_plaintext(1_500_000)).await;
    assert_eq!(rig.post(&s).await.len(), 3);
    for to in 1..3 {
        rig.propagate(&s, 0, to).await;
    }
    let shelf = VerifyShelf::new().unwrap();

    assert_eq!(rig.verify_in(&s, Some(&shelf)).await, JobOutcome::Ack);
    assert!(rig.released(&s));
    assert_eq!(shelf.parked(), 2);
    assert_eq!(rig.bridge.nntp.live(), 2);
    // The first one read (p0) went first.
    assert_eq!(held(&rig, "p0").await, 0);
    for id in ["p1", "p2"] {
        assert_eq!(held(&rig, id).await, 1, "{id}");
    }
    rig.close_shelf(&shelf).await;
    assert_eq!(rig.bridge.nntp.live(), 0);
    for id in ["p0", "p1", "p2"] {
        assert_eq!(held(&rig, id).await, 0, "{id}");
    }
}

/// A release job of the batch asks its backbones over the sessions the
/// verify job before it kept: no new connection.
#[tokio::test]
async fn a_release_job_of_a_batch_takes_the_kept_sessions() {
    let rig = two_backbone_rig().await;
    assert!(!rig.bridge.cfg.release_at_verify);
    let s = rig.on_two(1).await;
    let shelf = VerifyShelf::new().unwrap();

    assert_eq!(rig.verify_in(&s, Some(&shelf)).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&s).stage, OutboxStage::Release);
    assert!(rig.held(&s));
    let before = rig.verify_connections();
    // A second after the round: in the same millisecond the release job
    // is put off (Retry) with or without a shelf in this rig.
    rig.bridge.clock.advance_secs(1);

    let lease = rig.claim(&s, OutboxStage::Release).await;
    let job = rig.job(&s).await;
    assert_eq!(
        rig.bridge
            .release_stage_in(&lease, &job, Some(&shelf))
            .await,
        JobOutcome::Ack
    );
    assert!(rig.released(&s));
    assert_eq!(rig.verify_connections(), before);
    assert_eq!(shelf.reused(), 2);
    rig.close_shelf(&shelf).await;
    assert_eq!(rig.bridge.nntp.live(), 0);
}

/// A job that has to wait for a slot closes the sessions the batch kept
/// before it waits: none of them stays logged in, unrenewed, while it
/// sleeps, and their slots are free for others.
#[tokio::test]
async fn a_job_that_waits_for_a_slot_closes_the_kept_sessions_first() {
    let mut rig = two_backbone_rig().await;
    rig.with_timer();
    let first = rig.on_two(1).await;
    let second = rig.on_two(2).await;
    let shelf = VerifyShelf::new().unwrap();

    // The first extent's round is at its second backbone: its job reads
    // bb1 only and keeps p1's session.
    let lease = rig.claim(&first, OutboxStage::Verify).await;
    let now = rig.bridge.clock.now();
    let pass = VerificationRow {
        extent_id: first.extent.clone(),
        backbone: "bb0".into(),
        provider_id: "p0".into(),
        verified_at: now,
        plan_rev: 1,
        articles_ok: 3,
        articles_total: 3,
        result: VerifyResult::Ok,
        kind: VerifyKind::Body,
    };
    let catalog = &rig.bridge.catalog;
    assert!(catalog.record_verification(&lease, &pass).await.unwrap());
    assert!(catalog.defer_at(&lease, 8, now, now).await.unwrap());
    rig.bridge.clock.advance_secs(1);
    assert_eq!(rig.verify_in(&first, Some(&shelf)).await, JobOutcome::Ack);
    assert_eq!(rig.outbox(&first).stage, OutboxStage::Release);
    assert_eq!(shelf.parked(), 1);
    assert_eq!(held(&rig, "p1").await, 1);

    // Every slot of p0 is someone else's: the second job waits for one.
    let now = rig.bridge.clock.now();
    let others = rig.take_slots(0, now.plus_secs(30)).await;
    let outcome = rig.verify_in(&second, Some(&shelf)).await;
    assert!(matches!(outcome, JobOutcome::Retry { .. }), "{outcome:?}");
    assert_eq!(shelf.parked(), 0);
    assert_eq!(rig.bridge.nntp.live(), 0);
    assert_eq!(held(&rig, "p1").await, 0);
    assert!(rig.held(&second));

    for permit in others {
        rig.bridge.catalog.release_permit(&permit).await.unwrap();
    }
    rig.close_shelf(&shelf).await;
}

/// While one session reads for a long time, the sessions the batch keeps
/// are renewed with it: the next backbone still finds its kept session
/// on a live slot and goes on with it.
#[tokio::test]
async fn a_long_pass_keeps_the_other_kept_slots_alive() {
    let rig = rig_on().await;
    let first = rig.on_two(1).await;
    let second = rig.on_two(2).await;
    let shelf = VerifyShelf::new().unwrap();

    assert_eq!(rig.verify_in(&first, Some(&shelf)).await, JobOutcome::Ack);
    assert_eq!(shelf.parked(), 2);
    let before = rig.verify_connections();

    // Every call takes 50 s (under the 80 s bound of a call): the second
    // job's pass on bb0 alone outlasts a background permit (120 s).
    rig.bridge.nntp.slow(&rig.bridge.clock, 50_000);
    let started = rig.bridge.clock.now();
    assert_eq!(rig.verify_in(&second, Some(&shelf)).await, JobOutcome::Ack);
    assert!(rig.bridge.clock.now().0 - started.0 > 120_000);
    assert!(rig.released(&second));
    assert_eq!(shelf.reused(), 2, "both kept sessions taken again");
    assert_eq!(rig.verify_connections(), before);
    assert_eq!(held(&rig, "p0").await, 1);
    assert_eq!(held(&rig, "p1").await, 1);
    rig.close_shelf(&shelf).await;
    assert_eq!(held(&rig, "p1").await, 0);
}
