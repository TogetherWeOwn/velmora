//! The tenant chain over a record store: put-once at the next seq, the
//! loser of a race validated again, the head found by a listing after
//! the last known seq, and a damaged chain refused.

use std::collections::BTreeMap;

use velmora_bridge::directory::chain::{
    record_key, ChainError, ControlSeal, TenantChain, Written, MAX_PUT_TRIES,
};
use velmora_bridge::directory::record::DeletionReason;
use velmora_bridge::directory::record::{HoldMode, OperatorReason, Tenant, TenantState};
use velmora_bridge::directory::testing::{HookedRecords, PlainSeal};
use velmora_bridge::directory::transition::{
    next, Actor, Change, OperatorHoldRequest, Outcome, KEY_CHECK_LEN,
};
use velmora_bridge::UnixMs;

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const DAY: i64 = 24 * 3_600_000;

fn t1() -> Tenant {
    Tenant::parse("t_00000000000000a1").unwrap()
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn create() -> Change {
    Change::Create {
        jurisdiction: "us".into(),
        location_hint: None,
        synthetic: false,
        limits: BTreeMap::new(),
        rate_json: Default::default(),
        features_json: Default::default(),
    }
}

fn hold(mode: HoldMode) -> Change {
    Change::SetOperatorHold {
        hold: Some(OperatorHoldRequest {
            mode,
            reason: OperatorReason::Security,
            preserve: None,
        }),
    }
}

fn delete(key: u8) -> Change {
    Change::SetDeletion {
        shred_due_at: UnixMs(NOW.0 + 7 * DAY),
        reason: DeletionReason::CustomerRequest,
        key_hash: format!("{key:02x}").repeat(32),
    }
}

/// Creates t1 and takes it to `active`: 4 records.
async fn active(chain: &TenantChain<'_, HookedRecords, PlainSeal>) {
    let t = t1();
    for change in [
        create(),
        Change::ClaimKeyVersion { version: 1 },
        Change::CommitKeyVersion {
            version: 1,
            kcv: [1; KEY_CHECK_LEN],
        },
        Change::Activate {
            external_ref: Some("ws_1".into()),
        },
    ] {
        let w = chain
            .write(&t, &change, Actor::TenantCreation, NOW, 0)
            .await;
        assert!(
            matches!(w, Ok(Written::Wrote(_))),
            "a creation step did not write"
        );
    }
}

/// The sealed bytes of the record that `change` makes on top of the head
/// of `store`, as a second writer would put them.
fn competitor(
    store: &HookedRecords,
    seal: &PlainSeal,
    change: Change,
    actor: Actor,
) -> (String, Vec<u8>) {
    let chain = TenantChain { store, seal };
    let head = block_on(chain.head(&t1(), 0)).unwrap().unwrap();
    let record = velmora_bridge::directory::record::TenantRecord {
        door: head.door,
        private: head.private.unwrap(),
    };
    let Ok(Outcome::Next(rec)) = next(&t1(), Some(&record), &change, actor, NOW) else {
        panic!("competitor");
    };
    let name = record_key(&t1(), rec.door.seq);
    let door = serde_json::to_vec(&rec.door).unwrap();
    let private = serde_json::to_vec(&rec.private).unwrap();
    let sealed = seal
        .seal(&name, &t1(), rec.door.tk_version, &door, &private)
        .unwrap();
    (name, sealed)
}

#[test]
fn records_are_put_once_at_the_next_seq() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        assert!(chain.head(&t1(), 0).await.unwrap().is_none());
        active(&chain).await;
        let head = chain.head(&t1(), 0).await.unwrap().unwrap();
        assert_eq!(head.door.seq, 4);
        assert_eq!(head.door.state(), TenantState::Active);
        assert_eq!(head.private.unwrap().external_ref.as_deref(), Some("ws_1"));
        assert_eq!(
            store.keys(),
            (1..=4).map(|s| record_key(&t1(), s)).collect::<Vec<_>>()
        );
        // A known seq starts the listing after it.
        assert_eq!(chain.head_seq(&t1(), 3).await.unwrap(), Some(4));
        assert_eq!(chain.head_seq(&t1(), 4).await.unwrap(), Some(4));
        // Every record of the chain still reads.
        for seq in 1..=4 {
            let r = chain.read(&t1(), seq).await.unwrap().unwrap();
            assert_eq!(r.door.seq, seq);
        }
    });
}

#[test]
fn a_change_the_head_carries_writes_nothing() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        active(&chain).await;
        let lift = Change::SetOperatorHold { hold: None };
        let w = chain
            .write(&t1(), &lift, Actor::Operator, NOW, 0)
            .await
            .unwrap();
        let Written::Unchanged(head) = w else {
            panic!("{w:?}")
        };
        assert_eq!(head.door.seq, 4);
        assert_eq!(store.keys().len(), 4);
    });
}

#[test]
fn a_refused_change_writes_nothing() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        active(&chain).await;
        let w = chain
            .write(&t1(), &hold(HoldMode::Locked), Actor::Customer, NOW, 0)
            .await;
        let Err(ChainError::Refused(r)) = w else {
            panic!("{w:?}")
        };
        assert_eq!(r.status, 403);
        assert_eq!(store.keys().len(), 4);
    });
}

/// The loser of a race reads the new head and validates again; its
/// change lands at the seq after the winner's.
#[test]
fn the_loser_of_a_race_is_validated_again_on_the_new_head() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(active(&chain));
    let (name, sealed) = competitor(
        &store,
        &seal,
        Change::SetBillingHold {
            mode: Some(HoldMode::ReadOnly),
        },
        Actor::Billing,
    );
    let mut planted = Some((name, sealed));
    store.before_put(move |_key, objects| {
        if let Some((name, sealed)) = planted.take() {
            objects.insert(name, sealed);
        }
    });
    block_on(async {
        let w = chain
            .write(&t1(), &hold(HoldMode::Locked), Actor::Operator, NOW, 0)
            .await
            .unwrap();
        let Written::Wrote(rec) = w else {
            panic!("{w:?}")
        };
        assert_eq!(rec.door.seq, 6);
        // Both changes are in force: the winner's was not overwritten.
        assert!(rec.door.holds.billing.is_some());
        assert!(rec.door.holds.operator.is_some());
        let head = chain.head(&t1(), 0).await.unwrap().unwrap();
        assert_eq!(head.door.seq, 6);
    });
}

/// A race whose winner makes the loser's change invalid: the loser is
/// refused and is never written at seq + 1.
#[test]
fn a_loser_that_is_no_longer_valid_is_refused() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(active(&chain));
    let (name, sealed) = competitor(&store, &seal, delete(1), Actor::Customer);
    let mut planted = Some((name, sealed));
    store.before_put(move |_key, objects| {
        if let Some((name, sealed)) = planted.take() {
            objects.insert(name, sealed);
        }
    });
    block_on(async {
        let w = chain
            .write(&t1(), &delete(2), Actor::Customer, NOW, 0)
            .await;
        let Err(ChainError::Refused(r)) = w else {
            panic!("{w:?}")
        };
        assert_eq!(r.code, "already_deleting");
        assert_eq!(store.keys().len(), 5);
        let head = chain.head(&t1(), 0).await.unwrap().unwrap();
        assert_eq!(head.door.deletion.unwrap().key_hash, "01".repeat(32));
    });
}

/// A bucket made while an operator's unit change was built: the unit
/// change, built on the head before the bucket, loses the put and is
/// refused, instead of writing its placements over the new bucket's.
#[test]
fn a_whole_field_change_never_erases_a_concurrent_bucket() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(active(&chain));
    let base = block_on(chain.head(&t1(), 0)).unwrap().unwrap().door;
    let (name, sealed) = competitor(
        &store,
        &seal,
        Change::CreateBucket {
            bucket: "b_new".into(),
            unit: 0,
            creator: "p_owner".into(),
        },
        Actor::Customer,
    );
    let mut planted = Some((name, sealed));
    store.before_put(move |_key, objects| {
        if let Some((name, sealed)) = planted.take() {
            objects.insert(name, sealed);
        }
    });
    // A second unit, with the placements the operator saw (none).
    assert!(base.placements.is_empty());
    let units = Change::SetUnits {
        base_seq: base.seq,
        units: vec![0, 1],
        placements: vec![],
    };
    block_on(async {
        let w = chain.write(&t1(), &units, Actor::Operator, NOW, 0).await;
        let Err(ChainError::Refused(r)) = w else {
            panic!("the stale unit change was not refused")
        };
        assert_eq!((r.status, r.code), (409, "stale_base"));
        let head = chain.head(&t1(), 0).await.unwrap().unwrap();
        assert_eq!(head.door.seq, base.seq + 1);
        assert_eq!(head.door.placements.len(), 1);
        assert_eq!(head.door.placements[0].bucket, "b_new");
        // Built again on the new head, it keeps the bucket.
        let again = Change::SetUnits {
            base_seq: head.door.seq,
            units: vec![0, 1],
            placements: head.door.placements.clone(),
        };
        let w = chain
            .write(&t1(), &again, Actor::Operator, NOW, head.door.seq)
            .await
            .unwrap();
        let Written::Wrote(rec) = w else {
            panic!("the rebuilt unit change did not write")
        };
        assert_eq!(rec.door.units, [0, 1]);
        assert_eq!(rec.door.placements[0].bucket, "b_new");
    });
}

#[test]
fn a_writer_that_keeps_losing_answers_busy() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(active(&chain));
    // Every put finds its seq taken: another writer is always first.
    let seal_for_hook = PlainSeal::new();
    store.before_put(move |key, objects| {
        let t = t1();
        let seq: u64 = key.rsplit('/').next().unwrap().parse().unwrap();
        // A copy of the record before, re-sealed under this name, as a
        // valid next record of another writer.
        let prev = objects.get(&record_key(&t, seq - 1)).cloned().unwrap();
        let opened = seal_for_hook
            .open(&record_key(&t, seq - 1), &t, &prev)
            .unwrap();
        let mut door: serde_json::Value = serde_json::from_slice(&opened.door).unwrap();
        door["seq"] = serde_json::json!(seq);
        let door = serde_json::to_vec(&door).unwrap();
        let sealed = seal_for_hook
            .seal(
                key,
                &t,
                opened.key_version,
                &door,
                opened.private.as_deref().unwrap(),
            )
            .unwrap();
        objects.insert(key.to_string(), sealed);
    });
    block_on(async {
        let w = chain
            .write(&t1(), &hold(HoldMode::Locked), Actor::Operator, NOW, 0)
            .await;
        assert!(matches!(w, Err(ChainError::Busy)), "{w:?}");
        assert_eq!(store.keys().len(), 4 + MAX_PUT_TRIES as usize);
    });
}

#[test]
fn a_damaged_chain_is_refused() {
    let seal = PlainSeal::new();
    let t2 = Tenant::parse("t_00000000000000b2").unwrap();

    // A gap.
    let store = HookedRecords::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(active(&chain));
    let rec3 = store.raw(&record_key(&t1(), 3)).unwrap();
    assert!(store.lose(&record_key(&t1(), 3)));
    let r = block_on(chain.head(&t1(), 0));
    assert!(matches!(r, Err(ChainError::Damaged(_))), "{r:?}");
    // A record moved to another seq does not open as that seq.
    store.plant(
        &record_key(&t1(), 3),
        store.raw(&record_key(&t1(), 2)).unwrap(),
    );
    assert!(block_on(chain.read(&t1(), 3)).is_err());
    store.plant(&record_key(&t1(), 3), rec3.clone());
    assert!(block_on(chain.head(&t1(), 0)).is_ok());

    // A stray name under the chain's prefix.
    store.plant(&format!("{}x", record_key(&t1(), 9)), vec![1]);
    let r = block_on(chain.head(&t1(), 0));
    assert!(matches!(r, Err(ChainError::Damaged(_))), "{r:?}");

    // A record of t1 under t2's name: the seal refuses it, and a seal
    // that would open it still finds the door naming another tenant.
    let store = HookedRecords::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(active(&chain));
    let bytes = store.raw(&record_key(&t1(), 1)).unwrap();
    store.plant(&record_key(&t2, 1), bytes);
    assert!(block_on(chain.read(&t2, 1)).is_err());
    let door = {
        let opened = seal
            .open(
                &record_key(&t1(), 1),
                &t1(),
                &store.raw(&record_key(&t1(), 1)).unwrap(),
            )
            .unwrap();
        opened.door
    };
    let forged = seal
        .seal(&record_key(&t2, 1), &t2, 0, &door, b"{\"v\":1}")
        .unwrap();
    store.plant(&record_key(&t2, 1), forged);
    let r = block_on(chain.read(&t2, 1));
    assert!(
        matches!(r, Err(ChainError::Damaged("record_names_another"))),
        "{r:?}"
    );

    // A known seq above the head, also on an empty chain.
    let r = block_on(chain.head(&t1(), 9));
    assert!(
        matches!(r, Err(ChainError::Damaged("known_above_head"))),
        "{r:?}"
    );
    let r = block_on(chain.head_seq(&t1(), 5));
    assert!(
        matches!(r, Err(ChainError::Damaged("known_above_head"))),
        "{r:?}"
    );
    let r = block_on(chain.head_seq(&Tenant::parse("t_00000000000000e5").unwrap(), 7));
    assert!(
        matches!(r, Err(ChainError::Damaged("known_above_head"))),
        "{r:?}"
    );
    // The known seq itself is the head.
    assert_eq!(block_on(chain.head_seq(&t1(), 4)).unwrap(), Some(4));
}

#[test]
fn a_head_whose_private_part_does_not_open_takes_no_record() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(active(&chain));
    seal.lose_private(true);
    block_on(async {
        // The door part still reads, so a gate can still close doors.
        let head = chain.head(&t1(), 0).await.unwrap().unwrap();
        assert_eq!(head.private, None);
        assert_eq!(head.door.state(), TenantState::Active);
        let w = chain
            .write(&t1(), &hold(HoldMode::Locked), Actor::Operator, NOW, 0)
            .await;
        assert!(matches!(w, Err(ChainError::PrivateUnreadable)), "{w:?}");
        assert_eq!(store.keys().len(), 4);
    });
}

#[test]
fn the_head_is_found_across_listing_pages() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        active(&chain).await;
        // 1,100 more records: hold on, hold off.
        let mut known = 4;
        for i in 0..1_100 {
            let change = match i % 2 {
                0 => hold(HoldMode::ReadOnly),
                _ => Change::SetOperatorHold { hold: None },
            };
            let Written::Wrote(rec) = chain
                .write(&t1(), &change, Actor::Operator, NOW, known)
                .await
                .unwrap()
            else {
                panic!("write {i}");
            };
            known = rec.door.seq;
        }
        assert_eq!(known, 1_104);
        assert_eq!(chain.head_seq(&t1(), 0).await.unwrap(), Some(1_104));
        // From a known seq, one listing call.
        let before = store.lists();
        assert_eq!(chain.head_seq(&t1(), 1_100).await.unwrap(), Some(1_104));
        assert_eq!(store.lists() - before, 1);
    });
}

/// The shredded stub is written after every key version was destroyed: it
/// is sealed with no tenant key and reads back as the head.
#[test]
fn the_shredded_stub_needs_no_tenant_key() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        active(&chain).await;
        let w = chain
            .write(&t1(), &delete(1), Actor::Customer, NOW, 0)
            .await;
        assert!(matches!(w, Ok(Written::Wrote(_))), "{w:?}");
        let due = UnixMs(NOW.0 + 7 * DAY);
        let w = chain
            .write(&t1(), &Change::StartShred, Actor::ShredJob, due, 0)
            .await;
        assert!(matches!(w, Ok(Written::Wrote(_))), "{w:?}");
        // The shred destroys version 1; then the stub is written.
        seal.destroy_version(1);
        let w = chain
            .write(&t1(), &Change::FinishShred, Actor::ShredJob, due, 0)
            .await;
        let Ok(Written::Wrote(stub)) = w else {
            panic!("{w:?}")
        };
        assert_eq!(stub.door.state(), TenantState::Shredded);
        assert_eq!(stub.door.tk_version, 1);
        let head = chain.head(&t1(), 0).await.unwrap().unwrap();
        assert_eq!(head.door.state(), TenantState::Shredded);
        assert_eq!(head.private.unwrap().external_ref, None);
        // Older records keep their door part; their private part is gone.
        let older = chain.read(&t1(), 4).await.unwrap().unwrap();
        assert_eq!(older.private, None);
        assert_eq!(older.door.state(), TenantState::Active);
        // Nothing follows the stub.
        let w = chain
            .write(&t1(), &Change::UndoDeletion, Actor::Operator, due, 0)
            .await;
        let Err(ChainError::Refused(r)) = w else {
            panic!("{w:?}")
        };
        assert_eq!(r.code, "tenant_shredded");
    });
}

/// A record that does not open is damage of that record, not a failure of
/// the store.
#[test]
fn a_record_that_does_not_open_is_damage() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(active(&chain));
    let mut bytes = store.raw(&record_key(&t1(), 4)).unwrap();
    bytes[0] ^= 1;
    store.plant(&record_key(&t1(), 4), bytes);
    let r = block_on(chain.head(&t1(), 0));
    assert!(
        matches!(r, Err(ChainError::Damaged("record_does_not_open"))),
        "{r:?}"
    );
}

/// A shred's purge leaves the stub alone, with the gap below it: the stub
/// is the head. Any other record alone above a gap is damage.
#[test]
fn a_purged_chain_reads_its_stub_as_the_head() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        active(&chain).await;
        chain
            .write(&t1(), &delete(1), Actor::Customer, NOW, 0)
            .await
            .unwrap();
        let due = UnixMs(NOW.0 + 7 * DAY);
        chain
            .write(&t1(), &Change::StartShred, Actor::ShredJob, due, 0)
            .await
            .unwrap();
        seal.destroy_version(1);
        chain
            .write(&t1(), &Change::FinishShred, Actor::ShredJob, due, 0)
            .await
            .unwrap();
        // The purge: every record below the stub goes.
        for seq in 1..=6 {
            assert!(store.lose(&record_key(&t1(), seq)));
        }
        for known in [0, 1, 7] {
            assert_eq!(
                chain.head_seq(&t1(), known).await.unwrap(),
                Some(7),
                "known {known}"
            );
        }
        let head = chain.head(&t1(), 0).await.unwrap().unwrap();
        assert_eq!(head.door.state(), TenantState::Shredded);
        assert!(matches!(
            chain.head_seq(&t1(), 8).await,
            Err(ChainError::Damaged("known_above_head"))
        ));
    });

    // A live record alone above a gap is damage, not a stub.
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(active(&chain));
    for seq in 1..=3 {
        assert!(store.lose(&record_key(&t1(), seq)));
    }
    let r = block_on(chain.head_seq(&t1(), 0));
    assert!(matches!(r, Err(ChainError::Damaged(_))), "{r:?}");
}

/// A record under a key version this isolate does not hold yet is a
/// failure that may pass, not damage.
#[test]
fn a_key_version_not_held_yet_is_not_damage() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(active(&chain));
    seal.not_held(1, true);
    let r = block_on(chain.head(&t1(), 0));
    assert!(
        matches!(r, Err(ChainError::KeyNotHeld { version: 1 })),
        "{r:?}"
    );
    seal.not_held(1, false);
    assert!(block_on(chain.head(&t1(), 0)).unwrap().is_some());
}

/// A purge under way (it deletes from the first record up) leaves a
/// contiguous tail that ends in the stub: the stub is the head.
#[test]
fn a_purge_under_way_reads_its_stub_as_the_head() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        active(&chain).await;
        chain
            .write(&t1(), &delete(1), Actor::Customer, NOW, 0)
            .await
            .unwrap();
        let due = UnixMs(NOW.0 + 7 * DAY);
        chain
            .write(&t1(), &Change::StartShred, Actor::ShredJob, due, 0)
            .await
            .unwrap();
        seal.destroy_version(1);
        chain
            .write(&t1(), &Change::FinishShred, Actor::ShredJob, due, 0)
            .await
            .unwrap();
        // Records 1 to 3 are gone; 4 to 7 are left.
        for seq in 1..=3 {
            assert!(store.lose(&record_key(&t1(), seq)));
        }
        for known in [0, 2, 4, 7] {
            assert_eq!(
                chain.head_seq(&t1(), known).await.unwrap(),
                Some(7),
                "known {known}"
            );
        }
        // A gap inside the tail is still damage.
        assert!(store.lose(&record_key(&t1(), 5)));
        let r = chain.head_seq(&t1(), 0).await;
        assert!(matches!(r, Err(ChainError::Damaged(_))), "{r:?}");
    });
}

/// A known seq above a gap whose record below is still there is a gap
/// inside the chain, not a purge.
#[test]
fn a_gap_inside_the_chain_is_not_taken_for_a_purge() {
    let store = HookedRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        active(&chain).await;
        chain
            .write(&t1(), &delete(1), Actor::Customer, NOW, 0)
            .await
            .unwrap();
        let due = UnixMs(NOW.0 + 7 * DAY);
        chain
            .write(&t1(), &Change::StartShred, Actor::ShredJob, due, 0)
            .await
            .unwrap();
        seal.destroy_version(1);
        chain
            .write(&t1(), &Change::FinishShred, Actor::ShredJob, due, 0)
            .await
            .unwrap();
        // Record 5 lost, 4 still there: with known = 5 that is damage.
        assert!(store.lose(&record_key(&t1(), 5)));
        let r = chain.head_seq(&t1(), 5).await;
        assert!(matches!(r, Err(ChainError::Damaged(_))), "{r:?}");
    });
}
