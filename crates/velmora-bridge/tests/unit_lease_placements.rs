//! The worker's bucket changes and placement list for a unit sync.

use serde_json::json;
use velmora_bridge::directory::chain::ReadRecord;
use velmora_bridge::directory::record::{
    BucketCreated, BucketSecrets, Placement, Restoring, TenantDoor, TenantPrivate,
};
use velmora_bridge::unit::buckets::BucketChange;
use velmora_bridge::unit_lease::placements::{
    bucket_changes, placed, ERR_BUCKET_SECRETS, ERR_RECORD_ORDER,
};
use velmora_bridge::BridgeError;

const HERE: u32 = 0;
const REMOTE: u32 = 1;
const A: &str = "b_00000000000000a1";
const B: &str = "b_00000000000000a2";
const C: &str = "b_00000000000000a3";

fn door(seq: u64, placements: &[(&str, u32)]) -> TenantDoor {
    let mut door: TenantDoor = serde_json::from_value(json!({
        "v": 1,
        "tenant": "t_00000000000000a1",
        "seq": seq,
        "written_at": 1_800_000_000_000u64 + seq,
        "created_at": 1_800_000_000_001u64,
        "lifecycle": "live",
        "units": [HERE, REMOTE],
        "max_move_epoch": 1,
        "last_grant_seq": 0,
        "tk_version": 4,
        "highest_claimed": 4,
        "jurisdiction": "us"
    }))
    .expect("valid tenant door fixture");
    door.placements = placements
        .iter()
        .map(|&(bucket, unit)| Placement {
            bucket: bucket.into(),
            unit,
            epoch: 1,
        })
        .collect();
    door
}

fn record(door: TenantDoor) -> ReadRecord {
    ReadRecord {
        door,
        private: None,
    }
}

fn create(unit: u32, private: Option<TenantPrivate>) -> ReadRecord {
    let mut door = door(11, &[(A, unit)]);
    door.last_grant_seq = 7;
    door.bucket_created = Some(BucketCreated {
        bucket: A.into(),
        creator: "p_test".into(),
        grant_seq: 7,
    });
    ReadRecord { door, private }
}

fn assert_invalid_error(actual: BridgeError, expected: BridgeError) {
    assert!(
        matches!(
            (&actual, &expected),
            (BridgeError::Invalid(actual), BridgeError::Invalid(expected)) if actual == expected
        ),
        "expected {expected:?}, got {actual:?}"
    );
}

/// A local create copies the private bucket fields and the create door's write time.
#[test]
fn a_local_create_uses_private_bucket_fields_and_the_record_write_time() {
    let from = door(10, &[]);
    let created = create(
        HERE,
        Some(TenantPrivate {
            v: 1,
            bucket_created: Some(BucketSecrets {
                name: "fixture-bucket".into(),
                bdk_wrapped: vec![1, 2, 3],
                // Deliberately distinct from the synthetic door's version.
                tk_version: 3,
            }),
            ..TenantPrivate::default()
        }),
    );

    assert_eq!(
        bucket_changes(HERE, &from, &[created]).unwrap(),
        vec![BucketChange::Created {
            seq: 11,
            bucket_id: A.into(),
            grant_seq: 7,
            creator: "p_test".into(),
            name: "fixture-bucket".into(),
            bdk_wrapped: vec![1, 2, 3],
            tk_version: 3,
            written_at: 1_800_000_000_011,
        }]
    );
}

/// A local create fails both when the private part did not open and when it lacks the bucket fields.
#[test]
fn a_local_create_requires_bucket_secrets() {
    let from = door(10, &[]);
    let empty_private = TenantPrivate {
        v: 1,
        ..TenantPrivate::default()
    };

    for private in [None, Some(empty_private)] {
        let err = bucket_changes(HERE, &from, &[create(HERE, private)]).unwrap_err();
        assert_invalid_error(err, ERR_BUCKET_SECRETS);
    }
}

/// A remote create does not emit a change or require the bucket's private fields on this unit.
#[test]
fn a_remote_create_emits_no_local_change() {
    let from = door(10, &[]);

    assert!(bucket_changes(HERE, &from, &[create(REMOTE, None)])
        .unwrap()
        .is_empty());
}

/// A single local removal outside restore emits `Dropped`.
#[test]
fn removing_one_local_placement_emits_a_drop() {
    let from = door(10, &[(A, HERE), (B, REMOTE)]);
    let removed = record(door(11, &[(B, REMOTE)]));

    assert_eq!(
        bucket_changes(HERE, &from, &[removed]).unwrap(),
        vec![BucketChange::Dropped {
            seq: 11,
            bucket_id: A.into(),
        }]
    );
}

/// A single removal is `Unplaced` when the preceding door marks this unit as restoring.
#[test]
fn removing_one_placement_from_a_previously_restoring_unit_emits_an_unplace() {
    let mut from = door(10, &[(A, HERE)]);
    from.restoring = vec![Restoring {
        unit: HERE,
        since_seq: 9,
    }];
    // Only the preceding door has the entry so the test distinguishes the two doors.
    let removed = record(door(11, &[]));

    assert_eq!(
        bucket_changes(HERE, &from, &[removed]).unwrap(),
        vec![BucketChange::Unplaced {
            seq: 11,
            buckets: vec![A.into()],
        }]
    );
}

/// Several removals use `Removed` outside an entry and `Unplaced` under one.
#[test]
fn removing_several_local_placements_uses_the_preceding_doors_entry() {
    let mut from = door(10, &[(C, HERE), (B, HERE), (A, HERE)]);
    let removed = record(door(11, &[(B, HERE)]));

    assert_eq!(
        bucket_changes(HERE, &from, std::slice::from_ref(&removed)).unwrap(),
        vec![BucketChange::Removed {
            seq: 11,
            buckets: vec![A.into(), C.into()],
        }]
    );

    from.restoring = vec![Restoring {
        unit: HERE,
        since_seq: 9,
    }];
    assert_eq!(
        bucket_changes(HERE, &from, &[removed]).unwrap(),
        vec![BucketChange::Unplaced {
            seq: 11,
            buckets: vec![A.into(), C.into()],
        }]
    );
}

/// A gap rejects the entire batch, even after a contiguous record produced a change.
#[test]
fn a_gap_in_the_record_sequence_rejects_the_batch() {
    let from = door(10, &[(A, HERE)]);
    let records = [record(door(11, &[])), record(door(13, &[]))];

    let err = bucket_changes(HERE, &from, &records).unwrap_err();
    assert_invalid_error(err, ERR_RECORD_ORDER);
}

/// The head's local list omits remote placements and returns distinct ids in sorted order.
#[test]
fn the_placement_list_contains_sorted_distinct_ids_for_this_unit() {
    let head = door(10, &[(C, HERE), (B, REMOTE), (A, HERE), (C, HERE)]);

    assert_eq!(placed(&head, HERE), vec![String::from(A), String::from(C)]);
}
