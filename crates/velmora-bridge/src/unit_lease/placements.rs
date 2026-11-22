//! The bucket part of a `sync` (AM-57), built by the Worker from the
//! tenant records it reads and verifies anyway.
//!
//! [`bucket_changes`] walks the records after the unit's `state_seq`, in
//! seq order, each against the one before it, and keeps what concerns
//! the buckets placed on this unit:
//!
//! - **`created`**: a record whose door names the bucket it creates
//!   (`bucket_created`) and places it on this unit. Its name and wrapped
//!   BDK come from the record's private part; a record that should carry
//!   them and does not is damage, and nothing is sent.
//! - **a placement on this unit that a record removes**: `unplaced` when
//!   the record before it held this unit's `restoring` entry (only
//!   `UnplaceMovedBuckets` removes placements then: `DropBucket` and
//!   `SetUnits` are refused while an entry is set), else `dropped` for
//!   one bucket (`DropBucket`), and `removed` for several at once (an
//!   operator's `SetUnits`: the unit drops each as a `dropped`, whatever
//!   entry it holds when it applies them).
//!
//! A placement added without a `bucket_created` (the owner's moved
//! buckets, `PlaceMovedBuckets`) makes no change: their rows come through
//! the import. [`placed`] is the head's list for this unit, which every
//! `sync` carries whole.
//!
//! Pure: no I/O. The caller reads the records.

use std::collections::BTreeSet;

use crate::directory::chain::ReadRecord;
use crate::directory::record::TenantDoor;
use crate::types::{BridgeError, Result};
use crate::unit::buckets::BucketChange;

/// A record that creates a bucket on this unit carries no name or wrap
/// (its private part did not open, or holds none).
pub const ERR_BUCKET_SECRETS: BridgeError =
    BridgeError::Invalid("unit sync: a bucket record carries no name or key");
/// The records do not follow each other from the unit's own seq.
pub const ERR_RECORD_ORDER: BridgeError =
    BridgeError::Invalid("unit sync: the tenant records are not in order");

/// The bucket ids `door` places on `unit`, in id order.
pub fn placed(door: &TenantDoor, unit: u32) -> Vec<String> {
    let set: BTreeSet<&str> = door
        .placements
        .iter()
        .filter(|p| p.unit == unit)
        .map(|p| p.bucket.as_str())
        .collect();
    set.into_iter().map(str::to_string).collect()
}

/// The bucket changes for `unit` of `records` (seqs `from.seq + 1`, `+ 2`,
/// ... with no gap), each against the one before; `from` is the record at
/// the unit's `state_seq`.
pub fn bucket_changes(
    unit: u32,
    from: &TenantDoor,
    records: &[ReadRecord],
) -> Result<Vec<BucketChange>> {
    let mut changes = Vec::new();
    let mut prev = from;
    for r in records {
        let door = &r.door;
        if Some(door.seq) != prev.seq.checked_add(1) {
            return Err(ERR_RECORD_ORDER);
        }
        let before: BTreeSet<String> = placed(prev, unit).into_iter().collect();
        let after: BTreeSet<String> = placed(door, unit).into_iter().collect();
        if let Some(bc) = &door.bucket_created {
            if after.contains(&bc.bucket) && !before.contains(&bc.bucket) {
                let secrets = r
                    .private
                    .as_ref()
                    .and_then(|p| p.bucket_created.as_ref())
                    .ok_or(ERR_BUCKET_SECRETS)?;
                changes.push(BucketChange::Created {
                    seq: door.seq,
                    bucket_id: bc.bucket.clone(),
                    grant_seq: bc.grant_seq,
                    creator: bc.creator.clone(),
                    name: secrets.name.clone(),
                    bdk_wrapped: secrets.bdk_wrapped.clone(),
                    tk_version: secrets.tk_version,
                    written_at: u64::try_from(door.written_at.0).map_err(|_| ERR_RECORD_ORDER)?,
                });
            }
        }
        let removed: Vec<String> = before.difference(&after).cloned().collect();
        let under_entry = prev.restoring_entry(unit).is_some();
        match removed.len() {
            0 => {}
            // Under an entry only `UnplaceMovedBuckets` removes placements.
            _ if under_entry => changes.push(BucketChange::Unplaced {
                seq: door.seq,
                buckets: removed,
            }),
            1 => changes.push(BucketChange::Dropped {
                seq: door.seq,
                bucket_id: removed.into_iter().next().unwrap_or_default(),
            }),
            _ => changes.push(BucketChange::Removed {
                seq: door.seq,
                buckets: removed,
            }),
        }
        prev = door;
    }
    Ok(changes)
}
