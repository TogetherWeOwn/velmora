//! The events of the management plane's feed, built from chain records
//! (AM-37, AM-74, AM-75, AM-79). The directory step of each chain's
//! finisher appends them ([`super::finish`], [`super::keys`]); no handler
//! writes a chain event itself.
//!
//! **Sources.** An event's `source` is unique per tenant, so a finisher
//! that repeats itself after a crash or a lost answer writes one row
//! (AM-74): `t/<seq>` or `k/<seq>` for the one event of a chain record,
//! and `t/<seq>.<n>` (`n` from 1, in a fixed order) when a record makes
//! more than one.
//!
//! **Data.** Ids and names only, never a secret or a URL: `bucket_id` and
//! `bucket` (the name, from the record's private part, when it opened),
//! `key_id` and `kind` for a key, `principal_id` for a principal, and
//! `key_hash` when the record names the call that wrote it (AM-79).
//!
//! | Record | Event |
//! |---|---|
//! | tenant: a hold placed or made stricter, so the state is `suspended` | `tenant.suspended` (`mode`) |
//! | tenant: the last hold lifted | `tenant.resumed` |
//! | tenant: a deletion set | `tenant.deletion_scheduled` (`shred_due_at_ms`) |
//! | tenant: a deletion undone | `tenant.deletion_cancelled` |
//! | tenant: `bucket_created`; each moved-in bucket | `bucket.created` |
//! | tenant: a placement that is gone | `bucket.deleted` |
//! | key: create | `key.created` / `principal.created` |
//! | key: revoke | `key.revoked` / `principal.revoked` |
//! | key: disable | `key.disabled` (`principal.updated` for a principal) |
//! | key: re-enable, grant change | `key.updated` / `principal.updated` |
//!
//! A restatement under a new key version, a marker, an internal key's
//! record and every other tenant record make no event.

use serde_json::{Map, Value};

use super::chain::ReadRecord;
use super::feed::NewEvent;
use super::record::{HoldMode, Lifecycle, Tenant};
use crate::crypto::scheme2::TenantId;
use crate::keys::record::{ChainRecord, KeyOp, SubjectKind, SubjectStatus};
use crate::types::UnixMs;

/// Every event type of milestone 1, as `velmora_mgmt_types::wire::
/// EVENT_TYPES` lists them (a test holds every type made here to it).
pub const EVENT_TYPES: [&str; 16] = [
    "bucket.created",
    "bucket.deleted",
    "key.created",
    "key.updated",
    "key.disabled",
    "key.revoked",
    "principal.created",
    "principal.updated",
    "principal.revoked",
    "tenant.suspended",
    "tenant.resumed",
    "tenant.deletion_scheduled",
    "tenant.deletion_cancelled",
    "presign.write",
    "presign.read_hour",
    "presign.refused",
];

/// The events of tenant record `record`, whose predecessor is `prev`
/// (`None` for seq 1), in their fixed order with their sources.
pub fn tenant_events(prev: Option<&ReadRecord>, record: &ReadRecord) -> Vec<NewEvent> {
    let door = &record.door;
    let Some(prev) = prev else {
        // The first record creates the tenant: no event names it.
        return Vec::new();
    };
    let before = &prev.door;
    // A shred ends every door; it makes no event, and its stub drops the
    // holds and the deletion without lifting or undoing them.
    if matches!(door.lifecycle, Lifecycle::Shredding | Lifecycle::Shredded) {
        return Vec::new();
    }
    let mut out: Vec<(&'static str, Map<String, Value>)> = Vec::new();
    match (before.holds.mode(), door.holds.mode()) {
        // Placed, or made stricter; a hold made less strict while one
        // stands says nothing.
        (old, Some(mode)) if old.is_none_or(|o| mode > o) => {
            let mut data = Map::new();
            data.insert("mode".into(), Value::from(hold_mode(mode)));
            out.push(("tenant.suspended", data));
        }
        (Some(_), None) => out.push(("tenant.resumed", Map::new())),
        _ => {}
    }
    match (&before.deletion, &door.deletion) {
        (None, Some(d)) => {
            let mut data = Map::new();
            data.insert("shred_due_at_ms".into(), Value::from(d.shred_due_at.0));
            out.push(("tenant.deletion_scheduled", data));
        }
        (Some(_), None) => out.push(("tenant.deletion_cancelled", Map::new())),
        _ => {}
    }
    if let Some(created) = &door.bucket_created {
        let mut data = Map::new();
        data.insert("bucket_id".into(), Value::from(created.bucket.clone()));
        let name = record
            .private
            .as_ref()
            .and_then(|p| p.bucket_created.as_ref())
            .map(|b| b.name.clone());
        if let Some(name) = name {
            data.insert("bucket".into(), Value::from(name));
        }
        out.push(("bucket.created", data));
    }
    if let Some(moved) = &door.buckets_moved_in {
        for bucket in &moved.buckets {
            let mut data = Map::new();
            data.insert("bucket_id".into(), Value::from(bucket.clone()));
            out.push(("bucket.created", data));
        }
    }
    for gone in before
        .placements
        .iter()
        .filter(|old| !door.placements.iter().any(|p| p.bucket == old.bucket))
    {
        let mut data = Map::new();
        data.insert("bucket_id".into(), Value::from(gone.bucket.clone()));
        out.push(("bucket.deleted", data));
    }
    sourced(
        &door.tenant,
        't',
        door.seq,
        door.written_at,
        door.call_key_hash.as_deref(),
        out,
    )
}

/// The events of key-chain record `record` of `tenant`.
pub fn key_events(tenant: &TenantId, record: &ChainRecord) -> Vec<NewEvent> {
    let ChainRecord::Key(r) = record else {
        return Vec::new();
    };
    let principal = match r.door.kind {
        SubjectKind::Principal => true,
        SubjectKind::S3 | SubjectKind::AppPassword => false,
        // The tenant's own key for presigned URLs: not a customer's.
        SubjectKind::Internal => return Vec::new(),
    };
    let kind = match (r.op, r.door.status, principal) {
        (KeyOp::Create, _, false) => "key.created",
        (KeyOp::Create, _, true) => "principal.created",
        (KeyOp::Status, SubjectStatus::Revoked, false) => "key.revoked",
        (KeyOp::Status, SubjectStatus::Revoked, true) => "principal.revoked",
        (KeyOp::Status, SubjectStatus::Disabled, false) => "key.disabled",
        (KeyOp::Status | KeyOp::Grants, _, false) => "key.updated",
        (KeyOp::Status | KeyOp::Grants, _, true) => "principal.updated",
        (KeyOp::Restate, _, _) => return Vec::new(),
    };
    let mut data = Map::new();
    if principal {
        data.insert("principal_id".into(), Value::from(r.door.id.clone()));
    } else {
        data.insert("key_id".into(), Value::from(r.door.id.clone()));
        let k = match r.door.kind {
            SubjectKind::AppPassword => "app_password",
            _ => "s3",
        };
        data.insert("kind".into(), Value::from(k));
    }
    let at = UnixMs(i64::try_from(r.at).unwrap_or(i64::MAX));
    sourced(
        &Tenant::Managed(tenant.clone()),
        'k',
        r.seq,
        at,
        None,
        vec![(kind, data)],
    )
}

/// The events of one record with their sources: `<c>/<seq>` for one,
/// `<c>/<seq>.<n>` (from 1) for more.
fn sourced(
    tenant: &Tenant,
    chain: char,
    seq: u64,
    at: UnixMs,
    key_hash: Option<&str>,
    events: Vec<(&'static str, Map<String, Value>)>,
) -> Vec<NewEvent> {
    let many = events.len() > 1;
    events
        .into_iter()
        .enumerate()
        .map(|(i, (kind, mut data))| {
            if let Some(hash) = key_hash {
                data.insert("key_hash".into(), Value::from(hash));
            }
            NewEvent {
                tenant: tenant.clone(),
                kind: kind.to_string(),
                source: match many {
                    true => format!("{chain}/{seq}.{}", i + 1),
                    false => format!("{chain}/{seq}"),
                },
                at,
                data,
            }
        })
        .collect()
}

fn hold_mode(mode: HoldMode) -> &'static str {
    match mode {
        HoldMode::ReadOnly => "read_only",
        HoldMode::Locked => "locked",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::record::{KeyRecord, Marker, MarkerRecord, SubjectDoor};

    fn tenant() -> TenantId {
        TenantId::parse("t_00000000000000a1").unwrap()
    }

    fn record(op: KeyOp, kind: SubjectKind, status: SubjectStatus) -> ChainRecord {
        ChainRecord::Key(KeyRecord {
            seq: 7,
            op,
            at: 99,
            door: SubjectDoor {
                id: "AKVL0001".into(),
                kind,
                status,
                made_by: None,
                grants: vec![],
                created_at: 1,
                secret_kek_version: None,
            },
            private: None,
            tk_version: 1,
            closes: false,
            private_unchanged: false,
            frozen_at: None,
            rid: None,
        })
    }

    #[test]
    fn every_key_record_maps_to_a_listed_type_or_none() {
        use KeyOp::*;
        use SubjectKind::*;
        use SubjectStatus::*;
        let cases = [
            (Create, S3, Active, Some("key.created")),
            (Create, AppPassword, Active, Some("key.created")),
            (Create, Principal, Active, Some("principal.created")),
            (Status, S3, Revoked, Some("key.revoked")),
            (Status, Principal, Revoked, Some("principal.revoked")),
            (Status, S3, Disabled, Some("key.disabled")),
            (Status, Principal, Disabled, Some("principal.updated")),
            (Status, S3, Active, Some("key.updated")),
            (Grants, AppPassword, Active, Some("key.updated")),
            (Grants, Principal, Active, Some("principal.updated")),
            (Restate, S3, Active, None),
            (Restate, Principal, Active, None),
            (Create, Internal, Active, None),
            (Status, Internal, Revoked, None),
        ];
        for (op, kind, status, want) in cases {
            let got = key_events(&tenant(), &record(op, kind, status));
            match want {
                None => assert!(got.is_empty(), "{op:?} {kind:?}"),
                Some(t) => {
                    assert_eq!(got.len(), 1);
                    assert_eq!(got[0].kind, t);
                    assert!(EVENT_TYPES.contains(&got[0].kind.as_str()));
                    assert_eq!(got[0].source, "k/7");
                    assert_eq!(got[0].at, UnixMs(99));
                    // Ids only.
                    let keys: Vec<&String> = got[0].data.keys().collect();
                    assert!(
                        keys.iter()
                            .all(|k| ["key_id", "kind", "principal_id"].contains(&k.as_str())),
                        "{keys:?}"
                    );
                }
            }
        }
        let marker = ChainRecord::Marker(MarkerRecord {
            seq: 8,
            at: 1,
            marker: Marker::KeysFrozen,
            frozen_at: Some(7),
        });
        assert!(key_events(&tenant(), &marker).is_empty());
    }
}
