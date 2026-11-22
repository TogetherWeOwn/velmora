//! The key chain as a unit takes it: the unit client's [`KeyFeed`] over
//! L4's reader (lane L6, package L6-5b; AM-71, AM-62).
//!
//! [`RootKeyFeed::after`] answers the records of `m/k/<t>/` after the
//! unit's `keys_seq`, up to the chain's head, one item per record:
//!
//! - a subject's entry **in head state**, stamped at the record's seq
//!   (AM-62), with the `m/rk/` revocations in force
//!   (`keys::apply::Feed::entries`);
//! - a marker record (`KeysFrozen`, `KeysThawed`) as the unit's marker
//!   item, in its place, so the run has no gap;
//! - an opening that the directory may not have yet, **held** with its
//!   `owner_ref` (`ApplyEntry::Held`, AM-72), through L4's
//!   `Feed::entries_for` in the closing step's mode, as L4's writer sends
//!   it to a unit before the directory acknowledged. The client supplies
//!   the unit's actual closed subjects so a subject held below `keys_seq`
//!   stays held until acknowledged without re-closing an already open one.
//!   With no directory bound there is no store to wait for (AM-75), so
//!   every entry is sent as the chain has it.
//!
//! The tenant's key ring comes from [`Root::tenant_keys`], so the feed
//! fails closed when the key locations or a live key version are missing
//! (AM-71). A chain with no record after `after` reads no key at all: a
//! tenant before its first key record (key version 0) syncs.
//!
//! [`unit_item`] is the one mapping of a key-chain item onto the unit's
//! wire; the management adapters can use it too.

use crate::crypto::scheme2::TenantId as KeyTenant;
use crate::directory::record::Tenant;
use std::collections::BTreeSet;

use crate::keys::apply::{Feed, Mode};
use crate::keys::checkpoint::read_key_chain;
use crate::keys::ports::{ApplyEntry as ChainItem, MAX_APPLY};
use crate::keys::record::{
    key_chain, Access as ChainAccess, Marker, SubjectKind, SubjectStatus as ChainStatus,
};
use crate::types::{BridgeError, Result};
use crate::unit::keys::{
    Access as UnitAccess, ApplyEntry as UnitItem, KeyEntry, KeyGrant, KeyKind, KeyMarker,
    MarkerKind, SubjectStatus as UnitStatus,
};
use crate::unit::reserve::Rid as UnitRid;
use crate::unit::TenantId;
use crate::unit_lease::client::{KeyBatch, KeyFeed};
use velmora::rng::FillRandom;

use super::{Root, RootPorts};

/// The door part and the private part of an entry name different
/// buckets: damage.
pub const ERR_GRANTS_DIFFER: BridgeError = BridgeError::Crypto("key entry: grants do not match");
/// A tenant id that names no key chain (tenant 0 has none here).
const ERR_FEED_TENANT: BridgeError = BridgeError::Invalid("key feed: not a managed tenant");
/// The reader stopped short of the head it listed.
const ERR_FEED_SHORT: BridgeError = BridgeError::Invalid("key feed: the chain read stopped short");

/// The unit client's [`KeyFeed`] through the composition root.
pub struct RootKeyFeed<'r, 'a, P: RootPorts, R> {
    pub(super) root: &'r Root<'a, P, R>,
}

impl<P: RootPorts, R: FillRandom> KeyFeed for RootKeyFeed<'_, '_, P, R> {
    async fn acked(&self, tenant: &TenantId) -> u64 {
        let Ok(tenant) = KeyTenant::parse(tenant.as_str()) else {
            return 0;
        };
        let Some(dir) = self.root.directory() else {
            return u64::MAX;
        };
        dir.tenant(&Tenant::Managed(tenant))
            .await
            .ok()
            .flatten()
            .map_or(0, |row| row.keys_seq)
    }

    async fn after(
        &self,
        tenant: &TenantId,
        after: u64,
        acked: u64,
        closed: &[String],
    ) -> Result<KeyBatch> {
        if tenant.is_zero() {
            return Err(ERR_FEED_TENANT);
        }
        let t = KeyTenant::parse(tenant.as_str()).map_err(|_| ERR_FEED_TENANT)?;
        let records = self.root.records();
        // The chain's head, listed from the unit's own seq (a chain behind
        // it is refused there). Nothing after it: no key is loaded.
        let head = key_chain(&t).head(records, after).await?;
        if head <= after {
            return Ok(KeyBatch {
                head,
                entries: Vec::new(),
                answers: Vec::new(),
            });
        }
        let ring = self.root.tenant_keys(&t).await?;
        let read = read_key_chain(records, self.root.kek(), &ring, &t).await?;
        let top = read.table.seq();
        if top < head {
            return Err(ERR_FEED_SHORT);
        }
        let mode = Mode::Closing { acked };
        let closed: BTreeSet<String> = closed.iter().cloned().collect();
        let feed = Feed::new(records, self.root.kek(), &ring, &read.table, &read.revoked);
        let mut entries = Vec::new();
        let mut from = after;
        while from < top {
            let page = feed.entries_for(from, MAX_APPLY, mode, &closed).await?;
            let Some(last) = page.last().map(ChainItem::seq) else {
                return Err(ERR_FEED_SHORT);
            };
            for item in &page {
                entries.push(unit_item(item)?);
            }
            from = last;
        }
        Ok(KeyBatch {
            head: top,
            entries,
            // The kept answers of reservations are sent by the writer that
            // recorded them (L4-W's last root-unit apply), not by a renewal.
            answers: Vec::new(),
        })
    }
}

/// One key-chain item in the unit's wire form (`ApplyKeys`), as L4's
/// `ApplyEntry` states it:
/// - a subject's entry: `held` when its private part did not open, and
///   then with no secret, no `secret_kek_version`, no `owner_ref` and no
///   grant limit;
/// - a held entry (`Held`, the closing step's hold): `held`, with its
///   `owner_ref` (AM-72) and nothing else of its private part;
/// - a marker: the unit's marker item of its kind (a thaw's `ends` is not
///   on the wire).
pub fn unit_item(item: &ChainItem) -> Result<UnitItem> {
    let (e, kept_owner) = match item {
        ChainItem::Marker { seq, marker } => {
            let marker = match marker {
                Marker::KeysFrozen => MarkerKind::KeysFrozen,
                Marker::KeysThawed { .. } => MarkerKind::KeysThawed,
            };
            return Ok(UnitItem::Marker(KeyMarker { marker, seq: *seq }));
        }
        ChainItem::Subject(e) => (e, None),
        ChainItem::Held { entry, owner_ref } => (entry, Some(owner_ref)),
    };
    // A held entry never carries its private part (L4's form); one that
    // did would be sent held with no part of it.
    let held = e.private.is_none() || kept_owner.is_some();
    let private = e.private.as_ref().filter(|_| !held);
    if let Some(p) = private {
        // The door and the private part name the same buckets in the same
        // order (the record's own rule); anything else is damage.
        let same = p.grants.len() == e.door.grants.len()
            && p.grants
                .iter()
                .zip(&e.door.grants)
                .all(|(p, d)| p.bucket_id == d.bucket_id);
        if !same {
            return Err(ERR_GRANTS_DIFFER);
        }
    }
    let grants = e
        .door
        .grants
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let p = private.and_then(|p| p.grants.get(i));
            KeyGrant {
                bucket_id: d.bucket_id.clone(),
                access: match d.access {
                    ChainAccess::Ro => UnitAccess::Ro,
                    ChainAccess::Rw => UnitAccess::Rw,
                },
                expires_at: d.expires_at,
                prefix: p.and_then(|p| p.prefix.clone()),
                ip_list: p.map(|p| p.ip_list.clone()).unwrap_or_default(),
            }
        })
        .collect();
    Ok(UnitItem::Key(KeyEntry {
        id: e.door.id.clone(),
        kind: match e.door.kind {
            SubjectKind::S3 => KeyKind::S3,
            SubjectKind::AppPassword => KeyKind::AppPassword,
            SubjectKind::Principal => KeyKind::Principal,
            SubjectKind::Internal => KeyKind::Internal,
        },
        status: match e.door.status {
            ChainStatus::Active => UnitStatus::Active,
            ChainStatus::Disabled => UnitStatus::Disabled,
            ChainStatus::Revoked => UnitStatus::Revoked,
        },
        held,
        made_by: e.door.made_by.clone(),
        grants,
        created_at: e.door.created_at,
        secret_wrapped: private.and_then(|p| p.secret_wrapped.clone()),
        secret_kek_version: match held {
            true => None,
            false => e.door.secret_kek_version,
        },
        owner_ref: match kept_owner {
            Some(owner_ref) => owner_ref.clone(),
            None => private.and_then(|p| p.owner_ref.clone()),
        },
        last_seq: e.last_seq,
        rid: e.rid.map(|r| UnitRid(r.0)),
    }))
}
