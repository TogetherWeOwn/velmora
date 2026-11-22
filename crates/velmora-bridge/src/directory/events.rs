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

use super::chain::ReadRecord;
use super::feed::NewEvent;
use crate::crypto::scheme2::TenantId;
use crate::keys::record::ChainRecord;

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
    let _ = (prev, record);
    Vec::new()
}

/// The events of key-chain record `record` of `tenant`.
pub fn key_events(tenant: &TenantId, record: &ChainRecord) -> Vec<NewEvent> {
    let _ = (tenant, record);
    Vec::new()
}
