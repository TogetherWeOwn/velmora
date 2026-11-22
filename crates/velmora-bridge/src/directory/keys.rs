//! The directory as a store of the key chain (ADR §2.5, AM-75).
//!
//! The directory is [`crate::keys::writer::KeyEnv`]'s `directory` target,
//! never an entry of its `units`: the writer's bring-up runs the units
//! with what closes, then the directory, then the units in full once the
//! directory has acknowledged (AM-9). An opening key change answers `200`
//! only after the directory has acknowledged it.
//!
//! [`DirectoryKeys`] is that target for one managed tenant, over the
//! directory database. It follows a unit's base, `Behind` and marker rules
//! ([`KeyTarget::apply`]):
//!
//! - its `keys_seq` is the tenant row's `keys_seq` (no row: an error);
//! - it puts a `key_routes` row for every access key, app password and
//!   internal key the first time a record names it, and only for an entry
//!   above its `keys_seq` (a move's key records are at or below it: DS1
//!   §3.4 step 8(c) raises it past them, and moved keys' routes change
//!   only through [`SqlDirectory::move_route`]). A principal has no
//!   secret and is never presented on the S3 path: it gets no route;
//! - [`RoutePut::Inserted`] and [`RoutePut::Same`] are success;
//!   [`RoutePut::NoTenant`], [`RoutePut::Conflict`] and
//!   [`RoutePut::WrongKind`] make the apply an `Err`, so `keys_seq` is not
//!   raised and the `pending_ops` rows stay. The last two page
//!   ([`pages`]);
//! - before it raises `keys_seq` from `s` to `h`, it reads the verified
//!   key-chain records `s + 1` to `h` from the record store (never from
//!   the entries, which are in head state) and appends their events
//!   ([`super::events::key_events`]): events first, so after a crash the
//!   next run repeats the appends and `UNIQUE (tenant, source)` keeps one
//!   row each;
//! - a `raise_keys_seq` that answers `false` is success only when a
//!   re-read finds the row at or above the seq;
//! - `closed` answers no subject. It is brought up only in `Mode::Full`,
//!   so it never receives a held entry; a marker writes no route.
//!
//! [`UnboundDirectory`] is the target of an environment with no
//! `DIRECTORY` binding: `keys_seq` answers `u64::MAX`, `closed` no
//! subject, and `apply` answers `Done` and writes nothing, so AM-9 holds
//! nothing back.

use super::store::{RoutePut, SqlDirectory};
use crate::crypto::scheme2::TenantId;
use crate::keys::ports::{Applied, ApplyEntry, KeyTarget};
use crate::keys::record::TkRing;
use crate::ports::{Kek, Sql};
use crate::records::RecordStore;
use crate::types::{BridgeError, Result};

/// The label of the directory target in logs and reports.
pub const DIRECTORY_LABEL: &str = "directory";

/// The label of the target of an environment with no directory.
pub const UNBOUND_LABEL: &str = "directory (unbound)";

/// The tenant has no directory row, or it is shredded: no route can be
/// stored. The apply is an `Err`; it does not page.
pub const ERR_NO_TENANT_ROW: BridgeError =
    BridgeError::Invalid("directory: the tenant has no live row");

/// A route to another tenant, or of another kind, is stored for a key of
/// this tenant: damage or a forged call. It pages.
pub const ERR_ROUTE_CONFLICT: BridgeError =
    BridgeError::Invalid("directory: a key route names another tenant or kind");

/// A key id that does not fit its kind (an app password without its
/// prefix, or another kind with it). It pages.
pub const ERR_ROUTE_WRONG_KIND: BridgeError =
    BridgeError::Invalid("directory: a key id does not fit its kind");

/// The row's `keys_seq` was not raised and a re-read finds it below the
/// apply's seq.
pub const ERR_KEYS_SEQ_NOT_RAISED: BridgeError =
    BridgeError::Invalid("directory: keys_seq was not raised");

/// The entries are not the records after `from_seq` without a gap, or
/// more than one apply carries.
pub const ERR_APPLY_SHAPE: BridgeError =
    BridgeError::Invalid("directory: apply entries do not follow their base");

/// Whether an error of a directory apply pages (a route conflict or a key
/// id that does not fit its kind): damage, not an outage.
pub fn pages(e: &BridgeError) -> bool {
    is(e, &ERR_ROUTE_CONFLICT) || is(e, &ERR_ROUTE_WRONG_KIND)
}

/// Whether `e` is the fixed error `of`.
pub fn is(e: &BridgeError, of: &BridgeError) -> bool {
    matches!((e, of), (BridgeError::Invalid(a), BridgeError::Invalid(b)) if a == b)
}

/// The directory as one managed tenant's key-chain target. See the
/// [module](self).
pub struct DirectoryKeys<'a, Q, S, K, T> {
    pub dir: SqlDirectory<'a, Q>,
    pub tenant: &'a TenantId,
    /// The record store the key chain is read from, for the events.
    pub store: &'a S,
    pub kek: &'a K,
    pub ring: &'a T,
}

impl<Q: Sql, S: RecordStore, K: Kek, T: TkRing> KeyTarget for DirectoryKeys<'_, Q, S, K, T> {
    fn label(&self) -> &str {
        DIRECTORY_LABEL
    }

    async fn keys_seq(&self) -> Result<u64> {
        Err(BridgeError::NotImplemented("DirectoryKeys::keys_seq"))
    }

    async fn closed(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    async fn apply(&self, _from_seq: u64, _entries: &[ApplyEntry]) -> Result<Applied> {
        let _ = RoutePut::Same;
        Err(BridgeError::NotImplemented("DirectoryKeys::apply"))
    }
}

/// The directory target where `DIRECTORY` is not bound (AM-75). See the
/// [module](self).
#[derive(Clone, Copy, Debug, Default)]
pub struct UnboundDirectory;

impl KeyTarget for UnboundDirectory {
    fn label(&self) -> &str {
        UNBOUND_LABEL
    }

    async fn keys_seq(&self) -> Result<u64> {
        Ok(u64::MAX)
    }

    async fn closed(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    async fn apply(&self, _from_seq: u64, _entries: &[ApplyEntry]) -> Result<Applied> {
        Ok(Applied::Done { keys_seq: u64::MAX })
    }
}
