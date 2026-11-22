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

use super::events::key_events;
use super::record::Tenant;
use super::store::{KeyRoute, RouteKind, RoutePut, SqlDirectory};
use crate::crypto::scheme2::TenantId;
use crate::keys::ports::{Applied, ApplyEntry, KeyTarget, MAX_APPLY};
use crate::keys::record::{key_chain, open_chain_record, SubjectKind, TkRing};
use crate::ports::{Kek, Sql};
use crate::records::RecordStore;
use crate::types::{BridgeError, Result, UnixMs};

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

impl<Q: Sql, S: RecordStore, K: Kek, T: TkRing> DirectoryKeys<'_, Q, S, K, T> {
    fn row_tenant(&self) -> Tenant {
        Tenant::Managed(self.tenant.clone())
    }

    /// The events of the key-chain records `(from, to]`, read and verified
    /// from the record store, appended in seq order.
    async fn append_events(&self, from: u64, to: u64) -> Result<()> {
        let chain = key_chain(self.tenant);
        for seq in from + 1..=to {
            let bytes = chain.get(self.store, seq).await?;
            let record = open_chain_record(self.kek, self.ring, self.tenant, seq, &bytes)?;
            for event in key_events(self.tenant, &record) {
                self.dir.append_event(&event).await?;
            }
        }
        Ok(())
    }

    /// The route of an entry, if its subject has one.
    fn route_of(&self, entry: &ApplyEntry) -> Result<Option<KeyRoute>> {
        let (e, owner_ref) = match entry {
            ApplyEntry::Subject(e) => (e, e.private.as_ref().and_then(|p| p.owner_ref.clone())),
            ApplyEntry::Held { entry, owner_ref } => (entry, owner_ref.clone()),
            ApplyEntry::Marker { .. } => return Ok(None),
        };
        let kind = match e.door.kind {
            SubjectKind::S3 => RouteKind::S3,
            SubjectKind::AppPassword => RouteKind::AppPassword,
            SubjectKind::Internal => RouteKind::Internal,
            SubjectKind::Principal => return Ok(None),
        };
        Ok(Some(KeyRoute {
            akid: e.door.id.clone(),
            tenant: self.row_tenant(),
            kind,
            owner_ref,
            created_at: UnixMs(i64::try_from(e.door.created_at).map_err(|_| ERR_APPLY_SHAPE)?),
        }))
    }
}

impl<Q: Sql, S: RecordStore, K: Kek, T: TkRing> KeyTarget for DirectoryKeys<'_, Q, S, K, T> {
    fn label(&self) -> &str {
        DIRECTORY_LABEL
    }

    async fn keys_seq(&self) -> Result<u64> {
        self.dir
            .keys_seq_of(&self.row_tenant())
            .await?
            .ok_or(ERR_NO_TENANT_ROW)
    }

    async fn closed(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    async fn apply(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied> {
        let follows = entries
            .iter()
            .enumerate()
            .all(|(i, e)| from_seq.checked_add(i as u64 + 1) == Some(e.seq()));
        if entries.len() > MAX_APPLY || !follows {
            return Err(ERR_APPLY_SHAPE);
        }
        let held = self.keys_seq().await?;
        if from_seq > held {
            return Ok(Applied::Behind { keys_seq: held });
        }
        let Some(last) = entries.last().map(ApplyEntry::seq).filter(|&l| l > held) else {
            return Ok(Applied::Done { keys_seq: held });
        };
        // Events first: a crash after them repeats them, once each.
        self.append_events(held, last).await?;
        for entry in entries.iter().filter(|e| e.seq() > held) {
            let Some(route) = self.route_of(entry)? else {
                continue;
            };
            match self.dir.put_route(&route).await? {
                RoutePut::Inserted | RoutePut::Same => {}
                RoutePut::NoTenant => return Err(ERR_NO_TENANT_ROW),
                RoutePut::Conflict => return Err(ERR_ROUTE_CONFLICT),
                RoutePut::WrongKind => return Err(ERR_ROUTE_WRONG_KIND),
            }
        }
        if !self.dir.raise_keys_seq(&self.row_tenant(), last).await? {
            // Raised by another run meanwhile, or not at all.
            let now = self.keys_seq().await?;
            if now < last {
                return Err(ERR_KEYS_SEQ_NOT_RAISED);
            }
        }
        Ok(Applied::Done { keys_seq: last })
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
