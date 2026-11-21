//! Whether tenant 0 may be served from the D1 catalogue: the fence of
//! the move of tenant 0's data into a tenant of its own.
//!
//! Tenant 0's catalogue selector is a field of its tenant record in R2
//! (`d1`, or `moved` once the data belongs to another tenant). The
//! request path reads it from the record, never from the directory, so a
//! restored directory cannot bring `d1` back. The database itself is
//! checked too: the move writes a **cutover marker** row into the frozen
//! D1 before its flip, and a database that carries the marker while the
//! record carries the flip's stamp was left behind.
//!
//! | Record | Marker in the bound D1 | Answer |
//! |---|---|---|
//! | `moved` | any | `503`: the data is another tenant's now |
//! | `d1`, no cutover stamp | none | serve |
//! | `d1`, no cutover stamp | present | serve: the move's window, in which nothing can change |
//! | `d1`, cutover stamp, no undo | any | `503` and page: a database left behind |
//! | `d1`, undo stamp above the cutover stamp | none or present | serve only if the bound D1 carries the catalogue id the record names |
//!
//! **`moved` is sticky.** An isolate that has seen `moved` goes back to
//! `d1` only on a head that carries an undo stamp higher than the cutover
//! stamp it saw, and names a catalogue id that its bound database
//! carries. A head that says `d1` without both is a rolled-back or forged
//! view: `503`, and page.
//!
//! The head is read when the isolate first serves tenant 0 and then
//! checked every [`RECHECK_MS`] by one listing after its seq; a head that
//! moved is read again before the answer. A record that cannot be read
//! answers `503`: that is a failure of R2, where the data is too.
//!
//! # A failed directory read
//!
//! When the directory cannot be read, a request is not refused as an
//! unknown key and no tenant is guessed ([`route_without_directory`]).
//! While tenant 0 is served from D1, its catalogue is asked for the key:
//! a key it holds goes on as a request of tenant 0. Any other key answers
//! `503`, unless the route record of the key (written when the key was
//! made) names its tenant. An answer of "no such key" from a directory
//! that was read is never taken for a failure.

use super::chain::{ChainError, ControlSeal, RecordStore, TenantChain};
use super::record::{Selector, TenantDoor, TenantId};
use crate::ports::{Sql, SqlValue};
use crate::types::{Result, UnixMs};

/// How often an isolate checks that tenant 0's head has not moved.
pub const RECHECK_MS: i64 = 60_000;

/// The `meta` key of the cutover marker in the D1 catalogue. Its value is
/// the time it was written.
pub const CUTOVER_MARKER_KEY: &str = "cutover_marker";

/// What the bound D1 says about itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DatabaseFacts {
    /// The cutover marker is there.
    pub marker: bool,
    /// The catalogue id of the database's rollback stamp row, `None` when
    /// it has none.
    pub catalogue_id: Option<String>,
}

/// Reads [`DatabaseFacts`] from the D1 catalogue: two read-only queries.
pub async fn database_facts<S: Sql>(catalog: &S) -> Result<DatabaseFacts> {
    let marker = catalog
        .query(
            "SELECT 1 FROM meta WHERE k = ?1",
            &[SqlValue::Text(CUTOVER_MARKER_KEY.to_string())],
        )
        .await?;
    let id = catalog
        .query("SELECT catalogue_id FROM rollback_stamp WHERE id = 1", &[])
        .await?;
    let catalogue_id = match id.first().and_then(|r| r.first()) {
        Some(SqlValue::Text(s)) => Some(s.clone()),
        _ => None,
    };
    Ok(DatabaseFacts {
        marker: !marker.is_empty(),
        catalogue_id,
    })
}

/// The answer for tenant 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZeroServe {
    /// Serve tenant 0 from the bound D1.
    Serve,
    /// `503` for tenant 0. With `page` set, this is damage or a database
    /// left behind, and an operator is paged.
    Unavailable { code: &'static str, page: bool },
}

const fn unavailable(code: &'static str, page: bool) -> ZeroServe {
    ZeroServe::Unavailable { code, page }
}

/// What an isolate has seen of tenant 0's selector: the cutover stamp of
/// the newest `moved` head it served on. Kept for the isolate's life.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    pub moved_at_stamp: Option<u64>,
}

/// Decides for one head and one database. See the [module](self). It
/// updates `seen` when the head is `moved`.
pub fn decide(head: &TenantDoor, db: &DatabaseFacts, seen: &mut Seen) -> ZeroServe {
    if !head.tenant.is_zero() {
        return unavailable("not_tenant_zero", true);
    }
    let Some(zero) = &head.tenant_zero else {
        return unavailable("selector_missing", true);
    };
    let cutover = zero.cutover_stamp;
    match &zero.selector {
        Selector::Moved { .. } => {
            let stamp = cutover.unwrap_or(0);
            seen.moved_at_stamp = Some(seen.moved_at_stamp.map_or(stamp, |s| s.max(stamp)));
            unavailable("tenant_zero_moved", false)
        }
        Selector::D1 => {
            let undone = match (zero.undo_stamp, cutover) {
                (Some(undo), Some(cut)) => undo > cut,
                _ => false,
            };
            if let Some(moved) = seen.moved_at_stamp {
                // Back to d1 only by a stamped undo past what this
                // isolate saw.
                if !zero.undo_stamp.is_some_and(|undo| undo > moved) || !undone {
                    return unavailable("selector_went_back", true);
                }
            }
            if undone {
                return match (&zero.catalogue_id, &db.catalogue_id) {
                    (Some(named), Some(bound)) if named == bound => {
                        seen.moved_at_stamp = None;
                        ZeroServe::Serve
                    }
                    _ => unavailable("database_is_not_the_named_one", true),
                };
            }
            match (cutover, db.marker) {
                (None, _) => ZeroServe::Serve,
                (Some(_), _) => unavailable("database_left_behind", true),
            }
        }
    }
}

/// An isolate's view of tenant 0's head, checked every [`RECHECK_MS`].
#[derive(Clone, Debug, Default)]
pub struct ZeroWatch {
    head: Option<TenantDoor>,
    checked_at: Option<UnixMs>,
    pub seen: Seen,
}

impl ZeroWatch {
    /// The head to decide on: the cached one while it is younger than
    /// [`RECHECK_MS`] and not `moved`; else checked by one listing after
    /// its seq and read again if it moved. `Err` = tenant 0 answers 503.
    pub async fn head<S: RecordStore, C: ControlSeal>(
        &mut self,
        chain: &TenantChain<'_, S, C>,
        now: UnixMs,
    ) -> std::result::Result<&TenantDoor, ChainError> {
        let zero = TenantId::zero();
        let fresh = self
            .checked_at
            .is_some_and(|at| now.0 >= at.0 && now.0 - at.0 < RECHECK_MS);
        if !(fresh && self.head.is_some()) {
            let known = self.head.as_ref().map_or(0, |h| h.seq);
            let seq = chain
                .head_seq(&zero, known)
                .await?
                .ok_or(ChainError::Damaged("tenant_zero_has_no_record"))?;
            if Some(seq) != self.head.as_ref().map(|h| h.seq) {
                let read = chain
                    .read(&zero, seq)
                    .await?
                    .ok_or(ChainError::Damaged("head_missing"))?;
                self.head = Some(read.door);
            }
            self.checked_at = Some(now);
        }
        self.head
            .as_ref()
            .ok_or(ChainError::Damaged("tenant_zero_has_no_record"))
    }

    /// The answer for a tenant-0 request now.
    pub async fn serve<S: RecordStore, C: ControlSeal>(
        &mut self,
        chain: &TenantChain<'_, S, C>,
        db: &DatabaseFacts,
        now: UnixMs,
    ) -> ZeroServe {
        let head = match self.head(chain, now).await {
            Ok(head) => head.clone(),
            Err(ChainError::Store(_)) => return unavailable("record_unreadable", false),
            Err(_) => return unavailable("record_damaged", true),
        };
        decide(&head, db, &mut self.seen)
    }
}

/// What the directory answered for an access key id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryAnswer {
    /// The directory was read: the key's tenant, or `None` for no such key.
    Read(Option<TenantId>),
    /// The directory could not be read.
    Failed,
}

/// Where a request goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    Tenant(TenantId),
    /// No tenant has the key: the request is refused as an unknown key.
    UnknownKey,
    /// `503`: the tenant cannot be known now.
    Unavailable,
}

/// The route of a request after the directory answered. `zero_holds_key`
/// is asked only on a failed read, and only while tenant 0 is served from
/// D1 (`zero` is [`ZeroServe::Serve`]); `route_record` is the tenant named
/// by the key's route record, read only on a failed read, `None` when it
/// has none or it could not be read.
pub fn route_without_directory(
    answer: DirectoryAnswer,
    zero: ZeroServe,
    zero_holds_key: impl FnOnce() -> bool,
    route_record: impl FnOnce() -> Option<TenantId>,
) -> Route {
    match answer {
        DirectoryAnswer::Read(Some(tenant)) => Route::Tenant(tenant),
        DirectoryAnswer::Read(None) => Route::UnknownKey,
        DirectoryAnswer::Failed => {
            if zero == ZeroServe::Serve && zero_holds_key() {
                return Route::Tenant(TenantId::zero());
            }
            match route_record() {
                // Tenant 0 is reached through its catalogue, never by a
                // route record.
                Some(tenant) if !tenant.is_zero() => Route::Tenant(tenant),
                _ => Route::Unavailable,
            }
        }
    }
}
