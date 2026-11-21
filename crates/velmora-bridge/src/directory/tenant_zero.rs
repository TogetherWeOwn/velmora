//! Whether tenant 0 may be served from the D1 catalogue: the fence of the
//! move of tenant 0's data into a tenant of its own.
//!
//! Tenant 0's catalogue selector is a field of its tenant record in R2:
//! `d1`, `moving` (the move's window), `moved` (the data is another
//! tenant's) or `retired`. The request path reads it from the record,
//! never from the directory, so a restored directory cannot bring `d1`
//! back. The database itself is checked too: the move writes a **cutover
//! marker** row into D1 before it freezes it, and the frozen catalogue's
//! id is in the move.
//!
//! | Record | Bound D1 | Answer |
//! |---|---|---|
//! | `d1`, no move | no marker | serve |
//! | `d1`, no move | the next move's marker | reads only: the window is opening or was given up, and nothing writes |
//! | `moving` | its id is the frozen one | reads only |
//! | `moving` | another id | `503`, paged |
//! | `moved` | any | [`ZeroServe::Moved`]: drop cached tenant-0 routes and resolve the key again |
//! | `d1`, a move with no undo above its stamp | any | `503`, paged: a database left behind |
//! | `d1` after an undo (it names a catalogue id) | its id is the named one, no marker | serve |
//! | `d1` after an undo | a marker of a move already made | `503`, paged: a database left behind |
//! | `d1` after an undo | the next move's marker | reads only: its window is opening |
//! | `d1` after an undo | another id | `503`, paged |
//! | `retired`, or `d1` with an undo stamp and no move | any | `503`, paged |
//!
//! Only the undo of a flipped move names a catalogue id, and every later
//! record keeps it, so "after a move, only the catalogue the undo named
//! serves" holds for every later `d1` head.
//!
//! **What an isolate has seen stays seen.** An isolate that has met a
//! `moved` head serves `d1` from then on only on a head that names a
//! catalogue id, and only from that catalogue. The chain reader already
//! refuses a head below a seq it knows; this is the second lock.
//!
//! The head is read when the isolate first serves tenant 0 and then
//! checked every [`RECHECK_MS`] by one listing after its seq, whatever the
//! head says; a head that moved is read again before the answer. A record
//! that cannot be read answers `503`: that is a failure of R2, where the
//! data is too.
//!
//! # A failed directory read
//!
//! When the directory cannot be read, a request is not refused as an
//! unknown key and no tenant is guessed ([`route_without_directory`]):
//!
//! 1. the key's route record (written when the key was made) names its
//!    tenant;
//! 2. no route record, and tenant 0 is served from D1 (`d1` or `moving`):
//!    tenant 0's catalogue is asked for the key, and a key it holds goes on
//!    as a request of tenant 0;
//! 3. anything else, a failed lookup among them, answers `503`.
//!
//! An answer of "no such key" from a directory that was read is never
//! taken for a failure, and a failed lookup is never taken for "no such
//! key".

use super::chain::{ChainError, ControlSeal, RecordStore, TenantChain};
use super::record::{Selector, TenantDoor, TenantId, TenantZero};
use crate::ports::{Sql, SqlValue};
use crate::types::{Result, UnixMs};

/// How often an isolate checks that tenant 0's head has not moved.
pub const RECHECK_MS: i64 = 60_000;

/// The `meta` key of the cutover marker in the D1 catalogue. Its value is
/// the ordinal of the move that wrote it.
pub const CUTOVER_MARKER_KEY: &str = "cutover_marker";

/// What the bound D1 says about itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DatabaseFacts {
    /// The cutover marker's value: the ordinal of the move that wrote it
    /// (1 for the first), `None` with no marker.
    pub marker: Option<i64>,
    /// The catalogue id of the database's rollback stamp row, `None` when
    /// it has none.
    pub catalogue_id: Option<String>,
}

/// Reads [`DatabaseFacts`] from the D1 catalogue: two read-only queries.
pub async fn database_facts<S: Sql>(catalog: &S) -> Result<DatabaseFacts> {
    let marker = catalog
        .query(
            "SELECT v FROM meta WHERE k = ?1",
            &[SqlValue::Text(CUTOVER_MARKER_KEY.to_string())],
        )
        .await?;
    let marker = match marker.first().and_then(|r| r.first()) {
        None => None,
        Some(SqlValue::Int(v)) => Some(*v),
        Some(_) => return Err(crate::types::BridgeError::Invalid("cutover marker")),
    };
    let id = catalog
        .query("SELECT catalogue_id FROM rollback_stamp WHERE id = 1", &[])
        .await?;
    let catalogue_id = match id.first().and_then(|r| r.first()) {
        Some(SqlValue::Text(s)) => Some(s.clone()),
        _ => None,
    };
    Ok(DatabaseFacts {
        marker,
        catalogue_id,
    })
}

/// The answer for tenant 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZeroServe {
    /// Serve tenant 0 from the bound D1.
    Serve,
    /// Serve reads from the bound D1; every write answers `503`.
    ServeReadOnly,
    /// The data is another tenant's: drop every cached tenant-0 route and
    /// resolve the key again. A key that still resolves to tenant 0
    /// answers `503` and pages.
    Moved,
    /// `503` for tenant 0. With `page` set, this is damage or a database
    /// left behind, and an operator is paged.
    Unavailable { code: &'static str, page: bool },
}

impl ZeroServe {
    /// Whether tenant 0 is still served from D1 (reads at least).
    pub fn serves_from_d1(self) -> bool {
        matches!(self, ZeroServe::Serve | ZeroServe::ServeReadOnly)
    }
}

const fn unavailable(code: &'static str) -> ZeroServe {
    ZeroServe::Unavailable { code, page: true }
}

/// What an isolate has seen of tenant 0's record. Kept for the isolate's
/// life; never cleared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// It has met a `moved` head.
    pub moved: bool,
}

/// Decides for one head and one database. See the [module](self).
pub fn decide(head: &TenantDoor, db: &DatabaseFacts, seen: &mut Seen) -> ZeroServe {
    if !head.tenant.is_zero() {
        return unavailable("not_tenant_zero");
    }
    let Some(z) = &head.tenant_zero else {
        return unavailable("selector_missing");
    };
    match z.selector {
        Selector::Retired => unavailable("tenant_zero_retired"),
        Selector::Moved => {
            seen.moved = true;
            ZeroServe::Moved
        }
        Selector::Moving => {
            let frozen = z.moved.as_ref().map(|m| m.catalogue_id_frozen.as_str());
            match (frozen, db.catalogue_id.as_deref()) {
                (Some(frozen), Some(bound)) if frozen == bound => ZeroServe::ServeReadOnly,
                _ => unavailable("database_is_not_the_frozen_one"),
            }
        }
        Selector::D1 => d1(z, db, seen),
    }
}

fn d1(z: &TenantZero, db: &DatabaseFacts, seen: &Seen) -> ZeroServe {
    match (&z.moved, z.undo_stamp) {
        (None, Some(_)) => return unavailable("undo_without_move"),
        (Some(_), _) if !z.undone() => return unavailable("database_left_behind"),
        _ => {}
    }
    // After a move, only the catalogue that the undo named serves.
    let after_a_move = seen.moved || z.moved.is_some() || z.catalogue_id.is_some();
    if after_a_move {
        match (&z.catalogue_id, &db.catalogue_id) {
            (Some(named), Some(bound)) if named == bound => {}
            _ if seen.moved && z.catalogue_id.is_none() => {
                return unavailable("selector_went_back")
            }
            _ => return unavailable("database_is_not_the_named_one"),
        }
    }
    // The marker names its move: one of a move that already happened
    // means this database was left behind; one of the next move means
    // that move's window is opening (or was given up), and nothing writes.
    let moves_done = z.frozen_catalogues.len() as i64;
    match db.marker {
        None => ZeroServe::Serve,
        Some(ordinal) if ordinal > moves_done => ZeroServe::ServeReadOnly,
        Some(_) => unavailable("database_left_behind"),
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
    /// [`RECHECK_MS`], whatever it says; else checked by one listing after
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
            Err(ChainError::Damaged(_)) => return unavailable("record_damaged"),
            Err(_) => {
                return ZeroServe::Unavailable {
                    code: "record_unreadable",
                    page: false,
                }
            }
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

/// The answer of a lookup that may fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup<T> {
    Found(T),
    /// Looked up: not there.
    Absent,
    /// The lookup failed: nothing is known.
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

/// The route of a request after the directory answered. `route_record`
/// reads the key's route record; `zero_holds_key` asks tenant 0's D1
/// catalogue for the key. Each is called only when its step is reached
/// (see the [module](self)).
pub async fn route_without_directory(
    answer: DirectoryAnswer,
    zero: ZeroServe,
    route_record: impl AsyncFnOnce() -> Lookup<TenantId>,
    zero_holds_key: impl AsyncFnOnce() -> Lookup<()>,
) -> Route {
    match answer {
        DirectoryAnswer::Read(Some(tenant)) => Route::Tenant(tenant),
        DirectoryAnswer::Read(None) => Route::UnknownKey,
        DirectoryAnswer::Failed => match route_record().await {
            Lookup::Found(tenant) => Route::Tenant(tenant),
            Lookup::Failed => Route::Unavailable,
            Lookup::Absent if zero.serves_from_d1() => match zero_holds_key().await {
                Lookup::Found(()) => Route::Tenant(TenantId::zero()),
                Lookup::Absent | Lookup::Failed => Route::Unavailable,
            },
            Lookup::Absent => Route::Unavailable,
        },
    }
}
