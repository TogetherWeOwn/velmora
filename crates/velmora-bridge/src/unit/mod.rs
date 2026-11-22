//! A tenancy unit: one tenant's catalogue in its own SQLite Durable
//! Object (`docs/units.md`).
//!
//! The rules live here, generic over the database, so they run natively
//! in tests and unchanged in the object (`workers/unit`):
//!
//! - [`name`]: the name `<tenant>/<unit>`.
//! - [`identity`]: the chain numbers of every call (rule 5).
//! - [`birth`]: the birth certificate, on both sides (rules 6, 13).
//! - [`call`]: the call and its answer, as JSON.
//! - [`object`]: the unit itself (rules 1 to 7 and 11).
//! - [`keys`]: the key-chain apply and the effective grant.
//! - [`import`]: the owner move's import.
//! - [`export`]: the unit's rows read back out (the move's checks, the
//!   reverse move).
//! - [`jobcall`]: the job path's catalogue calls.
//! - [`request`]: the S3 request path's catalogue calls.
//! - [`request_client`]: the Worker's side of them.
//! - [`recount`]: the usage recount of a closed unit.
//! - [`reserve`]: the reservation of a capped opening call.
//! - [`size`]: the size guard.
//! - [`restore`]: the restore calls.
//! - [`lift`]: the lift, checked in the unit.
//! - [`schema`]: what a unit is born with.
//! - [`gate`]: the restore gate's lift decision.
//!
//! Nothing here holds a key or reaches the network (rules 3 and 4).

pub mod birth;
pub mod buckets;
pub mod call;
pub mod export;
pub mod gate;
pub mod identity;
pub mod import;
pub mod jobcall;
pub mod keys;
pub mod lift;
pub mod name;
pub mod object;
pub mod recount;
pub mod request;
pub mod request_client;
pub mod reserve;
pub mod restore;
pub mod schema;
pub mod size;

pub use birth::{may_provision, BirthKind, BirthToken, HeadView, ProvisionRefusal};
pub use call::{Reader, Refused, SyncHead, TenantState, UnitAnswer, UnitCall, UnitOp, UnitReply};
pub use identity::{CallKind, Seqs, Verdict};
pub use name::{TenantId, UnitName};
pub use object::{poll_once, AlarmStep, Unit, UnitSql};
