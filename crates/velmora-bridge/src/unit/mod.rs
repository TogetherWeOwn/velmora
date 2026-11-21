//! A tenancy unit: one tenant's catalogue in its own SQLite Durable
//! Object (tenancy ADR §2.1 to §2.4, §8.3).
//!
//! The rules live here, generic over the database, so they run natively
//! in tests and unchanged in the object (`workers/unit`):
//!
//! - [`name`]: the name `<tenant>/<unit>`.
//! - [`identity`]: the chain numbers of every call (rule 5).
//! - [`birth`]: the birth certificate, on both sides (rules 6, 13).
//! - [`call`]: the call and its answer, as JSON.
//! - [`object`]: the unit itself (rules 1 to 7 and 11).
//! - [`schema`]: what a unit is born with.
//!
//! Nothing here holds a key or reaches the network (rules 3 and 4).

pub mod birth;
pub mod call;
pub mod identity;
pub mod name;
pub mod object;
pub mod schema;

pub use birth::{may_provision, BirthKind, BirthToken, HeadView, ProvisionRefusal};
pub use call::{Reader, Refused, SyncHead, TenantState, UnitAnswer, UnitCall, UnitOp};
pub use identity::{CallKind, Seqs, Verdict};
pub use name::{TenantId, UnitName};
pub use object::{poll_once, Unit, UnitSql};
