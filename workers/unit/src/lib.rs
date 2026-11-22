//! The Durable Object side of a velmora unit: one tenant's catalogue in
//! its own SQLite Durable Object (`docs/units.md`).
//!
//! - [`DoSql`]: the catalogue's [`velmora_bridge::Sql`] port over the
//!   object's SQLite storage. A batch is one transaction through the
//!   JavaScript shim (`shim.js`, `storage.transactionSync`).
//! - [`PointInTime`]: the object's 30 days of history, through the same
//!   shim.
//! - [`UnitObject`]: the unit's Durable Object class. One call per
//!   `fetch`, as JSON ([`velmora_bridge::unit::UnitCall`]); the rules are
//!   in [`velmora_bridge::unit`]. Exported by a Worker that depends on
//!   this crate; bound by none yet.
//!
//! - the alarm ([`alarm`]): the one place that sends to a queue (the
//!   unit's `renew` and `stamp_raise` jobs) and arms the alarm (rules 4,
//!   8 and 12).
//!
//! Nothing here holds a key or reaches the network, and nothing but the
//! alarm sends or sets a timer (rules 3 and 4).

pub mod alarm;
mod do_sql;
mod object;
mod pitr;
mod unit_sql;

pub use do_sql::{bind_text, significant_end, DoSql};
pub use object::UnitObject;
pub use pitr::PointInTime;
