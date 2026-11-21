//! The Durable Object side of a velmora unit (tenancy ADR §2.4, §8.3).
//!
//! - [`DoSql`]: the catalogue's [`velmora_bridge::Sql`] port over the
//!   object's SQLite storage. A batch is one transaction through the
//!   JavaScript shim (`shim.js`, `storage.transactionSync`).
//! - [`PointInTime`]: the object's 30 days of history, through the same
//!   shim.
//!
//! Nothing here holds a key, reaches the network or sets a timer
//! (ADR §2.4 rules 3 and 4).

mod do_sql;
mod pitr;

pub use do_sql::{bind_text, significant_end, DoSql};
pub use pitr::PointInTime;
