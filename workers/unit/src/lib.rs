//! The Durable Object side of a velmora unit: one tenant's catalogue in
//! its own SQLite Durable Object.
//!
//! - [`DoSql`]: the catalogue's [`velmora_bridge::Sql`] port over the
//!   object's SQLite storage. A batch is one transaction through the
//!   JavaScript shim (`shim.js`, `storage.transactionSync`).
//! - [`PointInTime`]: the object's 30 days of history, through the same
//!   shim.
//!
//! Nothing here holds a key, reaches the network or sets a timer.

mod do_sql;
mod pitr;

pub use do_sql::{bind_text, significant_end, DoSql};
pub use pitr::PointInTime;
