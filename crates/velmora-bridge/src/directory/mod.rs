//! The directory of tenants and the tenant chain.
//!
//! The record chain in R2 decides; the directory is an index that can be
//! rebuilt from it. This module holds the parts of that which name no
//! store yet:
//!
//! - [`record`]: the tenant record, its door part and its private part,
//!   and the state derived from it;
//! - [`transition`]: which record may follow which, and who may write it;
//! - [`chain`]: the chain `m/t/<tenant>/<seq>` in R2, its head, its reader
//!   and its put-once writer, over two ports (a record store with
//!   put-if-absent, and the two-part control seal);
//! - [`store`]: the directory database (`migrations-directory/`): tenant
//!   rows copied from chain heads, unit rows, key routes, pending
//!   operations and the gate;
//! - [`gate`]: the directory gate and the rebuild of the tenant rows from
//!   the chains, and the read-only comparison of the two.
//!
//! Nothing in the Worker calls this module yet. No request is routed by
//! it and no record is written by it in production.

pub mod chain;
pub mod gate;
pub mod record;
pub mod store;
pub mod transition;

#[cfg(any(test, feature = "testkit"))]
pub mod testing;
