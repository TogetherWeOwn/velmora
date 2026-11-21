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
//!   the chains, and the read-only comparison of the two;
//! - [`fence`]: the move's freeze of tenant 0's D1 catalogue: the cutover
//!   marker, the freeze triggers, the legacy stamp, and the thaw;
//! - [`tenant_zero`]: whether tenant 0 may be served from the D1
//!   catalogue, from its record and the database's own marker, and the
//!   route of a request when the directory cannot be read.
//!
//! Nothing in the Worker calls this module yet. No request is routed by
//! it and no record is written by it in production.

pub mod chain;
pub mod fence;
pub mod gate;
pub mod record;
pub mod store;
pub mod tenant_zero;
pub mod transition;

#[cfg(any(test, feature = "testkit"))]
pub mod testing;
