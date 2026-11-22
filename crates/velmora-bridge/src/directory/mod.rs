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
//! - [`feed`]: the event feed of the management plane in the directory,
//!   its per-tenant read, its epochs and its prune;
//! - [`gate`]: the directory gate and the rebuild of the tenant rows from
//!   the chains, and the read-only comparison of the two;
//! - [`fence`]: the move's freeze of tenant 0's D1 catalogue: the cutover
//!   marker, the freeze triggers, the legacy stamp, and the thaw;
//! - [`move_copy`]: the move's copy of the frozen D1's rows into the
//!   owner's root unit, by bounded pages and resumable import batches;
//! - [`move_flip`]: the move's flip (legacy stamp, the unit opened by the
//!   `move` report, the routes, tenant 0 `moved`), its give-up before the
//!   flip, and the exit that removes the moved-in placements;
//! - [`move_keys`]: the move's key steps on the unit (the direct key
//!   apply, the revocation sweep, step 9's check) and the give-up's
//!   revocations on the thawed D1;
//! - [`move_preflight`]: the read-only counts of precondition P2 that
//!   stop the move before its window;
//! - [`tenant_zero`]: whether tenant 0 may be served from the D1
//!   catalogue, from its record and the database's own marker, and the
//!   route of a request when the directory cannot be read.
//!
//! Nothing in the Worker calls this module yet. No request is routed by
//! it and no record is written by it in production.

pub mod chain;
pub mod feed;
pub mod fence;
pub mod gate;
pub mod move_copy;
pub mod move_flip;
pub mod move_keys;
pub mod move_preflight;
pub mod record;
pub mod store;
pub mod tenant_zero;
pub mod transition;

#[cfg(any(test, feature = "testkit"))]
pub mod testing;
