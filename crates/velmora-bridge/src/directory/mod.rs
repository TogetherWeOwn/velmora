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
//! - [`seal`]: the real control seal of the chain over key scheme 2
//!   ([`seal::ChainSeal`]), with the tenant keys the composition root
//!   loaded ([`seal::SealKeys`]);
//! - [`store`]: the directory database (`migrations-directory/`): tenant
//!   rows copied from chain heads, unit rows, key routes, pending
//!   operations and the gate;
//! - [`feed`]: the event feed of the management plane in the directory,
//!   its per-tenant read, its epochs and its prune;
//! - [`gate`]: the directory gate and the rebuild of the tenant rows from
//!   the chains, and the read-only comparison of the two;
//! - [`fence`]: the move's freeze of tenant 0's D1 catalogue: the cutover
//!   marker, the freeze triggers, the legacy stamp, and the thaw;
//! - [`tenant_zero`]: whether tenant 0 may be served from the D1
//!   catalogue, from its record and the database's own marker, and the
//!   route of a request when the directory cannot be read;
//! - [`keys`]: the directory as a store of the key chain
//!   ([`keys::DirectoryKeys`], `KeyEnv.directory`), and the target of an
//!   environment with no directory ([`keys::UnboundDirectory`]);
//! - [`finish`]: the finisher of a tenant chain (`finish_tenant`), the
//!   directory as a store of the tenant chain;
//! - [`events`]: the feed events built from chain records;
//! - [`sweep`]: the pending sweep's rows over `pending_ops`;
//! - [`first_open`]: the gate's first open (`FirstOpen`, AM-78);
//! - [`caps`]: the global backstops per service token (ADR §6.3);
//! - [`port`]: [`Directory`], the port that finds the tenant of an access
//!   key, and its one adapter [`SingleTenant`] (every key is tenant 0's).
//!
//! Nothing in the Worker calls this module yet. No request is routed by
//! it and no record is written by it in production. The composition
//! root wires [`keys::DirectoryKeys`] and [`finish::finish_tenant`] in
//! (AM-75).

pub mod caps;
pub mod chain;
pub mod events;
pub mod feed;
pub mod fence;
pub mod finish;
pub mod first_open;
pub mod gate;
pub mod keys;
pub mod port;
pub mod record;
pub mod seal;
pub mod store;
pub mod sweep;
pub mod tenant_zero;
pub mod transition;

pub use port::{Directory, SingleTenant};

#[cfg(any(test, feature = "testkit"))]
pub mod testing;
