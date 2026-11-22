//! The storage management plane (`/v1`).
//!
//! It is served by a named entrypoint of the Worker that has no route
//! and no custom domain; only `kofra-api` holds a binding to it, and the
//! public handler has no `/v1` router at all. This module holds what the
//! plane checks before any handler runs.
//!
//! - [`adapters`]: the ports of the handlers over the tenancy plane's
//!   stores (the tenant head, the root unit, the key chain).
//! - [`events`]: one tenant's events, from the directory's feed.
//! - [`gate`]: what every call passes before its handler runs.
//! - [`idem`]: `Idempotency-Key` for the capped opening calls, through
//!   the root unit's reservation.
//! - [`request`]: the acting header, the `Idempotency-Key` and the query
//!   of each call.
//! - [`principal`]: principal create, the first handler, over the ports
//!   of the stores it reads and writes.
//! - [`route`]: the calls, their paths and the least scope of each.
//! - [`serve`]: one request, from the gate to its answer.
//! - [`setup`]: the two operator setup routes under `/_admin` (the first
//!   key-location record, the directory gate's first open; AM-70b).
//! - [`tenant`]: tenant read, from the verified head.
//! - [`tenant_create`]: tenant create (AM-58).
//! - [`token`]: the service tokens, their classes and scopes, and the
//!   records that disable one.

pub mod adapters;
pub mod events;
pub mod gate;
pub mod idem;
pub mod principal;
pub mod request;
pub mod route;
pub mod serve;
pub mod setup;
pub mod tenant;
pub mod tenant_create;
pub mod token;
