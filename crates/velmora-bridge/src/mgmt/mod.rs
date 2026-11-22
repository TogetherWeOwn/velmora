//! The storage management plane (`/v1`).
//!
//! It is served by a named entrypoint of the Worker that has no route
//! and no custom domain; only `kofra-api` holds a binding to it, and the
//! public handler has no `/v1` router at all. This module holds what the
//! plane checks before any handler runs.
//!
//! - [`gate`]: what every call passes before its handler runs.
//! - [`idem`]: `Idempotency-Key` for the capped opening calls, through
//!   the root unit's reservation.
//! - [`request`]: the acting header, the `Idempotency-Key` and the query
//!   of each call.
//! - [`principal`]: principal create, the first handler, over the ports
//!   of the stores it reads and writes.
//! - [`route`]: the calls, their paths and the least scope of each.
//! - [`serve`]: one request, from the gate to its answer.
//! - [`token`]: the service tokens, their classes and scopes, and the
//!   records that disable one.

pub mod gate;
pub mod idem;
pub mod principal;
pub mod request;
pub mod route;
pub mod serve;
pub mod token;
