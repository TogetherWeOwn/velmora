//! The storage management plane (`/v1`).
//!
//! It is served by a named entrypoint of the Worker that has no route
//! and no custom domain; only `kofra-api` holds a binding to it, and the
//! public handler has no `/v1` router at all. This module holds what the
//! plane checks before any handler runs.
//!
//! - [`gate`]: what every call passes before its handler runs.
//! - [`route`]: the calls, their paths and the least scope of each.
//! - [`serve`]: one request, from the gate to its answer.
//! - [`token`]: the service tokens, their classes and scopes, and the
//!   records that disable one.

pub mod gate;
pub mod route;
pub mod serve;
pub mod token;
