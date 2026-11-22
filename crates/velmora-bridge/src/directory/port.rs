//! The directory port: which tenant an access key belongs to.
//!
//! A store with more than one tenant has to find the tenant of a
//! request before it can ask that tenant's catalogue anything.
//! [`Directory`] is the port for that question. This module is the seam
//! and no more: nothing asks a directory yet. No request and no job is
//! routed by one, and nothing is stored for one.
//!
//! The one adapter there is, [`SingleTenant`], is the directory of the
//! store as it is today: every access key is a key of tenant 0.
//!
//! # What a directory does not decide
//!
//! A route says whose key an id would be. It does not say that the key
//! exists, that it is enabled or what it may do: the key row in the
//! tenant's catalogue decides those, as it does today.
//!
//! An answer of "no such key" (`Ok(None)`) is not a failure of the
//! directory (`Err`), and a caller treats the two differently:
//!
//! - On `Ok(None)` the directory was read and no tenant has the key.
//!   The caller refuses the request and never guesses a tenant.
//! - On `Err` the directory could not be read, and that says nothing
//!   about the key. The caller must not take it for "no such key". It
//!   may do one thing: ask the catalogue of tenant 0 whether it holds
//!   the key, and go on as a request of tenant 0 if it does. In every
//!   other case it refuses, with an answer that says the service is
//!   unavailable and not that the key is unknown.
//!
//! The way through tenant 0 is for a failed read only, never for an
//! answer of "no such key": a store whose directory is down still
//! serves the tenant whose catalogue it can reach without one.

use crate::tenant::TenantScope;
use crate::types::Result;

/// Finds the tenant of an access key. See the [module](self).
#[allow(async_fn_in_trait)]
pub trait Directory {
    /// The tenant that `access_key_id` would be a key of, or `None`
    /// when no tenant has such a key.
    async fn route(&self, access_key_id: &str) -> Result<Option<TenantScope>>;
}

/// The directory of a store with one tenant: every access key id is
/// routed to tenant 0. It reads nothing and cannot fail.
#[derive(Clone, Copy, Debug, Default)]
pub struct SingleTenant;

impl Directory for SingleTenant {
    async fn route(&self, _access_key_id: &str) -> Result<Option<TenantScope>> {
        Ok(Some(TenantScope::tenant_zero()))
    }
}
