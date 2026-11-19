//! The tenant a piece of work is done for.
//!
//! Today the service has one tenant, tenant 0: the owner of every
//! bucket. This module is the seam for more. Code that names a stored
//! blob for a job takes a [`TenantScope`] and asks it for the name, so
//! that a second tenant later changes this module and the places that
//! make a scope, and not every place that names a blob.
//!
//! Nothing stored and nothing sent changes with it. The names of
//! tenant 0 are the ones they were (`x/<extent>`, `c/<extent>`, the
//! record layouts of [`crate::recovery::Layout`]), a queue message
//! carries no tenant, and the catalogue id is not made from one.
//!
//! # Where a scope is made
//!
//! [`TenantScope::tenant_zero`] is the only constructor, and the type
//! has no `Default`: a scope cannot appear by accident. It is called
//! where work enters with no tenant on it:
//!
//! - the queue consumer, once for each message;
//! - the configuration, for the record layout `tenant`;
//! - the replay and the recovery copy, which go through the records of
//!   the whole store.
//!
//! A source test (`tests/tenant_seams.rs`) holds that list. The request
//! path and the catalogue's own delete lists still name blobs without a
//! scope ([`crate::types::ExtentId::safety_key`]); the same test holds
//! the list of those places, so that it can only get shorter.
//!
//! # Names kept free
//!
//! Two families of names are reserved here and written by nothing:
//! [`BUCKET_CONFIG_DIR`] under a tenant's record directory, and
//! [`CATALOGUE_DUMP_PREFIX`].

use crate::recovery::DEFAULT_TENANT;
use crate::types::ExtentId;

/// Reserved: the directory of a tenant's bucket configuration records,
/// under the tenant's record directory
/// (`m/x/<tenant>/b/<bucket>/<sequence>`). Nothing writes it, and
/// [`crate::recovery::record_name`] takes no name under it for a record.
/// Like every name under `m/`, no delete removes one.
pub const BUCKET_CONFIG_DIR: &str = "b/";

/// Reserved: the prefix of sealed dumps of a catalogue
/// (`cb/<tenant>/<unit>/<day>/`). Nothing writes it.
pub const CATALOGUE_DUMP_PREFIX: &str = "cb/";

/// The tenant a piece of work is done for. See the [module](self).
///
/// On purpose not `Default`, not `Deserialize` and with a private
/// field: [`TenantScope::tenant_zero`] is the one way to get one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantScope {
    tenant: &'static str,
}

impl TenantScope {
    /// The scope of tenant 0, the owner of every bucket there is.
    pub const fn tenant_zero() -> TenantScope {
        TenantScope {
            tenant: DEFAULT_TENANT,
        }
    }

    /// The tenant id, as a record name takes it.
    pub fn tenant_id(&self) -> &str {
        self.tenant
    }

    pub fn is_tenant_zero(&self) -> bool {
        self.tenant == DEFAULT_TENANT
    }

    /// The name of the safety copy of `extent`.
    pub fn safety_key(&self, extent: &ExtentId) -> String {
        match self.is_tenant_zero() {
            true => extent.safety_key(),
            false => blob_key("x/", self.tenant, extent),
        }
    }

    /// The name of the cache copy of `extent`.
    pub fn cache_key(&self, extent: &ExtentId) -> String {
        match self.is_tenant_zero() {
            true => extent.cache_key(),
            false => blob_key("c/", self.tenant, extent),
        }
    }
}

/// The name of a blob of a tenant other than tenant 0: the tenant comes
/// before the extent. No scope of such a tenant can be made yet, so
/// nothing is stored under such a name.
fn blob_key(family: &str, tenant: &str, extent: &ExtentId) -> String {
    format!("{family}{tenant}/{}", extent.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{is_protected_key, record_name, Layout, TENANT_DIR};

    fn extent() -> ExtentId {
        ExtentId::new("x_000102030405060708090a0b0c")
    }

    /// Tenant 0 keeps every name it had.
    #[test]
    fn tenant_zero_names_blobs_as_before() {
        let scope = TenantScope::tenant_zero();
        assert!(scope.is_tenant_zero());
        assert_eq!(scope.tenant_id(), "t_0000000000000000");
        assert_eq!(
            scope.safety_key(&extent()),
            "x/x_000102030405060708090a0b0c"
        );
        assert_eq!(scope.cache_key(&extent()), "c/x_000102030405060708090a0b0c");
        assert_eq!(scope.safety_key(&extent()), extent().safety_key());
        assert_eq!(scope.cache_key(&extent()), extent().cache_key());
    }

    #[test]
    fn the_layouts_of_tenant_zero_are_the_two_there_were() {
        let scope = TenantScope::tenant_zero();
        assert_eq!(Layout::of(&scope).root(), "m/x/t_0000000000000000/");
        assert_eq!(Some(Layout::of(&scope)), Layout::tenant(scope.tenant_id()));
        let [flat, tenant] = Layout::all(&scope);
        assert_eq!(flat, Layout::flat());
        assert_eq!(tenant, Layout::of(&scope));
    }

    /// The form a second tenant's blobs will take cannot meet a name of
    /// tenant 0: an extent id has no `/`.
    #[test]
    fn another_tenant_would_get_names_of_its_own() {
        let key = blob_key("x/", "t_1", &extent());
        assert_eq!(key, "x/t_1/x_000102030405060708090a0b0c");
        assert_ne!(key, extent().safety_key());
        assert_eq!(
            blob_key("c/", "t_1", &extent()),
            "c/t_1/x_000102030405060708090a0b0c"
        );
        assert!(!extent().as_str().contains('/'));
    }

    /// The reserved names are no record of any kind, and the bucket
    /// configuration directory is under the prefix no delete touches.
    #[test]
    fn the_reserved_names_are_free() {
        let tenant = TenantScope::tenant_zero();
        let config = format!(
            "{TENANT_DIR}{}/{BUCKET_CONFIG_DIR}photos/00000000000000000001",
            tenant.tenant_id()
        );
        assert_eq!(
            config,
            "m/x/t_0000000000000000/b/photos/00000000000000000001"
        );
        assert!(record_name(&config).is_none());
        assert!(is_protected_key(&config));
        // Also a bucket whose name looks like a record id.
        for bucket in ["g_0195c2a4b3e7f00112233445566778", "art", "del"] {
            let config = format!(
                "{TENANT_DIR}{}/{BUCKET_CONFIG_DIR}{bucket}/1",
                tenant.tenant_id()
            );
            assert!(record_name(&config).is_none(), "{config}");
        }
        let dump = format!("{CATALOGUE_DUMP_PREFIX}t_0000000000000000/u1/2026-01-01/part");
        assert!(record_name(&dump).is_none());
        // Not the cache family, whose names start with `c/`.
        assert!(!dump.starts_with("c/"));
        assert!(!extent().cache_key().starts_with(CATALOGUE_DUMP_PREFIX));
    }
}
