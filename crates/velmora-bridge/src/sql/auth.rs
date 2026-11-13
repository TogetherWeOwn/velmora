//! Buckets, access keys and grants (catalogue lane A).
//!
//! Walking-skeleton stub: every function answers `NotImplemented`.

use super::SqlCatalog;
use crate::ports::{Guard, Sql};
use crate::types::{AccessKeyRow, BridgeError, Bucket, BucketId, Perm, Result};

pub(super) async fn create_bucket<S: Sql>(_c: &SqlCatalog<S>, _b: &Bucket) -> Result<Guard<()>> {
    Err(BridgeError::NotImplemented("sql::auth::create_bucket"))
}

pub(super) async fn create_access_key<S: Sql>(_c: &SqlCatalog<S>, _k: &AccessKeyRow) -> Result<()> {
    Err(BridgeError::NotImplemented("sql::auth::create_access_key"))
}

pub(super) async fn put_grant<S: Sql>(
    _c: &SqlCatalog<S>,
    _akid: &str,
    _bucket: &BucketId,
    _perm: Perm,
) -> Result<()> {
    Err(BridgeError::NotImplemented("sql::auth::put_grant"))
}

pub(super) async fn bucket_by_name<S: Sql>(
    _c: &SqlCatalog<S>,
    _name: &str,
) -> Result<Option<Bucket>> {
    Err(BridgeError::NotImplemented("sql::auth::bucket_by_name"))
}

pub(super) async fn buckets_for<S: Sql>(_c: &SqlCatalog<S>, _akid: &str) -> Result<Vec<Bucket>> {
    Err(BridgeError::NotImplemented("sql::auth::buckets_for"))
}

pub(super) async fn access_key<S: Sql>(
    _c: &SqlCatalog<S>,
    _akid: &str,
) -> Result<Option<AccessKeyRow>> {
    Err(BridgeError::NotImplemented("sql::auth::access_key"))
}

pub(super) async fn grant<S: Sql>(
    _c: &SqlCatalog<S>,
    _akid: &str,
    _bucket: &BucketId,
) -> Result<Option<Perm>> {
    Err(BridgeError::NotImplemented("sql::auth::grant"))
}
