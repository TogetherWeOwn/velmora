//! Objects, generations, listing and admin status (catalogue lane A).
//!
//! Walking-skeleton stub: every function answers `NotImplemented`.

use super::SqlCatalog;
use crate::ports::Sql;
use crate::types::{
    BridgeError, BucketId, CommitGeneration, ExtentId, ExtentRow, GenerationRow, ListPage,
    ListQuery, ObjectStatus, Result, SafetyState, UnixMs,
};

pub(super) async fn live_object<S: Sql>(
    _c: &SqlCatalog<S>,
    _bucket: &BucketId,
    _key: &str,
) -> Result<Option<(GenerationRow, Vec<ExtentRow>)>> {
    Err(BridgeError::NotImplemented("sql::objects::live_object"))
}

pub(super) async fn commit_generation<S: Sql>(
    _c: &SqlCatalog<S>,
    _commit: &CommitGeneration,
) -> Result<()> {
    Err(BridgeError::NotImplemented(
        "sql::objects::commit_generation",
    ))
}

pub(super) async fn delete_object<S: Sql>(
    _c: &SqlCatalog<S>,
    _bucket: &BucketId,
    _key: &str,
    _now: UnixMs,
) -> Result<()> {
    Err(BridgeError::NotImplemented("sql::objects::delete_object"))
}

pub(super) async fn list<S: Sql>(
    _c: &SqlCatalog<S>,
    _bucket: &BucketId,
    _q: &ListQuery,
) -> Result<ListPage> {
    Err(BridgeError::NotImplemented("sql::objects::list"))
}

pub(super) async fn object_status<S: Sql>(
    _c: &SqlCatalog<S>,
    _bucket: &BucketId,
    _key: &str,
) -> Result<Option<ObjectStatus>> {
    Err(BridgeError::NotImplemented("sql::objects::object_status"))
}

pub(super) async fn set_safety_state<S: Sql>(
    _c: &SqlCatalog<S>,
    _extent: &ExtentId,
    _from: SafetyState,
    _to: SafetyState,
) -> Result<bool> {
    Err(BridgeError::NotImplemented(
        "sql::objects::set_safety_state",
    ))
}
