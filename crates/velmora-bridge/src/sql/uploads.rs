//! Multipart uploads: guarded batches and the completion receipt (catalogue lane B).
//!
//! Walking-skeleton stub: every function answers `NotImplemented`.

use super::SqlCatalog;
use crate::ports::{Guard, Sql, UploadTarget};
use crate::types::{
    BridgeError, CompleteUpload, ExtentRow, Result, UnixMs, UploadPartRow, UploadRow,
};

pub(super) async fn create_upload<S: Sql>(_c: &SqlCatalog<S>, _u: &UploadRow) -> Result<()> {
    Err(BridgeError::NotImplemented("sql::uploads::create_upload"))
}

pub(super) async fn upload<S: Sql>(
    _c: &SqlCatalog<S>,
    _t: &UploadTarget<'_>,
) -> Result<Option<(UploadRow, Vec<UploadPartRow>)>> {
    Err(BridgeError::NotImplemented("sql::uploads::upload"))
}

pub(super) async fn put_upload_part<S: Sql>(
    _c: &SqlCatalog<S>,
    _t: &UploadTarget<'_>,
    _part: &UploadPartRow,
    _extent: &ExtentRow,
    _now: UnixMs,
) -> Result<Guard<()>> {
    Err(BridgeError::NotImplemented("sql::uploads::put_upload_part"))
}

pub(super) async fn complete_upload<S: Sql>(
    _c: &SqlCatalog<S>,
    _t: &UploadTarget<'_>,
    _revision: u64,
    _digest: &[u8; 32],
    _commit: &CompleteUpload,
) -> Result<Guard<()>> {
    Err(BridgeError::NotImplemented("sql::uploads::complete_upload"))
}

pub(super) async fn abort_upload<S: Sql>(
    _c: &SqlCatalog<S>,
    _t: &UploadTarget<'_>,
    _now: UnixMs,
) -> Result<Guard<()>> {
    Err(BridgeError::NotImplemented("sql::uploads::abort_upload"))
}
