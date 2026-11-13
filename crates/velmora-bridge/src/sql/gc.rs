//! Garbage-collection rows (catalogue lane B).
//!
//! Walking-skeleton stub: every function answers `NotImplemented`.

use super::SqlCatalog;
use crate::ports::Sql;
use crate::types::{BridgeError, GcRow, GcStep, Result, UnixMs};

pub(super) async fn gc_due<S: Sql>(
    _c: &SqlCatalog<S>,
    _now: UnixMs,
    _limit: u32,
    _disposable_only: bool,
) -> Result<Vec<GcRow>> {
    Err(BridgeError::NotImplemented("sql::gc::gc_due"))
}

pub(super) async fn gc_begin<S: Sql>(
    _c: &SqlCatalog<S>,
    _row: &GcRow,
    _now: UnixMs,
) -> Result<GcStep> {
    Err(BridgeError::NotImplemented("sql::gc::gc_begin"))
}

pub(super) async fn gc_done<S: Sql>(_c: &SqlCatalog<S>, _id: i64, _now: UnixMs) -> Result<()> {
    Err(BridgeError::NotImplemented("sql::gc::gc_done"))
}
