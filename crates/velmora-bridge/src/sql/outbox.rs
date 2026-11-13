//! Outbox leases with fencing tokens, article plans, verification and release (catalogue lane B).
//!
//! Walking-skeleton stub: every function answers `NotImplemented`.

use super::SqlCatalog;
use crate::ports::{Guard, Lease, Sql};
use crate::types::{
    ArticleRow, BackboneStatus, BridgeError, DueRow, ExtentId, FailClass, GenerationId, JobExtent,
    OutboxStage, OutboxStats, Result, UnixMs, VerificationRow,
};

pub(super) async fn claim<S: Sql>(
    _c: &SqlCatalog<S>,
    _extent: &ExtentId,
    _generation: &GenerationId,
    _stage: OutboxStage,
    _owner: &str,
    _now: UnixMs,
) -> Result<Option<Lease>> {
    Err(BridgeError::NotImplemented("sql::outbox::claim"))
}

pub(super) async fn renew<S: Sql>(_c: &SqlCatalog<S>, _l: &Lease, _now: UnixMs) -> Result<bool> {
    Err(BridgeError::NotImplemented("sql::outbox::renew"))
}

pub(super) async fn advance<S: Sql>(
    _c: &SqlCatalog<S>,
    _l: &Lease,
    _to: OutboxStage,
    _next_at: UnixMs,
    _now: UnixMs,
) -> Result<bool> {
    Err(BridgeError::NotImplemented("sql::outbox::advance"))
}

pub(super) async fn fail<S: Sql>(
    _c: &SqlCatalog<S>,
    _l: &Lease,
    _class: FailClass,
    _next_at: UnixMs,
    _now: UnixMs,
) -> Result<bool> {
    Err(BridgeError::NotImplemented("sql::outbox::fail"))
}

pub(super) async fn defer<S: Sql>(
    _c: &SqlCatalog<S>,
    _l: &Lease,
    _next_at: UnixMs,
    _now: UnixMs,
) -> Result<bool> {
    Err(BridgeError::NotImplemented("sql::outbox::defer"))
}

pub(super) async fn job_extent<S: Sql>(
    _c: &SqlCatalog<S>,
    _extent: &ExtentId,
    _generation: &GenerationId,
) -> Result<Option<JobExtent>> {
    Err(BridgeError::NotImplemented("sql::outbox::job_extent"))
}

pub(super) async fn plan_articles<S: Sql>(
    _c: &SqlCatalog<S>,
    _l: &Lease,
    _rows: &[ArticleRow],
) -> Result<Option<Vec<ArticleRow>>> {
    Err(BridgeError::NotImplemented("sql::outbox::plan_articles"))
}

pub(super) async fn articles<S: Sql>(
    _c: &SqlCatalog<S>,
    _extent: &ExtentId,
) -> Result<Vec<ArticleRow>> {
    Err(BridgeError::NotImplemented("sql::outbox::articles"))
}

pub(super) async fn mark_posted<S: Sql>(
    _c: &SqlCatalog<S>,
    _l: &Lease,
    _idx: u32,
    _provider: &str,
    _now: UnixMs,
) -> Result<bool> {
    Err(BridgeError::NotImplemented("sql::outbox::mark_posted"))
}

pub(super) async fn record_verification<S: Sql>(
    _c: &SqlCatalog<S>,
    _l: &Lease,
    _v: &VerificationRow,
) -> Result<bool> {
    Err(BridgeError::NotImplemented(
        "sql::outbox::record_verification",
    ))
}

pub(super) async fn backbone_status<S: Sql>(
    _c: &SqlCatalog<S>,
    _extent: &ExtentId,
) -> Result<Vec<BackboneStatus>> {
    Err(BridgeError::NotImplemented("sql::outbox::backbone_status"))
}

pub(super) async fn begin_release<S: Sql>(
    _c: &SqlCatalog<S>,
    _l: &Lease,
    _required: u32,
    _evidence_json: &str,
    _now: UnixMs,
) -> Result<Guard<()>> {
    Err(BridgeError::NotImplemented("sql::outbox::begin_release"))
}

pub(super) async fn finish_release<S: Sql>(
    _c: &SqlCatalog<S>,
    _l: &Lease,
    _now: UnixMs,
) -> Result<bool> {
    Err(BridgeError::NotImplemented("sql::outbox::finish_release"))
}

pub(super) async fn due<S: Sql>(
    _c: &SqlCatalog<S>,
    _now: UnixMs,
    _limit: u32,
) -> Result<Vec<DueRow>> {
    Err(BridgeError::NotImplemented("sql::outbox::due"))
}

pub(super) async fn bury_exhausted<S: Sql>(
    _c: &SqlCatalog<S>,
    _max_attempts: u32,
    _now: UnixMs,
) -> Result<u64> {
    Err(BridgeError::NotImplemented("sql::outbox::bury_exhausted"))
}

pub(super) async fn set_cursor<S: Sql>(
    _c: &SqlCatalog<S>,
    _l: &Lease,
    _cursor: u32,
    _now: UnixMs,
) -> Result<bool> {
    Err(BridgeError::NotImplemented("sql::outbox::set_cursor"))
}

pub(super) async fn record_dispatch<S: Sql>(_c: &SqlCatalog<S>, _now: UnixMs) -> Result<()> {
    Err(BridgeError::NotImplemented("sql::outbox::record_dispatch"))
}

pub(super) async fn outbox_stats<S: Sql>(_c: &SqlCatalog<S>) -> Result<OutboxStats> {
    Err(BridgeError::NotImplemented("sql::outbox::outbox_stats"))
}
