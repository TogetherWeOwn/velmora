//! Provider connection permits: fenced D1 slots (catalogue lane B).
//!
//! Walking-skeleton stub: every function answers `NotImplemented`.

use super::SqlCatalog;
use crate::ports::{Permit, PermitClass, Sql};
use crate::types::{BridgeError, ProviderConfig, Result, UnixMs};

pub(super) async fn seed_permits<S: Sql>(
    _c: &SqlCatalog<S>,
    _providers: &[ProviderConfig],
) -> Result<()> {
    Err(BridgeError::NotImplemented("sql::permits::seed_permits"))
}

pub(super) async fn acquire_permit<S: Sql>(
    _c: &SqlCatalog<S>,
    _p: &ProviderConfig,
    _class: PermitClass,
    _holder: &str,
    _now: UnixMs,
) -> Result<Option<Permit>> {
    Err(BridgeError::NotImplemented("sql::permits::acquire_permit"))
}

pub(super) async fn renew_permit<S: Sql>(
    _c: &SqlCatalog<S>,
    _p: &Permit,
    _now: UnixMs,
) -> Result<bool> {
    Err(BridgeError::NotImplemented("sql::permits::renew_permit"))
}

pub(super) async fn release_permit<S: Sql>(_c: &SqlCatalog<S>, _p: &Permit) -> Result<()> {
    Err(BridgeError::NotImplemented("sql::permits::release_permit"))
}
