//! `impl Sql` over D1 (adapter lane): `SqlValue` <-> JS, atomic `batch`,
//! CHECK failure of `tx_guard` -> `GuardFailed` (via
//! `velmora_bridge::is_tx_guard_violation`).
//!
//! Walking-skeleton stub: every call answers `NotImplemented`.

use velmora_bridge::{BridgeError, Result, Row, Sql, SqlValue};
use worker::D1Database;

pub struct D1Sql {
    #[allow(dead_code)] // read once the adapter lands
    db: D1Database,
}

impl D1Sql {
    pub fn new(db: D1Database) -> Self {
        D1Sql { db }
    }
}

impl Sql for D1Sql {
    async fn query(&self, _sql: &str, _params: &[SqlValue]) -> Result<Vec<Row>> {
        Err(BridgeError::NotImplemented("d1::query"))
    }

    async fn exec(&self, _sql: &str, _params: &[SqlValue]) -> Result<u64> {
        Err(BridgeError::NotImplemented("d1::exec"))
    }

    async fn batch(&self, _stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        Err(BridgeError::NotImplemented("d1::batch"))
    }
}
