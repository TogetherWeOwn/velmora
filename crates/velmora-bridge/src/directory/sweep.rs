//! The pending sweep's rows in the directory: [`PendingRows`] over the
//! `pending_ops` table (AM-75).
//!
//! The sweep steps from chain to chain on the primary key `(tenant,
//! chain, seq)` and takes each chain's oldest row from the additive index
//! `pending_ops (tenant, chain, created_at)`
//! (`migrations-directory/0003_pending_chains_and_caps.sql`), so a pass
//! costs O(`limit`) index reads whatever the rows' ages. Every statement's
//! plan is checked to use an index (the tests, and the receipt).
//!
//! A row whose tenant is not a managed tenant id (tenant 0, or a damaged
//! row) is stepped over and never answered: no finisher takes it, and the
//! age alarm on the oldest row (`oldest_pending`) keeps paging until an
//! operator removes it.

use super::store::SqlDirectory;
use crate::pending::{ChainKey, PendingRows};
use crate::ports::Sql;
use crate::types::{BridgeError, Result, UnixMs};

/// The next chain after a key, with its oldest row: two index seeks.
pub const NEXT_CHAIN: &str = "SELECT p.tenant, p.chain, \
     (SELECT MIN(q.created_at) FROM pending_ops q WHERE q.tenant = p.tenant AND q.chain = p.chain) \
     FROM pending_ops p WHERE (p.tenant, p.chain) > (?1, ?2) ORDER BY p.tenant, p.chain LIMIT 1";

/// The rows of one chain above a head, noted at or before a cutoff.
pub const DROP_ABOVE: &str = "DELETE FROM pending_ops WHERE tenant = ?1 AND chain = ?2 \
     AND seq > ?3 AND created_at <= ?4";

impl<S: Sql> PendingRows for SqlDirectory<'_, S> {
    async fn chains_after(
        &self,
        after: Option<&ChainKey>,
        limit: u32,
    ) -> Result<Vec<(ChainKey, UnixMs)>> {
        let _ = (after, limit);
        Err(BridgeError::NotImplemented("chains_after"))
    }

    async fn drop_above(&self, chain: &ChainKey, head: u64, cutoff: UnixMs) -> Result<u32> {
        let _ = (chain, head, cutoff);
        Err(BridgeError::NotImplemented("drop_above"))
    }
}
