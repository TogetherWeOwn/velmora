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
//! row) is stepped over, one seek each, and never answered: no finisher
//! takes it, and the age alarm on the oldest row (`oldest_pending`) keeps
//! paging until an operator removes it.

use super::store::{int, SqlDirectory};
use crate::crypto::scheme2::TenantId;
use crate::keys::ports::ControlChain;
use crate::pending::{ChainKey, PendingRows};
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result, UnixMs};

/// The next chain after a key, with its oldest row: two index seeks. The
/// seek is on the whole primary key, past the last seq a chain can hold
/// (`MAX_SQL_INT`), so it never steps through the rows of the chain it
/// starts after.
pub const NEXT_CHAIN: &str = "SELECT p.tenant, p.chain, \
     (SELECT MIN(q.created_at) FROM pending_ops q WHERE q.tenant = p.tenant AND q.chain = p.chain) \
     FROM pending_ops p WHERE (p.tenant, p.chain, p.seq) > (?1, ?2, 9007199254740991) \
     ORDER BY p.tenant, p.chain, p.seq LIMIT 1";

/// The rows of one chain above a head, noted at or before a cutoff.
pub const DROP_ABOVE: &str = "DELETE FROM pending_ops WHERE tenant = ?1 AND chain = ?2 \
     AND seq > ?3 AND created_at <= ?4";

const ERR_PENDING_ROW: BridgeError = BridgeError::Invalid("pending row");

fn chain_code(chain: ControlChain) -> &'static str {
    match chain {
        ControlChain::Keys => "k",
        ControlChain::Tenant => "t",
    }
}

impl<S: Sql> PendingRows for SqlDirectory<'_, S> {
    async fn chains_after(
        &self,
        after: Option<&ChainKey>,
        limit: u32,
    ) -> Result<Vec<(ChainKey, UnixMs)>> {
        let mut out = Vec::new();
        // The key the next step starts after, as stored; the empty key
        // sorts before every row.
        let mut cursor: (String, String) = after.map_or((String::new(), String::new()), |c| {
            (
                c.tenant.as_str().to_string(),
                chain_code(c.chain).to_string(),
            )
        });
        while (out.len() as u32) < limit {
            let rows = self
                .sql
                .query(
                    NEXT_CHAIN,
                    &[
                        SqlValue::Text(cursor.0.clone()),
                        SqlValue::Text(cursor.1.clone()),
                    ],
                )
                .await?;
            let Some(row) = rows.into_iter().next() else {
                break;
            };
            let (tenant, chain, oldest) = match row.as_slice() {
                [SqlValue::Text(t), SqlValue::Text(c), SqlValue::Int(at)] => {
                    (t.clone(), c.clone(), *at)
                }
                _ => return Err(ERR_PENDING_ROW),
            };
            cursor = (tenant.clone(), chain.clone());
            let kind = match chain.as_str() {
                "k" => Some(ControlChain::Keys),
                "t" => Some(ControlChain::Tenant),
                _ => None,
            };
            // Any other row is stepped over: one index seek each, and the
            // age alarm keeps paging on it.
            if let (Ok(tenant), Some(chain)) = (TenantId::parse(&tenant), kind) {
                out.push((ChainKey { tenant, chain }, UnixMs(oldest)));
            }
        }
        Ok(out)
    }

    async fn drop_above(&self, chain: &ChainKey, head: u64, cutoff: UnixMs) -> Result<u32> {
        let n = self
            .sql
            .exec(
                DROP_ABOVE,
                &[
                    SqlValue::Text(chain.tenant.as_str().to_string()),
                    SqlValue::Text(chain_code(chain.chain).to_string()),
                    int(head)?,
                    SqlValue::Int(cutoff.0),
                ],
            )
            .await?;
        u32::try_from(n).map_err(|_| ERR_PENDING_ROW)
    }
}
