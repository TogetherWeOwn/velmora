//! The global backstops per service token in the directory (ADR §6.3,
//! AM-75 / L5-C7): one counter row per token, action and window.
//!
//! [`SqlDirectory::take_token_cap`] takes one slot of a window in one
//! statement: it counts up only while the count is below the cap, so two
//! calls that race never pass the cap together. The window is the
//! caller's (a day for tenant create: `day_window`). A failed take says
//! nothing about the count; the caller answers `503` (§6.3, "fails
//! closed"). Old windows are removed by [`SqlDirectory::prune_token_caps`],
//! one range of the primary key.

use super::store::SqlDirectory;
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result, UnixMs};

/// The action of the tenant-create backstop.
pub const TENANT_CREATE: &str = "tenant_create";

/// The most rows one prune removes.
pub const MAX_PRUNE_CAPS: u32 = 1_000;

/// What a take did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapTake {
    /// One slot was taken; `count` slots of the window are taken now (for
    /// the alarm at a share of the cap).
    Taken { count: u32 },
    /// The window is full: nothing changed.
    Full,
}

/// The start of the UTC day of `now`, in ms: the window of a daily cap.
pub fn day_window(now: UnixMs) -> i64 {
    now.0 - now.0.rem_euclid(24 * 3_600_000)
}

/// Counts one slot up while fewer than `?4` are taken.
pub const TAKE_CAP: &str = "INSERT INTO token_caps (window_start, token, action, count) \
     SELECT ?1, ?2, ?3, 1 WHERE ?4 > 0 \
     ON CONFLICT (window_start, token, action) DO UPDATE SET count = token_caps.count + 1 \
     WHERE token_caps.count < ?4";

/// The count of one window: a point read of the key.
pub const CAP_COUNT: &str =
    "SELECT count FROM token_caps WHERE window_start = ?1 AND token = ?2 AND action = ?3";

/// The oldest windows' rows: one range of the key.
pub const PRUNE_CAPS: &str = "DELETE FROM token_caps WHERE rowid IN \
     (SELECT rowid FROM token_caps WHERE window_start < ?1 ORDER BY window_start LIMIT ?2)";

const ERR_CAP: BridgeError = BridgeError::Invalid("token cap");

/// 1 to 64 bytes of ASCII letters, digits and `_.:-`.
fn valid_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

impl<S: Sql> SqlDirectory<'_, S> {
    /// Takes one slot of `token`'s `action` in the window starting at
    /// `window_start`, if fewer than `cap` are taken. `token` and `action`
    /// are 1 to 64 bytes of ASCII letters, digits and `_.:-`.
    pub async fn take_token_cap(
        &self,
        token: &str,
        action: &str,
        window_start: i64,
        cap: u32,
    ) -> Result<CapTake> {
        if !valid_name(token) || !valid_name(action) {
            return Err(ERR_CAP);
        }
        let key = [
            SqlValue::Int(window_start),
            SqlValue::Text(token.to_string()),
            SqlValue::Text(action.to_string()),
        ];
        let mut params = key.to_vec();
        params.push(SqlValue::Int(i64::from(cap)));
        if self.sql.exec(TAKE_CAP, &params).await? == 0 {
            return Ok(CapTake::Full);
        }
        let rows = self.sql.query(CAP_COUNT, &key).await?;
        let count = match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Int(n)) => u32::try_from(*n).map_err(|_| ERR_CAP)?,
            _ => return Err(ERR_CAP),
        };
        Ok(CapTake::Taken { count })
    }

    /// Removes up to `limit` (1 to [`MAX_PRUNE_CAPS`]) rows of windows
    /// that start before `before`; answers how many.
    pub async fn prune_token_caps(&self, before: i64, limit: u32) -> Result<u64> {
        if !(1..=MAX_PRUNE_CAPS).contains(&limit) {
            return Err(ERR_CAP);
        }
        self.sql
            .exec(
                PRUNE_CAPS,
                &[SqlValue::Int(before), SqlValue::Int(i64::from(limit))],
            )
            .await
    }
}
