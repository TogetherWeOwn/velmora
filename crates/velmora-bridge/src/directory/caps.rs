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
use crate::ports::Sql;
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
        let _ = (token, action, window_start, cap);
        Err(BridgeError::NotImplemented("take_token_cap"))
    }

    /// Removes up to `limit` (1 to [`MAX_PRUNE_CAPS`]) rows of windows
    /// that start before `before`; answers how many.
    pub async fn prune_token_caps(&self, before: i64, limit: u32) -> Result<u64> {
        let _ = (before, limit);
        Err(BridgeError::NotImplemented("prune_token_caps"))
    }
}
