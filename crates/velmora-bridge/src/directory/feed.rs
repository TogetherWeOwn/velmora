//! The event feed of the management plane, in the directory
//! (`migrations-directory/0002_tenant_events.sql`, AM-37).
//!
//! One feed holds every tenant's events in `seq` order. A tenant reads its
//! own part, oldest first, with [`SqlDirectory::tenant_events`]: one range
//! of the `(tenant, seq)` index, at most [`MAX_EVENTS_PAGE`] rows. A
//! position is `(epoch, seq)` (`e<epoch>.<seq>` on the wire). The answer is
//! [`FeedReset`] when the position's epoch is not the feed's current one,
//! or when its seq is below the newest seq the prune removed of that
//! tenant's events: a poller never skips an event silently, and it reads
//! the tenant's state again instead.
//!
//! The feed's epoch is the directory gate's: a gate run starts a new one
//! at its step 8 ([`SqlDirectory::start_feed_epoch`]), and the rows of
//! every older epoch are not served again. Events are kept 30 days
//! ([`SqlDirectory::prune_events`]).
//!
//! Every statement here is a point read, one bounded range of an index or
//! of the primary key, or a write of one row; the receipt of the package
//! shows each plan.

use serde_json::{Map, Value};

use super::record::Tenant;
use super::store::{int, int_at, text, SqlDirectory};
use crate::ports::{Sql, SqlValue};
use crate::types::{BridgeError, Result, UnixMs};

/// The most events one read answers.
pub const MAX_EVENTS_PAGE: u32 = 1_000;

/// The most rows one prune step removes.
pub const MAX_PRUNE_ROWS: u32 = 1_000;

/// How long the feed keeps an event: 30 days.
pub const EVENT_KEEP_MS: i64 = 30 * 24 * 3_600_000;

/// The most bytes of an event's `data` as JSON.
pub const MAX_EVENT_DATA_BYTES: usize = 4_096;

/// The most bytes of an event's `source`.
pub const MAX_EVENT_SOURCE_BYTES: usize = 128;

/// A place in the feed: the last event a poller has, or the feed's head.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FeedPosition {
    pub epoch: u64,
    pub seq: u64,
}

/// An event to append.
#[derive(Clone, Debug, PartialEq)]
pub struct NewEvent {
    pub tenant: Tenant,
    /// The event type, `^[a-z_]+(\.[a-z_]+)+$`
    /// (`velmora_mgmt_types::wire::EVENT_TYPES`).
    pub kind: String,
    /// What the event is of, unique per tenant: `t/<seq>` for a tenant
    /// record, `k/<seq>` for a key record, and so on. A writer that repeats
    /// itself writes one row.
    pub source: String,
    pub at: UnixMs,
    /// Names `bucket_id` and `bucket` (the name) or `key_id` and
    /// `principal_id`: never a secret or a URL.
    pub data: Map<String, Value>,
}

/// An event as the feed holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct FeedEvent {
    pub epoch: u64,
    pub seq: u64,
    pub kind: String,
    pub at: UnixMs,
    pub data: Map<String, Value>,
}

/// A page of one tenant's events, oldest first. `position` is the last
/// item's position; with no item, `after` itself, or without `after` the
/// feed's head (never below the tenant's prune mark).
#[derive(Clone, Debug, PartialEq)]
pub struct EventPage {
    pub items: Vec<FeedEvent>,
    pub position: FeedPosition,
}

/// The position names an older epoch, or events the prune removed:
/// `409 feed_reset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeedReset;

/// What [`SqlDirectory::append_event`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Appended {
    /// The row is new.
    Appended,
    /// The tenant already has an event of this `source`: nothing written.
    Repeated,
}

const ERR_EVENT: BridgeError = BridgeError::Invalid("event");
const ERR_LIMIT: BridgeError = BridgeError::Invalid("event page limit");

// The statements are public for the plan checks of the tests and the
// receipt; nothing else runs them.

/// The feed's epoch, its base, the tenant's prune mark and the feed's
/// newest seq, in one read of one row each.
pub const FEED_STATE: &str = "SELECT \
     (SELECT epoch FROM feed_epoch WHERE id = 1), \
     (SELECT base_seq FROM feed_epoch WHERE id = 1), \
     (SELECT seq FROM tenant_feed_pruned WHERE tenant = ?1), \
     (SELECT MAX(seq) FROM tenant_events)";

/// One range of the `(tenant, seq)` index. The epoch filter only drops
/// rows that a new epoch wrote after the state was read, which are at
/// the top of the range.
pub const TENANT_RANGE: &str = "SELECT seq, epoch, type, at, data_json FROM tenant_events \
     WHERE tenant = ?1 AND seq > ?2 AND epoch = ?3 ORDER BY seq LIMIT ?4";

/// The epoch is read in the statement, so a row is never of an epoch that
/// started before it and below whose base it lies.
pub const APPEND: &str = "INSERT INTO tenant_events (epoch, tenant, type, source, at, data_json) \
     SELECT COALESCE((SELECT epoch FROM feed_epoch WHERE id = 1), 0), ?1, ?2, ?3, ?4, ?5 \
     WHERE 1 ON CONFLICT DO NOTHING";

/// Every row so far belongs to the older epochs.
pub const START_EPOCH: &str = "INSERT INTO feed_epoch (id, epoch, base_seq) \
     SELECT 1, ?1, COALESCE((SELECT MAX(seq) FROM tenant_events), 0) WHERE 1 \
     ON CONFLICT (id) DO UPDATE SET epoch = excluded.epoch, base_seq = excluded.base_seq \
     WHERE excluded.epoch > feed_epoch.epoch";

/// The oldest `?2` rows by the primary key, and the seq of the first one
/// that is not old enough. Every row the prune removes is below that one.
pub const PRUNE_CUT: &str = "SELECT MAX(seq), MIN(CASE WHEN at >= ?1 THEN seq END) FROM \
     (SELECT seq, at FROM tenant_events ORDER BY seq LIMIT ?2)";

/// `NOT INDEXED` keeps it on the key range: for the `GROUP BY` the
/// planner would otherwise scan the whole `(tenant, seq)` index.
pub const PRUNE_MARKS: &str = "INSERT INTO tenant_feed_pruned (tenant, seq) \
     SELECT tenant, MAX(seq) FROM tenant_events NOT INDEXED WHERE seq <= ?1 GROUP BY tenant \
     ON CONFLICT (tenant) DO UPDATE SET seq = excluded.seq WHERE excluded.seq > tenant_feed_pruned.seq";

pub const PRUNE_ROWS: &str = "DELETE FROM tenant_events WHERE seq <= ?1";

/// The shred's purge takes the oldest `?3` events of tenant `?1` at or
/// below seq `?2` (one range of the `(tenant, seq)` index), and raises the tenant's prune mark as the prune does.
pub const PURGE_MARK: &str = "INSERT INTO tenant_feed_pruned (tenant, seq) \
     SELECT ?1, m FROM (SELECT MAX(seq) AS m FROM \
     (SELECT seq FROM tenant_events WHERE tenant = ?1 AND seq <= ?2 ORDER BY seq LIMIT ?3)) \
     WHERE m IS NOT NULL \
     ON CONFLICT (tenant) DO UPDATE SET seq = excluded.seq WHERE excluded.seq > tenant_feed_pruned.seq";

pub const PURGE_ROWS: &str = "DELETE FROM tenant_events WHERE seq IN \
     (SELECT seq FROM tenant_events WHERE tenant = ?1 AND seq <= ?2 ORDER BY seq LIMIT ?3)";

/// `^[a-z_]+(\.[a-z_]+)+$`.
fn valid_event_type(s: &str) -> bool {
    let mut parts = 0;
    for part in s.split('.') {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            return false;
        }
        parts += 1;
    }
    parts >= 2
}

/// 1 to 128 bytes of ASCII letters, digits and `/_.:-`.
fn valid_source(s: &str) -> bool {
    (1..=MAX_EVENT_SOURCE_BYTES).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_.:-".contains(&b))
}

/// A field name that would carry a secret or a URL. The feed is read by
/// `kofra-api` and shown to customers; it names ids, never credentials.
fn forbidden_field(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "secret",
        "password",
        "token",
        "url",
        "signature",
        "credential",
    ]
    .iter()
    .any(|w| n.contains(w))
}

fn forbidden_anywhere(v: &Value) -> bool {
    match v {
        Value::Object(m) => m
            .iter()
            .any(|(k, v)| forbidden_field(k) || forbidden_anywhere(v)),
        Value::Array(a) => a.iter().any(forbidden_anywhere),
        _ => false,
    }
}

fn opt_u64(row: &[SqlValue], i: usize) -> Result<Option<u64>> {
    match row.get(i) {
        Some(SqlValue::Null) => Ok(None),
        Some(SqlValue::Int(v)) => u64::try_from(*v).map(Some).map_err(|_| ERR_EVENT),
        _ => Err(ERR_EVENT),
    }
}

/// The feed's state for `tenant`.
struct State {
    epoch: u64,
    base: u64,
    pruned: u64,
    newest: u64,
}

impl<S: Sql> SqlDirectory<'_, S> {
    async fn feed_state(&self, tenant: &Tenant) -> Result<State> {
        let rows = self
            .sql
            .query(FEED_STATE, &[SqlValue::Text(tenant.as_str().to_string())])
            .await?;
        let row = rows.first().ok_or(ERR_EVENT)?;
        Ok(State {
            epoch: opt_u64(row, 0)?.unwrap_or(0),
            base: opt_u64(row, 1)?.unwrap_or(0),
            pruned: opt_u64(row, 2)?.unwrap_or(0),
            newest: opt_u64(row, 3)?.unwrap_or(0),
        })
    }

    /// The feed's current epoch; 0 before the first gate run.
    pub async fn feed_epoch(&self) -> Result<u64> {
        let rows = self
            .sql
            .query("SELECT epoch FROM feed_epoch WHERE id = 1", &[])
            .await?;
        match rows.first() {
            None => Ok(0),
            Some(row) => u64::try_from(int_at(row, 0)?).map_err(|_| ERR_EVENT),
        }
    }

    /// Appends one event. The tenant's event of the same `source` stays as
    /// it is: [`Appended::Repeated`]. A malformed event, or one whose
    /// `data` names a field for a secret or a URL, is refused before any
    /// write.
    pub async fn append_event(&self, event: &NewEvent) -> Result<Appended> {
        if !valid_event_type(&event.kind) || !valid_source(&event.source) {
            return Err(ERR_EVENT);
        }
        let data = Value::Object(event.data.clone());
        if forbidden_anywhere(&data) {
            return Err(ERR_EVENT);
        }
        let json = serde_json::to_string(&data).map_err(|_| ERR_EVENT)?;
        if json.len() > MAX_EVENT_DATA_BYTES {
            return Err(ERR_EVENT);
        }
        let changed = self
            .sql
            .exec(
                APPEND,
                &[
                    SqlValue::Text(event.tenant.as_str().to_string()),
                    SqlValue::Text(event.kind.clone()),
                    SqlValue::Text(event.source.clone()),
                    SqlValue::Int(event.at.0),
                    SqlValue::Text(json),
                ],
            )
            .await?;
        Ok(match changed {
            0 => Appended::Repeated,
            _ => Appended::Appended,
        })
    }

    /// Up to `limit` (1 to [`MAX_EVENTS_PAGE`]) of `tenant`'s events after
    /// `after`, oldest first; without `after`, from the tenant's oldest
    /// kept event of the current epoch. Three bounded reads: the state,
    /// one index range, and the state again, so that an epoch started or a
    /// prune run in between answers [`FeedReset`] rather than a page with
    /// a hole in it.
    pub async fn tenant_events(
        &self,
        tenant: &Tenant,
        after: Option<FeedPosition>,
        limit: u32,
    ) -> Result<std::result::Result<EventPage, FeedReset>> {
        if !(1..=MAX_EVENTS_PAGE).contains(&limit) {
            return Err(ERR_LIMIT);
        }
        let state = self.feed_state(tenant).await?;
        let from = match after {
            Some(p) if p.epoch != state.epoch || p.seq < state.pruned => return Ok(Err(FeedReset)),
            Some(p) => p.seq.max(state.base),
            None => state.base.max(state.pruned),
        };
        let rows = self
            .sql
            .query(
                TENANT_RANGE,
                &[
                    SqlValue::Text(tenant.as_str().to_string()),
                    int(from)?,
                    int(state.epoch)?,
                    SqlValue::Int(i64::from(limit)),
                ],
            )
            .await?;
        let items = rows
            .iter()
            .map(|row| {
                let data = match serde_json::from_str(&text(row, 4)?) {
                    Ok(Value::Object(m)) => m,
                    _ => return Err(ERR_EVENT),
                };
                Ok(FeedEvent {
                    seq: u64::try_from(int_at(row, 0)?).map_err(|_| ERR_EVENT)?,
                    epoch: u64::try_from(int_at(row, 1)?).map_err(|_| ERR_EVENT)?,
                    kind: text(row, 2)?,
                    at: UnixMs(int_at(row, 3)?),
                    data,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        // A new epoch makes the page stale. After a position, a prune that
        // ran meanwhile may have removed rows of this range before the
        // read saw them. Without one, the read starts at the oldest kept
        // event, and a row the prune took is no longer kept.
        let again = self.feed_state(tenant).await?;
        if again.epoch != state.epoch || (after.is_some() && again.pruned > from) {
            return Ok(Err(FeedReset));
        }
        let position = match (items.last(), after) {
            (Some(last), _) => FeedPosition {
                epoch: state.epoch,
                seq: last.seq,
            },
            (None, Some(p)) => p,
            (None, None) => FeedPosition {
                epoch: state.epoch,
                seq: state.newest.max(state.base).max(state.pruned),
            },
        };
        Ok(Ok(EventPage { items, position }))
    }

    /// Starts the feed's epoch `epoch` (gate step 8, with the gate's
    /// epoch): every row written so far belongs to the older epochs. An
    /// epoch at or below the current one changes nothing: `false`.
    pub async fn start_feed_epoch(&self, epoch: u64) -> Result<bool> {
        // Epoch 0 is the feed before any gate run.
        if epoch == 0 {
            return Ok(false);
        }
        let changed = self.sql.exec(START_EPOCH, &[int(epoch)?]).await?;
        Ok(changed > 0)
    }

    /// One step of the 30-day prune: removes the oldest events written
    /// before `before`, at most `limit` (1 to [`MAX_PRUNE_ROWS`]), and
    /// raises each tenant's prune mark to the newest seq removed of it, in
    /// one batch. Returns the rows removed; fewer than `limit` = done for
    /// now. It removes a prefix of the feed only: it stops at the first
    /// row that is not old enough.
    pub async fn prune_events(&self, before: UnixMs, limit: u32) -> Result<u64> {
        if !(1..=MAX_PRUNE_ROWS).contains(&limit) {
            return Err(ERR_LIMIT);
        }
        let rows = self
            .sql
            .query(
                PRUNE_CUT,
                &[SqlValue::Int(before.0), SqlValue::Int(i64::from(limit))],
            )
            .await?;
        let row = rows.first().ok_or(ERR_EVENT)?;
        let cut = match (opt_u64(row, 0)?, opt_u64(row, 1)?) {
            (None, _) => return Ok(0),
            (Some(_), Some(young)) => young.saturating_sub(1),
            (Some(last), None) => last,
        };
        if cut == 0 {
            return Ok(0);
        }
        let changed = self
            .sql
            .batch(vec![
                (PRUNE_MARKS, vec![int(cut)?]),
                (PRUNE_ROWS, vec![int(cut)?]),
            ])
            .await?;
        Ok(changed.get(1).copied().unwrap_or(0))
    }
}

impl<S: Sql> SqlDirectory<'_, S> {
    /// One step of the shred's purge of `tenant`'s events (ADR §3.3): its
    /// oldest events at or below `through` (the seq before the final,
    /// name-free shred events), at most `limit` (1 to [`MAX_PRUNE_ROWS`]),
    /// with its prune mark raised in the same batch, so a position below
    /// them answers [`FeedReset`]. Returns the rows removed; fewer than
    /// `limit` = done. The event data names buckets, which the shred
    /// erases everywhere else with the tenant key.
    pub async fn purge_tenant_events(
        &self,
        tenant: &Tenant,
        through: u64,
        limit: u32,
    ) -> Result<u64> {
        if !(1..=MAX_PRUNE_ROWS).contains(&limit) {
            return Err(ERR_LIMIT);
        }
        let p = || {
            Ok::<_, BridgeError>(vec![
                SqlValue::Text(tenant.as_str().to_string()),
                int(through)?,
                SqlValue::Int(i64::from(limit)),
            ])
        };
        let changed = self
            .sql
            .batch(vec![(PURGE_MARK, p()?), (PURGE_ROWS, p()?)])
            .await?;
        Ok(changed.get(1).copied().unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_types_and_sources() {
        for ok in ["bucket.created", "tenant.deletion_scheduled", "a.b.c"] {
            assert!(valid_event_type(ok), "{ok}");
        }
        for bad in [
            "bucket",
            "Bucket.created",
            "bucket.",
            ".x",
            "a..b",
            "a.b1",
            "",
        ] {
            assert!(!valid_event_type(bad), "{bad}");
        }
        for ok in ["t/12", "k/9", "hour:2026-11-22T10:p_ab"] {
            assert!(valid_source(ok), "{ok}");
        }
        for bad in ["", "a b", "t/1?x", &"a".repeat(129)] {
            assert!(!valid_source(bad), "{bad}");
        }
    }

    #[test]
    fn no_field_names_a_secret_or_a_url() {
        let ok =
            serde_json::json!({"bucket_id": "b_1", "bucket": "photos", "key_id": "AK", "n": [1]});
        assert!(!forbidden_anywhere(&ok));
        for bad in [
            serde_json::json!({"secret_access_key": "x"}),
            serde_json::json!({"nested": {"presigned_url": "x"}}),
            serde_json::json!({"list": [{"Token": 1}]}),
        ] {
            assert!(forbidden_anywhere(&bad), "{bad}");
        }
    }
}
