//! `GET /v1/tenants/{t}/events?after=&limit=`: one tenant's part of the
//! event feed (`Tenancy::events`; R4-1 C4, AM-37).
//!
//! A read of the directory's feed (`directory::feed`, L3-D): one indexed
//! range of `(tenant, seq)`, at most `limit` rows (1 to 1,000, default
//! 100). The answer is `{items, position}`, oldest first; `position` is
//! never `null` (the last item's, `after` itself when nothing follows, or
//! the feed's head without `after`). A position of an older epoch, or below
//! the tenant's prune mark, answers `409 feed_reset`.
//!
//! The tenant must have a chain (`404 tenant_not_found` otherwise): the
//! head is read first, as the tenant read does; a shredding or shredded
//! tenant answers `409 tenant_unavailable` (AM-40). The directory gate
//! must be open (ADR §8.6). A directory that is not bound, a closed gate,
//! or a store that cannot be read answers `503`; a row that does not
//! read, or a head that does not verify, `500`. Event `data` is the feed's own
//! (it refuses secret-named fields when an event is written); it is
//! answered as stored.

use velmora_mgmt_types::position::EventPosition;
use velmora_mgmt_types::query::List;
use velmora_mgmt_types::wire::{Event, EventPage as WirePage};
use velmora_mgmt_types::Code;

use crate::directory::feed::{EventPage, FeedPosition, FeedReset};
use crate::directory::gate::is_open;
use crate::directory::record::{Lifecycle, Tenant};
use crate::directory::store::SqlDirectory;
use crate::mgmt::request::CallQuery;
use crate::mgmt::serve::Answer;
use crate::mgmt::tenant::TenantHeadRead;
use crate::ports::Sql;
use crate::records::RecordStore;
use crate::types::{BridgeError, Result};
use crate::unit::TenantId;

/// One tenant's events, as the directory's feed answers them, and the
/// directory gate the feed is served behind.
#[allow(async_fn_in_trait)]
pub trait TenantFeed {
    /// Whether the directory gate is open (ADR §8.6: after a restore or a
    /// rebuild the management plane answers `503` until the gate's steps
    /// are done; the feed may hold rows of another history until then).
    /// An `Err` is closed.
    async fn gate_open(&self) -> Result<bool>;
    async fn events(
        &self,
        tenant: &Tenant,
        after: Option<FeedPosition>,
        limit: u32,
    ) -> Result<std::result::Result<EventPage, FeedReset>>;
}

/// The directory's feed and its gate: the directory's store and the
/// records the gate's anchors are in (`SAFETY`).
pub struct GatedFeed<'a, S, Q> {
    pub records: &'a S,
    pub directory: SqlDirectory<'a, Q>,
}

impl<S: RecordStore, Q: Sql> TenantFeed for GatedFeed<'_, S, Q> {
    async fn gate_open(&self) -> Result<bool> {
        is_open(self.records, &self.directory).await
    }

    async fn events(
        &self,
        tenant: &Tenant,
        after: Option<FeedPosition>,
        limit: u32,
    ) -> Result<std::result::Result<EventPage, FeedReset>> {
        self.directory.tenant_events(tenant, after, limit).await
    }
}

/// The page of the answer; `None` when a stored time is before 1970
/// (damage: no correct writer stores one).
pub fn wire_page(page: EventPage) -> Option<WirePage> {
    let items = page
        .items
        .into_iter()
        .map(|e| {
            Some(Event {
                epoch: e.epoch,
                seq: e.seq,
                kind: e.kind,
                at_ms: u64::try_from(e.at.0).ok()?,
                data: e.data,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(WirePage {
        items,
        position: EventPosition {
            epoch: page.position.epoch,
            seq: page.position.seq,
        }
        .encode(),
    })
}

/// Runs the read. `query` is the call's checked query (a list whose
/// `after`, if any, the request checks parsed as an event position).
pub async fn read_events<H: TenantHeadRead, F: TenantFeed>(
    heads: &H,
    feed: Option<&F>,
    tenant: &str,
    query: &CallQuery,
) -> Answer {
    let Some(id) = TenantId::parse(tenant) else {
        return Answer::code(Code::TenantNotFound, None);
    };
    let CallQuery::List(List { after, limit }) = query else {
        return Answer::code(Code::InternalError, None);
    };
    let after = match after.as_deref().map(EventPosition::parse).transpose() {
        Ok(after) => after.map(|p| FeedPosition {
            epoch: p.epoch,
            seq: p.seq,
        }),
        Err(_) => return Answer::code(Code::InvalidPosition, None),
    };
    match heads.door(&id).await {
        Ok(Some(door)) => {
            let named = match &door.tenant {
                Tenant::Managed(t) => t.as_str() == id.as_str(),
                Tenant::Zero => false,
            };
            if !named {
                return Answer::code(Code::InternalError, None);
            }
            // AM-40: any call while shredding or shredded.
            if matches!(door.lifecycle, Lifecycle::Shredding | Lifecycle::Shredded) {
                return Answer::code(Code::TenantUnavailable, None);
            }
        }
        Ok(None) => return Answer::code(Code::TenantNotFound, None),
        Err(e) if crate::mgmt::adapters::head_damaged(&e) => {
            return Answer::code(Code::InternalError, None)
        }
        Err(_) => return Answer::code(Code::ServiceUnavailable, None),
    }
    let Some(feed) = feed else {
        return Answer::code(Code::ServiceUnavailable, None);
    };
    if !matches!(feed.gate_open().await, Ok(true)) {
        return Answer::code(Code::ServiceUnavailable, None);
    }
    let Some(managed) = crate::TenantId::parse(id.as_str()).ok() else {
        return Answer::code(Code::TenantNotFound, None);
    };
    match feed.events(&Tenant::Managed(managed), after, *limit).await {
        Ok(Ok(page)) => match wire_page(page).map(|p| serde_json::to_vec(&p)) {
            Some(Ok(json)) => Answer::json(200, json),
            _ => Answer::code(Code::InternalError, None),
        },
        Ok(Err(FeedReset)) => Answer::code(Code::FeedReset, None),
        // A row that does not read as an event: damage, `500` (pages).
        Err(BridgeError::Invalid(_)) => Answer::code(Code::InternalError, None),
        Err(_) => Answer::code(Code::ServiceUnavailable, None),
    }
}

/// The plane's tenant events over the head reader and the feed (`None`:
/// no directory bound).
pub struct TenantEventsHandler<'a, H, F> {
    pub heads: &'a H,
    pub feed: Option<&'a F>,
}

impl<H: TenantHeadRead, F: TenantFeed> crate::mgmt::serve::Handlers
    for TenantEventsHandler<'_, H, F>
{
    fn serves(&self, call: &crate::mgmt::route::Call) -> bool {
        matches!(call, crate::mgmt::route::Call::TenantEvents { .. })
    }

    async fn handle(&self, ctx: crate::mgmt::serve::CallContext<'_>, _body: &[u8]) -> Answer {
        let crate::mgmt::route::Call::TenantEvents { tenant } = &ctx.admitted.call else {
            return crate::mgmt::serve::not_built();
        };
        read_events(self.heads, self.feed, tenant, &ctx.checked.query).await
    }
}
