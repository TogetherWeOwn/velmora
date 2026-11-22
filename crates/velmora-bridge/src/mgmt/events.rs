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
//! head is read first, as the tenant read does. A directory that is not
//! bound or cannot be read answers `503`. Event `data` is the feed's own
//! (it refuses secret-named fields when an event is written); it is
//! answered as stored.

use velmora_mgmt_types::position::EventPosition;
use velmora_mgmt_types::query::List;
use velmora_mgmt_types::wire::{Event, EventPage as WirePage};
use velmora_mgmt_types::Code;

use crate::directory::feed::{EventPage, FeedPosition, FeedReset};
use crate::directory::record::Tenant;
use crate::directory::store::SqlDirectory;
use crate::mgmt::request::CallQuery;
use crate::mgmt::serve::Answer;
use crate::mgmt::tenant::TenantHeadRead;
use crate::ports::Sql;
use crate::types::Result;
use crate::unit::TenantId;

/// One tenant's events, as the directory's feed answers them.
#[allow(async_fn_in_trait)]
pub trait TenantFeed {
    async fn events(
        &self,
        tenant: &Tenant,
        after: Option<FeedPosition>,
        limit: u32,
    ) -> Result<std::result::Result<EventPage, FeedReset>>;
}

impl<S: Sql> TenantFeed for SqlDirectory<'_, S> {
    async fn events(
        &self,
        tenant: &Tenant,
        after: Option<FeedPosition>,
        limit: u32,
    ) -> Result<std::result::Result<EventPage, FeedReset>> {
        self.tenant_events(tenant, after, limit).await
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
        Ok(Some(_)) => {}
        Ok(None) => return Answer::code(Code::TenantNotFound, None),
        Err(_) => return Answer::code(Code::ServiceUnavailable, None),
    }
    let Some(feed) = feed else {
        return Answer::code(Code::ServiceUnavailable, None);
    };
    let Some(managed) = crate::TenantId::parse(id.as_str()).ok() else {
        return Answer::code(Code::TenantNotFound, None);
    };
    match feed.events(&Tenant::Managed(managed), after, *limit).await {
        Ok(Ok(page)) => match wire_page(page).map(|p| serde_json::to_vec(&p)) {
            Some(Ok(json)) => Answer::json(200, json),
            _ => Answer::code(Code::InternalError, None),
        },
        Ok(Err(FeedReset)) => Answer::code(Code::FeedReset, None),
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
