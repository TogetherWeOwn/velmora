//! Route records `m/kr/<akid>`: which tenant an access key id belongs to,
//! put once, before the key's chain record.
//!
//! A route never changes, so it can live in a put-once record
//! beside the directory's `key_routes` row. A Worker whose directory read
//! **failed** reads the route record instead; the unit still decides the
//! key's status. It is never read on
//! a directory answer of "no such key", and a missing record is never a
//! guess.
//!
//! The record holds no secret and is sealed with the control key alone,
//! because it is read before the tenant is known.

use serde::{Deserialize, Serialize};
use velmora::rng::FillRandom;

use super::record::SubjectKind;
use crate::crypto::scheme2::{parse_control, seal_control, ControlOwner, ControlSealer, TenantId};
use crate::ports::Kek;
use crate::records::RecordStore;
use crate::recovery::valid_key_id;
use crate::types::{BridgeError, Result};

/// The directory of route records.
pub const ROUTE_PREFIX: &str = "m/kr/";

const ERR_ROUTE: BridgeError = BridgeError::Invalid("route record is malformed");

/// The route record of `akid`.
pub fn route_name(akid: &str) -> String {
    format!("{ROUTE_PREFIX}{akid}")
}

/// What a route record says.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub access_key_id: String,
    pub tenant: String,
    pub kind: SubjectKind,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteBody {
    v: u32,
    route: Route,
}

/// The outcome of [`put_route`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutePut {
    /// The record names this tenant: written now, or by an earlier try.
    Ours,
    /// The id is routed to another tenant. The key must not be created.
    Taken,
}

/// Puts the route of `akid` to `tenant`, or finds it already there.
pub async fn put_route<S: RecordStore, K: Kek, R: FillRandom>(
    store: &S,
    kek: &K,
    tenant: &TenantId,
    akid: &str,
    kind: SubjectKind,
    at: u64,
    rng: &mut R,
) -> Result<RoutePut> {
    if !valid_key_id(akid) || !kind.has_secret() {
        return Err(ERR_ROUTE);
    }
    let name = route_name(akid);
    let body = serde_json::to_vec(&RouteBody {
        v: 1,
        route: Route {
            access_key_id: akid.to_owned(),
            tenant: tenant.as_str().to_owned(),
            kind,
            created_at: at,
        },
    })
    .map_err(|_| ERR_ROUTE)?;
    let sealed = seal_control(kek, &name, &ControlSealer::Global, &body, None, rng)?;
    let put = store.put_if_absent(&name, sealed).await;
    if let Ok(true) = put {
        return Ok(RoutePut::Ours);
    }
    // Lost, or the answer was lost: the stored record decides.
    match (read_route(store, kek, akid).await, put) {
        (Ok(Some(r)), _) if r.tenant == tenant.as_str() => Ok(RoutePut::Ours),
        (Ok(Some(_)), _) => Ok(RoutePut::Taken),
        (Ok(None), Err(e)) => Err(e),
        (Ok(None), Ok(_)) => Err(ERR_ROUTE),
        (Err(e), _) => Err(e),
    }
}

/// The route of `akid`; `None` when there is no record.
pub async fn read_route<S: RecordStore, K: Kek>(
    store: &S,
    kek: &K,
    akid: &str,
) -> Result<Option<Route>> {
    if !valid_key_id(akid) {
        return Ok(None);
    }
    let name = route_name(akid);
    let Some(bytes) = store.get(&name).await? else {
        return Ok(None);
    };
    let opened = parse_control(&bytes)?.open_door(kek, &name, ControlOwner::Global)?;
    let body: RouteBody = serde_json::from_slice(opened.door()).map_err(|_| ERR_ROUTE)?;
    if body.v != 1
        || body.route.access_key_id != akid
        || TenantId::parse(&body.route.tenant).is_err()
    {
        return Err(ERR_ROUTE);
    }
    Ok(Some(body.route))
}
