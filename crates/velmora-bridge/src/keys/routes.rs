//! Route records `m/kr/<akid>`: which tenant an access key id belongs to,
//! put once, before the key's chain record.
//!
//! A route changes only in the owner move and its undo, which replace the
//! record conditioned on the ETag they read ([`replace_route`]), so it
//! lives in a record beside the directory's `key_routes` row that is
//! otherwise put once. A Worker whose directory read
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
use crate::records::{RecordStore, Tagged};
use crate::recovery::{valid_key_id, DEFAULT_TENANT};
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
    let sealed = seal_route(
        kek,
        &Route {
            access_key_id: akid.to_owned(),
            tenant: tenant.as_str().to_owned(),
            kind,
            created_at: at,
        },
        rng,
    )?;
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
    let Some(bytes) = store.get(&route_name(akid)).await? else {
        return Ok(None);
    };
    open_route(kek, akid, &bytes).map(Some)
}

/// How many times [`replace_route`] reads and replaces before it gives up
/// on a record that keeps changing under it.
pub const REPLACE_TRIES: u32 = 4;

/// The conditional replace of the owner move and its undo (ADR addendum
/// §2.2, DS1 §3.4 step 8(c) and §3.7): the route record of `akid` that
/// names `from` is replaced, conditioned on the ETag it was read with, by
/// one that names `to` with `kind` (the key's directory row; a later
/// window's keymap may change it) and keeps the record's `created_at`.
/// `from` and `to` are tenant ids as the record stores them: a managed
/// tenant's, or tenant 0's ([`DEFAULT_TENANT`]), which the undo and the
/// give-up put routes back to.
///
/// `Ok(true)`: the record names `to` with `kind`, replaced by this call or
/// found so (a retry, or a record that names `to` with another kind is
/// replaced to `kind`). `Ok(false)`: no record exists, or it names a
/// third tenant; nothing is written. A record that does not open, or
/// that names another key id, is an `Err`, and nothing is written. A
/// replace whose answer was lost is read back: the stored record decides.
/// A record that still needs the replace after [`REPLACE_TRIES`] tries is an
/// `Err`. Tenant 0 must be on exactly one side (the move or its undo);
/// anything else is an `Err` before any read.
pub async fn replace_route<S: RecordStore, K: Kek, R: FillRandom>(
    store: &S,
    kek: &K,
    akid: &str,
    from: &str,
    to: &str,
    kind: SubjectKind,
    rng: &mut R,
) -> Result<bool> {
    // Only the move and its undo replace a route: tenant 0 on exactly one
    // side (ADR addendum §2.2, "the only overwrite").
    let one_side_zero = (from == DEFAULT_TENANT) != (to == DEFAULT_TENANT);
    if !valid_key_id(akid)
        || !kind.has_secret()
        || !route_tenant(from)
        || !route_tenant(to)
        || !one_side_zero
    {
        return Err(ERR_ROUTE);
    }
    let name = route_name(akid);
    let mut last_err = None;
    // Every try reads first; one more read after the last try settles a
    // lost answer there.
    for tried in 0..=REPLACE_TRIES {
        let Some(Tagged { bytes, etag }) = store.get_tagged(&name).await? else {
            return Ok(false);
        };
        let route = open_route(kek, akid, &bytes)?;
        if route.tenant == to && route.kind == kind {
            return Ok(true);
        }
        if route.tenant != to && route.tenant != from {
            return Ok(false);
        }
        if tried == REPLACE_TRIES {
            break;
        }
        let sealed = seal_route(
            kek,
            &Route {
                access_key_id: akid.to_owned(),
                tenant: to.to_owned(),
                kind,
                created_at: route.created_at,
            },
            rng,
        )?;
        match store.replace_if_match(&name, &etag, sealed).await {
            Ok(true) => return Ok(true),
            // Lost to another write, or the answer was lost: read again.
            Ok(false) => last_err = None,
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or(ERR_ROUTE_CHANGING))
}

const ERR_ROUTE_CHANGING: BridgeError = BridgeError::Invalid("route record keeps changing");

fn seal_route<K: Kek, R: FillRandom>(kek: &K, route: &Route, rng: &mut R) -> Result<Vec<u8>> {
    let name = route_name(&route.access_key_id);
    let body = serde_json::to_vec(&RouteBody {
        v: 1,
        route: route.clone(),
    })
    .map_err(|_| ERR_ROUTE)?;
    seal_control(kek, &name, &ControlSealer::Global, &body, None, rng)
}

fn open_route<K: Kek>(kek: &K, akid: &str, bytes: &[u8]) -> Result<Route> {
    let name = route_name(akid);
    let opened = parse_control(bytes)?.open_door(kek, &name, ControlOwner::Global)?;
    let body: RouteBody = serde_json::from_slice(opened.door()).map_err(|_| ERR_ROUTE)?;
    if body.v != 1 || body.route.access_key_id != akid || !route_tenant(&body.route.tenant) {
        return Err(ERR_ROUTE);
    }
    Ok(body.route)
}

/// A tenant a route may name: a managed tenant, or tenant 0 (only after
/// the undo or a give-up put it back; a key is never created with a route
/// to tenant 0).
fn route_tenant(tenant: &str) -> bool {
    tenant == DEFAULT_TENANT || TenantId::parse(tenant).is_ok()
}
