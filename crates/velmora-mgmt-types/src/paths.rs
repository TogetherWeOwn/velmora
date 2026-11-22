//! The paths of the contract, by call. Ids go in paths, never names; an
//! id of the wrong form (see [`crate::ids`]) makes a path that velmora
//! answers with `404 not_found`, so a caller checks ids before it builds
//! a path. Tenant 0 is not a tenant of this plane.
//!
//! | `kofra-api` call | Method and path | Scope, token |
//! |---|---|---|
//! | `Tenancy::create_tenant` | `POST /v1/tenants` | `tenants:create`, confirmed |
//! | `Tenancy::create_principal` | `POST /v1/tenants/{t}/principals` | `principals:write`, confirmed |
//! | `tenant` | `GET /v1/tenants/{t}` | `tenants:read` |
//! | `tenant_reach` | `GET /v1/tenants/{t}/reach` | `tenants:read` |
//! | `delete_tenant` | `DELETE /v1/tenants/{t}?hold_days=<n>` | `tenants:delete`, confirmed, with a confirmation record |
//! | `restore_tenant` | `POST /v1/tenants/{t}/restore` | `tenants:delete`, confirmed, with a confirmation record |
//! | `buckets` | `GET /v1/tenants/{t}/buckets?after=&limit=` | `tenants:read` |
//! | (name lookup) | `GET /v1/tenants/{t}/buckets?name=<n>[&name=…]` | `tenants:read` |
//! | `bucket` | `GET /v1/tenants/{t}/buckets/{b}` | `tenants:read` |
//! | `create_bucket` | `POST /v1/tenants/{t}/buckets` | `buckets:write` |
//! | `delete_bucket` | `DELETE /v1/tenants/{t}/buckets/{b}` | `buckets:delete`, confirmed |
//! | `keys` | `GET /v1/tenants/{t}/keys?kind=&after=&limit=` | `tenants:read` |
//! | `key` | `GET /v1/tenants/{t}/keys/{k}` | `tenants:read` |
//! | `create_key` | `POST /v1/tenants/{t}/keys` | `keys:write` if every grant is `ro`; `keys:write_rw`, confirmed, otherwise |
//! | `update_key` | `PATCH /v1/tenants/{t}/keys/{k}` | `keys:write` for a rename or a narrowing; `principals:write`, confirmed, for a widening |
//! | `revoke_key` | `DELETE /v1/tenants/{t}/keys/{k}` | `keys:write` |
//! | `usage` | `GET /v1/tenants/{t}/usage` | `usage:read` |
//! | `usage_days` | `GET /v1/tenants/{t}/usage/days?after_day=&after=&limit=` | `usage:read` |
//! | `usage_buckets` | `GET /v1/tenants/{t}/usage/buckets?after=&limit=` | `usage:read` |
//! | `events` | `GET /v1/tenants/{t}/events?after=&limit=` | `events:read` |
//! | `objects` | `POST /v1/tenants/{t}/objects/list` | `objects:list` |
//! | `presign` | `POST /v1/tenants/{t}/objects/presign` | `objects:presign_read` |
//!
//! "Confirmed" is the confirmed service token; every other call takes the
//! standard one. Velmora checks the scope only: `kofra-api` picks the
//! class, so a velmora `insufficient_scope` is always a `kofra-api` fault.

/// The prefix of every path of the plane.
pub const PREFIX: &str = "/v1";

pub fn tenants() -> String {
    format!("{PREFIX}/tenants")
}

pub fn tenant(t: &str) -> String {
    format!("{PREFIX}/tenants/{t}")
}

/// A tenant delete, with its hold.
pub fn tenant_delete(t: &str, hold_days: u32) -> String {
    format!("{PREFIX}/tenants/{t}?hold_days={hold_days}")
}

pub fn tenant_restore(t: &str) -> String {
    format!("{PREFIX}/tenants/{t}/restore")
}

pub fn tenant_reach(t: &str) -> String {
    format!("{PREFIX}/tenants/{t}/reach")
}

pub fn principals(t: &str) -> String {
    format!("{PREFIX}/tenants/{t}/principals")
}

pub fn buckets(t: &str) -> String {
    format!("{PREFIX}/tenants/{t}/buckets")
}

pub fn bucket(t: &str, b: &str) -> String {
    format!("{PREFIX}/tenants/{t}/buckets/{b}")
}

pub fn keys(t: &str) -> String {
    format!("{PREFIX}/tenants/{t}/keys")
}

pub fn key(t: &str, k: &str) -> String {
    format!("{PREFIX}/tenants/{t}/keys/{k}")
}

pub fn usage(t: &str) -> String {
    format!("{PREFIX}/tenants/{t}/usage")
}

pub fn usage_days(t: &str) -> String {
    format!("{PREFIX}/tenants/{t}/usage/days")
}

pub fn usage_buckets(t: &str) -> String {
    format!("{PREFIX}/tenants/{t}/usage/buckets")
}

pub fn events(t: &str) -> String {
    format!("{PREFIX}/tenants/{t}/events")
}

pub fn objects_list(t: &str) -> String {
    format!("{PREFIX}/tenants/{t}/objects/list")
}

pub fn objects_presign(t: &str) -> String {
    format!("{PREFIX}/tenants/{t}/objects/presign")
}

/// `path` with `query` appended (`?query`), or `path` alone when the
/// query is empty.
pub fn with_query(path: String, query: &str) -> String {
    if query.is_empty() {
        path
    } else {
        format!("{path}?{query}")
    }
}
