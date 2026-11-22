//! The paths of the contract, by call. Ids go in paths, never names. A
//! builder that takes an id answers `None` for an id that is not of its
//! form ([`crate::ids`]), so no text from elsewhere becomes part of a
//! path (a `../` or a `?` in a key id could otherwise name another
//! tenant's path). Tenant 0 is not a tenant of this plane.
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
//! | `key` | `GET /v1/tenants/{t}/keys/{k}` (a principal id: `404 key_not_found`; the internal key: `403 internal_key_refused`) | `tenants:read` |
//! | `create_key` | `POST /v1/tenants/{t}/keys` | `keys:write` if every grant is `ro`; `keys:write_rw`, confirmed, otherwise |
//! | `update_key` | `PATCH /v1/tenants/{t}/keys/{k}` | `keys:write` for a rename or a narrowing; `principals:write`, confirmed, for a widening |
//! | `revoke_key` | `DELETE /v1/tenants/{t}/keys/{k}` (a repeat answers `204`; a principal id `404 key_not_found`, writing nothing; the internal key `403 internal_key_refused`) | `keys:write` |
//! | `usage` | `GET /v1/tenants/{t}/usage` | `usage:read` |
//! | `usage_days` | `GET /v1/tenants/{t}/usage/days?after_day=&after=&limit=` | `usage:read` |
//! | `usage_buckets` | `GET /v1/tenants/{t}/usage/buckets?after=&limit=` | `usage:read` |
//! | `events` | `GET /v1/tenants/{t}/events?after=&limit=` | `events:read` |
//! | `objects` | `POST /v1/tenants/{t}/objects/list` | `objects:list` |
//! | `presign` | `POST /v1/tenants/{t}/objects/presign` | `objects:presign_read` |
//!
//! "Confirmed" is the confirmed service token; every other call takes the
//! standard one. The plane checks the scope only: `kofra-api` picks the
//! class, so the plane's `insufficient_scope` is always a `kofra-api`
//! fault.

use crate::ids::{valid_bucket_id, valid_key_id, valid_tenant_id};

/// The prefix of every path of the plane.
pub const PREFIX: &str = "/v1";

pub fn tenants() -> String {
    format!("{PREFIX}/tenants")
}

/// `/v1/tenants/{t}` and `rest`, for a tenant id of its form.
fn under(t: &str, rest: &str) -> Option<String> {
    valid_tenant_id(t).then(|| format!("{PREFIX}/tenants/{t}{rest}"))
}

pub fn tenant(t: &str) -> Option<String> {
    under(t, "")
}

/// A tenant delete, with its hold.
pub fn tenant_delete(t: &str, hold_days: u32) -> Option<String> {
    under(t, &format!("?hold_days={hold_days}"))
}

pub fn tenant_restore(t: &str) -> Option<String> {
    under(t, "/restore")
}

pub fn tenant_reach(t: &str) -> Option<String> {
    under(t, "/reach")
}

pub fn principals(t: &str) -> Option<String> {
    under(t, "/principals")
}

pub fn buckets(t: &str) -> Option<String> {
    under(t, "/buckets")
}

pub fn bucket(t: &str, b: &str) -> Option<String> {
    under(t, &format!("/buckets/{b}")).filter(|_| valid_bucket_id(b))
}

pub fn keys(t: &str) -> Option<String> {
    under(t, "/keys")
}

pub fn key(t: &str, k: &str) -> Option<String> {
    under(t, &format!("/keys/{k}")).filter(|_| valid_key_id(k))
}

pub fn usage(t: &str) -> Option<String> {
    under(t, "/usage")
}

pub fn usage_days(t: &str) -> Option<String> {
    under(t, "/usage/days")
}

pub fn usage_buckets(t: &str) -> Option<String> {
    under(t, "/usage/buckets")
}

pub fn events(t: &str) -> Option<String> {
    under(t, "/events")
}

pub fn objects_list(t: &str) -> Option<String> {
    under(t, "/objects/list")
}

pub fn objects_presign(t: &str) -> Option<String> {
    under(t, "/objects/presign")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_builder_takes_only_ids_of_their_form() {
        let t = "t_1a2b3c4d5e6f7a8b";
        assert_eq!(
            key(t, "VKEXAMPLE0000001").as_deref(),
            Some("/v1/tenants/t_1a2b3c4d5e6f7a8b/keys/VKEXAMPLE0000001")
        );
        assert_eq!(key(t, "../../t_0123456789abcdef/keys/K"), None);
        assert_eq!(key(t, "K?x=1"), None);
        assert_eq!(bucket(t, "photos"), None);
        assert_eq!(bucket(t, "b_00aa11bb22cc33dd/../x"), None);
        assert_eq!(tenant("t_0000000000000000"), None);
        assert_eq!(tenant("../x"), None);
        assert_eq!(events("t_1A2B3C4D5E6F7A8B"), None);
    }
}
