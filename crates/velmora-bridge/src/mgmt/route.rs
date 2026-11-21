//! The calls of the management plane and the paths they are served on.
//!
//! A pure table: a method and a path give a [`Call`], or a refusal. Each
//! call names the **least** scope it needs ([`Call::scope`]). Where the
//! body decides more (a key that can write, a presign for an overwrite,
//! a bucket made public, a grant that widens), the handler asks for the
//! wider scope as well, after it has read the body; the table never
//! lowers what a handler asks for.
//!
//! Every path but tenant create and the event feed names its tenant.
//! **Tenant 0 is not a tenant of this plane**: a path that names it is
//! refused like a path that names no tenant, before any token is
//! checked against it. Ids are checked for form here, so that nothing
//! that is not an id reaches a handler.
//!
//! | Method | Path | Call | Least scope |
//! |---|---|---|---|
//! | GET | `/v1/tenants` | tenant list (`?external_ref=`; never tenant 0) | `tenants:read` |
//! | POST | `/v1/tenants` | tenant create | `tenants:create` |
//! | GET | `/v1/tenants/{t}` | tenant read | `tenants:read` |
//! | DELETE | `/v1/tenants/{t}` | delete request (hold of 7 days or more) | `tenants:delete` |
//! | POST | `/v1/tenants/{t}/restore` | undo of the customer's own delete request | `tenants:delete` |
//! | GET, POST | `/v1/tenants/{t}/buckets` | list, create | `tenants:read`, `buckets:write` |
//! | PATCH, DELETE | `/v1/tenants/{t}/buckets/{b}` | settings, delete an empty bucket | `buckets:write`, `buckets:delete` |
//! | GET, POST | `/v1/tenants/{t}/keys` | list, create a key or an app password | `tenants:read`, `keys:write` |
//! | PATCH, DELETE | `/v1/tenants/{t}/keys/{k}` | grant change, revoke | `keys:write` |
//! | POST | `/v1/tenants/{t}/keys/{k}/disable` | disable | `keys:write` |
//! | POST | `/v1/tenants/{t}/principals` | create | `principals:write` |
//! | PATCH, DELETE | `/v1/tenants/{t}/principals/{p}` | grant change, revoke | `keys:write` |
//! | POST | `/v1/tenants/{t}/principals/{p}/disable` | disable | `keys:write` |
//! | POST | `/v1/tenants/{t}/objects/presign` | `objects.presign` | `objects:presign_read` |
//! | POST | `/v1/tenants/{t}/objects/list` | `objects.list` | `objects:list` |
//! | POST | `/v1/tenants/{t}/objects/delete` | `objects.delete` | `objects:delete` |
//! | POST | `/v1/tenants/{t}/uploads` | `objects.multipart_create` | `objects:create` |
//! | POST | `/v1/tenants/{t}/uploads/{u}/complete` | `objects.multipart_complete` | `objects:create` |
//! | DELETE | `/v1/tenants/{t}/uploads/{u}` | `objects.multipart_abort` | `objects:create` |
//! | GET | `/v1/tenants/{t}/uploads/{u}/parts` | `objects.multipart_parts` | `objects:list` |
//! | GET | `/v1/tenants/{t}/usage` | usage totals | `usage:read` |
//! | GET | `/v1/tenants/{t}/usage/days`, `/v1/tenants/{t}/usage/downloads` | usage by day, downloads | `usage:read` |
//! | GET | `/v1/events` | the event feed (`?after=`) | `events:read` |
//!
//! The paths are a proposal of this package for the contract with
//! `kofra-api`; the call list and the scopes are the tenancy design's.

use crate::mgmt::token::Scope;
use crate::recovery::{valid_key_id, DEFAULT_TENANT};

/// The prefix of every management path.
pub const PREFIX: &str = "/v1";

/// One call of the management plane, with the ids its path names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    TenantList,
    TenantCreate,
    TenantRead { tenant: String },
    TenantDelete { tenant: String },
    TenantRestore { tenant: String },
    BucketList { tenant: String },
    BucketCreate { tenant: String },
    BucketUpdate { tenant: String, bucket: String },
    BucketDelete { tenant: String, bucket: String },
    KeyList { tenant: String },
    KeyCreate { tenant: String },
    KeyUpdate { tenant: String, key: String },
    KeyRevoke { tenant: String, key: String },
    KeyDisable { tenant: String, key: String },
    PrincipalCreate { tenant: String },
    PrincipalUpdate { tenant: String, principal: String },
    PrincipalRevoke { tenant: String, principal: String },
    PrincipalDisable { tenant: String, principal: String },
    Presign { tenant: String },
    ObjectList { tenant: String },
    ObjectDelete { tenant: String },
    UploadCreate { tenant: String },
    UploadComplete { tenant: String, upload: String },
    UploadAbort { tenant: String, upload: String },
    UploadParts { tenant: String, upload: String },
    Usage { tenant: String },
    UsageDays { tenant: String },
    UsageDownloads { tenant: String },
    Events,
}

impl Call {
    /// The least scope of the call. See the [module](self).
    pub fn scope(&self) -> Scope {
        use Call::*;
        match self {
            TenantCreate => Scope::TenantsCreate,
            TenantList | TenantRead { .. } | BucketList { .. } | KeyList { .. } => {
                Scope::TenantsRead
            }
            TenantDelete { .. } | TenantRestore { .. } => Scope::TenantsDelete,
            BucketCreate { .. } | BucketUpdate { .. } => Scope::BucketsWrite,
            BucketDelete { .. } => Scope::BucketsDelete,
            KeyCreate { .. }
            | KeyUpdate { .. }
            | KeyRevoke { .. }
            | KeyDisable { .. }
            | PrincipalUpdate { .. }
            | PrincipalRevoke { .. }
            | PrincipalDisable { .. } => Scope::KeysWrite,
            PrincipalCreate { .. } => Scope::PrincipalsWrite,
            Presign { .. } => Scope::ObjectsPresignRead,
            ObjectList { .. } | UploadParts { .. } => Scope::ObjectsList,
            ObjectDelete { .. } => Scope::ObjectsDelete,
            UploadCreate { .. } | UploadComplete { .. } | UploadAbort { .. } => {
                Scope::ObjectsCreate
            }
            Usage { .. } | UsageDays { .. } | UsageDownloads { .. } => Scope::UsageRead,
            Events => Scope::EventsRead,
        }
    }

    /// A closing call: it only takes something away (a revoke, a
    /// disable, an abort). It is never capped and needs no directory row. A grant
    /// change is closing only when the unit finds it a narrowing, which
    /// the table cannot know, so it is not listed here.
    pub fn closing(&self) -> bool {
        matches!(
            self,
            Call::KeyRevoke { .. }
                | Call::KeyDisable { .. }
                | Call::PrincipalRevoke { .. }
                | Call::PrincipalDisable { .. }
                | Call::UploadAbort { .. }
        )
    }

    /// The tenant the path names; `None` for the tenant list, tenant
    /// create and the feed.
    pub fn tenant(&self) -> Option<&str> {
        use Call::*;
        match self {
            TenantList | TenantCreate | Events => None,
            TenantRead { tenant }
            | TenantDelete { tenant }
            | TenantRestore { tenant }
            | BucketList { tenant }
            | BucketCreate { tenant }
            | BucketUpdate { tenant, .. }
            | BucketDelete { tenant, .. }
            | KeyList { tenant }
            | KeyCreate { tenant }
            | KeyUpdate { tenant, .. }
            | KeyRevoke { tenant, .. }
            | KeyDisable { tenant, .. }
            | PrincipalCreate { tenant }
            | PrincipalUpdate { tenant, .. }
            | PrincipalRevoke { tenant, .. }
            | PrincipalDisable { tenant, .. }
            | Presign { tenant }
            | ObjectList { tenant }
            | ObjectDelete { tenant }
            | UploadCreate { tenant }
            | UploadComplete { tenant, .. }
            | UploadAbort { tenant, .. }
            | UploadParts { tenant, .. }
            | Usage { tenant }
            | UsageDays { tenant }
            | UsageDownloads { tenant } => Some(tenant),
        }
    }
}

/// Why a path is no call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoCall {
    /// No call has this path, or an id in it is not an id, or it names
    /// tenant 0: `404`, the same answer for each.
    NotFound,
    /// The path is a call's, the method is not: `405`.
    Method,
}

impl NoCall {
    pub fn status(self) -> u16 {
        match self {
            NoCall::NotFound => 404,
            NoCall::Method => 405,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            NoCall::NotFound => "not_found",
            NoCall::Method => "method_not_allowed",
        }
    }
}

/// Whether `path` (no query) is under the management prefix: `/v1` or
/// `/v1/...`. The public handler refuses every such path.
pub fn is_management_path(path: &str) -> bool {
    path == PREFIX
        || path
            .strip_prefix(PREFIX)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The call of `method` on `path`. `path` is the decoded path without
/// its query. A trailing `/` is not the same path.
pub fn route(method: &str, path: &str) -> Result<Call, NoCall> {
    let rest = path.strip_prefix("/v1/").ok_or(NoCall::NotFound)?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(NoCall::NotFound);
    }
    let t = |s: &str| tenant_id(s).map(str::to_string).ok_or(NoCall::NotFound);
    let id = |s: &str, ok: fn(&str) -> bool| ok(s).then(|| s.to_string()).ok_or(NoCall::NotFound);
    // The call of the method on the path; `None`: the path is a call's,
    // the method is not.
    let call: Option<Call> = match parts.as_slice() {
        ["events"] => (method == "GET").then_some(Call::Events),
        ["tenants"] => match method {
            "GET" => Some(Call::TenantList),
            "POST" => Some(Call::TenantCreate),
            _ => None,
        },
        ["tenants", tn] => {
            let tenant = t(tn)?;
            match method {
                "GET" => Some(Call::TenantRead { tenant }),
                "DELETE" => Some(Call::TenantDelete { tenant }),
                _ => None,
            }
        }
        ["tenants", tn, "restore"] => {
            let tenant = t(tn)?;
            (method == "POST").then_some(Call::TenantRestore { tenant })
        }
        ["tenants", tn, "buckets"] => {
            let tenant = t(tn)?;
            match method {
                "GET" => Some(Call::BucketList { tenant }),
                "POST" => Some(Call::BucketCreate { tenant }),
                _ => None,
            }
        }
        ["tenants", tn, "buckets", b] => {
            let (tenant, bucket) = (t(tn)?, id(b, bucket_id)?);
            match method {
                "PATCH" => Some(Call::BucketUpdate { tenant, bucket }),
                "DELETE" => Some(Call::BucketDelete { tenant, bucket }),
                _ => None,
            }
        }
        ["tenants", tn, "keys"] => {
            let tenant = t(tn)?;
            match method {
                "GET" => Some(Call::KeyList { tenant }),
                "POST" => Some(Call::KeyCreate { tenant }),
                _ => None,
            }
        }
        ["tenants", tn, "keys", k] => {
            let (tenant, key) = (t(tn)?, id(k, valid_key_id)?);
            match method {
                "PATCH" => Some(Call::KeyUpdate { tenant, key }),
                "DELETE" => Some(Call::KeyRevoke { tenant, key }),
                _ => None,
            }
        }
        ["tenants", tn, "keys", k, "disable"] => {
            let (tenant, key) = (t(tn)?, id(k, valid_key_id)?);
            (method == "POST").then_some(Call::KeyDisable { tenant, key })
        }
        ["tenants", tn, "principals"] => {
            let tenant = t(tn)?;
            (method == "POST").then_some(Call::PrincipalCreate { tenant })
        }
        ["tenants", tn, "principals", p] => {
            let (tenant, principal) = (t(tn)?, id(p, principal_id)?);
            match method {
                "PATCH" => Some(Call::PrincipalUpdate { tenant, principal }),
                "DELETE" => Some(Call::PrincipalRevoke { tenant, principal }),
                _ => None,
            }
        }
        ["tenants", tn, "principals", p, "disable"] => {
            let (tenant, principal) = (t(tn)?, id(p, principal_id)?);
            (method == "POST").then_some(Call::PrincipalDisable { tenant, principal })
        }
        ["tenants", tn, "objects", verb] => {
            let tenant = t(tn)?;
            let call = match *verb {
                "presign" => Call::Presign { tenant },
                "list" => Call::ObjectList { tenant },
                "delete" => Call::ObjectDelete { tenant },
                _ => return Err(NoCall::NotFound),
            };
            (method == "POST").then_some(call)
        }
        ["tenants", tn, "uploads"] => {
            let tenant = t(tn)?;
            (method == "POST").then_some(Call::UploadCreate { tenant })
        }
        ["tenants", tn, "uploads", u] => {
            let (tenant, upload) = (t(tn)?, id(u, upload_id)?);
            (method == "DELETE").then_some(Call::UploadAbort { tenant, upload })
        }
        ["tenants", tn, "uploads", u, "complete"] => {
            let (tenant, upload) = (t(tn)?, id(u, upload_id)?);
            (method == "POST").then_some(Call::UploadComplete { tenant, upload })
        }
        ["tenants", tn, "uploads", u, "parts"] => {
            let (tenant, upload) = (t(tn)?, id(u, upload_id)?);
            (method == "GET").then_some(Call::UploadParts { tenant, upload })
        }
        ["tenants", tn, "usage"] => {
            let tenant = t(tn)?;
            (method == "GET").then_some(Call::Usage { tenant })
        }
        ["tenants", tn, "usage", "days"] => {
            let tenant = t(tn)?;
            (method == "GET").then_some(Call::UsageDays { tenant })
        }
        ["tenants", tn, "usage", "downloads"] => {
            let tenant = t(tn)?;
            (method == "GET").then_some(Call::UsageDownloads { tenant })
        }
        _ => return Err(NoCall::NotFound),
    };
    call.ok_or(NoCall::Method)
}

/// A tenant id this plane serves: `t_` and 16 lowercase hex characters,
/// and not tenant 0.
pub fn tenant_id(s: &str) -> Option<&str> {
    let hex = s.strip_prefix("t_")?;
    let ok = hex.len() == 16 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    (ok && s != DEFAULT_TENANT).then_some(s)
}

/// `b_` and 16 lowercase hex characters, as the catalogue mints them.
fn bucket_id(s: &str) -> bool {
    s.strip_prefix("b_")
        .is_some_and(|h| h.len() == 16 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// 32 lowercase hex characters, as the catalogue mints upload ids.
fn upload_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A principal's key-chain id is opaque here: 1 to 64 ASCII letters,
/// digits, `_` or `-`. Its form is the key chain's.
fn principal_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
