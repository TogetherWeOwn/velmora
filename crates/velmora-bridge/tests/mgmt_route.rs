//! The calls of the management plane: each method and path, the ids it
//! takes, and the least scope of each call.

use velmora_bridge::mgmt::route::{is_management_path, route, tenant_id, Call, NoCall};
use velmora_bridge::mgmt::token::{Scope, TokenClass};

const TENANT: &str = "t_00000000000000a1";
const BUCKET: &str = "b_0123456789abcdef";
const KEY: &str = "AKVL0123456789ABCDEF";
const PRINCIPAL: &str = "p_member-1";
const UPLOAD: &str = "0123456789abcdef0123456789abcdef";

const INVALID_TENANTS: [&str; 5] = [
    "t_0000000000000000",
    "t_00000000000000A1",
    "t_0a1",
    "x_00000000000000a1",
    "",
];

fn cases() -> [(&'static str, String, Call, Scope); 33] {
    let tenant_path = format!("/v1/tenants/{TENANT}");
    [
        (
            "POST",
            "/v1/tenants".into(),
            Call::TenantCreate,
            Scope::TenantsCreate,
        ),
        (
            "GET",
            tenant_path.clone(),
            Call::TenantRead {
                tenant: TENANT.into(),
            },
            Scope::TenantsRead,
        ),
        (
            "DELETE",
            tenant_path.clone(),
            Call::TenantDelete {
                tenant: TENANT.into(),
            },
            Scope::TenantsDelete,
        ),
        (
            "POST",
            format!("{tenant_path}/restore"),
            Call::TenantRestore {
                tenant: TENANT.into(),
            },
            Scope::TenantsDelete,
        ),
        (
            "GET",
            format!("{tenant_path}/buckets"),
            Call::BucketList {
                tenant: TENANT.into(),
            },
            Scope::TenantsRead,
        ),
        (
            "POST",
            format!("{tenant_path}/buckets"),
            Call::BucketCreate {
                tenant: TENANT.into(),
            },
            Scope::BucketsWrite,
        ),
        (
            "PATCH",
            format!("{tenant_path}/buckets/{BUCKET}"),
            Call::BucketUpdate {
                tenant: TENANT.into(),
                bucket: BUCKET.into(),
            },
            Scope::BucketsWrite,
        ),
        (
            "DELETE",
            format!("{tenant_path}/buckets/{BUCKET}"),
            Call::BucketDelete {
                tenant: TENANT.into(),
                bucket: BUCKET.into(),
            },
            Scope::BucketsDelete,
        ),
        (
            "GET",
            format!("{tenant_path}/keys"),
            Call::KeyList {
                tenant: TENANT.into(),
            },
            Scope::TenantsRead,
        ),
        (
            "POST",
            format!("{tenant_path}/keys"),
            Call::KeyCreate {
                tenant: TENANT.into(),
            },
            Scope::KeysWrite,
        ),
        (
            "PATCH",
            format!("{tenant_path}/keys/{KEY}"),
            Call::KeyUpdate {
                tenant: TENANT.into(),
                key: KEY.into(),
            },
            Scope::KeysWrite,
        ),
        (
            "DELETE",
            format!("{tenant_path}/keys/{KEY}"),
            Call::KeyRevoke {
                tenant: TENANT.into(),
                key: KEY.into(),
            },
            Scope::KeysWrite,
        ),
        (
            "POST",
            format!("{tenant_path}/principals"),
            Call::PrincipalCreate {
                tenant: TENANT.into(),
            },
            Scope::PrincipalsWrite,
        ),
        (
            "PATCH",
            format!("{tenant_path}/principals/{PRINCIPAL}"),
            Call::PrincipalUpdate {
                tenant: TENANT.into(),
                principal: PRINCIPAL.into(),
            },
            Scope::KeysWrite,
        ),
        (
            "DELETE",
            format!("{tenant_path}/principals/{PRINCIPAL}"),
            Call::PrincipalRevoke {
                tenant: TENANT.into(),
                principal: PRINCIPAL.into(),
            },
            Scope::KeysWrite,
        ),
        (
            "POST",
            format!("{tenant_path}/objects/presign"),
            Call::Presign {
                tenant: TENANT.into(),
            },
            Scope::ObjectsPresignRead,
        ),
        (
            "POST",
            format!("{tenant_path}/objects/list"),
            Call::ObjectList {
                tenant: TENANT.into(),
            },
            Scope::ObjectsList,
        ),
        (
            "POST",
            format!("{tenant_path}/objects/delete"),
            Call::ObjectDelete {
                tenant: TENANT.into(),
            },
            Scope::ObjectsDelete,
        ),
        (
            "POST",
            format!("{tenant_path}/uploads"),
            Call::UploadCreate {
                tenant: TENANT.into(),
            },
            Scope::ObjectsCreate,
        ),
        (
            "POST",
            format!("{tenant_path}/uploads/{UPLOAD}/complete"),
            Call::UploadComplete {
                tenant: TENANT.into(),
                upload: UPLOAD.into(),
            },
            Scope::ObjectsCreate,
        ),
        (
            "DELETE",
            format!("{tenant_path}/uploads/{UPLOAD}"),
            Call::UploadAbort {
                tenant: TENANT.into(),
                upload: UPLOAD.into(),
            },
            Scope::ObjectsCreate,
        ),
        (
            "GET",
            format!("{tenant_path}/uploads/{UPLOAD}/parts"),
            Call::UploadParts {
                tenant: TENANT.into(),
                upload: UPLOAD.into(),
            },
            Scope::ObjectsList,
        ),
        (
            "GET",
            format!("{tenant_path}/usage"),
            Call::Usage {
                tenant: TENANT.into(),
            },
            Scope::UsageRead,
        ),
        (
            "GET",
            format!("{tenant_path}/usage/days"),
            Call::UsageDays {
                tenant: TENANT.into(),
            },
            Scope::UsageRead,
        ),
        (
            "GET",
            format!("{tenant_path}/usage/downloads"),
            Call::UsageDownloads {
                tenant: TENANT.into(),
            },
            Scope::UsageRead,
        ),
        (
            "POST",
            format!("{tenant_path}/keys/{KEY}/disable"),
            Call::KeyDisable {
                tenant: TENANT.into(),
                key: KEY.into(),
            },
            Scope::KeysWrite,
        ),
        (
            "POST",
            format!("{tenant_path}/principals/{PRINCIPAL}/disable"),
            Call::PrincipalDisable {
                tenant: TENANT.into(),
                principal: PRINCIPAL.into(),
            },
            Scope::KeysWrite,
        ),
        (
            "GET",
            "/v1/tenants".into(),
            Call::TenantList,
            Scope::TenantsRead,
        ),
        ("GET", "/v1/events".into(), Call::Events, Scope::EventsRead),
        (
            "GET",
            format!("{tenant_path}/reach"),
            Call::TenantReach {
                tenant: TENANT.into(),
            },
            Scope::TenantsRead,
        ),
        (
            "GET",
            format!("{tenant_path}/buckets/{BUCKET}"),
            Call::BucketRead {
                tenant: TENANT.into(),
                bucket: BUCKET.into(),
            },
            Scope::TenantsRead,
        ),
        (
            "GET",
            format!("{tenant_path}/keys/{KEY}"),
            Call::KeyRead {
                tenant: TENANT.into(),
                key: KEY.into(),
            },
            Scope::TenantsRead,
        ),
        (
            "GET",
            format!("{tenant_path}/usage/buckets"),
            Call::UsageBuckets {
                tenant: TENANT.into(),
            },
            Scope::UsageRead,
        ),
    ]
}

/// Every documented method and path resolves to its call with the listed least scope.
#[test]
fn documented_routes() {
    for (method, path, expected_call, expected_scope) in cases() {
        let call = route(method, &path).unwrap_or_else(|err| panic!("{method} {path}: {err:?}"));
        assert_eq!(call, expected_call, "{method} {path}");
        assert_eq!(call.scope(), expected_scope, "{method} {path}");
    }
}

/// Every call names its tenant except the tenant list, tenant creation and the event feed.
#[test]
fn calls_name_their_tenants() {
    for (method, path, expected_call, _) in cases() {
        let expected = match expected_call {
            Call::TenantList | Call::TenantCreate | Call::Events => None,
            _ => Some(TENANT),
        };
        assert_eq!(
            route(method, &path).unwrap().tenant(),
            expected,
            "{method} {path}"
        );
    }
}

/// Only revokes, disables and the upload abort are closing calls.
#[test]
fn closing_calls() {
    for (method, path, expected_call, _) in cases() {
        let expected = matches!(
            expected_call,
            Call::KeyRevoke { .. }
                | Call::KeyDisable { .. }
                | Call::PrincipalRevoke { .. }
                | Call::PrincipalDisable { .. }
                | Call::UploadAbort { .. }
        );
        assert_eq!(
            route(method, &path).unwrap().closing(),
            expected,
            "{method} {path}"
        );
    }
}

/// An unlisted method on a documented path returns 405 with the method_not_allowed code.
#[test]
fn wrong_methods() {
    let routes = cases();
    for (_, path, _, _) in &routes {
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
            if routes
                .iter()
                .any(|(listed, candidate, _, _)| *listed == method && candidate == path)
            {
                continue;
            }
            let err = route(method, path).expect_err(&format!("{method} {path}"));
            assert_eq!(err, NoCall::Method, "{method} {path}");
            assert_eq!(err.status(), 405, "{method} {path}");
            assert_eq!(err.code(), "method_not_allowed", "{method} {path}");
        }
    }
}

/// Tenant zero and malformed IDs cause documented routes to return 404.
#[test]
fn invalid_ids_are_not_found() {
    let long_principal = "p".repeat(65);
    for (method, path, _, _) in cases() {
        for (id, invalid_ids) in [
            (TENANT, INVALID_TENANTS.as_slice()),
            (BUCKET, &["photos", "b_0123"]),
            (KEY, &["AKVL-bad!"]),
            (PRINCIPAL, &[long_principal.as_str(), "p/x"]),
            (
                UPLOAD,
                &[
                    "0123456789abcdef0123456789abcde",
                    "0123456789ABCDEF0123456789ABCDEF",
                ],
            ),
        ] {
            if !path.contains(id) {
                continue;
            }
            for invalid in invalid_ids {
                let bad_path = path.replace(id, invalid);
                let err = route(method, &bad_path).expect_err(&format!("{method} {bad_path}"));
                assert_eq!(err, NoCall::NotFound, "{method} {bad_path}");
                assert_eq!(err.status(), 404, "{method} {bad_path}");
            }
        }
    }
}

/// Undocumented paths return NotFound for GET and POST.
#[test]
fn paths_without_calls() {
    for path in [
        "/v1",
        "/v1/",
        "/v1/tenants/",
        "/v1//tenants",
        "/v1/tenants/t_00000000000000a1/",
        "/v1/unknown",
        "/v1/tenants/t_00000000000000a1/objects/copy",
        "/v1/tenants/t_00000000000000a1/buckets/b_0123456789abcdef/extra",
        "/v2/tenants",
        "/_admin/status",
        "/v1/tenants/t_00000000000000a1/uploads/0123456789abcdef0123456789abcdef/other",
        "/V1/tenants",
    ] {
        for method in ["GET", "POST"] {
            assert_eq!(
                route(method, path),
                Err(NoCall::NotFound),
                "{method} {path}"
            );
        }
    }
}

/// The management prefix is the case-sensitive /v1 path segment at the root.
#[test]
fn management_path_prefix() {
    for path in ["/v1", "/v1/", "/v1/x", "/v1/tenants/t_00000000000000a1"] {
        assert!(is_management_path(path), "{path:?}");
    }
    for path in ["/v10", "/v1x", "/", "", "/bucket/v1", "/_admin", "/V1"] {
        assert!(!is_management_path(path), "{path:?}");
    }
}

/// The standard token lacks six calls' least scopes, and the confirmed token holds every call's least scope.
#[test]
fn token_classes_cover_the_expected_least_scopes() {
    for (method, path, expected_call, _) in cases() {
        let standard_allowed = !matches!(
            expected_call,
            Call::TenantCreate
                | Call::TenantDelete { .. }
                | Call::TenantRestore { .. }
                | Call::BucketDelete { .. }
                | Call::PrincipalCreate { .. }
                | Call::ObjectDelete { .. }
        );
        let scope = route(method, &path).unwrap().scope();
        assert_eq!(
            TokenClass::Standard.allows(scope),
            standard_allowed,
            "{method} {path}"
        );
        assert!(TokenClass::Confirmed.allows(scope), "{method} {path}");
    }
}

/// A management tenant ID is a nonzero value written as t_ and 16 lowercase hex digits.
#[test]
fn tenant_id_validation() {
    for id in [TENANT, "t_ffffffffffffffff"] {
        assert_eq!(tenant_id(id), Some(id), "{id:?}");
    }
    for id in INVALID_TENANTS {
        assert_eq!(tenant_id(id), None, "{id:?}");
    }
}
