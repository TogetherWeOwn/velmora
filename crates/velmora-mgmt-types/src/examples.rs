//! One example per call of the contract: the request a caller sends and
//! the answer the plane gives. A caller's contract tests can build a fake
//! plane from them; this crate's tests parse each body into its type and
//! back.
//!
//! The ids, names and the secret are made up.

use crate::idem::TokenClass;

/// One call of the contract, by example.
#[derive(Clone, Copy, Debug)]
pub struct Example {
    /// The `kofra-api` port call (`Tenancy::` for the sign-up port).
    pub call: &'static str,
    pub method: &'static str,
    /// The path with its query.
    pub path: &'static str,
    pub token: TokenClass,
    /// `Kofra-Acting-Owner-Ref`.
    pub acting: Option<&'static str>,
    /// `Idempotency-Key`.
    pub idempotency_key: Option<&'static str>,
    /// The request body (JSON), if the call has one.
    pub request: Option<&'static str>,
    pub status: u16,
    /// The answer body (JSON); `None` for a `204`.
    pub answer: Option<&'static str>,
}

/// The tenant of the examples.
pub const TENANT: &str = "t_1a2b3c4d5e6f7a8b";
/// A bucket of the examples.
pub const BUCKET: &str = "b_00aa11bb22cc33dd";
/// A key of the examples.
pub const KEY: &str = "VKEXAMPLE0000001";
/// The member who acts in the examples.
pub const OWNER_REF: &str = "usr_01JD2Q9A7M";

const TENANT_JSON: &str = r#"{
  "id": "t_1a2b3c4d5e6f7a8b", "state": "active", "access": "full",
  "limits": {"storage_bytes": 10737418240, "upload_24h_bytes": null,
             "download_allowance_bytes": null, "active_keys": 20},
  "suspension": null, "deletion": null, "created_at_ms": 1763800000000
}"#;

const KEY_JSON: &str = r#"{
  "id": "VKEXAMPLE0000001", "kind": "s3", "name": "nightly-backup", "status": "active",
  "grants": [{"bucket_id": "b_00aa11bb22cc33dd", "bucket_name": "photos", "access": "ro"}],
  "created_at_ms": 1763800300000, "last_used_at_ms": null, "seq": 12
}"#;

const BUCKET_JSON: &str = r#"{"id": "b_00aa11bb22cc33dd", "name": "photos",
  "created_at_ms": 1763800200000, "stored_bytes": 52428800, "object_count": 42}"#;

/// Every call of the contract, once: 21 calls and the name lookup.
pub const EXAMPLES: &[Example] = &[
    Example {
        call: "Tenancy::create_tenant",
        method: "POST",
        path: "/v1/tenants",
        token: TokenClass::Confirmed,
        acting: None,
        idempotency_key: Some("ws_01JD2Q8V5X"),
        request: Some(r#"{"external_ref": "ws_01JD2Q8V5X"}"#),
        status: 201,
        answer: Some(TENANT_JSON),
    },
    Example {
        call: "Tenancy::create_principal",
        method: "POST",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/principals",
        token: TokenClass::Confirmed,
        acting: None,
        idempotency_key: Some("ws_01JD2Q8V5X/usr_01JD2Q9A7M"),
        request: Some(r#"{"owner_ref": "usr_01JD2Q9A7M", "grants": []}"#),
        status: 201,
        answer: Some(
            r#"{"id": "p_4f2a9c1d0e7b6a35", "owner_ref": "usr_01JD2Q9A7M", "status": "active", "grants": []}"#,
        ),
    },
    Example {
        call: "tenant",
        method: "GET",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b",
        token: TokenClass::Standard,
        acting: None,
        idempotency_key: None,
        request: None,
        status: 200,
        answer: Some(TENANT_JSON),
    },
    Example {
        call: "tenant_reach",
        method: "GET",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/reach",
        token: TokenClass::Standard,
        acting: None,
        idempotency_key: None,
        request: None,
        status: 200,
        answer: Some(r#"{"buckets": 2, "objects": 42, "stored_bytes": 52428800, "keys": 1}"#),
    },
    Example {
        call: "delete_tenant",
        method: "DELETE",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b?hold_days=30",
        token: TokenClass::Confirmed,
        acting: Some(OWNER_REF),
        idempotency_key: Some("cfm_01JD3A0000"),
        request: None,
        status: 200,
        answer: Some(
            r#"{
  "id": "t_1a2b3c4d5e6f7a8b", "state": "deleting", "access": "read_only",
  "limits": {"storage_bytes": 10737418240, "upload_24h_bytes": null,
             "download_allowance_bytes": null, "active_keys": 20},
  "suspension": null,
  "deletion": {"seq": 7, "actor": "customer", "requested_at_ms": 1763900000000,
               "shred_due_at_ms": 1766492000000},
  "created_at_ms": 1763800000000
}"#,
        ),
    },
    Example {
        call: "restore_tenant",
        method: "POST",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/restore",
        token: TokenClass::Confirmed,
        acting: Some(OWNER_REF),
        idempotency_key: Some("cfm_01JD3B0000"),
        request: Some(r#"{"deletion_seq": 7}"#),
        status: 200,
        answer: Some(TENANT_JSON),
    },
    Example {
        call: "buckets",
        method: "GET",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/buckets?limit=100",
        token: TokenClass::Standard,
        acting: None,
        idempotency_key: None,
        request: None,
        status: 200,
        answer: Some(
            r#"{"items": [{"id": "b_00aa11bb22cc33dd", "name": "photos",
  "created_at_ms": 1763800200000, "stored_bytes": 52428800, "object_count": 42}], "next": null}"#,
        ),
    },
    Example {
        call: "(name lookup)",
        method: "GET",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/buckets?name=photos&name=gone",
        token: TokenClass::Standard,
        acting: None,
        idempotency_key: None,
        request: None,
        status: 200,
        answer: Some(
            r#"{"items": [{"id": "b_00aa11bb22cc33dd", "name": "photos",
  "created_at_ms": 1763800200000, "stored_bytes": 52428800, "object_count": 42}], "next": null}"#,
        ),
    },
    Example {
        call: "bucket",
        method: "GET",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/buckets/b_00aa11bb22cc33dd",
        token: TokenClass::Standard,
        acting: None,
        idempotency_key: None,
        request: None,
        status: 200,
        answer: Some(BUCKET_JSON),
    },
    Example {
        call: "create_bucket",
        method: "POST",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/buckets",
        token: TokenClass::Standard,
        acting: Some(OWNER_REF),
        idempotency_key: Some("req_01JD2R0001"),
        request: Some(r#"{"name": "photos"}"#),
        status: 201,
        answer: Some(
            r#"{"id": "b_00aa11bb22cc33dd", "name": "photos",
  "created_at_ms": 1763800200000, "stored_bytes": 0, "object_count": 0}"#,
        ),
    },
    Example {
        call: "delete_bucket",
        method: "DELETE",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/buckets/b_00aa11bb22cc33dd",
        token: TokenClass::Confirmed,
        acting: Some(OWNER_REF),
        idempotency_key: Some("cfm_01JD3C0000"),
        request: None,
        status: 204,
        answer: None,
    },
    Example {
        call: "keys",
        method: "GET",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/keys?kind=s3&limit=100",
        token: TokenClass::Standard,
        acting: None,
        idempotency_key: None,
        request: None,
        status: 200,
        answer: Some(
            r#"{"items": [{
  "id": "VKEXAMPLE0000001", "kind": "s3", "name": "nightly-backup", "status": "active",
  "grants": [{"bucket_id": "b_00aa11bb22cc33dd", "bucket_name": "photos", "access": "ro"}],
  "created_at_ms": 1763800300000, "last_used_at_ms": null, "seq": 12
}], "next": null}"#,
        ),
    },
    Example {
        call: "key",
        method: "GET",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/keys/VKEXAMPLE0000001",
        token: TokenClass::Standard,
        acting: None,
        idempotency_key: None,
        request: None,
        status: 200,
        answer: Some(KEY_JSON),
    },
    Example {
        call: "create_key",
        method: "POST",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/keys",
        token: TokenClass::Standard,
        acting: Some(OWNER_REF),
        idempotency_key: Some("req_01JD2R0002"),
        request: Some(
            r#"{"kind": "s3", "name": "nightly-backup",
  "grants": [{"bucket_id": "b_00aa11bb22cc33dd", "access": "ro"}]}"#,
        ),
        status: 201,
        answer: Some(
            r#"{
  "id": "VKEXAMPLE0000001", "kind": "s3", "name": "nightly-backup", "status": "active",
  "grants": [{"bucket_id": "b_00aa11bb22cc33dd", "bucket_name": "photos", "access": "ro"}],
  "created_at_ms": 1763800300000, "last_used_at_ms": null, "seq": 12,
  "secret_access_key": "example-secret-not-real-xxxxxxxxxxxxxxxx"
}"#,
        ),
    },
    Example {
        call: "update_key",
        method: "PATCH",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/keys/VKEXAMPLE0000001",
        token: TokenClass::Confirmed,
        acting: Some(OWNER_REF),
        idempotency_key: Some("cfm_01JD3D0000"),
        request: Some(
            r#"{"grants": [{"bucket_id": "b_00aa11bb22cc33dd", "access": "rw"}], "if_seq": 12}"#,
        ),
        status: 200,
        answer: Some(
            r#"{
  "id": "VKEXAMPLE0000001", "kind": "s3", "name": "nightly-backup", "status": "active",
  "grants": [{"bucket_id": "b_00aa11bb22cc33dd", "bucket_name": "photos", "access": "rw"}],
  "created_at_ms": 1763800300000, "last_used_at_ms": null, "seq": 13
}"#,
        ),
    },
    Example {
        call: "revoke_key",
        method: "DELETE",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/keys/VKEXAMPLE0000001",
        token: TokenClass::Standard,
        acting: Some(OWNER_REF),
        idempotency_key: Some("req_01JD2R0003"),
        request: None,
        status: 204,
        answer: None,
    },
    Example {
        call: "usage",
        method: "GET",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/usage",
        token: TokenClass::Standard,
        acting: None,
        idempotency_key: None,
        request: None,
        status: 200,
        answer: Some(
            r#"{"as_of_ms": 1763900000000, "stored_bytes": 52428800, "object_count": 42,
  "storage_limit_bytes": 10737418240, "upload_24h": null, "downloads": null,
  "open_uploads": {"count": 0, "limit": 100}}"#,
        ),
    },
    Example {
        call: "usage_days",
        method: "GET",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/usage/days?after_day=2026-11-01&limit=1",
        token: TokenClass::Standard,
        acting: None,
        idempotency_key: None,
        request: None,
        status: 200,
        answer: Some(
            r#"{"items": [{"day": "2026-11-21", "status": "final", "peak_stored_bytes": 52428800,
  "uploaded_bytes": 1048576, "downloaded_bytes": 0, "requests_approx": 310}], "next": "d2026-11-21"}"#,
        ),
    },
    Example {
        call: "usage_buckets",
        method: "GET",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/usage/buckets?limit=100",
        token: TokenClass::Standard,
        acting: None,
        idempotency_key: None,
        request: None,
        status: 200,
        answer: Some(
            r#"{"items": [{"bucket_id": "b_00aa11bb22cc33dd", "bucket": "photos",
  "stored_bytes": 52428800, "object_count": 42, "as_of_ms": 1763900000000}], "next": null}"#,
        ),
    },
    Example {
        call: "events",
        method: "GET",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/events?after=e1.40&limit=100",
        token: TokenClass::Standard,
        acting: None,
        idempotency_key: None,
        request: None,
        status: 200,
        answer: Some(
            r#"{"items": [{"epoch": 1, "seq": 41, "type": "bucket.created", "at_ms": 1763800200000,
  "data": {"bucket_id": "b_00aa11bb22cc33dd", "bucket": "photos"}}], "position": "e1.41"}"#,
        ),
    },
    Example {
        call: "objects",
        method: "POST",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/objects/list",
        token: TokenClass::Standard,
        acting: Some(OWNER_REF),
        idempotency_key: None,
        request: Some(
            r#"{"bucket_id": "b_00aa11bb22cc33dd", "prefix": "2026/", "delimiter": "/", "limit": 2}"#,
        ),
        status: 200,
        answer: Some(
            r#"{"objects": [{"key": "2026/a.jpg", "size_bytes": 1048576, "last_modified_ms": 1763800400000}],
  "prefixes": ["2026/11/"], "next": "p2026/11/"}"#,
        ),
    },
    Example {
        call: "presign",
        method: "POST",
        path: "/v1/tenants/t_1a2b3c4d5e6f7a8b/objects/presign",
        token: TokenClass::Standard,
        acting: Some(OWNER_REF),
        idempotency_key: None,
        request: Some(
            r#"{"bucket_id": "b_00aa11bb22cc33dd", "key": "2026/a.jpg", "op": "GetObject", "expires_s": 300}"#,
        ),
        status: 200,
        answer: Some(
            r#"{"url": "https://s3.example.com/photos/2026/a.jpg?X-Amz-Expires=300", "expires_at_ms": 1763800700000}"#,
        ),
    },
];
