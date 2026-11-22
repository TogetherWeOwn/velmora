#![cfg(feature = "testkit")]
//! One management request from the gate to its answer: what each refusal
//! answers, and that every call that passes waits for its handler.

use std::cell::RefCell;

use sha2::{Digest, Sha256};
use velmora_bridge::mgmt::serve::{serve, Answer, MgmtRequest, NOT_BUILT_RETRY_AFTER_SECS};
use velmora_bridge::mgmt::token::{DisabledTokens, TokenHashes};
use velmora_bridge::testkit::MemBlobStore;
use velmora_bridge::UnixMs;

const STANDARD: &str = "std-token-0123456789abcdef0123456789abcdef";
const CONFIRMED: &str = "conf-token-0123456789abcdef0123456789abcdef";
const TENANT: &str = "t_00000000000000a1";
const T0: UnixMs = UnixMs(1_000_000);

fn hash(token: &str) -> String {
    Sha256::digest(token)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hashes() -> TokenHashes {
    let (standard, confirmed) = (hash(STANDARD), hash(CONFIRMED));
    TokenHashes::from_vars(|name| match name {
        "MGMT_TOKEN_SHA256_STANDARD" => Some(standard.clone()),
        "MGMT_TOKEN_SHA256_CONFIRMED" => Some(confirmed.clone()),
        _ => None,
    })
    .unwrap()
}

const ACTING: &str = "usr_01JD2Q9A7M";
const KEY: &str = "req_01JD2R0001";

/// The answer to `method` on `target` (a path, with its query if any),
/// with the headers given.
async fn answer_with(
    method: &str,
    target: &str,
    token: Option<&str>,
    acting: Option<&str>,
    idempotency_key: Option<&str>,
) -> Answer {
    let disabled = RefCell::new(DisabledTokens::default());
    let authorization = token.map(|token| format!("Bearer {token}"));
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let req = MgmtRequest {
        method,
        path,
        query,
        authorization: authorization.as_deref(),
        acting,
        idempotency_key,
    };
    serve(&disabled, &hashes(), &MemBlobStore::new(), req, T0).await
}

/// The answer with the headers every call accepts: the acting member on
/// every call, and a key on every write.
async fn answer(method: &str, target: &str, token: Option<&str>) -> Answer {
    let write = method != "GET";
    answer_with(method, target, token, Some(ACTING), write.then_some(KEY)).await
}

fn expect(answer: Answer, status: u16, code: &str, retry_after: Option<u32>) {
    assert_eq!(answer.status, status, "{code}");
    assert_eq!(answer.code, code);
    assert_eq!(answer.retry_after, retry_after, "{code}");
    assert_eq!(answer.body(), format!("{{\"code\":\"{code}\"}}"));
    // A fixed lowercase word: the body needs no escaping.
    assert!(code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
}

/// A call that passes the gate waits for its handler: 503 with a long Retry-After.
#[tokio::test(flavor = "current_thread")]
async fn admitted_calls_wait_for_their_handler() {
    let tenant = format!("/v1/tenants/{TENANT}");
    for (method, path, token) in [
        ("GET", tenant.clone(), STANDARD),
        ("GET", format!("{tenant}/buckets"), STANDARD),
        ("POST", format!("{tenant}/keys"), STANDARD),
        ("DELETE", format!("{tenant}?hold_days=30"), CONFIRMED),
        ("GET", "/v1/events".to_string(), STANDARD),
        (
            "GET",
            format!("{tenant}/events?after=e1.40&limit=100"),
            STANDARD,
        ),
        (
            "GET",
            format!("{tenant}/buckets?name=photos&name=gone"),
            STANDARD,
        ),
        ("GET", format!("{tenant}/keys?kind=s3"), STANDARD),
    ] {
        expect(
            answer(method, &path, Some(token)).await,
            503,
            "service_unavailable",
            Some(NOT_BUILT_RETRY_AFTER_SECS),
        );
    }
}

/// Each step of the gate answers with its own status and code, with no Retry-After.
#[tokio::test(flavor = "current_thread")]
async fn gate_refusals_keep_their_status_and_code() {
    let tenant = format!("/v1/tenants/{TENANT}");
    expect(
        answer("GET", "/v1/nothing", Some(STANDARD)).await,
        404,
        "not_found",
        None,
    );
    expect(
        answer("PUT", &tenant, Some(STANDARD)).await,
        405,
        "method_not_allowed",
        None,
    );
    expect(
        answer("GET", "/v1/tenants/t_0000000000000000", Some(CONFIRMED)).await,
        404,
        "not_found",
        None,
    );
    expect(
        answer("GET", &tenant, None).await,
        401,
        "unauthenticated",
        None,
    );
    expect(
        answer("GET", &tenant, Some("not-a-token")).await,
        401,
        "unauthenticated",
        None,
    );
    expect(
        answer("DELETE", &tenant, Some(STANDARD)).await,
        403,
        "insufficient_scope",
        None,
    );
}

/// Tenant create and a principal create at sign-up come with no acting
/// member, and are admitted to their handler.
#[tokio::test(flavor = "current_thread")]
async fn sign_up_calls_need_no_acting_member() {
    let principals = format!("/v1/tenants/{TENANT}/principals");
    for (target, token) in [("/v1/tenants", CONFIRMED), (principals.as_str(), CONFIRMED)] {
        expect(
            answer_with("POST", target, Some(token), None, Some(KEY)).await,
            503,
            "service_unavailable",
            Some(NOT_BUILT_RETRY_AFTER_SECS),
        );
    }
    // Tenant create refuses one: nobody of a tenant that does not exist acts.
    expect(
        answer_with(
            "POST",
            "/v1/tenants",
            Some(CONFIRMED),
            Some(ACTING),
            Some(KEY),
        )
        .await,
        400,
        "bad_request",
        None,
    );
}

/// The checks of the request follow the gate: a caller with no valid token
/// learns nothing of them.
#[tokio::test(flavor = "current_thread")]
async fn request_checks_follow_the_gate() {
    let keys = format!("/v1/tenants/{TENANT}/keys");
    expect(
        answer_with("POST", &keys, None, Some("bad ref"), None).await,
        401,
        "unauthenticated",
        None,
    );
    expect(
        answer_with("POST", &keys, Some(STANDARD), Some(ACTING), None).await,
        400,
        "idempotency_key_required",
        None,
    );
    expect(
        answer_with("POST", &keys, Some(STANDARD), None, Some(KEY)).await,
        400,
        "bad_request",
        None,
    );
    expect(
        answer_with("POST", &keys, Some(STANDARD), Some("a b"), Some(KEY)).await,
        400,
        "bad_request",
        None,
    );
    expect(
        answer_with("POST", &keys, Some(STANDARD), Some(ACTING), Some("a b")).await,
        400,
        "bad_request",
        None,
    );
    expect(
        answer("GET", &format!("{keys}?limit=0"), Some(STANDARD)).await,
        400,
        "bad_request",
        None,
    );
    expect(
        answer("GET", &format!("{keys}?after=x"), Some(STANDARD)).await,
        400,
        "invalid_position",
        None,
    );
    expect(
        answer("GET", &format!("{keys}?after=nphotos"), Some(STANDARD)).await,
        400,
        "invalid_position",
        None,
    );
    expect(
        answer(
            "GET",
            &format!("/v1/tenants/{TENANT}/events?after="),
            Some(STANDARD),
        )
        .await,
        400,
        "invalid_position",
        None,
    );
    expect(
        answer("DELETE", &format!("/v1/tenants/{TENANT}"), Some(CONFIRMED)).await,
        400,
        "bad_request",
        None,
    );
    expect(
        answer("GET", &format!("/v1/tenants/{TENANT}?x=1"), Some(STANDARD)).await,
        400,
        "bad_request",
        None,
    );
}
