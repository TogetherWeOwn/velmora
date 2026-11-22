#![cfg(feature = "testkit")]
//! One management request from the gate to its answer: what each refusal
//! answers, and that every call that passes waits for its handler.

use std::cell::RefCell;

use sha2::{Digest, Sha256};
use velmora_bridge::mgmt::serve::{serve, Answer, NOT_BUILT_RETRY_AFTER_SECS};
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

async fn answer(method: &str, path: &str, token: Option<&str>) -> Answer {
    let disabled = RefCell::new(DisabledTokens::default());
    let authorization = token.map(|token| format!("Bearer {token}"));
    serve(
        &disabled,
        &hashes(),
        &MemBlobStore::new(),
        method,
        path,
        authorization.as_deref(),
        T0,
    )
    .await
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
        ("DELETE", tenant.clone(), CONFIRMED),
        ("POST", "/v1/tenants".to_string(), CONFIRMED),
        ("GET", "/v1/events".to_string(), STANDARD),
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
