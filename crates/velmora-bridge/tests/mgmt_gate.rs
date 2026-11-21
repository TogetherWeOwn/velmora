#![cfg(feature = "testkit")]
//! The management gate's routing, authentication, and scope checks.
//! Covers disable-list refreshes and the stale-list cutoff through admission.

use std::cell::{Cell, RefCell};

use sha2::{Digest, Sha256};
use velmora_bridge::mgmt::gate::{admit, Admitted, Shut};
use velmora_bridge::mgmt::route::{Call, NoCall};
use velmora_bridge::mgmt::token::{
    id_of_hash, write_disable, DisabledTokens, Refused, Scope, TokenClass, TokenHashes,
};
use velmora_bridge::recovery::Unpublished;
use velmora_bridge::testkit::{MemBlobStore, TestKek};
use velmora_bridge::{BlobMeta, BlobStore, BridgeError, ByteSpan, Result, UnixMs};

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

fn from_vars(
    standard: Option<&str>,
    confirmed: Option<&str>,
) -> std::result::Result<TokenHashes, String> {
    TokenHashes::from_vars(|name| {
        match name {
            "MGMT_TOKEN_SHA256_STANDARD" => standard,
            "MGMT_TOKEN_SHA256_CONFIRMED" => confirmed,
            _ => panic!("an unexpected variable is read"),
        }
        .map(str::to_owned)
    })
}

fn configured_hashes() -> TokenHashes {
    from_vars(Some(&hash(STANDARD)), Some(&hash(CONFIRMED))).unwrap()
}

async fn read_tenant(
    disabled: &RefCell<DisabledTokens>,
    hashes: &TokenHashes,
    store: &impl BlobStore,
    token: Option<&str>,
    elapsed_ms: i64,
) -> std::result::Result<Admitted, Shut> {
    let authorization = token.map(|token| format!("Bearer {token}"));
    admit(
        disabled,
        hashes,
        store,
        "GET",
        &format!("/v1/tenants/{TENANT}"),
        authorization.as_deref(),
        UnixMs(T0.0 + elapsed_ms),
    )
    .await
}

struct CountingStore {
    inner: MemBlobStore,
    lists: Cell<usize>,
}

impl CountingStore {
    fn new() -> Self {
        Self {
            inner: MemBlobStore::new(),
            lists: Cell::new(0),
        }
    }
}

impl BlobStore for CountingStore {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.inner.put(key, bytes, meta).await
    }

    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.inner.get(key, span).await
    }

    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.inner.head(key).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }

    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.inner.delete_record(refused).await
    }

    async fn list(&self, prefix: &str, after: &str, limit: u32) -> Result<Vec<String>> {
        self.lists.set(self.lists.get() + 1);
        self.inner.list(prefix, after, limit).await
    }
}

struct FailingListStore {
    inner: MemBlobStore,
    fail_list: Cell<bool>,
}

impl FailingListStore {
    fn new(fail_list: bool) -> Self {
        Self {
            inner: MemBlobStore::new(),
            fail_list: Cell::new(fail_list),
        }
    }
}

impl BlobStore for FailingListStore {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.inner.put(key, bytes, meta).await
    }

    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.inner.get(key, span).await
    }

    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.inner.head(key).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }

    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.inner.delete_record(refused).await
    }

    async fn list(&self, prefix: &str, after: &str, limit: u32) -> Result<Vec<String>> {
        if self.fail_list.get() {
            return Err(BridgeError::Blob("listing failed".into()));
        }
        self.inner.list(prefix, after, limit).await
    }
}

/// Routing rejects unknown paths, tenant zero, and wrong methods before listing.
#[tokio::test(flavor = "current_thread")]
async fn routing_precedes_listing() {
    let store = CountingStore::new();
    let hashes = configured_hashes();
    let disabled = RefCell::new(DisabledTokens::default());
    let tenant_path = format!("/v1/tenants/{TENANT}");

    for (method, path, expected, status) in [
        ("GET", "/v1/unknown", NoCall::NotFound, 404),
        (
            "GET",
            "/v1/tenants/t_0000000000000000",
            NoCall::NotFound,
            404,
        ),
        ("POST", tenant_path.as_str(), NoCall::Method, 405),
    ] {
        let shut = admit(&disabled, &hashes, &store, method, path, None, T0)
            .await
            .unwrap_err();
        assert_eq!(shut, Shut::NoCall(expected), "{method} {path}");
        assert_eq!(shut.status(), status);
        assert_eq!(store.lists.get(), 0, "{method} {path}");
    }
}

/// A failed first listing returns 503 with Retry-After whether a token is present or absent.
#[tokio::test(flavor = "current_thread")]
async fn failed_first_listing_precedes_authentication() {
    let store = FailingListStore::new(true);
    let hashes = configured_hashes();

    for token in [Some(CONFIRMED), None] {
        let disabled = RefCell::new(DisabledTokens::default());
        let shut = read_tenant(&disabled, &hashes, &store, token, 0)
            .await
            .unwrap_err();
        assert_eq!(shut, Shut::Refused(Refused::Unavailable));
        assert_eq!(shut.status(), 503);
        assert_eq!(shut.retry_after(), Some(5));
    }
}

/// The first call lists disabled tokens and the next listing is due after one minute.
#[tokio::test(flavor = "current_thread")]
async fn listing_refresh_interval() {
    let store = CountingStore::new();
    let hashes = configured_hashes();
    let disabled = RefCell::new(DisabledTokens::default());

    for (elapsed_ms, expected_lists) in [(0, 1), (30_000, 1), (60_000, 2)] {
        read_tenant(&disabled, &hashes, &store, Some(STANDARD), elapsed_ms)
            .await
            .unwrap();
        assert_eq!(store.lists.get(), expected_lists, "at {elapsed_ms} ms");
    }
}

/// Missing, wrong, and already disabled tokens receive 401 without Retry-After.
#[tokio::test(flavor = "current_thread")]
async fn unauthenticated_tokens() {
    let store = MemBlobStore::new();
    let hashes = configured_hashes();
    let disabled = RefCell::new(DisabledTokens::default());
    let id = id_of_hash(&hash(STANDARD)).unwrap();
    write_disable(&store, &TestKek::new(), &id, T0)
        .await
        .unwrap();

    let wrong = format!("{STANDARD}x");
    for token in [None, Some(wrong.as_str()), Some(STANDARD)] {
        let shut = read_tenant(&disabled, &hashes, &store, token, 0)
            .await
            .unwrap_err();
        assert_eq!(shut, Shut::Refused(Refused::Unauthenticated));
        assert_eq!(shut.status(), 401);
        assert_eq!(shut.retry_after(), None);
    }
}

/// Tenant creation returns insufficient_scope for standard and admits confirmed.
#[tokio::test(flavor = "current_thread")]
async fn tenant_create_requires_confirmed() {
    let store = MemBlobStore::new();
    let hashes = configured_hashes();
    let disabled = RefCell::new(DisabledTokens::default());

    let shut = admit(
        &disabled,
        &hashes,
        &store,
        "POST",
        "/v1/tenants",
        Some(&format!("Bearer {STANDARD}")),
        T0,
    )
    .await
    .unwrap_err();
    assert_eq!(shut, Shut::Refused(Refused::Scope(Scope::TenantsCreate)));
    assert_eq!(shut.status(), 403);
    assert_eq!(shut.code(), "insufficient_scope");

    let admitted = admit(
        &disabled,
        &hashes,
        &store,
        "POST",
        "/v1/tenants",
        Some(&format!("Bearer {CONFIRMED}")),
        T0,
    )
    .await
    .unwrap();
    assert_eq!(admitted.actor.class, TokenClass::Confirmed);
    assert_eq!(admitted.call, Call::TenantCreate);
}

/// Both classes can create a key, but only confirmed has the wider write scope.
#[tokio::test(flavor = "current_thread")]
async fn admitted_checks_wider_scope() {
    let store = MemBlobStore::new();
    let hashes = configured_hashes();
    let disabled = RefCell::new(DisabledTokens::default());
    let path = format!("/v1/tenants/{TENANT}/keys");

    for (token, expected) in [
        (
            STANDARD,
            Err(Shut::Refused(Refused::Scope(Scope::KeysWriteRw))),
        ),
        (CONFIRMED, Ok(())),
    ] {
        let admitted = admit(
            &disabled,
            &hashes,
            &store,
            "POST",
            &path,
            Some(&format!("Bearer {token}")),
            T0,
        )
        .await
        .unwrap();
        assert_eq!(
            admitted.call,
            Call::KeyCreate {
                tenant: TENANT.to_owned(),
            }
        );
        assert_eq!(admitted.call.scope(), Scope::KeysWrite);
        assert_eq!(admitted.require(Scope::KeysWriteRw), expected);
    }
}

/// A disable written after the last listing takes effect when the next listing is due.
#[tokio::test(flavor = "current_thread")]
async fn disable_takes_effect_on_refresh() {
    let store = MemBlobStore::new();
    let hashes = configured_hashes();
    let disabled = RefCell::new(DisabledTokens::default());
    read_tenant(&disabled, &hashes, &store, Some(STANDARD), 0)
        .await
        .unwrap();

    let id = id_of_hash(&hash(STANDARD)).unwrap();
    write_disable(&store, &TestKek::new(), &id, UnixMs(T0.0 + 1_000))
        .await
        .unwrap();

    read_tenant(&disabled, &hashes, &store, Some(STANDARD), 59_000)
        .await
        .unwrap();
    assert_eq!(
        read_tenant(&disabled, &hashes, &store, Some(STANDARD), 60_000).await,
        Err(Shut::Refused(Refused::Unauthenticated))
    );
}

/// Failed refreshes allow admission through five minutes after the last good listing.
#[tokio::test(flavor = "current_thread")]
async fn stale_listing_closes_gate() {
    let store = FailingListStore::new(false);
    let hashes = configured_hashes();
    let disabled = RefCell::new(DisabledTokens::default());
    read_tenant(&disabled, &hashes, &store, Some(STANDARD), 0)
        .await
        .unwrap();

    store.fail_list.set(true);
    for elapsed_ms in [60_000, 120_000, 180_000, 240_000, 300_000] {
        read_tenant(&disabled, &hashes, &store, Some(STANDARD), elapsed_ms)
            .await
            .unwrap();
    }
    assert_eq!(
        read_tenant(&disabled, &hashes, &store, Some(STANDARD), 300_001).await,
        Err(Shut::Refused(Refused::Unavailable))
    );
}

/// A store whose listing never completes.
struct HangingStore(MemBlobStore);

impl BlobStore for HangingStore {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.0.put(key, bytes, meta).await
    }

    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.0.get(key, span).await
    }

    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.0.head(key).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.0.delete(key).await
    }

    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.0.delete_record(refused).await
    }

    async fn list(&self, _: &str, _: &str, _: u32) -> Result<Vec<String>> {
        std::future::pending().await
    }
}

/// A call dropped while it lists gives its listing back: the next call
/// lists at once and gets in.
#[tokio::test(flavor = "current_thread")]
async fn a_call_dropped_while_listing_lets_the_next_one_list() {
    let hashes = configured_hashes();
    let disabled = RefCell::new(DisabledTokens::default());
    let hanging = HangingStore(MemBlobStore::new());
    let dropped = tokio::time::timeout(
        std::time::Duration::from_millis(20),
        read_tenant(&disabled, &hashes, &hanging, Some(STANDARD), 0),
    )
    .await;
    assert!(dropped.is_err(), "the listing never completes");
    let store = CountingStore::new();
    let admitted = read_tenant(&disabled, &hashes, &store, Some(STANDARD), 1).await;
    assert!(admitted.is_ok(), "{admitted:?}");
    assert_eq!(store.lists.get(), 1);
}
