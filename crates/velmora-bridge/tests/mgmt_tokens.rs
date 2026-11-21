//! The service tokens of the management plane: the scopes of each
//! class, the hashes in the Worker secrets, and the records that
//! disable a token.

#![cfg(feature = "testkit")]

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use velmora_bridge::mgmt::token::{
    authenticate, id_of_hash, list_disabled, write_disable, Actor, DisabledTokens, Refused, Scope,
    TokenClass, TokenHashes, TokenId, DISABLED_TOKEN_PREFIX, LIST_AGAIN_SHUT_MS, LIST_EVERY_MS,
    STALE_AFTER_MS,
};
use velmora_bridge::recovery::{is_protected_key, record_name, Unpublished};
use velmora_bridge::testkit::{MemBlobStore, TestKek};
use velmora_bridge::{
    BlobMeta, BlobStore, BridgeError, BucketId, ByteSpan, ExtentId, Result, UnixMs,
};

const STANDARD: &str = "std-token-0123456789abcdef0123456789abcdef";
const CONFIRMED: &str = "conf-token-0123456789abcdef0123456789abcdef";
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

fn actor(class: TokenClass, token: &str) -> Actor {
    Actor {
        class,
        token: id_of_hash(&hash(token)).unwrap(),
    }
}

fn fresh_list() -> DisabledTokens {
    let mut disabled = DisabledTokens::default();
    let listing = disabled.begin(T0).expect("a first listing is due");
    disabled.record(listing, Ok(BTreeSet::new()));
    disabled
}

fn present(
    hashes: &TokenHashes,
    disabled: &DisabledTokens,
    token: &str,
    now: UnixMs,
) -> std::result::Result<Actor, Refused> {
    authenticate(hashes, disabled, Some(&format!("Bearer {token}")), now)
}

/// Confirmed allows every scope, while standard allows exactly the listed subset.
#[test]
fn scope_table_is_exhaustive() {
    let standard = BTreeSet::from([
        Scope::TenantsRead,
        Scope::BucketsWrite,
        Scope::KeysWrite,
        Scope::ObjectsList,
        Scope::ObjectsPresignRead,
        Scope::ObjectsCreate,
        Scope::UsageRead,
        Scope::EventsRead,
    ]);
    let mut allowed = BTreeSet::new();
    let mut refused = Vec::new();
    for scope in Scope::ALL {
        assert!(TokenClass::Confirmed.allows(scope), "{scope:?}");
        assert_eq!(
            TokenClass::Standard.allows(scope),
            standard.contains(&scope),
            "{scope:?}"
        );
        if TokenClass::Standard.allows(scope) {
            allowed.insert(scope);
        } else {
            refused.push(scope.as_str());
        }
    }
    assert_eq!(allowed, standard);
    assert_eq!(
        refused,
        [
            "tenants:create",
            "tenants:delete",
            "buckets:publish",
            "buckets:delete",
            "keys:write_rw",
            "principals:write",
            "objects:presign_write",
            "objects:delete",
        ]
    );
}

/// Operator and billing actions are absent from the management token scope table.
#[test]
fn operator_and_billing_scopes_are_absent() {
    for scope in Scope::ALL {
        let name = scope.as_str();
        assert!(!matches!(name, "tenants:delete_now" | "tenants:suspend"));
        for forbidden in ["hold", "limit", "billing"] {
            assert!(!name.contains(forbidden), "{name}");
        }
    }
}

/// Secrets accept up to two distinct lowercase hashes per class and redact values in diagnostics.
#[test]
fn secret_validation_and_redaction() {
    assert!(from_vars(None, None).unwrap().is_empty());

    let standard = hash(STANDARD);
    let confirmed = hash(CONFIRMED);
    let hashes = from_vars(Some(&standard), Some(&confirmed)).unwrap();
    assert!(!hashes.is_empty());
    let debug = format!("{hashes:?}");
    assert!(!debug.contains(&standard));
    assert!(!debug.contains(&confirmed));

    let two = format!("{standard},{confirmed}");
    assert!(!from_vars(Some(&two), None).unwrap().is_empty());

    let three = format!("{two},{}", "0".repeat(64));
    let uppercase = confirmed.to_uppercase();
    let short = &standard[..63];
    for (configured_standard, configured_confirmed, expected) in [
        (Some(three.as_str()), None, "MGMT_TOKEN_SHA256_STANDARD"),
        (
            None,
            Some(uppercase.as_str()),
            "MGMT_TOKEN_SHA256_CONFIRMED",
        ),
        (Some(short), None, "MGMT_TOKEN_SHA256_STANDARD"),
        (Some(standard.as_str()), Some(standard.as_str()), "token id"),
    ] {
        let error = from_vars(configured_standard, configured_confirmed).unwrap_err();
        assert!(error.contains(expected));
        for value in [configured_standard, configured_confirmed]
            .into_iter()
            .flatten()
        {
            for offending_hash in value.split(',') {
                assert!(!error.contains(offending_hash));
            }
        }
    }

    assert!(from_vars(Some(""), None).unwrap().is_empty());
    let hashes = from_vars(Some(""), Some(&confirmed)).unwrap();
    let disabled = fresh_list();
    assert_eq!(
        present(&hashes, &disabled, STANDARD, T0),
        Err(Refused::Unauthenticated)
    );
    assert_eq!(
        present(&hashes, &disabled, CONFIRMED, T0),
        Ok(actor(TokenClass::Confirmed, CONFIRMED))
    );
}

/// Authentication returns 503 until the first successful disable listing.
#[test]
fn authentication_requires_a_good_listing() {
    assert_eq!(
        present(
            &configured_hashes(),
            &DisabledTokens::default(),
            STANDARD,
            T0
        ),
        Err(Refused::Unavailable)
    );
    assert_eq!(Refused::Unavailable.status(), 503);
}

/// A fresh list permits configured bearer tokens and rejects missing, malformed, or unknown credentials.
#[test]
fn authentication_checks_bearer_credentials() {
    let hashes = configured_hashes();
    let disabled = fresh_list();
    assert_eq!(
        present(&hashes, &disabled, STANDARD, T0),
        Ok(actor(TokenClass::Standard, STANDARD))
    );
    assert_eq!(
        present(&hashes, &disabled, CONFIRMED, T0),
        Ok(actor(TokenClass::Confirmed, CONFIRMED))
    );
    let wrong = format!("Bearer {STANDARD}x");
    for header in [None, Some("Basic x"), Some(wrong.as_str())] {
        assert_eq!(
            authenticate(&hashes, &disabled, header, T0),
            Err(Refused::Unauthenticated)
        );
    }

    for token in [
        "0123456789",
        &format!("{STANDARD} x"),
        &format!("{STANDARD}é"),
    ] {
        let hashes = from_vars(Some(&hash(token)), None).unwrap();
        assert_eq!(
            present(&hashes, &disabled, token, T0),
            Err(Refused::Unauthenticated)
        );
    }
    assert_eq!(Refused::Unauthenticated.status(), 401);
}

/// An actor inherits its class's scopes and receives insufficient_scope for a forbidden action.
#[test]
fn actor_checks_scope() {
    let standard = actor(TokenClass::Standard, STANDARD);
    assert_eq!(standard.may(Scope::KeysWrite), Ok(()));
    let refusal = standard.may(Scope::KeysWriteRw).unwrap_err();
    assert_eq!(refusal, Refused::Scope(Scope::KeysWriteRw));
    assert_eq!(refusal.status(), 403);
    assert_eq!(refusal.code(), "insufficient_scope");
    assert_eq!(
        actor(TokenClass::Confirmed, CONFIRMED).may(Scope::ObjectsDelete),
        Ok(())
    );
}

/// Rotation accepts both standard tokens with distinct IDs until the old hash is removed.
#[test]
fn standard_token_rotation() {
    let new = hash(CONFIRMED);
    let rotating = from_vars(Some(&format!("{},{new}", hash(STANDARD))), None).unwrap();
    let disabled = fresh_list();
    let old_actor = present(&rotating, &disabled, STANDARD, T0).unwrap();
    let new_actor = present(&rotating, &disabled, CONFIRMED, T0).unwrap();
    assert_eq!(old_actor, actor(TokenClass::Standard, STANDARD));
    assert_eq!(new_actor, actor(TokenClass::Standard, CONFIRMED));
    assert_ne!(old_actor.token, new_actor.token);

    let rotated = from_vars(Some(&new), None).unwrap();
    assert_eq!(
        present(&rotated, &disabled, STANDARD, T0),
        Err(Refused::Unauthenticated)
    );
    assert_eq!(present(&rotated, &disabled, CONFIRMED, T0), Ok(new_actor));
}

/// A disable record overrides its configured token and repeated writes use the same key.
#[tokio::test(flavor = "current_thread")]
async fn disable_wins() {
    let store = MemBlobStore::new();
    let kek = TestKek::new();
    let standard_hash = hash(STANDARD);
    let id = id_of_hash(&standard_hash).unwrap();
    write_disable(&store, &kek, &id, T0).await.unwrap();

    let key = format!("m/rst/{}", &standard_hash[..16]);
    assert!(store.contains(&key));
    let bytes = store.stored(&key).unwrap().bytes;
    for secret in [STANDARD, standard_hash.as_str()] {
        assert!(!bytes
            .windows(secret.len())
            .any(|window| window == secret.as_bytes()));
    }

    let listed = list_disabled(&store).await.unwrap();
    assert!(listed.contains(&id));
    let mut disabled = DisabledTokens::default();
    let listing = disabled.begin(T0).expect("a first listing is due");
    disabled.record(listing, Ok(listed));
    let hashes = configured_hashes();
    assert_eq!(
        present(&hashes, &disabled, STANDARD, T0),
        Err(Refused::Unauthenticated)
    );
    assert_eq!(
        present(&hashes, &disabled, CONFIRMED, T0),
        Ok(actor(TokenClass::Confirmed, CONFIRMED))
    );

    write_disable(&store, &kek, &id, T0).await.unwrap();
    assert_eq!(
        store
            .list(DISABLED_TOKEN_PREFIX, DISABLED_TOKEN_PREFIX, 10)
            .await
            .unwrap(),
        vec![key]
    );
}

/// Listing skips malformed IDs and nested keys under the disable prefix.
#[tokio::test(flavor = "current_thread")]
async fn listing_skips_invalid_record_names() {
    let store = MemBlobStore::new();
    let id = actor(TokenClass::Standard, STANDARD).token;
    write_disable(&store, &TestKek::new(), &id, T0)
        .await
        .unwrap();

    let bytes = b"invalid record name";
    let meta = BlobMeta {
        bucket: &BucketId::new("-"),
        extent: &ExtentId::new("-"),
        cipher_sha256: &Sha256::digest(bytes).into(),
    };
    for key in ["m/rst/NOTHEX", "m/rst/0123", "m/rst/0123456789abcdef/x"] {
        store.put(key, bytes.to_vec(), &meta).await.unwrap();
    }
    assert_eq!(list_disabled(&store).await.unwrap(), BTreeSet::from([id]));
}

/// Listing collects every disable ID across multiple pages.
#[tokio::test(flavor = "current_thread")]
async fn listing_reads_all_pages() {
    let store = MemBlobStore::new();
    let kek = TestKek::new();
    let mut expected = BTreeSet::new();
    for i in 0..2_500 {
        let id = TokenId::parse(&format!("{i:016x}")).unwrap();
        write_disable(&store, &kek, &id, T0).await.unwrap();
        expected.insert(id);
    }
    let listed = list_disabled(&store).await.unwrap();
    assert_eq!(listed.len(), 2_500);
    assert_eq!(listed, expected);
}

/// Refreshes are spaced one minute apart and failures leave the last good list aging toward expiry.
#[test]
fn listing_freshness_and_expiry() {
    let hashes = configured_hashes();
    let mut disabled = DisabledTokens::default();
    assert_eq!(LIST_EVERY_MS, 60_000);
    assert_eq!(STALE_AFTER_MS, 300_000);
    let first = disabled.begin(T0).expect("a first listing is due");
    disabled.record(first, Ok(BTreeSet::new()));
    assert!(disabled.begin(UnixMs(T0.0 + 59_999)).is_none());
    let refresh = UnixMs(T0.0 + 60_000);
    let second = disabled.begin(refresh).expect("due after a minute");

    let before_bound = UnixMs(T0.0 + STALE_AFTER_MS - 1);
    let bound = UnixMs(T0.0 + STALE_AFTER_MS);
    let expired = UnixMs(bound.0 + 1);
    let standard = actor(TokenClass::Standard, STANDARD);
    assert_eq!(
        present(&hashes, &disabled, STANDARD, bound),
        Ok(standard.clone())
    );
    assert_eq!(
        present(&hashes, &disabled, STANDARD, expired),
        Err(Refused::Unavailable)
    );

    disabled.record(second, Err(BridgeError::Blob("listing failed".into())));
    assert_eq!(
        present(&hashes, &disabled, STANDARD, before_bound),
        Ok(standard.clone())
    );
    assert_eq!(
        present(&hashes, &disabled, STANDARD, expired),
        Err(Refused::Unavailable)
    );

    let third = disabled.begin(expired).expect("due again");
    disabled.record(third, Ok(BTreeSet::new()));
    assert_eq!(present(&hashes, &disabled, STANDARD, expired), Ok(standard));
}

/// A late result from an older listing cannot replace a newer successful listing.
#[test]
fn older_listing_cannot_replace_newer_list() {
    let hashes = configured_hashes();
    let mut disabled = fresh_list();
    let older = UnixMs(T0.0 + 60_000);
    let newer = UnixMs(T0.0 + 120_000);
    let older = disabled.begin(older).expect("due");
    let newer_listing = disabled.begin(newer).expect("due");
    disabled.record(
        newer_listing,
        Ok(BTreeSet::from(
            [actor(TokenClass::Standard, STANDARD).token],
        )),
    );
    disabled.record(older, Ok(BTreeSet::new()));
    assert_eq!(
        present(&hashes, &disabled, STANDARD, newer),
        Err(Refused::Unauthenticated)
    );
    assert_eq!(
        present(&hashes, &disabled, CONFIRMED, newer),
        Ok(actor(TokenClass::Confirmed, CONFIRMED))
    );
}

struct FailingListStore(MemBlobStore);

impl BlobStore for FailingListStore {
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
        Err(BridgeError::Blob("listing failed".into()))
    }
}

/// A store listing error propagates and leaves authentication unavailable without a prior good list.
#[tokio::test(flavor = "current_thread")]
async fn failed_first_listing_keeps_authentication_unavailable() {
    let store = FailingListStore(MemBlobStore::new());
    let mut disabled = DisabledTokens::default();
    let listing = disabled.begin(T0).expect("a first listing is due");
    let listed = list_disabled(&store).await;
    assert!(matches!(&listed, Err(BridgeError::Blob(message)) if message == "listing failed"));
    disabled.record(listing, listed);
    assert_eq!(
        present(&configured_hashes(), &disabled, STANDARD, T0),
        Err(Refused::Unavailable)
    );
}

/// Disable keys are protected from deletion and excluded from catalogue recovery.
#[test]
fn disable_key_is_protected_and_excluded_from_recovery() {
    let name = format!("{DISABLED_TOKEN_PREFIX}{}", "0123456789abcdef");
    assert!(record_name(&name).is_none());
    assert!(is_protected_key(&name));
}

/// A clock that steps back cannot make an older listing win, and a list
/// stamped after now is not fresh: the next call lists again.
#[test]
fn a_clock_step_back_fails_closed_and_lists_again() {
    let hashes = configured_hashes();
    let mut disabled = DisabledTokens::default();
    let later = UnixMs(T0.0 + 600_000);
    let first = disabled.begin(later).expect("due");
    disabled.record(first, Ok(BTreeSet::new()));
    assert!(present(&hashes, &disabled, STANDARD, later).is_ok());
    // The clock steps back by 10 minutes: the list is from the future.
    assert_eq!(
        present(&hashes, &disabled, STANDARD, T0),
        Err(Refused::Unavailable)
    );
    let again = disabled
        .begin(T0)
        .expect("a clock behind the last listing lists again");
    disabled.record(
        again,
        Ok(BTreeSet::from(
            [actor(TokenClass::Standard, STANDARD).token],
        )),
    );
    assert_eq!(
        present(&hashes, &disabled, STANDARD, T0),
        Err(Refused::Unauthenticated)
    );
    assert!(present(&hashes, &disabled, CONFIRMED, T0).is_ok());
}

/// A listing that never finished gives its ticket back: the next call
/// lists at once; a ticket that is no longer the last one changes nothing.
#[test]
fn an_abandoned_listing_lets_the_next_call_list() {
    let mut disabled = DisabledTokens::default();
    let first = disabled.begin(T0).expect("due");
    assert!(disabled.begin(UnixMs(T0.0 + 1)).is_none());
    disabled.abandon(first);
    let second = disabled.begin(UnixMs(T0.0 + 2)).expect("due again at once");
    let third_try = disabled.begin(UnixMs(T0.0 + 3));
    assert!(third_try.is_none(), "one listing at a time");
    disabled.record(second, Ok(BTreeSet::new()));
    // A fresh list: the next listing waits the full minute.
    assert!(disabled.begin(UnixMs(T0.0 + 59_000)).is_none());
    assert!(disabled.begin(UnixMs(T0.0 + 60_002)).is_some());
}

/// While the door is shut (no good list), a failed listing is tried again
/// after a few seconds, not after a minute.
#[test]
fn a_shut_door_lists_again_soon() {
    let mut disabled = DisabledTokens::default();
    let first = disabled.begin(T0).expect("due");
    disabled.record(first, Err(BridgeError::Blob("listing failed".into())));
    assert!(disabled
        .begin(UnixMs(T0.0 + LIST_AGAIN_SHUT_MS - 1))
        .is_none());
    let again = disabled
        .begin(UnixMs(T0.0 + LIST_AGAIN_SHUT_MS))
        .expect("due again while shut");
    disabled.record(again, Ok(BTreeSet::new()));
    assert!(present(
        &configured_hashes(),
        &disabled,
        STANDARD,
        UnixMs(T0.0 + LIST_AGAIN_SHUT_MS)
    )
    .is_ok());
}
