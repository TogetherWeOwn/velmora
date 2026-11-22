use std::rc::Rc;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::{
    tk_blob_check_value, tk_blob_name, wrap_tenant_key, TenantId, TenantKey,
};
use velmora_bridge::keys::audit::{audit, audit_page, repair_missing, Finding};
use velmora_bridge::keys::escrow::{restore_check, EscrowCopy};
use velmora_bridge::keys::locations::two_in_account;
use velmora_bridge::keys::tk::{
    create_key_version, is_foreign, tk_prefix, Claim, Commit, KeyBuckets, KeyVersionClaims, TkCache,
};
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::testkit::{FixedClock, TestKek};
use velmora_bridge::{BridgeError, Result, UnixMs};

#[derive(Default)]
struct TestRng(u64);

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut hash = Sha256::new();
            hash.update(b"tenant keys probes");
            hash.update(self.0.to_be_bytes());
            self.0 += 1;
            block.copy_from_slice(&hash.finalize()[..block.len()]);
        }
        Ok(())
    }
}

fn tenant() -> TenantId {
    TenantId::parse("t_00000000000000a1").unwrap()
}

fn kek(version: u32) -> TestKek {
    TestKek::with_versions(
        version,
        &[(version, Sha256::digest(version.to_be_bytes()).into())],
    )
}

fn key(tenant: &TenantId, version: u32, label: &str) -> TenantKey {
    TenantKey::from_bytes(tenant, version, Sha256::digest(label.as_bytes()).into()).unwrap()
}

fn wrapped(kek: &TestKek, key: &TenantKey, rng: &mut TestRng) -> (String, Vec<u8>) {
    let (version, blob) = wrap_tenant_key(kek, key, rng).unwrap();
    (tk_blob_name(key.tenant(), key.version(), version), blob)
}

fn marker(tenant: &TenantId) -> String {
    format!("{}shredded", tk_prefix(tenant))
}

fn buckets<'a, S>(a: &'a S, b: &'a S) -> KeyBuckets<'a, S> {
    KeyBuckets {
        by_name: vec![("KEYS_A", a), ("KEYS_B", b)],
    }
}

/// Audit compares both copies on later pages and joins KEK names across a page boundary.
#[tokio::test(flavor = "current_thread")]
async fn audit_compares_all_pages() {
    let (tenant, set, first_kek) = (tenant(), two_in_account(), kek(1));
    let mut rng = TestRng::default();
    let (a, b) = (MemRecords::new(), MemRecords::new());
    let first_buckets = buckets(&a, &b);
    for version in 1..=1001 {
        let (name, blob) = wrapped(&first_kek, &key(&tenant, version, "original"), &mut rng);
        a.plant(&name, blob.clone());
        b.plant(&name, blob);
    }

    // Decimal names sort lexically, so 999 is the last of these names.
    let (name, different) = wrapped(&first_kek, &key(&tenant, 999, "different"), &mut rng);
    a.plant(&name, different);
    let report = audit(&set, &first_buckets, Some(&first_kek)).await.unwrap();
    assert_eq!(report.blobs.len(), 1001);
    assert_eq!(
        report.findings,
        [
            Finding::Mismatch { name },
            Finding::VersionMismatch {
                tenant: tenant.to_string(),
                version: 999,
            },
        ]
    );

    let (a, b) = (MemRecords::new(), MemRecords::new());
    let split_buckets = buckets(&a, &b);
    let second_kek = kek(2);
    let ring = TestKek::with_versions(
        2,
        &[
            (1, Sha256::digest(1u32.to_be_bytes()).into()),
            (2, Sha256::digest(2u32.to_be_bytes()).into()),
        ],
    );
    // These 999 names sort before 1001.1 and place it at the page boundary.
    for version in 1_000_000..1_000_999 {
        let (name, blob) = wrapped(&first_kek, &key(&tenant, version, "original"), &mut rng);
        a.plant(&name, blob.clone());
        b.plant(&name, blob);
    }
    let (old_name, old_blob) = wrapped(&first_kek, &key(&tenant, 1001, "original"), &mut rng);
    let (new_name, new_blob) = wrapped(&second_kek, &key(&tenant, 1001, "different"), &mut rng);
    a.plant(&old_name, old_blob);
    a.plant(&new_name, new_blob);

    let (page, cursor) = audit_page(&set, &split_buckets, Some(&ring), &tk_prefix(&tenant), 1000)
        .await
        .unwrap();
    assert_eq!(cursor.as_deref(), Some(old_name.as_str()));
    assert!(page.blobs.contains_key(&old_name));
    assert!(!page.blobs.contains_key(&new_name));
    let report = audit(&set, &split_buckets, Some(&ring)).await.unwrap();
    assert!(report.findings.contains(&Finding::VersionMismatch {
        tenant: tenant.to_string(),
        version: 1001,
    }));
}

struct CommittedClaim<'a>(&'a TenantKey);

impl KeyVersionClaims for CommittedClaim<'_> {
    async fn claim(&self, tenant: &TenantId, from: u32) -> Result<Claim> {
        assert_eq!(tenant, self.0.tenant());
        assert!(from < self.0.version());
        Ok(Claim::Committed {
            version: self.0.version(),
            kcv: self.0.check_value(),
        })
    }

    async fn void(&self, _: &TenantId, _: u32) -> Result<Claim> {
        panic!("a committed claim must not be voided");
    }

    async fn commit(&self, _: &TenantId, _: u32, _: [u8; 8]) -> Result<Commit> {
        panic!("a committed claim must not be committed again");
    }
}

/// Committed adoption refuses the arbiter's shred marker even with a valid replica.
#[tokio::test(flavor = "current_thread")]
async fn committed_adoption_refuses_a_shred_marker() {
    let (tenant, set, kek) = (tenant(), two_in_account(), kek(1));
    let (a, b) = (MemRecords::new(), MemRecords::new());
    let committed = key(&tenant, 1, "committed");
    let mut rng = TestRng::default();
    let (name, blob) = wrapped(&kek, &committed, &mut rng);
    b.plant(&name, blob);
    a.plant(&marker(&tenant), vec![]);

    let error = create_key_version(
        &set,
        &buckets(&a, &b),
        &CommittedClaim(&committed),
        &kek,
        &tenant,
        0,
        &mut rng,
    )
    .await
    .unwrap_err();
    assert!(is_foreign(&error), "{error:?}");
    assert_eq!(b.lists(), 0);
}

/// Committed adoption reads the replica when the arbiter's blob header is damaged.
#[tokio::test(flavor = "current_thread")]
async fn committed_adoption_falls_back_from_a_damaged_header() {
    let (tenant, set, kek) = (tenant(), two_in_account(), kek(1));
    let (a, b) = (MemRecords::new(), MemRecords::new());
    let committed = key(&tenant, 1, "committed");
    let mut rng = TestRng::default();
    let (name, mut blob) = wrapped(&kek, &committed, &mut rng);
    b.plant(&name, blob.clone());
    blob[committed.check_value().len()] ^= 1;
    assert!(tk_blob_check_value(&blob).is_err());
    a.plant(&name, blob);

    let created = create_key_version(
        &set,
        &buckets(&a, &b),
        &CommittedClaim(&committed),
        &kek,
        &tenant,
        0,
        &mut rng,
    )
    .await
    .unwrap();
    assert_eq!(created.key.version(), committed.version());
    assert_eq!(created.key.check_value(), committed.check_value());
    assert_eq!(created.kek_version, 1);
    assert!(!created.generated_here);
}

/// A foreign-name load error evicts fresh tenant cache entries, while a missing key leaves them cached.
#[tokio::test(flavor = "current_thread")]
async fn cache_only_forgets_the_tenant_on_foreign_errors() {
    let (tenant, set, kek) = (tenant(), two_in_account(), kek(1));
    let (a, b) = (MemRecords::new(), MemRecords::new());
    let buckets = buckets(&a, &b);
    let (cache, clock) = (
        TkCache::default(),
        FixedClock::new(UnixMs(1_700_000_000_000)),
    );
    let existing = key(&tenant, 1, "cached");
    let missing = key(&tenant, 2, "missing");
    let (name, blob) = wrapped(&kek, &existing, &mut TestRng::default());
    a.plant(&name, blob);

    let load = |key: &TenantKey| {
        cache.load(
            &set,
            &buckets,
            &kek,
            &clock,
            &tenant,
            key.version(),
            key.check_value(),
        )
    };
    let cached = load(&existing).await.unwrap();
    let error = load(&missing).await.unwrap_err();
    assert!(matches!(
        error,
        BridgeError::Crypto("tenant key is missing")
    ));
    let lists = (a.lists(), b.lists());
    let hit = load(&existing).await.unwrap();
    assert!(Rc::ptr_eq(&hit, &cached));
    assert_eq!((a.lists(), b.lists()), lists);

    a.plant(&marker(&tenant), vec![]);
    let error = load(&missing).await.unwrap_err();
    assert!(is_foreign(&error), "{error:?}");
    let lists = a.lists();
    let error = load(&existing).await.unwrap_err();
    assert!(is_foreign(&error), "{error:?}");
    assert!(a.lists() > lists);
}

/// A pinned blob under an unavailable KEK returns the distinct no-KEK error.
#[tokio::test(flavor = "current_thread")]
async fn cache_load_distinguishes_an_unavailable_kek() {
    let (tenant, set) = (tenant(), two_in_account());
    let (a, b) = (MemRecords::new(), MemRecords::new());
    let committed = key(&tenant, 1, "committed");
    let (name, blob) = wrapped(&kek(1), &committed, &mut TestRng::default());
    a.plant(&name, blob.clone());
    b.plant(&name, blob);

    let error = TkCache::default()
        .load(
            &set,
            &buckets(&a, &b),
            &kek(2),
            &FixedClock::new(UnixMs(1_700_000_000_000)),
            &tenant,
            committed.version(),
            committed.check_value(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            BridgeError::Crypto("tenant key copies are under a KEK this Worker lacks")
        ),
        "{error:?}"
    );
}

#[derive(Default)]
struct MarkerOnPut {
    records: MemRecords,
    marker: Option<String>,
}

impl RecordStore for MarkerOnPut {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        let written = self.records.put_if_absent(name, bytes).await?;
        if let Some(marker) = &self.marker {
            self.records.plant(marker, vec![]);
        }
        Ok(written)
    }

    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.records.get(name).await
    }

    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.records.list(prefix, start_after, limit).await
    }
}

/// Repair rechecks the audited check value and live listings, and alarms on a marker during the write.
#[tokio::test(flavor = "current_thread")]
async fn repair_rechecks_sources_listings_and_markers() {
    let (tenant, set, kek) = (tenant(), two_in_account(), kek(1));
    let a = MarkerOnPut::default();
    let marker = marker(&tenant);
    let b = MarkerOnPut {
        marker: Some(marker.clone()),
        ..MarkerOnPut::default()
    };
    let buckets = buckets(&a, &b);
    let mut rng = TestRng::default();
    let (name, original) = wrapped(&kek, &key(&tenant, 1, "original"), &mut rng);
    let (_, different) = wrapped(&kek, &key(&tenant, 1, "different"), &mut rng);
    a.records.plant(&name, original.clone());
    let report = audit(&set, &buckets, Some(&kek)).await.unwrap();
    assert_eq!(
        report.findings,
        [Finding::Missing {
            location: "KEYS_B".into(),
            name: name.clone()
        }]
    );

    a.records.plant(&name, different);
    let repair = repair_missing(&set, &buckets, &kek, &report).await.unwrap();
    assert!(repair.restored.is_empty());
    assert_eq!(b.records.puts(), 0);

    a.records.plant(&name, original.clone());
    b.records.refuse_lists(true);
    let repair = repair_missing(&set, &buckets, &kek, &report).await.unwrap();
    assert!(repair.restored.is_empty());
    assert_eq!(b.records.puts(), 0);
    b.records.refuse_lists(false);

    let repair = repair_missing(&set, &buckets, &kek, &report).await.unwrap();
    assert_eq!(repair.restored, [("KEYS_B".into(), name.clone())]);
    assert_eq!(repair.alarms, [("KEYS_B".into(), name.clone())]);
    assert_eq!(b.records.raw(&name), Some(original));
    assert_eq!(b.records.raw(&marker), Some(vec![]));
}

/// Escrow restore checks reject repeated labels even when two distinct buckets are represented.
#[test]
fn restore_check_rejects_duplicate_bucket_labels() {
    let (tenant, kek) = (tenant(), kek(1));
    let (_, blob) = wrapped(&kek, &key(&tenant, 1, "escrow"), &mut TestRng::default());
    let copy = EscrowCopy::of_blob(&tenant, 1, 1, &blob).unwrap();

    for (labels, expected) in [
        (&["KEYS_A", "KEYS_B"][..], true),
        (&["KEYS_A", "KEYS_A"][..], false),
        (&["KEYS_A", "KEYS_B", "KEYS_A"][..], false),
    ] {
        let blobs: Vec<_> = labels.iter().map(|&label| (label, blob.clone())).collect();
        let checks = restore_check(&copy, &kek, &blobs, None, None);
        assert!(checks.contains(&("open", true)));
        assert!(
            checks.contains(&("key_buckets", expected)),
            "{labels:?}: {checks:?}"
        );
    }
}

/// A key that opens in the arbiter is refused when the other
/// synchronous location holds a shred marker.
#[tokio::test(flavor = "current_thread")]
async fn a_marker_in_the_other_location_refuses_a_key_that_opens() {
    let (tenant, set, kek) = (tenant(), two_in_account(), kek(1));
    let (a, b) = (MemRecords::new(), MemRecords::new());
    let committed = key(&tenant, 1, "committed");
    let mut rng = TestRng::default();
    let (name, blob) = wrapped(&kek, &committed, &mut rng);
    a.plant(&name, blob);
    b.plant(&marker(&tenant), vec![]);
    let clock = velmora_bridge::testkit::FixedClock::new(velmora_bridge::UnixMs(1_700_000_000_000));
    let error = TkCache::default()
        .load(
            &set,
            &buckets(&a, &b),
            &kek,
            &clock,
            &tenant,
            1,
            committed.check_value(),
        )
        .await
        .unwrap_err();
    assert!(is_foreign(&error), "{error:?}");
}
