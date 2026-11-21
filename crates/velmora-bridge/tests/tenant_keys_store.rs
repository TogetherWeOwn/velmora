use std::rc::Rc;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::{
    open_record_v2, seal_record_v2, tk_blob_check_value, tk_blob_name, wrap_tenant_key, TenantId,
    TenantKey,
};
use velmora_bridge::keys::audit::{audit, repair_missing, Finding};
use velmora_bridge::keys::escrow::{restore_escrow, EscrowCopy, RestoreStep};
use velmora_bridge::keys::locations::{
    read_locations, two_in_account, write_locations, KeyLocation, KeyLocations, LocationStatus,
};
use velmora_bridge::keys::record::TkRing;
use velmora_bridge::keys::store::MemRecords;
use velmora_bridge::keys::tk::{is_foreign, KeyBuckets, LoadedRing, TkCache};
use velmora_bridge::testkit::{FixedClock, TestKek};
use velmora_bridge::{BridgeError, UnixMs};

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

struct TestRng {
    seed: [u8; 32],
    counter: u64,
}

impl TestRng {
    fn new(label: &str) -> Self {
        Self {
            seed: derived(label),
            counter: 0,
        }
    }
}

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut hash = Sha256::new();
            hash.update(self.seed);
            hash.update(self.counter.to_be_bytes());
            self.counter += 1;
            block.copy_from_slice(&hash.finalize()[..block.len()]);
        }
        Ok(())
    }
}

fn kek() -> TestKek {
    TestKek::with_versions(1, &[(1, derived("tenant keys store kek"))])
}

fn tenant(n: u8) -> TenantId {
    TenantId::parse(&format!("t_00000000000000{n:02x}")).unwrap()
}

fn key(tenant: &TenantId, version: u32, label: &str) -> TenantKey {
    TenantKey::from_bytes(tenant, version, derived(label)).unwrap()
}

fn wrapped(kek: &TestKek, key: &TenantKey, rng: &mut TestRng) -> (String, Vec<u8>) {
    let (version, blob) = wrap_tenant_key(kek, key, rng).unwrap();
    (tk_blob_name(key.tenant(), key.version(), version), blob)
}

fn clock() -> FixedClock {
    FixedClock::new(UnixMs(1_700_000_000_000))
}

#[derive(Default)]
struct Stores {
    a: MemRecords,
    b: MemRecords,
}

impl Stores {
    fn buckets(&self) -> KeyBuckets<'_, MemRecords> {
        KeyBuckets {
            by_name: vec![("KEYS_A", &self.a), ("KEYS_B", &self.b)],
        }
    }

    fn plant_both(&self, name: &str, blob: &[u8]) {
        self.a.plant(name, blob.to_vec());
        self.b.plant(name, blob.to_vec());
    }
}

fn retired_set() -> KeyLocations {
    KeyLocations {
        v: 1,
        seq: 2,
        locations: vec![
            KeyLocation {
                name: "KEYS_A".into(),
                status: LocationStatus::Active,
                arbiter: true,
                synchronous: true,
            },
            KeyLocation {
                name: "KEYS_B".into(),
                status: LocationStatus::Retired,
                arbiter: false,
                synchronous: true,
            },
        ],
    }
}

#[test]
fn two_in_account_lists_the_arbiter_first() {
    let mut set = two_in_account();
    set.check().unwrap();
    assert_eq!(set.arbiter().name, "KEYS_A");
    set.locations.reverse();
    let active: Vec<_> = set.active().iter().map(|l| l.name.as_str()).collect();
    assert_eq!(active, ["KEYS_A", "KEYS_B"]);
    let copies: Vec<_> = set
        .synchronous_copies()
        .iter()
        .map(|l| l.name.as_str())
        .collect();
    assert_eq!(copies, ["KEYS_B"]);
}

#[test]
fn location_checks_refuse_invalid_sets() {
    let mut no_arbiter = two_in_account();
    no_arbiter.locations[0].arbiter = false;
    let mut two_arbiters = two_in_account();
    two_arbiters.locations[1].arbiter = true;
    let mut proposed = two_in_account();
    proposed.locations[0].status = LocationStatus::Proposed;
    let mut asynchronous = two_in_account();
    asynchronous.locations[0].synchronous = false;
    let mut duplicate = two_in_account();
    duplicate.locations[1].name = "KEYS_A".into();
    let mut lowercase = two_in_account();
    lowercase.locations[1].name = "keys_b".into();
    let mut zero = two_in_account();
    zero.seq = 0;
    for (case, set) in [
        ("no arbiter", no_arbiter),
        ("two arbiters", two_arbiters),
        ("proposed arbiter", proposed),
        ("asynchronous arbiter", asynchronous),
        ("duplicate name", duplicate),
        ("lowercase name", lowercase),
        ("zero sequence", zero),
    ] {
        assert!(set.check().is_err(), "{case}");
    }
}

#[test]
fn locations_admit_only_valid_successors() {
    use LocationStatus::{Active, Lost, Proposed, Retired};

    let set = two_in_account();
    let mut next = set.clone();
    next.seq += 1;
    let retired = retired_set();
    let mut lost = next.clone();
    lost.locations[1].status = Lost;
    let mut proposed = next.clone();
    proposed.locations.push(KeyLocation {
        name: "KEYS_C".into(),
        status: Proposed,
        arbiter: false,
        synchronous: true,
    });
    for allowed in [&next, &retired, &lost, &proposed] {
        set.admits(allowed).unwrap();
    }

    let mut skipped = next.clone();
    skipped.seq += 1;
    let mut removed = next.clone();
    removed.locations.pop();
    let mut retired_arbiter = next.clone();
    retired_arbiter.locations[0].status = Retired;
    let mut lost_arbiter = next.clone();
    lost_arbiter.locations[0].status = Lost;
    let mut moved_arbiter = next.clone();
    moved_arbiter.locations[0].arbiter = false;
    moved_arbiter.locations[1].arbiter = true;
    let mut flipped_sync = next.clone();
    flipped_sync.locations[1].synchronous = false;
    let mut added_active = proposed;
    added_active.locations[2].status = Active;

    for (case, refused) in [
        ("skipped sequence", skipped),
        ("removed location", removed),
        ("retired arbiter", retired_arbiter),
        ("lost arbiter", lost_arbiter),
        ("moved arbiter", moved_arbiter),
        ("changed synchronous flag", flipped_sync),
        ("new active location", added_active),
    ] {
        assert!(set.admits(&refused).is_err(), "{case}");
    }

    next.seq += 1;
    assert!(
        retired.admits(&next).is_err(),
        "reactivated retired location"
    );
    next.locations[1].status = Retired;
    assert!(lost.admits(&next).is_err(), "changed lost location");
}

#[tokio::test(flavor = "current_thread")]
async fn location_records_advance_the_head_and_reject_garbage() {
    let (store, kek) = (MemRecords::new(), kek());
    let mut rng = TestRng::new("location records");
    let initial = two_in_account();
    let mut skipped = initial.clone();
    skipped.seq = 2;
    assert_eq!(read_locations(&store, &kek, 0).await.unwrap(), None);
    assert!(write_locations(&store, &kek, &skipped, &mut rng)
        .await
        .is_err());
    assert!(write_locations(&store, &kek, &initial, &mut rng)
        .await
        .unwrap());
    assert_eq!(
        read_locations(&store, &kek, 0).await.unwrap(),
        Some(initial)
    );

    let retired = retired_set();
    assert!(write_locations(&store, &kek, &retired, &mut rng)
        .await
        .unwrap());
    assert_eq!(
        read_locations(&store, &kek, 0).await.unwrap(),
        Some(retired)
    );
    assert!(write_locations(&store, &kek, &skipped, &mut rng)
        .await
        .is_err());
    assert_eq!(store.names_under("m/kl/").len(), 2);

    store.plant("m/kl/00000000000000000003", b"garbage".to_vec());
    assert!(read_locations(&store, &kek, 0).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn cached_keys_are_read_again_at_sixty_seconds() {
    let (stores, set, kek, clock, tenant) = (
        Stores::default(),
        two_in_account(),
        kek(),
        clock(),
        tenant(1),
    );
    let buckets = stores.buckets();
    let original = key(&tenant, 1, "cached key");
    let (name, blob) = wrapped(&kek, &original, &mut TestRng::new("cache"));
    stores.a.plant(&name, blob);
    let cache = TkCache::default();

    let loaded = cache
        .load(&set, &buckets, &kek, &clock, &tenant, 1, None)
        .await
        .unwrap();
    assert_eq!(loaded.check_value(), original.check_value());
    let lists = stores.a.lists();
    let cached = cache
        .load(&set, &buckets, &kek, &clock, &tenant, 1, None)
        .await
        .unwrap();
    assert!(Rc::ptr_eq(&loaded, &cached));
    assert_eq!(stores.a.lists(), lists);

    clock.advance_ms(60_000);
    let reloaded = cache
        .load(&set, &buckets, &kek, &clock, &tenant, 1, None)
        .await
        .unwrap();
    assert!(stores.a.lists() > lists);
    assert_eq!(reloaded.check_value(), original.check_value());
}

#[tokio::test(flavor = "current_thread")]
async fn loading_falls_back_to_the_second_bucket_and_reports_missing_keys() {
    let (stores, set, kek, clock, tenant) = (
        Stores::default(),
        two_in_account(),
        kek(),
        clock(),
        tenant(1),
    );
    let buckets = stores.buckets();
    let original = key(&tenant, 1, "fallback key");
    let (name, blob) = wrapped(&kek, &original, &mut TestRng::new("fallback"));
    stores.b.plant(&name, blob);
    let loaded = TkCache::default()
        .load(&set, &buckets, &kek, &clock, &tenant, 1, None)
        .await
        .unwrap();
    assert_eq!(loaded.check_value(), original.check_value());

    assert!(stores.b.lose(&name));
    let error = TkCache::default()
        .load(&set, &buckets, &kek, &clock, &tenant, 1, None)
        .await
        .unwrap_err();
    assert!(
        matches!(error, BridgeError::Crypto("tenant key is missing")),
        "{error:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_foreign_name_evicts_all_cached_versions_of_the_tenant() {
    let (stores, set, kek, clock, tenant) = (
        Stores::default(),
        two_in_account(),
        kek(),
        clock(),
        tenant(1),
    );
    let buckets = stores.buckets();
    let cache = TkCache::default();
    let mut rng = TestRng::new("foreign cache name");
    for version in [1, 2] {
        let original = key(&tenant, version, &format!("cached version {version}"));
        let (name, blob) = wrapped(&kek, &original, &mut rng);
        stores.a.plant(&name, blob);
        cache
            .load(&set, &buckets, &kek, &clock, &tenant, version, None)
            .await
            .unwrap();
    }
    assert_eq!(cache.len(), 2);

    stores.a.plant(&format!("m/tk/{tenant}/shredded"), vec![]);
    clock.advance_ms(60_001);
    let error = cache
        .load(&set, &buckets, &kek, &clock, &tenant, 1, None)
        .await
        .unwrap_err();
    assert!(is_foreign(&error), "{error:?}");
    assert_eq!(cache.len(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn loading_prefers_the_active_kek_and_accepts_an_older_kek() {
    let (stores, set, clock, tenant) = (Stores::default(), two_in_account(), clock(), tenant(1));
    let buckets = stores.buckets();
    let old_kek = kek();
    let kek = TestKek::with_versions(
        2,
        &[(1, derived("tenant keys store kek")), (2, derived("kek 2"))],
    );
    let original = key(&tenant, 1, "rewrapped key");
    let mut rng = TestRng::new("two kek versions");
    let (old_name, mut old_blob) = wrapped(&old_kek, &original, &mut rng);
    stores.a.plant(&old_name, old_blob.clone());
    let loaded = TkCache::default()
        .load(&set, &buckets, &kek, &clock, &tenant, 1, None)
        .await
        .unwrap();
    assert_eq!(loaded.check_value(), original.check_value());

    let (new_name, new_blob) = wrapped(&kek, &original, &mut rng);
    stores.a.plant(&new_name, new_blob);
    old_blob[40] ^= 1;
    stores.a.plant(&old_name, old_blob);
    let loaded = TkCache::default()
        .load(&set, &buckets, &kek, &clock, &tenant, 1, None)
        .await
        .unwrap();
    assert_eq!(loaded.check_value(), original.check_value());
}

#[test]
fn loaded_rings_find_each_version_and_refuse_keys_from_other_tenants() {
    let current = Rc::new(key(&tenant(1), 2, "current"));
    let older = Rc::new(key(&tenant(1), 1, "older"));
    let foreign = Rc::new(key(&tenant(2), 1, "foreign"));
    assert!(LoadedRing::new(current.clone(), vec![foreign]).is_err());

    let ring = LoadedRing::new(current.clone(), vec![older.clone()]).unwrap();
    assert!(std::ptr::eq(ring.current().unwrap(), current.as_ref()));
    assert!(std::ptr::eq(ring.key(2).unwrap(), current.as_ref()));
    assert!(std::ptr::eq(ring.key(1).unwrap(), older.as_ref()));
    assert!(ring.key(3).is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn audit_reports_two_clean_copies_for_each_tenant() {
    let (stores, set, kek) = (Stores::default(), two_in_account(), kek());
    let mut rng = TestRng::new("clean audit");
    let mut names = Vec::new();
    for n in [1, 2] {
        let original = key(&tenant(n), 1, &format!("tenant {n} audit key"));
        let (name, blob) = wrapped(&kek, &original, &mut rng);
        stores.plant_both(&name, &blob);
        names.push(name);
    }

    let report = audit(&set, &stores.buckets(), Some(&kek)).await.unwrap();
    assert!(report.clean(), "{:?}", report.findings);
    assert_eq!(report.blobs.len(), 2);
    for name in names {
        let copies = &report.blobs[&name];
        assert_eq!(copies.len(), 2);
        assert_eq!(copies["KEYS_A"], copies["KEYS_B"]);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn repair_restores_a_missing_copy_byte_for_byte() {
    let (stores, set, kek) = (Stores::default(), two_in_account(), kek());
    let buckets = stores.buckets();
    let original = key(&tenant(1), 1, "missing copy");
    let (name, blob) = wrapped(&kek, &original, &mut TestRng::new("repair missing"));
    stores.plant_both(&name, &blob);
    assert!(stores.b.lose(&name));

    let report = audit(&set, &buckets, Some(&kek)).await.unwrap();
    assert_eq!(
        report.findings,
        [Finding::Missing {
            location: "KEYS_B".into(),
            name: name.clone(),
        }]
    );
    assert_eq!(
        repair_missing(&set, &buckets, &report).await.unwrap(),
        [("KEYS_B".into(), name.clone())]
    );
    assert_eq!(stores.b.raw(&name), stores.a.raw(&name));
    assert!(audit(&set, &buckets, Some(&kek)).await.unwrap().clean());
}

#[tokio::test(flavor = "current_thread")]

async fn audit_flags_both_mismatches_when_copies_of_one_name_disagree() {
    let (stores, set, kek, tenant) = (Stores::default(), two_in_account(), kek(), tenant(1));
    let buckets = stores.buckets();
    let mut rng = TestRng::new("same name mismatch");
    let (name, first) = wrapped(&kek, &key(&tenant, 1, "first key"), &mut rng);
    let (second_name, second) = wrapped(&kek, &key(&tenant, 1, "different key"), &mut rng);
    assert_eq!(name, second_name);
    stores.a.plant(&name, first.clone());
    stores.b.plant(&name, second.clone());

    let report = audit(&set, &buckets, Some(&kek)).await.unwrap();
    let puts = (stores.a.puts(), stores.b.puts());
    assert!(repair_missing(&set, &buckets, &report)
        .await
        .unwrap()
        .is_empty());
    assert_eq!((stores.a.puts(), stores.b.puts()), puts);
    assert_eq!(stores.a.names(), std::slice::from_ref(&name));
    assert_eq!(stores.b.names(), std::slice::from_ref(&name));
    assert_eq!(stores.a.raw(&name), Some(first));
    assert_eq!(stores.b.raw(&name), Some(second));
    assert_eq!(
        report.findings,
        [
            Finding::Mismatch { name },
            Finding::VersionMismatch {
                tenant: tenant.to_string(),
                version: 1
            },
        ]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn audit_flags_version_mismatch_across_kek_versions() {
    let (stores, set, old_kek, tenant) = (Stores::default(), two_in_account(), kek(), tenant(1));
    let kek = TestKek::with_versions(
        2,
        &[(1, derived("tenant keys store kek")), (2, derived("kek 2"))],
    );
    let mut rng = TestRng::new("different kek mismatch");
    let (old_name, old_blob) = wrapped(&old_kek, &key(&tenant, 1, "key x"), &mut rng);
    let (new_name, new_blob) = wrapped(&kek, &key(&tenant, 1, "key y"), &mut rng);
    stores.plant_both(&old_name, &old_blob);
    stores.plant_both(&new_name, &new_blob);

    let report = audit(&set, &stores.buckets(), Some(&kek)).await.unwrap();
    assert_eq!(
        report.findings,
        [Finding::VersionMismatch {
            tenant: tenant.to_string(),
            version: 1,
        }]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn audit_reports_foreign_names_and_repair_skips_the_tenant() {
    let (stores, set, kek, tenant) = (Stores::default(), two_in_account(), kek(), tenant(1));
    let buckets = stores.buckets();
    let (name, blob) = wrapped(
        &kek,
        &key(&tenant, 1, "foreign directory key"),
        &mut TestRng::new("foreign audit"),
    );
    let marker = format!("m/tk/{tenant}/shredded");
    stores.a.plant(&name, blob);
    stores.a.plant(&marker, vec![]);
    stores.b.plant("m/tk/garbage", vec![]);

    let report = audit(&set, &buckets, Some(&kek)).await.unwrap();
    assert_eq!(
        report.findings,
        [
            Finding::Missing {
                location: "KEYS_B".into(),
                name: name.clone()
            },
            Finding::Foreign {
                location: "KEYS_A".into(),
                name: marker
            },
            Finding::Foreign {
                location: "KEYS_B".into(),
                name: "m/tk/garbage".into()
            },
        ]
    );
    assert!(repair_missing(&set, &buckets, &report)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(stores.b.names(), ["m/tk/garbage"]);
}

#[tokio::test(flavor = "current_thread")]
async fn audit_reports_copies_in_retired_locations() {
    let (stores, set, kek) = (Stores::default(), retired_set(), kek());
    let (name, blob) = wrapped(
        &kek,
        &key(&tenant(1), 1, "retired copy"),
        &mut TestRng::new("inactive audit"),
    );
    stores.plant_both(&name, &blob);

    let report = audit(&set, &stores.buckets(), Some(&kek)).await.unwrap();
    assert_eq!(
        report.findings,
        [Finding::Inactive {
            location: "KEYS_B".into(),
            name: name.clone(),
        }]
    );
    assert!(stores.b.lose(&name));
    assert!(audit(&set, &stores.buckets(), Some(&kek))
        .await
        .unwrap()
        .clean());
}

#[tokio::test(flavor = "current_thread")]
async fn audit_detects_corrupt_ciphertext_when_given_the_kek() {
    let (stores, set, kek) = (Stores::default(), two_in_account(), kek());
    let buckets = stores.buckets();
    let (name, mut blob) = wrapped(
        &kek,
        &key(&tenant(1), 1, "corrupted copy"),
        &mut TestRng::new("ciphertext audit"),
    );
    stores.b.plant(&name, blob.clone());
    blob[40] ^= 1;
    stores.a.plant(&name, blob);

    let report = audit(&set, &buckets, Some(&kek)).await.unwrap();
    assert_eq!(
        report.findings,
        [Finding::Unopenable {
            location: "KEYS_A".into(),
            name
        }]
    );
    assert!(audit(&set, &buckets, None::<&TestKek>)
        .await
        .unwrap()
        .clean());
}

fn escrow_fixture() -> (TestKek, TenantKey, EscrowCopy) {
    let kek = kek();
    let original = key(&tenant(1), 1, "escrowed key");
    let (version, blob) =
        wrap_tenant_key(&kek, &original, &mut TestRng::new("escrow copy")).unwrap();
    let copy = EscrowCopy::of_blob(original.tenant(), original.version(), version, &blob).unwrap();
    (kek, original, copy)
}

#[test]
fn escrow_text_round_trips_and_opens_with_the_original_kek() {
    let (kek, original, copy) = escrow_fixture();
    let text = copy.to_text();
    assert_eq!(text.lines().count(), 7);
    assert!(text.starts_with("velmora tenant key escrow v1\n"));
    let hex: String = tk_blob_check_value(copy.blob())
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(text.lines().nth(4).unwrap(), format!("kcv: {hex}"));
    let parsed = EscrowCopy::parse(&text).unwrap();
    assert_eq!(parsed, copy);
    assert_eq!(
        parsed.open(&kek).unwrap().check_value(),
        original.check_value()
    );
}

#[test]
fn escrow_parser_refuses_single_character_changes_and_invalid_line_counts() {
    let (_, _, copy) = escrow_fixture();
    let text = copy.to_text();
    for (index, byte) in text.bytes().enumerate() {
        let replacement = match byte {
            b'\n' => continue,
            b'0' => b'1',
            b'1' => b'0',
            b'a' => b'b',
            b'b' => b'a',
            b'x' => b'y',
            _ => b'x',
        };
        let mut changed = text.as_bytes().to_vec();
        changed[index] = replacement;
        assert!(
            EscrowCopy::parse(std::str::from_utf8(&changed).unwrap()).is_err(),
            "accepted byte {index} changed from {:?} to {:?}",
            char::from(byte),
            char::from(replacement)
        );
    }
    assert!(EscrowCopy::parse(text.strip_suffix('\n').unwrap()).is_err());
    assert!(EscrowCopy::parse(&format!("{text}extra\n")).is_err());
    assert!(EscrowCopy::parse("").is_err());
}

#[test]
fn escrow_open_refuses_a_different_kek() {
    let (_, _, copy) = escrow_fixture();
    let other = TestKek::with_versions(1, &[(1, derived("other"))]);
    assert!(copy.open(&other).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn escrow_restores_both_lost_copies_and_opens_existing_records() {
    let (kek, original, copy) = escrow_fixture();
    let (stores, set) = (Stores::default(), two_in_account());
    let buckets = stores.buckets();
    let tenant = original.tenant();
    let record_name = format!("m/x/{tenant}/g_1");
    let sealed = seal_record_v2(
        &original,
        &record_name,
        b"data",
        &mut TestRng::new("record before loss"),
    )
    .unwrap();

    let name = copy.name();
    stores.plant_both(&name, copy.blob());
    assert!(stores.a.lose(&name));
    assert!(stores.b.lose(&name));
    assert_eq!(
        restore_escrow(&copy, &kek, &set, &buckets).await.unwrap(),
        [
            ("KEYS_A".into(), RestoreStep::Restored),
            ("KEYS_B".into(), RestoreStep::Restored)
        ]
    );

    let loaded = TkCache::default()
        .load(&set, &buckets, &kek, &clock(), tenant, 1, None)
        .await
        .unwrap();
    assert_eq!(loaded.check_value(), original.check_value());
    assert_eq!(
        &open_record_v2(&loaded, tenant, &record_name, &sealed).unwrap()[..],
        b"data"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn escrow_leaves_present_copies_without_calling_put() {
    let (kek, _, copy) = escrow_fixture();
    let stores = Stores::default();
    stores.plant_both(&copy.name(), copy.blob());
    let puts = (stores.a.puts(), stores.b.puts());

    assert_eq!(
        restore_escrow(&copy, &kek, &two_in_account(), &stores.buckets())
            .await
            .unwrap(),
        [
            ("KEYS_A".into(), RestoreStep::Present),
            ("KEYS_B".into(), RestoreStep::Present)
        ]
    );
    assert_eq!((stores.a.puts(), stores.b.puts()), puts);
}

#[tokio::test(flavor = "current_thread")]
async fn escrow_reports_conflicting_keys_and_preserves_their_bytes() {
    let (kek, original, copy) = escrow_fixture();
    let stores = Stores::default();
    let name = copy.name();
    stores.a.plant(&name, copy.blob().to_vec());
    let (other_name, other) = wrapped(
        &kek,
        &key(original.tenant(), 1, "conflicting key"),
        &mut TestRng::new("conflicting escrow"),
    );
    assert_eq!(name, other_name);
    stores.b.plant(&name, other.clone());

    assert_eq!(
        restore_escrow(&copy, &kek, &two_in_account(), &stores.buckets())
            .await
            .unwrap(),
        [
            ("KEYS_A".into(), RestoreStep::Present),
            ("KEYS_B".into(), RestoreStep::Conflict)
        ]
    );
    assert_eq!(stores.b.raw(&name), Some(other));
}

#[tokio::test(flavor = "current_thread")]
async fn escrow_refuses_a_foreign_name_before_writing_to_the_second_bucket() {
    let (kek, original, copy) = escrow_fixture();
    let stores = Stores::default();
    stores
        .a
        .plant(&format!("m/tk/{}/shredded", original.tenant()), vec![]);
    assert!(stores.b.names().is_empty());
    let puts = stores.b.puts();

    assert!(
        restore_escrow(&copy, &kek, &two_in_account(), &stores.buckets())
            .await
            .is_err()
    );
    assert!(stores.b.names().is_empty());
    assert_eq!(stores.b.puts(), puts);
}
