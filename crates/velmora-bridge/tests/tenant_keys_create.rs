//! Creating a tenant key version in the two key buckets, and the restore
//! test of an offline escrow copy, end to end in memory.

use std::cell::RefCell;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::{
    open_record_v2, seal_record_v2, tk_blob_check_value, tk_blob_name, unwrap_bdk_v2, wrap_bdk_v2,
    wrap_tenant_key, TenantId, TenantKey,
};
use velmora_bridge::crypto::DataKey;
use velmora_bridge::keys::escrow::{restore_check, restore_escrow, EscrowCopy, RestoreStep};
use velmora_bridge::keys::locations::two_in_account;
use velmora_bridge::keys::record::{
    seal_key_record, KeyOp, OneKey, SubjectDoor, SubjectKind, SubjectPrivate, SubjectStatus,
};
use velmora_bridge::keys::store::{MemRecords, RecordStore};
use velmora_bridge::keys::tk::{
    create_key_version, is_foreign, tk_prefix, Claim, Commit, KeyBuckets, KeyVersionClaims, TkCache,
};
use velmora_bridge::testkit::{FixedClock, TestKek};
use velmora_bridge::{BridgeError, BucketId, Result, UnixMs};

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

struct TestRng(u64);

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(b"tenant keys create");
            h.update(self.0.to_be_bytes());
            self.0 += 1;
            block.copy_from_slice(&h.finalize()[..block.len()]);
        }
        Ok(())
    }
}

fn tenant() -> TenantId {
    TenantId::parse("t_00000000000000a1").unwrap()
}

fn kek() -> TestKek {
    TestKek::with_versions(1, &[(1, derived("kek"))])
}

/// The tenant chain's claim and commit, as a small state machine.
#[derive(Default)]
struct Claims {
    state: RefCell<ClaimState>,
}

#[derive(Default)]
struct ClaimState {
    tk_version: u32,
    rotating_to: Option<u32>,
    highest: u32,
    refuse: bool,
    stop: bool,
    voids: Vec<u32>,
    commits: Vec<u32>,
    pinned: Option<[u8; 8]>,
}

impl KeyVersionClaims for Claims {
    async fn claim(&self, _t: &TenantId, from: u32) -> Result<Claim> {
        let mut s = self.state.borrow_mut();
        if s.refuse {
            return Ok(Claim::Refused);
        }
        if let Some(m) = s.rotating_to {
            return Ok(Claim::Claimed(m));
        }
        if s.tk_version > from {
            return Ok(Claim::Committed {
                version: s.tk_version,
                kcv: s.pinned.expect("a committed version is pinned"),
            });
        }
        s.highest += 1;
        s.rotating_to = Some(s.highest);
        Ok(Claim::Claimed(s.highest))
    }

    async fn void(&self, _t: &TenantId, version: u32) -> Result<Claim> {
        let mut s = self.state.borrow_mut();
        if s.rotating_to != Some(version) {
            return Err(BridgeError::Invalid("void of a claim that is not open"));
        }
        s.voids.push(version);
        s.highest = version + 1;
        s.rotating_to = Some(version + 1);
        Ok(Claim::Claimed(version + 1))
    }

    async fn commit(&self, _t: &TenantId, version: u32, kcv: [u8; 8]) -> Result<Commit> {
        let mut s = self.state.borrow_mut();
        if s.stop {
            return Ok(Commit::Stopped);
        }
        if s.rotating_to.is_none() && s.tk_version == version {
            // A concurrent run committed it: only with the same key.
            return match s.pinned.is_none_or(|p| p == kcv) {
                true => Ok(Commit::Committed),
                false => Err(BridgeError::Invalid("commit of another key")),
            };
        }
        if s.rotating_to != Some(version) {
            return Err(BridgeError::Invalid("commit of a claim that is not open"));
        }
        s.tk_version = version;
        s.rotating_to = None;
        s.pinned = Some(kcv);
        s.commits.push(version);
        Ok(Commit::Committed)
    }
}

struct World {
    a: MemRecords,
    b: MemRecords,
    claims: Claims,
    kek: TestKek,
    t: TenantId,
}

impl World {
    fn new() -> Self {
        World {
            a: MemRecords::new(),
            b: MemRecords::new(),
            claims: Claims::default(),
            kek: kek(),
            t: tenant(),
        }
    }

    fn buckets(&self) -> KeyBuckets<'_, MemRecords> {
        KeyBuckets {
            by_name: vec![("KEYS_A", &self.a), ("KEYS_B", &self.b)],
        }
    }

    fn blobs(store: &MemRecords, t: &TenantId) -> Vec<String> {
        store.names_under(&tk_prefix(t))
    }
}

fn is_crypto(e: &BridgeError, msg: &str) -> bool {
    matches!(e, BridgeError::Crypto(m) if *m == msg)
}

#[tokio::test(flavor = "current_thread")]
async fn the_first_key_is_created_in_the_arbiter_copied_and_committed() {
    let w = World::new();
    let set = two_in_account();
    let created = create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(1),
    )
    .await
    .unwrap();
    assert_eq!(created.key.version(), 1);
    assert_eq!(created.kek_version, 1);
    assert!(created.generated_here);
    assert!(created.voided.is_empty());
    let name = tk_blob_name(&w.t, 1, 1);
    assert_eq!(World::blobs(&w.a, &w.t), vec![name.clone()]);
    assert_eq!(World::blobs(&w.b, &w.t), vec![name.clone()]);
    assert_eq!(
        w.a.raw(&name),
        w.b.raw(&name),
        "the copy is the arbiter's bytes"
    );
    assert_eq!(
        tk_blob_check_value(&w.a.raw(&name).unwrap()).unwrap(),
        created.key.check_value()
    );
    let s = w.claims.state.borrow();
    assert_eq!(
        (s.tk_version, s.rotating_to, s.commits.clone()),
        (1, None, vec![1])
    );
}

/// Two runs on the same open claim end with the same key: the second
/// adopts what the arbiter holds.
#[tokio::test(flavor = "current_thread")]
async fn a_second_run_adopts_the_arbiters_key() {
    let w = World::new();
    let set = two_in_account();
    // Another run won the arbiter's put for version 1 and died before
    // copying it.
    let winner = TenantKey::from_bytes(&w.t, 1, derived("the other run")).unwrap();
    let (_, blob) = wrap_tenant_key(&w.kek, &winner, &mut TestRng(9)).unwrap();
    w.a.plant(&tk_blob_name(&w.t, 1, 1), blob.clone());
    w.claims.state.borrow_mut().highest = 1;
    w.claims.state.borrow_mut().rotating_to = Some(1);

    let created = create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(2),
    )
    .await
    .unwrap();
    assert!(!created.generated_here);
    assert_eq!(created.key.check_value(), winner.check_value());
    assert_eq!(w.b.raw(&tk_blob_name(&w.t, 1, 1)), Some(blob));
    // A run repeated after the commit (its answer was lost), from the
    // same base, adopts version 1 and starts no version 2.
    let again = create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(3),
    )
    .await
    .unwrap();
    assert_eq!(again.key.check_value(), winner.check_value());
    assert_eq!(again.key.version(), 1);
    assert_eq!(w.claims.state.borrow().highest, 1);
    assert_eq!(World::blobs(&w.a, &w.t).len(), 1);
}

/// Copies that disagree void the version; nothing is deleted.
#[tokio::test(flavor = "current_thread")]
async fn copies_that_disagree_void_the_version_and_delete_nothing() {
    let w = World::new();
    let set = two_in_account();
    let stray = TenantKey::from_bytes(&w.t, 1, derived("stray")).unwrap();
    let (_, stray_blob) = wrap_tenant_key(&w.kek, &stray, &mut TestRng(8)).unwrap();
    w.b.plant(&tk_blob_name(&w.t, 1, 1), stray_blob.clone());

    let created = create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(4),
    )
    .await
    .unwrap();
    assert_eq!(created.voided, vec![1]);
    assert_eq!(created.key.version(), 2);
    let s = w.claims.state.borrow();
    assert_eq!((s.voids.clone(), s.commits.clone()), (vec![1], vec![2]));
    // Both version-1 blobs are still there, untouched.
    assert_eq!(w.b.raw(&tk_blob_name(&w.t, 1, 1)), Some(stray_blob));
    assert!(w.a.raw(&tk_blob_name(&w.t, 1, 1)).is_some());
    assert_ne!(
        w.a.raw(&tk_blob_name(&w.t, 1, 1)),
        w.b.raw(&tk_blob_name(&w.t, 1, 1))
    );
    // Version 2 agrees in both.
    assert_eq!(
        w.a.raw(&tk_blob_name(&w.t, 2, 1)),
        w.b.raw(&tk_blob_name(&w.t, 2, 1))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_marker_or_a_foreign_name_stops_the_writer_before_any_write() {
    for (store_name, foreign) in [("a", "shredded"), ("b", "1.1.bak")] {
        let w = World::new();
        let set = two_in_account();
        let store = if store_name == "a" { &w.a } else { &w.b };
        store.plant(&format!("{}{foreign}", tk_prefix(&w.t)), b"x".to_vec());
        let e = create_key_version(
            &set,
            &w.buckets(),
            &w.claims,
            &w.kek,
            &w.t,
            0,
            &mut TestRng(5),
        )
        .await
        .unwrap_err();
        assert!(is_foreign(&e), "{e:?}");
        assert!(w.claims.state.borrow().commits.is_empty());
        if store_name == "a" {
            // Stopped in the arbiter before its put.
            assert_eq!(World::blobs(&w.a, &w.t).len(), 1);
            assert!(World::blobs(&w.b, &w.t).is_empty());
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_refused_claim_writes_nothing_and_a_stopped_commit_keeps_the_blob() {
    let w = World::new();
    let set = two_in_account();
    w.claims.state.borrow_mut().refuse = true;
    assert!(create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(6)
    )
    .await
    .is_err());
    assert!(w.a.names().is_empty() && w.b.names().is_empty());

    let w = World::new();
    w.claims.state.borrow_mut().stop = true;
    assert!(create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(7)
    )
    .await
    .is_err());
    // The blobs stay: nothing is deleted because a commit was refused.
    assert_eq!(World::blobs(&w.a, &w.t).len(), 1);
    assert_eq!(World::blobs(&w.b, &w.t).len(), 1);
}

/// A copy location that is down stops the run with the claim open; the
/// next run resumes and ends with the same key.
#[tokio::test(flavor = "current_thread")]
async fn a_run_that_could_not_copy_is_resumed_with_the_same_key() {
    let w = World::new();
    let set = two_in_account();
    w.b.refuse(&tk_prefix(&w.t));
    assert!(create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(10)
    )
    .await
    .is_err());
    assert_eq!(w.claims.state.borrow().rotating_to, Some(1));
    let first = w.a.raw(&tk_blob_name(&w.t, 1, 1)).unwrap();
    w.b.allow(&tk_prefix(&w.t));
    let created = create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(11),
    )
    .await
    .unwrap();
    assert_eq!(created.key.version(), 1);
    assert!(!created.generated_here);
    assert_eq!(w.a.raw(&tk_blob_name(&w.t, 1, 1)), Some(first.clone()));
    assert_eq!(w.b.raw(&tk_blob_name(&w.t, 1, 1)), Some(first));
}

#[tokio::test(flavor = "current_thread")]
async fn a_lost_answer_of_the_arbiters_put_is_read_back() {
    let w = World::new();
    let set = two_in_account();
    w.a.lose_answers(1);
    let created = create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(12),
    )
    .await
    .unwrap();
    assert!(created.generated_here);
    assert_eq!(
        w.a.raw(&tk_blob_name(&w.t, 1, 1)),
        w.b.raw(&tk_blob_name(&w.t, 1, 1))
    );
}

/// The escrow restore test: a tenant key is created, data is sealed
/// under it, both key buckets lose it, the offline copy brings it back,
/// and the data opens again.
#[tokio::test(flavor = "current_thread")]
async fn an_escrow_copy_restores_a_tenant_after_both_key_buckets_lost_its_key() {
    let w = World::new();
    let set = two_in_account();
    let clock = FixedClock::new(UnixMs(1_700_000_000_000));
    let mut rng = TestRng(20);
    let created = create_key_version(&set, &w.buckets(), &w.claims, &w.kek, &w.t, 0, &mut rng)
        .await
        .unwrap();
    let bucket = BucketId::mint([7; 8]);
    let bdk = DataKey::from_bytes(derived("bucket key"));
    let bdk_wrapped = wrap_bdk_v2(&created.key, &bucket, &bdk, &mut rng).unwrap();
    let name = format!("m/x/{}/g_0195c2a4b3e7f00112233445566778", w.t);
    let record = seal_record_v2(&created.key, &name, b"a generation", &mut rng).unwrap();

    // The operator's offline copy, taken from the arbiter after the
    // commit.
    let blob_name = tk_blob_name(&w.t, 1, created.kek_version);
    let blob = w.a.get(&blob_name).await.unwrap().unwrap();
    let text = EscrowCopy::of_blob(&w.t, 1, created.kek_version, &blob)
        .unwrap()
        .to_text();

    // Both key buckets lose it.
    assert!(w.a.lose(&blob_name) && w.b.lose(&blob_name));
    let cache = TkCache::new();
    let e = cache
        .load(&set, &w.buckets(), &w.kek, &clock, &w.t, 1, None)
        .await
        .unwrap_err();
    assert!(is_crypto(&e, "tenant key is missing"), "{e:?}");

    // The restore.
    let copy = EscrowCopy::parse(&text).unwrap();
    let steps = restore_escrow(&copy, &w.kek, &set, &w.buckets())
        .await
        .unwrap();
    assert_eq!(
        steps,
        vec![
            ("KEYS_A".to_owned(), RestoreStep::Restored),
            ("KEYS_B".to_owned(), RestoreStep::Restored),
        ]
    );
    let loaded = cache
        .load(&set, &w.buckets(), &w.kek, &clock, &w.t, 1, None)
        .await
        .unwrap();
    assert_eq!(loaded.check_value(), created.key.check_value());
    let back = unwrap_bdk_v2(&loaded, &w.t, 1, &bucket, &bdk_wrapped).unwrap();
    // The BDK that comes back is the one that was wrapped: it wraps to a
    // value that opens with the original key too.
    let rewrapped = wrap_bdk_v2(&loaded, &bucket, &back, &mut rng).unwrap();
    assert!(unwrap_bdk_v2(&created.key, &w.t, 1, &bucket, &rewrapped).is_ok());
    assert_eq!(
        &open_record_v2(&loaded, &w.t, &name, &record).unwrap()[..],
        b"a generation"
    );
    // A second restore finds both copies present and writes nothing.
    let puts = (w.a.puts(), w.b.puts());
    let steps = restore_escrow(&copy, &w.kek, &set, &w.buckets())
        .await
        .unwrap();
    assert!(steps.iter().all(|(_, s)| *s == RestoreStep::Present));
    assert_eq!((w.a.puts(), w.b.puts()), puts);

    // The restore test the operator runs before the move, with what the
    // key buckets hold, the newest key-chain record and a data record.
    let door = SubjectDoor {
        id: "PR0001".into(),
        kind: SubjectKind::Principal,
        status: SubjectStatus::Active,
        made_by: None,
        grants: Vec::new(),
        created_at: 1,
        secret_kek_version: None,
    };
    let private = SubjectPrivate {
        owner_ref: Some("member".into()),
        label: None,
        grants: Vec::new(),
        secret_wrapped: None,
    };
    let ring = OneKey(TenantKey::from_bytes(&w.t, 1, [0; 32]).unwrap());
    // Sealed under the real key: re-load it into a ring.
    let ring = OneKey(
        cache
            .load(&set, &w.buckets(), &w.kek, &clock, &w.t, 1, None)
            .await
            .map(|k| {
                let _ = &ring;
                // A ring needs an owned key; unwrap the blob again.
                velmora_bridge::crypto::scheme2::unwrap_tenant_key(
                    &w.kek,
                    created.kek_version,
                    &w.t,
                    k.version(),
                    &w.a.raw(&blob_name).unwrap(),
                )
                .unwrap()
            })
            .unwrap(),
    );
    let key_record = seal_key_record(
        &w.kek,
        &ring,
        &w.t,
        1,
        KeyOp::Create,
        1,
        &door,
        Some(&private),
        &mut rng,
    )
    .unwrap();
    let blobs = vec![w.a.raw(&blob_name).unwrap(), w.b.raw(&blob_name).unwrap()];
    let checks = restore_check(
        &copy,
        &w.kek,
        &blobs,
        Some((1, &key_record)),
        Some((&name, &record)),
    );
    assert_eq!(
        checks,
        vec![
            ("open", true),
            ("key_buckets", true),
            ("key_chain", true),
            ("data_record", true)
        ]
    );
    // A key bucket that holds another key, or another tenant's data
    // record, is a mismatch.
    let other = TenantKey::from_bytes(&w.t, 1, derived("other key")).unwrap();
    let (_, other_blob) = wrap_tenant_key(&w.kek, &other, &mut rng).unwrap();
    let checks = restore_check(&copy, &w.kek, &[blobs[0].clone(), other_blob], None, None);
    // A missing input is a mismatch, never a line left out.
    assert_eq!(
        checks,
        vec![
            ("open", true),
            ("key_buckets", false),
            ("key_chain", false),
            ("data_record", false)
        ]
    );
    // One bucket's blob alone is not both key buckets.
    let checks = restore_check(
        &copy,
        &w.kek,
        &blobs[..1],
        Some((1, &key_record)),
        Some((&name, &record)),
    );
    assert!(checks.contains(&("key_buckets", false)));
    let wrong_kek = TestKek::with_versions(1, &[(1, derived("not the kek"))]);
    let checks = restore_check(&copy, &wrong_kek, &blobs, Some((1, &key_record)), None);
    assert!(checks.iter().any(|(c, ok)| *c == "open" && !ok));
    assert!(checks.iter().any(|(c, ok)| *c == "key_chain" && !ok));
}

/// A store that runs a hook once, just before its first put: another
/// run's put lands between this run's listing and its own put.
struct Hooked<'a> {
    inner: &'a MemRecords,
    before_put: RefCell<Option<Box<dyn FnOnce() + 'a>>>,
}

impl RecordStore for Hooked<'_> {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        if let Some(hook) = self.before_put.borrow_mut().take() {
            hook();
        }
        self.inner.put_if_absent(name, bytes).await
    }
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(name).await
    }
    async fn list(&self, prefix: &str, after: &str, limit: u32) -> Result<Vec<String>> {
        self.inner.list(prefix, after, limit).await
    }
}

/// Two runs under different active KEK versions (a KEK rotation): run A
/// commits version 1 under KEK 1 while run B, under KEK 2, had listed the
/// arbiter before A's put. B's put takes another name, so both land. B
/// finds two keys for version 1, its void is refused (1 is committed),
/// and it fails. Readers take only the pinned key; the audit reports the
/// stray.
#[tokio::test(flavor = "current_thread")]
async fn a_run_racing_under_another_kek_version_never_replaces_the_committed_key() {
    let t = tenant();
    let both = TestKek::with_versions(2, &[(1, derived("kek")), (2, derived("kek 2"))]);
    let (a, b) = (MemRecords::new(), MemRecords::new());
    let a_key = TenantKey::from_bytes(&t, 1, derived("run A")).unwrap();
    let (_, a_blob) = wrap_tenant_key(&kek(), &a_key, &mut TestRng(30)).unwrap();
    let a_name = tk_blob_name(&t, 1, 1);
    // Run A's state once it has committed: its blob in both buckets, and
    // the commit pinned to its key.
    let claims = Claims::default();
    {
        let mut s = claims.state.borrow_mut();
        s.highest = 1;
        s.tk_version = 1;
        s.pinned = Some(a_key.check_value());
    }
    // Run B saw the claim of version 1 open before A committed.
    struct Stale<'a>(&'a Claims);
    impl KeyVersionClaims for Stale<'_> {
        async fn claim(&self, _t: &TenantId, _from: u32) -> Result<Claim> {
            Ok(Claim::Claimed(1))
        }
        async fn void(&self, t: &TenantId, version: u32) -> Result<Claim> {
            self.0.void(t, version).await
        }
        async fn commit(&self, t: &TenantId, version: u32, kcv: [u8; 8]) -> Result<Commit> {
            self.0.commit(t, version, kcv).await
        }
    }
    let ha = Hooked {
        inner: &a,
        before_put: RefCell::new(Some(Box::new(|| {
            a.plant(&a_name, a_blob.clone());
            b.plant(&a_name, a_blob.clone());
        }))),
    };
    let hb = Hooked {
        inner: &b,
        before_put: RefCell::new(None),
    };
    let buckets = KeyBuckets {
        by_name: vec![("KEYS_A", &ha), ("KEYS_B", &hb)],
    };
    let set = two_in_account();
    assert!(create_key_version(
        &set,
        &buckets,
        &Stale(&claims),
        &both,
        &t,
        0,
        &mut TestRng(31)
    )
    .await
    .is_err());
    // B's stray is there, under KEK 2, beside A's key under KEK 1.
    assert_eq!(World::blobs(&a, &t).len(), 2);
    assert_eq!(claims.state.borrow().pinned, Some(a_key.check_value()));

    // A reader with the pinned check value takes A's key, although the
    // stray is under the active KEK. Without it, the load is refused.
    let clock = FixedClock::new(UnixMs(1_700_000_000_000));
    let plain = KeyBuckets {
        by_name: vec![("KEYS_A", &a), ("KEYS_B", &b)],
    };
    let cache = TkCache::new();
    let loaded = cache
        .load(
            &set,
            &plain,
            &both,
            &clock,
            &t,
            1,
            Some(a_key.check_value()),
        )
        .await
        .unwrap();
    assert_eq!(loaded.check_value(), a_key.check_value());
    let cache = TkCache::new();
    let e = cache
        .load(&set, &plain, &both, &clock, &t, 1, None)
        .await
        .unwrap_err();
    assert!(velmora_bridge::keys::tk::is_split(&e), "{e:?}");
    let report = velmora_bridge::keys::audit::audit(&set, &plain, Some(&both))
        .await
        .unwrap();
    assert!(report.findings.iter().any(|f| matches!(
        f,
        velmora_bridge::keys::audit::Finding::VersionMismatch { version: 1, .. }
    )));
    // A cached key that is not the pinned one is not served.
    let cache = TkCache::new();
    let stray = cache.load(&set, &plain, &both, &clock, &t, 1, None).await;
    assert!(stray.is_err());
}

// ---------------------------------------------------------------------------
// From the review of the tenant-key package
// ---------------------------------------------------------------------------

fn flip(store: &MemRecords, name: &str, at: usize) {
    let mut b = store.raw(name).unwrap();
    b[at] ^= 1;
    store.plant(name, b);
}

#[tokio::test(flavor = "current_thread")]
async fn a_corrupt_copy_falls_back_to_the_other_bucket() {
    let w = World::new();
    let set = two_in_account();
    let created = create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(50),
    )
    .await
    .unwrap();
    // One flipped byte of the arbiter's ciphertext; its check value holds.
    flip(&w.a, &tk_blob_name(&w.t, 1, 1), 40);
    let clock = FixedClock::new(UnixMs(1_700_000_000_000));
    let key = TkCache::new()
        .load(
            &set,
            &w.buckets(),
            &w.kek,
            &clock,
            &w.t,
            1,
            Some(created.key.check_value()),
        )
        .await
        .unwrap();
    assert_eq!(key.check_value(), created.key.check_value());
}

#[tokio::test(flavor = "current_thread")]
async fn a_marker_in_the_copy_location_stops_the_copy_before_its_put() {
    let w = World::new();
    let set = two_in_account();
    w.b.plant(&format!("{}shredded", tk_prefix(&w.t)), b"x".to_vec());
    assert!(create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(51)
    )
    .await
    .is_err());
    assert!(
        w.b.raw(&tk_blob_name(&w.t, 1, 1)).is_none(),
        "no copy beside a marker"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_set_with_one_synchronous_location_creates_nothing() {
    let w = World::new();
    let mut set = two_in_account();
    set.locations[1].status = velmora_bridge::keys::locations::LocationStatus::Lost;
    let e = create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(52),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(e, BridgeError::Invalid(m) if m.contains("two synchronous")),
        "{e:?}"
    );
    assert!(w.a.names().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn the_cache_lets_no_key_outlive_its_time() {
    let w = World::new();
    let set = two_in_account();
    let created = create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(53),
    )
    .await
    .unwrap();
    let clock = FixedClock::new(UnixMs(1_700_000_000_000));
    let cache = TkCache::new();
    let pin = Some(created.key.check_value());
    cache
        .load(&set, &w.buckets(), &w.kek, &clock, &w.t, 1, pin)
        .await
        .unwrap();
    assert_eq!(cache.len(), 1);
    // Another tenant's load, past the minute, drops the first one.
    clock.advance_ms(60_000);
    let other = TenantId::parse("t_00000000000000b2").unwrap();
    let _ = cache
        .load(&set, &w.buckets(), &w.kek, &clock, &other, 1, None)
        .await;
    assert_eq!(cache.len(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_restore_in_conflict_anywhere_writes_nothing_anywhere() {
    let w = World::new();
    let set = two_in_account();
    let created = create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(54),
    )
    .await
    .unwrap();
    let name = tk_blob_name(&w.t, 1, 1);
    let copy = EscrowCopy::of_blob(&w.t, 1, 1, &w.a.raw(&name).unwrap()).unwrap();
    // The arbiter holds another key under the name; KEYS_B lost its copy.
    let other = TenantKey::from_bytes(&w.t, 1, derived("other")).unwrap();
    let (_, other_blob) = wrap_tenant_key(&w.kek, &other, &mut TestRng(55)).unwrap();
    w.a.plant(&name, other_blob);
    w.b.lose(&name);
    let steps = restore_escrow(&copy, &w.kek, &set, &w.buckets())
        .await
        .unwrap();
    assert_eq!(
        steps,
        vec![
            ("KEYS_A".to_owned(), RestoreStep::Conflict),
            ("KEYS_B".to_owned(), RestoreStep::Withheld),
        ]
    );
    assert!(w.b.raw(&name).is_none());
    let _ = created;
}

#[tokio::test(flavor = "current_thread")]
async fn a_damaged_copy_is_a_conflict_not_present() {
    let w = World::new();
    let set = two_in_account();
    create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(56),
    )
    .await
    .unwrap();
    let name = tk_blob_name(&w.t, 1, 1);
    let copy = EscrowCopy::of_blob(&w.t, 1, 1, &w.a.raw(&name).unwrap()).unwrap();
    // The right check value, a rotten tag.
    flip(&w.b, &name, 80);
    let steps = restore_escrow(&copy, &w.kek, &set, &w.buckets())
        .await
        .unwrap();
    assert_eq!(steps[1], ("KEYS_B".to_owned(), RestoreStep::Conflict));
}

#[tokio::test(flavor = "current_thread")]
async fn an_escrow_copy_under_an_old_kek_brings_no_old_name_back() {
    let w = World::new();
    let set = two_in_account();
    let both = TestKek::with_versions(2, &[(1, derived("kek")), (2, derived("kek 2"))]);
    let created = create_key_version(
        &set,
        &w.buckets(),
        &w.claims,
        &w.kek,
        &w.t,
        0,
        &mut TestRng(57),
    )
    .await
    .unwrap();
    let old = tk_blob_name(&w.t, 1, 1);
    let copy = EscrowCopy::of_blob(&w.t, 1, 1, &w.a.raw(&old).unwrap()).unwrap();
    // A KEK rotation wrote <1>.2 and removed <1>.1 in both buckets.
    let blob2 = velmora_bridge::crypto::scheme2::wrap_tenant_key_as(
        &both,
        2,
        &created.key,
        &mut TestRng(58),
    )
    .unwrap();
    let new = tk_blob_name(&w.t, 1, 2);
    for s in [&w.a, &w.b] {
        s.plant(&new, blob2.clone());
        s.lose(&old);
    }
    let puts = (w.a.puts(), w.b.puts());
    let steps = restore_escrow(&copy, &both, &set, &w.buckets())
        .await
        .unwrap();
    assert!(
        steps.iter().all(|(_, s)| *s == RestoreStep::Present),
        "{steps:?}"
    );
    assert_eq!((w.a.puts(), w.b.puts()), puts);
    assert!(w.a.raw(&old).is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn a_repair_copies_only_from_a_source_that_opens() {
    use velmora_bridge::keys::audit::{audit, repair_missing};
    use velmora_bridge::keys::locations::{KeyLocation, KeyLocations, LocationStatus};
    let w = World::new();
    let c = MemRecords::new();
    let set = KeyLocations {
        v: 1,
        seq: 1,
        locations: vec![
            KeyLocation {
                name: "KEYS_A".into(),
                status: LocationStatus::Active,
                arbiter: true,
                synchronous: true,
            },
            KeyLocation {
                name: "KEYS_B".into(),
                status: LocationStatus::Active,
                arbiter: false,
                synchronous: true,
            },
            KeyLocation {
                name: "KEYS_C".into(),
                status: LocationStatus::Active,
                arbiter: false,
                synchronous: true,
            },
        ],
    };
    let buckets = KeyBuckets {
        by_name: vec![("KEYS_A", &w.a), ("KEYS_B", &w.b), ("KEYS_C", &c)],
    };
    create_key_version(&set, &buckets, &w.claims, &w.kek, &w.t, 0, &mut TestRng(59))
        .await
        .unwrap();
    let name = tk_blob_name(&w.t, 1, 1);
    // The arbiter's copy rots; KEYS_C loses its copy.
    flip(&w.a, &name, 40);
    c.lose(&name);
    let report = audit(&set, &buckets, Some(&w.kek)).await.unwrap();
    // The audit sees the rot, so nothing is repaired for that name.
    assert!(report
        .findings
        .iter()
        .any(|f| matches!(f, velmora_bridge::keys::audit::Finding::Unopenable { .. })));
    assert!(repair_missing(&set, &buckets, &w.kek, &report)
        .await
        .unwrap()
        .is_empty());
    assert!(c.raw(&name).is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn an_audit_by_small_pages_finds_what_one_audit_finds() {
    use velmora_bridge::keys::audit::{audit, audit_page};
    let w = World::new();
    let set = two_in_account();
    // Five tenants, one of them with a split version and a missing copy.
    for n in 1..=5u8 {
        let t = TenantId::parse(&format!("t_00000000000000c{n}")).unwrap();
        let claims = Claims::default();
        create_key_version(
            &set,
            &w.buckets(),
            &claims,
            &w.kek,
            &t,
            0,
            &mut TestRng(60 + u64::from(n)),
        )
        .await
        .unwrap();
        if n == 3 {
            let stray = TenantKey::from_bytes(&t, 1, derived("stray")).unwrap();
            let both = TestKek::with_versions(2, &[(1, derived("kek")), (2, derived("kek 2"))]);
            let blob = velmora_bridge::crypto::scheme2::wrap_tenant_key_as(
                &both,
                2,
                &stray,
                &mut TestRng(70),
            )
            .unwrap();
            w.a.plant(&tk_blob_name(&t, 1, 2), blob);
            w.b.lose(&tk_blob_name(&t, 1, 1));
        }
    }
    let whole = audit::<MemRecords, TestKek>(&set, &w.buckets(), None)
        .await
        .unwrap();
    assert!(!whole.clean());
    let mut findings = Vec::new();
    let mut after = "m/tk/".to_owned();
    let mut pages = 0;
    loop {
        let (page, next) = audit_page::<MemRecords, TestKek>(&set, &w.buckets(), None, &after, 2)
            .await
            .unwrap();
        findings.extend(page.findings);
        pages += 1;
        match next {
            Some(n) => after = n,
            None => break,
        }
    }
    findings.sort();
    assert_eq!(findings, whole.findings);
    assert!(pages > 2, "{pages}");
}
