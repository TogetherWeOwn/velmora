//! The tenant chain's real seal (`directory::seal::ChainSeal`) over key
//! scheme 2: records round-trip through the chain for tenant 0 and a
//! managed tenant, before and after its first key version and after the
//! shred; a changed byte, another name, another tenant, another label or
//! kind, a stripped private part and a key the chain did not commit are
//! refused; a key is used only for the check value its record names and
//! only while it is fresh; a version not held asks for a load; a version
//! gone opens the door part only; and no key byte reaches an error.

use std::collections::BTreeMap;
use std::rc::Rc;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::{
    parse_control, seal_control, ControlOwner, ControlSealer, PrivateKeyRef, TenantId, TenantKey,
    CONTROL_HEADER_LEN,
};
use velmora_bridge::directory::chain::{
    record_key, ChainError, ControlSeal, SealError, TenantChain, Written,
};
use velmora_bridge::directory::record::{
    DeletionReason, Tenant, TenantDoor, TenantPrivate, TenantState, RECORD_FORMAT,
};
use velmora_bridge::directory::seal::{ChainSeal, DoorSeal, SealKeys};
use velmora_bridge::directory::testing::HookedRecords;
use velmora_bridge::directory::transition::{Actor, Change};
use velmora_bridge::keys::record::key_chain;
use velmora_bridge::keys::tk::TK_CACHE_MS;
use velmora_bridge::ports::Clock;
use velmora_bridge::records::RecordStore;
use velmora_bridge::testkit::{FixedClock, TestKek};
use velmora_bridge::UnixMs;

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const DAY: i64 = 24 * 3_600_000;
const KEK_1: [u8; 32] = [0x11; 32];
const KEK_2: [u8; 32] = [0x22; 32];
const TK_1: &str = "tenant a key 1";

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

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn id(n: u8) -> TenantId {
    TenantId::parse(&format!("t_00000000000000{n:02x}")).unwrap()
}

fn t(n: u8) -> Tenant {
    Tenant::Managed(id(n))
}

fn tk(n: u8, v: u32, label: &str) -> Rc<TenantKey> {
    Rc::new(TenantKey::from_bytes(&id(n), v, derived(label)).unwrap())
}

fn kek() -> TestKek {
    TestKek::with_versions(1, &[(1, KEK_1)])
}

fn clock() -> FixedClock {
    FixedClock::new(NOW)
}

fn empty() -> Vec<u8> {
    serde_json::to_vec(&TenantPrivate {
        v: RECORD_FORMAT,
        external_ref: None,
    })
    .unwrap()
}

fn create() -> Change {
    Change::Create {
        jurisdiction: "us".into(),
        location_hint: None,
        synthetic: false,
        limits: BTreeMap::new(),
        rate_json: Default::default(),
        features_json: Default::default(),
    }
}

async fn wrote<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    tenant: &Tenant,
    change: Change,
    actor: Actor,
    now: UnixMs,
) {
    let w = chain.write(tenant, &change, actor, now, 0).await;
    assert!(matches!(w, Ok(Written::Wrote(_))), "{change:?}: {w:?}");
}

fn commit(key: &TenantKey) -> Change {
    Change::CommitKeyVersion {
        version: key.version(),
        kcv: key.check_value(),
    }
}

/// Takes tenant `n` to `active` under key version 1, committed with
/// `key`'s check value (4 records: two keyless, two under version 1).
async fn active<S: RecordStore, C: ControlSeal>(
    chain: &TenantChain<'_, S, C>,
    n: u8,
    key: &TenantKey,
) {
    let tenant = t(n);
    wrote(chain, &tenant, create(), Actor::TenantCreation, NOW).await;
    wrote(
        chain,
        &tenant,
        Change::ClaimKeyVersion { version: 1 },
        Actor::TenantCreation,
        NOW,
    )
    .await;
    wrote(chain, &tenant, commit(key), Actor::TenantCreation, NOW).await;
    wrote(
        chain,
        &tenant,
        Change::Activate {
            external_ref: Some("ws_secret_ref".into()),
        },
        Actor::TenantCreation,
        NOW,
    )
    .await;
}

/// A store holding tenant 1, active under [`TK_1`] (records 1 to 4).
fn active_store(kek: &TestKek) -> HookedRecords {
    let store = HookedRecords::new();
    let keys = SealKeys::new();
    let key = tk(1, 1, TK_1);
    keys.hold(key.clone(), NOW).unwrap();
    let clock = clock();
    let seal = ChainSeal::new(kek, &keys, &clock, TestRng::new("fixture"));
    block_on(active(
        &TenantChain {
            store: &store,
            seal: &seal,
        },
        1,
        &key,
    ));
    store
}

fn kind(sealed: &[u8]) -> PrivateKeyRef {
    parse_control(sealed).unwrap().private_key()
}

fn damaged<T>(e: Result<T, SealError>) -> bool {
    matches!(e, Err(SealError::Damaged))
}

/// The door part of record `seq` of tenant `n`, as JSON bytes.
fn door_of(store: &HookedRecords, kek: &TestKek, tenant: &Tenant, seq: u64) -> Vec<u8> {
    let keys = SealKeys::new();
    let clock = clock();
    let seal = ChainSeal::new(kek, &keys, &clock, TestRng::new("door"));
    let name = record_key(tenant, seq);
    seal.door(&name, tenant, &store.raw(&name).unwrap())
        .unwrap()
}

#[test]
fn a_managed_tenant_round_trips_from_its_first_record_to_active() {
    let kek = kek();
    let store = active_store(&kek);
    let keys = SealKeys::new();
    keys.hold(tk(1, 1, TK_1), NOW).unwrap();
    let clock = clock();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("r"));
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        // Records 1 and 2 have no tenant key: door part only.
        for seq in 1..=2 {
            let raw = store.raw(&record_key(&t(1), seq)).unwrap();
            assert_eq!(kind(&raw), PrivateKeyRef::None, "seq {seq}");
            let r = chain.read(&t(1), seq).await.unwrap().unwrap();
            assert_eq!(r.private.unwrap().external_ref, None);
        }
        // From the commit on, under version 1.
        for seq in 3..=4 {
            let raw = store.raw(&record_key(&t(1), seq)).unwrap();
            assert_eq!(kind(&raw), PrivateKeyRef::Tenant(1), "seq {seq}");
        }
        let head = chain.head(&t(1), 0).await.unwrap().unwrap();
        assert_eq!(head.door.state(), TenantState::Active);
        assert_eq!(
            head.private.unwrap().external_ref.as_deref(),
            Some("ws_secret_ref")
        );
        // The private part is not in clear.
        let raw = store.raw(&record_key(&t(1), 4)).unwrap();
        let needle = b"ws_secret_ref";
        assert!(!raw.windows(needle.len()).any(|w| w == needle));
    });
}

#[test]
fn a_version_not_held_asks_for_a_load_and_the_door_names_what_to_load() {
    let kek = kek();
    let store = active_store(&kek);
    let key = tk(1, 1, TK_1);
    let keys = SealKeys::new();
    let clock = clock();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("r"));
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        let e = chain.head(&t(1), 0).await.unwrap_err();
        assert!(matches!(e, ChainError::KeyNotHeld { version: 1 }), "{e:?}");
        // The door part alone opens and names the version and its check.
        let door: TenantDoor = serde_json::from_slice(&door_of(&store, &kek, &t(1), 4)).unwrap();
        assert_eq!(door.tk_version, 1);
        let kcv: String = key
            .check_value()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(door.key_checks.get(&1), Some(&kcv));
        // Loaded: the head reads.
        keys.hold(key.clone(), NOW).unwrap();
        assert!(keys.holds(&id(1), 1, &key.check_value(), NOW));
        let head = chain.head(&t(1), 0).await.unwrap().unwrap();
        assert_eq!(head.door.state(), TenantState::Active);
        // Another tenant's key of the same version is not this one's.
        let other = SealKeys::new();
        other.hold(tk(2, 1, TK_1), NOW).unwrap();
        let seal = ChainSeal::new(&kek, &other, &clock, TestRng::new("o"));
        let name = record_key(&t(1), 4);
        let e = seal.open(&name, &t(1), &store.raw(&name).unwrap());
        assert!(matches!(e, Err(SealError::KeyNotHeld { version: 1 })));
    });
}

/// Review M1: a key is used only for the check value its record names.
#[test]
fn a_key_is_used_only_for_the_check_value_its_record_names() {
    let kek = kek();
    let clock = clock();
    let committed = tk(1, 1, TK_1);
    let stray = tk(1, 1, "another key 1");

    // A reader that holds only a stray key of the version asks for a load:
    // no other key of the version is tried, and the record is not damage.
    let store = active_store(&kek);
    let keys = SealKeys::new();
    keys.hold(stray.clone(), NOW).unwrap();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("r"));
    let name = record_key(&t(1), 4);
    let e = seal.open(&name, &t(1), &store.raw(&name).unwrap());
    assert!(matches!(e, Err(SealError::KeyNotHeld { version: 1 })));

    // The commit is sealed only under the key whose check value it commits.
    // Two runs of a rotation in one isolate, each holding its own key: the
    // record carries B's check value, so A's key is never used for it.
    let store = HookedRecords::new();
    let keys = SealKeys::new();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("w"));
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        wrote(&chain, &t(1), create(), Actor::TenantCreation, NOW).await;
        wrote(
            &chain,
            &t(1),
            Change::ClaimKeyVersion { version: 1 },
            Actor::TenantCreation,
            NOW,
        )
        .await;
        keys.hold(stray.clone(), NOW).unwrap();
        // Only the stray key is held: the commit of `committed` is refused
        // and nothing is put.
        let w = chain
            .write(&t(1), &commit(&committed), Actor::TenantCreation, NOW, 0)
            .await;
        assert!(w.is_err(), "{w:?}");
        assert_eq!(store.keys().len(), 2);
        // Both held: it is sealed under `committed`, which a pinned reader
        // holds.
        keys.hold(committed.clone(), NOW).unwrap();
        wrote(
            &chain,
            &t(1),
            commit(&committed),
            Actor::TenantCreation,
            NOW,
        )
        .await;
        let only = SealKeys::new();
        only.hold(committed.clone(), NOW).unwrap();
        let reader = ChainSeal::new(&kek, &only, &clock, TestRng::new("p"));
        let name = record_key(&t(1), 3);
        assert!(reader
            .open(&name, &t(1), &store.raw(&name).unwrap())
            .is_ok());
    });

    // A door part that names no check value for its version is refused on
    // both sides.
    let store = active_store(&kek);
    let mut door: TenantDoor = serde_json::from_slice(&door_of(&store, &kek, &t(1), 4)).unwrap();
    door.key_checks.clear();
    let door = serde_json::to_vec(&door).unwrap();
    let keys = SealKeys::new();
    keys.hold(committed.clone(), NOW).unwrap();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("n"));
    let name = record_key(&t(1), 5);
    let e = seal.seal(&name, &t(1), 1, &door, b"{}").unwrap_err();
    assert!(format!("{e:?}").contains("check value"), "{e:?}");
    let forged = seal_control(
        &kek,
        &name,
        &ControlSealer::Managed(&committed),
        &door,
        Some(b"{}"),
        &mut TestRng::new("f"),
    )
    .unwrap();
    assert!(damaged(seal.open(&name, &t(1), &forged)));
}

/// Review M2: a key is held for at most the loader's cache time.
#[test]
fn a_held_key_expires_with_the_loaders_cache_time() {
    let kek = kek();
    let store = active_store(&kek);
    let key = tk(1, 1, TK_1);
    let keys = SealKeys::new();
    let clock = clock();
    keys.hold(key.clone(), NOW).unwrap();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("r"));
    let name = record_key(&t(1), 4);
    let sealed = store.raw(&name).unwrap();
    clock.advance_ms(TK_CACHE_MS - 1);
    assert!(seal.open(&name, &t(1), &sealed).is_ok());
    clock.advance_ms(1);
    assert!(matches!(
        seal.open(&name, &t(1), &sealed),
        Err(SealError::KeyNotHeld { version: 1 })
    ));
    assert!(!keys.holds(&id(1), 1, &key.check_value(), clock.now()));
    let door = door_of(&store, &kek, &t(1), 4);
    let e = seal
        .seal(&record_key(&t(1), 5), &t(1), 1, &door, b"{}")
        .unwrap_err();
    assert!(format!("{e:?}").contains("not held"), "{e:?}");
    // A clock that went back does not make a key fresh.
    let keys = SealKeys::new();
    keys.hold(key.clone(), NOW).unwrap();
    clock.set(UnixMs(NOW.0 - 1));
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("b"));
    assert!(matches!(
        seal.open(&name, &t(1), &sealed),
        Err(SealError::KeyNotHeld { version: 1 })
    ));
}

#[test]
fn every_changed_byte_is_refused() {
    let kek = kek();
    let store = active_store(&kek);
    let keys = SealKeys::new();
    keys.hold(tk(1, 1, TK_1), NOW).unwrap();
    let clock = clock();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("s"));
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let zero = Tenant::zero();
    block_on(wrote(
        &chain,
        &zero,
        Change::CreateTenantZero {
            jurisdiction: "us".into(),
        },
        Actor::Operator,
        NOW,
    ));
    for (tenant, seq) in [(t(1), 4), (t(1), 1), (zero.clone(), 1)] {
        let name = record_key(&tenant, seq);
        let sealed = store.raw(&name).unwrap();
        assert!(seal.open(&name, &tenant, &sealed).is_ok());
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 0x10;
            match seal.open(&name, &tenant, &bad) {
                Err(SealError::Damaged) => {}
                // The header's KEK version now names one newer than this
                // Worker's: refused, not read, and may pass.
                Err(SealError::Failed(_)) if (4..8).contains(&i) => {}
                other => panic!("{name} byte {i}: {:?}", other.map(|_| ())),
            }
        }
        // Cut short, or with a byte added.
        assert!(damaged(seal.open(
            &name,
            &tenant,
            &sealed[..sealed.len() - 1]
        )));
        let mut longer = sealed.clone();
        longer.push(0);
        assert!(damaged(seal.open(&name, &tenant, &longer)));
    }
}

#[test]
fn a_record_opens_only_under_its_own_name_and_tenant() {
    let store = HookedRecords::new();
    let kek = kek();
    let keys = SealKeys::new();
    let (a, b) = (tk(1, 1, TK_1), tk(2, 1, "tenant b key 1"));
    keys.hold(a.clone(), NOW).unwrap();
    keys.hold(b.clone(), NOW).unwrap();
    let clock = clock();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("s"));
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        active(&chain, 1, &a).await;
        active(&chain, 2, &b).await;
        for seq in 1..=4 {
            let sealed = store.raw(&record_key(&t(1), seq)).unwrap();
            // Another seq of the same chain.
            let other_seq = record_key(&t(1), seq % 4 + 1);
            assert!(damaged(seal.open(&other_seq, &t(1), &sealed)), "seq {seq}");
            // The same seq of another tenant's chain, read as that tenant.
            let other_tenant = record_key(&t(2), seq);
            assert!(
                damaged(seal.open(&other_tenant, &t(2), &sealed)),
                "seq {seq}"
            );
            // Its own name, read as another tenant.
            let own = record_key(&t(1), seq);
            assert!(damaged(seal.open(&own, &t(2), &sealed)), "seq {seq}");
            assert!(
                damaged(seal.open(&own, &Tenant::zero(), &sealed)),
                "seq {seq}"
            );
        }
        // Planted over the next seq, the chain refuses it as damage.
        store.plant(
            &record_key(&t(1), 5),
            store.raw(&record_key(&t(1), 4)).unwrap(),
        );
        let e = chain.head(&t(1), 0).await.unwrap_err();
        assert!(matches!(e, ChainError::Damaged(_)), "{e:?}");
        // Sealing refuses a name outside the tenant's chain, and a door of
        // another tenant.
        let door = door_of(&store, &kek, &t(1), 4);
        assert!(seal
            .seal(&record_key(&t(2), 9), &t(1), 1, &door, b"{}")
            .is_err());
        assert!(seal.seal("m/rst/x", &t(1), 1, &door, b"{}").is_err());
        assert!(seal
            .seal(&record_key(&t(2), 9), &t(2), 1, &door, b"{}")
            .is_err());
    });
}

#[test]
fn a_record_of_another_label_or_kind_is_refused() {
    let kek = kek();
    let store = active_store(&kek);
    let keys = SealKeys::new();
    let key = tk(1, 1, TK_1);
    keys.hold(key.clone(), NOW).unwrap();
    let clock = clock();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("s"));
    let name = record_key(&t(1), 3);
    let mut rng = TestRng::new("label");

    // A global door-only record (as `m/rst/` seals, label `velmora/rst/v1`)
    // put under a chain name.
    let rst = seal_control(
        &kek,
        "m/rst/00000000000000000001",
        &ControlSealer::Global,
        b"{\"label\":\"velmora/rst/v1\"}",
        None,
        &mut rng,
    )
    .unwrap();
    assert!(damaged(seal.open(&name, &t(1), &rst)));
    // A key-chain record of the same tenant, under the same key.
    let key_record = seal_control(
        &kek,
        &key_chain(&id(1)).name(3),
        &ControlSealer::Managed(&key),
        b"{}",
        Some(b"{}"),
        &mut rng,
    )
    .unwrap();
    assert!(damaged(seal.open(&name, &t(1), &key_record)));
    // Not a control record at all.
    assert!(damaged(seal.open(&name, &t(1), b"PLN1\0not a record")));
    assert!(damaged(seal.open(&name, &t(1), b"")));

    // The private part stripped and the header relabelled as keyless: the
    // door's AAD holds the header and the private part's hash.
    let keyed = store.raw(&name).unwrap();
    let door_len = u32::from_be_bytes(keyed[13..17].try_into().unwrap()) as usize;
    let mut stripped = keyed[..CONTROL_HEADER_LEN + door_len].to_vec();
    stripped[8] = 0; // kind: none
    stripped[9..13].copy_from_slice(&0u32.to_be_bytes());
    stripped[17..21].copy_from_slice(&0u32.to_be_bytes());
    assert!(parse_control(&stripped).is_ok());
    assert!(damaged(seal.open(&name, &t(1), &stripped)));

    // Review L1: a door-only record of a managed tenant exists only in its
    // tenant chain, never in its key chain, checkpoints or bucket
    // configuration.
    for other in [
        key_chain(&id(1)).name(3),
        format!("m/kc/{}/00000000000000000003", id(1).as_str()),
        format!("m/x/{}/b/b_01/00000000000000000001", id(1).as_str()),
    ] {
        let e = seal_control(
            &kek,
            &other,
            &ControlSealer::ManagedKeyless(&id(1)),
            b"{}",
            None,
            &mut rng,
        );
        assert!(e.is_err(), "{other}");
    }
    // And a keyless chain record planted there is refused by the door.
    let keyless = store.raw(&record_key(&t(1), 1)).unwrap();
    let key_name = key_chain(&id(1)).name(1);
    assert!(parse_control(&keyless)
        .unwrap()
        .open_door(&kek, &key_name, ControlOwner::Managed(&id(1)))
        .is_err());
    // No global reader takes a keyless record.
    assert!(parse_control(&keyless)
        .unwrap()
        .open_door(&kek, &record_key(&t(1), 1), ControlOwner::Global)
        .is_err());
}

/// Review L3: a keyed door is never sealed or read as keyless, nor the
/// reverse.
#[test]
fn a_door_and_its_key_version_must_agree() {
    let kek = kek();
    let store = active_store(&kek);
    let keys = SealKeys::new();
    let key = tk(1, 1, TK_1);
    keys.hold(key.clone(), NOW).unwrap();
    let clock = clock();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("s"));
    let keyed_door = door_of(&store, &kek, &t(1), 4);
    let keyless_door = door_of(&store, &kek, &t(1), 1);
    let name = record_key(&t(1), 5);
    // The seal refuses both mismatches before any put.
    let e = seal
        .seal(&name, &t(1), 0, &keyed_door, &empty())
        .unwrap_err();
    assert!(format!("{e:?}").contains("key version"), "{e:?}");
    let e = seal
        .seal(&name, &t(1), 1, &keyless_door, b"{}")
        .unwrap_err();
    assert!(format!("{e:?}").contains("key version"), "{e:?}");
    // A keyed door sealed door-only by hand and planted at the next seq:
    // the chain refuses it.
    let mut door: TenantDoor = serde_json::from_slice(&keyed_door).unwrap();
    door.seq = 5;
    let door = serde_json::to_vec(&door).unwrap();
    let planted = seal_control(
        &kek,
        &name,
        &ControlSealer::ManagedKeyless(&id(1)),
        &door,
        None,
        &mut TestRng::new("p"),
    )
    .unwrap();
    store.plant(&name, planted);
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let e = block_on(chain.read(&t(1), 5)).unwrap_err();
    assert!(
        matches!(e, ChainError::Damaged("private_part_version")),
        "{e:?}"
    );
}

#[test]
fn a_keyless_record_carries_nothing_private() {
    let kek = kek();
    let store = active_store(&kek);
    let keys = SealKeys::new();
    let clock = clock();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("s"));
    let name = record_key(&t(1), 1);
    let door = door_of(&store, &kek, &t(1), 1);
    assert!(seal.seal(&name, &t(1), 0, &door, &empty()).is_ok());
    for private in [
        &br#"{"v":1,"external_ref":"ws_1"}"#[..],
        &br#"{"v":1} "#[..],
        &b""[..],
    ] {
        let e = seal.seal(&name, &t(1), 0, &door, private).unwrap_err();
        assert!(format!("{e:?}").contains("private part without a tenant key"));
    }
    // A version not held.
    let door4 = door_of(&store, &kek, &t(1), 4);
    let e = seal.seal(&name, &t(1), 1, &door4, b"{}").unwrap_err();
    assert!(format!("{e:?}").contains("not held"), "{e:?}");
    // Not a door part at all.
    assert!(seal.seal(&name, &t(1), 0, b"{}", &empty()).is_err());
}

#[test]
fn the_shred_leaves_door_parts_and_a_keyless_stub() {
    let store = HookedRecords::new();
    let kek = kek();
    let keys = SealKeys::new();
    let key = tk(1, 1, TK_1);
    keys.hold(key.clone(), NOW).unwrap();
    let clock = clock();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("s"));
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        active(&chain, 1, &key).await;
        wrote(
            &chain,
            &t(1),
            Change::SetDeletion {
                shred_due_at: UnixMs(NOW.0 + 7 * DAY),
                reason: DeletionReason::CustomerRequest,
                key_hash: "ab".repeat(32),
            },
            Actor::Customer,
            NOW,
        )
        .await;
        let due = UnixMs(NOW.0 + 7 * DAY);
        // The key is loaded again for the shred job's run.
        clock.set(due);
        keys.hold(key.clone(), due).unwrap();
        wrote(&chain, &t(1), Change::StartShred, Actor::ShredJob, due).await;
        // The shred destroys version 1.
        keys.gone(&id(1), 1);
        assert!(!keys.holds(&id(1), 1, &key.check_value(), due));
        assert!(
            keys.hold(key.clone(), due).is_err(),
            "a gone version is not taken back"
        );
        wrote(&chain, &t(1), Change::FinishShred, Actor::ShredJob, due).await;
        let stub = store.raw(&record_key(&t(1), 7)).unwrap();
        assert_eq!(kind(&stub), PrivateKeyRef::None);
        let head = chain.head(&t(1), 0).await.unwrap().unwrap();
        assert_eq!(head.door.state(), TenantState::Shredded);
        // A record under the gone version opens its door part only.
        let r = chain.read(&t(1), 4).await.unwrap().unwrap();
        assert_eq!(r.door.state(), TenantState::Active);
        assert!(r.private.is_none());
        // Nothing is sealed under it again.
        let door = door_of(&store, &kek, &t(1), 6);
        let e = seal
            .seal(&record_key(&t(1), 8), &t(1), 1, &door, b"{}")
            .unwrap_err();
        assert!(format!("{e:?}").contains("gone"), "{e:?}");
        // Review L2: `forget` drops keys, never a gone mark.
        keys.forget(&id(1));
        let r = chain.read(&t(1), 4).await.unwrap().unwrap();
        assert!(r.private.is_none());
    });
}

#[test]
fn tenant_zero_seals_under_the_kek_and_reads_after_a_kek_rotation() {
    let store = HookedRecords::new();
    let keys = SealKeys::new();
    let kek1 = kek();
    let clock = clock();
    let seal = ChainSeal::new(&kek1, &keys, &clock, TestRng::new("s"));
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let zero = Tenant::zero();
    block_on(async {
        wrote(
            &chain,
            &zero,
            Change::CreateTenantZero {
                jurisdiction: "us".into(),
            },
            Actor::Operator,
            NOW,
        )
        .await;
        let name = record_key(&zero, 1);
        let raw = store.raw(&name).unwrap();
        assert_eq!(kind(&raw), PrivateKeyRef::Kek(1));
        assert!(chain
            .head(&zero, 0)
            .await
            .unwrap()
            .unwrap()
            .private
            .is_some());
        let door = seal.door(&name, &zero, &raw).unwrap();
        // Tenant 0 under a tenant key version: refused.
        assert!(seal.seal(&name, &zero, 1, &door, b"{}").is_err());

        // Rotated: v2 active, v1 still held. The old record reads, a new
        // one is sealed under v2.
        let kek2 = TestKek::with_versions(2, &[(1, KEK_1), (2, KEK_2)]);
        let seal2 = ChainSeal::new(&kek2, &keys, &clock, TestRng::new("s2"));
        let chain2 = TenantChain {
            store: &store,
            seal: &seal2,
        };
        assert!(chain2.read(&zero, 1).await.unwrap().is_some());
        let sealed2 = seal2.seal(&name, &zero, 0, &door, b"{}").unwrap();
        assert_eq!(kind(&sealed2), PrivateKeyRef::Kek(2));
        assert_eq!(parse_control(&sealed2).unwrap().kek_version(), 2);

        // Review L (security): a Worker that no longer carries the KEK
        // version a record names reads it as damage (it pages)...
        let only2 = TestKek::with_versions(2, &[(2, KEK_2)]);
        let seal3 = ChainSeal::new(&only2, &keys, &clock, TestRng::new("s3"));
        assert!(damaged(seal3.open(&name, &zero, &raw)));
        // ... while one older than the record (a newer deploy wrote it)
        // fails in a way that may pass.
        let seal4 = ChainSeal::new(&kek1, &keys, &clock, TestRng::new("s4"));
        assert!(matches!(
            seal4.open(&name, &zero, &sealed2),
            Err(SealError::Failed(_))
        ));
        // Another KEK under the same version number: damage.
        let other = TestKek::with_versions(1, &[(1, [0x33; 32])]);
        let seal5 = ChainSeal::new(&other, &keys, &clock, TestRng::new("s5"));
        assert!(damaged(seal5.open(&name, &zero, &raw)));
    });
}

#[test]
fn no_key_byte_reaches_an_error() {
    let kek = kek();
    let store = active_store(&kek);
    let keys = SealKeys::new();
    let key = tk(1, 1, TK_1);
    keys.hold(key.clone(), NOW).unwrap();
    let clock = clock();
    let seal = ChainSeal::new(&kek, &keys, &clock, TestRng::new("s"));
    let name = record_key(&t(1), 4);
    let sealed = store.raw(&name).unwrap();
    let door = door_of(&store, &kek, &t(1), 4);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let secrets = [
        hex(&KEK_1),
        hex(&derived(TK_1)),
        format!("{:?}", KEK_1),
        format!("{:?}", derived(TK_1)),
    ];
    let mut texts = vec![format!("{key:?}")];
    let wrong = SealKeys::new();
    wrong.hold(tk(1, 1, "x"), NOW).unwrap();
    let wrong_seal = ChainSeal::new(&kek, &wrong, &clock, TestRng::new("w"));
    texts.push(format!(
        "{:?}",
        wrong_seal.open(&name, &t(1), &sealed).map(|_| ())
    ));
    let mut bad = sealed.clone();
    bad[30] ^= 1;
    texts.push(format!("{:?}", seal.open(&name, &t(1), &bad).map(|_| ())));
    texts.push(format!(
        "{:?}",
        seal.seal(&name, &t(1), 0, &door, b"x").unwrap_err()
    ));
    texts.push(format!(
        "{:?}",
        seal.seal(&name, &t(1), 7, &door, b"{}").unwrap_err()
    ));
    let only2 = TestKek::with_versions(2, &[(2, KEK_2)]);
    let seal2 = ChainSeal::new(&only2, &keys, &clock, TestRng::new("s2"));
    texts.push(format!(
        "{:?}",
        seal2.open(&name, &t(1), &sealed).map(|_| ())
    ));
    for text in &texts {
        for s in &secrets {
            assert!(!text.contains(s.as_str()), "{text}");
        }
    }
}

#[test]
fn a_door_reader_reads_heads_without_a_tenant_key_and_writes_nothing() {
    let kek = kek();
    let store = active_store(&kek);
    let doors = DoorSeal::new(&kek);
    let chain = TenantChain {
        store: &store,
        seal: &doors,
    };
    block_on(async {
        let head = chain.head(&t(1), 0).await.unwrap().unwrap();
        assert_eq!(head.door.state(), TenantState::Active);
        assert!(head.private.is_none());
        // The router's port.
        use velmora_bridge::unit_lease::client::TenantHeads;
        let unit_tenant = velmora_bridge::unit::TenantId::parse(id(1).as_str()).unwrap();
        let door = TenantHeads::head(&chain, &unit_tenant, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(door.seq, 4);
        // Nothing is written through it.
        let w = chain
            .write(
                &t(1),
                &Change::Activate {
                    external_ref: Some("ws_2".into()),
                },
                Actor::TenantCreation,
                NOW,
                0,
            )
            .await;
        assert!(w.is_err(), "{w:?}");
        assert_eq!(store.keys().len(), 4);
        let door4 = door_of(&store, &kek, &t(1), 4);
        assert!(doors
            .seal(&record_key(&t(1), 5), &t(1), 1, &door4, b"{}")
            .is_err());
        // It proves the whole record as the full seal does.
        let name = record_key(&t(1), 4);
        let sealed = store.raw(&name).unwrap();
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 0x01;
            assert!(doors.open(&name, &t(1), &bad).is_err(), "byte {i}");
        }
        assert!(damaged(doors.open(&record_key(&t(1), 3), &t(1), &sealed)));
        assert!(damaged(doors.open(&record_key(&t(2), 4), &t(2), &sealed)));
    });
}
