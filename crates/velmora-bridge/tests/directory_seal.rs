//! The tenant chain's real seal (`directory::seal::ChainSeal`) over key
//! scheme 2: records round-trip through the chain for tenant 0 and a
//! managed tenant, before and after its first key version and after the
//! shred; a changed byte, another name, another tenant, another label or
//! kind, a stripped private part and a key the chain did not commit are
//! refused; a version not held asks for a load; a version gone opens the
//! door part only; and no key byte reaches an error.

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
use velmora_bridge::directory::record::DeletionReason;
use velmora_bridge::directory::record::{Tenant, TenantDoor, TenantState};
use velmora_bridge::directory::seal::{ChainSeal, DoorSeal, SealKeys};
use velmora_bridge::directory::testing::HookedRecords;
use velmora_bridge::directory::transition::{Actor, Change};
use velmora_bridge::keys::record::{key_chain, open_key_record, OneKey};
use velmora_bridge::testkit::TestKek;
use velmora_bridge::UnixMs;

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const DAY: i64 = 24 * 3_600_000;
const KEK_1: [u8; 32] = [0x11; 32];
const KEK_2: [u8; 32] = [0x22; 32];

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

const TK_1: &str = "tenant a key 1";

fn tk(n: u8, v: u32, label: &str) -> Rc<TenantKey> {
    Rc::new(TenantKey::from_bytes(&id(n), v, derived(label)).unwrap())
}

fn kek() -> TestKek {
    TestKek::with_versions(1, &[(1, KEK_1)])
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

async fn wrote<S, C>(
    chain: &TenantChain<'_, S, C>,
    tenant: &Tenant,
    change: Change,
    actor: Actor,
    now: UnixMs,
) where
    S: velmora_bridge::records::RecordStore,
    C: ControlSeal,
{
    let w = chain.write(tenant, &change, actor, now, 0).await;
    assert!(matches!(w, Ok(Written::Wrote(_))), "{change:?}: {w:?}");
}

/// Takes tenant `n` to `active` under key version 1 (4 records: two
/// keyless, two under version 1).
async fn active<S: velmora_bridge::records::RecordStore, C: ControlSeal>(
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
    wrote(
        chain,
        &tenant,
        Change::CommitKeyVersion {
            version: 1,
            kcv: key.check_value(),
        },
        Actor::TenantCreation,
        NOW,
    )
    .await;
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

fn kind(sealed: &[u8]) -> PrivateKeyRef {
    parse_control(sealed).unwrap().private_key()
}

fn damaged<T>(e: Result<T, SealError>) -> bool {
    matches!(e, Err(SealError::Damaged))
}

#[test]
fn a_managed_tenant_round_trips_from_its_first_record_to_active() {
    let store = HookedRecords::new();
    let kek = kek();
    let keys = SealKeys::new();
    let key = tk(1, 1, TK_1);
    keys.hold(key.clone()).unwrap();
    let seal = ChainSeal::new(&kek, &keys, TestRng::new("seal"));
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        active(&chain, 1, &key).await;
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
        // The private part is not readable with the control key alone.
        let raw = store.raw(&record_key(&t(1), 4)).unwrap();
        let needle = b"ws_secret_ref";
        assert!(!raw.windows(needle.len()).any(|w| w == needle));
    });
}

#[test]
fn a_version_not_held_asks_for_a_load_and_the_door_names_what_to_load() {
    let store = HookedRecords::new();
    let kek = kek();
    let key = tk(1, 1, TK_1);
    let writer_keys = SealKeys::new();
    writer_keys.hold(key.clone()).unwrap();
    let writer = ChainSeal::new(&kek, &writer_keys, TestRng::new("w"));
    block_on(active(
        &TenantChain {
            store: &store,
            seal: &writer,
        },
        1,
        &key,
    ));

    // A reader that holds nothing yet.
    let keys = SealKeys::new();
    let seal = ChainSeal::new(&kek, &keys, TestRng::new("r"));
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    block_on(async {
        let e = chain.head(&t(1), 0).await.unwrap_err();
        assert!(matches!(e, ChainError::KeyNotHeld { version: 1 }), "{e:?}");
        // The door part alone opens and names the version and its check.
        let name = record_key(&t(1), 4);
        let door = seal.door(&name, &t(1), &store.raw(&name).unwrap()).unwrap();
        let door: TenantDoor = serde_json::from_slice(&door).unwrap();
        assert_eq!(door.tk_version, 1);
        let kcv: String = key
            .check_value()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(door.key_checks.get(&1), Some(&kcv));
        // Loaded: the head reads.
        keys.hold(key.clone()).unwrap();
        assert!(keys.holds(&id(1), 1));
        let head = chain.head(&t(1), 0).await.unwrap().unwrap();
        assert_eq!(head.door.state(), TenantState::Active);
        // Another tenant's key of the same version is not this one's.
        let other = SealKeys::new();
        other.hold(tk(2, 1, TK_1)).unwrap();
        let seal = ChainSeal::new(&kek, &other, TestRng::new("o"));
        let e = seal.open(&name, &t(1), &store.raw(&name).unwrap());
        assert!(matches!(e, Err(SealError::KeyNotHeld { version: 1 })));
    });
}

#[test]
fn a_key_the_chain_did_not_commit_does_not_open_the_private_part() {
    let store = HookedRecords::new();
    let kek = kek();
    let key = tk(1, 1, TK_1);
    let keys = SealKeys::new();
    keys.hold(key.clone()).unwrap();
    let seal = ChainSeal::new(&kek, &keys, TestRng::new("w"));
    block_on(active(
        &TenantChain {
            store: &store,
            seal: &seal,
        },
        1,
        &key,
    ));
    let wrong = SealKeys::new();
    wrong.hold(tk(1, 1, "another key 1")).unwrap();
    let seal = ChainSeal::new(&kek, &wrong, TestRng::new("r"));
    let name = record_key(&t(1), 4);
    assert!(damaged(seal.open(&name, &t(1), &store.raw(&name).unwrap())));
}

#[test]
fn every_changed_byte_is_refused() {
    let kek = kek();
    let keys = SealKeys::new();
    keys.hold(tk(1, 1, TK_1)).unwrap();
    let seal = ChainSeal::new(&kek, &keys, TestRng::new("s"));
    let name = record_key(&t(1), 4);
    let keyed = seal
        .seal(&name, &t(1), 1, b"{\"door\":1}", b"{\"private\":1}")
        .unwrap();
    let name0 = record_key(&Tenant::zero(), 4);
    let zero = seal
        .seal(
            &name0,
            &Tenant::zero(),
            0,
            b"{\"door\":0}",
            b"{\"private\":0}",
        )
        .unwrap();
    let name1 = record_key(&t(1), 1);
    let empty = serde_json::to_vec(&velmora_bridge::directory::record::TenantPrivate {
        v: velmora_bridge::directory::record::RECORD_FORMAT,
        external_ref: None,
    })
    .unwrap();
    let keyless = seal
        .seal(&name1, &t(1), 0, b"{\"door\":2}", &empty)
        .unwrap();
    for (name, tenant, sealed) in [
        (&name, t(1), &keyed),
        (&name0, Tenant::zero(), &zero),
        (&name1, t(1), &keyless),
    ] {
        assert!(seal.open(name, &tenant, sealed).is_ok());
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 0x10;
            match seal.open(name, &tenant, &bad) {
                Err(SealError::Damaged) => {}
                // The header's KEK version names one this Worker lacks:
                // refused, not read.
                Err(SealError::Failed(_)) if (4..8).contains(&i) => {}
                other => panic!("{name} byte {i}: {:?}", other.map(|_| ())),
            }
        }
        // Cut short, or with a byte added.
        assert!(damaged(seal.open(
            name,
            &tenant,
            &sealed[..sealed.len() - 1]
        )));
        let mut longer = sealed.clone();
        longer.push(0);
        assert!(damaged(seal.open(name, &tenant, &longer)));
    }
}

#[test]
fn a_record_opens_only_under_its_own_name_and_tenant() {
    let store = HookedRecords::new();
    let kek = kek();
    let keys = SealKeys::new();
    let (a, b) = (tk(1, 1, TK_1), tk(2, 1, "tenant b key 1"));
    keys.hold(a.clone()).unwrap();
    keys.hold(b.clone()).unwrap();
    let seal = ChainSeal::new(&kek, &keys, TestRng::new("s"));
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
        // Sealing refuses a name outside the tenant's chain.
        assert!(seal
            .seal(&record_key(&t(2), 9), &t(1), 1, b"{}", b"{}")
            .is_err());
        assert!(seal.seal("m/rst/x", &t(1), 1, b"{}", b"{}").is_err());
    });
}

#[test]
fn a_record_of_another_label_or_kind_is_refused() {
    let kek = kek();
    let keys = SealKeys::new();
    let key = tk(1, 1, TK_1);
    keys.hold(key.clone()).unwrap();
    let seal = ChainSeal::new(&kek, &keys, TestRng::new("s"));
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
    let keyed = seal
        .seal(&name, &t(1), 1, b"{\"d\":1}", b"{\"p\":1}")
        .unwrap();
    let door_len = u32::from_be_bytes(keyed[13..17].try_into().unwrap()) as usize;
    let mut stripped = keyed[..CONTROL_HEADER_LEN + door_len].to_vec();
    stripped[8] = 0; // kind: none
    stripped[9..13].copy_from_slice(&0u32.to_be_bytes());
    stripped[17..21].copy_from_slice(&0u32.to_be_bytes());
    assert!(parse_control(&stripped).is_ok());
    assert!(damaged(seal.open(&name, &t(1), &stripped)));

    // A keyless tenant record does not open as a key record or a
    // checkpoint: those readers need a private part.
    let empty = br#"{"v":1}"#;
    let keyless = seal.seal(&name, &t(1), 0, b"{}", empty).unwrap();
    assert!(seal.open(&name, &t(1), &keyless).is_ok());
    let key_name = key_chain(&id(1)).name(3);
    let keyless_key_record = seal_control(
        &kek,
        &key_name,
        &ControlSealer::ManagedKeyless(&id(1)),
        b"{}",
        None,
        &mut rng,
    )
    .unwrap();
    assert!(open_key_record(
        &kek,
        &OneKey(TenantKey::from_bytes(&id(1), 1, derived(TK_1)).unwrap()),
        &id(1),
        3,
        &keyless_key_record
    )
    .is_err());
    // And no global reader takes it.
    assert!(parse_control(&keyless)
        .unwrap()
        .open_door(&kek, &name, ControlOwner::Global)
        .is_err());
}

#[test]
fn a_keyless_record_carries_nothing_private() {
    let kek = kek();
    let keys = SealKeys::new();
    let seal = ChainSeal::new(&kek, &keys, TestRng::new("s"));
    let name = record_key(&t(1), 1);
    for private in [
        &br#"{"v":1,"external_ref":"ws_1"}"#[..],
        &br#"{"v":1} "#[..],
        &b""[..],
    ] {
        let e = seal.seal(&name, &t(1), 0, b"{}", private).unwrap_err();
        assert!(format!("{e:?}").contains("private part without a tenant key"));
    }
    // A version not held, and tenant 0 under a tenant key version.
    let e = seal.seal(&name, &t(1), 1, b"{}", b"{}").unwrap_err();
    assert!(format!("{e:?}").contains("not held"), "{e:?}");
    let e = seal
        .seal(
            &record_key(&Tenant::zero(), 1),
            &Tenant::zero(),
            1,
            b"{}",
            b"{}",
        )
        .unwrap_err();
    assert!(format!("{e:?}").contains("tenant 0"), "{e:?}");
}

#[test]
fn the_shred_leaves_door_parts_and_a_keyless_stub() {
    let store = HookedRecords::new();
    let kek = kek();
    let keys = SealKeys::new();
    let key = tk(1, 1, TK_1);
    keys.hold(key.clone()).unwrap();
    let seal = ChainSeal::new(&kek, &keys, TestRng::new("s"));
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
        wrote(&chain, &t(1), Change::StartShred, Actor::ShredJob, due).await;
        // The shred destroys version 1.
        keys.gone(&id(1), 1);
        assert!(!keys.holds(&id(1), 1));
        assert!(
            keys.hold(key.clone()).is_err(),
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
        let e = seal
            .seal(&record_key(&t(1), 8), &t(1), 1, b"{}", b"{}")
            .unwrap_err();
        assert!(format!("{e:?}").contains("gone"), "{e:?}");
        // `forget` drops the gone mark with the keys (a new load decides).
        keys.forget(&id(1));
        assert!(matches!(
            chain.read(&t(1), 4).await,
            Err(ChainError::KeyNotHeld { version: 1 })
        ));
    });
}

#[test]
fn tenant_zero_seals_under_the_kek_and_reads_after_a_kek_rotation() {
    let store = HookedRecords::new();
    let keys = SealKeys::new();
    let kek1 = kek();
    let seal = ChainSeal::new(&kek1, &keys, TestRng::new("s"));
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
        let raw = store.raw(&record_key(&zero, 1)).unwrap();
        assert_eq!(kind(&raw), PrivateKeyRef::Kek(1));
        assert!(chain
            .head(&zero, 0)
            .await
            .unwrap()
            .unwrap()
            .private
            .is_some());

        // Rotated: v2 active, v1 still held. The old record reads, a new
        // one is sealed under v2.
        let kek2 = TestKek::with_versions(2, &[(1, KEK_1), (2, KEK_2)]);
        let seal2 = ChainSeal::new(&kek2, &keys, TestRng::new("s2"));
        let chain2 = TenantChain {
            store: &store,
            seal: &seal2,
        };
        assert!(chain2.read(&zero, 1).await.unwrap().is_some());
        let name = record_key(&zero, 9);
        let sealed = seal2.seal(&name, &zero, 0, b"{}", b"{}").unwrap();
        assert_eq!(kind(&sealed), PrivateKeyRef::Kek(2));
        assert_eq!(parse_control(&sealed).unwrap().kek_version(), 2);

        // A Worker without the KEK version a record names fails, and does
        // not call the record damaged.
        let only2 = TestKek::with_versions(2, &[(2, KEK_2)]);
        let seal3 = ChainSeal::new(&only2, &keys, TestRng::new("s3"));
        let e = seal3.open(&record_key(&zero, 1), &zero, &raw);
        assert!(matches!(e, Err(SealError::Failed(_))));
        // Another KEK under the same version number: damage.
        let other = TestKek::with_versions(1, &[(1, [0x33; 32])]);
        let seal4 = ChainSeal::new(&other, &keys, TestRng::new("s4"));
        assert!(damaged(seal4.open(&record_key(&zero, 1), &zero, &raw)));
    });
}

#[test]
fn no_key_byte_reaches_an_error() {
    let kek = kek();
    let keys = SealKeys::new();
    let key = tk(1, 1, TK_1);
    keys.hold(key.clone()).unwrap();
    let seal = ChainSeal::new(&kek, &keys, TestRng::new("s"));
    let name = record_key(&t(1), 4);
    let sealed = seal.seal(&name, &t(1), 1, b"{}", b"{}").unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let secrets = [
        hex(&KEK_1),
        hex(&derived(TK_1)),
        format!("{:?}", KEK_1),
        format!("{:?}", derived(TK_1)),
    ];
    let mut texts = vec![format!("{key:?}")];
    let wrong = SealKeys::new();
    wrong.hold(tk(1, 1, "x")).unwrap();
    let wrong_seal = ChainSeal::new(&kek, &wrong, TestRng::new("w"));
    texts.push(format!(
        "{:?}",
        wrong_seal.open(&name, &t(1), &sealed).map(|_| ())
    ));
    let mut bad = sealed.clone();
    bad[30] ^= 1;
    texts.push(format!("{:?}", seal.open(&name, &t(1), &bad).map(|_| ())));
    texts.push(format!(
        "{:?}",
        seal.seal(&name, &t(1), 0, b"{}", b"x").unwrap_err()
    ));
    texts.push(format!(
        "{:?}",
        seal.seal(&name, &t(1), 7, b"{}", b"{}").unwrap_err()
    ));
    let only2 = TestKek::with_versions(2, &[(2, KEK_2)]);
    let seal2 = ChainSeal::new(&only2, &keys, TestRng::new("s2"));
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
    let store = HookedRecords::new();
    let kek = kek();
    let keys = SealKeys::new();
    let key = tk(1, 1, TK_1);
    keys.hold(key.clone()).unwrap();
    let writer = ChainSeal::new(&kek, &keys, TestRng::new("w"));
    block_on(active(
        &TenantChain {
            store: &store,
            seal: &writer,
        },
        1,
        &key,
    ));
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
        let door = TenantHeads::head(
            &chain,
            &velmora_bridge::unit::TenantId::parse(id(1).as_str()).unwrap(),
            0,
        )
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
        assert!(doors
            .seal(&record_key(&t(1), 5), &t(1), 1, b"{}", b"{}")
            .is_err());
        assert!(doors
            .seal(&record_key(&t(1), 5), &t(1), 0, b"{}", br#"{"v":1}"#)
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
