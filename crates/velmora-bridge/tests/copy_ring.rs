//! Recovery-copy rings are loaded from the tenant chain and key buckets, without a directory.

use velmora::rng::SystemRng;
use velmora_bridge::crypto::scheme2::{tk_blob_name, wrap_tenant_key, TenantId, TenantKey};
use velmora_bridge::directory::chain::Written;
use velmora_bridge::directory::record::{DeletionReason, Tenant};
use velmora_bridge::directory::transition::{Actor, Change};
use velmora_bridge::keys::locations::{two_in_account, write_locations};
use velmora_bridge::keys::tk::{is_foreign, tk_prefix, KeyBuckets};
use velmora_bridge::ports::TenantRingState;
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::root::{Root, RootCache, RootPorts};
use velmora_bridge::testkit::{FixedClock, RusqliteSql, TestKek};
use velmora_bridge::UnixMs;

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const DUE: UnixMs = UnixMs(NOW.0 + 7 * 24 * 3_600_000);

// The root fixture, with a physically separate in-memory store for each location.
struct Ports<'a> {
    records: &'a MemRecords,
    keys_a: MemRecords,
    keys_b: MemRecords,
    kek: TestKek,
    clock: FixedClock,
}

impl RootPorts for Ports<'_> {
    type Records = MemRecords;
    type KeyStore = MemRecords;
    type Kek = TestKek;
    type Sql = RusqliteSql;
    type Clock = FixedClock;

    fn records(&self) -> &MemRecords {
        self.records
    }
    fn key_buckets(&self) -> KeyBuckets<'_, MemRecords> {
        KeyBuckets {
            by_name: vec![("KEYS_A", &self.keys_a), ("KEYS_B", &self.keys_b)],
        }
    }
    fn kek(&self) -> &TestKek {
        &self.kek
    }
    fn directory(&self) -> Option<&RusqliteSql> {
        None
    }
    fn clock(&self) -> &FixedClock {
        &self.clock
    }
}

fn tenant() -> TenantId {
    TenantId::parse("t_00000000000000a1").unwrap()
}

fn key(version: u32) -> TenantKey {
    TenantKey::from_bytes(&tenant(), version, [version as u8; 32]).unwrap()
}

impl<'a> Ports<'a> {
    fn new(records: &'a MemRecords) -> Self {
        Self {
            records,
            keys_a: MemRecords::default(),
            keys_b: MemRecords::default(),
            kek: TestKek::new(),
            clock: FixedClock::new(NOW),
        }
    }

    async fn put_key(&self, version: u32) {
        let (kek_v, blob) = wrap_tenant_key(&self.kek, &key(version), &mut SystemRng).unwrap();
        let name = tk_blob_name(&tenant(), version, kek_v);
        for store in [&self.keys_a, &self.keys_b] {
            assert!(store.put_if_absent(&name, blob.clone()).await.unwrap());
        }
    }
}

async fn write(root: &Root<'_, Ports<'_>, SystemRng>, change: Change, actor: Actor, now: UnixMs) {
    let written = root
        .chain()
        .write(&Tenant::Managed(tenant()), &change, actor, now, 0)
        .await;
    assert!(
        matches!(written, Ok(Written::Wrote(_))),
        "{change:?}: {written:?}"
    );
}

async fn commit(root: &Root<'_, Ports<'_>, SystemRng>, version: u32, actor: Actor) {
    let kcv = key(version).check_value();
    root.load_key(&tenant(), version, kcv).await.unwrap();
    write(root, Change::CommitKeyVersion { version, kcv }, actor, NOW).await;
}

async fn active(ports: &Ports<'_>, root: &Root<'_, Ports<'_>, SystemRng>) {
    assert!(
        write_locations(ports.records, &ports.kek, &two_in_account(), &mut SystemRng)
            .await
            .unwrap()
    );
    ports.put_key(1).await;
    let actor = Actor::TenantCreation;
    write(
        root,
        Change::Create {
            jurisdiction: "us".into(),
            location_hint: None,
            synthetic: false,
            limits: Default::default(),
            rate_json: Default::default(),
            features_json: Default::default(),
        },
        actor,
        NOW,
    )
    .await;
    write(root, Change::ClaimKeyVersion { version: 1 }, actor, NOW).await;
    commit(root, 1, actor).await;
    write(
        root,
        Change::Activate {
            external_ref: Some("ws_1".into()),
        },
        actor,
        NOW,
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn no_tenant_chain_has_no_key_yet() {
    let records = MemRecords::default();
    let ports = Ports::new(&records);
    let cache = RootCache::new();
    let root = Root::new(&ports, &cache, SystemRng);
    assert!(matches!(
        root.copy_ring(&tenant()).await.unwrap(),
        TenantRingState::NoKeyYet
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn shredding_and_shredded_heads_do_not_need_keys() {
    let records = MemRecords::default();
    let writer_ports = Ports::new(&records);
    let writer_cache = RootCache::new();
    let writer = Root::new(&writer_ports, &writer_cache, SystemRng);
    active(&writer_ports, &writer).await;
    write(
        &writer,
        Change::SetDeletion {
            shred_due_at: DUE,
            reason: DeletionReason::CustomerRequest,
            key_hash: "ab".repeat(32),
        },
        Actor::Customer,
        NOW,
    )
    .await;
    writer_ports.clock.set(DUE);
    writer
        .load_key(&tenant(), 1, key(1).check_value())
        .await
        .unwrap();
    write(&writer, Change::StartShred, Actor::ShredJob, DUE).await;

    let empty = Ports::new(&records);
    empty.clock.set(DUE);
    let cache = RootCache::new();
    let root = Root::new(&empty, &cache, SystemRng);
    assert!(matches!(
        root.copy_ring(&tenant()).await.unwrap(),
        TenantRingState::Shredded
    ));
    // The real shred path reads the head first, marking the old key gone for the writer.
    assert!(root
        .tenant_head(&tenant())
        .await
        .unwrap()
        .unwrap()
        .private
        .is_none());
    write(&root, Change::FinishShred, Actor::ShredJob, DUE).await;
    let cold = RootCache::new();
    let root = Root::new(&empty, &cold, SystemRng);
    assert!(matches!(
        root.copy_ring(&tenant()).await.unwrap(),
        TenantRingState::Shredded
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn committed_version_with_missing_blobs_stays_named_in_a_partial_ring() {
    let records = MemRecords::default();
    let writer_ports = Ports::new(&records);
    let cache = RootCache::new();
    let writer = Root::new(&writer_ports, &cache, SystemRng);
    active(&writer_ports, &writer).await;
    write(
        &writer,
        Change::ClaimKeyVersion { version: 2 },
        Actor::RotationJob,
        NOW,
    )
    .await;
    writer_ports.put_key(2).await;
    commit(&writer, 2, Actor::RotationJob).await;

    let reader_ports = Ports::new(&records);
    reader_ports.put_key(1).await;
    let cold = RootCache::new();
    let reader = Root::new(&reader_ports, &cold, SystemRng);
    let TenantRingState::Ring(ring) = reader.copy_ring(&tenant()).await.unwrap() else {
        panic!("expected a partial ring");
    };
    assert!(ring.named(1) && ring.named(2) && !ring.named(3));
    assert_eq!(ring.key(1).unwrap().check_value(), key(1).check_value());
    assert!(ring.key(2).is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn rotating_claim_is_named_but_uncommitted_blob_is_not_a_key() {
    let records = MemRecords::default();
    let ports = Ports::new(&records);
    let cache = RootCache::new();
    let writer = Root::new(&ports, &cache, SystemRng);
    active(&ports, &writer).await;
    write(
        &writer,
        Change::ClaimKeyVersion { version: 2 },
        Actor::RotationJob,
        NOW,
    )
    .await;
    ports.put_key(2).await;

    let cache = RootCache::new();
    let reader = Root::new(&ports, &cache, SystemRng);
    let TenantRingState::Ring(ring) = reader.copy_ring(&tenant()).await.unwrap() else {
        panic!("expected a ring with an open claim");
    };
    assert!(ring.named(1) && ring.named(2) && !ring.named(3));
    assert!(ring.key(1).is_some());
    assert!(ring.key(2).is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn marker_or_foreign_name_in_either_key_location_refuses_the_ring() {
    let records = MemRecords::default();
    let ports = Ports::new(&records);
    let cache = RootCache::new();
    let root = Root::new(&ports, &cache, SystemRng);
    active(&ports, &root).await;
    for (in_a, leaf) in [(true, "shredded"), (false, "foreign-name")] {
        let reader_ports = Ports::new(&records);
        reader_ports.put_key(1).await;
        let location = if in_a {
            &reader_ports.keys_a
        } else {
            &reader_ports.keys_b
        };
        let name = format!("{}{leaf}", tk_prefix(&tenant()));
        assert!(location.put_if_absent(&name, vec![1]).await.unwrap());
        let cold = RootCache::new();
        let reader = Root::new(&reader_ports, &cold, SystemRng);
        assert!(
            matches!(reader.copy_ring(&tenant()).await, Err(e) if is_foreign(&e)),
            "{name}"
        );
    }
}
