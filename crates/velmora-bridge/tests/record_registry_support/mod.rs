//! Recording fixtures shared by the writer registry and recovery-copy acceptance tests.

#[path = "../segmented_support/mod.rs"]
mod segmented;

use std::cell::Cell;
use std::rc::Rc;

use sha2::{Digest, Sha256};
use velmora::rng::SystemRng;
use velmora_bridge::crypto::scheme2::{seal_control, seal_record_v2, ControlSealer, TenantKey};
use velmora_bridge::directory::chain::{TenantChain, Written};
use velmora_bridge::directory::record::{DeletionReason, Tenant};
use velmora_bridge::directory::seal::{ChainSeal, SealKeys};
use velmora_bridge::directory::store::SqlDirectory;
use velmora_bridge::directory::transition::{Actor, Change};
use velmora_bridge::keys::chain::Put;
use velmora_bridge::keys::checkpoint::{checkpoint_name, CHECKPOINT_EVERY};
use velmora_bridge::keys::frozen::{freeze_keys, thaw_keys};
use velmora_bridge::keys::gate::{MoveGate, TenantDoor, ZeroHead};
use velmora_bridge::keys::locations::{two_in_account, write_locations};
use velmora_bridge::keys::ports::{
    Admission, Applied, ApplyEntry, Binding, BucketAdmission, BucketReservation, ControlChain,
    ControlIntents, KeyAdmission, KeyTarget, OpeningChange,
};
use velmora_bridge::keys::record::{
    key_chain, seal_key_record, KeyOp, KeyTable, OneKey, Subject, SubjectDoor, SubjectKind,
    SubjectPrivate, SubjectStatus,
};
use velmora_bridge::keys::revocations::put_tenant_revocation;
use velmora_bridge::keys::routes::put_route;
use velmora_bridge::keys::tk::LoadedRing;
use velmora_bridge::keys::writer::{finish_keys, KeyAnswer, KeyEnv, KeyRequest, Limits};
use velmora_bridge::plan::StoredPlan;
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::recovery::{self, GenerationManifest, Layout, ScopeSealer, Sealer};
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::tenant_catalog::{TenantCatalog, UnitPort};
use velmora_bridge::testkit::{FixedClock, MemBlobStore, RusqliteSql, TestKek};
use velmora_bridge::unit::{Seqs, UnitAnswer, UnitCall, UnitName};
use velmora_bridge::*;

pub const A: &str = "t_00000000000000a1";
pub const B: &str = "t_00000000000000b2";
pub const SHREDDED: &str = "t_00000000000000c3";
pub const ZERO: &str = "t_0000000000000000";
const NOW: UnixMs = UnixMs(1_800_000_000_000);
pub type Records = Vec<(String, Vec<u8>)>;

pub fn scope(t: &str) -> TenantScope {
    if t == ZERO {
        TenantScope::tenant_zero()
    } else {
        TenantScope::managed(&velmora_bridge::unit::TenantId::parse(t).unwrap()).unwrap()
    }
}

pub fn key(t: &str, v: u32) -> TenantKey {
    let bytes = Sha256::digest(format!("fixture-key/{t}/{v}")).into();
    TenantKey::from_bytes(&TenantId::parse(t).unwrap(), v, bytes).unwrap()
}

struct NoUnitCalls;

impl UnitPort for NoUnitCalls {
    async fn call(&self, _: &UnitCall) -> Result<UnitAnswer> {
        panic!("record sealing must not call the unit")
    }
}

fn ring_catalog(t: &str) -> TenantCatalog<NoUnitCalls, SqlCatalog<RusqliteSql>> {
    let tk = Rc::new(key(t, 1));
    TenantCatalog::new(
        NoUnitCalls,
        SqlCatalog::new(RusqliteSql::with_schema().unwrap()),
        UnitName::new(velmora_bridge::unit::TenantId::parse(t).unwrap(), 0),
        Seqs {
            state_seq: 1,
            keys_seq: 0,
        },
    )
    .with_ring(Rc::new(move || {
        let tk = Rc::clone(&tk);
        Box::pin(async move { Ok(Rc::new(LoadedRing::new(tk, Vec::new()).unwrap())) })
    }))
}

pub async fn tenant_control(kek: &TestKek, store: &MemRecords, t: &str, shred: bool) {
    let keys = SealKeys::new();
    let clock = FixedClock::new(NOW);
    let seal = ChainSeal::new(kek, &keys, &clock, SystemRng);
    let chain = TenantChain { store, seal: &seal };
    let tenant = if t == ZERO {
        Tenant::Zero
    } else {
        Tenant::Managed(TenantId::parse(t).unwrap())
    };
    let write = async |change: Change, actor, at| {
        let result = chain.write(&tenant, &change, actor, at, 0).await;
        assert!(
            matches!(result, Ok(Written::Wrote(_))),
            "{t}: {change:?}: {result:?}"
        );
    };
    if t == ZERO {
        write(
            Change::CreateTenantZero {
                jurisdiction: "us".into(),
            },
            Actor::Operator,
            NOW,
        )
        .await;
        return;
    }
    let actor = Actor::TenantCreation;
    write(
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
    write(Change::ClaimKeyVersion { version: 1 }, actor, NOW).await;
    let tk = Rc::new(key(t, 1));
    keys.hold(Rc::clone(&tk), NOW, NOW).unwrap();
    write(
        Change::CommitKeyVersion {
            version: 1,
            kcv: tk.check_value(),
        },
        actor,
        NOW,
    )
    .await;
    write(
        Change::Activate {
            external_ref: Some(format!("ws_{t}")),
        },
        actor,
        NOW,
    )
    .await;
    if shred {
        let due = UnixMs(NOW.0 + 7 * 24 * 3_600_000);
        write(
            Change::SetDeletion {
                shred_due_at: due,
                reason: DeletionReason::CustomerRequest,
                key_hash: "ab".repeat(32),
            },
            Actor::Customer,
            NOW,
        )
        .await;
        clock.set(due);
        keys.hold(tk, due, due).unwrap();
        write(Change::StartShred, Actor::ShredJob, due).await;
        keys.gone(&TenantId::parse(t).unwrap(), 1);
        write(Change::FinishShred, Actor::ShredJob, due).await;
    }
}

fn recorded(store: &MemRecords) -> Records {
    store
        .names()
        .into_iter()
        .map(|n| {
            let bytes = store.raw(&n).unwrap();
            (n, bytes)
        })
        .collect()
}

pub async fn shredded_controls(kek: &TestKek, t: &str) -> Records {
    let store = MemRecords::new();
    tenant_control(kek, &store, t, true).await;
    put_tenant_revocation(
        &store,
        kek,
        &TenantId::parse(t).unwrap(),
        "SHREDDEDKEY",
        NOW.0 as u64,
        &mut SystemRng,
    )
    .await
    .unwrap();
    recorded(&store)
}

#[derive(Default)]
struct KeyPorts(Cell<u64>);

impl KeyTarget for KeyPorts {
    fn label(&self) -> &str {
        "fixture"
    }
    async fn keys_seq(&self) -> Result<u64> {
        Ok(self.0.get())
    }
    async fn closed(&self) -> Result<Vec<String>> {
        Ok(vec![])
    }
    async fn apply(&self, from: u64, entries: &[ApplyEntry]) -> Result<Applied> {
        if from > self.0.get() {
            return Ok(Applied::Behind {
                keys_seq: self.0.get(),
            });
        }
        let keys_seq = entries
            .iter()
            .map(ApplyEntry::seq)
            .max()
            .unwrap_or(from)
            .max(self.0.get());
        self.0.set(keys_seq);
        Ok(Applied::Done { keys_seq })
    }
}

impl KeyAdmission for KeyPorts {
    async fn admit(&self, _: &TenantId, _: &str, _: &OpeningChange<'_>) -> Result<Admission> {
        Ok(Admission::Admitted {
            keys_seq: self.0.get(),
        })
    }
    async fn release(&self, _: &TenantId, _: &str) -> Result<()> {
        Ok(())
    }
    async fn admit_bucket(
        &self,
        _: &TenantId,
        _: &str,
        _: &BucketReservation<'_>,
    ) -> Result<BucketAdmission> {
        panic!("these fixtures do not reserve buckets")
    }
    async fn bind_bucket(&self, _: &TenantId, _: &str, _: Option<u64>, _: u64) -> Result<bool> {
        panic!("these fixtures do not bind buckets")
    }
    async fn release_bound(&self, _: &TenantId, _: &str, _: Option<u64>) -> Result<bool> {
        panic!("these fixtures do not release buckets")
    }
    async fn bucket_binding(&self, _: &TenantId, _: u64) -> Result<Binding> {
        Ok(Binding::None)
    }
}

impl ControlIntents for KeyPorts {
    async fn send(&self, _: &TenantId, _: ControlChain, _: u64) -> Result<()> {
        Ok(())
    }
    async fn note(&self, _: &TenantId, _: ControlChain, _: u64, _: &str) -> Result<()> {
        Ok(())
    }
    async fn clear(&self, _: &TenantId, _: ControlChain, _: u64) -> Result<()> {
        Ok(())
    }
}

impl MoveGate for KeyPorts {
    async fn zero_head(&self) -> Result<ZeroHead> {
        Ok(ZeroHead::D1)
    }
    async fn tenant_door(&self, _: &TenantId) -> Result<TenantDoor> {
        Ok(TenantDoor::default())
    }
    async fn zero_revoke(&self, _: &str) -> Result<()> {
        panic!("not tenant zero's key")
    }
    async fn refuse_in_d1(&self, _: &str) -> Result<()> {
        panic!("not tenant zero's key")
    }
}

async fn key_records(store: &MemRecords, kek: &TestKek, t: &str) {
    let tenant = TenantId::parse(t).unwrap();
    let ring = OneKey(key(t, 1));
    let subject = Subject {
        door: SubjectDoor {
            id: "PR0001".into(),
            kind: SubjectKind::Principal,
            status: SubjectStatus::Active,
            made_by: None,
            grants: vec![],
            created_at: NOW.0 as u64,
            secret_kek_version: None,
        },
        private: SubjectPrivate {
            owner_ref: Some("owner".into()),
            label: Some("fixture".into()),
            grants: vec![],
            secret_wrapped: None,
        },
    };
    let records = MemRecords::new();
    let units = [KeyPorts::default()];
    let directory = KeyPorts::default();
    let ports = KeyPorts::default();
    let clock = FixedClock::new(NOW);
    let env = KeyEnv {
        store: &records,
        kek,
        ring: &ring,
        tenant: &tenant,
        admission: &units[0],
        intents: &ports,
        units: &units,
        directory: &directory,
        clock: &clock,
        limits: Limits::NotServed,
        gate: &ports,
    };
    let mut table = KeyTable::empty(tenant.clone());
    let answer = env
        .change(
            &mut table,
            "fixture-create",
            &KeyRequest::Create(subject.clone()),
            &mut SystemRng,
        )
        .await
        .unwrap();
    assert_eq!(answer, KeyAnswer::Done { seq: 1 });

    // Seed enough authentic history for the finisher's actual checkpoint writer.
    // The setup records are not needed by the copy test.
    let chain = key_chain(&tenant);
    for seq in 2..=CHECKPOINT_EVERY {
        let mut door = subject.door.clone();
        if seq % 2 == 0 {
            door.status = SubjectStatus::Disabled;
        }
        let sealed = seal_key_record(
            kek,
            &ring,
            &tenant,
            seq,
            KeyOp::Status,
            NOW.0 as u64,
            &door,
            Some(&subject.private),
            seq % 2 == 0,
            None,
            &mut SystemRng,
        )
        .unwrap();
        assert_eq!(
            chain.put(&records, seq, sealed).await.unwrap(),
            Put::Written
        );
    }
    let report = finish_keys(&env, &mut SystemRng).await.unwrap();
    assert_eq!(report.checkpoint, Some(CHECKPOINT_EVERY));
    put_tenant_revocation(
        &records,
        kek,
        &tenant,
        "PR0001",
        NOW.0 as u64,
        &mut SystemRng,
    )
    .await
    .unwrap();
    let report = finish_keys(&env, &mut SystemRng).await.unwrap();
    let revoked = CHECKPOINT_EVERY + 1;
    assert_eq!(report.appended, [revoked]);
    freeze_keys(&env, None, &mut SystemRng).await.unwrap();
    thaw_keys(&env, revoked, &mut SystemRng).await.unwrap();
    for name in [
        chain.name(1),
        chain.name(revoked),
        chain.name(revoked + 1),
        chain.name(revoked + 2),
        checkpoint_name(&tenant, CHECKPOINT_EVERY),
    ] {
        assert!(store
            .put_if_absent(&name, records.raw(&name).expect("native key writer output"))
            .await
            .unwrap());
    }
}

/// Actual control writers, plus wire fixtures for families with no writer in this crate.
pub async fn control_records(kek: &TestKek) -> Records {
    let store = MemRecords::new();
    for t in [ZERO, A, B] {
        tenant_control(kek, &store, t, false).await;
    }
    for t in [A, B] {
        key_records(&store, kek, t).await;
        put_tenant_revocation(
            &store,
            kek,
            &TenantId::parse(t).unwrap(),
            "REVOKEDKEY",
            NOW.0 as u64,
            &mut SystemRng,
        )
        .await
        .unwrap();
    }
    write_locations(&store, kek, &two_in_account(), &mut SystemRng)
        .await
        .unwrap();
    put_route(
        &store,
        kek,
        &TenantId::parse(A).unwrap(),
        "ROUTEDKEY",
        SubjectKind::S3,
        NOW.0 as u64,
        &mut SystemRng,
    )
    .await
    .unwrap();
    let db = RusqliteSql::open_in_memory().unwrap();
    db.apply(include_str!(
        "../../../../workers/s3-bridge/migrations-directory/0001_directory.sql"
    ))
    .unwrap();
    velmora_bridge::directory::gate::close(&store, &SqlDirectory { sql: &db }, "fixture", NOW)
        .await
        .unwrap();

    // These global families have no crate writer; put_tenant_revocation always uses
    // the tenant-scoped name, so the accepted flat VCR1 revocation is also a fixture.
    for name in [
        "m/tref/workspace",
        "m/ub/birth",
        "m/reg/account",
        "m/rst/token",
        "m/rk/FLATVCR",
    ] {
        let sealed = seal_control(
            kek,
            name,
            &ControlSealer::Global,
            b"{}",
            None,
            &mut SystemRng,
        )
        .unwrap();
        assert!(store.put_if_absent(name, sealed).await.unwrap());
    }
    // This crate writes bucket-created tenant-chain entries, not a bucket-configuration chain.
    for t in [ZERO, A, B] {
        let tk = (t != ZERO).then(|| key(t, 1));
        let sealer = tk
            .as_ref()
            .map_or(ControlSealer::TenantZero, ControlSealer::Managed);
        let name = format!("m/x/{t}/b/b_fixture/00000000000000000001");
        let sealed = seal_control(kek, &name, &sealer, b"{}", Some(b"{}"), &mut SystemRng).unwrap();
        assert!(store.put_if_absent(&name, sealed).await.unwrap());
    }
    let mut records = recorded(&store);
    records.extend(shredded_controls(kek, SHREDDED).await);
    records
}

fn bucket() -> Bucket {
    Bucket {
        id: BucketId::new("b_0123456789abcdef"),
        name: "vault".into(),
        owner: "fixture".into(),
        bdk_wrapped: vec![0x42; 40],
        kek_version: 1,
        disposable: true,
        created_at: NOW,
    }
}

fn generation(bucket: &Bucket, tail: u8, count: u32, at: UnixMs) -> GenerationRow {
    GenerationRow {
        id: GenerationId::mint(at, [tail; 8]),
        bucket_id: bucket.id.clone(),
        key: format!("object-{tail}"),
        state: GenerationState::Live,
        size: u64::from(count) * 10,
        etag: "\"etag\"".into(),
        checksum_json: None,
        content_json: "{}".into(),
        user_meta_json: "{}".into(),
        extent_count: count,
        created_at: at,
        retired_at: None,
    }
}

fn extents(g: &GenerationRow) -> Vec<ExtentRow> {
    (0..g.extent_count)
        .map(|seq| ExtentRow {
            id: ExtentId::mint([seq as u8; 13]),
            bucket_id: g.bucket_id.clone(),
            generation_id: Some(g.id.clone()),
            state: ExtentState::Committed,
            seq: Some(seq),
            plain_offset: Some(u64::from(seq) * 10),
            plain_size: 10,
            cipher_size: 50,
            media_header: vec![1, 2, 3],
            key_mode: 1,
            wrapped_file_key: Some(vec![7; 40]),
            plain_md5: [1; 16],
            plain_sha256: [2; 32],
            cipher_sha256: [3; 32],
            safety_state: SafetyState::Held,
            article_count: None,
            plan_rev: 0,
            last_verified_at: None,
            release_evidence: None,
            released_at: None,
            created_at: g.created_at,
        })
        .collect()
}

fn blobs(store: &MemBlobStore) -> Records {
    store
        .keys()
        .into_iter()
        .map(|n| {
            let bytes = store.stored(&n).unwrap().bytes;
            (n, bytes)
        })
        .collect()
}

pub async fn data_records(kek: &TestKek) -> Records {
    let store = MemBlobStore::new();
    let catalog = SqlCatalog::new(RusqliteSql::with_schema().unwrap());
    let bucket = bucket();
    catalog.create_bucket(&bucket).await.unwrap();
    let at = UnixMs(NOW.0 - 600_000);
    recovery::write_key_revocation(&store, kek, "FLATV1", at)
        .await
        .unwrap();
    let tenant_zero_sealer = Sealer {
        catalog: &catalog,
        kek,
    };
    let flat = Layout::flat();
    let g = generation(&bucket, 1, 0, at);
    recovery::write_generation(
        &catalog,
        &store,
        &tenant_zero_sealer,
        &flat,
        &bucket,
        &g,
        &[],
    )
    .await
    .unwrap();
    let batch = recovery::NewTombstone {
        key: "batch-delete",
        id: GenerationId::mint(at, [9; 8]),
        now: at,
    };
    for result in recovery::write_tombstones(
        &catalog,
        &store,
        &tenant_zero_sealer,
        &flat,
        &bucket.id,
        &[batch],
    )
    .await
    .unwrap()
    {
        result.unwrap();
    }
    let zero = scope(ZERO);
    let job_zero = ScopeSealer {
        scope: &zero,
        catalog: &catalog,
        kek,
    };
    let zero_layout = Layout::tenant(ZERO).unwrap();
    let zero_g = generation(&bucket, 2, 1, at);
    recovery::write_article_plan(&store, &job_zero, &zero_layout, &extents(&zero_g)[0], &[])
        .await
        .unwrap();

    for (i, t) in [A, B].into_iter().enumerate() {
        let layout = Layout::tenant(t).unwrap();
        let keys = ring_catalog(t);
        let sealer = Sealer {
            catalog: &keys,
            kek,
        };
        let g = generation(&bucket, 3 + i as u8, 0, at);
        recovery::write_generation(&catalog, &store, &sealer, &layout, &bucket, &g, &[])
            .await
            .unwrap();
        recovery::write_tombstone(
            &catalog,
            &store,
            &sealer,
            &layout,
            &bucket.id,
            "gone",
            &GenerationId::mint(at, [5 + i as u8; 8]),
            at,
        )
        .await
        .unwrap();
    }
    let mut written = blobs(&store);
    written.extend(move_records().await);
    written
}

async fn move_records() -> Records {
    use velmora_bridge::crypto::scheme2::wrap_bdk_v2;
    use velmora_bridge::crypto::DataKey;
    use velmora_bridge::keys::moving::{
        put_sealed, reseal_article_plan, reseal_generation, reseal_tombstone,
    };

    let store = MemRecords::new();
    let ring = OneKey(key(A, 1));
    let mut rng = SystemRng;
    let mut bucket = bucket();
    let bdk = DataKey::generate(&mut rng).unwrap();
    bucket.bdk_wrapped = wrap_bdk_v2(&ring.0, &bucket.id, &bdk, &mut rng).unwrap();
    let at = UnixMs(NOW.0 - 600_000);
    let g = generation(&bucket, 12, 0, at);
    let one_extent = generation(&bucket, 13, 1, at);
    let extent = extents(&one_extent).remove(0);
    let plan = StoredPlan {
        rows: Vec::new(),
        packed: None,
        parity: None,
    };
    let gone = recovery::Tombstone {
        v: 1,
        id: one_extent.id.to_string(),
        bucket_id: bucket.id.to_string(),
        key: one_extent.key,
        deleted_at: at.0,
    };
    for sealed in [
        reseal_generation(&ring.0, &bucket, &g, &[], &mut rng).unwrap(),
        reseal_article_plan(&ring.0, &extent, &plan, &mut rng).unwrap(),
        reseal_tombstone(&ring.0, &gone, &mut rng).unwrap(),
    ] {
        put_sealed(&store, &ring, ring.0.tenant(), &sealed)
            .await
            .unwrap();
    }
    recorded(&store)
}

pub struct SegmentedRecords {
    pub plans: Records,
    pub segments: Records,
    pub head: (String, Vec<u8>),
}

pub async fn segmented_records(kek: &TestKek, t: &str) -> SegmentedRecords {
    let store = MemBlobStore::new();
    let bucket = bucket();
    let g = generation(&bucket, 17, 2, UnixMs(NOW.0 - 600_000));
    let extents = extents(&g);
    let scope = scope(t);
    let catalog = ring_catalog(t);
    let sealer = ScopeSealer {
        scope: &scope,
        catalog: &catalog,
        kek,
    };
    let layout = Layout::tenant(t).unwrap();
    for extent in &extents {
        recovery::write_stored_plan(
            &store,
            &sealer,
            &layout,
            extent,
            &StoredPlan {
                rows: vec![],
                packed: None,
                parity: None,
            },
        )
        .await
        .unwrap();
    }

    // Format-2 heads and segments have readers but no production writer in this crate.
    let manifest = GenerationManifest::new(&bucket, &g, &extents).unwrap();
    let set = segmented::set_id(g.created_at.0, 1);
    let plain = segmented::split(&manifest, &set, 1);
    let tk = key(t, 1);
    let segments: Records = plain
        .iter()
        .map(|segment| {
            let name = layout.segment_key(&set, segment.index);
            let sealed = seal_record_v2(
                &tk,
                &name,
                &serde_json::to_vec(segment).unwrap(),
                &mut SystemRng,
            )
            .unwrap();
            (name, sealed)
        })
        .collect();
    let digests: Vec<_> = segments
        .iter()
        .map(|(_, sealed)| Sha256::digest(sealed).to_vec())
        .collect();
    let head = segmented::head_of(&manifest, &set, &plain, &digests);
    let name = layout.generation_key(&g.id);
    let sealed = seal_record_v2(
        &tk,
        &name,
        &serde_json::to_vec(&head).unwrap(),
        &mut SystemRng,
    )
    .unwrap();
    SegmentedRecords {
        plans: blobs(&store),
        segments,
        head: (name, sealed),
    }
}
