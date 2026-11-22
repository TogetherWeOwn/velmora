use std::cell::RefCell;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::{
    open_record_v2, rewrap_bdk_to_v1, rewrap_bdk_to_v2, rewrap_secret_to_v1, rewrap_secret_to_v2,
    same_bdk, same_secret, seal_record_v2, unwrap_secret_v2, TenantId, TenantKey,
};
use velmora_bridge::crypto::{
    seal_extent, unwrap_bdk, unwrap_secret, wrap_bdk, wrap_secret, DataKey,
};
use velmora_bridge::keys::chain::Put;
use velmora_bridge::keys::checkpoint::read_key_chain;
use velmora_bridge::keys::moving::{
    check_file_keys, count_records, moved_bucket, put_sealed, rehome_blob, reseal_article_plan,
    reseal_generation, reseal_tombstone, tenant_cache_key, tenant_safety_key, verify_held,
    write_moved_keys, MovedKey, MovedKeys, Placed, Rehomed, Sealed,
};
use velmora_bridge::keys::record::{
    key_chain, seal_key_record, Access, Entry, Grant, KeyOp, OneKey, SubjectDoor, SubjectKind,
    SubjectPrivate, SubjectStatus,
};
use velmora_bridge::keys::revocations::tenant_revocation_name;
use velmora_bridge::plan::StoredPlan;
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::recovery::{GenerationManifest, Tombstone};
use velmora_bridge::testkit::{MemBlobStore, TestKek};
use velmora_bridge::{
    ArticleRow, ArticleState, BlobMeta, BlobStore, BridgeError, Bucket, BucketId, ExtentId,
    ExtentRow, ExtentState, GenerationId, GenerationRow, GenerationState, Result, SafetyState,
    UnixMs,
};

const TENANT: &str = "t_00000000000000a1";
const PRINCIPAL: &str = "PR0001";
const OWNER: &str = "member";
const AT: u64 = 10;

/// A ring of one borrowed key.
struct RefRing<'a>(&'a TenantKey);

impl velmora_bridge::keys::record::TkRing for RefRing<'_> {
    fn current(&self) -> Option<&TenantKey> {
        Some(self.0)
    }
    fn key(&self, v: u32) -> Option<&TenantKey> {
        (self.0.version() == v).then_some(self.0)
    }
}

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

#[derive(Default)]
struct TestRng(u64);

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut hash = Sha256::new();
            hash.update(b"owner move keys");
            hash.update(self.0.to_be_bytes());
            self.0 += 1;
            block.copy_from_slice(&hash.finalize()[..block.len()]);
        }
        Ok(())
    }
}

fn kek() -> TestKek {
    TestKek::with_versions(1, &[(1, derived("kek"))])
}

fn tenant_key() -> TenantKey {
    TenantKey::from_bytes(&TenantId::parse(TENANT).unwrap(), 1, derived("tk")).unwrap()
}

fn bucket_v1(kek: &TestKek, n: u8, bdk: &DataKey, rng: &mut TestRng) -> Bucket {
    let id = BucketId::mint([n; 8]);
    let (kek_version, wrapped) = wrap_bdk(kek, &id, bdk, rng).unwrap();
    Bucket {
        id,
        name: format!("bucket-{n}"),
        owner: "admin".into(),
        bdk_wrapped: wrapped.to_vec(),
        kek_version,
        disposable: false,
        created_at: UnixMs(1),
    }
}

const PLAINTEXT: &[u8] = b"extent contents";

fn extent(bdk: &DataKey, bucket_id: &BucketId, n: u8, rng: &mut TestRng) -> (ExtentRow, Vec<u8>) {
    let id = ExtentId::mint([n; 13]);
    let sealed = seal_extent(bdk, bucket_id, &id, PLAINTEXT, rng).unwrap();
    let row = ExtentRow {
        id,
        bucket_id: bucket_id.clone(),
        generation_id: None,
        state: ExtentState::Staged,
        seq: None,
        plain_offset: None,
        plain_size: PLAINTEXT.len() as u64,
        cipher_size: sealed.ciphertext.len() as u64,
        media_header: sealed.media_header.to_vec(),
        key_mode: 1,
        wrapped_file_key: Some(sealed.wrapped_file_key.to_vec()),
        plain_md5: sealed.plain_md5,
        plain_sha256: sealed.plain_sha256,
        cipher_sha256: sealed.cipher_sha256,
        safety_state: SafetyState::Held,
        article_count: None,
        plan_rev: 0,
        last_verified_at: None,
        release_evidence: None,
        released_at: None,
        created_at: UnixMs(1),
    };
    (row, sealed.ciphertext)
}

struct Records {
    tk: TenantKey,
    original: Bucket,
    moved: Bucket,
    generation: GenerationRow,
    extents: Vec<ExtentRow>,
    ciphertext: Vec<u8>,
    rng: TestRng,
}

impl Records {
    fn new() -> Self {
        let kek = kek();
        let tk = tenant_key();
        let mut rng = TestRng::default();
        let bdk = DataKey::from_bytes(derived("bdk"));
        let original = bucket_v1(&kek, 1, &bdk, &mut rng);
        let moved = moved_bucket(&kek, &tk, &original, PRINCIPAL, None, &mut rng).unwrap();
        let id = GenerationId::new("g_01");
        let (first, ciphertext) = extent(&bdk, &original.id, 1, &mut rng);
        let (second, _) = extent(&bdk, &original.id, 2, &mut rng);
        let mut extents = vec![first, second];
        let mut size = 0;
        for (seq, row) in extents.iter_mut().enumerate() {
            row.generation_id = Some(id.clone());
            row.state = ExtentState::Committed;
            row.seq = Some(seq as u32);
            row.plain_offset = Some(size);
            size += row.plain_size;
        }
        let generation = GenerationRow {
            id,
            bucket_id: original.id.clone(),
            key: "object".into(),
            state: GenerationState::Live,
            size,
            etag: "\"original\"".into(),
            checksum_json: None,
            content_json: "{}".into(),
            user_meta_json: "{}".into(),
            extent_count: extents.len() as u32,
            created_at: UnixMs(1),
            retired_at: None,
        };
        Self {
            tk,
            original,
            moved,
            generation,
            extents,
            ciphertext,
            rng,
        }
    }

    fn reseal(&mut self) -> Sealed {
        reseal_generation(
            &self.tk,
            &self.moved,
            &self.generation,
            &self.extents,
            &mut self.rng,
        )
        .unwrap()
    }

    fn tombstone(&mut self) -> Sealed {
        reseal_tombstone(
            &self.tk,
            &Tombstone {
                v: 1,
                id: "g_deleted".into(),
                bucket_id: self.moved.id.as_str().into(),
                key: "deleted-object".into(),
                deleted_at: 2,
            },
            &mut self.rng,
        )
        .unwrap()
    }

    fn article_plan(&mut self) -> Sealed {
        let extent = &self.extents[0];
        let mid = self.ciphertext.len() / 2;
        let rows = [0..mid, mid..self.ciphertext.len()]
            .into_iter()
            .enumerate()
            .map(|(idx, bytes)| ArticleRow {
                extent_id: extent.id.clone(),
                idx: idx as u32,
                message_id: format!("article-{idx}@example.test"),
                newsgroup: "alt.test".into(),
                headers: Vec::new(),
                cipher_offset: bytes.start as u64,
                cipher_len: bytes.len() as u64,
                payload_sha256: Sha256::digest(&self.ciphertext[bytes]).into(),
                yenc_name: None,
                state: ArticleState::Planned,
                provider_id: None,
                posted_at: None,
                reposted_at: None,
            })
            .collect();
        let plan = StoredPlan {
            rows,
            packed: None,
            parity: None,
        };
        reseal_article_plan(&self.tk, extent, &plan, &mut self.rng).unwrap()
    }
}

fn assert_invalid(error: BridgeError, expected: &str) {
    match error {
        BridgeError::Invalid(message) => assert_eq!(message, expected),
        other => panic!("expected invalid input with message {expected:?}, got {other:?}"),
    }
}

fn assert_record_opens(tk: &TenantKey, record: &Sealed) {
    let opened = open_record_v2(tk, tk.tenant(), &record.name, &record.sealed).unwrap();
    assert_eq!(*opened, record.plain);
}

#[test]
fn a_bucket_key_round_trips_between_schemes() {
    let kek = kek();
    let tk = tenant_key();
    let mut rng = TestRng::default();
    let bdk = DataKey::from_bytes(derived("bdk"));
    let old = bucket_v1(&kek, 1, &bdk, &mut rng);
    let other = bucket_v1(&kek, 2, &bdk, &mut rng);
    let new = rewrap_bdk_to_v2(
        &kek,
        old.kek_version,
        &old.id,
        &old.bdk_wrapped,
        &tk,
        &mut rng,
    )
    .unwrap();
    assert_eq!(new.len(), 73);
    assert_eq!(new[0], 0x02);

    let matches = |version, wrapped: &[u8]| {
        same_bdk(&kek, version, wrapped, &tk, tk.tenant(), 1, &old.id, &new)
    };
    assert!(matches(old.kek_version, &old.bdk_wrapped).unwrap());
    assert!(!matches(other.kek_version, &other.bdk_wrapped).unwrap_or(false));

    let (version, back) = rewrap_bdk_to_v1(&kek, &tk, &old.id, &new, &mut rng).unwrap();
    assert_eq!(back[0], 0x01);
    assert!(unwrap_bdk(&kek, version, &old.id, &back).is_ok());
    assert!(matches(version, &back).unwrap());
}

#[test]
fn an_access_key_secret_round_trips_between_schemes() {
    let kek = kek();
    let tk = tenant_key();
    let t = tk.tenant();
    let mut rng = TestRng::default();
    let id = "AKVL0001";
    let secret = derived(id);
    let (v1, old) = wrap_secret(&kek, id, &secret, &mut rng).unwrap();
    let (v2, new) = rewrap_secret_to_v2(&kek, v1, id, &old, t, &mut rng).unwrap();
    assert_eq!(new[0], 0x02);
    assert_eq!(
        unwrap_secret_v2(&kek, v2, t, id, &new).unwrap().as_slice(),
        secret
    );
    assert!(same_secret(&kek, v1, &old, t, v2, &new, id).unwrap());
    assert!(!same_secret(&kek, v1, &old, t, v2, &new, "AKVL0002").unwrap_or(false));

    let (v1, back) = rewrap_secret_to_v1(&kek, v2, id, &new, t, &mut rng).unwrap();
    assert_eq!(
        unwrap_secret(&kek, v1, id, &back).unwrap().as_slice(),
        secret
    );
}

#[test]
fn moving_a_bucket_preserves_its_metadata_and_requires_scheme_one() {
    let kek = kek();
    let t = TenantId::parse(TENANT).unwrap();
    let tk = TenantKey::from_bytes(&t, 2, derived("tk")).unwrap();
    let mut rng = TestRng::default();
    let old = bucket_v1(&kek, 1, &DataKey::from_bytes(derived("bdk")), &mut rng);
    let moved = moved_bucket(&kek, &tk, &old, PRINCIPAL, None, &mut rng).unwrap();

    assert_eq!(moved.id, old.id);
    assert_eq!(moved.name, old.name);
    assert_eq!(moved.disposable, old.disposable);
    assert_eq!(moved.created_at, old.created_at);
    assert_eq!(moved.owner, PRINCIPAL);
    assert_eq!(moved.kek_version, tk.version());
    assert_eq!(moved.bdk_wrapped[0], 0x02);
    assert!(moved_bucket(&kek, &tk, &moved, PRINCIPAL, None, &mut rng).is_err());
}

#[test]
fn checking_file_keys_reports_opened_failed_and_missing_keys() {
    let mut records = Records::new();
    let bdk = DataKey::from_bytes(derived("bdk"));
    let bucket = &records.moved;
    records
        .extents
        .push(extent(&bdk, &bucket.id, 3, &mut records.rng).0);
    let check = check_file_keys(&records.tk, bucket, &records.extents).unwrap();
    assert_eq!(check.opened, 3);
    assert_eq!(check.without_key, 0);
    assert!(check.failed.is_empty());

    let wrong_bdk = DataKey::from_bytes(derived("other bdk"));
    let (wrong_key, _) = extent(&wrong_bdk, &bucket.id, 4, &mut records.rng);
    let (wrong_bucket, _) = extent(&bdk, &BucketId::mint([2; 8]), 5, &mut records.rng);
    let (mut no_key, _) = extent(&bdk, &bucket.id, 6, &mut records.rng);
    no_key.wrapped_file_key = None;
    let check = check_file_keys(
        &records.tk,
        bucket,
        records
            .extents
            .iter()
            .chain([&wrong_key, &wrong_bucket, &no_key]),
    )
    .unwrap();
    assert_eq!(check.opened, 3);
    assert_eq!(check.without_key, 1);
    assert_eq!(check.failed, [wrong_key.id, wrong_bucket.id]);
}

#[test]
fn resealing_a_generation_preserves_file_key_wraps_and_checks_the_bucket() {
    let mut records = Records::new();
    let sealed = records.reseal();
    assert_eq!(
        sealed.name,
        format!("m/x/{TENANT}/{}", records.generation.id.as_str())
    );
    assert_record_opens(&records.tk, &sealed);
    let manifest: GenerationManifest = serde_json::from_slice(&sealed.plain).unwrap();
    assert_eq!(manifest.bucket.bdk_wrapped, records.moved.bdk_wrapped);
    assert_eq!(manifest.bucket.kek_version, 1);
    assert_eq!(manifest.extents.len(), 2);
    for (entry, row) in manifest.extents.iter().zip(&records.extents) {
        assert_eq!(entry.id, row.id.as_str());
        assert_eq!(
            &entry.wrapped_file_key,
            row.wrapped_file_key.as_ref().unwrap()
        );
    }

    let wrong_version = Bucket {
        kek_version: 2,
        ..records.moved.clone()
    };
    let wrong_bucket = GenerationRow {
        bucket_id: BucketId::mint([2; 8]),
        ..records.generation.clone()
    };
    for (bucket, generation) in [
        (&records.original, &records.generation),
        (&wrong_version, &records.generation),
        (&records.moved, &wrong_bucket),
    ] {
        assert!(reseal_generation(
            &records.tk,
            bucket,
            generation,
            &records.extents,
            &mut records.rng
        )
        .is_err());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn putting_a_sealed_record_distinguishes_retries_from_conflicts() {
    let mut records = Records::new();
    let store = MemRecords::new();
    let first = records.reseal();
    assert_eq!(
        put_sealed(&store, &RefRing(&records.tk), records.tk.tenant(), &first)
            .await
            .unwrap(),
        Placed::Written
    );
    assert_eq!(
        put_sealed(&store, &RefRing(&records.tk), records.tk.tenant(), &first)
            .await
            .unwrap(),
        Placed::Written
    );

    let same = records.reseal();
    assert_eq!(same.name, first.name);
    assert_eq!(same.plain, first.plain);
    assert_ne!(same.sealed, first.sealed);
    assert_eq!(
        put_sealed(&store, &RefRing(&records.tk), records.tk.tenant(), &same)
            .await
            .unwrap(),
        Placed::Same
    );

    records.generation.etag = "\"changed\"".into();
    let different = records.reseal();
    assert_invalid(
        put_sealed(
            &store,
            &RefRing(&records.tk),
            records.tk.tenant(),
            &different,
        )
        .await
        .unwrap_err(),
        "the target holds something else under this name",
    );
    assert_eq!(store.raw(&first.name), Some(first.sealed));
}

#[test]
fn tombstones_and_article_plans_open_under_their_tenant_names() {
    let mut records = Records::new();
    let tombstone = records.tombstone();
    let plan = records.article_plan();
    assert_eq!(tombstone.name, format!("m/x/{TENANT}/del/g_deleted"));
    assert_eq!(
        plan.name,
        format!("m/x/{TENANT}/art/{}", records.extents[0].id.as_str())
    );
    assert_record_opens(&records.tk, &tombstone);
    assert_record_opens(&records.tk, &plan);
}

#[tokio::test(flavor = "current_thread")]
async fn counting_records_reports_garbage_and_foreign_records_and_skips_bucket_config() {
    let mut records = Records::new();
    let store = MemRecords::new();
    let first = records.reseal();
    records.generation.id = GenerationId::new("g_02");
    for extent in &mut records.extents {
        extent.generation_id = Some(records.generation.id.clone());
    }
    for sealed in [
        first,
        records.reseal(),
        records.tombstone(),
        records.article_plan(),
    ] {
        assert_eq!(
            put_sealed(&store, &RefRing(&records.tk), records.tk.tenant(), &sealed)
                .await
                .unwrap(),
            Placed::Written
        );
    }

    let garbage_name = format!("m/x/{TENANT}/g_garbage");
    let foreign_name = format!("m/x/{TENANT}/g_other");
    let foreign_tenant = TenantId::parse("t_00000000000000a2").unwrap();
    let foreign_key = TenantKey::from_bytes(&foreign_tenant, 1, derived("foreign tk")).unwrap();
    let foreign_record = seal_record_v2(
        &foreign_key,
        &format!("m/x/{foreign_tenant}/g_other"),
        b"foreign body",
        &mut records.rng,
    )
    .unwrap();
    store.plant(&garbage_name, b"garbage".to_vec());
    store.plant(&foreign_name, foreign_record);
    store.plant(&format!("m/x/{TENANT}/b/b_01"), b"bucket config".to_vec());

    let tenant = records.tk.tenant().clone();
    let count = count_records(&store, &OneKey(records.tk), &tenant)
        .await
        .unwrap();
    assert_eq!(count.generations, 2);
    assert_eq!(count.tombstones, 1);
    assert_eq!(count.plans, 1);
    assert_eq!(count.other, 0);
    assert_eq!(count.failed, [garbage_name, foreign_name]);
}

struct FrozenKeys {
    store: MemRecords,
    kek: TestKek,
    ring: OneKey,
    buckets: Vec<String>,
    keys: Vec<MovedKey>,
    rng: TestRng,
}

impl FrozenKeys {
    async fn new() -> Self {
        let mut fixture = Self {
            store: MemRecords::new(),
            kek: kek(),
            ring: OneKey(tenant_key()),
            buckets: vec!["b_01".into(), "b_02".into()],
            keys: Vec::new(),
            rng: TestRng::default(),
        };
        let initial = fixture.seal_principal(1, PRINCIPAL);
        assert_eq!(
            key_chain(fixture.ring.0.tenant())
                .put(&fixture.store, 1, initial)
                .await
                .unwrap(),
            Put::Written
        );

        use SubjectKind::{AppPassword, S3};
        use SubjectStatus::{Active, Disabled, Revoked};
        for (id, kind, status, bucket, access) in [
            ("AKVL0001", S3, Active, 0, Access::Rw),
            ("AKVL0002", AppPassword, Active, 1, Access::Ro),
            ("AKVL0003", S3, Disabled, 0, Access::Ro),
            ("AKVL0004", S3, Revoked, 0, Access::Rw),
        ] {
            let (kek_version, secret_wrapped_v1) =
                wrap_secret(&fixture.kek, id, &derived(id), &mut fixture.rng).unwrap();
            fixture.keys.push(MovedKey {
                access_key_id: id.into(),
                kind,
                status,
                secret_wrapped_v1,
                kek_version,
                grants: vec![(fixture.buckets[bucket].clone(), access)],
                created_at: 2,
            });
        }
        fixture
    }

    fn seal_principal(&mut self, seq: u64, id: &str) -> Vec<u8> {
        seal_key_record(
            &self.kek,
            &self.ring,
            self.ring.0.tenant(),
            seq,
            KeyOp::Create,
            AT,
            &SubjectDoor {
                id: id.into(),
                kind: SubjectKind::Principal,
                status: SubjectStatus::Active,
                made_by: None,
                grants: Vec::new(),
                created_at: 1,
                secret_kek_version: None,
            },
            Some(&SubjectPrivate {
                owner_ref: Some(OWNER.into()),
                label: None,
                grants: Vec::new(),
                secret_wrapped: None,
            }),
            false,
            &mut self.rng,
        )
        .unwrap()
    }

    async fn write(&mut self, principal: &str) -> Result<MovedKeys> {
        write_moved_keys(
            &self.store,
            &self.kek,
            &self.ring,
            self.ring.0.tenant(),
            principal,
            OWNER,
            &self.buckets,
            &self.keys,
            AT,
            &mut self.rng,
        )
        .await
    }
}

fn assert_grants(entry: &Entry, expected: impl IntoIterator<Item = (String, Access)>) {
    let expected: Vec<_> = expected
        .into_iter()
        .map(|(bucket_id, access)| Grant {
            bucket_id,
            access,
            expires_at: None,
            prefix: None,
            ip_list: Vec::new(),
        })
        .collect();
    assert_eq!(entry.subject().unwrap().grants(), expected);
}

#[tokio::test(flavor = "current_thread")]
async fn moving_frozen_keys_preserves_grants_statuses_and_secrets() {
    let mut fixture = FrozenKeys::new().await;
    let report = fixture.write(PRINCIPAL).await.unwrap();
    let tenant = fixture.ring.0.tenant();
    let read = read_key_chain(&fixture.store, &fixture.kek, &fixture.ring, tenant)
        .await
        .unwrap();
    assert_grants(
        read.table.get(PRINCIPAL).unwrap(),
        fixture
            .buckets
            .iter()
            .cloned()
            .map(|bucket| (bucket, Access::Rw)),
    );
    for key in &fixture.keys {
        let id = &key.access_key_id;
        let entry = read.table.get(id).unwrap();
        assert_eq!(entry.door.made_by.as_deref(), Some(PRINCIPAL));
        assert_eq!(entry.door.kind, key.kind);
        assert_eq!(entry.door.status, key.status);
        assert_grants(entry, key.grants.clone());
        let wrapped = entry
            .private
            .as_ref()
            .unwrap()
            .secret_wrapped
            .as_deref()
            .unwrap();
        let secret = unwrap_secret_v2(
            &fixture.kek,
            entry.door.secret_kek_version.unwrap(),
            tenant,
            id,
            wrapped,
        )
        .unwrap();
        assert_eq!(secret.as_slice(), derived(id));
    }

    let name = tenant_revocation_name(tenant, "AKVL0004");
    assert_eq!(name, format!("m/rk/{TENANT}/AKVL0004"));
    assert!(fixture.store.exists(&name).await.unwrap());
    assert_eq!(report.revoked, ["AKVL0004"]);
}

#[tokio::test(flavor = "current_thread")]
async fn repeating_a_key_move_leaves_the_chain_head_unchanged() {
    let mut fixture = FrozenKeys::new().await;
    assert!(!fixture.write(PRINCIPAL).await.unwrap().written.is_empty());
    let chain = key_chain(fixture.ring.0.tenant());
    let head = chain.head(&fixture.store, 0).await.unwrap();

    let report = fixture.write(PRINCIPAL).await.unwrap();
    assert!(report.written.is_empty());
    assert_eq!(
        report.present,
        ["AKVL0001", "AKVL0002", "AKVL0003", "AKVL0004"]
    );
    assert_eq!(chain.head(&fixture.store, 0).await.unwrap(), head);
}

#[tokio::test(flavor = "current_thread")]
async fn repeating_a_key_move_with_changed_grants_reports_a_conflict() {
    let mut fixture = FrozenKeys::new().await;
    fixture.write(PRINCIPAL).await.unwrap();
    fixture.keys[0].grants[0].1 = Access::Ro;
    assert_invalid(
        fixture.write(PRINCIPAL).await.unwrap_err(),
        "the target holds something else under this name",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn moving_keys_rejects_an_unmoved_bucket_unsupported_kinds_and_a_missing_principal() {
    let mut fixture = FrozenKeys::new().await;
    let expected = "move input is not valid";
    assert_invalid(fixture.write("PR9999").await.unwrap_err(), expected);

    let original = fixture.keys[0].clone();
    fixture.keys[0].grants[0].0 = "b_03".into();
    assert_invalid(fixture.write(PRINCIPAL).await.unwrap_err(), expected);

    fixture.keys[0] = original;
    for kind in [SubjectKind::Principal, SubjectKind::Internal] {
        fixture.keys[0].kind = kind;
        assert_invalid(fixture.write(PRINCIPAL).await.unwrap_err(), expected);
    }
}

struct RacingRecords<'a> {
    store: &'a MemRecords,
    contested_name: String,
    competing_record: RefCell<Option<Vec<u8>>>,
}

impl RecordStore for RacingRecords<'_> {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        let competing = (name == self.contested_name)
            .then(|| self.competing_record.take())
            .flatten();
        if let Some(competing) = competing {
            self.store.plant(name, competing);
        }
        self.store.put_if_absent(name, bytes).await
    }

    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.store.get(name).await
    }

    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.store.list(prefix, start_after, limit).await
    }
}

#[tokio::test(flavor = "current_thread")]
async fn moving_keys_stops_when_another_writer_takes_the_next_sequence() {
    let mut fixture = FrozenKeys::new().await;
    let competing = fixture.seal_principal(2, "PR0002");
    let tenant = fixture.ring.0.tenant();
    let store = RacingRecords {
        store: &fixture.store,
        contested_name: key_chain(tenant).name(2),
        competing_record: RefCell::new(Some(competing)),
    };
    assert_invalid(
        write_moved_keys(
            &store,
            &fixture.kek,
            &fixture.ring,
            tenant,
            PRINCIPAL,
            OWNER,
            &fixture.buckets,
            &fixture.keys,
            AT,
            &mut fixture.rng,
        )
        .await
        .unwrap_err(),
        "the key chain moved under the move",
    );
    let read = read_key_chain(&store, &fixture.kek, &fixture.ring, tenant)
        .await
        .unwrap();
    assert_eq!(read.table.seq(), 2);
    assert_eq!(
        read.table.get("PR0002").unwrap().door.kind,
        SubjectKind::Principal
    );
}

async fn put_blob(store: &MemBlobStore, name: &str, row: &ExtentRow, bytes: &[u8]) {
    let digest = Sha256::digest(bytes).into();
    let meta = BlobMeta {
        bucket: &row.bucket_id,
        extent: &row.id,
        cipher_sha256: &digest,
    };
    store.put(name, bytes.to_vec(), &meta).await.unwrap();
}

async fn rehome_extent(
    store: &MemBlobStore,
    tenant: &TenantId,
    row: &ExtentRow,
) -> Result<Rehomed> {
    rehome_blob(
        store,
        &row.id.safety_key(),
        &tenant_safety_key(tenant, &row.id),
        &row.bucket_id,
        &row.id,
        &row.cipher_sha256,
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn rehoming_a_blob_preserves_the_source_and_checks_both_digests() {
    let records = Records::new();
    let tenant = records.tk.tenant();
    let row = &records.extents[0];
    let bytes = &records.ciphertext;
    let from = row.id.safety_key();
    let to = tenant_safety_key(tenant, &row.id);
    let store = MemBlobStore::new();
    put_blob(&store, &from, row, bytes).await;
    assert_eq!(
        rehome_extent(&store, tenant, row).await.unwrap(),
        Rehomed::Copied
    );
    assert_eq!(
        store.get(&to, None).await.unwrap().as_deref(),
        Some(bytes.as_slice())
    );
    assert_eq!(
        store.get(&from, None).await.unwrap().as_deref(),
        Some(bytes.as_slice())
    );
    assert_eq!(
        rehome_extent(&store, tenant, row).await.unwrap(),
        Rehomed::Present
    );

    let store = MemBlobStore::new();
    assert_eq!(
        rehome_extent(&store, tenant, row).await.unwrap(),
        Rehomed::Missing
    );
    put_blob(&store, &from, row, b"wrong source").await;
    let expected = "a copy does not match its catalogued digest";
    assert_invalid(
        rehome_extent(&store, tenant, row).await.unwrap_err(),
        expected,
    );
    assert!(store.get(&to, None).await.unwrap().is_none());

    let store = MemBlobStore::new();
    put_blob(&store, &from, row, bytes).await;
    put_blob(&store, &to, row, b"wrong target").await;
    assert_invalid(
        rehome_extent(&store, tenant, row).await.unwrap_err(),
        expected,
    );
    assert_eq!(
        store.get(&to, None).await.unwrap().as_deref(),
        Some(&b"wrong target"[..])
    );
}

#[tokio::test(flavor = "current_thread")]
async fn verifying_held_extents_reports_missing_and_corrupt_tenant_copies() {
    let tk = tenant_key();
    let tenant = tk.tenant();
    let bdk = DataKey::from_bytes(derived("bdk"));
    let bucket = BucketId::mint([1; 8]);
    let mut rng = TestRng::default();
    let store = MemBlobStore::new();
    let mut held = Vec::new();

    for n in 1..=3 {
        let (row, bytes) = extent(&bdk, &bucket, n, &mut rng);
        put_blob(&store, &row.id.safety_key(), &row, &bytes).await;
        if n <= 2 {
            assert_eq!(
                rehome_extent(&store, tenant, &row).await.unwrap(),
                Rehomed::Copied
            );
        }
        held.push((row.id, row.cipher_sha256));
    }

    assert_eq!(
        verify_held(&store, tenant, &held).await.unwrap(),
        [held[2].0.clone()]
    );
    assert!(
        store.corrupt(&tenant_safety_key(tenant, &held[0].0), |bytes| bytes[0] ^=
            1)
    );
    assert_eq!(
        verify_held(&store, tenant, &held).await.unwrap(),
        [held[0].0.clone(), held[2].0.clone()],
    );
}

#[test]
fn tenant_blob_keys_include_the_tenant_and_extent_ids() {
    let tk = tenant_key();
    let id = ExtentId::mint([1; 13]);
    assert_eq!(
        tenant_safety_key(tk.tenant(), &id),
        format!("x/{TENANT}/{}", id.as_str())
    );
    assert_eq!(
        tenant_cache_key(tk.tenant(), &id),
        format!("c/{TENANT}/{}", id.as_str())
    );
}

/// A bucket is re-wrapped once: a resumed run that passes the stored
/// wrap re-seals the same plaintext; a fresh wrap would not; a wrap of
/// another bucket key is refused.
#[tokio::test(flavor = "current_thread")]
async fn a_resumed_move_reuses_the_stored_bucket_wrap() {
    let mut records = Records::new();
    let store = MemRecords::new();
    let first = records.reseal();
    assert_eq!(
        put_sealed(&store, &RefRing(&records.tk), records.tk.tenant(), &first)
            .await
            .unwrap(),
        Placed::Written
    );
    let stored = records.moved.bdk_wrapped.clone();
    let again = moved_bucket(
        &kek(),
        &records.tk,
        &records.original,
        PRINCIPAL,
        Some(&stored),
        &mut records.rng,
    )
    .unwrap();
    assert_eq!(again.bdk_wrapped, stored);
    records.moved = again;
    let resumed = records.reseal();
    assert_eq!(
        put_sealed(&store, &RefRing(&records.tk), records.tk.tenant(), &resumed)
            .await
            .unwrap(),
        Placed::Same
    );
    // A fresh wrap holds the same key, but the record differs.
    records.moved = moved_bucket(
        &kek(),
        &records.tk,
        &records.original,
        PRINCIPAL,
        None,
        &mut records.rng,
    )
    .unwrap();
    assert_ne!(records.moved.bdk_wrapped, stored);
    let fresh = records.reseal();
    assert!(
        put_sealed(&store, &RefRing(&records.tk), records.tk.tenant(), &fresh)
            .await
            .is_err()
    );
    // A stored wrap of another bucket key is refused.
    let other = bucket_v1(
        &kek(),
        1,
        &DataKey::from_bytes(derived("another bdk")),
        &mut records.rng,
    );
    let other_moved = moved_bucket(
        &kek(),
        &records.tk,
        &other,
        PRINCIPAL,
        None,
        &mut records.rng,
    )
    .unwrap();
    assert_invalid(
        moved_bucket(
            &kek(),
            &records.tk,
            &records.original,
            PRINCIPAL,
            Some(&other_moved.bdk_wrapped),
            &mut records.rng,
        )
        .unwrap_err(),
        "the target holds something else under this name",
    );
}

/// A record sealed before a tenant-key rotation is compared under the
/// version its envelope names.
#[tokio::test(flavor = "current_thread")]
async fn a_record_sealed_before_a_key_rotation_compares_as_the_same() {
    struct Two<'a>(&'a TenantKey, &'a TenantKey);
    impl velmora_bridge::keys::record::TkRing for Two<'_> {
        fn current(&self) -> Option<&TenantKey> {
            Some(self.1)
        }
        fn key(&self, v: u32) -> Option<&TenantKey> {
            [self.0, self.1].into_iter().find(|k| k.version() == v)
        }
    }
    let mut records = Records::new();
    let store = MemRecords::new();
    let old = records.tombstone();
    put_sealed(&store, &RefRing(&records.tk), records.tk.tenant(), &old)
        .await
        .unwrap();
    let tenant = records.tk.tenant().clone();
    let v2 = TenantKey::from_bytes(&tenant, 2, derived("tk v2")).unwrap();
    let tombstone = Tombstone {
        v: 1,
        id: "g_deleted".into(),
        bucket_id: records.moved.id.as_str().into(),
        key: "deleted-object".into(),
        deleted_at: 2,
    };
    let new = reseal_tombstone(&v2, &tombstone, &mut records.rng).unwrap();
    assert_eq!(new.plain, old.plain);
    assert_eq!(
        put_sealed(&store, &Two(&records.tk, &v2), &tenant, &new)
            .await
            .unwrap(),
        Placed::Same
    );
    assert!(put_sealed(&store, &RefRing(&v2), &tenant, &new)
        .await
        .is_err());
}

/// A resumed key move refuses a key whose owner differs.
#[tokio::test(flavor = "current_thread")]
async fn repeating_a_key_move_for_another_owner_reports_a_conflict() {
    let mut fixture = FrozenKeys::new().await;
    fixture.write(PRINCIPAL).await.unwrap();
    assert_invalid(
        write_moved_keys(
            &fixture.store,
            &fixture.kek,
            &fixture.ring,
            fixture.ring.0.tenant(),
            PRINCIPAL,
            "another-member",
            &fixture.buckets,
            &fixture.keys,
            AT,
            &mut fixture.rng,
        )
        .await
        .unwrap_err(),
        "the target holds something else under this name",
    );
}

/// A bad key anywhere in the input stops the move before any record.
#[tokio::test(flavor = "current_thread")]
async fn a_bad_last_key_writes_nothing() {
    let mut fixture = FrozenKeys::new().await;
    fixture.keys[3].grants[0].0 = "b_09".into();
    assert_invalid(
        fixture.write(PRINCIPAL).await.unwrap_err(),
        "move input is not valid",
    );
    let chain = key_chain(fixture.ring.0.tenant());
    assert_eq!(chain.head(&fixture.store, 0).await.unwrap(), 1);
}

/// A revoked key's revocation is written before its create record.
#[tokio::test(flavor = "current_thread")]
async fn a_revoked_key_is_revoked_before_it_is_created() {
    let mut fixture = FrozenKeys::new().await;
    let all = std::mem::take(&mut fixture.keys);
    fixture.write(PRINCIPAL).await.unwrap();
    fixture.keys = vec![all[3].clone()];
    let tenant = fixture.ring.0.tenant().clone();
    fixture.store.refuse(key_chain(&tenant).prefix());
    assert!(fixture.write(PRINCIPAL).await.is_err());
    assert!(fixture
        .store
        .raw(&tenant_revocation_name(&tenant, "AKVL0004"))
        .is_some());
}
