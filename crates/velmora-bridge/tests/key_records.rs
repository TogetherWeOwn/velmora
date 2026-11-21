use std::cell::Cell;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::{wrap_secret_v2, TenantId, TenantKey};
use velmora_bridge::keys::chain::Put;
use velmora_bridge::keys::checkpoint::{
    checkpoint_name, open_checkpoint, read_key_chain, seal_checkpoint,
};
use velmora_bridge::keys::record::{
    grant_within, grants_narrow, key_chain, open_key_record, seal_key_record, Access, Entry, Grant,
    KeyOp, KeyRecord, KeyTable, NoKeys, OneKey, PrivateGrant, Subject, SubjectDoor, SubjectKind,
    SubjectPrivate, SubjectStatus,
};
use velmora_bridge::keys::revocations::{
    list_tenant_revocations, list_tenant_zero_revocations, put_tenant_revocation,
    read_tenant_revocation, tenant_revocation_name, tenant_revocation_prefix,
};
use velmora_bridge::keys::routes::{put_route, read_route, route_name, Route, RoutePut};
use velmora_bridge::keys::store::{MemRecords, RecordStore};
use velmora_bridge::ports::{BlobMeta, BlobStore};
use velmora_bridge::recovery::Unpublished;
use velmora_bridge::testkit::{MemBlobStore, TestKek};
use velmora_bridge::{BridgeError, BucketId, ByteSpan, ExtentId, Result};

const PRINCIPAL: &str = "PR0001";
const KEY: &str = "AKVL0001";

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
    TestKek::with_versions(1, &[(1, derived("key records kek"))])
}

fn tenant(n: u8) -> TenantId {
    TenantId::parse(&format!("t_00000000000000{n:02x}")).unwrap()
}

fn ring(n: u8, v: u32, label: &str) -> OneKey {
    OneKey(TenantKey::from_bytes(&tenant(n), v, derived(label)).unwrap())
}

fn grant() -> Grant {
    Grant {
        bucket_id: "b_01".into(),
        access: Access::Rw,
        expires_at: None,
        prefix: None,
        ip_list: vec![],
    }
}

fn principal(id: &str, grants: &[Grant]) -> Subject {
    let mut subject = Subject {
        door: SubjectDoor {
            id: id.into(),
            kind: SubjectKind::Principal,
            status: SubjectStatus::Active,
            made_by: None,
            grants: vec![],
            created_at: 10,
            secret_kek_version: None,
        },
        private: SubjectPrivate {
            owner_ref: Some(format!("owner-of-{id}")),
            label: Some(format!("label-for-{id}")),
            grants: vec![],
            secret_wrapped: None,
        },
    };
    subject.set_grants(grants);
    subject
}

fn s3_key(id: &str, made_by: &str, grants: &[Grant], kek: &TestKek, tenant: &TenantId) -> Subject {
    let mut rng = TestRng::new(&format!("secret wrap {tenant}/{id}"));
    let (version, wrapped) = wrap_secret_v2(
        kek,
        tenant,
        id,
        format!("secret-of-{id}").as_bytes(),
        &mut rng,
    )
    .unwrap();
    let mut subject = principal(id, grants);
    subject.door.kind = SubjectKind::S3;
    subject.door.made_by = Some(made_by.into());
    subject.door.secret_kek_version = Some(version);
    subject.private.secret_wrapped = Some(wrapped);
    subject
}

fn seal(
    kek: &TestKek,
    ring: &OneKey,
    t: &TenantId,
    seq: u64,
    op: KeyOp,
    subject: &Subject,
) -> Vec<u8> {
    let mut rng = TestRng::new(&format!("record {t}/{seq}/{}", ring.0.version()));
    seal_key_record(
        kek,
        ring,
        t,
        seq,
        op,
        10 + seq,
        &subject.door,
        Some(&subject.private),
        // Closing statuses are classed closing, as the writer does.
        op == KeyOp::Status && subject.door.status != SubjectStatus::Active,
        &mut rng,
    )
    .unwrap()
}

async fn write(
    store: &MemRecords,
    kek: &TestKek,
    ring: &OneKey,
    t: &TenantId,
    seq: u64,
    op: KeyOp,
    subject: &Subject,
) -> Vec<u8> {
    let bytes = seal(kek, ring, t, seq, op, subject);
    assert_eq!(
        key_chain(t).put(store, seq, bytes.clone()).await.unwrap(),
        Put::Written
    );
    bytes
}

#[tokio::test(flavor = "current_thread")]
async fn chain_head_starts_at_zero_and_advances_from_known_seq() {
    let store = MemRecords::new();
    let chain = key_chain(&tenant(1));
    assert_eq!(chain.head(&store, 0).await.unwrap(), 0);
    for seq in 1..=3 {
        assert_eq!(
            chain.put(&store, seq, vec![seq as u8]).await.unwrap(),
            Put::Written
        );
    }
    assert_eq!(chain.head(&store, 0).await.unwrap(), 3);
    assert_eq!(chain.head(&store, 2).await.unwrap(), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn chain_head_refuses_a_gap() {
    let store = MemRecords::new();
    let chain = key_chain(&tenant(1));
    assert_eq!(chain.put(&store, 1, vec![1]).await.unwrap(), Put::Written);
    store.plant(&chain.name(3), vec![3]);
    assert!(matches!(
        chain.head(&store, 0).await,
        Err(BridgeError::Invalid("record chain has a gap"))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn chain_head_refuses_a_foreign_name() {
    let store = MemRecords::new();
    let chain = key_chain(&tenant(1));
    store.plant(&format!("{}zzz", chain.prefix()), vec![1]);
    assert!(matches!(
        chain.head(&store, 0).await,
        Err(BridgeError::Invalid("record chain has a gap"))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn chain_head_refuses_a_known_seq_ahead_of_the_chain() {
    let store = MemRecords::new();
    let chain = key_chain(&tenant(1));
    assert_eq!(chain.put(&store, 1, vec![1]).await.unwrap(), Put::Written);
    assert!(matches!(
        chain.head(&store, 2).await,
        Err(BridgeError::Invalid("record chain is behind the known seq"))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn chain_head_reads_two_list_pages() {
    let store = MemRecords::new();
    let chain = key_chain(&tenant(1));
    for seq in 1..=1005 {
        store.plant(&chain.name(seq), vec![seq as u8]);
    }
    let before = store.lists();
    assert_eq!(chain.head(&store, 0).await.unwrap(), 1005);
    assert_eq!(store.lists() - before, 2);
}

#[tokio::test(flavor = "current_thread")]
async fn chain_put_distinguishes_collisions_retries_and_refusals() {
    let store = MemRecords::new();
    let chain = key_chain(&tenant(1));
    assert_eq!(chain.put(&store, 1, vec![1]).await.unwrap(), Put::Written);
    assert_eq!(chain.put(&store, 1, vec![9]).await.unwrap(), Put::Lost);
    assert_eq!(chain.put(&store, 1, vec![1]).await.unwrap(), Put::Written);
    store.lose_answers(1);
    assert_eq!(chain.put(&store, 2, vec![2]).await.unwrap(), Put::Written);
    assert_eq!(store.raw(&chain.name(2)), Some(vec![2]));
    store.refuse(chain.prefix());
    assert!(chain.put(&store, 3, vec![3]).await.is_err());
    assert_eq!(store.raw(&chain.name(3)), None);
}

#[test]
fn principal_record_round_trips_and_opens_door_without_tenant_key() {
    let (kek, t, ring) = (kek(), tenant(1), ring(1, 1, "tk1"));
    let subject = principal(
        PRINCIPAL,
        &[Grant {
            prefix: Some("a/".into()),
            ip_list: vec!["1.1.1.1".into()],
            ..grant()
        }],
    );
    let bytes = seal(&kek, &ring, &t, 1, KeyOp::Create, &subject);
    let opened = open_key_record(&kek, &ring, &t, 1, &bytes).unwrap();
    assert_eq!(
        opened,
        KeyRecord {
            seq: 1,
            op: KeyOp::Create,
            at: 11,
            door: subject.door.clone(),
            private: Some(subject.private),
            tk_version: 1,
            closes: false,
            private_unchanged: false,
        }
    );
    let closed = open_key_record(&kek, &NoKeys, &t, 1, &bytes).unwrap();
    assert_eq!(
        closed,
        KeyRecord {
            private: None,
            ..opened
        }
    );
}

#[test]
fn key_record_is_bound_to_its_seq_and_tenant() {
    let (kek, t, key) = (kek(), tenant(1), ring(1, 1, "tk1"));
    let bytes = seal(
        &kek,
        &key,
        &t,
        1,
        KeyOp::Create,
        &principal(PRINCIPAL, &[grant()]),
    );
    assert!(open_key_record(&kek, &key, &t, 2, &bytes).is_err());
    assert!(open_key_record(&kek, &ring(2, 1, "tk2"), &tenant(2), 1, &bytes).is_err());
}

fn fold(table: &mut KeyTable, op: KeyOp, subject: &Subject) {
    table
        .apply(&KeyRecord {
            seq: table.seq() + 1,
            op,
            at: 10 + table.seq() + 1,
            door: subject.door.clone(),
            private: Some(subject.private.clone()),
            tk_version: 1,
            closes: false,
            private_unchanged: false,
        })
        .unwrap();
}

#[test]
fn key_table_folds_valid_changes_and_refuses_invalid_transitions() {
    let (kek, t) = (kek(), tenant(1));
    let grants = [grant()];
    let parent = principal(PRINCIPAL, &grants);
    let active = s3_key(KEY, PRINCIPAL, &grants, &kek, &t);
    let mut disabled = active.clone();
    disabled.door.status = SubjectStatus::Disabled;
    let mut narrowed = active.clone();
    narrowed.set_grants(&[Grant {
        access: Access::Ro,
        ..grant()
    }]);
    let mut revoked = narrowed.clone();
    revoked.door.status = SubjectStatus::Revoked;

    let mut table = KeyTable::empty(t.clone());
    fold(&mut table, KeyOp::Create, &parent);
    fold(&mut table, KeyOp::Create, &active);
    fold(&mut table, KeyOp::Status, &disabled);
    fold(&mut table, KeyOp::Status, &active);
    fold(&mut table, KeyOp::Grants, &narrowed);
    let before_revocation = table.clone();
    fold(&mut table, KeyOp::Status, &revoked);
    assert_eq!(table.seq(), 6);
    let entry = table.get(KEY).unwrap();
    assert_eq!(entry.door.status, SubjectStatus::Revoked);
    assert_eq!(entry.last_seq, 6);

    let mut restore = revoked.clone();
    restore.door.status = SubjectStatus::Active;
    let mut change_revoked_grants = revoked.clone();
    change_revoked_grants.set_grants(&[]);
    let mut disabled_create = s3_key("AKVL0002", PRINCIPAL, &grants, &kek, &t);
    disabled_create.door.status = SubjectStatus::Disabled;
    let mut mixed = active.clone();
    mixed.door.status = SubjectStatus::Disabled;
    let mut restate = narrowed.clone();
    restate.private.label = Some("changed".into());

    for (case, at, op, subject) in [
        ("reactivate revoked key", &table, KeyOp::Status, restore),
        (
            "change revoked grants",
            &table,
            KeyOp::Grants,
            change_revoked_grants,
        ),
        ("restate revoked key", &table, KeyOp::Restate, revoked),
        ("duplicate id", &table, KeyOp::Create, parent),
        (
            "unknown parent",
            &table,
            KeyOp::Create,
            s3_key("AKVL0002", "UNKNOWN", &grants, &kek, &t),
        ),
        (
            "non-principal parent",
            &before_revocation,
            KeyOp::Create,
            s3_key("AKVL0002", KEY, &grants, &kek, &t),
        ),
        ("disabled create", &table, KeyOp::Create, disabled_create),
        (
            "status changes grants",
            &before_revocation,
            KeyOp::Status,
            mixed.clone(),
        ),
        (
            "grants change status",
            &before_revocation,
            KeyOp::Grants,
            mixed,
        ),
        (
            "restate changes label",
            &before_revocation,
            KeyOp::Restate,
            restate,
        ),
    ] {
        assert!(
            at.admits(op, &subject.door, Some(&subject.private))
                .is_err(),
            "{case}"
        );
    }
}

#[test]
fn effective_status_closes_unreadable_subjects_and_preserves_revocation() {
    let mut entry = Entry {
        door: principal(PRINCIPAL, &[grant()]).door,
        private: None,
        last_seq: 1,
        private_seq: 1,
        tk_version: 1,
        closes: false,
    };
    assert_eq!(entry.effective_status(), SubjectStatus::Disabled);
    entry.door.status = SubjectStatus::Revoked;
    assert_eq!(entry.effective_status(), SubjectStatus::Revoked);
}

#[test]
fn revocation_override_marks_known_ids_and_reports_unknown_ids() {
    let mut table = KeyTable::empty(tenant(1));
    fold(&mut table, KeyOp::Create, &principal(PRINCIPAL, &[grant()]));
    assert!(table.override_revoked(PRINCIPAL));
    assert_eq!(
        table.get(PRINCIPAL).unwrap().door.status,
        SubjectStatus::Revoked
    );
    assert!(!table.override_revoked("UNKNOWN"));
    assert_eq!(table.seq(), 1);
}

#[test]
fn grant_narrowing_checks_bucket_access_prefix_expiry_and_ips() {
    let base = grant();
    let read_only = Grant {
        access: Access::Ro,
        ..grant()
    };
    let prefix = Grant {
        prefix: Some("a/".into()),
        ..grant()
    };
    let subprefix = Grant {
        prefix: Some("a/b".into()),
        ..grant()
    };
    let early = Grant {
        expires_at: Some(10),
        ..grant()
    };
    let late = Grant {
        expires_at: Some(20),
        ..grant()
    };
    let one_ip = Grant {
        ip_list: vec!["1.1.1.1".into()],
        ..grant()
    };
    let two_ips = Grant {
        ip_list: vec!["1.1.1.1".into(), "2.2.2.2".into()],
        ..grant()
    };
    let other = Grant {
        bucket_id: "b_02".into(),
        ..grant()
    };

    for (case, inner, outer, expected) in [
        ("lower access", &read_only, &base, true),
        ("higher access", &base, &read_only, false),
        ("subprefix", &subprefix, &prefix, true),
        ("whole bucket", &base, &prefix, false),
        ("earlier expiry", &early, &late, true),
        ("missing expiry", &base, &late, false),
        ("expiry inside unbounded grant", &late, &base, true),
        ("both expiries unbounded", &base, &base, true),
        ("fewer IPs", &one_ip, &two_ips, true),
        ("any IP inside restricted grant", &base, &one_ip, false),
        (
            "restricted IP inside unrestricted grant",
            &two_ips,
            &base,
            true,
        ),
        ("different bucket", &other, &base, false),
    ] {
        assert_eq!(grant_within(inner, outer), expected, "{case}");
    }

    let both = [base.clone(), other];
    assert!(!grants_narrow(&both, std::slice::from_ref(&base)));
    assert!(grants_narrow(&[base], &both));
}

struct CheckpointFixture {
    store: MemRecords,
    kek: TestKek,
    ring: OneKey,
    tenant: TenantId,
    at_512: KeyTable,
    table: KeyTable,
}

impl CheckpointFixture {
    async fn new() -> Self {
        let (store, kek, ring, tenant) = (MemRecords::new(), kek(), ring(1, 1, "tk1"), tenant(1));
        let grants = [grant()];
        let mut table = KeyTable::empty(tenant.clone());
        let mut subject = principal(PRINCIPAL, &grants);
        let mut rng = TestRng::new("checkpoint fixture");
        let mut at_512 = None;
        for seq in 1_u64..=600 {
            let op = if seq == 1 {
                KeyOp::Create
            } else if seq == 2 {
                // The first key must exist before its first status change.
                subject = s3_key(KEY, PRINCIPAL, &grants, &kek, &tenant);
                KeyOp::Create
            } else if seq % 2 == 1 {
                let id = format!("AKVL{:04}", seq.div_ceil(2));
                subject = s3_key(&id, PRINCIPAL, &grants, &kek, &tenant);
                KeyOp::Create
            } else {
                subject.door.status = SubjectStatus::Disabled;
                KeyOp::Status
            };
            table
                .admits(op, &subject.door, Some(&subject.private))
                .unwrap();
            let record = write(&store, &kek, &ring, &tenant, seq, op, &subject).await;
            table
                .apply(&open_key_record(&kek, &ring, &tenant, seq, &record).unwrap())
                .unwrap();
            if matches!(seq, 256 | 512) {
                let checkpoint = seal_checkpoint(&kek, &ring, &table, &record, &mut rng).unwrap();
                assert!(store
                    .put_if_absent(&checkpoint_name(&tenant, seq), checkpoint)
                    .await
                    .unwrap());
                if seq == 512 {
                    at_512 = Some(table.clone());
                }
            }
        }
        Self {
            store,
            kek,
            ring,
            tenant,
            at_512: at_512.unwrap(),
            table,
        }
    }

    fn replace_latest(&self, ring: &OneKey, record_seq: u64) {
        let record = self
            .store
            .raw(&key_chain(&self.tenant).name(record_seq))
            .unwrap();
        let mut rng = TestRng::new("replacement checkpoint");
        let bytes = seal_checkpoint(&self.kek, ring, &self.at_512, &record, &mut rng).unwrap();
        self.store.plant(&checkpoint_name(&self.tenant, 512), bytes);
    }

    async fn assert_latest_skipped(&self) {
        let read = read_key_chain(&self.store, &self.kek, &self.ring, &self.tenant)
            .await
            .unwrap();
        assert_eq!(read.from_checkpoint, Some(256));
        assert_eq!(read.skipped_checkpoints, vec![512]);
        assert_eq!(read.newest_checkpoint, Some(512));
        assert_eq!(read.table, self.table);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn newest_checkpoint_and_full_replay_match_the_local_fold() {
    let fixture = CheckpointFixture::new().await;
    let CheckpointFixture {
        store,
        kek,
        ring,
        tenant,
        table,
        ..
    } = fixture;
    let read = read_key_chain(&store, &kek, &ring, &tenant).await.unwrap();
    assert_eq!(read.from_checkpoint, Some(512));
    assert_eq!(read.newest_checkpoint, Some(512));
    assert!(read.skipped_checkpoints.is_empty());
    assert_eq!(read.table, table);

    let chain = key_chain(&tenant);
    let without_checkpoints = MemRecords::new();
    for name in store.names_under(chain.prefix()) {
        without_checkpoints.plant(&name, store.raw(&name).unwrap());
    }
    let replay = read_key_chain(&without_checkpoints, &kek, &ring, &tenant)
        .await
        .unwrap();
    assert_eq!(replay.from_checkpoint, None);
    assert_eq!(replay.table, table);
}

#[tokio::test(flavor = "current_thread")]
async fn checkpoint_with_unavailable_private_key_is_skipped() {
    let fixture = CheckpointFixture::new().await;
    fixture.replace_latest(&ring(1, 2, "other"), 512);
    fixture.assert_latest_skipped().await;
}

#[tokio::test(flavor = "current_thread")]
async fn checkpoint_bound_to_another_record_or_corrupted_is_skipped() {
    let fixture = CheckpointFixture::new().await;
    let name = checkpoint_name(&fixture.tenant, 512);
    let mut valid = fixture.store.raw(&name).unwrap();
    fixture.replace_latest(&fixture.ring, 511);
    fixture.assert_latest_skipped().await;

    *valid.last_mut().unwrap() ^= 1;
    fixture.store.plant(&name, valid);
    fixture.assert_latest_skipped().await;
}

#[tokio::test(flavor = "current_thread")]
async fn unreadable_newest_record_stays_closed_through_a_checkpoint() {
    let (store, kek, t, v1) = (MemRecords::new(), kek(), tenant(1), ring(1, 1, "tk1"));
    let grants = [grant()];
    let parent = principal(PRINCIPAL, &grants);
    let mut subject = s3_key(KEY, PRINCIPAL, &grants, &kek, &t);
    write(&store, &kek, &v1, &t, 1, KeyOp::Create, &parent).await;
    write(&store, &kek, &v1, &t, 2, KeyOp::Create, &subject).await;
    subject.set_grants(&[Grant {
        access: Access::Ro,
        ..grant()
    }]);
    write(&store, &kek, &v1, &t, 3, KeyOp::Grants, &subject).await;

    subject.door.status = SubjectStatus::Disabled;
    let v2 = ring(1, 2, "other");
    let newest = write(&store, &kek, &v2, &t, 4, KeyOp::Status, &subject).await;
    let table = read_key_chain(&store, &kek, &v1, &t).await.unwrap().table;
    assert_eq!(table.seq(), 4);
    let entry = table.get(KEY).unwrap();
    assert_eq!(entry.last_seq, 4);
    assert_eq!(entry.tk_version, 2);
    assert_eq!(entry.private, None);
    assert_eq!(entry.effective_status(), SubjectStatus::Disabled);

    // The checkpoint carries the subject closed, door fields only.
    let mut rng = TestRng::new("closed entry checkpoint");
    let closed_cp = seal_checkpoint(&kek, &v1, &table, &newest, &mut rng).unwrap();
    assert_eq!(
        open_checkpoint(&kek, &v1, &t, 4, &closed_cp, &newest),
        Some(table.clone())
    );
    // A reader with both versions that starts from that checkpoint opens
    // the subject again from its own record.
    store.plant(&checkpoint_name(&t, 4), closed_cp);
    // A reader with both versions opens it.
    struct Both(OneKey, OneKey);
    impl velmora_bridge::keys::record::TkRing for Both {
        fn current(&self) -> Option<&TenantKey> {
            self.1.current()
        }
        fn key(&self, v: u32) -> Option<&TenantKey> {
            self.0.key(v).or_else(|| self.1.key(v))
        }
    }
    let both = Both(v1, v2);
    let read = read_key_chain(&store, &kek, &both, &t).await.unwrap();
    assert_eq!(read.from_checkpoint, Some(4));
    let table = read.table;
    assert!(table.get(KEY).unwrap().private.is_some());
    assert_eq!(
        table.get(KEY).unwrap().effective_status(),
        SubjectStatus::Disabled
    );
    let checkpoint = seal_checkpoint(&kek, &both, &table, &newest, &mut rng).unwrap();
    assert_eq!(
        open_checkpoint(&kek, &both, &t, 4, &checkpoint, &newest),
        Some(table)
    );
}

/// LOW 1 of the review: a stray name below something that is no tenant
/// directory does not hide a tenant-0 revocation that sorts after it.
#[tokio::test(flavor = "current_thread")]
async fn a_stray_directory_does_not_hide_a_tenant_zero_revocation() {
    let store = CountingBlobStore::default();
    let bytes = vec![1];
    let meta = BlobMeta {
        bucket: &BucketId::mint([1; 8]),
        extent: &ExtentId::mint([2; 13]),
        cipher_sha256: &Sha256::digest(&bytes).into(),
    };
    for name in ["m/rk/AKID/x", "m/rk/AKID0", "m/rk/AKID00"] {
        store.put(name, bytes.clone(), &meta).await.unwrap();
    }
    assert_eq!(collect_tenant_zero(&store, 1000).await, ["AKID0", "AKID00"]);
    assert_eq!(collect_tenant_zero(&store, 1).await, ["AKID0", "AKID00"]);
}

/// LOW 2 of the review: a checkpoint whose private part names a subject
/// twice, or whose grants do not line up with its door part, is skipped.
#[tokio::test(flavor = "current_thread")]
async fn a_checkpoint_with_duplicate_or_misaligned_subjects_is_skipped() {
    use velmora_bridge::crypto::scheme2::{seal_control, ControlSealer};
    let fixture = CheckpointFixture::new().await;
    let t = &fixture.tenant;
    let record = fixture.store.raw(&key_chain(t).name(512)).unwrap();
    let sha: String = Sha256::digest(&record)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let entries: Vec<&Entry> = fixture.at_512.entries().collect();
    let door = serde_json::json!({
        "v": 1,
        "tenant": t.as_str(),
        "seq": 512,
        "record_sha256": sha,
        "subjects": entries.iter().map(|e| serde_json::json!({
            "door": e.door, "last_seq": e.last_seq, "private_seq": e.private_seq,
            "tk_version": e.tk_version, "closes": e.closes, "open": true
        })).collect::<Vec<_>>(),
    });
    let privates = |dup: bool, misalign: bool| {
        let mut list: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                let mut p = e.private.clone().unwrap();
                if misalign && e.door.id == PRINCIPAL {
                    p.grants.push(PrivateGrant {
                        bucket_id: "b_99".into(),
                        prefix: None,
                        ip_list: vec![],
                    });
                }
                serde_json::json!({ "id": e.door.id, "private": p })
            })
            .collect();
        if dup {
            list.push(list[0].clone());
        }
        serde_json::json!({ "v": 1, "subjects": list })
    };
    let name = checkpoint_name(t, 512);
    // A checkpoint that verifies but leaves the principal out: the records
    // after it, made under that principal, do not fold into it, so the
    // reader takes the one before.
    let without_principal = serde_json::json!({
        "v": 1,
        "tenant": t.as_str(),
        "seq": 512,
        "record_sha256": door["record_sha256"].clone(),
        "subjects": entries.iter().filter(|e| e.door.id != PRINCIPAL).map(|e| serde_json::json!({
            "door": e.door, "last_seq": e.last_seq, "private_seq": e.private_seq,
            "tk_version": e.tk_version, "closes": e.closes, "open": true
        })).collect::<Vec<_>>(),
    });
    let without_private = serde_json::json!({
        "v": 1,
        "subjects": entries.iter().filter(|e| e.door.id != PRINCIPAL).map(|e| serde_json::json!({
            "id": e.door.id, "private": e.private.clone().unwrap()
        })).collect::<Vec<_>>(),
    });
    let sealed = seal_control(
        &fixture.kek,
        &name,
        &ControlSealer::Managed(&fixture.ring.0),
        &serde_json::to_vec(&without_principal).unwrap(),
        Some(&serde_json::to_vec(&without_private).unwrap()),
        &mut TestRng::new("crafted checkpoint 2"),
    )
    .unwrap();
    fixture.store.plant(&name, sealed);
    let read = read_key_chain(&fixture.store, &fixture.kek, &fixture.ring, t)
        .await
        .unwrap();
    assert_eq!(read.from_checkpoint, Some(256));
    assert_eq!(read.skipped_checkpoints, vec![512]);
    assert_eq!(read.table, fixture.table);
    for (dup, misalign) in [(false, false), (true, false), (false, true)] {
        let sealed = seal_control(
            &fixture.kek,
            &name,
            &ControlSealer::Managed(&fixture.ring.0),
            &serde_json::to_vec(&door).unwrap(),
            Some(&serde_json::to_vec(&privates(dup, misalign)).unwrap()),
            &mut TestRng::new("crafted checkpoint"),
        )
        .unwrap();
        fixture.store.plant(&name, sealed);
        let read = read_key_chain(&fixture.store, &fixture.kek, &fixture.ring, t)
            .await
            .unwrap();
        // The well-formed control case shows the crafting is right.
        let expected = if dup || misalign {
            Some(256)
        } else {
            Some(512)
        };
        assert_eq!(
            read.from_checkpoint, expected,
            "dup {dup} misalign {misalign}"
        );
        assert_eq!(read.table, fixture.table);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn managed_revocations_preserve_the_first_put_and_are_tenant_scoped() {
    let (store, kek, t) = (MemRecords::new(), kek(), tenant(1));
    let mut rng = TestRng::new("managed revocations");
    for at in [100, 200] {
        put_tenant_revocation(&store, &kek, &t, KEY, at, &mut rng)
            .await
            .unwrap();
    }
    assert_eq!(store.names(), vec![tenant_revocation_name(&t, KEY)]);
    assert_eq!(
        read_tenant_revocation(&store, &kek, &t, KEY).await.unwrap(),
        Some(100)
    );
    let other = tenant(2);
    put_tenant_revocation(&store, &kek, &t, "AKVL0002", 300, &mut rng)
        .await
        .unwrap();
    put_tenant_revocation(&store, &kek, &other, "AKVL0003", 400, &mut rng)
        .await
        .unwrap();
    assert_eq!(store.names_under(&tenant_revocation_prefix(&t)).len(), 2);
    assert_eq!(
        list_tenant_revocations(&store, &t).await.unwrap(),
        [KEY, "AKVL0002"]
    );
    assert_eq!(
        list_tenant_revocations(&store, &other).await.unwrap(),
        ["AKVL0003"]
    );
}

#[derive(Default)]
struct CountingBlobStore {
    inner: MemBlobStore,
    lists: Cell<u32>,
}

impl BlobStore for CountingBlobStore {
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

async fn collect_tenant_zero(store: &CountingBlobStore, limit: u32) -> Vec<String> {
    let mut after = "m/rk/".to_owned();
    let mut all = Vec::new();
    loop {
        let (ids, next) = list_tenant_zero_revocations(store, &after, limit)
            .await
            .unwrap();
        assert!(ids.len() <= limit as usize);
        if let Some(cursor) = &next {
            assert!(cursor > &after);
            assert!(!ids.is_empty());
            assert_eq!(*cursor, format!("m/rk/{}", ids.last().unwrap()));
        }
        all.extend(ids);
        match next {
            Some(cursor) => after = cursor,
            None => return all,
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn tenant_zero_listing_skips_managed_directories_and_paginates() {
    let store = CountingBlobStore::default();
    let bytes = vec![1];
    let meta = BlobMeta {
        bucket: &BucketId::mint([1; 8]),
        extent: &ExtentId::mint([2; 13]),
        cipher_sha256: &Sha256::digest(&bytes).into(),
    };
    // Every managed directory starts with t_. Valid direct ids can flank
    // that entire range, since they cannot contain an underscore.
    let expected = [
        "0AKV1", "AKVL0000", "AKVL0001", "ZZZZ1", "t0AKV1", "taAKV1", "zAKV1",
    ];
    for n in 1..=50 {
        if let Some(id) = expected.get(usize::from(n - 1)) {
            store
                .put(&format!("m/rk/{id}"), bytes.clone(), &meta)
                .await
                .unwrap();
        }
        let t = tenant(n);
        for j in 0..100 {
            store
                .put(&format!("m/rk/{t}/AKVL{j:04}"), bytes.clone(), &meta)
                .await
                .unwrap();
        }
    }
    assert_eq!(collect_tenant_zero(&store, 1000).await, expected);
    assert!(store.lists.get() <= 60, "list calls: {}", store.lists.get());
    assert_eq!(collect_tenant_zero(&store, 2).await, expected);
}

#[tokio::test(flavor = "current_thread")]
async fn routes_are_put_once_and_bound_to_the_access_key_id() {
    let (store, kek, t) = (MemRecords::new(), kek(), tenant(1));
    let mut rng = TestRng::new("routes");
    for (owner, at, expected) in [
        (t.clone(), 100, RoutePut::Ours),
        (t.clone(), 200, RoutePut::Ours),
        (tenant(2), 300, RoutePut::Taken),
    ] {
        assert_eq!(
            put_route(&store, &kek, &owner, KEY, SubjectKind::S3, at, &mut rng)
                .await
                .unwrap(),
            expected
        );
    }
    assert_eq!(
        read_route(&store, &kek, KEY).await.unwrap(),
        Some(Route {
            access_key_id: KEY.into(),
            tenant: t.to_string(),
            kind: SubjectKind::S3,
            created_at: 100
        })
    );
    assert_eq!(read_route(&store, &kek, "UNKNOWN").await.unwrap(), None);
    assert!(put_route(
        &store,
        &kek,
        &t,
        PRINCIPAL,
        SubjectKind::Principal,
        100,
        &mut rng
    )
    .await
    .is_err());

    let bytes = store.raw(&route_name(KEY)).unwrap();
    store.plant(&route_name("OTHER"), bytes);
    assert!(read_route(&store, &kek, "OTHER").await.is_err());
}
