use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use serde_json::json;
use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::{
    seal_control, tk_blob_check_value, tk_blob_name, unwrap_tenant_key, wrap_tenant_key,
    ControlSealer, TenantId, TenantKey,
};
use velmora_bridge::keys::audit::{audit, repair_missing, Finding};
use velmora_bridge::keys::checkpoint::{
    checkpoint_name, open_checkpoint, read_key_chain, seal_checkpoint,
};
use velmora_bridge::keys::escrow::{restore_escrow, EscrowCopy, RestoreStep};
use velmora_bridge::keys::locations::{two_in_account, KeyLocation, KeyLocations, LocationStatus};
use velmora_bridge::keys::ports::{
    Admission, ControlChain, ControlIntents, KeyAdmission, KeyTarget, OpeningChange,
};
use velmora_bridge::keys::record::{
    key_chain, open_key_record, seal_key_record, Access, Entry, Grant, KeyOp, KeyRecord, KeyTable,
    OneKey, Subject, SubjectDoor, SubjectKind, SubjectPrivate, SubjectStatus, TkRing,
    KEY_RECORD_VERSION,
};
use velmora_bridge::keys::tk::{tk_prefix, KeyBuckets};
use velmora_bridge::keys::writer::{finish_keys, KeyEnv, Limits};
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::testkit::{FixedClock, TestKek};
use velmora_bridge::{BridgeError, Result, UnixMs};

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

struct TestRng(u64);

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(b"key writer");
            h.update(self.0.to_be_bytes());
            self.0 += 1;
            block.copy_from_slice(&h.finalize()[..block.len()]);
        }
        Ok(())
    }
}

fn tenant(n: u8) -> TenantId {
    TenantId::parse(&format!("t_00000000000000{n:02x}")).unwrap()
}

fn grant(bucket: &str, access: Access, prefix: Option<&str>) -> Grant {
    Grant {
        bucket_id: bucket.to_owned(),
        access,
        expires_at: None,
        prefix: prefix.map(str::to_owned),
        ip_list: Vec::new(),
    }
}

fn subject(id: &str, kind: SubjectKind, made_by: Option<&str>, grants: &[Grant]) -> Subject {
    let mut s = Subject {
        door: SubjectDoor {
            id: id.to_owned(),
            kind,
            status: SubjectStatus::Active,
            made_by: made_by.map(str::to_owned),
            grants: Vec::new(),
            created_at: 1_000,
            secret_kek_version: None,
        },
        private: SubjectPrivate {
            owner_ref: Some(format!("member-of-{id}")),
            label: None,
            grants: Vec::new(),
            secret_wrapped: None,
        },
    };
    s.set_grants(grants);
    s
}

fn principal(id: &str, grants: &[Grant]) -> Subject {
    subject(id, SubjectKind::Principal, None, grants)
}

struct Ring(Vec<TenantKey>);

impl TkRing for Ring {
    fn current(&self) -> Option<&TenantKey> {
        self.0.last()
    }
    fn key(&self, v: u32) -> Option<&TenantKey> {
        self.0.iter().find(|k| k.version() == v)
    }
}

const ID: &str = "PR0001";

fn key(tenant: &TenantId, version: u32, label: &str) -> TenantKey {
    TenantKey::from_bytes(tenant, version, derived(label)).unwrap()
}

fn kek(versions: &[u32]) -> TestKek {
    let keys: Vec<_> = versions
        .iter()
        .map(|&version| (version, Sha256::digest(version.to_be_bytes()).into()))
        .collect();
    TestKek::with_versions(*versions.last().unwrap(), &keys)
}

struct World {
    tenant: TenantId,
    store: MemRecords,
    kek: TestKek,
    ring: OneKey,
    rng: TestRng,
}

impl World {
    fn new() -> Self {
        let tenant = tenant(1);
        Self {
            ring: OneKey(key(&tenant, 1, "first tenant key")),
            tenant,
            store: MemRecords::new(),
            kek: kek(&[1]),
            rng: TestRng(0),
        }
    }

    fn record(&mut self, seq: u64, op: KeyOp, subject: &Subject, closes: bool) -> Vec<u8> {
        seal_key_record(
            &self.kek,
            &self.ring,
            &self.tenant,
            seq,
            op,
            10 + seq,
            &subject.door,
            Some(&subject.private),
            closes,
            &mut self.rng,
        )
        .unwrap()
    }

    fn plant_record(&mut self, seq: u64, op: KeyOp, subject: &Subject, closes: bool) -> Vec<u8> {
        let record = self.record(seq, op, subject, closes);
        self.store
            .plant(&key_chain(&self.tenant).name(seq), record.clone());
        record
    }

    async fn checkpoint(
        &mut self,
        seq: u64,
        read_with: &impl TkRing,
        seal_with: &impl TkRing,
        record: &[u8],
    ) {
        let read = read_key_chain(&self.store, &self.kek, read_with, &self.tenant)
            .await
            .unwrap();
        assert_eq!(read.table.seq(), seq);
        let bytes =
            seal_checkpoint(&self.kek, seal_with, &read.table, record, &mut self.rng).unwrap();
        self.store.plant(&checkpoint_name(&self.tenant, seq), bytes);
    }
}

/// An older checkpoint cannot reopen a subject with a superseded wider private part.
#[tokio::test(flavor = "current_thread")]
async fn older_checkpoint_cannot_reopen_a_superseded_private_part() {
    let mut w = World::new();
    let wide = principal(ID, &[grant("b_01", Access::Rw, None)]);
    let narrow = principal(ID, &[grant("b_01", Access::Rw, Some("narrow/"))]);
    let first = w.plant_record(1, KeyOp::Create, &wide, false);
    let v1 = OneKey(key(&w.tenant, 1, "first tenant key"));
    let v2 = OneKey(key(&w.tenant, 2, "second tenant key"));
    let v3 = OneKey(key(&w.tenant, 3, "third tenant key"));
    w.checkpoint(1, &v1, &v2, &first).await;
    let second = w.plant_record(2, KeyOp::Grants, &narrow, true);
    w.checkpoint(2, &v3, &v3, &second).await;

    let ring = Ring(vec![v2.0, v3.0]);
    for (seq, record) in [(1, first), (2, second)] {
        let bytes = w.store.raw(&checkpoint_name(&w.tenant, seq)).unwrap();
        let table = open_checkpoint(&w.kek, &ring, &w.tenant, seq, &bytes, &record)
            .expect("both checkpoints open with the final ring");
        let entry = table.get(ID).unwrap();
        assert_eq!(entry.private_seq, seq);
        assert_eq!(entry.private.as_ref(), (seq == 1).then_some(&wide.private));
    }
    let read = read_key_chain(&w.store, &w.kek, &ring, &w.tenant)
        .await
        .unwrap();
    assert_eq!(read.from_checkpoint, Some(2));
    let entry = read.table.get(ID).unwrap();
    assert_eq!(entry.private_seq, 2);
    assert!(entry.private.is_none());
    assert_eq!(entry.effective_status(), SubjectStatus::Disabled);
}

#[derive(Default)]
struct FakeTarget {
    seq: Cell<u64>,
    rows: RefCell<BTreeMap<String, Entry>>,
    reject_apply: bool,
}

impl KeyTarget for &FakeTarget {
    fn label(&self) -> &str {
        "review target"
    }

    async fn keys_seq(&self) -> Result<u64> {
        Ok(self.seq.get())
    }

    async fn closed(&self) -> Result<Vec<String>> {
        Ok(self
            .rows
            .borrow()
            .values()
            .filter(|e| e.private.is_none() && e.door.status != SubjectStatus::Revoked)
            .map(|e| e.door.id.clone())
            .collect())
    }

    async fn apply(&self, to_seq: u64, entries: &[Entry]) -> Result<()> {
        if self.reject_apply {
            return Err(BridgeError::Sql("fake: cannot apply".into()));
        }
        self.rows
            .borrow_mut()
            .extend(entries.iter().map(|e| (e.door.id.clone(), e.clone())));
        self.seq.set(to_seq);
        Ok(())
    }
}

struct FakeAdmission;

impl KeyAdmission for FakeAdmission {
    async fn admit(&self, _: &TenantId, _: &str, _: &OpeningChange<'_>) -> Result<Admission> {
        panic!("the finisher does not request admission");
    }

    async fn release(&self, _: &TenantId, _: &str) -> Result<()> {
        panic!("the finisher does not release reservations");
    }
}

struct FakeIntents;

impl ControlIntents for FakeIntents {
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

/// The closing pass sends a subject open at the directory's exact acknowledged sequence.
#[tokio::test(flavor = "current_thread")]
async fn closing_pass_opens_at_the_directory_acknowledgment() {
    let mut w = World::new();
    w.plant_record(1, KeyOp::Create, &principal(ID, &[]), false);
    w.plant_record(2, KeyOp::Create, &principal("PR0002", &[]), false);
    let unit = FakeTarget::default();
    let directory = FakeTarget {
        seq: Cell::new(1),
        // Keep the full pass from masking what the unit got during closing.
        reject_apply: true,
        ..FakeTarget::default()
    };
    let env = KeyEnv {
        store: &w.store,
        kek: &w.kek,
        ring: &w.ring,
        tenant: &w.tenant,
        admission: &FakeAdmission,
        intents: &FakeIntents,
        units: &[&unit],
        directory: &&directory,
        clock: &FixedClock::new(UnixMs(1_700_000_000_000)),
        limits: Limits::Recorded,
    };
    finish_keys(&env, &mut w.rng).await.unwrap();
    assert_eq!(directory.seq.get(), 1);
    assert_eq!(unit.seq.get(), 2);
    let rows = unit.rows.borrow();
    assert_eq!(rows[ID].opened_seq, directory.seq.get());
    assert!(rows[ID].private.is_some());
    assert!(rows["PR0002"].private.is_none());
}

async fn check_checkpoint_sequences(cases: &[(u64, u64, bool)]) {
    let mut w = World::new();
    let subject = principal(ID, &[]);
    let other = principal("PR0002", &[]);
    w.plant_record(1, KeyOp::Create, &subject, false);
    let record = w.plant_record(2, KeyOp::Create, &other, false);
    let sha: String = Sha256::digest(&record)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let name = checkpoint_name(&w.tenant, 2);
    let private = json!({
        "v": 1,
        "subjects": [
            { "id": ID, "private": subject.private },
            { "id": other.door.id, "private": other.private },
        ],
    });
    for &(private_seq, opened_seq, valid) in cases {
        let door = json!({
            "v": 1,
            "tenant": w.tenant.as_str(),
            "seq": 2,
            "record_sha256": sha,
            "subjects": [
                {
                    "door": subject.door, "last_seq": 1, "private_seq": private_seq,
                    "tk_version": 1, "closes": false, "opened_seq": opened_seq, "open": true
                },
                {
                    "door": other.door, "last_seq": 2, "private_seq": 2,
                    "tk_version": 1, "closes": false, "opened_seq": 2, "open": true
                },
            ],
        });
        let bytes = seal_control(
            &w.kek,
            &name,
            &ControlSealer::Managed(&w.ring.0),
            &serde_json::to_vec(&door).unwrap(),
            Some(&serde_json::to_vec(&private).unwrap()),
            &mut w.rng,
        )
        .unwrap();
        w.store.plant(&name, bytes);
        let read = read_key_chain(&w.store, &w.kek, &w.ring, &w.tenant)
            .await
            .unwrap();
        assert_eq!(
            read.from_checkpoint,
            valid.then_some(2),
            "private_seq={private_seq}, opened_seq={opened_seq}"
        );
        assert_eq!(
            read.skipped_checkpoints,
            if valid { vec![] } else { vec![2] }
        );
    }
}

/// A checkpoint whose opening sequence exceeds the entry's last sequence is skipped.
#[tokio::test(flavor = "current_thread")]
async fn checkpoint_skips_opened_sequence_above_last_sequence() {
    check_checkpoint_sequences(&[(1, 1, true), (1, 2, false)]).await;
}

/// A checkpoint whose private sequence is zero or exceeds the entry's last sequence is skipped.
#[tokio::test(flavor = "current_thread")]
async fn checkpoint_skips_private_sequence_outside_entry_history() {
    check_checkpoint_sequences(&[(1, 1, true), (0, 1, false), (2, 1, false)]).await;
}

/// Private reuse requires a prior entry and a closing status record.
#[test]
fn private_unchanged_requires_a_prior_entry() {
    let mut w = World::new();
    let subject = principal(ID, &[]);
    // Create passes admission for a new subject, reaching the fold's private-part guard.
    let mut record = KeyRecord {
        seq: 1,
        op: KeyOp::Create,
        at: 11,
        door: subject.door,
        private: None,
        tk_version: 1,
        closes: false,
        private_unchanged: true,
    };
    let mut table = KeyTable::empty(w.tenant.clone());
    assert!(table.apply(&record).is_err());
    assert_eq!(table.seq(), 0);
    assert!(table.get(ID).is_none());
    record.private_unchanged = false;
    record.private = Some(subject.private);
    table.apply(&record).unwrap();

    let name = key_chain(&w.tenant).name(2);
    let private = json!({ "v": KEY_RECORD_VERSION, "id": ID, "subject": record.private });
    for (status, closes) in [
        (SubjectStatus::Active, true),
        (SubjectStatus::Disabled, false),
    ] {
        record.door.status = status;
        let mut door = json!({
            "v": KEY_RECORD_VERSION,
            "tenant": w.tenant.as_str(),
            "seq": 2,
            "op": KeyOp::Status,
            "at": 12,
            "subject": record.door,
            "closes": closes,
            "private_unchanged": false,
        });
        for private_unchanged in [false, true] {
            door["private_unchanged"] = json!(private_unchanged);
            let bytes = seal_control(
                &w.kek,
                &name,
                &ControlSealer::Managed(&w.ring.0),
                &serde_json::to_vec(&door).unwrap(),
                Some(&serde_json::to_vec(&private).unwrap()),
                &mut w.rng,
            )
            .unwrap();
            // A status change whose `closes` does not fit it is refused,
            // with or without its private part.
            let opened = open_key_record(&w.kek, &w.ring, &w.tenant, 2, &bytes);
            assert!(matches!(
                opened,
                Err(BridgeError::Invalid("key record is malformed"))
            ));
        }
    }
}

/// Opening a record returns the closing flag carried by its sealed door.
#[test]
fn sealed_record_preserves_both_closing_flag_values() {
    let mut w = World::new();
    let subject = principal(ID, &[]);
    for closes in [false, true] {
        let bytes = w.record(1, KeyOp::Grants, &subject, closes);
        let record = open_key_record(&w.kek, &w.ring, &w.tenant, 1, &bytes).unwrap();
        assert_eq!(record.closes, closes);
    }
}

#[derive(Default)]
struct Stores {
    a: MemRecords,
    b: MemRecords,
    offsite: MemRecords,
}

impl Stores {
    fn buckets(&self) -> KeyBuckets<'_, MemRecords> {
        KeyBuckets {
            by_name: vec![
                ("KEYS_A", &self.a),
                ("KEYS_B", &self.b),
                ("KEYS_OFFSITE", &self.offsite),
            ],
        }
    }
}

fn with_async_location() -> KeyLocations {
    let mut set = two_in_account();
    set.locations.push(KeyLocation {
        name: "KEYS_OFFSITE".into(),
        status: LocationStatus::Active,
        arbiter: false,
        synchronous: false,
    });
    set.check().unwrap();
    set
}

fn wrapped(kek: &TestKek, key: &TenantKey, rng: &mut TestRng) -> (String, Vec<u8>) {
    let (version, blob) = wrap_tenant_key(kek, key, rng).unwrap();
    (tk_blob_name(key.tenant(), key.version(), version), blob)
}

#[derive(Default)]
struct LosePut {
    records: MemRecords,
    winner: Option<Vec<u8>>,
}

impl RecordStore for LosePut {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        if let Some(winner) = &self.winner {
            assert!(self.records.put_if_absent(name, winner.clone()).await?);
            return Ok(false);
        }
        self.records.put_if_absent(name, bytes).await
    }

    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.records.get(name).await
    }

    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.records.list(prefix, start_after, limit).await
    }
}

fn steps(a: RestoreStep, b: RestoreStep) -> [(String, RestoreStep); 2] {
    [("KEYS_A".into(), a), ("KEYS_B".into(), b)]
}

/// Escrow restore writes the newest verified name and withholds writes when a copy casts doubt on it.
#[tokio::test(flavor = "current_thread")]
async fn escrow_restore_uses_newest_verified_copy_and_stops_on_conflict() {
    use RestoreStep::{Conflict, Present, Restored, Unverified, Withheld};

    let tenant = tenant(1);
    let key_to_restore = key(&tenant, 1, "escrow");
    let kcv = key_to_restore.check_value();
    let mut rng = TestRng(0);
    let ring = kek(&[1, 2]);
    let (old_name, old_blob) = wrapped(&kek(&[1]), &key_to_restore, &mut rng);
    let (new_name, new_blob) = wrapped(&ring, &key_to_restore, &mut rng);
    let old_copy = EscrowCopy::of_blob(&tenant, 1, 1, &old_blob).unwrap();
    let new_copy = EscrowCopy::of_blob(&tenant, 1, 2, &new_blob).unwrap();
    let set = two_in_account();

    // Test empty buckets and an older surviving copy that could displace the escrow candidate.
    for keep_older_copy in [false, true] {
        let stores = Stores::default();
        let expected_a = if keep_older_copy {
            stores.a.plant(&old_name, old_blob.clone());
            Present
        } else {
            Restored
        };
        let actual = restore_escrow(&new_copy, &ring, kcv, &set, &stores.buckets())
            .await
            .unwrap();
        assert_eq!(actual, steps(expected_a, Restored));
        assert_eq!(
            stores.b.raw(&new_name).as_deref(),
            Some(new_blob.as_slice())
        );
        assert!(stores.b.raw(&old_name).is_none());
        assert_eq!(stores.a.raw(&new_name).is_some(), !keep_older_copy);
    }

    let stores = Stores::default();
    let (unknown_name, unknown_blob) = wrapped(&kek(&[3]), &key_to_restore, &mut rng);
    stores.b.plant(&unknown_name, unknown_blob.clone());
    let actual = restore_escrow(&new_copy, &ring, kcv, &set, &stores.buckets())
        .await
        .unwrap();
    assert_eq!(actual, steps(Withheld, Unverified));
    assert_eq!((stores.a.puts(), stores.b.puts()), (0, 0));
    assert_eq!(stores.b.raw(&unknown_name), Some(unknown_blob));
    assert!(stores.a.raw(&new_name).is_none());

    let mut corrupt = new_blob.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(tk_blob_check_value(&corrupt).unwrap(), kcv);
    assert!(unwrap_tenant_key(&ring, 2, &tenant, 1, &corrupt).is_err());
    for (winner, expected) in [
        (new_blob.as_slice(), steps(Present, Restored)),
        (corrupt.as_slice(), steps(Conflict, Withheld)),
    ] {
        let a = LosePut {
            winner: Some(winner.to_vec()),
            ..LosePut::default()
        };
        let b = LosePut::default();
        let buckets = KeyBuckets {
            by_name: vec![("KEYS_A", &a), ("KEYS_B", &b)],
        };
        let actual = restore_escrow(&new_copy, &ring, kcv, &set, &buckets)
            .await
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(a.records.puts(), 1);
        assert_eq!(a.records.raw(&new_name).as_deref(), Some(winner));
        assert_eq!(b.records.puts(), u64::from(expected[1].1 == Restored));
    }

    let set = with_async_location();
    let (_, conflicting_blob) = wrapped(&ring, &key(&tenant, 1, "different key"), &mut rng);
    for (offsite_blob, expected) in [
        (&new_blob, steps(Restored, Restored)),
        (&conflicting_blob, steps(Withheld, Withheld)),
    ] {
        let stores = Stores::default();
        stores.offsite.plant(&new_name, offsite_blob.clone());
        let actual = restore_escrow(&old_copy, &ring, kcv, &set, &stores.buckets())
            .await
            .unwrap();
        let mut expected = expected.to_vec();
        if expected[0].1 == Withheld {
            // The asynchronous location that withheld the writes is named.
            expected.push(("KEYS_OFFSITE".into(), RestoreStep::Conflict));
        }
        assert_eq!(actual, expected);
        for store in [&stores.a, &stores.b] {
            let restored = expected[0].1 == Restored;
            assert_eq!(store.puts(), u64::from(restored));
            assert_eq!(
                store.raw(&new_name).as_deref(),
                restored.then_some(new_blob.as_slice())
            );
            assert!(store.raw(&old_name).is_none());
        }
        assert_eq!(stores.offsite.puts(), 0);
    }
}

/// Repair re-lists the active asynchronous location and withholds the missing synchronous copy on a foreign name.
#[tokio::test(flavor = "current_thread")]
async fn repair_missing_checks_async_location_for_foreign_names() {
    let tenant = tenant(1);
    let ring = kek(&[1]);
    let set = with_async_location();
    let stores = Stores::default();
    let buckets = stores.buckets();
    let (name, blob) = wrapped(&ring, &key(&tenant, 1, "audited"), &mut TestRng(0));
    stores.a.plant(&name, blob.clone());
    stores.offsite.plant(&name, blob.clone());

    let report = audit(&set, &buckets, Some(&ring)).await.unwrap();
    assert_eq!(
        report.findings,
        [Finding::Missing {
            location: "KEYS_B".into(),
            name: name.clone()
        }]
    );
    let foreign = format!("{}foreign", tk_prefix(&tenant));
    stores.offsite.plant(&foreign, vec![]);
    let repair = repair_missing(&set, &buckets, &ring, &report)
        .await
        .unwrap();
    assert!(repair.restored.is_empty());
    assert_eq!(stores.b.puts(), 0);
    assert!(stores.b.raw(&name).is_none());

    assert!(stores.offsite.lose(&foreign));
    let repair = repair_missing(&set, &buckets, &ring, &report)
        .await
        .unwrap();
    assert_eq!(repair.restored, [("KEYS_B".into(), name.clone())]);
    assert_eq!(stores.b.raw(&name), Some(blob));
}

/// A create or a re-enable sealed as closing is refused, and a restate
/// that does not move to a newer key version does not fold.
#[test]
fn closes_must_fit_the_change_and_restates_move_forward() {
    let mut w = World::new();
    let subject = principal(ID, &[]);
    // A create sealed as closing.
    assert!(seal_key_record(
        &w.kek,
        &w.ring,
        &w.tenant,
        1,
        KeyOp::Create,
        11,
        &subject.door,
        Some(&subject.private),
        true,
        &mut w.rng,
    )
    .is_err());
    // A restate under the same key version.
    let bytes = w.record(1, KeyOp::Create, &subject, false);
    let create = open_key_record(&w.kek, &w.ring, &w.tenant, 1, &bytes).unwrap();
    let mut table = KeyTable::empty(w.tenant.clone());
    table.apply(&create).unwrap();
    let mut restate = create.clone();
    restate.seq = 2;
    restate.op = KeyOp::Restate;
    assert!(table.apply(&restate).is_err());
    restate.tk_version = 2;
    table.apply(&restate).unwrap();
}
