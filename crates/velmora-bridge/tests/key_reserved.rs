//! The key writer under a reservation the caller holds (AM-38), against
//! fake stores: the record at exactly `keys_seq + 1` with the `rid`, a
//! record of the same `rid` winning over the call's own bytes, the kept
//! answer only with the root unit's full apply, `carrying` and `finish`.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::{TenantId, TenantKey};
use velmora_bridge::keys::checkpoint::{open_checkpoint, seal_checkpoint};
use velmora_bridge::keys::gate::testkit::FakeGate;
use velmora_bridge::keys::ports::{
    Admission, Applied, ApplyEntry, Binding, BucketAdmission, BucketReservation, ControlChain,
    ControlIntents, KeptAnswer, KeyAdmission, KeyTarget, OpeningChange,
};
use velmora_bridge::keys::record::{
    key_chain, open_key_record, seal_key_record_carrying, Access, Entry, Grant, KeyOp, KeyTable,
    OneKey, Rid, Subject, SubjectDoor, SubjectKind, SubjectPrivate, SubjectStatus,
};
use velmora_bridge::keys::reserved::{Carried, Finished, Reserved, ReservedAnswer};
use velmora_bridge::keys::writer::{KeyAnswer, KeyEnv, KeyRequest, Limits};
use velmora_bridge::records::{MemRecords, RecordStore};
use velmora_bridge::testkit::{FixedClock, TestKek};
use velmora_bridge::{BridgeError, Result, UnixMs};

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

struct TestRng(u64);

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(b"key reserved");
            h.update(self.0.to_be_bytes());
            self.0 += 1;
            block.copy_from_slice(&h.finalize()[..block.len()]);
        }
        Ok(())
    }
}

/// A store with a copy of the key table, logging every `rid` it was sent
/// and every answer it kept.
struct Target {
    label: &'static str,
    seq: Cell<u64>,
    rows: RefCell<BTreeMap<String, Entry>>,
    down: Cell<bool>,
    /// Keeps answers ([`KeyTarget::apply_kept`]); only the root unit.
    keeps: bool,
    /// `(rid, seq, held)` of every entry that carried a `rid`.
    rids: RefCell<Vec<(Rid, u64, bool)>>,
    /// `(rid, status)` of every answer kept, with the `rid`s applied so
    /// far at that moment.
    kept: RefCell<Vec<(Rid, u16)>>,
    applied_rids: RefCell<Vec<Rid>>,
    /// The `owner_ref` of each row, write-once (AM-72): from an open
    /// entry's private part or a held entry's identity.
    owners: RefCell<BTreeMap<String, String>>,
}

impl Target {
    fn new(label: &'static str, keeps: bool) -> Self {
        Target {
            label,
            seq: Cell::new(0),
            rows: RefCell::new(BTreeMap::new()),
            down: Cell::new(false),
            keeps,
            rids: RefCell::new(Vec::new()),
            kept: RefCell::new(Vec::new()),
            applied_rids: RefCell::new(Vec::new()),
            owners: RefCell::new(BTreeMap::new()),
        }
    }

    fn row(&self, id: &str) -> Option<Entry> {
        self.rows.borrow().get(id).cloned()
    }

    fn reset(&self) {
        self.seq.set(0);
        self.rows.borrow_mut().clear();
        self.rids.borrow_mut().clear();
        self.owners.borrow_mut().clear();
    }

    fn down_err() -> BridgeError {
        BridgeError::Sql("fake: down".into())
    }
}

impl KeyTarget for Target {
    fn label(&self) -> &str {
        self.label
    }

    async fn keys_seq(&self) -> Result<u64> {
        if self.down.get() {
            return Err(Self::down_err());
        }
        Ok(self.seq.get())
    }

    async fn closed(&self) -> Result<Vec<String>> {
        if self.down.get() {
            return Err(Self::down_err());
        }
        Ok(self
            .rows
            .borrow()
            .values()
            .filter(|e| e.private.is_none() && e.door.status != SubjectStatus::Revoked)
            .map(|e| e.door.id.clone())
            .collect())
    }

    async fn apply(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied> {
        if self.down.get() {
            return Err(Self::down_err());
        }
        if from_seq > self.seq.get() {
            return Ok(Applied::Behind {
                keys_seq: self.seq.get(),
            });
        }
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.seq(), from_seq + 1 + i as u64, "{}: a gap", self.label);
        }
        let mut rows = self.rows.borrow_mut();
        for e in entries {
            let (e, held_owner) = match e {
                ApplyEntry::Subject(e) => (e, None),
                ApplyEntry::Held { entry, owner_ref } => {
                    assert!(
                        entry.private.is_none(),
                        "{}: a held entry opens",
                        self.label
                    );
                    (entry, owner_ref.clone())
                }
                ApplyEntry::Marker { .. } => continue,
            };
            let owner = e
                .private
                .as_ref()
                .and_then(|p| p.owner_ref.clone())
                .or(held_owner);
            if let Some(owner) = owner {
                let mut owners = self.owners.borrow_mut();
                let kept = owners.entry(e.door.id.clone()).or_insert(owner.clone());
                assert_eq!(*kept, owner, "{}: owner_ref changed", self.label);
            }
            if let Some(rid) = e.rid {
                self.rids
                    .borrow_mut()
                    .push((rid, e.last_seq, e.private.is_none()));
                self.applied_rids.borrow_mut().push(rid);
            }
            let replace = match rows.get(&e.door.id) {
                None => true,
                Some(r) => {
                    e.last_seq > r.last_seq
                        || (e.last_seq == r.last_seq && r.private.is_none() && e.private.is_some())
                }
            };
            if replace {
                rows.insert(e.door.id.clone(), e.clone());
            }
        }
        let last = from_seq + entries.len() as u64;
        self.seq.set(self.seq.get().max(last));
        Ok(Applied::Done {
            keys_seq: self.seq.get(),
        })
    }

    async fn apply_kept(
        &self,
        from_seq: u64,
        entries: &[ApplyEntry],
        answers: &[KeptAnswer],
    ) -> Result<Applied> {
        if !self.keeps && !answers.is_empty() {
            return Err(BridgeError::Invalid("fake: keeps no answers"));
        }
        let applied = self.apply(from_seq, entries).await?;
        if let Applied::Done { .. } = applied {
            for a in answers {
                // The unit keeps an answer only for an applied reservation
                // that has none yet.
                let applied = self.applied_rids.borrow().contains(&a.rid);
                let fresh = !self.kept.borrow().iter().any(|(r, _)| *r == a.rid);
                if applied && fresh {
                    self.kept.borrow_mut().push((a.rid, a.status));
                }
            }
        }
        Ok(applied)
    }
}

impl KeyTarget for &Target {
    fn label(&self) -> &str {
        self.label
    }
    async fn keys_seq(&self) -> Result<u64> {
        KeyTarget::keys_seq(*self).await
    }
    async fn closed(&self) -> Result<Vec<String>> {
        KeyTarget::closed(*self).await
    }
    async fn apply(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied> {
        KeyTarget::apply(*self, from_seq, entries).await
    }
    async fn apply_kept(
        &self,
        from_seq: u64,
        entries: &[ApplyEntry],
        answers: &[KeptAnswer],
    ) -> Result<Applied> {
        KeyTarget::apply_kept(*self, from_seq, entries, answers).await
    }
}

/// A root unit with only the required methods: it keeps no answers.
struct Plain<'a>(&'a Target);

impl KeyTarget for Plain<'_> {
    fn label(&self) -> &str {
        self.0.label
    }
    async fn keys_seq(&self) -> Result<u64> {
        self.0.keys_seq().await
    }
    async fn closed(&self) -> Result<Vec<String>> {
        self.0.closed().await
    }
    async fn apply(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied> {
        self.0.apply(from_seq, entries).await
    }
}

/// The reserved writer never calls the reservation port.
struct NoAdmission;

impl KeyAdmission for NoAdmission {
    async fn admit(&self, _: &TenantId, _: &str, _: &OpeningChange<'_>) -> Result<Admission> {
        panic!("a reserved create asked for a reservation")
    }
    async fn release(&self, _: &TenantId, _: &str) -> Result<()> {
        panic!("a reserved create released a reservation")
    }
    async fn admit_bucket(
        &self,
        _: &TenantId,
        _: &str,
        _: &BucketReservation<'_>,
    ) -> Result<BucketAdmission> {
        panic!("not a bucket create")
    }
    async fn bind_bucket(&self, _: &TenantId, _: &str, _: Option<u64>, _: u64) -> Result<bool> {
        panic!("not a bucket create")
    }
    async fn release_bound(&self, _: &TenantId, _: &str, _: Option<u64>) -> Result<bool> {
        panic!("not a bucket create")
    }
    async fn bucket_binding(&self, _: &TenantId, _: u64) -> Result<Binding> {
        panic!("not a bucket create")
    }
}

/// The admission of the plain writer's seed records: always admitted at
/// the root's seq.
struct AtRoot<'a>(&'a Target);

impl KeyAdmission for AtRoot<'_> {
    async fn admit(&self, _: &TenantId, _: &str, _: &OpeningChange<'_>) -> Result<Admission> {
        Ok(Admission::Admitted {
            keys_seq: self.0.seq.get(),
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
        unreachable!()
    }
    async fn bind_bucket(&self, _: &TenantId, _: &str, _: Option<u64>, _: u64) -> Result<bool> {
        unreachable!()
    }
    async fn release_bound(&self, _: &TenantId, _: &str, _: Option<u64>) -> Result<bool> {
        unreachable!()
    }
    async fn bucket_binding(&self, _: &TenantId, _: u64) -> Result<Binding> {
        unreachable!()
    }
}

#[derive(Default)]
struct Intents {
    sent: RefCell<Vec<u64>>,
    cleared: RefCell<Vec<u64>>,
}

impl ControlIntents for Intents {
    async fn send(&self, _: &TenantId, chain: ControlChain, seq: u64) -> Result<()> {
        assert_eq!(chain, ControlChain::Keys);
        self.sent.borrow_mut().push(seq);
        Ok(())
    }
    async fn note(&self, _: &TenantId, _: ControlChain, _: u64, _: &str) -> Result<()> {
        Ok(())
    }
    async fn clear(&self, _: &TenantId, _: ControlChain, seq: u64) -> Result<()> {
        self.cleared.borrow_mut().push(seq);
        Ok(())
    }
}

/// A record store that, on the chain's put of `seq`, lets another call's
/// bytes land first.
struct PlantOnPut<'a> {
    inner: &'a MemRecords,
    name: String,
    theirs: RefCell<Option<Vec<u8>>>,
}

impl RecordStore for PlantOnPut<'_> {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        if name == self.name {
            let theirs = self.theirs.borrow_mut().take();
            if let Some(theirs) = theirs {
                assert!(self.inner.put_if_absent(name, theirs).await?);
            }
        }
        self.inner.put_if_absent(name, bytes).await
    }
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(name).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.inner.list(prefix, start_after, limit).await
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

struct World {
    t: TenantId,
    store: MemRecords,
    kek: TestKek,
    ring: OneKey,
    root: Target,
    unit2: Target,
    directory: Target,
    intents: Intents,
    clock: FixedClock,
    gate: FakeGate,
}

impl World {
    fn new() -> Self {
        let t = TenantId::parse("t_0000000000000001").unwrap();
        World {
            ring: OneKey(TenantKey::from_bytes(&t, 1, derived("tk")).unwrap()),
            t,
            store: MemRecords::new(),
            kek: TestKek::with_versions(1, &[(1, derived("kek"))]),
            root: Target::new("root", true),
            unit2: Target::new("unit 2", false),
            directory: Target::new("directory", false),
            intents: Intents::default(),
            clock: FixedClock::new(UnixMs(1_700_000_000_000)),
            gate: FakeGate::before_move(),
        }
    }

    fn head(&self) -> u64 {
        self.store.names_under(key_chain(&self.t).prefix()).len() as u64
    }
}

macro_rules! env {
    ($w:expr, $store:expr, $adm:expr, $units:expr) => {
        KeyEnv {
            store: $store,
            kek: &$w.kek,
            ring: &$w.ring,
            tenant: &$w.t,
            admission: $adm,
            intents: &$w.intents,
            units: $units,
            directory: &$w.directory,
            clock: &$w.clock,
            limits: Limits::Recorded,
            gate: &$w.gate,
        }
    };
}

fn principal(id: &str, made_by: Option<&str>) -> Subject {
    let mut s = Subject {
        door: SubjectDoor {
            id: id.to_owned(),
            kind: SubjectKind::Principal,
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
    s.set_grants(&[Grant {
        bucket_id: "b_01".into(),
        access: Access::Rw,
        expires_at: None,
        prefix: None,
        ip_list: Vec::new(),
    }]);
    s
}

const RID: Rid = Rid([7; 16]);
const OTHER: Rid = Rid([9; 16]);

fn kept(rid: Rid) -> KeptAnswer {
    KeptAnswer {
        rid,
        status: 201,
        body: r#"{"principal":{"id":"p_0000000000000002"}}"#.into(),
    }
}

/// One principal p_0000000000000001 at seq 1, by the plain writer.
async fn seed(w: &World) -> KeyTable {
    let units = [&w.root, &w.unit2];
    let adm = AtRoot(&w.root);
    let env = env!(w, &w.store, &adm, &units);
    let mut table = KeyTable::empty(w.t.clone());
    assert_eq!(
        env.change(
            &mut table,
            "idem-seed",
            &KeyRequest::Create(principal("p_0000000000000001", None)),
            &mut TestRng(1),
        )
        .await
        .unwrap(),
        KeyAnswer::Done { seq: 1 }
    );
    table
}

const NEW: &str = "p_0000000000000002";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_reserved_create_records_exactly_keys_seq_plus_one_with_its_rid() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let reserved = Reserved {
        rid: RID,
        keys_seq: 1,
        answer: &answer,
    };
    let subject = principal(NEW, Some("p_0000000000000001"));
    assert_eq!(
        env.create_reserved(&mut table, &subject, reserved, &mut TestRng(2))
            .await
            .unwrap(),
        ReservedAnswer::Done { seq: 2 }
    );
    assert_eq!(w.head(), 2);
    let bytes = w.store.raw(&key_chain(&w.t).name(2)).unwrap();
    let record = open_key_record(&w.kek, &w.ring, &w.t, 2, &bytes).unwrap();
    assert_eq!(record.rid, Some(RID));
    assert_eq!(record.op, KeyOp::Create);
    assert_eq!(table.get(NEW).unwrap().rid, Some(RID));
    for store in [&w.root, &w.unit2, &w.directory] {
        assert_eq!(store.seq.get(), 2, "{}", store.label);
        assert!(store.row(NEW).unwrap().private.is_some(), "{}", store.label);
        assert!(
            store
                .rids
                .borrow()
                .iter()
                .all(|(r, s, _)| *r == RID && *s == 2),
            "{}",
            store.label
        );
    }
    // The answer is kept once, by the root unit only, after its full apply.
    assert_eq!(*w.root.kept.borrow(), vec![(RID, 201)]);
    assert!(w.unit2.kept.borrow().is_empty());
    assert_eq!(*w.intents.sent.borrow(), vec![1, 2]);
    assert!(w.intents.cleared.borrow().contains(&2));
}

#[tokio::test(flavor = "current_thread")]
async fn no_answer_is_kept_while_the_subject_is_held_closed() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let subject = principal(NEW, Some("p_0000000000000001"));
    let reserved = Reserved {
        rid: RID,
        keys_seq: 1,
        answer: &answer,
    };
    w.directory.down.set(true);
    assert_eq!(
        env.create_reserved(&mut table, &subject, reserved, &mut TestRng(2))
            .await
            .unwrap(),
        ReservedAnswer::Unfinished { seq: 2 }
    );
    // The units hold it closed, with the rid (the unit turns the
    // reservation applied), and keep no answer.
    for unit in [&w.root, &w.unit2] {
        assert!(unit.row(NEW).unwrap().private.is_none(), "{}", unit.label);
        assert_eq!(*unit.rids.borrow(), vec![(RID, 2, true)], "{}", unit.label);
    }
    assert!(w.root.kept.borrow().is_empty());

    // finish(subject): the idempotent path keeps none either.
    assert_eq!(
        env.finish_subject(&mut table, NEW).await.unwrap(),
        Finished::Unfinished
    );
    w.directory.down.set(false);
    assert_eq!(
        env.finish_subject(&mut table, NEW).await.unwrap(),
        Finished::Done { seq: 2 }
    );
    assert!(w.root.row(NEW).unwrap().private.is_some());
    assert!(w.root.kept.borrow().is_empty());

    // The retry under the same reservation writes nothing and keeps the
    // answer now.
    assert_eq!(
        env.create_reserved(&mut table, &subject, reserved, &mut TestRng(3))
            .await
            .unwrap(),
        ReservedAnswer::Done { seq: 2 }
    );
    assert_eq!(w.head(), 2);
    assert_eq!(*w.root.kept.borrow(), vec![(RID, 201)]);
}

/// Another call's record of `subject` under `rid` at `seq`, sealed apart.
fn their_record(w: &World, subject: &Subject, rid: Option<Rid>, seq: u64) -> Vec<u8> {
    let mut door = subject.door.clone();
    door.created_at = 2_000;
    seal_key_record_carrying(
        &w.kek,
        &w.ring,
        &w.t,
        seq,
        KeyOp::Create,
        9,
        &door,
        Some(&subject.private),
        false,
        None,
        rid,
        &mut TestRng(99),
    )
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn a_put_lost_to_a_record_of_the_same_rid_takes_that_record() {
    let w = World::new();
    let mut table = seed(&w).await;
    let subject = principal(NEW, Some("p_0000000000000001"));
    let theirs = their_record(&w, &subject, Some(RID), 2);
    let store = PlantOnPut {
        inner: &w.store,
        name: key_chain(&w.t).name(2),
        theirs: RefCell::new(Some(theirs.clone())),
    };
    let units = [&w.root, &w.unit2];
    let env = env!(w, &store, &NoAdmission, &units);
    let answer = kept(RID);
    let reserved = Reserved {
        rid: RID,
        keys_seq: 1,
        answer: &answer,
    };
    assert_eq!(
        env.create_reserved(&mut table, &subject, reserved, &mut TestRng(2))
            .await
            .unwrap(),
        ReservedAnswer::Done { seq: 2 }
    );
    // Their bytes win; ours were never written.
    assert_eq!(w.store.raw(&key_chain(&w.t).name(2)), Some(theirs));
    assert_eq!(table.get(NEW).unwrap().door.created_at, 2_000);
    assert_eq!(w.root.row(NEW).unwrap().door.created_at, 2_000);
    assert_eq!(*w.root.kept.borrow(), vec![(RID, 201)]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_put_lost_to_another_record_answers_lost_with_the_stores_at_the_head() {
    let w = World::new();
    let mut table = seed(&w).await;
    let subject = principal(NEW, Some("p_0000000000000001"));
    let other = principal("p_0000000000000003", Some("p_0000000000000001"));
    for rid in [None, Some(OTHER)] {
        let w = World::new();
        let mut table = seed(&w).await;
        let store = PlantOnPut {
            inner: &w.store,
            name: key_chain(&w.t).name(2),
            theirs: RefCell::new(Some(their_record(&w, &other, rid, 2))),
        };
        let units = [&w.root, &w.unit2];
        let env = env!(w, &store, &NoAdmission, &units);
        let answer = kept(RID);
        let reserved = Reserved {
            rid: RID,
            keys_seq: 1,
            answer: &answer,
        };
        assert_eq!(
            env.create_reserved(&mut table, &subject, reserved, &mut TestRng(2))
                .await
                .unwrap(),
            ReservedAnswer::Lost
        );
        assert_eq!(w.head(), 2);
        assert!(table.get(NEW).is_none());
        for store in [&w.root, &w.unit2, &w.directory] {
            assert_eq!(store.seq.get(), 2, "{}", store.label);
            assert!(store.row(NEW).is_none());
        }
        assert!(w.root.kept.borrow().is_empty());
    }
    // A head already past keys_seq: nothing is put at all.
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &AtRoot(&w.root), &units);
    env.change(
        &mut table,
        "idem-other",
        &KeyRequest::Create(other.clone()),
        &mut TestRng(5),
    )
    .await
    .unwrap();
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let reserved = Reserved {
        rid: RID,
        keys_seq: 1,
        answer: &answer,
    };
    let puts = w.store.puts();
    assert_eq!(
        env.create_reserved(&mut table, &subject, reserved, &mut TestRng(2))
            .await
            .unwrap(),
        ReservedAnswer::Lost
    );
    assert_eq!(w.store.puts(), puts);
    assert_eq!(w.head(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn carrying_finds_the_record_of_a_rid_above_a_seq() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let subject = principal(NEW, Some("p_0000000000000001"));
    let reserved = Reserved {
        rid: RID,
        keys_seq: 1,
        answer: &answer,
    };
    env.create_reserved(&mut table, &subject, reserved, &mut TestRng(2))
        .await
        .unwrap();
    let mut cold = KeyTable::empty(w.t.clone());
    assert_eq!(
        env.carrying(&mut cold, &RID, 1).await.unwrap(),
        Some(Carried {
            seq: 2,
            id: NEW.into()
        })
    );
    assert_eq!(cold.seq(), 2, "read from the head");
    assert_eq!(env.carrying(&mut cold, &RID, 2).await.unwrap(), None);
    // One read, at `above + 1` (AM-55): seq 1 is another record.
    assert_eq!(env.carrying(&mut cold, &RID, 0).await.unwrap(), None);
    assert_eq!(env.carrying(&mut cold, &OTHER, 0).await.unwrap(), None);
    assert_eq!(
        env.finish_subject(&mut cold, "p_00000000000000ff")
            .await
            .unwrap(),
        Finished::NotHeld
    );
}

#[tokio::test(flavor = "current_thread")]
async fn each_entry_carries_the_rid_of_its_own_record() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let subject = principal(NEW, Some("p_0000000000000001"));
    let reserved = Reserved {
        rid: RID,
        keys_seq: 1,
        answer: &answer,
    };
    env.create_reserved(&mut table, &subject, reserved, &mut TestRng(2))
        .await
        .unwrap();
    let env = env!(w, &w.store, &AtRoot(&w.root), &units);
    assert_eq!(
        env.change(
            &mut table,
            "idem-disable",
            &KeyRequest::SetStatus {
                id: NEW.into(),
                status: SubjectStatus::Disabled,
            },
            &mut TestRng(3),
        )
        .await
        .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert_eq!(
        table.get(NEW).unwrap().rid,
        None,
        "the disable carries none"
    );
    // A store rebuilt from nothing gets seq 2 with the rid, seq 3 without.
    w.unit2.reset();
    let env = env!(w, &w.store, &NoAdmission, &units);
    env.finish_subject(&mut table, NEW).await.unwrap();
    assert_eq!(*w.unit2.rids.borrow(), vec![(RID, 2, false)]);
    assert_eq!(
        w.unit2.row(NEW).unwrap().door.status,
        SubjectStatus::Disabled
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_root_unit_that_keeps_no_answers_leaves_the_create_unfinished() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [Plain(&w.root)];
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let subject = principal(NEW, Some("p_0000000000000001"));
    let reserved = Reserved {
        rid: RID,
        keys_seq: 1,
        answer: &answer,
    };
    assert_eq!(
        env.create_reserved(&mut table, &subject, reserved, &mut TestRng(2))
            .await
            .unwrap(),
        ReservedAnswer::Unfinished { seq: 2 }
    );
    assert!(w.root.row(NEW).unwrap().private.is_some());
    assert!(w.root.kept.borrow().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn a_kept_answer_of_another_reservation_is_refused_before_anything() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(OTHER);
    let reserved = Reserved {
        rid: RID,
        keys_seq: 1,
        answer: &answer,
    };
    let puts = w.store.puts();
    assert!(env
        .create_reserved(
            &mut table,
            &principal(NEW, Some("p_0000000000000001")),
            reserved,
            &mut TestRng(2)
        )
        .await
        .is_err());
    assert_eq!(w.store.puts(), puts);
}

#[tokio::test(flavor = "current_thread")]
async fn a_record_of_the_rid_for_another_subject_is_an_error() {
    let w = World::new();
    let mut table = seed(&w).await;
    let other = principal("p_0000000000000003", Some("p_0000000000000001"));
    w.store.plant(
        &key_chain(&w.t).name(2),
        their_record(&w, &other, Some(RID), 2),
    );
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let reserved = Reserved {
        rid: RID,
        keys_seq: 1,
        answer: &answer,
    };
    assert!(env
        .create_reserved(
            &mut table,
            &principal(NEW, Some("p_0000000000000001")),
            reserved,
            &mut TestRng(2)
        )
        .await
        .is_err());
    assert!(w.root.kept.borrow().is_empty());
}

#[test]
fn only_an_opening_record_carries_a_rid_and_checkpoints_keep_it() {
    let w = World::new();
    let subject = principal(NEW, None);
    let mut closing = subject.door.clone();
    closing.status = SubjectStatus::Disabled;
    assert!(seal_key_record_carrying(
        &w.kek,
        &w.ring,
        &w.t,
        2,
        KeyOp::Status,
        9,
        &closing,
        Some(&subject.private),
        true,
        None,
        Some(RID),
        &mut TestRng(1),
    )
    .is_err());

    // A record with no rid stores no `rid` field (older records read the
    // same), and one with a rid opens with it.
    let none = their_record(&w, &subject, None, 1);
    let with = their_record(&w, &subject, Some(RID), 1);
    assert_eq!(
        open_key_record(&w.kek, &w.ring, &w.t, 1, &none)
            .unwrap()
            .rid,
        None
    );
    let record = open_key_record(&w.kek, &w.ring, &w.t, 1, &with).unwrap();
    assert_eq!(record.rid, Some(RID));

    let mut table = KeyTable::empty(w.t.clone());
    table.apply(&record).unwrap();
    let cp = seal_checkpoint(&w.kek, &w.ring, &table, &with, &mut TestRng(2)).unwrap();
    let back = open_checkpoint(&w.kek, &w.ring, &w.t, 1, &cp, &with).unwrap();
    assert_eq!(back.get(NEW).unwrap().rid, Some(RID));
}

#[test]
fn a_rid_is_32_lowercase_hex_digits() {
    let rid = Rid([0xab; 16]);
    assert_eq!(rid.hex(), "ab".repeat(16));
    assert_eq!(Rid::parse(&rid.hex()), Some(rid));
    for bad in [
        "AB".repeat(16),
        "ab".repeat(15),
        "ab".repeat(17),
        "zz".repeat(16),
    ] {
        assert_eq!(Rid::parse(&bad), None, "{bad}");
    }
    assert_eq!(
        serde_json::to_string(&rid).unwrap(),
        format!("\"{}\"", "ab".repeat(16))
    );
    assert!(format!("{:?}", kept(rid)).contains("201"));
    assert!(!format!("{:?}", kept(rid)).contains("principal"));
}

#[tokio::test(flavor = "current_thread")]
async fn the_move_rules_stop_a_reserved_create_before_any_put() {
    use velmora_bridge::keys::gate::ZeroHead;
    for (zero, expected) in [
        (
            ZeroHead::Moving {
                to: TenantId::parse("t_0000000000000001").unwrap(),
            },
            ReservedAnswer::Busy,
        ),
        (
            ZeroHead::Undone {
                to: TenantId::parse("t_0000000000000001").unwrap(),
            },
            ReservedAnswer::KeyMoved,
        ),
    ] {
        let w = World::new();
        let mut table = seed(&w).await;
        w.gate.set_zero(zero);
        let units = [&w.root, &w.unit2];
        let env = env!(w, &w.store, &NoAdmission, &units);
        let answer = kept(RID);
        let reserved = Reserved {
            rid: RID,
            keys_seq: 1,
            answer: &answer,
        };
        let puts = w.store.puts();
        assert_eq!(
            env.create_reserved(
                &mut table,
                &principal(NEW, Some("p_0000000000000001")),
                reserved,
                &mut TestRng(2)
            )
            .await
            .unwrap(),
            expected
        );
        assert_eq!(w.store.puts(), puts);
        assert_eq!(*w.intents.sent.borrow(), vec![1]);
    }
}

#[test]
fn principal_ids_are_p_and_16_hex_and_no_key_takes_one() {
    use velmora_bridge::keys::record::is_principal_id;
    assert!(is_principal_id("p_0123456789abcdef"));
    for bad in [
        "p_0123456789ABCDEF",
        "p_0123456789abcde",
        "q_0123456789abcdef",
        "p_",
    ] {
        assert!(!is_principal_id(bad), "{bad}");
    }
    let w = World::new();
    // The same S3 key under an alphanumeric id seals; under a principal
    // id it does not.
    let seal_key = |id: &str| {
        let mut key = principal(id, Some("p_0000000000000001"));
        key.door.kind = SubjectKind::S3;
        let (v, wrapped) = velmora_bridge::crypto::scheme2::wrap_secret_v2(
            &w.kek,
            &w.t,
            "AKVL0001",
            b"secret",
            &mut TestRng(4),
        )
        .unwrap();
        key.door.secret_kek_version = Some(v);
        key.private.secret_wrapped = Some(wrapped);
        seal_key_record_carrying(
            &w.kek,
            &w.ring,
            &w.t,
            1,
            KeyOp::Create,
            9,
            &key.door,
            Some(&key.private),
            false,
            None,
            None,
            &mut TestRng(1),
        )
    };
    assert!(seal_key("AKVL0001").is_ok());
    assert!(seal_key("p_0123456789abcdef").is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn a_plane_principal_is_revoked_with_its_m_rk_first() {
    use velmora_bridge::keys::revocations::{list_tenant_revocations, tenant_revocation_name};
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let reserved = Reserved {
        rid: RID,
        keys_seq: 1,
        answer: &answer,
    };
    env.create_reserved(
        &mut table,
        &principal(NEW, Some("p_0000000000000001")),
        reserved,
        &mut TestRng(2),
    )
    .await
    .unwrap();
    let env = env!(w, &w.store, &AtRoot(&w.root), &units);
    assert_eq!(
        env.change(
            &mut table,
            "idem-revoke",
            &KeyRequest::SetStatus {
                id: NEW.into(),
                status: SubjectStatus::Revoked,
            },
            &mut TestRng(3),
        )
        .await
        .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert!(w.store.raw(&tenant_revocation_name(&w.t, NEW)).is_some());
    assert_eq!(
        list_tenant_revocations(&w.store, &w.t).await.unwrap(),
        vec![NEW.to_owned()]
    );
    for store in [&w.root, &w.unit2, &w.directory] {
        assert_eq!(
            store.row(NEW).unwrap().door.status,
            SubjectStatus::Revoked,
            "{}",
            store.label
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_subject_revoked_by_m_rk_alone_is_not_answered_as_open() {
    use velmora_bridge::keys::revocations::put_tenant_revocation;
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let subject = principal(NEW, Some("p_0000000000000001"));
    let reserved = Reserved {
        rid: RID,
        keys_seq: 1,
        answer: &answer,
    };
    w.directory.down.set(true);
    assert_eq!(
        env.create_reserved(&mut table, &subject, reserved, &mut TestRng(2))
            .await
            .unwrap(),
        ReservedAnswer::Unfinished { seq: 2 }
    );
    w.directory.down.set(false);
    // A revoke that stopped after its `m/rk/`, before its record.
    put_tenant_revocation(&w.store, &w.kek, &w.t, NEW, 5, &mut TestRng(4))
        .await
        .unwrap();
    assert_eq!(
        env.finish_subject(&mut table, NEW).await.unwrap(),
        Finished::Unfinished
    );
    assert_eq!(
        env.create_reserved(&mut table, &subject, reserved, &mut TestRng(3))
            .await
            .unwrap(),
        ReservedAnswer::Unfinished { seq: 2 }
    );
    assert!(w.root.kept.borrow().is_empty());
    assert_eq!(w.root.row(NEW).unwrap().door.status, SubjectStatus::Revoked);

    // Once the revoke is recorded, the table states it: `finish` is done,
    // and a retry keeps the create's answer.
    let env = env!(w, &w.store, &AtRoot(&w.root), &units);
    assert_eq!(
        env.change(
            &mut table,
            "idem-revoke",
            &KeyRequest::SetStatus {
                id: NEW.into(),
                status: SubjectStatus::Revoked,
            },
            &mut TestRng(5),
        )
        .await
        .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    let env = env!(w, &w.store, &NoAdmission, &units);
    assert_eq!(
        env.finish_subject(&mut table, NEW).await.unwrap(),
        Finished::Done { seq: 3 }
    );
    assert_eq!(
        env.create_reserved(&mut table, &subject, reserved, &mut TestRng(6))
            .await
            .unwrap(),
        ReservedAnswer::Done { seq: 2 }
    );
    assert_eq!(*w.root.kept.borrow(), vec![(RID, 201)]);
    assert_eq!(w.head(), 3);
}

/// The root unit's principal reservation check (D21, AM-36), as the unit
/// makes it before a create: a live principal row (open or held) with the
/// same `owner_ref` refuses `principal_exists` (`409`), unless it is the
/// same principal with the same grants (`Exists`, `200`). Otherwise the
/// reservation is admitted at the unit's `keys_seq`.
#[derive(Debug, PartialEq, Eq)]
enum UnitReserve {
    Admitted { keys_seq: u64 },
    Exists,
    PrincipalExists,
}

fn unit_reserve(root: &Target, subject: &Subject) -> UnitReserve {
    let Some(owner) = subject.private.owner_ref.as_deref() else {
        return UnitReserve::Admitted {
            keys_seq: root.seq.get(),
        };
    };
    let owners = root.owners.borrow();
    for (id, row) in root.rows.borrow().iter() {
        let live = row.door.kind == SubjectKind::Principal
            && row.door.status != SubjectStatus::Revoked
            && owners.get(id).map(String::as_str) == Some(owner);
        if !live {
            continue;
        }
        return match row.door.grants == subject.door.grants && *id == subject.door.id {
            true => UnitReserve::Exists,
            false => UnitReserve::PrincipalExists,
        };
    }
    UnitReserve::Admitted {
        keys_seq: root.seq.get(),
    }
}

/// AM-72 (the plane's #246 review, M2): while the directory is down a
/// principal create lands held at the units, and the held entry keeps its
/// `owner_ref`. So the unit's one-principal-per-member check (D21) still
/// finds the member: a second create for it, with other grants, is
/// refused `principal_exists` at the reservation, and nothing is recorded.
/// Without the `owner_ref` on the held row the same check admits it (the
/// defect).
#[tokio::test(flavor = "current_thread")]
async fn a_second_create_for_the_member_of_a_held_principal_is_refused() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &NoAdmission, &units);
    let first = principal(NEW, Some("p_0000000000000001"));
    let member = first.private.owner_ref.clone().unwrap();
    w.directory.down.set(true);
    let UnitReserve::Admitted { keys_seq } = unit_reserve(&w.root, &first) else {
        panic!("the first create is admitted");
    };
    let answer = kept(RID);
    assert_eq!(
        env.create_reserved(
            &mut table,
            &first,
            Reserved {
                rid: RID,
                keys_seq,
                answer: &answer,
            },
            &mut TestRng(2)
        )
        .await
        .unwrap(),
        ReservedAnswer::Unfinished { seq: 2 }
    );
    for unit in [&w.root, &w.unit2] {
        assert!(unit.row(NEW).unwrap().private.is_none(), "{}", unit.label);
        assert_eq!(
            unit.owners.borrow().get(NEW),
            Some(&member),
            "{}: held without its owner_ref",
            unit.label
        );
    }

    // The second create for the same member, another principal with other
    // grants, under another key: refused at the reservation.
    let mut second = principal("p_0000000000000003", Some("p_0000000000000001"));
    second.private.owner_ref = Some(member.clone());
    second.set_grants(&[]);
    assert_eq!(unit_reserve(&w.root, &second), UnitReserve::PrincipalExists);
    // A retry of the first is `Exists`, not a refusal.
    assert_eq!(unit_reserve(&w.root, &first), UnitReserve::Exists);
    assert_eq!(w.head(), 2);
    assert!(w.root.row("p_0000000000000003").is_none());
    // The defect, for contrast: a held row without its owner_ref admits it.
    w.root.owners.borrow_mut().remove(NEW);
    assert!(matches!(
        unit_reserve(&w.root, &second),
        UnitReserve::Admitted { .. }
    ));
    w.root
        .owners
        .borrow_mut()
        .insert(NEW.into(), member.clone());

    // Once the directory is back the principal opens with the same owner.
    w.directory.down.set(false);
    assert_eq!(
        env.finish_subject(&mut table, NEW).await.unwrap(),
        Finished::Done { seq: 2 }
    );
    let row = w.root.row(NEW).unwrap();
    assert_eq!(row.private.unwrap().owner_ref, Some(member));
}

// ---------------------------------------------------------------------------
// change_reserved (L4-W2, AM-72): widenings, re-enables, grant changes
// ---------------------------------------------------------------------------

const SEED: &str = "p_0000000000000001";

fn rw(bucket: &str) -> Grant {
    Grant {
        bucket_id: bucket.into(),
        access: Access::Rw,
        expires_at: None,
        prefix: None,
        ip_list: Vec::new(),
    }
}

fn widen() -> KeyRequest {
    KeyRequest::SetGrants {
        id: SEED.into(),
        grants: vec![rw("b_01"), rw("b_02")],
        acting: None,
    }
}

fn set_status(status: SubjectStatus) -> KeyRequest {
    KeyRequest::SetStatus {
        id: SEED.into(),
        status,
    }
}

/// Another call's widening of the seed principal under `rid` at `seq`.
fn their_widening(w: &World, table: &KeyTable, rid: Option<Rid>, seq: u64) -> Vec<u8> {
    let mut next = table.get(SEED).unwrap().subject().unwrap();
    next.set_grants(&[rw("b_01"), rw("b_03")]);
    seal_key_record_carrying(
        &w.kek,
        &w.ring,
        &w.t,
        seq,
        KeyOp::Grants,
        9,
        &next.door,
        Some(&next.private),
        false,
        None,
        rid,
        &mut TestRng(98),
    )
    .unwrap()
}

fn reserved_at(answer: &KeptAnswer, keys_seq: u64) -> Reserved<'_> {
    Reserved {
        rid: answer.rid,
        keys_seq,
        answer,
    }
}

/// A widening under a reservation: the record is exactly `keys_seq + 1`,
/// carries the `rid`, reaches every store, and the root unit keeps the
/// answer once, after the full apply. A retry writes nothing more.
#[tokio::test(flavor = "current_thread")]
async fn a_reserved_widening_records_exactly_keys_seq_plus_one_with_its_rid() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    assert_eq!(
        env.change_reserved(
            &mut table,
            &widen(),
            reserved_at(&answer, 1),
            &mut TestRng(2)
        )
        .await
        .unwrap(),
        ReservedAnswer::Done { seq: 2 }
    );
    assert_eq!(w.head(), 2);
    let bytes = w.store.raw(&key_chain(&w.t).name(2)).unwrap();
    let record = open_key_record(&w.kek, &w.ring, &w.t, 2, &bytes).unwrap();
    assert_eq!(record.rid, Some(RID));
    assert_eq!(record.op, KeyOp::Grants);
    assert_eq!(record.door.grants.len(), 2);
    for store in [&w.root, &w.unit2, &w.directory] {
        assert_eq!(store.seq.get(), 2, "{}", store.label);
        let row = store.row(SEED).unwrap();
        assert_eq!(row.door.grants.len(), 2, "{}", store.label);
        assert!(row.private.is_some(), "{}", store.label);
    }
    assert_eq!(*w.root.kept.borrow(), vec![(RID, 201)]);
    assert!(w.unit2.kept.borrow().is_empty());
    assert_eq!(*w.intents.sent.borrow(), vec![1, 2]);
    // The retry: its record wins, nothing is put, the answer is kept once.
    let puts = w.store.puts();
    assert_eq!(
        env.change_reserved(
            &mut table,
            &widen(),
            reserved_at(&answer, 1),
            &mut TestRng(3)
        )
        .await
        .unwrap(),
        ReservedAnswer::Done { seq: 2 }
    );
    assert_eq!(w.store.puts(), puts);
    assert_eq!(*w.root.kept.borrow(), vec![(RID, 201)]);
}

/// A re-enable under a reservation answers `503` until the unit's
/// reservation has an `Opening` for it (AM-72): nothing is put, no intent
/// is sent, no answer is kept.
#[tokio::test(flavor = "current_thread")]
async fn a_reserved_re_enable_answers_busy_until_the_unit_can_name_it() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let plain = env!(w, &w.store, &AtRoot(&w.root), &units);
    assert_eq!(
        plain
            .change(
                &mut table,
                "idem-off",
                &set_status(SubjectStatus::Disabled),
                &mut TestRng(2)
            )
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 2 }
    );
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let puts = w.store.puts();
    assert_eq!(
        env.change_reserved(
            &mut table,
            &set_status(SubjectStatus::Active),
            reserved_at(&answer, 2),
            &mut TestRng(3)
        )
        .await
        .unwrap(),
        ReservedAnswer::Busy
    );
    assert_eq!(w.store.puts(), puts);
    assert_eq!(w.head(), 2);
    assert_eq!(*w.intents.sent.borrow(), vec![1, 2]);
    assert!(w.root.kept.borrow().is_empty());
    assert_eq!(
        w.root.row(SEED).unwrap().door.status,
        SubjectStatus::Disabled
    );
}

/// The class comes from the head: a change that closes there (a
/// narrowing, a disable, a revoke, a dropped grant) is not a reserved
/// call, and one the head already states records nothing. Neither puts
/// anything or keeps an answer.
#[tokio::test(flavor = "current_thread")]
async fn a_closing_or_already_held_change_records_nothing_under_the_reservation() {
    for (request, expected) in [
        (
            KeyRequest::SetGrants {
                id: SEED.into(),
                grants: Vec::new(),
                acting: None,
            },
            ReservedAnswer::Closes,
        ),
        (set_status(SubjectStatus::Disabled), ReservedAnswer::Closes),
        (set_status(SubjectStatus::Revoked), ReservedAnswer::Closes),
        (
            KeyRequest::DropGrant {
                id: SEED.into(),
                bucket_id: "b_01".into(),
            },
            ReservedAnswer::Closes,
        ),
        // Already active: the head's state, not a re-enable.
        (
            set_status(SubjectStatus::Active),
            ReservedAnswer::InHead { seq: 1, done: true },
        ),
        (
            KeyRequest::SetGrants {
                id: SEED.into(),
                grants: vec![rw("b_01")],
                acting: None,
            },
            ReservedAnswer::InHead { seq: 1, done: true },
        ),
    ] {
        let w = World::new();
        let mut table = seed(&w).await;
        let units = [&w.root, &w.unit2];
        let env = env!(w, &w.store, &NoAdmission, &units);
        let answer = kept(RID);
        let puts = w.store.puts();
        assert_eq!(
            env.change_reserved(
                &mut table,
                &request,
                reserved_at(&answer, 1),
                &mut TestRng(2)
            )
            .await
            .unwrap(),
            expected,
            "{request:?}"
        );
        assert_eq!(w.store.puts(), puts, "{request:?}");
        assert_eq!(w.head(), 1);
        assert!(w.root.kept.borrow().is_empty());
        assert_eq!(*w.intents.sent.borrow(), vec![1], "{request:?}");
    }
}

/// A put lost to a record of the same `rid` takes that record; one lost
/// to any other record, or a head already past `keys_seq`, answers `Lost`
/// with the stores at the head.
#[tokio::test(flavor = "current_thread")]
async fn a_reserved_change_lost_to_its_own_rid_takes_it_and_to_another_answers_lost() {
    for (rid, expected) in [
        (Some(RID), ReservedAnswer::Done { seq: 2 }),
        (Some(OTHER), ReservedAnswer::Lost),
        (None, ReservedAnswer::Lost),
    ] {
        let w = World::new();
        let mut table = seed(&w).await;
        let theirs = their_widening(&w, &table, rid, 2);
        let store = PlantOnPut {
            inner: &w.store,
            name: key_chain(&w.t).name(2),
            theirs: RefCell::new(Some(theirs.clone())),
        };
        let units = [&w.root, &w.unit2];
        let env = env!(w, &store, &NoAdmission, &units);
        let answer = kept(RID);
        assert_eq!(
            env.change_reserved(
                &mut table,
                &widen(),
                reserved_at(&answer, 1),
                &mut TestRng(2)
            )
            .await
            .unwrap(),
            expected,
            "{rid:?}"
        );
        // Their bytes, never ours.
        assert_eq!(w.store.raw(&key_chain(&w.t).name(2)), Some(theirs));
        let bucket_ids: Vec<String> = table
            .get(SEED)
            .unwrap()
            .door
            .grants
            .iter()
            .map(|g| g.bucket_id.clone())
            .collect();
        assert_eq!(bucket_ids, ["b_01", "b_03"]);
        for store in [&w.root, &w.unit2, &w.directory] {
            assert_eq!(store.seq.get(), 2, "{}", store.label);
        }
        let kept_now = w.root.kept.borrow().clone();
        match expected {
            ReservedAnswer::Done { .. } => assert_eq!(kept_now, vec![(RID, 201)]),
            _ => assert!(kept_now.is_empty()),
        }
    }
    // A head already past keys_seq: nothing is put.
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let plain = env!(w, &w.store, &AtRoot(&w.root), &units);
    plain
        .change(
            &mut table,
            "idem-other",
            &KeyRequest::Create(principal(NEW, Some(SEED))),
            &mut TestRng(5),
        )
        .await
        .unwrap();
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let puts = w.store.puts();
    assert_eq!(
        env.change_reserved(
            &mut table,
            &widen(),
            reserved_at(&answer, 1),
            &mut TestRng(6)
        )
        .await
        .unwrap(),
        ReservedAnswer::Lost
    );
    assert_eq!(w.store.puts(), puts);
}

/// A record of the `rid` that names another subject, and a kept answer of
/// another reservation, are errors before anything is put.
#[tokio::test(flavor = "current_thread")]
async fn a_reserved_change_refuses_another_subjects_rid_and_another_answer() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &NoAdmission, &units);
    // The rid's record is a create of NEW at 2.
    let answer = kept(RID);
    assert_eq!(
        env.create_reserved(
            &mut table,
            &principal(NEW, Some(SEED)),
            reserved_at(&answer, 1),
            &mut TestRng(2)
        )
        .await
        .unwrap(),
        ReservedAnswer::Done { seq: 2 }
    );
    let puts = w.store.puts();
    assert!(env
        .change_reserved(
            &mut table,
            &widen(),
            reserved_at(&answer, 1),
            &mut TestRng(3)
        )
        .await
        .is_err());
    let other = kept(OTHER);
    let mismatched = Reserved {
        rid: RID,
        keys_seq: 2,
        answer: &other,
    };
    assert!(env
        .change_reserved(&mut table, &widen(), mismatched, &mut TestRng(4))
        .await
        .is_err());
    assert_eq!(w.store.puts(), puts);
}

/// The move rules stop a reserved change before any put (AM-28, AM-31):
/// `moving` answers `Busy`, and the undo's `d1` answers `key_moved`.
#[tokio::test(flavor = "current_thread")]
async fn the_move_rules_stop_a_reserved_change_before_any_put() {
    use velmora_bridge::keys::gate::ZeroHead;
    let t = TenantId::parse("t_0000000000000001").unwrap();
    for (zero, expected) in [
        (ZeroHead::Moving { to: t.clone() }, ReservedAnswer::Busy),
        (ZeroHead::Undone { to: t.clone() }, ReservedAnswer::KeyMoved),
    ] {
        let w = World::new();
        let mut table = seed(&w).await;
        w.gate.set_zero(zero);
        let units = [&w.root, &w.unit2];
        let env = env!(w, &w.store, &NoAdmission, &units);
        let answer = kept(RID);
        let puts = w.store.puts();
        assert_eq!(
            env.change_reserved(
                &mut table,
                &widen(),
                reserved_at(&answer, 1),
                &mut TestRng(2)
            )
            .await
            .unwrap(),
            expected
        );
        assert_eq!(w.store.puts(), puts);
        assert_eq!(*w.intents.sent.borrow(), vec![1]);
    }
}

/// A create sent through `change_reserved` is `create_reserved`.
#[tokio::test(flavor = "current_thread")]
async fn a_create_through_change_reserved_is_the_reserved_create() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    assert_eq!(
        env.change_reserved(
            &mut table,
            &KeyRequest::Create(principal(NEW, Some(SEED))),
            reserved_at(&answer, 1),
            &mut TestRng(2)
        )
        .await
        .unwrap(),
        ReservedAnswer::Done { seq: 2 }
    );
    let record = open_key_record(
        &w.kek,
        &w.ring,
        &w.t,
        2,
        &w.store.raw(&key_chain(&w.t).name(2)).unwrap(),
    )
    .unwrap();
    assert_eq!((record.op, record.rid), (KeyOp::Create, Some(RID)));
}

/// Review r1 of L4-W2: the class comes from the head whatever `keys_seq`
/// is. A closing change with a reservation behind the head answers
/// `Closes` (never `Lost`); an in-head answer names the subject's own
/// newest record, not the chain head.
#[tokio::test(flavor = "current_thread")]
async fn the_class_and_the_in_head_seq_come_from_the_head_whatever_keys_seq() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    let plain = env!(w, &w.store, &AtRoot(&w.root), &units);
    plain
        .change(
            &mut table,
            "idem-other",
            &KeyRequest::Create(principal(NEW, Some(SEED))),
            &mut TestRng(5),
        )
        .await
        .unwrap();
    assert_eq!(w.head(), 2);
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let puts = w.store.puts();
    let narrow = KeyRequest::SetGrants {
        id: SEED.into(),
        grants: Vec::new(),
        acting: None,
    };
    assert_eq!(
        env.change_reserved(
            &mut table,
            &narrow,
            reserved_at(&answer, 1),
            &mut TestRng(6)
        )
        .await
        .unwrap(),
        ReservedAnswer::Closes
    );
    let same = KeyRequest::SetGrants {
        id: SEED.into(),
        grants: vec![rw("b_01")],
        acting: None,
    };
    for keys_seq in [1, 2] {
        assert_eq!(
            env.change_reserved(
                &mut table,
                &same,
                reserved_at(&answer, keys_seq),
                &mut TestRng(7)
            )
            .await
            .unwrap(),
            ReservedAnswer::InHead { seq: 1, done: true }
        );
    }
    assert_eq!(w.store.puts(), puts);
    // An opening change behind the head is still `Lost`.
    assert_eq!(
        env.change_reserved(
            &mut table,
            &widen(),
            reserved_at(&answer, 1),
            &mut TestRng(8)
        )
        .await
        .unwrap(),
        ReservedAnswer::Lost
    );
    assert_eq!(w.store.puts(), puts);
}

/// Review r1 of L4-W2 (MEDIUM): `change_closing` records a closing change
/// and never an opening one. A change classed `Closes` at an older head
/// that a newer head makes a widening answers `Busy`, with nothing put and
/// nothing admitted; the caller's retry reserves again.
#[tokio::test(flavor = "current_thread")]
async fn change_closing_never_records_an_opening_change() {
    let w = World::new();
    let mut table = seed(&w).await;
    let units = [&w.root, &w.unit2];
    // The seed principal holds b_01 and b_02.
    let plain = env!(w, &w.store, &AtRoot(&w.root), &units);
    assert_eq!(
        plain
            .change(&mut table, "idem-w", &widen(), &mut TestRng(2))
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 2 }
    );
    let env = env!(w, &w.store, &NoAdmission, &units);
    let answer = kept(RID);
    let to_a = KeyRequest::SetGrants {
        id: SEED.into(),
        grants: vec![rw("b_01")],
        acting: None,
    };
    assert_eq!(
        env.change_reserved(&mut table, &to_a, reserved_at(&answer, 2), &mut TestRng(3))
            .await
            .unwrap(),
        ReservedAnswer::Closes
    );
    // A concurrent narrowing to b_02 only lands first.
    let to_b = KeyRequest::SetGrants {
        id: SEED.into(),
        grants: vec![rw("b_02")],
        acting: None,
    };
    let mut other = table.clone();
    assert_eq!(
        env.change_closing(&mut other, &to_b, &mut TestRng(4))
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    // Against that head, b_01 alone is a widening: nothing is recorded.
    let puts = w.store.puts();
    assert_eq!(
        env.change_closing(&mut table, &to_a, &mut TestRng(5))
            .await
            .unwrap(),
        KeyAnswer::Busy
    );
    assert_eq!(w.store.puts(), puts);
    assert_eq!(w.head(), 3);
    // A disable through it is recorded at the head + 1.
    assert_eq!(
        env.change_closing(
            &mut table,
            &set_status(SubjectStatus::Disabled),
            &mut TestRng(6)
        )
        .await
        .unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
}
