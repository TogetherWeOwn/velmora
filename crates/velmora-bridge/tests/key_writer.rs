//! The record-first key writer and the finisher, against fake units, a
//! fake directory, a fake reservation call and fake intents.
//!
//! What these tests hold:
//! - every change is in the chain before any store has it;
//! - a closing change takes effect in the units with the directory down;
//! - a change whose record is written reaches every store through the
//!   finisher, whatever step it stopped at (the crash between the
//!   revocation record and the chain record among them);
//! - a key is never recorded against a grant that an earlier record has
//!   already narrowed;
//! - an opening change with no reservation writes nothing.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::crypto::scheme2::{wrap_secret_v2, TenantId, TenantKey};
use velmora_bridge::keys::chain::Put;
use velmora_bridge::keys::checkpoint::{list_checkpoints, read_key_chain};
use velmora_bridge::keys::ports::{
    Admission, ControlChain, ControlIntents, KeyAdmission, KeyTarget, OpeningChange, Refusal,
};
use velmora_bridge::keys::record::{
    grant_within, key_chain, open_key_record, seal_key_record, Access, Entry, Grant, KeyOp, OneKey,
    Subject, SubjectDoor, SubjectKind, SubjectPrivate, SubjectStatus,
};
use velmora_bridge::keys::revocations::{put_tenant_revocation, tenant_revocation_name};
use velmora_bridge::keys::routes::{put_route, read_route, RoutePut};
use velmora_bridge::keys::store::{MemRecords, RecordStore};
use velmora_bridge::keys::writer::{finish_keys, KeyAnswer, KeyEnv, KeyRequest};
use velmora_bridge::testkit::{FixedClock, TestKek};
use velmora_bridge::{BridgeError, Result, UnixMs};

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

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

/// A store that holds a copy of the key table: a unit or the directory.
struct FakeTarget {
    label: &'static str,
    seq: Cell<u64>,
    rows: RefCell<BTreeMap<String, Entry>>,
    down: Cell<bool>,
    applies: Cell<u32>,
}

impl FakeTarget {
    fn new(label: &'static str) -> Self {
        FakeTarget {
            label,
            seq: Cell::new(0),
            rows: RefCell::new(BTreeMap::new()),
            down: Cell::new(false),
            applies: Cell::new(0),
        }
    }

    fn status(&self, id: &str) -> Option<SubjectStatus> {
        self.rows.borrow().get(id).map(Entry::effective_status)
    }

    fn row(&self, id: &str) -> Option<Entry> {
        self.rows.borrow().get(id).cloned()
    }

    /// The store lost what it held (a restore to an empty point).
    fn reset(&self) {
        self.seq.set(0);
        self.rows.borrow_mut().clear();
    }
}

impl KeyTarget for FakeTarget {
    fn label(&self) -> &str {
        self.label
    }

    async fn keys_seq(&self) -> Result<u64> {
        if self.down.get() {
            return Err(BridgeError::Sql("fake: down".into()));
        }
        Ok(self.seq.get())
    }

    async fn closed(&self) -> Result<Vec<String>> {
        if self.down.get() {
            return Err(BridgeError::Sql("fake: down".into()));
        }
        Ok(self
            .rows
            .borrow()
            .values()
            .filter(|e| e.private.is_none() && e.door.status != SubjectStatus::Revoked)
            .map(|e| e.door.id.clone())
            .collect())
    }

    /// As the port says: per subject, in chain order.
    async fn apply(&self, to_seq: u64, entries: &[Entry]) -> Result<()> {
        if self.down.get() {
            return Err(BridgeError::Sql("fake: down".into()));
        }
        self.applies.set(self.applies.get() + 1);
        let mut rows = self.rows.borrow_mut();
        for e in entries {
            let was_revoked = rows
                .get(&e.door.id)
                .is_some_and(|r| r.door.status == SubjectStatus::Revoked);
            let replace = match rows.get(&e.door.id) {
                None => true,
                Some(r) => {
                    e.last_seq > r.last_seq
                        || (e.last_seq == r.last_seq && r.private.is_none() && e.private.is_some())
                }
            };
            if replace {
                let mut row = e.clone();
                if was_revoked {
                    row.door.status = SubjectStatus::Revoked;
                }
                rows.insert(e.door.id.clone(), row);
            } else if e.door.status == SubjectStatus::Revoked {
                if let Some(r) = rows.get_mut(&e.door.id) {
                    r.door.status = SubjectStatus::Revoked;
                }
            }
        }
        self.seq.set(self.seq.get().max(to_seq));
        Ok(())
    }
}

/// The root unit's reservation call, checked against the root fake.
struct FakeAdmission<'a> {
    root: &'a FakeTarget,
    cap: usize,
    calls: Cell<u32>,
    refuse: Cell<Option<Refusal>>,
    /// Answers this `keys_seq` instead of the root's.
    stale: Cell<Option<u64>>,
    /// Runs once, inside the first call, before the answer is computed:
    /// another writer's record lands between the reservation and the put.
    race: RefCell<Option<Box<dyn FnOnce() -> u64 + 'a>>>,
}

impl<'a> FakeAdmission<'a> {
    fn new(root: &'a FakeTarget) -> Self {
        FakeAdmission {
            root,
            cap: 20,
            calls: Cell::new(0),
            refuse: Cell::new(None),
            stale: Cell::new(None),
            race: RefCell::new(None),
        }
    }
}

fn joined(e: &Entry) -> Vec<Grant> {
    e.subject().map(|s| s.grants()).unwrap_or_default()
}

impl KeyAdmission for FakeAdmission<'_> {
    async fn admit(
        &self,
        _tenant: &TenantId,
        _idempotency_key: &str,
        change: &OpeningChange<'_>,
    ) -> Result<Admission> {
        self.calls.set(self.calls.get() + 1);
        // The answer is computed from the root as it is now; a race runs
        // after it, so the answer is stale by the time the writer puts.
        let seq = self.root.seq.get();
        let answer = self.decide(change, seq);
        if let Some(race) = self.race.borrow_mut().take() {
            race();
        }
        Ok(answer)
    }
}

impl FakeAdmission<'_> {
    fn decide(&self, change: &OpeningChange<'_>, seq: u64) -> Admission {
        if let Some(r) = self.refuse.get() {
            return Admission::Refused(r);
        }
        let rows = self.root.rows.borrow();
        let keys = rows
            .values()
            .filter(|e| e.door.kind == SubjectKind::S3 && e.door.status != SubjectStatus::Revoked)
            .count();
        if change.op == KeyOp::Create
            && change.subject.door.kind == SubjectKind::S3
            && keys >= self.cap
        {
            return Admission::Refused(Refusal::CapFull);
        }
        if let Some(p) = change.acting {
            let Some(principal) = rows.get(p) else {
                return Admission::Refused(Refusal::NotSubset);
            };
            let outer = joined(principal);
            let within = change
                .subject
                .grants()
                .iter()
                .all(|g| outer.iter().any(|o| grant_within(g, o)));
            if principal.effective_status() != SubjectStatus::Active || !within {
                return Admission::Refused(Refusal::NotSubset);
            }
        }
        Admission::Admitted {
            keys_seq: self.stale.get().unwrap_or(seq),
        }
    }
}

#[derive(Default)]
struct FakeIntents {
    sent: RefCell<Vec<u64>>,
    /// The pending rows, as the directory would hold them.
    notes: RefCell<Vec<(u64, String)>>,
    /// Every row ever written.
    noted: RefCell<Vec<(u64, String)>>,
    cleared: RefCell<Vec<u64>>,
    fail_send: Cell<bool>,
    /// The directory is down: the `pending_ops` row cannot be written.
    fail_note: Cell<bool>,
}

impl ControlIntents for FakeIntents {
    async fn send(&self, _t: &TenantId, chain: ControlChain, seq: u64) -> Result<()> {
        assert_eq!(chain, ControlChain::Keys);
        if self.fail_send.get() {
            return Err(BridgeError::Queue("fake: down".into()));
        }
        self.sent.borrow_mut().push(seq);
        Ok(())
    }

    async fn note(&self, _t: &TenantId, _c: ControlChain, seq: u64, kind: &str) -> Result<()> {
        if self.fail_note.get() {
            return Err(BridgeError::Sql("fake: directory down".into()));
        }
        self.notes.borrow_mut().push((seq, kind.to_owned()));
        self.noted.borrow_mut().push((seq, kind.to_owned()));
        Ok(())
    }

    /// Clears every row at or below `seq`.
    async fn clear(&self, _t: &TenantId, _c: ControlChain, seq: u64) -> Result<()> {
        if self.fail_note.get() {
            return Err(BridgeError::Sql("fake: directory down".into()));
        }
        self.cleared.borrow_mut().push(seq);
        self.notes.borrow_mut().retain(|(s, _)| *s > seq);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

fn tenant(n: u8) -> TenantId {
    TenantId::parse(&format!("t_00000000000000{n:02x}")).unwrap()
}

fn kek() -> TestKek {
    TestKek::with_versions(1, &[(1, derived("kek"))])
}

fn ring(t: &TenantId) -> OneKey {
    OneKey(TenantKey::from_bytes(t, 1, derived("tk")).unwrap())
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

fn s3_key(t: &TenantId, id: &str, made_by: &str, grants: &[Grant]) -> Subject {
    let mut s = subject(id, SubjectKind::S3, Some(made_by), grants);
    let (v, wrapped) = wrap_secret_v2(
        &kek(),
        t,
        id,
        format!("secret-of-{id}").as_bytes(),
        &mut TestRng(7),
    )
    .unwrap();
    s.door.secret_kek_version = Some(v);
    s.private.secret_wrapped = Some(wrapped);
    s
}

struct World {
    t: TenantId,
    store: MemRecords,
    kek: TestKek,
    ring: OneKey,
    root: FakeTarget,
    unit2: FakeTarget,
    directory: FakeTarget,
    intents: FakeIntents,
    clock: FixedClock,
}

impl World {
    fn new() -> Self {
        let t = tenant(1);
        World {
            ring: ring(&t),
            t,
            store: MemRecords::new(),
            kek: kek(),
            root: FakeTarget::new("root"),
            unit2: FakeTarget::new("unit 2"),
            directory: FakeTarget::new("directory"),
            intents: FakeIntents::default(),
            clock: FixedClock::new(UnixMs(1_700_000_000_000)),
        }
    }

    fn units(&self) -> [&FakeTarget; 2] {
        [&self.root, &self.unit2]
    }

    /// The head, by the names stored under the chain's prefix.
    fn head(&self) -> u64 {
        self.store.names_under(key_chain(&self.t).prefix()).len() as u64
    }
}

/// The key table every test starts from.
fn table(w: &World) -> velmora_bridge::keys::record::KeyTable {
    velmora_bridge::keys::record::KeyTable::empty(w.t.clone())
}

macro_rules! env {
    ($w:expr, $adm:expr, $units:expr) => {
        KeyEnv {
            store: &$w.store,
            kek: &$w.kek,
            ring: &$w.ring,
            tenant: &$w.t,
            admission: $adm,
            intents: &$w.intents,
            units: $units,
            directory: &&$w.directory,
            clock: &$w.clock,
        }
    };
}

impl KeyTarget for &FakeTarget {
    fn label(&self) -> &str {
        self.label
    }
    async fn keys_seq(&self) -> Result<u64> {
        KeyTarget::keys_seq(*self).await
    }
    async fn closed(&self) -> Result<Vec<String>> {
        KeyTarget::closed(*self).await
    }
    async fn apply(&self, to_seq: u64, entries: &[Entry]) -> Result<()> {
        KeyTarget::apply(*self, to_seq, entries).await
    }
}

const RW: Access = Access::Rw;
const RO: Access = Access::Ro;

/// A principal PR0001 with `rw` on b_01, and key AKVL0001 under it with
/// `ro` on b_01: seqs 1 and 2.
async fn seed(w: &World, adm: &FakeAdmission<'_>) -> velmora_bridge::keys::record::KeyTable {
    let units = w.units();
    let env = env!(w, adm, &units);
    let mut table = table(w);
    let p = principal("PR0001", &[grant("b_01", RW, None)]);
    let k = s3_key(&w.t, "AKVL0001", "PR0001", &[grant("b_01", RO, None)]);
    let mut rng = TestRng(1);
    assert_eq!(
        env.change(&mut table, "idem-p", &KeyRequest::Create(p), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 1 }
    );
    assert_eq!(
        env.change(&mut table, "idem-k", &KeyRequest::Create(k), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 2 }
    );
    table
}

fn revoke(id: &str) -> KeyRequest {
    KeyRequest::SetStatus {
        id: id.to_owned(),
        status: SubjectStatus::Revoked,
    }
}

fn disable(id: &str) -> KeyRequest {
    KeyRequest::SetStatus {
        id: id.to_owned(),
        status: SubjectStatus::Disabled,
    }
}

fn enable(id: &str) -> KeyRequest {
    KeyRequest::SetStatus {
        id: id.to_owned(),
        status: SubjectStatus::Active,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn a_new_key_is_in_the_chain_first_and_then_in_every_store() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    seed(&w, &adm).await;

    assert_eq!(w.head(), 2);
    assert_eq!(adm.calls.get(), 2);
    let route = read_route(&w.store, &w.kek, "AKVL0001")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(route.tenant, w.t.as_str());
    assert_eq!(route.kind, SubjectKind::S3);
    // A principal has no route: it has no secret and signs nothing.
    assert!(read_route(&w.store, &w.kek, "PR0001")
        .await
        .unwrap()
        .is_none());
    for store in [&w.root, &w.unit2, &w.directory] {
        assert_eq!(store.seq.get(), 2, "{}", store.label);
        assert_eq!(store.status("AKVL0001"), Some(SubjectStatus::Active));
        assert_eq!(store.status("PR0001"), Some(SubjectStatus::Active));
    }
    // The secret reaches the stores as it was recorded.
    let row = w.root.row("AKVL0001").unwrap();
    assert!(row.private.unwrap().secret_wrapped.is_some());
    assert_eq!(*w.intents.sent.borrow(), vec![1, 2]);
    assert_eq!(*w.intents.cleared.borrow(), vec![1, 2]);
    assert_eq!(w.intents.noted.borrow()[1].1, "key.create");
    assert!(w.intents.notes.borrow().is_empty(), "every row cleared");
}

#[tokio::test(flavor = "current_thread")]
async fn closing_changes_take_effect_with_the_directory_down() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    w.directory.down.set(true);
    w.intents.fail_note.set(true);
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(2);
    let calls = adm.calls.get();

    // Narrow, disable, revoke: each answers Done and is in force in the
    // units; none asks for a reservation.
    let narrower = KeyRequest::SetGrants {
        id: "AKVL0001".into(),
        grants: vec![grant("b_01", RO, Some("photos/"))],
        acting: None,
    };
    assert_eq!(
        env.change(&mut table, "i1", &narrower, &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert_eq!(
        env.change(&mut table, "i2", &disable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
    assert_eq!(
        env.change(&mut table, "i3", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 5 }
    );
    assert_eq!(adm.calls.get(), calls);
    assert_eq!(w.root.status("AKVL0001"), Some(SubjectStatus::Revoked));
    assert_eq!(w.unit2.status("AKVL0001"), Some(SubjectStatus::Revoked));
    // The revocation record exists beside the chain record.
    assert!(w
        .store
        .exists(&tenant_revocation_name(&w.t, "AKVL0001"))
        .await
        .unwrap());
    // The directory got nothing, and no pending row could be written.
    assert_eq!(w.directory.seq.get(), 2);
    assert!(w.intents.notes.borrow().iter().all(|(s, _)| *s <= 2));
    // The narrowed grant reached the units with its prefix.
    let narrowed = w.root.row("AKVL0001").unwrap();
    assert_eq!(
        narrowed.private.unwrap().grants[0].prefix.as_deref(),
        Some("photos/")
    );

    // The directory comes back: the finisher brings it up.
    w.directory.down.set(false);
    w.intents.fail_note.set(false);
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(report.failed.is_empty(), "{report:?}");
    assert_eq!(w.directory.seq.get(), 5);
    assert_eq!(w.directory.status("AKVL0001"), Some(SubjectStatus::Revoked));
}

#[tokio::test(flavor = "current_thread")]
async fn a_closing_change_with_a_unit_down_answers_unfinished_until_finished() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(3);

    w.unit2.down.set(true);
    assert_eq!(
        env.change(&mut table, "i", &disable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Unfinished { seq: 3 }
    );
    // The root unit is closed already; the other one is not.
    assert_eq!(w.root.status("AKVL0001"), Some(SubjectStatus::Disabled));
    assert_eq!(w.unit2.status("AKVL0001"), Some(SubjectStatus::Active));
    // The pending row stays for the sweep.
    assert!(!w.intents.cleared.borrow().contains(&3));

    // A finisher run while it is still down reports it, and the queue
    // retries.
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert_eq!(report.failed, vec!["unit 2".to_owned()]);
    w.unit2.down.set(false);
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(report.failed.is_empty());
    assert_eq!(report.head, 3);
    assert_eq!(w.unit2.status("AKVL0001"), Some(SubjectStatus::Disabled));
    assert!(w.intents.cleared.borrow().contains(&3));
}

/// The crash between the `m/rk/` put and the chain record: the key is
/// refused once the finisher has run, and the chain holds the revoke
/// record afterwards.
#[tokio::test(flavor = "current_thread")]
async fn a_revoke_that_stopped_after_its_revocation_record_is_completed() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(4);

    let chain_dir = format!("m/k/{}/", w.t);
    w.store.refuse(&chain_dir);
    assert!(env
        .change(&mut table, "i", &revoke("AKVL0001"), &mut rng)
        .await
        .is_err());
    w.store.allow(&chain_dir);
    // The revocation is written, the chain record is not, and no store
    // has applied anything yet.
    assert!(w
        .store
        .exists(&tenant_revocation_name(&w.t, "AKVL0001"))
        .await
        .unwrap());
    assert_eq!(w.head(), 2);
    assert_eq!(w.root.status("AKVL0001"), Some(SubjectStatus::Active));
    // The intent was sent before anything else.
    assert_eq!(w.intents.sent.borrow().last(), Some(&3));

    // The message's consumer (the finisher) completes it.
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert_eq!(report.appended, vec![3]);
    assert_eq!(report.head, 3);
    for store in [&w.root, &w.unit2, &w.directory] {
        assert_eq!(store.status("AKVL0001"), Some(SubjectStatus::Revoked));
    }
    let bytes = key_chain(&w.t).get(&w.store, 3).await.unwrap();
    let record = open_key_record(&w.kek, &w.ring, &w.t, 3, &bytes).unwrap();
    assert_eq!(record.op, KeyOp::Status);
    assert_eq!(record.door.status, SubjectStatus::Revoked);
    // A second run changes nothing.
    let again = finish_keys(&env, &mut rng).await.unwrap();
    assert!(again.appended.is_empty());
    assert_eq!(again.head, 3);
}

/// A revocation that reached `m/rk/` only is in force at a store even
/// before its chain record exists: the stores apply every listed
/// revocation.
#[tokio::test(flavor = "current_thread")]
async fn a_revocation_overrides_the_chain_in_every_store() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(5);
    put_tenant_revocation(&w.store, &w.kek, &w.t, "AKVL0001", 5, &mut rng)
        .await
        .unwrap();
    // An unrelated change brings the override along.
    let other = s3_key(&w.t, "AKVL0002", "PR0001", &[grant("b_01", RO, None)]);
    assert_eq!(
        env.change(&mut table, "i", &KeyRequest::Create(other), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert_eq!(w.root.status("AKVL0001"), Some(SubjectStatus::Revoked));
    assert_eq!(w.unit2.status("AKVL0001"), Some(SubjectStatus::Revoked));
    // The chain still says active until the finisher appends the record.
    assert_eq!(
        table.get("AKVL0001").unwrap().door.status,
        SubjectStatus::Active
    );
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert_eq!(report.appended, vec![4]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_crash_after_the_record_is_finished_by_the_finisher() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(6);
    w.root.down.set(true);
    w.unit2.down.set(true);
    assert_eq!(
        env.change(&mut table, "i", &disable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Unfinished { seq: 3 }
    );
    w.root.down.set(false);
    w.unit2.down.set(false);
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(report.failed.is_empty());
    for store in [&w.root, &w.unit2, &w.directory] {
        assert_eq!(store.status("AKVL0001"), Some(SubjectStatus::Disabled));
    }
}

/// A closing call whose effect the head already carries writes no
/// record, applies the head to every store, and never answers Done while
/// a store cannot be reached.
#[tokio::test(flavor = "current_thread")]
async fn a_closing_call_already_in_the_head_still_reaches_every_store() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(7);
    assert_eq!(
        env.change(&mut table, "i", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    // The root unit lost what it held (a restore to an empty point).
    w.root.reset();
    w.root.down.set(true);
    let puts = w.store.puts();
    assert_eq!(
        env.change(&mut table, "i", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Unfinished { seq: 3 }
    );
    w.root.down.set(false);
    assert_eq!(
        env.change(&mut table, "i", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert_eq!(w.head(), 3);
    assert_eq!(w.store.puts(), puts, "no record, no revocation was written");
    assert_eq!(w.root.status("AKVL0001"), Some(SubjectStatus::Revoked));
    assert_eq!(w.root.seq.get(), 3);
}

/// Two orders of a key creation and a narrowing of its principal.
#[tokio::test(flavor = "current_thread")]
async fn a_key_is_never_recorded_wider_than_its_principal_at_its_seq() {
    // (a) The narrowing is recorded between the reservation and the put:
    // the create loses its seq, asks again at the new head and is refused.
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let narrowing = {
        let w = &w;
        move || {
            let mut p = principal("PR0001", &[grant("b_01", RO, None)]);
            p.door.created_at = 1_000;
            let bytes = seal_key_record(
                &w.kek,
                &w.ring,
                &w.t,
                3,
                KeyOp::Grants,
                9,
                &p.door,
                Some(&p.private),
                true,
                &mut TestRng(99),
            )
            .unwrap();
            w.store.plant(&key_chain(&w.t).name(3), bytes.clone());
            // The writer of the narrowing applied it to the root unit.
            let record = open_key_record(&w.kek, &w.ring, &w.t, 3, &bytes).unwrap();
            let mut rows = w.root.rows.borrow_mut();
            rows.insert(
                "PR0001".into(),
                Entry {
                    door: record.door,
                    private: record.private,
                    last_seq: 3,
                    private_seq: 3,
                    tk_version: 1,
                    closes: true,
                },
            );
            w.root.seq.set(3);
            3
        }
    };
    *adm.race.borrow_mut() = Some(Box::new(narrowing));
    let units = w.units();
    let env = env!(w, &adm, &units);
    let wide = s3_key(&w.t, "AKVL0009", "PR0001", &[grant("b_01", RW, None)]);
    let answer = env
        .change(&mut table, "i", &KeyRequest::Create(wide), &mut TestRng(8))
        .await
        .unwrap();
    assert_eq!(answer, KeyAnswer::Refused(Refusal::NotSubset));
    assert_eq!(
        adm.calls.get(),
        5,
        "seed 2, then the lost try, the retry, and one ask after a catch-up"
    );
    assert_eq!(w.head(), 3);
    let read = read_key_chain(&w.store, &w.kek, &w.ring, &w.t)
        .await
        .unwrap();
    assert!(read.table.get("AKVL0009").is_none());
    assert!(w.root.row("AKVL0009").is_none());

    // (b) The create is recorded first: the key exists with `made_by`,
    // and the narrowing that follows is recorded after it, so the unit
    // applies both in seq order and serves the key by the narrower grant.
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(9);
    let wide = s3_key(&w.t, "AKVL0009", "PR0001", &[grant("b_01", RW, None)]);
    assert_eq!(
        env.change(&mut table, "i", &KeyRequest::Create(wide), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    let narrow = KeyRequest::SetGrants {
        id: "PR0001".into(),
        grants: vec![grant("b_01", RO, None)],
        acting: None,
    };
    assert_eq!(
        env.change(&mut table, "j", &narrow, &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
    let key = w.root.row("AKVL0009").unwrap();
    assert_eq!(key.door.made_by.as_deref(), Some("PR0001"));
    assert!(key.last_seq < w.root.row("PR0001").unwrap().last_seq);
}

#[tokio::test(flavor = "current_thread")]
async fn an_opening_change_without_a_reservation_writes_nothing() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let sent = w.intents.sent.borrow().len();
    let puts = w.store.puts();
    for refusal in [Refusal::CapFull, Refusal::NotSubset] {
        adm.refuse.set(Some(refusal));
        let key = s3_key(&w.t, "AKVL0003", "PR0001", &[grant("b_01", RO, None)]);
        assert_eq!(
            env.change(&mut table, "i", &KeyRequest::Create(key), &mut TestRng(10))
                .await
                .unwrap(),
            KeyAnswer::Refused(refusal)
        );
    }
    assert_eq!(w.head(), 2);
    assert_eq!(w.store.puts(), puts, "no route, no record");
    assert_eq!(w.intents.sent.borrow().len(), sent, "no intent");
    assert!(read_route(&w.store, &w.kek, "AKVL0003")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn the_cap_is_counted_by_the_reservation() {
    let w = World::new();
    let mut adm = FakeAdmission::new(&w.root);
    adm.cap = 1;
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let key = s3_key(&w.t, "AKVL0002", "PR0001", &[grant("b_01", RO, None)]);
    assert_eq!(
        env.change(&mut table, "i", &KeyRequest::Create(key), &mut TestRng(11))
            .await
            .unwrap(),
        KeyAnswer::Refused(Refusal::CapFull)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_reservation_that_never_matches_the_head_answers_busy() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let puts = w.store.puts();
    for stale in [1, 7] {
        adm.stale.set(Some(stale));
        let calls = adm.calls.get();
        let key = s3_key(&w.t, "AKVL0003", "PR0001", &[grant("b_01", RO, None)]);
        assert_eq!(
            env.change(&mut table, "i", &KeyRequest::Create(key), &mut TestRng(12))
                .await
                .unwrap(),
            KeyAnswer::Busy
        );
        assert_eq!(adm.calls.get() - calls, 3);
    }
    assert_eq!(w.head(), 2);
    assert_eq!(w.store.puts(), puts);
}

#[tokio::test(flavor = "current_thread")]
async fn an_opening_change_with_the_directory_down_opens_no_unit_until_finished() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(13);
    w.directory.down.set(true);
    let key = s3_key(&w.t, "AKVL0002", "PR0001", &[grant("b_01", RO, None)]);
    assert_eq!(
        env.change(&mut table, "i", &KeyRequest::Create(key), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Unfinished { seq: 3 }
    );
    // With the directory down, the units hold the key closed.
    for unit in [&w.root, &w.unit2] {
        assert_eq!(unit.status("AKVL0002"), Some(SubjectStatus::Disabled));
        assert_eq!(unit.seq.get(), 3);
    }
    w.directory.down.set(false);
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(report.failed.is_empty());
    for store in [&w.root, &w.unit2, &w.directory] {
        assert_eq!(store.status("AKVL0002"), Some(SubjectStatus::Active));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_key_id_routed_to_another_tenant_is_refused() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(14);
    assert_eq!(
        put_route(
            &w.store,
            &w.kek,
            &tenant(2),
            "AKVL0007",
            SubjectKind::S3,
            1,
            &mut rng
        )
        .await
        .unwrap(),
        RoutePut::Ours
    );
    let key = s3_key(&w.t, "AKVL0007", "PR0001", &[grant("b_01", RO, None)]);
    assert_eq!(
        env.change(&mut table, "i", &KeyRequest::Create(key), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Refused(Refusal::IdTaken)
    );
    assert_eq!(w.head(), 2);
    assert_eq!(
        read_route(&w.store, &w.kek, "AKVL0007")
            .await
            .unwrap()
            .unwrap()
            .tenant,
        tenant(2).as_str()
    );
}

/// The writer classes a grant change from the head: a narrowing is
/// closing and asks for no reservation; anything else is a widening.
#[tokio::test(flavor = "current_thread")]
async fn a_widening_needs_a_reservation_and_a_narrowing_does_not() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(15);
    let set = |grants: Vec<Grant>| KeyRequest::SetGrants {
        id: "AKVL0001".into(),
        grants,
        acting: Some("PR0001".into()),
    };
    // Drop the prefix-free grant for one with a prefix: narrower.
    let calls = adm.calls.get();
    assert_eq!(
        env.change(
            &mut table,
            "a",
            &set(vec![grant("b_01", RO, Some("x/"))]),
            &mut rng
        )
        .await
        .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert_eq!(adm.calls.get(), calls);
    // Narrower in the prefix but wider in access: a widening. PR0001 has
    // rw on b_01, so it is admitted.
    assert_eq!(
        env.change(
            &mut table,
            "b",
            &set(vec![grant("b_01", RW, Some("x/y/"))]),
            &mut rng
        )
        .await
        .unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
    assert_eq!(adm.calls.get(), calls + 1);
    // Adding a bucket the principal does not hold: refused, no record.
    assert_eq!(
        env.change(
            &mut table,
            "c",
            &set(vec![
                grant("b_01", RW, Some("x/y/")),
                grant("b_02", RO, None)
            ]),
            &mut rng
        )
        .await
        .unwrap(),
        KeyAnswer::Refused(Refusal::NotSubset)
    );
    assert_eq!(w.head(), 4);
    // The same grants again: already in the head.
    assert_eq!(
        env.change(
            &mut table,
            "d",
            &set(vec![grant("b_01", RW, Some("x/y/"))]),
            &mut rng
        )
        .await
        .unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
}

#[tokio::test(flavor = "current_thread")]
async fn changes_the_head_does_not_admit_are_refused() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(16);
    // Unknown subject.
    assert_eq!(
        env.change(&mut table, "a", &disable("AKVLNONE"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Refused(Refusal::NotFound)
    );
    // The same id with other content. (The same content again is a
    // retry: see the test of retried creates.)
    let again = s3_key(&w.t, "AKVL0001", "PR0001", &[grant("b_01", RW, None)]);
    assert_eq!(
        env.change(&mut table, "b", &KeyRequest::Create(again), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Refused(Refusal::Conflict)
    );
    // A key under a principal that does not exist.
    let orphan = s3_key(&w.t, "AKVL0005", "PR9999", &[grant("b_01", RO, None)]);
    assert_eq!(
        env.change(&mut table, "c", &KeyRequest::Create(orphan), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Refused(Refusal::Conflict)
    );
    // Revoked is final.
    assert_eq!(
        env.change(&mut table, "d", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert_eq!(
        env.change(&mut table, "e", &enable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Refused(Refusal::Conflict)
    );
    assert_eq!(w.head(), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn an_intent_that_cannot_be_sent_stops_the_change_before_its_record() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    w.intents.fail_send.set(true);
    assert!(env
        .change(&mut table, "i", &revoke("AKVL0001"), &mut TestRng(17))
        .await
        .is_err());
    assert_eq!(w.head(), 2);
    assert!(!w
        .store
        .exists(&tenant_revocation_name(&w.t, "AKVL0001"))
        .await
        .unwrap());
}

/// A stale cached table (another isolate wrote since) is brought to the
/// head before the change is validated.
#[tokio::test(flavor = "current_thread")]
async fn a_stale_cached_table_is_brought_to_the_head_first() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut fresh = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut stale = table(&w);
    assert_eq!(
        env.change(&mut stale, "i", &disable("AKVL0001"), &mut TestRng(18))
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert_eq!(stale.seq(), 3);
    assert_eq!(
        env.change(&mut fresh, "j", &disable("AKVL0001"), &mut TestRng(19))
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
}

#[tokio::test(flavor = "current_thread")]
async fn the_finisher_writes_a_checkpoint_when_one_is_due() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(20);
    for i in 0..254u32 {
        let req = if i % 2 == 0 {
            disable("AKVL0001")
        } else {
            enable("AKVL0001")
        };
        let answer = env.change(&mut table, "i", &req, &mut rng).await.unwrap();
        assert_eq!(
            answer,
            KeyAnswer::Done {
                seq: 3 + u64::from(i)
            }
        );
    }
    assert_eq!(w.head(), 256);
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert_eq!(report.checkpoint, Some(256));
    assert_eq!(list_checkpoints(&w.store, &w.t).await.unwrap(), vec![256]);
    let read = read_key_chain(&w.store, &w.kek, &w.ring, &w.t)
        .await
        .unwrap();
    assert_eq!(read.from_checkpoint, Some(256));
    assert_eq!(read.table, table);
    // Not due again on the next run.
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert_eq!(report.checkpoint, None);
}

/// A chain record written by another writer between our head read and
/// our put is never overwritten: the put loses and the change is
/// validated again.
#[tokio::test(flavor = "current_thread")]
async fn a_lost_seq_is_validated_again_at_the_new_head() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let table = seed(&w, &adm).await;
    // Another isolate disables the key at seq 3.
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut other = table.clone();
    assert_eq!(
        env.change(&mut other, "o", &disable("AKVL0001"), &mut TestRng(21))
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    // Our stale view tries to put seq 3 directly: it loses.
    let e = table.get("AKVL0001").unwrap();
    let mut door = e.door.clone();
    door.status = SubjectStatus::Disabled;
    let bytes = seal_key_record(
        &w.kek,
        &w.ring,
        &w.t,
        3,
        KeyOp::Status,
        1,
        &door,
        e.private.as_ref(),
        true,
        &mut TestRng(22),
    )
    .unwrap();
    assert_eq!(
        key_chain(&w.t).put(&w.store, 3, bytes).await.unwrap(),
        Put::Lost
    );
}

// ---------------------------------------------------------------------------
// From the review
// ---------------------------------------------------------------------------

/// A ring with two key versions: version 2 current.
struct TwoKeys(TenantKey, TenantKey);

impl velmora_bridge::keys::record::TkRing for TwoKeys {
    fn current(&self) -> Option<&TenantKey> {
        Some(&self.1)
    }
    fn key(&self, v: u32) -> Option<&TenantKey> {
        [&self.0, &self.1].into_iter().find(|k| k.version() == v)
    }
}

macro_rules! env_with {
    ($w:expr, $ring:expr, $adm:expr, $units:expr) => {
        KeyEnv {
            store: &$w.store,
            kek: &$w.kek,
            ring: $ring,
            tenant: &$w.t,
            admission: $adm,
            intents: &$w.intents,
            units: $units,
            directory: &&$w.directory,
            clock: &$w.clock,
        }
    };
}

/// A create that answered Unfinished, asked again with the same content,
/// is finished, not refused: the caller must not make a second key.
#[tokio::test(flavor = "current_thread")]
async fn a_retried_create_is_finished_not_refused() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(40);
    w.directory.down.set(true);
    let key = s3_key(&w.t, "AKVL0002", "PR0001", &[grant("b_01", RO, None)]);
    let req = KeyRequest::Create(key);
    assert_eq!(
        env.change(&mut table, "i", &req, &mut rng).await.unwrap(),
        KeyAnswer::Unfinished { seq: 3 }
    );
    // Still down: the retry answers Unfinished again, writes nothing.
    assert_eq!(
        env.change(&mut table, "i", &req, &mut rng).await.unwrap(),
        KeyAnswer::Unfinished { seq: 3 }
    );
    w.directory.down.set(false);
    assert_eq!(
        env.change(&mut table, "i", &req, &mut rng).await.unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert_eq!(w.head(), 3);
    for store in [&w.root, &w.unit2, &w.directory] {
        assert_eq!(store.status("AKVL0002"), Some(SubjectStatus::Active));
    }
}

/// The finisher brings the units to the head whether or not the
/// directory answers, but opens nothing there before the directory has
/// it: what does not close is held closed until then.
#[tokio::test(flavor = "current_thread")]
async fn the_finisher_brings_the_units_up_while_the_directory_is_down() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(41);
    for s in [&w.root, &w.unit2, &w.directory] {
        s.down.set(true);
    }
    let key = s3_key(&w.t, "AKVL0002", "PR0001", &[grant("b_01", RO, None)]);
    assert_eq!(
        env.change(&mut table, "a", &KeyRequest::Create(key), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Unfinished { seq: 3 }
    );
    assert_eq!(
        env.change(&mut table, "b", &disable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Unfinished { seq: 4 }
    );
    w.root.down.set(false);
    w.unit2.down.set(false);
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert_eq!(report.failed, vec!["directory".to_owned()]);
    assert!(report.retry());
    for unit in [&w.root, &w.unit2] {
        assert_eq!(unit.status("AKVL0001"), Some(SubjectStatus::Disabled));
        assert_eq!(unit.status("AKVL0002"), Some(SubjectStatus::Disabled));
        assert_eq!(unit.seq.get(), 4);
    }
    assert!(w.directory.row("AKVL0002").is_none(), "not routed yet");
    w.directory.down.set(false);
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(!report.retry(), "{report:?}");
    assert_eq!(w.directory.status("AKVL0002"), Some(SubjectStatus::Active));
    for unit in [&w.root, &w.unit2] {
        assert_eq!(unit.status("AKVL0002"), Some(SubjectStatus::Active));
        assert_eq!(unit.status("AKVL0001"), Some(SubjectStatus::Disabled));
    }
    assert_eq!(w.intents.cleared.borrow().last(), Some(&4));
    assert!(w.intents.notes.borrow().is_empty(), "every row cleared");
}

/// A key's grant is checked against the principal it was made under,
/// whatever the call names.
#[tokio::test(flavor = "current_thread")]
async fn a_key_widening_is_bounded_by_its_own_principal() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(42);
    // A second principal that holds b_09.
    let p2 = principal("PR0002", &[grant("b_09", RW, None)]);
    assert_eq!(
        env.change(&mut table, "p2", &KeyRequest::Create(p2), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    let wider = vec![grant("b_01", RW, None), grant("b_09", RW, None)];
    for acting in [None, Some("PR0001".to_owned()), Some("PR0002".to_owned())] {
        let req = KeyRequest::SetGrants {
            id: "AKVL0001".into(),
            grants: wider.clone(),
            acting,
        };
        assert_eq!(
            env.change(&mut table, "w", &req, &mut rng).await.unwrap(),
            KeyAnswer::Refused(Refusal::NotSubset)
        );
    }
    assert_eq!(w.head(), 3);
}

/// A subject with an `m/rk/` revocation takes its revoke record and
/// nothing else, even before the chain says so.
#[tokio::test(flavor = "current_thread")]
async fn a_revocation_refuses_every_other_change() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(43);
    put_tenant_revocation(&w.store, &w.kek, &w.t, "AKVL0001", 5, &mut rng)
        .await
        .unwrap();
    for req in [
        disable("AKVL0001"),
        enable("AKVL0001"),
        KeyRequest::SetGrants {
            id: "AKVL0001".into(),
            grants: vec![grant("b_01", RO, Some("x/"))],
            acting: None,
        },
    ] {
        assert_eq!(
            env.change(&mut table, "i", &req, &mut rng).await.unwrap(),
            KeyAnswer::Refused(Refusal::Conflict)
        );
    }
    assert_eq!(
        env.change(&mut table, "r", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert_eq!(w.root.status("AKVL0001"), Some(SubjectStatus::Revoked));
}

/// A finisher whose ring holds no key: it can seal no revoke record and
/// opens no private part. The revocation is in force in the stores all
/// the same; the subjects it could not open are disabled there, remembered
/// as closed, and opened again by the next run with the key. No
/// checkpoint carries them closed.
#[tokio::test(flavor = "current_thread")]
async fn a_finisher_without_the_key_closes_and_a_later_one_heals() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(44);
    // 254 more records, so a checkpoint is due at 256.
    for i in 0..254u32 {
        let req = if i % 2 == 0 {
            disable("AKVL0001")
        } else {
            enable("AKVL0001")
        };
        env.change(&mut table, "i", &req, &mut rng).await.unwrap();
    }
    let other = s3_key(&w.t, "AKVL0002", "PR0001", &[grant("b_01", RO, None)]);
    put_tenant_revocation(&w.store, &w.kek, &w.t, "AKVL0001", 5, &mut rng)
        .await
        .unwrap();
    let _ = other;
    // A store that lost everything is brought up by a keyless finisher.
    w.unit2.reset();
    let nokeys = velmora_bridge::keys::record::NoKeys;
    let blind = env_with!(w, &nokeys, &adm, &units);
    let report = finish_keys(&blind, &mut rng).await.unwrap();
    assert_eq!(report.append_failed, vec!["AKVL0001".to_owned()]);
    assert!(report.retry());
    assert_eq!(
        report.checkpoint, None,
        "no checkpoint with closed subjects"
    );
    assert!(report.checkpoint_skipped);
    assert_eq!(
        list_checkpoints(&w.store, &w.t).await.unwrap(),
        Vec::<u64>::new()
    );
    assert_eq!(w.unit2.status("AKVL0001"), Some(SubjectStatus::Revoked));
    assert_eq!(w.unit2.status("PR0001"), Some(SubjectStatus::Disabled));
    // The next run with the key: the revoke record is appended, the
    // principal opens again, and the checkpoint is written.
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(!report.retry(), "{report:?}");
    assert_eq!(report.appended, vec![257]);
    assert_eq!(w.unit2.status("PR0001"), Some(SubjectStatus::Active));
    assert_eq!(report.checkpoint, Some(257));
    let read = read_key_chain(&w.store, &w.kek, &w.ring, &w.t)
        .await
        .unwrap();
    assert_eq!(
        read.table.get("PR0001").unwrap().effective_status(),
        SubjectStatus::Active
    );
}

/// A checkpoint that cannot be written stops nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_checkpoint_that_cannot_be_written_stops_nothing() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(45);
    for i in 0..254u32 {
        let req = if i % 2 == 0 {
            disable("AKVL0001")
        } else {
            enable("AKVL0001")
        };
        env.change(&mut table, "i", &req, &mut rng).await.unwrap();
    }
    w.store.refuse(&format!("m/kc/{}/", w.t));
    w.unit2.reset();
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(report.checkpoint_skipped);
    assert!(!report.retry());
    assert_eq!(w.unit2.seq.get(), 256);
    // A planted checkpoint name far above the head breaks nothing either.
    w.store.allow(&format!("m/kc/{}/", w.t));
    w.store.plant(
        &velmora_bridge::keys::checkpoint::checkpoint_name(&w.t, u64::MAX),
        b"junk".to_vec(),
    );
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert_eq!(report.checkpoint, Some(256));
}

/// A Worker that cannot open a subject's private part may still disable
/// or revoke it: the record carries no private part and keeps the one
/// before, so a later re-enable with the key restores the subject whole.
/// A narrowing or a re-enable answers busy.
#[tokio::test(flavor = "current_thread")]
async fn a_close_without_the_private_part_keeps_the_one_before() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let _ = seed(&w, &adm).await;
    // A Worker that holds key version 2 only.
    let v2_only = OneKey(TenantKey::from_bytes(&w.t, 2, derived("tk v2")).unwrap());
    let units = w.units();
    let blind = env_with!(w, &v2_only, &adm, &units);
    let mut rng = TestRng(46);
    let mut fresh = velmora_bridge::keys::record::KeyTable::empty(w.t.clone());
    let narrow = KeyRequest::SetGrants {
        id: "AKVL0001".into(),
        grants: vec![grant("b_01", RO, Some("x/"))],
        acting: None,
    };
    assert_eq!(
        blind
            .change(&mut fresh, "n", &narrow, &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Busy
    );
    assert_eq!(
        blind
            .change(&mut fresh, "d", &disable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert_eq!(
        blind
            .change(&mut fresh, "e", &enable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Busy
    );
    let both = TwoKeys(
        TenantKey::from_bytes(&w.t, 1, derived("tk")).unwrap(),
        TenantKey::from_bytes(&w.t, 2, derived("tk v2")).unwrap(),
    );
    let read = read_key_chain(&w.store, &w.kek, &both, &w.t).await.unwrap();
    let e = read.table.get("AKVL0001").unwrap();
    assert_eq!(e.door.status, SubjectStatus::Disabled);
    assert_eq!((e.last_seq, e.private_seq, e.tk_version), (3, 2, 1));
    assert!(e.private.as_ref().unwrap().secret_wrapped.is_some());
    // With every key, the re-enable restores it whole.
    let full = env_with!(w, &both, &adm, &units);
    let mut table = read.table.clone();
    assert_eq!(
        full.change(&mut table, "e2", &enable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
    let row = w.root.row("AKVL0001").unwrap();
    assert_eq!(row.effective_status(), SubjectStatus::Active);
    assert!(row.private.unwrap().secret_wrapped.is_some());
    // A revoke without the private part goes through too.
    assert_eq!(
        blind
            .change(&mut fresh, "r", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 5 }
    );
}

type HookFut<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>;

/// A store whose first `keys_seq` runs another call first (a concurrent
/// request), then optionally fails (a timeout).
struct Hooked<'a> {
    inner: &'a FakeTarget,
    hook: RefCell<Option<HookFut<'a>>>,
    fail_after_hook: bool,
}

impl KeyTarget for Hooked<'_> {
    fn label(&self) -> &str {
        self.inner.label
    }
    async fn keys_seq(&self) -> Result<u64> {
        let hook = self.hook.borrow_mut().take();
        if let Some(h) = hook {
            h.await;
            if self.fail_after_hook {
                return Err(BridgeError::Sql("fake: timed out".into()));
            }
        }
        KeyTarget::keys_seq(self.inner).await
    }
    async fn closed(&self) -> Result<Vec<String>> {
        KeyTarget::closed(self.inner).await
    }
    async fn apply(&self, to_seq: u64, entries: &[Entry]) -> Result<()> {
        KeyTarget::apply(self.inner, to_seq, entries).await
    }
}

/// A finisher whose read is stale (a disable was recorded and applied
/// closed by a keyless finisher meanwhile) sends an older, open entry:
/// the stores keep the newer one, and a retried disable is in force.
#[tokio::test(flavor = "current_thread")]
async fn a_stale_open_entry_never_replaces_a_newer_closed_one() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let _ = seed(&w, &adm).await;
    let units = w.units();
    let both = TwoKeys(
        TenantKey::from_bytes(&w.t, 1, derived("tk")).unwrap(),
        TenantKey::from_bytes(&w.t, 2, derived("tk v2")).unwrap(),
    );
    let adm2 = FakeAdmission::new(&w.root);
    let units2 = w.units();
    let full2 = env_with!(w, &both, &adm2, &units2);
    let v1 = env!(w, &adm2, &units2);
    let mut rng2 = TestRng(93);
    let mut t2 = velmora_bridge::keys::record::KeyTable::empty(w.t.clone());
    let hook: HookFut<'_> = Box::pin(async {
        for s in [&w.root, &w.unit2, &w.directory] {
            s.down.set(true);
        }
        assert_eq!(
            full2
                .change(&mut t2, "d", &disable("AKVL0001"), &mut rng2)
                .await
                .unwrap(),
            KeyAnswer::Unfinished { seq: 3 }
        );
        for s in [&w.root, &w.unit2, &w.directory] {
            s.down.set(false);
        }
        let r = finish_keys(&v1, &mut rng2).await.unwrap();
        assert_eq!(r.closed, vec!["AKVL0001".to_owned()]);
        assert_eq!(w.root.status("AKVL0001"), Some(SubjectStatus::Disabled));
    });
    let dir = Hooked {
        inner: &w.directory,
        hook: RefCell::new(Some(hook)),
        fail_after_hook: false,
    };
    // A full-ring finisher whose read was at seq 2; the units, then the
    // directory (whose hook runs the other calls first).
    let stale_units: [&FakeTarget; 0] = [];
    let stale = KeyEnv {
        store: &w.store,
        kek: &w.kek,
        ring: &both,
        tenant: &w.t,
        admission: &adm,
        intents: &w.intents,
        units: &stale_units,
        directory: &dir,
        clock: &w.clock,
    };
    let mut rng = TestRng(94);
    let report = finish_keys(&stale, &mut rng).await.unwrap();
    assert_eq!(report.head, 2, "the stale finisher's table");
    // Now bring the units up from the same stale view, by hand.
    let stale_table = {
        let mut t = velmora_bridge::keys::record::KeyTable::empty(w.t.clone());
        let chain = key_chain(&w.t);
        for seq in 1..=2 {
            let b = chain.get(&w.store, seq).await.unwrap();
            t.apply(&open_key_record(&w.kek, &both, &w.t, seq, &b).unwrap())
                .unwrap();
        }
        t
    };
    for unit in [&w.root, &w.unit2] {
        let entries: Vec<Entry> = stale_table.entries().cloned().collect();
        KeyTarget::apply(unit, 2, &entries).await.unwrap();
        assert_eq!(
            unit.status("AKVL0001"),
            Some(SubjectStatus::Disabled),
            "{}",
            unit.label
        );
    }
    // The next full run opens it as the disabled key it is.
    let full = env_with!(w, &both, &adm, &units);
    let report = finish_keys(&full, &mut rng).await.unwrap();
    assert!(!report.retry(), "{report:?}");
    let row = w.root.row("AKVL0001").unwrap();
    assert_eq!(row.last_seq, 3);
    assert!(row.private.is_some());
    assert_eq!(row.effective_status(), SubjectStatus::Disabled);
}

/// A widening retried while the directory is still down is classed as
/// the record that made it (opening): never Done before the directory.
#[tokio::test(flavor = "current_thread")]
async fn a_retried_widening_waits_for_the_directory() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(70);
    w.directory.down.set(true);
    let wider = KeyRequest::SetGrants {
        id: "AKVL0001".into(),
        grants: vec![grant("b_01", RW, None)],
        acting: None,
    };
    for _ in 0..2 {
        assert_eq!(
            env.change(&mut table, "w", &wider, &mut rng).await.unwrap(),
            KeyAnswer::Unfinished { seq: 3 }
        );
    }
    w.directory.down.set(false);
    assert_eq!(
        env.change(&mut table, "w", &wider, &mut rng).await.unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
}

/// A closing change with the directory down answers Done, and leaves its
/// pending row for the finisher.
#[tokio::test(flavor = "current_thread")]
async fn a_close_with_the_directory_down_keeps_its_pending_row() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(71);
    w.directory.down.set(true);
    assert_eq!(
        env.change(&mut table, "d", &disable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert!(w.intents.notes.borrow().iter().any(|(s, _)| *s == 3));
    w.directory.down.set(false);
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(!report.retry());
    assert!(w.intents.notes.borrow().is_empty());
}

/// A finisher without the key asks for a retry and keeps the rows.
#[tokio::test(flavor = "current_thread")]
async fn a_finisher_without_the_key_keeps_the_rows() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(72);
    w.root.down.set(true);
    let key = s3_key(&w.t, "AKVL0002", "PR0001", &[grant("b_01", RO, None)]);
    assert_eq!(
        env.change(&mut table, "a", &KeyRequest::Create(key), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Unfinished { seq: 3 }
    );
    w.root.down.set(false);
    let nokeys = velmora_bridge::keys::record::NoKeys;
    let blind = env_with!(w, &nokeys, &adm, &units);
    let report = finish_keys(&blind, &mut rng).await.unwrap();
    assert!(report.retry());
    assert!(w.intents.notes.borrow().iter().any(|(s, _)| *s == 3));
    assert_eq!(w.root.status("AKVL0002"), Some(SubjectStatus::Disabled));
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(!report.retry(), "{report:?}");
    assert_eq!(w.root.status("AKVL0002"), Some(SubjectStatus::Active));
    assert!(w.intents.notes.borrow().is_empty());
}

/// A cached table built while the ring missed a key opens again in the
/// next change made with the key; a retried create with the key missing
/// answers busy, not conflict; a create of a revoked id is refused.
#[tokio::test(flavor = "current_thread")]
async fn a_cached_table_opens_again_and_retries_need_the_key() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let _ = seed(&w, &adm).await;
    let units = w.units();
    let mut rng = TestRng(73);
    let nokeys = velmora_bridge::keys::record::NoKeys;
    let blind = env_with!(w, &nokeys, &adm, &units);
    let mut cached = velmora_bridge::keys::record::KeyTable::empty(w.t.clone());
    let key = s3_key(&w.t, "AKVL0001", "PR0001", &[grant("b_01", RO, None)]);
    assert_eq!(
        blind
            .change(&mut cached, "c", &KeyRequest::Create(key.clone()), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Busy
    );
    assert!(cached.get("AKVL0001").unwrap().private.is_none());
    let env = env!(w, &adm, &units);
    let narrow = KeyRequest::SetGrants {
        id: "AKVL0001".into(),
        grants: vec![grant("b_01", RO, Some("x/"))],
        acting: None,
    };
    assert_eq!(
        env.change(&mut cached, "n", &narrow, &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    // The same content again, now with the key: a retry, Done.
    let mut fresh = velmora_bridge::keys::record::KeyTable::empty(w.t.clone());
    put_tenant_revocation(&w.store, &w.kek, &w.t, "AKVL0001", 5, &mut rng)
        .await
        .unwrap();
    assert_eq!(
        env.change(&mut fresh, "c", &KeyRequest::Create(key), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Refused(Refusal::Conflict),
        "a revoked id is never created again"
    );
}

#[test]
fn debug_output_shows_no_prefix_or_address() {
    let g = Grant {
        bucket_id: "b_01".into(),
        access: RO,
        expires_at: None,
        prefix: Some("secret-folder/".into()),
        ip_list: vec!["203.0.113.7".into()],
    };
    let req = KeyRequest::SetGrants {
        id: "AKVL0001".into(),
        grants: vec![g.clone()],
        acting: None,
    };
    for shown in [format!("{g:?}"), format!("{req:?}")] {
        assert!(!shown.contains("secret-folder"), "{shown}");
        assert!(!shown.contains("203.0.113.7"), "{shown}");
    }
}

// ---------------------------------------------------------------------------
// Review, round 3
// ---------------------------------------------------------------------------

/// Revoked is final in a store: no entry, newer or reopened, makes a
/// revoked row anything else.
#[tokio::test(flavor = "current_thread")]
async fn a_revoked_row_stays_revoked() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let stale = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(101);
    let mut table = stale.clone();
    assert_eq!(
        env.change(&mut table, "r", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    let open = stale.get("AKVL0001").unwrap().clone();
    // A closed revoked row, then the same seq opened.
    let mut closed = w.unit2.row("AKVL0001").unwrap();
    closed.private = None;
    let unit = FakeTarget::new("unit 3");
    KeyTarget::apply(&unit, 3, std::slice::from_ref(&closed))
        .await
        .unwrap();
    let mut same = open.clone();
    same.last_seq = closed.last_seq;
    KeyTarget::apply(&unit, 3, &[same]).await.unwrap();
    assert_eq!(unit.status("AKVL0001"), Some(SubjectStatus::Revoked));
    // A newer entry that is not revoked.
    let mut newer = open;
    newer.last_seq = 9;
    for store in [&w.root, &unit] {
        KeyTarget::apply(store, 9, std::slice::from_ref(&newer))
            .await
            .unwrap();
        assert_eq!(store.status("AKVL0001"), Some(SubjectStatus::Revoked));
    }
}

/// A re-enable with the directory down answers unfinished and opens no
/// unit; the finisher opens it once the directory has it.
#[tokio::test(flavor = "current_thread")]
async fn a_re_enable_with_the_directory_down_opens_no_unit() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(102);
    assert_eq!(
        env.change(&mut table, "d", &disable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    w.directory.down.set(true);
    assert_eq!(
        env.change(&mut table, "e", &enable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Unfinished { seq: 4 }
    );
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(report.retry());
    for unit in [&w.root, &w.unit2] {
        assert_eq!(unit.status("AKVL0001"), Some(SubjectStatus::Disabled));
        assert_eq!(unit.seq.get(), 4, "the unit still reaches the head");
    }
    w.directory.down.set(false);
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(!report.retry(), "{report:?}");
    for store in [&w.root, &w.unit2, &w.directory] {
        assert_eq!(store.status("AKVL0001"), Some(SubjectStatus::Active));
    }
}

/// A widening with the directory down is not in force at any unit: the
/// key is held closed there until the directory has the head.
#[tokio::test(flavor = "current_thread")]
async fn a_widening_with_the_directory_down_is_in_force_nowhere() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(103);
    w.directory.down.set(true);
    let widen = KeyRequest::SetGrants {
        id: "AKVL0001".into(),
        grants: vec![grant("b_01", RW, None)],
        acting: None,
    };
    assert_eq!(
        env.change(&mut table, "w", &widen, &mut rng).await.unwrap(),
        KeyAnswer::Unfinished { seq: 3 }
    );
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(report.retry());
    for unit in [&w.root, &w.unit2] {
        let row = unit.row("AKVL0001").unwrap();
        assert_eq!(
            row.effective_status(),
            SubjectStatus::Disabled,
            "{}",
            unit.label
        );
    }
    w.directory.down.set(false);
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(!report.retry(), "{report:?}");
    let row = w.root.row("AKVL0001").unwrap();
    assert_eq!(row.effective_status(), SubjectStatus::Active);
    assert_eq!(joined(&row), vec![grant("b_01", RW, None)]);
}

/// A create of an id that `m/rk/` revoked is refused even when the
/// request is an exact retry of the one that made it.
#[tokio::test(flavor = "current_thread")]
async fn an_exact_retry_of_a_create_revoked_in_m_rk_is_refused() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(104);
    let key = s3_key(&w.t, "AKVL0002", "PR0001", &[grant("b_01", RO, None)]);
    let req = KeyRequest::Create(key);
    assert_eq!(
        env.change(&mut table, "c", &req, &mut rng).await.unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    // The revoke stopped after its `m/rk/` record.
    put_tenant_revocation(&w.store, &w.kek, &w.t, "AKVL0002", 5, &mut rng)
        .await
        .unwrap();
    assert_eq!(
        env.change(&mut table, "c", &req, &mut rng).await.unwrap(),
        KeyAnswer::Refused(Refusal::Conflict)
    );
}

/// A writer whose ring leaves a subject closed answers, but keeps the
/// pending rows: a run with the key must still open the subject.
#[tokio::test(flavor = "current_thread")]
async fn a_writer_with_a_closed_subject_keeps_the_rows() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let _ = seed(&w, &adm).await;
    let v2_only = OneKey(TenantKey::from_bytes(&w.t, 2, derived("tk v2")).unwrap());
    let units = w.units();
    let blind = env_with!(w, &v2_only, &adm, &units);
    let mut rng = TestRng(105);
    let mut fresh = velmora_bridge::keys::record::KeyTable::empty(w.t.clone());
    assert_eq!(
        blind
            .change(&mut fresh, "d", &disable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert!(w.intents.notes.borrow().iter().any(|(s, _)| *s == 3));
    let both = TwoKeys(
        TenantKey::from_bytes(&w.t, 1, derived("tk")).unwrap(),
        TenantKey::from_bytes(&w.t, 2, derived("tk v2")).unwrap(),
    );
    let full = env_with!(w, &both, &adm, &units);
    let report = finish_keys(&full, &mut rng).await.unwrap();
    assert!(!report.retry(), "{report:?}");
    assert!(w.intents.notes.borrow().is_empty());
}

/// A subject closed by a record that keeps the private part before is
/// opened again from the record that holds it (`private_seq`), not from
/// its newest one.
#[tokio::test(flavor = "current_thread")]
async fn a_cached_table_reopens_from_the_record_that_holds_the_private_part() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let _ = seed(&w, &adm).await;
    let v2_only = OneKey(TenantKey::from_bytes(&w.t, 2, derived("tk v2")).unwrap());
    let units = w.units();
    let blind = env_with!(w, &v2_only, &adm, &units);
    let mut rng = TestRng(106);
    let mut cached = velmora_bridge::keys::record::KeyTable::empty(w.t.clone());
    assert_eq!(
        blind
            .change(&mut cached, "d", &disable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    let e = cached.get("AKVL0001").unwrap();
    assert!(e.private.is_none());
    assert_eq!((e.last_seq, e.private_seq), (3, 2));
    let both = TwoKeys(
        TenantKey::from_bytes(&w.t, 1, derived("tk")).unwrap(),
        TenantKey::from_bytes(&w.t, 2, derived("tk v2")).unwrap(),
    );
    let full = env_with!(w, &both, &adm, &units);
    assert_eq!(
        full.change(&mut cached, "e", &enable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
    assert_eq!(w.root.status("AKVL0001"), Some(SubjectStatus::Active));
}

/// A root restored behind the head refuses a key whose principal is at
/// the head: the writer brings the units up once and asks again.
#[tokio::test(flavor = "current_thread")]
async fn a_refusal_by_a_restored_root_is_asked_again_after_catch_up() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(111);
    w.root.reset();
    let key = s3_key(&w.t, "AKVL0002", "PR0001", &[grant("b_01", RO, None)]);
    assert_eq!(
        env.change(&mut table, "c", &KeyRequest::Create(key), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    assert_eq!(w.root.status("AKVL0002"), Some(SubjectStatus::Active));
}

/// A store that plants `bytes` under `name` on its `nth` list call: a
/// record that lands while the finisher reads.
struct PlantOnList<'a> {
    inner: &'a MemRecords,
    nth: u32,
    calls: Cell<u32>,
    name: String,
    bytes: Vec<u8>,
}

impl RecordStore for PlantOnList<'_> {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        self.inner.put_if_absent(name, bytes).await
    }
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(name).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.calls.set(self.calls.get() + 1);
        if self.calls.get() == self.nth {
            self.inner.plant(&self.name, self.bytes.clone());
        }
        self.inner.list(prefix, start_after, limit).await
    }
}

/// A chain that cannot be read to its head makes the run fail.
#[tokio::test(flavor = "current_thread")]
async fn a_finisher_that_cannot_read_to_the_head_asks_for_a_retry() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let _ = seed(&w, &adm).await;
    let units = w.units();
    let mut rng = TestRng(112);
    let mut seen = None;
    for nth in 1..12 {
        let store = PlantOnList {
            inner: &w.store,
            nth,
            calls: Cell::new(0),
            name: key_chain(&w.t).name(3),
            bytes: b"not a record".to_vec(),
        };
        let env = KeyEnv {
            store: &store,
            kek: &w.kek,
            ring: &w.ring,
            tenant: &w.t,
            admission: &adm,
            intents: &w.intents,
            units: &units,
            directory: &&w.directory,
            clock: &w.clock,
        };
        // The first list call that lands the record after the read and
        // before the final one; an earlier one fails the read itself.
        let result = finish_keys(&env, &mut rng).await;
        let planted = store.calls.get() >= nth;
        w.store.lose(&key_chain(&w.t).name(3));
        if let (Ok(report), true) = (result, planted) {
            seen = Some(report);
            break;
        }
    }
    let report = seen.expect("a run that read the planted record after its first read");
    assert!(report.failed.contains(&"chain".to_owned()), "{report:?}");
    assert!(report.retry());
}
