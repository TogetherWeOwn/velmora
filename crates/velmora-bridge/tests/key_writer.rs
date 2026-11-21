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

    async fn apply(&self, to_seq: u64, entries: &[Entry]) -> Result<()> {
        if self.down.get() {
            return Err(BridgeError::Sql("fake: down".into()));
        }
        self.applies.set(self.applies.get() + 1);
        let mut rows = self.rows.borrow_mut();
        for e in entries {
            rows.insert(e.door.id.clone(), e.clone());
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
    notes: RefCell<Vec<(u64, String)>>,
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
        Ok(())
    }

    async fn clear(&self, _t: &TenantId, _c: ControlChain, seq: u64) -> Result<()> {
        if self.fail_note.get() {
            return Err(BridgeError::Sql("fake: directory down".into()));
        }
        self.cleared.borrow_mut().push(seq);
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
    assert_eq!(w.intents.notes.borrow()[1].1, "key.create");
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
                    tk_version: 1,
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
        4,
        "seed 2, then the lost try and the retry"
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
async fn an_opening_change_with_the_directory_down_reaches_no_unit_until_finished() {
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
    // Directory first: with it down, no unit holds the key.
    assert!(w.root.row("AKVL0002").is_none());
    assert!(w.unit2.row("AKVL0002").is_none());
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
        KeyAnswer::Refused(Refusal::Conflict)
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
    // The same id twice.
    let again = s3_key(&w.t, "AKVL0001", "PR0001", &[grant("b_01", RO, None)]);
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
        &mut TestRng(22),
    )
    .unwrap();
    assert_eq!(
        key_chain(&w.t).put(&w.store, 3, bytes).await.unwrap(),
        Put::Lost
    );
}
