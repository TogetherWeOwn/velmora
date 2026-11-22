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
use velmora_bridge::keys::buckets::{
    finish_creator_grant, BucketAnswer, BucketRequest, CreatorGrant, BUCKET_CREATE_KIND,
    MAX_ORDER_TRIES,
};
use velmora_bridge::keys::chain::Put;
use velmora_bridge::keys::checkpoint::{list_checkpoints, read_key_chain};
use velmora_bridge::keys::gate::testkit::FakeGate;
use velmora_bridge::keys::ports::{
    Admission, Applied, ApplyEntry, Binding, BucketAdmission, BucketPut, BucketRecords,
    BucketReservation, ControlChain, ControlIntents, KeyAdmission, KeyTarget, OpeningChange,
    Refusal, MAX_APPLY,
};
use velmora_bridge::keys::record::{
    grant_within, key_chain, open_key_record, seal_key_record, Access, Entry, Grant, KeyOp, OneKey,
    Subject, SubjectDoor, SubjectKind, SubjectPrivate, SubjectStatus,
};
use velmora_bridge::keys::revocations::{put_tenant_revocation, tenant_revocation_name};
use velmora_bridge::keys::routes::{put_route, read_route, RoutePut};
use velmora_bridge::keys::writer::{finish_keys, KeyAnswer, KeyEnv, KeyRequest, Limits};
use velmora_bridge::records::{bucket_id, MemRecords, RecordStore};
use velmora_bridge::testkit::{FixedClock, TestKek};
use velmora_bridge::{BridgeError, BucketId, Result, UnixMs};

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
    /// The seqs of the markers it was sent.
    markers: RefCell<Vec<u64>>,
    /// Goes down after this many more applies.
    down_after: Cell<Option<u32>>,
}

impl FakeTarget {
    fn new(label: &'static str) -> Self {
        FakeTarget {
            label,
            seq: Cell::new(0),
            rows: RefCell::new(BTreeMap::new()),
            down: Cell::new(false),
            applies: Cell::new(0),
            markers: RefCell::new(Vec::new()),
            down_after: Cell::new(None),
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

    /// As the port says (AM-12): an exclusive base, no gap, at most a
    /// page, `Behind` above the store's seq; then per subject, in chain
    /// order. A call that breaks the run fails the test.
    async fn apply(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied> {
        match self.down_after.get() {
            Some(0) => self.down.set(true),
            Some(n) => self.down_after.set(Some(n - 1)),
            None => {}
        }
        if self.down.get() {
            return Err(BridgeError::Sql("fake: down".into()));
        }
        if from_seq > self.seq.get() {
            return Ok(Applied::Behind {
                keys_seq: self.seq.get(),
            });
        }
        assert!(
            entries.len() <= MAX_APPLY,
            "{}: more than a page",
            self.label
        );
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.seq(), from_seq + 1 + i as u64, "{}: a gap", self.label);
        }
        self.applies.set(self.applies.get() + 1);
        let mut rows = self.rows.borrow_mut();
        for e in entries {
            let e = match e {
                ApplyEntry::Subject(e) => e,
                ApplyEntry::Marker { seq } => {
                    self.markers.borrow_mut().push(*seq);
                    continue;
                }
            };
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
        let last = from_seq + entries.len() as u64;
        self.seq.set(self.seq.get().max(last));
        Ok(Applied::Done {
            keys_seq: self.seq.get(),
        })
    }
}

/// An open bucket reservation: (creator, unit, bound seq, name).
type OpenBucket = (String, u32, Option<u64>, String);

/// The root unit's reservation call, checked against the root fake.
struct FakeAdmission<'a> {
    root: &'a FakeTarget,
    cap: usize,
    calls: Cell<u32>,
    /// The idempotency keys released, in order.
    released: RefCell<Vec<String>>,
    refuse: Cell<Option<Refusal>>,
    /// Answers this `keys_seq` instead of the root's.
    stale: Cell<Option<u64>>,
    /// Bucket reservations asked for, by idempotency key.
    bucket_asks: RefCell<Vec<String>>,
    /// The reservation already became this bucket (a retry).
    bucket_done: RefCell<Option<(BucketId, u64)>>,
    /// Bucket creates left under the cap.
    bucket_cap: Cell<u32>,
    /// Open bucket reservations: key -> (creator, unit, bound seq).
    bucket_open: RefCell<BTreeMap<String, OpenBucket>>,
    /// `bind_bucket` fails while set.
    bind_down: Cell<bool>,
    /// `release` fails while set.
    release_down: Cell<bool>,
    /// Seqs a `Binding::None` answer fenced.
    fenced: RefCell<std::collections::BTreeSet<u64>>,
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
            released: RefCell::new(Vec::new()),
            refuse: Cell::new(None),
            stale: Cell::new(None),
            bucket_asks: RefCell::new(Vec::new()),
            bucket_done: RefCell::new(None),
            bucket_cap: Cell::new(50),
            bucket_open: RefCell::new(BTreeMap::new()),
            bind_down: Cell::new(false),
            release_down: Cell::new(false),
            fenced: RefCell::new(Default::default()),
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

    async fn release(&self, _tenant: &TenantId, idempotency_key: &str) -> Result<()> {
        if self.release_down.get() {
            return Err(BridgeError::Sql("fake: root unit down".into()));
        }
        self.released.borrow_mut().push(idempotency_key.to_owned());
        self.bucket_open.borrow_mut().remove(idempotency_key);
        Ok(())
    }

    async fn bind_bucket(
        &self,
        _t: &TenantId,
        idempotency_key: &str,
        expected: Option<u64>,
        grant_seq: u64,
    ) -> Result<bool> {
        if self.bind_down.get() {
            return Err(BridgeError::Sql("fake: root unit down".into()));
        }
        if self.fenced.borrow().contains(&grant_seq) {
            return Ok(false);
        }
        let mut open = self.bucket_open.borrow_mut();
        let Some(r) = open.get_mut(idempotency_key) else {
            return Ok(false);
        };
        if r.2 == Some(grant_seq) {
            return Ok(true);
        }
        if r.2 != expected {
            return Ok(false);
        }
        assert!(r.2.is_none_or(|b| b < grant_seq), "a bind only moves up");
        r.2 = Some(grant_seq);
        Ok(true)
    }

    async fn release_bound(
        &self,
        t: &TenantId,
        idempotency_key: &str,
        bound: Option<u64>,
    ) -> Result<bool> {
        let current = self.bucket_open.borrow().get(idempotency_key).map(|r| r.2);
        match current {
            Some(b) if b == bound => {
                self.release(t, idempotency_key).await?;
                Ok(true)
            }
            Some(_) => Ok(false),
            None => Ok(self.bucket_done.borrow().is_none()),
        }
    }

    async fn bucket_binding(&self, _t: &TenantId, grant_seq: u64) -> Result<Binding> {
        if self
            .bucket_done
            .borrow()
            .as_ref()
            .is_some_and(|(_, k)| *k == grant_seq)
        {
            return Ok(Binding::Created);
        }
        let open = self
            .bucket_open
            .borrow()
            .iter()
            .find(|(_, (_, _, b, _))| *b == Some(grant_seq))
            .map(|(key, (creator, unit, _, name))| Binding::Open {
                idempotency_key: key.clone(),
                name: name.clone(),
                creator: creator.clone(),
                unit: *unit,
            });
        Ok(match open {
            Some(b) => b,
            None => {
                self.fenced.borrow_mut().insert(grant_seq);
                Binding::None
            }
        })
    }

    async fn admit_bucket(
        &self,
        _tenant: &TenantId,
        idempotency_key: &str,
        bucket: &BucketReservation<'_>,
    ) -> Result<BucketAdmission> {
        self.calls.set(self.calls.get() + 1);
        self.bucket_asks
            .borrow_mut()
            .push(idempotency_key.to_owned());
        let seq = self.root.seq.get();
        let bound = self
            .bucket_open
            .borrow()
            .get(idempotency_key)
            .and_then(|r| r.2);
        let answer = if let Some((b, k)) = self.bucket_done.borrow().clone() {
            BucketAdmission::Created {
                bucket: b,
                grant_seq: k,
            }
        } else if let Some(k) = bound {
            // A bound reservation is answered whatever its creator is now.
            BucketAdmission::Admitted {
                keys_seq: self.stale.get().unwrap_or(seq),
                bound: Some(k),
            }
        } else if let Some(r) = self.refuse.get() {
            BucketAdmission::Refused(r)
        } else if self.bucket_cap.get() == 0 {
            BucketAdmission::Refused(Refusal::CapFull)
        } else {
            let rows = self.root.rows.borrow();
            match rows.get(bucket.creator) {
                None => BucketAdmission::Refused(Refusal::NotFound),
                Some(p)
                    if p.door.kind != SubjectKind::Principal
                        || p.effective_status() != SubjectStatus::Active =>
                {
                    BucketAdmission::Refused(Refusal::CreatorNotActive)
                }
                Some(_) => {
                    let mut open = self.bucket_open.borrow_mut();
                    let r = open.entry(idempotency_key.to_owned()).or_insert((
                        bucket.creator.to_owned(),
                        bucket.unit,
                        None,
                        bucket.name.to_owned(),
                    ));
                    BucketAdmission::Admitted {
                        keys_seq: self.stale.get().unwrap_or(seq),
                        bound: r.2,
                    }
                }
            }
        };
        if let Some(race) = self.race.borrow_mut().take() {
            race();
        }
        Ok(answer)
    }
}

/// The tenant chain's `CreateBucket`, as #199's transition decides it:
/// the derived id, not placed, `grant_seq` above `last_grant_seq`.
#[derive(Default)]
struct FakeBuckets {
    /// (bucket, unit, creator, grant_seq)
    placed: RefCell<Vec<(String, u32, String, u64)>>,
    last_grant_seq: Cell<u64>,
    refuse: Cell<Option<(u16, &'static str)>>,
    /// The next N creates lose the order: another create with a higher
    /// creator-grant seq was recorded first.
    lose_orders: Cell<u32>,
    down: Cell<bool>,
    /// The next N creates are recorded and then answer an error.
    lose_answers: Cell<u32>,
    /// The directory or the unit does not acknowledge.
    not_in_force: Cell<bool>,
    calls: Cell<u32>,
}

impl FakeBuckets {
    fn placed_now(&self) -> BucketPut {
        BucketPut::Placed {
            in_force: !self.not_in_force.get(),
        }
    }
}

impl BucketRecords for FakeBuckets {
    async fn bucket_created(
        &self,
        t: &TenantId,
        bucket: &BucketId,
        unit: u32,
        creator: &str,
        grant_seq: u64,
    ) -> Result<BucketPut> {
        self.calls.set(self.calls.get() + 1);
        if self.down.get() {
            return Err(BridgeError::Blob("fake: tenant chain down".into()));
        }
        assert_eq!(*bucket, bucket_id(t, grant_seq), "bucket_id_not_derived");
        if self
            .placed
            .borrow()
            .iter()
            .any(|(b, ..)| b == bucket.as_str())
        {
            assert!(grant_seq <= self.last_grant_seq.get());
            if self.lose_answers.get() > 0 {
                self.lose_answers.set(self.lose_answers.get() - 1);
                return Err(BridgeError::Blob("fake: answer lost".into()));
            }
            return Ok(self.placed_now());
        }
        if let Some((status, code)) = self.refuse.get() {
            return Ok(BucketPut::Refused { status, code });
        }
        if self.lose_orders.get() > 0 {
            self.lose_orders.set(self.lose_orders.get() - 1);
            self.last_grant_seq.set(grant_seq + 1);
        }
        if grant_seq <= self.last_grant_seq.get() {
            return Ok(BucketPut::OrderLost);
        }
        self.last_grant_seq.set(grant_seq);
        self.placed.borrow_mut().push((
            bucket.as_str().to_owned(),
            unit,
            creator.to_owned(),
            grant_seq,
        ));
        if self.lose_answers.get() > 0 {
            self.lose_answers.set(self.lose_answers.get() - 1);
            return Err(BridgeError::Blob("fake: answer lost".into()));
        }
        Ok(self.placed_now())
    }

    async fn is_placed(&self, _t: &TenantId, bucket: &BucketId) -> Result<bool> {
        if self.down.get() {
            return Err(BridgeError::Blob("fake: tenant chain down".into()));
        }
        Ok(self
            .placed
            .borrow()
            .iter()
            .any(|(b, ..)| b == bucket.as_str()))
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
            limits: Limits::Recorded,
            gate: &FakeGate::before_move(),
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
    async fn apply(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied> {
        KeyTarget::apply(*self, from_seq, entries).await
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
                None,
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
                    opened_seq: 1,
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
    // No record will use the reservation: it is released.
    assert_eq!(*adm.released.borrow(), vec!["i".to_owned()]);
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
        None,
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
            limits: Limits::Recorded,
            gate: &FakeGate::before_move(),
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
    async fn apply(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied> {
        KeyTarget::apply(self.inner, from_seq, entries).await
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
        limits: Limits::Recorded,
        gate: &FakeGate::before_move(),
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
        // Each stale entry alone at its own seq, as a resend is sent.
        for e in stale_table.entries().cloned() {
            let base = e.last_seq - 1;
            KeyTarget::apply(unit, base, &[ApplyEntry::Subject(e)])
                .await
                .unwrap();
        }
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
    // Stores far enough ahead that each entry is sent alone at its seq.
    unit.seq.set(10);
    w.root.seq.set(10);
    let at = |e: &Entry| (e.last_seq - 1, [ApplyEntry::Subject(e.clone())]);
    let (base, one) = at(&closed);
    KeyTarget::apply(&unit, base, &one).await.unwrap();
    let mut same = open.clone();
    same.last_seq = closed.last_seq;
    let (base, one) = at(&same);
    KeyTarget::apply(&unit, base, &one).await.unwrap();
    assert_eq!(unit.status("AKVL0001"), Some(SubjectStatus::Revoked));
    // A newer entry that is not revoked.
    let mut newer = open;
    newer.last_seq = 9;
    for store in [&w.root, &unit] {
        let (base, one) = at(&newer);
        KeyTarget::apply(store, base, &one).await.unwrap();
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
            limits: Limits::Recorded,
            gate: &FakeGate::before_move(),
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

/// A ring of any key versions, the last one current.
struct Ring(Vec<TenantKey>);

impl velmora_bridge::keys::record::TkRing for Ring {
    fn current(&self) -> Option<&TenantKey> {
        self.0.last()
    }
    fn key(&self, v: u32) -> Option<&TenantKey> {
        self.0.iter().find(|k| k.version() == v)
    }
}

/// A checkpoint written by a Worker that could not open a subject
/// carries it door-only; a reader that cannot open the subject's record
/// but holds the key of an older checkpoint that carries it whole opens
/// it from there.
#[tokio::test(flavor = "current_thread")]
async fn a_subject_closed_in_a_checkpoint_opens_from_an_older_one() {
    use velmora_bridge::keys::checkpoint::{checkpoint_name, seal_checkpoint};
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let _ = seed(&w, &adm).await;
    let k = |v: u32, label: &str| TenantKey::from_bytes(&w.t, v, derived(label)).unwrap();
    let chain = key_chain(&w.t);
    let mut rng = TestRng(130);
    // An older checkpoint at seq 2, sealed under version 2, carrying
    // AKVL0001 whole (its record is sealed under version 1).
    let v12 = Ring(vec![k(1, "tk"), k(2, "tk v2")]);
    let read = read_key_chain(&w.store, &w.kek, &v12, &w.t).await.unwrap();
    let record2 = chain.get(&w.store, 2).await.unwrap();
    let c1 = seal_checkpoint(&w.kek, &v12, &read.table, &record2, &mut rng).unwrap();
    assert!(w
        .store
        .put_if_absent(&checkpoint_name(&w.t, 2), c1)
        .await
        .unwrap());
    // A Worker holding version 3 only records another subject at seq 3
    // and writes a checkpoint there: AKVL0001 is door-only in it.
    let v3 = Ring(vec![k(3, "tk v3")]);
    let units = w.units();
    let blind = env_with!(w, &v3, &adm, &units);
    let mut cached = velmora_bridge::keys::record::KeyTable::empty(w.t.clone());
    assert_eq!(
        blind
            .change(
                &mut cached,
                "p",
                &KeyRequest::Create(principal("PR0002", &[])),
                &mut rng
            )
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    let read3 = read_key_chain(&w.store, &w.kek, &v3, &w.t).await.unwrap();
    assert!(read3.table.get("AKVL0001").unwrap().private.is_none());
    let record3 = chain.get(&w.store, 3).await.unwrap();
    let c2 = seal_checkpoint(&w.kek, &v3, &read3.table, &record3, &mut rng).unwrap();
    assert!(w
        .store
        .put_if_absent(&checkpoint_name(&w.t, 3), c2)
        .await
        .unwrap());
    // A reader with versions 2 and 3 starts at seq 3, cannot open the
    // record at seq 2, and opens the subject from the checkpoint at 2.
    let v23 = Ring(vec![k(2, "tk v2"), k(3, "tk v3")]);
    let read = read_key_chain(&w.store, &w.kek, &v23, &w.t).await.unwrap();
    assert_eq!(read.from_checkpoint, Some(3));
    let e = read.table.get("AKVL0001").unwrap();
    assert!(e.private.is_some(), "opened from the older checkpoint");
    assert_eq!(e.effective_status(), SubjectStatus::Active);
    // A writer with the same ring and a cached table that holds the
    // subject closed opens it the same way, so a narrowing goes through.
    let mut cached = read3.table.clone();
    assert!(cached.get("AKVL0001").unwrap().private.is_none());
    let writer = env_with!(w, &v23, &adm, &units);
    let narrow = KeyRequest::SetGrants {
        id: "AKVL0001".into(),
        grants: vec![grant("b_01", RO, Some("x/"))],
        acting: None,
    };
    assert_eq!(
        writer
            .change(&mut cached, "n", &narrow, &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
}

/// A closing record that follows an opening one the directory has not
/// acknowledged does not open the subject at a unit.
#[tokio::test(flavor = "current_thread")]
async fn a_close_after_an_unacknowledged_open_keeps_the_subject_closed() {
    // Re-enable with the directory down, then narrow.
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(140);
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
    let narrow = KeyRequest::SetGrants {
        id: "AKVL0001".into(),
        grants: vec![grant("b_01", RO, Some("x/"))],
        acting: None,
    };
    assert_eq!(
        env.change(&mut table, "n", &narrow, &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 5 }
    );
    for unit in [&w.root, &w.unit2] {
        assert_eq!(unit.status("AKVL0001"), Some(SubjectStatus::Disabled));
    }

    // Widen with the directory down, then narrow within the widening.
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
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
    let narrow = KeyRequest::SetGrants {
        id: "AKVL0001".into(),
        grants: vec![grant("b_01", RW, Some("x/"))],
        acting: None,
    };
    assert_eq!(
        env.change(&mut table, "n", &narrow, &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
    for unit in [&w.root, &w.unit2] {
        let row = unit.row("AKVL0001").unwrap();
        assert_eq!(row.effective_status(), SubjectStatus::Disabled);
    }
    // Once the directory is back, the key opens as recorded.
    w.directory.down.set(false);
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(!report.retry(), "{report:?}");
    let row = w.root.row("AKVL0001").unwrap();
    assert_eq!(row.effective_status(), SubjectStatus::Active);
    assert_eq!(joined(&row), vec![grant("b_01", RW, Some("x/"))]);
}

/// A closing change with the directory unreadable narrows a key the
/// directory already has; it does not disable it.
#[tokio::test(flavor = "current_thread")]
async fn a_narrowing_with_the_directory_down_keeps_an_acknowledged_key_open() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(150);
    w.directory.down.set(true);
    let narrow = KeyRequest::SetGrants {
        id: "AKVL0001".into(),
        grants: vec![grant("b_01", RO, Some("x/"))],
        acting: None,
    };
    assert_eq!(
        env.change(&mut table, "n", &narrow, &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    for unit in [&w.root, &w.unit2] {
        let row = unit.row("AKVL0001").unwrap();
        assert_eq!(
            row.effective_status(),
            SubjectStatus::Active,
            "{}",
            unit.label
        );
        assert_eq!(joined(&row), vec![grant("b_01", RO, Some("x/"))]);
        assert_eq!(unit.status("PR0001"), Some(SubjectStatus::Active));
    }
}

/// A unit that missed a narrowing of a principal is brought up by a
/// finisher while the directory is unreadable: the principal stays
/// open there, narrowed.
#[tokio::test(flavor = "current_thread")]
async fn a_finisher_with_the_directory_down_narrows_without_disabling() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(151);
    w.unit2.down.set(true);
    let narrow = KeyRequest::SetGrants {
        id: "PR0001".into(),
        grants: vec![grant("b_01", RO, None)],
        acting: None,
    };
    assert_eq!(
        env.change(&mut table, "n", &narrow, &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Unfinished { seq: 3 }
    );
    w.unit2.down.set(false);
    w.directory.down.set(true);
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(report.retry());
    let row = w.unit2.row("PR0001").unwrap();
    assert_eq!(row.effective_status(), SubjectStatus::Active);
    assert_eq!(joined(&row), vec![grant("b_01", RO, None)]);
    assert_eq!(w.unit2.status("AKVL0001"), Some(SubjectStatus::Active));
}

/// A refusal that comes after a catch-up that could not reach every
/// unit in full answers busy, not the refusal.
#[tokio::test(flavor = "current_thread")]
async fn a_refusal_after_a_partial_catch_up_answers_busy() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(152);
    w.root.reset();
    w.directory.down.set(true);
    let key = s3_key(&w.t, "AKVL0002", "PR0001", &[grant("b_01", RO, None)]);
    assert_eq!(
        env.change(&mut table, "c", &KeyRequest::Create(key), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Busy
    );
}

// ---------------------------------------------------------------------------
// AM-18: milestone 1 serves unlimited grants only
// ---------------------------------------------------------------------------

fn limited_grants() -> Vec<(&'static str, Grant)> {
    let mut expiring = grant("b_01", RO, None);
    expiring.expires_at = Some(1_800_000_000_000);
    let mut addressed = grant("b_01", RO, None);
    addressed.ip_list = vec!["203.0.113.7".into()];
    vec![
        ("prefix", grant("b_01", RO, Some("x/"))),
        ("expiry", expiring),
        ("ip list", addressed),
    ]
}

/// A create whose grant has a prefix, an expiry or an IP list is refused
/// with `400 grant_limits_not_served`: no reservation, intent, route or
/// record.
#[tokio::test(flavor = "current_thread")]
async fn a_create_with_a_limited_grant_is_refused_before_its_reservation() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let mut env = env!(w, &adm, &units);
    env.limits = Limits::NotServed;
    let mut rng = TestRng(180);
    let head = w.head();
    let calls = adm.calls.get();
    let sent = w.intents.sent.borrow().len();
    for (what, g) in limited_grants() {
        let key = s3_key(&w.t, "AKVL0180", "PR0001", &[g]);
        let answer = env
            .change(&mut table, "i180", &KeyRequest::Create(key), &mut rng)
            .await
            .unwrap();
        assert_eq!(
            answer,
            KeyAnswer::Refused(Refusal::GrantLimitsNotServed),
            "{what}"
        );
    }
    assert_eq!(Refusal::GrantLimitsNotServed.status(), 400);
    assert_eq!(
        Refusal::GrantLimitsNotServed.code(),
        "grant_limits_not_served"
    );
    assert_eq!(w.head(), head);
    assert_eq!(adm.calls.get(), calls);
    assert_eq!(w.intents.sent.borrow().len(), sent);
    assert!(read_route(&w.store, &w.kek, "AKVL0180")
        .await
        .unwrap()
        .is_none());
    // The same key without the limit is made.
    let key = s3_key(&w.t, "AKVL0180", "PR0001", &[grant("b_01", RO, None)]);
    assert!(matches!(
        env.change(&mut table, "i180", &KeyRequest::Create(key), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { .. }
    ));
}

/// A grant change that adds a limit is refused, a narrowing among them
/// (it would leave a key that cannot work); one that adds none is made.
#[tokio::test(flavor = "current_thread")]
async fn a_grant_change_that_adds_a_limit_is_refused() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let mut env = env!(w, &adm, &units);
    env.limits = Limits::NotServed;
    let mut rng = TestRng(181);
    let p = principal(
        "PR0181",
        &[grant("b_01", RW, None), grant("b_02", RW, None)],
    );
    assert!(matches!(
        env.change(&mut table, "i181p", &KeyRequest::Create(p), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { .. }
    ));
    let key = s3_key(
        &w.t,
        "AKVL0181",
        "PR0181",
        &[grant("b_01", RO, None), grant("b_02", RO, None)],
    );
    assert!(matches!(
        env.change(&mut table, "i181", &KeyRequest::Create(key), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { .. }
    ));
    let head = w.head();
    for (what, g) in limited_grants() {
        let answer = env
            .change(
                &mut table,
                "i181b",
                &KeyRequest::SetGrants {
                    id: "AKVL0181".into(),
                    grants: vec![g],
                    acting: None,
                },
                &mut rng,
            )
            .await
            .unwrap();
        assert_eq!(
            answer,
            KeyAnswer::Refused(Refusal::GrantLimitsNotServed),
            "{what}"
        );
    }
    assert_eq!(w.head(), head);
    // A narrowing with no limit (a bucket dropped) is recorded.
    assert!(matches!(
        env.change(
            &mut table,
            "i181c",
            &KeyRequest::SetGrants {
                id: "AKVL0181".into(),
                grants: vec![grant("b_01", RO, None)],
                acting: None,
            },
            &mut rng,
        )
        .await
        .unwrap(),
        KeyAnswer::Done { .. }
    ));
    assert_eq!(w.head(), head + 1);
}

// ---------------------------------------------------------------------------
// The creator-grant writer (DS1 A7, ADR §6.2, AM-8, AM-24)
// ---------------------------------------------------------------------------

fn photos(creator: &str) -> BucketRequest<'_> {
    BucketRequest {
        name: "photos",
        creator,
        unit: 1,
    }
}

/// The grants of `id` at the chain's head.
async fn head_grants(w: &World, id: &str) -> Vec<String> {
    let read = read_key_chain(&w.store, &w.kek, &w.ring, &w.t)
        .await
        .unwrap();
    read.table
        .get(id)
        .unwrap()
        .door
        .grants
        .iter()
        .map(|g| g.bucket_id.clone())
        .collect()
}

/// Every subject at the head that holds a grant on `bucket`.
async fn holders(w: &World, bucket: &BucketId) -> Vec<String> {
    let read = read_key_chain(&w.store, &w.kek, &w.ring, &w.t)
        .await
        .unwrap();
    read.table
        .entries()
        .filter(|e| e.door.grants.iter().any(|g| g.bucket_id == bucket.as_str()))
        .map(|e| e.door.id.clone())
        .collect()
}

/// The entry of `id` at the chain's head (sync, from the planted store).
fn read_entry(w: &World, id: &str) -> Entry {
    let mut table = velmora_bridge::keys::record::KeyTable::empty(w.t.clone());
    let chain = key_chain(&w.t);
    let mut seq = 1;
    while let Some(bytes) = w.store.raw(&chain.name(seq)) {
        let record = open_key_record(&w.kek, &w.ring, &w.t, seq, &bytes).unwrap();
        table.apply(&record).unwrap();
        seq += 1;
    }
    table.get(id).unwrap().clone()
}

/// A create writes the creator grant at exactly the reservation's
/// `keys_seq + 1` = K, binds K to the reservation, derives the bucket id
/// from K, and records `bucket_created` with `grant_seq = K`. Only the
/// creator gains the grant: no key under it does.
#[tokio::test(flavor = "current_thread")]
async fn a_bucket_create_writes_the_creator_grant_first_with_the_derived_id() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let answer = env
        .create_bucket(
            &buckets,
            &mut table,
            "ib1",
            &photos("PR0001"),
            &mut TestRng(200),
        )
        .await
        .unwrap();
    let id3 = bucket_id(&w.t, 3);
    assert_eq!(
        answer,
        BucketAnswer::Created {
            bucket: id3.clone(),
            grant_seq: 3,
        }
    );
    assert_eq!(w.head(), 3);
    let bytes = key_chain(&w.t).get(&w.store, 3).await.unwrap();
    let record = open_key_record(&w.kek, &w.ring, &w.t, 3, &bytes).unwrap();
    assert_eq!(record.op, KeyOp::Grants);
    assert_eq!(record.door.id, "PR0001");
    assert!(!record.closes, "a creator grant opens");
    assert_eq!(
        joined(&w.root.row("PR0001").unwrap()),
        vec![grant("b_01", RW, None), grant(id3.as_str(), RW, None)]
    );
    assert_eq!(
        *buckets.placed.borrow(),
        vec![(id3.as_str().to_owned(), 1, "PR0001".to_owned(), 3)]
    );
    assert_eq!(adm.bucket_open.borrow()["ib1"].2, Some(3), "K is bound");
    assert!(w.intents.sent.borrow().contains(&3));
    assert!(w
        .intents
        .noted
        .borrow()
        .contains(&(3, BUCKET_CREATE_KIND.to_owned())));
    // A key gets nothing from it.
    assert_eq!(holders(&w, &id3).await, vec!["PR0001".to_owned()]);
    for store in [&w.root, &w.unit2, &w.directory] {
        assert_eq!(store.seq.get(), 3);
    }
    assert!(adm.released.borrow().is_empty());
}

/// Another record lands between the reservation and the put: the put
/// loses, the reservation is asked for again at the new head, and the id
/// is derived from the seq of this writer's own put.
#[tokio::test(flavor = "current_thread")]
async fn a_lost_grant_put_derives_the_id_from_its_own_seq() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let disable_at_3 = {
        let w = &w;
        move || {
            let e = read_entry(w, "AKVL0001");
            let mut door = e.door.clone();
            door.status = SubjectStatus::Disabled;
            let bytes = seal_key_record(
                &w.kek,
                &w.ring,
                &w.t,
                3,
                KeyOp::Status,
                9,
                &door,
                e.private.as_ref(),
                true,
                None,
                &mut TestRng(201),
            )
            .unwrap();
            w.store.plant(&key_chain(&w.t).name(3), bytes);
            3
        }
    };
    *adm.race.borrow_mut() = Some(Box::new(disable_at_3));
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let answer = env
        .create_bucket(
            &buckets,
            &mut table,
            "ib2",
            &photos("PR0001"),
            &mut TestRng(202),
        )
        .await
        .unwrap();
    assert_eq!(
        answer,
        BucketAnswer::Created {
            bucket: bucket_id(&w.t, 4),
            grant_seq: 4,
        }
    );
    assert_eq!(w.head(), 4);
    assert_eq!(
        head_grants(&w, "PR0001").await,
        vec!["b_01".to_owned(), bucket_id(&w.t, 4).as_str().to_owned()]
    );
    assert_eq!(buckets.calls.get(), 1, "only the grant it wrote is placed");
    assert_eq!(adm.bucket_open.borrow()["ib2"].2, Some(4));
}

/// A put whose answer was lost is read back: the same bytes are this
/// writer's, so K is still its own.
#[tokio::test(flavor = "current_thread")]
async fn a_lost_answer_of_the_grant_put_is_read_back() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    w.store.lose_answers(1);
    let answer = env
        .create_bucket(
            &buckets,
            &mut table,
            "ib3",
            &photos("PR0001"),
            &mut TestRng(203),
        )
        .await
        .unwrap();
    assert_eq!(
        answer,
        BucketAnswer::Created {
            bucket: bucket_id(&w.t, 3),
            grant_seq: 3,
        }
    );
    assert_eq!(w.head(), 3);
}

/// (Review H1.) `bucket_created` is recorded but every answer is lost:
/// the call answers unfinished, and the retry under the same key places
/// the bound grant's bucket again. One create, one bucket.
#[tokio::test(flavor = "current_thread")]
async fn a_retry_after_a_lost_placement_answer_places_no_second_bucket() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(211);
    buckets.lose_answers.set(MAX_ORDER_TRIES);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib11", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 }
    );
    let id3 = bucket_id(&w.t, 3);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib11", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Created {
            bucket: id3.clone(),
            grant_seq: 3,
        }
    );
    assert_eq!(buckets.placed.borrow().len(), 1);
    assert_eq!(w.head(), 3, "no second grant");
    // A second call while the first is placed: the same bucket.
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib11", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Created {
            bucket: id3,
            grant_seq: 3,
        }
    );
    assert_eq!(w.head(), 3);
}

/// (Review M1.) A placement that the directory or the unit has not
/// acknowledged answers unfinished, not `200`; the retry answers it once
/// it is in force.
#[tokio::test(flavor = "current_thread")]
async fn a_bucket_that_is_not_in_force_answers_unfinished() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(212);
    buckets.not_in_force.set(true);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib12", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 }
    );
    buckets.not_in_force.set(false);
    w.directory.down.set(true);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib12", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 },
        "the creator grant is not acknowledged by the directory"
    );
    w.directory.down.set(false);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib12", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Created {
            bucket: bucket_id(&w.t, 3),
            grant_seq: 3,
        }
    );
    assert_eq!(buckets.placed.borrow().len(), 1);
}

/// (Review M2.) The retry of a create whose grant was the creator's 64th,
/// or whose creator was disabled since, is answered its bucket, not a
/// refusal.
#[tokio::test(flavor = "current_thread")]
async fn a_retry_is_answered_its_bucket_whatever_the_creator_is_now() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(213);
    let many: Vec<Grant> = (0..63)
        .map(|i| grant(&format!("b_{i:02}"), RW, None))
        .collect();
    assert!(matches!(
        env.change(
            &mut table,
            "p63",
            &KeyRequest::Create(principal("PR0063", &many)),
            &mut rng
        )
        .await
        .unwrap(),
        KeyAnswer::Done { seq: 3 }
    ));
    buckets.not_in_force.set(true);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib13", &photos("PR0063"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 4 }
    );
    assert_eq!(head_grants(&w, "PR0063").await.len(), 64);
    buckets.not_in_force.set(false);
    let id4 = BucketAnswer::Created {
        bucket: bucket_id(&w.t, 4),
        grant_seq: 4,
    };
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib13", &photos("PR0063"), &mut rng)
            .await
            .unwrap(),
        id4
    );
    assert!(matches!(
        env.change(&mut table, "d", &disable("PR0063"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { .. }
    ));
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib13", &photos("PR0063"), &mut rng)
            .await
            .unwrap(),
        id4
    );
    assert_eq!(buckets.placed.borrow().len(), 1);
}

/// (Review L3.) A grant on the id that K derives, held before the bucket
/// exists by another subject, is dropped first: only the creator reaches
/// the new bucket.
#[tokio::test(flavor = "current_thread")]
async fn a_grant_held_on_the_next_derived_id_is_dropped_first() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(214);
    // PR0002, made at seq 3, holds a grant on the id K = 4 would derive.
    let id4 = bucket_id(&w.t, 4);
    let early = principal("PR0002", &[grant(id4.as_str(), RW, None)]);
    assert!(matches!(
        env.change(&mut table, "p2", &KeyRequest::Create(early), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    ));
    let answer = env
        .create_bucket(&buckets, &mut table, "ib14", &photos("PR0001"), &mut rng)
        .await
        .unwrap();
    // 4 drops PR0002's grant; the creator grant is 5.
    let id5 = bucket_id(&w.t, 5);
    assert_eq!(
        answer,
        BucketAnswer::Created {
            bucket: id5.clone(),
            grant_seq: 5,
        }
    );
    assert!(holders(&w, &id4).await.is_empty());
    assert_eq!(holders(&w, &id5).await, vec!["PR0001".to_owned()]);
}

/// A create that loses the K order revokes its orphan grant with a
/// closing record (the creator's other grants stay), then writes a new
/// creator grant at a new K under the same reservation.
#[tokio::test(flavor = "current_thread")]
async fn a_create_that_loses_the_order_revokes_its_orphan_and_tries_again() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    buckets.lose_orders.set(1);
    let answer = env
        .create_bucket(
            &buckets,
            &mut table,
            "ib4",
            &photos("PR0001"),
            &mut TestRng(204),
        )
        .await
        .unwrap();
    let id5 = bucket_id(&w.t, 5);
    assert_eq!(
        answer,
        BucketAnswer::Created {
            bucket: id5.clone(),
            grant_seq: 5,
        }
    );
    // 3: the orphan grant; 4: its revoke (closing); 5: the new grant.
    let bytes = key_chain(&w.t).get(&w.store, 4).await.unwrap();
    let revoke = open_key_record(&w.kek, &w.ring, &w.t, 4, &bytes).unwrap();
    assert!(revoke.closes);
    assert_eq!(
        head_grants(&w, "PR0001").await,
        vec!["b_01".to_owned(), id5.as_str().to_owned()]
    );
    assert_eq!(
        joined(&w.root.row("PR0001").unwrap()),
        vec![grant("b_01", RW, None), grant(id5.as_str(), RW, None)]
    );
    assert_eq!(*adm.bucket_asks.borrow(), vec!["ib4", "ib4"]);
    assert_eq!(adm.bucket_open.borrow()["ib4"].2, Some(5), "bound again");
    assert!(adm.released.borrow().is_empty());
}

/// After [`MAX_ORDER_TRIES`] lost orders the call answers busy, and no
/// orphan grant is left. A retry does not place a lost one again.
#[tokio::test(flavor = "current_thread")]
async fn three_lost_orders_answer_busy_and_leave_no_orphan() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(205);
    buckets.lose_orders.set(MAX_ORDER_TRIES);
    let answer = env
        .create_bucket(&buckets, &mut table, "ib5", &photos("PR0001"), &mut rng)
        .await
        .unwrap();
    assert_eq!(answer, BucketAnswer::Busy);
    let head = 2 + 2 * u64::from(MAX_ORDER_TRIES);
    assert_eq!(w.head(), head);
    assert_eq!(head_grants(&w, "PR0001").await, vec!["b_01".to_owned()]);
    assert_eq!(
        joined(&w.root.row("PR0001").unwrap()),
        vec![grant("b_01", RW, None)]
    );
    assert!(buckets.placed.borrow().is_empty());
    assert_eq!(adm.bucket_asks.borrow().len(), MAX_ORDER_TRIES as usize);
    // The retry: the bound seq lost (its revoke is in the head), so a
    // new grant is written and placed.
    let answer = env
        .create_bucket(&buckets, &mut table, "ib5", &photos("PR0001"), &mut rng)
        .await
        .unwrap();
    assert_eq!(
        answer,
        BucketAnswer::Created {
            bucket: bucket_id(&w.t, head + 1),
            grant_seq: head + 1,
        }
    );
    assert_eq!(buckets.placed.borrow().len(), 1);
}

/// Any other refusal of `bucket_created` (here `restoring`) revokes the
/// orphan grant, releases the reservation and answers the refusal.
#[tokio::test(flavor = "current_thread")]
async fn a_state_refusal_revokes_the_orphan_and_releases_the_reservation() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    buckets.refuse.set(Some((409, "restoring")));
    let answer = env
        .create_bucket(
            &buckets,
            &mut table,
            "ib6",
            &photos("PR0001"),
            &mut TestRng(206),
        )
        .await
        .unwrap();
    assert_eq!(
        answer,
        BucketAnswer::StateRefused {
            status: 409,
            code: "restoring"
        }
    );
    assert_eq!(w.head(), 4);
    assert_eq!(head_grants(&w, "PR0001").await, vec!["b_01".to_owned()]);
    assert_eq!(
        joined(&w.root.row("PR0001").unwrap()),
        vec![grant("b_01", RW, None)]
    );
    assert_eq!(*adm.released.borrow(), vec!["ib6".to_owned()]);
}

/// The creator is checked at the head: it must exist, be an active
/// principal and have room for one more grant. A refusal after the
/// reservation releases it.
#[tokio::test(flavor = "current_thread")]
async fn the_creator_is_checked_and_a_refusal_releases_the_reservation() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(207);
    let full: Vec<Grant> = (0..64)
        .map(|i| grant(&format!("b_{i:02}"), RW, None))
        .collect();
    for (id, request) in [
        ("PR0064", KeyRequest::Create(principal("PR0064", &full))),
        ("PR0003", KeyRequest::Create(principal("PR0003", &[]))),
    ] {
        assert!(
            matches!(
                env.change(&mut table, id, &request, &mut rng)
                    .await
                    .unwrap(),
                KeyAnswer::Done { .. }
            ),
            "{id}"
        );
    }
    assert!(matches!(
        env.change(&mut table, "d", &disable("PR0003"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { .. }
    ));
    let head = w.head();
    for (creator, refusal) in [
        ("PR0404", Refusal::NotFound),
        ("AKVL0001", Refusal::CreatorNotActive),
        ("PR0003", Refusal::CreatorNotActive),
        ("PR0064", Refusal::GrantCap),
    ] {
        let key = format!("ib7-{creator}");
        assert_eq!(
            env.create_bucket(&buckets, &mut table, &key, &photos(creator), &mut rng)
                .await
                .unwrap(),
            BucketAnswer::Refused(refusal),
            "{creator}"
        );
    }
    assert_eq!(Refusal::GrantCap.status(), 409);
    assert_eq!(Refusal::CreatorNotActive.status(), 403);
    assert_eq!(w.head(), head);
    assert_eq!(buckets.calls.get(), 0);
    // Only the one the unit admitted held a reservation to release.
    assert_eq!(*adm.released.borrow(), vec!["ib7-PR0064".to_owned()]);
}

/// A full bucket cap answers `429` before any record; a retry whose
/// reservation already became a bucket answers that bucket and writes
/// nothing; a reservation that names an id that is not derived is an
/// error.
#[tokio::test(flavor = "current_thread")]
async fn the_reservation_answers_the_cap_and_retries() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(208);
    adm.bucket_cap.set(0);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib8", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Refused(Refusal::CapFull)
    );
    assert_eq!(adm.bucket_asks.borrow().len(), 1, "a cap is not stale");
    adm.bucket_cap.set(50);
    *adm.bucket_done.borrow_mut() = Some((bucket_id(&w.t, 7), 7));
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib8", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Created {
            bucket: bucket_id(&w.t, 7),
            grant_seq: 7,
        }
    );
    *adm.bucket_done.borrow_mut() = Some((bucket_id(&w.t, 8), 7));
    assert!(env
        .create_bucket(&buckets, &mut table, "ib8", &photos("PR0001"), &mut rng)
        .await
        .is_err());
    assert_eq!(w.head(), 2);
    // Only the retry asked the tenant chain, to confirm it is in force.
    assert_eq!(buckets.calls.get(), 1);
}

/// The finisher decides every creator grant by its reservation: it
/// places the bucket of an open bound one (the call that wrote it could
/// not), and revokes one no open reservation is bound to.
#[tokio::test(flavor = "current_thread")]
async fn the_finisher_places_a_bound_grant_and_revokes_an_unbound_one() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(209);

    // (a) The tenant chain is down for the call: grant 3, bound.
    buckets.down.set(true);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib9", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 }
    );
    let mut fin = table.clone();
    assert!(
        finish_creator_grant(&env, &buckets, &mut fin, 3, &mut rng)
            .await
            .is_err(),
        "the tenant chain is still down: the message is retried"
    );
    buckets.down.set(false);
    assert_eq!(
        finish_creator_grant(&env, &buckets, &mut fin, 3, &mut rng)
            .await
            .unwrap(),
        CreatorGrant::Placed
    );
    assert_eq!(buckets.placed.borrow().len(), 1);
    assert_eq!(buckets.placed.borrow()[0].3, 3);

    // (b) The bind fails: grant 4 is never bound, so never placed.
    adm.bind_down.set(true);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib10", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 4 }
    );
    adm.bind_down.set(false);
    assert_eq!(
        finish_creator_grant(&env, &buckets, &mut fin, 4, &mut rng)
            .await
            .unwrap(),
        CreatorGrant::Revoked { seq: 5 }
    );
    let id4 = bucket_id(&w.t, 4);
    assert!(holders(&w, &id4).await.is_empty());
    assert_eq!(buckets.placed.borrow().len(), 1);
    // Again: already revoked, nothing written.
    assert_eq!(
        finish_creator_grant(&env, &buckets, &mut fin, 4, &mut rng)
            .await
            .unwrap(),
        CreatorGrant::Revoked { seq: 5 }
    );
    assert_eq!(w.head(), 5);
    for (seq, outcome) in [
        (3, CreatorGrant::Placed),
        (2, CreatorGrant::NotOne),
        (5, CreatorGrant::NotOne),
        (9, CreatorGrant::NotOne),
    ] {
        assert_eq!(
            finish_creator_grant(&env, &buckets, &mut fin, seq, &mut rng)
                .await
                .unwrap(),
            outcome,
            "seq {seq}"
        );
    }
}

/// An open bound grant whose bucket the tenant chain refuses is revoked by
/// the finisher, and its reservation released.
#[tokio::test(flavor = "current_thread")]
async fn the_finisher_revokes_a_bound_grant_the_tenant_chain_refuses() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(215);
    buckets.down.set(true);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib15", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 }
    );
    buckets.down.set(false);
    buckets.refuse.set(Some((409, "restoring")));
    let mut fin = table.clone();
    assert_eq!(
        finish_creator_grant(&env, &buckets, &mut fin, 3, &mut rng)
            .await
            .unwrap(),
        CreatorGrant::Revoked { seq: 4 }
    );
    assert_eq!(*adm.released.borrow(), vec!["ib15".to_owned()]);
    assert!(holders(&w, &bucket_id(&w.t, 3)).await.is_empty());
}

/// `DropGrant` removes one bucket's grant and keeps every other one, at
/// the head: a change to the subject's other grants is never undone.
#[tokio::test(flavor = "current_thread")]
async fn drop_grant_removes_one_bucket_at_the_head() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(210);
    let mut stale = table.clone();
    let mut current = table;
    let widen = KeyRequest::SetGrants {
        id: "PR0001".into(),
        grants: vec![
            grant("b_01", RW, None),
            grant("b_02", RW, None),
            grant("b_03", RW, None),
        ],
        acting: None,
    };
    assert!(matches!(
        env.change(&mut current, "w", &widen, &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    ));
    // The stale copy is brought to the head before it plans.
    let drop = KeyRequest::DropGrant {
        id: "PR0001".into(),
        bucket_id: "b_02".into(),
    };
    assert_eq!(
        env.change(&mut stale, "", &drop, &mut rng).await.unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
    assert_eq!(
        head_grants(&w, "PR0001").await,
        vec!["b_01".to_owned(), "b_03".to_owned()]
    );
    // Again: in the head already, nothing written.
    assert_eq!(
        env.change(&mut stale, "", &drop, &mut rng).await.unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
    assert_eq!(w.head(), 4);
}

// ---------------------------------------------------------------------------
// KeyVersionGone in the finisher (AM-11)
// ---------------------------------------------------------------------------

/// A ring with version 2 only; version 1 gone or merely not loaded.
struct OnlyTwo {
    key: TenantKey,
    one_gone: bool,
}

impl velmora_bridge::keys::record::TkRing for OnlyTwo {
    fn current(&self) -> Option<&TenantKey> {
        Some(&self.key)
    }
    fn key(&self, v: u32) -> Option<&TenantKey> {
        (v == 2).then_some(&self.key)
    }
    fn gone(&self, v: u32) -> bool {
        self.one_gone && v == 1
    }
}

/// Subjects whose private part is sealed under a gone version are applied
/// disabled, reported as gone, not retried, and their pending rows clear.
/// The same subjects under a version that merely did not load are closed
/// and retried.
#[tokio::test(flavor = "current_thread")]
async fn subjects_under_a_gone_version_are_disabled_reported_and_not_retried() {
    for one_gone in [true, false] {
        let w = World::new();
        let adm = FakeAdmission::new(&w.root);
        let mut table = seed(&w, &adm).await;
        let units = w.units();
        let env = env!(w, &adm, &units);
        // A third subject, revoked: it stays revoked and is not reported.
        let k3 = s3_key(&w.t, "AKVL0003", "PR0001", &[grant("b_01", RO, None)]);
        let mut rng = TestRng(220);
        assert!(matches!(
            env.change(&mut table, "k3", &KeyRequest::Create(k3), &mut rng)
                .await
                .unwrap(),
            KeyAnswer::Done { .. }
        ));
        assert!(matches!(
            env.change(&mut table, "r3", &revoke("AKVL0003"), &mut rng)
                .await
                .unwrap(),
            KeyAnswer::Done { .. }
        ));
        let ring = OnlyTwo {
            key: TenantKey::from_bytes(&w.t, 2, derived("tk 2")).unwrap(),
            one_gone,
        };
        let env2 = env_with!(w, &ring, &adm, &units);
        let report = finish_keys(&env2, &mut rng).await.unwrap();
        let both = vec!["AKVL0001".to_owned(), "PR0001".to_owned()];
        if one_gone {
            assert_eq!(report.gone, both);
            assert!(report.closed.is_empty());
            assert!(!report.retry());
            assert_eq!(w.intents.cleared.borrow().last(), Some(&report.head));
        } else {
            assert!(report.gone.is_empty());
            assert_eq!(report.closed, both);
            assert!(report.retry());
        }
        // Gone: disabled by a record, whatever row a store held. Not
        // loaded: a store keeps the open row it holds at the same seq.
        let expected = match one_gone {
            true => SubjectStatus::Disabled,
            false => SubjectStatus::Active,
        };
        assert_eq!(report.gone_disabled.len(), if one_gone { 2 } else { 0 });
        for store in [&w.root, &w.unit2, &w.directory] {
            assert_eq!(store.status("AKVL0001"), Some(expected));
            assert_eq!(store.status("PR0001"), Some(expected));
            assert_eq!(store.status("AKVL0003"), Some(SubjectStatus::Revoked));
        }
        // A second run writes nothing more.
        let head = report.head;
        let again = finish_keys(&env2, &mut rng).await.unwrap();
        assert_eq!(again.head, head);
        assert!(again.gone_disabled.is_empty());
        assert_eq!(again.gone, report.gone);
    }
}

/// A ring with version 3 current, the keys `held`, and the versions
/// `gone` marked gone; `partial`: a committed version did not load.
struct Ring3 {
    keys: Vec<TenantKey>,
    gone: Vec<u32>,
    partial: bool,
}

impl velmora_bridge::keys::record::TkRing for Ring3 {
    fn current(&self) -> Option<&TenantKey> {
        self.keys.iter().find(|k| k.version() == 3)
    }
    fn key(&self, v: u32) -> Option<&TenantKey> {
        self.keys.iter().find(|k| k.version() == v)
    }
    fn gone(&self, v: u32) -> bool {
        self.gone.contains(&v)
    }
    fn partial(&self) -> bool {
        self.partial
    }
}

/// (Review of the gone-disable.) Version 1 is gone, but a checkpoint
/// sealed under version 2 carries both subjects whole. While version 2
/// does not load (a partial ring), or is merely missing from the ring,
/// nothing is disabled and the run is retried; with version 2 loaded the
/// subjects open; only with version 2 gone too are they disabled.
#[tokio::test(flavor = "current_thread")]
async fn a_private_part_a_checkpoint_may_hold_is_never_taken_for_lost() {
    let tk = |v: u32| TenantKey::from_bytes(&tenant(1), v, derived(&format!("tk {v}"))).unwrap();
    for (case, held, gone, partial, checkpoint) in [
        ("v2 did not load", vec![3], vec![1], true, true),
        ("v2 missing, not gone", vec![3], vec![1], false, true),
        ("v2 loaded", vec![2, 3], vec![1], false, true),
        ("v2 gone too", vec![3], vec![1, 2], false, true),
        ("no checkpoint, partial ring", vec![3], vec![1], true, false),
        ("no checkpoint", vec![3], vec![1], false, false),
    ] {
        let w = World::new();
        let adm = FakeAdmission::new(&w.root);
        let table = seed(&w, &adm).await;
        // A checkpoint at seq 2, sealed under version 2.
        let record = key_chain(&w.t).get(&w.store, 2).await.unwrap();
        let sealed = velmora_bridge::keys::checkpoint::seal_checkpoint(
            &w.kek,
            &OneKey(tk(2)),
            &table,
            &record,
            &mut TestRng(230),
        )
        .unwrap();
        if checkpoint {
            w.store.plant(
                &velmora_bridge::keys::checkpoint::checkpoint_name(&w.t, 2),
                sealed,
            );
        }
        let ring = Ring3 {
            keys: held.iter().map(|v| tk(*v)).collect(),
            gone,
            partial,
        };
        let units = w.units();
        let env = env_with!(w, &ring, &adm, &units);
        let report = finish_keys(&env, &mut TestRng(231)).await.unwrap();
        let both = vec!["AKVL0001".to_owned(), "PR0001".to_owned()];
        match case {
            "v2 gone too" | "no checkpoint" => {
                assert_eq!(report.gone, both, "{case}");
                assert_eq!(report.gone_disabled.len(), 2, "{case}");
            }
            "v2 loaded" => {
                assert!(report.gone.is_empty() && report.closed.is_empty(), "{case}");
                assert!(!report.retry(), "{case}");
            }
            _ => {
                assert!(report.gone.is_empty(), "{case}");
                assert!(report.gone_disabled.is_empty(), "{case}");
                assert_eq!(report.closed, both, "{case}");
                assert!(report.retry(), "{case}");
                assert_eq!(w.root.status("AKVL0001"), Some(SubjectStatus::Active));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Second review of the creator-grant writer and the gone-disable
// ---------------------------------------------------------------------------

mod interleave {
    //! Polls one call until it parks, inside another call's step: two
    //! calls under one key, overlapping.
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    pub type BoxFut<'b, T> = Pin<Box<dyn Future<Output = T> + 'b>>;

    pub fn poll_once<T>(f: &mut BoxFut<'_, T>) -> Option<T> {
        let mut cx = Context::from_waker(Waker::noop());
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(r) => Some(r),
            Poll::Pending => None,
        }
    }

    /// Ready once `gate` is set.
    pub async fn until(gate: &std::cell::Cell<bool>) {
        std::future::poll_fn(|_| match gate.get() {
            true => Poll::Ready(()),
            false => Poll::Pending,
        })
        .await
    }
}

use interleave::{poll_once, until, BoxFut};

/// Delegates to the fake; on its first `bind_bucket` it first polls
/// `other` until that call parks or ends. `gate`: this adm's own bind
/// waits until it opens.
struct HookAdm<'i, 'a, 'b> {
    inner: &'i FakeAdmission<'a>,
    other: RefCell<Option<BoxFut<'b, Result<BucketAnswer>>>>,
    other_done: RefCell<Option<Result<BucketAnswer>>>,
    gate: Option<&'b Cell<bool>>,
}

impl HookAdm<'_, '_, '_> {
    fn run_other(&self) {
        let taken = self.other.borrow_mut().take();
        if let Some(mut f) = taken {
            match poll_once(&mut f) {
                Some(r) => *self.other_done.borrow_mut() = Some(r),
                None => *self.other.borrow_mut() = Some(f),
            }
        }
    }
}

impl KeyAdmission for HookAdm<'_, '_, '_> {
    async fn admit(&self, t: &TenantId, k: &str, c: &OpeningChange<'_>) -> Result<Admission> {
        self.inner.admit(t, k, c).await
    }
    async fn release(&self, t: &TenantId, k: &str) -> Result<()> {
        self.inner.release(t, k).await
    }
    async fn admit_bucket(
        &self,
        t: &TenantId,
        k: &str,
        b: &BucketReservation<'_>,
    ) -> Result<BucketAdmission> {
        self.inner.admit_bucket(t, k, b).await
    }
    async fn bind_bucket(
        &self,
        t: &TenantId,
        k: &str,
        expected: Option<u64>,
        seq: u64,
    ) -> Result<bool> {
        self.run_other();
        if let Some(g) = self.gate {
            until(g).await;
        }
        self.inner.bind_bucket(t, k, expected, seq).await
    }
    async fn release_bound(&self, t: &TenantId, k: &str, bound: Option<u64>) -> Result<bool> {
        self.inner.release_bound(t, k, bound).await
    }
    async fn bucket_binding(&self, t: &TenantId, seq: u64) -> Result<Binding> {
        self.inner.bucket_binding(t, seq).await
    }
}

/// Two overlapping calls under one key: the second is admitted after
/// the first one's put and before its bind, and writes a grant of its
/// own. The bind is a compare-and-set, so one binds; the other revokes
/// its grant and places the bound one's bucket. One create, one bucket.
#[tokio::test(flavor = "current_thread")]
async fn two_overlapping_calls_under_one_key_place_one_bucket() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table_a = seed(&w, &adm).await;
    let units = w.units();
    let buckets = FakeBuckets::default();
    let gate = Cell::new(false);
    let adm_b = HookAdm {
        inner: &adm,
        other: RefCell::new(None),
        other_done: RefCell::new(None),
        gate: Some(&gate),
    };
    let env_b = env!(w, &adm_b, &units);
    let mut table_b = table(&w);
    let mut rng_b = TestRng(901);
    let req = photos("PR0001");
    let fut_b: BoxFut<'_, _> =
        Box::pin(env_b.create_bucket(&buckets, &mut table_b, "same", &req, &mut rng_b));
    let adm_a = HookAdm {
        inner: &adm,
        other: RefCell::new(Some(fut_b)),
        other_done: RefCell::new(None),
        gate: None,
    };
    let env_a = env!(w, &adm_a, &units);
    let a = env_a
        .create_bucket(&buckets, &mut table_a, "same", &req, &mut TestRng(902))
        .await
        .unwrap();
    gate.set(true);
    let fut_b = adm_a.other.borrow_mut().take();
    let b = match fut_b {
        Some(f) => f.await.unwrap(),
        None => adm_a.other_done.borrow_mut().take().unwrap().unwrap(),
    };
    assert_eq!(buckets.placed.borrow().len(), 1, "one create, one bucket");
    let placed = buckets.placed.borrow()[0].0.clone();
    assert!(matches!(a, BucketAnswer::Created { ref bucket, .. } if bucket.as_str() == placed));
    assert!(matches!(b, BucketAnswer::Created { ref bucket, .. } if bucket.as_str() == placed));
    assert_eq!(
        head_grants(&w, "PR0001").await,
        vec!["b_01".to_owned(), placed.clone()],
        "the losing call's grant is revoked"
    );
}

/// A retry answered `Created` by the reservation is answered `200` only
/// once the tenant chain's stores hold the bucket too.
#[tokio::test(flavor = "current_thread")]
async fn a_created_retry_waits_for_the_tenant_chain_in_force() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(921);
    buckets.not_in_force.set(true);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 }
    );
    // The root unit applied bucket_created; the directory has not.
    *adm.bucket_done.borrow_mut() = Some((bucket_id(&w.t, 3), 3));
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 }
    );
    buckets.not_in_force.set(false);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Created {
            bucket: bucket_id(&w.t, 3),
            grant_seq: 3,
        }
    );
}

/// A bound grant dropped after the create was recorded is a later change:
/// the retry places that grant's bucket and writes no second grant.
#[tokio::test(flavor = "current_thread")]
async fn a_bound_grant_dropped_since_is_still_placed() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(941);
    buckets.down.set(true);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 }
    );
    let drop = KeyRequest::DropGrant {
        id: "PR0001".into(),
        bucket_id: bucket_id(&w.t, 3).as_str().to_owned(),
    };
    assert_eq!(
        env.change(&mut table, "", &drop, &mut rng).await.unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
    buckets.down.set(false);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Created {
            bucket: bucket_id(&w.t, 3),
            grant_seq: 3,
        }
    );
    assert_eq!(buckets.placed.borrow().len(), 1);
    assert_eq!(buckets.placed.borrow()[0].3, 3);
    assert_eq!(w.head(), 4, "no second grant");
}

/// The finisher of an open bound grant runs the create again under its
/// reservation: after a lost order that is a new grant and a new bucket
/// (AM-8), and the old grant is revoked.
#[tokio::test(flavor = "current_thread")]
async fn the_finisher_creates_again_after_a_lost_order() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(951);
    buckets.down.set(true);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 }
    );
    buckets.down.set(false);
    buckets.lose_orders.set(1);
    let mut fin = table.clone();
    assert!(matches!(
        finish_creator_grant(&env, &buckets, &mut fin, 3, &mut rng)
            .await
            .unwrap(),
        CreatorGrant::Revoked { .. }
    ));
    let id5 = bucket_id(&w.t, 5);
    assert_eq!(buckets.placed.borrow().len(), 1);
    assert_eq!(buckets.placed.borrow()[0].0, id5.as_str());
    assert_eq!(
        head_grants(&w, "PR0001").await,
        vec!["b_01".to_owned(), id5.as_str().to_owned()]
    );
    assert!(
        adm.released.borrow().is_empty(),
        "its reservation became the bucket"
    );
}

/// A name and what to run on its second get.
type Hook<'a> = (String, Box<dyn FnOnce() + 'a>);

/// A store that runs a hook on the second get of one name, and counts
/// the gets under a prefix.
struct Watch<'a> {
    inner: &'a MemRecords,
    prefix: String,
    gets: Cell<u32>,
    seen: Cell<u32>,
    on_get: RefCell<Option<Hook<'a>>>,
}

impl RecordStore for Watch<'_> {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        self.inner.put_if_absent(name, bytes).await
    }
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        if name.starts_with(&self.prefix) {
            self.gets.set(self.gets.get() + 1);
        }
        let hook = match self.on_get.borrow().as_ref() {
            Some((n, _)) if n == name => {
                self.seen.set(self.seen.get() + 1);
                self.seen.get() == 2
            }
            _ => false,
        };
        if hook {
            if let Some((_, f)) = self.on_get.borrow_mut().take() {
                f();
            }
        }
        self.inner.get(name).await
    }
    async fn list(&self, prefix: &str, after: &str, limit: u32) -> Result<Vec<String>> {
        self.inner.list(prefix, after, limit).await
    }
}

/// (Review of the gone-disable.) A record that opens the subject lands
/// between the decision that its private part is lost and the disable:
/// the disable is not written. The checkpoints are read once per run,
/// whatever the number of lost subjects.
#[tokio::test(flavor = "current_thread")]
async fn a_subject_that_opens_after_the_decision_is_not_disabled() {
    // Restated under v3 (held: it opens) or v4 (neither held nor gone: it
    // stays closed, and is retried, not reported gone).
    for restated in [3, 4] {
        opens_after_the_decision(restated).await;
    }
}

async fn opens_after_the_decision(restated: u32) {
    use velmora_bridge::keys::checkpoint::{checkpoint_name, checkpoint_prefix, seal_checkpoint};
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let table = seed(&w, &adm).await;
    // Checkpoints at 1 and 2, both sealed under version 1 (gone).
    for seq in [1, 2] {
        let mut t = velmora_bridge::keys::record::KeyTable::empty(w.t.clone());
        for s in 1..=seq {
            let bytes = key_chain(&w.t).get(&w.store, s).await.unwrap();
            t.apply(&open_key_record(&w.kek, &w.ring, &w.t, s, &bytes).unwrap())
                .unwrap();
        }
        let record = key_chain(&w.t).get(&w.store, seq).await.unwrap();
        let sealed = seal_checkpoint(&w.kek, &w.ring, &t, &record, &mut TestRng(960)).unwrap();
        w.store.plant(&checkpoint_name(&w.t, seq), sealed);
    }
    let v3 = || TenantKey::from_bytes(&w.t, 3, derived("tk 3")).unwrap();
    let ring = Ring3 {
        keys: vec![v3()],
        gone: vec![1],
        partial: false,
    };
    // The hook: AKVL0001 is restated under version 3 at seq 3.
    let restate = {
        let w = &w;
        let key =
            TenantKey::from_bytes(&w.t, restated, derived(&format!("tk {restated}"))).unwrap();
        let e = table.get("AKVL0001").unwrap().clone();
        move || {
            let bytes = seal_key_record(
                &w.kek,
                &OneKey(key),
                &w.t,
                3,
                KeyOp::Restate,
                9,
                &e.door,
                e.private.as_ref(),
                false,
                None,
                &mut TestRng(961),
            )
            .unwrap();
            w.store.plant(&key_chain(&w.t).name(3), bytes);
        }
    };
    let store = Watch {
        inner: &w.store,
        prefix: checkpoint_prefix(&w.t),
        gets: Cell::new(0),
        seen: Cell::new(0),
        on_get: RefCell::new(Some((checkpoint_name(&w.t, 1), Box::new(restate)))),
    };
    let units = w.units();
    let env = KeyEnv {
        store: &store,
        kek: &w.kek,
        ring: &ring,
        tenant: &w.t,
        admission: &adm,
        intents: &w.intents,
        units: &units,
        directory: &&w.directory,
        clock: &w.clock,
        limits: Limits::Recorded,
        gate: &FakeGate::before_move(),
    };
    // Reading the chain gets each checkpoint once (none opens); the hook
    // fires on the second get of checkpoint 1, inside the one pass of the
    // lost decision, so the restate lands after AKVL0001 was found lost.
    let report = finish_keys(&env, &mut TestRng(962)).await.unwrap();
    let read = read_key_chain(&w.store, &w.kek, &ring, &w.t).await.unwrap();
    assert_eq!(
        read.table.get("AKVL0001").unwrap().private.is_some(),
        restated == 3
    );
    assert_eq!(
        read.table.get("AKVL0001").unwrap().door.status,
        SubjectStatus::Active,
        "the restated key is not disabled"
    );
    assert_eq!(
        read.table.get("PR0001").unwrap().door.status,
        SubjectStatus::Disabled
    );
    assert_eq!(report.gone, vec!["PR0001".to_owned()]);
    if restated == 4 {
        assert_eq!(report.closed, vec!["AKVL0001".to_owned()]);
        assert!(
            report.retry(),
            "a closed subject that is not lost is retried"
        );
    }
    // Two checkpoints: at most two gets to read the chain and two for the
    // one pass of the lost decision.
    assert!(store.gets.get() <= 4, "gets: {}", store.gets.get());
}

// ---------------------------------------------------------------------------
// Third review of the creator-grant writer
// ---------------------------------------------------------------------------

/// A bucket recorded under a bound grant stays the create's bucket after
/// its grant is dropped: the retry answers it and places no second one.
#[tokio::test(flavor = "current_thread")]
async fn a_placed_bucket_whose_grant_was_dropped_is_still_the_answer() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(970);
    buckets.lose_answers.set(MAX_ORDER_TRIES);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 }
    );
    let drop = KeyRequest::DropGrant {
        id: "PR0001".into(),
        bucket_id: bucket_id(&w.t, 3).as_str().to_owned(),
    };
    assert!(matches!(
        env.change(&mut table, "", &drop, &mut rng).await.unwrap(),
        KeyAnswer::Done { seq: 4 }
    ));
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Created {
            bucket: bucket_id(&w.t, 3),
            grant_seq: 3,
        }
    );
    assert_eq!(buckets.placed.borrow().len(), 1);
    assert_eq!(w.head(), 4, "no second grant");
}

/// A call that stalls between its put and its bind while the finisher
/// revokes the unbound grant: the finisher's answer fenced the seq, so the
/// late bind fails, and the call makes a new grant and bucket that its
/// creator holds.
#[tokio::test(flavor = "current_thread")]
async fn a_stalled_bind_never_binds_a_grant_the_finisher_revoked() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let buckets = FakeBuckets::default();
    let gate = Cell::new(false);
    let hooked = HookAdm {
        inner: &adm,
        other: RefCell::new(None),
        other_done: RefCell::new(None),
        gate: Some(&gate),
    };
    let env_a = env!(w, &hooked, &units);
    let req = photos("PR0001");
    let mut rng_a = TestRng(980);
    let mut call: BoxFut<'_, _> =
        Box::pin(env_a.create_bucket(&buckets, &mut table, "ib", &req, &mut rng_a));
    assert!(poll_once(&mut call).is_none(), "parked at its bind");
    assert_eq!(w.head(), 3);
    // The finisher of grant 3, past the intent's delay.
    let env = env!(w, &adm, &units);
    let mut fin = velmora_bridge::keys::record::KeyTable::empty(w.t.clone());
    assert_eq!(
        finish_creator_grant(&env, &buckets, &mut fin, 3, &mut TestRng(981))
            .await
            .unwrap(),
        CreatorGrant::Revoked { seq: 4 }
    );
    gate.set(true);
    let answer = call.await.unwrap();
    let BucketAnswer::Created { bucket, grant_seq } = answer else {
        panic!("{answer:?}");
    };
    assert_ne!(grant_seq, 3);
    assert_eq!(buckets.placed.borrow().len(), 1);
    assert_eq!(buckets.placed.borrow()[0].0, bucket.as_str());
    assert!(head_grants(&w, "PR0001")
        .await
        .contains(&bucket.as_str().to_owned()));
}

/// A refusal releases the reservation before it revokes the grant and
/// answers the `409`; that create never becomes a bucket, the finisher
/// revokes. A refusal whose release failed answers `503` and keeps both,
/// so the create may still finish later, by the finisher.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_create_never_becomes_a_bucket_later() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(991);
    buckets.refuse.set(Some((409, "restoring")));
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::StateRefused {
            status: 409,
            code: "restoring"
        }
    );
    buckets.refuse.set(None);
    let mut fin = table.clone();
    assert!(matches!(
        finish_creator_grant(&env, &buckets, &mut fin, 3, &mut rng)
            .await
            .unwrap(),
        CreatorGrant::Revoked { .. }
    ));
    assert!(buckets.placed.borrow().is_empty());
    assert_eq!(head_grants(&w, "PR0001").await, vec!["b_01".to_owned()]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_refusal_whose_release_failed_answers_503_and_may_finish() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(990);
    buckets.refuse.set(Some((409, "restoring")));
    adm.release_down.set(true);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 }
    );
    adm.release_down.set(false);
    assert_eq!(
        head_grants(&w, "PR0001").await,
        vec!["b_01".to_owned(), bucket_id(&w.t, 3).as_str().to_owned()],
        "the grant is kept with its reservation"
    );
    buckets.refuse.set(None);
    let mut fin = table.clone();
    assert_eq!(
        finish_creator_grant(&env, &buckets, &mut fin, 3, &mut rng)
            .await
            .unwrap(),
        CreatorGrant::Placed
    );
    assert_eq!(buckets.placed.borrow().len(), 1);
}

/// Releases the reservation inside `bucket_binding`, after answering it:
/// the client's refused retry releasing between the finisher's read and
/// its create.
struct ReleasingAdm<'i, 'a> {
    inner: &'i FakeAdmission<'a>,
}

impl KeyAdmission for ReleasingAdm<'_, '_> {
    async fn admit(&self, t: &TenantId, k: &str, c: &OpeningChange<'_>) -> Result<Admission> {
        self.inner.admit(t, k, c).await
    }
    async fn release(&self, t: &TenantId, k: &str) -> Result<()> {
        self.inner.release(t, k).await
    }
    async fn admit_bucket(
        &self,
        t: &TenantId,
        k: &str,
        b: &BucketReservation<'_>,
    ) -> Result<BucketAdmission> {
        self.inner.admit_bucket(t, k, b).await
    }
    async fn bind_bucket(&self, t: &TenantId, k: &str, e: Option<u64>, s: u64) -> Result<bool> {
        self.inner.bind_bucket(t, k, e, s).await
    }
    async fn release_bound(&self, t: &TenantId, k: &str, b: Option<u64>) -> Result<bool> {
        self.inner.release_bound(t, k, b).await
    }
    async fn bucket_binding(&self, t: &TenantId, seq: u64) -> Result<Binding> {
        let answer = self.inner.bucket_binding(t, seq).await?;
        if let Binding::Open {
            idempotency_key, ..
        } = &answer
        {
            self.inner.release(t, idempotency_key).await?;
        }
        Ok(answer)
    }
}

/// The finisher goes on only under the reservation bound to its grant: it
/// never reserves afresh, and undoes a reservation its own admission made.
#[tokio::test(flavor = "current_thread")]
async fn the_finisher_never_reserves_afresh() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let mut rng = TestRng(995);
    buckets.down.set(true);
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 }
    );
    buckets.down.set(false);
    let releasing = ReleasingAdm { inner: &adm };
    let env_f = env!(w, &releasing, &units);
    let mut fin = table.clone();
    assert!(matches!(
        finish_creator_grant(&env_f, &buckets, &mut fin, 3, &mut rng)
            .await
            .unwrap(),
        CreatorGrant::Revoked { .. }
    ));
    assert!(buckets.placed.borrow().is_empty());
    assert!(
        adm.bucket_open.borrow().is_empty(),
        "no fresh reservation left"
    );
}

/// `bucket_created` waits for its gate once (review round 4).
struct GatedBuckets<'i, 'g> {
    inner: &'i FakeBuckets,
    gate: RefCell<Option<&'g Cell<bool>>>,
}

impl BucketRecords for GatedBuckets<'_, '_> {
    async fn bucket_created(
        &self,
        t: &TenantId,
        bucket: &BucketId,
        unit: u32,
        creator: &str,
        grant_seq: u64,
    ) -> Result<BucketPut> {
        let g = self.gate.borrow_mut().take();
        if let Some(g) = g {
            until(g).await;
        }
        self.inner
            .bucket_created(t, bucket, unit, creator, grant_seq)
            .await
    }
    async fn is_placed(&self, t: &TenantId, bucket: &BucketId) -> Result<bool> {
        self.inner.is_placed(t, bucket).await
    }
}

/// (Review round 4.) A call parked in `bucket_created`, an ordinary drop
/// of its grant, and a retry under the same key: the retry places the
/// bound grant's bucket, not a second one.
#[tokio::test(flavor = "current_thread")]
async fn an_inflight_place_and_a_retry_after_a_drop_place_one_bucket() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table_a = seed(&w, &adm).await;
    let units = w.units();
    let buckets = FakeBuckets::default();
    let gate_a = Cell::new(false);
    let gate_b = Cell::new(false);
    let gb_a = GatedBuckets {
        inner: &buckets,
        gate: RefCell::new(Some(&gate_a)),
    };
    let gb_b = GatedBuckets {
        inner: &buckets,
        gate: RefCell::new(Some(&gate_b)),
    };
    let env = env!(w, &adm, &units);
    let req = photos("PR0001");
    let mut rng_a = TestRng(4001);
    let mut fut_a: BoxFut<'_, _> =
        Box::pin(env.create_bucket(&gb_a, &mut table_a, "ib", &req, &mut rng_a));
    assert!(
        poll_once(&mut fut_a).is_none(),
        "A parked in bucket_created"
    );
    // An ordinary DropGrant of the creator grant on bucket(3).
    let mut table_c = table(&w);
    let drop = KeyRequest::DropGrant {
        id: "PR0001".into(),
        bucket_id: bucket_id(&w.t, 3).as_str().to_owned(),
    };
    let dropped = env
        .change(&mut table_c, "", &drop, &mut TestRng(4002))
        .await
        .unwrap();
    assert_eq!(dropped, KeyAnswer::Done { seq: 4 });
    // A retry under the same key, parked in its own bucket_created.
    let mut table_b = table(&w);
    let mut rng_b = TestRng(4003);
    let mut fut_b: BoxFut<'_, _> =
        Box::pin(env.create_bucket(&gb_b, &mut table_b, "ib", &req, &mut rng_b));
    let early_b = poll_once(&mut fut_b);
    gate_a.set(true);
    let a = fut_a.await.unwrap();
    gate_b.set(true);
    let b = match early_b {
        Some(r) => r.unwrap(),
        None => fut_b.await.unwrap(),
    };
    assert_eq!(
        buckets.placed.borrow().len(),
        1,
        "two buckets for one create"
    );
    let three = BucketAnswer::Created {
        bucket: bucket_id(&w.t, 3),
        grant_seq: 3,
    };
    assert_eq!((a, b), (three.clone(), three));
}

/// (Review round 5.) The parked call is refused after the reservation
/// moved on to a new K that was placed: it answers that bucket, never 409.
#[tokio::test(flavor = "current_thread")]
async fn a_refusal_after_a_sibling_took_a_new_k_answers_its_bucket() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table_a = seed(&w, &adm).await;
    let units = w.units();
    let buckets = FakeBuckets::default();
    let gate_a = Cell::new(false);
    let gb_a = GatedBuckets {
        inner: &buckets,
        gate: RefCell::new(Some(&gate_a)),
    };
    let env = env!(w, &adm, &units);
    let req = photos("PR0001");
    let mut rng_a = TestRng(5201);
    let mut fut_a: BoxFut<'_, _> =
        Box::pin(env.create_bucket(&gb_a, &mut table_a, "ib", &req, &mut rng_a));
    assert!(
        poll_once(&mut fut_a).is_none(),
        "A parked in bucket_created(3)"
    );
    buckets.lose_orders.set(1);
    let mut table_b = table(&w);
    let _b = env
        .create_bucket(&buckets, &mut table_b, "ib", &req, &mut TestRng(5202))
        .await
        .unwrap();
    buckets.refuse.set(Some((409, "restoring")));
    gate_a.set(true);
    let a = fut_a.await.unwrap();
    assert!(matches!(a, BucketAnswer::Created { .. }), "{a:?}");
    assert_eq!(buckets.placed.borrow().len(), 1);
    let placed = buckets.placed.borrow()[0].0.clone();
    assert_eq!(
        head_grants(&w, "PR0001").await,
        vec!["b_01".to_owned(), placed],
        "the creator holds the placed bucket, and grant 3 is revoked"
    );
    let a_refused = matches!(a, BucketAnswer::StateRefused { .. });
    assert!(
        !(a_refused && !buckets.placed.borrow().is_empty()),
        "R5b: A answered 409 while the create's bucket exists"
    );
}

/// (Review round 5.) The parked call is refused after the reservation
/// moved on to a new K that was placed: it answers that bucket, never 409.
#[tokio::test(flavor = "current_thread")]
async fn a_refusal_after_the_finisher_took_a_new_k_answers_its_bucket() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table_a = seed(&w, &adm).await;
    let units = w.units();
    let buckets = FakeBuckets::default();
    let gate_a = Cell::new(false);
    let gb_a = GatedBuckets {
        inner: &buckets,
        gate: RefCell::new(Some(&gate_a)),
    };
    let env = env!(w, &adm, &units);
    let req = photos("PR0001");
    let mut rng_a = TestRng(5301);
    let mut fut_a: BoxFut<'_, _> =
        Box::pin(env.create_bucket(&gb_a, &mut table_a, "ib", &req, &mut rng_a));
    assert!(
        poll_once(&mut fut_a).is_none(),
        "A parked in bucket_created(3)"
    );
    buckets.lose_orders.set(1);
    let mut fin = table(&w);
    let _f = finish_creator_grant(&env, &buckets, &mut fin, 3, &mut TestRng(5302))
        .await
        .unwrap();
    buckets.refuse.set(Some((409, "restoring")));
    gate_a.set(true);
    let a = fut_a.await.unwrap();
    assert!(matches!(a, BucketAnswer::Created { .. }), "{a:?}");
    assert_eq!(buckets.placed.borrow().len(), 1);
    let placed = buckets.placed.borrow()[0].0.clone();
    assert_eq!(
        head_grants(&w, "PR0001").await,
        vec!["b_01".to_owned(), placed],
        "the creator holds the placed bucket, and grant 3 is revoked"
    );
    let a_refused = matches!(a, BucketAnswer::StateRefused { .. });
    assert!(
        !(a_refused && !buckets.placed.borrow().is_empty()),
        "R5c: the client got 409 while its create's bucket exists"
    );
}

/// The tenant chain decided `bucket_created` Refused (restoring) for the
/// first call; its answer reaches the caller only once the gate opens.
/// Later calls pass through.
struct RefusedLate<'i, 'g> {
    inner: &'i FakeBuckets,
    gate: RefCell<Option<&'g Cell<bool>>>,
}

impl BucketRecords for RefusedLate<'_, '_> {
    async fn bucket_created(
        &self,
        t: &TenantId,
        bucket: &BucketId,
        unit: u32,
        creator: &str,
        grant_seq: u64,
    ) -> Result<BucketPut> {
        let g = self.gate.borrow_mut().take();
        if let Some(g) = g {
            until(g).await;
            return Ok(BucketPut::Refused {
                status: 409,
                code: "restoring",
            });
        }
        self.inner
            .bucket_created(t, bucket, unit, creator, grant_seq)
            .await
    }
    async fn is_placed(&self, t: &TenantId, bucket: &BucketId) -> Result<bool> {
        self.inner.is_placed(t, bucket).await
    }
}

/// (Review round 6.) A's put of 3 is refused; before A releases, a
/// same-key retry places 3 and the unit turns the reservation into bucket
/// 3. A gives nothing up and answers 503; the creator keeps grant 3.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_put_whose_bucket_a_sibling_placed_keeps_its_grant() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table_a = seed(&w, &adm).await;
    let units = w.units();
    let buckets = FakeBuckets::default();
    let gate_a = Cell::new(false);
    let late = RefusedLate {
        inner: &buckets,
        gate: RefCell::new(Some(&gate_a)),
    };
    let env = env!(w, &adm, &units);
    let req = photos("PR0001");
    let mut rng_a = TestRng(6101);
    let mut fut_a: BoxFut<'_, _> =
        Box::pin(env.create_bucket(&late, &mut table_a, "ib", &req, &mut rng_a));
    assert!(
        poll_once(&mut fut_a).is_none(),
        "A parked in bucket_created(3)"
    );
    let mut table_b = table(&w);
    let b = env
        .create_bucket(&buckets, &mut table_b, "ib", &req, &mut TestRng(6102))
        .await
        .unwrap();
    let three = bucket_id(&w.t, 3);
    assert!(
        matches!(b, BucketAnswer::Created { grant_seq: 3, .. }),
        "{b:?}"
    );
    // The unit applies bucket_created(3): the reservation becomes the bucket.
    *adm.bucket_done.borrow_mut() = Some((three.clone(), 3));
    adm.bucket_open.borrow_mut().remove("ib");
    gate_a.set(true);
    let a = fut_a.await.unwrap();
    assert_eq!(a, BucketAnswer::Unfinished { grant_seq: 3 });
    let grants = head_grants(&w, "PR0001").await;
    assert!(
        grants.iter().any(|g| g == three.as_str()),
        "R6a: bucket 3 is placed and answered {a:?}, but its creator's grant was dropped"
    );
}

/// (Review round 6.) as R6a with A being the finisher of intent 3.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_finisher_put_whose_bucket_a_retry_placed_keeps_its_grant() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table0 = seed(&w, &adm).await;
    let units = w.units();
    let buckets = FakeBuckets::default();
    let env = env!(w, &adm, &units);
    let req = photos("PR0001");
    // A client call writes and binds 3, then the tenant chain is down.
    buckets.down.set(true);
    assert_eq!(
        env.create_bucket(&buckets, &mut table0, "ib", &req, &mut TestRng(6201))
            .await
            .unwrap(),
        BucketAnswer::Unfinished { grant_seq: 3 }
    );
    buckets.down.set(false);
    let gate_f = Cell::new(false);
    let late = RefusedLate {
        inner: &buckets,
        gate: RefCell::new(Some(&gate_f)),
    };
    let mut fin = table(&w);
    let mut rng_f = TestRng(6202);
    let mut fut_f: BoxFut<'_, _> =
        Box::pin(finish_creator_grant(&env, &late, &mut fin, 3, &mut rng_f));
    assert!(
        poll_once(&mut fut_f).is_none(),
        "finisher parked in bucket_created(3)"
    );
    let mut table_b = table(&w);
    let b = env
        .create_bucket(&buckets, &mut table_b, "ib", &req, &mut TestRng(6203))
        .await
        .unwrap();
    let three = bucket_id(&w.t, 3);
    assert!(
        matches!(b, BucketAnswer::Created { grant_seq: 3, .. }),
        "{b:?}"
    );
    *adm.bucket_done.borrow_mut() = Some((three.clone(), 3));
    adm.bucket_open.borrow_mut().remove("ib");
    gate_f.set(true);
    let f = fut_f.await.unwrap();
    assert_eq!(f, CreatorGrant::Busy);
    let grants = head_grants(&w, "PR0001").await;
    assert!(
        grants.iter().any(|g| g == three.as_str()),
        "R6b: bucket 3 is placed (client told Created), but the finisher dropped its creator's grant"
    );
}

/// (Review round 7.) A sibling records bucket 3 but the unit lags (not in
/// force, the reservation still bound to 3); A's refused put of 3 then
/// gives nothing up, and the sibling's retry answers bucket 3: one bucket,
/// never a 409 for a bucket that exists.
#[tokio::test(flavor = "current_thread")]
async fn a_refusal_while_a_sibling_placed_the_same_bucket_gives_nothing_up() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table_a = seed(&w, &adm).await;
    let units = w.units();
    let buckets = FakeBuckets::default();
    let gate_a = Cell::new(false);
    let late = RefusedLate {
        inner: &buckets,
        gate: RefCell::new(Some(&gate_a)),
    };
    let env = env!(w, &adm, &units);
    let req = photos("PR0001");
    let mut rng_a = TestRng(7101);
    let mut fut_a: BoxFut<'_, _> =
        Box::pin(env.create_bucket(&late, &mut table_a, "ib", &req, &mut rng_a));
    assert!(
        poll_once(&mut fut_a).is_none(),
        "A parked in bucket_created(3)"
    );
    buckets.not_in_force.set(true);
    let mut table_b = table(&w);
    let b = env
        .create_bucket(&buckets, &mut table_b, "ib", &req, &mut TestRng(7102))
        .await
        .unwrap();
    assert_eq!(b, BucketAnswer::Unfinished { grant_seq: 3 });
    gate_a.set(true);
    let a = fut_a.await.unwrap();
    assert_eq!(a, BucketAnswer::Unfinished { grant_seq: 3 });
    buckets.not_in_force.set(false);
    let retry = env
        .create_bucket(&buckets, &mut table_b, "ib", &req, &mut TestRng(7103))
        .await
        .unwrap();
    let three = bucket_id(&w.t, 3);
    assert_eq!(
        retry,
        BucketAnswer::Created {
            bucket: three.clone(),
            grant_seq: 3,
        }
    );
    assert_eq!(buckets.placed.borrow().len(), 1);
    assert_eq!(
        head_grants(&w, "PR0001").await,
        vec!["b_01".to_owned(), three.as_str().to_owned()]
    );
}

/// Refuses every `bucket_created` while armed. On its first `is_placed`
/// it answers, then lets a sibling's placement of bucket 3 land and the
/// unit turn the reservation into it: between the refused call's
/// placement check and its release.
struct RaceAfterCheck<'i, 'a> {
    inner: &'i FakeBuckets,
    adm: &'i FakeAdmission<'a>,
    armed: Cell<bool>,
}

impl BucketRecords for RaceAfterCheck<'_, '_> {
    async fn bucket_created(
        &self,
        t: &TenantId,
        bucket: &BucketId,
        unit: u32,
        creator: &str,
        grant_seq: u64,
    ) -> Result<BucketPut> {
        if self.armed.get() {
            return Ok(BucketPut::Refused {
                status: 409,
                code: "restoring",
            });
        }
        self.inner
            .bucket_created(t, bucket, unit, creator, grant_seq)
            .await
    }
    async fn is_placed(&self, t: &TenantId, bucket: &BucketId) -> Result<bool> {
        let answer = self.inner.is_placed(t, bucket).await?;
        if self.armed.replace(false) {
            let three = bucket_id(t, 3);
            self.inner.placed.borrow_mut().push((
                three.as_str().to_owned(),
                1,
                "PR0001".to_owned(),
                3,
            ));
            self.inner.last_grant_seq.set(3);
            *self.adm.bucket_done.borrow_mut() = Some((three, 3));
            self.adm.bucket_open.borrow_mut().remove("ib");
        }
        Ok(answer)
    }
}

/// (Review round 8.) A sibling places this very bucket after the refused
/// call's placement check and before its release: the release answers
/// that the reservation became the bucket, and the call keeps its grant
/// and answers it.
#[tokio::test(flavor = "current_thread")]
async fn a_bucket_placed_between_the_check_and_the_release_keeps_its_grant() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let buckets = FakeBuckets::default();
    let race = RaceAfterCheck {
        inner: &buckets,
        adm: &adm,
        armed: Cell::new(true),
    };
    let three = bucket_id(&w.t, 3);
    let answer = env
        .create_bucket(
            &race,
            &mut table,
            "ib",
            &photos("PR0001"),
            &mut TestRng(8101),
        )
        .await
        .unwrap();
    assert_eq!(
        answer,
        BucketAnswer::Created {
            bucket: three.clone(),
            grant_seq: 3,
        }
    );
    assert_eq!(
        head_grants(&w, "PR0001").await,
        vec!["b_01".to_owned(), three.as_str().to_owned()]
    );
}

// ---------------------------------------------------------------------------
// AM-28: the undo's key freeze, and the move rules of the writer
// ---------------------------------------------------------------------------

use velmora_bridge::keys::checkpoint::{open_checkpoint, seal_checkpoint};
use velmora_bridge::keys::frozen::{
    d1_projection, drop_moved_grants, freeze_keys, table_at, thaw_keys, Freeze, Thaw,
};
use velmora_bridge::keys::gate::{TenantDoor, ZeroHead};
use velmora_bridge::keys::record::{
    open_chain_record, seal_marker_record, ChainRecord, KeyTable, Marker,
};
use velmora_bridge::keys::routes::route_name;

macro_rules! env_gate {
    ($w:expr, $adm:expr, $units:expr, $gate:expr) => {
        env_gate!($w, $adm, $units, $gate, &$w.store)
    };
    ($w:expr, $adm:expr, $units:expr, $gate:expr, $store:expr) => {
        KeyEnv {
            store: $store,
            kek: &$w.kek,
            ring: &$w.ring,
            tenant: &$w.t,
            admission: $adm,
            intents: &$w.intents,
            units: $units,
            directory: &&$w.directory,
            clock: &$w.clock,
            limits: Limits::Recorded,
            gate: $gate,
        }
    };
}

/// The record at `seq`, opened.
async fn chain_record(w: &World, seq: u64) -> ChainRecord {
    let bytes = key_chain(&w.t).get(&w.store, seq).await.unwrap();
    open_chain_record(&w.kek, &w.ring, &w.t, seq, &bytes).unwrap()
}

/// The head table, read from scratch.
async fn head_table(w: &World) -> KeyTable {
    read_key_chain(&w.store, &w.kek, &w.ring, &w.t)
        .await
        .unwrap()
        .table
}

fn narrow(id: &str) -> KeyRequest {
    KeyRequest::SetGrants {
        id: id.to_owned(),
        grants: Vec::new(),
        acting: None,
    }
}

/// A gate at tenant 0 `moved` into `w.t`, the tenant head with the moved
/// bucket b_01 placed on the root unit.
fn moved_gate(w: &World) -> FakeGate {
    let gate = FakeGate::before_move();
    gate.set_zero(ZeroHead::Moved { to: w.t.clone() });
    gate.set_door(TenantDoor {
        keys_frozen: None,
        moved_in: true,
        root_placed: ["b_01".to_owned()].into_iter().collect(),
    });
    gate
}

/// Freeze, refusals while frozen, the exit's grant removals, the thaw:
/// every later record carries `frozen_at` until the thaw, and a fresh
/// read folds the same table.
#[tokio::test(flavor = "current_thread")]
async fn the_freeze_is_a_key_chain_record_and_only_the_exit_and_the_thaw_pass_it() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    let env = env_gate!(w, &adm, &units, &gate);
    let mut rng = TestRng(300);

    assert_eq!(
        freeze_keys(&env, None, &mut rng).await.unwrap(),
        Freeze::Frozen { k_u: 2, seq: 3 }
    );
    match chain_record(&w, 3).await {
        ChainRecord::Marker(m) => {
            assert_eq!(m.marker, Marker::KeysFrozen);
            assert_eq!(m.frozen_at, Some(2));
        }
        other => panic!("not a marker: {other:?}"),
    }
    // A re-run whose receipt names K_u adopts it and writes nothing.
    assert_eq!(
        freeze_keys(&env, Some(2), &mut rng).await.unwrap(),
        Freeze::Adopted { k_u: 2 }
    );
    assert_eq!(w.head(), 3);

    // Every customer change but a revoke: 503, nothing put.
    for request in [
        narrow("AKVL0001"),
        disable("AKVL0001"),
        enable("AKVL0001"),
        KeyRequest::Create(principal("PR0009", &[])),
        KeyRequest::DropGrant {
            id: "PR0001".into(),
            bucket_id: "b_01".into(),
        },
    ] {
        assert_eq!(
            env.change(&mut table, "idem-f", &request, &mut rng)
                .await
                .unwrap(),
            KeyAnswer::Frozen,
            "{request:?}"
        );
    }
    assert_eq!(table.frozen_at(), Some(2));
    assert_eq!(w.head(), 3);
    assert_eq!(adm.calls.get(), 2, "no reservation is asked for");
    // A bucket create neither: no creator grant above K_u.
    let buckets = FakeBuckets::default();
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib-z", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Busy
    );
    assert_eq!(buckets.calls.get(), 0);
    assert_eq!(w.head(), 3);

    // The exit's grant removals pass, only for placed ids while moved_in.
    gate.set_door(TenantDoor {
        moved_in: false,
        ..moved_gate(&w).door.borrow().clone().unwrap()
    });
    let refused = drop_moved_grants(&env, &["b_01".into()], &mut rng)
        .await
        .unwrap();
    assert_eq!(refused.refused, Some("not_moved_in"));
    gate.set_door(moved_gate(&w).door.borrow().clone().unwrap());
    let refused = drop_moved_grants(&env, &["b_02".into()], &mut rng)
        .await
        .unwrap();
    assert_eq!(refused.refused, Some("not_placed"));
    assert_eq!(w.head(), 3);
    let drops = drop_moved_grants(&env, &["b_01".into()], &mut rng)
        .await
        .unwrap();
    assert_eq!(drops.written, vec![4, 5]);
    assert!(drops.done && drops.refused.is_none());
    for seq in [4, 5] {
        let ChainRecord::Key(r) = chain_record(&w, seq).await else {
            panic!("a subject's record");
        };
        assert_eq!(r.op, KeyOp::Grants);
        assert!(r.closes);
        assert!(r.door.grants.is_empty());
        assert_eq!(r.frozen_at, Some(2), "a frozen chain's record carries K_u");
    }
    // A re-run writes nothing more.
    let again = drop_moved_grants(&env, &["b_01".into()], &mut rng)
        .await
        .unwrap();
    assert!(again.written.is_empty() && again.done);

    // The D1 build reads to K_u, never further: the grants are there.
    let at = table_at(&w.store, &w.kek, &w.ring, &w.t, 2).await.unwrap();
    assert_eq!(at.seq(), 2);
    assert_eq!(at.frozen_at(), None);
    assert_eq!(
        at.get("AKVL0001").unwrap().door.grants.len(),
        1,
        "the cut is before the exit's removals"
    );
    // A cut that is not a freeze's is refused.
    assert!(table_at(&w.store, &w.kek, &w.ring, &w.t, 1).await.is_err());
    assert!(table_at(&w.store, &w.kek, &w.ring, &w.t, 4).await.is_err());

    // The thaw: only with the tenant head's keys_frozen cleared, and only
    // of the freeze in force.
    gate.set_door(TenantDoor {
        keys_frozen: Some(2),
        ..moved_gate(&w).door.borrow().clone().unwrap()
    });
    assert_eq!(
        thaw_keys(&env, 2, &mut rng).await.unwrap(),
        Thaw::Refused {
            code: "tenant_keys_frozen"
        }
    );
    gate.set_door(moved_gate(&w).door.borrow().clone().unwrap());
    assert_eq!(
        thaw_keys(&env, 1, &mut rng).await.unwrap(),
        Thaw::Refused {
            code: "freeze_mismatch"
        }
    );
    assert_eq!(w.head(), 5);
    assert_eq!(
        thaw_keys(&env, 2, &mut rng).await.unwrap(),
        Thaw::Thawed { seq: 6 }
    );
    assert_eq!(thaw_keys(&env, 2, &mut rng).await.unwrap(), Thaw::NotFrozen);
    // After the thaw the writer takes changes again, with no frozen_at.
    assert_eq!(
        env.change(&mut table, "", &disable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 7 }
    );
    let ChainRecord::Key(r) = chain_record(&w, 7).await else {
        panic!("a subject's record");
    };
    assert_eq!(r.frozen_at, None);
    assert_eq!(table.frozen_at(), None);
    // A fresh read folds the same table, markers and all.
    assert_eq!(head_table(&w).await, table);
}

/// A writer that read the head before the freeze and loses its put to
/// `KeysFrozen` reads the head again and refuses: nothing it planned
/// lands above K_u.
#[tokio::test(flavor = "current_thread")]
async fn a_writer_that_loses_its_put_to_the_freeze_writes_nothing() {
    struct FreezeFirst<'a> {
        inner: &'a MemRecords,
        at: String,
        marker: RefCell<Option<Vec<u8>>>,
    }
    impl RecordStore for FreezeFirst<'_> {
        async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
            if name == self.at {
                if let Some(m) = self.marker.borrow_mut().take() {
                    self.inner.plant(name, m);
                }
            }
            self.inner.put_if_absent(name, bytes).await
        }
        async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
            self.inner.get(name).await
        }
        async fn list(&self, p: &str, a: &str, l: u32) -> Result<Vec<String>> {
            self.inner.list(p, a, l).await
        }
    }
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let marker = seal_marker_record(
        &w.kek,
        &w.ring,
        &w.t,
        3,
        1,
        Marker::KeysFrozen,
        &mut TestRng(310),
    )
    .unwrap();
    let store = FreezeFirst {
        inner: &w.store,
        at: key_chain(&w.t).name(3),
        marker: RefCell::new(Some(marker)),
    };
    let gate = moved_gate(&w);
    let env = env_gate!(w, &adm, &units, &gate, &store);
    // A narrowing: closing, so no reservation stands between.
    assert_eq!(
        env.change(&mut table, "", &narrow("AKVL0001"), &mut TestRng(311))
            .await
            .unwrap(),
        KeyAnswer::Frozen
    );
    assert_eq!(w.head(), 3);
    assert_eq!(table.frozen_at(), Some(2));
    assert!(matches!(chain_record(&w, 3).await, ChainRecord::Marker(_)));
}

/// A revoke while frozen puts its `m/rk/<t>/` and no record, closes the
/// key at the units by the override, and answers 503; once tenant 0 is
/// `d1` again (the undo, or a give-up) it applies itself to D1 and
/// answers 200.
#[tokio::test(flavor = "current_thread")]
async fn a_revoke_during_the_freeze_wins_and_applies_itself_to_d1_after_the_undo() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    let env = env_gate!(w, &adm, &units, &gate);
    let mut rng = TestRng(320);
    freeze_keys(&env, None, &mut rng).await.unwrap();

    assert_eq!(
        env.change(&mut table, "", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Frozen
    );
    assert_eq!(w.head(), 3, "the revoke record is refused");
    assert!(w
        .store
        .raw(&tenant_revocation_name(&w.t, "AKVL0001"))
        .is_some());
    assert_eq!(w.root.status("AKVL0001"), Some(SubjectStatus::Revoked));
    assert!(gate.calls.borrow().is_empty());

    // Tenant 0's head moves to the undo's d1 between the two reads.
    *gate.then.borrow_mut() = Some((1, ZeroHead::Undone { to: w.t.clone() }));
    assert_eq!(
        env.change(&mut table, "", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::RevokedOffChain
    );
    assert_eq!(*gate.calls.borrow(), vec!["refuse_in_d1 AKVL0001"]);
    assert_eq!(w.head(), 3);

    // D1 that cannot be reached: 503, the m/rk/ stays.
    gate.calls.borrow_mut().clear();
    gate.set_zero(ZeroHead::Moved { to: w.t.clone() });
    *gate.then.borrow_mut() = Some((1, ZeroHead::D1));
    *gate.d1_down.borrow_mut() = true;
    assert_eq!(
        env.change(&mut table, "", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Frozen
    );
    // A revoke of a subject the chain does not hold: 503, nothing put.
    *gate.d1_down.borrow_mut() = false;
    assert_eq!(
        env.change(&mut table, "", &revoke("AKVL0404"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Frozen
    );
    assert!(w
        .store
        .raw(&tenant_revocation_name(&w.t, "AKVL0404"))
        .is_none());
    assert_eq!(w.head(), 3);
}

/// After the undo (tenant 0 `d1` with `undo_stamp`, `move.to` = this
/// tenant), a revoke of a key the chain holds is made on tenant 0's path
/// and answers 200 once D1 refuses it; every other change is
/// `409 key_moved` and puts nothing (AM-54 LOW 3).
#[tokio::test(flavor = "current_thread")]
async fn after_the_undo_a_revoke_takes_tenant_zeros_path() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    let env = env_gate!(w, &adm, &units, &gate);
    let mut rng = TestRng(330);
    freeze_keys(&env, None, &mut rng).await.unwrap();
    gate.set_zero(ZeroHead::Undone { to: w.t.clone() });

    assert_eq!(
        env.change(&mut table, "", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::RevokedOffChain
    );
    assert_eq!(*gate.calls.borrow(), vec!["zero_revoke AKVL0001"]);
    assert!(w
        .store
        .raw(&tenant_revocation_name(&w.t, "AKVL0001"))
        .is_none());
    for request in [
        disable("AKVL0001"),
        narrow("AKVL0001"),
        revoke("PR0001"),
        KeyRequest::Create(principal("PR0009", &[])),
    ] {
        assert_eq!(
            env.change(&mut table, "", &request, &mut rng)
                .await
                .unwrap(),
            KeyAnswer::KeyMoved,
            "{request:?}"
        );
    }
    // D1 down: 503, for the retry.
    *gate.d1_down.borrow_mut() = true;
    assert_eq!(
        env.change(&mut table, "", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Busy
    );
    assert_eq!(w.head(), 3);
    // A bucket create is key_moved as well.
    let buckets = FakeBuckets::default();
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib-u", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::StateRefused {
            status: 409,
            code: "key_moved"
        }
    );
    assert_eq!(buckets.calls.get(), 0);
    assert_eq!(w.head(), 3);
}

/// With tenant 0 at `d1` and no move (after a give-up), a change of a key
/// whose route does not name this tenant is `409 key_moved` with nothing
/// put, frozen or not; an existing `m/rk/<t>/` of it is applied to D1
/// first (AM-31, AM-54 LOW 2).
#[tokio::test(flavor = "current_thread")]
async fn after_a_give_up_a_key_routed_elsewhere_is_key_moved() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let gate = FakeGate::before_move();
    let env = env_gate!(w, &adm, &units, &gate);
    let mut rng = TestRng(340);

    // The route names this tenant: the change goes on.
    assert_eq!(
        env.change(&mut table, "", &disable("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    // The route is gone (unverifiable counts the same): key_moved.
    assert!(w.store.lose(&route_name("AKVL0001")));
    for request in [narrow("AKVL0001"), enable("AKVL0001")] {
        assert_eq!(
            env.change(&mut table, "", &request, &mut rng)
                .await
                .unwrap(),
            KeyAnswer::KeyMoved
        );
    }
    assert!(gate.calls.borrow().is_empty(), "no m/rk/<t>/ to apply");
    // A principal has no route; its change goes on.
    assert!(matches!(
        env.change(&mut table, "", &narrow("PR0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { .. }
    ));
    let head = w.head();
    // A revocation that a give-up's window left in m/rk/<t>/: applied to
    // D1 before the answer, also on a frozen chain.
    put_tenant_revocation(&w.store, &w.kek, &w.t, "AKVL0001", 5, &mut rng)
        .await
        .unwrap();
    let frozen_gate = moved_gate(&w);
    let fenv = env_gate!(w, &adm, &units, &frozen_gate);
    freeze_keys(&fenv, None, &mut rng).await.unwrap();
    let head = head + 1;
    assert_eq!(
        env.change(&mut table, "", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::KeyMoved
    );
    assert_eq!(*gate.calls.borrow(), vec!["refuse_in_d1 AKVL0001"]);
    *gate.d1_down.borrow_mut() = true;
    assert_eq!(
        env.change(&mut table, "", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Busy,
        "the pre-apply failed: retry"
    );
    assert_eq!(w.head(), head);
}

/// While tenant 0 is `moving` into this tenant, only revokes go on
/// (AM-31).
#[tokio::test(flavor = "current_thread")]
async fn while_moving_only_revokes_go_on() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    gate.set_zero(ZeroHead::Moving { to: w.t.clone() });
    let env = env_gate!(w, &adm, &units, &gate);
    let mut rng = TestRng(350);
    for request in [narrow("AKVL0001"), disable("AKVL0001")] {
        assert_eq!(
            env.change(&mut table, "", &request, &mut rng)
                .await
                .unwrap(),
            KeyAnswer::Busy
        );
    }
    let buckets = FakeBuckets::default();
    assert_eq!(
        env.create_bucket(&buckets, &mut table, "ib-m", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Busy
    );
    assert_eq!(w.head(), 2);
    assert_eq!(
        env.change(&mut table, "", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 3 }
    );
    // A move into another tenant changes nothing here.
    gate.set_zero(ZeroHead::Moving { to: tenant(2) });
    assert_eq!(
        env.change(&mut table, "", &narrow("PR0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { seq: 4 }
    );
    // Tenant 0's head that cannot be read: 503.
    *gate.zero.borrow_mut() = None;
    assert_eq!(
        env.change(&mut table, "", &revoke("PR0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Busy
    );
}

/// The finisher on a frozen chain appends nothing: an `m/rk/` revocation
/// without its record is done (the stores get it by the override), and
/// the rows are cleared. A creator grant is decided after the thaw.
#[tokio::test(flavor = "current_thread")]
async fn the_finisher_on_a_frozen_chain_writes_nothing_and_clears_the_rows() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    let env = env_gate!(w, &adm, &units, &gate);
    let mut rng = TestRng(360);
    let buckets = FakeBuckets::default();
    assert!(matches!(
        env.create_bucket(&buckets, &mut table, "ib-f", &photos("PR0001"), &mut rng)
            .await
            .unwrap(),
        BucketAnswer::Created { grant_seq: 3, .. }
    ));
    freeze_keys(&env, None, &mut rng).await.unwrap();
    put_tenant_revocation(&w.store, &w.kek, &w.t, "AKVL0001", 5, &mut rng)
        .await
        .unwrap();
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(report.frozen);
    assert!(report.appended.is_empty() && report.append_failed.is_empty());
    assert!(!report.retry(), "{report:?}");
    assert_eq!(report.head, 4);
    assert_eq!(w.head(), 4);
    assert!(w.intents.cleared.borrow().contains(&4));
    assert_eq!(w.root.status("AKVL0001"), Some(SubjectStatus::Revoked));
    assert_eq!(
        finish_creator_grant(&env, &buckets, &mut table.clone(), 3, &mut rng)
            .await
            .unwrap(),
        CreatorGrant::Frozen
    );
    // A marker's seq is no creator grant.
    assert_eq!(
        finish_creator_grant(&env, &buckets, &mut table.clone(), 4, &mut rng)
            .await
            .unwrap(),
        CreatorGrant::NotOne
    );
    // After the thaw the finisher records the revocation.
    thaw_keys(&env, 3, &mut rng).await.unwrap();
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(!report.frozen);
    assert_eq!(report.appended, vec![6]);
}

/// The D1 build's projection: each key's grants ∩ its principal's, the
/// lower access; disabled when the principal is not active; the
/// internal key, principals and limited grants are not carried.
#[tokio::test(flavor = "current_thread")]
async fn the_d1_projection_is_the_effective_grant_at_k_u() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    let env = env_gate!(w, &adm, &units, &gate);
    let mut rng = TestRng(370);
    let change = |r: KeyRequest| r;
    // PR0002 rw on b_01 and b_02; AKVL0002 rw on both, AKVL0003 rw on a
    // prefix of b_02; then PR0002 narrowed to ro on b_01 only.
    let p2 = principal(
        "PR0002",
        &[grant("b_01", RW, None), grant("b_02", RW, None)],
    );
    let k2 = s3_key(
        &w.t,
        "AKVL0002",
        "PR0002",
        &[grant("b_01", RW, None), grant("b_02", RW, None)],
    );
    let k3 = s3_key(&w.t, "AKVL0003", "PR0002", &[grant("b_02", RW, Some("a/"))]);
    for (idem, r) in [
        ("i2", change(KeyRequest::Create(p2))),
        ("i3", KeyRequest::Create(k2)),
        ("i4", KeyRequest::Create(k3)),
    ] {
        assert!(matches!(
            env.change(&mut table, idem, &r, &mut rng).await.unwrap(),
            KeyAnswer::Done { .. }
        ));
    }
    assert!(matches!(
        env.change(
            &mut table,
            "",
            &KeyRequest::SetGrants {
                id: "PR0002".into(),
                grants: vec![grant("b_01", RO, None)],
                acting: None,
            },
            &mut rng
        )
        .await
        .unwrap(),
        KeyAnswer::Done { .. }
    ));
    let Freeze::Frozen { k_u, .. } = freeze_keys(&env, None, &mut rng).await.unwrap() else {
        panic!("frozen");
    };
    let at = table_at(&w.store, &w.kek, &w.ring, &w.t, k_u)
        .await
        .unwrap();
    let d1 = d1_projection(&at);
    let ids: Vec<&str> = d1.iter().map(|k| k.id.as_str()).collect();
    assert_eq!(ids, vec!["AKVL0001", "AKVL0002", "AKVL0003"]);
    assert_eq!(d1[0].status, SubjectStatus::Active);
    assert_eq!(d1[0].grants, vec![("b_01".to_owned(), RO)]);
    assert_eq!(d1[1].status, SubjectStatus::Active);
    assert_eq!(
        d1[1].grants,
        vec![("b_01".to_owned(), RO)],
        "the principal's lower access; b_02 is no longer the principal's"
    );
    assert!(d1[2].grants.is_empty());
    assert_eq!(d1[2].limited_dropped, 0, "the principal holds no b_02");

    // A disabled principal disables its keys; a revoked key stays revoked.
    let w2 = World::new();
    let adm2 = FakeAdmission::new(&w2.root);
    let mut t2 = seed(&w2, &adm2).await;
    let units2 = w2.units();
    let gate2 = moved_gate(&w2);
    let env2 = env_gate!(w2, &adm2, &units2, &gate2);
    let k5 = s3_key(
        &w2.t,
        "AKVL0005",
        "PR0001",
        &[grant("b_01", RW, Some("p/"))],
    );
    for (idem, r) in [
        ("i5", KeyRequest::Create(k5)),
        ("", revoke("AKVL0001")),
        ("", disable("PR0001")),
    ] {
        assert!(matches!(
            env2.change(&mut t2, idem, &r, &mut rng).await.unwrap(),
            KeyAnswer::Done { .. }
        ));
    }
    let d1 = d1_projection(&t2);
    assert_eq!(d1.len(), 2);
    assert_eq!(d1[0].status, SubjectStatus::Revoked);
    assert_eq!(d1[1].status, SubjectStatus::Disabled);
    assert!(d1[1].grants.is_empty());
    env2.change(&mut t2, "", &enable("PR0001"), &mut rng)
        .await
        .unwrap();
    let d1 = d1_projection(&head_table(&w2).await);
    assert_eq!(d1[1].status, SubjectStatus::Active);
    assert!(d1[1].grants.is_empty());
    assert_eq!(d1[1].limited_dropped, 1, "a prefix is not carried to D1");
}

/// The record rules: a subject's record must carry the head's
/// `frozen_at`; a freeze only on an unfrozen head; a thaw only of the
/// freeze in force. A checkpoint carries the freeze.
#[tokio::test(flavor = "current_thread")]
async fn records_that_break_the_freeze_rules_stop_the_reader() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    let env = env_gate!(w, &adm, &units, &gate);
    let mut rng = TestRng(380);
    freeze_keys(&env, None, &mut rng).await.unwrap();
    let chain = key_chain(&w.t);
    let p = principal("PR0007", &[]);
    let plant = |seq: u64, bytes: Vec<u8>| w.store.plant(&chain.name(seq), bytes);
    let subject_at = |frozen_at: Option<u64>, rng: &mut TestRng| {
        seal_key_record(
            &w.kek,
            &w.ring,
            &w.t,
            4,
            KeyOp::Create,
            1,
            &p.door,
            Some(&p.private),
            false,
            frozen_at,
            rng,
        )
        .unwrap()
    };
    for bad in [
        subject_at(None, &mut rng),
        subject_at(Some(1), &mut rng),
        seal_marker_record(&w.kek, &w.ring, &w.t, 4, 1, Marker::KeysFrozen, &mut rng).unwrap(),
        seal_marker_record(
            &w.kek,
            &w.ring,
            &w.t,
            4,
            1,
            Marker::KeysThawed { ends: 1 },
            &mut rng,
        )
        .unwrap(),
    ] {
        plant(4, bad);
        assert!(read_key_chain(&w.store, &w.kek, &w.ring, &w.t)
            .await
            .is_err());
        assert!(w.store.lose(&chain.name(4)));
    }
    // Sealing refuses a frozen_at at or above the record's seq.
    assert!(seal_key_record(
        &w.kek,
        &w.ring,
        &w.t,
        4,
        KeyOp::Create,
        1,
        &p.door,
        Some(&p.private),
        false,
        Some(4),
        &mut rng,
    )
    .is_err());
    // The right one folds.
    plant(4, subject_at(Some(2), &mut rng));
    let read = read_key_chain(&w.store, &w.kek, &w.ring, &w.t)
        .await
        .unwrap();
    assert_eq!(read.table.seq(), 4);
    assert_eq!(read.table.frozen_at(), Some(2));
    // A checkpoint keeps the freeze, so a reader from it folds the same.
    let record = chain.get(&w.store, 4).await.unwrap();
    let sealed = seal_checkpoint(&w.kek, &w.ring, &read.table, &record, &mut rng).unwrap();
    let opened = open_checkpoint(&w.kek, &w.ring, &w.t, 4, &sealed, &record).unwrap();
    assert_eq!(opened, read.table);
    // A marker opened as a subject's record is the marker error.
    let marker = chain.get(&w.store, 3).await.unwrap();
    assert!(open_key_record(&w.kek, &w.ring, &w.t, 3, &marker).is_err());
}

/// LOW 1 of AM-54: a freeze the receipt does not name is ended first
/// (only with the tenant head's `keys_frozen` clear), then a new one is
/// put.
#[tokio::test(flavor = "current_thread")]
async fn a_freeze_the_receipt_does_not_name_is_thawed_before_a_new_one() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    let env = env_gate!(w, &adm, &units, &gate);
    let mut rng = TestRng(390);
    assert_eq!(
        freeze_keys(&env, None, &mut rng).await.unwrap(),
        Freeze::Frozen { k_u: 2, seq: 3 }
    );
    gate.set_door(TenantDoor {
        keys_frozen: Some(2),
        ..TenantDoor::default()
    });
    assert_eq!(
        freeze_keys(&env, Some(7), &mut rng).await.unwrap(),
        Freeze::Refused {
            code: "tenant_keys_frozen"
        }
    );
    gate.set_door(TenantDoor::default());
    assert_eq!(
        freeze_keys(&env, None, &mut rng).await.unwrap(),
        Freeze::Frozen { k_u: 4, seq: 5 }
    );
    assert_eq!(
        chain_record(&w, 4).await,
        ChainRecord::Marker(velmora_bridge::keys::record::MarkerRecord {
            seq: 4,
            at: 1_700_000_000_000,
            marker: Marker::KeysThawed { ends: 2 },
            frozen_at: None,
        })
    );
    assert_eq!(head_table(&w).await.frozen_at(), Some(4));
}

// ---------------------------------------------------------------------------
// apply(from_seq): one entry per record, pages, Behind
// ---------------------------------------------------------------------------

use velmora_bridge::keys::apply::{apply_direct, ERR_APPLY_BEHIND};

/// Plants `subject` at `seq` with `op` (no reservation: a fixture).
fn plant(w: &World, seq: u64, op: KeyOp, subject: &Subject, frozen_at: Option<u64>) {
    let closes = op == KeyOp::Status && subject.door.status != SubjectStatus::Active;
    let bytes = seal_key_record(
        &w.kek,
        &w.ring,
        &w.t,
        seq,
        op,
        seq,
        &subject.door,
        Some(&subject.private),
        closes,
        frozen_at,
        &mut TestRng(10_000 + seq),
    )
    .unwrap();
    w.store.plant(&key_chain(&w.t).name(seq), bytes);
}

fn plant_marker(w: &World, seq: u64, marker: Marker) {
    let bytes = seal_marker_record(
        &w.kek,
        &w.ring,
        &w.t,
        seq,
        seq,
        marker,
        &mut TestRng(20_000 + seq),
    )
    .unwrap();
    w.store.plant(&key_chain(&w.t).name(seq), bytes);
}

/// `n` principals, `PA0001` …, at seqs 1 to n.
fn plant_principals(w: &World, n: u64) {
    for seq in 1..=n {
        plant(
            w,
            seq,
            KeyOp::Create,
            &principal(&format!("PA{seq:04}"), &[]),
            None,
        );
    }
}

/// A store far behind gets every record after its seq, one entry per
/// record, in pages of at most 100 with no gap (the fake asserts both).
#[tokio::test(flavor = "current_thread")]
async fn a_store_behind_gets_every_record_in_pages_without_a_gap() {
    let w = World::new();
    plant_principals(&w, 250);
    let table = head_table(&w).await;
    let none = Default::default();
    let fresh = FakeTarget::new("fresh");
    apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &fresh)
        .await
        .unwrap();
    assert_eq!(fresh.seq.get(), 250);
    assert_eq!(fresh.applies.get(), 3, "100 + 100 + 50");
    assert_eq!(fresh.rows.borrow().len(), 250);
    // From its own seq: only what it lacks.
    let mid = FakeTarget::new("mid");
    mid.seq.set(120);
    apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &mid)
        .await
        .unwrap();
    assert_eq!(mid.applies.get(), 2, "121..=220, 221..=250");
    assert_eq!(mid.rows.borrow().len(), 130);
    // At the head: nothing to send.
    apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &mid)
        .await
        .unwrap();
    assert_eq!(mid.applies.get(), 2);
}

/// A store that stops between two pages holds every subject it took as
/// the head holds it: a subject disabled in page 1 and re-enabled at the
/// head (in page 2) is sent in page 1 as the head has it. In full mode the
/// directory has the head, so that is in force; the closing step holds it
/// (see the hold rule's test).
#[tokio::test(flavor = "current_thread")]
async fn a_store_that_stops_between_pages_holds_the_chain_as_of_its_last_page() {
    let w = World::new();
    let x = principal("PX0001", &[]);
    plant(&w, 1, KeyOp::Create, &x, None);
    for seq in 2..=149 {
        plant(
            &w,
            seq,
            KeyOp::Create,
            &principal(&format!("PA{seq:04}"), &[]),
            None,
        );
    }
    let mut off = x.clone();
    off.door.status = SubjectStatus::Disabled;
    plant(&w, 50, KeyOp::Status, &off, None);
    plant(&w, 150, KeyOp::Status, &x, None);
    let table = head_table(&w).await;
    assert_eq!(
        table.get("PX0001").unwrap().door.status,
        SubjectStatus::Active
    );
    let unit = FakeTarget::new("unit");
    unit.down_after.set(Some(1));
    let none = Default::default();
    assert!(
        apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &unit)
            .await
            .is_err()
    );
    assert_eq!(unit.seq.get(), 100);
    let row = unit.row("PX0001").unwrap();
    assert_eq!(row.last_seq, 50);
    assert_eq!(row.door.status, SubjectStatus::Active);
    assert_eq!(row.door, table.get("PX0001").unwrap().door);
    // Once back, the rest: the head's state.
    unit.down.set(false);
    unit.down_after.set(None);
    apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &unit)
        .await
        .unwrap();
    assert_eq!(unit.seq.get(), 150);
    assert_eq!(
        unit.row("PX0001").unwrap(),
        table.get("PX0001").unwrap().clone()
    );
}

/// The markers of a freeze and a thaw hold their seqs' places; the store
/// skips them and reaches the head.
#[tokio::test(flavor = "current_thread")]
async fn markers_hold_their_place_in_the_run() {
    let w = World::new();
    plant_principals(&w, 3);
    plant_marker(&w, 4, Marker::KeysFrozen);
    plant(
        &w,
        5,
        KeyOp::Grants,
        &principal("PA0001", &[grant("b_09", RW, None)]),
        Some(3),
    );
    plant_marker(&w, 6, Marker::KeysThawed { ends: 3 });
    plant(&w, 7, KeyOp::Create, &principal("PA0007", &[]), None);
    let table = head_table(&w).await;
    assert_eq!(table.seq(), 7);
    let unit = FakeTarget::new("unit");
    apply_direct(
        &w.store,
        &w.kek,
        &w.ring,
        &table,
        &Default::default(),
        &unit,
    )
    .await
    .unwrap();
    assert_eq!(unit.seq.get(), 7);
    assert_eq!(*unit.markers.borrow(), vec![4, 6]);
    assert_eq!(unit.rows.borrow().len(), 4);
}

/// A store restored between its `keys_seq` and the apply answers
/// `Behind`; the bring-up reads it again and sends from its own seq. One
/// that keeps falling behind fails after a bound.
#[tokio::test(flavor = "current_thread")]
async fn a_store_that_answers_behind_is_read_again() {
    struct Restored<'a> {
        inner: &'a FakeTarget,
        restores: Cell<u32>,
        /// Reports this seq whatever it holds (restored after each read).
        reports: Option<u64>,
    }
    impl KeyTarget for Restored<'_> {
        fn label(&self) -> &str {
            "restored"
        }
        async fn keys_seq(&self) -> Result<u64> {
            match self.reports {
                Some(n) => Ok(n),
                None => KeyTarget::keys_seq(self.inner).await,
            }
        }
        async fn closed(&self) -> Result<Vec<String>> {
            KeyTarget::closed(self.inner).await
        }
        async fn apply(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied> {
            if self.restores.get() > 0 {
                self.restores.set(self.restores.get() - 1);
                self.inner.reset();
            }
            KeyTarget::apply(self.inner, from_seq, entries).await
        }
    }
    let w = World::new();
    plant_principals(&w, 30);
    let table = head_table(&w).await;
    let none = Default::default();
    let inner = FakeTarget::new("inner");
    inner.seq.set(20);
    let once = Restored {
        inner: &inner,
        restores: Cell::new(1),
        reports: None,
    };
    apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &once)
        .await
        .unwrap();
    assert_eq!(inner.seq.get(), 30);
    assert_eq!(inner.rows.borrow().len(), 30, "everything again from seq 1");
    let inner = FakeTarget::new("inner");
    inner.seq.set(20);
    let always = Restored {
        inner: &inner,
        restores: Cell::new(u32::MAX),
        reports: Some(20),
    };
    let err = apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &always)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), ERR_APPLY_BEHIND.to_string());
    assert_eq!(inner.applies.get(), 0, "nothing was kept");
}

/// The writer's own bring-up after a change sends one entry per new
/// record, and a subject held closed at the unit is sent again alone at
/// its own seq once the directory has it.
#[tokio::test(flavor = "current_thread")]
async fn a_change_sends_its_record_and_the_second_send_is_one_entry() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(400);
    w.directory.down.set(true);
    let k = s3_key(&w.t, "AKVL0002", "PR0001", &[grant("b_01", RO, None)]);
    assert_eq!(
        env.change(&mut table, "i-k2", &KeyRequest::Create(k), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Unfinished { seq: 3 }
    );
    assert_eq!(w.root.seq.get(), 3);
    assert!(w.root.row("AKVL0002").unwrap().private.is_none(), "held");
    w.directory.down.set(false);
    let before = w.root.applies.get();
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(!report.retry(), "{report:?}");
    assert!(w.root.row("AKVL0002").unwrap().private.is_some());
    assert_eq!(
        w.root.applies.get() - before,
        1,
        "only the second send, alone"
    );
}

/// An `m/rk/` revocation the chain does not record yet is in force in
/// every entry sent: in the pages, and alone at its seq for a store that
/// already holds the record.
#[tokio::test(flavor = "current_thread")]
async fn an_unrecorded_revocation_is_in_force_in_every_entry_sent() {
    let w = World::new();
    plant_principals(&w, 3);
    let table = head_table(&w).await;
    let revoked: std::collections::BTreeSet<String> = ["PA0002".to_owned()].into();
    let fresh = FakeTarget::new("fresh");
    apply_direct(&w.store, &w.kek, &w.ring, &table, &revoked, &fresh)
        .await
        .unwrap();
    assert_eq!(fresh.status("PA0002"), Some(SubjectStatus::Revoked));
    assert_eq!(fresh.status("PA0001"), Some(SubjectStatus::Active));
    // A store at the head: one call, the revoke alone.
    let at_head = FakeTarget::new("at head");
    apply_direct(
        &w.store,
        &w.kek,
        &w.ring,
        &table,
        &Default::default(),
        &at_head,
    )
    .await
    .unwrap();
    let before = at_head.applies.get();
    apply_direct(&w.store, &w.kek, &w.ring, &table, &revoked, &at_head)
        .await
        .unwrap();
    assert_eq!(at_head.applies.get() - before, 1);
    assert_eq!(at_head.status("PA0002"), Some(SubjectStatus::Revoked));
}

/// Review r1 (M1): on a frozen chain a principal's revoke has no `m/rk/`
/// that D1 honours, so it is 503 with nothing put, whatever tenant 0's
/// head becomes.
#[tokio::test(flavor = "current_thread")]
async fn a_principal_revoke_on_a_frozen_chain_is_503_and_puts_nothing() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    let env = env_gate!(w, &adm, &units, &gate);
    let mut rng = TestRng(410);
    freeze_keys(&env, None, &mut rng).await.unwrap();
    for (zero, then) in [
        (ZeroHead::D1, None),
        (
            ZeroHead::Moved { to: w.t.clone() },
            Some((1, ZeroHead::Undone { to: w.t.clone() })),
        ),
    ] {
        gate.set_zero(zero);
        *gate.then.borrow_mut() = then;
        assert_eq!(
            env.change(&mut table, "", &revoke("PR0001"), &mut rng)
                .await
                .unwrap(),
            KeyAnswer::Frozen
        );
    }
    assert!(w
        .store
        .raw(&tenant_revocation_name(&w.t, "PR0001"))
        .is_none());
    assert!(gate.calls.borrow().is_empty());
    assert_eq!(w.head(), 3);
    // A key's revoke with tenant 0 at d1 and no move applies itself.
    gate.set_zero(ZeroHead::Moved { to: w.t.clone() });
    *gate.then.borrow_mut() = Some((1, ZeroHead::D1));
    assert_eq!(
        env.change(&mut table, "", &revoke("AKVL0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::RevokedOffChain
    );
    assert_eq!(*gate.calls.borrow(), vec!["refuse_in_d1 AKVL0001"]);
}

/// A store that plants `bytes` at `at` just before the first put there:
/// another writer's record wins the seq.
struct PlantFirst<'a> {
    inner: &'a MemRecords,
    at: String,
    bytes: RefCell<Option<Vec<u8>>>,
}

impl RecordStore for PlantFirst<'_> {
    async fn put_if_absent(&self, name: &str, bytes: Vec<u8>) -> Result<bool> {
        if name == self.at {
            if let Some(b) = self.bytes.borrow_mut().take() {
                self.inner.plant(name, b);
            }
        }
        self.inner.put_if_absent(name, bytes).await
    }
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(name).await
    }
    async fn list(&self, p: &str, a: &str, l: u32) -> Result<Vec<String>> {
        self.inner.list(p, a, l).await
    }
}

fn sealed(w: &World, seq: u64, op: KeyOp, subject: &Subject) -> Vec<u8> {
    seal_key_record(
        &w.kek,
        &w.ring,
        &w.t,
        seq,
        op,
        seq,
        &subject.door,
        Some(&subject.private),
        false,
        None,
        &mut TestRng(30_000 + seq),
    )
    .unwrap()
}

/// Review r1 (M2) and its confirmation (N1): a revoke that read tenant 0
/// `moving` is decided by the head after its `m/rk/` put, and a writer
/// whose put is lost reads tenant 0's head again: a give-up in between
/// (tenant 0 back at `d1`, the key's route not this tenant's) answers
/// AM-31's `409 key_moved` after the pre-apply, with no revoke record in
/// the chain of a tenant that no longer serves the key.
#[tokio::test(flavor = "current_thread")]
async fn a_revoke_that_read_moving_is_decided_by_the_head_after_its_put() {
    // `switch`: tenant 0's head becomes `d1` after this many reads.
    for switch in [1, 2] {
        let w = World::new();
        let adm = FakeAdmission::new(&w.root);
        let mut table = seed(&w, &adm).await;
        let units = w.units();
        let gate = moved_gate(&w);
        gate.set_zero(ZeroHead::Moving { to: w.t.clone() });
        *gate.then.borrow_mut() = Some((switch, ZeroHead::D1));
        assert!(w.store.lose(&route_name("AKVL0001")));
        let store = PlantFirst {
            inner: &w.store,
            at: key_chain(&w.t).name(3),
            bytes: RefCell::new(Some(sealed(
                &w,
                3,
                KeyOp::Create,
                &principal("PR0003", &[]),
            ))),
        };
        let env = env_gate!(w, &adm, &units, &gate, &store);
        assert_eq!(
            env.change(&mut table, "", &revoke("AKVL0001"), &mut TestRng(420))
                .await
                .unwrap(),
            KeyAnswer::KeyMoved,
            "switch after {switch}"
        );
        let head = head_table(&w).await;
        assert_ne!(
            head.get("AKVL0001").unwrap().door.status,
            SubjectStatus::Revoked,
            "no revoke record after the give-up"
        );
        assert_eq!(*gate.calls.borrow(), vec!["refuse_in_d1 AKVL0001"]);
    }
}

/// Confirmation N2: after the undo, a revoke of the tenant's internal key
/// is the tenant's own: its `m/rk/<t>/` is put (D1 never held the key).
#[tokio::test(flavor = "current_thread")]
async fn after_the_undo_the_internal_keys_revoke_is_the_tenants_own() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    let env = env_gate!(w, &adm, &units, &gate);
    let mut rng = TestRng(425);
    let mut internal = subject("AKIN0001", SubjectKind::Internal, None, &[]);
    let (v, wrapped) =
        wrap_secret_v2(&kek(), &w.t, "AKIN0001", b"internal", &mut TestRng(8)).unwrap();
    internal.door.secret_kek_version = Some(v);
    internal.private.secret_wrapped = Some(wrapped);
    assert!(matches!(
        env.change(&mut table, "i-in", &KeyRequest::Create(internal), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Done { .. }
    ));
    freeze_keys(&env, None, &mut rng).await.unwrap();
    gate.set_zero(ZeroHead::Undone { to: w.t.clone() });
    assert_eq!(
        env.change(&mut table, "", &revoke("AKIN0001"), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::RevokedOffChain
    );
    assert!(w
        .store
        .raw(&tenant_revocation_name(&w.t, "AKIN0001"))
        .is_some());
    assert_eq!(*gate.calls.borrow(), vec!["refuse_in_d1 AKIN0001"]);
}

/// Confirmation N4: a bucket create reads tenant 0's head for every
/// attempt: a put lost to the move tool's first record sees `moving`.
#[tokio::test(flavor = "current_thread")]
async fn a_bucket_create_whose_put_is_lost_reads_tenant_zero_again() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    gate.set_zero(ZeroHead::D1);
    *gate.then.borrow_mut() = Some((1, ZeroHead::Moving { to: w.t.clone() }));
    let store = PlantFirst {
        inner: &w.store,
        at: key_chain(&w.t).name(3),
        bytes: RefCell::new(Some(sealed(
            &w,
            3,
            KeyOp::Create,
            &principal("PR0003", &[]),
        ))),
    };
    let env = env_gate!(w, &adm, &units, &gate, &store);
    let buckets = FakeBuckets::default();
    assert_eq!(
        env.create_bucket(
            &buckets,
            &mut table,
            "ib-l",
            &photos("PR0001"),
            &mut TestRng(426)
        )
        .await
        .unwrap(),
        BucketAnswer::Busy
    );
    assert_eq!(w.head(), 3, "only the planted record");
    assert_eq!(buckets.calls.get(), 0);
}

/// Second confirmation (LOW 4): a revoke that read the move's window and
/// finds the undo's `d1` after its `m/rk/` put takes the post-undo path:
/// tenant 0's for a moved key, the tenant's own for its internal key.
#[tokio::test(flavor = "current_thread")]
async fn a_revoke_that_read_moving_and_finds_the_undo_takes_its_path() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    let env = env_gate!(w, &adm, &units, &gate);
    let mut rng = TestRng(450);
    let mut internal = subject("AKIN0001", SubjectKind::Internal, None, &[]);
    let (v, wrapped) =
        wrap_secret_v2(&kek(), &w.t, "AKIN0001", b"internal", &mut TestRng(9)).unwrap();
    internal.door.secret_kek_version = Some(v);
    internal.private.secret_wrapped = Some(wrapped);
    env.change(&mut table, "i-in", &KeyRequest::Create(internal), &mut rng)
        .await
        .unwrap();
    let head = w.head();
    for (id, answer, call) in [
        (
            "AKVL0001",
            KeyAnswer::RevokedOffChain,
            "zero_revoke AKVL0001",
        ),
        (
            "AKIN0001",
            KeyAnswer::RevokedOffChain,
            "refuse_in_d1 AKIN0001",
        ),
    ] {
        gate.calls.borrow_mut().clear();
        gate.set_zero(ZeroHead::Moving { to: w.t.clone() });
        *gate.then.borrow_mut() = Some((1, ZeroHead::Undone { to: w.t.clone() }));
        assert_eq!(
            env.change(&mut table, "", &revoke(id), &mut rng)
                .await
                .unwrap(),
            answer,
            "{id}"
        );
        assert_eq!(*gate.calls.borrow(), vec![call]);
    }
    assert_eq!(w.head(), head, "no revoke record");
    assert!(w
        .store
        .raw(&tenant_revocation_name(&w.t, "AKIN0001"))
        .is_some());
}

/// A ring that holds v1, marks v2 gone, and may report itself partial.
struct GoneTwo {
    key: TenantKey,
    partial: bool,
}

impl velmora_bridge::keys::record::TkRing for GoneTwo {
    fn current(&self) -> Option<&TenantKey> {
        Some(&self.key)
    }
    fn key(&self, v: u32) -> Option<&TenantKey> {
        (v == 1).then_some(&self.key)
    }
    fn gone(&self, v: u32) -> bool {
        v == 2
    }
    fn partial(&self) -> bool {
        self.partial
    }
}

/// Second confirmation (LOW 1): the exit skips a holder sealed under a
/// gone version only by AM-11's test; with a partial ring it is blocked.
#[tokio::test(flavor = "current_thread")]
async fn the_exit_skips_a_gone_holder_only_when_it_is_lost_for_good() {
    // (partial ring, a checkpoint at the holder's seq that cannot be read)
    for (partial, unreadable_checkpoint) in [(false, false), (true, false), (false, true)] {
        let w = World::new();
        let adm = FakeAdmission::new(&w.root);
        seed(&w, &adm).await;
        let units = w.units();
        let gate = moved_gate(&w);
        let v2 = OneKey(TenantKey::from_bytes(&w.t, 2, derived("tk v2")).unwrap());
        let p4 = principal("PR0004", &[grant("b_01", RW, None)]);
        let bytes = seal_key_record(
            &w.kek,
            &v2,
            &w.t,
            3,
            KeyOp::Create,
            3,
            &p4.door,
            Some(&p4.private),
            false,
            None,
            &mut TestRng(451),
        )
        .unwrap();
        w.store.plant(&key_chain(&w.t).name(3), bytes);
        let ring = GoneTwo {
            key: TenantKey::from_bytes(&w.t, 1, derived("tk")).unwrap(),
            partial,
        };
        if unreadable_checkpoint {
            // It may hold PR0004 whole: never taken for lost (AM-11).
            w.store.plant(
                &velmora_bridge::keys::checkpoint::checkpoint_name(&w.t, 3),
                b"not a checkpoint".to_vec(),
            );
        }
        let env = env_with!(w, &ring, &adm, &units);
        let env = KeyEnv { gate: &gate, ..env };
        let drops = drop_moved_grants(&env, &["b_01".into()], &mut TestRng(452))
            .await
            .unwrap();
        assert_eq!(drops.written, vec![4, 5], "partial = {partial}");
        match partial || unreadable_checkpoint {
            false => assert!(drops.done && drops.blocked.is_empty()),
            true => {
                assert!(!drops.done);
                assert_eq!(drops.blocked, vec!["PR0004".to_owned()]);
            }
        }
    }
}

/// Second confirmation (LOW 3): a disabled key reaches D1 with its
/// effective grant, so a re-enable on tenant 0's path finds it.
#[tokio::test(flavor = "current_thread")]
async fn a_disabled_key_keeps_its_effective_grant_in_d1() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(453);
    env.change(&mut table, "", &disable("AKVL0001"), &mut rng)
        .await
        .unwrap();
    let d1 = d1_projection(&head_table(&w).await);
    assert_eq!(d1[0].status, SubjectStatus::Disabled);
    assert_eq!(d1[0].grants, vec![("b_01".to_owned(), RO)]);
    // Also under a disabled principal.
    env.change(&mut table, "", &enable("AKVL0001"), &mut rng)
        .await
        .unwrap();
    env.change(&mut table, "", &disable("PR0001"), &mut rng)
        .await
        .unwrap();
    let d1 = d1_projection(&head_table(&w).await);
    assert_eq!(d1[0].status, SubjectStatus::Disabled);
    assert_eq!(d1[0].grants, vec![("b_01".to_owned(), RO)]);
}

/// Final confirmation (LOW 1): a revoked key, and a key under a revoked
/// principal, reach D1 with no grant.
#[tokio::test(flavor = "current_thread")]
async fn a_revoked_key_or_principal_carries_no_grant_to_d1() {
    for id in ["PR0001", "AKVL0001"] {
        let w = World::new();
        let adm = FakeAdmission::new(&w.root);
        let mut table = seed(&w, &adm).await;
        let units = w.units();
        let env = env!(w, &adm, &units);
        env.change(&mut table, "", &revoke(id), &mut TestRng(460))
            .await
            .unwrap();
        let d1 = d1_projection(&head_table(&w).await);
        let expect = match id {
            "PR0001" => SubjectStatus::Disabled,
            _ => SubjectStatus::Revoked,
        };
        assert_eq!(d1[0].status, expect, "{id}");
        assert!(d1[0].grants.is_empty(), "{id}");
    }
}

/// Review r1 (L1, L2): the exit's holders are found again at every head,
/// so one that gains a listed grant during the run is dropped too; a
/// holder whose private part does not open is reported, not retried.
#[tokio::test(flavor = "current_thread")]
async fn the_exit_finds_new_holders_and_reports_blocked_ones() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    seed(&w, &adm).await;
    let units = w.units();
    let gate = moved_gate(&w);
    // A subject gains b_01 just as the exit writes its first record.
    let store = PlantFirst {
        inner: &w.store,
        at: key_chain(&w.t).name(3),
        bytes: RefCell::new(Some(sealed(
            &w,
            3,
            KeyOp::Create,
            &principal("PR0003", &[grant("b_01", RW, None)]),
        ))),
    };
    let env = env_gate!(w, &adm, &units, &gate, &store);
    let mut rng = TestRng(430);
    let drops = drop_moved_grants(&env, &["b_01".into()], &mut rng)
        .await
        .unwrap();
    assert_eq!(drops.written, vec![4, 5, 6]);
    assert!(drops.done && drops.blocked.is_empty());
    let head = head_table(&w).await;
    for id in ["AKVL0001", "PR0001", "PR0003"] {
        assert!(head.get(id).unwrap().door.grants.is_empty(), "{id}");
    }
    // A holder sealed under a key version this ring does not hold.
    let other = OneKey(TenantKey::from_bytes(&w.t, 2, derived("tk v2")).unwrap());
    let p4 = principal("PR0004", &[grant("b_01", RW, None)]);
    let bytes = seal_key_record(
        &w.kek,
        &other,
        &w.t,
        7,
        KeyOp::Create,
        7,
        &p4.door,
        Some(&p4.private),
        false,
        None,
        &mut rng,
    )
    .unwrap();
    w.store.plant(&key_chain(&w.t).name(7), bytes);
    // An open holder that sorts after it is still dropped.
    let p5 = principal("PR0005", &[grant("b_01", RW, None)]);
    w.store
        .plant(&key_chain(&w.t).name(8), sealed(&w, 8, KeyOp::Create, &p5));
    // A holder revoked by `m/rk/` only holds nothing in force: skipped.
    let p6 = principal("PR0006", &[grant("b_01", RW, None)]);
    w.store
        .plant(&key_chain(&w.t).name(9), sealed(&w, 9, KeyOp::Create, &p6));
    put_tenant_revocation(&w.store, &w.kek, &w.t, "PR0006", 9, &mut rng)
        .await
        .unwrap();
    let env = env_gate!(w, &adm, &units, &gate);
    let drops = drop_moved_grants(&env, &["b_01".into()], &mut rng)
        .await
        .unwrap();
    assert_eq!(drops.written, vec![10]);
    assert_eq!(drops.blocked, vec!["PR0004".to_owned()]);
    assert!(!drops.done);
}

/// Review r1 of the apply (M1): a store that stops between pages never
/// serves a subject more open than the head or than it did before. The
/// unit holds PX0001 disabled; the chain re-enables it at 60 and disables
/// it again at the head; after page 1 alone it must not be active.
#[tokio::test(flavor = "current_thread")]
async fn an_older_record_never_opens_a_subject_between_pages() {
    let w = World::new();
    let x = principal("PX0001", &[]);
    let mut off = x.clone();
    off.door.status = SubjectStatus::Disabled;
    plant(&w, 1, KeyOp::Create, &x, None);
    plant(&w, 2, KeyOp::Status, &off, None);
    for seq in 3..=149 {
        plant(
            &w,
            seq,
            KeyOp::Create,
            &principal(&format!("PA{seq:04}"), &[]),
            None,
        );
    }
    plant(&w, 60, KeyOp::Status, &x, None);
    plant(&w, 150, KeyOp::Status, &off, None);
    let table = head_table(&w).await;
    let none = Default::default();
    let unit = FakeTarget::new("unit");
    // The unit at seq 2, PX0001 disabled.
    {
        let early = {
            let mut t = KeyTable::empty(w.t.clone());
            let chain = key_chain(&w.t);
            for seq in 1..=2 {
                let b = chain.get(&w.store, seq).await.unwrap();
                t.apply(&open_key_record(&w.kek, &w.ring, &w.t, seq, &b).unwrap())
                    .unwrap();
            }
            t
        };
        let e = early.get("PX0001").unwrap().clone();
        KeyTarget::apply(
            &unit,
            0,
            &[ApplyEntry::Marker { seq: 1 }, ApplyEntry::Subject(e)],
        )
        .await
        .unwrap();
    }
    assert_eq!(unit.status("PX0001"), Some(SubjectStatus::Disabled));
    unit.down_after.set(Some(1));
    assert!(
        apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &unit)
            .await
            .is_err()
    );
    assert_eq!(unit.seq.get(), 102);
    assert_ne!(unit.status("PX0001"), Some(SubjectStatus::Active));
}

/// Review r1 of the apply (M2): an `m/rk/` revocation without its record
/// reaches a store before any page, so a page that fails cannot keep it
/// out.
#[tokio::test(flavor = "current_thread")]
async fn an_unrecorded_revocation_goes_before_the_pages() {
    let w = World::new();
    plant_principals(&w, 200);
    let table = head_table(&w).await;
    let revoked: std::collections::BTreeSet<String> = ["PA0010".to_owned()].into();
    let unit = FakeTarget::new("unit");
    unit.seq.set(50);
    unit.down_after.set(Some(1));
    assert!(
        apply_direct(&w.store, &w.kek, &w.ring, &table, &revoked, &unit)
            .await
            .is_err()
    );
    assert_eq!(unit.status("PA0010"), Some(SubjectStatus::Revoked));
    assert_eq!(unit.seq.get(), 50, "no page was taken");
}

/// Review r1 of the apply (LOW 3): many held subjects that now open are
/// sent again as one run of the records, not one call each.
#[tokio::test(flavor = "current_thread")]
async fn many_reopened_subjects_take_one_run() {
    let w = World::new();
    plant_principals(&w, 250);
    let table = head_table(&w).await;
    let none = Default::default();
    let unit = FakeTarget::new("unit");
    apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &unit)
        .await
        .unwrap();
    // Every row held closed (applied by a Worker that could not open them).
    for row in unit.rows.borrow_mut().values_mut() {
        row.private = None;
    }
    let before = unit.applies.get();
    apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &unit)
        .await
        .unwrap();
    assert_eq!(unit.applies.get() - before, 3, "100 + 100 + 50, not 250");
    assert!(unit.rows.borrow().values().all(|r| r.private.is_some()));
}

/// Confirmation of the apply (N1): a directory that stopped between
/// pages holds what it took as the head has it, so the closing step at a
/// unit opens nothing the directory holds closed. PX0001 is made at 40 and
/// narrowed at 150; the directory takes page 1 and stops; then the unit's
/// closing step at `acked = 100` must match what the directory holds.
#[tokio::test(flavor = "current_thread")]
async fn the_closing_step_never_opens_what_a_partial_directory_holds_closed() {
    let w = World::new();
    for seq in 1..=149 {
        let id = match seq {
            40 => "PX0001".to_owned(),
            _ => format!("PA{seq:04}"),
        };
        let g = [grant("b_01", RW, None)];
        let grants: &[Grant] = if seq == 40 { &g } else { &[] };
        plant(&w, seq, KeyOp::Create, &principal(&id, grants), None);
    }
    plant(&w, 150, KeyOp::Grants, &principal("PX0001", &[]), None);
    let table = head_table(&w).await;
    let none = Default::default();
    let directory = FakeTarget::new("directory");
    directory.down_after.set(Some(1));
    assert!(
        apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &directory)
            .await
            .is_err()
    );
    assert_eq!(directory.seq.get(), 100);
    let at_dir = directory.row("PX0001").unwrap();
    assert!(at_dir.private.is_some(), "the directory holds it open");
    assert!(at_dir.door.grants.is_empty(), "as the head narrows it");
}

/// Confirmation of the apply (N6): the closing step sends open what the
/// directory acknowledged, without waiting for the full step.
#[tokio::test(flavor = "current_thread")]
async fn the_closing_step_sends_open_what_the_directory_acknowledged() {
    let w = World::new();
    let adm = FakeAdmission::new(&w.root);
    let mut table = seed(&w, &adm).await;
    let units = w.units();
    let env = env!(w, &adm, &units);
    let mut rng = TestRng(440);
    // A new key at 3, held at the units (the directory was down).
    w.directory.down.set(true);
    let k = s3_key(&w.t, "AKVL0002", "PR0001", &[grant("b_01", RO, None)]);
    assert_eq!(
        env.change(&mut table, "i-k2", &KeyRequest::Create(k), &mut rng)
            .await
            .unwrap(),
        KeyAnswer::Unfinished { seq: 3 }
    );
    w.directory.down.set(false);
    // The directory takes the head by itself; the units are reset to seq
    // 2, then a finisher whose directory step fails.
    apply_direct(
        &w.store,
        &w.kek,
        &w.ring,
        &head_table(&w).await,
        &Default::default(),
        &w.directory,
    )
    .await
    .unwrap();
    for u in [&w.root, &w.unit2] {
        u.rows.borrow_mut().remove("AKVL0002");
        u.seq.set(2);
    }
    // A revoke of another key lands first, so the directory has a step
    // to fail.
    put_tenant_revocation(&w.store, &w.kek, &w.t, "AKVL0001", 5, &mut rng)
        .await
        .unwrap();
    w.directory.down_after.set(Some(0));
    let report = finish_keys(&env, &mut rng).await.unwrap();
    assert!(report.failed.contains(&"directory".to_owned()));
    assert!(w.root.row("AKVL0002").unwrap().private.is_some());
}

/// Confirmation of the apply (N2, N6): one held subject with a long span
/// is sent alone; a store ahead of the table is never asked for records
/// past the table.
#[tokio::test(flavor = "current_thread")]
async fn the_second_send_picks_the_cheaper_form_and_stays_within_the_table() {
    let w = World::new();
    plant_principals(&w, 250);
    let table = head_table(&w).await;
    let none = Default::default();
    let unit = FakeTarget::new("unit");
    apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &unit)
        .await
        .unwrap();
    unit.rows.borrow_mut().get_mut("PA0001").unwrap().private = None;
    let before = unit.applies.get();
    apply_direct(&w.store, &w.kek, &w.ring, &table, &none, &unit)
        .await
        .unwrap();
    assert_eq!(unit.applies.get() - before, 1, "alone, not 3 pages");
    // A store ahead of the caller's table (another writer's records) with
    // five held subjects: the run stops at the table's head.
    let stale = {
        let mut t = KeyTable::empty(w.t.clone());
        let chain = key_chain(&w.t);
        for seq in 1..=5 {
            let b = chain.get(&w.store, seq).await.unwrap();
            t.apply(&open_key_record(&w.kek, &w.ring, &w.t, seq, &b).unwrap())
                .unwrap();
        }
        t
    };
    for id in ["PA0001", "PA0002", "PA0003", "PA0004", "PA0005"] {
        unit.rows.borrow_mut().get_mut(id).unwrap().private = None;
    }
    apply_direct(&w.store, &w.kek, &w.ring, &stale, &none, &unit)
        .await
        .unwrap();
    for id in ["PA0001", "PA0002", "PA0003", "PA0004", "PA0005"] {
        assert!(unit.row(id).unwrap().private.is_some(), "{id}");
    }
}
