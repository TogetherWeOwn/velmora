//! The unit client (round 5 §R5-4, AM-50, AM-51): the Worker's side of
//! `renew` and `sync`, rule 5 on the request path, and the `renew` and
//! `stamp_raise` jobs, against the real unit (`Unit` over SQLite), L3's
//! tenant chain (`TenantChain` over an in-memory record store) and the
//! in-memory safety bucket the proof reads.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::{poll_fn, Future};
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use tokio::sync::oneshot;
use velmora_bridge::directory::chain::{
    record_key, ChainError, ControlSeal, ReadRecord, TenantChain, Written,
};
use velmora_bridge::directory::record::{HoldMode, OperatorReason, Tenant, TenantDoor};
use velmora_bridge::directory::testing::{HookedRecords, PlainSeal};
use velmora_bridge::directory::transition::{Actor, Change, OperatorHoldRequest, KEY_CHECK_LEN};
use velmora_bridge::jobmsg::UnitJob;
use velmora_bridge::keys::record::key_chain;
use velmora_bridge::keys::revocations::tenant_revocation_prefix;
use velmora_bridge::recovery::Unpublished;
use velmora_bridge::stamp::stamp_key;
use velmora_bridge::testkit::{FixedClock, MemBlobStore, RusqliteSql};
use velmora_bridge::unit::jobcall::JobCall;
use velmora_bridge::unit::keys::{Access, ApplyEntry, KeyEntry, KeyGrant, KeyKind, SubjectStatus};
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Refused, Seqs, TenantId, TenantState, Unit, UnitAnswer,
    UnitCall, UnitName, UnitOp, UnitReply,
};
use velmora_bridge::unit_lease::client::{
    lease_expired, Answered, Delivery, InFlight, KeyBatch, KeyFeed, KeyFinisher, Page, RecordNames,
    Renewal, Sleep, Synced, TenantHeads, UnitClient, UnitReplies, RENEW_POLL_MS, RENEW_WAIT_MS,
};
use velmora_bridge::unit_lease::lease::LeaseRules;
use velmora_bridge::unit_lease::renewal::ChainNames;
use velmora_bridge::{
    BlobMeta, BlobStore, BridgeError, BucketId, ByteSpan, Clock, ExtentId, Result, UnixMs,
};

const NOW: UnixMs = UnixMs(1_800_000_000_000);
const T: i64 = LeaseRules::DEFAULT.term_ms;
const P: &str = "p_owner";
const K: &str = "AKCLIENT000000000001";
const GONE: &str = "AKCLIENT000000000099";
const B1: &str = "b_00000000000000e1";

fn tid() -> &'static str {
    "t_00000000000000a1"
}

fn tenant() -> TenantId {
    TenantId::parse(tid()).unwrap()
}

fn dir_tenant() -> Tenant {
    Tenant::parse(tid()).unwrap()
}

fn own() -> UnitName {
    UnitName::new(tenant(), 0)
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

// ---------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------

type Hook<'a> = Box<dyn FnOnce(&Unit<RusqliteSql>) + 'a>;

struct SyncAttempt {
    from_seq: u64,
    to_seq: u64,
    answer: UnitAnswer,
}

/// The unit object as the stub reaches it: the real unit at the rig's
/// clock, with a log of the calls and a way to fail them.
struct Obj<'a> {
    unit: Unit<RusqliteSql>,
    clock: &'a FixedClock,
    log: RefCell<Vec<(CallKind, bool, String, bool)>>,
    sync_attempts: RefCell<Vec<SyncAttempt>>,
    /// Holds the next sync just before it reaches the unit.
    sync_gate: RefCell<Option<oneshot::Receiver<()>>>,
    fail: Cell<bool>,
    /// Run once, right after the first `stamp` read answered.
    after_stamp_read: RefCell<Option<Hook<'a>>>,
    /// Holds the next stamp reply until the test releases it.
    stamp_read_gate: RefCell<Option<oneshot::Receiver<()>>>,
    /// The answer to the next call of this op is lost after the unit ran
    /// it.
    lose_answer_of: Cell<Option<&'static str>>,
    /// Another writer raises the stamp after every stamp read.
    raise_after_each_read: Cell<bool>,
    /// Calls of this op are answered with this, not by the unit.
    answer_of: RefCell<Option<(&'static str, UnitAnswer)>>,
    /// The next call of this op is answered with this, once.
    answer_once: RefCell<Option<(&'static str, UnitAnswer)>>,
    safety: &'a MemBlobStore,
}

fn op_name(op: &UnitOp) -> String {
    match op {
        UnitOp::Job { call } => format!("job:{}", call.name()),
        other => {
            let v = serde_json::to_value(other).unwrap();
            v.get("op")
                .and_then(|o| o.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| format!("{v}").chars().take(24).collect())
        }
    }
}

impl UnitReplies for Obj<'_> {
    async fn reply(&self, call: &UnitCall) -> Result<UnitReply> {
        if self.fail.get() {
            return Err(BridgeError::Sql("unit: call failed".into()));
        }
        self.log.borrow_mut().push((
            call.kind,
            call.listed,
            op_name(&call.op),
            call.authenticated,
        ));
        let once = self
            .answer_once
            .borrow()
            .as_ref()
            .is_some_and(|(op, _)| *op == op_name(&call.op));
        if once {
            let (_, answer) = self.answer_once.borrow_mut().take().unwrap();
            return Ok(UnitReply {
                answer,
                lease_left_ms: 0,
                revoked: None,
            });
        }
        if let Some((op, answer)) = self.answer_of.borrow().as_ref() {
            if *op == op_name(&call.op) {
                return Ok(UnitReply {
                    answer: answer.clone(),
                    lease_left_ms: 0,
                    revoked: None,
                });
            }
        }
        if matches!(call.op, UnitOp::Sync { .. }) {
            let gate = self.sync_gate.borrow_mut().take();
            if let Some(gate) = gate {
                gate.await.expect("the test must release the sync");
            }
        }
        let reply = self.unit.reply(call, self.clock.now());
        if let UnitOp::Sync { head } = &call.op {
            self.sync_attempts.borrow_mut().push(SyncAttempt {
                from_seq: head.from_seq,
                to_seq: head.seqs.state_seq,
                answer: reply.answer.clone(),
            });
        }
        if let UnitOp::Job {
            call: JobCall::stamp { catalogue },
        } = &call.op
        {
            if let Some(hook) = self.after_stamp_read.borrow_mut().take() {
                hook(&self.unit);
            }
            if self.raise_after_each_read.get() {
                raise_now(&self.unit, self.safety, catalogue, self.clock.now());
            }
            let gate = self.stamp_read_gate.borrow_mut().take();
            if let Some(gate) = gate {
                gate.await.expect("the test must release the stamp reply");
            }
        }
        if self.lose_answer_of.get() == Some(op_name(&call.op).as_str()) {
            self.lose_answer_of.set(None);
            return Err(BridgeError::Sql("unit: answer lost".into()));
        }
        Ok(reply)
    }
}

/// The key chain as the Worker reads it: entries by seq.
#[derive(Default)]
struct Keys(
    RefCell<BTreeMap<u64, ApplyEntry>>,
    /// What `acked` answers.
    Cell<u64>,
    /// Every `after` call: its base, `acked` and `closed`.
    RefCell<Vec<(u64, u64, Vec<String>)>>,
);

impl KeyFeed for Keys {
    async fn acked(&self, t: &TenantId) -> u64 {
        assert_eq!(t, &tenant());
        self.1.get()
    }
    async fn after(
        &self,
        t: &TenantId,
        after: u64,
        acked: u64,
        closed: &[String],
    ) -> Result<KeyBatch> {
        assert_eq!(t, &tenant());
        self.2.borrow_mut().push((after, acked, closed.to_vec()));
        let all = self.0.borrow();
        // The chain's own head, whatever `after` says.
        let head = all.keys().next_back().copied().unwrap_or(0);
        Ok(KeyBatch {
            head,
            entries: all.range(after + 1..).map(|(_, e)| e.clone()).collect(),
            answers: vec![],
        })
    }
}

#[derive(Default)]
struct Finisher(Cell<u32>, Cell<bool>);

impl KeyFinisher for Finisher {
    async fn revocations_unrecorded(&self, t: &TenantId) -> Result<()> {
        assert_eq!(t, &tenant());
        self.0.set(self.0.get() + 1);
        match self.1.get() {
            true => Err(BridgeError::Queue("send failed".into())),
            false => Ok(()),
        }
    }
}

/// Another writer's raise: the counter in the unit, then the object.
fn raise_now(unit: &Unit<RusqliteSql>, safety: &MemBlobStore, id: &str, now: UnixMs) {
    let seqs = unit.head().unwrap().seqs;
    let read = UnitCall {
        name: own(),
        kind: CallKind::Job,
        seqs: Some(seqs),
        authenticated: true,
        listed: false,
        op: UnitOp::Job {
            call: JobCall::stamp {
                catalogue: id.to_string(),
            },
        },
    };
    let UnitAnswer::Ok { body, .. } = unit.handle(&read, now) else {
        return;
    };
    let row: velmora_bridge::stamp::StampRow = serde_json::from_value(body).unwrap();
    let advance = UnitCall {
        op: UnitOp::Job {
            call: JobCall::stamp_advance {
                from: row.counter,
                catalogue: id.to_string(),
            },
        },
        ..read
    };
    if matches!(unit.handle(&advance, now), UnitAnswer::Ok { .. }) {
        put_inline(safety, &stamp_key(id, row.counter.map_or(1, |c| c + 1)));
    }
}

struct Rig<'a> {
    clock: &'a FixedClock,
    records: &'a HookedRecords,
    seal: &'a PlainSeal,
    safety: &'a MemBlobStore,
    keys: &'a Keys,
    finisher: &'a Finisher,
    flights: InFlight,
    record_reads: RefCell<Vec<u64>>,
    obj: Obj<'a>,
}

/// The real tenant chain, with a trace of the exact records a sync opens.
struct Heads<'a> {
    chain: TenantChain<'a, HookedRecords, PlainSeal>,
    record_reads: &'a RefCell<Vec<u64>>,
}

impl TenantHeads for Heads<'_> {
    async fn head(
        &self,
        tenant: &TenantId,
        known: u64,
    ) -> std::result::Result<Option<TenantDoor>, ChainError> {
        TenantHeads::head(&self.chain, tenant, known).await
    }

    async fn record(
        &self,
        tenant: &TenantId,
        seq: u64,
    ) -> std::result::Result<Option<ReadRecord>, ChainError> {
        self.record_reads.borrow_mut().push(seq);
        self.chain.record(tenant, seq).await
    }
}

/// The rig's safety bucket, lent to a client.
struct Safety<'a>(&'a MemBlobStore);

impl BlobStore for Safety<'_> {
    async fn put(&self, key: &str, bytes: Vec<u8>, meta: &BlobMeta<'_>) -> Result<()> {
        self.0.put(key, bytes, meta).await
    }
    async fn get(&self, key: &str, span: Option<ByteSpan>) -> Result<Option<Vec<u8>>> {
        self.0.get(key, span).await
    }
    async fn head(&self, key: &str) -> Result<Option<u64>> {
        self.0.head(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.0.delete(key).await
    }
    async fn delete_record(&self, refused: &Unpublished) -> Result<()> {
        self.0.delete_record(refused).await
    }
    async fn list(&self, prefix: &str, start_after: &str, limit: u32) -> Result<Vec<String>> {
        self.0.list(prefix, start_after, limit).await
    }
}

type Client<'s, 'a> =
    UnitClient<&'s Obj<'a>, Safety<'s>, FixedClock, RecordNames, Heads<'s>, &'s Keys, &'s Finisher>;

impl<'a> Rig<'a> {
    fn client<'s>(&'s self) -> Client<'s, 'a> {
        self.client_of(own())
    }

    fn client_of<'s>(&'s self, name: UnitName) -> Client<'s, 'a> {
        UnitClient {
            unit: &self.obj,
            safety: Safety(self.safety),
            clock: self.clock.clone(),
            names: RecordNames,
            heads: Heads {
                chain: TenantChain {
                    store: self.records,
                    seal: self.seal,
                },
                record_reads: &self.record_reads,
            },
            keys: self.keys,
            finisher: self.finisher,
            name,
            listed: true,
            lease: LeaseRules::DEFAULT,
            flights: self.flights.clone(),
        }
    }

    /// One tenant record, mirrored into the safety bucket under its name
    /// (the proof HEADs it there).
    fn write(&self, change: Change, actor: Actor) {
        let chain = TenantChain {
            store: self.records,
            seal: self.seal,
        };
        let w = block_on(chain.write(&dir_tenant(), &change, actor, self.clock.now(), 0));
        assert!(matches!(w, Ok(Written::Wrote(_))), "{w:?}");
        self.mirror();
    }

    fn mirror(&self) {
        for key in self.records.keys() {
            if !self.safety.contains(&key) {
                put(self.safety, &key);
            }
        }
    }

    fn head_seq(&self) -> u64 {
        let chain = TenantChain {
            store: self.records,
            seal: self.seal,
        };
        block_on(chain.head(&dir_tenant(), 0))
            .unwrap()
            .unwrap()
            .door
            .seq
    }

    /// A key-chain record at `seq`, with its name in the safety bucket.
    fn key_record(&self, seq: u64, entry: impl Into<ApplyEntry>) {
        self.keys.0.borrow_mut().insert(seq, entry.into());
        put(self.safety, &RecordNames.key_record(tid(), seq));
    }

    fn unit_seqs(&self) -> Seqs {
        self.obj.unit.head().unwrap().seqs
    }

    /// A request ping at the unit's own numbers, as an S3 call would make.
    fn ping(&self) -> UnitAnswer {
        let c = request(self.unit_seqs(), UnitOp::Ping {});
        self.obj.unit.handle(&c, self.clock.now())
    }

    fn calls(&self) -> Vec<String> {
        self.obj.log.borrow().iter().map(|c| c.2.clone()).collect()
    }

    fn assert_call_auth(&self, expected: &[(&str, bool)]) {
        let log = self.obj.log.borrow();
        let actual: Vec<_> = log.iter().map(|c| (c.2.as_str(), c.3)).collect();
        assert_eq!(actual.as_slice(), expected);
    }
}

fn put(safety: &MemBlobStore, key: &str) {
    block_on(put_now(safety, key));
}

/// [`put`] from inside a call (the in-memory store never waits).
fn put_inline(safety: &MemBlobStore, key: &str) {
    velmora_bridge::unit::poll_once(put_now(safety, key)).unwrap();
}

async fn put_now(safety: &MemBlobStore, key: &str) {
    let (bucket, extent) = (BucketId::new("-"), ExtentId::new("planted"));
    let sha: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(b"r").into()
    };
    let meta = BlobMeta {
        bucket: &bucket,
        extent: &extent,
        cipher_sha256: &sha,
    };
    safety.put(key, b"r".to_vec(), &meta).await.unwrap();
}

fn request(seqs: Seqs, op: UnitOp) -> UnitCall {
    UnitCall {
        name: own(),
        kind: CallKind::Request,
        seqs: Some(seqs),
        authenticated: true,
        listed: true,
        op,
    }
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

/// A record that changes nothing a unit holds but its seq.
fn limits(rig: &Rig<'_>) -> Change {
    Change::SetLimits {
        base_seq: rig.head_seq(),
        // A new value each time: the same one again changes nothing.
        limits: BTreeMap::from([("bytes".to_string(), (1 << 30) + rig.head_seq())]),
        rate_json: None,
    }
}

/// The unit's stamp row, read through its job path.
fn stamp_row(rig: &Rig<'_>, id: &str) -> velmora_bridge::stamp::StampRow {
    let c = UnitCall {
        name: own(),
        kind: CallKind::Job,
        seqs: Some(rig.unit_seqs()),
        authenticated: true,
        listed: false,
        op: UnitOp::Job {
            call: JobCall::stamp {
                catalogue: id.to_string(),
            },
        },
    };
    match rig.obj.unit.handle(&c, rig.clock.now()) {
        UnitAnswer::Ok { body, .. } => serde_json::from_value(body).unwrap(),
        other => panic!("{other:?}"),
    }
}

fn principal(seq: u64) -> KeyEntry {
    KeyEntry {
        id: P.into(),
        kind: KeyKind::Principal,
        status: SubjectStatus::Active,
        held: false,
        made_by: None,
        grants: vec![KeyGrant {
            bucket_id: B1.into(),
            access: Access::Rw,
            expires_at: None,
            prefix: None,
            ip_list: vec![],
        }],
        created_at: 1,
        secret_wrapped: None,
        secret_kek_version: None,
        owner_ref: Some("member-1".into()),
        last_seq: seq,
        rid: None,
    }
}

fn key(id: &str, seq: u64, status: SubjectStatus) -> KeyEntry {
    KeyEntry {
        id: id.into(),
        kind: KeyKind::S3,
        status,
        held: false,
        made_by: Some(P.into()),
        grants: vec![KeyGrant {
            bucket_id: B1.into(),
            access: Access::Ro,
            expires_at: None,
            prefix: None,
            ip_list: vec![],
        }],
        created_at: 2,
        secret_wrapped: Some(vec![2, 0xaa]),
        secret_kek_version: Some(1),
        owner_ref: Some("member-1".into()),
        last_seq: seq,
        rid: None,
    }
}

/// A live tenant (4 records: create, claim, commit, activate, which lists
/// unit 0) with two key-chain records (the principal, a key), and its
/// unit 0 born at seq 4 and not yet synced.
fn with_rig<R>(f: impl FnOnce(&Rig<'_>) -> R) -> R {
    let clock = FixedClock::new(NOW);
    let (records, seal, safety) = (HookedRecords::new(), PlainSeal::new(), MemBlobStore::new());
    let (keys, finisher) = (Keys::default(), Finisher::default());
    let rig = Rig {
        clock: &clock,
        records: &records,
        seal: &seal,
        safety: &safety,
        keys: &keys,
        finisher: &finisher,
        flights: InFlight::default(),
        record_reads: RefCell::default(),
        obj: Obj {
            unit: Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), ""),
            clock: &clock,
            log: RefCell::new(vec![]),
            sync_attempts: RefCell::default(),
            sync_gate: RefCell::default(),
            fail: Cell::new(false),
            after_stamp_read: RefCell::new(None),
            stamp_read_gate: RefCell::default(),
            lose_answer_of: Cell::new(None),
            raise_after_each_read: Cell::new(false),
            answer_of: RefCell::new(None),
            answer_once: RefCell::new(None),
            safety: &safety,
        },
    };
    for change in [
        create(),
        Change::ClaimKeyVersion { version: 1 },
        Change::CommitKeyVersion {
            version: 1,
            kcv: [1; KEY_CHECK_LEN],
        },
        Change::Activate {
            external_ref: Some("ws_1".into()),
        },
    ] {
        rig.write(change, Actor::TenantCreation);
    }
    assert_eq!(rig.head_seq(), 4);
    rig.key_record(1, principal(1));
    rig.key_record(2, key(K, 2, SubjectStatus::Active));
    let token = BirthToken {
        name: own(),
        jurisdiction: String::new(),
        record_seq: 4,
        schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
        key_scheme: 2,
        kind: BirthKind::Birth,
    };
    let provision = UnitCall {
        name: own(),
        kind: CallKind::Worker,
        seqs: Some(Seqs {
            state_seq: 4,
            keys_seq: 0,
        }),
        authenticated: true,
        listed: true,
        op: UnitOp::Provision {
            token,
            sealed: b"sealed".to_vec(),
        },
    };
    let a = rig.obj.unit.handle(&provision, NOW);
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    f(&rig)
}

/// The rig with the unit synced and renewed.
fn with_fresh<R>(f: impl FnOnce(&Rig<'_>) -> R) -> R {
    with_rig(|rig| {
        let c = rig.client();
        assert!(matches!(synced(&c, rig.unit_seqs()), Synced::Synced { .. }));
        let (r, pages) = renewed(&c, rig.unit_seqs());
        assert!(matches!(r, Renewal::Renewed { .. }), "{r:?}");
        assert!(pages.is_empty(), "{pages:?}");
        f(rig)
    })
}

/// A renewed unit just past its lease, with the setup calls cleared.
fn with_expired<R>(f: impl FnOnce(&Rig<'_>) -> R) -> R {
    with_fresh(|rig| {
        rig.clock.advance_ms(T + 1);
        rig.obj.log.borrow_mut().clear();
        f(rig)
    })
}

/// A request-path call that did not fail, and its pages.
fn called(
    c: &Client<'_, '_>,
    call: UnitCall,
) -> (velmora_bridge::unit_lease::client::Answered, Vec<Page>) {
    let (a, pages) = block_on(c.call(call));
    (a.unwrap(), pages)
}

/// A sync that neither failed nor paged.
fn synced(c: &Client<'_, '_>, seqs: Seqs) -> Synced {
    let (result, pages) = block_on(c.sync(seqs));
    assert!(pages.is_empty(), "{pages:?}");
    result.unwrap()
}

/// A renewal that did not fail: what it came to, and its pages.
fn renewed(c: &Client<'_, '_>, seqs: Seqs) -> (Renewal, Vec<Page>) {
    let (r, pages) = block_on(c.renew(seqs));
    (r.unwrap(), pages)
}

fn revoked_count(rig: &Rig<'_>) -> u64 {
    velmora_bridge::unit_lease::store::revoked(rig.obj.unit.sql())
        .unwrap()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// sync
// ---------------------------------------------------------------------------

/// A new unit takes both chain heads: the key records first, then the
/// tenant record, in one `sync` of the client.
#[test]
fn sync_brings_a_new_unit_to_both_chain_heads() {
    with_rig(|rig| {
        let before = rig.unit_seqs();
        assert_eq!(before.keys_seq, 0);
        let s = synced(&rig.client(), before);
        let want = Seqs {
            state_seq: 4,
            keys_seq: 2,
        };
        assert_eq!(s, Synced::Synced { seqs: want });
        assert_eq!(rig.unit_seqs(), want);
        let head = rig.obj.unit.head().unwrap();
        assert_eq!(head.tenant_state, TenantState::Active);
        assert_eq!(rig.calls(), ["held_keys", "apply_keys", "sync"]);
    });
}

/// A held tenant reaches the unit as `suspended` with its mode.
#[test]
fn sync_copies_the_heads_state_and_mode() {
    with_fresh(|rig| {
        rig.write(
            Change::SetOperatorHold {
                hold: Some(OperatorHoldRequest {
                    mode: HoldMode::ReadOnly,
                    reason: OperatorReason::Security,
                    preserve: None,
                }),
            },
            Actor::Operator,
        );
        let s = synced(&rig.client(), rig.unit_seqs());
        assert!(matches!(s, Synced::Synced { seqs } if seqs.state_seq == 5));
        let head = rig.obj.unit.head().unwrap();
        assert_eq!(head.tenant_state, TenantState::Suspended);
        assert_eq!(
            head.tenant_mode,
            Some(velmora_bridge::unit::call::HoldMode::ReadOnly)
        );
    });
}

/// A unit the head does not list is never called.
#[test]
fn a_unit_the_head_does_not_list_is_not_synced() {
    with_rig(|rig| {
        let c = rig.client_of(UnitName::new(tenant(), 1));
        let s = synced(
            &c,
            Seqs {
                state_seq: 0,
                keys_seq: 0,
            },
        );
        assert_eq!(s, Synced::NotListed);
        assert!(rig.calls().is_empty());
    });
}

/// The head clears this unit's `restoring` entry: only the restore tool's
/// `sync` carries the lift, so the client changes nothing (AM-45).
#[test]
fn a_head_that_clears_the_entry_leaves_the_lift_to_the_tool() {
    with_fresh(|rig| {
        rig.write(Change::SetRestoring { unit: 0 }, Actor::Operator);
        let s = synced(&rig.client(), rig.unit_seqs());
        assert!(matches!(s, Synced::Synced { .. }), "{s:?}");
        let since = rig.obj.unit.head().unwrap().restoring_since;
        assert_eq!(since, Some(5));
        rig.write(
            Change::LiftRestoring {
                unit: 0,
                since_seq: 5,
            },
            Actor::RestoreTool,
        );
        let s = synced(&rig.client(), rig.unit_seqs());
        assert!(matches!(s, Synced::LiftPending { .. }), "{s:?}");
        let head = rig.obj.unit.head().unwrap();
        assert_eq!(head.restoring_since, Some(5));
        assert_eq!(head.seqs.state_seq, 5, "nothing changed");
    });
}

/// A key chain that ends below what the unit holds is damage: no write
/// (only the read of the unit's closed subjects).
#[test]
fn a_key_chain_below_the_unit_is_an_error() {
    with_fresh(|rig| {
        rig.keys.0.borrow_mut().clear();
        rig.obj.log.borrow_mut().clear();
        assert!(block_on(rig.client().sync(rig.unit_seqs())).0.is_err());
        assert_eq!(rig.calls(), ["held_keys"]);
    });
}

fn write_bucket_creation(rig: &Rig<'_>, grant_seq: u64, name: &str) -> (BucketId, Vec<u8>) {
    let bucket = velmora_bridge::records::bucket_id(dir_tenant().managed().unwrap(), grant_seq);
    let mut wrap = vec![0xa5; velmora_bridge::crypto::WRAPPED_KEY_LEN];
    wrap[0] = velmora_bridge::crypto::scheme2::WRAP_VERSION_2;
    rig.write(
        Change::CreateBucket {
            bucket: bucket.as_str().into(),
            unit: 0,
            creator: P.into(),
            grant_seq,
            name: name.into(),
            bdk_wrapped: wrap.clone(),
            tk_version: 1,
        },
        Actor::Customer,
    );
    (bucket, wrap)
}

/// Syncing a bucket creation reads the tenant record and makes the placed row.
#[test]
fn sync_creates_the_bucket_from_the_tenant_record() {
    with_fresh(|rig| {
        let before = rig.unit_seqs();
        rig.clock.advance_ms(123);
        let written_at = rig.clock.now();
        let (bucket, wrap) = write_bucket_creation(rig, 1, "client-bucket");
        rig.clock.advance_ms(456);
        let want = Seqs {
            state_seq: before.state_seq + 1,
            ..before
        };
        assert_eq!(synced(&rig.client(), before), Synced::Synced { seqs: want });
        assert_eq!(rig.unit_seqs(), want);
        assert_eq!(
            *rig.record_reads.borrow(),
            [before.state_seq, want.state_seq]
        );

        let row = rig.obj.unit.sql().with_conn(|conn| {
            conn.query_row(
                "SELECT name, owner, bdk_wrapped, kek_version, created_at, grant_seq \
                 FROM buckets JOIN unit_bucket_grant ON bucket_id = id WHERE id = ?1",
                [bucket.as_str()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                },
            )
            .unwrap()
        });
        assert_eq!(
            row,
            ("client-bucket".into(), P.into(), wrap, 1, written_at.0, 1)
        );
    });
}

/// A restore entry gets its own sync step, so the preceding `SetUnits`
/// drops both empty buckets before the unit starts preserving rows.
#[test]
fn sync_drops_unplaced_buckets_before_entering_restore() {
    with_fresh(|rig| {
        let (x, _) = write_bucket_creation(rig, 1, "client-bucket-x");
        let (y, _) = write_bucket_creation(rig, 2, "client-bucket-y");
        let client = rig.client();
        synced(&client, rig.unit_seqs());
        let before = rig.unit_seqs();
        let bucket_rows = || {
            rig.obj.unit.sql().with_conn(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM buckets WHERE id IN (?1, ?2)",
                    [x.as_str(), y.as_str()],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
            })
        };
        assert_eq!(bucket_rows(), 2);
        rig.obj.sync_attempts.borrow_mut().clear();

        rig.write(
            Change::SetUnits {
                base_seq: before.state_seq,
                units: vec![0],
                placements: vec![],
            },
            Actor::Operator,
        );
        rig.write(Change::SetRestoring { unit: 0 }, Actor::Operator);
        let want = Seqs {
            state_seq: before.state_seq + 2,
            ..before
        };
        assert_eq!(synced(&client, before), Synced::Synced { seqs: want });
        let attempts = rig.obj.sync_attempts.borrow();
        let [removal, restore] = attempts.as_slice() else {
            panic!("expected two sync dispatches, got {}", attempts.len());
        };
        assert_eq!(
            (removal.from_seq, removal.to_seq),
            (before.state_seq, before.state_seq + 1)
        );
        assert_eq!(
            (restore.from_seq, restore.to_seq),
            (before.state_seq + 1, want.state_seq)
        );
        assert!(
            matches!(&removal.answer, UnitAnswer::Ok { body, .. } if body["buckets"]["dropped"] == 2),
            "{:?}",
            removal.answer
        );
        assert!(
            matches!(restore.answer, UnitAnswer::Ok { .. }),
            "{:?}",
            restore.answer
        );
        let head = rig.obj.unit.head().unwrap();
        assert_eq!(head.seqs, want);
        assert_eq!(head.restoring_since, Some(want.state_seq));
        assert_eq!(bucket_rows(), 0);
    });
}

/// A racing sync from the old base reads the unit's numbers again and leaves exactly one bucket row.
#[test]
fn a_racing_sync_reloads_the_base_and_does_not_reapply_the_bucket() {
    with_fresh(|rig| {
        let before = rig.unit_seqs();
        let (bucket, _) = write_bucket_creation(rig, 1, "client-bucket");
        let want = Seqs {
            state_seq: before.state_seq + 1,
            ..before
        };
        let first = rig.client();
        let second = UnitClient {
            flights: InFlight::default(),
            ..rig.client()
        };
        rig.obj.sync_attempts.borrow_mut().clear();
        rig.obj.log.borrow_mut().clear();

        let (release, held) = oneshot::channel();
        *rig.obj.sync_gate.borrow_mut() = Some(held);
        let mut late = std::pin::pin!(second.sync(before));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(late.as_mut().poll(&mut cx).is_pending());
        assert!(rig.obj.sync_gate.borrow().is_none());
        assert!(rig.obj.sync_attempts.borrow().is_empty());

        let (result, pages) = block_on(first.sync(before));
        assert_eq!(result.unwrap(), Synced::Synced { seqs: want });
        assert!(pages.is_empty(), "{pages:?}");
        assert_eq!(rig.unit_seqs(), want);
        release.send(()).unwrap();
        let (result, pages) = block_on(late);
        assert_eq!(result.unwrap(), Synced::Synced { seqs: want });
        assert!(pages.is_empty(), "{pages:?}");
        assert_eq!(rig.unit_seqs(), want);
        rig.assert_call_auth(&[
            ("held_keys", true),
            ("sync", true), // second stops at the gate
            ("held_keys", true),
            ("sync", true),  // first reaches the unit
            ("ping", false), // second reads the unit's new base
            ("held_keys", true),
            ("sync", true),
        ]);

        let attempts = rig.obj.sync_attempts.borrow();
        let [winner, stale, retry] = attempts.as_slice() else {
            panic!("expected three sync dispatches, got {}", attempts.len());
        };
        for attempt in [winner, stale] {
            assert_eq!(
                (attempt.from_seq, attempt.to_seq),
                (before.state_seq, want.state_seq)
            );
        }
        assert!(
            matches!(&winner.answer, UnitAnswer::Ok { body, .. } if body["buckets"]["created"] == 1)
        );
        assert_eq!(
            stale.answer,
            UnitAnswer::Refused {
                reason: Refused::StaleSync,
                alarm: false
            }
        );
        assert_eq!(
            (retry.from_seq, retry.to_seq),
            (want.state_seq, want.state_seq)
        );
        assert!(
            matches!(&retry.answer, UnitAnswer::Ok { body, .. } if body["buckets"]["created"] == 0)
        );
        rig.obj.unit.sql().with_conn(|conn| {
            for sql in [
                "SELECT id FROM buckets",
                "SELECT bucket_id FROM unit_bucket_grant",
            ] {
                let mut stmt = conn.prepare(sql).unwrap();
                let ids: Vec<String> = stmt
                    .query_map([], |row| row.get(0))
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap();
                assert_eq!(ids, [bucket.as_str()]);
            }
        });
    });
}

/// A backlog beyond 32 records is applied in multiple, bounded sync steps.
#[test]
fn sync_splits_a_long_tenant_backlog_into_steps() {
    with_fresh(|rig| {
        let before = rig.unit_seqs();
        let middle = before.state_seq + 32;
        let want = Seqs {
            state_seq: middle + 1,
            ..before
        };
        for _ in 0..33 {
            rig.write(limits(rig), Actor::Operator);
        }
        rig.obj.log.borrow_mut().clear();
        rig.obj.sync_attempts.borrow_mut().clear();
        assert_eq!(synced(&rig.client(), before), Synced::Synced { seqs: want });
        assert_eq!(rig.unit_seqs(), want);
        assert_eq!(rig.calls().iter().filter(|op| *op == "sync").count(), 2);
        let targets: Vec<_> = rig
            .obj
            .sync_attempts
            .borrow()
            .iter()
            .map(|a| a.to_seq)
            .collect();
        assert_eq!(targets, [middle, want.state_seq]);
        let expected_reads: Vec<_> = (before.state_seq..=middle)
            .chain(middle..=want.state_seq)
            .collect();
        assert_eq!(*rig.record_reads.borrow(), expected_reads);
    });
}

/// An open bucket row not present in the chain refuses both sync attempts.
#[test]
fn sync_retries_a_placement_mismatch_once_then_pages() {
    use velmora_bridge::unit::buckets::BucketRefusal;

    with_fresh(|rig| {
        let before = rig.unit_seqs();
        rig.obj.unit.sql().with_conn(|conn| {
            conn.execute(
                "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
                 VALUES (?1, 'orphan', ?2, x'02', 1, 1)",
                [B1, P],
            )
            .unwrap();
        });
        rig.write(limits(rig), Actor::Operator);
        rig.obj.log.borrow_mut().clear();
        rig.obj.sync_attempts.borrow_mut().clear();
        let (result, pages) = block_on(rig.client().sync(before));
        assert!(result.is_err(), "{result:?}");
        assert_eq!(pages, [Page::PlacementsOff]);
        assert_eq!(rig.unit_seqs(), before);
        assert_eq!(rig.calls().iter().filter(|op| *op == "sync").count(), 2);
        let next = before.state_seq + 1;
        let attempts = rig.obj.sync_attempts.borrow();
        assert_eq!(attempts.len(), 2);
        for attempt in attempts.iter() {
            assert_eq!(attempt.to_seq, next);
            let answer = &attempt.answer;
            assert!(
                matches!(
                    answer,
                    UnitAnswer::Refused {
                        reason: Refused::Buckets(BucketRefusal::PlacementsOff),
                        alarm: true,
                    }
                ),
                "{answer:?}"
            );
        }
        assert_eq!(
            *rig.record_reads.borrow(),
            [before.state_seq, next, before.state_seq, next]
        );
    });
}

// ---------------------------------------------------------------------------
// renew
// ---------------------------------------------------------------------------

/// The unit's own answers give the proof its numbers, counter and revoked
/// count; then `renew` opens the unit for T: one stamp read and one renew.
#[test]
fn a_renewal_reads_the_unit_proves_and_opens_it() {
    with_rig(|rig| {
        synced(&rig.client(), rig.unit_seqs());
        assert!(matches!(rig.ping(), UnitAnswer::RenewNeeded { .. }));
        rig.obj.log.borrow_mut().clear();
        let (r, pages) = renewed(&rig.client(), rig.unit_seqs());
        assert_eq!(
            r,
            Renewal::Renewed {
                seqs: rig.unit_seqs(),
                lease_left_ms: T as u64,
            }
        );
        assert!(pages.is_empty());
        assert_eq!(rig.calls(), ["job:stamp", "renew"]);
        assert!(matches!(rig.ping(), UnitAnswer::Ok { .. }));
        // The stamp read is a job call with `listed = false` (AM-50).
        let log = rig.obj.log.borrow();
        assert_eq!((log[0].0, log[0].1), (CallKind::Job, false));
        assert_eq!(log[1].0, CallKind::Worker);
    });
}

/// A newer tenant record found by the proof: sync, then prove again.
#[test]
fn a_renewal_that_finds_a_newer_record_syncs_first() {
    with_fresh(|rig| {
        let old = rig.unit_seqs();
        rig.write(limits(rig), Actor::Operator);
        rig.clock.advance_ms(T + 1);
        let (r, _) = renewed(&rig.client(), old);
        let Renewal::Renewed { seqs, .. } = r else {
            panic!("{r:?}")
        };
        assert_eq!(seqs.state_seq, 5);
        assert_eq!(rig.unit_seqs().state_seq, 5);
    });
}

/// A newer key record: applied (through `sync`), then renewed.
#[test]
fn a_renewal_that_finds_a_newer_key_record_applies_it_first() {
    with_fresh(|rig| {
        rig.key_record(3, key(GONE, 3, SubjectStatus::Active));
        rig.clock.advance_ms(T + 1);
        let (r, _) = renewed(&rig.client(), rig.unit_seqs());
        assert!(
            matches!(r, Renewal::Renewed { seqs, .. } if seqs.keys_seq == 3),
            "{r:?}"
        );
    });
}

/// A revocation under `m/rk/<t>/` the unit does not hold: applied with
/// the renewal, and the finisher is told once (SEC-6).
#[test]
fn a_listed_revocation_is_applied_and_the_finisher_told() {
    with_fresh(|rig| {
        put(
            rig.safety,
            &format!("{}{K}", RecordNames.revocation_dir(tid())),
        );
        rig.clock.advance_ms(T + 1);
        let (r, pages) = renewed(&rig.client(), rig.unit_seqs());
        assert!(matches!(r, Renewal::Renewed { .. }), "{r:?}");
        assert!(pages.is_empty(), "{pages:?}");
        assert_eq!(revoked_count(rig), 1);
        assert_eq!(rig.finisher.0.get(), 1);
        // The next renewal lists the same count: nothing to apply.
        rig.clock.advance_ms(T + 1);
        renewed(&rig.client(), rig.unit_seqs());
        assert_eq!(rig.finisher.0.get(), 1);
    });
}

/// A name under the revocations that is no access key id: skipped, and
/// paged.
#[test]
fn a_stray_revocation_name_pages_and_renews() {
    with_fresh(|rig| {
        let stray = format!("{}not.an-id", RecordNames.revocation_dir(tid()));
        put(rig.safety, &stray);
        rig.clock.advance_ms(T + 1);
        let (r, pages) = renewed(&rig.client(), rig.unit_seqs());
        assert!(matches!(r, Renewal::Renewed { .. }), "{r:?}");
        assert_eq!(
            pages,
            [Page::StrayRevocationNames {
                first: vec![stray],
                total: 1
            }]
        );
    });
}

/// The unit holds a revocation the bucket does not list: no renewal, and
/// a page.
#[test]
fn more_revocations_held_than_listed_is_refused_and_pages() {
    with_fresh(|rig| {
        rig.key_record(3, key(K, 3, SubjectStatus::Revoked));
        synced(&rig.client(), rig.unit_seqs());
        assert_eq!(revoked_count(rig), 1);
        rig.clock.advance_ms(T + 1);
        let (r, pages) = renewed(&rig.client(), rig.unit_seqs());
        assert_eq!(r, Renewal::Refused);
        assert_eq!(pages, [Page::RevocationsShort { listed: 0, held: 1 }]);
        assert!(matches!(rig.ping(), UnitAnswer::RenewNeeded { .. }));
    });
}

/// A stamp object after the unit's counter, with the counter unchanged:
/// the unit is rolled back. The client records it through the unit,
/// which closes; a later renewal answers closed without a page.
#[test]
fn a_stamp_ahead_of_the_counter_closes_the_unit_as_rolled_back() {
    with_fresh(|rig| {
        let id = rig.client().stamp_id().unwrap();
        put(rig.safety, &stamp_key(id.as_str(), 1));
        rig.clock.advance_ms(T + 1);
        let (r, pages) = renewed(&rig.client(), rig.unit_seqs());
        assert_eq!(r, Renewal::Closed { rolled_back: true });
        assert_eq!(pages, [Page::RolledBack]);
        // Seen again: closed, and paged again (the page that recorded it
        // may have been lost).
        let (r, pages) = renewed(&rig.client(), rig.unit_seqs());
        assert_eq!(r, Renewal::Closed { rolled_back: true });
        assert_eq!(pages, [Page::RolledBack]);
        assert!(matches!(rig.ping(), UnitAnswer::RenewNeeded { .. }));
    });
}

/// A raise that lands between the stamp read and the proof's list moves
/// the counter: not a rollback; the client proves again and renews.
#[test]
fn a_raise_between_the_read_and_the_list_is_not_a_rollback() {
    with_fresh(|rig| {
        let id = rig.client().stamp_id().unwrap();
        let safety = rig.safety;
        let seqs = rig.unit_seqs();
        let id2 = id.as_str().to_string();
        *rig.obj.after_stamp_read.borrow_mut() = Some(Box::new(move |unit| {
            // The raise of another consumer: the counter, then the object.
            let c = UnitCall {
                name: own(),
                kind: CallKind::Job,
                seqs: Some(seqs),
                authenticated: true,
                listed: false,
                op: UnitOp::Job {
                    call: JobCall::stamp_advance {
                        from: None,
                        catalogue: id2.clone(),
                    },
                },
            };
            assert!(matches!(unit.handle(&c, NOW), UnitAnswer::Ok { .. }));
            put_inline(safety, &stamp_key(&id2, 1));
        }));
        let (r, pages) = renewed(&rig.client(), rig.unit_seqs());
        assert!(matches!(r, Renewal::Renewed { .. }), "{r:?}");
        assert!(pages.is_empty(), "{pages:?}");
    });
}

/// A closed unit (a `restoring` entry) takes no renewal.
#[test]
fn a_restoring_unit_is_not_renewed() {
    with_fresh(|rig| {
        rig.write(Change::SetRestoring { unit: 0 }, Actor::Operator);
        synced(&rig.client(), rig.unit_seqs());
        let (r, _) = renewed(&rig.client(), rig.unit_seqs());
        assert_eq!(r, Renewal::Closed { rolled_back: false });
    });
}

/// An unborn unit answers so, with no page and no write.
#[test]
fn an_unborn_unit_is_reported() {
    let clock = FixedClock::new(NOW);
    let (records, seal, safety) = (HookedRecords::new(), PlainSeal::new(), MemBlobStore::new());
    let (keys, finisher) = (Keys::default(), Finisher::default());
    let rig = Rig {
        clock: &clock,
        records: &records,
        seal: &seal,
        safety: &safety,
        keys: &keys,
        finisher: &finisher,
        flights: InFlight::default(),
        record_reads: RefCell::default(),
        obj: Obj {
            unit: Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), ""),
            clock: &clock,
            log: RefCell::new(vec![]),
            sync_attempts: RefCell::default(),
            sync_gate: RefCell::default(),
            fail: Cell::new(false),
            after_stamp_read: RefCell::new(None),
            stamp_read_gate: RefCell::default(),
            lose_answer_of: Cell::new(None),
            raise_after_each_read: Cell::new(false),
            answer_of: RefCell::new(None),
            answer_once: RefCell::new(None),
            safety: &safety,
        },
    };
    let seqs = Seqs {
        state_seq: 4,
        keys_seq: 0,
    };
    let (r, pages) = renewed(&rig.client(), seqs);
    assert_eq!(r, Renewal::Unborn);
    assert!(pages.is_empty());
    let job = block_on(rig.client().run_job(UnitJob::Renew { at: NOW }, seqs));
    assert_eq!(job.delivery, Delivery::Unborn);
}

/// Numbers older than the unit's (a message sent before a sync): the
/// unit's own are taken, with no error.
#[test]
fn a_renewal_from_old_numbers_takes_the_units() {
    with_fresh(|rig| {
        rig.write(limits(rig), Actor::Operator);
        synced(&rig.client(), rig.unit_seqs());
        rig.clock.advance_ms(T + 1);
        let old = Seqs {
            state_seq: 4,
            keys_seq: 2,
        };
        let (r, _) = renewed(&rig.client(), old);
        assert!(
            matches!(r, Renewal::Renewed { seqs, .. } if seqs.state_seq == 5),
            "{r:?}"
        );
    });
}

/// AM-71: `sync` reads the directory's `acked` once, and the unit's
/// closed subjects before each feed read, and hands both to the feed.
#[test]
fn a_sync_hands_the_feed_the_directorys_ack_and_the_units_closed_subjects() {
    with_fresh(|rig| {
        rig.keys.1.set(7);
        rig.keys.2.borrow_mut().clear();
        let mut held = key(K, 3, SubjectStatus::Active);
        held.held = true;
        rig.key_record(3, held);
        synced(&rig.client(), rig.unit_seqs());
        let calls = rig.keys.2.borrow().clone();
        assert!(!calls.is_empty());
        assert!(calls.iter().all(|(_, acked, _)| *acked == 7), "{calls:?}");
        assert!(calls[0].2.is_empty(), "nothing held before: {calls:?}");
        // Now the unit holds K closed: the next sync names it.
        rig.keys.2.borrow_mut().clear();
        rig.key_record(4, key(K, 4, SubjectStatus::Active));
        synced(&rig.client(), rig.unit_seqs());
        let calls = rig.keys.2.borrow().clone();
        assert_eq!(calls[0].2, vec![K.to_string()], "{calls:?}");
    });
}

/// A key backlog longer than the unit takes in one apply goes in pages,
/// each from the unit's own `keys_seq` (review finding 1).
#[test]
fn a_long_key_backlog_is_applied_in_pages() {
    with_rig(|rig| {
        // 250 records: the principal, the key, and 248 more keys.
        for seq in 3..=250 {
            rig.key_record(
                seq,
                key(&format!("AKCLIENT{seq:012}"), seq, SubjectStatus::Active),
            );
        }
        let s = synced(&rig.client(), rig.unit_seqs());
        assert!(
            matches!(s, Synced::Synced { seqs } if seqs.keys_seq == 250),
            "{s:?}"
        );
        let applies = rig.calls().iter().filter(|c| *c == "apply_keys").count();
        assert_eq!(applies, 3, "100 + 100 + 50");
    });
}

/// Rule 11: unsigned calls on an expired lease renew only through the
/// isolate's spacing: none while one runs, and after a failed attempt a
/// backoff from 60 s doubling up to T; signed calls renew for themselves
/// (review findings 2 and M1).
#[test]
fn unsigned_calls_space_failed_renewals_with_a_backoff() {
    with_fresh(|rig| {
        // A renewal that is refused every time: a revocation the bucket
        // does not list.
        rig.key_record(3, key(K, 3, SubjectStatus::Revoked));
        synced(&rig.client(), rig.unit_seqs());
        rig.clock.advance_ms(T + 1);
        let unsigned = || {
            // An unsigned call (rule 11). Not `key_row`: with an expired
            // lease the unit answers it, marked (AM-63).
            let mut c = request(rig.unit_seqs(), UnitOp::Ping {});
            c.authenticated = false;
            called(&rig.client(), c)
        };
        let reads = || rig.calls().iter().filter(|c| *c == "job:stamp").count();
        let before = reads();
        let pages: usize = (0..5).map(|_| unsigned().1.len()).sum();
        assert_eq!(reads() - before, 1, "one attempt");
        assert_eq!(pages, 1, "one page");
        // 60 s on: one more; then the wait doubles.
        rig.clock.advance_ms(60_000);
        unsigned();
        unsigned();
        assert_eq!(reads() - before, 2);
        rig.clock.advance_ms(60_000);
        unsigned();
        assert_eq!(reads() - before, 2, "120 s now");
        rig.clock.advance_ms(60_000);
        unsigned();
        assert_eq!(reads() - before, 3);
        // A signed call waits at most 1 s after a failure (review LOW 1):
        // two at once make one attempt, one a second later another.
        let signed = || called(&rig.client(), request(rig.unit_seqs(), UnitOp::Ping {}));
        rig.clock.advance_ms(1_000);
        signed();
        signed();
        assert_eq!(reads() - before, 4);
        rig.clock.advance_ms(1_000);
        signed();
        assert_eq!(reads() - before, 5);
    });
}

/// A transient failure holds unsigned renewals back for the first backoff
/// only, not for T; a success clears it (review M1).
#[test]
fn a_transient_failure_delays_unsigned_renewals_by_the_first_backoff_only() {
    with_fresh(|rig| {
        rig.clock.advance_ms(T + 1);
        let unsigned = || {
            // An unsigned call (rule 11). Not `key_row`: with an expired
            // lease the unit answers it, marked (AM-63).
            let mut c = request(rig.unit_seqs(), UnitOp::Ping {});
            c.authenticated = false;
            block_on(rig.client().call(c))
        };
        rig.obj.lose_answer_of.set(Some("job:stamp"));
        let (a, _) = unsigned();
        assert!(a.is_err(), "the attempt failed");
        let (a, _) = unsigned();
        assert!(matches!(
            a.unwrap().reply.answer,
            UnitAnswer::RenewNeeded { .. }
        ));
        rig.clock.advance_ms(60_000);
        let (a, p) = unsigned();
        let a = a.unwrap();
        // Renewed, and the call ran again (an unsigned ping is then
        // refused as unauthenticated: past the lease check).
        let renewed = |a: &Answered| {
            matches!(a.renewal, Some(Renewal::Renewed { .. }))
                && !matches!(a.reply.answer, UnitAnswer::RenewNeeded { .. })
        };
        assert!(
            renewed(&a),
            "recovered after 60 s: {a:?} {p:?} {:?}",
            rig.calls()
        );
        // Cleared: a later expiry is renewed at once.
        rig.clock.advance_ms(T + 1);
        let (a, _) = unsigned();
        assert!(renewed(&a.unwrap()));
    });
}

/// The background renewal takes the same spacing (review M2).
#[test]
fn background_renewals_are_spaced_too() {
    with_fresh(|rig| {
        rig.key_record(3, key(K, 3, SubjectStatus::Revoked));
        synced(&rig.client(), rig.unit_seqs());
        let c = rig.client();
        let first = block_on(c.renew_in_background(rig.unit_seqs()));
        assert!(
            matches!(first, Some((Ok(Renewal::Refused), _))),
            "{first:?}"
        );
        for _ in 0..4 {
            assert!(block_on(c.renew_in_background(rig.unit_seqs())).is_none());
        }
        rig.clock.advance_ms(60_000);
        assert!(block_on(c.renew_in_background(rig.unit_seqs())).is_some());
    });
}

/// The pages of a renewal a call made come back with its error (review
/// L1).
#[test]
fn a_calls_error_keeps_the_renewals_pages() {
    with_fresh(|rig| {
        put(
            rig.safety,
            &format!("{}{K}", RecordNames.revocation_dir(tid())),
        );
        rig.clock.advance_ms(T + 1);
        rig.finisher.1.set(true);
        rig.obj.lose_answer_of.set(Some("renew"));
        let (a, pages) = block_on(rig.client().call(request(rig.unit_seqs(), UnitOp::Ping {})));
        assert!(a.is_err());
        assert_eq!(pages, [Page::FinisherNotTold]);
    });
}

/// The finisher is told before the `renew` call: an answer lost after
/// the unit kept the listed ids leaves nothing for a later proof to tell
/// (review finding 3). The pages come back with the error (finding 6).
#[test]
fn the_finisher_is_told_before_the_renew_call() {
    with_fresh(|rig| {
        put(
            rig.safety,
            &format!("{}{K}", RecordNames.revocation_dir(tid())),
        );
        rig.clock.advance_ms(T + 1);
        rig.finisher.1.set(true);
        rig.obj.lose_answer_of.set(Some("renew"));
        let (r, pages) = block_on(rig.client().renew(rig.unit_seqs()));
        assert!(r.is_err());
        assert_eq!(rig.finisher.0.get(), 1, "told before the call");
        assert_eq!(pages, [Page::FinisherNotTold], "kept with the error");
        // The unit kept the id: the next proof has equal counts.
        assert_eq!(revoked_count(rig), 1);
        rig.finisher.1.set(false);
        let (r, _) = renewed(&rig.client(), rig.unit_seqs());
        assert!(matches!(r, Renewal::Renewed { .. }));
    });
}

/// Another writer raises the stamp after every read of it: the proof
/// holds the newest stamp, which the unit holds by then, and renews in
/// one round (review finding 4).
#[test]
fn a_unit_whose_stamp_moves_under_every_read_still_renews() {
    with_fresh(|rig| {
        rig.clock.advance_ms(T + 1);
        rig.obj.raise_after_each_read.set(true);
        let (r, pages) = renewed(&rig.client(), rig.unit_seqs());
        assert!(matches!(r, Renewal::Renewed { .. }), "{r:?}");
        assert!(pages.is_empty(), "{pages:?}");
        let renews = rig.calls().iter().filter(|c| *c == "renew").count();
        assert_eq!(renews, 2, "the fixture's and this one");
    });
}

/// The stray-name page carries the first few names and the count
/// (review finding 7).
#[test]
fn a_stray_page_is_bounded() {
    with_fresh(|rig| {
        let dir = RecordNames.revocation_dir(tid());
        for n in 0..15 {
            put(rig.safety, &format!("{dir}stray.{n:02}"));
        }
        rig.clock.advance_ms(T + 1);
        let (_, pages) = renewed(&rig.client(), rig.unit_seqs());
        let [Page::StrayRevocationNames { first, total }] = pages.as_slice() else {
            panic!("{pages:?}");
        };
        assert_eq!((first.len(), *total), (10, 15));
    });
}

// ---------------------------------------------------------------------------
// The jobs
// ---------------------------------------------------------------------------

#[test]
fn a_renew_job_renews_and_is_acknowledged() {
    with_rig(|rig| {
        synced(&rig.client(), rig.unit_seqs());
        let job = block_on(
            rig.client()
                .run_job(UnitJob::Renew { at: NOW }, rig.unit_seqs()),
        );
        assert_eq!((job.delivery, job.code), (Delivery::Ack, "renewed"));
        assert!(matches!(rig.ping(), UnitAnswer::Ok { .. }));
    });
}

/// A failed call hands the message back (the queue's retry delay).
#[test]
fn a_renew_job_whose_call_fails_is_handed_back() {
    with_rig(|rig| {
        rig.obj.fail.set(true);
        let job = block_on(
            rig.client()
                .run_job(UnitJob::Renew { at: NOW }, rig.unit_seqs()),
        );
        assert_eq!(
            (job.delivery, job.code),
            (Delivery::HandBack, "renew_failed")
        );
    });
}

/// Missing bucket secrets in a placed creation are damage, so a queued
/// renewal that encounters them dead-letters and pages instead of retrying.
#[test]
fn a_renew_job_dead_letters_a_bucket_creation_missing_its_secrets() {
    use velmora_bridge::unit_lease::placements::ERR_BUCKET_SECRETS;

    with_expired(|rig| {
        let before = rig.unit_seqs();
        let client = rig.client();
        write_bucket_creation(rig, 1, "client-bucket");
        let seq = rig.head_seq();
        let ReadRecord { door, private } = block_on(client.heads.record(&tenant(), seq))
            .unwrap()
            .unwrap();
        let mut private = private.unwrap();
        private.bucket_created.take().unwrap();
        // Preserve the valid public record and seal just this private part
        // without its synthetic bucket material.
        let name = record_key(&dir_tenant(), seq);
        let sealed = rig
            .seal
            .seal(
                &name,
                &dir_tenant(),
                door.tk_version,
                &serde_json::to_vec(&door).unwrap(),
                &serde_json::to_vec(&private).unwrap(),
            )
            .unwrap();
        rig.records.plant(&name, sealed);

        let job = block_on(client.run_job(
            UnitJob::Renew {
                at: rig.clock.now(),
            },
            before,
        ));
        assert_eq!(
            (job.delivery, job.code),
            (Delivery::DeadLetter, "unit_refused")
        );
        let BridgeError::Invalid(reason) = ERR_BUCKET_SECRETS else {
            panic!("expected a placement damage reason");
        };
        assert_eq!(job.pages, [Page::UnitRefused(reason)]);
        assert_eq!(rig.unit_seqs(), before);
        assert!(!rig.calls().iter().any(|call| call == "sync"));
    });
}

/// A queued success clears the unsigned request's failure backoff, even
/// when a new renewal is needed before that backoff would have elapsed.
#[test]
fn a_successful_queued_renewal_clears_unsigned_backoff() {
    with_expired(|rig| {
        let client = rig.client();
        let unsigned = || {
            let mut call = request(rig.unit_seqs(), UnitOp::Ping {});
            call.authenticated = false;
            block_on(client.call(call))
        };
        rig.obj.lose_answer_of.set(Some("job:stamp"));
        let (failed, pages) = unsigned();
        assert!(matches!(failed, Err(BridgeError::Sql(ref text)) if text == "unit: answer lost"));
        assert!(pages.is_empty(), "{pages:?}");
        let (spaced, pages) = unsigned();
        let spaced = spaced.unwrap();
        assert!(spaced.renewal.is_none(), "{spaced:?}");
        assert!(matches!(
            spaced.reply.answer,
            UnitAnswer::RenewNeeded { .. }
        ));
        assert!(pages.is_empty(), "{pages:?}");

        let at = rig.clock.now();
        let job = block_on(client.run_job(UnitJob::Renew { at }, rig.unit_seqs()));
        assert_eq!((job.delivery, job.code), (Delivery::Ack, "renewed"));
        assert!(job.pages.is_empty(), "{job:?}");
        assert!(matches!(rig.ping(), UnitAnswer::Ok { .. }));

        // End the lease without advancing the clock past the old backoff.
        velmora_bridge::unit_lease::store::close(rig.obj.unit.sql()).unwrap();
        let (retried, pages) = unsigned();
        let retried = retried.unwrap();
        assert!(
            matches!(retried.renewal, Some(Renewal::Renewed { .. })),
            "{retried:?}"
        );
        assert!(pages.is_empty(), "{pages:?}");
        assert_eq!(rig.clock.now(), at);
        assert!(matches!(rig.ping(), UnitAnswer::Ok { .. }));
    });
}

/// A unit answer no rule expects (a failed unit, a refusal outside
/// AM-50's table) sends a unit job to the dead-letter queue with a page;
/// a store or call failure is handed back (review MEDIUM 4).
#[test]
fn an_unexpected_answer_dead_letters_the_job_and_pages() {
    use velmora_bridge::unit::Refused;
    with_fresh(|rig| {
        // A refusal no rule expects: dead letter and page.
        *rig.obj.answer_of.borrow_mut() = Some((
            "job:stamp",
            UnitAnswer::Refused {
                reason: Refused::Unauthenticated,
                alarm: false,
            },
        ));
        for job in [UnitJob::Renew { at: NOW }, UnitJob::StampRaise { at: NOW }] {
            let r = block_on(rig.client().run_job(job, rig.unit_seqs()));
            assert_eq!(
                (r.delivery, r.code),
                (Delivery::DeadLetter, "unit_refused"),
                "{job:?}"
            );
            assert!(
                matches!(r.pages.as_slice(), [Page::UnitRefused(_)]),
                "{r:?}"
            );
        }
        // A failure inside the unit (`Failed`) is a store failure: handed
        // back, no page (confirmation LOW 1).
        *rig.obj.answer_of.borrow_mut() = Some((
            "job:stamp",
            UnitAnswer::Failed {
                class: "sql".into(),
            },
        ));
        let r = block_on(
            rig.client()
                .run_job(UnitJob::Renew { at: NOW }, rig.unit_seqs()),
        );
        assert_eq!(
            (r.delivery, r.pages.len()),
            (Delivery::HandBack, 0),
            "{r:?}"
        );
        // Stale twice (the unit moved again): acknowledged, no page.
        *rig.obj.answer_of.borrow_mut() = Some((
            "job:stamp",
            UnitAnswer::Stale {
                seqs: rig.unit_seqs(),
            },
        ));
        let r = block_on(
            rig.client()
                .run_job(UnitJob::Renew { at: NOW }, rig.unit_seqs()),
        );
        assert_eq!(
            (r.delivery, r.code, r.pages.len()),
            (Delivery::Ack, "stale", 0),
            "{r:?}"
        );
        // A tenant that is shredding refuses jobs: acknowledged, no page.
        *rig.obj.answer_of.borrow_mut() = Some((
            "job:stamp",
            UnitAnswer::Refused {
                reason: Refused::AccountProblem,
                alarm: false,
            },
        ));
        let r = block_on(
            rig.client()
                .run_job(UnitJob::Renew { at: NOW }, rig.unit_seqs()),
        );
        assert_eq!(
            (r.delivery, r.code, r.pages.len()),
            (Delivery::Ack, "shredding", 0),
            "{r:?}"
        );
        let r = block_on(
            rig.client()
                .run_job(UnitJob::StampRaise { at: NOW }, rig.unit_seqs()),
        );
        assert_eq!((r.delivery, r.code), (Delivery::Ack, "shredding"), "{r:?}");
        // A call that fails is handed back, never dead-lettered.
        *rig.obj.answer_of.borrow_mut() = None;
        rig.obj.fail.set(true);
        let r = block_on(
            rig.client()
                .run_job(UnitJob::Renew { at: NOW }, rig.unit_seqs()),
        );
        assert_eq!(r.delivery, Delivery::HandBack);
    });
}

/// The arms the first review found untested (review M2): each one's
/// outcome.
#[test]
fn every_arm_of_the_jobs_and_the_sync_has_its_outcome() {
    use velmora_bridge::unit::Refused;
    with_fresh(|rig| {
        let c = rig.client();
        // A key apply answered `keys_behind`: read again, then applied.
        rig.key_record(3, key(GONE, 3, SubjectStatus::Active));
        *rig.obj.answer_once.borrow_mut() = Some((
            "apply_keys",
            UnitAnswer::KeysBehind {
                seqs: rig.unit_seqs(),
            },
        ));
        let s = synced(&c, rig.unit_seqs());
        assert!(
            matches!(s, Synced::Synced { seqs } if seqs.keys_seq == 3),
            "{s:?}"
        );
        // A `sync` refused as stale (another sync landed): the unit's
        // numbers are read again, then it syncs.
        rig.write(limits(rig), Actor::Operator);
        *rig.obj.answer_once.borrow_mut() = Some((
            "sync",
            UnitAnswer::Refused {
                reason: Refused::StaleSync,
                alarm: false,
            },
        ));
        let s = synced(&c, rig.unit_seqs());
        assert!(
            matches!(s, Synced::Synced { seqs } if seqs.state_seq == 5),
            "{s:?}"
        );
        // A raise job with numbers above the unit's: synced, then raised.
        let mut ahead = rig.unit_seqs();
        rig.write(limits(rig), Actor::Operator);
        ahead.state_seq += 1;
        let r = block_on(c.run_job(UnitJob::StampRaise { at: NOW }, ahead));
        assert_eq!((r.delivery, r.code), (Delivery::Ack, "raised"), "{r:?}");
        assert_eq!(rig.unit_seqs().state_seq, 6);
    });
    // A renew job whose renewal is refused for good: acknowledged, paged.
    with_fresh(|rig| {
        rig.key_record(3, key(K, 3, SubjectStatus::Revoked));
        synced(&rig.client(), rig.unit_seqs());
        rig.clock.advance_ms(T + 1);
        let r = block_on(
            rig.client()
                .run_job(UnitJob::Renew { at: NOW }, rig.unit_seqs()),
        );
        assert_eq!(
            (r.delivery, r.code),
            (Delivery::Ack, "renew_refused"),
            "{r:?}"
        );
        assert_eq!(r.pages, [Page::RevocationsShort { listed: 0, held: 1 }]);
    });
    // A raise on a unit whose rollback is recorded: acknowledged, paged.
    with_fresh(|rig| {
        let id = rig.client().stamp_id().unwrap();
        put(rig.safety, &stamp_key(id.as_str(), 1));
        rig.clock.advance_ms(T + 1);
        let (r, _) = renewed(&rig.client(), rig.unit_seqs());
        assert_eq!(r, Renewal::Closed { rolled_back: true });
        let r = block_on(
            rig.client()
                .run_job(UnitJob::StampRaise { at: NOW }, rig.unit_seqs()),
        );
        assert_eq!(
            (r.delivery, r.code),
            (Delivery::Ack, "rolled_back"),
            "{r:?}"
        );
        assert_eq!(r.pages, [Page::RolledBack]);
    });
    // A shredding tenant's unit on the request path: the call says why
    // it was not renewed (review M1).
    with_fresh(|rig| {
        rig.clock.advance_ms(T + 1);
        *rig.obj.answer_of.borrow_mut() = Some((
            "job:stamp",
            UnitAnswer::Refused {
                reason: Refused::AccountProblem,
                alarm: false,
            },
        ));
        let (a, pages) = called(&rig.client(), request(rig.unit_seqs(), UnitOp::Ping {}));
        assert!(matches!(a.reply.answer, UnitAnswer::RenewNeeded { .. }));
        assert_eq!(a.renewal, Some(Renewal::Shredding));
        assert!(pages.is_empty());
    });
}

/// A raise moves the unit's counter, then puts its object.
#[test]
fn a_stamp_raise_job_raises_once() {
    with_fresh(|rig| {
        let id = rig.client().stamp_id().unwrap();
        let job = block_on(
            rig.client()
                .run_job(UnitJob::StampRaise { at: NOW }, rig.unit_seqs()),
        );
        assert_eq!((job.delivery, job.code), (Delivery::Ack, "raised"));
        assert!(rig.safety.contains(&stamp_key(id.as_str(), 1)));
        let row = stamp_row(rig, id.as_str());
        assert_eq!(row.counter, Some(1));
    });
}

/// With the lease run out the unit refuses the advance: the client renews,
/// then raises.
#[test]
fn a_stamp_raise_with_an_expired_lease_renews_first() {
    with_fresh(|rig| {
        rig.clock.advance_ms(T + 1);
        let job = block_on(
            rig.client()
                .run_job(UnitJob::StampRaise { at: NOW }, rig.unit_seqs()),
        );
        assert_eq!(
            (job.delivery, job.code),
            (Delivery::Ack, "raised"),
            "{job:?}"
        );
        assert!(matches!(rig.ping(), UnitAnswer::Ok { .. }));
    });
}

/// A closed unit takes no raise: acknowledged.
#[test]
fn a_stamp_raise_on_a_closed_unit_is_acknowledged() {
    with_fresh(|rig| {
        rig.write(Change::SetRestoring { unit: 0 }, Actor::Operator);
        synced(&rig.client(), rig.unit_seqs());
        let job = block_on(
            rig.client()
                .run_job(UnitJob::StampRaise { at: NOW }, rig.unit_seqs()),
        );
        assert_eq!(
            (job.delivery, job.code),
            (Delivery::Ack, "closed"),
            "{job:?}"
        );
    });
}

// ---------------------------------------------------------------------------
// Rule 5 on the request path
// ---------------------------------------------------------------------------

/// `renew_needed`: renewed, then the call once more.
#[test]
fn a_request_on_an_expired_lease_renews_and_runs_once_more() {
    with_rig(|rig| {
        synced(&rig.client(), rig.unit_seqs());
        let a = called(&rig.client(), request(rig.unit_seqs(), UnitOp::Ping {})).0;
        assert!(matches!(a.reply.answer, UnitAnswer::Ok { .. }), "{a:?}");
        assert_eq!(a.refreshed, None);
        assert!(!a.renew_due);
        assert_eq!(
            rig.calls(),
            [
                "held_keys",
                "apply_keys",
                "sync",
                "ping",
                "job:stamp",
                "renew",
                "ping"
            ]
        );
    });
}

/// `sync_needed` (the caller knows a newer record): synced, then once
/// more.
#[test]
fn a_request_with_newer_numbers_syncs_and_runs_once_more() {
    with_fresh(|rig| {
        rig.write(limits(rig), Actor::Operator);
        let mut seqs = rig.unit_seqs();
        seqs.state_seq = 5;
        let a = called(&rig.client(), request(seqs, UnitOp::Ping {})).0;
        assert!(matches!(a.reply.answer, UnitAnswer::Ok { .. }), "{a:?}");
        assert_eq!(rig.unit_seqs().state_seq, 5);
    });
}

/// A lower number (the caller's head is old): the unit's numbers, once
/// more, and the caller is told to read its head again.
#[test]
fn a_request_with_older_numbers_takes_the_units_once() {
    with_fresh(|rig| {
        let now = rig.unit_seqs();
        let old = Seqs {
            state_seq: now.state_seq - 1,
            keys_seq: now.keys_seq,
        };
        let a = called(&rig.client(), request(old, UnitOp::Ping {})).0;
        assert!(matches!(a.reply.answer, UnitAnswer::Ok { .. }), "{a:?}");
        assert_eq!(a.refreshed, Some(now));
    });
}

/// Each fix runs at most once: a unit that stays expired is answered as
/// it is.
#[test]
fn a_request_renews_at_most_once() {
    with_rig(|rig| {
        synced(&rig.client(), rig.unit_seqs());
        // The bucket lists a revocation the unit cannot hold: refused.
        rig.key_record(3, key(K, 3, SubjectStatus::Revoked));
        synced(&rig.client(), rig.unit_seqs());
        let (a, pages) = called(&rig.client(), request(rig.unit_seqs(), UnitOp::Ping {}));
        assert!(matches!(a.reply.answer, UnitAnswer::RenewNeeded { .. }));
        assert_eq!(pages, [Page::RevocationsShort { listed: 0, held: 1 }]);
        let renews = rig.calls().iter().filter(|c| *c == "job:stamp").count();
        assert_eq!(renews, 1);
    });
}

/// Below half of T, the answer asks for a background renewal.
#[test]
fn a_background_renewal_is_due_below_half_of_t() {
    with_fresh(|rig| {
        let c = rig.client();
        let reply = |left| UnitReply {
            answer: UnitAnswer::Ok {
                seqs: rig.unit_seqs(),
                body: serde_json::Value::Null,
            },
            lease_left_ms: left,
            revoked: None,
        };
        let half = (T / 2) as u64;
        assert!(!c.renew_due(&reply(0)), "no lease: renew_needed decides");
        assert!(c.renew_due(&reply(1)));
        assert!(c.renew_due(&reply(half - 1)));
        assert!(!c.renew_due(&reply(half)));
        assert!(!c.renew_due(&reply(T as u64)));
        rig.clock.advance_ms(T / 2 + 1);
        let a = called(&c, request(rig.unit_seqs(), UnitOp::Ping {})).0;
        assert!(a.renew_due);
    });
}

/// One background renewal per unit and isolate.
#[test]
fn in_flight_holds_one_renewal_per_unit() {
    let flights = InFlight::default();
    let a = flights.begin(&own()).expect("first");
    assert!(flights.begin(&own()).is_none());
    let other = UnitName::new(tenant(), 1);
    assert!(flights.clone().begin(&other).is_some());
    drop(a);
    assert!(flights.begin(&own()).is_some());
}

enum Follower {
    /// Its first timer is pending; release the leader before that timer completes.
    WaitsForRenewal,
    /// Keep the leader gated until the follower completes after exactly this many yields.
    FinishesWhileGated(usize),
}

/// Polls the two callers separately so the stamp gate remains closed for the exact wait under test.
fn during_a_gated_renewal<L: Future, F: Future>(
    rig: &Rig<'_>,
    flights: &InFlight,
    renewal: L,
    other: F,
    follower: Follower,
) -> (L::Output, F::Output) {
    let (release, held) = oneshot::channel();
    *rig.obj.stamp_read_gate.borrow_mut() = Some(held);
    let mut renewal = std::pin::pin!(renewal);
    let mut other = std::pin::pin!(other);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(renewal.as_mut().poll(&mut cx).is_pending());
    assert!(rig.obj.stamp_read_gate.borrow().is_none());
    assert!(flights.running(&own()));

    let early = match follower {
        Follower::WaitsForRenewal => {
            assert!(other.as_mut().poll(&mut cx).is_pending());
            None
        }
        Follower::FinishesWhileGated(polls) => {
            for tick in 0..polls {
                assert!(
                    other.as_mut().poll(&mut cx).is_pending(),
                    "finished before timer {} completed",
                    tick + 1
                );
            }
            let Poll::Ready(result) = other.as_mut().poll(&mut cx) else {
                panic!("the follower did not finish while renewal was gated");
            };
            Some(result)
        }
    };
    assert!(flights.running(&own()));
    assert!(
        rig.calls().iter().all(|op| op != "renew"),
        "no renewal has reached the unit"
    );
    release.send(()).expect("the stamp read is still held");
    let Poll::Ready(renewal) = renewal.poll(&mut cx) else {
        panic!("the renewal did not finish after releasing the stamp reply");
    };
    assert!(!flights.running(&own()));
    let result = early.unwrap_or_else(|| {
        let Poll::Ready(result) = other.poll(&mut cx) else {
            panic!("the follower did not finish after its timer and the renewal");
        };
        result
    });
    assert_eq!(rig.calls().iter().filter(|op| **op == "renew").count(), 1);
    (renewal, result)
}

fn during_a_gated_request_renewal<F: Future>(
    rig: &Rig<'_>,
    leader: &Client<'_, '_>,
    other: F,
    follower: Follower,
) -> F::Output {
    let ((answer, pages), result) = during_a_gated_renewal(
        rig,
        &leader.flights,
        leader.call(request(rig.unit_seqs(), UnitOp::Ping {})),
        other,
        follower,
    );
    assert!(pages.is_empty(), "{pages:?}");
    assert!(matches!(
        answer.unwrap().reply.answer,
        UnitAnswer::Ok { .. }
    ));
    result
}

/// Records every sleep in milliseconds and yields once before each one completes.
fn fake_sleep() -> (InFlight, Rc<RefCell<Vec<u64>>>) {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let sleep: Sleep = Rc::new({
        let seen = Rc::clone(&seen);
        move |ms| {
            seen.borrow_mut().push(ms);
            let mut pending = true;
            Box::pin(poll_fn(move |cx| {
                if std::mem::take(&mut pending) {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            }))
        }
    });
    (InFlight::with_sleep(sleep), seen)
}

/// Two expired requests share one renewal; the waiting one retries once.
#[test]
fn an_expired_request_waits_for_the_shared_renewal() {
    with_expired(|rig| {
        let (flights, slept) = fake_sleep();
        let leader = UnitClient {
            flights: flights.clone(),
            ..rig.client()
        };
        let waiter = UnitClient {
            flights,
            ..rig.client()
        };
        let (answer, pages) = during_a_gated_request_renewal(
            rig,
            &leader,
            waiter.call(request(rig.unit_seqs(), UnitOp::Ping {})),
            Follower::WaitsForRenewal,
        );
        let answer = answer.unwrap();
        assert!(matches!(answer.reply.answer, UnitAnswer::Ok { .. }));
        assert!(matches!(answer.renewal, Some(Renewal::Renewed { .. })));
        assert!(pages.is_empty());
        assert_eq!(*slept.borrow(), [50]);
        assert_eq!(
            rig.calls(),
            ["ping", "job:stamp", "ping", "renew", "ping", "ping"]
        );
    });
}

/// A request whose waiter times out cannot start a second renewal.
#[test]
fn a_waiter_that_times_out_returns_renew_needed() {
    with_expired(|rig| {
        let (flights, slept) = fake_sleep();
        assert_eq!((RENEW_WAIT_MS, RENEW_POLL_MS), (5_000, 50));
        let polls = usize::try_from(RENEW_WAIT_MS / RENEW_POLL_MS).unwrap();
        let leader = UnitClient {
            flights: flights.clone(),
            ..rig.client()
        };
        let waiter = UnitClient {
            flights,
            ..rig.client()
        };
        let (answer, pages) = during_a_gated_request_renewal(
            rig,
            &leader,
            waiter.call(request(rig.unit_seqs(), UnitOp::Ping {})),
            Follower::FinishesWhileGated(polls),
        );
        let answer = answer.unwrap();
        assert!(matches!(
            answer.reply.answer,
            UnitAnswer::RenewNeeded { why: None, .. }
        ));
        assert_eq!(answer.renewal, None);
        assert!(pages.is_empty());
        assert_eq!(*slept.borrow(), vec![RENEW_POLL_MS; polls]);
        assert_eq!(slept.borrow().iter().sum::<u64>(), RENEW_WAIT_MS);
        assert_eq!(rig.calls(), ["ping", "job:stamp", "ping", "renew", "ping"]);
    });
}

/// A client using the default timerless isolate state does not wait.
#[test]
fn an_expired_request_without_a_timer_returns_renew_needed() {
    with_expired(|rig| {
        let leader = rig.client();
        let other = rig.client();
        let (answer, pages) = during_a_gated_request_renewal(
            rig,
            &leader,
            other.call(request(rig.unit_seqs(), UnitOp::Ping {})),
            Follower::FinishesWhileGated(0),
        );
        let answer = answer.unwrap();
        assert!(matches!(
            answer.reply.answer,
            UnitAnswer::RenewNeeded { why: None, .. }
        ));
        assert_eq!(answer.renewal, None);
        assert!(pages.is_empty());
        assert_eq!(rig.calls(), ["ping", "job:stamp", "ping", "renew", "ping"]);
    });
}

/// Background work neither starts a second renewal nor waits for the first.
#[test]
fn a_background_renewal_does_not_wait_for_an_in_flight_renewal() {
    with_expired(|rig| {
        let (flights, slept) = fake_sleep();
        let leader = UnitClient {
            flights: flights.clone(),
            ..rig.client()
        };
        let background = UnitClient {
            flights,
            ..rig.client()
        };
        let result = during_a_gated_request_renewal(
            rig,
            &leader,
            background.renew_in_background(rig.unit_seqs()),
            Follower::FinishesWhileGated(0),
        );
        assert!(result.is_none());
        assert!(slept.borrow().is_empty());
        assert_eq!(rig.calls(), ["ping", "job:stamp", "renew", "ping"]);
    });
}

/// A queued renew acknowledges a renewal already in this isolate without proving a second lease.
#[test]
fn a_renew_job_acknowledges_a_renewal_already_in_flight() {
    with_expired(|rig| {
        let leader = rig.client();
        let queue = rig.client();
        let job = during_a_gated_request_renewal(
            rig,
            &leader,
            queue.run_job(UnitJob::Renew { at: NOW }, rig.unit_seqs()),
            Follower::FinishesWhileGated(0),
        );
        assert_eq!((job.delivery, job.code), (Delivery::Ack, "renewing"));
        assert!(job.pages.is_empty(), "{:?}", job.pages);
        assert_eq!(rig.calls(), ["ping", "job:stamp", "renew", "ping"]);
    });
}

/// A request waits for a queued renew registered by another caller in the same isolate.
#[test]
fn a_request_waits_for_a_queued_renewal_and_is_served_after_it() {
    with_expired(|rig| {
        let (flights, slept) = fake_sleep();
        let queue = UnitClient {
            flights: flights.clone(),
            ..rig.client()
        };
        let waiter = UnitClient {
            flights: flights.clone(),
            ..rig.client()
        };
        let seqs = rig.unit_seqs();
        let (job, (answer, pages)) = during_a_gated_renewal(
            rig,
            &flights,
            queue.run_job(UnitJob::Renew { at: NOW }, seqs),
            waiter.call(request(seqs, UnitOp::Ping {})),
            Follower::WaitsForRenewal,
        );
        assert_eq!((job.delivery, job.code), (Delivery::Ack, "renewed"));
        assert!(job.pages.is_empty(), "{:?}", job.pages);
        let answer = answer.unwrap();
        assert!(matches!(answer.reply.answer, UnitAnswer::Ok { .. }));
        assert!(matches!(answer.renewal, Some(Renewal::Renewed { .. })));
        assert!(pages.is_empty(), "{pages:?}");
        assert_eq!(*slept.borrow(), [50]);
        assert_eq!(rig.calls(), ["job:stamp", "ping", "renew", "ping"]);
    });
}

/// A stamp raise that needs a lease hands back while a renewal already holds the slot.
#[test]
fn a_stamp_raise_that_needs_renewal_is_handed_back_while_one_runs() {
    with_expired(|rig| {
        let leader = rig.client();
        let queue = rig.client();
        let id = queue.stamp_id().unwrap();
        let before = stamp_row(rig, id.as_str()).counter;
        let next = before.unwrap_or(0) + 1;
        let stamp = stamp_key(id.as_str(), next);
        let job = during_a_gated_request_renewal(
            rig,
            &leader,
            queue.run_job(UnitJob::StampRaise { at: NOW }, rig.unit_seqs()),
            Follower::FinishesWhileGated(0),
        );
        assert_eq!((job.delivery, job.code), (Delivery::HandBack, "renewing"));
        assert!(job.pages.is_empty(), "{:?}", job.pages);
        assert_eq!(stamp_row(rig, id.as_str()).counter, before);
        assert!(!rig.safety.contains(&stamp));
        assert_eq!(
            rig.calls(),
            [
                "ping",
                "job:stamp",
                "job:stamp",
                "job:stamp_advance",
                "renew",
                "ping"
            ]
        );

        let retry = block_on(queue.run_job(UnitJob::StampRaise { at: NOW }, rig.unit_seqs()));
        assert_eq!((retry.delivery, retry.code), (Delivery::Ack, "raised"));
        assert!(retry.pages.is_empty(), "{:?}", retry.pages);
        assert_eq!(stamp_row(rig, id.as_str()).counter, Some(next));
        assert!(rig.safety.contains(&stamp));
        assert_eq!(rig.calls().iter().filter(|op| **op == "renew").count(), 1);
    });
}

/// The read used to verify the signature does not carry authentication yet.
fn unsigned_key_row(seqs: Seqs) -> UnitCall {
    UnitCall {
        authenticated: false,
        ..request(
            seqs,
            UnitOp::KeyRow {
                access_key_id: K.into(),
                presigned: None,
            },
        )
    }
}

/// A fresh unsigned key row is reusable unchanged after verification.
#[test]
fn a_verified_key_row_without_a_marker_needs_no_unit_call() {
    with_fresh(|rig| {
        rig.obj.log.borrow_mut().clear();
        let c = rig.client();
        let call = unsigned_key_row(rig.unit_seqs());
        let (first, pages) = called(&c, call.clone());
        assert!(pages.is_empty());
        assert!(
            matches!(&first.reply.answer, UnitAnswer::Ok { body, .. } if body["key"].is_object())
        );
        assert!(!lease_expired(&first.reply));
        rig.assert_call_auth(&[("key_row", false)]);
        rig.obj.log.borrow_mut().clear();

        let (answer, pages) = block_on(c.key_row_verified(first.clone(), call));
        assert_eq!(answer.unwrap(), first);
        assert!(pages.is_empty());
        assert!(rig.calls().is_empty());
    });
}

/// A marked unsigned key row is used for verification only; renewal allows
/// a fresh, signed read before anything can use the row.
#[test]
fn a_verified_expired_key_row_is_reread_signed_after_renewal() {
    with_expired(|rig| {
        let c = rig.client();
        let call = unsigned_key_row(rig.unit_seqs());
        let (first, pages) = called(&c, call.clone());
        assert!(pages.is_empty());
        assert!(
            matches!(&first.reply.answer, UnitAnswer::Ok { body, .. } if body["key"].is_object())
        );
        assert!(lease_expired(&first.reply));
        rig.assert_call_auth(&[("key_row", false)]);

        let (answer, pages) = block_on(c.key_row_verified(first, call));
        let answer = answer.unwrap();
        assert!(
            matches!(&answer.reply.answer, UnitAnswer::Ok { body, .. } if body["key"].is_object())
        );
        assert!(!lease_expired(&answer.reply));
        assert!(matches!(answer.renewal, Some(Renewal::Renewed { .. })));
        assert!(pages.is_empty());
        rig.assert_call_auth(&[
            ("key_row", false),
            ("key_row", true),
            ("job:stamp", true),
            ("renew", true),
            ("key_row", true),
        ]);
    });
}

/// A signed reread reports a revocation that landed after the marked unsigned key read.
#[test]
fn a_verified_expired_key_row_reports_an_intervening_revocation() {
    with_expired(|rig| {
        let c = rig.client();
        let call = unsigned_key_row(rig.unit_seqs());
        let (first, pages) = called(&c, call.clone());
        assert!(pages.is_empty(), "{pages:?}");
        assert!(lease_expired(&first.reply));
        assert!(
            matches!(&first.reply.answer, UnitAnswer::Ok { body, .. } if body["key"]["status"] == "active")
        );
        rig.assert_call_auth(&[("key_row", false)]);

        put(
            rig.safety,
            &format!("{}{K}", RecordNames.revocation_dir(tid())),
        );
        let (answer, pages) = block_on(c.key_row_verified(first, call));
        let answer = answer.unwrap();
        assert!(pages.is_empty(), "{pages:?}");
        assert!(matches!(answer.renewal, Some(Renewal::Renewed { .. })));
        assert!(!lease_expired(&answer.reply));
        assert_eq!(revoked_count(rig), 1);
        rig.assert_call_auth(&[
            ("key_row", false),
            ("key_row", true),
            ("job:stamp", true),
            ("renew", true),
            ("key_row", true),
        ]);
        let UnitAnswer::Ok { body, .. } = answer.reply.answer else {
            panic!("expected a successful signed key lookup");
        };
        let key = body
            .get("key")
            .expect("the signed reread includes a key field");
        // The catalogue serves active keys only: a revoked key reads as
        // none, which the Worker answers 403. Never the old active row.
        assert!(
            key.is_null() || key["status"].as_str() != Some("active"),
            "{key}"
        );
    });
}

/// Losing the stamp-read answer must not release the expired unsigned row.
#[test]
fn a_verified_expired_key_row_is_never_served_when_the_renewal_fails() {
    with_expired(|rig| {
        let c = rig.client();
        let seqs = rig.unit_seqs();
        let call = unsigned_key_row(seqs);
        let (first, pages) = called(&c, call.clone());
        assert!(pages.is_empty());
        assert!(lease_expired(&first.reply));
        rig.obj.lose_answer_of.set(Some("job:stamp"));

        let (answer, pages) = block_on(c.key_row_verified(first, call));
        rig.assert_call_auth(&[("key_row", false), ("key_row", true), ("job:stamp", true)]);
        // The renewal's read was lost: an error (the Worker's `503`, the
        // call may be made again), never the marked row.
        match answer {
            Err(_) => {}
            Ok(answer) => {
                assert_eq!(
                    answer.reply.answer,
                    UnitAnswer::RenewNeeded { seqs, why: None }
                );
                assert!(!lease_expired(&answer.reply));
            }
        }
        assert!(pages.is_empty());
    });
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// The proof's names are the writers' own.
#[test]
fn the_record_names_are_the_writers() {
    let kt = velmora_bridge::crypto::scheme2::TenantId::parse(tid()).unwrap();
    for seq in [1, 9, 10, 12_345] {
        assert_eq!(
            RecordNames.tenant_record(tid(), seq),
            record_key(&dir_tenant(), seq)
        );
        assert_eq!(RecordNames.key_record(tid(), seq), key_chain(&kt).name(seq));
    }
    assert_eq!(
        RecordNames.revocation_dir(tid()),
        tenant_revocation_prefix(&kt)
    );
    // Tenant 0 has no unit: its names are none a record has.
    let zero = Tenant::zero();
    assert!(RecordNames.key_record(zero.as_str(), 1).contains("/-/"));
    assert!(RecordNames.revocation_dir(zero.as_str()).contains("/-/"));
}
