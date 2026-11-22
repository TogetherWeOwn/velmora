//! The unit client (round 5 §R5-4, AM-50, AM-51): the Worker's side of
//! `renew` and `sync`, rule 5 on the request path, and the `renew` and
//! `stamp_raise` jobs, against the real unit (`Unit` over SQLite), L3's
//! tenant chain (`TenantChain` over an in-memory record store) and the
//! in-memory safety bucket the proof reads.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use velmora_bridge::directory::chain::{record_key, TenantChain, Written};
use velmora_bridge::directory::record::{HoldMode, OperatorReason, Tenant};
use velmora_bridge::directory::testing::{HookedRecords, PlainSeal};
use velmora_bridge::directory::transition::{Actor, Change, OperatorHoldRequest, KEY_CHECK_LEN};
use velmora_bridge::jobmsg::UnitJob;
use velmora_bridge::keys::record::key_chain;
use velmora_bridge::keys::revocations::tenant_revocation_prefix;
use velmora_bridge::recovery::Unpublished;
use velmora_bridge::stamp::stamp_key;
use velmora_bridge::testkit::{FixedClock, MemBlobStore, RusqliteSql};
use velmora_bridge::unit::jobcall::JobCall;
use velmora_bridge::unit::keys::{Access, KeyEntry, KeyGrant, KeyKind, SubjectStatus};
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Seqs, TenantId, TenantState, Unit, UnitAnswer, UnitCall,
    UnitName, UnitOp, UnitReply,
};
use velmora_bridge::unit_lease::client::{
    Delivery, InFlight, KeyBatch, KeyFeed, KeyFinisher, Page, RecordNames, Renewal, Synced,
    UnitClient, UnitReplies,
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

/// The unit object as the stub reaches it: the real unit at the rig's
/// clock, with a log of the calls and a way to fail them.
struct Obj<'a> {
    unit: Unit<RusqliteSql>,
    clock: &'a FixedClock,
    log: RefCell<Vec<(CallKind, bool, String)>>,
    fail: Cell<bool>,
    /// Run once, right after the first `stamp` read answered.
    after_stamp_read: RefCell<Option<Hook<'a>>>,
    /// The answer to the next call of this op is lost after the unit ran
    /// it.
    lose_answer_of: Cell<Option<&'static str>>,
    /// Another writer raises the stamp after every stamp read.
    raise_after_each_read: Cell<bool>,
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
        self.log
            .borrow_mut()
            .push((call.kind, call.listed, op_name(&call.op)));
        let reply = self.unit.reply(call, self.clock.now());
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
struct Keys(RefCell<BTreeMap<u64, KeyEntry>>);

impl KeyFeed for Keys {
    async fn after(&self, t: &TenantId, after: u64) -> Result<KeyBatch> {
        assert_eq!(t, &tenant());
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
    obj: Obj<'a>,
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

type Client<'s, 'a> = UnitClient<
    &'s Obj<'a>,
    Safety<'s>,
    FixedClock,
    RecordNames,
    TenantChain<'s, HookedRecords, PlainSeal>,
    &'s Keys,
    &'s Finisher,
>;

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
            heads: TenantChain {
                store: self.records,
                seal: self.seal,
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
    fn key_record(&self, seq: u64, entry: KeyEntry) {
        self.keys.0.borrow_mut().insert(seq, entry);
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
        limits: BTreeMap::from([("bytes".to_string(), 1 << 30)]),
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
        obj: Obj {
            unit: Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), ""),
            clock: &clock,
            log: RefCell::new(vec![]),
            fail: Cell::new(false),
            after_stamp_read: RefCell::new(None),
            lose_answer_of: Cell::new(None),
            raise_after_each_read: Cell::new(false),
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
        assert!(matches!(
            block_on(c.sync(rig.unit_seqs())).unwrap(),
            Synced::Synced { .. }
        ));
        let (r, pages) = renewed(&c, rig.unit_seqs());
        assert!(matches!(r, Renewal::Renewed { .. }), "{r:?}");
        assert!(pages.is_empty(), "{pages:?}");
        f(rig)
    })
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
        let s = block_on(rig.client().sync(before)).unwrap();
        let want = Seqs {
            state_seq: 4,
            keys_seq: 2,
        };
        assert_eq!(s, Synced::Synced { seqs: want });
        assert_eq!(rig.unit_seqs(), want);
        let head = rig.obj.unit.head().unwrap();
        assert_eq!(head.tenant_state, TenantState::Active);
        assert_eq!(rig.calls(), ["apply_keys", "sync"]);
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
        let s = block_on(rig.client().sync(rig.unit_seqs())).unwrap();
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
        let s = block_on(c.sync(Seqs {
            state_seq: 0,
            keys_seq: 0,
        }))
        .unwrap();
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
        let s = block_on(rig.client().sync(rig.unit_seqs())).unwrap();
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
        let s = block_on(rig.client().sync(rig.unit_seqs())).unwrap();
        assert!(matches!(s, Synced::LiftPending { .. }), "{s:?}");
        let head = rig.obj.unit.head().unwrap();
        assert_eq!(head.restoring_since, Some(5));
        assert_eq!(head.seqs.state_seq, 5, "nothing changed");
    });
}

/// A key chain that ends below what the unit holds is damage: no call.
#[test]
fn a_key_chain_below_the_unit_is_an_error() {
    with_fresh(|rig| {
        rig.keys.0.borrow_mut().clear();
        rig.obj.log.borrow_mut().clear();
        assert!(block_on(rig.client().sync(rig.unit_seqs())).is_err());
        assert!(rig.calls().is_empty());
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
        block_on(rig.client().sync(rig.unit_seqs())).unwrap();
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
        block_on(rig.client().sync(rig.unit_seqs())).unwrap();
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
        block_on(rig.client().sync(rig.unit_seqs())).unwrap();
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
        obj: Obj {
            unit: Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), ""),
            clock: &clock,
            log: RefCell::new(vec![]),
            fail: Cell::new(false),
            after_stamp_read: RefCell::new(None),
            lose_answer_of: Cell::new(None),
            raise_after_each_read: Cell::new(false),
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
        block_on(rig.client().sync(rig.unit_seqs())).unwrap();
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
        let s = block_on(rig.client().sync(rig.unit_seqs())).unwrap();
        assert!(
            matches!(s, Synced::Synced { seqs } if seqs.keys_seq == 250),
            "{s:?}"
        );
        let applies = rig.calls().iter().filter(|c| *c == "apply_keys").count();
        assert_eq!(applies, 3, "100 + 100 + 50");
    });
}

/// Rule 11: unsigned calls on an expired lease make at most one renewal
/// attempt per unit and T; signed calls renew for themselves (review
/// finding 2).
#[test]
fn unsigned_calls_try_one_renewal_per_unit_and_t() {
    with_fresh(|rig| {
        // A renewal that is refused every time: a revocation the bucket
        // does not list.
        rig.key_record(3, key(K, 3, SubjectStatus::Revoked));
        block_on(rig.client().sync(rig.unit_seqs())).unwrap();
        rig.clock.advance_ms(T + 1);
        let unsigned = || {
            let mut c = request(rig.unit_seqs(), UnitOp::Ping {});
            c.authenticated = false;
            block_on(rig.client().call(c)).unwrap()
        };
        let reads = || rig.calls().iter().filter(|c| *c == "job:stamp").count();
        let before = reads();
        let pages: usize = (0..5).map(|_| unsigned().pages.len()).sum();
        assert_eq!(reads() - before, 1, "one attempt");
        assert_eq!(pages, 1, "one page");
        // One T later: one more.
        rig.clock.advance_ms(T);
        unsigned();
        unsigned();
        assert_eq!(reads() - before, 2);
        // A signed call tries every time.
        for _ in 0..2 {
            block_on(rig.client().call(request(rig.unit_seqs(), UnitOp::Ping {}))).unwrap();
        }
        assert_eq!(reads() - before, 4);
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
        block_on(rig.client().sync(rig.unit_seqs())).unwrap();
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
        block_on(rig.client().sync(rig.unit_seqs())).unwrap();
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
        block_on(rig.client().sync(rig.unit_seqs())).unwrap();
        let a = block_on(rig.client().call(request(rig.unit_seqs(), UnitOp::Ping {}))).unwrap();
        assert!(matches!(a.reply.answer, UnitAnswer::Ok { .. }), "{a:?}");
        assert_eq!(a.refreshed, None);
        assert!(!a.renew_due);
        assert_eq!(
            rig.calls(),
            ["apply_keys", "sync", "ping", "job:stamp", "renew", "ping"]
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
        let a = block_on(rig.client().call(request(seqs, UnitOp::Ping {}))).unwrap();
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
        let a = block_on(rig.client().call(request(old, UnitOp::Ping {}))).unwrap();
        assert!(matches!(a.reply.answer, UnitAnswer::Ok { .. }), "{a:?}");
        assert_eq!(a.refreshed, Some(now));
    });
}

/// Each fix runs at most once: a unit that stays expired is answered as
/// it is.
#[test]
fn a_request_renews_at_most_once() {
    with_rig(|rig| {
        block_on(rig.client().sync(rig.unit_seqs())).unwrap();
        // The bucket lists a revocation the unit cannot hold: refused.
        rig.key_record(3, key(K, 3, SubjectStatus::Revoked));
        block_on(rig.client().sync(rig.unit_seqs())).unwrap();
        let a = block_on(rig.client().call(request(rig.unit_seqs(), UnitOp::Ping {}))).unwrap();
        assert!(matches!(a.reply.answer, UnitAnswer::RenewNeeded { .. }));
        assert_eq!(a.pages, [Page::RevocationsShort { listed: 0, held: 1 }]);
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
        let a = block_on(c.call(request(rig.unit_seqs(), UnitOp::Ping {}))).unwrap();
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
