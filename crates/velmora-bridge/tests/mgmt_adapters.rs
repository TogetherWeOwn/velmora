//! The management plane's store adapters (`mgmt::adapters`, round 6
//! L5-R4): [`HeadDoor`] over a tenant head, [`RoutedUnit`] over the
//! request router (L6) with a unit client that calls a real unit, and
//! [`KeyChain`] over L4's writer with the root unit as its key target.
//!
//! The end-to-end case runs a principal create (sign-up) through the
//! plane's `serve_with`, the three adapters, the real `Router`, a real
//! unit (`Unit<RusqliteSql>`) and L4's `KeyEnv` over an in-memory record
//! store: the record lands at exactly `keys_seq + 1`, the root unit keeps
//! the answer by its full apply, and a retry answers it with no record.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use futures_util::StreamExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::config::Maintenance;
use velmora_bridge::crypto::scheme2::TenantKey;
use velmora_bridge::directory::chain::ChainError;
use velmora_bridge::directory::record::{
    ActorClass, BillingHold, Deletion, DeletionReason, HoldMode, Lifecycle, OperatorHold,
    OperatorReason, Placement, Restoring, TenantDoor as Door,
};
use velmora_bridge::keys::gate::testkit::FakeGate;
use velmora_bridge::keys::ports::{
    Admission, Applied, ApplyEntry, Binding, BucketAdmission, BucketReservation, ControlChain,
    ControlIntents, KeyAdmission, KeyTarget, OpeningChange,
};
use velmora_bridge::keys::record::{
    key_chain, Access as ChainAccess, DoorGrant, Entry, OneKey, PrivateGrant, SubjectDoor,
    SubjectKind, SubjectPrivate, SubjectStatus as ChainStatus,
};
use velmora_bridge::keys::writer::{KeyEnv, Limits};
use velmora_bridge::mgmt::adapters::{
    door_state, unit_entry, BucketNames, HeadDoor, KeyChain, NoBucketNames, RoutedUnit, ERR_TENANT,
};
use velmora_bridge::mgmt::principal::{
    ChainWrite, DoorState, NewPrincipal, PrincipalChain, PrincipalHandlers, PrincipalPorts,
    ReserveAnswer, RootUnit, TenantDoor,
};
use velmora_bridge::mgmt::serve::{serve_with, Answer, MgmtRequest};
use velmora_bridge::mgmt::token::{DisabledTokens, TokenHashes};
use velmora_bridge::records::MemRecords;
use velmora_bridge::testkit::{FixedClock, MemBlobStore, RusqliteSql, TestKek};
use velmora_bridge::types::Body;
use velmora_bridge::unit::keys::KeptAnswer as UnitKept;
use velmora_bridge::unit::reserve::Rid;
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Seqs, SyncHead, TenantId, TenantState, Unit, UnitAnswer,
    UnitCall, UnitName, UnitOp, UnitReply,
};
use velmora_bridge::unit_lease::client::{Answered, Page, TenantHeads};
use velmora_bridge::unit_lease::lease::Proven;
use velmora_bridge::unit_router::{
    test_door, HeadCache, RequestClient, RequestClients, RouteRefusal, Routed, Router, UnitRouter,
};
use velmora_bridge::{BridgeError, Result, UnixMs};

const NOW: UnixMs = UnixMs(1_795_000_000_000);
const TENANT: &str = "t_0000000000000f01";
const B1: &str = "b_00000000000000f1";
const B2: &str = "b_00000000000000f2";
const NEW_OWNER: &str = "usr_01JD2Q9A7M";
const KEY: &str = "ws_01JD2Q8V5X/usr_01JD2Q9A7M";
const CONFIRMED: &str = "conf-token-0123456789abcdef0123456789abcdef";
const STANDARD: &str = "std-token-0123456789abcdef0123456789abcdef";
/// The unit's `state_seq` after `ready()`, which the head names.
const STATE_SEQ: u64 = 4;

fn tenant() -> TenantId {
    TenantId::parse(TENANT).unwrap()
}

fn chain_tenant() -> velmora_bridge::TenantId {
    velmora_bridge::TenantId::parse(TENANT).unwrap()
}

fn own() -> UnitName {
    UnitName::new(tenant(), 0)
}

fn worker_call(op: UnitOp) -> UnitCall {
    UnitCall {
        name: own(),
        kind: CallKind::Worker,
        seqs: None,
        authenticated: true,
        listed: true,
        op,
    }
}

fn derived(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn hash(token: &str) -> String {
    Sha256::digest(token)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hashes() -> TokenHashes {
    let (standard, confirmed) = (hash(STANDARD), hash(CONFIRMED));
    TokenHashes::from_vars(|name| match name {
        "MGMT_TOKEN_SHA256_STANDARD" => Some(standard.clone()),
        "MGMT_TOKEN_SHA256_CONFIRMED" => Some(confirmed.clone()),
        _ => None,
    })
    .unwrap()
}

// ---------------------------------------------------------------------------
// The unit
// ---------------------------------------------------------------------------

/// The Worker's renewal at `now` (rule 12).
fn renew(u: &Unit<RusqliteSql>, now: UnixMs) {
    let seqs = u.head().unwrap().seqs;
    let op = UnitOp::Renew {
        proof_start: now,
        proven: Proven {
            state_seq: seqs.state_seq,
            keys_seq: seqs.keys_seq,
            stamp_counter: None,
            revoked: 0,
        },
        revocations: Vec::new(),
    };
    let a = u.handle(&worker_call(op), now);
    assert!(matches!(a, UnitAnswer::Ok { .. }), "renew: {a:?}");
}

/// A born, active managed root unit at `state_seq` 4, `keys_seq` 0.
fn ready() -> Unit<RusqliteSql> {
    let u = Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), "");
    let token = BirthToken {
        name: own(),
        jurisdiction: String::new(),
        record_seq: 3,
        schema_version: velmora_bridge::unit::schema::SCHEMA_VERSION,
        key_scheme: 2,
        kind: BirthKind::Birth,
    };
    let mut c = worker_call(UnitOp::Provision {
        token,
        sealed: b"sealed".to_vec(),
    });
    c.seqs = Some(Seqs {
        state_seq: 3,
        keys_seq: 0,
    });
    assert!(matches!(u.handle(&c, NOW), UnitAnswer::Ok { .. }));
    let a = u.handle(
        &worker_call(UnitOp::Sync {
            head: SyncHead {
                seqs: Seqs {
                    state_seq: STATE_SEQ,
                    keys_seq: 0,
                },
                tenant_mode: None,
                tenant_state: TenantState::Active,
                restoring_since: None,
                lift: None,
            },
        }),
        NOW,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
    renew(&u, NOW);
    u
}

/// L2's unit client as the router calls it, over a unit in this process:
/// a call the unit answers `renew_needed` is renewed and sent once more.
#[derive(Clone, Copy)]
struct Direct<'a> {
    unit: &'a Unit<RusqliteSql>,
    log: &'a RefCell<Vec<UnitCall>>,
    down: &'a Cell<bool>,
}

impl RequestClient for Direct<'_> {
    async fn call(&self, call: UnitCall) -> (Result<Answered>, Vec<Page>) {
        if self.down.get() {
            return (
                Err(BridgeError::Sql("fake: unreachable".into())),
                Vec::new(),
            );
        }
        self.log.borrow_mut().push(call.clone());
        let answer = match self.unit.handle(&call, NOW) {
            UnitAnswer::RenewNeeded { why: None, .. } => {
                renew(self.unit, NOW);
                self.unit.handle(&call, NOW)
            }
            a => a,
        };
        let answered = Answered {
            reply: UnitReply {
                answer,
                lease_left_ms: 1,
                revoked: None,
            },
            refreshed: None,
            renew_due: false,
            renewal: None,
            synced: None,
        };
        (Ok(answered), Vec::new())
    }
}

impl<'a> RequestClients for Direct<'a> {
    type Client = Direct<'a>;
    fn client(&self, _: &Routed) -> Result<Direct<'a>> {
        Ok(*self)
    }
}

/// The tenant's verified head (door part).
struct Heads {
    door: RefCell<Option<Door>>,
    down: Cell<bool>,
    reads: Cell<u32>,
}

impl Heads {
    fn live() -> Heads {
        Heads {
            door: RefCell::new(Some(test_door(&tenant(), STATE_SEQ, Lifecycle::Live, &[0]))),
            down: Cell::new(false),
            reads: Cell::new(0),
        }
    }

    fn with(&self, f: impl FnOnce(&mut Door)) {
        if let Some(d) = self.door.borrow_mut().as_mut() {
            f(d)
        }
    }
}

impl TenantHeads for Heads {
    async fn head(&self, t: &TenantId, _: u64) -> std::result::Result<Option<Door>, ChainError> {
        self.reads.set(self.reads.get() + 1);
        if self.down.get() {
            return Err(ChainError::Store(velmora_bridge::BridgeError::Sql(
                "fake: down".into(),
            )));
        }
        Ok(self.door.borrow().clone().filter(|_| t.as_str() == TENANT))
    }
}

/// The root unit's bucket names (a read L1-5 will serve).
#[derive(Default)]
struct Names {
    rows: BTreeMap<String, String>,
    asked: RefCell<Vec<Vec<String>>>,
}

impl BucketNames for Names {
    async fn names(&self, _: &TenantId, ids: &[String]) -> Result<Vec<Option<String>>> {
        self.asked.borrow_mut().push(ids.to_vec());
        Ok(ids.iter().map(|id| self.rows.get(id).cloned()).collect())
    }
}

// ---------------------------------------------------------------------------
// L4's writer's other ports
// ---------------------------------------------------------------------------

struct TestRng(u64);

impl FillRandom for TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::Result<()> {
        for block in dest.chunks_mut(32) {
            let mut h = Sha256::new();
            h.update(b"mgmt adapters");
            h.update(self.0.to_be_bytes());
            self.0 += 1;
            block.copy_from_slice(&h.finalize()[..block.len()]);
        }
        Ok(())
    }
}

/// The plane's handler draws its ids from this (distinct values).
struct Counter(Cell<u8>);

impl FillRandom for Counter {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::error::Result<()> {
        let n = self.0.get().wrapping_add(1);
        self.0.set(n);
        dest.fill(n);
        Ok(())
    }
}

/// The reserved writer never asks its own admission.
struct NoAdmission;

impl KeyAdmission for NoAdmission {
    async fn admit(
        &self,
        _: &velmora_bridge::TenantId,
        _: &str,
        _: &OpeningChange<'_>,
    ) -> Result<Admission> {
        panic!("a reserved create asked for a reservation")
    }
    async fn release(&self, _: &velmora_bridge::TenantId, _: &str) -> Result<()> {
        panic!("a reserved create released a reservation")
    }
    async fn admit_bucket(
        &self,
        _: &velmora_bridge::TenantId,
        _: &str,
        _: &BucketReservation<'_>,
    ) -> Result<BucketAdmission> {
        panic!("not a bucket create")
    }
    async fn bind_bucket(
        &self,
        _: &velmora_bridge::TenantId,
        _: &str,
        _: Option<u64>,
        _: u64,
    ) -> Result<bool> {
        panic!("not a bucket create")
    }
    async fn release_bound(
        &self,
        _: &velmora_bridge::TenantId,
        _: &str,
        _: Option<u64>,
    ) -> Result<bool> {
        panic!("not a bucket create")
    }
    async fn bucket_binding(&self, _: &velmora_bridge::TenantId, _: u64) -> Result<Binding> {
        panic!("not a bucket create")
    }
}

#[derive(Default)]
struct Intents {
    sent: RefCell<Vec<u64>>,
}

impl ControlIntents for Intents {
    async fn send(
        &self,
        _: &velmora_bridge::TenantId,
        chain: ControlChain,
        seq: u64,
    ) -> Result<()> {
        assert_eq!(chain, ControlChain::Keys);
        self.sent.borrow_mut().push(seq);
        Ok(())
    }
    async fn note(
        &self,
        _: &velmora_bridge::TenantId,
        _: ControlChain,
        _: u64,
        _: &str,
    ) -> Result<()> {
        Ok(())
    }
    async fn clear(&self, _: &velmora_bridge::TenantId, _: ControlChain, _: u64) -> Result<()> {
        Ok(())
    }
}

/// The directory's copy of the key table: acknowledges every apply (or
/// none, while `down`).
#[derive(Default)]
struct Directory {
    seq: Cell<u64>,
    down: Cell<bool>,
}

impl KeyTarget for Directory {
    fn label(&self) -> &str {
        "directory"
    }
    async fn keys_seq(&self) -> Result<u64> {
        if self.down.get() {
            return Err(BridgeError::Sql("fake: down".into()));
        }
        Ok(self.seq.get())
    }
    async fn closed(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    async fn apply(&self, from_seq: u64, entries: &[ApplyEntry]) -> Result<Applied> {
        if self.down.get() {
            return Err(BridgeError::Sql("fake: down".into()));
        }
        if from_seq > self.seq.get() {
            return Ok(Applied::Behind {
                keys_seq: self.seq.get(),
            });
        }
        let last = from_seq + entries.len() as u64;
        self.seq.set(self.seq.get().max(last));
        Ok(Applied::Done {
            keys_seq: self.seq.get(),
        })
    }
}

// ---------------------------------------------------------------------------
// The world: one request through the three adapters
// ---------------------------------------------------------------------------

struct Stores {
    unit: Unit<RusqliteSql>,
    heads: Heads,
    log: RefCell<Vec<UnitCall>>,
    unreachable: Cell<bool>,
    cache: HeadCache,
    clock: FixedClock,
    records: MemRecords,
    kek: TestKek,
    ring: OneKey,
    chain_tenant: velmora_bridge::TenantId,
    intents: Intents,
    directory: Directory,
    gate: FakeGate,
}

impl Stores {
    fn new() -> Stores {
        let t = chain_tenant();
        Stores {
            unit: ready(),
            heads: Heads::live(),
            log: RefCell::new(Vec::new()),
            unreachable: Cell::new(false),
            cache: HeadCache::default(),
            clock: FixedClock::new(NOW),
            records: MemRecords::new(),
            kek: TestKek::with_versions(1, &[(1, derived("kek"))]),
            ring: OneKey(TenantKey::from_bytes(&t, 1, derived("tk")).unwrap()),
            chain_tenant: t,
            intents: Intents::default(),
            directory: Directory::default(),
            gate: FakeGate::before_move(),
        }
    }

    fn clients(&self) -> Direct<'_> {
        Direct {
            unit: &self.unit,
            log: &self.log,
            down: &self.unreachable,
        }
    }

    fn chain_head(&self) -> u64 {
        self.records
            .names_under(key_chain(&self.chain_tenant).prefix())
            .len() as u64
    }

    fn unit_principal(&self, owner_ref: &str) -> Option<(String, String)> {
        self.unit
            .sql()
            .with_conn(|c| {
                Ok::<_, rusqlite::Error>(
                    c.query_row(
                        "SELECT id, status FROM unit_keys WHERE kind = 'principal' AND owner_ref = ?1",
                        [owner_ref],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .ok(),
                )
            })
            .unwrap()
    }

    fn reservations(&self) -> Vec<(String, Option<String>)> {
        self.unit
            .sql()
            .with_conn(|c| {
                let mut s = c
                    .prepare("SELECT state, answer_body FROM unit_reservations ORDER BY rid")
                    .unwrap();
                let rows = s
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                    .unwrap()
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .unwrap();
                Ok::<_, rusqlite::Error>(rows)
            })
            .unwrap()
    }

    /// One principal create through `serve_with` and the three adapters.
    async fn create(&self, body: &str) -> Answer {
        let clients = self.clients();
        let router = Router {
            maintenance: Maintenance::Off,
            clients: &clients,
            heads: &self.heads,
            cache: &self.cache,
            clock: &self.clock,
        };
        let unit = RoutedUnit::new(&router);
        let units = [unit.keys(tenant())];
        let env = KeyEnv {
            store: &self.records,
            kek: &self.kek,
            ring: &self.ring,
            tenant: &self.chain_tenant,
            admission: &NoAdmission,
            intents: &self.intents,
            units: &units,
            directory: &self.directory,
            clock: &self.clock,
            limits: Limits::NotServed,
            gate: &self.gate,
        };
        let chain = KeyChain::new(&env, TestRng(1));
        let door = HeadDoor {
            heads: &self.heads,
            names: &NoBucketNames,
        };
        let rng = RefCell::new(Counter(Cell::new(0)));
        let handlers = PrincipalHandlers {
            ports: PrincipalPorts {
                door: &door,
                unit: &unit,
                chain: &chain,
                rng: &rng,
            },
        };
        let bytes = body.as_bytes().to_vec();
        let body = Body::Stream {
            declared_len: Some(bytes.len() as u64),
            stream: futures_util::stream::iter(vec![Ok(bytes)]).boxed_local(),
        };
        let disabled = RefCell::new(DisabledTokens::default());
        let authorization = format!("Bearer {CONFIRMED}");
        let path = format!("/v1/tenants/{TENANT}/principals");
        let req = MgmtRequest {
            method: "POST",
            path: &path,
            query: "",
            authorization: Some(&authorization),
            acting: None,
            idempotency_key: Some(KEY),
        };
        let a = serve_with(
            &disabled,
            &hashes(),
            &MemBlobStore::new(),
            &handlers,
            req,
            body,
            NOW,
        )
        .await;
        assert!(unit.take_pages().is_empty());
        assert!(unit.take_alerts().is_empty());
        a
    }
}

fn signup() -> String {
    json!({"owner_ref": NEW_OWNER, "grants": []}).to_string()
}

fn json_of(a: &Answer) -> Value {
    serde_json::from_str(a.json.as_deref().expect("a JSON answer")).unwrap()
}

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn sign_up_runs_through_the_three_adapters_and_a_retry_answers_the_kept_answer() {
    let s = Stores::new();
    let a = s.create(&signup()).await;
    assert_eq!((a.status, a.code), (201, "ok"), "{a:?}");
    let p = json_of(&a);
    let id = p["id"].as_str().unwrap().to_string();
    assert_eq!(
        p,
        json!({"id": id, "owner_ref": NEW_OWNER, "status": "active", "grants": []})
    );
    // One record, at the reservation's keys_seq + 1, with its intent.
    assert_eq!(s.chain_head(), 1);
    assert_eq!(*s.intents.sent.borrow(), vec![1]);
    // The root unit holds the principal open, and kept the answer by its
    // full apply.
    assert_eq!(
        s.unit_principal(NEW_OWNER),
        Some((id.clone(), "active".into()))
    );
    assert_eq!(s.reservations(), vec![("applied".into(), Some(a.body()))]);
    assert_eq!(s.directory.seq.get(), 1);
    // Every unit call was a Worker call to the root unit, authenticated,
    // with the head's state_seq.
    for c in s.log.borrow().iter() {
        assert_eq!(c.kind, CallKind::Worker);
        assert!(c.authenticated && c.listed);
        assert_eq!(c.name, own());
        assert_eq!(c.seqs.map(|s| s.state_seq), Some(STATE_SEQ));
    }
    assert!(s
        .log
        .borrow()
        .iter()
        .any(|c| matches!(&c.op, UnitOp::ApplyKeys { answers, .. } if answers.len() == 1)));

    let again = s.create(&signup()).await;
    assert_eq!(again, a);
    assert_eq!(s.chain_head(), 1, "a retry writes no record");
}

#[tokio::test(flavor = "current_thread")]
async fn while_the_directory_is_down_the_create_answers_503_and_keeps_nothing() {
    let s = Stores::new();
    s.directory.down.set(true);
    let a = s.create(&signup()).await;
    assert_eq!((a.status, a.code), (503, "service_unavailable"), "{a:?}");
    // The record is written; the unit holds no kept answer for it.
    assert_eq!(s.chain_head(), 1);
    assert!(s.reservations().iter().all(|(_, body)| body.is_none()));
    // The directory comes back: the retry finishes the same record.
    s.directory.down.set(false);
    let again = s.create(&signup()).await;
    assert_eq!(again.status, 201, "{again:?}");
    assert_eq!(
        s.chain_head(),
        1,
        "the retry brings the stores up, no new record"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_unreachable_root_unit_answers_503_with_no_record() {
    let s = Stores::new();
    s.unreachable.set(true);
    let a = s.create(&signup()).await;
    assert_eq!((a.status, a.code), (503, "service_unavailable"), "{a:?}");
    assert_eq!(s.chain_head(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_head_that_does_not_list_the_root_unit_answers_503() {
    let s = Stores::new();
    s.heads.with(|d| d.units = vec![1]);
    let a = s.create(&signup()).await;
    assert_eq!((a.status, a.code), (503, "service_unavailable"), "{a:?}");
    assert!(s.log.borrow().is_empty(), "no unit call");
    assert_eq!(s.chain_head(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn a_tenant_with_no_chain_is_not_found() {
    let s = Stores::new();
    *s.heads.door.borrow_mut() = None;
    let a = s.create(&signup()).await;
    assert_eq!((a.status, a.code), (404, "tenant_not_found"), "{a:?}");
}

// ---------------------------------------------------------------------------
// HeadDoor
// ---------------------------------------------------------------------------

fn door() -> Door {
    test_door(&tenant(), STATE_SEQ, Lifecycle::Live, &[0])
}

#[test]
fn the_door_state_is_read_from_the_head() {
    let mut d = door();
    assert_eq!(door_state(&d), DoorState::Open);
    d.holds.billing = Some(BillingHold {
        mode: HoldMode::ReadOnly,
        since: UnixMs(5),
    });
    assert_eq!(door_state(&d), DoorState::ReadOnly);
    d.holds.operator = Some(OperatorHold {
        mode: HoldMode::Locked,
        reason: OperatorReason::Abuse,
        preserve: true,
        since: UnixMs(6),
    });
    assert_eq!(door_state(&d), DoorState::Unavailable);
    // A restoring entry holds the writes of a held tenant too, and of an
    // open one.
    let mut r = door();
    r.restoring = vec![Restoring {
        unit: 0,
        since_seq: 2,
    }];
    assert_eq!(door_state(&r), DoorState::Restoring);
    let mut del = door();
    del.deletion = Some(Deletion {
        seq: 3,
        requested_at: UnixMs(1),
        shred_due_at: UnixMs(2),
        reason: DeletionReason::CustomerRequest,
        actor: ActorClass::Customer,
        key_hash: "00".repeat(32),
    });
    assert_eq!(door_state(&del), DoorState::Unavailable);
    for (lifecycle, state) in [
        (Lifecycle::Provisioning, DoorState::Provisioning),
        (Lifecycle::Shredding, DoorState::Unavailable),
        (Lifecycle::Shredded, DoorState::Unavailable),
    ] {
        let mut d = door();
        d.lifecycle = lifecycle;
        assert_eq!(door_state(&d), state, "{lifecycle:?}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn bucket_names_come_from_the_unit_only_for_placed_ids() {
    let heads = Heads::live();
    heads.with(|d| {
        d.placements = vec![Placement {
            bucket: B1.into(),
            unit: 0,
            epoch: 1,
        }]
    });
    let names = Names {
        rows: BTreeMap::from([(B1.to_string(), "alpha".to_string())]),
        ..Names::default()
    };
    let door = HeadDoor {
        heads: &heads,
        names: &names,
    };
    let ids = vec![B2.to_string(), B1.to_string()];
    assert_eq!(
        door.bucket_names(&tenant(), &ids).await.unwrap(),
        vec![None, Some("alpha".into())]
    );
    assert_eq!(*names.asked.borrow(), vec![vec![B1.to_string()]]);
    // Only unplaced ids: no read of the unit.
    assert_eq!(
        door.bucket_names(&tenant(), &[B2.to_string()])
            .await
            .unwrap(),
        vec![None]
    );
    assert_eq!(names.asked.borrow().len(), 1);
    // A placed id the unit holds no row for: the unit is behind, an error.
    heads.with(|d| {
        d.placements.push(Placement {
            bucket: B2.into(),
            unit: 0,
            epoch: 2,
        })
    });
    assert!(door.bucket_names(&tenant(), &ids).await.is_err());
    // This build has no names read: a placed id is an error, an unplaced
    // one is still `None` (`404 bucket_not_found`).
    let none = HeadDoor {
        heads: &heads,
        names: &NoBucketNames,
    };
    assert!(none
        .bucket_names(&tenant(), &[B1.to_string()])
        .await
        .is_err());
    assert_eq!(
        none.bucket_names(&tenant(), &["b_00000000000000f9".to_string()])
            .await
            .unwrap(),
        vec![None]
    );
    // A head that cannot be read is an error, never "no tenant".
    heads.down.set(true);
    assert!(door.state(&tenant()).await.is_err());
    assert!(door.bucket_names(&tenant(), &ids).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn a_tenant_with_no_chain_has_no_state() {
    let heads = Heads::live();
    *heads.door.borrow_mut() = None;
    let door = HeadDoor {
        heads: &heads,
        names: &NoBucketNames,
    };
    assert_eq!(door.state(&tenant()).await.unwrap(), None);
    assert_eq!(
        door.bucket_names(&tenant(), &[B1.to_string()])
            .await
            .unwrap(),
        vec![None]
    );
}

// ---------------------------------------------------------------------------
// RoutedUnit and RootKeys
// ---------------------------------------------------------------------------

/// A router that refuses every route with one refusal.
struct Refusing(RouteRefusal);

impl UnitRouter for Refusing {
    async fn route(
        &self,
        _: &TenantId,
        _: Option<&str>,
        _: Seqs,
    ) -> std::result::Result<Routed, RouteRefusal> {
        Err(self.0)
    }
    async fn call(
        &self,
        _: &Routed,
        _: CallKind,
        _: bool,
        _: UnitOp,
    ) -> (std::result::Result<Answered, RouteRefusal>, Vec<Page>) {
        unreachable!("no route, no call")
    }
}

fn ask() -> UnitOp {
    UnitOp::Release { rid: Rid([1; 16]) }
}

#[tokio::test(flavor = "current_thread")]
async fn router_refusals_become_the_calls_answers() {
    let shredding = Refusing(RouteRefusal::AccountProblem);
    let unit = RoutedUnit::new(&shredding);
    let reserve = UnitOp::Reserve {
        key_hash: velmora_bridge::unit::reserve::Hash32([1; 32]),
        fingerprint: velmora_bridge::unit::reserve::Hash32([2; 32]),
        rid: Rid([3; 16]),
        acting: None,
        opening: velmora_bridge::unit::reserve::Opening::Principal {
            id: "p_0101010101010101".into(),
            owner_ref: NEW_OWNER.into(),
            grants: vec![],
        },
    };
    assert_eq!(
        unit.reserve(&tenant(), &reserve).await.unwrap(),
        ReserveAnswer::AccountProblem
    );
    for r in [
        RouteRefusal::Unavailable,
        RouteRefusal::NotPlaced,
        RouteRefusal::Closed,
        RouteRefusal::Maintenance,
        RouteRefusal::CatalogueLost,
    ] {
        let router = Refusing(r);
        let unit = RoutedUnit::new(&router);
        assert_eq!(
            unit.reserve(&tenant(), &reserve).await.unwrap(),
            ReserveAnswer::Unavailable,
            "{r:?}"
        );
        assert!(unit.release(&tenant(), &Rid([3; 16])).await.is_err());
    }
    // Only a reservation ask goes through `reserve`.
    assert!(unit.reserve(&tenant(), &ask()).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn the_root_units_key_target_reads_and_applies_through_the_router() {
    let s = Stores::new();
    let clients = s.clients();
    let router = Router {
        maintenance: Maintenance::Off,
        clients: &clients,
        heads: &s.heads,
        cache: &s.cache,
        clock: &s.clock,
    };
    let unit = RoutedUnit::new(&router);
    let keys = unit.keys(tenant());
    assert_eq!(keys.label(), "root");
    assert_eq!(keys.keys_seq().await.unwrap(), 0);
    assert_eq!(keys.closed().await.unwrap(), Vec::<String>::new());
    // A held principal at seq 1 (no private part): the unit holds it
    // closed.
    let held = ApplyEntry::Subject(entry("p_00000000000000a1", 1, None));
    assert_eq!(
        keys.apply(0, std::slice::from_ref(&held)).await.unwrap(),
        Applied::Done { keys_seq: 1 }
    );
    assert_eq!(keys.keys_seq().await.unwrap(), 1);
    assert_eq!(
        keys.closed().await.unwrap(),
        vec!["p_00000000000000a1".to_string()]
    );
    // A base above the unit's: behind, nothing applied.
    let next = ApplyEntry::Subject(entry("p_00000000000000a2", 5, Some(private())));
    assert_eq!(
        keys.apply(4, &[next]).await.unwrap(),
        Applied::Behind { keys_seq: 1 }
    );
    // A marker has no wire form yet: nothing is sent.
    let calls = s.log.borrow().len();
    assert!(keys
        .apply(1, &[ApplyEntry::Marker { seq: 2 }])
        .await
        .is_err());
    assert_eq!(s.log.borrow().len(), calls);
}

fn private() -> SubjectPrivate {
    SubjectPrivate {
        owner_ref: Some("member-9".into()),
        label: None,
        grants: vec![PrivateGrant {
            bucket_id: B1.into(),
            prefix: None,
            ip_list: vec![],
        }],
        secret_wrapped: None,
    }
}

fn entry(id: &str, seq: u64, private: Option<SubjectPrivate>) -> Entry {
    Entry {
        door: SubjectDoor {
            id: id.into(),
            kind: SubjectKind::Principal,
            status: ChainStatus::Active,
            made_by: None,
            grants: vec![DoorGrant {
                bucket_id: B1.into(),
                access: ChainAccess::Rw,
                expires_at: None,
            }],
            created_at: 1,
            secret_kek_version: None,
        },
        private,
        last_seq: seq,
        private_seq: seq,
        tk_version: 1,
        closes: false,
        opened_seq: seq,
        rid: None,
    }
}

#[test]
fn a_held_entry_is_sent_without_its_private_part() {
    let mut e = entry("k_held", 3, None);
    e.door.kind = SubjectKind::S3;
    e.door.secret_kek_version = Some(1);
    let w = unit_entry(&ApplyEntry::Subject(e.clone())).unwrap();
    assert!(w.held);
    assert_eq!(w.secret_wrapped, None);
    assert_eq!(w.secret_kek_version, None);
    assert_eq!(w.owner_ref, None);
    assert_eq!(w.grants.len(), 1);
    assert_eq!(w.grants[0].prefix, None);
    // Open: the private part's owner and limits travel.
    let mut p = private();
    p.grants[0].prefix = Some("docs/".into());
    p.secret_wrapped = Some(vec![9; 4]);
    e.private = Some(p);
    let w = unit_entry(&ApplyEntry::Subject(e.clone())).unwrap();
    assert!(!w.held);
    assert_eq!(w.secret_kek_version, Some(1));
    assert_eq!(w.secret_wrapped, Some(vec![9; 4]));
    assert_eq!(w.owner_ref.as_deref(), Some("member-9"));
    assert_eq!(w.grants[0].prefix.as_deref(), Some("docs/"));
    // A private part naming other buckets than the door is damage.
    let mut bad = e;
    bad.private.as_mut().unwrap().grants[0].bucket_id = B2.into();
    assert!(unit_entry(&ApplyEntry::Subject(bad)).is_err());
}

// ---------------------------------------------------------------------------
// KeyChain
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn the_key_chain_serves_its_own_tenant_and_reservation_only() {
    let s = Stores::new();
    let units = [Directory::default()];
    let env = KeyEnv {
        store: &s.records,
        kek: &s.kek,
        ring: &s.ring,
        tenant: &s.chain_tenant,
        admission: &NoAdmission,
        intents: &s.intents,
        units: &units,
        directory: &s.directory,
        clock: &s.clock,
        limits: Limits::NotServed,
        gate: &s.gate,
    };
    let chain = KeyChain::new(&env, TestRng(7));
    let other = TenantId::parse("t_0000000000000f02").unwrap();
    let rid = Rid([4; 16]);
    assert!(matches!(
        chain.carrying(&other, &rid, 0).await,
        Err(e) if e.to_string() == ERR_TENANT.to_string()
    ));
    assert!(chain.finish(&other, "p_x").await.is_err());
    // Nothing above 0 yet.
    assert_eq!(chain.carrying(&tenant(), &rid, 0).await.unwrap(), None);
    // A subject the head does not hold is not finished.
    assert_eq!(
        chain.finish(&tenant(), "p_00000000000000a1").await.unwrap(),
        ChainWrite::Busy
    );
    let p = NewPrincipal {
        id: "p_00000000000000a1".into(),
        owner_ref: NEW_OWNER.into(),
        grants: vec![],
        made_by: None,
        rid,
        seq: 1,
        created_at: NOW,
    };
    // An answer of another reservation is refused before any write.
    let wrong = UnitKept {
        rid: Rid([5; 16]),
        status: 201,
        body: "{}".into(),
    };
    assert!(chain.create(&tenant(), &p, &wrong).await.is_err());
    assert_eq!(s.chain_head(), 0);
    // A root unit that keeps no answer (the default `apply_kept`): the
    // record lands, the create is unfinished, and `carrying` finds it.
    let kept = UnitKept {
        rid,
        status: 201,
        body: "{}".into(),
    };
    assert_eq!(
        chain.create(&tenant(), &p, &kept).await.unwrap(),
        ChainWrite::Unfinished
    );
    assert_eq!(s.chain_head(), 1);
    let found = chain.carrying(&tenant(), &rid, 0).await.unwrap().unwrap();
    assert_eq!(found.id, p.id);
    assert_eq!(found.owner_ref, NEW_OWNER);
    // Another reservation's rid at that seq is not this call's.
    assert_eq!(
        chain.carrying(&tenant(), &Rid([6; 16]), 0).await.unwrap(),
        None
    );
    // The stores all hold it: finished.
    assert!(matches!(
        chain.finish(&tenant(), &p.id).await.unwrap(),
        ChainWrite::Done(r) if r.id == p.id
    ));
}

/// Rule 7: a listed root unit that is unborn pages "catalogue lost" for a
/// `live` tenant, and never while the head is `provisioning` (AM-58).
#[tokio::test(flavor = "current_thread")]
async fn an_unborn_root_unit_of_a_live_tenant_pages() {
    let unborn = Unit::new(RusqliteSql::open_in_memory().unwrap(), own(), "");
    let log = RefCell::new(Vec::new());
    let down = Cell::new(false);
    let clients = Direct {
        unit: &unborn,
        log: &log,
        down: &down,
    };
    let clock = FixedClock::new(NOW);
    for (lifecycle, alerts) in [
        (Lifecycle::Live, vec![RouteRefusal::CatalogueLost]),
        (Lifecycle::Provisioning, vec![]),
    ] {
        let heads = Heads::live();
        heads.with(|d| d.lifecycle = lifecycle);
        let cache = HeadCache::default();
        let router = Router {
            maintenance: Maintenance::Off,
            clients: &clients,
            heads: &heads,
            cache: &cache,
            clock: &clock,
        };
        let unit = RoutedUnit::new(&router);
        assert!(unit.keys(tenant()).keys_seq().await.is_err());
        assert_eq!(unit.take_alerts(), alerts, "{lifecycle:?}");
        assert!(unit.take_alerts().is_empty(), "taken once");
    }
}
