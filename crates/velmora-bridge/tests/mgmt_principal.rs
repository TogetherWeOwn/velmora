#![cfg(feature = "testkit")]
//! Principal create (`POST /v1/tenants/{t}/principals`) from the gate to
//! its answer, against the real root unit (L1's reservation, on the
//! native database) and a key chain that applies its records to that
//! unit, as L4's writer does (ADR §2.5, §6.2, §6.4; AM-35, AM-36, AM-38).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use futures_util::StreamExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use velmora::rng::FillRandom;
use velmora_bridge::mgmt::principal::{
    refusal, reserve_answer, ChainWrite, DoorState, NewPrincipal, PrincipalChain,
    PrincipalHandlers, PrincipalPorts, RecordedPrincipal, ReserveAnswer, RootUnit, TenantDoor,
    CAP_RETRY_AFTER_SECS, MAX_ASKS,
};
use velmora_bridge::mgmt::serve::{serve_with, Answer, MgmtRequest};
use velmora_bridge::mgmt::token::{DisabledTokens, TokenHashes};
use velmora_bridge::testkit::{MemBlobStore, RusqliteSql};
use velmora_bridge::types::Body;
use velmora_bridge::unit::keys::{Access, KeptAnswer, KeyEntry, KeyGrant, KeyKind, SubjectStatus};
use velmora_bridge::unit::reserve::{PrincipalView, ReserveRefusal, Rid, CHANGES_PER_HOUR};
use velmora_bridge::unit::{
    BirthKind, BirthToken, CallKind, Refused, Seqs, SyncHead, TenantId, TenantState, Unit,
    UnitAnswer, UnitCall, UnitName, UnitOp,
};
use velmora_bridge::unit_lease::lease::Proven;
use velmora_bridge::{BridgeError, Result, UnixMs};

const NOW: UnixMs = UnixMs(1_795_000_000_000);
const TENANT: &str = "t_0000000000000f01";
const B1: &str = "b_00000000000000f1";
const B2: &str = "b_00000000000000f2";
/// Placed nowhere.
const B3: &str = "b_00000000000000f3";
/// The acting principal: `rw` on B1, `ro` on B2.
const P: &str = "p_member";
const OWNER: &str = "member-1";
const NEW_OWNER: &str = "usr_01JD2Q9A7M";
const KEY: &str = "ws_01JD2Q8V5X/usr_01JD2Q9A7M";

const STANDARD: &str = "std-token-0123456789abcdef0123456789abcdef";
const CONFIRMED: &str = "conf-token-0123456789abcdef0123456789abcdef";

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

fn tenant() -> TenantId {
    TenantId::parse(TENANT).unwrap()
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

/// One Worker call at `now`, as the Worker makes it under rule 12: an
/// answer `renew_needed` (the lease ran out, or none was taken yet) is
/// followed by a renewal at `now` and the same call once more.
fn at(u: &Unit<RusqliteSql>, c: &UnitCall, now: UnixMs) -> UnitAnswer {
    match u.handle(c, now) {
        UnitAnswer::RenewNeeded { why: None, .. } => {
            renew(u, now);
            u.handle(c, now)
        }
        a => a,
    }
}

/// The Worker's renewal at `now` (rule 12): the lease then holds for T.
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

fn grant(bucket: &str, access: Access) -> KeyGrant {
    KeyGrant {
        bucket_id: bucket.into(),
        access,
        expires_at: None,
        prefix: None,
        ip_list: vec![],
    }
}

fn entry(p: &RecordedPrincipal, seq: u64, rid: Option<Rid>, made_by: Option<String>) -> KeyEntry {
    KeyEntry {
        id: p.id.clone(),
        kind: KeyKind::Principal,
        status: p.status,
        held: false,
        made_by,
        grants: p.grants.clone(),
        created_at: 1,
        secret_wrapped: None,
        secret_kek_version: None,
        owner_ref: Some(p.owner_ref.clone()),
        last_seq: seq,
        rid,
    }
}

fn unit_keys_seq(u: &Unit<RusqliteSql>) -> u64 {
    u.head().unwrap().seqs.keys_seq
}

fn sync(u: &Unit<RusqliteSql>, state: TenantState) {
    let h = u.head().unwrap();
    let a = at(
        u,
        &worker_call(UnitOp::Sync {
            head: SyncHead {
                seqs: Seqs {
                    state_seq: h.seqs.state_seq + 1,
                    keys_seq: h.seqs.keys_seq,
                },
                tenant_mode: (state == TenantState::Suspended)
                    .then_some(velmora_bridge::unit::call::HoldMode::ReadOnly),
                tenant_state: state,
                restoring_since: None,
                lift: None,
            },
        }),
        NOW,
    );
    assert!(matches!(a, UnitAnswer::Ok { .. }), "{a:?}");
}

/// A born, active managed unit holding B1, with the acting principal at
/// key-chain seq 1.
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
    sync(&u, TenantState::Active);
    u.sql()
        .apply(&format!(
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
               VALUES ('{B1}', 'alpha', 'o', x'02', 1, 1);"
        ))
        .unwrap();
    u
}

/// A bucket row on the unit (the unit refuses a grant on an id it holds
/// no row for, AM-61, before any reservation).
fn add_bucket(u: &Unit<RusqliteSql>, id: &str, name: &str) {
    u.sql()
        .apply(&format!(
            "INSERT INTO buckets(id, name, owner, bdk_wrapped, kek_version, created_at) \
               VALUES ('{id}', '{name}', 'o', x'02', 1, 1);"
        ))
        .unwrap();
}

// ---------------------------------------------------------------------------
// Fakes of the ports
// ---------------------------------------------------------------------------

struct Door {
    state: Cell<Option<DoorState>>,
    buckets: RefCell<BTreeMap<String, String>>,
    down: Cell<bool>,
}

impl Door {
    fn new() -> Door {
        Door {
            state: Cell::new(Some(DoorState::Open)),
            buckets: RefCell::new(
                [(B1, "alpha"), (B2, "beta")]
                    .into_iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect(),
            ),
            down: Cell::new(false),
        }
    }
}

fn down() -> BridgeError {
    BridgeError::Sql("store down".into())
}

impl TenantDoor for Door {
    async fn state(&self, t: &TenantId) -> Result<Option<DoorState>> {
        if self.down.get() {
            return Err(down());
        }
        Ok((t.as_str() == TENANT).then(|| self.state.get()).flatten())
    }

    async fn bucket_names(&self, _t: &TenantId, ids: &[String]) -> Result<Vec<Option<String>>> {
        if self.down.get() {
            return Err(down());
        }
        Ok(ids
            .iter()
            .map(|id| self.buckets.borrow().get(id).cloned())
            .collect())
    }
}

/// The real unit behind the port, as L6's router and L2's client would
/// reach it.
struct Root<'a> {
    unit: &'a Unit<RusqliteSql>,
    now: Cell<UnixMs>,
    down: Cell<bool>,
    asks: RefCell<Vec<UnitOp>>,
    releases: Cell<u32>,
}

impl<'a> Root<'a> {
    fn new(unit: &'a Unit<RusqliteSql>) -> Root<'a> {
        Root {
            unit,
            now: Cell::new(NOW),
            down: Cell::new(false),
            asks: RefCell::new(Vec::new()),
            releases: Cell::new(0),
        }
    }
}

impl RootUnit for Root<'_> {
    async fn reserve(&self, _t: &TenantId, op: &UnitOp) -> Result<ReserveAnswer> {
        if self.down.get() {
            return Err(down());
        }
        self.asks.borrow_mut().push(op.clone());
        Ok(reserve_answer(&at(
            self.unit,
            &worker_call(op.clone()),
            self.now.get(),
        )))
    }

    async fn release(&self, _t: &TenantId, rid: &Rid) -> Result<()> {
        self.releases.set(self.releases.get() + 1);
        at(
            self.unit,
            &worker_call(UnitOp::Release { rid: *rid }),
            self.now.get(),
        );
        Ok(())
    }
}

#[derive(Clone)]
struct Record {
    seq: u64,
    rid: Option<Rid>,
    made_by: Option<String>,
    principal: RecordedPrincipal,
}

/// The key chain: records in memory; the stores are the unit (the root
/// unit, the door store of an opening change once the directory acked).
struct Chain<'a> {
    unit: &'a Unit<RusqliteSql>,
    records: RefCell<Vec<Record>>,
    /// The highest seq the unit holds in full (open).
    open_upto: Cell<u64>,
    /// The directory cannot be reached: the units get new records held
    /// closed only (AM-9), and nothing is in force.
    directory_down: Cell<bool>,
    /// The next create writes its record and stops before the stores.
    crash_after_record: Cell<bool>,
    /// Records another call puts first, one per create, before its put.
    races: RefCell<Vec<RecordedPrincipal>>,
    /// The next create is refused before any record.
    refuse: Cell<Option<velmora_mgmt_types::Code>>,
    /// The next create cannot record now (nothing written).
    busy: Cell<bool>,
    /// The create after the next one is refused before any record.
    refuse_second: Cell<Option<velmora_mgmt_types::Code>>,
    /// The chain cannot be read.
    unreadable: Cell<bool>,
    creates: Cell<u32>,
}

impl<'a> Chain<'a> {
    fn new(unit: &'a Unit<RusqliteSql>) -> Chain<'a> {
        let chain = Chain {
            unit,
            records: RefCell::new(Vec::new()),
            open_upto: Cell::new(0),
            directory_down: Cell::new(false),
            crash_after_record: Cell::new(false),
            races: RefCell::new(Vec::new()),
            refuse: Cell::new(None),
            busy: Cell::new(false),
            refuse_second: Cell::new(None),
            unreadable: Cell::new(false),
            creates: Cell::new(0),
        };
        // Seq 1: the acting principal.
        chain.push(
            RecordedPrincipal {
                id: P.into(),
                owner_ref: OWNER.into(),
                status: SubjectStatus::Active,
                grants: vec![grant(B1, Access::Rw), grant(B2, Access::Ro)],
            },
            None,
            None,
        );
        assert!(chain.bring_up(&[]));
        chain
    }

    fn head(&self) -> u64 {
        self.records.borrow().last().map_or(0, |r| r.seq)
    }

    fn push(&self, p: RecordedPrincipal, rid: Option<Rid>, made_by: Option<String>) -> u64 {
        let seq = self.head() + 1;
        self.records.borrow_mut().push(Record {
            seq,
            rid,
            made_by,
            principal: p,
        });
        seq
    }

    fn apply(&self, from_seq: u64, held: bool, answers: &[KeptAnswer]) {
        let entries: Vec<velmora_bridge::unit::keys::ApplyEntry> = self
            .records
            .borrow()
            .iter()
            .filter(|r| r.seq > from_seq)
            .map(|r| {
                let mut e = entry(&r.principal, r.seq, r.rid, r.made_by.clone());
                e.held = held;
                velmora_bridge::unit::keys::ApplyEntry::Key(e)
            })
            .collect();
        if entries.is_empty() {
            return;
        }
        let a = at(
            self.unit,
            &worker_call(UnitOp::ApplyKeys {
                from_seq,
                entries,
                answers: answers.to_vec(),
            }),
            NOW,
        );
        assert!(matches!(a, UnitAnswer::Ok { .. }), "apply: {a:?}");
    }

    /// The writer's bring-up: the units get every record (held closed
    /// while the directory is down), then, once the directory has them,
    /// the units in full with the answers. `true`: in force everywhere.
    fn bring_up(&self, answers: &[KeptAnswer]) -> bool {
        self.apply(unit_keys_seq(self.unit), true, &[]);
        if self.directory_down.get() {
            return false;
        }
        self.apply(self.open_upto.get(), false, answers);
        self.open_upto.set(self.head());
        true
    }

    /// A grant change of the acting principal: it also holds `ro` on B3,
    /// which no bucket is.
    fn acting_holds_b3(&self) {
        self.push(
            RecordedPrincipal {
                id: P.into(),
                owner_ref: OWNER.into(),
                status: SubjectStatus::Active,
                grants: vec![
                    grant(B1, Access::Rw),
                    grant(B2, Access::Ro),
                    grant(B3, Access::Ro),
                ],
            },
            None,
            None,
        );
        assert!(self.bring_up(&[]));
    }

    fn count(&self, owner_ref: &str) -> usize {
        self.records
            .borrow()
            .iter()
            .filter(|r| r.principal.owner_ref == owner_ref)
            .count()
    }
}

impl PrincipalChain for Chain<'_> {
    async fn carrying(
        &self,
        _t: &TenantId,
        rid: &Rid,
        above: u64,
    ) -> Result<Option<RecordedPrincipal>> {
        if self.unreadable.get() {
            return Err(down());
        }
        Ok(self
            .records
            .borrow()
            .iter()
            .find(|r| r.seq > above && r.rid == Some(*rid))
            .map(|r| r.principal.clone()))
    }

    async fn finish(&self, _t: &TenantId, id: &str) -> Result<ChainWrite> {
        if self.unreadable.get() {
            return Err(down());
        }
        let Some(p) = self
            .records
            .borrow()
            .iter()
            .rev()
            .find(|r| r.principal.id == id)
            .map(|r| r.principal.clone())
        else {
            return Ok(ChainWrite::Busy);
        };
        Ok(match self.bring_up(&[]) {
            true => ChainWrite::Done(p),
            false => ChainWrite::Unfinished,
        })
    }

    async fn create(
        &self,
        t: &TenantId,
        p: &NewPrincipal,
        answer: &KeptAnswer,
    ) -> Result<ChainWrite> {
        self.creates.set(self.creates.get() + 1);
        if let Some(code) = self.refuse.take() {
            return Ok(ChainWrite::Refused(code));
        }
        if self.busy.take() {
            return Ok(ChainWrite::Busy);
        }
        if self.creates.get() == 2 {
            if let Some(code) = self.refuse_second.take() {
                return Ok(ChainWrite::Refused(code));
            }
        }
        if let Some(other) = self.races.borrow_mut().pop() {
            self.push(other, None, None);
        }
        if p.seq != self.head() + 1 {
            // Lost: to a record of this reservation, or to another.
            if let Some(own) = self.carrying(t, &p.rid, p.seq - 1).await? {
                return Ok(match self.bring_up(&[]) {
                    true => ChainWrite::Done(own),
                    false => ChainWrite::Unfinished,
                });
            }
            // The writer brings the stores to the head before it asks
            // again.
            self.bring_up(&[]);
            return Ok(ChainWrite::Lost);
        }
        let recorded = RecordedPrincipal {
            id: p.id.clone(),
            owner_ref: p.owner_ref.clone(),
            status: SubjectStatus::Active,
            grants: p.grants.clone(),
        };
        self.push(recorded.clone(), Some(p.rid), p.made_by.clone());
        if self.crash_after_record.take() {
            return Ok(ChainWrite::Unfinished);
        }
        Ok(match self.bring_up(std::slice::from_ref(answer)) {
            true => ChainWrite::Done(recorded),
            false => ChainWrite::Unfinished,
        })
    }
}

/// Counts up from a seed: every draw is new and known.
struct Counter(Cell<u8>);

impl FillRandom for Counter {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> velmora::error::Result<()> {
        let n = self.0.get().wrapping_add(1);
        self.0.set(n);
        dest.fill(n);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

struct World<'a> {
    door: Door,
    root: Root<'a>,
    chain: Chain<'a>,
    rng: RefCell<Counter>,
}

impl<'a> World<'a> {
    fn new(unit: &'a Unit<RusqliteSql>) -> World<'a> {
        World {
            door: Door::new(),
            root: Root::new(unit),
            chain: Chain::new(unit),
            rng: RefCell::new(Counter(Cell::new(0))),
        }
    }

    async fn send(
        &self,
        token: &str,
        acting: Option<&str>,
        key: Option<&str>,
        body: &str,
    ) -> Answer {
        self.send_to(
            &format!("/v1/tenants/{TENANT}/principals"),
            token,
            acting,
            key,
            body,
        )
        .await
    }

    async fn send_to(
        &self,
        path: &str,
        token: &str,
        acting: Option<&str>,
        key: Option<&str>,
        body: &str,
    ) -> Answer {
        let bytes = body.as_bytes().to_vec();
        let body = Body::Stream {
            declared_len: Some(bytes.len() as u64),
            stream: futures_util::stream::iter(vec![Ok(bytes)]).boxed_local(),
        };
        self.send_body(path, token, acting, key, body).await
    }

    async fn send_body(
        &self,
        path: &str,
        token: &str,
        acting: Option<&str>,
        key: Option<&str>,
        body: Body,
    ) -> Answer {
        let handlers = PrincipalHandlers {
            ports: PrincipalPorts {
                door: &self.door,
                unit: &self.root,
                chain: &self.chain,
                rng: &self.rng,
            },
        };
        let disabled = RefCell::new(DisabledTokens::default());
        let authorization = format!("Bearer {token}");
        let req = MgmtRequest {
            method: "POST",
            path,
            query: "",
            authorization: Some(&authorization),
            acting,
            idempotency_key: key,
        };
        serve_with(
            &disabled,
            &hashes(),
            &MemBlobStore::new(),
            &handlers,
            req,
            body,
            NOW,
        )
        .await
    }
}

fn json_of(a: &Answer) -> Value {
    serde_json::from_str(a.json.as_deref().expect("a JSON answer")).unwrap()
}

fn expect_code(a: &Answer, status: u16, code: &str, retry_after: Option<u32>) {
    assert_eq!(
        (a.status, a.code, a.retry_after),
        (status, code, retry_after),
        "{a:?}"
    );
    assert!(a.json.is_none());
    assert_eq!(a.body(), format!("{{\"code\":\"{code}\"}}"));
}

fn signup() -> String {
    json!({"owner_ref": NEW_OWNER, "grants": []}).to_string()
}

fn with_grants(grants: Value) -> String {
    json!({"owner_ref": NEW_OWNER, "grants": grants}).to_string()
}

fn reservations(u: &Unit<RusqliteSql>) -> Vec<(String, Option<String>)> {
    u.sql()
        .with_conn(|c| {
            let mut s = c
                .prepare(
                    "SELECT state, answer_body FROM unit_reservations ORDER BY reserved_at, rid",
                )
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

fn unit_principal(u: &Unit<RusqliteSql>, owner_ref: &str) -> Option<(String, String)> {
    u.sql()
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

// ---------------------------------------------------------------------------
// Sign-up
// ---------------------------------------------------------------------------

/// The sign-up create: no acting header, no grant. `201` with the
/// principal, once the unit holds it; the same request again answers the
/// kept answer and writes nothing.
#[tokio::test(flavor = "current_thread")]
async fn sign_up_creates_the_principal_and_a_retry_answers_the_kept_answer() {
    let u = ready();
    let w = World::new(&u);
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    assert_eq!(
        (a.status, a.code, a.retry_after),
        (201, "ok", None),
        "{a:?}"
    );
    let p = json_of(&a);
    let id = p["id"].as_str().unwrap().to_string();
    // `p_` and 8 random bytes as hex, as the contract's example.
    assert!(id.starts_with("p_") && id.len() == 18, "{id}");
    assert_eq!(
        p,
        json!({"id": id, "owner_ref": NEW_OWNER, "status": "active", "grants": []})
    );
    // The contract crate reads it as a `Principal`.
    let _: velmora_mgmt_types::wire::Principal = serde_json::from_value(p.clone()).unwrap();
    assert_eq!(
        unit_principal(&u, NEW_OWNER),
        Some((id.clone(), "active".into()))
    );
    assert_eq!(w.chain.head(), 2);
    assert_eq!(reservations(&u), vec![("applied".into(), Some(a.body()))]);

    let again = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    assert_eq!(again, a);
    assert_eq!(w.chain.head(), 2, "a retry writes no record");
    assert_eq!(w.chain.creates.get(), 1);
}

/// The record carries the reservation's `rid` and the record is exactly
/// the reservation's `keys_seq + 1`.
#[tokio::test(flavor = "current_thread")]
async fn the_record_carries_the_rid_at_keys_seq_plus_one() {
    let u = ready();
    let w = World::new(&u);
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    assert_eq!(a.status, 201);
    let asks = w.root.asks.borrow();
    let UnitOp::Reserve { rid, acting, .. } = &asks[0] else {
        panic!("not an ask");
    };
    assert_eq!(*acting, None);
    let records = w.chain.records.borrow();
    assert_eq!(records[1].seq, 2);
    assert_eq!(records[1].rid, Some(*rid));
    assert_eq!(records[1].made_by, None);
}

/// Same key, another request: `422`, no reservation, no record.
#[tokio::test(flavor = "current_thread")]
async fn the_key_with_another_request_is_refused() {
    let u = ready();
    let w = World::new(&u);
    assert_eq!(
        w.send(CONFIRMED, None, Some(KEY), &signup()).await.status,
        201
    );
    let other = json!({"owner_ref": "usr_other", "grants": []}).to_string();
    let a = w.send(CONFIRMED, None, Some(KEY), &other).await;
    expect_code(&a, 422, "idempotency_key_reused", None);
    assert_eq!(w.chain.head(), 2);
    assert!(unit_principal(&u, "usr_other").is_none());
}

/// A principal for the `owner_ref` exists (another key): `200` with it
/// when the grants are equal as a set, `409 principal_exists` otherwise
/// (AM-36). Nothing is written either way.
#[tokio::test(flavor = "current_thread")]
async fn an_existing_principal_is_answered_or_refused_by_its_grants() {
    let u = ready();
    let w = World::new(&u);
    let first = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    let id = json_of(&first)["id"].as_str().unwrap().to_string();

    let found = w
        .send(CONFIRMED, None, Some("other-key-1"), &signup())
        .await;
    assert_eq!(found.status, 200, "{found:?}");
    assert_eq!(json_of(&found)["id"], id.as_str());
    assert_eq!(json_of(&found)["grants"], json!([]));

    let wider = with_grants(json!([{"bucket_id": B1, "access": "ro"}]));
    let a = w
        .send(CONFIRMED, Some(OWNER), Some("other-key-2"), &wider)
        .await;
    expect_code(&a, 409, "principal_exists", None);
    assert_eq!(w.chain.head(), 2);
    assert_eq!(w.chain.count(NEW_OWNER), 1);
}

/// The grants of an existing principal are named by the head.
#[tokio::test(flavor = "current_thread")]
async fn an_existing_principal_with_grants_is_named() {
    let u = ready();
    let w = World::new(&u);
    let body = json!({"owner_ref": OWNER, "grants": [
        {"bucket_id": B2, "access": "ro"}, {"bucket_id": B1, "access": "rw"}]})
    .to_string();
    let a = w.send(CONFIRMED, Some(OWNER), Some(KEY), &body).await;
    assert_eq!(a.status, 200, "{a:?}");
    let p = json_of(&a);
    assert_eq!(p["id"], P);
    let mut grants = p["grants"].as_array().unwrap().clone();
    grants.sort_by_key(|g| g["bucket_id"].as_str().unwrap().to_string());
    assert_eq!(
        grants,
        vec![
            json!({"bucket_id": B1, "bucket_name": "alpha", "access": "rw"}),
            json!({"bucket_id": B2, "bucket_name": "beta", "access": "ro"}),
        ]
    );
}

// ---------------------------------------------------------------------------
// With an acting member
// ---------------------------------------------------------------------------

/// With the acting header, every grant must be the acting principal's
/// (the subset rule): `201`, made by that principal.
#[tokio::test(flavor = "current_thread")]
async fn a_member_creates_a_principal_within_its_own_grants() {
    let u = ready();
    let w = World::new(&u);
    let body = with_grants(json!([{"bucket_id": B1, "access": "rw"}]));
    let a = w.send(CONFIRMED, Some(OWNER), Some(KEY), &body).await;
    assert_eq!(a.status, 201, "{a:?}");
    assert_eq!(
        json_of(&a)["grants"],
        json!([{"bucket_id": B1, "bucket_name": "alpha", "access": "rw"}])
    );
    assert_eq!(w.chain.records.borrow()[1].made_by.as_deref(), Some(P));
}

#[tokio::test(flavor = "current_thread")]
async fn grants_outside_the_acting_principals_are_refused_with_no_row() {
    let u = ready();
    add_bucket(&u, B2, "beta");
    let w = World::new(&u);
    let body = with_grants(json!([{"bucket_id": B2, "access": "rw"}]));
    let a = w.send(CONFIRMED, Some(OWNER), Some(KEY), &body).await;
    expect_code(&a, 403, "grant_not_held", None);
    assert!(reservations(&u).is_empty());
    assert_eq!(w.chain.head(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn an_unknown_acting_member_is_refused() {
    let u = ready();
    let w = World::new(&u);
    let body = with_grants(json!([{"bucket_id": B1, "access": "ro"}]));
    let a = w.send(CONFIRMED, Some("nobody"), Some(KEY), &body).await;
    expect_code(&a, 403, "acting_principal_unknown", None);
}

/// A grant on a bucket id the head does not place, even one the acting
/// principal holds (an orphan creator grant on a derived id): `404`, and
/// the reservation is given back.
#[tokio::test(flavor = "current_thread")]
async fn a_grant_on_a_bucket_that_is_not_placed_is_refused_with_no_row() {
    let u = ready();
    // The unit holds a row, so its own check passes; the head does not
    // place the id, so the handler's does not.
    add_bucket(&u, B3, "gamma");
    let w = World::new(&u);
    w.chain.acting_holds_b3();
    let body = with_grants(json!([{"bucket_id": B3, "access": "ro"}]));
    let a = w.send(CONFIRMED, Some(OWNER), Some(KEY), &body).await;
    expect_code(&a, 404, "bucket_not_found", None);
    assert_eq!(w.root.asks.borrow().len(), 1);
    assert_eq!(w.root.releases.get(), 1);
    assert!(reservations(&u).is_empty());
    assert_eq!(w.chain.count(NEW_OWNER), 0);
}

/// A grant on an id the unit holds no row for: the unit refuses it before
/// any reservation (AM-61), so nothing is given back.
#[tokio::test(flavor = "current_thread")]
async fn a_grant_on_an_id_with_no_unit_row_is_refused_before_a_reservation() {
    let u = ready();
    let w = World::new(&u);
    w.chain.acting_holds_b3();
    let body = with_grants(json!([{"bucket_id": B3, "access": "ro"}]));
    let a = w.send(CONFIRMED, Some(OWNER), Some(KEY), &body).await;
    expect_code(&a, 404, "bucket_not_found", None);
    assert_eq!(w.root.asks.borrow().len(), 1);
    assert_eq!(w.root.releases.get(), 0);
    assert!(reservations(&u).is_empty());
    assert_eq!(w.chain.count(NEW_OWNER), 0);
}

// ---------------------------------------------------------------------------
// The body and the headers
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn bodies_that_are_not_a_create_are_refused_before_the_ask() {
    let u = ready();
    let w = World::new(&u);
    let limited = with_grants(json!([{"bucket_id": B1, "access": "ro", "prefix": "a/"}]));
    let cases: [(&str, Option<&str>, u16, &str); 6] = [
        // Grants need the acting header (AM-36).
        (
            &with_grants(json!([{"bucket_id": B1, "access": "ro"}])),
            None,
            400,
            "bad_request",
        ),
        (&limited, Some(OWNER), 400, "grant_limits_not_served"),
        ("{\"owner_ref\": \"u\"}", None, 400, "bad_request"),
        (
            "{\"owner_ref\": \"u\", \"grants\": [], \"role\": \"admin\"}",
            None,
            400,
            "bad_request",
        ),
        ("not json", None, 400, "bad_request"),
        (
            "{\"owner_ref\": \"a b\", \"grants\": []}",
            None,
            400,
            "bad_request",
        ),
    ];
    for (body, acting, status, code) in cases {
        let a = w.send(CONFIRMED, acting, Some(KEY), body).await;
        expect_code(&a, status, code, None);
    }
    assert!(w.root.asks.borrow().is_empty());
}

/// The body is read at most to 16 KiB: a declared length above it is
/// refused before the stream is polled, and a stream with no length is
/// refused at the chunk that crosses it, before the next one is polled.
/// The body would otherwise be a valid create padded with whitespace.
#[tokio::test(flavor = "current_thread")]
async fn a_body_over_16_kib_is_refused_without_reading_on() {
    let u = ready();
    let w = World::new(&u);
    let path = format!("/v1/tenants/{TENANT}/principals");
    let never = || -> Result<Vec<u8>> { panic!("polled past the limit") };
    let declared = Body::Stream {
        declared_len: Some(16 * 1024 + 1),
        stream: futures_util::stream::iter(std::iter::from_fn(move || Some(never()))).boxed_local(),
    };
    let a = w
        .send_body(&path, CONFIRMED, None, Some(KEY), declared)
        .await;
    expect_code(&a, 400, "bad_request", None);

    let head = br#"{"owner_ref": "usr_1", "grants": []"#.to_vec();
    let chunks: Vec<Result<Vec<u8>>> =
        vec![Ok(head), Ok(vec![b' '; 8 * 1024]), Ok(vec![b' '; 8 * 1024])];
    let streamed = Body::Stream {
        declared_len: None,
        stream: futures_util::stream::iter(chunks)
            .chain(futures_util::stream::iter(std::iter::from_fn(move || {
                Some(never())
            })))
            .boxed_local(),
    };
    let a = w
        .send_body(&path, CONFIRMED, None, Some(KEY), streamed)
        .await;
    expect_code(&a, 400, "bad_request", None);

    // The same body under the limit is a create.
    let mut ok = br#"{"owner_ref": "usr_1", "grants": []"#.to_vec();
    ok.extend(vec![b' '; 16 * 1024 - ok.len() - 1]);
    ok.push(b'}');
    let fits = Body::Stream {
        declared_len: None,
        stream: futures_util::stream::iter(vec![Ok(ok)]).boxed_local(),
    };
    let a = w.send_body(&path, CONFIRMED, None, Some(KEY), fits).await;
    assert_eq!(a.status, 201, "{a:?}");
    assert_eq!(w.root.asks.borrow().len(), 1);
}

/// The standard token never creates a principal (`principals:write` is
/// the confirmed token's); a write needs its key.
#[tokio::test(flavor = "current_thread")]
async fn the_gate_and_the_checks_run_first() {
    let u = ready();
    let w = World::new(&u);
    let a = w.send(STANDARD, None, Some(KEY), &signup()).await;
    expect_code(&a, 403, "insufficient_scope", None);
    let a = w.send(CONFIRMED, None, None, &signup()).await;
    expect_code(&a, 400, "idempotency_key_required", None);
    assert!(w.root.asks.borrow().is_empty());
}

// ---------------------------------------------------------------------------
// The tenant
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn the_tenant_state_answers_before_or_through_the_unit() {
    let u = ready();
    let w = World::new(&u);
    let other = "/v1/tenants/t_0000000000000f02/principals";
    let a = w
        .send_to(other, CONFIRMED, None, Some(KEY), &signup())
        .await;
    expect_code(&a, 404, "tenant_not_found", None);

    w.door.state.set(Some(DoorState::Restoring));
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 409, "tenant_restoring", Some(5));

    w.door.state.set(Some(DoorState::Provisioning));
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 503, "service_unavailable", Some(5));
    assert!(w.root.asks.borrow().is_empty());

    // Suspended `read_only`: the unit refuses the opening ask.
    sync(&u, TenantState::Suspended);
    w.door.state.set(Some(DoorState::ReadOnly));
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 409, "tenant_read_only", None);
    // A deleting tenant.
    w.door.state.set(Some(DoorState::Unavailable));
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 409, "tenant_unavailable", None);
    assert!(reservations(&u).is_empty());
    assert_eq!(w.chain.head(), 1);
}

// ---------------------------------------------------------------------------
// Crashes, races and stores that cannot be reached
// ---------------------------------------------------------------------------

/// The record is written and the stores are not: `503`. A retry finds its
/// own reservation and a record that carries its `rid`: `409
/// idempotency_key_in_use` with `Retry-After: 30`, and no second record.
/// Once the finisher applied it (with no answer kept), a retry answers
/// `201` with the principal as the chain holds it.
#[tokio::test(flavor = "current_thread")]
async fn a_create_that_stopped_after_its_record_is_finished_not_repeated() {
    let u = ready();
    let w = World::new(&u);
    w.chain.crash_after_record.set(true);
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 503, "service_unavailable", Some(5));
    assert_eq!(w.chain.head(), 2);
    assert!(unit_principal(&u, NEW_OWNER).is_none());

    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 409, "idempotency_key_in_use", Some(30));
    assert_eq!(w.chain.head(), 2);
    assert_eq!(w.chain.creates.get(), 1);

    // The finisher applies the record; it keeps no answer.
    assert!(w.chain.bring_up(&[]));
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    assert_eq!(a.status, 201, "{a:?}");
    let id = w.chain.records.borrow()[1].principal.id.clone();
    assert_eq!(
        json_of(&a),
        json!({"id": id, "owner_ref": NEW_OWNER, "status": "active", "grants": []})
    );
    assert_eq!(w.chain.head(), 2);
}

/// A retry asked again before any record keeps the first `rid` and the
/// first principal id, whatever it drew itself.
#[tokio::test(flavor = "current_thread")]
async fn a_reask_keeps_the_first_rid_and_subject() {
    let u = ready();
    let w = World::new(&u);
    // The first call is refused by the chain after its ask, with no
    // record, and gives its slot back.
    w.chain
        .refuse
        .set(Some(velmora_mgmt_types::Code::TenantUnavailable));
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 409, "tenant_unavailable", None);
    assert_eq!(w.root.releases.get(), 1);
    assert!(reservations(&u).is_empty());

    // Another try that loses its first put to another record: asked
    // again at the new head with the same rid and subject.
    w.chain.races.borrow_mut().push(RecordedPrincipal {
        id: "p_other".into(),
        owner_ref: "other-1".into(),
        status: SubjectStatus::Active,
        grants: vec![],
    });
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    assert_eq!(a.status, 201, "{a:?}");
    let asks = w.root.asks.borrow();
    let (UnitOp::Reserve { rid: r1, .. }, UnitOp::Reserve { rid: r2, .. }) = (&asks[1], &asks[2])
    else {
        panic!("asks");
    };
    assert_ne!(r1, r2, "every ask draws a rid");
    let rec = w.chain.records.borrow()[2].clone();
    assert_eq!(rec.seq, 3);
    assert_eq!(rec.rid, Some(*r1), "the first rid is kept");
    assert_eq!(json_of(&a)["id"], rec.principal.id.as_str());
}

/// Every put lost: `503` after [`MAX_ASKS`] asks, and the reservation is
/// kept for the retry.
#[tokio::test(flavor = "current_thread")]
async fn puts_lost_every_time_answer_503() {
    let u = ready();
    let w = World::new(&u);
    for i in 0..MAX_ASKS {
        w.chain.races.borrow_mut().push(RecordedPrincipal {
            id: format!("p_other{i}"),
            owner_ref: format!("other-{i}"),
            status: SubjectStatus::Active,
            grants: vec![],
        });
    }
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 503, "service_unavailable", Some(5));
    assert_eq!(w.root.asks.borrow().len(), MAX_ASKS as usize);
    assert_eq!(w.chain.count(NEW_OWNER), 0);
    assert_eq!(reservations(&u).len(), 1);
    // The retry finishes it.
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    assert_eq!(a.status, 201, "{a:?}");
    assert_eq!(w.chain.count(NEW_OWNER), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn a_store_that_cannot_be_reached_answers_503_and_keeps_nothing() {
    let u = ready();
    let w = World::new(&u);
    w.door.down.set(true);
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 503, "service_unavailable", Some(5));
    w.door.down.set(false);
    w.root.down.set(true);
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 503, "service_unavailable", Some(5));
    assert!(reservations(&u).is_empty());
    assert_eq!(w.chain.head(), 1);
}

/// The cap of creates per hour (ADR §6.3): `429 cap_reached` with
/// `Retry-After`.
#[tokio::test(flavor = "current_thread")]
async fn the_hourly_cap_answers_429() {
    let u = ready();
    let w = World::new(&u);
    for i in 0..CHANGES_PER_HOUR {
        let body = json!({"owner_ref": format!("usr_{i}"), "grants": []}).to_string();
        let a = w
            .send(CONFIRMED, None, Some(&format!("key-{i}")), &body)
            .await;
        assert_eq!(a.status, 201, "{i}: {a:?}");
    }
    let a = w.send(CONFIRMED, None, Some("key-last"), &signup()).await;
    expect_code(&a, 429, "cap_reached", Some(CAP_RETRY_AFTER_SECS));
}

// ---------------------------------------------------------------------------
// The unit's answer, read
// ---------------------------------------------------------------------------

fn ok(body: Value) -> UnitAnswer {
    UnitAnswer::Ok {
        seqs: Seqs {
            state_seq: 1,
            keys_seq: 1,
        },
        body,
    }
}

#[test]
fn the_units_answers_are_read() {
    let rid = Rid([0xab; 16]);
    let hex = "ab".repeat(16);
    assert_eq!(
        reserve_answer(&ok(
            json!({"admitted": {"rid": hex, "keys_seq": 4, "again": true,
            "scope": "p_1", "bound": null, "subject": "p_2", "unit": null}})
        )),
        ReserveAnswer::Admitted {
            rid,
            keys_seq: 4,
            again: true,
            scope: Some("p_1".into()),
            subject: Some("p_2".into()),
        }
    );
    assert_eq!(
        reserve_answer(&ok(json!({"applied": {"status": 201, "body": "{}",
            "subject": "p_2", "bucket": null, "grant_seq": null}}))),
        ReserveAnswer::Applied {
            status: Some(201),
            body: Some("{}".into()),
            subject: Some("p_2".into()),
        }
    );
    assert_eq!(
        reserve_answer(&ok(json!({"reused": true}))),
        ReserveAnswer::Reused
    );
    assert_eq!(
        reserve_answer(&ok(json!({"not_open": {"rid": hex, "keys_seq": 2}}))),
        ReserveAnswer::NotOpen { rid, keys_seq: 2 }
    );
    assert_eq!(
        reserve_answer(&ok(json!({"exists": {"id": "p_1", "status": "active",
            "held": false, "grants": []}}))),
        ReserveAnswer::Exists(PrincipalView {
            id: "p_1".into(),
            status: SubjectStatus::Active,
            held: false,
            grants: vec![],
        })
    );
    // What a reservation never answers a create.
    for body in [
        json!({"narrowing": {"keys_seq": 1}}),
        json!({"admitted": {"rid": "zz", "keys_seq": 1, "again": false}}),
        json!({"admitted": {"keys_seq": 1, "again": false}}),
        json!({"applied": {"status": 70000}}),
        json!({"reused": true, "applied": {}}),
        json!({}),
        json!([]),
    ] {
        assert_eq!(
            reserve_answer(&ok(body.clone())),
            ReserveAnswer::Unavailable,
            "{body}"
        );
    }
    assert_eq!(
        reserve_answer(&UnitAnswer::Refused {
            reason: Refused::Reserve(ReserveRefusal::CapReached),
            alarm: false
        }),
        ReserveAnswer::Refused(ReserveRefusal::CapReached)
    );
    assert_eq!(
        reserve_answer(&UnitAnswer::Refused {
            reason: Refused::AccountProblem,
            alarm: false
        }),
        ReserveAnswer::AccountProblem
    );
    assert_eq!(
        reserve_answer(&UnitAnswer::Unborn { listed: true }),
        ReserveAnswer::Unavailable
    );
    assert_eq!(
        reserve_answer(&UnitAnswer::Refused {
            reason: Refused::Unauthenticated,
            alarm: false
        }),
        ReserveAnswer::Unavailable
    );
}

/// Every refusal of the unit, with its contract code and `Retry-After`
/// (AM-40), or `None` (`500`) where it is not the request's; none is
/// `bad_request`, which would blame the caller for an ask this Worker
/// built.
#[test]
fn every_refusal_maps_to_its_contract_code() {
    use velmora_mgmt_types::Code as C;
    use ReserveRefusal::*;
    let table = [
        (
            CapReached,
            Some((C::CapReached, Some(CAP_RETRY_AFTER_SECS))),
        ),
        (GrantNotHeld, Some((C::GrantNotHeld, None))),
        (GrantLimitsNotServed, Some((C::GrantLimitsNotServed, None))),
        (TooManyGrants, Some((C::GrantLimitReached, None))),
        (
            ActingPrincipalUnknown,
            Some((C::ActingPrincipalUnknown, None)),
        ),
        (
            ActingPrincipalInactive,
            Some((C::ActingPrincipalInactive, None)),
        ),
        (ActingPrincipalHeld, Some((C::ServiceUnavailable, Some(5)))),
        (PrincipalExists, Some((C::ServiceUnavailable, Some(5)))),
        (InternalKeyRefused, Some((C::InternalKeyRefused, None))),
        (OwnerRefAmbiguous, None),
        (BucketAlreadyExists, None),
        (Conflict, None),
        (NotFound, None),
        (RidTaken, None),
        (Malformed, None),
    ];
    for (r, want) in table {
        assert_eq!(refusal(r), want, "{r:?}");
        if let Some((code, retry_after)) = want {
            assert_eq!(code.retry_after(), retry_after.is_some(), "{r:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// Review round 1: the held phase, the bucket check, the state code
// ---------------------------------------------------------------------------

/// The directory is down: the record is written and the units hold the
/// principal closed (AM-9), so the call answers `503`, and so does every
/// retry, under its own key (`applied` at the unit) or another
/// (`exists`, held), until the directory acknowledges. Then both answer:
/// the retry `201`, the other key `200`.
#[tokio::test(flavor = "current_thread")]
async fn no_success_while_the_directory_lacks_the_principal() {
    let u = ready();
    let w = World::new(&u);
    w.chain.directory_down.set(true);
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 503, "service_unavailable", Some(5));
    // The unit holds it, closed, and its reservation is applied with no
    // answer.
    let held: bool = u
        .sql()
        .with_conn(|c| {
            c.query_row(
                "SELECT held FROM unit_keys WHERE owner_ref = ?1",
                [NEW_OWNER],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert!(held);
    assert_eq!(reservations(&u), vec![("applied".into(), None)]);

    let retry = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&retry, 503, "service_unavailable", Some(5));
    let other = w.send(CONFIRMED, None, Some("other-key"), &signup()).await;
    expect_code(&other, 503, "service_unavailable", Some(5));
    assert_eq!(w.chain.count(NEW_OWNER), 1);
    assert_eq!(w.chain.creates.get(), 1);

    w.chain.directory_down.set(false);
    let other = w.send(CONFIRMED, None, Some("other-key"), &signup()).await;
    assert_eq!(other.status, 200, "{other:?}");
    let retry = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    assert_eq!(retry.status, 201, "{retry:?}");
    assert_eq!(json_of(&retry), json_of(&other));
    assert_eq!(
        unit_principal(&u, NEW_OWNER).map(|p| p.1),
        Some("active".into())
    );
    assert_eq!(w.chain.count(NEW_OWNER), 1);
}

/// A kept answer is sent only once the stores hold the principal open.
#[tokio::test(flavor = "current_thread")]
async fn a_kept_answer_waits_for_the_stores() {
    let u = ready();
    let w = World::new(&u);
    let first = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    assert_eq!(first.status, 201);
    w.chain.unreadable.set(true);
    let retry = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&retry, 503, "service_unavailable", Some(5));
    w.chain.unreadable.set(false);
    assert_eq!(w.send(CONFIRMED, None, Some(KEY), &signup()).await, first);
}

/// A bucket deleted after the create never hides the kept answer.
#[tokio::test(flavor = "current_thread")]
async fn a_bucket_deleted_since_does_not_hide_the_kept_answer() {
    let u = ready();
    let w = World::new(&u);
    let body = with_grants(json!([{"bucket_id": B1, "access": "rw"}]));
    let first = w.send(CONFIRMED, Some(OWNER), Some(KEY), &body).await;
    assert_eq!(first.status, 201, "{first:?}");
    w.door.buckets.borrow_mut().remove(B1);
    let retry = w.send(CONFIRMED, Some(OWNER), Some(KEY), &body).await;
    assert_eq!(retry, first);
}

/// A refusal after a re-ask leaves the reservation alone: another call
/// under it may be writing its record. A first ask's refusal gives it
/// back.
#[tokio::test(flavor = "current_thread")]
async fn only_the_call_that_made_a_reservation_gives_it_back() {
    let u = ready();
    let w = World::new(&u);
    w.chain.busy.set(true);
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 503, "service_unavailable", Some(5));
    assert_eq!(w.root.releases.get(), 0);
    w.chain
        .refuse
        .set(Some(velmora_mgmt_types::Code::TenantUnavailable));
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 409, "tenant_unavailable", None);
    assert_eq!(w.root.releases.get(), 0, "a re-ask never releases");
    assert_eq!(reservations(&u), vec![("reserved".into(), None)]);

    // A bucket that is not placed, on a first ask: given back.
    add_bucket(&u, B3, "gamma");
    w.chain.acting_holds_b3();
    let body =
        json!({"owner_ref": "usr_2", "grants": [{"bucket_id": B3, "access": "ro"}]}).to_string();
    let a = w.send(CONFIRMED, Some(OWNER), Some("key-2"), &body).await;
    expect_code(&a, 404, "bucket_not_found", None);
    assert_eq!(w.root.releases.get(), 1);
    assert_eq!(reservations(&u).len(), 1);
}

/// The unit refuses for the tenant's state while the head still says
/// open: no state code can be told, `503`.
#[tokio::test(flavor = "current_thread")]
async fn a_state_refusal_the_head_does_not_explain_answers_503() {
    let u = ready();
    let w = World::new(&u);
    sync(&u, TenantState::Suspended);
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 503, "service_unavailable", Some(5));
}

/// A held tenant, and the call's own record exists: the finisher applies
/// it, `409 idempotency_key_in_use`.
#[tokio::test(flavor = "current_thread")]
async fn a_held_tenant_with_the_calls_record_answers_in_use() {
    let u = ready();
    let w = World::new(&u);
    w.chain.crash_after_record.set(true);
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 503, "service_unavailable", Some(5));
    sync(&u, TenantState::Suspended);
    w.door.state.set(Some(DoorState::ReadOnly));
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 409, "idempotency_key_in_use", Some(30));
}

#[tokio::test(flavor = "current_thread")]
async fn a_chain_that_cannot_be_read_answers_503() {
    let u = ready();
    let w = World::new(&u);
    w.chain.busy.set(true);
    assert_eq!(
        w.send(CONFIRMED, None, Some(KEY), &signup()).await.status,
        503
    );
    // The re-ask must read the chain for its rid: it cannot.
    w.chain.unreadable.set(true);
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 503, "service_unavailable", Some(5));
    assert_eq!(w.chain.creates.get(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn more_than_64_grants_are_refused() {
    let u = ready();
    let w = World::new(&u);
    let grants: Vec<Value> = (0..65)
        .map(|i| json!({"bucket_id": format!("b_{i:016x}"), "access": "ro"}))
        .collect();
    let a = w
        .send(
            CONFIRMED,
            Some(OWNER),
            Some(KEY),
            &with_grants(json!(grants)),
        )
        .await;
    expect_code(&a, 409, "grant_limit_reached", None);
    assert!(w.root.asks.borrow().is_empty());
}

// ---------------------------------------------------------------------------
// Review round 2
// ---------------------------------------------------------------------------

/// A put lost, then a refusal: the re-ask answers `again` for the
/// reservation this call made, and the call still gives it back.
#[tokio::test(flavor = "current_thread")]
async fn a_call_gives_back_its_own_reservation_after_a_lost_put() {
    let u = ready();
    let w = World::new(&u);
    w.chain.races.borrow_mut().push(RecordedPrincipal {
        id: "p_other".into(),
        owner_ref: "other-1".into(),
        status: SubjectStatus::Active,
        grants: vec![],
    });
    // The first put is lost; the second create (after the re-ask) is
    // refused.
    w.chain
        .refuse_second
        .set(Some(velmora_mgmt_types::Code::TenantUnavailable));
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 409, "tenant_unavailable", None);
    assert_eq!(w.root.asks.borrow().len(), 2);
    assert_eq!(w.root.releases.get(), 1);
    assert!(reservations(&u).is_empty());
}

/// A create for an `owner_ref` another create holds, before that one has
/// a principal: `503`, and once the first is recorded the second answers
/// `200` with it.
#[tokio::test(flavor = "current_thread")]
async fn a_create_racing_another_for_the_owner_ref_waits() {
    let u = ready();
    let w = World::new(&u);
    w.chain.busy.set(true);
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    expect_code(&a, 503, "service_unavailable", Some(5));
    let b = w.send(CONFIRMED, None, Some("other-key"), &signup()).await;
    expect_code(&b, 503, "service_unavailable", Some(5));
    let a = w.send(CONFIRMED, None, Some(KEY), &signup()).await;
    assert_eq!(a.status, 201, "{a:?}");
    let b = w.send(CONFIRMED, None, Some("other-key"), &signup()).await;
    assert_eq!(b.status, 200, "{b:?}");
    assert_eq!(json_of(&a), json_of(&b));
}
