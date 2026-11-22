//! The move's flip: the legacy stamp, the owner's unit opened by the
//! move's lift report, the keys and routes moved, tenant 0 `moved`;
//! finished by a second run after a crash at any sub-step; and the
//! give-up before the flip, ending in the exit order of AM-23.

mod service_support;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use service_support::*;
use velmora_bridge::directory::chain::{TenantChain, Written};
use velmora_bridge::directory::fence::{freeze, legacy_stamp_key, stamp_row, thaw};
use velmora_bridge::directory::move_copy::ImportState;
use velmora_bridge::directory::move_flip::MAX_WINDOW_RECORDS;
use velmora_bridge::directory::move_flip::{
    flip, floor_after_empty, give_up, FlipError, Flipped, GateView, GaveUp, OwnerUnit, Reported,
    RouteRecords, Synced, Window,
};
use velmora_bridge::directory::move_keys::{KeyUnit, OwnerKeys};
use velmora_bridge::directory::record::{HoldMode, OperatorReason};
use velmora_bridge::directory::record::{Selector, Tenant, TenantDoor};
use velmora_bridge::directory::store::{KeyRoute, RouteKind, SqlDirectory};
use velmora_bridge::directory::testing::{HookedRecords, PlainSeal};
use velmora_bridge::directory::transition::{Actor, Change, OperatorHoldRequest, KEY_CHECK_LEN};
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::unit::keys::{Applied, KeyEntry, KeyKind, SubjectStatus};
use velmora_bridge::unit::lift::{GateRefusal, LiftProof, ReplayId};
use velmora_bridge::unit::Refused as UnitRefused;
use velmora_bridge::*;

const OWNER: &str = "t_00000000000000a1";
/// When the fake unit says the move's lift landed (`ImportProgress`).
const LIFTED_AT: UnixMs = UnixMs(1_700_000_000_000);
const KEYS: [&str; 2] = ["AKMOVE00000000000001", "AKMOVE00000000000002"];

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn owner() -> Tenant {
    Tenant::parse(OWNER).unwrap()
}

fn keys() -> Vec<String> {
    KEYS.iter().map(|k| k.to_string()).collect()
}

/// The owner's root unit as L1's package 4 states it: a `move` report
/// is taken only for the entry the unit is closed under; the `sync` that
/// lifts needs the stored report's proof; key rows from the chain apply.
struct FakeUnit {
    /// Every head the unit was synced with, and the lift it carried.
    synced: RefCell<Vec<(TenantDoor, Option<LiftProof>)>>,
    /// The `since_seq` the unit is closed under (`None`: open).
    closed: Cell<Option<u64>>,
    /// The stored `move` report.
    report: RefCell<Option<ReplayId>>,
    reports: Cell<u32>,
    /// The next N syncs are not reached.
    fail: Cell<u32>,
    /// The next N syncs that lift are refused.
    refuse_lift: Cell<u32>,
    /// The next N gate reads say the lift would not pass.
    not_ok: Cell<u32>,
    renews: Cell<u32>,
    v9_ok: Cell<bool>,
    v9_runs: Cell<u32>,
    nonces: Cell<u32>,
    keys_seq: Cell<u64>,
    /// The next N syncs that lift are not reached.
    fail_lift: Cell<u32>,
    /// Answers for the next syncs that lift, in order (then as usual).
    lift_answers: RefCell<std::collections::VecDeque<UnitRefused>>,
    /// A refused lift opens the unit anyway (its answer was the stale one).
    open_on_refusal: Cell<bool>,
    /// The unit refuses every `move` report.
    refuse_report: Cell<bool>,
    /// The sync after a refused lift is not reached.
    fail_after_refusal: Cell<bool>,
    armed: Cell<bool>,
    /// The import the unit holds (default: this window's, sealed).
    import: RefCell<Option<ImportState>>,
    /// Changes every `GateStatus` answer (a unit that answers wrongly).
    bend: RefCell<Option<fn(&mut GateView)>>,
    /// Key status by id, as applied.
    key_rows: RefCell<BTreeMap<String, SubjectStatus>>,
    applies: Cell<u32>,
}

impl Default for FakeUnit {
    fn default() -> Self {
        FakeUnit {
            synced: RefCell::default(),
            closed: Cell::new(None),
            report: RefCell::default(),
            reports: Cell::new(0),
            fail: Cell::new(0),
            refuse_lift: Cell::new(0),
            not_ok: Cell::new(0),
            renews: Cell::new(0),
            v9_ok: Cell::new(true),
            v9_runs: Cell::new(0),
            nonces: Cell::new(0),
            keys_seq: Cell::new(0),
            bend: RefCell::new(None),
            import: RefCell::new(Some(ImportState {
                t0_seq: Some(1 << 40),
                sealed: Some(1),
                lifted_at: Some(LIFTED_AT),
                tables: vec![],
            })),
            fail_lift: Cell::new(0),
            lift_answers: RefCell::default(),
            open_on_refusal: Cell::new(false),
            refuse_report: Cell::new(false),
            fail_after_refusal: Cell::new(false),
            armed: Cell::new(false),
            key_rows: RefCell::default(),
            applies: Cell::new(0),
        }
    }
}

fn take(c: &Cell<u32>) -> bool {
    let n = c.get();
    if n > 0 {
        c.set(n - 1);
    }
    n > 0
}

impl KeyUnit for FakeUnit {
    async fn apply_keys(&self, from_seq: u64, entries: &[KeyEntry]) -> Result<Applied> {
        self.applies.set(self.applies.get() + 1);
        if from_seq > self.keys_seq.get() {
            return Ok(Applied::Behind {
                keys_seq: self.keys_seq.get(),
            });
        }
        for e in entries {
            assert!(!e.held, "the move sends no held entry");
            if e.last_seq > self.keys_seq.get() {
                let mut rows = self.key_rows.borrow_mut();
                // Revoked is final.
                if rows.get(&e.id) != Some(&SubjectStatus::Revoked) {
                    rows.insert(e.id.clone(), e.status);
                }
            }
        }
        let last = entries.last().map_or(0, |e| e.last_seq);
        self.keys_seq.set(self.keys_seq.get().max(last));
        Ok(Applied::Done {
            keys_seq: self.keys_seq.get(),
            applied: entries.len() as u64,
            skipped: 0,
        })
    }

    async fn key_active(&self, akid: &str) -> Result<bool> {
        Ok(self.key_rows.borrow().get(akid) == Some(&SubjectStatus::Active))
    }
}

impl OwnerUnit for FakeUnit {
    async fn sync(&self, owner: &TenantDoor, lift: Option<&LiftProof>) -> Result<Synced> {
        if take(&self.fail) || self.armed.replace(false) {
            return Err(BridgeError::Blob("unit unreachable".into()));
        }
        if owner.restoring_entry(0).is_none() && take(&self.fail_lift) {
            return Err(BridgeError::Blob("unit unreachable".into()));
        }
        if owner.restoring_entry(0).is_none() {
            if let Some(r) = self.lift_answers.borrow_mut().pop_front() {
                if self.open_on_refusal.get() {
                    self.closed.set(None);
                }
                return Ok(Synced::Refused(r));
            }
        }
        match owner.restoring_entry(0) {
            Some(e) => self.closed.set(Some(e.since_seq)),
            None => {
                // The in-unit lift check: the stored report, for the entry
                // the unit is closed under, named by the sync.
                let report = self.report.borrow().clone();
                let ok = match (lift, &report, self.closed.get()) {
                    (_, _, None) => true,
                    (Some(l), Some(r), Some(s)) => l.replay_id == *r && r.since == s,
                    _ => false,
                };
                if !ok {
                    return Ok(Synced::Refused(UnitRefused::Gate(
                        GateRefusal::ProofMismatch,
                    )));
                }
                if self.closed.get().is_some() && take(&self.refuse_lift) {
                    self.armed.set(self.fail_after_refusal.get());
                    return Ok(Synced::Refused(UnitRefused::Gate(GateRefusal::Closed)));
                }
                self.closed.set(None);
            }
        }
        self.synced
            .borrow_mut()
            .push((owner.clone(), lift.cloned()));
        Ok(Synced::Ok)
    }

    async fn restoring_since(&self) -> Result<Option<u64>> {
        Ok(self.closed.get())
    }

    async fn renew(&self) -> Result<()> {
        assert!(self.closed.get().is_none(), "a closed unit refuses renew");
        self.renews.set(self.renews.get() + 1);
        Ok(())
    }

    async fn stamp_ordinal(&self) -> Result<u64> {
        Ok(2)
    }

    async fn report_move(&self, zero: &TenantDoor, replay_id: &ReplayId) -> Result<Reported> {
        let moving = zero
            .tenant_zero
            .as_ref()
            .is_some_and(|z| z.selector == Selector::Moving);
        if self.refuse_report.get() || !moving || self.closed.get() != Some(replay_id.since) {
            return Ok(Reported::Refused(GateRefusal::MoveNotBound));
        }
        self.reports.set(self.reports.get() + 1);
        *self.report.borrow_mut() = Some(replay_id.clone());
        Ok(Reported::Done)
    }

    async fn gate_status(&self) -> Result<GateView> {
        let report = self.report.borrow().clone();
        let lift_ok = report
            .as_ref()
            .is_some_and(|r| Some(r.since) == self.closed.get())
            && !take(&self.not_ok);
        let mut view = GateView {
            kind_move: report.is_some(),
            lift_ok,
            proof: report.clone().map(|replay_id| LiftProof {
                replay_id,
                acknowledged: Default::default(),
            }),
            replay_id: report,
        };
        if let Some(bend) = *self.bend.borrow() {
            bend(&mut view);
        }
        Ok(view)
    }

    async fn move_import(&self) -> Result<Option<ImportState>> {
        Ok(self.import.borrow().clone())
    }

    async fn v9(&self) -> Result<bool> {
        assert!(self.closed.get().is_none(), "V9 reads an open unit");
        self.v9_runs.set(self.v9_runs.get() + 1);
        Ok(self.v9_ok.get())
    }

    fn nonce(&self) -> String {
        self.nonces.set(self.nonces.get() + 1);
        format!("n{}", self.nonces.get())
    }
}

/// The owner's key chain (one entry per record) and the revocations.
#[derive(Default)]
struct FakeKeys {
    chain: RefCell<Vec<KeyEntry>>,
    flat: RefCell<BTreeSet<String>>,
    tenant: RefCell<BTreeSet<String>>,
    /// The bucket lists of every grant revocation, in order.
    grants_revoked: RefCell<Vec<Vec<String>>>,
    /// The next N grant revocations are not reached.
    fail_grants: Cell<u32>,
    /// What happened, in order; a test may add the chain's puts.
    log: Rc<RefCell<Vec<String>>>,
}

fn entry(id: &str, status: SubjectStatus, seq: u64) -> KeyEntry {
    KeyEntry {
        id: id.into(),
        kind: KeyKind::S3,
        status,
        held: false,
        made_by: Some("PRowner".into()),
        grants: vec![],
        created_at: 1,
        secret_wrapped: (status == SubjectStatus::Active).then(|| vec![2; 40]),
        secret_kek_version: Some(1),
        owner_ref: None,
        last_seq: seq,
    }
}

impl FakeKeys {
    /// Step 5(b): one record per moved key.
    fn with_moved_keys() -> FakeKeys {
        let k = FakeKeys::default();
        for akid in KEYS {
            let seq = k.chain.borrow().len() as u64 + 1;
            k.chain
                .borrow_mut()
                .push(entry(akid, SubjectStatus::Active, seq));
        }
        k
    }
}

impl OwnerKeys for FakeKeys {
    async fn head(&self) -> Result<u64> {
        Ok(self.chain.borrow().len() as u64)
    }

    async fn entries(&self, after: u64, limit: usize) -> Result<Vec<KeyEntry>> {
        Ok(self
            .chain
            .borrow()
            .iter()
            .skip(after as usize)
            .take(limit)
            .cloned()
            .collect())
    }

    async fn flat_revoked(&self, akid: &str) -> Result<bool> {
        Ok(self.flat.borrow().contains(akid))
    }

    async fn tenant_revoked(&self, akid: &str) -> Result<bool> {
        Ok(self.tenant.borrow().contains(akid))
    }

    async fn put_tenant_revocation(&self, akid: &str) -> Result<()> {
        self.tenant.borrow_mut().insert(akid.into());
        self.log.borrow_mut().push(format!("rk/t/{akid}"));
        Ok(())
    }

    async fn revoke(&self, akid: &str) -> Result<()> {
        let revoked = self
            .chain
            .borrow()
            .iter()
            .rev()
            .find(|e| e.id == akid)
            .is_some_and(|e| e.status == SubjectStatus::Revoked);
        if !revoked {
            let seq = self.chain.borrow().len() as u64 + 1;
            self.chain
                .borrow_mut()
                .push(entry(akid, SubjectStatus::Revoked, seq));
            self.log.borrow_mut().push(format!("revoke {akid}"));
        }
        Ok(())
    }

    async fn revoke_grants(&self, buckets: &[String]) -> Result<()> {
        if take(&self.fail_grants) {
            return Err(BridgeError::Blob("key chain unreachable".into()));
        }
        self.grants_revoked.borrow_mut().push(buckets.to_vec());
        self.log.borrow_mut().push("revoke_grants".into());
        Ok(())
    }

    async fn flat_revocations(&self, after: Option<&str>) -> Result<(Vec<String>, Option<String>)> {
        Ok((
            self.flat
                .borrow()
                .iter()
                .filter(|id| after.is_none_or(|a| id.as_str() > a))
                .cloned()
                .collect(),
            None,
        ))
    }
}

/// Route records, put once.
#[derive(Default)]
struct FakeRoutes {
    records: RefCell<BTreeMap<String, String>>,
    /// Puts fail after this many more.
    fail_after: Cell<Option<u32>>,
    /// The next N puts store, then answer an error.
    lose: Cell<u32>,
    /// Replaces that changed a record.
    replaced: Cell<u32>,
    /// A third tenant took every record before a replace.
    third: Cell<bool>,
}

impl RouteRecords for FakeRoutes {
    async fn put(&self, akid: &str, tenant: &Tenant, kind: RouteKind) -> Result<bool> {
        assert_eq!(kind, RouteKind::S3);
        if let Some(n) = self.fail_after.get() {
            if n == 0 {
                return Err(BridgeError::Blob("route store unreachable".into()));
            }
            self.fail_after.set(Some(n - 1));
        }
        let ours = {
            let mut records = self.records.borrow_mut();
            let named = records
                .entry(akid.to_string())
                .or_insert_with(|| tenant.as_str().to_string());
            named == tenant.as_str()
        };
        if self.lose.get() > 0 {
            self.lose.set(self.lose.get() - 1);
            return Err(BridgeError::Blob("answer lost".into()));
        }
        Ok(ours)
    }

    async fn get(&self, akid: &str) -> Result<Option<String>> {
        Ok(self.records.borrow().get(akid).cloned())
    }

    async fn replace(
        &self,
        akid: &str,
        from: &Tenant,
        to: &Tenant,
        kind: RouteKind,
    ) -> Result<bool> {
        assert_eq!(kind, RouteKind::S3);
        let mut records = self.records.borrow_mut();
        if self.third.get() {
            records.insert(akid.into(), "t_00000000000000b2".into());
        }
        match records.get(akid).map(String::as_str) {
            Some(t) if t == to.as_str() => Ok(true),
            Some(t) if t == from.as_str() => {
                records.insert(akid.into(), to.as_str().into());
                self.replaced.set(self.replaced.get() + 1);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

struct Move {
    rig: Rig,
    store: HookedRecords,
    seal: PlainSeal,
    db: RusqliteSql,
    unit: FakeUnit,
    routes: FakeRoutes,
    keys: FakeKeys,
    excluded: BTreeSet<String>,
    since: u64,
    zero_seq: u64,
    /// The frozen D1's bucket ids, placed in the owner.
    buckets: Vec<String>,
}

impl Move {
    fn chain(&self) -> TenantChain<'_, HookedRecords, PlainSeal> {
        TenantChain {
            store: &self.store,
            seal: &self.seal,
        }
    }

    fn dir(&self) -> SqlDirectory<'_, RusqliteSql> {
        SqlDirectory { sql: &self.db }
    }

    async fn write(&self, tenant: &Tenant, change: Change, actor: Actor) -> TenantDoor {
        match self
            .chain()
            .write(tenant, &change, actor, self.rig.now(), 0)
            .await
            .unwrap()
        {
            Written::Wrote(r) => r.door,
            Written::Unchanged(r) => r.door,
        }
    }

    async fn head(&self, tenant: &Tenant) -> TenantDoor {
        self.chain().head(tenant, 0).await.unwrap().unwrap().door
    }

    /// The owner's newest lift record (the move floor (b1) writes after
    /// it, so it need not be the head).
    async fn lift_record(&self) -> Option<velmora_bridge::directory::record::Lifted> {
        let head = self.head(&owner()).await;
        for seq in (1..=head.seq).rev() {
            let door = self.chain().read(&owner(), seq).await.unwrap()?.door;
            if door.lifted.is_some() {
                return door.lifted;
            }
        }
        None
    }

    async fn flip(&self) -> std::result::Result<Flipped, FlipError> {
        let k = keys();
        let window = Window {
            owner: &owner(),
            zero_seq: self.zero_seq,
            since: self.since,
            keys: &k,
            excluded: &self.excluded,
        };
        flip(
            &self.chain(),
            &self.rig.bridge.catalog.sql,
            &self.rig.bridge.safety,
            &self.dir(),
            &self.unit,
            &self.routes,
            &self.keys,
            &window,
            &self.rig.bridge.clock,
        )
        .await
    }

    async fn give_up(&self) -> std::result::Result<GaveUp, FlipError> {
        let k = keys();
        let window = Window {
            owner: &owner(),
            zero_seq: self.zero_seq,
            since: self.since,
            keys: &k,
            excluded: &self.excluded,
        };
        give_up(
            &self.chain(),
            &self.rig.bridge.catalog.sql,
            &self.rig.bridge.safety,
            &self.dir(),
            &self.unit,
            &self.routes,
            &self.keys,
            &window,
            self.rig.now(),
        )
        .await
    }

    fn records(&self) -> usize {
        self.store.keys().len()
    }

    async fn route_row(&self, akid: &str) -> Tenant {
        self.dir().route(akid).await.unwrap().unwrap().tenant
    }

    async fn stamp_put(&self) -> bool {
        let counter = stamp_row(&self.rig.bridge.catalog.sql)
            .await
            .unwrap()
            .map(|(c, _)| c);
        self.rig
            .bridge
            .safety
            .head(&legacy_stamp_key("main", counter))
            .await
            .unwrap()
            .is_some()
    }

    async fn selector(&self) -> Selector {
        self.head(&Tenant::zero())
            .await
            .tenant_zero
            .unwrap()
            .selector
    }

    /// The directory's row of `tenant`: its seq and selector.
    async fn dir_row(&self, tenant: &Tenant) -> (u64, Option<Selector>) {
        let row = self.dir().tenant(tenant).await.unwrap().unwrap();
        (row.door.seq, row.door.tenant_zero.map(|z| z.selector))
    }

    async fn place(&self) {
        self.chain()
            .place_moved_buckets(&owner(), &self.buckets, 0, self.rig.now(), 0)
            .await
            .unwrap();
    }
}

/// The window up to step 7: tenant 0 frozen and `moving` into the owner,
/// the owner's unit 0 `restoring` with the moved buckets placed, the unit
/// closed under that entry, the moved keys in the owner's key chain, both
/// tenants and tenant 0's key routes in the directory. The canary bucket
/// is excluded.
async fn window() -> Move {
    window_with(true).await
}

async fn window_with(placed: bool) -> Move {
    let rig = rig();
    let (vault, signer) = rig.standard("vault").await;
    rig.put(&signer, "vault", "a.bin", &pattern(1, 1_000))
        .await
        .expect(200);
    let canary = rig.bucket("mq-canary", true).await;
    rig.bridge.raise_stamp().await.unwrap();
    freeze(&rig.bridge.catalog.sql, 1).await.unwrap();
    let vault = vault.id.as_str().to_string();
    let canary = canary.id.as_str().to_string();
    let db = RusqliteSql::open_in_memory().unwrap();
    db.apply(include_str!(
        "../../../workers/s3-bridge/migrations-directory/0001_directory.sql"
    ))
    .unwrap();
    let mut m = Move {
        rig,
        store: HookedRecords::new(),
        seal: PlainSeal::new(),
        db,
        unit: FakeUnit::default(),
        routes: FakeRoutes::default(),
        keys: FakeKeys::with_moved_keys(),
        excluded: BTreeSet::from([canary]),
        since: 0,
        zero_seq: 0,
        buckets: vec![vault],
    };
    let zero = Tenant::zero();
    m.write(
        &zero,
        Change::CreateTenantZero {
            jurisdiction: "us".into(),
        },
        Actor::Operator,
    )
    .await;
    let o = owner();
    for (change, actor) in [
        (
            Change::Create {
                jurisdiction: "us".into(),
                location_hint: None,
                synthetic: false,
                limits: Default::default(),
                rate_json: Default::default(),
                features_json: Default::default(),
            },
            Actor::TenantCreation,
        ),
        (
            Change::ClaimKeyVersion { version: 1 },
            Actor::TenantCreation,
        ),
        (
            Change::CommitKeyVersion {
                version: 1,
                kcv: [1; KEY_CHECK_LEN],
            },
            Actor::TenantCreation,
        ),
        (
            Change::Activate { external_ref: None },
            Actor::TenantCreation,
        ),
    ] {
        m.write(&o, change, actor).await;
    }
    m.zero_seq = m
        .write(
            &zero,
            Change::StartMove {
                to: o.clone(),
                catalogue_id_frozen: "main".into(),
            },
            Actor::MoveTool,
        )
        .await
        .seq;
    let closed = m
        .write(&o, Change::SetRestoring { unit: 0 }, Actor::Operator)
        .await;
    m.since = closed.restoring_entry(0).unwrap().since_seq;
    if placed {
        m.place().await;
    }
    // The window's step 2 closed the unit under its entry.
    m.unit.closed.set(Some(m.since));
    let dir = m.dir();
    for t in [&zero, &o] {
        dir.apply_tenant(&m.head(t).await, m.rig.now())
            .await
            .unwrap();
    }
    for akid in KEYS {
        dir.put_route(&KeyRoute {
            akid: akid.into(),
            tenant: zero.clone(),
            kind: RouteKind::S3,
            owner_ref: None,
            created_at: m.rig.now(),
        })
        .await
        .unwrap();
    }
    m
}

async fn assert_flipped(m: &Move, stamp: u64) {
    let z = m.head(&Tenant::zero()).await;
    let z = z.tenant_zero.unwrap();
    assert_eq!(z.selector, Selector::Moved);
    assert_eq!(z.moved.unwrap().stamp, Some(stamp));
    let o = m.head(&owner()).await;
    assert!(o.restoring.is_empty());
    // (b1): the floor at the unit's lift time (AM-67).
    assert_eq!(o.move_floors.get(&0), Some(&LIFTED_AT));
    // The lift record carries the move report's proof, and the unit last
    // saw the lifted head with it.
    // (A later owner record may stand on the lift.)
    let lifted = m.lift_record().await;
    let (seen, proof) = m.unit.synced.borrow().last().unwrap().clone();
    assert!(seen.restoring.is_empty());
    let proof = proof.expect("the opening sync names the lift");
    if let Some(l) = lifted {
        assert_eq!(l.proof, proof);
        // The directory took the lift before the unit did.
        assert_eq!(m.dir_row(&owner()).await.0, o.seq);
    }
    assert_eq!(Some(proof.replay_id), *m.unit.report.borrow());
    assert!(m.unit.closed.get().is_none());
    assert!(m.unit.renews.get() > 0);
    for akid in KEYS {
        assert_eq!(m.routes.records.borrow()[akid], OWNER);
        assert_eq!(m.route_row(akid).await, owner());
    }
    let key = legacy_stamp_key("main", Some(stamp - 1));
    assert!(m.rig.bridge.safety.head(&key).await.unwrap().is_some());
    // The directory copies: tenant 0's selector, the owner's keys_seq.
    assert_eq!(m.dir_row(&Tenant::zero()).await.1, Some(Selector::Moved));
    let row = m.dir().tenant(&owner()).await.unwrap().unwrap();
    assert!(row.keys_seq >= m.keys.chain.borrow().len() as u64);
    // The unit holds every key record.
    assert_eq!(m.unit.keys_seq.get(), m.keys.chain.borrow().len() as u64);
}

#[test]
fn the_flip_runs_its_four_steps_in_order() {
    block_on(async {
        let m = window().await;
        let before = m.records();
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
        assert_flipped(&m, f.stamp).await;
        // Three records: the owner's lift, its move floor (b1) and tenant
        // 0's flip.
        assert_eq!(m.records(), before + 3);
        // Run again: found, nothing written.
        let again = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_eq!(
            again,
            Flipped {
                stamp: f.stamp,
                wrote: false
            }
        );
        assert_eq!(m.records(), before + 3);
        // No give-up after the flip: the way back is the reverse move.
        assert!(matches!(m.give_up().await, Err(FlipError::NotThisMove)));
    });
}

#[test]
fn a_crash_at_any_step_is_finished_by_running_the_flip_again() {
    block_on(async {
        let m = window().await;
        let before = m.records();
        // After (a) and the lift record: the unit is not reached.
        m.unit.fail_lift.set(1);
        assert!(matches!(m.flip().await, Err(FlipError::Store(_))));
        assert!(m.head(&owner()).await.restoring.is_empty());
        assert_eq!(
            m.head(&Tenant::zero()).await.tenant_zero.unwrap().selector,
            Selector::Moving
        );
        // In (c): the second key's route record is not reached.
        m.routes.fail_after.set(Some(1));
        assert!(matches!(m.flip().await, Err(FlipError::Store(_))));
        assert_eq!(m.route_row(KEYS[0]).await, owner());
        assert!(m.route_row(KEYS[1]).await.is_zero());
        m.routes.fail_after.set(None);
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_flipped(&m, f.stamp).await;
        // Still one lift record, one floor record and one flip record.
        assert_eq!(m.records(), before + 3);
    });
}

#[test]
fn a_route_record_of_another_tenant_stops_the_flip() {
    block_on(async {
        let m = window().await;
        m.routes
            .records
            .borrow_mut()
            .insert(KEYS[1].into(), "t_00000000000000b2".into());
        let r = m.flip().await;
        assert!(
            matches!(&r, Err(FlipError::RouteTaken(k)) if k == KEYS[1]),
            "{r:?}"
        );
        // Refused before the first write: no stamp, the unit still
        // closed, the first key's record not put.
        assert_eq!(m.selector().await, Selector::Moving);
        assert!(!m.stamp_put().await);
        assert!(m.head(&owner()).await.restoring_entry(0).is_some());
        assert!(!m.routes.records.borrow().contains_key(KEYS[0]));
        // So the move can still be given up.
        let g = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_eq!(
            g,
            GaveUp {
                catalogue_id_frozen: "main".into(),
                stamp_put: false
            }
        );
        assert_eq!(m.selector().await, Selector::D1);
    });
}

#[test]
fn the_flip_acts_only_on_this_windows_entry() {
    block_on(async {
        let mut m = window().await;
        m.since += 1;
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::OtherWindow { .. })), "{r:?}");
        assert!(!m.head(&owner()).await.restoring.is_empty());
        assert!(m.routes.records.borrow().is_empty());
    });
}

#[test]
fn the_move_is_given_up_before_its_routes() {
    block_on(async {
        let m = window().await;
        // (a) and (b) done, (c) not reached.
        m.routes.fail_after.set(Some(0));
        assert!(m.flip().await.is_err());
        assert!(m.head(&owner()).await.restoring.is_empty());
        let g = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        // (a) ran: the tool levels the thawed D1's stamp.
        assert!(g.stamp_put);
        assert!(m.stamp_put().await);
        let o = m.head(&owner()).await;
        let entry = o.restoring_entry(0).unwrap().since_seq;
        assert!(entry > m.since);
        // The unit was closed again under the new entry.
        assert_eq!(m.unit.closed.get(), Some(entry));
        let z = m.head(&Tenant::zero()).await.tenant_zero.unwrap();
        assert_eq!(z.selector, Selector::D1);
        assert!(z.moved.is_none());
        assert_eq!(m.dir_row(&Tenant::zero()).await.1, Some(Selector::D1));
        for akid in KEYS {
            assert!(m.route_row(akid).await.is_zero());
        }
        // The exit: the grants on the moved bucket revoked, then the
        // placements removed and `moved_in` cleared.
        assert_eq!(*m.keys.grants_revoked.borrow(), vec![m.buckets.clone()]);
        assert!(o.placements.is_empty());
        assert_eq!(o.moved_in, None);
        assert_eq!(m.dir_row(&owner()).await.0, o.seq);
        // Run again: nothing more is written, and the answer is the same
        // (a re-run after a lost answer still learns the level step).
        let n = m.records();
        assert_eq!(
            m.give_up().await.map_err(|e| format!("{e:?}")).unwrap(),
            GaveUp {
                catalogue_id_frozen: "main".into(),
                stamp_put: true
            }
        );
        assert_eq!(m.keys.grants_revoked.borrow().len(), 1);
        assert_eq!(m.records(), n);
        // And the flip no longer runs.
        assert!(matches!(m.flip().await, Err(FlipError::NotThisMove)));
    });
}

#[test]
fn the_give_up_puts_a_route_record_back_by_the_conditional_replace() {
    block_on(async {
        let m = window().await;
        // (c) put the first key's record, then stopped.
        m.routes.fail_after.set(Some(1));
        assert!(m.flip().await.is_err());
        assert_eq!(m.routes.records.borrow()[KEYS[0]], OWNER);
        m.routes.fail_after.set(None);
        let g = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(g.stamp_put);
        // Closed first, then the record back on tenant 0, then d1.
        assert_eq!(m.routes.records.borrow()[KEYS[0]], Tenant::zero().as_str());
        assert_eq!(m.routes.replaced.get(), 1);
        assert!(m.unit.closed.get().is_some());
        assert_eq!(m.selector().await, Selector::D1);
        for akid in KEYS {
            assert!(m.route_row(akid).await.is_zero());
        }
        // A record that names a third tenant stops the give-up before d1.
        let m = window().await;
        m.routes.fail_after.set(Some(1));
        assert!(m.flip().await.is_err());
        m.routes.fail_after.set(None);
        m.routes.third.set(true);
        let r = m.give_up().await;
        assert!(
            matches!(&r, Err(FlipError::RouteTaken(k)) if k == KEYS[0]),
            "{r:?}"
        );
        assert_eq!(m.selector().await, Selector::Moving);
    });
}

#[test]
fn lost_answers_in_the_routes_and_the_flip_record_are_read_back() {
    block_on(async {
        let m = window().await;
        let before = m.records();
        // The first key's record is stored, its answer lost.
        m.routes.lose.set(1);
        assert!(matches!(m.flip().await, Err(FlipError::Store(_))));
        assert_eq!(m.routes.records.borrow()[KEYS[0]], OWNER);
        assert!(m.route_row(KEYS[0]).await.is_zero());
        // The flip record is stored, its answer lost: read back as
        // written. (The lift is already done, so the next record put is
        // the flip's.)
        m.store.lose_answers(1);
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
        assert_flipped(&m, f.stamp).await;
        assert_eq!(m.records(), before + 3);
    });
}

#[test]
fn the_move_is_given_up_before_the_unit_opens() {
    block_on(async {
        let m = window().await;
        let before = m.records();
        let o = m.head(&owner()).await;
        let g = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(!g.stamp_put);
        // The entry stood: no new entry; tenant 0's record and the
        // owner's unplace only.
        let after = m.head(&owner()).await;
        assert_eq!(after.seq, o.seq + 1);
        assert_eq!(after.restoring, o.restoring);
        assert!(after.placements.is_empty());
        assert_eq!(m.records(), before + 2);
        assert_eq!(m.selector().await, Selector::D1);
        assert_eq!(m.unit.closed.get(), Some(m.since));
    });
}

#[test]
fn a_give_up_that_crashed_after_closing_the_unit_runs_again() {
    block_on(async {
        let m = window().await;
        m.routes.fail_after.set(Some(0));
        assert!(m.flip().await.is_err());
        // The unit is not reached after the new restoring entry.
        m.unit.fail.set(1);
        assert!(matches!(m.give_up().await, Err(FlipError::Store(_))));
        let closed = m.head(&owner()).await;
        let entry = closed.restoring_entry(0).unwrap().since_seq;
        assert!(entry > m.since);
        assert_eq!(m.selector().await, Selector::Moving);
        let g = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(g.stamp_put);
        // No second entry; the unit is closed under it.
        let after = m.head(&owner()).await;
        assert_eq!(after.restoring_entry(0).unwrap().since_seq, entry);
        assert_eq!(m.unit.closed.get(), Some(entry));
        assert_eq!(m.selector().await, Selector::D1);
    });
}

#[test]
fn the_flip_needs_this_windows_marker_and_a_later_window_is_not_this_one() {
    block_on(async {
        let m = window().await;
        // A marker of another move ordinal.
        thaw(&m.rig.bridge.catalog.sql).await.unwrap();
        freeze(&m.rig.bridge.catalog.sql, 2).await.unwrap();
        assert!(matches!(m.flip().await, Err(FlipError::Marker)));
        assert!(!m.stamp_put().await);
        thaw(&m.rig.bridge.catalog.sql).await.unwrap();
        freeze(&m.rig.bridge.catalog.sql, 1).await.unwrap();
        // Opened, given up (a new restoring entry), then a new window into
        // the same owner: the old window's flip does not act on it. (A
        // window whose entry was never lifted keeps it, and the next window
        // takes the same one: the two cannot be told apart.)
        m.routes.fail_after.set(Some(0));
        assert!(m.flip().await.is_err());
        m.routes.fail_after.set(None);
        m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        let w2 = m
            .write(
                &Tenant::zero(),
                Change::StartMove {
                    to: owner(),
                    catalogue_id_frozen: "main".into(),
                },
                Actor::MoveTool,
            )
            .await;
        let o = m.head(&owner()).await;
        assert!(o.restoring_entry(0).is_some());
        // A stale run of the first window acts on nothing: the flip does
        // not run, and the give-up does not answer a catalogue the second
        // window has frozen again.
        let n = m.records();
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::NotThisMove)), "{r:?}");
        let r = m.give_up().await;
        assert!(matches!(r, Err(FlipError::NotThisMove)), "{r:?}");
        assert_eq!(m.records(), n);
        assert_eq!(m.selector().await, Selector::Moving);
        // The second window, named by its own record: the first window's
        // exit removed the placements, so its flip stops at the placement
        // check until the second window places them again.
        let mut m2 = m;
        m2.zero_seq = w2.seq;
        let r = m2.flip().await;
        assert!(
            matches!(&r, Err(FlipError::Placements { missing, extra })
                if *missing == m2.buckets && extra.is_empty()),
            "{r:?}"
        );
        m2.place().await;
        assert_eq!(
            m2.head(&owner()).await.moved_in.map(|m| m.zero_seq),
            Some(w2.seq)
        );
        m2.since = o.restoring_entry(0).unwrap().since_seq;
        let f = m2.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
    });
}

#[test]
fn the_pre_pass_refuses_a_key_with_no_route_row_before_any_write() {
    block_on(async {
        let m = window().await;
        m.db.apply(&format!(
            "DELETE FROM key_routes WHERE akid = '{}';",
            KEYS[1]
        ))
        .unwrap();
        let n = m.records();
        let r = m.flip().await;
        assert!(
            matches!(&r, Err(FlipError::RouteRow(k)) if k == KEYS[1]),
            "{r:?}"
        );
        assert_eq!(m.records(), n);
        assert!(!m.stamp_put().await);
        assert!(m.routes.records.borrow().is_empty());
    });
}

#[test]
fn a_missing_entry_counts_as_lifted_only_if_this_window_set_it() {
    block_on(async {
        let mut m = window().await;
        // Lifted by a run that stopped in (c).
        m.routes.fail_after.set(Some(0));
        assert!(m.flip().await.is_err());
        m.routes.fail_after.set(None);
        // A window that names another seq for its entry: the record there
        // did not set one.
        let real = m.since;
        m.since = real - 1;
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::OtherWindow { .. })), "{r:?}");
        m.since = real;
        m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
    });
}

#[test]
fn a_give_up_landing_before_the_flip_record_stops_the_flip() {
    use velmora_bridge::directory::chain::{record_key, ControlSeal};
    use velmora_bridge::directory::record::TenantRecord;
    use velmora_bridge::directory::transition::{next, Outcome};
    block_on(async {
        let m = window().await;
        // A give-up of tenant 0, sealed as another writer would, put just
        // before this run's flip record.
        let head = m.chain().head(&Tenant::zero(), 0).await.unwrap().unwrap();
        let record = TenantRecord {
            door: head.door,
            private: head.private.unwrap(),
        };
        let Ok(Outcome::Next(gave_up)) = next(
            &Tenant::zero(),
            Some(&record),
            &Change::GiveUpMove,
            Actor::MoveTool,
            m.rig.now(),
        ) else {
            panic!("give-up record");
        };
        let name = record_key(&Tenant::zero(), gave_up.door.seq);
        let sealed = m
            .seal
            .seal(
                &name,
                &Tenant::zero(),
                gave_up.door.tk_version,
                &serde_json::to_vec(&gave_up.door).unwrap(),
                &serde_json::to_vec(&gave_up.private).unwrap(),
            )
            .unwrap();
        let mut planted = Some((name, sealed));
        let zero_prefix = "m/t/t_0000000000000000/".to_string();
        m.store.before_put(move |key, objects| {
            if key.starts_with(&zero_prefix) {
                if let Some((name, sealed)) = planted.take() {
                    objects.insert(name, sealed);
                }
            }
        });
        let r = m.flip().await;
        assert!(r.is_err(), "{r:?}");
        assert_eq!(m.selector().await, Selector::D1);
    });
}

fn hold(on: bool) -> Change {
    Change::SetOperatorHold {
        hold: on.then_some(OperatorHoldRequest {
            mode: HoldMode::ReadOnly,
            reason: OperatorReason::Security,
            preserve: None,
        }),
    }
}

#[test]
fn a_tenant_zero_record_during_the_run_stops_the_flip_record_until_run_again() {
    block_on(async {
        let m = window().await;
        // A record of tenant 0 that keeps the window open lands while the
        // flip runs (at the owner's lift): the re-walk before (d) sees a
        // head this run did not check.
        let head = m.chain().head(&Tenant::zero(), 0).await.unwrap().unwrap();
        let (name, sealed) = sealed_next(&m, head, hold(true));
        let mut planted = Some((name, sealed));
        let owner_prefix = format!("m/t/{OWNER}/");
        m.store.before_put(move |key, objects| {
            if key.starts_with(&owner_prefix) {
                if let Some((name, sealed)) = planted.take() {
                    objects.insert(name, sealed);
                }
            }
        });
        let n = m.records();
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::NotThisMove)), "{r:?}");
        // The lift, the floor and the planted record; no flip record.
        assert_eq!(m.records(), n + 3);
        assert_eq!(m.selector().await, Selector::Moving);
        // The window is still this one: run again, it flips.
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
    });
}

/// The sealed record that `change` makes on `head` of tenant 0, as another
/// writer would put it.
fn sealed_next(
    m: &Move,
    head: velmora_bridge::directory::chain::ReadRecord,
    change: Change,
) -> (String, Vec<u8>) {
    use velmora_bridge::directory::chain::{record_key, ControlSeal};
    use velmora_bridge::directory::record::TenantRecord;
    use velmora_bridge::directory::transition::{next, Outcome};
    let record = TenantRecord {
        door: head.door,
        private: head.private.unwrap(),
    };
    let Ok(Outcome::Next(rec)) = next(
        &Tenant::zero(),
        Some(&record),
        &change,
        Actor::Operator,
        m.rig.now(),
    ) else {
        panic!("tenant-0 record");
    };
    let name = record_key(&Tenant::zero(), rec.door.seq);
    let sealed = m
        .seal
        .seal(
            &name,
            &Tenant::zero(),
            rec.door.tk_version,
            &serde_json::to_vec(&rec.door).unwrap(),
            &serde_json::to_vec(&rec.private).unwrap(),
        )
        .unwrap();
    (name, sealed)
}

#[test]
fn the_give_up_refuses_an_older_windows_entry() {
    block_on(async {
        let mut m = window().await;
        m.since += 1;
        let n = m.records();
        let r = m.give_up().await;
        assert!(matches!(r, Err(FlipError::OtherWindow { .. })), "{r:?}");
        assert_eq!(m.records(), n);
        assert_eq!(m.selector().await, Selector::Moving);
    });
}

#[test]
fn an_owner_without_a_live_directory_row_stops_the_flip_before_any_write() {
    block_on(async {
        let m = window().await;
        m.db.apply(&format!(
            "DELETE FROM units WHERE tenant = '{OWNER}';\n\
             DELETE FROM bucket_index WHERE tenant = '{OWNER}';\n\
             DELETE FROM tenants WHERE id = '{OWNER}';"
        ))
        .unwrap();
        let n = m.records();
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::OwnerRow)), "{r:?}");
        assert_eq!(m.records(), n);
        assert!(!m.stamp_put().await);
    });
}

#[test]
fn a_window_named_by_a_record_outside_any_run_is_not_a_window() {
    block_on(async {
        let mut m = window().await;
        // Seq 1: tenant 0's first record, on its D1 with no move.
        m.zero_seq = 1;
        assert!(matches!(m.flip().await, Err(FlipError::NotThisMove)));
        assert!(matches!(m.give_up().await, Err(FlipError::NotThisMove)));
        // Above the head.
        m.zero_seq = 99;
        assert!(matches!(m.flip().await, Err(FlipError::NotThisMove)));
    });
}

#[test]
fn a_window_longer_than_the_bound_is_not_walked() {
    block_on(async {
        let m = window().await;
        let zero = Tenant::zero();
        // Records that keep the window open, up to the bound.
        let mut head = m.head(&zero).await.seq;
        let mut on = true;
        while head - m.zero_seq < MAX_WINDOW_RECORDS - 1 {
            head = m.write(&zero, hold(on), Actor::Operator).await.seq;
            on = !on;
        }
        // Inside the bound: still this window.
        assert!(m.give_up().await.is_ok(), "inside the bound");
        let m = window().await;
        let mut head = m.head(&zero).await.seq;
        let mut on = true;
        while head - m.zero_seq < MAX_WINDOW_RECORDS {
            head = m.write(&zero, hold(on), Actor::Operator).await.seq;
            on = !on;
        }
        assert!(matches!(m.flip().await, Err(FlipError::NotThisMove)));
    });
}

#[test]
fn records_of_no_window_after_the_give_up_keep_its_answer() {
    block_on(async {
        let m = window().await;
        let first = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        let zero = Tenant::zero();
        m.write(&zero, hold(true), Actor::Operator).await;
        m.write(&zero, hold(false), Actor::Operator).await;
        let n = m.records();
        assert_eq!(
            m.give_up().await.map_err(|e| format!("{e:?}")).unwrap(),
            first
        );
        assert_eq!(m.records(), n);
        assert!(matches!(m.flip().await, Err(FlipError::NotThisMove)));
    });
}

#[test]
fn a_shredded_owner_row_stops_the_flip_before_any_write() {
    use velmora_bridge::directory::record::Lifecycle;
    block_on(async {
        let m = window().await;
        let mut gone = m.head(&owner()).await;
        gone.seq += 1;
        gone.lifecycle = Lifecycle::Shredded;
        m.dir().apply_tenant(&gone, m.rig.now()).await.unwrap();
        let n = m.records();
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::OwnerRow)), "{r:?}");
        assert_eq!(m.records(), n);
        assert!(!m.stamp_put().await);
    });
}

// ---------------------------------------------------------------------------
// Round 3: the move's lift report, re-entry, V9, keys, placements, exit
// ---------------------------------------------------------------------------

#[test]
fn the_lift_opens_one_move_report_for_the_units_entry() {
    block_on(async {
        let m = window().await;
        m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        // One report, for (S, the unit's stamp ordinal, a nonce).
        assert_eq!(m.unit.reports.get(), 1);
        let r = m.unit.report.borrow().clone().unwrap();
        assert_eq!((r.since, r.ordinal, r.nonce.as_str()), (m.since, 2, "n1"));
        // The lift record names the entry and the report, by the move
        // tool; the move floor (b1) and tenant 0's flip follow it.
        let l = m.lift_record().await.unwrap();
        assert_eq!((l.unit, l.since_seq), (0, m.since));
        assert_eq!(l.proof.replay_id, r);
        assert!(l.proof.acknowledged.is_empty());
        // V9 ran once, on the open unit, before the routes.
        assert_eq!(m.unit.v9_runs.get(), 1);
        // A run after the flip opens nothing more.
        m.flip().await.unwrap();
        assert_eq!(m.unit.reports.get(), 1);
    });
}

#[test]
fn a_stored_report_that_passes_is_used_and_a_failing_one_replaced() {
    block_on(async {
        // The gate says no once: a second report, with a new nonce.
        let m = window().await;
        m.unit.not_ok.set(1);
        m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_eq!(m.unit.reports.get(), 2);
        assert_eq!(m.unit.report.borrow().clone().unwrap().nonce, "n2");
        // It never passes: no lift record, the unit closed, give-up open.
        let m = window().await;
        m.unit.not_ok.set(99);
        let before = m.records();
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::LiftNotOk)), "{r:?}");
        assert_eq!(m.records(), before);
        assert!(m.head(&owner()).await.restoring_entry(0).is_some());
        assert_eq!(m.unit.closed.get(), Some(m.since));
        m.unit.not_ok.set(0);
        // The next run takes the stored report as it passes now.
        let n = m.unit.reports.get();
        m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_eq!(m.unit.reports.get(), n);
    });
}

#[test]
fn a_refused_report_stops_the_lift() {
    block_on(async {
        let m = window().await;
        // The unit refuses the binding (for one, an import not sealed).
        m.unit.refuse_report.set(true);
        let before = m.records();
        let r = m.flip().await;
        assert!(
            matches!(r, Err(FlipError::Report(GateRefusal::MoveNotBound))),
            "{r:?}"
        );
        assert_eq!(m.records(), before);
    });
}

#[test]
fn a_refused_sync_re_enters_under_a_new_entry() {
    block_on(async {
        let m = window().await;
        let before = m.records();
        m.unit.refuse_lift.set(1);
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
        assert_flipped(&m, f.stamp).await;
        // The first lift, the re-entry's entry, the second lift, the
        // floor, the flip.
        assert_eq!(m.records(), before + 5);
        let l = m.lift_record().await.unwrap();
        assert!(l.since_seq > m.since);
        // The second report names the new entry.
        assert_eq!(m.unit.reports.get(), 2);
        assert_eq!(m.unit.report.borrow().clone().unwrap().since, l.since_seq);
    });
}

#[test]
fn a_lift_the_unit_keeps_refusing_stops_before_the_routes() {
    block_on(async {
        let m = window().await;
        m.unit.refuse_lift.set(99);
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::SyncRefused(_))), "{r:?}");
        assert!(m.routes.records.borrow().is_empty());
        assert_eq!(m.selector().await, Selector::Moving);
        assert!(m.unit.closed.get().is_some());
        assert_eq!(m.unit.v9_runs.get(), 0);
        // The owner's head was lifted by the last try; the give-up closes
        // the unit again and exits.
        let g = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(g.stamp_put);
        let o = m.head(&owner()).await;
        assert!(o.restoring_entry(0).is_some());
        assert!(o.placements.is_empty());
    });
}

#[test]
fn a_crash_after_the_lift_record_syncs_with_its_proof() {
    block_on(async {
        let m = window().await;
        m.unit.fail_lift.set(1);
        assert!(matches!(m.flip().await, Err(FlipError::Store(_))));
        let lifted = m.lift_record().await.unwrap();
        // A tenant-0-free owner record lands on top (a later record of
        // the window): the proof is found below it.
        m.write(&owner(), hold(true), Actor::Operator).await;
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        let (_, proof) = m.unit.synced.borrow().last().unwrap().clone();
        assert_eq!(proof, Some(lifted.proof));
        assert_eq!(m.unit.reports.get(), 1);
        assert!(f.wrote);
    });
}

/// Logs every put of a tenant record, by chain, into the keys' log.
fn log_puts(m: &Move) {
    let log = Rc::clone(&m.keys.log);
    let zero_prefix = "m/t/t_0000000000000000/".to_string();
    let owner_prefix = format!("m/t/{OWNER}/");
    m.store.before_put(move |key, _| {
        if key.starts_with(&zero_prefix) {
            log.borrow_mut().push("zero".into());
        } else if key.starts_with(&owner_prefix) {
            log.borrow_mut().push("owner".into());
        }
    });
}

#[test]
fn v9_failing_in_the_open_unit_gives_the_move_up_for_good() {
    block_on(async {
        let m = window().await;
        log_puts(&m);
        m.unit.v9_ok.set(false);
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::V9Failed)), "{r:?}");
        // The lift and its floor (b1), tenant 0 at d1 first (durable), the
        // unit closed again, the grant revocations, the unplace.
        assert_eq!(
            *m.keys.log.borrow(),
            ["owner", "owner", "zero", "owner", "revoke_grants", "owner"]
        );
        assert!(m.routes.records.borrow().is_empty());
        let o = m.head(&owner()).await;
        assert!(o.placements.is_empty());
        assert_eq!(o.buckets_unplaced.clone().unwrap().buckets, m.buckets);
        assert_eq!(
            m.unit.closed.get(),
            o.restoring_entry(0).map(|e| e.since_seq)
        );
        assert_eq!(m.selector().await, Selector::D1);
        // V9 passing now changes nothing: the window is given up.
        m.unit.v9_ok.set(true);
        assert!(matches!(m.flip().await, Err(FlipError::NotThisMove)));
        assert!(m.routes.records.borrow().is_empty());
        assert_eq!(m.unit.v9_runs.get(), 1);
    });
}

#[test]
fn the_give_up_after_the_unit_opened_exits_in_order() {
    block_on(async {
        let m = window().await;
        log_puts(&m);
        m.routes.fail_after.set(Some(0));
        assert!(m.flip().await.is_err());
        m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        // The lift and its floor (b1); then the unit closed, tenant 0 at
        // d1, the grant revocations, the unplace.
        assert_eq!(
            *m.keys.log.borrow(),
            ["owner", "owner", "owner", "zero", "revoke_grants", "owner"]
        );
    });
}

#[test]
fn a_give_up_that_crashed_before_its_unplace_finishes_it() {
    block_on(async {
        let m = window().await;
        // Tenant 0 is back at d1; the grant revocations are not reached.
        m.keys.fail_grants.set(1);
        let r = m.give_up().await;
        assert!(matches!(r, Err(FlipError::Store(_))), "{r:?}");
        assert_eq!(m.selector().await, Selector::D1);
        let o = m.head(&owner()).await;
        assert_eq!(o.placements.len(), 1);
        assert!(o.moved_in.is_some());
        // Run again: the exit is finished (the revocations again, which
        // are idempotent, then the unplace).
        let g = m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(!g.stamp_put);
        let o = m.head(&owner()).await;
        assert!(o.placements.is_empty());
        assert!(o.moved_in.is_none());
        assert_eq!(m.keys.grants_revoked.borrow().len(), 1);
        // And again: nothing more.
        let n = m.records();
        m.give_up().await.unwrap();
        assert_eq!(m.records(), n);
        assert_eq!(m.keys.grants_revoked.borrow().len(), 1);
    });
}

#[test]
fn an_exit_before_any_placement_revokes_and_removes_nothing() {
    block_on(async {
        let m = window_with(false).await;
        let before = m.records();
        m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(m.keys.grants_revoked.borrow().is_empty());
        // Tenant 0's give-up only.
        assert_eq!(m.records(), before + 1);
        assert_eq!(m.selector().await, Selector::D1);
    });
}

#[test]
fn the_placements_must_be_the_frozen_buckets_less_the_excluded() {
    block_on(async {
        // The canary is not excluded: it should have been placed.
        let mut m = window().await;
        m.excluded.clear();
        let before = m.records();
        let r = m.flip().await;
        assert!(
            matches!(&r, Err(FlipError::Placements { missing, extra })
                if missing.len() == 1 && extra.is_empty()),
            "{r:?}"
        );
        assert_eq!(m.records(), before);
        assert!(!m.stamp_put().await);
        // A placement of a bucket the frozen D1 does not hold.
        let m = window().await;
        m.chain()
            .place_moved_buckets(
                &owner(),
                &["b_00000000000000ff".to_string()],
                0,
                m.rig.now(),
                0,
            )
            .await
            .unwrap();
        let r = m.flip().await;
        assert!(
            matches!(&r, Err(FlipError::Placements { missing, extra })
                if missing.is_empty() && *extra == ["b_00000000000000ff"]),
            "{r:?}"
        );
        assert!(!m.stamp_put().await);
    });
}

#[test]
fn a_flat_revocation_is_swept_into_the_unit_before_the_lift_record() {
    block_on(async {
        let m = window().await;
        m.keys.flat.borrow_mut().insert(KEYS[1].into());
        // The unit had the key active from step 5(e).
        m.unit
            .key_rows
            .borrow_mut()
            .insert(KEYS[1].into(), SubjectStatus::Active);
        let log = Rc::clone(&m.keys.log);
        let owner_prefix = format!("m/t/{OWNER}/");
        m.store.before_put(move |key, _| {
            if key.starts_with(&owner_prefix) {
                log.borrow_mut().push("owner".into());
            }
        });
        m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_eq!(
            m.keys.log.borrow()[..3],
            [
                format!("rk/t/{}", KEYS[1]),
                format!("revoke {}", KEYS[1]),
                "owner".to_string()
            ]
        );
        assert!(m.keys.tenant.borrow().contains(KEYS[1]));
        assert_eq!(m.unit.key_rows.borrow()[KEYS[1]], SubjectStatus::Revoked);
        assert_eq!(m.unit.key_rows.borrow()[KEYS[0]], SubjectStatus::Active);
        // keys_seq of the directory covers the revoke record.
        let row = m.dir().tenant(&owner()).await.unwrap().unwrap();
        assert_eq!(row.keys_seq, 3);
        // A re-run does not revoke twice.
        m.flip().await.unwrap();
        assert_eq!(m.keys.chain.borrow().len(), 3);
    });
}

#[test]
fn a_crash_after_the_flip_record_still_copies_the_selector() {
    block_on(async {
        let m = window().await;
        m.flip().await.unwrap();
        // The directory's copy went missing (a crash before it).
        m.db
            .apply("UPDATE tenants SET selector = 'moving', record_seq = 1 WHERE id = 't_0000000000000000';")
            .unwrap();
        m.flip().await.unwrap();
        assert_eq!(m.dir_row(&Tenant::zero()).await.1, Some(Selector::Moved));
    });
}

#[test]
fn a_gate_answer_that_is_not_this_lift_is_never_used() {
    let bends: [fn(&mut GateView); 5] = [
        |v| v.kind_move = false,
        |v| {
            if let Some(p) = v.proof.as_mut() {
                p.acknowledged.insert(
                    velmora_bridge::unit::lift::AckClass::Damaged,
                    velmora_bridge::unit::lift::ClassProof {
                        count: 1,
                        sha256: "0".repeat(64),
                    },
                );
            }
        },
        |v| {
            if let Some(p) = v.proof.as_mut() {
                p.replay_id.since += 1;
            }
        },
        |v| {
            if let Some(p) = v.proof.as_mut() {
                p.replay_id.nonce = "other".into();
            }
        },
        |v| v.replay_id = None,
    ];
    for bend in bends {
        block_on(async {
            let m = window().await;
            *m.unit.bend.borrow_mut() = Some(bend);
            let before = m.records();
            let r = m.flip().await;
            assert!(matches!(r, Err(FlipError::LiftNotOk)), "{r:?}");
            assert_eq!(m.records(), before);
            assert!(m.head(&owner()).await.restoring_entry(0).is_some());
        });
    }
}

#[test]
fn a_re_entry_that_stopped_after_its_record_closes_the_unit_first() {
    block_on(async {
        let m = window().await;
        // The lift is refused once; the re-entry's closing sync is not
        // reached.
        m.unit.refuse_lift.set(1);
        m.unit.fail_after_refusal.set(true);
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::Store(_))), "{r:?}");
        let o = m.head(&owner()).await;
        let s2 = o.restoring_entry(0).unwrap().since_seq;
        assert!(s2 > m.since);
        // The unit is still on the first entry.
        assert_eq!(m.unit.closed.get(), Some(m.since));
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
        assert_eq!(m.unit.report.borrow().clone().unwrap().since, s2);
        assert_eq!(m.lift_record().await.unwrap().since_seq, s2);
    });
}

#[test]
fn a_crash_after_the_lift_record_then_a_refusal_re_enters() {
    block_on(async {
        let m = window().await;
        let before = m.records();
        m.unit.fail_lift.set(1);
        assert!(matches!(m.flip().await, Err(FlipError::Store(_))));
        // The stored lift's sync is refused once: a re-entry from the
        // lifted head.
        m.unit.refuse_lift.set(1);
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
        // Lift, re-entry, lift, floor, flip.
        assert_eq!(m.records(), before + 5);
        assert_eq!(m.unit.reports.get(), 2);
    });
}

#[test]
fn a_lift_refused_every_time_stops_after_the_bound() {
    use velmora_bridge::directory::move_flip::MAX_REENTRIES;
    block_on(async {
        let m = window().await;
        let before = m.records();
        m.unit.refuse_lift.set(99);
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::SyncRefused(_))), "{r:?}");
        let tries = MAX_REENTRIES as usize + 1;
        // A lift per try, an entry between tries.
        assert_eq!(m.records(), before + tries + MAX_REENTRIES as usize);
        assert_eq!(m.unit.reports.get() as usize, tries);
    });
}

#[test]
fn a_later_window_replaces_a_route_record_an_earlier_give_up_put_back() {
    block_on(async {
        let mut m = window().await;
        // The first window put one route record, then gave up: the record
        // names tenant 0 again.
        m.routes.fail_after.set(Some(1));
        assert!(m.flip().await.is_err());
        m.routes.fail_after.set(None);
        m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_eq!(m.routes.records.borrow()[KEYS[0]], Tenant::zero().as_str());
        // A second window into the same owner.
        let w2 = m
            .write(
                &Tenant::zero(),
                Change::StartMove {
                    to: owner(),
                    catalogue_id_frozen: "main".into(),
                },
                Actor::MoveTool,
            )
            .await;
        m.zero_seq = w2.seq;
        m.since = m.head(&owner()).await.restoring_entry(0).unwrap().since_seq;
        m.place().await;
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
        for akid in KEYS {
            assert_eq!(m.routes.records.borrow()[akid], OWNER);
        }
        // Give-up's replace, then the second window's.
        assert_eq!(m.routes.replaced.get(), 2);
    });
}

#[test]
fn a_window_with_nothing_to_move_stops_before_any_write() {
    block_on(async {
        let mut m = window_with(false).await;
        m.excluded.extend(m.buckets.clone());
        let before = m.records();
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::NothingMoved)), "{r:?}");
        assert_eq!(m.records(), before);
        assert!(!m.stamp_put().await);
        assert_eq!(m.unit.closed.get(), Some(m.since));
    });
}

#[test]
fn a_v9_give_up_that_stopped_keeps_the_v9_answer() {
    block_on(async {
        let m = window().await;
        m.unit.v9_ok.set(false);
        m.keys.fail_grants.set(1);
        let r = m.flip().await;
        assert!(
            matches!(&r, Err(FlipError::V9GiveUp(inner)) if matches!(**inner, FlipError::Store(_))),
            "{r:?}"
        );
        // Tenant 0 is at d1; the give-up finishes the exit.
        assert_eq!(m.selector().await, Selector::D1);
        m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(m.head(&owner()).await.placements.is_empty());
        assert!(m.unit.closed.get().is_some());
    });
}

#[test]
fn the_lift_sync_applies_the_keys_and_re_reads_a_stale_head() {
    block_on(async {
        let m = window().await;
        let before = m.records();
        m.unit
            .lift_answers
            .borrow_mut()
            .extend([UnitRefused::KeysNotApplied, UnitRefused::StaleSync]);
        let applies = m.unit.applies.get();
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
        assert_flipped(&m, f.stamp).await;
        // Neither re-entered: one lift record, the floor and the flip.
        assert_eq!(m.records(), before + 3);
        assert_eq!(m.unit.reports.get(), 1);
        assert!(m.unit.applies.get() > applies + 1);
        // A refusal that is neither stops the flip, before the routes.
        let m = window().await;
        m.unit
            .lift_answers
            .borrow_mut()
            .push_back(UnitRefused::AccountProblem);
        let r = m.flip().await;
        assert!(
            matches!(r, Err(FlipError::SyncRefused(UnitRefused::AccountProblem))),
            "{r:?}"
        );
        assert!(m.routes.records.borrow().is_empty());
    });
}

#[test]
fn a_gate_refusal_on_an_open_unit_is_the_lift_that_landed() {
    block_on(async {
        let m = window().await;
        let before = m.records();
        m.unit.open_on_refusal.set(true);
        m.unit
            .lift_answers
            .borrow_mut()
            .push_back(UnitRefused::Gate(GateRefusal::NotRestoring));
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert!(f.wrote);
        // No re-entry: the lift record, the floor and the flip only.
        assert_eq!(m.records(), before + 3);
        assert!(m.unit.closed.get().is_none());
    });
}

#[test]
fn the_lift_needs_this_windows_sealed_import() {
    for import in [
        None,
        Some(ImportState {
            t0_seq: Some(1 << 40),
            sealed: None,
            lifted_at: None,
            tables: vec![],
        }),
        Some(ImportState {
            t0_seq: Some(1 << 40),
            sealed: Some(2),
            lifted_at: None,
            tables: vec![],
        }),
        Some(ImportState {
            t0_seq: Some(1),
            sealed: Some(1),
            lifted_at: None,
            tables: vec![],
        }),
        Some(ImportState {
            t0_seq: None,
            sealed: Some(1),
            lifted_at: None,
            tables: vec![],
        }),
    ] {
        block_on(async {
            let m = window().await;
            *m.unit.import.borrow_mut() = import.clone();
            let before = m.records();
            let r = m.flip().await;
            assert!(
                matches!(r, Err(FlipError::NotThisImport)),
                "{import:?}: {r:?}"
            );
            assert_eq!(m.records(), before);
            assert_eq!(m.unit.reports.get(), 0);
            assert!(m.head(&owner()).await.restoring_entry(0).is_some());
        });
    }
}

/// AM-67 (b1): the flip writes the move floor at the unit's own lift time
/// before V9 and the routes, and stops there while the unit does not say
/// it; a later run with the time writes it and goes on.
#[test]
fn the_flip_writes_the_move_floor_before_v9_and_the_routes() {
    block_on(async {
        let m = window().await;
        if let Some(i) = m.unit.import.borrow_mut().as_mut() {
            i.lifted_at = None;
        }
        let r = m.flip().await;
        assert!(matches!(r, Err(FlipError::NoLiftTime)), "{r:?}");
        // The unit is open; no V9, no route, no floor.
        assert!(m.unit.closed.get().is_none());
        assert_eq!(m.unit.v9_runs.get(), 0);
        assert!(m.routes.records.borrow().is_empty());
        assert!(m.head(&owner()).await.move_floors.is_empty());
        assert_eq!(m.selector().await, Selector::Moving);
        // The unit says its lift time now: the floor, then the rest.
        if let Some(i) = m.unit.import.borrow_mut().as_mut() {
            i.lifted_at = Some(LIFTED_AT);
        }
        let f = m.flip().await.map_err(|e| format!("{e:?}")).unwrap();
        assert_flipped(&m, f.stamp).await;
        // The directory's copy holds the floor too.
        let row = m.dir().tenant(&owner()).await.unwrap().unwrap();
        assert_eq!(row.door.move_floors.get(&0), Some(&LIFTED_AT));
    });
}

/// AM-67 writer 2: after a give-up's `deleteAll()`, the floor of the unit
/// rises to the clock after it, also for a window whose import never
/// lifted; a repeat or an older clock changes nothing.
#[test]
fn an_exit_that_empties_the_unit_raises_its_floor() {
    block_on(async {
        let m = window().await;
        m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        let emptied = UnixMs(m.rig.now().0 + 1_000);
        let o = floor_after_empty(&m.chain(), &m.dir(), &owner(), 0, emptied)
            .await
            .map_err(|e| format!("{e:?}"))
            .unwrap();
        assert_eq!(o.move_floors.get(&0), Some(&emptied));
        let n = m.records();
        let again = floor_after_empty(&m.chain(), &m.dir(), &owner(), 0, emptied)
            .await
            .unwrap();
        assert_eq!(again.move_floors.get(&0), Some(&emptied));
        assert!(
            floor_after_empty(&m.chain(), &m.dir(), &owner(), 0, UnixMs(emptied.0 - 5))
                .await
                .is_ok()
        );
        assert_eq!(m.records(), n);
        let row = m.dir().tenant(&owner()).await.unwrap().unwrap();
        assert_eq!(row.door.move_floors.get(&0), Some(&emptied));
    });
}

/// Review b1 r1 MEDIUM: an exit of this owner's move that runs after a
/// later move into another tenant began still raises the owner's floor
/// (writer 2), and so does the restore tool (writer 3).
#[test]
fn an_exit_after_a_later_move_elsewhere_still_raises_the_floor() {
    block_on(async {
        let m = window().await;
        m.give_up().await.map_err(|e| format!("{e:?}")).unwrap();
        // A later window into another tenant.
        let other = Tenant::parse("t_00000000000000b2").unwrap();
        m.chain()
            .write(
                &Tenant::zero(),
                &Change::StartMove {
                    to: other,
                    catalogue_id_frozen: velmora_bridge::config::DEFAULT_CATALOGUE_ID.into(),
                },
                Actor::MoveTool,
                m.rig.now(),
                0,
            )
            .await
            .unwrap();
        assert_eq!(m.selector().await, Selector::Moving);
        let emptied = UnixMs(m.rig.now().0 + 1_000);
        let o = floor_after_empty(&m.chain(), &m.dir(), &owner(), 0, emptied)
            .await
            .map_err(|e| format!("{e:?}"))
            .unwrap();
        assert_eq!(o.move_floors.get(&0), Some(&emptied));
        let raised = UnixMs(emptied.0 + 1);
        m.chain()
            .set_move_floor(&owner(), 0, raised, Actor::RestoreTool, raised, 0)
            .await
            .unwrap();
        assert_eq!(m.head(&owner()).await.move_floors.get(&0), Some(&raised));
    });
}
