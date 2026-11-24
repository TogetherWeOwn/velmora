//! Provider permits from a gate (`velmora_bridge::gate`): the same rules
//! as the catalogue's slot rows, a restart that loses the memory, old
//! and new Workers side by side, and what it costs in requests and
//! writes.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::Future;
use std::rc::Rc;

use futures_util::future::join_all;
use velmora_bridge::gate::*;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::TestSql;
use velmora_bridge::*;

const T0: i64 = 1_762_992_000_123;
const JOB_MS: i64 = 120_000;
const READ_MS: i64 = 35_000;

fn provider(id: &str, max_conns: u32) -> ProviderConfig {
    let json = format!(
        "{{\"id\":\"{id}\",\"host\":\"news.example.invalid\",\"port\":563,\"tls\":true,\
         \"user\":\"u\",\"pass\":\"p\",\"backbone\":\"bb\",\"post\":true,\"read\":true,\
         \"max_conns\":{max_conns}}}"
    );
    serde_json::from_str(&json).unwrap()
}

fn with_ips(mut p: ProviderConfig, max_ips: u32) -> ProviderConfig {
    p.max_ips = Some(max_ips);
    p
}

fn pooled(id: &str, max_conns: u32, pool: &str, pool_max_conns: u32) -> ProviderConfig {
    let mut p = provider(id, max_conns);
    p.pool = Some(pool.into());
    p.pool_max_conns = Some(pool_max_conns);
    p
}

/// One database for the catalogue callers and the gates.
#[derive(Clone)]
struct Db(Rc<TestSql>);

impl Sql for Db {
    fn dialect(&self) -> Dialect {
        self.0.dialect()
    }
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.0.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.0.exec(sql, params).await
    }
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        self.0.batch(stmts).await
    }
}

/// The durable storage of one gate. It outlives the gate's memory.
#[derive(Clone, Default)]
struct Store {
    record: Rc<RefCell<Option<GateRecord>>>,
    saves: Rc<Cell<u32>>,
    fail: Rc<Cell<bool>>,
}

impl GateStore for Store {
    async fn load(&self) -> Result<Option<GateRecord>> {
        Ok(self.record.borrow().clone())
    }
    async fn save(&self, record: &GateRecord) -> Result<()> {
        if self.fail.get() {
            return Err(BridgeError::Sql("storage is down".into()));
        }
        self.saves.set(self.saves.get() + 1);
        *self.record.borrow_mut() = Some(record.clone());
        Ok(())
    }
}

/// What the runtime keeps of a gate's open sessions while the object
/// is out of memory: per session, what was attached to its connection.
type Sockets = BTreeMap<String, BTreeMap<u64, SessionState>>;

/// The most the runtime keeps with one connection, in bytes.
const ATTACHMENT_MAX: usize = 16_384;

/// The gates of a deployment: their storage, their open sessions, their
/// memory (lost on [`World::hibernate`], [`World::restart`] and
/// [`World::crash`]) and the clock they read.
struct World {
    db: Db,
    now: Cell<i64>,
    stores: RefCell<BTreeMap<String, Store>>,
    gates: RefCell<BTreeMap<String, Rc<Gate<Db, Store>>>>,
    sockets: RefCell<Sockets>,
    /// The version of the code the gates run.
    boot: Cell<u32>,
    /// Every round trip to a gate: `opens + msgs + posts`.
    calls: Cell<u32>,
    /// Sessions opened: each is one billed request.
    opens: Cell<u32>,
    /// Messages on open sessions: each is billed as 1/20 request.
    msgs: Cell<u32>,
    /// Requests without a session: each is one billed request.
    posts: Cell<u32>,
    ops: Cell<u32>,
    /// No gate can be reached.
    down: Cell<bool>,
    /// Requests to a gate do not arrive while this is set.
    stall: Cell<bool>,
    /// Replies on a session do not arrive while this is set; the gate
    /// has answered.
    late: Cell<bool>,
}

impl World {
    fn new() -> Rc<Self> {
        Rc::new(World {
            db: Db(Rc::new(TestSql::with_schema().unwrap())),
            now: Cell::new(T0),
            stores: RefCell::default(),
            gates: RefCell::default(),
            sockets: RefCell::default(),
            boot: Cell::new(1),
            calls: Cell::new(0),
            opens: Cell::new(0),
            msgs: Cell::new(0),
            posts: Cell::new(0),
            ops: Cell::new(0),
            down: Cell::new(false),
            late: Cell::new(false),
            stall: Cell::new(false),
        })
    }

    fn now(&self) -> UnixMs {
        UnixMs(self.now.get())
    }

    fn pass(&self, ms: i64) {
        self.now.set(self.now.get() + ms);
    }

    fn store(&self, name: &str) -> Store {
        self.stores
            .borrow_mut()
            .entry(name.to_string())
            .or_default()
            .clone()
    }

    /// The gate in memory, as the host brings it there for an event:
    /// with the sessions whose connections are still open.
    async fn gate(&self, name: &str) -> Rc<Gate<Db, Store>> {
        let store = self.store(name);
        let gate = self
            .gates
            .borrow_mut()
            .entry(name.to_string())
            .or_insert_with(|| {
                Rc::new(Gate::new(
                    self.db.clone(),
                    store,
                    format!("v{}", self.boot.get()),
                ))
            })
            .clone();
        if !gate.started() {
            let open = self.sockets.borrow().get(name).cloned().unwrap_or_default();
            let sessions = open.into_values().collect();
            // A start that fails is tried again at the next event.
            let _ = gate.resume(sessions, self.now()).await;
        }
        gate
    }

    /// The objects leave memory between two events. Their sessions stay
    /// open.
    fn hibernate(&self) {
        self.gates.borrow_mut().clear();
    }

    /// New code that cuts every session: the objects lose their memory
    /// and their connections, and start as another version.
    fn restart(&self) {
        self.boot.set(self.boot.get() + 1);
        self.crash();
    }

    /// The objects are reset without a deploy: memory and connections
    /// are gone, the version is the same.
    fn crash(&self) {
        self.gates.borrow_mut().clear();
        self.sockets.borrow_mut().clear();
    }

    /// Sessions open at the gate `name`.
    fn sessions(&self, name: &str) -> usize {
        self.sockets.borrow().get(name).map_or(0, BTreeMap::len)
    }

    /// A catalogue as a Worker of `mode` has it.
    fn catalog(
        self: &Rc<Self>,
        mode: PermitMode,
        sharding: GateSharding,
        providers: &[ProviderConfig],
    ) -> SqlCatalog<Db> {
        self.catalog_of(mode, sharding, 1, providers)
    }

    /// The same, with each account or pool divided over `shards` gates.
    fn catalog_of(
        self: &Rc<Self>,
        mode: PermitMode,
        sharding: GateSharding,
        shards: u32,
        providers: &[ProviderConfig],
    ) -> SqlCatalog<Db> {
        let clock = {
            let w = self.clone();
            move || w.now()
        };
        let client = GateClient::new(Wire(self.clone()), clock, mode, sharding, shards, providers);
        SqlCatalog::with_gate(self.db.clone(), client.into_gate())
    }

    /// A catalogue as a Worker from before the gate has it.
    fn old_catalog(&self) -> SqlCatalog<Db> {
        SqlCatalog::new(self.db.clone())
    }

    async fn count(&self, sql: &str) -> i64 {
        match self.db.0.fixture_query(sql, &[]).await.unwrap()[0][0] {
            SqlValue::Int(n) => n,
            ref other => panic!("not an integer: {other:?}"),
        }
    }

    /// Slot rows of `provider` that a catalogue caller holds now.
    async fn rows_of_callers(&self, provider: &str) -> i64 {
        self.count(&format!(
            "SELECT COUNT(*) FROM provider_permits WHERE provider_id = '{provider}' \
             AND lease_until >= {} AND holder NOT LIKE 'do-gate:%'",
            self.now.get()
        ))
        .await
    }

    /// Slot rows of `provider` that a gate has seized.
    async fn rows_of_gates(&self, provider: &str) -> i64 {
        self.count(&format!(
            "SELECT COUNT(*) FROM provider_permits WHERE provider_id = '{provider}' \
             AND lease_until >= {} AND holder LIKE 'do-gate:%'",
            self.now.get()
        ))
        .await
    }

    async fn load(&self, gate: &str) -> Vec<GateLoad> {
        let reply = self
            .gate(gate)
            .await
            .handle(
                None,
                GateRequest {
                    id: 0,
                    gate: gate.into(),
                    ops: vec![GateOp::Load],
                },
                self.now(),
            )
            .await
            .unwrap();
        match reply.answers.into_iter().next() {
            Some(GateAnswer::Load(load)) => load,
            other => panic!("not a load: {other:?}"),
        }
    }

    /// Slots the gate `gate` has handed out on `provider` and that are
    /// live.
    async fn held(&self, gate: &str, provider: &str) -> u32 {
        self.load(gate)
            .await
            .iter()
            .find(|l| l.provider == provider)
            .map_or(0, |l| l.held)
    }
}

struct Wire(Rc<World>);

impl Wire {
    /// A request on its way: it may not arrive, or find no gate.
    async fn arrive(&self, request: &GateRequest) -> Result<GateRequest> {
        core::future::poll_fn(|_| match self.0.stall.get() {
            true => core::task::Poll::Pending,
            false => core::task::Poll::Ready(()),
        })
        .await;
        if self.0.down.get() {
            return Err(BridgeError::Sql("gate: unreachable".into()));
        }
        self.0.calls.set(self.0.calls.get() + 1);
        self.0.ops.set(self.0.ops.get() + request.ops.len() as u32);
        // As on the wire: the request and the reply are JSON.
        Ok(serde_json::from_str(&serde_json::to_string(request).unwrap()).unwrap())
    }
}

fn on_the_wire(reply: &GateReply) -> GateReply {
    serde_json::from_str(&serde_json::to_string(reply).unwrap()).unwrap()
}

/// The caller's end of a session.
struct Line {
    world: Rc<World>,
    gate: String,
    id: u64,
}

impl Line {
    /// The session is kept with its connection, as the host does before
    /// a reply leaves.
    fn attach(&self, gate: &Gate<Db, Store>) {
        let state = gate.session(self.id, self.world.now());
        let size = serde_json::to_string(&state).unwrap().len();
        assert!(size <= ATTACHMENT_MAX, "{size} bytes with one connection");
        self.world
            .sockets
            .borrow_mut()
            .entry(self.gate.clone())
            .or_default()
            .insert(self.id, state);
    }

    fn open(&self) -> bool {
        self.world
            .sockets
            .borrow()
            .get(&self.gate)
            .is_some_and(|s| s.contains_key(&self.id))
    }
}

impl GateSession for Line {
    async fn call(&self, request: GateRequest) -> Result<GateReply> {
        let request = Wire(self.world.clone()).arrive(&request).await?;
        if !self.open() {
            return Err(BridgeError::Sql("gate: session ended".into()));
        }
        self.world.msgs.set(self.world.msgs.get() + 1);
        let gate = self.world.gate(&self.gate).await;
        let id = request.id;
        // The host answers a request the gate failed at with no answers.
        let reply = gate
            .handle(Some(self.id), request, self.world.now())
            .await
            .unwrap_or(GateReply::failed(id));
        self.attach(&gate);
        // A reply that was sent is read even if the session ended
        // while it was on its way.
        core::future::poll_fn(|_| match self.world.late.get() {
            true => core::task::Poll::Pending,
            false => core::task::Poll::Ready(()),
        })
        .await;
        Ok(on_the_wire(&reply))
    }

    fn close(&self) {
        let was_open = self
            .world
            .sockets
            .borrow_mut()
            .get_mut(&self.gate)
            .is_some_and(|s| s.remove(&self.id).is_some());
        // An object in memory hears of the end at once; one that is not
        // starts without the session.
        let gate = self.world.gates.borrow().get(&self.gate).cloned();
        if let (true, Some(gate)) = (was_open, gate) {
            gate.close(self.id);
        }
    }
}

impl GateTransport for Wire {
    type Session = Line;

    async fn open(&self, request: GateRequest) -> Result<(Line, GateReply)> {
        let request = self.arrive(&request).await?;
        self.0.opens.set(self.0.opens.get() + 1);
        let gate = self.0.gate(&request.gate).await;
        let now = self.0.now();
        let line = Line {
            world: self.0.clone(),
            gate: request.gate.clone(),
            id: gate.open(now).await?,
        };
        match gate.handle(Some(line.id), request, now).await {
            Ok(reply) => {
                line.attach(&gate);
                Ok((line, on_the_wire(&reply)))
            }
            Err(e) => {
                gate.close(line.id);
                Err(e)
            }
        }
    }

    async fn call(&self, request: GateRequest) -> Result<GateReply> {
        let request = self.arrive(&request).await?;
        self.0.posts.set(self.0.posts.get() + 1);
        let gate = self.0.gate(&request.gate).await;
        let reply = gate.handle(None, request, self.0.now()).await?;
        Ok(on_the_wire(&reply))
    }
}

/// The lease of a job whose outbox row is not there: its renewal
/// changes nothing and says so.
fn no_lease() -> Lease {
    Lease {
        extent: ExtentId::new("x_none"),
        generation: GenerationId::new("g_none"),
        stage: OutboxStage::Post,
        token: 1,
        attempts: 1,
        cursor: 0,
        claimed_at: UnixMs(T0),
    }
}

const JOB: PermitClass = PermitClass::Background;
const READ: PermitClass = PermitClass::Read;

async fn take(
    c: &SqlCatalog<Db>,
    w: &World,
    p: &ProviderConfig,
    class: PermitClass,
    holder: &str,
) -> Option<Permit> {
    c.acquire_permit(p, class, holder, w.now()).await.unwrap()
}

// ---------------------------------------------------------------------------
// The same rules as the catalogue
// ---------------------------------------------------------------------------

/// A small generator with a fixed seed: the schedule is the same on
/// every run.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, below: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % below
    }
}

/// The slots in memory decide every acquire, renewal and release as the
/// slot rows do, over a long schedule on providers with every kind of
/// limit: the same answer and the same slot number each time.
#[tokio::test]
async fn memory_and_slot_rows_decide_alike() {
    let providers = [
        provider("plain", 3),
        provider("one", 1),
        with_ips(provider("two-ips", 4), 2),
        with_ips(provider("one-ip", 3), 1),
        with_ips(provider("three-ips", 5), 3),
        pooled("pool-a", 3, "bundle", 4),
        pooled("pool-b", 3, "bundle", 4),
        with_ips(pooled("pool-c", 2, "bundle", 4), 2),
        pooled("solo", 2, "alone", 1),
    ];
    for seed in 1..=6u64 {
        let rows = SqlCatalog::new(TestSql::with_schema().unwrap());
        rows.seed_permits(&providers).await.unwrap();
        let mut core = Core::new(UnixMs(T0));
        let mut rng = Lcg(seed);
        let mut now = T0;
        // The same slot as each side knows it.
        let mut held: Vec<(Permit, GatePermit)> = Vec::new();
        let (mut granted, mut refused) = (0, 0);
        for step in 0..4000 {
            match rng.next(10) {
                0..=4 => {
                    let p = &providers[rng.next(providers.len() as u64) as usize];
                    let class = if rng.next(3) == 0 { READ } else { JOB };
                    let holder = format!("h{}", rng.next(4));
                    let a = rows
                        .acquire_permit(p, class, &holder, UnixMs(now))
                        .await
                        .unwrap();
                    let b = core.acquire(
                        &GateProvider::from(p),
                        &[],
                        class == JOB,
                        (&holder, 1),
                        UnixMs(now),
                        Warm::Done,
                    );
                    assert_eq!(
                        a.as_ref().map(|a| a.slot),
                        b.as_ref().map(|b| b.slot),
                        "seed {seed} step {step}: {} {class:?} {holder}",
                        p.id
                    );
                    match (a, b) {
                        (Some(a), Some(b)) => {
                            granted += 1;
                            held.push((a, b));
                        }
                        _ => refused += 1,
                    }
                }
                5..=6 if !held.is_empty() => {
                    let (a, b) = &held[rng.next(held.len() as u64) as usize];
                    let x = rows.renew_permit(a, UnixMs(now)).await.unwrap();
                    let y = core.renew(b, 1, UnixMs(now));
                    assert_eq!(x, y, "seed {seed} step {step}: renew {}", a.provider);
                }
                7 if !held.is_empty() => {
                    let (a, b) = held.swap_remove(rng.next(held.len() as u64) as usize);
                    rows.release_permit(&a).await.unwrap();
                    core.release(&b, 1);
                }
                _ => now += rng.next(30_000) as i64,
            }
        }
        assert!(granted > 300 && refused > 300, "{granted} / {refused}");
    }
}

/// What the dispatcher reads to pick a provider is what the gate has
/// handed out, not the seized rows.
#[tokio::test]
async fn load_is_what_the_gate_handed_out() {
    let w = World::new();
    let providers = [with_ips(provider("p", 4), 3), provider("q", 2)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let a = take(&c, &w, &providers[0], JOB, "job-1").await.unwrap();
    take(&c, &w, &providers[0], JOB, "job-1").await.unwrap();
    take(&c, &w, &providers[0], READ, "read-1").await.unwrap();
    let load = c.provider_load(w.now()).await.unwrap();
    let p = load.iter().find(|l| l.provider_id == "p").unwrap();
    assert_eq!((p.held, p.holders, p.background_holders), (3, 2, 1));
    assert_eq!(p.uses, 3);
    let q = load.iter().find(|l| l.provider_id == "q").unwrap();
    assert_eq!((q.held, q.holders, q.background_holders), (0, 0, 0));
    c.release_permit(&a).await.unwrap();
    let load = c.provider_load(w.now()).await.unwrap();
    assert_eq!(load.iter().find(|l| l.provider_id == "p").unwrap().held, 2);
}

// ---------------------------------------------------------------------------
// Losing the memory
// ---------------------------------------------------------------------------

/// New code that starts after the horizon of the old slots has passed
/// waits for nothing.
#[tokio::test]
async fn a_start_after_idle_hands_out_at_once() {
    let w = World::new();
    let providers = [provider("p", 3)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let a = take(&c, &w, &providers[0], JOB, "job-1").await.unwrap();
    c.release_permit(&a).await.unwrap();
    let record = w.store("permits:all:0").record.borrow().clone().unwrap();
    w.pass(record.jobs_until + SKEW_MS - w.now.get());

    w.restart();
    w.pass(1);
    assert!(take(&c, &w, &providers[0], JOB, "job-2").await.is_some());
    assert!(take(&c, &w, &providers[0], READ, "read-2").await.is_some());
}

/// The object leaves memory between two messages of its sessions and
/// comes back with every slot as it was: the holders renew and free
/// them, nobody else gets them, and nothing waits. Nothing is written
/// for it.
#[tokio::test]
async fn slots_outlive_the_memory_with_their_sessions() {
    let w = World::new();
    let p = with_ips(provider("p", 3), 2);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let a = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    let b = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    let r = take(&c, &w, &p, READ, "read-1").await.unwrap();
    let store = w.store("permits:all:0");
    let saves = store.saves.get();

    for _ in 0..5 {
        w.hibernate();
        w.pass(15_000);
        assert_eq!(w.held("permits:all:0", "p").await, 3);
        assert!(take(&c, &w, &p, JOB, "job-2").await.is_none(), "full");
        w.hibernate();
        assert!(c.renew_permit(&a, w.now()).await.unwrap());
        assert!(c.renew_permit(&b, w.now()).await.unwrap());
        assert!(c.renew_permit(&r, w.now()).await.unwrap());
    }
    assert_eq!(store.saves.get(), saves, "no write for any of it");

    // Freed at an object that has just come back: the place is free.
    w.hibernate();
    c.release_permit(&a).await.unwrap();
    let next = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    assert_eq!(next.slot, a.slot);
    assert!(next.token > r.token.max(b.token), "tokens never repeat");
    // A slot not renewed ends on time, in or out of memory.
    w.hibernate();
    w.pass(READ_MS + 1);
    assert!(!c.renew_permit(&r, w.now()).await.unwrap());
}

/// The end of a session frees its slots at once, whether the object is
/// in memory or not: a holder whose invocation ended holds nothing.
#[tokio::test]
async fn the_end_of_a_session_frees_its_slots() {
    let w = World::new();
    let p = provider("p", 4);
    let providers = [p.clone()];
    for asleep in [false, true] {
        let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
        take(&c, &w, &p, JOB, "job-1").await.unwrap();
        take(&c, &w, &p, JOB, "job-1").await.unwrap();
        take(&c, &w, &p, JOB, "job-2").await.unwrap();
        assert_eq!(w.sessions("permits:all:0"), 2);
        if asleep {
            w.hibernate();
        }
        // The invocation of job-1 ends: the runtime closes its socket.
        let ended: Vec<u64> = w.sockets.borrow()["permits:all:0"]
            .iter()
            .filter(|(_, s)| s.held.len() == 2)
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(ended.len(), 1);
        Line {
            world: w.clone(),
            gate: "permits:all:0".into(),
            id: ended[0],
        }
        .close();
        assert_eq!(w.held("permits:all:0", "p").await, 1);
        assert!(take(&c, &w, &p, JOB, "job-3").await.is_some());
        w.restart();
        assert_eq!(w.held("permits:all:0", "p").await, 0);
        w.pass(JOB_MS + SKEW_MS + 1);
    }
}

/// What this design leaves open, pinned so that a change to it is
/// seen: a reset that is not a deploy cuts the sessions and the gate
/// starts with nothing to wait for. A holder from before learns at its
/// next renewal that it holds nothing.
#[tokio::test]
async fn a_reset_without_a_deploy_is_not_waited_out() {
    let w = World::new();
    let p = provider("p", 2);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let old = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    w.crash();
    w.pass(1);
    let other = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    assert!(take(&other, &w, &p, JOB, "job-2").await.is_some());
    assert!(!c.renew_permit(&old, w.now()).await.unwrap());
}

/// A permit from before a restart is worth nothing at the new object:
/// it cannot be renewed, and giving it back frees nothing, even where
/// the new object handed out the same slot number.
#[tokio::test]
async fn an_old_permit_neither_renews_nor_frees_after_a_restart() {
    let w = World::new();
    let providers = [provider("p", 2)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let old = take(&c, &w, &providers[0], JOB, "job-1").await.unwrap();
    assert_eq!(old.slot, 0);

    w.restart();
    w.pass(1);
    assert!(!c.renew_permit(&old, w.now()).await.unwrap());
    // The wait counts from the first request the new object sees.
    assert_eq!(w.held("permits:all:0", "p").await, 0);
    w.pass(JOB_MS + SKEW_MS);
    let new = take(&c, &w, &providers[0], JOB, "job-2").await.unwrap();
    assert_eq!(new.slot, 0, "the same slot number");
    assert!(new.token > old.token, "tokens never repeat");
    assert!(!c.renew_permit(&old, w.now()).await.unwrap());
    c.release_permit(&old).await.unwrap();
    assert_eq!(
        w.held("permits:all:0", "p").await,
        1,
        "the new holder keeps it"
    );
    assert!(c.renew_permit(&new, w.now()).await.unwrap());
}

/// Tokens of a later start are above those of an earlier one even when
/// the earlier one handed out many.
#[test]
fn tokens_of_a_later_start_are_higher() {
    let p = GateProvider::from(&provider("p", 1));
    let mut first = Core::new(UnixMs(T0));
    let mut last = 0;
    for _ in 0..100_000 {
        let permit = first
            .acquire(&p, &[], true, ("h", 1), UnixMs(T0), Warm::Done)
            .unwrap();
        last = permit.token;
        first.release(&permit, 1);
    }
    let mut second = Core::new(UnixMs(T0 + 1));
    let permit = second
        .acquire(&p, &[], true, ("h", 1), UnixMs(T0 + 1), Warm::Done)
        .unwrap();
    assert!(permit.token > last);
}

/// The worst case of a restart, step by step. Just before the object
/// loses its memory every slot is taken and renewed, so the old holders
/// keep their connections for a full lifetime. From the restart on, the
/// old connections that may still be open plus the slots handed out
/// anew never exceed `max_conns`, the jobs' share, or the addresses.
#[tokio::test]
async fn a_restart_under_load_never_exceeds_the_limits() {
    let w = World::new();
    // 4 connections (3 for jobs), 3 addresses (2 for jobs).
    let p = with_ips(provider("p", 4), 3);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let mut old = vec![
        (take(&c, &w, &p, JOB, "job-1").await.unwrap(), JOB),
        (take(&c, &w, &p, JOB, "job-1").await.unwrap(), JOB),
        (take(&c, &w, &p, JOB, "job-2").await.unwrap(), JOB),
        (take(&c, &w, &p, READ, "read-1").await.unwrap(), READ),
    ];
    assert!(take(&c, &w, &p, READ, "read-2").await.is_none(), "full");
    w.pass(20_000);
    for (permit, _) in &old {
        assert!(c.renew_permit(permit, w.now()).await.unwrap());
    }
    let crashed = w.now.get();
    w.restart();

    let mut new: Vec<(Permit, PermitClass, i64)> = Vec::new();
    let (mut first_read, mut first_job) = (None, None);
    for second in 0..200 {
        w.pass(1000);
        let now = w.now.get();
        // An old holder finds out at its next renewal; until then, and
        // at worst until its slot would have expired, its socket is open.
        old.retain(|(_, class)| {
            let ttl = if *class == JOB { JOB_MS } else { READ_MS };
            now <= crashed + ttl
        });
        new.retain(|(_, _, until)| now <= *until);
        for (class, holder) in [(JOB, "job-3"), (READ, "read-3"), (JOB, "job-4")] {
            if let Some(permit) = take(&c, &w, &p, class, holder).await {
                let ttl = if class == JOB { JOB_MS } else { READ_MS };
                new.push((permit, class, now + ttl));
                match class {
                    PermitClass::Read => first_read.get_or_insert(second),
                    PermitClass::Background => first_job.get_or_insert(second),
                    PermitClass::Drill => unreachable!("no drill slot is asked for here"),
                };
            }
        }
        let jobs = |old: &[(Permit, PermitClass)], new: &[(Permit, PermitClass, i64)]| {
            old.iter().filter(|o| o.1 == JOB).count() + new.iter().filter(|n| n.1 == JOB).count()
        };
        let open = old.len() + new.len();
        assert!(open <= 4, "second {second}: {open} connections");
        assert!(jobs(&old, &new) <= 3, "second {second}: jobs");
        // Addresses: each old holder may be one; the new ones are
        // job-3, job-4 and read-3.
        let mut holders: Vec<&str> = Vec::new();
        if old.iter().any(|o| o.1 == JOB) {
            holders.extend(["job-1", "job-2"]);
        }
        if old.iter().any(|o| o.1 == READ) {
            holders.push("read-1");
        }
        for (_, class, _) in &new {
            holders.push(if *class == READ { "read-3" } else { "job" });
        }
        holders.sort_unstable();
        holders.dedup();
        // "job" stands for job-3 and job-4: at most 2 job addresses.
        assert!(holders.len() <= 3, "second {second}: {holders:?}");
        // Slots that expire unrenewed are handed out again: the holders
        // here take and let go.
        new.retain(|(_, class, until)| *class == JOB || now + 1000 <= *until);
    }
    // Reads come back once old reads must be gone, on the slot and the
    // address jobs cannot have; jobs once the old jobs must be gone.
    let (first_read, first_job) = (first_read.unwrap(), first_job.unwrap());
    assert!((35..=41).contains(&first_read), "read after {first_read} s");
    assert!((120..=126).contains(&first_job), "job after {first_job} s");
}

/// During the jobs' wait a read gets the slot kept back for reads and
/// nothing else; where jobs may hold every slot or the only address, it
/// waits as long as they do.
#[tokio::test]
async fn a_read_during_the_wait_uses_only_what_jobs_cannot_hold() {
    let w = World::new();
    let wide = provider("wide", 4);
    let one_ip = with_ips(provider("one-ip", 3), 1);
    let single = provider("single", 1);
    let a = pooled("pool-a", 3, "bundle", 3);
    let b = pooled("pool-b", 3, "bundle", 3);
    let providers = [
        wide.clone(),
        one_ip.clone(),
        single.clone(),
        a.clone(),
        b.clone(),
    ];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    for p in &providers {
        let permit = take(&c, &w, p, JOB, "job-1").await.unwrap();
        c.release_permit(&permit).await.unwrap();
    }
    // A job took a slot within the horizon, so a restart must assume
    // jobs are still out there.
    w.restart();
    // The wait counts from the first request the new object sees.
    assert_eq!(w.held("permits:all:0", "wide").await, 0);
    w.pass(READ_MS + SKEW_MS + 1);

    let read = take(&c, &w, &wide, READ, "read-1").await.unwrap();
    assert_eq!(read.slot, 3, "the slot kept back for reads");
    assert!(take(&c, &w, &wide, READ, "read-1").await.is_none());
    assert!(take(&c, &w, &wide, JOB, "job-2").await.is_none());
    assert!(take(&c, &w, &one_ip, READ, "read-1").await.is_none());
    assert!(take(&c, &w, &single, READ, "read-1").await.is_none());
    // The pool keeps one connection back for reads, over both accounts.
    assert!(take(&c, &w, &a, READ, "read-1").await.is_some());
    assert!(take(&c, &w, &b, READ, "read-1").await.is_none());

    w.pass(JOB_MS - READ_MS);
    for p in [&wide, &one_ip, &single, &b] {
        assert!(take(&c, &w, p, JOB, "job-2").await.is_some(), "{}", p.id);
    }
}

/// The horizon is in storage before a slot is promised: with storage
/// down, nothing is handed out and nothing is renewed past what is
/// stored.
#[tokio::test]
async fn nothing_is_promised_past_the_stored_horizon() {
    let w = World::new();
    let providers = [provider("p", 3)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let store = w.store("permits:all:0");

    store.fail.set(true);
    assert!(c
        .acquire_permit(&providers[0], JOB, "job-1", w.now())
        .await
        .is_err());
    assert_eq!(w.held("permits:all:0", "p").await, 0);

    store.fail.set(false);
    w.pass(SEIZE_EVERY_MS);
    let permit = take(&c, &w, &providers[0], JOB, "job-1").await.unwrap();
    let stored = store.record.borrow().clone().unwrap();
    assert!(stored.jobs_until >= w.now.get() + JOB_MS);
    assert_eq!(stored.reads_until, 0, "no read took a slot");

    // Renewals inside the stored horizon need no write; one that would
    // pass it needs the write first.
    store.fail.set(true);
    let mut renewed = 0;
    while w.now.get() + 20_000 + JOB_MS <= stored.jobs_until {
        w.pass(20_000);
        assert!(c.renew_permit(&permit, w.now()).await.unwrap());
        renewed += 1;
    }
    assert_eq!(renewed, HORIZON_STEP_MS / 20_000);
    w.pass(20_000);
    // The slot is not extended, and the holder hears that the gate
    // could not answer. Its session stands with what is held on it:
    // one request that failed frees nothing behind a holder's back.
    assert!(c.renew_permit(&permit, w.now()).await.is_err());
    assert_eq!(w.sessions("permits:all:0"), 1);
    assert_eq!(w.held("permits:all:0", "p").await, 1);
    store.fail.set(false);
    assert!(c.renew_permit(&permit, w.now()).await.unwrap());
    c.release_permit(&permit).await.unwrap();
    assert_eq!(w.sessions("permits:all:0"), 0);
    assert_eq!(w.held("permits:all:0", "p").await, 0);
}

/// A class that is refused moves no horizon: nothing was promised, and
/// a deploy has nothing of that class to wait out.
#[tokio::test]
async fn a_refused_class_stores_nothing() {
    let w = World::new();
    let p = provider("p", 1);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let _held = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    let store = w.store("permits:all:0");
    let saves = store.saves.get();
    for _ in 0..3 {
        assert!(take(&c, &w, &p, READ, "read-1").await.is_none());
        w.pass(1000);
    }
    assert_eq!(store.saves.get(), saves);
    let stored = store.record.borrow().clone().unwrap();
    assert_eq!(stored.reads_until, 0);
}

/// The cost in storage: one write when a class first takes a slot and
/// one per [`HORIZON_STEP_MS`] while slots stay in use. Never one per
/// permit, none when all is quiet again, none for leaving memory.
#[tokio::test]
async fn storage_is_written_per_horizon_step_not_per_permit() {
    let w = World::new();
    let providers = [provider("p", 8), provider("q", 8)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let store = w.store("permits:all:0");
    let seized = store.saves.get();
    assert!(seized <= 2, "one write for the start, one for the seizure");
    if !TestSql::postgres_selected() {
        w.db.0.sqlite().meter_writes().unwrap();
    }

    // 30 minutes of jobs: 6 slots taken, renewed every 20 s, given
    // back and taken again every minute. The object leaves memory
    // between any two requests.
    let (mut permits, mut cycles) = (Vec::new(), 0);
    for second in (0..1800).step_by(20) {
        if second % 60 == 0 {
            for permit in permits.drain(..) {
                c.release_permit(&permit).await.unwrap();
            }
            for i in 0..6 {
                let p = &providers[i % 2];
                permits.push(take(&c, &w, p, JOB, "job-1").await.unwrap());
                cycles += 1;
            }
        }
        w.hibernate();
        let held = c.renew_permit(&permits[0], w.now()).await.unwrap();
        assert!(held);
        w.pass(20_000);
        w.hibernate();
    }
    assert_eq!(cycles, 180);
    let busy = store.saves.get() - seized;
    // 30 minutes over a 10 minute step: the first write and 3 more.
    assert!((3..=4).contains(&busy), "{busy} writes in 30 minutes");
    for permit in permits.drain(..) {
        c.release_permit(&permit).await.unwrap();
    }
    w.pass(HORIZON_STEP_MS * 3);
    w.hibernate();
    assert_eq!(w.held("permits:all:0", "p").await, 0);
    assert_eq!(store.saves.get() - seized, busy, "nothing to clear");
    if !TestSql::postgres_selected() {
        // sqlite_only: preupdate-hook row billing
        assert_eq!(
            w.db.0.sqlite().writes().billed(),
            0,
            "no catalogue row for any acquire, renewal or release"
        );
    }
}

/// New code is two writes per gate: the first start under it, and the
/// slot rows it then finds to be its own still. Starts of the same code
/// (the object left memory) write nothing and ask the catalogue
/// nothing.
#[tokio::test]
async fn a_deploy_is_two_writes_and_a_start_is_none() {
    let w = World::new();
    let providers = [provider("p", 4)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let a = take(&c, &w, &providers[0], JOB, "job-1").await.unwrap();
    let store = w.store("permits:all:0");
    let saves = store.saves.get();
    if !TestSql::postgres_selected() {
        w.db.0.sqlite().meter_writes().unwrap();
    }

    for _ in 0..10 {
        w.hibernate();
        w.pass(10_000);
        assert!(c.renew_permit(&a, w.now()).await.unwrap());
    }
    assert_eq!(store.saves.get(), saves);

    w.restart();
    assert!(!c.renew_permit(&a, w.now()).await.unwrap());
    assert_eq!(w.held("permits:all:0", "p").await, 0);
    assert_eq!(store.saves.get(), saves + 1, "the wait is stored");
    for _ in 0..10 {
        w.hibernate();
        w.pass(1000);
        assert!(take(&c, &w, &providers[0], JOB, "job-2").await.is_none());
    }
    assert_eq!(store.saves.get(), saves + 2, "and the rows asked for once");
    // The wait is not forgotten with the memory, nor begun again.
    w.pass(JOB_MS + SKEW_MS - 10_000);
    w.hibernate();
    assert!(take(&c, &w, &providers[0], JOB, "job-2").await.is_some());
    if !TestSql::postgres_selected() {
        // sqlite_only: preupdate-hook row billing
        assert_eq!(w.db.0.sqlite().writes().billed(), 0, "no catalogue row");
    }
    assert_eq!(store.saves.get(), saves + 2);
}

/// A second deploy during the wait of the first does not cut the wait
/// short. It begins one of its own: what the first handed out in
/// between is not known to it.
#[tokio::test]
async fn a_deploy_during_the_wait_does_not_cut_it_short() {
    let w = World::new();
    let p = provider("p", 2);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    take(&c, &w, &p, JOB, "job-1").await.unwrap();
    w.restart();
    assert_eq!(w.held("permits:all:0", "p").await, 0);
    w.pass(JOB_MS / 2);
    w.restart();
    w.pass(JOB_MS / 2 - 1);
    assert!(take(&c, &w, &p, JOB, "job-2").await.is_none());
    w.pass(SKEW_MS + 2);
    assert!(take(&c, &w, &p, JOB, "job-2").await.is_none());
    w.pass(JOB_MS);
    assert!(take(&c, &w, &p, JOB, "job-2").await.is_some());
}

// ---------------------------------------------------------------------------
// Old and new side by side
// ---------------------------------------------------------------------------

/// A rollout: Workers that take slot rows and Workers that ask the gate
/// run against one catalogue. The gate hands out nothing while a
/// catalogue caller holds a row, the callers find no row the gate has
/// seized, and the two together never exceed `max_conns`.
#[tokio::test]
async fn the_gate_waits_until_the_catalogue_callers_have_drained() {
    let w = World::new();
    let p = provider("p", 3);
    let providers = [p.clone()];
    let old = w.old_catalog();
    old.seed_permits(&providers).await.unwrap();
    let new = w.catalog(PermitMode::Gate, GateSharding::One, &providers);

    let a = take(&old, &w, &p, JOB, "old-job").await.unwrap();
    let b = take(&old, &w, &p, READ, "old-read").await.unwrap();

    // The gate seizes the one free row and hands out nothing.
    assert!(take(&new, &w, &p, JOB, "new-job").await.is_none());
    assert_eq!(w.rows_of_callers("p").await, 2);
    assert_eq!(w.rows_of_gates("p").await, 1);
    assert!(take(&old, &w, &p, JOB, "old-job-2").await.is_none());

    // The callers keep what they hold for as long as they renew.
    w.pass(20_000);
    assert!(old.renew_permit(&a, w.now()).await.unwrap());
    assert!(old.renew_permit(&b, w.now()).await.unwrap());
    assert!(take(&new, &w, &p, READ, "new-read").await.is_none());

    // One finishes, one goes away without a word.
    old.release_permit(&a).await.unwrap();
    w.pass(SEIZE_EVERY_MS);
    assert!(take(&new, &w, &p, JOB, "new-job").await.is_none());
    assert_eq!(w.rows_of_gates("p").await, 2);
    w.pass(READ_MS + 1);
    assert_eq!(w.rows_of_callers("p").await, 0);

    // Every row is the gate's: it hands out, the callers get nothing,
    // and a caller's late renewal or release of a seized row is void.
    let c1 = take(&new, &w, &p, JOB, "new-job").await.unwrap();
    assert_eq!(w.rows_of_gates("p").await, 3);
    assert!(!old.renew_permit(&b, w.now()).await.unwrap());
    old.release_permit(&b).await.unwrap();
    assert_eq!(w.rows_of_gates("p").await, 3);
    assert!(take(&old, &w, &p, READ, "old-read-2").await.is_none());
    assert!(take(&new, &w, &p, JOB, "new-job").await.is_some());
    assert!(take(&new, &w, &p, READ, "new-read").await.is_some());
    assert!(
        take(&new, &w, &p, READ, "new-read").await.is_none(),
        "3 of 3"
    );
    assert!(new.renew_permit(&c1, w.now()).await.unwrap());
}

/// Accounts that share a pool limit change hands together: a caller on
/// one account keeps the gate from handing out on any of them.
#[tokio::test]
async fn a_pool_changes_hands_as_a_whole() {
    let w = World::new();
    let a = pooled("a", 2, "bundle", 3);
    let b = pooled("b", 2, "bundle", 3);
    let other = provider("other", 2);
    let providers = [a.clone(), b.clone(), other.clone()];
    let old = w.old_catalog();
    old.seed_permits(&providers).await.unwrap();
    let new = w.catalog(PermitMode::Gate, GateSharding::Account, &providers);

    let held = take(&old, &w, &b, JOB, "old-job").await.unwrap();
    assert!(take(&new, &w, &a, JOB, "new-job").await.is_none());
    assert!(take(&new, &w, &b, JOB, "new-job").await.is_none());
    // An account outside the pool is not held up, and has its own gate.
    assert!(take(&new, &w, &other, JOB, "new-job").await.is_some());
    assert_eq!(w.held("permits:account.other:0", "other").await, 1);

    old.release_permit(&held).await.unwrap();
    w.pass(SEIZE_EVERY_MS);
    let mut got = 0;
    for p in [&a, &b, &a, &b] {
        got += u32::from(take(&new, &w, p, READ, "new-read").await.is_some());
    }
    assert_eq!(got, 3, "the pool's limit, over both accounts");
    assert_eq!(
        w.held("permits:pool.bundle:0", "a").await + w.held("permits:pool.bundle:0", "b").await,
        3
    );
}

/// Old and new Workers under an interleaved schedule, forwards and
/// back: whoever asks, the connections in use on an account never
/// exceed its limit, and no connection is ever counted by both sides.
#[tokio::test]
async fn both_sides_together_never_exceed_the_limits() {
    for seed in 1..=4u64 {
        let w = World::new();
        let providers = [
            provider("p", 3),
            with_ips(provider("ips", 4), 2),
            pooled("a", 3, "bundle", 4),
            pooled("b", 3, "bundle", 4),
        ];
        let rows = w.catalog(PermitMode::Catalog, GateSharding::One, &providers);
        let gate = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
        rows.seed_permits(&providers).await.unwrap();
        let mut rng = Lcg(seed);
        // (permit, from the gate, expiry, holder)
        let mut held: Vec<(Permit, bool, i64, String)> = Vec::new();
        let (mut by_rows, mut by_gate) = (0, 0);
        for step in 0..3000 {
            let now = w.now.get();
            held.retain(|h| h.2 >= now);
            let side = rng.next(2) == 0;
            let c = if side { &gate } else { &rows };
            match rng.next(12) {
                0..=5 => {
                    let p = &providers[rng.next(4) as usize];
                    let class = if rng.next(3) == 0 { READ } else { JOB };
                    let holder = format!("{}{}", if side { "g" } else { "r" }, rng.next(3));
                    if let Some(permit) = take(c, &w, p, class, &holder).await {
                        let ttl = if class == JOB { JOB_MS } else { READ_MS };
                        held.push((permit, side, now + ttl, holder));
                        if side {
                            by_gate += 1
                        } else {
                            by_rows += 1
                        }
                    }
                }
                6..=7 if !held.is_empty() => {
                    let i = rng.next(held.len() as u64) as usize;
                    let c = if held[i].1 { &gate } else { &rows };
                    if c.renew_permit(&held[i].0, w.now()).await.unwrap() {
                        let ttl = if held[i].0.class == JOB {
                            JOB_MS
                        } else {
                            READ_MS
                        };
                        held[i].2 = now + ttl;
                    } else {
                        held.swap_remove(i);
                    }
                }
                8 if !held.is_empty() => {
                    let h = held.swap_remove(rng.next(held.len() as u64) as usize);
                    let c = if h.1 { &gate } else { &rows };
                    c.release_permit(&h.0).await.unwrap();
                }
                // The periodic step of either kind of Worker.
                9 => c.seed_permits(&providers).await.unwrap(),
                10 if rng.next(40) == 0 => w.restart(),
                _ => {
                    w.pass(rng.next(20_000) as i64);
                    if rng.next(3) == 0 {
                        w.hibernate();
                    }
                }
            }
            for p in &providers {
                let here = || held.iter().filter(|h| h.0.provider == p.id);
                let open = here().count() as u32;
                assert!(open <= p.max_conns, "seed {seed} step {step}: {}", p.id);
                let mut holders: Vec<&str> = here().map(|h| h.3.as_str()).collect();
                holders.sort_unstable();
                holders.dedup();
                if let Some(max_ips) = p.max_ips {
                    assert!(
                        holders.len() as u32 <= max_ips,
                        "seed {seed} step {step}: ips"
                    );
                }
            }
            let pool = held
                .iter()
                .filter(|h| h.0.provider == "a" || h.0.provider == "b")
                .count();
            assert!(pool <= 4, "seed {seed} step {step}: pool {pool}");
        }
        assert!(
            by_rows > 20 && by_gate > 20,
            "seed {seed}: {by_rows} / {by_gate}"
        );
    }
}

/// Going back to the slot rows: the gate is told to retire, stops
/// handing out, lets its holders finish, and only then frees the rows.
#[tokio::test]
async fn a_retired_gate_frees_the_rows_once_its_holders_are_done() {
    let w = World::new();
    let p = provider("p", 3);
    let providers = [p.clone()];
    let new = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    new.seed_permits(&providers).await.unwrap();
    let job = take(&new, &w, &p, JOB, "new-job").await.unwrap();

    // The deploy goes back to `d1`; some Workers of the gate kind are
    // still finishing.
    let back = w.catalog(PermitMode::Catalog, GateSharding::One, &providers);
    assert!(take(&back, &w, &p, JOB, "back-job").await.is_none());
    // That miss ran the rollout step: the gate is retired.
    assert_eq!(
        w.store("permits:all:0")
            .record
            .borrow()
            .as_ref()
            .unwrap()
            .mode,
        GateMode::Retired
    );
    assert!(take(&new, &w, &p, JOB, "new-job-2").await.is_none());
    assert_eq!(w.rows_of_gates("p").await, 3, "held until the job is done");

    // The job keeps its slot for as long as it runs.
    w.pass(20_000);
    assert!(new.renew_permit(&job, w.now()).await.unwrap());
    back.seed_permits(&providers).await.unwrap();
    assert_eq!(w.rows_of_gates("p").await, 3);
    assert!(take(&back, &w, &p, READ, "back-read").await.is_none());

    new.release_permit(&job).await.unwrap();
    back.seed_permits(&providers).await.unwrap();
    assert_eq!(w.rows_of_gates("p").await, 0);
    let mut got = 0;
    for _ in 0..4 {
        got += u32::from(take(&back, &w, &p, READ, "back-read").await.is_some());
    }
    assert_eq!(got, 3);
    assert!(take(&new, &w, &p, JOB, "new-job-3").await.is_none());

    // And forwards again: the gate takes charge once the rows are free.
    let stored = w.store("permits:all:0").record.borrow().clone().unwrap();
    assert!(stored.seized.is_empty());
    w.pass(READ_MS + 1);
    new.seed_permits(&providers).await.unwrap();
    assert!(take(&new, &w, &p, JOB, "new-job-4").await.is_some());
}

/// Without the periodic step: after a change of `PERMITS` the first
/// acquire that finds nothing runs the rollout step itself, so the
/// other side lets go at once and not at the next sweep.
#[tokio::test]
async fn an_acquire_that_finds_nothing_moves_the_rollout_on() {
    let w = World::new();
    let p = provider("p", 2);
    let providers = [p.clone()];
    let new = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let permit = take(&new, &w, &p, READ, "new-read").await.unwrap();
    new.release_permit(&permit).await.unwrap();
    w.pass(READ_MS + SKEW_MS);

    let back = w.catalog(PermitMode::Catalog, GateSharding::One, &providers);
    assert!(take(&back, &w, &p, READ, "back-read").await.is_none());
    assert_eq!(w.rows_of_gates("p").await, 0, "retired and freed");
    assert!(take(&back, &w, &p, READ, "back-read").await.is_some());

    // Forwards: the gate is retired, and an acquire through it finds
    // nothing once, then is served.
    let fresh = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    w.pass(READ_MS + 1);
    assert!(take(&fresh, &w, &p, READ, "new-read").await.is_none());
    w.pass(SEIZE_EVERY_MS);
    assert!(take(&fresh, &w, &p, READ, "new-read").await.is_some());
}

/// A gate that lost its memory while it was retiring does not free the
/// rows while holders from before may still be connected.
#[tokio::test]
async fn a_retiring_gate_that_restarted_waits_out_the_old_holders() {
    let w = World::new();
    let p = provider("p", 2);
    let providers = [p.clone()];
    let new = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    take(&new, &w, &p, JOB, "new-job").await.unwrap();
    w.restart();
    w.pass(1000);

    let back = w.catalog(PermitMode::Catalog, GateSharding::One, &providers);
    back.seed_permits(&providers).await.unwrap();
    assert_eq!(w.rows_of_gates("p").await, 2);
    w.pass(JOB_MS);
    back.seed_permits(&providers).await.unwrap();
    assert_eq!(w.rows_of_gates("p").await, 2, "inside the margin");
    w.pass(SKEW_MS);
    back.seed_permits(&providers).await.unwrap();
    assert_eq!(w.rows_of_gates("p").await, 0);
    assert!(take(&back, &w, &p, JOB, "back-job").await.is_some());
}

/// A change of how providers are spread over gates: the gates no longer
/// in use are retired by the periodic step and the new ones take over.
#[tokio::test]
async fn a_gate_no_longer_in_use_is_retired() {
    let w = World::new();
    let p = provider("p", 2);
    let providers = [p.clone()];
    let one = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let a = take(&one, &w, &p, JOB, "job-1").await.unwrap();
    one.release_permit(&a).await.unwrap();
    w.pass(JOB_MS + SKEW_MS);

    let split = w.catalog(PermitMode::Gate, GateSharding::Account, &providers);
    split.seed_permits(&providers).await.unwrap();
    w.pass(SEIZE_EVERY_MS);
    assert!(take(&split, &w, &p, JOB, "job-2").await.is_some());
    assert_eq!(w.held("permits:account.p:0", "p").await, 1);
    assert_eq!(
        w.count(
            "SELECT COUNT(*) FROM provider_permits WHERE holder = 'do-gate:permits:account.p:0'"
        )
        .await,
        2
    );
}

// ---------------------------------------------------------------------------
// An account divided over several gates
// ---------------------------------------------------------------------------

/// Workers of the given kinds (permit mode, `PERMIT_SHARDS`) take,
/// renew and free permits at random, with restarts of the gates and
/// the periodic step in between. After every step, what the callers
/// hold together is under every limit.
async fn storm(kinds: &[(PermitMode, u32)], seed: u64) -> Vec<u32> {
    let w = World::new();
    let providers = [
        provider("p", 5),
        with_ips(provider("ips", 6), 3),
        pooled("a", 4, "bundle", 6),
        pooled("b", 4, "bundle", 6),
    ];
    let sides: Vec<SqlCatalog<Db>> = kinds
        .iter()
        .map(|(mode, shards)| w.catalog_of(*mode, GateSharding::Account, *shards, &providers))
        .collect();
    sides[0].seed_permits(&providers).await.unwrap();
    let mut rng = Lcg(seed);
    // (permit, side, expiry, holder)
    let mut held: Vec<(Permit, usize, i64, String)> = Vec::new();
    let mut taken = vec![0u32; sides.len()];
    for step in 0..3000 {
        let now = w.now.get();
        held.retain(|h| h.2 >= now);
        let side = rng.next(sides.len() as u64) as usize;
        let c = &sides[side];
        match rng.next(12) {
            0..=5 => {
                let p = &providers[rng.next(4) as usize];
                let class = if rng.next(3) == 0 { READ } else { JOB };
                let holder = format!("s{side}h{}", rng.next(4));
                if let Some(permit) = take(c, &w, p, class, &holder).await {
                    let ttl = if class == JOB { JOB_MS } else { READ_MS };
                    held.push((permit, side, now + ttl, holder));
                    taken[side] += 1;
                }
            }
            6..=7 if !held.is_empty() => {
                let i = rng.next(held.len() as u64) as usize;
                if sides[held[i].1]
                    .renew_permit(&held[i].0, w.now())
                    .await
                    .unwrap()
                {
                    let ttl = if held[i].0.class == JOB {
                        JOB_MS
                    } else {
                        READ_MS
                    };
                    held[i].2 = now + ttl;
                } else {
                    held.swap_remove(i);
                }
            }
            8 if !held.is_empty() => {
                let h = held.swap_remove(rng.next(held.len() as u64) as usize);
                sides[h.1].release_permit(&h.0).await.unwrap();
            }
            9 => c.seed_permits(&providers).await.unwrap(),
            10 if rng.next(40) == 0 => w.restart(),
            _ => {
                w.pass(rng.next(20_000) as i64);
                if rng.next(3) == 0 {
                    w.hibernate();
                }
            }
        }
        let at = format!("kinds {kinds:?} seed {seed} step {step}");
        for p in &providers {
            let here = || held.iter().filter(|h| h.0.provider == p.id);
            assert!(here().count() as u32 <= p.max_conns, "{at}: {}", p.id);
            let mut slots: Vec<u32> = here().map(|h| h.0.slot).collect();
            slots.sort_unstable();
            slots.dedup();
            assert_eq!(slots.len(), here().count(), "{at}: a slot twice");
            let jobs = here().filter(|h| h.0.class == JOB).count() as u32;
            assert!(jobs <= p.background_conns(), "{at}: jobs on {}", p.id);
            let mut holders: Vec<&str> = here().map(|h| h.3.as_str()).collect();
            holders.sort_unstable();
            holders.dedup();
            if let Some(max_ips) = p.max_ips {
                assert!(holders.len() as u32 <= max_ips, "{at}: ips");
            }
        }
        let pool = || {
            held.iter()
                .filter(|h| h.0.provider == "a" || h.0.provider == "b")
        };
        assert!(pool().count() <= 6, "{at}: pool");
        assert!(
            pool().filter(|h| h.0.class == JOB).count() <= 5,
            "{at}: pool jobs"
        );
    }
    taken
}

/// Three gates per account and per pool: together they keep the limits
/// of the account and of the pool, through restarts.
#[tokio::test]
async fn the_gates_of_an_account_keep_its_limits_together() {
    for seed in 1..=4u64 {
        let taken = storm(&[(PermitMode::Gate, 3)], seed).await;
        assert!(taken[0] > 100, "seed {seed}: {taken:?}");
    }
}

/// A rollout that changes the number of gates while they are in use,
/// beside Workers that still use the slot rows: nobody's view of the
/// division is the same, and the limits still hold, because a gate
/// hands out a slot only while its row is the gate's own.
#[tokio::test]
async fn workers_that_divide_an_account_differently_keep_its_limits() {
    for seed in 1..=4u64 {
        storm(
            &[
                (PermitMode::Catalog, 1),
                (PermitMode::Gate, 1),
                (PermitMode::Gate, 3),
                (PermitMode::Gate, 2),
            ],
            seed,
        )
        .await;
    }
}

/// Two gates on one account: each owns its own slot rows, a holder that
/// finds its gate full is served by the other, and a renewal and a
/// release reach the gate that handed the slot out.
#[tokio::test]
async fn a_holder_finds_room_in_the_other_gate_of_its_account() {
    let w = World::new();
    let p = provider("p", 4);
    let providers = [p.clone()];
    let c = w.catalog_of(PermitMode::Gate, GateSharding::Account, 2, &providers);
    let mut jobs = Vec::new();
    for _ in 0..3 {
        jobs.push(take(&c, &w, &p, JOB, "job").await.unwrap());
        // The gate asked first hands out once it has seen that the
        // other has its rows: at its next look at the catalogue.
        w.pass(SEIZE_EVERY_MS);
    }
    let mut slots: Vec<u32> = jobs.iter().map(|j| j.slot).collect();
    slots.sort_unstable();
    assert_eq!(slots, [0, 1, 2], "every slot a job may hold");
    assert!(take(&c, &w, &p, JOB, "job").await.is_none());
    let read = take(&c, &w, &p, READ, "read").await.unwrap();
    assert_eq!(read.slot, 3, "the slot kept back for reads");

    let (even, odd) = ("permits:account.p:0", "permits:account.p:1");
    assert_eq!(w.held(even, "p").await, 2);
    assert_eq!(w.held(odd, "p").await, 2);
    for (gate, rest) in [(even, 0), (odd, 1)] {
        let sql = format!(
            "SELECT COUNT(*) FROM provider_permits \
             WHERE holder = 'do-gate:{gate}' AND slot % 2 = {rest}"
        );
        assert_eq!(w.count(&sql).await, 2, "{gate}");
    }
    assert_eq!(w.rows_of_gates("p").await, 4);
    let load = c.provider_load(w.now()).await.unwrap();
    let lines: Vec<u32> = load
        .iter()
        .filter(|l| l.provider_id == "p")
        .map(|l| l.held)
        .collect();
    assert_eq!(lines, [4], "one line for the account");

    w.pass(60_000);
    let all: Vec<Permit> = jobs.to_vec();
    let (_, renewed) = c.renew_all(&no_lease(), &all, w.now()).await.unwrap();
    assert_eq!(renewed, vec![true; 3]);
    for permit in &jobs {
        c.release_permit(permit).await.unwrap();
    }
    assert_eq!(w.held(even, "p").await + w.held(odd, "p").await, 0);
}

/// No more gates than the smallest limit of the account less what it
/// keeps for reads: each of them has a connection and an address to
/// hand out to a job. Two addresses, one of them kept for reads, are
/// one gate: a second would hold the reads' address and serve no job.
#[tokio::test]
async fn an_account_has_no_more_gates_than_its_smallest_limit() {
    let w = World::new();
    let p = with_ips(provider("p", 8), 2);
    let providers = [p.clone()];
    let c = w.catalog_of(PermitMode::Gate, GateSharding::Account, 5, &providers);
    let mut held = Vec::new();
    for i in 0..8 {
        if let Some(permit) = take(&c, &w, &p, JOB, &format!("job-{i}")).await {
            held.push(permit);
        }
    }
    assert_eq!(held.len(), 1, "one address for jobs, one kept for reads");
    assert!(take(&c, &w, &p, READ, "read").await.is_some());
    assert_eq!(
        w.count(
            "SELECT COUNT(DISTINCT holder) FROM provider_permits WHERE holder LIKE 'do-gate:%'"
        )
        .await,
        1
    );
    assert_eq!(w.rows_of_gates("p").await, 8);

    // Four addresses, one for reads: three gates, and each serves jobs.
    let w = World::new();
    let p = with_ips(provider("p", 9), 4);
    let providers = [p.clone()];
    let c = w.catalog_of(PermitMode::Gate, GateSharding::Account, 5, &providers);
    c.seed_permits(&providers).await.unwrap();
    w.pass(SEIZE_EVERY_MS);
    let mut gates = Vec::new();
    for i in 0..3 {
        assert!(take(&c, &w, &p, JOB, &format!("job-{i}")).await.is_some());
    }
    assert!(take(&c, &w, &p, JOB, "job-3").await.is_none(), "addresses");
    for shard in 0..3 {
        gates.push(w.held(&format!("permits:account.p:{shard}"), "p").await);
    }
    assert_eq!(gates.iter().sum::<u32>(), 3);
    assert_eq!(
        w.count(
            "SELECT COUNT(DISTINCT holder) FROM provider_permits WHERE holder LIKE 'do-gate:%'"
        )
        .await,
        3
    );
}

/// Workers that use the slot rows beside Workers that divide each
/// account over several gates: a gate hands out only while every row
/// of the account is a gate's, so the address and pool limits, which
/// the gates share out among themselves, are never counted twice.
#[tokio::test]
async fn slot_rows_and_several_gates_keep_the_limits_together() {
    let mut gates_took = 0;
    for shards in [2, 3] {
        for seed in 1..=12u64 {
            let taken = storm(
                &[(PermitMode::Catalog, 1), (PermitMode::Gate, shards)],
                seed,
            )
            .await;
            gates_took += taken[1];
        }
    }
    // Both kinds ask all the time, so the rows keep changing hands only
    // through the periodic step: the gates get their turns.
    assert!(gates_took > 0, "the gates never took charge");
}

/// One gate of two is retired and idle while the other still has a job
/// running: the rows of both stay out of the catalogue callers' reach
/// until the last gate is done, then all become free together.
#[tokio::test]
async fn the_gates_of_an_account_free_its_rows_together() {
    let w = World::new();
    let p = with_ips(provider("p", 4), 3);
    let providers = [p.clone()];
    let new = w.catalog_of(PermitMode::Gate, GateSharding::Account, 2, &providers);
    new.seed_permits(&providers).await.unwrap();
    w.pass(SEIZE_EVERY_MS);
    let job = take(&new, &w, &p, JOB, "new-job").await.unwrap();
    let busy = format!("permits:account.p:{}", job.slot % 2);
    let idle = format!("permits:account.p:{}", 1 - job.slot % 2);
    assert_eq!(w.held(&busy, "p").await, 1);

    let back = w.catalog(PermitMode::Catalog, GateSharding::Account, &providers);
    back.seed_permits(&providers).await.unwrap();
    let rows = |holder: String| {
        let w = &w;
        async move {
            let sql = format!("SELECT COUNT(*) FROM provider_permits WHERE holder = '{holder}'");
            w.count(&sql).await
        }
    };
    assert_eq!(rows(gate_idle_holder(&idle)).await, 2, "kept, not freed");
    assert_eq!(rows(gate_holder(&busy)).await, 2);
    for holder in ["back-1", "back-2", "back-3"] {
        assert!(take(&back, &w, &p, READ, holder).await.is_none());
        assert!(take(&back, &w, &p, JOB, holder).await.is_none());
    }

    // Forwards again before the job is done: the idle gate takes its
    // rows back and both hand out.
    new.seed_permits(&providers).await.unwrap();
    assert_eq!(rows(gate_holder(&idle)).await, 2);
    w.pass(SEIZE_EVERY_MS);
    let second = take(&new, &w, &p, JOB, "new-job-2").await.unwrap();
    new.release_permit(&second).await.unwrap();

    // And back for good.
    back.seed_permits(&providers).await.unwrap();
    assert_eq!(rows(gate_idle_holder(&idle)).await, 2);
    new.release_permit(&job).await.unwrap();
    back.seed_permits(&providers).await.unwrap();
    assert_eq!(w.rows_of_gates("p").await, 0);
    assert_eq!(rows(gate_idle_holder(&idle)).await, 0);
    assert!(take(&back, &w, &p, JOB, "back-1").await.is_some());
}

/// The rows are cleared by hand while the gate is not in memory, and
/// catalogue callers take them. A gate under new code (a deploy is how
/// `PERMITS` changes) does not rely on what it stored: its first
/// acquire asks the catalogue, before any periodic step.
#[tokio::test]
async fn a_gate_does_not_trust_what_it_stored_about_the_rows() {
    let w = World::new();
    let p = provider("p", 2);
    let providers = [p.clone()];
    let new = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let job = take(&new, &w, &p, JOB, "new-job").await.unwrap();
    new.release_permit(&job).await.unwrap();
    let stored = w.store("permits:all:0").record.borrow().clone().unwrap();
    assert_eq!(stored.seized.get("p"), Some(&2));

    w.restart();
    w.db.0
        .fixture_exec(
            "UPDATE provider_permits SET lease_until = 0, holder = NULL, pool = NULL",
            &[],
        )
        .await
        .unwrap();
    w.pass(JOB_MS + SKEW_MS + 1);
    let old = w.old_catalog();
    assert!(take(&old, &w, &p, JOB, "old-job").await.is_some());
    assert!(take(&old, &w, &p, READ, "old-read").await.is_some());

    for _ in 0..3 {
        assert!(take(&new, &w, &p, JOB, "new-job").await.is_none());
        assert!(take(&new, &w, &p, READ, "new-read").await.is_none());
        w.pass(SEIZE_EVERY_MS);
    }
    assert_eq!(w.held("permits:all:0", "p").await, 0);
}

/// The same for a gate that stays in memory through a retirement that
/// someone else undid: back in charge, it asks the catalogue again.
#[tokio::test]
async fn a_gate_back_in_charge_asks_the_catalogue_again() {
    let w = World::new();
    let p = provider("p", 2);
    let providers = [p.clone()];
    let new = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let job = take(&new, &w, &p, JOB, "new-job").await.unwrap();
    new.release_permit(&job).await.unwrap();
    let back = w.catalog(PermitMode::Catalog, GateSharding::One, &providers);
    back.seed_permits(&providers).await.unwrap();
    assert_eq!(w.rows_of_gates("p").await, 0);
    assert!(take(&back, &w, &p, JOB, "back-job").await.is_some());
    assert!(take(&back, &w, &p, READ, "back-read").await.is_some());

    new.seed_permits(&providers).await.unwrap();
    w.pass(SEIZE_EVERY_MS);
    assert!(take(&new, &w, &p, JOB, "new-job").await.is_none());
    assert!(take(&new, &w, &p, READ, "new-read").await.is_none());
}

/// The write of a start under new code fails: nothing is handed out,
/// and the next request tries the start again.
#[tokio::test]
async fn a_start_that_cannot_store_its_wait_hands_out_nothing() {
    let w = World::new();
    let p = provider("p", 2);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let store = w.store("permits:all:0");
    take(&c, &w, &p, JOB, "job").await.unwrap();

    w.restart();
    store.fail.set(true);
    w.pass(JOB_MS + SKEW_MS + 1);
    assert!(c.acquire_permit(&p, JOB, "job-2", w.now()).await.is_err());
    assert_eq!(store.record.borrow().as_ref().unwrap().boot, "v1");

    store.fail.set(false);
    // The wait counts from the start that could be stored.
    assert!(take(&c, &w, &p, JOB, "job-2").await.is_none());
    assert_eq!(store.record.borrow().as_ref().unwrap().boot, "v2");
    w.pass(JOB_MS + SKEW_MS + 1);
    assert!(take(&c, &w, &p, JOB, "job-2").await.is_some());
}

/// In slot-rows mode a gate that cannot be reached does not stop the
/// periodic step, nor an acquire.
#[tokio::test]
async fn an_unreachable_gate_does_not_stop_the_slot_rows_mode() {
    let w = World::new();
    let p = provider("p", 2);
    let providers = [p.clone()];
    let new = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let job = take(&new, &w, &p, JOB, "new-job").await.unwrap();
    new.release_permit(&job).await.unwrap();
    w.pass(JOB_MS + SKEW_MS);

    let back = w.catalog(PermitMode::Catalog, GateSharding::One, &providers);
    w.down.set(true);
    back.seed_permits(&providers).await.unwrap();
    assert!(take(&back, &w, &p, JOB, "back-job").await.is_none());
    assert_eq!(w.rows_of_gates("p").await, 2, "nobody told the gate");

    w.down.set(false);
    back.seed_permits(&providers).await.unwrap();
    assert_eq!(w.rows_of_gates("p").await, 0);
    assert!(take(&back, &w, &p, JOB, "back-job").await.is_some());
}

/// A drill's slots stay slot rows while a gate hands out the provider's
/// own: a drill takes none of what reads and jobs have, the gate hears
/// of no drill, and the drill slot is renewed and freed as a row.
#[tokio::test]
async fn a_drill_slot_is_not_the_gates() {
    let w = World::new();
    let mut p = provider("p", 2);
    p.drill_conns = 1;
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    w.pass(JOB_MS + SKEW_MS);

    let drill = take(&c, &w, &p, PermitClass::Drill, "drill").await.unwrap();
    assert_eq!(drill.class, PermitClass::Drill);
    assert_eq!(
        w.held("permits:all:0", "p").await,
        0,
        "the gate gave nothing"
    );
    assert!(take(&c, &w, &p, PermitClass::Drill, "drill-2")
        .await
        .is_none());
    // Everything of the provider's own is still there for production.
    let read = take(&c, &w, &p, READ, "read").await.unwrap();
    let job = take(&c, &w, &p, JOB, "job").await.unwrap();
    assert_eq!(w.held("permits:all:0", "p").await, 2);
    assert!(take(&c, &w, &p, READ, "read-2").await.is_none());

    assert!(c.renew_permit(&drill, w.now()).await.unwrap());
    c.release_permit(&drill).await.unwrap();
    assert_eq!(
        w.held("permits:all:0", "p").await,
        2,
        "not the gate's to free"
    );
    assert!(take(&c, &w, &p, PermitClass::Drill, "drill-3")
        .await
        .is_some());
    c.release_permit(&read).await.unwrap();
    c.release_permit(&job).await.unwrap();
}

/// A request of several questions that fails at one of them hands out
/// nothing: the caller hears of no slot, so none stays taken.
#[tokio::test]
async fn a_request_that_fails_keeps_no_slot() {
    let w = World::new();
    let whole = GateProvider::from(&provider("p", 2));
    let acquire = |provider: GateProvider| GateOp::Acquire {
        provider,
        peers: Vec::new(),
        background: true,
        holder: "job".into(),
    };
    let gate = w.gate("permits:all:0").await;
    let ask = GateRequest {
        id: 1,
        gate: "permits:all:0".into(),
        ops: vec![acquire(whole.clone()), acquire(whole.clone().part(2, 2))],
    };
    let session = gate.open(w.now()).await.unwrap();
    assert!(gate.handle(Some(session), ask, w.now()).await.is_err());
    assert!(gate.session(session, w.now()).held.is_empty());
    assert_eq!(w.held("permits:all:0", "p").await, 0);
}

/// A renewal that arrives late, after a later one of the same permit,
/// does not move the expiry back.
#[test]
fn a_late_renewal_does_not_shorten_a_permit() {
    let p = GateProvider::from(&provider("p", 2));
    let mut core = Core::new(UnixMs(T0));
    let now = UnixMs(T0);
    let permit = core
        .acquire(&p, &[], true, ("job", 1), now, Warm::Done)
        .unwrap();
    assert!(core.renew(&permit, 1, UnixMs(T0 + 60_000)));
    assert!(core.renew(&permit, 1, UnixMs(T0 + 30_000)));
    // Still held where the later renewal put it.
    assert!(core.renew(&permit, 1, UnixMs(T0 + 60_000 + JOB_MS)));
}

/// A caller dropped before its question was sent is not asked for: the
/// slot would be nobody's.
#[tokio::test]
async fn a_caller_that_has_gone_takes_no_slot() {
    let w = World::new();
    let providers = [provider("p", 4)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    w.ops.set(0);
    let now = w.now();

    let mut gone = Box::pin(c.acquire_permit(&providers[0], JOB, "job-1", now));
    let mut stays = Box::pin(c.acquire_permit(&providers[0], JOB, "job-1", now));
    let waker = futures_util::task::noop_waker();
    let mut cx = core::task::Context::from_waker(&waker);
    assert!(gone.as_mut().poll(&mut cx).is_pending());
    assert!(stays.as_mut().poll(&mut cx).is_pending());
    drop(gone);
    assert!(stays.await.unwrap().is_some());
    assert_eq!(w.ops.get(), 1);
    assert_eq!(w.held("permits:all:0", "p").await, 1);
}

/// A gate asked for a part of an account that does not exist refuses.
#[tokio::test]
async fn a_part_outside_the_division_is_refused() {
    let w = World::new();
    let p = GateProvider::from(&provider("p", 2)).part(2, 2);
    let ask = GateRequest {
        id: 1,
        gate: "permits:account.p:2".into(),
        ops: vec![GateOp::Acquire {
            provider: p,
            peers: Vec::new(),
            background: true,
            holder: "job".into(),
        }],
    };
    let gate = w.gate("permits:account.p:2").await;
    let session = gate.open(w.now()).await.unwrap();
    assert!(gate.handle(Some(session), ask, w.now()).await.is_err());
    assert_eq!(w.rows_of_gates("p").await, 0);
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// The permits of a job's sockets, taken together, are one request; so
/// are their renewals and their releases.
#[tokio::test]
async fn calls_made_together_are_one_request() {
    let w = World::new();
    let providers = [provider("p", 8), provider("q", 8)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    w.calls.set(0);
    w.ops.set(0);

    let now = w.now();
    let permits: Vec<Permit> = join_all((0..6).map(|i| {
        let p = &providers[i % 2];
        let c = &c;
        async move { c.acquire_permit(p, JOB, "job-1", now).await }
    }))
    .await
    .into_iter()
    .map(|p| p.unwrap().unwrap())
    .collect();
    assert_eq!((w.calls.get(), w.ops.get()), (1, 6));
    let mut slots: Vec<(String, u32)> = permits
        .iter()
        .map(|p| (p.provider.clone(), p.slot))
        .collect();
    slots.sort();
    slots.dedup();
    assert_eq!(slots.len(), 6, "six different slots");

    // The lease is renewed in the catalogue, the permits in one request.
    let lease = no_lease();
    let (_, held) = c.renew_all(&lease, &permits, w.now()).await.unwrap();
    assert_eq!(held, vec![true; 6]);
    assert_eq!(w.calls.get(), 2);

    join_all(permits.iter().map(|p| c.release_permit(p))).await;
    assert_eq!(w.calls.get(), 3);
    assert_eq!(
        w.held("permits:all:0", "p").await + w.held("permits:all:0", "q").await,
        0
    );
}

/// With one gate per account, a job with sockets on two accounts asks
/// each gate once.
#[tokio::test]
async fn each_gate_is_asked_once() {
    let w = World::new();
    let providers = [
        provider("p", 4),
        pooled("a", 4, "bundle", 6),
        pooled("b", 4, "bundle", 6),
    ];
    let c = w.catalog(PermitMode::Gate, GateSharding::Account, &providers);
    c.seed_permits(&providers).await.unwrap();
    w.calls.set(0);
    let now = w.now();
    let permits: Vec<Permit> = join_all((0..6).map(|i| {
        let p = &providers[i % 3];
        let c = &c;
        async move { c.acquire_permit(p, JOB, "job-1", now).await }
    }))
    .await
    .into_iter()
    .map(|p| p.unwrap().unwrap())
    .collect();
    assert_eq!(w.calls.get(), 2, "the account's gate and the pool's");
    assert_eq!(c.renew_all_permits(&permits).await, vec![true; 6]);
    assert_eq!(w.calls.get(), 4);
}

/// What a job costs at its gates, from its first slot to its last: one
/// billed request per gate (the opening of its session), a message for
/// everything after, no stored row and no catalogue row. A message is
/// billed as a twentieth of a request.
#[tokio::test]
async fn a_job_is_one_request_per_gate_and_no_row() {
    for (sharding, shards, gates) in [
        (GateSharding::One, 1, 1),
        (GateSharding::Account, 1, 2),
        (GateSharding::Account, 2, 2),
    ] {
        let w = World::new();
        let providers = [provider("p", 8), provider("q", 8)];
        let c = w.catalog_of(PermitMode::Gate, sharding, shards, &providers);
        // The gates of an account take it over in two periodic steps:
        // each needs the others to have taken their part.
        c.seed_permits(&providers).await.unwrap();
        w.pass(SEIZE_EVERY_MS);
        c.seed_permits(&providers).await.unwrap();
        // An earlier run of the job: the horizon of this step is stored.
        let first = take(&c, &w, &providers[0], JOB, "job-1").await.unwrap();
        let other = take(&c, &w, &providers[1], JOB, "job-1").await.unwrap();
        c.release_permit(&first).await.unwrap();
        c.release_permit(&other).await.unwrap();
        w.pass(1000);
        let saves = || -> u32 { w.stores.borrow().values().map(|s| s.saves.get()).sum() };
        let saved = saves();
        if !TestSql::postgres_selected() {
            w.db.0.sqlite().meter_writes().unwrap();
        }
        for counter in [&w.calls, &w.opens, &w.msgs, &w.posts] {
            counter.set(0);
        }

        // Two sockets, one per account, held for 100 s.
        let now = w.now();
        let order = c.provider_load(now).await.unwrap();
        assert_eq!(order.len(), 2);
        let permits: Vec<Permit> = join_all(providers.iter().map(|p| {
            let c = &c;
            async move { c.acquire_permit(p, JOB, "job-1", now).await }
        }))
        .await
        .into_iter()
        .map(|p| p.unwrap().unwrap())
        .collect();
        let lease = no_lease();
        for _ in 0..5 {
            w.hibernate();
            w.pass(20_000);
            let (_, held) = c.renew_all(&lease, &permits, w.now()).await.unwrap();
            assert_eq!(held, vec![true; 2]);
        }
        w.hibernate();
        join_all(permits.iter().map(|p| c.release_permit(p))).await;

        let at = format!("{sharding:?} x{shards}");
        assert_eq!(w.opens.get(), gates, "{at}: one session per gate");
        assert_eq!(w.posts.get(), 0, "{at}: nothing asked without a session");
        // Five renewals and the release, per gate.
        assert_eq!(w.msgs.get(), gates * 6, "{at}");
        assert_eq!(saves(), saved, "{at}: no stored row");
        if !TestSql::postgres_selected() {
            // sqlite_only: preupdate-hook row billing
            assert_eq!(
                w.db.0.sqlite().writes().billed(),
                0,
                "{at}: no catalogue row"
            );
        }
        let open: usize = w.sockets.borrow().values().map(BTreeMap::len).sum();
        assert_eq!(open, 0, "{at}: the sessions ended with the job");
    }
}

/// A holder that finds every slot taken is left without a session (an
/// open socket can keep its invocation from ending), and the gate in
/// charge is not asked to take over: one request for each time it asks.
#[tokio::test]
async fn a_refused_holder_leaves_no_session_open() {
    let w = World::new();
    let p = provider("p", 2);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let held = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    for counter in [&w.opens, &w.msgs, &w.posts] {
        counter.set(0);
    }
    for _ in 0..3 {
        assert!(take(&c, &w, &p, JOB, "job-2").await.is_none());
        assert_eq!(w.sessions("permits:all:0"), 1, "only the holder's");
        w.pass(5000);
    }
    assert_eq!((w.opens.get(), w.msgs.get(), w.posts.get()), (3, 0, 0));
    c.release_permit(&held).await.unwrap();
    assert_eq!(w.sessions("permits:all:0"), 0);
    assert!(take(&c, &w, &p, JOB, "job-2").await.is_some());
    assert_eq!(w.sessions("permits:all:0"), 1);
}

/// A permit is held on the session it was taken on and nowhere else:
/// shown on another session, or on none, it is neither renewed nor
/// freed.
#[tokio::test]
async fn a_permit_is_held_only_on_its_own_session() {
    let w = World::new();
    let p = provider("p", 3);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let name = "permits:all:0";
    let a = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    take(&c, &w, &p, JOB, "job-2").await.unwrap();
    let ids: Vec<u64> = w.sockets.borrow()[name].keys().copied().collect();
    assert_eq!(ids.len(), 2);
    let ask = |session: Option<u64>, op: GateOp| {
        let w = w.clone();
        async move {
            let request = GateRequest {
                id: 1,
                gate: name.into(),
                ops: vec![op],
            };
            let reply = w.gate(name).await.handle(session, request, w.now()).await;
            reply.unwrap().answers.remove(0)
        }
    };
    let permits = vec![GatePermit::from(&a)];
    let renew = || GateOp::Renew {
        permits: permits.clone(),
    };
    let release = || GateOp::Release {
        permits: permits.clone(),
    };
    let mut own = Vec::new();
    for id in &ids {
        if ask(Some(*id), renew()).await == GateAnswer::Renewed(vec![true]) {
            own.push(*id);
        }
    }
    assert_eq!(own.len(), 1, "renewed on its own session only");
    assert_eq!(ask(None, renew()).await, GateAnswer::Renewed(vec![false]));
    let other = ids.iter().find(|id| **id != own[0]).unwrap();
    ask(Some(*other), release()).await;
    ask(None, release()).await;
    assert_eq!(w.held(name, "p").await, 2, "freed by nobody else");
    ask(Some(own[0]), release()).await;
    assert_eq!(w.held(name, "p").await, 1);
}

fn step<F: Future>(f: core::pin::Pin<&mut F>) -> core::task::Poll<F::Output> {
    let waker = futures_util::task::noop_waker();
    f.poll(&mut core::task::Context::from_waker(&waker))
}

/// Calls of one holder that cross the end of its session do not run
/// beside each other: the one that waited and the one that came after
/// share one session, and none is left open that nobody knows.
#[tokio::test]
async fn calls_that_cross_the_end_of_a_session_share_the_next() {
    let w = World::new();
    let p = provider("p", 3);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let name = "permits:all:0";
    let first = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    w.opens.set(0);

    // The release is on its way and holds the turn.
    w.stall.set(true);
    let mut release = Box::pin(c.release_permit(&first));
    for _ in 0..4 {
        assert!(step(release.as_mut()).is_pending());
    }
    // A second call waits for its turn.
    let mut one = Box::pin(c.acquire_permit(&p, JOB, "job-1", w.now()));
    for _ in 0..4 {
        assert!(step(one.as_mut()).is_pending());
    }
    // The release arrives and ends the session; the waiter opens the
    // next one, and that is on its way when a third call comes.
    w.stall.set(false);
    assert!(step(release.as_mut()).is_ready());
    assert_eq!(w.sessions(name), 0);
    w.stall.set(true);
    assert!(step(one.as_mut()).is_pending());
    let mut two = Box::pin(c.acquire_permit(&p, JOB, "job-1", w.now()));
    for _ in 0..4 {
        assert!(step(two.as_mut()).is_pending());
        assert!(step(one.as_mut()).is_pending());
    }
    w.stall.set(false);
    let mut done = Vec::new();
    for _ in 0..8 {
        if let core::task::Poll::Ready(permit) = step(one.as_mut()) {
            done.push(permit.unwrap().unwrap());
            break;
        }
    }
    for _ in 0..8 {
        if let core::task::Poll::Ready(permit) = step(two.as_mut()) {
            done.push(permit.unwrap().unwrap());
            break;
        }
    }
    assert_eq!(done.len(), 2);
    assert_eq!((w.sessions(name), w.opens.get()), (1, 1), "one session");
    assert_eq!(w.held(name, "p").await, 2);
    // Both are known to their holder: giving them back ends it.
    for permit in &done {
        assert!(c.renew_permit(permit, w.now()).await.unwrap());
    }
    for permit in &done {
        c.release_permit(permit).await.unwrap();
    }
    assert_eq!((w.sessions(name), w.held(name, "p").await), (0, 0));
}

/// A holder that is gone without giving its slots back (a job that was
/// abandoned) leaves no session open: it ends with the last permit
/// that is forgotten, and the gate frees what was held on it.
#[tokio::test]
async fn an_abandoned_holder_leaves_no_session_open() {
    let w = World::new();
    let p = provider("p", 3);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let name = "permits:all:0";
    let a = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    let b = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    let (calls, _) = (w.calls.get(), c.forget_permit(&a));
    assert_eq!(w.sessions(name), 1, "another slot is still in use on it");
    assert!(c.renew_permit(&b, w.now()).await.unwrap());
    let calls = calls + 1;
    c.forget_permit(&b);
    assert_eq!(w.calls.get(), calls, "nothing is asked");
    assert_eq!(w.sessions(name), 0);
    assert_eq!(w.held(name, "p").await, 0);
    // Forgotten twice, or after its release, is nothing.
    c.forget_permit(&b);
    assert!(take(&c, &w, &p, JOB, "job-1").await.is_some());
}

/// A permit forgotten while another call of its holder is on its way
/// ends the session under that call. The call is answered as on no
/// session: what it asked for is taken on a new one, never counted on
/// from the one that ended.
#[tokio::test]
async fn a_call_that_crosses_a_forgotten_session_asks_again() {
    let w = World::new();
    let p = provider("p", 3);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let name = "permits:all:0";
    let a = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    // The gate hands out a second slot on the session; its answer is
    // on its way when the session ends.
    w.late.set(true);
    let mut more = Box::pin(c.acquire_permit(&p, JOB, "job-1", w.now()));
    for _ in 0..4 {
        assert!(step(more.as_mut()).is_pending());
    }
    assert_eq!(w.msgs.get(), 1, "asked on the open session");
    assert_eq!(w.held(name, "p").await, 2, "and granted on it");
    c.forget_permit(&a);
    assert_eq!(w.sessions(name), 0);
    w.late.set(false);
    let mut got = None;
    for _ in 0..8 {
        if let core::task::Poll::Ready(permit) = step(more.as_mut()) {
            got = permit.unwrap();
            break;
        }
    }
    let got = got.expect("a slot on a new session");
    assert_eq!((w.sessions(name), w.held(name, "p").await), (1, 1));
    assert!(c.renew_permit(&got, w.now()).await.unwrap());
    c.release_permit(&got).await.unwrap();
    assert_eq!((w.sessions(name), w.held(name, "p").await), (0, 0));
}

/// The invocations of one isolate share its sessions and read the
/// time each on a clock of its own, which stands still between two
/// events of that invocation: one can read less than another wrote a
/// moment before. A call whose clock is behind leaves the session of
/// another holder alone: the holder renews on it and gives its slot
/// back on it, and the gate hands the slot on at once. Were the session
/// dropped there, the holder would find none to give its slot back on,
/// the socket would stay open with the invocation that opened it, and
/// the slot would be held until it ran out.
#[tokio::test]
async fn a_call_whose_clock_is_behind_leaves_the_sessions_of_others() {
    let w = World::new();
    let p = provider("p", 3);
    let providers = [p.clone()];
    let behind = Rc::new(Cell::new(0_i64));
    let clock = {
        let (w, behind) = (w.clone(), behind.clone());
        move || UnixMs(w.now().0 - behind.get())
    };
    let (mode, one) = (PermitMode::Gate, GateSharding::One);
    let client = GateClient::new(Wire(w.clone()), clock, mode, one, 1, &providers);
    let c = SqlCatalog::with_gate(w.db.clone(), client.into_gate());
    c.seed_permits(&providers).await.unwrap();
    let name = "permits:all:0";
    for ms in [1, 24, 5_000] {
        let a = take(&c, &w, &p, JOB, "job-1").await.unwrap();
        behind.set(ms);
        let b = take(&c, &w, &p, JOB, "job-2").await.unwrap();
        behind.set(0);
        assert_eq!((w.sessions(name), w.held(name, "p").await), (2, 2));
        assert!(c.renew_permit(&a, w.now()).await.unwrap(), "{ms} ms: held");
        c.release_permit(&a).await.unwrap();
        let open = (w.sessions(name), w.held(name, "p").await);
        assert_eq!(open, (1, 1), "{ms} ms: given back at once");
        c.release_permit(&b).await.unwrap();
        assert_eq!((w.sessions(name), w.held(name, "p").await), (0, 0));
    }
}

/// A session nobody has used for the lifetime of a slot and the time a
/// gate keeps an idle session holds nothing any more: it is forgotten
/// when another holder next asks, and its holder is answered with no
/// request. A millisecond earlier it is still known, and asked on.
#[tokio::test]
async fn a_session_unused_for_the_lifetime_of_a_slot_is_still_forgotten() {
    let w = World::new();
    let p = provider("p", 3);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let name = "permits:all:0";
    for (idle, asked) in [(LINK_IDLE_MS - 1, 1), (LINK_IDLE_MS, 0)] {
        let a = take(&c, &w, &p, JOB, "job-1").await.unwrap();
        w.pass(idle);
        let b = take(&c, &w, &p, JOB, "job-2").await.unwrap();
        let msgs = w.msgs.get();
        assert!(!c.renew_permit(&a, w.now()).await.unwrap(), "ran out");
        assert_eq!(w.msgs.get(), msgs + asked, "after {idle} ms");
        c.release_permit(&a).await.unwrap();
        assert_eq!(w.msgs.get(), msgs + asked, "nothing is held on it");
        c.release_permit(&b).await.unwrap();
        assert_eq!(w.held(name, "p").await, 0);
        w.pass(LINK_IDLE_MS);
    }
}

/// A session stamped by a clock a whole lifetime ahead is not a reading
/// order but a clock that jumped: it is forgotten like an idle one, so
/// a stamp from the future cannot keep a session known forever. A
/// millisecond less ahead, it is still known, and asked on.
#[tokio::test]
async fn a_session_stamped_far_ahead_is_still_forgotten() {
    let w = World::new();
    let p = provider("p", 3);
    let providers = [p.clone()];
    let ahead = Rc::new(Cell::new(0_i64));
    let clock = {
        let (w, ahead) = (w.clone(), ahead.clone());
        move || UnixMs(w.now().0 + ahead.get())
    };
    let (mode, one) = (PermitMode::Gate, GateSharding::One);
    let client = GateClient::new(Wire(w.clone()), clock, mode, one, 1, &providers);
    let c = SqlCatalog::with_gate(w.db.clone(), client.into_gate());
    c.seed_permits(&providers).await.unwrap();
    let name = "permits:all:0";
    for (skew, asked) in [(LINK_IDLE_MS - 1, 1), (LINK_IDLE_MS, 0)] {
        ahead.set(skew);
        let a = take(&c, &w, &p, JOB, "job-1").await.unwrap();
        ahead.set(0);
        let b = take(&c, &w, &p, JOB, "job-2").await.unwrap();
        let msgs = w.msgs.get();
        c.release_permit(&a).await.unwrap();
        assert_eq!(w.msgs.get(), msgs + asked, "{skew} ms ahead");
        c.release_permit(&b).await.unwrap();
        w.pass(LINK_IDLE_MS);
        assert_eq!(w.held(name, "p").await, 0);
    }
}

/// What a gate said of its load is heard by one invocation and read by
/// another, whose clock can be behind: it is used all the same, unless
/// it is a whole hint's life ahead, which is a clock that jumped.
#[tokio::test]
async fn the_load_a_gate_told_is_used_by_a_call_whose_clock_is_behind() {
    let w = World::new();
    let p = provider("p", 3);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    take(&c, &w, &p, JOB, "job-1").await.unwrap();
    for behind in [0, 1, 24, HINT_MS - 1] {
        let load = c.provider_load(UnixMs(w.now().0 - behind)).await.unwrap();
        assert_eq!(load[0].held, 1, "{behind} ms behind");
    }
    let load = c.provider_load(UnixMs(w.now().0 - HINT_MS)).await.unwrap();
    assert_eq!(load[0].held, 0, "too far ahead to go by");
    let load = c.provider_load(UnixMs(w.now().0 + HINT_MS)).await.unwrap();
    assert_eq!(load[0].held, 0, "too old to go by");
}

/// Names that are not ASCII are counted at their stored size, and
/// their providers are served like any other.
#[tokio::test]
async fn a_provider_with_a_name_beyond_ascii_gets_its_slots() {
    let w = World::new();
    let p = provider("n\u{e9}v\u{e9}-\u{65e5}\u{672c}", 3);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let a = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    assert!(c.renew_permit(&a, w.now()).await.unwrap());
    c.release_permit(&a).await.unwrap();
}

/// A deploy is waited out whether or not a session is still listed at
/// the first start under the new code: the sessions that are listed do
/// not show that nothing else was held.
#[tokio::test]
async fn a_deploy_is_waited_out_with_a_session_still_listed() {
    let w = World::new();
    let p = provider("p", 3);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let name = "permits:all:0";
    let kept = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    // New code; this session's connection was not cut.
    w.boot.set(w.boot.get() + 1);
    w.hibernate();
    w.pass(1);
    assert!(take(&c, &w, &p, JOB, "job-2").await.is_none());
    assert!(c.renew_permit(&kept, w.now()).await.unwrap(), "it holds on");
    assert_eq!(w.held(name, "p").await, 1);
    w.pass(20_000);
    assert!(c.renew_permit(&kept, w.now()).await.unwrap());
    w.pass(JOB_MS + SKEW_MS - 20_000);
    assert!(take(&c, &w, &p, JOB, "job-2").await.is_some());
}

/// The slots of one session fit with its connection: a session is
/// refused a slot before what must be kept for it grows too large.
#[tokio::test]
async fn a_session_holds_no_more_than_fits_with_its_connection() {
    let w = World::new();
    let p = provider("p", 2000);
    let providers = [p.clone()];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let mut taken = 0;
    while take(&c, &w, &p, JOB, "job-1").await.is_some() {
        taken += 1;
    }
    assert!((64..1999).contains(&taken), "{taken} slots on one session");
    let kept = serde_json::to_string(&w.sockets.borrow()["permits:all:0"])
        .unwrap()
        .len();
    assert!(kept <= SESSION_STATE_MAX + 64, "{kept} bytes");
    // Another holder has a session of its own.
    assert!(take(&c, &w, &p, JOB, "job-2").await.is_some());
}

trait RenewPermits {
    async fn renew_all_permits(&self, permits: &[Permit]) -> Vec<bool>;
}

impl RenewPermits for SqlCatalog<Db> {
    async fn renew_all_permits(&self, permits: &[Permit]) -> Vec<bool> {
        let lease = no_lease();
        self.renew_all(&lease, permits, UnixMs(T0)).await.unwrap().1
    }
}

/// A caller that gives up waiting (a read bounds its renewal with a
/// timer) may be the one that carried the questions of others. They
/// ask again and are answered.
#[tokio::test]
async fn a_dropped_call_does_not_strand_the_calls_it_carried() {
    let w = World::new();
    let providers = [provider("p", 4)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let a = take(&c, &w, &providers[0], READ, "read-1").await.unwrap();
    let b = take(&c, &w, &providers[0], READ, "read-1").await.unwrap();
    let now = w.now();

    let mut first = Box::pin(c.renew_permit(&a, now));
    let mut second = Box::pin(c.renew_permit(&b, now));
    let waker = futures_util::task::noop_waker();
    let mut cx = core::task::Context::from_waker(&waker);
    // Both are queued.
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    // The first is dropped while both still wait in the queue: the
    // second sends both questions.
    drop(first);
    assert!(second.await.unwrap());
}

/// The same once the request is on its way: the caller that sent the
/// questions of both is dropped before the answer comes. The other is
/// told that its question was lost and asks again alone.
#[tokio::test]
async fn a_call_dropped_in_flight_does_not_strand_the_calls_it_carried() {
    let w = World::new();
    let providers = [provider("p", 4)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let a = take(&c, &w, &providers[0], READ, "read-1").await.unwrap();
    let b = take(&c, &w, &providers[0], READ, "read-1").await.unwrap();
    let now = w.now();
    let calls = w.calls.get();

    let mut first = Box::pin(c.renew_permit(&a, now));
    let mut second = Box::pin(c.renew_permit(&b, now));
    let waker = futures_util::task::noop_waker();
    let mut cx = core::task::Context::from_waker(&waker);
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    // The first sends both questions; the request does not arrive.
    w.stall.set(true);
    assert!(first.as_mut().poll(&mut cx).is_pending());
    // The second finds the queue taken and waits for its answer.
    assert!(second.as_mut().poll(&mut cx).is_pending());
    assert_eq!(w.calls.get(), calls);
    drop(first);
    w.stall.set(false);
    assert!(second.await.unwrap());
    // One request: that of the second, alone.
    assert_eq!(w.calls.get(), calls + 1);
    assert_eq!(c.provider_load(now).await.unwrap()[0].held, 2);
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[test]
fn the_switch_defaults_to_the_slot_rows() {
    assert_eq!(PermitMode::from_var(None), Ok(PermitMode::Catalog));
    assert_eq!(PermitMode::from_var(Some("")), Ok(PermitMode::Catalog));
    assert_eq!(PermitMode::from_var(Some("d1")), Ok(PermitMode::Catalog));
    assert_eq!(PermitMode::from_var(Some(" do ")), Ok(PermitMode::Gate));
    assert!(PermitMode::from_var(Some("DO")).is_err());
    assert!(PermitMode::from_var(Some("gate")).is_err());
    assert_eq!(GateSharding::from_var(None), Ok(GateSharding::Account));
    assert_eq!(GateSharding::from_var(Some("one")), Ok(GateSharding::One));
    assert_eq!(
        GateSharding::from_var(Some("account")),
        Ok(GateSharding::Account)
    );
    assert!(GateSharding::from_var(Some("many")).is_err());
    assert_eq!(shards_from_var(None), Ok(1));
    assert_eq!(shards_from_var(Some(" ")), Ok(1));
    assert_eq!(shards_from_var(Some("4")), Ok(4));
    assert_eq!(shards_from_var(Some("64")), Ok(MAX_GATE_SHARDS));
    assert!(shards_from_var(Some("0")).is_err());
    assert!(shards_from_var(Some("65")).is_err());
    assert!(shards_from_var(Some("two")).is_err());
}

/// With `PERMITS=d1` and no gate in the catalogue's way, nothing asks a
/// gate: the switch costs one read at the periodic step.
#[tokio::test]
async fn the_slot_rows_mode_asks_no_gate() {
    let w = World::new();
    let providers = [provider("p", 2)];
    let c = w.catalog(PermitMode::Catalog, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let a = take(&c, &w, &providers[0], JOB, "job-1").await.unwrap();
    let b = take(&c, &w, &providers[0], READ, "read-1").await.unwrap();
    assert!(take(&c, &w, &providers[0], READ, "read-2").await.is_none());
    assert!(c.renew_permit(&a, w.now()).await.unwrap());
    c.release_permit(&b).await.unwrap();
    c.provider_load(w.now()).await.unwrap();
    assert_eq!(w.calls.get(), 0);
    assert_eq!(w.rows_of_callers("p").await, 1);
}

/// A gate answers under one name only.
#[tokio::test]
async fn a_gate_asked_under_another_name_refuses() {
    let w = World::new();
    let gate = w.gate("permits:all:0").await;
    let ask = |name: &str| GateRequest {
        id: 1,
        gate: name.into(),
        ops: vec![GateOp::Load],
    };
    gate.handle(None, ask("permits:all:0"), w.now())
        .await
        .unwrap();
    assert!(gate.handle(None, ask("other"), w.now()).await.is_err());
}
