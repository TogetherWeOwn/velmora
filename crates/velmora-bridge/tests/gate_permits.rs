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
use velmora_bridge::testkit::RusqliteSql;
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
struct Db(Rc<RusqliteSql>);

impl Sql for Db {
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

/// The gates of a deployment: their storage, their memory (lost on
/// [`World::restart`]) and the clock they read.
struct World {
    db: Db,
    now: Cell<i64>,
    stores: RefCell<BTreeMap<String, Store>>,
    gates: RefCell<BTreeMap<String, Rc<Gate<Db, Store>>>>,
    calls: Cell<u32>,
    ops: Cell<u32>,
}

impl World {
    fn new() -> Rc<Self> {
        Rc::new(World {
            db: Db(Rc::new(RusqliteSql::with_schema().unwrap())),
            now: Cell::new(T0),
            stores: RefCell::default(),
            gates: RefCell::default(),
            calls: Cell::new(0),
            ops: Cell::new(0),
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

    fn gate(&self, name: &str) -> Rc<Gate<Db, Store>> {
        let store = self.store(name);
        self.gates
            .borrow_mut()
            .entry(name.to_string())
            .or_insert_with(|| Rc::new(Gate::new(self.db.clone(), store)))
            .clone()
    }

    /// The object loses its memory: a deploy, or a move.
    fn restart(&self) {
        self.gates.borrow_mut().clear();
    }

    /// Lets every gate do its housekeeping, as the host does while
    /// [`Gate::next_wake`] names a time.
    async fn tick(&self) {
        let gates: Vec<_> = self.gates.borrow().values().cloned().collect();
        for gate in gates {
            gate.tick(self.now()).await;
        }
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
        let client = GateClient::new(Wire(self.clone()), mode, sharding, shards, providers);
        SqlCatalog::with_gate(self.db.clone(), client.into_gate())
    }

    /// A catalogue as a Worker from before the gate has it.
    fn old_catalog(&self) -> SqlCatalog<Db> {
        SqlCatalog::new(self.db.clone())
    }

    async fn count(&self, sql: &str) -> i64 {
        match self.db.query(sql, &[]).await.unwrap()[0][0] {
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
            .handle(
                GateRequest {
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

impl GateTransport for Wire {
    async fn call(&self, request: GateRequest) -> Result<GateReply> {
        self.0.calls.set(self.0.calls.get() + 1);
        self.0.ops.set(self.0.ops.get() + request.ops.len() as u32);
        // As on the wire: the request and the reply are JSON.
        let request: GateRequest =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        let gate = self.0.gate(&request.gate);
        let reply = gate.handle(request, self.0.now()).await?;
        Ok(serde_json::from_str(&serde_json::to_string(&reply).unwrap()).unwrap())
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
        let rows = SqlCatalog::new(RusqliteSql::with_schema().unwrap());
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
                        &holder,
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
                    let y = core.renew(b, UnixMs(now));
                    assert_eq!(x, y, "seed {seed} step {step}: renew {}", a.provider);
                }
                7 if !held.is_empty() => {
                    let (a, b) = held.swap_remove(rng.next(held.len() as u64) as usize);
                    rows.release_permit(&a).await.unwrap();
                    core.release(&b);
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

/// A gate that was idle when it lost its memory waits for nothing.
#[tokio::test]
async fn a_start_after_idle_hands_out_at_once() {
    let w = World::new();
    let providers = [provider("p", 3)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let a = take(&c, &w, &providers[0], JOB, "job-1").await.unwrap();
    c.release_permit(&a).await.unwrap();
    // Nothing held: after the linger the horizon is cleared.
    let gate = w.gate("permits:all:0");
    assert!(gate.next_wake(w.now()).is_some());
    w.pass(LINGER_MS);
    w.tick().await;
    let record = w.store("permits:all:0").record.borrow().clone().unwrap();
    assert_eq!((record.jobs_until, record.reads_until), (0, 0));
    assert_eq!(gate.next_wake(w.now()), None, "nothing keeps it in memory");

    w.restart();
    w.pass(1);
    assert!(take(&c, &w, &providers[0], JOB, "job-2").await.is_some());
    assert!(take(&c, &w, &providers[0], READ, "read-2").await.is_some());
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
            .acquire(&p, &[], true, "h", UnixMs(T0), Warm::Done)
            .unwrap();
        last = permit.token;
        first.release(&permit);
    }
    let mut second = Core::new(UnixMs(T0 + 1));
    let permit = second
        .acquire(&p, &[], true, "h", UnixMs(T0 + 1), Warm::Done)
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
    assert!(c.renew_permit(&permit, w.now()).await.is_err());
    // The slot is not extended: it ends where the last renewal put it.
    store.fail.set(false);
    w.pass(JOB_MS - 20_000 + 1);
    assert!(!c.renew_permit(&permit, w.now()).await.unwrap());
}

/// The cost in storage: one write when a class first takes a slot, one
/// per [`HORIZON_STEP_MS`] while slots stay in use, one when all is
/// quiet again. Never one per permit.
#[tokio::test]
async fn storage_is_written_per_busy_period_not_per_permit() {
    let w = World::new();
    let providers = [provider("p", 8), provider("q", 8)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    c.seed_permits(&providers).await.unwrap();
    let store = w.store("permits:all:0");
    let seized = store.saves.get();
    assert!(seized <= 1, "the seizure is one write");
    w.db.0.meter_writes().unwrap();

    // 30 minutes of jobs: 6 slots taken, renewed every 20 s, given
    // back and taken again every minute.
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
        let held = c.renew_permit(&permits[0], w.now()).await.unwrap();
        assert!(held);
        w.pass(20_000);
        w.tick().await;
    }
    assert_eq!(cycles, 180);
    let busy = store.saves.get() - seized;
    // 30 minutes over a 10 minute step: the first write and 3 more.
    assert!((3..=4).contains(&busy), "{busy} writes in 30 minutes");
    for permit in permits.drain(..) {
        c.release_permit(&permit).await.unwrap();
    }
    w.pass(LINGER_MS);
    w.tick().await;
    assert_eq!(store.saves.get() - seized, busy + 1, "one write to clear");
    assert_eq!(
        w.db.0.writes().billed(),
        0,
        "no catalogue row for any acquire, renewal or release"
    );
}

/// A horizon being cleared while a request arrives: the slot is handed
/// out only with its horizon back in storage.
#[tokio::test]
async fn a_slot_taken_after_the_clear_is_covered_again() {
    let w = World::new();
    let providers = [provider("p", 2)];
    let c = w.catalog(PermitMode::Gate, GateSharding::One, &providers);
    let a = take(&c, &w, &providers[0], READ, "read-1").await.unwrap();
    c.release_permit(&a).await.unwrap();
    w.pass(LINGER_MS);
    w.tick().await;
    let b = take(&c, &w, &providers[0], READ, "read-2").await.unwrap();
    let stored = w.store("permits:all:0").record.borrow().clone().unwrap();
    assert!(stored.reads_until >= w.now.get() + READ_MS);
    // And a tick with a live slot clears nothing.
    w.pass(LINGER_MS * 3);
    w.tick().await;
    let stored = w.store("permits:all:0").record.borrow().clone().unwrap();
    assert!(stored.reads_until >= w.now.get() + READ_MS - LINGER_MS * 3);
    assert!(w.gate("permits:all:0").next_wake(w.now()).is_some());
    c.release_permit(&b).await.unwrap();
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
                    w.tick().await;
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
    w.tick().await;

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
                w.tick().await;
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

/// No more gates than the smallest limit of the account: each of them
/// has a connection and an address to hand out.
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
        2
    );
    assert_eq!(w.rows_of_gates("p").await, 8);
}

/// A gate asked for a part of an account that does not exist refuses.
#[tokio::test]
async fn a_part_outside_the_division_is_refused() {
    let w = World::new();
    let p = GateProvider::from(&provider("p", 2)).part(2, 2);
    let ask = GateRequest {
        gate: "permits:account.p:2".into(),
        ops: vec![GateOp::Acquire {
            provider: p,
            peers: Vec::new(),
            background: true,
            holder: "job".into(),
        }],
    };
    let gate = w.gate("permits:account.p:2");
    assert!(gate.handle(ask, w.now()).await.is_err());
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
    // The first takes both questions with it and is dropped before it
    // is polled to the end.
    drop(first);
    assert!(second.await.unwrap());
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
    let gate = w.gate("permits:all:0");
    let ask = |name: &str| GateRequest {
        gate: name.into(),
        ops: vec![GateOp::Load],
    };
    gate.handle(ask("permits:all:0"), w.now()).await.unwrap();
    assert!(gate.handle(ask("other"), w.now()).await.is_err());
}
