//! Jobs that wait for a provider slot in the line of a gate
//! (`SLOT_WAIT = "push"`, `velmora_bridge::gate`): first come first, no
//! question while they wait, a holder or a waiter that dies, an object
//! that leaves memory or restarts, and what the wait costs in requests.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Poll;

use velmora_bridge::gate::*;
use velmora_bridge::ingress::Sleeper;
use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::*;

const T0: i64 = 1_762_992_000_123;
const JOB_MS: i64 = 120_000;
const GATE: &str = "permits:all:0";
const JOB: PermitClass = PermitClass::Background;
const READ: PermitClass = PermitClass::Read;

fn provider(id: &str, max_conns: u32) -> ProviderConfig {
    let json = format!(
        "{{\"id\":\"{id}\",\"host\":\"news.example.invalid\",\"port\":563,\"tls\":true,\
         \"user\":\"u\",\"pass\":\"p\",\"backbone\":\"bb\",\"post\":true,\"read\":true,\
         \"max_conns\":{max_conns}}}"
    );
    serde_json::from_str(&json).unwrap()
}

/// Not ready the first time it is asked: what else has arrived at the
/// object goes on meanwhile.
struct Aside(bool);

impl Future for Aside {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> Poll<()> {
        if core::mem::replace(&mut self.0, true) {
            return Poll::Ready(());
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// One database for the catalogue callers and the gates. With the flag
/// set, the next batch takes its time and then fails.
#[derive(Clone)]
struct Db(Rc<RusqliteSql>, Rc<Cell<bool>>);

impl Sql for Db {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        self.0.query(sql, params).await
    }
    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.0.exec(sql, params).await
    }
    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        if self.1.replace(false) {
            Aside(false).await;
            return Err(BridgeError::Invalid("the catalogue is down"));
        }
        self.0.batch(stmts).await
    }
}

/// The durable storage of one gate. It outlives the gate's memory.
#[derive(Clone, Default)]
struct Store {
    record: Rc<RefCell<Option<GateRecord>>>,
    saves: Rc<Cell<u32>>,
    /// The storage is down: nothing is saved.
    down: Rc<Cell<bool>>,
}

impl GateStore for Store {
    async fn load(&self) -> Result<Option<GateRecord>> {
        Ok(self.record.borrow().clone())
    }
    async fn save(&self, record: &GateRecord) -> Result<()> {
        if self.down.get() {
            return Err(BridgeError::Invalid("the storage is down"));
        }
        self.saves.set(self.saves.get() + 1);
        *self.record.borrow_mut() = Some(record.clone());
        Ok(())
    }
}

/// The caller's end of one open session, as the runtime has it: what
/// the object attached to it, what it sent and the caller has not read
/// yet, and the invocation that opened it.
struct Socket {
    state: SessionState,
    inbox: VecDeque<GateReply>,
    owner: String,
}

/// The gate of a deployment as its host runs it: storage, open
/// sessions, memory (lost on [`World::hibernate`] and
/// [`World::restart`]), the clock, and the replies it sends to
/// sessions that wait.
struct World {
    /// The name the object is asked under.
    name: String,
    db: Db,
    now: Cell<i64>,
    store: Store,
    gate: RefCell<Option<Rc<Gate<Db, Store>>>>,
    sockets: RefCell<BTreeMap<u64, Socket>>,
    /// Sessions whose connection has ended and the object has not
    /// heard of yet.
    ended: RefCell<Vec<u64>>,
    boot: Cell<u32>,
    /// Sessions opened: each is one billed request.
    opens: Cell<u32>,
    /// Messages on open sessions: each is billed as 1/20 request.
    msgs: Cell<u32>,
    /// Replies the gate sent to sessions that waited.
    pushed: Cell<u32>,
    /// The gate runs code from before the line: it cannot read a
    /// request to wait.
    old_code: Cell<bool>,
}

impl World {
    fn new() -> Rc<Self> {
        Self::named(GATE)
    }

    /// The gate `name` of a deployment with a catalogue of its own.
    fn named(name: &str) -> Rc<Self> {
        let db = Db(Rc::new(RusqliteSql::with_schema().unwrap()), Rc::default());
        Self::on(db, name)
    }

    /// The gate `name` of the deployment `other` is of: an object of
    /// its own on the same catalogue.
    fn beside(other: &World, name: &str) -> Rc<Self> {
        Self::on(other.db.clone(), name)
    }

    fn on(db: Db, name: &str) -> Rc<Self> {
        Rc::new(World {
            name: name.to_string(),
            db,
            now: Cell::new(T0),
            store: Store::default(),
            gate: RefCell::new(None),
            sockets: RefCell::default(),
            ended: RefCell::default(),
            boot: Cell::new(1),
            opens: Cell::new(0),
            msgs: Cell::new(0),
            pushed: Cell::new(0),
            old_code: Cell::new(false),
        })
    }

    fn now(&self) -> UnixMs {
        UnixMs(self.now.get())
    }

    fn pass(&self, ms: i64) {
        self.now.set(self.now.get() + ms);
    }

    /// A timer of the host: it ends when the clock has moved that far.
    fn sleeper(self: &Rc<Self>) -> Sleeper {
        let w = self.clone();
        Rc::new(move |ms| {
            let (w, due) = (w.clone(), w.now.get() + i64::from(ms));
            Box::pin(core::future::poll_fn(move |_| match w.now.get() >= due {
                true => Poll::Ready(()),
                false => Poll::Pending,
            }))
        })
    }

    /// The gate in memory, as the host brings it there for an event:
    /// with the sessions whose connections are open.
    async fn gate(&self) -> Rc<Gate<Db, Store>> {
        let gate = self
            .gate
            .borrow_mut()
            .get_or_insert_with(|| {
                Rc::new(Gate::new(
                    self.db.clone(),
                    self.store.clone(),
                    format!("v{}", self.boot.get()),
                ))
            })
            .clone();
        if !gate.started() {
            let now = self.now();
            let sessions: Vec<SessionState> = {
                // Nothing live on it and long silent: the host closes
                // it and does not bring it back.
                let mut sockets = self.sockets.borrow_mut();
                sockets.retain(|_, s| !s.state.stale(now));
                sockets.values().map(|s| s.state.clone()).collect()
            };
            let _ = gate.resume(sessions, now).await;
        }
        gate
    }

    /// What the host does when a request comes on no session or opens
    /// one: it closes the sessions that hold nothing live and have
    /// long been silent.
    fn reap(&self, gate: &Gate<Db, Store>) {
        let now = self.now();
        self.sockets.borrow_mut().retain(|id, s| {
            let idle = s.state.stale(now);
            if idle {
                gate.close(*id);
            }
            !idle
        });
    }

    /// The object leaves memory between two events. Its sessions stay
    /// open.
    fn hibernate(&self) {
        *self.gate.borrow_mut() = None;
    }

    /// New code that cuts every session: the object loses its memory
    /// and its connections, and starts as another version.
    fn restart(&self) {
        self.boot.set(self.boot.get() + 1);
        *self.gate.borrow_mut() = None;
        self.sockets.borrow_mut().clear();
        self.ended.borrow_mut().clear();
    }

    /// What the host does after every event at the gate: the sessions
    /// that were handed a slot are sent it, each kept with its
    /// connection first. One that cannot be sent to has ended.
    async fn deliver(&self, gate: &Gate<Db, Store>) {
        loop {
            let (mut lost, pushes) = (false, gate.pushes());
            if pushes.is_empty() {
                return;
            }
            for (id, reply) in pushes {
                let state = gate.session(id, self.now());
                match self.sockets.borrow_mut().get_mut(&id) {
                    Some(socket) => {
                        socket.state = state;
                        socket.inbox.push_back(on_the_wire(&reply));
                        self.pushed.set(self.pushed.get() + 1);
                    }
                    None => {
                        gate.close(id);
                        lost = true;
                    }
                }
            }
            if !lost {
                return;
            }
            gate.settle(self.now()).await;
        }
    }

    /// The object hears of the connections that ended, as it does
    /// before any later request reaches it.
    async fn hear(&self) {
        let ended = core::mem::take(&mut *self.ended.borrow_mut());
        if ended.is_empty() {
            return;
        }
        let gate = self.gate().await;
        for id in ended {
            gate.close(id);
        }
        gate.settle(self.now()).await;
        self.deliver(&gate).await;
    }

    /// The invocation `owner` ends, however: the runtime closes its
    /// sessions, and the object hears of it.
    async fn end(&self, owner: &str) {
        self.end_unheard(owner);
        self.hear().await;
    }

    /// The same, and the object has not heard of it yet.
    fn end_unheard(&self, owner: &str) {
        let mut sockets = self.sockets.borrow_mut();
        let gone: Vec<u64> = sockets
            .iter()
            .filter(|(_, s)| s.owner == owner)
            .map(|(id, _)| *id)
            .collect();
        for id in gone {
            sockets.remove(&id);
            self.ended.borrow_mut().push(id);
        }
    }

    /// The same, where the object never hears of it: it finds out when
    /// it sends to the session.
    fn vanish(&self, owner: &str) {
        self.sockets.borrow_mut().retain(|_, s| s.owner != owner);
    }

    fn sessions(&self) -> usize {
        self.sockets.borrow().len()
    }

    /// A catalogue as the invocation `owner` of a Worker has it, with
    /// `SLOT_WAIT` set to push or not.
    fn worker(
        self: &Rc<Self>,
        owner: &str,
        mode: PermitMode,
        push: bool,
        providers: &[ProviderConfig],
    ) -> SqlCatalog<Db> {
        let clock = {
            let w = self.clone();
            move || w.now()
        };
        let wire = Wire(self.clone(), owner.to_string());
        let client = GateClient::new(wire, clock, mode, GateSharding::One, 1, providers);
        SqlCatalog::with_gate(self.db.clone(), client.with_push(push).into_gate())
    }

    /// The same for a Worker that waits in the line.
    fn pushing(self: &Rc<Self>, owner: &str, providers: &[ProviderConfig]) -> SqlCatalog<Db> {
        self.worker(owner, PermitMode::Gate, true, providers)
    }

    /// Slots the gate has handed out on `provider` and that are live.
    async fn held(&self, provider: &str) -> u32 {
        self.hear().await;
        let gate = self.gate().await;
        let request = GateRequest {
            id: 0,
            gate: self.name.clone(),
            ops: vec![GateOp::Load],
        };
        let reply = gate.handle(None, request, self.now()).await.unwrap();
        self.deliver(&gate).await;
        let load = match reply.answers.into_iter().next() {
            Some(GateAnswer::Load(load)) => load,
            other => panic!("not a load: {other:?}"),
        };
        let mut load = load.iter();
        load.find(|l| l.provider == provider).map_or(0, |l| l.held)
    }
}

fn on_the_wire<T: serde::Serialize + serde::de::DeserializeOwned>(sent: &T) -> T {
    serde_json::from_str(&serde_json::to_string(sent).unwrap()).unwrap()
}

/// The way to the gate from the invocation named.
struct Wire(Rc<World>, String);

impl Wire {
    /// A request arrives: the object has heard of every connection
    /// that ended before it. Code from before the line reads no
    /// request to wait.
    async fn arrive(&self, request: &GateRequest) -> Result<GateRequest> {
        self.0.hear().await;
        let waits = |op: &GateOp| matches!(op, GateOp::Wait { .. });
        if self.0.old_code.get() && request.ops.iter().any(waits) {
            return Err(BridgeError::Sql("gate: call refused".into()));
        }
        Ok(on_the_wire(request))
    }
}

/// The caller's end of a session.
struct Line {
    world: Rc<World>,
    id: u64,
}

impl Line {
    fn open(&self) -> bool {
        self.world.sockets.borrow().contains_key(&self.id)
    }

    /// The session is kept with its connection, as the host does
    /// before a reply leaves.
    fn attach(&self, gate: &Gate<Db, Store>) {
        let state = gate.session(self.id, self.world.now());
        let size = serde_json::to_string(&state).unwrap().len();
        assert!(size <= 16_384, "{size} bytes with one connection");
        if let Some(socket) = self.world.sockets.borrow_mut().get_mut(&self.id) {
            socket.state = state;
        }
    }
}

impl GateSession for Line {
    async fn call(&self, request: GateRequest) -> Result<GateReply> {
        let request = Wire(self.world.clone(), String::new())
            .arrive(&request)
            .await?;
        if !self.open() {
            return Err(BridgeError::Sql("gate: session ended".into()));
        }
        self.world.msgs.set(self.world.msgs.get() + 1);
        let gate = self.world.gate().await;
        let id = request.id;
        let reply = gate
            .handle(Some(self.id), request, self.world.now())
            .await
            .unwrap_or(GateReply::failed(id));
        self.attach(&gate);
        self.world.deliver(&gate).await;
        // Read in the order sent: a slot that was on its way when the
        // question left comes first, under the same id.
        match self.world.sockets.borrow_mut().get_mut(&self.id) {
            Some(socket) => {
                socket.inbox.push_back(on_the_wire(&reply));
                let at = socket.inbox.iter().position(|r| r.id == id);
                Ok(socket.inbox.remove(at.unwrap()).unwrap())
            }
            None => Err(BridgeError::Sql("gate: session ended".into())),
        }
    }

    async fn pushed(&self, id: u64) -> Result<GateReply> {
        core::future::poll_fn(|_| {
            let mut sockets = self.world.sockets.borrow_mut();
            let Some(socket) = sockets.get_mut(&self.id) else {
                return Poll::Ready(Err(BridgeError::Sql("gate: session ended".into())));
            };
            match socket.inbox.iter().position(|r| r.id == id) {
                Some(at) => Poll::Ready(Ok(socket.inbox.remove(at).unwrap())),
                None => Poll::Pending,
            }
        })
        .await
    }

    fn close(&self) {
        if self.world.sockets.borrow_mut().remove(&self.id).is_some() {
            self.world.ended.borrow_mut().push(self.id);
        }
    }
}

/// The way from one invocation to the gates of two accounts, each an
/// object of its own.
struct Wires(Vec<(String, Wire)>);

impl Wires {
    fn to(&self, gate: &str) -> &Wire {
        let found = self.0.iter().find(|(name, _)| name == gate);
        &found.unwrap_or_else(|| panic!("no gate {gate}")).1
    }
}

impl GateTransport for Wires {
    type Session = Line;

    async fn open(&self, request: GateRequest) -> Result<(Line, GateReply)> {
        self.to(&request.gate).open(request).await
    }

    async fn call(&self, request: GateRequest) -> Result<GateReply> {
        self.to(&request.gate).call(request).await
    }
}

/// Two accounts with one job slot each, both taken by `c`, and a gate
/// for each: `(p, its gate)`, `(q, its gate)`.
struct Two {
    p: (ProviderConfig, Rc<World>),
    q: (ProviderConfig, Rc<World>),
    c: SqlCatalog<Db>,
    held: [Permit; 2],
}

impl Two {
    async fn new() -> Two {
        let wp = World::named(&gate_name("account.p", 0));
        let wq = World::beside(&wp, &gate_name("account.q", 0));
        let (p, q) = (provider("p", 2), provider("q", 2));
        let c = Two::client(&wp, &wq, "holders", &[p.clone(), q.clone()]);
        let on_p = take(&c, &wp, &p, JOB, "job-1").await.unwrap();
        let on_q = take(&c, &wq, &q, JOB, "job-2").await.unwrap();
        assert!(take(&c, &wp, &p, JOB, "job-3").await.is_none(), "full");
        assert!(take(&c, &wq, &q, JOB, "job-3").await.is_none(), "full");
        Two {
            p: (p, wp),
            q: (q, wq),
            c,
            held: [on_p, on_q],
        }
    }

    /// A catalogue of the invocation `owner`, which waits in the lines.
    fn client(
        wp: &Rc<World>,
        wq: &Rc<World>,
        owner: &str,
        providers: &[ProviderConfig],
    ) -> SqlCatalog<Db> {
        let wire = |w: &Rc<World>| (w.name.clone(), Wire(w.clone(), owner.into()));
        let wires = Wires(vec![wire(wp), wire(wq)]);
        let clock = {
            let w = wp.clone();
            move || w.now()
        };
        let (mode, by) = (PermitMode::Gate, GateSharding::Account);
        let client = GateClient::new(wires, clock, mode, by, 1, providers);
        SqlCatalog::with_gate(wp.db.clone(), client.with_push(true).into_gate())
    }

    fn both(&self) -> [ProviderConfig; 2] {
        [self.p.0.clone(), self.q.0.clone()]
    }
}

impl GateTransport for Wire {
    type Session = Line;

    async fn open(&self, request: GateRequest) -> Result<(Line, GateReply)> {
        let request = self.arrive(&request).await?;
        self.0.opens.set(self.0.opens.get() + 1);
        let gate = self.0.gate().await;
        self.0.reap(&gate);
        let now = self.0.now();
        let line = Line {
            world: self.0.clone(),
            id: gate.open(now).await?,
        };
        let reply = match gate.handle(Some(line.id), request, now).await {
            Ok(reply) => reply,
            Err(e) => {
                gate.close(line.id);
                gate.settle(now).await;
                self.0.deliver(&gate).await;
                return Err(e);
            }
        };
        let socket = Socket {
            state: gate.session(line.id, now),
            inbox: VecDeque::new(),
            owner: self.1.clone(),
        };
        self.0.sockets.borrow_mut().insert(line.id, socket);
        self.0.deliver(&gate).await;
        Ok((line, on_the_wire(&reply)))
    }

    async fn call(&self, request: GateRequest) -> Result<GateReply> {
        let request = self.arrive(&request).await?;
        let gate = self.0.gate().await;
        self.0.reap(&gate);
        let reply = gate.handle(None, request, self.0.now()).await;
        self.0.deliver(&gate).await;
        Ok(on_the_wire(&reply?))
    }
}

async fn take(
    c: &SqlCatalog<Db>,
    w: &World,
    p: &ProviderConfig,
    class: PermitClass,
    holder: &str,
) -> Option<Permit> {
    c.acquire_permit(p, class, holder, w.now()).await.unwrap()
}

type Waiting<'a> = Pin<Box<dyn Future<Output = Result<SlotWait>> + 'a>>;

/// `holder` waits in the line for a slot on one of `providers`.
fn wait<'a>(
    c: &'a SqlCatalog<Db>,
    providers: &'a [&'a ProviderConfig],
    holder: &'a str,
    ms: i64,
    sleep: &'a Sleeper,
) -> Waiting<'a> {
    Box::pin(c.await_permit(providers, holder, ms, sleep))
}

/// Runs a wait as far as it goes with what has arrived.
fn turn(f: &mut Waiting<'_>) -> Option<SlotWait> {
    let waker = futures_util::task::noop_waker();
    let mut cx = core::task::Context::from_waker(&waker);
    for _ in 0..64 {
        if let Poll::Ready(out) = f.as_mut().poll(&mut cx) {
            return Some(out.unwrap());
        }
    }
    None
}

/// Two jobs hold both job slots of `p`; a third slot is kept for
/// reads.
struct Full {
    w: Rc<World>,
    p: ProviderConfig,
    c: SqlCatalog<Db>,
    first: Permit,
    second: Permit,
}

async fn full() -> Full {
    let w = World::new();
    let p = provider("p", 3);
    let c = w.pushing("holders", core::slice::from_ref(&p));
    let first = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    let second = take(&c, &w, &p, JOB, "job-2").await.unwrap();
    assert!(take(&c, &w, &p, JOB, "job-3").await.is_none(), "full");
    w.pass(1_000);
    Full {
        w,
        p,
        c,
        first,
        second,
    }
}

// ---------------------------------------------------------------------------
// First come first, and nothing asked while waiting
// ---------------------------------------------------------------------------

/// A slot that is given back goes to the job that has waited longest,
/// the moment it is given back. The jobs that wait ask nothing in the
/// meantime: a wait costs the one request that began it. A job that
/// comes while others wait finds nothing.
#[tokio::test]
async fn a_slot_given_back_goes_to_the_job_that_waited_longest() {
    let Full {
        w,
        p,
        c,
        first,
        second,
    } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let (a, b) = (
        w.pushing("a", core::slice::from_ref(&p)),
        w.pushing("b", core::slice::from_ref(&p)),
    );
    let mut wait_a = wait(&a, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    w.pass(10);
    let mut wait_b = wait(&b, &on, "job-b", 60_000, &sleep);
    assert_eq!(turn(&mut wait_b), None);
    assert_eq!(w.sessions(), 4);
    let asked = (w.opens.get(), w.msgs.get());

    for _ in 0..20 {
        w.pass(2_000);
        w.hibernate();
        assert_eq!(turn(&mut wait_a), None);
        assert_eq!(turn(&mut wait_b), None);
    }
    assert_eq!((w.opens.get(), w.msgs.get()), asked, "nothing asked");

    // Renewals of the holders are no reason to hand anything out.
    assert!(c.renew_permit(&first, w.now()).await.unwrap());
    assert!(c.renew_permit(&second, w.now()).await.unwrap());
    assert_eq!(turn(&mut wait_a), None);
    c.release_permit(&second).await.unwrap();
    assert_eq!(turn(&mut wait_a), Some(SlotWait::Granted));
    assert_eq!(turn(&mut wait_b), None);
    assert_eq!(w.held("p").await, 2, "handed on, never free");

    // The job that came after both finds nothing, though a slot was
    // free for an instant.
    let late = w.pushing("late", core::slice::from_ref(&p));
    assert!(take(&late, &w, &p, JOB, "job-late").await.is_none());
    // The slot is the waiter's own at its next question.
    let got = take(&a, &w, &p, JOB, "job-a").await.unwrap();
    assert_eq!(got.slot, second.slot);
    assert!(got.token > second.token);
    assert!(a.renew_permit(&got, w.now()).await.unwrap());

    c.release_permit(&first).await.unwrap();
    assert_eq!(turn(&mut wait_b), Some(SlotWait::Granted));
    let got = take(&b, &w, &p, JOB, "job-b").await.unwrap();
    assert_eq!(got.slot, first.slot);
    assert_eq!(w.pushed.get(), 2);
}

/// A slot whose holder stopped renewing runs out with no word to the
/// gate. Whoever asks next makes the gate look: the slot goes to the
/// job that waits, not to the one that asked.
#[tokio::test]
async fn a_slot_that_ran_out_goes_to_the_line_before_who_asks() {
    let Full {
        w, p, c, second, ..
    } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let a = w.pushing("a", core::slice::from_ref(&p));
    let mut wait_a = wait(&a, &on, "job-a", 150_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    // job-2 renews, job-1 does not.
    w.pass(60_000);
    assert!(c.renew_permit(&second, w.now()).await.unwrap());
    w.pass(JOB_MS - 61_000);
    assert_eq!(turn(&mut wait_a), None, "the slot lives to its last ms");
    w.pass(1);

    let late = w.pushing("late", core::slice::from_ref(&p));
    assert!(take(&late, &w, &p, JOB, "job-late").await.is_none());
    assert_eq!(turn(&mut wait_a), Some(SlotWait::Granted));
    assert!(take(&a, &w, &p, JOB, "job-a").await.is_some());
}

/// The same with nobody else at the gate, which has left memory: the
/// job that waits asks once, when the gate told it the first slot can
/// run out, and gets it with that question.
#[tokio::test]
async fn a_slot_that_ran_out_is_found_with_one_question() {
    let Full { w, p, .. } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let a = w.pushing("a", core::slice::from_ref(&p));
    let mut wait_a = wait(&a, &on, "job-a", 150_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    let asked = (w.opens.get(), w.msgs.get());
    w.hibernate();
    // Both slots were taken 1 s before the wait began.
    w.pass(JOB_MS - 1_000);
    assert_eq!(turn(&mut wait_a), None);
    assert_eq!((w.opens.get(), w.msgs.get()), asked);
    w.pass(1);
    assert_eq!(turn(&mut wait_a), Some(SlotWait::Granted));
    assert_eq!((w.opens.get(), w.msgs.get()), (asked.0, asked.1 + 1));
    assert!(take(&a, &w, &p, JOB, "job-a").await.is_some());
}

/// Jobs that wait for different providers do not wait for each other,
/// and a job takes the first of its providers that has a slot.
#[tokio::test]
async fn a_job_waits_only_for_the_providers_it_can_use() {
    let w = World::new();
    let (p, q) = (provider("p", 2), provider("q", 2));
    let all = [p.clone(), q.clone()];
    let c = w.pushing("holders", &all);
    let on_p = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    let on_q = take(&c, &w, &q, JOB, "job-2").await.unwrap();
    let sleep = w.sleeper();
    let (a, b, d) = (
        w.pushing("a", &all),
        w.pushing("b", &all),
        w.pushing("d", &all),
    );
    let (only_p, only_q, both) = ([&p], [&q], [&p, &q]);
    let mut wait_a = wait(&a, &only_p, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    let mut wait_b = wait(&b, &both, "job-b", 60_000, &sleep);
    assert_eq!(turn(&mut wait_b), None);
    let mut wait_d = wait(&d, &only_q, "job-d", 60_000, &sleep);
    assert_eq!(turn(&mut wait_d), None);

    // `q` frees: the first in the line cannot use it, the second can.
    c.release_permit(&on_q).await.unwrap();
    assert_eq!(turn(&mut wait_a), None);
    assert_eq!(turn(&mut wait_b), Some(SlotWait::Granted));
    assert_eq!(turn(&mut wait_d), None);
    assert!(take(&b, &w, &p, JOB, "job-b").await.is_none());
    let got = take(&b, &w, &q, JOB, "job-b").await.unwrap();
    c.release_permit(&on_p).await.unwrap();
    assert_eq!(turn(&mut wait_a), Some(SlotWait::Granted));
    b.release_permit(&got).await.unwrap();
    assert_eq!(turn(&mut wait_d), Some(SlotWait::Granted));
    assert_eq!((w.held("p").await, w.held("q").await), (1, 1));
}

/// A job that is handed a slot from the line and then finds one on
/// another provider first does not keep the one it never used: it goes
/// back with the slot the job gives back, in the same request.
#[tokio::test]
async fn a_slot_from_the_line_that_was_never_used_goes_back_with_the_next() {
    let w = World::new();
    let (p, q) = (provider("p", 2), provider("q", 2));
    let all = [p.clone(), q.clone()];
    let c = w.pushing("holders", &all);
    let on_p = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    let on_q = take(&c, &w, &q, JOB, "job-2").await.unwrap();
    let (sleep, b, both) = (w.sleeper(), w.pushing("b", &all), [&p, &q]);
    let mut waiting = wait(&b, &both, "job-b", 60_000, &sleep);
    assert_eq!(turn(&mut waiting), None);
    c.release_permit(&on_q).await.unwrap();
    assert_eq!(turn(&mut waiting), Some(SlotWait::Granted));
    drop(waiting);
    c.release_permit(&on_p).await.unwrap();

    // It asks `p` first, which is free by now, and works there.
    let got = take(&b, &w, &p, JOB, "job-b").await.unwrap();
    assert_eq!((w.held("p").await, w.held("q").await), (1, 1));
    let before = w.opens.get() + w.msgs.get();
    b.release_permit(&got).await.unwrap();
    assert_eq!(w.opens.get() + w.msgs.get(), before + 1, "one request");
    assert_eq!((w.held("p").await, w.held("q").await), (0, 0));
    // The slot on `q` is another job's at once.
    assert!(take(&c, &w, &q, JOB, "job-3").await.is_some());
}

// ---------------------------------------------------------------------------
// Holders and waiters that die
// ---------------------------------------------------------------------------

/// A holder whose invocation dies with a slot in hand gives nothing
/// back itself. Its session ends with it: the slot goes to the line at
/// once, with the object in memory or not.
#[tokio::test]
async fn the_slot_of_a_holder_that_died_goes_to_the_line() {
    for asleep in [false, true] {
        let w = World::new();
        let p = provider("p", 3);
        let (c1, c2) = (
            w.pushing("one", core::slice::from_ref(&p)),
            w.pushing("two", core::slice::from_ref(&p)),
        );
        take(&c1, &w, &p, JOB, "job-1").await.unwrap();
        take(&c2, &w, &p, JOB, "job-2").await.unwrap();
        let (sleep, on) = (w.sleeper(), [&p]);
        let a = w.pushing("a", core::slice::from_ref(&p));
        let mut wait_a = wait(&a, &on, "job-a", 60_000, &sleep);
        assert_eq!(turn(&mut wait_a), None);
        w.pass(3_000);
        if asleep {
            w.hibernate();
        }

        w.end("one").await;

        assert_eq!(turn(&mut wait_a), Some(SlotWait::Granted));
        assert_eq!(w.held("p").await, 2);
        assert!(take(&a, &w, &p, JOB, "job-a").await.is_some());
        assert_eq!(w.msgs.get(), 1, "the renewal of the slot it took");
    }
}

/// A job that dies while it waits is out of the line when its session
/// ends, and one that died unheard of is found out when its slot is
/// sent: the slot goes to the next in the line, and none is lost.
#[tokio::test]
async fn a_waiter_that_died_does_not_keep_the_slot_from_the_next() {
    for heard in [true, false] {
        let Full {
            w, p, c, second, ..
        } = full().await;
        let (sleep, on) = (w.sleeper(), [&p]);
        let (a, b) = (
            w.pushing("a", core::slice::from_ref(&p)),
            w.pushing("b", core::slice::from_ref(&p)),
        );
        let mut wait_a = wait(&a, &on, "job-a", 60_000, &sleep);
        assert_eq!(turn(&mut wait_a), None);
        let mut wait_b = wait(&b, &on, "job-b", 60_000, &sleep);
        assert_eq!(turn(&mut wait_b), None);

        match heard {
            true => w.end("a").await,
            false => w.vanish("a"),
        }
        c.release_permit(&second).await.unwrap();

        assert_eq!(turn(&mut wait_b), Some(SlotWait::Granted));
        assert_eq!(w.held("p").await, 2);
        // The dead job's wait ends with its session, and holds nothing.
        assert_eq!(turn(&mut wait_a), Some(SlotWait::Unsupported));
        assert_eq!(w.sessions(), 2);
    }
}

/// A job that was handed a slot and died before it used it holds it no
/// longer than its session lives.
#[tokio::test]
async fn a_slot_handed_to_a_job_that_then_died_comes_back() {
    let Full {
        w, p, c, second, ..
    } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let (a, b) = (
        w.pushing("a", core::slice::from_ref(&p)),
        w.pushing("b", core::slice::from_ref(&p)),
    );
    let mut wait_a = wait(&a, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    let mut wait_b = wait(&b, &on, "job-b", 60_000, &sleep);
    assert_eq!(turn(&mut wait_b), None);
    c.release_permit(&second).await.unwrap();
    assert_eq!(turn(&mut wait_a), Some(SlotWait::Granted));

    w.end("a").await;

    assert_eq!(turn(&mut wait_b), Some(SlotWait::Granted));
    assert_eq!(w.held("p").await, 2);
}

/// The time a job may wait runs out: it is told so, its session ends,
/// and nothing is held for it. A slot that frees afterwards is free.
/// The same for a wait that is dropped (its job was abandoned).
#[tokio::test]
async fn a_wait_that_ran_out_or_was_dropped_holds_nothing() {
    for dropped in [false, true] {
        let Full {
            w, p, c, second, ..
        } = full().await;
        let (sleep, on) = (w.sleeper(), [&p]);
        let a = w.pushing("a", core::slice::from_ref(&p));
        let mut wait_a = wait(&a, &on, "job-a", 5_000, &sleep);
        assert_eq!(turn(&mut wait_a), None);
        w.pass(4_999);
        assert_eq!(turn(&mut wait_a), None);
        match dropped {
            true => drop(wait_a),
            false => {
                w.pass(1);
                assert_eq!(turn(&mut wait_a), Some(SlotWait::Elapsed));
            }
        }
        assert_eq!(w.sessions(), 2, "its session is closed");

        c.release_permit(&second).await.unwrap();
        assert_eq!(w.pushed.get(), 0);
        assert_eq!(w.held("p").await, 1);
        assert!(take(&a, &w, &p, JOB, "job-a").await.is_some());
    }
}

/// A slot that is sent in the instant the wait runs out is either the
/// job's, or free again: never held by a job that was told it has
/// none.
#[tokio::test]
async fn a_slot_sent_as_the_wait_runs_out_is_not_lost() {
    let Full {
        w, p, c, second, ..
    } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let a = w.pushing("a", core::slice::from_ref(&p));
    let mut wait_a = wait(&a, &on, "job-a", 5_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    w.pass(5_000);
    c.release_permit(&second).await.unwrap();
    assert_eq!(w.pushed.get(), 1);

    match turn(&mut wait_a).unwrap() {
        SlotWait::Granted => {
            assert_eq!(w.held("p").await, 2);
            assert!(take(&a, &w, &p, JOB, "job-a").await.is_some());
        }
        SlotWait::Elapsed => assert_eq!(w.held("p").await, 1),
        SlotWait::Unsupported => panic!("the gate keeps a line"),
    }
}

// ---------------------------------------------------------------------------
// The object leaves memory, or restarts
// ---------------------------------------------------------------------------

/// The line outlives the object's memory with the sessions of the jobs
/// in it, in its order, and with nothing written for it.
#[tokio::test]
async fn the_line_outlives_the_memory_in_its_order() {
    let Full {
        w,
        p,
        c,
        first,
        second,
    } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let saves = w.store.saves.get();
    let workers: Vec<SqlCatalog<Db>> = (0..4)
        .map(|i| w.pushing(&format!("w{i}"), core::slice::from_ref(&p)))
        .collect();
    let names: Vec<String> = (0..4).map(|i| format!("job-w{i}")).collect();
    let mut waits = Vec::new();
    for (worker, name) in workers.iter().zip(&names) {
        w.hibernate();
        let mut waiting = wait(worker, &on, name, 100_000, &sleep);
        assert_eq!(turn(&mut waiting), None);
        waits.push(waiting);
        w.pass(700);
    }

    // Each slot is given back by who holds it: the two holders
    // first, then the jobs that were served, in their order.
    let mut freed: Vec<(Option<usize>, Permit)> = vec![(None, second), (None, first)];
    for served in 0..4 {
        w.hibernate();
        w.pass(900);
        let (holder, permit) = freed.remove(0);
        match holder {
            Some(i) => workers[i].release_permit(&permit).await.unwrap(),
            None => c.release_permit(&permit).await.unwrap(),
        }
        let out: Vec<Option<SlotWait>> = waits[served..].iter_mut().map(turn).collect();
        let mut expected = vec![None; 4 - served];
        expected[0] = Some(SlotWait::Granted);
        assert_eq!(out, expected, "after {served} were served");
        w.hibernate();
        let got = take(&workers[served], &w, &p, JOB, &names[served]).await;
        freed.push((Some(served), got.unwrap()));
        // The holders work on, and renew.
        w.pass(5_000);
        for (holder, permit) in &freed {
            let by = holder.map_or(&c, |i| &workers[i]);
            assert!(by.renew_permit(permit, w.now()).await.unwrap());
        }
    }
    assert_eq!(w.store.saves.get(), saves, "no write for any of it");
    assert_eq!(w.held("p").await, 2);
}

/// New code that cuts every session ends the line: each job in it is
/// told that nothing waits for it, holds nothing, and asks again as a
/// job does where there is no line.
#[tokio::test]
async fn a_restart_ends_the_line_and_the_jobs_ask_again() {
    let Full { w, p, .. } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let a = w.pushing("a", core::slice::from_ref(&p));
    let mut wait_a = wait(&a, &on, "job-a", 100_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);

    w.restart();

    assert_eq!(turn(&mut wait_a), Some(SlotWait::Unsupported));
    assert_eq!(w.sessions(), 0);
    // The new object waits out the slots of the old one, and a job
    // that waits in its line is served when that is over: with one
    // question, at the time the gate named.
    w.pass(1);
    let mut again = wait(&a, &on, "job-a", 300_000, &sleep);
    assert_eq!(turn(&mut again), None);
    let asked = (w.opens.get(), w.msgs.get());
    let mut waited = 0;
    while turn(&mut again).is_none() {
        w.pass(1_000);
        waited += 1_000;
        assert!(waited <= JOB_MS + SKEW_MS + 1_000, "{waited}");
    }
    assert!(waited >= JOB_MS - 1_000, "{waited}");
    assert_eq!((w.opens.get(), w.msgs.get()), (asked.0, asked.1 + 1));
    assert!(take(&a, &w, &p, JOB, "job-a").await.is_some());
}

/// After a restart no job gets a slot while a read of the old object
/// may still hold one, which can be later than the last of its jobs.
/// The job in the line is told that time, not the earlier one: it asks
/// once, then, and is served.
#[tokio::test]
async fn a_job_waits_out_the_reads_of_the_old_object_with_one_question() {
    let w = World::new();
    let p = provider("p", 3);
    let c = w.pushing("c", core::slice::from_ref(&p));
    let (sleep, on) = (w.sleeper(), [&p]);
    // The horizon stored for jobs ends 5 s after the restart below;
    // the one for reads was stored just before it.
    let job = take(&c, &w, &p, JOB, "job-0").await.unwrap();
    c.release_permit(&job).await.unwrap();
    w.pass(JOB_MS + HORIZON_STEP_MS - 5_000);
    let read = take(&c, &w, &p, READ, "read-0").await.unwrap();
    c.release_permit(&read).await.unwrap();

    w.restart();
    w.pass(1);

    let read_ms = i64::from(READ_PERMIT_SECS) * 1000;
    let a = w.pushing("a", core::slice::from_ref(&p));
    let mut wait_a = wait(&a, &on, "job-a", 300_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    let asked = (w.opens.get(), w.msgs.get());
    let mut waited = 0;
    while turn(&mut wait_a).is_none() {
        w.pass(1_000);
        waited += 1_000;
        assert!(waited <= read_ms + SKEW_MS + 1_000, "{waited}");
    }
    assert!(waited >= read_ms - 1_000, "{waited}");
    assert_eq!((w.opens.get(), w.msgs.get()), (asked.0, asked.1 + 1));
    assert!(take(&a, &w, &p, JOB, "job-a").await.is_some());
}

// ---------------------------------------------------------------------------
// A slot that came and was not taken
// ---------------------------------------------------------------------------

/// A job that was handed a slot and stops before it takes it (the
/// catalogue failed, or its provider began to cool) gives it up when
/// it stops: the next in the line has it then, not when it runs out.
#[tokio::test]
async fn a_slot_a_job_did_not_take_goes_to_the_next_when_the_job_stops() {
    let Full {
        w, p, c, second, ..
    } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let (a, b) = (
        w.pushing("a", core::slice::from_ref(&p)),
        w.pushing("b", core::slice::from_ref(&p)),
    );
    let mut wait_a = wait(&a, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    let mut wait_b = wait(&b, &on, "job-b", 60_000, &sleep);
    assert_eq!(turn(&mut wait_b), None);
    c.release_permit(&second).await.unwrap();
    assert_eq!(turn(&mut wait_a), Some(SlotWait::Granted));
    assert_eq!(turn(&mut wait_b), None);
    let sessions = w.sessions();

    // Another job's stop changes nothing.
    a.leave_line("job-b");
    assert_eq!(w.sessions(), sessions);
    a.leave_line("job-a");
    assert_eq!(w.sessions(), sessions - 1);
    w.hear().await;

    assert_eq!(turn(&mut wait_b), Some(SlotWait::Granted));
    assert!(take(&a, &w, &p, JOB, "job-a").await.is_none());
    assert!(take(&b, &w, &p, JOB, "job-b").await.is_some());
    assert_eq!(w.held("p").await, 2);
}

// ---------------------------------------------------------------------------
// Gates of two accounts
// ---------------------------------------------------------------------------

/// A job that can use two accounts stands in the line of each gate,
/// takes the first slot that comes, and leaves the other line: a slot
/// that comes free there later is not held for it.
#[tokio::test]
async fn a_job_in_the_lines_of_two_gates_takes_the_first_slot_and_leaves_the_other() {
    let two = Two::new().await;
    let (wp, wq) = (&two.p.1, &two.q.1);
    let (sleep, both) = (wp.sleeper(), two.both());
    let on = [&both[0], &both[1]];
    let a = Two::client(wp, wq, "a", &both);
    let before = (wp.sessions(), wq.sessions());
    let mut wait_a = wait(&a, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    assert_eq!((wp.sessions(), wq.sessions()), (before.0 + 1, before.1 + 1));

    two.c.release_permit(&two.held[1]).await.unwrap();
    assert_eq!(turn(&mut wait_a), Some(SlotWait::Granted));
    assert_eq!(wp.sessions(), before.0, "out of the other line");
    assert_eq!((wp.held("p").await, wq.held("q").await), (1, 1));

    two.c.release_permit(&two.held[0]).await.unwrap();
    assert_eq!((wp.held("p").await, wq.held("q").await), (0, 1));
    assert!(take(&a, wq, &both[1], JOB, "job-a").await.is_some());
    assert_eq!((wp.pushed.get(), wq.pushed.get()), (0, 1));
}

/// One of the two gates keeps no line (it runs code from before it):
/// the job leaves the line of the other and asks both as before.
#[tokio::test]
async fn a_gate_without_a_line_ends_the_wait_at_the_other_gate_too() {
    let two = Two::new().await;
    let (wp, wq) = (&two.p.1, &two.q.1);
    let (sleep, both) = (wp.sleeper(), two.both());
    let on = [&both[0], &both[1]];
    let a = Two::client(wp, wq, "a", &both);
    let before = (wp.sessions(), wq.sessions());
    wq.old_code.set(true);

    let mut wait_a = wait(&a, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut wait_a), Some(SlotWait::Unsupported));
    assert_eq!((wp.sessions(), wq.sessions()), before);
    // Nothing waits at the gate that has a line: its slot, freed, is
    // there for who asks.
    two.c.release_permit(&two.held[0]).await.unwrap();
    assert_eq!(wp.held("p").await, 0);
    assert!(take(&a, wp, &both[0], JOB, "job-a").await.is_some());
}

// ---------------------------------------------------------------------------
// Duplicate delivery
// ---------------------------------------------------------------------------

/// One job delivered twice runs in two invocations under one name.
/// Each has a place of its own in the line and its own session: a slot
/// is handed to one of them, never the same slot to both, and the end
/// of one changes nothing for the other.
#[tokio::test]
async fn a_job_delivered_twice_is_never_handed_one_slot_twice() {
    let Full {
        w,
        p,
        c,
        first,
        second,
    } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let (one, two) = (
        w.pushing("one", core::slice::from_ref(&p)),
        w.pushing("two", core::slice::from_ref(&p)),
    );
    let name = "job:x_1:post:7";
    let mut wait_one = wait(&one, &on, name, 60_000, &sleep);
    assert_eq!(turn(&mut wait_one), None);
    let mut wait_two = wait(&two, &on, name, 60_000, &sleep);
    assert_eq!(turn(&mut wait_two), None);

    c.release_permit(&second).await.unwrap();
    assert_eq!(turn(&mut wait_one), Some(SlotWait::Granted));
    assert_eq!(turn(&mut wait_two), None);
    assert_eq!(w.held("p").await, 2);
    // A third delivery has no slot: the first one's is not its own.
    let three = w.pushing("three", core::slice::from_ref(&p));
    assert!(take(&three, &w, &p, JOB, name).await.is_none());
    let got = take(&one, &w, &p, JOB, name).await.unwrap();

    c.release_permit(&first).await.unwrap();
    assert_eq!(turn(&mut wait_two), Some(SlotWait::Granted));
    let other = take(&two, &w, &p, JOB, name).await.unwrap();
    assert_ne!((got.slot, got.token), (other.slot, other.token));
    w.end("one").await;
    assert!(two.renew_permit(&other, w.now()).await.unwrap());
    assert_eq!(w.held("p").await, 1);
}

/// The same in one isolate, where both invocations ask through one
/// client: the second finds the name in the line and asks as a job
/// does where there is none. The slot that comes is taken once.
#[tokio::test]
async fn a_job_delivered_twice_in_one_isolate_is_handed_a_slot_once() {
    let Full {
        w, p, c, second, ..
    } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let both = w.pushing("isolate", core::slice::from_ref(&p));
    let name = "job:x_1:post:7";
    let mut wait_one = wait(&both, &on, name, 60_000, &sleep);
    assert_eq!(turn(&mut wait_one), None);
    let mut wait_two = wait(&both, &on, name, 60_000, &sleep);
    assert_eq!(turn(&mut wait_two), None);
    assert_eq!(w.sessions(), 3, "one place in the line");

    c.release_permit(&second).await.unwrap();
    assert_eq!(turn(&mut wait_one), Some(SlotWait::Granted));
    assert_eq!(turn(&mut wait_two), Some(SlotWait::Unsupported));
    assert_eq!(w.held("p").await, 2);
    let got = take(&both, &w, &p, JOB, name).await.unwrap();
    assert!(take(&both, &w, &p, JOB, name).await.is_none());
    both.release_permit(&got).await.unwrap();
    assert_eq!(w.held("p").await, 1);
}

/// A request to wait that reaches the gate twice on one session keeps
/// the session's place, and the slot is sent once, under the id of the
/// request that asked last. A request with no question (the waiter
/// asking the gate to look) changes nothing while nothing is free.
#[tokio::test]
async fn a_request_to_wait_that_is_repeated_keeps_its_place() {
    let w = World::new();
    let p = provider("p", 2);
    let gate = w.gate().await;
    let request = |id: u64, op: GateOp| GateRequest {
        id,
        gate: GATE.into(),
        ops: vec![op],
    };
    let waits = |holder: &str| GateOp::Wait {
        wants: vec![GateWant {
            provider: GateProvider::from(&p),
            peers: Vec::new(),
        }],
        holder: holder.into(),
        ms: 60_000,
    };
    let mut open = Vec::new();
    for _ in 0..3 {
        open.push(gate.open(w.now()).await.unwrap());
    }
    let (holder, a, b) = (open[0], open[1], open[2]);
    // With a free slot the request to wait takes it and nothing waits.
    let reply = gate.handle(Some(holder), request(1, waits("job-1")), w.now());
    let reply = reply.await.unwrap();
    assert!(!reply.waiting && reply.wake.is_none());
    let Some(GateAnswer::Acquired(Some(slot))) = reply.answers.first().cloned() else {
        panic!("no slot: {reply:?}");
    };

    w.pass(1_000);
    let reply = gate.handle(Some(a), request(11, waits("job-a")), w.now());
    let reply = reply.await.unwrap();
    assert_eq!(reply.answers, [GateAnswer::Acquired(None)]);
    assert!(reply.waiting);
    assert_eq!(
        reply.wake,
        Some(JOB_MS - 1_000 + 1),
        "when the slot runs out"
    );
    let reply = gate.handle(Some(b), request(12, waits("job-b")), w.now());
    assert!(reply.await.unwrap().waiting);
    w.pass(500);
    let again = gate.handle(Some(a), request(13, waits("job-a")), w.now());
    assert!(again.await.unwrap().waiting);
    let look = GateRequest {
        id: 12,
        gate: GATE.into(),
        ops: Vec::new(),
    };
    let reply = gate.handle(Some(b), look, w.now()).await.unwrap();
    assert!(reply.waiting && reply.answers.is_empty());
    assert!(gate.pushes().is_empty());

    let free = GateOp::Release {
        permits: vec![slot],
    };
    gate.handle(Some(holder), request(2, free), w.now())
        .await
        .unwrap();

    let pushes = gate.pushes();
    assert_eq!(pushes.len(), 1, "{pushes:?}");
    let (session, reply) = &pushes[0];
    assert_eq!((*session, reply.id), (a, 13));
    assert!(matches!(reply.answers[..], [GateAnswer::Acquired(Some(_))]));
    assert!(!reply.waiting);
    // The slot is kept with the session that got it.
    assert_eq!(gate.session(a, w.now()).held.len(), 1);
    assert!(gate.session(a, w.now()).wait.is_none());
    assert!(gate.session(b, w.now()).wait.is_some());
    // The other waits on, and is served with its own question when
    // the slot ends with its session.
    gate.close(a);
    let look = GateRequest {
        id: 12,
        gate: GATE.into(),
        ops: Vec::new(),
    };
    let reply = gate.handle(Some(b), look, w.now()).await.unwrap();
    assert!(matches!(reply.answers[..], [GateAnswer::Acquired(Some(_))]));
    assert!(gate.pushes().is_empty(), "sent as the reply, once");
}

/// What a request gives back goes to the line before a later question
/// of the same request can take it, and a session that is past the
/// time it asked to wait for is handed nothing, open or not.
#[tokio::test]
async fn a_request_cannot_take_back_what_it_gave_and_a_late_waiter_gets_nothing() {
    let w = World::new();
    let p = provider("p", 2);
    let gate = w.gate().await;
    let request = |id: u64, ops: Vec<GateOp>| GateRequest {
        id,
        gate: GATE.into(),
        ops,
    };
    let want = || GateWant {
        provider: GateProvider::from(&p),
        peers: Vec::new(),
    };
    let waits = |holder: &str, ms: i64| GateOp::Wait {
        wants: vec![want()],
        holder: holder.into(),
        ms,
    };
    let takes = |holder: &str| GateOp::Acquire {
        provider: want().provider,
        peers: Vec::new(),
        background: true,
        holder: holder.into(),
    };
    let mut open = Vec::new();
    for _ in 0..3 {
        open.push(gate.open(w.now()).await.unwrap());
    }
    let (holder, late, b) = (open[0], open[1], open[2]);
    let reply = gate.handle(Some(holder), request(1, vec![takes("job-1")]), w.now());
    let Some(GateAnswer::Acquired(Some(slot))) = reply.await.unwrap().answers.first().cloned()
    else {
        panic!("no slot");
    };
    // The first in the line asked for 5 s and is still there after 6.
    let reply = gate.handle(
        Some(late),
        request(11, vec![waits("job-late", 5_000)]),
        w.now(),
    );
    assert!(reply.await.unwrap().waiting);
    let reply = gate.handle(Some(b), request(12, vec![waits("job-b", 60_000)]), w.now());
    assert!(reply.await.unwrap().waiting);
    w.pass(6_000);

    let free = GateOp::Release {
        permits: vec![slot],
    };
    let both = request(2, vec![free, takes("job-1")]);
    let reply = gate.handle(Some(holder), both, w.now()).await.unwrap();
    assert_eq!(
        reply.answers,
        [GateAnswer::Released, GateAnswer::Acquired(None)],
        "the slot went to the line"
    );
    let pushes = gate.pushes();
    assert_eq!(pushes.len(), 1, "{pushes:?}");
    assert_eq!((pushes[0].0, pushes[0].1.id), (b, 12));
    assert!(gate.session(late, w.now()).held.is_empty());
}

/// A request takes the last job slot and then fails at a later
/// question, and a job came to wait for that slot while the request
/// was still being answered. The slot the failed request never learned
/// of goes to that job at once, not when it next asks.
#[tokio::test]
async fn a_slot_undone_by_a_failed_request_goes_to_who_came_meanwhile() {
    let w = World::new();
    let (p, q) = (provider("p", 2), provider("q", 2));
    let gate = w.gate().await;
    let request = |id: u64, ops: Vec<GateOp>| GateRequest {
        id,
        gate: GATE.into(),
        ops,
    };
    let takes = |p: &ProviderConfig| GateOp::Acquire {
        provider: GateProvider::from(p),
        peers: Vec::new(),
        background: true,
        holder: "job-1".into(),
    };
    let (first, second) = (
        gate.open(w.now()).await.unwrap(),
        gate.open(w.now()).await.unwrap(),
    );
    // The gate is in charge of `p` already, and of `q` not yet: it
    // asks the catalogue for the rows of `q`, and that call fails.
    let reply = gate.handle(Some(first), request(1, vec![takes(&p)]), w.now());
    let Some(GateAnswer::Acquired(Some(slot))) = reply.await.unwrap().answers.first().cloned()
    else {
        panic!("no slot");
    };
    let free = GateOp::Release {
        permits: vec![slot],
    };
    let reply = gate.handle(Some(first), request(2, vec![free]), w.now());
    reply.await.unwrap();
    w.db.1.set(true);

    let both = request(3, vec![takes(&p), takes(&q)]);
    let mut failing = Box::pin(gate.handle(Some(first), both, w.now()));
    let waker = futures_util::task::noop_waker();
    let mut cx = core::task::Context::from_waker(&waker);
    assert!(failing.as_mut().poll(&mut cx).is_pending());
    assert_eq!(gate.session(first, w.now()).held.len(), 1);
    let waits = GateOp::Wait {
        wants: vec![GateWant {
            provider: GateProvider::from(&p),
            peers: Vec::new(),
        }],
        holder: "job-2".into(),
        ms: 60_000,
    };
    let reply = gate.handle(Some(second), request(21, vec![waits]), w.now());
    assert!(reply.await.unwrap().waiting);

    let Poll::Ready(failed) = failing.as_mut().poll(&mut cx) else {
        panic!("the request did not end");
    };
    assert!(failed.is_err());
    assert!(gate.session(first, w.now()).held.is_empty());
    let pushes = gate.pushes();
    assert_eq!(pushes.len(), 1, "{pushes:?}");
    assert_eq!((pushes[0].0, pushes[0].1.id), (second, 21));
    assert_eq!(gate.session(second, w.now()).held.len(), 1);
}

/// A job that waits says nothing for as long as it waits. Its session
/// is not taken for one whose holder has gone: it keeps its place when
/// the object leaves memory and when silent sessions are closed.
#[tokio::test]
async fn a_job_that_waits_in_silence_is_not_taken_for_gone() {
    let Full {
        w,
        p,
        c,
        first,
        second,
    } = full().await;
    let (sleep, a, on) = (w.sleeper(), w.pushing("a", core::slice::from_ref(&p)), [&p]);
    let mut waiting = wait(&a, &on, "job-a", 110_000, &sleep);
    assert_eq!(turn(&mut waiting), None);
    // The holders renew; the waiter is silent for 100 s, through an
    // object that left memory and through the closing of the silent.
    for _ in 0..4 {
        w.pass(25_000);
        w.hibernate();
        for held in [&first, &second] {
            assert!(c.renew_permit(held, w.now()).await.unwrap());
        }
        assert_eq!(turn(&mut waiting), None);
    }
    c.release_permit(&first).await.unwrap();
    assert_eq!(turn(&mut waiting), Some(SlotWait::Granted));
    assert!(take(&a, &w, &p, JOB, "job-a").await.is_some());
}

// ---------------------------------------------------------------------------
// Reads, and the kinds of job
// ---------------------------------------------------------------------------

/// Reads never stand in the line and never wait for it: the slot kept
/// for them is theirs however many jobs wait, and no job in the line
/// is handed it.
#[tokio::test]
async fn a_read_gets_its_slot_while_jobs_wait() {
    let Full { w, p, .. } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let workers: Vec<SqlCatalog<Db>> = (0..3)
        .map(|i| w.pushing(&format!("w{i}"), core::slice::from_ref(&p)))
        .collect();
    let names = ["job:x:post:1", "job:y:verify:2", "job:z:release:3"];
    let mut waits = Vec::new();
    for (worker, name) in workers.iter().zip(names) {
        let mut waiting = wait(worker, &on, name, 100_000, &sleep);
        assert_eq!(turn(&mut waiting), None);
        waits.push(waiting);
    }
    let reader = w.pushing("reader", core::slice::from_ref(&p));
    for i in 0..30 {
        w.pass(1_000);
        let name = format!("read-{i}");
        let read = take(&reader, &w, &p, READ, &name).await;
        let read = read.expect("the slot kept for reads");
        assert_eq!(w.held("p").await, 3);
        assert!(take(&reader, &w, &p, READ, "read-x").await.is_none());
        reader.release_permit(&read).await.unwrap();
        // The slot a read gave back is not a job's.
        assert!(waits.iter_mut().all(|f| turn(f).is_none()));
        assert_eq!(w.held("p").await, 2);
    }
    assert_eq!(w.pushed.get(), 0);
}

/// Post, verify and release jobs stand in one line: none is served
/// before a job of another kind that came first.
#[tokio::test]
async fn jobs_of_every_kind_are_served_in_the_order_they_came() {
    let Full {
        w,
        p,
        c,
        first,
        second,
    } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let names = [
        "job:a:release:1",
        "job:b:post:2",
        "job:c:verify:3",
        "job:d:post:4",
        "job:e:release:5",
        "job:f:verify:6",
    ];
    let workers: Vec<SqlCatalog<Db>> = names
        .iter()
        .map(|name| w.pushing(name, core::slice::from_ref(&p)))
        .collect();
    let mut waits = Vec::new();
    for (worker, name) in workers.iter().zip(names) {
        let mut waiting = wait(worker, &on, name, 100_000, &sleep);
        assert_eq!(turn(&mut waiting), None);
        waits.push(waiting);
        w.pass(100);
    }
    let mut served = Vec::new();
    let mut free = vec![(None, first), (None, second)];
    while served.len() < names.len() {
        let (holder, permit) = free.remove(0);
        match holder {
            Some(i) => workers[i as usize].release_permit(&permit).await.unwrap(),
            None => c.release_permit(&permit).await.unwrap(),
        }
        for (i, waiting) in waits.iter_mut().enumerate() {
            if served.contains(&i) || turn(waiting) != Some(SlotWait::Granted) {
                continue;
            }
            served.push(i);
            let got = take(&workers[i], &w, &p, JOB, names[i]).await.unwrap();
            free.push((Some(i as u32), got));
            *waiting = Box::pin(async { Ok(SlotWait::Elapsed) });
        }
        w.pass(1_500);
    }
    assert_eq!(served, [0, 1, 2, 3, 4, 5]);
}

// ---------------------------------------------------------------------------
// The slot that came
// ---------------------------------------------------------------------------

/// The slot that came from the line is renewed when its job takes it:
/// from then it lives as long as one it had just asked for. One that
/// was left for a slot's lifetime is given up, and the job asks as if
/// it had never waited.
#[tokio::test]
async fn a_slot_from_the_line_is_renewed_when_it_is_taken() {
    let Full {
        w, p, c, second, ..
    } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let a = w.pushing("a", core::slice::from_ref(&p));
    let mut wait_a = wait(&a, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    c.release_permit(&second).await.unwrap();
    assert_eq!(turn(&mut wait_a), Some(SlotWait::Granted));

    w.pass(100_000);
    let got = take(&a, &w, &p, JOB, "job-a").await.unwrap();
    w.pass(100_000);
    assert!(a.renew_permit(&got, w.now()).await.unwrap(), "renewed then");
    a.release_permit(&got).await.unwrap();

    // Another wait, and the slot is never asked for.
    let b = w.pushing("b", core::slice::from_ref(&p));
    let mut held = take(&b, &w, &p, JOB, "job-b").await.unwrap();
    while let Some(more) = take(&b, &w, &p, JOB, "job-b").await {
        held = more;
    }
    let mut wait_a = wait(&a, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    b.release_permit(&held).await.unwrap();
    assert_eq!(turn(&mut wait_a), Some(SlotWait::Granted));
    w.pass(JOB_MS + 1);
    let fresh = take(&a, &w, &p, JOB, "job-a").await.unwrap();
    assert!(fresh.token > held.token + 1, "a slot of its own asking");
    assert!(a.renew_permit(&fresh, w.now()).await.unwrap());
}

/// A slot from the line whose renewal the gate could not answer is
/// given up at once: it is in no pocket any more, and nothing else
/// would give it back before it runs out.
#[tokio::test]
async fn a_slot_from_the_line_that_could_not_be_renewed_is_given_up() {
    let w = World::new();
    let p = provider("p", 3);
    let c = w.pushing("holders", core::slice::from_ref(&p));
    let first = take(&c, &w, &p, JOB, "job-1").await.unwrap();
    let second = take(&c, &w, &p, JOB, "job-2").await.unwrap();
    // To where the stored horizon of the job slots ends: the next
    // renewal has to store a later one.
    for _ in 0..5 {
        w.pass(100_000);
        assert!(c.renew_permit(&first, w.now()).await.unwrap());
        assert!(c.renew_permit(&second, w.now()).await.unwrap());
    }
    let (sleep, on) = (w.sleeper(), [&p]);
    let a = w.pushing("a", core::slice::from_ref(&p));
    let mut wait_a = wait(&a, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    c.release_permit(&second).await.unwrap();
    assert_eq!(turn(&mut wait_a), Some(SlotWait::Granted));
    assert_eq!(w.held("p").await, 2);

    w.pass(101_000);
    let saved = w.store.saves.get();
    w.store.down.set(true);
    let asked = a.acquire_permit(&p, JOB, "job-a", w.now()).await;
    assert!(asked.is_err(), "the gate could not answer: {asked:?}");
    w.store.down.set(false);
    assert_eq!(w.store.saves.get(), saved);
    assert_eq!(w.held("p").await, 1, "the slot is free again");
    assert!(take(&c, &w, &p, JOB, "job-3").await.is_some());
}

/// A slot that came from the line for another holder is not this
/// holder's, and one on another provider is not asked for here.
#[tokio::test]
async fn a_slot_from_the_line_goes_to_its_holder_only() {
    let Full {
        w, p, c, second, ..
    } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let a = w.pushing("a", core::slice::from_ref(&p));
    let mut wait_a = wait(&a, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut wait_a), None);
    c.release_permit(&second).await.unwrap();
    assert_eq!(turn(&mut wait_a), Some(SlotWait::Granted));

    assert!(take(&a, &w, &p, JOB, "job-other").await.is_none());
    assert!(take(&a, &w, &p, READ, "job-a").await.is_some(), "a read");
    assert_eq!(w.held("p").await, 3);
    assert!(take(&a, &w, &p, JOB, "job-a").await.is_some());
    assert_eq!(w.held("p").await, 3);
}

// ---------------------------------------------------------------------------
// Where no line is kept
// ---------------------------------------------------------------------------

/// With the switch off, with the catalogue's slot rows, and at a gate
/// that runs code from before the line, nothing waits and nothing is
/// held: the job is told at once, and asks again later as it did
/// before. With the switch off and with slot rows no request is made.
#[tokio::test]
async fn where_no_line_is_kept_the_job_is_told_at_once() {
    let Full { w, p, .. } = full().await;
    let (sleep, on) = (w.sleeper(), [&p]);
    let asked = (w.opens.get(), w.msgs.get());
    let off = w.worker("off", PermitMode::Gate, false, core::slice::from_ref(&p));
    let mut waiting = wait(&off, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut waiting), Some(SlotWait::Unsupported));
    let rows = w.worker("rows", PermitMode::Catalog, true, core::slice::from_ref(&p));
    let mut waiting = wait(&rows, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut waiting), Some(SlotWait::Unsupported));
    let plain = SqlCatalog::new(w.db.clone());
    let mut waiting = wait(&plain, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut waiting), Some(SlotWait::Unsupported));
    assert_eq!((w.opens.get(), w.msgs.get()), asked, "nothing asked");

    w.old_code.set(true);
    let a = w.pushing("a", core::slice::from_ref(&p));
    let mut waiting = wait(&a, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut waiting), Some(SlotWait::Unsupported));
    assert_eq!(w.sessions(), 2);
    assert_eq!(w.held("p").await, 2);
    // No time to wait is no wait.
    w.old_code.set(false);
    let mut waiting = wait(&a, &on, "job-a", 0, &sleep);
    assert_eq!(turn(&mut waiting), Some(SlotWait::Unsupported));
    assert_eq!(w.sessions(), 2);
}

/// A wait is kept with the session's connection, where the host keeps
/// a bounded amount, and every account asked is written there with the
/// accounts of its pool. A job that can use eight accounts of one pool
/// waits in the line; with twelve the wait is not begun, nothing is
/// held, and the job asks again as it did before the line.
#[tokio::test]
async fn a_wait_too_large_to_keep_is_not_begun() {
    for (accounts, kept) in [(8, true), (12, false)] {
        let w = World::new();
        let pool: Vec<ProviderConfig> = (0..accounts)
            .map(|i| {
                let mut p = provider(&format!("account-{i}"), 2);
                p.pool = Some("shared".to_string());
                p.pool_max_conns = Some(2);
                p
            })
            .collect();
        let c = w.pushing("holders", &pool);
        let mut held = Vec::new();
        for p in &pool {
            while let Some(permit) = take(&c, &w, p, JOB, "job-1").await {
                held.push(permit);
            }
        }
        assert!(!held.is_empty());
        let (sleep, on) = (w.sleeper(), pool.iter().collect::<Vec<_>>());
        let a = w.pushing("a", &pool);
        let open = w.sessions();
        let mut waiting = wait(&a, &on, "job-a", 60_000, &sleep);
        match kept {
            true => {
                assert_eq!(turn(&mut waiting), None, "{accounts} accounts");
                assert_eq!(w.sessions(), open + 1);
                c.release_permit(&held[0]).await.unwrap();
                assert_eq!(turn(&mut waiting), Some(SlotWait::Granted));
            }
            false => {
                assert_eq!(turn(&mut waiting), Some(SlotWait::Unsupported));
                assert_eq!(w.sessions(), open, "{accounts} accounts");
            }
        }
    }
}

/// A gate that is not in charge of an account (a Worker on slot rows
/// holds one of its rows) keeps no line for it: the job asks the old
/// way, where the slots are.
#[tokio::test]
async fn a_gate_that_is_not_in_charge_keeps_no_line() {
    let w = World::new();
    let p = provider("p", 3);
    let rows = SqlCatalog::new(w.db.clone());
    rows.seed_permits(core::slice::from_ref(&p)).await.unwrap();
    let on_rows = rows.acquire_permit(&p, JOB, "job-old", w.now()).await;
    assert!(on_rows.unwrap().is_some());
    let (sleep, on) = (w.sleeper(), [&p]);
    let a = w.pushing("a", core::slice::from_ref(&p));

    let mut waiting = wait(&a, &on, "job-a", 60_000, &sleep);

    assert_eq!(turn(&mut waiting), Some(SlotWait::Unsupported));
    assert_eq!(w.sessions(), 0);
    assert_eq!(w.pushed.get(), 0);
}

/// A free slot at the time of asking is taken with the request to
/// wait: the job never stands in the line.
#[tokio::test]
async fn a_wait_that_finds_a_slot_takes_it_at_once() {
    let w = World::new();
    let p = provider("p", 3);
    let (sleep, on) = (w.sleeper(), [&p]);
    let a = w.pushing("a", core::slice::from_ref(&p));
    let mut waiting = wait(&a, &on, "job-a", 60_000, &sleep);
    assert_eq!(turn(&mut waiting), Some(SlotWait::Granted));
    assert_eq!((w.opens.get(), w.msgs.get(), w.pushed.get()), (1, 0, 0));
    let got = take(&a, &w, &p, JOB, "job-a").await.unwrap();
    assert!(a.renew_permit(&got, w.now()).await.unwrap());
    assert_eq!(w.held("p").await, 1);
}

// ---------------------------------------------------------------------------
// A long schedule
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

enum Phase<'a> {
    /// Not delivered yet.
    Idle,
    Waiting(Waiting<'a>, i64),
    /// With the slot, until the time given; then it gives it back, or
    /// dies with it.
    Working(Permit, i64, bool),
    Done,
}

/// Jobs that come at random, wait in the line, work, give their slot
/// back or die with it, wait out their time or die waiting, while the
/// object leaves memory at random and reads come and go:
///
/// * no limit is ever exceeded, and the slot kept for reads is never a
///   job's;
/// * a slot never goes to a job while one that came before it still
///   waits;
/// * every job that waited its whole time got a slot or was told that
///   the time is over, and holds nothing then;
/// * when all is over nothing is held and no session is open.
#[tokio::test]
async fn a_long_schedule_serves_in_order_and_loses_no_slot() {
    for seed in [3_u64, 17, 2_026] {
        let w = World::new();
        let p = provider("p", 4);
        let (sleep, on) = (w.sleeper(), [&p]);
        let mut rng = Lcg(seed);
        const JOBS: usize = 60;
        let workers: Vec<SqlCatalog<Db>> = (0..JOBS)
            .map(|i| w.pushing(&format!("w{i}"), core::slice::from_ref(&p)))
            .collect();
        let names: Vec<String> = (0..JOBS).map(|i| format!("job-{i}")).collect();
        let reader = w.pushing("reader", core::slice::from_ref(&p));
        let mut phases: Vec<Phase> = (0..JOBS).map(|_| Phase::Idle).collect();
        // The order the jobs began to wait in.
        let mut line: Vec<usize> = Vec::new();
        let (mut ran, mut timed_out, mut died, mut next, mut reads) = (0, 0, 0, 0, 0);
        let mut crashed = 0;
        let mut read: Option<Permit> = None;

        for _ in 0..4_000 {
            w.pass(250 + rng.next(1_500) as i64);
            if rng.next(7) == 0 {
                w.hibernate();
            }
            // Holders: work ends, with the slot given back or not.
            for i in 0..JOBS {
                let over =
                    matches!(&phases[i], Phase::Working(_, until, _) if *until <= w.now.get());
                if !over {
                    continue;
                }
                let Phase::Working(permit, _, dies) =
                    core::mem::replace(&mut phases[i], Phase::Done)
                else {
                    unreachable!()
                };
                match dies {
                    true => {
                        crashed += 1;
                        w.end(&format!("w{i}")).await;
                    }
                    false => workers[i].release_permit(&permit).await.unwrap(),
                }
                ran += 1;
            }
            // Waiters, in any order: served, out of time, or dead.
            let mut granted = Vec::new();
            for (i, phase) in phases.iter_mut().enumerate() {
                let Phase::Waiting(waiting, _) = phase else {
                    continue;
                };
                match turn(waiting) {
                    None if rng.next(300) == 0 => {
                        // Its invocation dies while it waits.
                        *phase = Phase::Done;
                        line.retain(|j| *j != i);
                        w.end(&format!("w{i}")).await;
                        died += 1;
                    }
                    None => {}
                    Some(SlotWait::Granted) => granted.push(i),
                    Some(SlotWait::Elapsed) => {
                        *phase = Phase::Done;
                        line.retain(|j| *j != i);
                        timed_out += 1;
                    }
                    Some(SlotWait::Unsupported) => panic!("job {i}: no line"),
                }
            }
            // A slot went only to the jobs at the head of the line.
            granted.sort_by_key(|i| line.iter().position(|j| j == i));
            for i in granted {
                assert_eq!(line.first(), Some(&i), "seed {seed}: {i} before {line:?}");
                line.remove(0);
                let got = take(&workers[i], &w, &p, JOB, &names[i]).await;
                let got = got.unwrap_or_else(|| panic!("seed {seed}: job {i} has no slot"));
                let until = w.now.get() + 500 + rng.next(20_000) as i64;
                phases[i] = Phase::Working(got, until, rng.next(5) == 0);
            }
            // One or two jobs are delivered.
            for _ in 0..rng.next(3) {
                if next == JOBS {
                    break;
                }
                let i = next;
                next += 1;
                match take(&workers[i], &w, &p, JOB, &names[i]).await {
                    Some(got) => {
                        assert!(line.is_empty(), "seed {seed}: {i} passed {line:?}");
                        let until = w.now.get() + 500 + rng.next(20_000) as i64;
                        phases[i] = Phase::Working(got, until, rng.next(5) == 0);
                    }
                    None => {
                        let ms = 2_000 + rng.next(118_000) as i64;
                        let mut waiting = wait(&workers[i], &on, &names[i], ms, &sleep);
                        match turn(&mut waiting) {
                            None => {
                                line.push(i);
                                phases[i] = Phase::Waiting(waiting, w.now.get() + ms);
                            }
                            // Taken with the request: nobody waited.
                            Some(SlotWait::Granted) => {
                                assert!(line.is_empty(), "seed {seed}: {i} passed {line:?}");
                                drop(waiting);
                                let got = take(&workers[i], &w, &p, JOB, &names[i]).await;
                                let until = w.now.get() + 500 + rng.next(20_000) as i64;
                                phases[i] = Phase::Working(got.unwrap(), until, false);
                            }
                            other => panic!("seed {seed}: job {i}: {other:?}"),
                        }
                    }
                }
            }
            // A read comes or goes: its slot is there whenever no read
            // has it.
            match read.take() {
                Some(permit) => reader.release_permit(&permit).await.unwrap(),
                None if rng.next(2) == 0 => {
                    let name = format!("read-{reads}");
                    let got = take(&reader, &w, &p, READ, &name).await;
                    assert!(got.is_some(), "seed {seed}: a read found no slot");
                    read = got;
                    reads += 1;
                }
                None => {}
            }
            // No wait outlives its time.
            for (i, phase) in phases.iter().enumerate() {
                if let Phase::Waiting(_, until) = phase {
                    assert!(
                        w.now.get() <= *until + 3_000,
                        "seed {seed}: job {i} waits on"
                    );
                }
            }
            let working = phases.iter().filter(|p| matches!(p, Phase::Working(..)));
            let (working, held) = (working.count() as u32, w.held("p").await);
            assert!(held <= 4, "seed {seed}: {held} of 4");
            assert!(working <= 3, "seed {seed}: {working} jobs on 3 job slots");
            let all_done = phases.iter().all(|p| matches!(p, Phase::Done));
            if next == JOBS && all_done && read.is_none() {
                break;
            }
        }

        assert!(
            phases.iter().all(|p| matches!(p, Phase::Done)),
            "seed {seed}"
        );
        assert_eq!(ran + timed_out + died, JOBS, "seed {seed}");
        assert!(
            ran >= 20 && crashed >= 2,
            "seed {seed}: {ran} ran, {crashed} crashed"
        );
        assert!(
            timed_out >= 1 && died >= 1,
            "seed {seed}: {timed_out}, {died}"
        );
        assert!(reads >= 30, "seed {seed}: {reads} reads");
        w.pass(JOB_MS + 1);
        assert_eq!(w.held("p").await, 0, "seed {seed}");
        drop(phases);
        drop(workers);
        drop(reader);
        w.hear().await;
        assert_eq!(w.sessions(), 0, "seed {seed}");
    }
}
