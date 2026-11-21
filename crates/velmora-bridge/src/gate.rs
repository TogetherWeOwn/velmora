//! Provider connection permits held in memory by a gate.
//!
//! The catalogue's permits ([`crate::sql`], table `provider_permits`) cost
//! database rows for every connection a job opens. A gate hands out the
//! same permits from memory: a long-lived object (a Durable Object on
//! Workers), asked over a request, with nothing written when a permit is
//! taken, renewed or given back.
//!
//! There is a gate per provider account, or per pool of accounts that
//! share a limit: what a limit covers is the smallest unit one gate can
//! keep it for. One object answers its requests in turn, so an account
//! busier than one object can serve is divided over several gates
//! ([`GateProvider::part`]): each takes the slots `n` with
//! `n % shards == shard` and the matching part of every limit, and the
//! parts add up to the account. A gate is named
//! `permits:<unit>:<shard>` ([`gate_name`]).
//!
//! A permit is a limit on connections and source addresses, not a
//! correctness fence. What a job may write is still decided by the lease
//! token of its outbox row and by nothing in here.
//!
//! # The same rules as the catalogue
//!
//! [`Core`] keeps numbered slots per provider and applies the rules of
//! the SQL statements one for one: `max_conns`, the slot kept back for
//! reads, the limit a pool of accounts shares, `max_ips` and the address
//! kept back for reads, a lifetime per class, a token per acquisition
//! that renew and release must name.
//!
//! # Sessions
//!
//! A holder talks to a gate over a **session**: a connection the object
//! keeps open without staying in memory (a hibernatable WebSocket on
//! Workers). The first request opens it, what follows are messages on
//! it, and its end, however it comes, frees its slots at once. The
//! slots of a session are kept with its connection ([`SessionState`]),
//! not in storage: the host hands them back when the object comes into
//! memory again ([`Gate::resume`]), so a pause between two messages
//! costs nothing and loses nothing.
//!
//! # Losing the memory
//!
//! What a pause does not lose, a deploy may: new code can cut every
//! session, and the object then starts with no slots while holders of
//! the old ones may still have connections open. Three things make that
//! safe:
//!
//! - **Tokens never repeat.** They start from the time of the start, so
//!   a holder from before cannot renew or free a slot handed out after.
//!   Its next renewal is refused and it drops its socket.
//! - **A horizon is stored before any slot is promised**: one small
//!   record ([`GateRecord`]) with the latest time a job's slot and a
//!   read's slot may still be held. It moves in steps of
//!   [`HORIZON_STEP_MS`], so it is written once per step under load and
//!   never otherwise.
//! - **The first start of new code inside the horizon waits it out.**
//!   The record names the code that last ran (`boot`). A start under
//!   another name that finds no session, inside the horizon, counts the
//!   places of each class as taken for one lifetime of the class (no
//!   old slot was renewed since), and stores that wait with the new
//!   name. Reads have short slots: after their wait, a read may use
//!   what jobs could never hold (the slot and the address kept back
//!   for reads) while the jobs' wait still runs. Every first start of
//!   new code also forgets which slot rows the gate had seized and
//!   asks the catalogue again: two writes per deploy, and one more
//!   for every further account or pool the gate serves.
//!
//! A start of the same code waits for nothing: its sessions are its
//! slots. What that leaves open is a reset that cuts sessions without a
//! deploy (the object crashed, its machine was lost) while their
//! holders live on: until such a holder's next renewal is refused (one
//! renewal interval) the gate may hand its place out again, and the
//! provider refuses a connection over its limit. Closing that needs a
//! write at the start and at the end of every busy period, which is
//! the cost this design removes.
//!
//! # Old and new side by side
//!
//! During a rollout some Workers still take permits from the catalogue
//! while others ask the gate. Both together must stay under the limits,
//! so the catalogue's slot rows stay the one arbiter of who owns a
//! connection:
//!
//! - The gate **seizes** the free slot rows of a provider: it takes them
//!   as an ordinary holder named after itself ([`gate_holder`]) with an
//!   expiry far in the future. A catalogue caller cannot take a seized
//!   row, and the gate cannot seize a row a catalogue caller holds.
//! - The gate hands out nothing on a provider until it owns **every**
//!   row of it and of every account that shares its pool. Until then the
//!   catalogue callers drain: they finish or expire, and find fewer and
//!   fewer free rows.
//! - Going back, the catalogue side asks the gate to **retire**. The
//!   gate stops handing out, waits for its own slots to end, and only
//!   then frees the rows.
//!
//! So at every moment each connection of an account is owned by exactly
//! one side. The seizure is written once, not per permit.
//!
//! The same holds between gates. A gate seizes only the rows of its own
//! part and hands out a slot only while its row is its own, so Workers
//! that divide an account differently (a rollout that changes the
//! number of gates) still cannot hold one connection twice. The shares
//! of `max_ips` and of a pool are tied to slots for the same reason.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use futures_util::future::{join_all, select, select_all, Either, LocalBoxFuture};
use futures_util::lock::Mutex as AsyncMutex;
use serde::{Deserialize, Serialize};

use crate::ingress::Sleeper;
use crate::ports::{Permit, PermitClass, SlotWait, Sql, SqlValue, PERMIT_SECS, READ_PERMIT_SECS};
use crate::types::{BridgeError, ProviderConfig, Result, UnixMs};

/// Prefix of the holder a gate writes on the slot rows it seizes.
pub const GATE_HOLDER_PREFIX: &str = "do-gate:";

/// The holder name of the gate `name` on seized slot rows.
pub fn gate_holder(name: &str) -> String {
    format!("{GATE_HOLDER_PREFIX}{name}")
}

/// Prefix of the holder name of a retired gate on the rows it no longer
/// hands out but that are not free yet: the gates of one account (or
/// pool) free their rows together, once every one of them is done.
pub const GATE_IDLE_PREFIX: &str = "do-gate-idle:";

/// The holder name of the retired gate `name` on its slot rows.
pub fn gate_idle_holder(name: &str) -> String {
    format!("{GATE_IDLE_PREFIX}{name}")
}

/// `name` without its shard: what the gates of one account or pool
/// have in common, with the colon that ends it.
fn unit_prefix(name: &str) -> &str {
    name.rfind(':').map_or(name, |at| &name[..=at])
}

/// Expiry of a seized slot row: 2100-01-01. Only the gate frees it.
pub const SEIZED_UNTIL_MS: i64 = 4_102_444_800_000;

/// How far past the expiry it needs the stored horizon is moved. One
/// write per step while slots of a class are in use.
pub const HORIZON_STEP_MS: i64 = 600_000;

/// The most a session's slots may take once written down for the host
/// ([`SessionState`]). A Durable Object keeps 16,384 bytes per socket.
pub const SESSION_STATE_MAX: usize = 12_000;

/// A session without a live slot that has not asked for this long is
/// closed by the host: when it next opens a session or is swept. Its
/// holder would have closed it at its next question.
pub const SESSION_IDLE_MS: i64 = 30_000;

/// Margin for the difference between the clocks of two machines the
/// object ran on, added to every wait after a start.
pub const SKEW_MS: i64 = 5_000;

/// The least time between two attempts to seize one provider's rows.
pub const SEIZE_EVERY_MS: i64 = 2_000;

const fn ttl_ms(background: bool) -> i64 {
    match background {
        true => PERMIT_SECS as i64 * 1000,
        false => READ_PERMIT_SECS as i64 * 1000,
    }
}

fn reserve(max: u32) -> u32 {
    u32::from(max >= 2)
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The limits of one provider account, as the caller's configuration
/// has them. No host and no credentials cross to the gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateProvider {
    pub id: String,
    pub max_conns: u32,
    #[serde(default)]
    pub max_ips: Option<u32>,
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub pool_max_conns: Option<u32>,
    /// The gate asked serves the slots `n` of this account with
    /// `n % shards == shard`, and that part of every limit.
    #[serde(default)]
    pub shard: u32,
    #[serde(default = "one_shard")]
    pub shards: u32,
}

fn one_shard() -> u32 {
    1
}

impl From<&ProviderConfig> for GateProvider {
    fn from(p: &ProviderConfig) -> Self {
        GateProvider {
            id: p.id.clone(),
            max_conns: p.max_conns,
            max_ips: p.max_ips,
            pool: p.pool.clone(),
            pool_max_conns: p.pool_max_conns,
            shard: 0,
            shards: 1,
        }
    }
}

impl GateProvider {
    /// As [`ProviderConfig::background_conns`].
    pub fn background_conns(&self) -> u32 {
        let reserve = self.max_conns >= 2 && self.max_ips != Some(1);
        self.max_conns - u32::from(reserve)
    }

    /// As [`ProviderConfig::background_ips`].
    pub fn background_ips(&self) -> Option<u32> {
        self.max_ips.map(|max| max - u32::from(max >= 2))
    }

    /// The pool whose limit applies, and that limit.
    fn pool_limit(&self) -> Option<(&str, u32)> {
        match (&self.pool, self.pool_max_conns) {
            (Some(pool), Some(max)) => Some((pool.as_str(), max)),
            _ => None,
        }
    }

    /// This account as the gate of `shard` out of `shards` serves it.
    pub fn part(&self, shard: u32, shards: u32) -> GateProvider {
        GateProvider {
            shard,
            shards,
            ..self.clone()
        }
    }

    fn whole(&self) -> bool {
        self.shards <= 1
    }

    /// Whether slot `n` belongs to this part.
    fn has(&self, n: u32) -> bool {
        self.whole() || n % self.shards == self.shard
    }

    /// The slots of this part, lowest first.
    fn slots(&self) -> impl DoubleEndedIterator<Item = u32> + '_ {
        (0..self.max_conns).filter(|n| self.has(*n))
    }

    fn count(&self, slots: core::ops::Range<u32>) -> u32 {
        let n = slots.filter(|n| self.has(*n)).count();
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// The name of this part in a gate's record: the id of the account
    /// when the gate serves all of it.
    fn part_name(&self) -> String {
        match self.whole() {
            true => self.id.clone(),
            false => format!("{}#{}/{}", self.id, self.shard, self.shards),
        }
    }

    /// The addresses of this part: all it may use, and those of them
    /// jobs may use.
    ///
    /// A gate that serves the whole account has `max_ips` and
    /// [`Self::background_ips`]. Between parts, each of the account's
    /// top `max_ips` slots carries one address and the highest of them
    /// carries the one kept back for reads, so the parts of an account
    /// add up to its limit however the slots are divided: a slot is in
    /// one part only.
    fn ip_limits(&self) -> Option<(u32, u32)> {
        let max = self.max_ips?;
        let jobs = self.background_ips().unwrap_or(max);
        if self.whole() {
            return Some((max, jobs));
        }
        let max = max.min(self.max_conns);
        let low = self.max_conns - max;
        let jobs = jobs.min(max - reserve(max));
        Some((self.count(low..self.max_conns), self.count(low..low + jobs)))
    }

    /// The pool's connections of this part: all, and those for jobs.
    /// Between parts they are carried by the top slots of the pool's
    /// accounts in the order of their ids, as in [`Self::ip_limits`].
    fn pool_limits(&self, peers: &[GateProvider]) -> Option<(&str, u32, u32)> {
        let (pool, max) = self.pool_limit()?;
        let jobs = max - reserve(max);
        if self.whole() {
            return Some((pool, max, jobs));
        }
        let mut members: Vec<&GateProvider> = peers
            .iter()
            .filter(|q| q.id != self.id && q.pool.as_deref() == Some(pool))
            .chain(core::iter::once(self))
            .collect();
        members.sort_by(|a, b| a.id.cmp(&b.id));
        members.dedup_by(|a, b| a.id == b.id);
        let total = members
            .iter()
            .fold(0u32, |n, q| n.saturating_add(q.max_conns));
        let low = total - max.min(total);
        let job_end = low.saturating_add(jobs).min(total);
        let (mut all, mut for_jobs, mut at) = (0u32, 0u32, 0u32);
        for q in members {
            for n in q.slots() {
                let place = at.saturating_add(n);
                all += u32::from(place >= low);
                for_jobs += u32::from(place >= low && place < job_end);
            }
            at = at.saturating_add(q.max_conns);
        }
        Some((pool, all, for_jobs))
    }
}

/// A held slot as it crosses the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatePermit {
    pub provider: String,
    pub slot: u32,
    pub token: u64,
}

impl From<&Permit> for GatePermit {
    fn from(p: &Permit) -> Self {
        GatePermit {
            provider: p.provider.clone(),
            slot: p.slot,
            token: p.token,
        }
    }
}

/// One question to a gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateOp {
    /// One slot on `provider` for `holder`. `peers`: the other accounts
    /// of its pool.
    Acquire {
        provider: GateProvider,
        peers: Vec<GateProvider>,
        background: bool,
        holder: String,
    },
    Renew {
        permits: Vec<GatePermit>,
    },
    Release {
        permits: Vec<GatePermit>,
    },
    /// One job slot for `holder` on the first of `wants` that has one.
    /// With none, the session waits in the gate's line for up to `ms`:
    /// the reply says so ([`GateReply::waiting`]), and the slot is sent
    /// on the session when it is this session's turn, as a second reply
    /// under the same id. Asked on a session that holds nothing.
    Wait {
        wants: Vec<GateWant>,
        holder: String,
        ms: i64,
    },
    /// What is held, per provider.
    Load,
    /// The gate is in charge of `providers`: seize what is free.
    Activate {
        providers: Vec<GateProvider>,
    },
    /// The catalogue is in charge again: hand out nothing more and free
    /// the seized rows once nothing is held.
    Retire,
}

/// An account a waiting job can use, with the other accounts of its
/// pool: what [`GateOp::Acquire`] names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateWant {
    pub provider: GateProvider,
    pub peers: Vec<GateProvider>,
}

/// The answer to the [`GateOp`] at the same place of the request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateAnswer {
    Acquired(Option<GatePermit>),
    Renewed(Vec<bool>),
    Released,
    Load(Vec<GateLoad>),
    /// `true`: every listed provider is the gate's.
    Activated(bool),
    /// `true`: the seized rows are free again.
    Retired(bool),
}

/// Several questions to one gate in one request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRequest {
    /// Chosen by the caller and repeated in the reply: on a session a
    /// caller that gave up on a request tells its late reply from the
    /// reply to the next one.
    #[serde(default)]
    pub id: u64,
    /// The gate's name. The object learns it from its callers.
    pub gate: String,
    pub ops: Vec<GateOp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReply {
    #[serde(default)]
    pub id: u64,
    pub answers: Vec<GateAnswer>,
    /// What the gate holds after this request: callers order providers
    /// by it without a request of its own.
    #[serde(default)]
    pub load: Vec<GateLoad>,
    /// A slot was refused because the gate is not in charge of the
    /// account (the slot rows are not all its own, or it is retired):
    /// the rollout step is due ([`PermitGate::sweep`]).
    #[serde(default)]
    pub unowned: bool,
    /// The gate could not answer this request (its storage or the
    /// catalogue failed). No slot it asked for was handed out; what
    /// it gave back before the failure is given back, and a renewal
    /// before it stands. The session is open and nothing else that is
    /// held on it has changed: the caller may ask again.
    #[serde(default)]
    pub failed: bool,
    /// The session is in the gate's line ([`GateOp::Wait`]): a reply
    /// with its slot follows under the id of the request that asked.
    #[serde(default)]
    pub waiting: bool,
    /// With `waiting`: in how many milliseconds a slot can next run out
    /// with no word to the gate (a holder that stopped renewing, the
    /// wait after a restart). The caller asks again then, with a
    /// request of no questions; a gate that has left memory wakes for
    /// nothing else.
    #[serde(default)]
    pub wake: Option<i64>,
}

impl GateReply {
    /// The reply to a request the gate could not answer.
    pub fn failed(id: u64) -> Self {
        GateReply {
            id,
            answers: Vec::new(),
            load: Vec::new(),
            unowned: false,
            failed: true,
            waiting: false,
            wake: None,
        }
    }
}

/// What a gate holds on one provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateLoad {
    pub provider: String,
    pub held: u32,
    pub holders: u32,
    pub background_holders: u32,
    /// Slots handed out since the object started.
    pub uses: u64,
}

// ---------------------------------------------------------------------------
// The slots in memory
// ---------------------------------------------------------------------------

/// One slot in use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    provider: String,
    slot: u32,
    token: u64,
    holder: String,
    background: bool,
    pool: Option<String>,
    until: i64,
    /// The session it was taken on.
    session: u64,
}

impl Held {
    /// This is the slot of `p`, taken on `session`.
    fn is(&self, p: &GatePermit, session: u64) -> bool {
        self.session == session
            && self.provider == p.provider
            && self.slot == p.slot
            && self.token == p.token
    }
}

/// A session in the line of a gate: a job that found no slot and waits
/// for one on its open session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiter {
    /// The request that asked: its slot is sent under this id.
    id: u64,
    holder: String,
    wants: Vec<GateWant>,
    /// Its place in the line: a number of this gate, as a token is.
    /// The lower one came first.
    place: u64,
    /// Until when its caller waits.
    until: i64,
}

/// A session and the slots taken on it: what the host keeps with the
/// session's connection, so that the slots outlive the object's memory
/// for as long as the connection does.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub id: u64,
    /// When the session last asked.
    pub seen: i64,
    pub held: Vec<Held>,
    /// What it waits for in the gate's line, if it does: the line
    /// outlives the object's memory as the slots do.
    #[serde(default)]
    pub wait: Option<Waiter>,
}

impl SessionState {
    /// Whether the host should close the session: nothing live on it,
    /// and for [`SESSION_IDLE_MS`] no question and no wait in the line
    /// that its caller still sits out. A caller that waits is silent
    /// by design, and ends its session itself when its time is over:
    /// it is given that long to do so.
    pub fn stale(&self, now: UnixMs) -> bool {
        let quiet = self
            .wait
            .as_ref()
            .map_or(self.seen, |w| w.until.max(self.seen));
        let idle = now.0 - quiet >= SESSION_IDLE_MS;
        idle && self.held.iter().all(|h| h.until < now.0)
    }

    /// Whether the host can keep this with the session's connection.
    /// The host's limit is on the stored form, which may take two bytes
    /// for each unit of a text that is not all ASCII.
    fn fits(&self) -> bool {
        serde_json::to_string(self).is_ok_and(|s| {
            let stored = match s.is_ascii() {
                true => s.len(),
                false => 2 * s.encode_utf16().count(),
            };
            stored <= SESSION_STATE_MAX
        })
    }
}

/// Which places are counted as taken by holders from before a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warm {
    /// None: every slot in memory is every slot there is.
    Done,
    /// Jobs from before may still hold what jobs can hold.
    Jobs,
    /// Jobs and reads from before may hold anything.
    All,
}

/// The slots of every provider this gate serves. No I/O and no clock:
/// the caller passes the time.
#[derive(Debug)]
pub struct Core {
    held: Vec<Held>,
    /// The sessions that wait for a job slot, each with its session.
    line: Vec<(u64, Waiter)>,
    next_token: u64,
    uses: BTreeMap<String, u64>,
}

impl Core {
    /// `started`: the time of the start. Tokens count up from it, so
    /// they are above every token of an earlier start.
    pub fn new(started: UnixMs) -> Self {
        Core::restored(started, Vec::new())
    }

    /// As [`Self::new`], with the slots of the sessions that outlived
    /// the memory. Tokens go on above theirs too.
    pub fn restored(started: UnixMs, sessions: Vec<SessionState>) -> Self {
        let ids = sessions.iter().map(|s| s.id);
        let held: Vec<Held> = sessions
            .iter()
            .flat_map(|s| s.held.iter().filter(|h| h.session == s.id).cloned())
            .collect();
        let line: Vec<(u64, Waiter)> = sessions
            .iter()
            .filter_map(|s| s.wait.clone().map(|w| (s.id, w)))
            .collect();
        let from_time = u64::try_from(started.0).unwrap_or(0) << 20;
        let numbers = held.iter().map(|h| h.token);
        let numbers = numbers.chain(line.iter().map(|(_, w)| w.place));
        let seen = ids.chain(numbers).max().unwrap_or(0);
        Core {
            held,
            line,
            next_token: from_time.max(seen),
            uses: BTreeMap::new(),
        }
    }

    /// A number no token and no session of this gate has had.
    fn next(&mut self) -> u64 {
        self.next_token += 1;
        self.next_token
    }

    /// The slots taken on `session` that are live at `now`.
    fn of_session(&mut self, session: u64, now: i64) -> Vec<Held> {
        self.prune(now);
        let mine = self.held.iter().filter(|h| h.session == session);
        mine.cloned().collect()
    }

    /// Frees every slot taken on `session`, and its place in the line.
    pub fn close(&mut self, session: u64) {
        self.held.retain(|h| h.session != session);
        self.line.retain(|(s, _)| *s != session);
    }

    /// Puts `session` in the line for a job slot on one of `wants`,
    /// behind every session that waits already. One that waits already
    /// keeps its place and waits for what it asks now. `id`: the
    /// request that asks.
    pub fn enlist(&mut self, session: u64, id: u64, holder: &str, wants: &[GateWant], until: i64) {
        let place = match self.unlist(session) {
            Some(before) => before.place,
            None => self.next(),
        };
        let waiter = Waiter {
            id,
            holder: holder.to_string(),
            wants: wants.to_vec(),
            place,
            until,
        };
        self.line.push((session, waiter));
    }

    /// Takes `session` out of the line.
    pub fn unlist(&mut self, session: u64) -> Option<Waiter> {
        let at = self.line.iter().position(|(s, _)| *s == session)?;
        Some(self.line.swap_remove(at).1)
    }

    /// What `session` waits for, if it is in the line.
    pub fn waiter(&self, session: u64) -> Option<&Waiter> {
        let mut line = self.line.iter();
        line.find(|(s, _)| *s == session).map(|(_, w)| w)
    }

    /// The line at `now`, first come first. A session whose caller has
    /// stopped waiting is out of it.
    pub fn line(&mut self, now: i64) -> Vec<(u64, Waiter)> {
        self.line.retain(|(_, w)| w.until >= now);
        let mut line = self.line.clone();
        line.sort_by_key(|(_, w)| w.place);
        line
    }

    /// When the first slot that is live at `now` runs out if it is
    /// not renewed.
    fn next_expiry(&self, now: i64) -> Option<i64> {
        let live = self.held.iter().filter(|h| h.until >= now);
        live.map(|h| h.until + 1).min()
    }

    fn prune(&mut self, now: i64) {
        self.held.retain(|h| h.until >= now);
    }

    /// Live slots at `now`.
    pub fn live(&mut self, now: UnixMs) -> usize {
        self.prune(now.0);
        self.held.len()
    }

    /// Takes a slot under every limit, or none. `by`: the holder and
    /// the session it asks on.
    pub fn acquire(
        &mut self,
        p: &GateProvider,
        peers: &[GateProvider],
        background: bool,
        by: (&str, u64),
        now: UnixMs,
        warm: Warm,
    ) -> Option<GatePermit> {
        let (holder, session) = by;
        let slot = self.free(p, peers, background, holder, now, warm)?;
        let token = self.next();
        self.held.push(Held {
            provider: p.id.clone(),
            slot,
            token,
            holder: holder.to_string(),
            background,
            pool: p.pool_limit().map(|(pool, _)| pool.to_string()),
            until: now.0 + ttl_ms(background),
            session,
        });
        *self.uses.entry(p.id.clone()).or_insert(0) += 1;
        Some(GatePermit {
            provider: p.id.clone(),
            slot,
            token,
        })
    }

    /// The slot [`Self::acquire`] would take for `holder`, or none.
    /// Nothing is taken.
    pub fn free(
        &mut self,
        p: &GateProvider,
        peers: &[GateProvider],
        background: bool,
        holder: &str,
        now: UnixMs,
        warm: Warm,
    ) -> Option<u32> {
        self.prune(now.0);
        // Places of holders this object does not know.
        let old_jobs = match (warm, background) {
            (Warm::All, _) | (Warm::Jobs, true) => return None,
            (Warm::Jobs, false) => true,
            (Warm::Done, _) => false,
        };
        let here = |h: &&Held| h.provider == p.id;
        if let Some((pool, max, job_limit)) = p.pool_limits(peers) {
            let limit = if background { job_limit } else { max };
            let live = self
                .held
                .iter()
                .filter(|h| h.pool.as_deref() == Some(pool))
                .count();
            let live = u32::try_from(live).unwrap_or(u32::MAX);
            let old = if old_jobs { job_limit } else { 0 };
            if live.saturating_add(old) >= limit {
                return None;
            }
        }
        if let Some((max_ips, job_ips)) = p.ip_limits() {
            let mine = self.held.iter().filter(here).any(|h| h.holder == holder);
            let holders: BTreeSet<&str> = self
                .held
                .iter()
                .filter(here)
                .map(|h| h.holder.as_str())
                .collect();
            let known = u32::try_from(holders.len()).unwrap_or(u32::MAX);
            let old = if old_jobs { job_ips } else { 0 };
            // A holder with a live slot here adds no address. It was
            // let in beside the old jobs, if any are still counted.
            if !(mine || known.saturating_add(old) < max_ips) {
                return None;
            }
            if background {
                let mine_job = self
                    .held
                    .iter()
                    .filter(here)
                    .any(|h| h.holder == holder && h.background);
                let jobs: BTreeSet<&str> = self
                    .held
                    .iter()
                    .filter(here)
                    .filter(|h| h.background)
                    .map(|h| h.holder.as_str())
                    .collect();
                if !(mine_job || u32::try_from(jobs.len()).unwrap_or(u32::MAX) < job_ips) {
                    return None;
                }
            }
        }
        let taken: BTreeSet<u32> = self.held.iter().filter(here).map(|h| h.slot).collect();
        // Jobs fill from the bottom and stay below the slot kept back;
        // reads fill from the top, and above the old jobs' slots.
        match background {
            true => p
                .slots()
                .take_while(|s| *s < p.background_conns())
                .find(|s| !taken.contains(s)),
            false => {
                let floor = if old_jobs { p.background_conns() } else { 0 };
                p.slots()
                    .rev()
                    .take_while(|s| *s >= floor)
                    .find(|s| !taken.contains(s))
            }
        }
    }

    /// The class of a slot that `p` still holds on `session` at `now`.
    fn class_of(&self, p: &GatePermit, session: u64, now: i64) -> Option<bool> {
        self.held
            .iter()
            .find(|h| h.is(p, session))
            .filter(|h| h.until >= now)
            .map(|h| h.background)
    }

    /// Extends a slot that is still held under this token, on the
    /// session it was taken on, by the lifetime of its class. `false`:
    /// the caller owns nothing. A slot lives and ends with its session,
    /// and what the host keeps for a session is written when that
    /// session asks: a permit shown on another session is not held.
    pub fn renew(&mut self, p: &GatePermit, session: u64, now: UnixMs) -> bool {
        self.prune(now.0);
        match self.held.iter_mut().find(|h| h.is(p, session)) {
            Some(h) => {
                // Never earlier: a renewal that was held up does not
                // undo one that came after it.
                h.until = h.until.max(now.0 + ttl_ms(h.background));
                true
            }
            None => false,
        }
    }

    /// Frees the slot if this token still owns it on `session`.
    pub fn release(&mut self, p: &GatePermit, session: u64) {
        self.held.retain(|h| !h.is(p, session));
    }

    pub fn load(&mut self, now: UnixMs) -> Vec<GateLoad> {
        self.prune(now.0);
        let mut ids: BTreeSet<&str> = self.uses.keys().map(String::as_str).collect();
        ids.extend(self.held.iter().map(|h| h.provider.as_str()));
        ids.into_iter()
            .map(|id| {
                let mine = || self.held.iter().filter(move |h| h.provider == id);
                let holders: BTreeSet<&str> = mine().map(|h| h.holder.as_str()).collect();
                let jobs: BTreeSet<&str> = mine()
                    .filter(|h| h.background)
                    .map(|h| h.holder.as_str())
                    .collect();
                GateLoad {
                    provider: id.to_string(),
                    held: u32::try_from(mine().count()).unwrap_or(u32::MAX),
                    holders: u32::try_from(holders.len()).unwrap_or(u32::MAX),
                    background_holders: u32::try_from(jobs.len()).unwrap_or(u32::MAX),
                    uses: self.uses.get(id).copied().unwrap_or(0),
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// The object: memory, its one stored record, and the slot rows it seizes
// ---------------------------------------------------------------------------

/// Who hands out permits, as the gate last heard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateMode {
    /// Never asked.
    #[default]
    Unset,
    Active,
    Retired,
}

/// All a gate stores. Written when the horizon moves, when a provider's
/// rows are seized or freed, when the mode changes and at the first
/// start under new code: never per permit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GateRecord {
    /// No job's slot handed out so far is held after this time.
    pub jobs_until: i64,
    /// The same for the slots of reads.
    pub reads_until: i64,
    pub mode: GateMode,
    /// The accounts, or parts of accounts ([`GateProvider::part`]),
    /// whose slot rows are all this gate's, with their count. A start
    /// goes by it; the rollout step ([`GateOp::Activate`]) asks the
    /// catalogue again.
    pub seized: BTreeMap<String, u32>,
    /// The code the object last started under ([`Gate::new`]).
    pub boot: String,
    /// Until when jobs, and reads, from before a start that lost its
    /// sessions are counted as present.
    pub warm_jobs: i64,
    pub warm_reads: i64,
}

/// The gate's own durable storage: one record.
#[allow(async_fn_in_trait)]
pub trait GateStore {
    async fn load(&self) -> Result<Option<GateRecord>>;
    /// Returns once the record is durable.
    async fn save(&self, record: &GateRecord) -> Result<()>;
}

struct Inner {
    name: Option<String>,
    core: Core,
    /// The record as it should be stored.
    record: GateRecord,
    /// The record as the last finished save left it.
    saved: GateRecord,
    seize_tried: BTreeMap<String, i64>,
    /// Replies to sessions that waited in the line, for the host to
    /// send: each with its session.
    pushes: Vec<(u64, GateReply)>,
}

/// One gate: [`Core`] plus what makes a restart and a rollout safe.
/// Single-threaded; several requests may be in flight and interleave
/// where one of them waits for storage or for the catalogue.
pub struct Gate<S: Sql, D: GateStore> {
    sql: S,
    store: D,
    /// What names the code this object runs: it changes with a deploy.
    boot: String,
    inner: RefCell<Option<Inner>>,
    /// One save at a time, each of the record as it is when it starts.
    saving: AsyncMutex<()>,
    /// One change of who owns slot rows at a time: a seizure and the
    /// freeing of a retirement never overlap.
    owning: AsyncMutex<()>,
    /// One pass over the line at a time: an event that comes during a
    /// pass has one of its own after it.
    serving: AsyncMutex<()>,
}

const SEED: &str = "INSERT OR IGNORE INTO provider_permits(provider_id, slot) \
     WITH RECURSIVE s(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM s WHERE n + 1 < ?2) \
     SELECT ?1, n FROM s WHERE n < ?2";

// Free and expired rows only: a row a catalogue caller holds stays its
// own until it is released or expires. The token moves, so a late
// renewal or release of the row's last holder changes nothing.
const SEIZE: &str = "UPDATE provider_permits \
     SET token = token + 1, holder = ?2, lease_until = ?3, pool = ?5, background = 0 \
     WHERE provider_id = ?1 AND lease_until < ?4 AND slot % ?6 = ?7";

// A retired gate's own rows, taken back into use (`?1` its name as a
// retired holder, `?2` as an active one).
const WAKE: &str = "UPDATE provider_permits SET holder = ?2 WHERE holder = ?1";

// Of the account `?1`: the rows of this part (`slot % ?4 = ?5`), those
// of them this gate holds, all rows, and those of all rows that a gate
// of the same account or pool holds, active (`?6`) or retired (`?7`).
// A part hands out only when the last two are equal: while a catalogue
// caller holds, or can take, any row of the account, its address and
// pool counts are not the gates' to share out.
const OWNED: &str = "SELECT \
       COALESCE(SUM(CASE WHEN slot % ?4 = ?5 THEN 1 ELSE 0 END), 0), \
       COALESCE(SUM(CASE WHEN slot % ?4 = ?5 AND holder = ?2 AND lease_until >= ?3 \
                         THEN 1 ELSE 0 END), 0), \
       COUNT(*), \
       COALESCE(SUM(CASE WHEN lease_until >= ?3 AND (substr(holder, 1, length(?6)) = ?6 \
                           OR substr(holder, 1, length(?7)) = ?7) THEN 1 ELSE 0 END), 0) \
     FROM provider_permits WHERE provider_id = ?1";

// A retired gate with nothing live keeps its rows, under its retired
// name (`?2`): a catalogue caller still sees them held.
const IDLE: &str = "UPDATE provider_permits SET holder = ?2 WHERE holder = ?1";

// The rows of the retired gates of one account or pool (`?1`, a holder
// prefix) become free in one statement, and only when no gate of it is
// active (`?2`): a gate that still hands out has the whole account.
const HAND_BACK: &str = "UPDATE provider_permits \
     SET lease_until = 0, holder = NULL, pool = NULL \
     WHERE substr(holder, 1, length(?1)) = ?1 \
       AND NOT EXISTS (SELECT 1 FROM provider_permits \
                       WHERE substr(holder, 1, length(?2)) = ?2)";

fn text(s: &str) -> SqlValue {
    SqlValue::Text(s.to_string())
}

fn int(row: &[SqlValue], i: usize) -> Result<i64> {
    match row.get(i) {
        Some(SqlValue::Int(n)) => Ok(*n),
        _ => Err(BridgeError::Sql("gate: not an integer".into())),
    }
}

impl<S: Sql, D: GateStore> Gate<S, D> {
    /// `boot` names the code the object runs (on Workers the id of the
    /// deployed version): a start under another `boot` than the stored
    /// one is the first after a deploy.
    pub fn new(sql: S, store: D, boot: impl Into<String>) -> Self {
        Gate {
            sql,
            store,
            boot: boot.into(),
            serving: AsyncMutex::new(()),
            inner: RefCell::new(None),
            saving: AsyncMutex::new(()),
            owning: AsyncMutex::new(()),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let mut inner = self.inner.borrow_mut();
        f(inner.as_mut().expect("gate started"))
    }

    /// Whether the object has started: `false` = the host has the
    /// sessions that outlived the memory to hand to [`Self::resume`].
    pub fn started(&self) -> bool {
        self.inner.borrow().is_some()
    }

    /// The start: once per time the object comes into memory, before
    /// the first [`Self::handle`], with the sessions whose connections
    /// are still open. Later calls change nothing.
    ///
    /// The slots of those sessions are in memory again. Whether slots
    /// may be held that are in no session is decided by how the memory
    /// was lost. An object that was only put to sleep, or that took up
    /// new code after it slept, keeps every connection: `sessions` is
    /// all there is. A deploy that could not wait for the object to
    /// sleep cuts every connection, and so do other resets. The first
    /// start under new code that finds no session inside the horizon
    /// therefore waits the old slots out, and stores that wait with
    /// the new `boot`, so that a later start keeps to it. Under new
    /// code the gate also forgets which slot rows it had seized.
    pub async fn resume(&self, sessions: Vec<SessionState>, now: UnixMs) -> Result<()> {
        if self.started() {
            return Ok(());
        }
        let mut record = self.store.load().await?.unwrap_or_default();
        let saved = record.clone();
        if record.boot != self.boot {
            // Slots from before cannot be renewed, so each class is
            // gone one lifetime after the start at the latest, and at
            // its horizon if that is sooner.
            // Sessions that are still listed do not show that nothing
            // else was held: an attachment the host could not read, or
            // a session that is ending, is not among them.
            let wait = |until: i64, background: bool| match until + SKEW_MS > now.0 {
                true => until.min(now.0 + ttl_ms(background)) + SKEW_MS,
                false => 0,
            };
            // Never sooner than a wait an earlier start began.
            record.warm_jobs = record.warm_jobs.max(wait(record.jobs_until, true));
            record.warm_reads = record.warm_reads.max(wait(record.reads_until, false));
            record.boot.clone_from(&self.boot);
            // What was stored about the slot rows is from before: a
            // deploy is how `PERMITS` changes, and the rows may have
            // been cleared by hand in between. The first acquire asks
            // the catalogue again.
            record.seized.clear();
        }
        {
            let mut inner = self.inner.borrow_mut();
            if inner.is_some() {
                return Ok(());
            }
            *inner = Some(Inner {
                name: None,
                core: Core::restored(now, sessions),
                saved,
                record,
                seize_tried: BTreeMap::new(),
                pushes: Vec::new(),
            });
        }
        // Before anything is promised under the new code.
        self.persist().await
    }

    /// A new session: slots are taken on one ([`Self::handle`]) and
    /// freed together when it ends ([`Self::close`]).
    pub async fn open(&self, now: UnixMs) -> Result<u64> {
        self.resume(Vec::new(), now).await?;
        Ok(self.with(|i| i.core.next()))
    }

    /// The session as the host keeps it with the connection. Written
    /// after every request on the session, before its reply leaves.
    pub fn session(&self, id: u64, now: UnixMs) -> SessionState {
        let held = match self.started() {
            true => self.with(|i| i.core.of_session(id, now.0)),
            false => Vec::new(),
        };
        let wait = match self.started() {
            true => self.with(|i| i.core.waiter(id).cloned()),
            false => None,
        };
        SessionState {
            id,
            seen: now.0,
            held,
            wait,
        }
    }

    /// The session's connection has ended: its slots are free. The
    /// holder's own connections ended with its invocation, or it learns
    /// at its next renewal that it holds nothing.
    /// The host serves the line next ([`Self::settle`]).
    pub fn close(&self, id: u64) {
        if self.started() {
            self.with(|i| {
                i.core.close(id);
                i.pushes.retain(|(session, _)| *session != id);
            });
        }
    }

    /// Serves the line after an event that is no request: the end of a
    /// session ([`Self::close`]). The host sends what [`Self::pushes`]
    /// then has.
    pub async fn settle(&self, now: UnixMs) {
        self.serve(now).await;
    }

    /// The replies to sessions that waited, each with its session, for
    /// the host to send after it has kept the session with its
    /// connection ([`Self::session`]). A session it cannot send to has
    /// ended ([`Self::close`], then [`Self::settle`]).
    pub fn pushes(&self) -> Vec<(u64, GateReply)> {
        match self.started() {
            true => self.with(|i| core::mem::take(&mut i.pushes)),
            false => Vec::new(),
        }
    }

    /// Hands what is free to the line, first come first: after every
    /// change that can free a slot, and before a request's own
    /// questions, so that no slot a waiting job can take goes to one
    /// that came later.
    async fn serve(&self, now: UnixMs) {
        if !self.started() || self.with(|i| i.core.line.is_empty()) {
            return;
        }
        let _one = self.serving.lock().await;
        for (session, waiter) in self.with(|i| i.core.line(now.0)) {
            for want in &waiter.wants {
                // Its session ended, or it was served, while an
                // earlier one was.
                let listed = |i: &mut Inner| {
                    let now = i.core.waiter(session);
                    now.is_some_and(|w| w.place == waiter.place && w.id == waiter.id)
                };
                if !self.with(listed) {
                    break;
                }
                let (provider, peers) = (&want.provider, &want.peers);
                let asked = self.acquire(provider, peers, true, &waiter.holder, session, now);
                let (permit, unowned) = match asked.await {
                    Ok(Ok(Some(permit))) => (Some(permit), false),
                    Ok(Ok(None)) => continue,
                    // Not in charge any more: the caller is told, and
                    // asks where the slots are now.
                    Ok(Err(Unowned)) => (None, true),
                    // Storage or the catalogue failed: the line stands
                    // and is served at the next event.
                    Err(_) => return,
                };
                self.with(|i| match (listed(i), permit) {
                    (true, permit) => {
                        i.core.unlist(session);
                        let reply = GateReply {
                            id: waiter.id,
                            answers: vec![GateAnswer::Acquired(permit)],
                            load: i.core.load(now),
                            unowned,
                            failed: false,
                            waiting: false,
                            wake: None,
                        };
                        i.pushes.push((session, reply));
                    }
                    // Its session ended while the slot was taken.
                    (false, Some(permit)) => i.core.release(&permit, session),
                    (false, None) => {}
                });
                break;
            }
        }
    }

    /// In how many milliseconds a job slot can next come free with no
    /// event at the gate: the first slot that runs out unrenewed, or,
    /// after a restart, the end of the wait in which no job gets one
    /// (that of either class: [`Warm`]).
    fn wake(&self, now: UnixMs) -> Option<i64> {
        self.with(|i| {
            let warm = i.record.warm_jobs.max(i.record.warm_reads);
            let next = match warm > now.0 {
                true => Some(warm),
                false => i.core.next_expiry(now.0),
            };
            next.map(|at| (at - now.0).max(1))
        })
    }

    /// Stores the record as it should be now.
    async fn persist(&self) -> Result<()> {
        let _one = self.saving.lock().await;
        let record = self.with(|i| i.record.clone());
        if self.with(|i| i.saved == record) {
            return Ok(());
        }
        self.store.save(&record).await?;
        self.with(|i| i.saved = record);
        Ok(())
    }

    /// Makes the stored horizon of a class cover an expiry before a
    /// slot with that expiry is promised.
    async fn cover(&self, background: bool, expiry: i64) -> Result<()> {
        let of = |r: &GateRecord| match background {
            true => r.jobs_until,
            false => r.reads_until,
        };
        // Until a save that covers it has come back.
        while self.with(|i| of(&i.saved) < expiry || of(&i.record) < expiry) {
            self.with(|i| {
                let until = match background {
                    true => &mut i.record.jobs_until,
                    false => &mut i.record.reads_until,
                };
                if *until < expiry {
                    *until = expiry + HORIZON_STEP_MS;
                }
            });
            self.persist().await?;
        }
        Ok(())
    }

    fn warm(&self, now: UnixMs) -> Warm {
        let warm = |r: &GateRecord| (now.0 < r.warm_reads, now.0 < r.warm_jobs);
        self.with(|i| match warm(&i.record) {
            (true, _) => Warm::All,
            (false, true) => Warm::Jobs,
            (false, false) => Warm::Done,
        })
    }

    fn owned(&self, p: &GateProvider) -> bool {
        self.with(|i| i.owned(p))
    }

    /// Seizes the free slot rows of `p` and records whether every row
    /// of it is this gate's now. At most one attempt per provider every
    /// [`SEIZE_EVERY_MS`], and never two at once.
    async fn seize(&self, p: &GateProvider, now: UnixMs) -> Result<()> {
        let due = self.with(|i| {
            let due = i
                .seize_tried
                .get(&p.part_name())
                .is_none_or(|at| now.0 - *at >= SEIZE_EVERY_MS || now.0 < *at);
            if due {
                i.seize_tried.insert(p.part_name(), now.0);
            }
            due
        });
        let Some(name) = self.with(|i| i.name.clone()).filter(|_| due) else {
            return Ok(());
        };
        let _one = self.owning.lock().await;
        if self.with(|i| i.record.mode != GateMode::Active) {
            return Ok(());
        }
        let (holder, idle) = (gate_holder(&name), gate_idle_holder(&name));
        let pool = match p.pool_limit() {
            Some((pool, _)) => text(pool),
            None => SqlValue::Null,
        };
        self.sql
            .batch(vec![
                (
                    SEED,
                    vec![text(&p.id), SqlValue::Int(i64::from(p.max_conns))],
                ),
                (WAKE, vec![text(&idle), text(&holder)]),
                (
                    SEIZE,
                    vec![
                        text(&p.id),
                        text(&holder),
                        SqlValue::Int(SEIZED_UNTIL_MS),
                        SqlValue::Int(now.0),
                        pool,
                        SqlValue::Int(i64::from(p.shards.max(1))),
                        SqlValue::Int(i64::from(p.shard)),
                    ],
                ),
            ])
            .await?;
        let rows = self
            .sql
            .query(
                OWNED,
                &[
                    text(&p.id),
                    text(&holder),
                    SqlValue::Int(now.0),
                    SqlValue::Int(i64::from(p.shards.max(1))),
                    SqlValue::Int(i64::from(p.shard)),
                    text(&gate_holder(unit_prefix(&name))),
                    text(&gate_idle_holder(unit_prefix(&name))),
                ],
            )
            .await?;
        let row = rows
            .first()
            .ok_or_else(|| BridgeError::Sql("gate: no count".into()))?;
        let (part, mine, all, gates) = (int(row, 0)?, int(row, 1)?, int(row, 2)?, int(row, 3)?);
        let whole = part == mine
            && part >= i64::from(p.count(0..p.max_conns))
            && all == gates
            && all >= i64::from(p.max_conns);
        // Under the lock still: a retirement has not come between.
        self.with(|i| match whole && i.record.mode == GateMode::Active {
            true => {
                let n = u32::try_from(part).unwrap_or(u32::MAX);
                i.record.seized.insert(p.part_name(), n);
            }
            false => {
                i.record.seized.remove(&p.part_name());
            }
        });
        Ok(())
    }

    /// Whether `p` and every account of its pool are this gate's,
    /// after one attempt to seize those that are not.
    async fn own(&self, p: &GateProvider, peers: &[GateProvider], now: UnixMs) -> Result<bool> {
        let mut all = true;
        for q in core::iter::once(p).chain(peers) {
            if !self.owned(q) {
                self.seize(q, now).await?;
                all &= self.owned(q);
            }
        }
        self.persist().await?;
        // Checked again as one step: a retirement may have come in
        // while the catalogue was asked.
        Ok(all && core::iter::once(p).chain(peers).all(|q| self.owned(q)))
    }

    async fn acquire(
        &self,
        p: &GateProvider,
        peers: &[GateProvider],
        background: bool,
        holder: &str,
        session: u64,
        now: UnixMs,
    ) -> Result<core::result::Result<Option<GatePermit>, Unowned>> {
        if core::iter::once(p)
            .chain(peers)
            .any(|q| q.shard >= q.shards.max(1))
        {
            return Err(BridgeError::Invalid("gate asked for a part that is none"));
        }
        match self.with(|i| i.record.mode) {
            GateMode::Retired => return Ok(Err(Unowned)),
            GateMode::Active => {}
            GateMode::Unset => self.with(|i| i.record.mode = GateMode::Active),
        }
        if !self.own(p, peers, now).await? {
            return Ok(Err(Unowned));
        }
        let warm = self.warm(now);
        // Nothing free: nothing is promised, and the horizon stays. A
        // class that only ever asked has no slot to wait out after a
        // deploy.
        let free = self.with(|i| i.core.free(p, peers, background, holder, now, warm));
        if free.is_none() {
            return Ok(Ok(None));
        }
        self.cover(background, now.0 + ttl_ms(background)).await?;
        let warm = self.warm(now);
        // One step, with nothing awaited: the mode, the ownership and
        // the horizon are those of this moment.
        Ok(self.with(|i| {
            let horizon = match background {
                true => i.saved.jobs_until.min(i.record.jobs_until),
                false => i.saved.reads_until.min(i.record.reads_until),
            };
            let owned = core::iter::once(p).chain(peers).all(|q| i.owned(q));
            if i.record.mode != GateMode::Active || !owned {
                return Err(Unowned);
            }
            if horizon < now.0 + ttl_ms(background) {
                return Ok(None);
            }
            let taken = i
                .core
                .acquire(p, peers, background, (holder, session), now, warm);
            let Some(permit) = taken else {
                return Ok(None);
            };
            // What the host cannot keep with the session is not handed
            // out on it.
            let state = SessionState {
                id: session,
                seen: now.0,
                held: i.core.of_session(session, now.0),
                wait: None,
            };
            if !state.fits() {
                i.core.release(&permit, session);
                return Ok(None);
            }
            Ok(Some(permit))
        }))
    }

    async fn renew(&self, permits: &[GatePermit], session: u64, now: UnixMs) -> Result<Vec<bool>> {
        for background in [true, false] {
            let any = self.with(|i| {
                permits
                    .iter()
                    .any(|p| i.core.class_of(p, session, now.0) == Some(background))
            });
            if any {
                self.cover(background, now.0 + ttl_ms(background)).await?;
            }
        }
        Ok(self.with(|i| {
            permits
                .iter()
                .map(|p| {
                    let class = i.core.class_of(p, session, now.0);
                    let covered = class.is_some_and(|background| {
                        let horizon = match background {
                            true => i.saved.jobs_until.min(i.record.jobs_until),
                            false => i.saved.reads_until.min(i.record.reads_until),
                        };
                        horizon >= now.0 + ttl_ms(background)
                    });
                    covered && i.core.renew(p, session, now)
                })
                .collect()
        }))
    }

    async fn activate(&self, providers: &[GateProvider], now: UnixMs) -> Result<bool> {
        // Back in charge: what it owned before is asked again, at once.
        self.with(|i| {
            if i.record.mode != GateMode::Active {
                i.record.mode = GateMode::Active;
                i.record.seized.clear();
                i.seize_tried.clear();
            }
        });
        // Asked of the catalogue again, owned or not: a start goes by
        // the stored record, and this step is where a change made to
        // the rows behind the gate's back comes to light.
        for p in providers {
            self.seize(p, now).await?;
        }
        self.persist().await?;
        Ok(providers.iter().all(|p| self.owned(p)))
    }

    /// Stops handing out. Once nothing is held and nothing from before
    /// a restart can be, the seized rows are freed. Slots still held
    /// may be renewed until their holders are done.
    async fn retire(&self, now: UnixMs) -> Result<bool> {
        self.with(|i| i.record.mode = GateMode::Retired);
        self.persist().await?;
        let _one = self.owning.lock().await;
        let warm = self.warm(now);
        // One step: nothing is held, nothing from before a restart can
        // be, and from here on nothing is owned, so nothing is handed
        // out until the rows have been seized again.
        let idle = self.with(|i| {
            let idle =
                i.record.mode == GateMode::Retired && i.core.live(now) == 0 && warm == Warm::Done;
            if idle {
                i.record.seized.clear();
            }
            idle
        });
        let Some(name) = self.with(|i| i.name.clone()).filter(|_| idle) else {
            return Ok(false);
        };
        self.persist().await?;
        // Its rows stay held, under the retired name, until every gate
        // of the account or pool is done: then all of them are freed in
        // one statement. A gate of it that still hands out counts on
        // no catalogue caller being on the account.
        let unit = unit_prefix(&name);
        self.sql
            .batch(vec![
                (
                    IDLE,
                    vec![text(&gate_holder(&name)), text(&gate_idle_holder(&name))],
                ),
                (
                    HAND_BACK,
                    vec![text(&gate_idle_holder(unit)), text(&gate_holder(unit))],
                ),
            ])
            .await?;
        Ok(true)
    }

    /// Answers one request at `now`, the object's own clock. `session`:
    /// the session it came on ([`Self::open`]), or `None` for a request
    /// on its own, which can take no slot.
    pub async fn handle(
        &self,
        session: Option<u64>,
        request: GateRequest,
        now: UnixMs,
    ) -> Result<GateReply> {
        self.resume(Vec::new(), now).await?;
        self.with(|i| {
            i.name.get_or_insert(request.gate.clone());
        });
        if self.with(|i| i.name.as_deref() != Some(request.gate.as_str())) {
            return Err(BridgeError::Invalid("gate asked under another name"));
        }
        // What ran out since the last event goes to the line first.
        self.serve(now).await;
        let (mut taken, mut unowned) = (Vec::new(), false);
        let asked = (session, request.id, request.ops.as_slice());
        let answers = self.answer(asked, now, &mut taken, &mut unowned).await;
        if let (Err(_), Some(session)) = (&answers, session) {
            // The caller learns of none of them, nor that it waits.
            self.with(|i| {
                taken.iter().for_each(|p| i.core.release(p, session));
                if i.core.waiter(session).is_some_and(|w| w.id == request.id) {
                    i.core.unlist(session);
                }
            });
            // What a request that went on beside this one waits for
            // may be what was just undone.
            self.serve(now).await;
        }
        let answers = answers?;
        // Its own turn in the line came with this request (it asked
        // again while it waited): that reply is this one.
        let served = session.and_then(|session| {
            self.with(|i| {
                let mine = |(s, r): &(u64, GateReply)| *s == session && r.id == request.id;
                let at = i.pushes.iter().position(mine)?;
                Some(i.pushes.remove(at).1)
            })
        });
        if let Some(reply) = served {
            return Ok(reply);
        }
        let waiting =
            session.is_some_and(|session| self.with(|i| i.core.waiter(session).is_some()));
        Ok(GateReply {
            id: request.id,
            answers,
            load: self.with(|i| i.core.load(now)),
            unowned,
            failed: false,
            waiting,
            wake: match waiting {
                true => self.wake(now),
                false => None,
            },
        })
    }

    /// `asked`: the session, the id of the request and its questions.
    async fn answer(
        &self,
        asked: (Option<u64>, u64, &[GateOp]),
        now: UnixMs,
        taken: &mut Vec<GatePermit>,
        unowned: &mut bool,
    ) -> Result<Vec<GateAnswer>> {
        let (session, id, ops) = asked;
        let mut answers = Vec::with_capacity(ops.len());
        for op in ops {
            answers.push(match op {
                GateOp::Acquire {
                    provider,
                    peers,
                    background,
                    holder,
                } => {
                    let session = session
                        .ok_or(BridgeError::Invalid("gate asked for a slot on no session"))?;
                    let permit = self
                        .acquire(provider, peers, *background, holder, session, now)
                        .await?
                        .unwrap_or_else(|Unowned| {
                            *unowned = true;
                            None
                        });
                    taken.extend(permit.clone());
                    GateAnswer::Acquired(permit)
                }
                // Nothing is held on no session.
                GateOp::Renew { permits } => GateAnswer::Renewed(match session {
                    Some(session) => self.renew(permits, session, now).await?,
                    None => vec![false; permits.len()],
                }),
                GateOp::Release { permits } => {
                    if let Some(session) = session {
                        self.with(|i| permits.iter().for_each(|p| i.core.release(p, session)));
                        // Before a later question of this request can
                        // take what it gave back.
                        self.serve(now).await;
                    }
                    GateAnswer::Released
                }
                GateOp::Wait { wants, holder, ms } => {
                    let session = session
                        .ok_or(BridgeError::Invalid("gate asked for a slot on no session"))?;
                    let (mut permit, mut mine) = (None, true);
                    for want in wants {
                        let (provider, peers) = (&want.provider, &want.peers);
                        let asked = self.acquire(provider, peers, true, holder, session, now);
                        match asked.await? {
                            Ok(Some(taken)) => {
                                permit = Some(taken);
                                break;
                            }
                            Ok(None) => {}
                            Err(Unowned) => {
                                *unowned = true;
                                mine = false;
                            }
                        }
                    }
                    taken.extend(permit.clone());
                    // No caller waits longer than its invocation lives.
                    let until = now.0 + (*ms).clamp(0, crate::jobtable::JOB_WAIT_MS);
                    self.with(|i| {
                        // Nothing is waited for at a gate that is not in
                        // charge of every account asked: the rollout
                        // step is due, and the caller asks the old way.
                        if permit.is_some() || !mine || wants.is_empty() {
                            i.core.unlist(session);
                            return;
                        }
                        i.core.enlist(session, id, holder, wants, until);
                        // A wait the host cannot keep with the session
                        // is not begun.
                        let state = SessionState {
                            id: session,
                            seen: now.0,
                            held: i.core.of_session(session, now.0),
                            wait: i.core.waiter(session).cloned(),
                        };
                        if !state.fits() {
                            i.core.unlist(session);
                        }
                    });
                    GateAnswer::Acquired(permit)
                }
                GateOp::Load => GateAnswer::Load(self.with(|i| i.core.load(now))),
                GateOp::Activate { providers } => {
                    GateAnswer::Activated(self.activate(providers, now).await?)
                }
                GateOp::Retire => GateAnswer::Retired(self.retire(now).await?),
            });
        }
        Ok(answers)
    }

    /// The record as it should be stored (for tests and status).
    pub fn record(&self) -> Option<GateRecord> {
        self.inner.borrow().as_ref().map(|i| i.record.clone())
    }
}

/// The gate is not in charge of the account asked for.
struct Unowned;

impl Inner {
    /// Every slot row of this part of `p` is the gate's.
    fn owned(&self, p: &GateProvider) -> bool {
        self.record
            .seized
            .get(&p.part_name())
            .is_some_and(|n| *n >= p.count(0..p.max_conns))
    }
}

// ---------------------------------------------------------------------------
// The caller's side
// ---------------------------------------------------------------------------

/// Which permits a deployment uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermitMode {
    /// The catalogue's slot rows.
    Catalog,
    /// The gates.
    Gate,
}

impl PermitMode {
    /// `PERMITS`: `d1` (also when unset) or `do`.
    pub fn from_var(raw: Option<&str>) -> core::result::Result<Self, String> {
        match raw.map(str::trim) {
            None | Some("") | Some("d1") => Ok(PermitMode::Catalog),
            Some("do") => Ok(PermitMode::Gate),
            Some(_) => Err("PERMITS must be d1 or do".to_string()),
        }
    }
}

/// How providers are spread over gates.
///
/// A limit can only be kept by the one gate that sees everything under
/// it, so the unit is what a limit covers: an account, or the pool of
/// accounts that share `pool_max_conns`. A unit that needs more than
/// one object can answer is divided further ([`MAX_GATE_SHARDS`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateSharding {
    /// Gates per account, and per pool of accounts that share a limit.
    Account,
    /// The same gates for every provider: the fewest objects.
    One,
}

/// The most gates one account or pool can be divided over.
pub const MAX_GATE_SHARDS: u32 = 64;

/// `PERMIT_SHARDS`: how many gates share one account or pool, 1 (also
/// when unset) to [`MAX_GATE_SHARDS`].
pub fn shards_from_var(raw: Option<&str>) -> core::result::Result<u32, String> {
    match raw.map(str::trim) {
        None | Some("") => Ok(1),
        Some(raw) => match raw.parse::<u32>() {
            Ok(n) if (1..=MAX_GATE_SHARDS).contains(&n) => Ok(n),
            _ => Err(format!("PERMIT_SHARDS must be 1 to {MAX_GATE_SHARDS}")),
        },
    }
}

/// `SLOT_WAIT`: `poll` (also when unset) or `push`. `true` for `push`:
/// a job that finds no slot waits in the line of its gates
/// ([`PermitGate::wait`]). It changes nothing where the permits are
/// the catalogue's (`PERMITS = "d1"`).
pub fn slot_wait_from_var(raw: Option<&str>) -> core::result::Result<bool, String> {
    match raw.map(str::trim) {
        None | Some("") | Some("poll") => Ok(false),
        Some("push") => Ok(true),
        Some(_) => Err("SLOT_WAIT must be poll or push".to_string()),
    }
}

impl GateSharding {
    /// `PERMIT_GATES`: `account` (also when unset) or `one`.
    pub fn from_var(raw: Option<&str>) -> core::result::Result<Self, String> {
        match raw.map(str::trim) {
            None | Some("") | Some("account") => Ok(GateSharding::Account),
            Some("one") => Ok(GateSharding::One),
            Some(_) => Err("PERMIT_GATES must be account or one".to_string()),
        }
    }

    /// What `p` shares its gates with: every provider of the same unit
    /// has the same answer.
    pub fn unit_of(self, p: &GateProvider) -> String {
        match (self, p.pool_limit()) {
            (GateSharding::One, _) => "all".to_string(),
            (GateSharding::Account, Some((pool, _))) => format!("pool.{pool}"),
            (GateSharding::Account, None) => format!("account.{}", p.id),
        }
    }
}

/// The name of the gate that serves part `shard` of `unit`.
pub fn gate_name(unit: &str, shard: u32) -> String {
    format!("permits:{unit}:{shard}")
}

/// Where a holder starts to ask among the gates of a unit (FNV-1a).
/// The connections of one invocation then meet in one gate, where they
/// count as one address.
fn first_shard(holder: &str, shards: u32) -> u32 {
    let hash = holder.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    (hash % u64::from(shards.max(1))) as u32
}

/// How long a caller goes by what a gate last told it of its load.
pub const HINT_MS: i64 = 30_000;

/// A session this caller has not used for this long belongs to an
/// invocation that has ended, and is forgotten: no slot outlives its
/// last renewal by more than the lifetime of its class.
pub const LINK_IDLE_MS: i64 = PERMIT_SECS as i64 * 1000 + 30_000;

/// An open session with one gate: the slots a holder takes there are
/// taken, renewed and given back on it, and the gate frees them all
/// when it ends. On Workers it is a WebSocket to the object, which
/// costs a request to open and a twentieth of one per message after.
#[allow(async_fn_in_trait)]
pub trait GateSession {
    /// One request and its reply. An error ends the session.
    async fn call(&self, request: GateRequest) -> Result<GateReply>;
    /// The next reply the gate sends under `id`, the id of a request
    /// it has answered already with [`GateReply::waiting`]. A session
    /// that cannot be sent to says so at once.
    async fn pushed(&self, _id: u64) -> Result<GateReply> {
        Err(BridgeError::Sql("gate: no reply follows".into()))
    }
    /// Ends the session. Nothing is awaited.
    fn close(&self);
}

/// The way to the gates.
#[allow(async_fn_in_trait)]
pub trait GateTransport {
    type Session: GateSession;
    /// Opens a session with the gate named in `request`. The request
    /// travels with the opening: one round trip for both.
    async fn open(&self, request: GateRequest) -> Result<(Self::Session, GateReply)>;
    /// One request outside any session. It can take no slot.
    async fn call(&self, request: GateRequest) -> Result<GateReply>;
}

/// The permit calls of the catalogue, answered by gates. Object-safe,
/// so the catalogue can hold one whatever the transport is.
pub trait PermitGate {
    /// `false`: the catalogue's own slot rows are used, and this gate
    /// is only told to retire ([`Self::sweep`]).
    fn active(&self) -> bool;
    fn acquire<'a>(
        &'a self,
        p: &'a ProviderConfig,
        class: PermitClass,
        holder: &'a str,
    ) -> LocalBoxFuture<'a, Result<Option<Permit>>>;
    fn renew<'a>(&'a self, permits: &'a [Permit]) -> LocalBoxFuture<'a, Result<Vec<bool>>>;
    fn release<'a>(&'a self, permit: &'a Permit) -> LocalBoxFuture<'a, Result<()>>;
    /// Waits up to `ms` in the lines of the gates of `providers` for a
    /// job slot for `holder`, which holds none there.
    /// [`SlotWait::Granted`]: one came, and the next
    /// [`Self::acquire`] of `holder` on its provider returns it.
    /// Dropped or out of time, nothing is held and no line has the
    /// caller. [`SlotWait::Unsupported`]: no line is kept (the switch
    /// is off, or a gate could not), and the caller asks again later
    /// as it did before.
    fn wait<'a>(
        &'a self,
        providers: &'a [&'a ProviderConfig],
        holder: &'a str,
        ms: i64,
        sleep: &'a Sleeper,
    ) -> LocalBoxFuture<'a, Result<SlotWait>>;
    /// `holder` has stopped. A slot that came to it from a line and
    /// that it never asked for is given up as by [`Self::forget`]: its
    /// session, which holds nothing else, is closed, and the gate
    /// hands the slot to the next in the line.
    fn leave(&self, holder: &str);
    /// The holder of `permit` is gone without having released it (its
    /// job was abandoned). Nothing is awaited: the session is closed
    /// if this was the last slot on it, and the gate frees what was
    /// held on a session that closes; otherwise the slot expires.
    fn forget(&self, permit: &Permit);
    /// What every gate holds, asked now: a request per gate.
    fn load(&self) -> LocalBoxFuture<'_, Result<Vec<GateLoad>>>;
    /// What the gates last said they hold, in replies to this caller no
    /// older than [`HINT_MS`]. Nothing is asked.
    fn hint(&self, now: UnixMs) -> Vec<GateLoad>;
    /// Whether a gate has said, since this was last asked, that it is
    /// not in charge of an account it was asked for a slot on.
    fn unowned(&self) -> bool;
    /// The periodic step of a rollout. `seized_by`: the gates that hold
    /// slot rows in the catalogue. In gate mode every gate in use is
    /// told it is in charge and every other gate that holds rows is
    /// retired; in catalogue mode all of them are retired.
    fn sweep<'a>(&'a self, seized_by: &'a [String]) -> LocalBoxFuture<'a, Result<()>>;
}

/// Where the answer to one queued question arrives.
#[derive(Default)]
struct Slot {
    answer: Option<Result<GateAnswer>>,
    /// The call that carried the question was dropped before its
    /// answer came.
    lost: bool,
    /// The caller that asked was dropped.
    gone: bool,
    waker: Option<core::task::Waker>,
}

type Waiting = (GateOp, Rc<RefCell<Slot>>);

/// The questions one request carries. Dropped without their answers,
/// they are marked lost, so that their callers ask again.
struct Carried(Vec<Rc<RefCell<Slot>>>);

impl Carried {
    fn settle(&mut self, mut answer: impl FnMut() -> Option<Result<GateAnswer>>) {
        for slot in self.0.drain(..) {
            let mut slot = slot.borrow_mut();
            match answer() {
                Some(answer) => slot.answer = Some(answer),
                None => slot.lost = true,
            }
            if let Some(waker) = slot.waker.take() {
                waker.wake();
            }
        }
    }
}

impl Drop for Carried {
    fn drop(&mut self) {
        self.settle(|| None);
    }
}

/// The gate a question goes to and, for a question that is asked on a
/// session, the holder whose session it is.
type Channel = (String, Option<String>);

/// This caller's session with one gate for one holder.
struct Link<S> {
    /// `None` until the first slot is asked for, and after the session
    /// has ended.
    session: Option<Rc<S>>,
    /// The tokens of the slots held on it.
    tokens: BTreeSet<u64>,
    used: i64,
    /// One request at a time: replies come back in order.
    turn: Rc<AsyncMutex<()>>,
}

/// The sessions of a caller, by gate and holder.
type Links<S> = BTreeMap<(String, String), Link<S>>;

/// Talks to the gates. Calls made together (the permits of a job's
/// sockets, taken, renewed or given back at once) travel as one request
/// per gate, and all of a holder's requests to one gate on one session.
pub struct GateClient<T: GateTransport> {
    transport: T,
    clock: Box<dyn Fn() -> UnixMs>,
    mode: PermitMode,
    sharding: GateSharding,
    shards: u32,
    providers: Vec<GateProvider>,
    queue: RefCell<BTreeMap<Channel, Vec<Waiting>>>,
    links: RefCell<Links<T::Session>>,
    /// What each gate last said it holds, and when.
    hints: RefCell<BTreeMap<String, (i64, Vec<GateLoad>)>>,
    unowned: core::cell::Cell<bool>,
    next_id: core::cell::Cell<u64>,
    /// Jobs wait in the gates' lines ([`PermitGate::wait`]).
    push: bool,
    /// Slots that came from a line and were not asked for yet: each
    /// with its holder and the time it came.
    pocket: RefCell<Vec<(String, Permit, i64)>>,
}

/// A session in a gate's line. Dropped before its slot came (the
/// caller's time ran out, or its job was abandoned), it ends the
/// session: the gate takes it out of the line and frees a slot that
/// was on its way.
struct Queued<'a, T: GateTransport> {
    client: &'a GateClient<T>,
    key: (String, String),
    session: Option<Rc<T::Session>>,
}

impl<T: GateTransport> Drop for Queued<'_, T> {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            session.close();
        }
        // The link is this call's to remove, as in `converse`: not
        // while another call waits for its turn on it.
        let Ok(mut links) = self.client.links.try_borrow_mut() else {
            return;
        };
        let idle = |link: &Link<T::Session>| {
            link.session.is_none() && link.tokens.is_empty() && Rc::strong_count(&link.turn) <= 2
        };
        if links.get(&self.key).is_some_and(idle) {
            links.remove(&self.key);
        }
    }
}

/// Returns `Pending` once, so that calls started together are all in
/// the queue before the first of them sends it.
/// Marks its slot when the caller that asked is dropped.
struct Asking(Rc<RefCell<Slot>>);

impl Drop for Asking {
    fn drop(&mut self) {
        self.0.borrow_mut().gone = true;
    }
}

// Resumes in the same round of the event loop it was awaited in: a
// batch is made of the calls one request started together, never of
// those of a later request.
struct YieldOnce(bool);

impl core::future::Future for YieldOnce {
    type Output = ();
    fn poll(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<()> {
        if self.0 {
            return core::task::Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        core::task::Poll::Pending
    }
}

/// One line per provider: the sum over the gates that serve parts of
/// it.
fn sum_load(parts: Vec<GateLoad>) -> Vec<GateLoad> {
    let mut load: BTreeMap<String, GateLoad> = BTreeMap::new();
    for part in parts {
        match load.get_mut(&part.provider) {
            Some(sum) => {
                sum.held += part.held;
                sum.holders += part.holders;
                sum.background_holders += part.background_holders;
                sum.uses += part.uses;
            }
            None => {
                load.insert(part.provider.clone(), part);
            }
        }
    }
    load.into_values().collect()
}

fn unexpected() -> BridgeError {
    BridgeError::Sql("gate: unexpected answer".into())
}

fn refused() -> BridgeError {
    BridgeError::Sql("gate: request not answered".into())
}

impl<T: GateTransport> GateClient<T> {
    pub fn new(
        transport: T,
        clock: impl Fn() -> UnixMs + 'static,
        mode: PermitMode,
        sharding: GateSharding,
        shards: u32,
        providers: &[ProviderConfig],
    ) -> Self {
        GateClient {
            transport,
            clock: Box::new(clock),
            links: RefCell::new(BTreeMap::new()),
            hints: RefCell::new(BTreeMap::new()),
            unowned: core::cell::Cell::new(false),
            next_id: core::cell::Cell::new(0),
            push: false,
            pocket: RefCell::new(Vec::new()),
            mode,
            sharding,
            shards: shards.clamp(1, MAX_GATE_SHARDS),
            providers: providers.iter().map(GateProvider::from).collect(),
            queue: RefCell::new(BTreeMap::new()),
        }
    }

    /// `SLOT_WAIT`: with `true` (`push`) a job that finds no slot
    /// waits in the gates' lines ([`PermitGate::wait`]).
    pub fn with_push(mut self, push: bool) -> Self {
        self.push = push;
        self
    }

    pub fn into_gate(self) -> Rc<dyn PermitGate>
    where
        T: 'static,
    {
        Rc::new(self)
    }

    /// How many gates serve the unit of `p`: `PERMIT_SHARDS`, and no
    /// more than the smallest limit in the unit less its read reserve,
    /// so that every gate has a connection and an address to hand out
    /// to a job. Every provider of a unit has the same answer.
    fn shards_of(&self, p: &GateProvider) -> u32 {
        let unit = self.sharding.unit_of(p);
        self.providers
            .iter()
            .filter(|q| self.sharding.unit_of(q) == unit)
            .flat_map(|q| [Some(q.max_conns), q.max_ips, q.pool_max_conns])
            .flatten()
            .map(|limit| limit - reserve(limit))
            .fold(self.shards, u32::min)
            .max(1)
    }

    /// The gate that handed out `slot` of `provider`.
    fn gate_of_slot(&self, provider: &str, slot: u32) -> Result<String> {
        self.providers
            .iter()
            .find(|p| p.id == provider)
            .map(|p| gate_name(&self.sharding.unit_of(p), slot % self.shards_of(p)))
            .ok_or(BridgeError::Invalid("permit of an unknown provider"))
    }

    /// The gates in use, each with the parts of the providers it serves.
    fn gates(&self) -> BTreeMap<String, Vec<GateProvider>> {
        let mut gates: BTreeMap<String, Vec<GateProvider>> = BTreeMap::new();
        for p in &self.providers {
            let (unit, shards) = (self.sharding.unit_of(p), self.shards_of(p));
            for shard in 0..shards {
                gates
                    .entry(gate_name(&unit, shard))
                    .or_default()
                    .push(p.part(shard, shards));
            }
        }
        gates
    }

    fn request(&self, gate: &str, ops: Vec<GateOp>) -> GateRequest {
        self.next_id.set(self.next_id.get().wrapping_add(1));
        GateRequest {
            id: self.next_id.get(),
            gate: gate.to_string(),
            ops,
        }
    }

    /// Notes what a reply says besides its answers.
    fn heard(&self, gate: &str, reply: &GateReply) {
        let now = (self.clock)().0;
        let mut hints = self.hints.borrow_mut();
        hints.insert(gate.to_string(), (now, reply.load.clone()));
        if reply.unowned {
            self.unowned.set(true);
        }
    }

    /// `session` is still the session of the link `key`.
    fn is_open(&self, key: &(String, String), session: &Rc<T::Session>) -> bool {
        let links = self.links.borrow();
        let now = links.get(key).and_then(|link| link.session.as_ref());
        now.is_some_and(|now| Rc::ptr_eq(now, session))
    }

    /// The session that holds `permit`, if this caller knows one.
    fn link_of(&self, permit: &Permit) -> Option<(String, String)> {
        let gate = self.gate_of_slot(&permit.provider, permit.slot).ok()?;
        let links = self.links.borrow();
        let mut held = links
            .iter()
            .filter(|((g, _), link)| *g == gate && link.tokens.contains(&permit.token));
        held.next().map(|(key, _)| key.clone())
    }

    async fn send(&self, channel: &Channel, ops: Vec<GateOp>) -> Result<Vec<GateAnswer>> {
        match channel {
            (gate, Some(holder)) => self.converse(gate, holder, ops).await,
            (gate, None) => {
                let n = ops.len();
                let reply = self.transport.call(self.request(gate, ops)).await?;
                self.heard(gate, &reply);
                match reply.answers.len() == n {
                    true => Ok(reply.answers),
                    false => Err(unexpected()),
                }
            }
        }
    }

    /// Sends `ops` on the session of `holder` with `gate`.
    ///
    /// Without a session, one is opened if a slot is asked for; nothing
    /// is held on a session that is not there, so a renewal is answered
    /// "not held" and a release is done, with no request. A session
    /// that fails has ended: the gate has freed what was held on it,
    /// and the request is answered as without one.
    async fn converse(
        &self,
        gate: &str,
        holder: &str,
        ops: Vec<GateOp>,
    ) -> Result<Vec<GateAnswer>> {
        let key = (gate.to_string(), holder.to_string());
        let now = (self.clock)().0;
        let fresh = || Link {
            session: None,
            tokens: BTreeSet::new(),
            used: now,
            turn: Rc::new(AsyncMutex::new(())),
        };
        let turn = {
            let mut links = self.links.borrow_mut();
            // Not closed: a session of an invocation that has ended is
            // not this one's to touch, and ended with it.
            // A session another invocation used a moment "after" this
            // one's clock is in use: see `UnixMs::within`.
            links
                .retain(|k, link| *k == key || UnixMs(now).within(UnixMs(link.used), LINK_IDLE_MS));
            let link = links.entry(key.clone()).or_insert_with(fresh);
            link.used = now;
            Rc::clone(&link.turn)
        };
        let _turn = turn.lock().await;
        let open = self
            .links
            .borrow()
            .get(&key)
            .and_then(|link| link.session.clone());
        let mut answers = None;
        if let Some(session) = open {
            match session.call(self.request(gate, ops.clone())).await {
                // The gate answered none of it and changed nothing:
                // the session and its slots stand, and the caller
                // asks again when it next would.
                Ok(reply) if reply.failed => return Err(refused()),
                // Not if the session was ended meanwhile (its last
                // permit was forgotten): the gate has freed what was
                // on it, this answer's slots too.
                Ok(reply) if reply.answers.len() == ops.len() && self.is_open(&key, &session) => {
                    self.heard(gate, &reply);
                    answers = Some(reply.answers);
                }
                _ => {
                    session.close();
                    if let Some(link) = self.links.borrow_mut().get_mut(&key) {
                        link.session = None;
                        link.tokens.clear();
                    }
                }
            }
        }
        let answers = match answers {
            Some(answers) => answers,
            None => {
                let wanted = |op: &&GateOp| matches!(op, GateOp::Acquire { .. });
                let asked: Vec<GateOp> = ops.iter().filter(wanted).cloned().collect();
                let mut taken = Vec::new();
                if !asked.is_empty() {
                    let n = asked.len();
                    let (session, reply) = self.transport.open(self.request(gate, asked)).await?;
                    if reply.failed || reply.answers.len() != n {
                        session.close();
                        return Err(unexpected());
                    }
                    self.heard(gate, &reply);
                    let mut links = self.links.borrow_mut();
                    let link = links.entry(key.clone()).or_insert_with(fresh);
                    link.session = Some(Rc::new(session));
                    taken = reply.answers;
                }
                let mut taken = taken.into_iter();
                ops.iter()
                    .map(|op| match op {
                        GateOp::Acquire { .. } => taken.next().ok_or_else(unexpected),
                        GateOp::Renew { permits } => {
                            Ok(GateAnswer::Renewed(vec![false; permits.len()]))
                        }
                        GateOp::Release { .. } => Ok(GateAnswer::Released),
                        _ => Err(unexpected()),
                    })
                    .collect::<Result<Vec<GateAnswer>>>()?
            }
        };
        let mut links = self.links.borrow_mut();
        if let Some(link) = links.get_mut(&key) {
            for (op, answer) in ops.iter().zip(&answers) {
                match (op, answer) {
                    (_, GateAnswer::Acquired(Some(permit))) => {
                        link.tokens.insert(permit.token);
                    }
                    (GateOp::Release { permits }, _) => {
                        permits.iter().for_each(|p| {
                            link.tokens.remove(&p.token);
                        });
                    }
                    (GateOp::Renew { permits }, GateAnswer::Renewed(held)) => {
                        for (p, _) in permits.iter().zip(held).filter(|(_, held)| !**held) {
                            link.tokens.remove(&p.token);
                        }
                    }
                    _ => {}
                }
            }
            // A session is open only while it holds a slot: it ends
            // with its last one, and one that was refused its first
            // ends at once. An open socket can keep the invocation that
            // opened it from ending, so none is left for the gate to
            // close.
            if link.tokens.is_empty() {
                if let Some(session) = link.session.take() {
                    session.close();
                }
                // Not while another call waits for its turn on it: a
                // call that came after would find no link, make one
                // with a turn of its own and run beside the waiter.
                // The last of them removes it.
                if Rc::strong_count(&link.turn) <= 2 {
                    links.remove(&key);
                }
            }
        }
        Ok(answers)
    }

    /// The other accounts of the pool of `p`.
    fn pool_of(&self, p: &GateProvider) -> Vec<&GateProvider> {
        match p.pool_limit() {
            Some((pool, _)) => {
                let same = |q: &&GateProvider| {
                    q.id != p.id && q.pool_limit().is_some_and(|(name, _)| name == pool)
                };
                self.providers.iter().filter(same).collect()
            }
            None => Vec::new(),
        }
    }

    /// The slot that came to `holder` from a line of `provider` and
    /// was not asked for yet, renewed now: who takes it counts it as
    /// taken at this time. What has lain for the lifetime of a slot is
    /// given up.
    async fn pocketed(&self, provider: &str, holder: &str) -> Option<Permit> {
        if self.pocket.borrow().is_empty() {
            return None;
        }
        let now = (self.clock)().0;
        let (mut found, mut old) = (None, Vec::new());
        self.pocket.borrow_mut().retain(|(by, permit, at)| {
            if !(0..ttl_ms(true)).contains(&(now - at)) {
                old.push(permit.clone());
                return false;
            }
            let mine = found.is_none() && by == holder && permit.provider == provider;
            if mine {
                found = Some(permit.clone());
            }
            !mine
        });
        old.iter().for_each(|permit| self.forget(permit));
        let permit = found?;
        let held = self.renew(core::slice::from_ref(&permit)).await;
        match held.ok().and_then(|held| held.first().copied()) {
            Some(true) => Some(permit),
            // Not renewed, or not known to be: given up, as it is in
            // no pocket any more and its session holds nothing else.
            _ => {
                self.forget(&permit);
                None
            }
        }
    }

    /// Waits in the line of `gate` on a session of its own. `true`: a
    /// slot came and is in the pocket. `false`: this gate keeps no line
    /// for the caller. It does not return while it waits: the caller
    /// bounds the wait and drops it.
    async fn wait_on(
        &self,
        gate: String,
        holder: &str,
        wants: Vec<GateWant>,
        ms: i64,
        sleep: &Sleeper,
    ) -> Result<bool> {
        let key = (gate.clone(), holder.to_string());
        let now = (self.clock)().0;
        let turn = {
            let mut links = self.links.borrow_mut();
            links.retain(|k, link| *k == key || (0..LINK_IDLE_MS).contains(&(now - link.used)));
            let link = links.entry(key.clone()).or_insert_with(|| Link {
                session: None,
                tokens: BTreeSet::new(),
                used: now,
                turn: Rc::new(AsyncMutex::new(())),
            });
            link.used = now;
            Rc::clone(&link.turn)
        };
        let _turn = turn.lock().await;
        let mut queued = Queued {
            client: self,
            key: key.clone(),
            session: None,
        };
        // Only on a session that holds nothing: the wait is ended by
        // ending the session.
        let held = |link: &Link<T::Session>| link.session.is_some() || !link.tokens.is_empty();
        if self.links.borrow().get(&key).is_some_and(held) {
            return Ok(false);
        }
        let wait = GateOp::Wait {
            wants,
            holder: holder.to_string(),
            ms,
        };
        let request = self.request(&gate, vec![wait]);
        let id = request.id;
        let (session, mut reply) = self.transport.open(request).await?;
        let session = Rc::new(session);
        queued.session = Some(Rc::clone(&session));
        loop {
            if reply.failed {
                return Ok(false);
            }
            self.heard(&gate, &reply);
            if let Some(GateAnswer::Acquired(Some(slot))) = reply.answers.first() {
                let now = (self.clock)().0;
                let mut links = self.links.borrow_mut();
                let link = links.entry(key).or_insert_with(|| Link {
                    session: None,
                    tokens: BTreeSet::new(),
                    used: now,
                    turn: Rc::clone(&turn),
                });
                link.session = queued.session.take();
                link.tokens.insert(slot.token);
                link.used = now;
                let permit = Permit {
                    provider: slot.provider.clone(),
                    slot: slot.slot,
                    token: slot.token,
                    class: PermitClass::Background,
                };
                let mut pocket = self.pocket.borrow_mut();
                pocket.push((holder.to_string(), permit, now));
                return Ok(true);
            }
            if !reply.waiting {
                return Ok(false);
            }
            if let Some(link) = self.links.borrow_mut().get_mut(&queued.key) {
                link.used = (self.clock)().0;
            }
            let again = GateRequest {
                id,
                gate: gate.clone(),
                ops: Vec::new(),
            };
            reply = match reply.wake {
                None => session.pushed(id).await?,
                Some(ms) => {
                    let nap = sleep(u32::try_from(ms).unwrap_or(u32::MAX));
                    match select(Box::pin(session.pushed(id)), nap).await {
                        Either::Left((reply, _)) => reply?,
                        // A slot may have run out with no word to the
                        // gate: it looks, and answers under the same
                        // id, with the slot if this is its turn.
                        Either::Right(_) => session.call(again).await?,
                    }
                }
            };
        }
    }

    /// Queues `op` for `gate` and sends the queue once every call that
    /// started with this one has joined it.
    async fn ask(&self, gate: &Channel, op: GateOp) -> Result<GateAnswer> {
        let slot = Rc::new(RefCell::new(Slot::default()));
        self.queue
            .borrow_mut()
            .entry(gate.clone())
            .or_default()
            .push((op.clone(), slot.clone()));
        let _asking = Asking(slot.clone());
        YieldOnce(false).await;
        let mut batch = self.queue.borrow_mut().remove(gate).unwrap_or_default();
        // Nobody is left to use a slot asked for by a caller that has
        // gone. What a gone caller gives back is still given back.
        batch.retain(|(op, slot)| !(slot.borrow().gone && matches!(op, GateOp::Acquire { .. })));
        if !batch.is_empty() {
            let (ops, slots): (Vec<GateOp>, Vec<_>) = batch.into_iter().unzip();
            let mut carried = Carried(slots);
            match self.send(gate, ops).await {
                Ok(answers) => {
                    let mut answers = answers.into_iter();
                    carried.settle(|| answers.next().map(Ok));
                }
                Err(e) => {
                    let text = e.to_string();
                    carried.settle(|| Some(Err(BridgeError::Sql(text.clone()))));
                }
            }
        }
        let answer = core::future::poll_fn(|cx| {
            let mut slot = slot.borrow_mut();
            match slot.answer.take() {
                Some(answer) => core::task::Poll::Ready(Some(answer)),
                None if slot.lost => core::task::Poll::Ready(None),
                None => {
                    slot.waker = Some(cx.waker().clone());
                    core::task::Poll::Pending
                }
            }
        })
        .await;
        match answer {
            Some(answer) => answer,
            // The call that carried this one was dropped before its
            // answer came (a renewal that took too long). Asked again
            // alone. A slot the dropped request took expires unused.
            None => self
                .send(gate, vec![op])
                .await?
                .pop()
                .ok_or_else(unexpected),
        }
    }
}

impl<T: GateTransport> PermitGate for GateClient<T> {
    fn active(&self) -> bool {
        self.mode == PermitMode::Gate
    }

    fn acquire<'a>(
        &'a self,
        p: &'a ProviderConfig,
        class: PermitClass,
        holder: &'a str,
    ) -> LocalBoxFuture<'a, Result<Option<Permit>>> {
        Box::pin(async move {
            if class == PermitClass::Background {
                if let Some(permit) = self.pocketed(&p.id, holder).await {
                    return Ok(Some(permit));
                }
            }
            let whole = GateProvider::from(p);
            let (unit, shards) = (self.sharding.unit_of(&whole), self.shards_of(&whole));
            let pool = self.pool_of(&whole);
            // The holder's own gate first, then the others in turn: a
            // gate that has nothing left is no reason to wait while
            // another has. Asked twice, a holder counts as an address
            // in both gates, which is never the looser count.
            let first = first_shard(holder, shards);
            for step in 0..shards {
                let shard = (first + step) % shards;
                let op = GateOp::Acquire {
                    provider: whole.part(shard, shards),
                    peers: pool.iter().map(|q| q.part(shard, shards)).collect(),
                    background: class == PermitClass::Background,
                    holder: holder.to_string(),
                };
                let channel = (gate_name(&unit, shard), Some(holder.to_string()));
                match self.ask(&channel, op).await? {
                    GateAnswer::Acquired(Some(g)) => {
                        return Ok(Some(Permit {
                            provider: g.provider,
                            slot: g.slot,
                            token: g.token,
                            class,
                        }))
                    }
                    GateAnswer::Acquired(None) => {}
                    _ => return Err(unexpected()),
                }
            }
            Ok(None)
        })
    }

    fn renew<'a>(&'a self, permits: &'a [Permit]) -> LocalBoxFuture<'a, Result<Vec<bool>>> {
        Box::pin(async move {
            // One question per session, asked together. A slot of no
            // session this caller has is not held: nothing is asked.
            let mut by_link: BTreeMap<Channel, Vec<usize>> = BTreeMap::new();
            for (i, p) in permits.iter().enumerate() {
                if let Some((gate, holder)) = self.link_of(p) {
                    by_link.entry((gate, Some(holder))).or_default().push(i);
                }
            }
            let answers = join_all(by_link.iter().map(|(channel, at)| {
                let permits = at.iter().map(|i| GatePermit::from(&permits[*i])).collect();
                self.ask(channel, GateOp::Renew { permits })
            }))
            .await;
            let mut held = vec![false; permits.len()];
            for ((_, at), answer) in by_link.iter().zip(answers) {
                match answer? {
                    GateAnswer::Renewed(renewed) if renewed.len() == at.len() => {
                        for (i, ok) in at.iter().zip(renewed) {
                            held[*i] = ok;
                        }
                    }
                    _ => return Err(unexpected()),
                }
            }
            Ok(held)
        })
    }

    fn release<'a>(&'a self, permit: &'a Permit) -> LocalBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Its session has ended, and the slot with it.
            let Some((gate, holder)) = self.link_of(permit) else {
                return Ok(());
            };
            // A slot that came to this holder from a line and that it
            // never asked for (it found one elsewhere first) goes back
            // with the first slot it gives back: sent together, so one
            // request for each gate. One that cannot be given back
            // runs out.
            let mut left: Vec<Permit> = Vec::new();
            self.pocket.borrow_mut().retain(|(by, slot, _)| {
                let mine = *by == holder;
                if mine {
                    left.push(slot.clone());
                }
                !mine
            });
            let back = |slot: &Permit| GateOp::Release {
                permits: vec![GatePermit::from(slot)],
            };
            let extras = left.iter().filter_map(|slot| {
                let (gate, holder) = self.link_of(slot)?;
                let channel = (gate, Some(holder));
                Some(async move { self.ask(&channel, back(slot)).await })
            });
            let own = (gate, Some(holder.clone()));
            let (own, _) =
                futures_util::future::join(self.ask(&own, back(permit)), join_all(extras)).await;
            match own? {
                GateAnswer::Released => Ok(()),
                _ => Err(unexpected()),
            }
        })
    }

    fn wait<'a>(
        &'a self,
        providers: &'a [&'a ProviderConfig],
        holder: &'a str,
        ms: i64,
        sleep: &'a Sleeper,
    ) -> LocalBoxFuture<'a, Result<SlotWait>> {
        Box::pin(async move {
            if !self.push || self.mode != PermitMode::Gate || ms <= 0 {
                return Ok(SlotWait::Unsupported);
            }
            let mut by_gate: BTreeMap<String, Vec<GateWant>> = BTreeMap::new();
            for p in providers {
                let whole = GateProvider::from(*p);
                let (unit, shards) = (self.sharding.unit_of(&whole), self.shards_of(&whole));
                let pool = self.pool_of(&whole);
                for shard in 0..shards {
                    let want = GateWant {
                        provider: whole.part(shard, shards),
                        peers: pool.iter().map(|q| q.part(shard, shards)).collect(),
                    };
                    let line = by_gate.entry(gate_name(&unit, shard)).or_default();
                    line.push(want);
                }
            }
            let lines = by_gate.into_iter().map(|(gate, wants)| {
                let line: LocalBoxFuture<'_, Result<bool>> =
                    Box::pin(self.wait_on(gate, holder, wants, ms, sleep));
                line
            });
            let lines: Vec<_> = lines.collect();
            if lines.is_empty() {
                return Ok(SlotWait::Unsupported);
            }
            // The first slot that comes: the other lines are left, by
            // ending their sessions. A gate that keeps no line for the
            // caller ends them all: it asks every gate the old way.
            let first = async {
                match select_all(lines).await.0 {
                    Ok(true) => SlotWait::Granted,
                    Ok(false) | Err(_) => SlotWait::Unsupported,
                }
            };
            let timer = sleep(u32::try_from(ms).unwrap_or(u32::MAX));
            Ok(match select(Box::pin(first), timer).await {
                Either::Left((out, _)) => out,
                Either::Right(_) => SlotWait::Elapsed,
            })
        })
    }

    fn leave(&self, holder: &str) {
        let Ok(mut pocket) = self.pocket.try_borrow_mut() else {
            return;
        };
        let (left, kept) = pocket.drain(..).partition(|(by, ..)| by == holder);
        *pocket = kept;
        drop(pocket);
        let left: Vec<(String, Permit, i64)> = left;
        left.iter().for_each(|(_, permit, _)| self.forget(permit));
    }

    fn forget(&self, permit: &Permit) {
        let Some(key) = self.link_of(permit) else {
            return;
        };
        let Ok(mut links) = self.links.try_borrow_mut() else {
            return;
        };
        let Some(link) = links.get_mut(&key) else {
            return;
        };
        link.tokens.remove(&permit.token);
        if link.tokens.is_empty() {
            // A call still under way on it fails and is answered as
            // on no session; the link is that call's to remove.
            if let Some(session) = link.session.take() {
                session.close();
            }
            if Rc::strong_count(&link.turn) <= 1 {
                links.remove(&key);
            }
        }
    }

    fn load(&self) -> LocalBoxFuture<'_, Result<Vec<GateLoad>>> {
        Box::pin(async move {
            let gates = self.gates();
            let channels: Vec<Channel> = gates.into_keys().map(|gate| (gate, None)).collect();
            let answers = join_all(channels.iter().map(|c| self.ask(c, GateOp::Load))).await;
            let mut parts = Vec::new();
            for answer in answers {
                let GateAnswer::Load(part) = answer? else {
                    return Err(unexpected());
                };
                parts.extend(part);
            }
            Ok(sum_load(parts))
        })
    }

    fn hint(&self, now: UnixMs) -> Vec<GateLoad> {
        let hints = self.hints.borrow();
        let fresh = hints
            .values()
            .filter(|(at, _)| now.within(UnixMs(*at), HINT_MS));
        sum_load(fresh.flat_map(|(_, load)| load.iter().cloned()).collect())
    }

    fn unowned(&self) -> bool {
        self.unowned.replace(false)
    }

    fn sweep<'a>(&'a self, seized_by: &'a [String]) -> LocalBoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mine = match self.mode {
                PermitMode::Gate => self.gates(),
                PermitMode::Catalog => BTreeMap::new(),
            };
            // The others first: what they free, the gates in use seize.
            let mut first_error = Ok(());
            for gate in seized_by.iter().filter(|g| !mine.contains_key(*g)) {
                let alone = (gate.clone(), None);
                if let Err(e) = self.send(&alone, vec![GateOp::Retire]).await {
                    first_error = first_error.and(Err(e));
                }
            }
            for (gate, providers) in mine {
                let alone = (gate, None);
                let told = self.send(&alone, vec![GateOp::Activate { providers }]);
                if let Err(e) = told.await {
                    first_error = first_error.and(Err(e));
                }
            }
            first_error
        })
    }
}
