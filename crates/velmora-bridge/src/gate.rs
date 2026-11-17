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
//! # Losing the memory
//!
//! The object can be restarted at any time (a deploy, a move to another
//! machine) and comes back with no slots. Holders of the old slots may
//! still have connections open. Three things make that safe:
//!
//! - **Tokens never repeat.** They start from the time of the start, so
//!   a holder from before cannot renew or free a slot handed out after.
//!   Its next renewal is refused and it drops its socket.
//! - **A horizon is stored before any slot is promised**: one small
//!   record ([`GateRecord`]) with the latest time a job's slot and a
//!   read's slot may still be held. It moves in steps of
//!   [`HORIZON_STEP_MS`], so it is written once per step under load, and
//!   it is cleared once nothing is held ([`Gate::tick`]).
//! - **A start inside the horizon waits it out.** Until the old slots of
//!   a class must have expired (the horizon, and no later than one
//!   lifetime of the class after the start, since nothing renewed them)
//!   their places are counted as taken. Reads have short slots: after
//!   their wait, a read may use what jobs could never hold (the slot and
//!   the address kept back for reads) while the jobs' wait still runs.
//!
//! A start outside the horizon (the object was idle) waits for nothing.
//!
//! While a slot is live the object must stay in memory, or every pause
//! between two requests would be such a restart. The host keeps it
//! there for as long as [`Gate::next_wake`] names a time.
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

use futures_util::future::{join_all, LocalBoxFuture};
use futures_util::lock::Mutex as AsyncMutex;
use serde::{Deserialize, Serialize};

use crate::ports::{Permit, PermitClass, Sql, SqlValue, PERMIT_SECS, READ_PERMIT_SECS};
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

/// How long nothing has to be held before the horizon is cleared.
pub const LINGER_MS: i64 = 2_000;

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
    /// The gate's name. The object learns it from its callers.
    pub gate: String,
    pub ops: Vec<GateOp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReply {
    pub answers: Vec<GateAnswer>,
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

#[derive(Clone, Debug)]
struct Held {
    provider: String,
    slot: u32,
    token: u64,
    holder: String,
    background: bool,
    pool: Option<String>,
    until: i64,
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
    next_token: u64,
    uses: BTreeMap<String, u64>,
}

impl Core {
    /// `started`: the time of the start. Tokens count up from it, so
    /// they are above every token of an earlier start.
    pub fn new(started: UnixMs) -> Self {
        Core {
            held: Vec::new(),
            next_token: u64::try_from(started.0).unwrap_or(0) << 20,
            uses: BTreeMap::new(),
        }
    }

    fn prune(&mut self, now: i64) {
        self.held.retain(|h| h.until >= now);
    }

    /// Live slots at `now`.
    pub fn live(&mut self, now: UnixMs) -> usize {
        self.prune(now.0);
        self.held.len()
    }

    /// The latest expiry of a live slot.
    fn latest(&self) -> Option<i64> {
        self.held.iter().map(|h| h.until).max()
    }

    /// Takes a slot under every limit, or none.
    pub fn acquire(
        &mut self,
        p: &GateProvider,
        peers: &[GateProvider],
        background: bool,
        holder: &str,
        now: UnixMs,
        warm: Warm,
    ) -> Option<GatePermit> {
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
        let slot = match background {
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
        }?;
        self.next_token += 1;
        let token = self.next_token;
        self.held.push(Held {
            provider: p.id.clone(),
            slot,
            token,
            holder: holder.to_string(),
            background,
            pool: p.pool_limit().map(|(pool, _)| pool.to_string()),
            until: now.0 + ttl_ms(background),
        });
        *self.uses.entry(p.id.clone()).or_insert(0) += 1;
        Some(GatePermit {
            provider: p.id.clone(),
            slot,
            token,
        })
    }

    /// The class of a slot that `p` still holds at `now`.
    fn class_of(&self, p: &GatePermit, now: i64) -> Option<bool> {
        self.held
            .iter()
            .find(|h| h.provider == p.provider && h.slot == p.slot && h.token == p.token)
            .filter(|h| h.until >= now)
            .map(|h| h.background)
    }

    /// Extends a slot that is still held under this token by the
    /// lifetime of its class. `false`: the caller owns nothing.
    pub fn renew(&mut self, p: &GatePermit, now: UnixMs) -> bool {
        self.prune(now.0);
        match self
            .held
            .iter_mut()
            .find(|h| h.provider == p.provider && h.slot == p.slot && h.token == p.token)
        {
            Some(h) => {
                h.until = now.0 + ttl_ms(h.background);
                true
            }
            None => false,
        }
    }

    /// Frees the slot if this token still owns it.
    pub fn release(&mut self, p: &GatePermit) {
        self.held
            .retain(|h| !(h.provider == p.provider && h.slot == p.slot && h.token == p.token));
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
/// rows are seized or freed and when the mode changes: never per permit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GateRecord {
    /// No job's slot handed out so far is held after this time.
    pub jobs_until: i64,
    /// The same for the slots of reads.
    pub reads_until: i64,
    pub mode: GateMode,
    /// The accounts, or parts of accounts ([`GateProvider::part`]),
    /// whose slot rows are all this gate's, with their count. Stored
    /// for the log only: a start asks the catalogue again.
    pub seized: BTreeMap<String, u32>,
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
    /// Until when old jobs, and old reads, are counted as present.
    warm_jobs: i64,
    warm_reads: i64,
    /// Requests being answered. The horizon is not cleared under one.
    busy: u32,
    empty_since: Option<i64>,
    seize_tried: BTreeMap<String, i64>,
}

/// One gate: [`Core`] plus what makes a restart and a rollout safe.
/// Single-threaded; several requests may be in flight and interleave
/// where one of them waits for storage or for the catalogue.
pub struct Gate<S: Sql, D: GateStore> {
    sql: S,
    store: D,
    inner: RefCell<Option<Inner>>,
    /// One save at a time, each of the record as it is when it starts.
    saving: AsyncMutex<()>,
    /// One change of who owns slot rows at a time: a seizure and the
    /// freeing of a retirement never overlap.
    owning: AsyncMutex<()>,
}

struct Busy<'a>(&'a RefCell<Option<Inner>>);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        if let Some(inner) = self.0.borrow_mut().as_mut() {
            inner.busy = inner.busy.saturating_sub(1);
        }
    }
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
    pub fn new(sql: S, store: D) -> Self {
        Gate {
            sql,
            store,
            inner: RefCell::new(None),
            saving: AsyncMutex::new(()),
            owning: AsyncMutex::new(()),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let mut inner = self.inner.borrow_mut();
        f(inner.as_mut().expect("gate started"))
    }

    /// Reads the record once per start and decides what to wait for.
    async fn start(&self, now: UnixMs) -> Result<()> {
        if self.inner.borrow().is_some() {
            return Ok(());
        }
        let mut record = self.store.load().await?.unwrap_or_default();
        let saved = record.clone();
        // What the gate owned is asked of the catalogue again: the rows
        // may have changed hands while the gate was not in memory.
        record.seized.clear();
        let mut inner = self.inner.borrow_mut();
        if inner.is_some() {
            return Ok(());
        }
        // Slots from before the start cannot be renewed, so each class
        // is gone one lifetime after it at the latest, and at its
        // horizon if that is sooner.
        let wait = |until: i64, background: bool| match until + SKEW_MS > now.0 {
            true => until.min(now.0 + ttl_ms(background)) + SKEW_MS,
            false => 0,
        };
        *inner = Some(Inner {
            name: None,
            core: Core::new(now),
            warm_jobs: wait(record.jobs_until, true),
            warm_reads: wait(record.reads_until, false),
            saved,
            record,
            busy: 0,
            empty_since: None,
            seize_tried: BTreeMap::new(),
        });
        Ok(())
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
        // Until a save that covers it has come back and nothing has
        // lowered it since: a tick may be clearing the horizon.
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
        self.with(|i| match (now.0 < i.warm_reads, now.0 < i.warm_jobs) {
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
        now: UnixMs,
    ) -> Result<Option<GatePermit>> {
        if core::iter::once(p)
            .chain(peers)
            .any(|q| q.shard >= q.shards.max(1))
        {
            return Err(BridgeError::Invalid("gate asked for a part that is none"));
        }
        match self.with(|i| i.record.mode) {
            GateMode::Retired => return Ok(None),
            GateMode::Active => {}
            GateMode::Unset => self.with(|i| i.record.mode = GateMode::Active),
        }
        if !self.own(p, peers, now).await? {
            return Ok(None);
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
            if i.record.mode != GateMode::Active || !owned || horizon < now.0 + ttl_ms(background) {
                return None;
            }
            i.core.acquire(p, peers, background, holder, now, warm)
        }))
    }

    async fn renew(&self, permits: &[GatePermit], now: UnixMs) -> Result<Vec<bool>> {
        for background in [true, false] {
            let any = self.with(|i| {
                permits
                    .iter()
                    .any(|p| i.core.class_of(p, now.0) == Some(background))
            });
            if any {
                self.cover(background, now.0 + ttl_ms(background)).await?;
            }
        }
        Ok(self.with(|i| {
            permits
                .iter()
                .map(|p| {
                    let covered = i.core.class_of(p, now.0).is_some_and(|background| {
                        let horizon = match background {
                            true => i.saved.jobs_until.min(i.record.jobs_until),
                            false => i.saved.reads_until.min(i.record.reads_until),
                        };
                        horizon >= now.0 + ttl_ms(background)
                    });
                    covered && i.core.renew(p, now)
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
        for p in providers {
            if !self.owned(p) {
                self.seize(p, now).await?;
            }
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

    /// Answers one request at `now`, the object's own clock.
    pub async fn handle(&self, request: GateRequest, now: UnixMs) -> Result<GateReply> {
        self.start(now).await?;
        self.with(|i| {
            i.busy += 1;
            i.name.get_or_insert(request.gate.clone());
        });
        let _busy = Busy(&self.inner);
        if self.with(|i| i.name.as_deref() != Some(request.gate.as_str())) {
            return Err(BridgeError::Invalid("gate asked under another name"));
        }
        let mut taken = Vec::new();
        let answers = self.answer(&request.ops, now, &mut taken).await;
        if answers.is_err() {
            // The caller learns of none of them.
            self.with(|i| taken.iter().for_each(|p| i.core.release(p)));
        }
        self.with(|i| i.note_empty(now));
        Ok(GateReply { answers: answers? })
    }

    async fn answer(
        &self,
        ops: &[GateOp],
        now: UnixMs,
        taken: &mut Vec<GatePermit>,
    ) -> Result<Vec<GateAnswer>> {
        let mut answers = Vec::with_capacity(ops.len());
        for op in ops {
            answers.push(match op {
                GateOp::Acquire {
                    provider,
                    peers,
                    background,
                    holder,
                } => {
                    let permit = self
                        .acquire(provider, peers, *background, holder, now)
                        .await?;
                    taken.extend(permit.clone());
                    GateAnswer::Acquired(permit)
                }
                GateOp::Renew { permits } => GateAnswer::Renewed(self.renew(permits, now).await?),
                GateOp::Release { permits } => {
                    self.with(|i| permits.iter().for_each(|p| i.core.release(p)));
                    GateAnswer::Released
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

    /// Housekeeping between requests: once nothing has been held for
    /// [`LINGER_MS`] and nothing from before a restart can be, the
    /// horizon is cleared, so that the next start waits for nothing.
    pub async fn tick(&self, now: UnixMs) {
        if self.inner.borrow().is_none() {
            return;
        }
        let clear = self.with(|i| {
            i.note_empty(now);
            let clear = i.busy == 0
                && now.0 >= i.warm_jobs.max(i.warm_reads)
                && i.empty_since.is_some_and(|at| now.0 - at >= LINGER_MS)
                && [&i.record, &i.saved]
                    .iter()
                    .any(|r| r.jobs_until != 0 || r.reads_until != 0);
            if clear {
                i.record.jobs_until = 0;
                i.record.reads_until = 0;
            }
            clear
        });
        if clear {
            // A failed save is tried again by the next tick (the saved
            // copy still has the horizon): until then the stored
            // horizon is only later than it has to be.
            let _ = self.persist().await;
        }
    }

    /// The next time [`Self::tick`] has work, or `None`: the object may
    /// leave memory. While this is a time, the host must keep it there.
    pub fn next_wake(&self, now: UnixMs) -> Option<UnixMs> {
        let inner = self.inner.borrow();
        let i = inner.as_ref()?;
        let warm = i.warm_jobs.max(i.warm_reads);
        if now.0 < warm {
            return Some(UnixMs(warm));
        }
        if let Some(latest) = i.core.latest().filter(|until| *until >= now.0) {
            return Some(UnixMs(latest + 1));
        }
        let stored = |r: &GateRecord| r.jobs_until != 0 || r.reads_until != 0;
        (i.busy > 0 || stored(&i.record) || stored(&i.saved))
            .then(|| UnixMs(i.empty_since.unwrap_or(now.0) + LINGER_MS))
    }

    /// The record as it should be stored (for tests and status).
    pub fn record(&self) -> Option<GateRecord> {
        self.inner.borrow().as_ref().map(|i| i.record.clone())
    }
}

impl Inner {
    /// Every slot row of this part of `p` is the gate's.
    fn owned(&self, p: &GateProvider) -> bool {
        self.record
            .seized
            .get(&p.part_name())
            .is_some_and(|n| *n >= p.count(0..p.max_conns))
    }

    fn note_empty(&mut self, now: UnixMs) {
        match self.core.live(now) {
            0 => {
                self.empty_since.get_or_insert(now.0);
            }
            _ => self.empty_since = None,
        }
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

/// One request to the gate named in it.
#[allow(async_fn_in_trait)]
pub trait GateTransport {
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
    fn load(&self) -> LocalBoxFuture<'_, Result<Vec<GateLoad>>>;
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

/// Talks to the gates. Calls made together (the permits of a job's
/// sockets, taken, renewed or given back at once) travel as one request
/// per gate.
pub struct GateClient<T: GateTransport> {
    transport: T,
    mode: PermitMode,
    sharding: GateSharding,
    shards: u32,
    providers: Vec<GateProvider>,
    queue: RefCell<BTreeMap<String, Vec<Waiting>>>,
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

fn unexpected() -> BridgeError {
    BridgeError::Sql("gate: unexpected answer".into())
}

impl<T: GateTransport> GateClient<T> {
    pub fn new(
        transport: T,
        mode: PermitMode,
        sharding: GateSharding,
        shards: u32,
        providers: &[ProviderConfig],
    ) -> Self {
        GateClient {
            transport,
            mode,
            sharding,
            shards: shards.clamp(1, MAX_GATE_SHARDS),
            providers: providers.iter().map(GateProvider::from).collect(),
            queue: RefCell::new(BTreeMap::new()),
        }
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

    async fn send(&self, gate: &str, ops: Vec<GateOp>) -> Result<Vec<GateAnswer>> {
        let n = ops.len();
        let reply = self
            .transport
            .call(GateRequest {
                gate: gate.to_string(),
                ops,
            })
            .await?;
        match reply.answers.len() == n {
            true => Ok(reply.answers),
            false => Err(unexpected()),
        }
    }

    /// Queues `op` for `gate` and sends the queue once every call that
    /// started with this one has joined it.
    async fn ask(&self, gate: &str, op: GateOp) -> Result<GateAnswer> {
        let slot = Rc::new(RefCell::new(Slot::default()));
        self.queue
            .borrow_mut()
            .entry(gate.to_string())
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
            let whole = GateProvider::from(p);
            let (unit, shards) = (self.sharding.unit_of(&whole), self.shards_of(&whole));
            let pool: Vec<&GateProvider> = match whole.pool_limit() {
                Some((pool, _)) => self
                    .providers
                    .iter()
                    .filter(|q| {
                        q.id != p.id && q.pool_limit().is_some_and(|(name, _)| name == pool)
                    })
                    .collect(),
                None => Vec::new(),
            };
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
                match self.ask(&gate_name(&unit, shard), op).await? {
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
            // One question per gate, asked together.
            let mut by_gate: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for (i, p) in permits.iter().enumerate() {
                by_gate
                    .entry(self.gate_of_slot(&p.provider, p.slot)?)
                    .or_default()
                    .push(i);
            }
            let answers = join_all(by_gate.iter().map(|(gate, at)| {
                let permits = at.iter().map(|i| GatePermit::from(&permits[*i])).collect();
                self.ask(gate, GateOp::Renew { permits })
            }))
            .await;
            let mut held = vec![false; permits.len()];
            for ((_, at), answer) in by_gate.iter().zip(answers) {
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
            let gate = self.gate_of_slot(&permit.provider, permit.slot)?;
            let op = GateOp::Release {
                permits: vec![GatePermit::from(permit)],
            };
            match self.ask(&gate, op).await? {
                GateAnswer::Released => Ok(()),
                _ => Err(unexpected()),
            }
        })
    }

    fn load(&self) -> LocalBoxFuture<'_, Result<Vec<GateLoad>>> {
        Box::pin(async move {
            let gates = self.gates();
            let answers = join_all(gates.keys().map(|gate| self.ask(gate, GateOp::Load))).await;
            // One line per provider: the sum over the gates that serve
            // parts of it.
            let mut load: BTreeMap<String, GateLoad> = BTreeMap::new();
            for answer in answers {
                let GateAnswer::Load(parts) = answer? else {
                    return Err(unexpected());
                };
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
            }
            Ok(load.into_values().collect())
        })
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
                if let Err(e) = self.send(gate, vec![GateOp::Retire]).await {
                    first_error = first_error.and(Err(e));
                }
            }
            for (gate, providers) in mine {
                let told = self.send(&gate, vec![GateOp::Activate { providers }]);
                if let Err(e) = told.await {
                    first_error = first_error.and(Err(e));
                }
            }
            first_error
        })
    }
}
