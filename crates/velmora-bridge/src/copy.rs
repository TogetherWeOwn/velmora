//! The recovery copy: every recovery record of the safety bucket, copied
//! to a store outside this account ([`crate::remote`]).
//!
//! A **pass** starts every [`PASS_INTERVAL_MS`] and does two things, in
//! this order:
//!
//! 1. **The fresh sweep.** The tombstones, then the generation records,
//!    minted in the last [`FRESH_MS`], of the flat layout and then of
//!    the tenant layout ([`Layout`]). Their keys start with the time,
//!    so each is a short range of the listing however many records the
//!    bucket holds. A new write or delete is over there one pass later.
//!    The sweep has the first [`SWEEP_MS`] of a pass; what it did not
//!    reach by then is left to the next pass, and reported.
//! 2. **The walk.** Everything else under `m/`, in key order, from
//!    where the last pass stopped ([`WALK_KEY`]). A pass ends when the
//!    next one starts; the walk goes on from the saved place, so every
//!    key is reached whatever their number. At the end of the keys the
//!    walk rests: the next one starts [`WALK_INTERVAL_MS`] after the
//!    pass that ended this one, or [`WALK_SOON_MS`] after it when a job
//!    left something undone meanwhile ([`WANT_KEY`]). A pass in which
//!    the walk rests lists the fresh records only, so what the copy
//!    costs follows what is written, not what is stored.
//!
//! Both compare the two listings by key, size and MD5. A record that is
//! missing or different over there is copied; nothing else is sent.
//!
//! The walk is what makes the copy whole: it reaches every record with
//! no help from anything saved, and it mends a copy that was damaged
//! over there. The sweep, and the hints below, only bring a new record
//! over sooner.
//!
//! - **An article plan is sent when its extent is posted.** A post job
//!   that is done sends a hint ([`Copier::hint`]): a job of its own
//!   that makes that one plan equal over there. A plan written long
//!   after its generation record is so not left to the walk. A hint is
//!   only a hint: one that is lost, or that finds the store down for
//!   longer than [`HINT_RETRY_MS`], leaves the plan to the walk and
//!   asks for it to come soon. While the store is known to be down
//!   ([`DOWN_KEY`]) a hint asks nothing of it: in an outage over there
//!   the hints that are running when it starts each wait for their
//!   tries once, and then once in [`HINT_PAUSE_MS`], so the queue they
//!   share with other jobs is held for a small part of the time.
//! - **A fresh generation record is sent after its article plans.** The
//!   key of an article plan is random, so a new one cannot be found in
//!   a listing without reading all of it. The sweep reads which extents
//!   a generation names and copies their plans first. A record with a
//!   plan that is not written yet (the extent is not posted) is held
//!   back (`pending`) and looked at again by the next pass, which goes
//!   on after the plans that are over there ([`SWEEP_KEY`]). The last
//!   pass in which the record is fresh sends it as it is; its other
//!   plans are copied by the walk when it comes to them.
//! - **A segmented generation record is sent after its segments.** Its
//!   head stands where a record of one document stands, and names the
//!   segments that hold its extents ([`GenerationHead`]). The job that
//!   sends the head first reads every segment, one at a time, and makes
//!   each equal over there. The head is sent only when every segment
//!   is stored, opens under its own name and is the one the head names;
//!   otherwise the record is counted (`source_unreadable`) and its head
//!   is not sent. This holds in the sweep and in the walk, and in the
//!   sweep the head also waits for its article plans, as a record of
//!   one document does. A segment is also a key under `m/` like any
//!   other, and is sent as one when a pass comes to it, whether or not
//!   its head or the plans it names are over there: a reader comes to
//!   a segment only through its head, so a segment without one says
//!   nothing. The order that is kept is the head's: after its plans in
//!   the sweep, and after its segments always.
//! - **Nothing is ever deleted over there.** "Absent in the safety
//!   bucket" cannot be told from "the safety bucket was lost", which is
//!   the event the copy exists for. A copy without a source is counted
//!   (`extra`) and left alone.
//! - **A record is copied only if it opens** under the KEK and its own
//!   name. One that does not is counted (`source_unreadable`) and never
//!   replaces a copy.
//! - **A generation record is copied once its id is two minutes old.**
//!   The record of a refused publication is removed in the request that
//!   wrote it ([`crate::recovery::discard_generation`]); the wait keeps
//!   it from being copied first, unless that request took longer than
//!   the wait. The copy then stays, like a record that could not be
//!   removed here: it replays as an object nobody was told exists, below
//!   whatever was published on the key after it.
//! - **Both layouts are copied, under the names they have.** The walk
//!   goes through every key under `m/`, so it reaches the records of
//!   any layout and any tenant, also of one this version does not
//!   know. The sweep knows the flat layout and the one of the default
//!   tenant. The article plan of an extent is looked for under the
//!   name of either layout: a plan can be in the other one than the
//!   generation record that names it, or than its hint says.
//! - **Tenant keys (`m/tk/`) never leave**, and neither do their names.
//! - **What something else wrote over there is counted (`foreign`) and
//!   passed.** It is never a copy, and it does not stop the pass. (One
//!   exception: a key with a control character is refused by the
//!   parser of the listing, so the step fails and says so.)
//! - **No catalogue.** The pass reads the two stores and the clock, so
//!   it runs while the catalogue is closed (rolled back, or a replay
//!   unfinished). The saved place of the walk is a hint: any value,
//!   or none, only changes where the walk starts, never what it
//!   reaches. What is saved of the sweep is a hint too: it can only
//!   change which record is sent before which. A lost or repeated job
//!   only makes a later pass do the work. It does not run in
//!   `MAINTENANCE=restore`, when the safety bucket may be half filled.
//! - **The times saved of the walk are hints as well.** Whatever
//!   [`WALKED_KEY`] holds, the walk starts [`WALK_INTERVAL_MS`] after
//!   it at the latest: a value that is no time, or a time that has not
//!   come yet, starts it at once. [`BEGAN_KEY`], [`WANT_KEY`] and
//!   [`SWEPT_KEY`] can only bring a walk forward, and [`DOWN_KEY`] can
//!   only hold the hints back for [`HINT_PAUSE_MS`]; none of them can
//!   put a walk off. They count only for the store they were saved
//!   about ([`STORE_KEY`]): a copy that is pointed at another bucket
//!   or prefix is walked at once. The saved place counts only while a
//!   walk is under
//!   way, that is when one began after the last one ended; otherwise
//!   the walk starts from the first key.
//! - **A time or a place that cannot be saved is reported in every
//!   pass** ([`StepError::Mark`]), and makes the walk come more often,
//!   not less: without the end, every pass walks from the first key;
//!   without the start or the place, every pass begins again. In the
//!   last case a walk that takes more than one pass does not reach its
//!   end until the safety bucket takes the write again (the sweep and
//!   the hints go on meanwhile).
//! - **A record of the walk that could not be copied waits for the walk
//!   to come round**, which it then does [`WALK_SOON_MS`] after the
//!   last one at the latest. One of the fresh sweep is tried again by
//!   the next pass.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use futures_util::future::FutureExt;
use futures_util::stream::{self, StreamExt};
use serde::Serialize;
use sha2::{Digest, Sha256};
use velmora_s3_proto::sign::Listed;

use crate::config::Maintenance;
use crate::crypto::open_manifest;
use crate::ports::{BlobEntry, BlobMeta, BlobStore, Clock, JobSink, Kek};
use crate::recovery::{
    article_key, other_plan_key, plan_keys, read_segment, record_name, record_version,
    segment_plan_keys, start_after, GenerationHead, Layout, RecordKind, MAX_SEGMENTS,
    RECORD_PREFIX, SEGMENTED_VERSION, TENANT_DIR, TENANT_KEY_PREFIX,
};
use crate::remote::{md5_hex, HttpSend, RemoteError, S3Remote, MAX_KEY_BYTES};
use crate::types::{
    BridgeError, BucketId, ExtentId, Job, JobOutcome, OutboxStage, Result, UnixMs, JOB_VERSION,
};

/// A pass starts on the cron run that falls in the first
/// [`START_WINDOW_MS`] of each interval of this length.
pub const PASS_INTERVAL_MS: i64 = 15 * 60 * 1000;
/// The cron period: exactly one run falls in the window.
pub const START_WINDOW_MS: i64 = 5 * 60 * 1000;
/// A generation record younger than this (by its id) is not copied yet.
pub const MIN_AGE_MS: i64 = 2 * 60 * 1000;
/// The fresh sweep of a pass covers the generation records and the
/// tombstones minted in this long before the pass started. Older ones
/// belong to the walk.
pub const FRESH_MS: i64 = 60 * 60 * 1000;
/// The fresh sweep has this much of a pass. After it the pass goes on
/// with the walk, so that neither can keep the other from its turn.
pub const SWEEP_MS: i64 = 10 * 60 * 1000;
/// The walk rests this long after the pass that ended the last one.
/// This bounds how long a record can be missing or damaged over there
/// when neither the sweep nor a hint brought it over and no job knew.
pub const WALK_INTERVAL_MS: i64 = 24 * 60 * 60 * 1000;
/// The walk rests only this long when a job left something undone
/// since the last walk began ([`WANT_KEY`]). It also bounds what a
/// record that never can be copied costs: a walk every so often.
pub const WALK_SOON_MS: i64 = 3 * 60 * 60 * 1000;
/// Where the walk stopped: a key of the safety bucket, outside the
/// records. Its body is the key the walk goes on after; empty, or no
/// such key, means the walk is not under way.
pub const WALK_KEY: &str = "rc/walk";
/// When the walk last came to its end: the time of the pass that
/// ended it, in decimal milliseconds.
pub const WALKED_KEY: &str = "rc/walk-ended";
/// When the walk last started from the first key: the time of that
/// pass, in decimal milliseconds.
pub const BEGAN_KEY: &str = "rc/walk-began";
/// When a job last left something undone that only the walk mends: a
/// record that failed or was refused, a sweep that was cut short, a
/// hint that was given up. Decimal milliseconds.
pub const WANT_KEY: &str = "rc/walk-wanted";
/// When a hint last found the store down. Decimal milliseconds.
pub const DOWN_KEY: &str = "rc/down";
/// The pass whose fresh sweep last came to its end, in decimal
/// milliseconds. A pass that does not find the pass before it here
/// asks for the walk: records may have grown too old for the sweep in
/// the gap (the copy was off, a pass was not started, its jobs were
/// lost).
pub const SWEPT_KEY: &str = "rc/swept";
/// A hint is tried again while it is younger than this, then given up.
pub const HINT_RETRY_MS: i64 = 10 * 60 * 1000;
pub const HINT_RETRY_SECS: u32 = 120;
/// After a hint found the store down, the others ask nothing of it for
/// this long.
pub const HINT_PAUSE_MS: i64 = 5 * 60 * 1000;
/// Where [`S3Remote::place`] of the store that the times of the walk
/// are about is saved. When it does not name the store of this pass
/// (the copy was pointed at another bucket or prefix), those times
/// count for nothing and the walk begins at once.
pub const STORE_KEY: &str = "rc/store";
/// The bytes read of a saved time.
const TIME_BYTES: usize = 20;
/// How far the fresh generation records came that are not sent yet: a
/// JSON object, key of the record to the number of its article plans,
/// from the first, that are over there. A plan is never changed or
/// removed over there, so a number that was true stays true.
pub const SWEEP_KEY: &str = "rc/sweep";
/// Records at most in [`SWEEP_KEY`], and the bytes read of it.
pub const SWEEP_RECORDS: usize = 1000;
const SWEEP_BYTES: usize = 1024 * 1024;
/// Bounds of one job; the next job goes on from the cursor. A copy and
/// a check of an article plan count alike: a job starts 250 of them at
/// most, [`CONCURRENCY`] at a time, and looks at the clock and at the
/// answers of the store after each group.
pub const JOB_COPIES: usize = 250;
pub const JOB_PAGES: u32 = 40;
pub const JOB_MS: i64 = 20_000;
/// Copies under way at once.
pub const CONCURRENCY: usize = 6;
/// Segments a job has room for whenever a head is the first record it
/// comes to. A job looks at every segment of a record before it sends
/// the head, so they all have to fit into one job, beside the other
/// records of its chunk and one group of article plans looked at again.
/// No head has more ([`MAX_SEGMENTS`]): one that does not fit into the
/// rest of a job is left to the next, and fits there.
pub const HEAD_SEGMENTS: usize = JOB_COPIES - 2 * CONCURRENCY;
const _: () = assert!(MAX_SEGMENTS <= HEAD_SEGMENTS);
/// Source keys read per page.
pub const PAGE: u32 = 1000;
/// A job that failed is retried while its pass is younger than this.
/// A pass ends when it is [`PASS_INTERVAL_MS`] old: the next one has
/// started.
pub const RETRY_WINDOW_MS: i64 = 10 * 60 * 1000;
pub const RETRY_SECS: u32 = 60;
/// A job of the fresh sweep that found the store down is retried while
/// its pass is younger than this. After it the sweep goes on past the
/// records that got no answer, while it still has time ([`SWEEP_MS`]).
pub const SWEEP_RETRY_MS: i64 = 5 * 60 * 1000;
/// List requests to the store for one page of the source, and for
/// counting the copies past the last source key.
pub const LIST_PAGES: u32 = 10;
/// A group of at least this many copies that got no answer at all means
/// the store is down. Fewer are taken as a fault of those records.
pub const OUTAGE_MIN: usize = 3;

/// The key after the last tombstone (of the flat layout, as the next
/// one: [`Layout::of_flat`] makes them the keys of another).
const TOMBSTONES_END: &str = "m/del0";
/// The key after the last generation record.
const GENERATIONS_END: &str = "m/g`";

/// What one job did. Counts only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CopyCounts {
    /// Source records seen (tenant keys excluded) and their bytes.
    pub records: u64,
    pub bytes: u64,
    /// Already equal over there.
    pub same: u64,
    /// Records sent. An article plan sent ahead of the walk, for a
    /// fresh generation record, is counted here and not in `records`.
    pub copied: u64,
    /// Not copied, and worth another try (a later pass makes it).
    pub failed: u64,
    /// Total refusals, including requests rejected before being sent.
    pub refused: u64,
    pub refused_put: RefusalCounts,
    pub refused_verify: RefusalCounts,
    pub refused_plan: RefusalCounts,
    pub unsignable: RefusalCounts,
    /// Does not open here; not copied.
    pub source_unreadable: u64,
    /// Generation records too young to copy.
    pub young: u64,
    /// Fresh generation records held back: an article plan they name is
    /// not over there yet. (One sent in its last fresh pass with a plan
    /// missing is `copied`.)
    pub pending: u64,
    /// Copies without a source (at least this many). Never deleted.
    pub extra: u64,
    /// Keys over there that this service would not write: something
    /// else did. Never a copy, never deleted.
    pub foreign: u64,
}

impl CopyCounts {
    /// Nothing is left for a later pass to mend.
    pub fn clean(&self) -> bool {
        self.failed == 0 && self.refused == 0
    }

    fn record_refusal(&mut self, refusal: Refusal) {
        self.refused += 1;
        let (counts, answer) = match refusal {
            Refusal::Put(status, code) => (&mut self.refused_put, Some((status, code))),
            Refusal::Verify(status, code) => (&mut self.refused_verify, Some((status, code))),
            Refusal::Plan(status, code) => (&mut self.refused_plan, Some((status, code))),
            Refusal::Unsignable => (&mut self.unsignable, None),
        };
        counts.count += 1;
        counts.status = answer.map(|(status, _)| status);
        counts.code = answer.and_then(|(_, code)| code);
    }
}

/// Number of refusals and the last answer for that operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RefusalCounts {
    pub count: u64,
    pub status: Option<u16>,
    pub code: Option<&'static str>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Put(u16, Option<&'static str>),
    Verify(u16, Option<&'static str>),
    Plan(u16, Option<&'static str>),
    Unsignable,
}

/// Result of one job: what it did, and where the next one goes on
/// (`None` = the pass has ended).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyStep {
    pub counts: CopyCounts,
    pub next: Option<String>,
    /// The step stopped because the store did not answer.
    pub outage: bool,
    /// The key the walk goes on after, when the step came to the walk
    /// (empty = from the start).
    pub walk: Option<String>,
    /// The step started the walk from the first key.
    pub began: bool,
    /// The step came to the end of the keys: the walk rests.
    pub ended: bool,
    /// The step came to the end of the fresh sweep.
    pub swept: bool,
    /// The fresh sweep was left unfinished: its time was up.
    pub late: bool,
    /// What the sweep learned could not be saved ([`SWEEP_KEY`]).
    pub unsaved: bool,
}

/// A counted step. Its successor is identified by a digest, not its
/// object-bearing cursor. `None` for `next` marks the end of a pass.
pub struct CopyProgress {
    pub next: Option<String>,
    /// The pass ran out of fresh-sweep time. A later walk can still
    /// verify copies, but this pass cannot certify a clean sweep.
    pub skipped_sweep: bool,
}

pub fn cursor_tag(cursor: &str) -> String {
    Sha256::digest(cursor.as_bytes())[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Why a job did not do its step: a class, and a status at most. Never
/// text from a store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepError {
    /// The safety bucket could not be read.
    Source,
    /// The recovery store could not be listed.
    Store(RemoteError),
    /// The job for the next step could not be sent.
    Queue,
    /// The fresh sweep was not at its end when its time was up
    /// ([`SWEEP_MS`]), or when the next pass started: what was left of
    /// it was not looked at. The next pass starts it again; what is
    /// over there by then costs it nothing.
    Expired,
    /// The place of the walk, or what the sweep learned, could not be
    /// saved. The pass goes on; a later pass does that part again.
    Mark,
    /// A hint did not make its article plan equal over there, the
    /// store having answered. It is tried again, then left to the walk.
    Hint,
}

/// The parts of a pass, in the order they are done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Fresh tombstones of the flat layout (`d` in a cursor).
    Tombstones,
    /// Fresh generation records of the flat layout, and whatever sorts
    /// after them and before the tenant layout (`g`).
    Generations,
    /// Fresh tombstones of the tenant layout (`e`).
    TenantTombstones,
    /// Fresh generation records of the tenant layout (`h`).
    TenantGenerations,
    /// The walk below the fresh tombstones (`a`).
    Low,
    /// The walk between the tombstones and the fresh generation
    /// records (`b`).
    High,
    /// The walk of the tenant layout below its fresh tombstones (`c`).
    TenantLow,
    /// The walk between the tombstones and the fresh generation
    /// records of the tenant layout (`f`).
    TenantHigh,
    /// The walk of whatever sorts after the generation records of the
    /// tenant layout, to the last key (`z`).
    Tail,
    /// No part of a pass: a hint, the job of one article plan
    /// (`key`), made at `made` (`x`).
    Plan,
}

/// The phases and their names in a cursor.
const PHASES: [(Phase, &str); 10] = [
    (Phase::Tombstones, "d"),
    (Phase::Generations, "g"),
    (Phase::TenantTombstones, "e"),
    (Phase::TenantGenerations, "h"),
    (Phase::Low, "a"),
    (Phase::High, "b"),
    (Phase::TenantLow, "c"),
    (Phase::TenantHigh, "f"),
    (Phase::Tail, "z"),
    (Phase::Plan, "x"),
];

impl Phase {
    /// Whether the phase is a part of the walk.
    fn walking(self) -> bool {
        use Phase::*;
        matches!(self, Low | High | TenantLow | TenantHigh | Tail)
    }

    /// The layout whose keys the phase goes through.
    fn layout(self) -> Layout {
        use Phase::*;
        match self {
            TenantTombstones | TenantGenerations | TenantLow | TenantHigh | Tail => {
                Layout::default_tenant()
            }
            Tombstones | Generations | Low | High | Plan => Layout::flat(),
        }
    }

    /// The key the phase starts after, in the pass that started at
    /// `pass`.
    fn first(self, pass: UnixMs) -> String {
        use Phase::*;
        let layout = self.layout();
        match self {
            Tombstones | TenantTombstones => fresh(&layout.tombstone_prefix(), pass),
            Generations | TenantGenerations => fresh(&layout.generation_prefix(), pass),
            Low | Plan => String::new(),
            TenantLow => TENANT_DIR.to_string(),
            High | TenantHigh => layout.of_flat(TOMBSTONES_END),
            Tail => layout.of_flat(GENERATIONS_END),
        }
    }

    /// The phase after this one, in the sweep and in the walk; `None`
    /// at the end of either.
    fn then(self) -> Option<Phase> {
        use Phase::*;
        match self {
            Tombstones => Some(Generations),
            Generations => Some(TenantTombstones),
            TenantTombstones => Some(TenantGenerations),
            Low => Some(High),
            High => Some(TenantLow),
            TenantLow => Some(TenantHigh),
            TenantHigh => Some(Tail),
            TenantGenerations | Tail | Plan => None,
        }
    }
}

/// Where a pass stands: the cursor of a job, as a JSON object. An
/// empty cursor, or one that does not parse, is the start of a pass.
///
/// The members: `p` the phase and `k` the key, both required; `g`, `n`
/// and `t`, each left out when empty or zero. A member of another name
/// is passed over; one of another type is no cursor, and neither is
/// an object that is not plain JSON of small depth.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Place {
    phase: Phase,
    /// The key the phase goes on after.
    key: String,
    /// A generation record after `key` that an earlier job began, and
    /// how many of its article plans, in order, are over there. They
    /// stay in the cursor until the phase ends; only that record reads
    /// them (`g` and `n`).
    generation: String,
    plans: u32,
    /// When a hint was made ([`Phase::Plan`]; `t`).
    made: i64,
}

/// A string as JSON. Serializing a string cannot fail.
fn quoted(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_default()
}

impl Place {
    fn at(phase: Phase, key: String) -> Place {
        Place {
            phase,
            key,
            generation: String::new(),
            plans: 0,
            made: 0,
        }
    }

    /// Read through the JSON value, and written by hand, rather than
    /// by derived code: the Worker has a size budget.
    fn parse(cursor: &str) -> Option<Place> {
        let value: serde_json::Value = serde_json::from_str(cursor).ok()?;
        let object = value.as_object()?;
        let name = object.get("p")?.as_str()?;
        let phase = PHASES.iter().find(|(_, p)| *p == name)?.0;
        let key = object.get("k")?.as_str()?.to_string();
        let generation = match object.get("g") {
            Some(generation) => generation.as_str()?.to_string(),
            None => String::new(),
        };
        let plans = match object.get("n") {
            Some(plans) => u32::try_from(plans.as_u64()?).ok()?,
            None => 0,
        };
        let made = match object.get("t") {
            Some(made) => made.as_i64()?,
            None => 0,
        };
        Some(Place {
            phase,
            key,
            generation,
            plans,
            made,
        })
    }

    fn cursor(&self) -> String {
        let name = PHASES.iter().find(|(p, _)| *p == self.phase);
        let name = name.map_or("", |(_, name)| name);
        let mut out = format!("{{\"p\":\"{name}\",\"k\":{}", quoted(&self.key));
        if !self.generation.is_empty() {
            out.push_str(",\"g\":");
            out.push_str(&quoted(&self.generation));
        }
        for (name, number) in [("n", i64::from(self.plans)), ("t", self.made)] {
            if number != 0 {
                out.push_str(&format!(",\"{name}\":{number}"));
            }
        }
        out.push('}');
        out
    }

    fn walking(&self) -> bool {
        self.phase.walking()
    }

    /// Where a pass starts.
    fn start(pass: UnixMs) -> Place {
        Place::first(Phase::Tombstones, pass)
    }

    /// The start of `phase` in the pass that started at `pass`.
    fn first(phase: Phase, pass: UnixMs) -> Place {
        Place::at(phase, phase.first(pass))
    }
}

/// The keys of one phase: after the place of the pass, up to and
/// including `until` (`None` = to the end).
struct Span {
    until: Option<String>,
    /// Generation records are sent after their article plans.
    plans: bool,
    /// A generation record is fresh when its id was minted at or
    /// after this time, in milliseconds.
    since: i64,
    /// A generation record up to this key is not fresh any more when
    /// the next pass starts: it is not held back.
    last: String,
}

/// The first key of the fresh generation records (or tombstones) of the
/// pass that started at `pass`: every fresh one sorts after it.
fn fresh(prefix: &str, pass: UnixMs) -> String {
    start_after(prefix, UnixMs(pass.0 - FRESH_MS))
}

/// The parts of the key space, in key order, with `T` for the directory
/// of the tenant layout (`m/x/<tenant id>/`):
///
/// | Keys | Phase |
/// |---|---|
/// | up to the fresh tombstones (`m/art/`, older `m/del/`) | walk: `Low` |
/// | fresh `m/del/g_` | sweep: `Tombstones` |
/// | older `m/g_` | walk: `High` |
/// | fresh `m/g_`, and on up to `m/x/` (`m/rk/`, `m/seg/` and every other family) | sweep: `Generations` |
/// | `m/x/` up to the fresh tombstones of `T` (`T art/`, older `T del/`) | walk: `TenantLow` |
/// | fresh `T del/g_` | sweep: `TenantTombstones` |
/// | older `T g_` | walk: `TenantHigh` |
/// | fresh `T g_` | sweep: `TenantGenerations` |
/// | everything after `T g_` | walk: `Tail` |
///
/// Every key under `m/` is in one part of the walk or of the sweep, in
/// every pass, wherever the fresh records begin. The segments of the
/// flat layout (`m/seg/`) are in the sweep, so every pass lists them
/// all; those of the tenant layout are in the `Tail` of the walk.
fn span(phase: Phase, pass: UnixMs) -> Span {
    let layout = phase.layout();
    let until = match phase {
        Phase::Tombstones | Phase::TenantTombstones => Some(layout.of_flat(TOMBSTONES_END)),
        Phase::Generations => Some(TENANT_DIR.to_string()),
        Phase::TenantGenerations => Some(layout.of_flat(GENERATIONS_END)),
        Phase::Low | Phase::TenantLow => Some(fresh(&layout.tombstone_prefix(), pass)),
        Phase::High | Phase::TenantHigh => Some(fresh(&layout.generation_prefix(), pass)),
        Phase::Tail => None,
        // No key lies in it: a hint is not a part of a pass.
        Phase::Plan => Some(String::new()),
    };
    Span {
        until,
        plans: matches!(phase, Phase::Generations | Phase::TenantGenerations),
        since: pass.0 - FRESH_MS,
        last: start_after(
            &layout.generation_prefix(),
            UnixMs(pass.0 - FRESH_MS + PASS_INTERVAL_MS),
        ),
    }
}

/// Where the walk of a pass starts, from the place that was saved. A
/// place outside the parts of the walk is read as the start.
fn walk_from(saved: String, pass: UnixMs) -> Place {
    use Phase::*;
    // The last part of the walk the place is at or after the start of;
    // the place is in it when it is also before its end.
    let part = [Tail, TenantHigh, TenantLow, High, Low]
        .into_iter()
        .find(|part| saved >= part.first(pass));
    match part {
        Some(part) if span(part, pass).until.is_none_or(|until| saved < until) => {
            Place::at(part, saved)
        }
        _ => Place::at(Low, String::new()),
    }
}

/// What a job has used of its bounds.
struct Budget {
    started: UnixMs,
    copies: usize,
    pages: u32,
}

/// What [`SWEEP_KEY`] holds, read when a job first needs it.
#[derive(Default)]
struct Known {
    loaded: bool,
    changed: bool,
    /// It could not be read: what this job knows is not all, and is
    /// not saved over it.
    unread: bool,
    plans: BTreeMap<String, u32>,
}

impl Known {
    /// Keeps that `n` of the `of` plans of the record at `key` are over
    /// there. Only a part is kept: a record with all of them is sent.
    fn keep(&mut self, key: &str, n: usize, of: usize) {
        let room = self.plans.len() < SWEEP_RECORDS || self.plans.contains_key(key);
        if n == 0 || n >= of || !room || self.plans.get(key) == Some(&(n as u32)) {
            return;
        }
        self.plans.insert(key.to_string(), n as u32);
        self.changed = true;
    }

    fn forget(&mut self, key: &str) {
        self.changed |= self.plans.remove(key).is_some();
    }
}

/// How a phase stopped.
#[derive(PartialEq, Eq)]
enum Walked {
    /// It reached the end of its keys.
    End,
    /// A bound of the job was reached.
    More,
    /// The store was found down.
    Outage,
}

/// What the store holds in a range.
#[derive(Default)]
struct Range {
    copies: Vec<Listed>,
    foreign: Vec<String>,
    /// The last key listed, when the requests ran out before the end of
    /// the range.
    cut: Option<String>,
}

/// Where a source page ends for the store. Tenant keys are passed as a
/// whole, by a key that sorts after all of them and names none.
fn page_end(last: &str) -> String {
    if last.starts_with(TENANT_KEY_PREFIX) {
        format!("{}0", TENANT_KEY_PREFIX.trim_end_matches('/'))
    } else {
        last.to_string()
    }
}

/// What the listings say of a source record.
enum What<'a> {
    Young,
    Same,
    /// To copy; the copy over there, when one is listed.
    Copy(Option<&'a Listed>),
}

struct Item<'a> {
    entry: &'a BlobEntry,
    what: What<'a>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Copied {
    Done,
    Same,
    Gone,
    Unreadable,
    /// Not copied; the store answered.
    Failed,
    /// Not copied; the store gave no answer.
    Down,
    Refused(Refusal),
    /// A generation record held back for an article plan.
    Held,
}

impl Copied {
    fn from_remote_error(
        e: RemoteError,
        operation: fn(u16, Option<&'static str>) -> Refusal,
    ) -> Self {
        match e {
            RemoteError::Refused(status) => Self::Refused(operation(status, None)),
            RemoteError::RefusedWithCode(status, code) => {
                Self::Refused(operation(status, Some(code)))
            }
            RemoteError::VerifyRefused(status, code) => {
                Self::Refused(Refusal::Verify(status, code))
            }
            RemoteError::Unsignable => Self::Refused(Refusal::Unsignable),
            RemoteError::Unavailable => Self::Down,
            RemoteError::Mismatch => Self::Failed,
        }
    }

    fn as_plan(self) -> Plan {
        match self {
            Self::Done => Plan::Sent,
            Self::Refused(refusal) => Plan::Refused(refusal),
            Self::Down => Plan::Down,
            _ => Plan::Failed,
        }
    }
}

/// A record to copy, after the first look at it.
enum Read {
    Is(Copied),
    /// A generation record that something is sent before: its bytes,
    /// and what it names.
    Generation {
        bytes: Vec<u8>,
        named: Named,
    },
}

/// What a generation record names that is sent before it.
enum Named {
    /// A fresh record of one document: the keys of its article plans.
    Plans(Vec<String>),
    /// A segmented record: its head.
    Segments(Box<GenerationHead>),
}

impl Named {
    /// How many extents the record has.
    fn extents(&self) -> usize {
        match self {
            Named::Plans(keys) => keys.len(),
            Named::Segments(head) => head.extent_count() as usize,
        }
    }
}

/// What became of the article plan of a fresh generation record.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Plan {
    /// Equal over there already.
    There,
    Sent,
    /// Not written yet: the extent is not posted.
    Absent,
    Unreadable,
    Failed,
    Down,
    Refused(Refusal),
}

/// What became of the records of a chunk.
struct Chunk {
    /// How many of them, from the first, are finished. The cursor does
    /// not pass the others.
    finished: usize,
    outage: bool,
}

/// At least [`OUTAGE_MIN`] requests, and no answer to any of them.
fn all_down(asked: usize, down: usize) -> bool {
    asked >= OUTAGE_MIN && down == asked
}

/// The store was asked for this record.
fn asked_store(copied: Copied) -> bool {
    !matches!(copied, Copied::Gone | Copied::Unreadable | Copied::Same)
}

/// True on the cron run that starts a pass.
pub fn pass_due(now: UnixMs) -> bool {
    now.0.rem_euclid(PASS_INTERVAL_MS) < START_WINDOW_MS
}

/// The hint for the article plan of the extent of `job`, when `job` is
/// a post job that is done: the plan is written by then, and nothing
/// but the walk would find it, its key being random.
///
/// The hint carries pass 0, a pass that ended long ago: a Worker of a
/// version that knows no hints acknowledges it and starts no pass.
pub fn plan_hint(job: &Job, outcome: &JobOutcome, now: UnixMs) -> Option<Job> {
    let extent = posted(job, outcome)?;
    let mut place = Place::at(Phase::Plan, article_key(extent));
    place.made = now.0;
    Some(Job::RecoveryCopy {
        v: JOB_VERSION,
        pass: UnixMs(0),
        cursor: place.cursor(),
        sequence: None,
    })
}

/// The extent of `job`, when `job` is a post job that is done: the one
/// [`plan_hint`] has a hint for.
pub fn posted<'j>(job: &'j Job, outcome: &JobOutcome) -> Option<&'j ExtentId> {
    match job {
        Job::Extent {
            extent,
            stage: OutboxStage::Post,
            ..
        } if *outcome == JobOutcome::Ack => Some(extent),
        _ => None,
    }
}

/// Sends the hint of [`plan_hint`]. True when one was sent. One that
/// cannot be sent asks for the walk instead (best effort). It needs
/// nothing of the recovery store; the caller does not send it in
/// `MAINTENANCE=restore`, or with the copy off.
pub async fn send_hint<B: BlobStore, J: JobSink>(
    safety: &B,
    jobs: &J,
    job: &Job,
    outcome: &JobOutcome,
    now: UnixMs,
) -> bool {
    let Some(hint) = plan_hint(job, outcome, now) else {
        return false;
    };
    let sent = jobs.send(&hint, 0).await.is_ok();
    if !sent {
        let _ = put_mark(safety, WANT_KEY, now.0.to_string().into_bytes()).await;
    }
    sent
}

/// Saves `body` at `key` of the safety bucket, as a mark of the copy.
async fn put_mark<B: BlobStore>(safety: &B, key: &str, body: Vec<u8>) -> Result<()> {
    let sha: [u8; 32] = Sha256::digest(&body).into();
    let meta = BlobMeta {
        bucket: &BucketId::new("-"),
        extent: &ExtentId::new("recovery-copy"),
        cipher_sha256: &sha,
    };
    safety.put(key, body, &meta).await
}

/// A saved time: decimal milliseconds, and nothing else.
fn saved_time(bytes: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(bytes).ok()?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Whether `key` names a generation record, of either layout.
fn generation(key: &str) -> bool {
    record_name(key).is_some_and(|n| n.kind == RecordKind::Generation)
}

/// Milliseconds in the id of a generation record's key, of either
/// layout.
fn minted_ms(key: &str) -> Option<i64> {
    let name = record_name(key).filter(|n| n.kind == RecordKind::Generation)?;
    let hex = name.id.strip_prefix("g_")?.get(..13)?;
    i64::from_str_radix(hex, 16).ok()
}

fn young(key: &str, now: UnixMs) -> bool {
    minted_ms(key).is_some_and(|ms| ms > now.0 - MIN_AGE_MS)
}

fn equal(copy: Option<&Listed>, size: u64, md5: &str) -> bool {
    copy.is_some_and(|c| c.size == size && c.etag.eq_ignore_ascii_case(md5))
}

/// Everything a pass touches.
pub struct Copier<'a, B: BlobStore, K: Kek, T: Clock, H: HttpSend> {
    pub safety: &'a B,
    pub kek: &'a K,
    pub clock: &'a T,
    pub remote: &'a S3Remote<H>,
    pub maintenance: Maintenance,
}

impl<B: BlobStore, K: Kek, T: Clock, H: HttpSend> Copier<'_, B, K, T, H> {
    /// The cron hook: sends the first job of a pass when one is due at
    /// `scheduled`, the time the cron run was set for. A run that
    /// starts late still starts its pass.
    pub async fn start_pass<J: JobSink>(&self, jobs: &J, scheduled: UnixMs) -> Result<bool> {
        if self.maintenance == Maintenance::Restore || !pass_due(scheduled) {
            return Ok(false);
        }
        let first = Job::RecoveryCopy {
            v: JOB_VERSION,
            pass: scheduled,
            cursor: String::new(),
            sequence: Some(0),
        };
        jobs.send(&first, 0).await?;
        Ok(true)
    }

    /// One queue job of a pass: a step from `cursor`, then the message
    /// for the next step. No counts = no step was done (maintenance, a
    /// newer pass has started, or the step failed). The third value is
    /// why the job did not do all of its work, when it did not; the
    /// job may be acknowledged all the same, so it has to be reported.
    ///
    /// A job that is to be retried does its step again, and counts it
    /// again: a sum over a pass takes the acknowledged jobs only.
    pub async fn run_job<J: JobSink>(
        &self,
        jobs: &J,
        pass: UnixMs,
        cursor: &str,
    ) -> (JobOutcome, Option<CopyCounts>, Option<StepError>) {
        let (outcome, counts, why, _) = self.run_job_with_sequence(jobs, pass, cursor, None).await;
        (outcome, counts, why)
    }

    /// Also reports whether this step can be counted, and whether it was
    /// the last in the pass. Telemetry cannot change a copy job's outcome.
    pub async fn run_job_with_sequence<J: JobSink>(
        &self,
        jobs: &J,
        pass: UnixMs,
        cursor: &str,
        sequence: Option<u16>,
    ) -> (
        JobOutcome,
        Option<CopyCounts>,
        Option<StepError>,
        Option<CopyProgress>,
    ) {
        if self.maintenance == Maintenance::Restore {
            return (JobOutcome::Ack, None, None, None);
        }
        let place = Place::parse(cursor);
        if let Some(hint) = place.as_ref().filter(|p| p.phase == Phase::Plan) {
            let (outcome, counts, why) = self.run_hint(hint).await;
            return (outcome, counts, why, None);
        }
        let (outcome, counts, why, final_step) =
            self.run_step(jobs, pass, cursor, place, sequence).await;
        // Something was left undone, and the job does not come again
        // for it. The sweep of the next pass may mend it; if it does
        // not, only the walk does, so the walk is asked to come soon.
        let undone = why.is_some() || counts.as_ref().is_some_and(|c| !c.clean());
        if undone && outcome == JobOutcome::Ack {
            self.want_walk().await;
        }
        (outcome, counts, why, final_step)
    }

    async fn run_step<J: JobSink>(
        &self,
        jobs: &J,
        pass: UnixMs,
        cursor: &str,
        place: Option<Place>,
        sequence: Option<u16>,
    ) -> (
        JobOutcome,
        Option<CopyCounts>,
        Option<StepError>,
        Option<CopyProgress>,
    ) {
        // A pass ends when the next one starts. The walk loses nothing
        // by it: the newer pass goes on from the place that was saved.
        // A fresh sweep that is cut short is late, and says so.
        let age = self.clock.now().0 - pass.0;
        if age >= PASS_INTERVAL_MS {
            let walking = place.as_ref().is_some_and(|p| p.walking());
            let why = (!walking).then_some(StepError::Expired);
            return (JobOutcome::Ack, None, why, None);
        }
        // Every step is idempotent, so a failed job simply runs again,
        // but not for ever: a later pass takes over.
        let again = if age < RETRY_WINDOW_MS {
            JobOutcome::Retry {
                delay_secs: RETRY_SECS,
            }
        } else {
            JobOutcome::Ack
        };
        // The first job of a pass: when the sweep of the pass before
        // did not come to its end (or there was no such pass), records
        // may have grown too old for this sweep, and the walk is asked
        // for. The time is before this pass, so that a walk that
        // begins in it answers.
        if place.is_none() {
            let last = self.read_time(SWEPT_KEY).await;
            if !matches!(last, Ok(Some(at)) if (0..=PASS_INTERVAL_MS).contains(&(pass.0 - at))) {
                // Not over a later time that has come: a job that
                // asked after this pass started would be forgotten.
                let asked = self.read_time(WANT_KEY).await;
                let later = pass.0..pass.0 + PASS_INTERVAL_MS;
                if !matches!(asked, Ok(Some(at)) if later.contains(&at)) {
                    let _ = self.save_time(WANT_KEY, UnixMs(pass.0 - 1)).await;
                }
            }
        }
        let step = match self.step(pass, cursor).await {
            Ok(step) => step,
            Err(e) => return (again, None, Some(e), None),
        };
        // The store is down: the cursor does not move while the job may
        // be retried. After that the pass goes on past the records that
        // failed, so that no record can hold back those behind it. A
        // job that stopped in the sweep goes on sooner: the sweep ends
        // at SWEEP_MS. One that began in the sweep and stopped in the
        // walk is held as long as any job of the walk.
        let hold = if step.walk.is_some() {
            RETRY_WINDOW_MS
        } else {
            SWEEP_RETRY_MS
        };
        if step.outage && age < hold {
            let down = StepError::Store(RemoteError::Unavailable);
            return (again, Some(step.counts), Some(down), None);
        }
        let mut why = step.late.then_some(StepError::Expired);
        if step.unsaved {
            why = why.or(Some(StepError::Mark));
        }
        // The times of the walk, each before the place it belongs to.
        // A start that is not saved saves no place: the next pass
        // begins again. An end that is not saved still puts the place
        // back at the first key, so that the next pass, which finds a
        // walk under way, goes through every key again: with the place
        // left near the end, every pass would walk that end only.
        // Best effort: without it the next pass asks for the walk.
        if step.swept {
            let _ = self.save_time(SWEPT_KEY, pass).await;
        }
        let mut saved = true;
        if step.began {
            // The place of an earlier walk goes first: a start with
            // such a place under it would go on from there.
            saved &= self.save_walk("").await.is_ok();
            saved = saved && self.save_time(BEGAN_KEY, pass).await.is_ok();
            // Last: until it is there, the next pass begins again.
            let store = self.remote.place().into_bytes();
            saved = saved && put_mark(self.safety, STORE_KEY, store).await.is_ok();
        }
        let started = saved;
        if step.ended {
            saved &= self.save_time(WALKED_KEY, pass).await.is_ok();
        }
        if let Some(at) = step.walk.as_ref().filter(|_| started) {
            saved &= self.save_walk(at).await.is_ok();
        }
        if !saved {
            why = why.or(Some(StepError::Mark));
        }
        let progress = sequence.map(|_| CopyProgress {
            next: step.next.as_deref().map(cursor_tag),
            skipped_sweep: step.late,
        });
        if let Some(cursor) = step.next {
            let next = Job::RecoveryCopy {
                v: JOB_VERSION,
                pass,
                cursor,
                sequence: sequence.and_then(|n| n.checked_add(1)),
            };
            // Past records that got no answer the pass goes on slowly:
            // a store that comes back finds most of them still ahead.
            let delay = if step.outage { RETRY_SECS } else { 0 };
            if jobs.send(&next, delay).await.is_err() {
                return (again, Some(step.counts), Some(StepError::Queue), None);
            }
        }
        (JobOutcome::Ack, Some(step.counts), why, progress)
    }

    fn spent(&self, started: UnixMs) -> bool {
        self.clock.now().0 - started.0 >= JOB_MS
    }

    /// Does the pass that started at `pass` from `cursor` on, phase
    /// after phase, until a bound of the job is reached, the store is
    /// found down, or the pass ends.
    pub async fn step(
        &self,
        pass: UnixMs,
        cursor: &str,
    ) -> std::result::Result<CopyStep, StepError> {
        let mut budget = Budget {
            started: self.clock.now(),
            copies: 0,
            pages: 0,
        };
        let mut counts = CopyCounts::default();
        let mut known = Known::default();
        let place = Place::parse(cursor).unwrap_or_else(|| Place::start(pass));
        // The time of the sweep is up: the walk has the rest of the pass.
        // A hint is no part of a pass ([`Copier::run_job`] does it).
        let hint = place.phase == Phase::Plan;
        let late = !hint && !place.walking() && budget.started.0 - pass.0 >= SWEEP_MS;
        let (mut began, mut ended, mut swept) = (false, false, false);
        // `None` = the pass is over: the walk rests.
        let mut turn = (!hint).then_some(place);
        if late {
            turn = self.enter_walk(pass, &mut began).await?;
        }
        let mut walk = None;
        let (next, outage) = loop {
            let Some(mut place) = turn.take() else {
                break (None, false);
            };
            let phase = span(place.phase, pass);
            let walked = self
                .walk(&phase, &mut place, &mut budget, &mut counts, &mut known)
                .await?;
            if place.walking() {
                walk = Some(place.key.clone());
            }
            if walked != Walked::End {
                break (Some(place.cursor()), walked == Walked::Outage);
            }
            turn = match (place.phase, place.phase.then()) {
                (_, Some(then)) => Some(Place::first(then, pass)),
                // The last phase of the sweep.
                (Phase::TenantGenerations, None) => {
                    swept = true;
                    self.enter_walk(pass, &mut began).await?
                }
                // The last phase of the walk.
                (Phase::Tail, None) => {
                    walk = Some(String::new());
                    ended = true;
                    None
                }
                (_, None) => None,
            };
        };
        Ok(CopyStep {
            counts,
            walk,
            began,
            ended,
            swept,
            next,
            outage,
            late,
            unsaved: !self.save_known(known).await,
        })
    }

    /// Where the walk of the pass that started at `pass` goes on, or
    /// `None` when it rests. A walk that is under way goes on whatever
    /// the times say. `began` is set when it starts from the first key.
    async fn enter_walk(
        &self,
        pass: UnixMs,
        began: &mut bool,
    ) -> std::result::Result<Option<Place>, StepError> {
        // What is saved of the walk, read in one place of the code (the
        // Worker has a size budget): its place, its end, its start,
        // and the store they are about.
        let here = self.remote.place().into_bytes();
        let marks = [
            (WALK_KEY, MAX_KEY_BYTES),
            (WALKED_KEY, TIME_BYTES),
            (BEGAN_KEY, TIME_BYTES),
            (STORE_KEY, here.len()),
        ];
        let mut read = [None, None, None, None];
        for (slot, (key, max)) in read.iter_mut().zip(marks) {
            let mark = self.read_mark(key, max).await;
            *slot = mark.map_err(|_| StepError::Source)?;
        }
        let [left, ended, start, store] = read;
        let left = left.and_then(|bytes| String::from_utf8(bytes).ok());
        let left = left.unwrap_or_default();
        let stale = !left.is_empty();
        let place = walk_from(left, pass);
        // A time that has not come yet is none: an end in the future
        // would otherwise make every pass begin the walk again.
        // And so is a time that is about another store: that one may
        // hold nothing yet.
        let same = store == Some(here);
        let time = |mark: Option<Vec<u8>>| {
            let at = mark.and_then(|bytes| saved_time(&bytes));
            at.filter(|at| same && *at < pass.0 + PASS_INTERVAL_MS)
        };
        let (ended, start) = (time(ended), time(start));
        // A walk is under way when one began after the last one ended.
        // Only then does the saved place count: a place without such a
        // start (stale, or written by something else) would make a walk
        // that began in the middle of the keys end, and rest.
        let under_way = start.is_some_and(|at| ended.is_none_or(|ended| at > ended));
        if under_way && (place.phase != Phase::Low || !place.key.is_empty()) {
            return Ok(Some(place));
        }
        // Under way without a place (the job that began it died before
        // the place was saved): it begins again.
        if !under_way && !self.walk_due(pass, ended, start).await {
            // A place left under a walk that rests is cleared: a start
            // that turns up later (one saved with a time that had not
            // come yet) would go on from it. Best effort: a walk that
            // begins clears it too.
            if stale {
                let _ = self.save_walk("").await;
            }
            return Ok(None);
        }
        *began = true;
        Ok(Some(Place::at(Phase::Low, String::new())))
    }

    /// True when the walk, being at its start, is to start in the pass
    /// that started at `pass`.
    ///
    /// Nothing that is saved can put it off for longer than
    /// [`WALK_INTERVAL_MS`]: without a time of the last end, or with
    /// one that has not come yet, it starts now. (A time up to one
    /// pass ahead is the end of a walk in a pass that overlaps this
    /// one.)
    async fn walk_due(&self, pass: UnixMs, ended: Option<i64>, began: Option<i64>) -> bool {
        let Some(ended) = ended else {
            return true;
        };
        let rested = pass.0 - ended;
        if rested <= -PASS_INTERVAL_MS || rested >= WALK_INTERVAL_MS {
            return true;
        }
        if rested < WALK_SOON_MS {
            return false;
        }
        // Sooner when a job left something undone since the last walk
        // began: that walk may have been past it already. A time that
        // has not come yet asks for nothing. If it cannot be read, the
        // walk is taken as asked for.
        let want = match self.read_time(WANT_KEY).await {
            Ok(Some(want)) => want,
            Ok(None) => return false,
            Err(_) => return true,
        };
        if want >= pass.0 + PASS_INTERVAL_MS {
            return false;
        }
        began.is_none_or(|began| want >= began)
    }

    /// The time saved at `key`; `None` when there is none, or what is
    /// there is not a time.
    fn read_time<'s>(&'s self, key: &'s str) -> impl Future<Output = Result<Option<i64>>> + 's {
        self.read_mark(key, TIME_BYTES)
            .map(|read| read.map(|bytes| bytes.and_then(|bytes| saved_time(&bytes))))
    }

    /// What is saved at `key`, when it is at most `max` bytes.
    async fn read_mark(&self, key: &str, max: usize) -> Result<Option<Vec<u8>>> {
        // Its size first: something else may have written it.
        match self.safety.head(key).await? {
            Some(size) if size <= max as u64 => {}
            _ => return Ok(None),
        }
        let bytes = self.safety.get(key, None).await?;
        Ok(bytes.filter(|bytes| bytes.len() <= max))
    }

    fn save_time<'s>(&'s self, key: &'s str, at: UnixMs) -> impl Future<Output = Result<()>> + 's {
        put_mark(self.safety, key, at.0.to_string().into_bytes())
    }

    /// Asks for the walk to come soon. Best effort: without it the walk
    /// comes [`WALK_INTERVAL_MS`] after the last.
    fn want_walk(&self) -> impl Future<Output = ()> + '_ {
        self.save_time(WANT_KEY, self.clock.now()).map(|_| ())
    }

    /// Sends the hint for the article plan of a post job that is done
    /// ([`plan_hint`]). True when one was sent. One that cannot be sent
    /// leaves the plan to the walk, and asks for it.
    pub async fn hint<J: JobSink>(&self, jobs: &J, job: &Job, outcome: &JobOutcome) -> bool {
        if self.maintenance == Maintenance::Restore {
            return false;
        }
        send_hint(self.safety, jobs, job, outcome, self.clock.now()).await
    }

    /// The job of a hint: makes one article plan equal over there.
    ///
    /// A hint that gets no further is tried again while it is young,
    /// then given up to the walk. While the store is known to be down
    /// it asks nothing of it: the jobs it shares a queue with are not
    /// to wait for a store that does not answer.
    async fn run_hint(&self, hint: &Place) -> (JobOutcome, Option<CopyCounts>, Option<StepError>) {
        let key = hint.key.as_str();
        let plan = record_name(key).is_some_and(|n| n.kind == RecordKind::ArticlePlan)
            && key.len() <= MAX_KEY_BYTES;
        if !plan {
            return (JobOutcome::Ack, None, None);
        }
        let now = self.clock.now().0;
        let young = (0..HINT_RETRY_MS).contains(&now.saturating_sub(hint.made));
        let down = StepError::Store(RemoteError::Unavailable);
        let paused = matches!(
            self.read_time(DOWN_KEY).await,
            Ok(Some(at)) if (0..HINT_PAUSE_MS).contains(&(now - at))
        );
        let mut counts = CopyCounts::default();
        let why = if paused {
            Some(down)
        } else {
            match self.plan(key).await {
                Plan::There => {
                    counts.same = 1;
                    None
                }
                Plan::Sent => {
                    counts.copied = 1;
                    None
                }
                // Not written, or removed: nothing to send.
                Plan::Absent => None,
                Plan::Unreadable => {
                    counts.source_unreadable = 1;
                    None
                }
                Plan::Refused(refusal) => {
                    counts.record_refusal(refusal);
                    None
                }
                Plan::Failed => {
                    counts.failed = 1;
                    Some(StepError::Hint)
                }
                Plan::Down => {
                    counts.failed = 1;
                    // The time after the tries, which take a minute
                    // when no answer comes.
                    let _ = self.save_time(DOWN_KEY, self.clock.now()).await;
                    Some(down)
                }
            }
        };
        let counts = (!paused).then_some(counts);
        if why.is_some() && young {
            let again = JobOutcome::Retry {
                delay_secs: HINT_RETRY_SECS,
            };
            return (again, counts, why);
        }
        if why.is_some() || counts.as_ref().is_some_and(|c| !c.clean()) {
            self.want_walk().await;
        }
        (JobOutcome::Ack, counts, why)
    }

    /// Reads [`SWEEP_KEY`], once in a job. Anything that is not what a
    /// job would have written is read as nothing, and a record that is
    /// not fresh any more is dropped.
    async fn load_known(&self, known: &mut Known, span: &Span) {
        if known.loaded {
            return;
        }
        known.loaded = true;
        // Its size first: something else may have written it.
        let bytes = match self.safety.head(SWEEP_KEY).await {
            Ok(None) => return,
            Ok(Some(size)) if size > SWEEP_BYTES as u64 => return,
            Ok(Some(_)) => self.safety.get(SWEEP_KEY, None).await,
            Err(e) => Err(e),
        };
        let bytes = match bytes {
            Ok(Some(bytes)) if bytes.len() > SWEEP_BYTES => return,
            Ok(Some(bytes)) => bytes,
            Ok(None) => return,
            Err(_) => {
                known.unread = true;
                return;
            }
        };
        let saved: BTreeMap<String, u32> = serde_json::from_slice(&bytes).unwrap_or_default();
        let before = saved.len();
        known.plans = saved
            .into_iter()
            .filter(|(key, _)| minted_ms(key).is_some_and(|ms| ms >= span.since))
            .take(SWEEP_RECORDS)
            .collect();
        known.changed = known.plans.len() < before;
    }

    /// Writes [`SWEEP_KEY`] when the job changed it. False when it
    /// could not be written.
    async fn save_known(&self, known: Known) -> bool {
        if !known.changed {
            return true;
        }
        if known.unread {
            return false;
        }
        // Serializing strings and integers cannot fail.
        let body = serde_json::to_vec(&known.plans).unwrap_or_default();
        put_mark(self.safety, SWEEP_KEY, body).await.is_ok()
    }

    fn save_walk(&self, at: &str) -> impl Future<Output = Result<()>> + '_ {
        put_mark(self.safety, WALK_KEY, at.as_bytes().to_vec())
    }

    /// Walks the keys of `span` after `place.key`, and moves the place,
    /// until a bound of the job is reached, the store is found down, or
    /// the keys end.
    async fn walk(
        &self,
        span: &Span,
        place: &mut Place,
        budget: &mut Budget,
        counts: &mut CopyCounts,
        known: &mut Known,
    ) -> std::result::Result<Walked, StepError> {
        let inside = |key: &str| span.until.iter().all(|until| key <= until.as_str());
        loop {
            if budget.pages >= JOB_PAGES
                || budget.copies >= JOB_COPIES
                || self.spent(budget.started)
            {
                return Ok(Walked::More);
            }
            budget.pages += 1;
            let mut source = self
                .safety
                .list_entries(RECORD_PREFIX, &place.key, PAGE)
                .await
                .map_err(|_| StepError::Source)?;
            source.retain(|e| inside(&e.key));
            let Some(last) = source.last().map(|e| page_end(&e.key)) else {
                // The keys have ended; what the store still lists in the
                // span is extra.
                let rest = self.listed(&place.key, span.until.as_ref()).await?;
                counts.extra += rest.copies.iter().filter(|o| inside(&o.key)).count() as u64;
                counts.foreign += rest.foreign.iter().filter(|k| inside(k)).count() as u64;
                return Ok(Walked::End);
            };
            // The store may hold far more keys in this range than the
            // source: its listing is cut after LIST_PAGES requests, and
            // the page then ends at the last key listed.
            let range = self.listed(&place.key, Some(&last)).await?;
            let end = match range.cut {
                Some(cut) => {
                    source.retain(|e| e.key <= cut);
                    cut
                }
                None => last,
            };
            let there: BTreeMap<&str, &Listed> =
                range.copies.iter().map(|o| (o.key.as_str(), o)).collect();
            let names: BTreeSet<&str> = source.iter().map(|e| e.key.as_str()).collect();
            let now = self.clock.now();
            let items: Vec<Item> = source
                .iter()
                .filter(|e| !e.key.starts_with(TENANT_KEY_PREFIX))
                .map(|entry| {
                    let copy = there.get(entry.key.as_str()).copied();
                    let what = if young(&entry.key, now) {
                        What::Young
                    } else if equal(copy, entry.size, &entry.md5) {
                        What::Same
                    } else {
                        What::Copy(copy)
                    };
                    Item { entry, what }
                })
                .collect();

            // In key order, a chunk of CONCURRENCY copies at a time; the
            // bounds are looked at after each chunk, and the page ends
            // at the last record that is finished.
            let mut done = 0;
            let mut outage = false;
            while done < items.len() {
                let room = CONCURRENCY.min(JOB_COPIES.saturating_sub(budget.copies));
                let mut to = done;
                let mut copies = 0;
                while to < items.len() {
                    if matches!(items[to].what, What::Copy(_)) {
                        if copies == room {
                            break;
                        }
                        copies += 1;
                    }
                    to += 1;
                }
                budget.copies += copies;
                let chunk = self
                    .copy_chunk(&items[done..to], span, place, budget, counts, known)
                    .await;
                done += chunk.finished;
                outage = chunk.outage;
                if done < to || outage || budget.copies >= JOB_COPIES || self.spent(budget.started)
                {
                    break;
                }
            }
            let upto = if done == items.len() {
                end
            } else if done == 0 {
                place.key.clone()
            } else {
                items[done - 1].entry.key.clone()
            };
            counts.extra += there
                .keys()
                .filter(|k| **k <= upto.as_str() && !names.contains(*k))
                .count() as u64;
            counts.foreign += range.foreign.iter().filter(|k| **k <= upto).count() as u64;
            place.key = upto;
            if outage {
                return Ok(Walked::Outage);
            }
            if done < items.len() {
                return Ok(Walked::More);
            }
        }
    }

    /// Does the records of `chunk` and counts those that are finished.
    ///
    /// In the fresh sweep a generation record is sent after the article
    /// plans it names: all the records are read, then the plans are
    /// looked at, record after record in key order and a group of
    /// [`CONCURRENCY`] at a time, then the records whose plans are all
    /// over there are sent. The bounds of the job and the answers of
    /// the store are looked at after each group. A record whose plans
    /// did not fit is not finished: `place` keeps how far it came, and
    /// the next job goes on there. Nothing after it is counted. (A
    /// record after it that is not a generation record was sent all the
    /// same; the next job finds it equal.)
    async fn copy_chunk(
        &self,
        chunk: &[Item<'_>],
        span: &Span,
        place: &mut Place,
        budget: &mut Budget,
        counts: &mut CopyCounts,
        known: &mut Known,
    ) -> Chunk {
        let plans = span.plans;
        let work = chunk
            .iter()
            .enumerate()
            .filter_map(|(i, item)| match item.what {
                What::Copy(copy) => Some((i, item.entry, copy)),
                _ => None,
            });
        let read: Vec<(usize, Read)> = stream::iter(work)
            .map(|(i, entry, copy)| async move {
                if generation(&entry.key) {
                    (i, self.read_generation(&entry.key, copy, plans).await)
                } else {
                    (i, Read::Is(self.copy_one(&entry.key, copy).await))
                }
            })
            .buffer_unordered(CONCURRENCY)
            .collect()
            .await;
        let mut result: Vec<Option<Copied>> = vec![None; chunk.len()];
        let mut generations: BTreeMap<usize, (Vec<u8>, Named)> = BTreeMap::new();
        let (mut asked, mut down) = (0, 0);
        for (i, read) in read {
            match read {
                Read::Is(copied) => {
                    asked += usize::from(asked_store(copied));
                    down += usize::from(copied == Copied::Down);
                    result[i] = Some(copied);
                }
                Read::Generation { bytes, named } => {
                    generations.insert(i, (bytes, named));
                }
            }
        }
        let mut outage = all_down(asked, down);
        if plans && !generations.is_empty() {
            self.load_known(known, span).await;
        }

        let mut finished = chunk.len();
        let mut ready: Vec<usize> = Vec::new();
        // Requests in a row, group after group, that got no answer.
        let mut silent = 0;
        for (i, (bytes, named)) in &generations {
            let key = &chunk[*i].entry.key;
            if outage && !plans {
                // Not looked at, and the walk does not pass it.
                finished = *i;
                break;
            }
            if outage {
                // Not looked at: the job comes again, or the next pass.
                result[*i] = Some(Copied::Held);
                continue;
            }
            let of = named.extents();
            let layout = record_name(key).map_or_else(Layout::flat, |n| n.layout);
            // How many of its plans are over there: what an earlier job
            // of this pass counted, or an earlier pass. A count for
            // another record is not believed, and neither is one that
            // leaves no plan to look at, unless segments are still to
            // be sent after the plans.
            let whole = matches!(named, Named::Segments(_));
            let believed = |n: u32| Some(n as usize).filter(|n| *n < of || (whole && *n == of));
            let counted = believed(place.plans).filter(|_| place.generation == *key);
            let saved = known.plans.get(key).copied().and_then(believed);
            // The walk sends a record as it is.
            let mut n = if plans {
                counted.max(saved).unwrap_or(0)
            } else {
                of
            };
            // A plan of the record is not over there.
            let mut stopped = false;
            // The plan keys of one segment, and which.
            let mut held: Option<(usize, Vec<String>)> = None;
            // A segment could not be read.
            let mut unread: Option<Copied> = None;
            while n < of && !stopped {
                let room = JOB_COPIES.saturating_sub(budget.copies);
                if room == 0 || self.spent(budget.started) {
                    break;
                }
                // The plans to look at: of a segmented record, those of
                // the one segment that holds the next extent.
                let rest: &[String] = match named {
                    Named::Plans(keys) => &keys[n..],
                    Named::Segments(head) => {
                        let Some(at) = head.segment_of(n as u32) else {
                            unread = Some(Copied::Unreadable);
                            break;
                        };
                        if held.as_ref().map(|(index, _)| *index) != Some(at) {
                            // One segment at a time.
                            held = None;
                            match self.segment_plans(head, &layout, at).await {
                                Ok(keys) => held = Some((at, keys)),
                                Err(copied) => {
                                    unread = Some(copied);
                                    break;
                                }
                            }
                        }
                        let first = head.segments[at].seq as usize;
                        match &held {
                            Some((_, keys)) => &keys[n - first..],
                            None => &[],
                        }
                    }
                };
                let take = CONCURRENCY.min(room).min(rest.len());
                budget.copies += take;
                let looked: Vec<Plan> = stream::iter(&rest[..take])
                    .map(|key| self.plan(key))
                    .buffered(CONCURRENCY)
                    .collect()
                    .await;
                let (mut asked, mut down, mut lead) = (0, 0, 0);
                for (at, plan) in looked.into_iter().enumerate() {
                    asked += usize::from(!matches!(plan, Plan::Absent | Plan::Unreadable));
                    match plan {
                        Plan::There => {}
                        Plan::Sent => counts.copied += 1,
                        Plan::Absent => continue,
                        Plan::Unreadable => {
                            counts.source_unreadable += 1;
                            continue;
                        }
                        Plan::Failed => {
                            counts.failed += 1;
                            continue;
                        }
                        Plan::Down => {
                            counts.failed += 1;
                            down += 1;
                            continue;
                        }
                        Plan::Refused(refusal) => {
                            counts.record_refusal(refusal);
                            continue;
                        }
                    }
                    lead += usize::from(lead == at);
                }
                n += lead;
                stopped = lead < take;
                // A group that asked nothing says nothing.
                if asked > 0 {
                    silent = if down == asked { silent + down } else { 0 };
                }
                outage = silent >= OUTAGE_MIN;
            }
            drop(held);
            if let Some(copied) = unread {
                // Its head is not sent: finished for this pass.
                result[*i] = Some(copied);
                continue;
            }
            known.keep(key, n, of);
            let more = if n == of || (stopped && !outage && *key <= span.last) {
                // All its plans are over there, or it is fresh for the
                // last time: the walk would send it as it is.
                match named {
                    Named::Plans(_) => {
                        ready.push(*i);
                        false
                    }
                    Named::Segments(head) => {
                        match self
                            .send_segmented(key, bytes, head, &layout, budget, counts)
                            .await
                        {
                            Some(copied) => {
                                if copied == Copied::Done {
                                    known.forget(key);
                                }
                                if copied == Copied::Down {
                                    silent += 1;
                                } else if asked_store(copied) {
                                    silent = 0;
                                }
                                outage = silent >= OUTAGE_MIN;
                                result[*i] = Some(copied);
                                false
                            }
                            // Its segments did not fit into the job.
                            None => true,
                        }
                    }
                }
            } else if stopped {
                // Held back: finished for this pass.
                result[*i] = Some(Copied::Held);
                false
            } else {
                true
            };
            if more {
                if plans {
                    place.generation = key.clone();
                    place.plans = n as u32;
                }
                finished = *i;
                break;
            }
        }

        let sent: Vec<(usize, Copied)> = stream::iter(ready)
            .map(|i| {
                let bytes = &generations[&i].0;
                async move { (i, self.send(&chunk[i].entry.key, bytes).await) }
            })
            .buffer_unordered(CONCURRENCY)
            .collect()
            .await;
        let (asked, mut down) = (sent.len(), 0);
        for (i, copied) in sent {
            down += usize::from(copied == Copied::Down);
            if copied == Copied::Done {
                known.forget(&chunk[i].entry.key);
            }
            result[i] = Some(copied);
        }
        outage |= all_down(asked, down);

        for (item, copied) in chunk.iter().zip(result).take(finished) {
            let copied = match item.what {
                What::Young => {
                    counts.young += 1;
                    None
                }
                What::Same => Some(Copied::Same),
                What::Copy(_) => copied,
            };
            match copied {
                // Removed since it was listed: not a record any more.
                Some(Copied::Gone) => continue,
                Some(Copied::Done) => counts.copied += 1,
                Some(Copied::Same) => counts.same += 1,
                Some(Copied::Unreadable) => counts.source_unreadable += 1,
                Some(Copied::Failed | Copied::Down) => counts.failed += 1,
                Some(Copied::Refused(refusal)) => counts.record_refusal(refusal),
                Some(Copied::Held) => counts.pending += 1,
                None => {}
            }
            counts.records += 1;
            counts.bytes += item.entry.size;
        }
        Chunk { finished, outage }
    }

    /// What the store holds after `after`, at least up to and including
    /// `upto` (`None` = to the end), from at most [`LIST_PAGES`]
    /// requests. The last answer may reach past `upto`; the caller
    /// counts only what lies before its cursor.
    async fn listed(
        &self,
        after: &str,
        upto: Option<&String>,
    ) -> std::result::Result<Range, StepError> {
        let mut range = Range::default();
        let mut after = after.to_string();
        for pages in 1..=LIST_PAGES {
            let page = self
                .remote
                .list(self.clock, RECORD_PREFIX, &after)
                .await
                .map_err(StepError::Store)?;
            let Some(last) = page.last else {
                break;
            };
            range.copies.extend(page.objects);
            range.foreign.extend(page.foreign);
            if !page.truncated || upto.is_some_and(|u| last.as_str() >= u.as_str()) {
                break;
            }
            if pages == LIST_PAGES {
                range.cut = upto.map(|_| last);
                return Ok(range);
            }
            after = last;
        }
        Ok(range)
    }

    /// Reads a generation record that is to be copied. A segmented one
    /// comes back with its head, in the sweep and in the walk; one of a
    /// single document with the plans it names when they go first
    /// (`plans`: the sweep), and is sent as it is otherwise.
    async fn read_generation(&self, key: &str, copy: Option<&Listed>, plans: bool) -> Read {
        let bytes = match self.safety.get(key, None).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Read::Is(Copied::Gone),
            Err(_) => return Read::Is(Copied::Failed),
        };
        let Ok(plain) = open_manifest(self.kek, key, &bytes) else {
            return Read::Is(Copied::Unreadable);
        };
        // The listing may name another digest than the MD5 of the bytes;
        // an equal copy is not sent again.
        if equal(copy, bytes.len() as u64, &md5_hex(&bytes)) {
            return Read::Is(Copied::Same);
        }
        if record_version(&plain) == Some(SEGMENTED_VERSION) {
            // A head that does not say which segments it has is never
            // sent: nothing could be sent before it.
            return match GenerationHead::parse(key, &plain) {
                Ok(head) => Read::Generation {
                    bytes,
                    named: Named::Segments(Box::new(head)),
                },
                Err(_) => Read::Is(Copied::Unreadable),
            };
        }
        if !plans {
            return Read::Is(self.send(key, &bytes).await);
        }
        // Without the extents it names, its plans cannot be sent first.
        // As the layout of the record names them; [`Copier::plan`]
        // looks under the other name too.
        let layout = record_name(key).map_or_else(Layout::flat, |n| n.layout);
        match plan_keys(&plain, &layout) {
            Some(plans) => Read::Generation {
                bytes,
                named: Named::Plans(plans),
            },
            None => Read::Is(Copied::Unreadable),
        }
    }

    /// The keys of the article plans that segment `index` of `head`
    /// names, in the order of its extents. `Err` = what became of the
    /// record instead: its segment could not be asked for (`Failed`),
    /// or is not stored or not the one the head names (`Unreadable`).
    async fn segment_plans(
        &self,
        head: &GenerationHead,
        layout: &Layout,
        index: usize,
    ) -> std::result::Result<Vec<String>, Copied> {
        match read_segment(self.safety, self.kek, layout, head, index).await {
            Ok(extents) => segment_plan_keys(&extents, layout).ok_or(Copied::Unreadable),
            Err(BridgeError::Blob(_)) => Err(Copied::Failed),
            Err(_) => Err(Copied::Unreadable),
        }
    }

    /// Makes every segment of `head` equal over there, in order and
    /// one at a time, and then sends the head, `bytes`, to `key`. The
    /// head is sent only if every segment is stored and is the one the
    /// head names ([`GenerationHead::open_segment`]), and is equal
    /// over there; whatever an earlier job did, this one looks at them
    /// all again. A segment that is sent is counted as copied.
    ///
    /// `None` = a bound of the job was reached; the next job begins
    /// again and finds the segments that were sent equal. A job sends
    /// at least one segment whatever the time, so the record is
    /// finished after as many jobs as it has segments at the most.
    async fn send_segmented(
        &self,
        key: &str,
        bytes: &[u8],
        head: &GenerationHead,
        layout: &Layout,
        budget: &mut Budget,
        counts: &mut CopyCounts,
    ) -> Option<Copied> {
        // At most `MAX_SEGMENTS`, which a job that starts at this head
        // has room for (`HEAD_SEGMENTS`).
        let segments = head.segments.len();
        if JOB_COPIES.saturating_sub(budget.copies) < segments {
            return None;
        }
        budget.copies += segments;
        let mut sent = 0;
        for index in 0..segments {
            let name = head.segment_key(layout, index);
            let sealed = match self.safety.get(&name, None).await {
                Ok(Some(sealed)) => sealed,
                Ok(None) => return Some(Copied::Unreadable),
                Err(_) => return Some(Copied::Failed),
            };
            if head.open_segment(self.kek, layout, index, &sealed).is_err() {
                return Some(Copied::Unreadable);
            }
            match self.remote.head(self.clock, &name).await {
                Ok(copy) if equal(copy.as_ref(), sealed.len() as u64, &md5_hex(&sealed)) => {
                    continue
                }
                Ok(_) => {}
                Err(e) => return Some(Copied::from_remote_error(e, Refusal::Plan)),
            }
            if sent > 0 && self.spent(budget.started) {
                return None;
            }
            match self.send(&name, &sealed).await {
                Copied::Done => {
                    sent += 1;
                    counts.copied += 1;
                }
                other => return Some(other),
            }
        }
        Some(self.send(key, bytes).await)
    }

    /// Makes the article plan at `key` equal over there, or the plan of
    /// the same extent under the name of the other layout, when there
    /// is none at `key` or it does not open: an extent has one plan,
    /// whichever name it was written under.
    async fn plan(&self, key: &str) -> Plan {
        let plan = self.plan_at(key).await;
        if !matches!(plan, Plan::Absent | Plan::Unreadable) {
            return plan;
        }
        match other_plan_key(key) {
            Some(other) => match self.plan_at(&other).await {
                Plan::Absent => plan,
                found => found,
            },
            None => plan,
        }
    }

    /// Makes the article plan at `key` equal over there.
    async fn plan_at(&self, key: &str) -> Plan {
        let bytes = match self.safety.get(key, None).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Plan::Absent,
            Err(_) => return Plan::Failed,
        };
        if open_manifest(self.kek, key, &bytes).is_err() {
            return Plan::Unreadable;
        }
        match self.remote.head(self.clock, key).await {
            Ok(copy) if equal(copy.as_ref(), bytes.len() as u64, &md5_hex(&bytes)) => {
                return Plan::There
            }
            Ok(_) => {}
            Err(e) => return Copied::from_remote_error(e, Refusal::Plan).as_plan(),
        }
        self.send(key, &bytes).await.as_plan()
    }

    async fn copy_one(&self, key: &str, copy: Option<&Listed>) -> Copied {
        let bytes = match self.safety.get(key, None).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Copied::Gone,
            Err(_) => return Copied::Failed,
        };
        if open_manifest(self.kek, key, &bytes).is_err() {
            return Copied::Unreadable;
        }
        // The listing may name another digest than the MD5 of the bytes;
        // an equal copy is not sent again.
        if equal(copy, bytes.len() as u64, &md5_hex(&bytes)) {
            return Copied::Same;
        }
        self.send(key, &bytes).await
    }

    async fn send(&self, key: &str, bytes: &[u8]) -> Copied {
        match self.remote.put(self.clock, key, bytes).await {
            Ok(()) => Copied::Done,
            Err(e) => Copied::from_remote_error(e, Refusal::Put),
        }
    }
}
