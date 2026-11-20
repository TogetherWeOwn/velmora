//! Phase timings of a post job, for the Worker's log.
//!
//! A post job notes how long each of its phases took; the Worker takes
//! the record after the job and logs it as one line. The record holds
//! milliseconds and counts only: no extent, key, message-id, provider or
//! host, so the line is safe to log.
//!
//! Records are kept per extent in the isolate, because one isolate runs
//! several jobs at once. A job's extent is leased to it alone, so two
//! running jobs never share a record. Time is the runtime clock, which in
//! a Worker only moves while the job waits on I/O: the phases measure the
//! waits (catalogue, R2, providers), not CPU time.

use core::fmt;
use std::cell::RefCell;
use std::collections::BTreeMap;

use crate::types::{ExtentId, UnixMs};

/// Records kept at most. A job whose record is never taken (a test, a
/// Worker that crashed between the job and the log) must not grow the map
/// for the life of the isolate.
const MAX_RECORDS: usize = 64;

/// What one post job spent its time on, in milliseconds, and its counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PostTrace {
    /// Waiting for room in the isolate's byte budget.
    pub wait_ms: i64,
    /// Taking the job's provider slots.
    pub permits_ms: i64,
    /// Reading, checking and planning the extent and storing its record.
    pub load_ms: i64,
    /// Connecting the sockets, which runs while the extent loads.
    pub connect_ms: i64,
    /// Posting every article, from the first socket to the last.
    pub post_ms: i64,
    /// Handing the extent over to the verify stage.
    pub advance_ms: i64,
    /// The whole job, from the claim to the end.
    pub total_ms: i64,
    /// Sockets the job held.
    pub sockets: u32,
    /// Articles the job set out to post.
    pub articles: u32,
    started: i64,
    /// The job that began the record has returned.
    finished: bool,
}

impl fmt::Display for PostTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "wait_ms={} permits_ms={} load_ms={} connect_ms={} post_ms={} advance_ms={} \
             total_ms={} sockets={} articles={}",
            self.wait_ms,
            self.permits_ms,
            self.load_ms,
            self.connect_ms,
            self.post_ms,
            self.advance_ms,
            self.total_ms,
            self.sockets,
            self.articles
        )
    }
}

thread_local! {
    static RECORDS: RefCell<BTreeMap<String, PostTrace>> = const { RefCell::new(BTreeMap::new()) };
}

/// Starts the record of a post job for `extent` at `now`.
pub(crate) fn begin(extent: &ExtentId, now: UnixMs) {
    RECORDS.with(|r| {
        let mut r = r.borrow_mut();
        if r.len() >= MAX_RECORDS {
            r.clear();
        }
        let trace = PostTrace {
            started: now.0,
            ..PostTrace::default()
        };
        r.insert(extent.as_str().to_string(), trace);
    });
}

/// Changes the record of `extent`, if a job started one.
pub(crate) fn note(extent: &ExtentId, f: impl FnOnce(&mut PostTrace)) {
    RECORDS.with(|r| {
        if let Some(t) = r.borrow_mut().get_mut(extent.as_str()) {
            f(t);
        }
    });
}

/// The job that began the record of `extent` has returned at `now`.
pub(crate) fn finish(extent: &ExtentId, now: UnixMs) {
    note(extent, |t| {
        t.total_ms = now.0 - t.started;
        t.finished = true;
    });
}

/// Takes the record of the post job for `extent` once that job has
/// returned. `None` = no post job for it has finished: none ran, or the
/// one that began the record is still running (a second delivery of the
/// same job, which claimed nothing, must not take its record).
pub fn take(extent: &ExtentId) -> Option<PostTrace> {
    RECORDS.with(|r| {
        let mut r = r.borrow_mut();
        match r.get(extent.as_str()) {
            Some(t) if t.finished => r.remove(extent.as_str()),
            _ => None,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_is_taken_once_after_its_job_returned() {
        let extent = ExtentId::new("x_trace_once");
        begin(&extent, UnixMs(1_000));
        note(&extent, |t| t.post_ms = 40);
        // The job is still running: a duplicate delivery takes nothing.
        assert_eq!(take(&extent), None);
        finish(&extent, UnixMs(1_250));
        let t = take(&extent).expect("record");
        assert_eq!((t.post_ms, t.total_ms), (40, 250));
        assert_eq!(take(&extent), None);
    }

    #[test]
    fn the_line_names_no_extent() {
        let extent = ExtentId::new("x_secretive");
        begin(&extent, UnixMs(0));
        finish(&extent, UnixMs(5));
        let line = take(&extent).expect("record").to_string();
        assert!(!line.contains("secretive"), "{line}");
        assert!(line.starts_with("wait_ms=0 ") && line.contains(" total_ms=5 "));
    }

    #[test]
    fn the_map_stays_bounded() {
        for i in 0..(MAX_RECORDS * 3) {
            begin(&ExtentId::new(format!("x_{i}")), UnixMs(0));
        }
        RECORDS.with(|r| assert!(r.borrow().len() <= MAX_RECORDS));
    }
}

thread_local! {
    static COLD_READS: std::cell::Cell<Option<fn(&str)>> = const { std::cell::Cell::new(None) };
}

/// Sends one line to `to` each time a read ends its connections to
/// Usenet: extents read, connections opened and broken, articles and
/// bytes per provider id, and the milliseconds spent reading and writing
/// to the cache. No key, bucket, message-id or host.
pub fn log_cold_reads(to: fn(&str)) {
    COLD_READS.with(|log| log.set(Some(to)));
}

thread_local! {
    static ALERTS: std::cell::Cell<Option<fn(&str)>> = const { std::cell::Cell::new(None) };
}

/// Sends one line to `to` for each event an operator has to see: a
/// failed full read of a sampled extent, for one. No key, bucket,
/// message-id or host.
pub fn log_alerts(to: fn(&str)) {
    ALERTS.with(|log| log.set(Some(to)));
}

/// Hands the line to the log set with [`log_alerts`], if any.
pub(crate) fn alert(line: impl FnOnce() -> String) {
    if let Some(to) = ALERTS.with(std::cell::Cell::get) {
        to(&line());
    }
}

/// Hands the line to the log set with [`log_cold_reads`], if any.
pub(crate) fn cold_read(line: impl FnOnce() -> String) {
    if let Some(to) = COLD_READS.with(std::cell::Cell::get) {
        to(&line());
    }
}

// ---------------------------------------------------------------------------
// Phase timings of a write request
// ---------------------------------------------------------------------------

/// What a write request was doing during a stretch of its time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Authentication: the key, bucket and grant lookups and the
    /// signature check.
    Auth,
    /// Waiting for room in the isolate's byte budget.
    Wait,
    /// Waiting for the next piece of the body to arrive.
    Read,
    /// Taking in a piece that arrived: copying it into wasm, decoding
    /// and hashing it.
    Hash,
    /// Encrypting and hashing an extent.
    Seal,
    /// Storing an extent's ciphertext in the safety store.
    R2,
    /// Catalogue statements.
    D1,
    /// Everything else: the recovery record, the job message, choosing
    /// ids, copying a source.
    Other,
}

const PHASES: usize = 8;

/// A future that lets the runtime's clock catch up, or nothing.
pub type Tick = fn() -> futures_util::future::LocalBoxFuture<'static, ()>;

/// Where the lines go, and the tick.
type WriteLog = (fn(&str), Tick);

thread_local! {
    static WRITES: std::cell::Cell<Option<WriteLog>> = const { std::cell::Cell::new(None) };
}

/// Sends one line to `to` for each PutObject and UploadPart, with the
/// milliseconds the request spent in each [`Phase`]. No key, bucket or
/// id. Off unless called: a drill measurement, not a production log.
///
/// A Worker's clock does not move while code runs, only when the
/// isolate waits on something: a phase that only computes (the seal)
/// would read as 0 ms and its time would land in the next phase that
/// waits. So at each phase boundary the trace awaits `tick` (a timer of
/// 0 ms in a Worker) before it reads the clock. That costs the request
/// one timer per boundary and per piece of the body, while it is on.
pub fn log_writes(to: fn(&str), tick: Tick) {
    WRITES.with(|log| log.set(Some((to, tick))));
}

/// Where a write request's time went. Each stretch of time from the
/// start to the last mark is in exactly one phase, so the phases add up
/// to `wall_ms`. Logs its line when dropped, so a request that fails
/// is logged too.
pub(crate) struct WriteTrace<'a> {
    on: Option<(WriteLog, &'a dyn crate::ports::Clock)>,
    kind: &'static str,
    ok: bool,
    bytes: u64,
    extents: u32,
    pieces: u32,
    ticks: u32,
    ms: [i64; PHASES],
    start: i64,
    last: i64,
}

impl<'a> WriteTrace<'a> {
    /// A trace of a request of `kind`, started now, if writes are logged.
    pub(crate) fn begin(kind: &'static str, clock: &'a dyn crate::ports::Clock) -> Self {
        let on = WRITES.with(std::cell::Cell::get);
        let now = if on.is_some() { clock.now().0 } else { 0 };
        WriteTrace {
            on: on.map(|log| (log, clock)),
            kind,
            ok: false,
            bytes: 0,
            extents: 0,
            pieces: 0,
            ticks: 0,
            ms: [0; PHASES],
            start: now,
            last: now,
        }
    }

    /// A trace that records nothing.
    pub(crate) fn off() -> Self {
        WriteTrace {
            on: None,
            kind: "",
            ok: false,
            bytes: 0,
            extents: 0,
            pieces: 0,
            ticks: 0,
            ms: [0; PHASES],
            start: 0,
            last: 0,
        }
    }

    pub(crate) fn kind(&mut self, kind: &'static str) {
        self.kind = kind;
    }

    /// The body is `bytes` long (decoded) and is stored as `extents`.
    pub(crate) fn body(&mut self, bytes: u64, extents: u32) {
        self.bytes = bytes;
        self.extents = extents;
    }

    /// The request is answered with a success.
    pub(crate) fn ok(&mut self) {
        self.ok = true;
    }

    /// The time since the last mark was spent in `phase`. Reads the
    /// clock as it is: right after an await on I/O it is current.
    pub(crate) fn mark(&mut self, phase: Phase) {
        if let Some((_, clock)) = self.on {
            self.note(phase, clock.now().0);
        }
    }

    /// As [`Self::mark`], after letting the clock catch up with the code
    /// that ran since the last await.
    pub(crate) async fn lap(&mut self, phase: Phase) {
        if let Some(((_, tick), clock)) = self.on {
            tick().await;
            self.ticks = self.ticks.saturating_add(1);
            self.note(phase, clock.now().0);
        }
    }

    /// One piece of the body was taken in (see [`Phase::Hash`]).
    pub(crate) async fn piece(&mut self) {
        if self.on.is_some() {
            self.pieces = self.pieces.saturating_add(1);
            self.lap(Phase::Hash).await;
        }
    }

    fn note(&mut self, phase: Phase, now: i64) {
        self.ms[phase as usize] += now.saturating_sub(self.last).max(0);
        self.last = self.last.max(now);
    }

    /// The line, after the time since the last mark went to `Other`.
    fn line(&mut self, now: i64) -> String {
        self.note(Phase::Other, now);
        let m = &self.ms;
        format!(
            "kind={} outcome={} bytes={} extents={} auth_ms={} wait_ms={} read_ms={} \
             hash_ms={} seal_ms={} r2_ms={} d1_ms={} other_ms={} wall_ms={} pieces={} ticks={}",
            self.kind,
            if self.ok { "ok" } else { "error" },
            self.bytes,
            self.extents,
            m[Phase::Auth as usize],
            m[Phase::Wait as usize],
            m[Phase::Read as usize],
            m[Phase::Hash as usize],
            m[Phase::Seal as usize],
            m[Phase::R2 as usize],
            m[Phase::D1 as usize],
            m[Phase::Other as usize],
            self.last - self.start,
            self.pieces,
            self.ticks,
        )
    }
}

impl Drop for WriteTrace<'_> {
    fn drop(&mut self) {
        if let Some(((to, _), clock)) = self.on {
            let line = self.line(clock.now().0);
            to(&line);
        }
    }
}
