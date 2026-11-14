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

/// Takes the record of the post job for `extent`, with its total up to
/// `now`. `None` = no post job ran for it.
pub fn take(extent: &ExtentId, now: UnixMs) -> Option<PostTrace> {
    RECORDS.with(|r| {
        r.borrow_mut().remove(extent.as_str()).map(|mut t| {
            t.total_ms = now.0 - t.started;
            t
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_is_taken_once_with_its_total() {
        let extent = ExtentId::new("x_trace_once");
        begin(&extent, UnixMs(1_000));
        note(&extent, |t| t.post_ms = 40);
        let t = take(&extent, UnixMs(1_250)).expect("record");
        assert_eq!((t.post_ms, t.total_ms), (40, 250));
        assert_eq!(take(&extent, UnixMs(2_000)), None);
    }

    #[test]
    fn the_line_names_no_extent() {
        let extent = ExtentId::new("x_secretive");
        begin(&extent, UnixMs(0));
        let line = take(&extent, UnixMs(5)).expect("record").to_string();
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
