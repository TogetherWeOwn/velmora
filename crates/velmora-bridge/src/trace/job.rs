//! Observation local to a sampled queue attempt, not to its extent or lease.

use std::cell::RefCell;
use std::future::{poll_fn, Future};

use crate::ports::Clock;
use crate::types::UnixMs;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JobKind {
    Post,
    Verify,
    Release,
    Repost,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum JobResult {
    #[default]
    Ok,
    NoPermit,
    Cooling,
    Fenced,
    Refused,
    Budget,
    Failed,
}

/// Only fixed dimensions, times and counts. The queue adapter supplies the
/// sample weight and sanitized lane separately.
#[derive(Default)]
pub struct JobTrace {
    pub(crate) kind: Option<JobKind>,
    pub(crate) result: JobResult,
    pub(crate) payload_bytes: Option<u64>,
    pub(crate) total_ms: u64,
    pub(crate) slot_wait_ms: u64,
    pub(crate) load_ms: u64,
    pub(crate) connect_ms: u64,
    pub(crate) wire_ms: u64,
    pub(crate) advance_ms: u64,
    pub(crate) wanted: u32,
    pub(crate) granted: u32,
    pub(crate) articles: u32,
    pub(crate) provider_bytes: [u64; 7],
    asked: Option<UnixMs>,
    first_grant: Option<UnixMs>,
    last_release: Option<UnixMs>,
    held: u32,
    dials: Activity,
    commands: Activity,
}

/// Wall-clock union of concurrent operations of the same kind.
#[derive(Default)]
struct Activity {
    since: Option<UnixMs>,
    active: u32,
}

impl Activity {
    fn start(&mut self, now: UnixMs) {
        self.since.get_or_insert(now);
        self.active += 1;
    }

    fn finish(&mut self, now: UnixMs) -> u64 {
        self.active = self.active.saturating_sub(1);
        if self.active == 0 {
            self.since.take().map_or(0, |start| elapsed(start, now))
        } else {
            0
        }
    }
}

pub(crate) fn elapsed(start: UnixMs, end: UnixMs) -> u64 {
    end.0.saturating_sub(start.0).max(0) as u64
}

impl JobTrace {
    pub(crate) fn ask(&mut self, at: UnixMs, wanted: u32) {
        self.asked.get_or_insert(at);
        self.wanted = self.wanted.max(wanted);
    }

    pub(crate) fn permit(&mut self, now: UnixMs, granted: bool) {
        if granted {
            self.first_grant.get_or_insert(now);
            self.held += 1;
            self.granted = self.granted.max(self.held);
        }
    }

    pub(crate) fn released(&mut self, now: UnixMs) {
        self.held = self.held.saturating_sub(1);
        self.last_release = Some(now);
    }

    pub(crate) fn permit_ms(&self) -> u64 {
        self.asked
            .zip(self.first_grant)
            .map_or(0, |(a, b)| elapsed(a, b))
    }

    pub(crate) fn held_ms(&self) -> u64 {
        self.first_grant
            .zip(self.last_release)
            .map_or(0, |(a, b)| elapsed(a, b))
    }

    /// Integrate the union of dial intervals: a parallel batch, its
    /// failover dials and its reconnects all contribute wall time once.
    pub(crate) fn connecting(&mut self, now: UnixMs) {
        self.dials.start(now);
    }

    pub(crate) fn connect_finished(&mut self, now: UnixMs) {
        self.connect_ms += self.dials.finish(now);
    }

    pub(crate) fn sent(&mut self, provider: &str, bytes: u64) {
        if let [b'p', digit @ b'1'..=b'7'] = provider.as_bytes() {
            let count = &mut self.provider_bytes[usize::from(digit - b'1')];
            *count = count.saturating_add(bytes);
        }
    }
}

thread_local! {
    static JOB: RefCell<Option<JobTrace>> = const { RefCell::new(None) };
}

pub(crate) fn job_note<R>(f: impl FnOnce(&mut JobTrace) -> R) -> Option<R> {
    JOB.with(|slot| slot.borrow_mut().as_mut().map(f))
}

/// Measure the wire command itself, excluding the dial and permit renewal
/// before it. Concurrent POST commands contribute wall time only once.
pub(crate) async fn observe_wire<T>(clock: &impl Clock, command: impl Future<Output = T>) -> T {
    job_note(|t| t.commands.start(clock.now()));
    let outcome = command.await;
    job_note(|t| t.wire_ms += t.commands.finish(clock.now()));
    outcome
}

/// Install the attempt only while its future is on the stack. Another job
/// interleaving at an await (even one for the same extent) cannot see it.
/// This does not retain a trace on cancellation or in an isolate-wide map.
pub async fn observe_job<T>(clock: &impl Clock, job: impl Future<Output = T>) -> (T, JobTrace) {
    struct Scope<'a> {
        saved: Option<JobTrace>,
        trace: &'a mut Option<JobTrace>,
    }
    impl Drop for Scope<'_> {
        fn drop(&mut self) {
            *self.trace = JOB.with(|slot| slot.replace(self.saved.take()));
        }
    }
    let started = clock.now();
    let mut job = std::pin::pin!(job);
    let mut trace = Some(JobTrace::default());
    let outcome = poll_fn(|cx| {
        let saved = JOB.with(|slot| slot.replace(trace.take()));
        let _scope = Scope {
            saved,
            trace: &mut trace,
        };
        job.as_mut().poll(cx)
    })
    .await;
    let mut trace = trace.expect("job observation restored after each poll");
    trace.total_ms = elapsed(started, clock.now());
    (outcome, trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::task::{Context, Poll, Waker};

    #[test]
    fn interleaved_attempts_keep_separate_timings_and_leave_no_context() {
        struct TestClock(Cell<i64>);
        impl Clock for TestClock {
            fn now(&self) -> UnixMs {
                UnixMs(self.0.get())
            }
        }
        let clock = TestClock(Cell::new(0));
        let mut first = true;
        let mut post = std::pin::pin!(observe_job(
            &clock,
            poll_fn(|_| {
                if std::mem::take(&mut first) {
                    job_note(|t| t.kind = Some(JobKind::Post));
                    job_note(|t| t.permit(UnixMs(10), true));
                    Poll::Pending
                } else {
                    job_note(|t| t.released(UnixMs(47)));
                    Poll::Ready(())
                }
            })
        ));
        let mut verify = std::pin::pin!(observe_job(&clock, async {
            job_note(|t| {
                t.kind = Some(JobKind::Verify);
                t.permit(UnixMs(21), true);
                t.released(UnixMs(22));
            });
            clock.0.set(23);
        }));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(post.as_mut().poll(&mut cx).is_pending());
        job_note(|_| panic!("an idle context accepted an observation"));
        clock.0.set(20);
        let Poll::Ready(((), verify)) = verify.as_mut().poll(&mut cx) else {
            panic!("verify finished immediately");
        };
        clock.0.set(50);
        let Poll::Ready(((), post)) = post.as_mut().poll(&mut cx) else {
            panic!("post finished after the second poll");
        };
        assert_eq!(verify.kind, Some(JobKind::Verify));
        assert_eq!((verify.total_ms, verify.held_ms()), (3, 1));
        assert_eq!(post.kind, Some(JobKind::Post));
        assert_eq!((post.total_ms, post.held_ms()), (50, 37));
    }

    #[test]
    fn connect_time_includes_redials_without_counting_overlap_twice() {
        let mut t = JobTrace::default();
        t.connecting(UnixMs(4));
        t.connecting(UnixMs(6));
        t.connect_finished(UnixMs(8));
        t.connect_finished(UnixMs(9));
        // A failover dial followed by a reconnect after the initial batch.
        t.connecting(UnixMs(12));
        t.connect_finished(UnixMs(14));
        t.connecting(UnixMs(18));
        t.connect_finished(UnixMs(22));
        assert_eq!(t.connect_ms, 11);
    }

    #[test]
    fn permits_report_first_grant_peak_width_and_last_release() {
        let mut t = JobTrace::default();
        t.ask(UnixMs(11), 3);
        t.permit(UnixMs(15), false);
        t.permit(UnixMs(17), true);
        t.permit(UnixMs(19), true);
        t.released(UnixMs(23));
        t.permit(UnixMs(26), true);
        t.released(UnixMs(27));
        t.released(UnixMs(30));
        assert_eq!(t.permit_ms(), 6);
        assert_eq!(t.held_ms(), 13);
        assert_eq!((t.wanted, t.granted), (3, 2));
    }
}
