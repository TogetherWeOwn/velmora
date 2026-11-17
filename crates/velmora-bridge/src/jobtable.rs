//! The jobs an isolate runs, held where a later invocation can reach
//! them.
//!
//! A job holds a [`Charge`](crate::ingress::Charge) against the
//! isolate's byte budget, an extent in memory and its sockets. All of it
//! is given back when the future of the job is dropped. An invocation
//! that the runtime cancels (the queue's connection to the consumer is
//! lost, say) is not dropped: its future is never polled again, and
//! nothing ever runs its destructors. The isolate lives on and serves
//! the next invocations with those bytes still charged; after a few such
//! jobs every job waits for room that never comes.
//!
//! So a job does not live in the frame of its invocation. The invocation
//! puts it in the isolate's [`JobTable`] and polls it there
//! ([`JobTable::run`]). A job that ends, or whose invocation is dropped,
//! leaves the table. One that is still there after
//! [`JOB_MAX_AGE_MS`] belongs to an invocation that is gone, since the
//! platform ends every invocation before that: [`JobTable::reap`] drops
//! it, which gives back its charge and its memory together. A charge is
//! therefore never given back while its memory may still be in use.
//!
//! Sixteen minutes is long: cancelled invocations come in bursts, and a
//! few of them hold the budget of an isolate until then. So a live
//! invocation also marks its job every [`JOB_BEAT_MS`]
//! ([`Running::seen`]), on a timer of its own. The timers of a cancelled
//! invocation never fire, so its job stops being marked, and
//! [`JobTable::reap_quiet`] drops a job not marked for [`JOB_QUIET_MS`].
//! Should a live invocation be that late once, its job is dropped and
//! its message is tried again: nothing is given back twice, and no
//! memory stays in use behind a charge that was returned.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use futures_util::future::LocalBoxFuture;

use crate::types::UnixMs;

/// The age at which a job in the table is taken to be abandoned: 16
/// minutes. An invocation of a queue consumer is ended by the platform
/// after 15 minutes of wall time, so nothing polls a job older than
/// that. Only for jobs that run inside one such invocation.
pub const JOB_MAX_AGE_MS: i64 = 16 * 60 * 1000;

/// How often a live invocation marks its job as seen.
pub const JOB_BEAT_MS: i64 = 5_000;

/// A job not marked for this long belongs to an invocation that no
/// longer runs: twelve marks in a row were missed.
pub const JOB_QUIET_MS: i64 = 60_000;

struct Slot<'a, T> {
    id: u64,
    started: UnixMs,
    /// When its invocation last showed it was running.
    seen: UnixMs,
    /// `None` while the job is being polled.
    job: Option<LocalBoxFuture<'a, T>>,
}

struct Inner<'a, T> {
    next_id: Cell<u64>,
    slots: RefCell<Vec<Slot<'a, T>>>,
    reaped: Cell<u64>,
}

impl<'a, T> Inner<'a, T> {
    /// Takes the slot off the table. The caller drops it, after the
    /// borrow has ended: what a job drops may look at the table.
    fn remove(&self, id: u64) -> Option<Slot<'a, T>> {
        let mut slots = self.slots.borrow_mut();
        let at = slots.iter().position(|s| s.id == id)?;
        Some(slots.swap_remove(at))
    }
}

/// The jobs of one isolate that have begun and not ended. One per
/// isolate (an `Rc` inside; a clone is the same table).
pub struct JobTable<'a, T> {
    inner: Rc<Inner<'a, T>>,
}

impl<T> Clone for JobTable<'_, T> {
    fn clone(&self) -> Self {
        JobTable {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<T> Default for JobTable<'_, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, T> JobTable<'a, T> {
    pub fn new() -> Self {
        JobTable {
            inner: Rc::new(Inner {
                next_id: Cell::new(0),
                slots: RefCell::new(Vec::new()),
                reaped: Cell::new(0),
            }),
        }
    }

    /// Puts `job` in the table as begun at `now`. The future returned
    /// polls it there and gives its output; `None` when the job was
    /// dropped by [`Self::reap`] meanwhile. Dropping that future drops
    /// the job. A future that is neither polled nor dropped leaves the
    /// job in the table, for `reap` to find.
    pub fn run(&self, now: UnixMs, job: impl Future<Output = T> + 'a) -> Running<'a, T> {
        let id = self.inner.next_id.get();
        self.inner.next_id.set(id.wrapping_add(1));
        self.inner.slots.borrow_mut().push(Slot {
            id,
            started: now,
            seen: now,
            job: Some(Box::pin(job)),
        });
        Running {
            inner: Rc::clone(&self.inner),
            id,
        }
    }

    /// Drops every job that began `max_age_ms` or longer before `now`,
    /// and says how many. Each is dropped once: the future that ran it
    /// finds it gone, and gives back nothing a second time.
    ///
    /// The future that ran a dropped job is not woken, on purpose: were
    /// its invocation cancelled, a wake would resume that invocation
    /// inside this one. Should it be alive after all, it learns of the
    /// drop when something else wakes it.
    pub fn reap(&self, now: UnixMs, max_age_ms: i64) -> usize {
        self.reap_where(|s| now.0.saturating_sub(s.started.0) >= max_age_ms)
    }

    /// Drops every job whose invocation has not marked it
    /// ([`Running::seen`]) for `max_quiet_ms`, and says how many. As
    /// [`Self::reap`] otherwise.
    pub fn reap_quiet(&self, now: UnixMs, max_quiet_ms: i64) -> usize {
        self.reap_where(|s| now.0.saturating_sub(s.seen.0) >= max_quiet_ms)
    }

    fn reap_where(&self, gone: impl Fn(&Slot<'a, T>) -> bool) -> usize {
        let mut n = 0;
        // One at a time, each off the table and counted before it is
        // dropped, with the table free: should a destructor fail, the
        // jobs behind it are still in the table for the next call.
        loop {
            let old = {
                let mut slots = self.inner.slots.borrow_mut();
                let at = slots.iter().position(&gone);
                at.map(|at| slots.swap_remove(at))
            };
            let Some(old) = old else {
                return n;
            };
            n += 1;
            self.inner
                .reaped
                .set(self.inner.reaped.get().saturating_add(1));
            drop(old);
        }
    }

    /// Jobs in the table now.
    pub fn len(&self) -> usize {
        self.inner.slots.borrow().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// When the oldest job in the table began.
    pub fn oldest(&self) -> Option<UnixMs> {
        self.inner.slots.borrow().iter().map(|s| s.started).min()
    }

    /// Jobs dropped by [`Self::reap`] since the isolate began.
    pub fn reaped(&self) -> u64 {
        self.inner.reaped.get()
    }
}

/// A job in a [`JobTable`], as its invocation holds it.
#[must_use = "a job runs only while this is polled"]
pub struct Running<'a, T> {
    inner: Rc<Inner<'a, T>>,
    id: u64,
}

impl<T> Running<'_, T> {
    /// Marks the job as seen running at `now`. Its invocation calls
    /// this on a timer of its own, every [`JOB_BEAT_MS`], for as long as
    /// it waits for the job. Never moves the mark back.
    pub fn seen(&self, now: UnixMs) {
        let mut slots = self.inner.slots.borrow_mut();
        if let Some(slot) = slots.iter_mut().find(|s| s.id == self.id) {
            if now.0 > slot.seen.0 {
                slot.seen = now;
            }
        }
    }
}

impl<T> Future for Running<'_, T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        // The job is polled outside the table's borrow: it may start or
        // end other jobs.
        let job = {
            let mut slots = self.inner.slots.borrow_mut();
            slots
                .iter_mut()
                .find(|s| s.id == self.id)
                .and_then(|s| s.job.take())
        };
        // Reaped, or ended on an earlier poll.
        let Some(mut job) = job else {
            return Poll::Ready(None);
        };
        match job.as_mut().poll(cx) {
            Poll::Ready(out) => {
                let slot = self.inner.remove(self.id);
                drop(slot);
                drop(job);
                Poll::Ready(Some(out))
            }
            Poll::Pending => {
                let mut slots = self.inner.slots.borrow_mut();
                match slots.iter_mut().find(|s| s.id == self.id) {
                    Some(slot) => {
                        slot.job = Some(job);
                        Poll::Pending
                    }
                    // Reaped during its own poll: dropped with the
                    // table free.
                    None => {
                        drop(slots);
                        drop(job);
                        Poll::Ready(None)
                    }
                }
            }
        }
    }
}

impl<T> Drop for Running<'_, T> {
    fn drop(&mut self) {
        let slot = self.inner.remove(self.id);
        drop(slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::ByteBudget;
    use futures_util::future::pending;
    use futures_util::FutureExt;

    const MIB: u64 = 1024 * 1024;

    /// A job as the queue consumer runs one: it charges, then waits on
    /// something that never comes.
    async fn stuck(budget: Rc<ByteBudget>, bytes: u64) -> i32 {
        let _charge = budget.charge_job(bytes).await.expect("room");
        pending().await
    }

    #[test]
    fn a_job_that_ends_or_is_dropped_leaves_the_table_and_gives_its_bytes_back() {
        let budget = Rc::new(ByteBudget::new(72 * MIB));
        let table = JobTable::new();
        let b = Rc::clone(&budget);
        let done = table.run(UnixMs(0), async move {
            let _charge = b.charge_job(22 * MIB).await.expect("room");
            7
        });
        assert_eq!(table.len(), 1);
        assert_eq!(done.now_or_never(), Some(Some(7)));
        assert_eq!((table.len(), budget.in_use()), (0, 0));

        let mut dropped = table.run(UnixMs(0), stuck(Rc::clone(&budget), 22 * MIB));
        assert!((&mut dropped).now_or_never().is_none());
        assert_eq!((table.len(), budget.in_use()), (1, 22 * MIB));
        drop(dropped);
        assert_eq!((table.len(), budget.in_use()), (0, 0));
        assert_eq!(table.reaped(), 0);
    }

    /// The invocation of a job is cancelled by the runtime: its future is
    /// never polled again and never dropped. Its bytes come back when
    /// the job is older than any invocation can be.
    #[test]
    fn an_abandoned_job_gives_its_bytes_back_once_it_is_too_old_to_be_running() {
        let budget = Rc::new(ByteBudget::new(72 * MIB));
        let table = JobTable::new();
        for _ in 0..3 {
            let mut job = table.run(UnixMs(1_000), stuck(Rc::clone(&budget), 22 * MIB));
            assert!((&mut job).now_or_never().is_none());
            // Never polled again, never dropped.
            std::mem::forget(job);
        }
        // The stall: three abandoned jobs hold the isolate's budget.
        assert_eq!(budget.in_use(), 66 * MIB);
        assert!(budget.try_charge_job(22 * MIB).is_none());

        // An invocation may still be running: nothing is touched.
        assert_eq!(
            table.reap(UnixMs(1_000 + JOB_MAX_AGE_MS - 1), JOB_MAX_AGE_MS),
            0
        );
        assert_eq!((table.len(), budget.in_use()), (3, 66 * MIB));
        assert_eq!(table.oldest(), Some(UnixMs(1_000)));

        assert_eq!(
            table.reap(UnixMs(1_000 + JOB_MAX_AGE_MS), JOB_MAX_AGE_MS),
            3
        );
        assert_eq!((table.len(), budget.in_use()), (0, 0));
        assert_eq!(table.reaped(), 3);
        assert!(budget.try_charge_job(22 * MIB).is_some());
    }

    /// A cancelled invocation stops marking its job, and the bytes come
    /// back after [`JOB_QUIET_MS`], not after sixteen minutes. A job of
    /// a live invocation is kept however long it runs.
    #[test]
    fn a_job_whose_invocation_went_quiet_gives_its_bytes_back_soon() {
        let budget = Rc::new(ByteBudget::new(72 * MIB));
        let table = JobTable::new();
        let mut live = table.run(UnixMs(1_000), stuck(Rc::clone(&budget), 22 * MIB));
        assert!((&mut live).now_or_never().is_none());
        for _ in 0..2 {
            let mut job = table.run(UnixMs(1_000), stuck(Rc::clone(&budget), 22 * MIB));
            assert!((&mut job).now_or_never().is_none());
            job.seen(UnixMs(3_000));
            // Cancelled: never polled, marked or dropped again.
            std::mem::forget(job);
        }
        assert!(budget.try_charge_job(22 * MIB).is_none());

        // The live invocation marks its job every few seconds.
        let mut now = 3_000;
        while now + JOB_BEAT_MS < 3_000 + JOB_QUIET_MS {
            now += JOB_BEAT_MS;
            live.seen(UnixMs(now));
            assert_eq!(table.reap_quiet(UnixMs(now), JOB_QUIET_MS), 0);
        }
        assert_eq!(
            table.reap_quiet(UnixMs(3_000 + JOB_QUIET_MS - 1), JOB_QUIET_MS),
            0
        );
        assert_eq!((table.len(), budget.in_use()), (3, 66 * MIB));

        live.seen(UnixMs(3_000 + JOB_QUIET_MS));
        assert_eq!(
            table.reap_quiet(UnixMs(3_000 + JOB_QUIET_MS), JOB_QUIET_MS),
            2
        );
        assert_eq!((table.len(), budget.in_use()), (1, 22 * MIB));
        assert_eq!(table.reaped(), 2);
        assert!(budget.try_charge_job(22 * MIB).is_some());

        // Long after, the live job is still there: it is not its age
        // that drops it.
        let late = 3_000 + 10 * JOB_QUIET_MS;
        live.seen(UnixMs(late));
        assert_eq!(
            table.reap_quiet(UnixMs(late + JOB_BEAT_MS), JOB_QUIET_MS),
            0
        );
        assert!((&mut live).now_or_never().is_none());
        assert_eq!(table.len(), 1);
    }

    /// A job that was never marked counts from when it began, and a
    /// mark never moves a job back in time.
    #[test]
    fn an_unmarked_job_is_quiet_from_its_start() {
        let table: JobTable<'_, i32> = JobTable::new();
        let job = table.run(UnixMs(5_000), pending());
        job.seen(UnixMs(4_000));
        assert_eq!(
            table.reap_quiet(UnixMs(5_000 + JOB_QUIET_MS - 1), JOB_QUIET_MS),
            0
        );
        assert_eq!(
            table.reap_quiet(UnixMs(5_000 + JOB_QUIET_MS), JOB_QUIET_MS),
            1
        );
        // The invocation was alive after all: it finds the job gone.
        job.seen(UnixMs(5_000 + JOB_QUIET_MS));
        assert_eq!(job.now_or_never(), Some(None));
    }

    /// A job that was dropped for its age gives its bytes back once: not
    /// again when the future that ran it is polled, or dropped. Giving
    /// them back twice would let more run than the isolate has memory
    /// for.
    #[test]
    fn a_reaped_job_gives_its_bytes_back_exactly_once() {
        let budget = Rc::new(ByteBudget::new(72 * MIB));
        let table = JobTable::new();
        let mut old = table.run(UnixMs(0), stuck(Rc::clone(&budget), 22 * MIB));
        assert!((&mut old).now_or_never().is_none());
        let mut young = table.run(UnixMs(JOB_MAX_AGE_MS), stuck(Rc::clone(&budget), 30 * MIB));
        assert!((&mut young).now_or_never().is_none());
        assert_eq!(budget.in_use(), 52 * MIB);

        assert_eq!(table.reap(UnixMs(JOB_MAX_AGE_MS), JOB_MAX_AGE_MS), 1);
        assert_eq!((table.len(), budget.in_use()), (1, 30 * MIB));
        // Its invocation was alive after all: it is told, and nothing
        // moves.
        assert_eq!((&mut old).now_or_never(), Some(None));
        assert_eq!((&mut old).now_or_never(), Some(None));
        drop(old);
        assert_eq!(table.reap(UnixMs(JOB_MAX_AGE_MS), JOB_MAX_AGE_MS), 0);
        assert_eq!((table.len(), budget.in_use()), (1, 30 * MIB));
        assert!((&mut young).now_or_never().is_none());
        drop(young);
        assert_eq!((table.len(), budget.in_use()), (0, 0));
    }

    /// A job may reap from inside its own poll, and what a reaped job
    /// drops may use the table.
    #[test]
    fn the_table_is_free_while_a_job_is_polled_or_dropped() {
        struct OnDrop<'a>(JobTable<'a, ()>, Rc<Cell<usize>>);
        impl Drop for OnDrop<'_> {
            fn drop(&mut self) {
                self.1.set(self.0.len() + 100);
            }
        }
        let table: JobTable<'_, ()> = JobTable::new();
        let seen = Rc::new(Cell::new(0));
        let guard = OnDrop(table.clone(), Rc::clone(&seen));
        let inner = table.clone();
        let mut job = table.run(UnixMs(0), async move {
            let _guard = guard;
            // Old enough already: this drops the job that is running.
            inner.reap(UnixMs(JOB_MAX_AGE_MS), JOB_MAX_AGE_MS);
            pending::<()>().await;
        });
        assert_eq!((&mut job).now_or_never(), Some(None));
        assert_eq!(seen.get(), 100);
        assert!(table.is_empty());
    }
}
