//! Writes request metrics to the Analytics Engine dataset bound as
//! `METRICS`. What a data point holds is decided in
//! `velmora_bridge::metrics`; nothing here adds a field.
//!
//! The binding is optional: without it, and on any failed write, the
//! request is answered as before and nothing is logged per request.

use std::cell::RefCell;
use std::future::Future;

use velmora_bridge::{metrics::Point, JobOutcome};
use worker::{AnalyticsEngineDataPointBuilder, AnalyticsEngineDataset, Env};

/// The dataset binding.
pub const BINDING: &str = "METRICS";

thread_local! {
    /// The dataset of this isolate; the read from Usenet that reports a
    /// cache miss has no `Env` at hand.
    static DATASET: RefCell<Option<AnalyticsEngineDataset>> = const { RefCell::new(None) };
}

thread_local! {
    static SEEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// A number no other request of this isolate got: what a request
/// without an id of its own is sampled by.
pub fn next() -> u64 {
    SEEN.with(|n| {
        n.set(n.get().wrapping_add(1));
        n.get()
    })
}

/// Looks the binding up, once per request: it costs no I/O.
pub fn bind(env: &Env) -> bool {
    let dataset = env.analytics_engine(BINDING).ok();
    let bound = dataset.is_some();
    DATASET.with(|d| *d.borrow_mut() = dataset);
    bound
}

/// Queue metadata may be absent or throw. An unrecognized/empty name is
/// mapped to `aux` by the point encoder; it cannot interrupt the job.
pub fn queue_name<E>(read: impl FnOnce() -> Result<String, E>) -> String {
    read().unwrap_or_default()
}

pub async fn emit_job(run: impl Future<Output = (JobOutcome, Option<Point>)>) -> JobOutcome {
    let (outcome, point) = run.await;
    if let Some(point) = point {
        write(&point);
    }
    outcome
}

#[cfg(test)]
thread_local! {
    static WRITTEN: RefCell<Vec<Point>> = const { RefCell::new(Vec::new()) };
}

/// Writes one point. A write is buffered by the runtime and never
/// awaited; its failure is not the request's.
pub fn write(point: &Point) {
    #[cfg(test)]
    WRITTEN.with(|points| points.borrow_mut().push(point.clone()));
    DATASET.with(|d| {
        let d = d.borrow();
        let Some(dataset) = d.as_ref() else {
            return;
        };
        let _ = AnalyticsEngineDataPointBuilder::new()
            .indexes([point.index])
            .blobs(point.analytics_blobs())
            .doubles(point.doubles.iter().copied())
            .write_to(dataset);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    use velmora_bridge::JobOutcome;

    #[test]
    fn queue_job_emit_keeps_ack_and_retry_even_without_queue_metadata() {
        let missing = queue_name(|| Err(()));
        assert!(missing.is_empty());
        for outcome in [JobOutcome::Ack, JobOutcome::Retry { delay_secs: 123 }] {
            // No typed SDK getter is required to execute and settle the job.
            assert_eq!(
                emit_job(async { (outcome, None) }).now_or_never(),
                Some(outcome)
            );
            let point = velmora_bridge::metrics::cold_read_point();
            assert_eq!(
                emit_job(async { (outcome, Some(point.clone())) }).now_or_never(),
                Some(outcome)
            );
            assert_eq!(WRITTEN.with(|points| points.take()), [point]);
        }
    }
}
