//! Writes request metrics to the Analytics Engine dataset bound as
//! `METRICS`. What a data point holds is decided in
//! `velmora_bridge::metrics`; nothing here adds a field.
//!
//! The binding is optional: without it, and on any failed write, the
//! request is answered as before and nothing is logged per request.

use std::cell::RefCell;

use velmora_bridge::metrics::Point;
use worker::{AnalyticsEngineDataPointBuilder, AnalyticsEngineDataset, Env};

/// The dataset binding.
pub const BINDING: &str = "METRICS";

thread_local! {
    /// The dataset of this isolate; the read from Usenet that reports a
    /// cache miss has no `Env` at hand.
    static DATASET: RefCell<Option<AnalyticsEngineDataset>> = const { RefCell::new(None) };
}

/// Looks the binding up, once per request: it costs no I/O.
pub fn bind(env: &Env) {
    let dataset = env.analytics_engine(BINDING).ok();
    DATASET.with(|d| *d.borrow_mut() = dataset);
}

/// Writes one point. A write is buffered by the runtime and never
/// awaited; its failure is not the request's.
pub fn write(point: &Point) {
    DATASET.with(|d| {
        let d = d.borrow();
        let Some(dataset) = d.as_ref() else {
            return;
        };
        let mut blobs: Vec<&str> = point.blobs.clone();
        blobs.push(&point.colo);
        let _ = AnalyticsEngineDataPointBuilder::new()
            .indexes([point.index])
            .blobs(blobs)
            .doubles(point.doubles.iter().copied())
            .write_to(dataset);
    });
}
