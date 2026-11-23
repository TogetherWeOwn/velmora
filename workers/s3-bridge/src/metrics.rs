//! Writes request metrics to the Analytics Engine dataset bound as
//! `METRICS`. What a data point holds is decided in
//! `velmora_bridge::metrics`; nothing here adds a field.
//!
//! The binding is optional: without it, and on any failed write, the
//! request is answered as before and nothing is logged per request.

use std::cell::RefCell;

use velmora_bridge::metrics::{job_sample, Point};
use worker::js_sys::Reflect;
use worker::wasm_bindgen::JsValue;
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
pub fn queue_name<E>(read: impl FnOnce() -> Result<Option<String>, E>) -> String {
    read().ok().flatten().unwrap_or_default()
}

pub fn sample_binding(env: &Env) -> u32 {
    let value = Reflect::get(env, &JsValue::from_str("JOB_METRICS_SAMPLE"));
    read_sample(value.map(|v| (!v.is_undefined()).then(|| v.as_string())))
}

/// Absent defaults; readonly argument inspection failures, non-string
/// values (including numbers), and invalid strings all turn sampling off.
fn read_sample<E>(value: Result<Option<Option<String>>, E>) -> u32 {
    match value {
        Ok(None) => job_sample(None),
        Ok(Some(Some(value))) => job_sample(Some(&value)),
        Ok(Some(None)) | Err(_) => 0,
    }
}

/// Writes one point. A write is buffered by the runtime and never
/// awaited; its failure is not the request's.
pub fn write(point: &Point) {
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
    #[test]
    fn queue_name_ignores_throwing_undefined_and_numeric_getters() {
        // `JsValue::as_string()` is None for undefined and numbers. These
        // fixtures are its converted result; native Rust cannot call JS.
        let throwing = queue_name(|| Err(()));
        let undefined = queue_name(|| Ok::<_, ()>(None));
        let number = queue_name(|| Ok::<_, ()>(None));
        assert_eq!([throwing, undefined, number], [""; 3]);
        assert_eq!(
            queue_name(|| Ok::<_, ()>(Some("velmora-post".into()))),
            "velmora-post"
        );
    }

    #[test]
    fn job_sample_binding_distinguishes_absence_from_non_strings() {
        assert_eq!(read_sample(Ok::<_, ()>(None)), 8); // absent/undefined
        assert_eq!(read_sample(Ok::<_, ()>(Some(None))), 0); // present numeric 0
        assert_eq!(read_sample(Err(())), 0); // getter threw
        for (raw, rate) in [("1", 1), ("0", 0), ("malformed", 0)] {
            assert_eq!(read_sample(Ok::<_, ()>(Some(Some(raw.into())))), rate);
        }
    }
}
