//! The point-in-time bridge (tenancy ADR §8.3, gate 4).
//!
//! A SQLite Durable Object keeps 30 days of history. The calls that
//! reach it exist only on the object's own storage, and workers-rs
//! 0.8.7 binds none of them, so they go through the shim:
//!
//! - [`PointInTime::current`]: a bookmark for now.
//! - [`PointInTime::at`]: the bookmark for a wall-clock time.
//! - [`PointInTime::restore_on_next_session`]: the object is reset to a
//!   bookmark the next time it starts. The answer is a bookmark for the
//!   state just before the restore, which undoes it the same way.
//!
//! A restore takes effect only when the object restarts. The caller
//! ends the session at once with [`PointInTime::restart`]
//! (`ctx.abort()`, queued to run as soon as the current call has
//! returned), so no later request is served from the old state.
//!
//! Bookmarks are opaque strings. A bookmark of one object means nothing
//! to another.

use velmora_bridge::{BridgeError, Result};
use worker::js_sys::Promise;
use worker::wasm_bindgen::{self, prelude::wasm_bindgen, JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::worker_sys::DurableObjectStorage;
use worker::State;

#[wasm_bindgen(module = "/src/shim.js")]
extern "C" {
    #[wasm_bindgen(js_name = pitrCurrent, catch)]
    fn pitr_current(storage: &DurableObjectStorage) -> std::result::Result<Promise, JsValue>;
    #[wasm_bindgen(js_name = pitrAt, catch)]
    fn pitr_at(
        storage: &DurableObjectStorage,
        unix_ms: f64,
    ) -> std::result::Result<Promise, JsValue>;
    #[wasm_bindgen(js_name = pitrRestart)]
    fn pitr_restart(state: &JsValue);
    #[wasm_bindgen(js_name = pitrRestoreOnNextSession, catch)]
    fn pitr_restore(
        storage: &DurableObjectStorage,
        bookmark: &str,
    ) -> std::result::Result<Promise, JsValue>;
}

/// The point-in-time calls of one object.
pub struct PointInTime {
    state: JsValue,
    storage: DurableObjectStorage,
}

impl PointInTime {
    pub fn new(state: &State) -> Self {
        let raw_state: &JsValue = state.as_raw().as_ref();
        let storage = state.storage();
        let raw_storage: &JsValue = storage.as_raw().as_ref();
        PointInTime {
            state: raw_state.clone(),
            storage: raw_storage.clone().unchecked_into(),
        }
    }

    /// A bookmark for the current state.
    pub async fn current(&self) -> Result<String> {
        bookmark(pitr_current(&self.storage)).await
    }

    /// The bookmark for `unix_ms`, which must lie within the last 30
    /// days.
    pub async fn at(&self, unix_ms: i64) -> Result<String> {
        // Milliseconds since 1970 stay far inside a JS number.
        bookmark(pitr_at(&self.storage, unix_ms as f64)).await
    }

    /// Asks for the object to start from `bookmark` at its next start.
    /// Returns the bookmark that undoes it.
    pub async fn restore_on_next_session(&self, bookmark_to: &str) -> Result<String> {
        bookmark(pitr_restore(&self.storage, bookmark_to)).await
    }

    /// Ends this session of the object (`ctx.abort()`): the next request
    /// starts it again, from the bookmark asked for, if any.
    pub fn restart(&self) -> Result<()> {
        // The shim calls `abort()` after this call has returned, so the
        // throw it makes never passes through the wasm module.
        pitr_restart(&self.state);
        Ok(())
    }
}

async fn bookmark(call: std::result::Result<Promise, JsValue>) -> Result<String> {
    let promise = call.map_err(pitr_err)?;
    let value = JsFuture::from(promise).await.map_err(pitr_err)?;
    value
        .as_string()
        .ok_or_else(|| BridgeError::Sql("pitr: bookmark is not a string".into()))
}

/// The runtime's answer, kept: it names no data, and "not implemented
/// locally" must be told apart from a refused time.
fn pitr_err(e: JsValue) -> BridgeError {
    let message = e
        .dyn_ref::<worker::js_sys::Error>()
        .map(|e| String::from(e.message()))
        .unwrap_or_else(|| "unknown".into());
    BridgeError::Sql(format!("pitr: {message}"))
}
