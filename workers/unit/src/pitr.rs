//! The point-in-time bridge: a unit's 30 days of history.
//!
//! A SQLite Durable Object keeps 30 days of history. The calls that
//! reach it exist only on the object's own storage, and workers-rs
//! 0.8.7 binds none of them, so they go through the shim:
//!
//! - [`PointInTime::current`]: a bookmark for now.
//! - [`PointInTime::at`]: the bookmark for a wall-clock time.
//! - [`PointInTime::restore_now`]: the object starts again from a
//!   bookmark. Arming the restore and ending the session are one step in
//!   the shim, so a restore is never left armed while the object goes on
//!   taking writes (they would be lost at its next restart). **The call
//!   does not return to its request:** `abort()` resets the object, the
//!   request fails, and the next request finds the restored state. The
//!   caller takes [`PointInTime::current`] first and keeps that bookmark
//!   outside the object; restoring it undoes the restore exactly only if
//!   no write commits in between, so the restore call must close the unit
//!   (no call writes) before it takes the bookmark. The bookmark that
//!   `onNextSessionRestoreBookmark` returns cannot leave the request,
//!   which ends in the reset.
//!
//! Bookmarks are opaque strings. A bookmark of one object means nothing
//! to another. Local workerd has no history: `at` and a restore answer
//! that the back end "does not implement point-in-time recovery".

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
    #[wasm_bindgen(js_name = pitrRestoreNow, catch)]
    fn pitr_restore_now(
        state: &JsValue,
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
    /// days and after the object was made (or last emptied).
    pub async fn at(&self, unix_ms: i64) -> Result<String> {
        // Milliseconds since 1970 stay far inside a JS number.
        bookmark(pitr_at(&self.storage, unix_ms as f64)).await
    }

    /// Restores the object to `bookmark` now: arms the restore and ends
    /// the session in one step. Answers only if the runtime refused the
    /// bookmark; otherwise the object is reset and this request fails.
    pub async fn restore_now(&self, bookmark_to: &str) -> Result<()> {
        let promise =
            pitr_restore_now(&self.state, &self.storage, bookmark_to).map_err(pitr_err)?;
        JsFuture::from(promise).await.map_err(pitr_err)?;
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
