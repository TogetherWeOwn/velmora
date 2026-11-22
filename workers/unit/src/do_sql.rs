//! `impl Sql` over the SQLite storage of a Durable Object.
//!
//! Every statement runs through the JavaScript shim (`shim.js`): a
//! `batch` inside `storage.transactionSync`, so it is all or nothing, and
//! rows changed are the difference of `total_changes()` around each
//! statement, which counts the rows triggers change (as D1's
//! `meta.changes` and the native test adapter do).
//!
//! Value mapping:
//! - `Null` <-> JS `null` (`undefined` reads as `Null` too).
//! - `Int` -> JS number, **bound through `+CAST(?N AS INTEGER)`**. The
//!   runtime binds every JS number as a SQLite REAL, so an integer bound
//!   plainly would be stored as `7.0` in a TEXT column, divide as a
//!   fraction (`?/2` of 5 is 2.5) and print as `5.0` in `json_array`.
//!   [`bind_text`] wraps every placeholder whose value is an `Int`, so
//!   SQLite sees the integer that a native binding gives, without the
//!   affinity a bare `CAST` would add. Only integers
//!   in `±(2^53 - 1)` are bound; others are refused before the call.
//! - `Int` <- JS number. A returned number that is fractional or outside
//!   `±(2^53 - 1)` is a decode error: the runtime rounds a larger
//!   integer silently (`SELECT 9007199254740993` reads as
//!   `9007199254740992`), so such a value is never taken.
//! - `Text` <-> JS string.
//! - `Blob` -> `Uint8Array`; a returned BLOB is an `ArrayBuffer`.
//!
//! Errors: a failure whose text is the `tx_guard` CHECK
//! ([`velmora_bridge::is_tx_guard_violation`]) is `GuardFailed`. Every
//! other failure is `BridgeError::Sql` with a class only, the classes of
//! the D1 adapter (`do: constraint violation`, `do: statement failed`):
//! no SQL text, parameter or database message leaves the adapter.

pub use velmora_bridge::sql_bind::{bind_text, significant_end};
use velmora_bridge::{
    is_tx_guard_violation, BridgeError, Result, Row, Sql, SqlValue, MAX_SQL_PARAMS,
    MAX_SQL_VALUE_BYTES,
};
use worker::js_sys::{self, Array, ArrayBuffer, Uint8Array};
use worker::wasm_bindgen::{self, prelude::wasm_bindgen, JsCast, JsValue};
use worker::worker_sys::DurableObjectStorage;
use worker::Storage;

/// Largest integer a JS number holds exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INT: i64 = (1 << 53) - 1;

#[wasm_bindgen(module = "/src/shim.js")]
extern "C" {
    #[wasm_bindgen(js_name = doQuery, catch)]
    fn do_query(
        storage: &DurableObjectStorage,
        text: &str,
        params: &Array,
    ) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = doExec, catch)]
    fn do_exec(
        storage: &DurableObjectStorage,
        text: &str,
        params: &Array,
    ) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = doBatch, catch)]
    fn do_batch(
        storage: &DurableObjectStorage,
        stmts: &Array,
    ) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = doApply, catch)]
    fn do_apply(storage: &DurableObjectStorage, script: &str) -> std::result::Result<(), JsValue>;
    #[wasm_bindgen(js_name = doDatabaseSize, catch)]
    fn do_database_size(storage: &DurableObjectStorage) -> std::result::Result<JsValue, JsValue>;
}

/// The SQLite storage of one Durable Object as a [`Sql`].
pub struct DoSql {
    storage: DurableObjectStorage,
}

impl DoSql {
    pub fn new(storage: &Storage) -> Self {
        let raw: &JsValue = storage.as_raw().as_ref();
        DoSql {
            storage: raw.clone().unchecked_into(),
        }
    }

    /// Runs a script of several statements (a migration) in one
    /// transaction. Not a [`Sql`] call: catalogue code never runs a
    /// script.
    ///
    /// Comments after the last statement are dropped first: the runtime
    /// refuses a script whose last part holds no statement ("SQL code did
    /// not contain a statement"), and migration 0017 ends in a comment.
    /// A script of comments alone runs nothing.
    pub fn apply(&self, script: &str) -> Result<()> {
        let end = significant_end(script);
        if end == 0 {
            return Ok(());
        }
        do_apply(&self.storage, &script[..end]).map_err(map_err)
    }

    /// The storage handle, for the other shim calls of this crate.
    pub(crate) fn raw(&self) -> &DurableObjectStorage {
        &self.storage
    }

    /// Size of the database in bytes, as the runtime reports it.
    pub fn database_size(&self) -> Result<u64> {
        let n = do_database_size(&self.storage).map_err(map_err)?;
        let n = n.as_f64().ok_or_else(decode_err)?;
        u64::try_from(number_to_int(n)?).map_err(|_| decode_err())
    }

    fn prepared(sql: &str, params: &[SqlValue]) -> Result<(String, Array)> {
        check_params(params)?;
        let text = bind_text(sql, params)?.into_owned();
        let values = params.iter().map(to_js).collect::<Result<Array>>()?;
        Ok((text, values))
    }
}

impl Sql for DoSql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        let (text, values) = Self::prepared(sql, params)?;
        let rows = do_query(&self.storage, &text, &values).map_err(map_err)?;
        let rows = rows.dyn_into::<Array>().map_err(|_| decode_err())?;
        rows.iter()
            .map(|row| {
                let row = row.dyn_into::<Array>().map_err(|_| decode_err())?;
                row.iter().map(from_js).collect()
            })
            .collect()
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        let (text, values) = Self::prepared(sql, params)?;
        changes(&do_exec(&self.storage, &text, &values).map_err(map_err)?)
    }

    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        if stmts.is_empty() {
            return Ok(Vec::new());
        }
        let list = Array::new();
        for (sql, params) in &stmts {
            let (text, values) = Self::prepared(sql, params)?;
            let pair = Array::new();
            pair.push(&JsValue::from_str(&text));
            pair.push(&values);
            list.push(&pair);
        }
        let results = do_batch(&self.storage, &list).map_err(map_err)?;
        let results = results.dyn_into::<Array>().map_err(|_| decode_err())?;
        if results.length() as usize != stmts.len() {
            return Err(decode_err());
        }
        results.iter().map(|n| changes(&n)).collect()
    }
}

/// Refuses what D1 refuses, with the same messages: more than
/// [`MAX_SQL_PARAMS`] bound values, or one above [`MAX_SQL_VALUE_BYTES`].
/// The SQLite storage of a Durable Object has the same two limits.
fn check_params(params: &[SqlValue]) -> Result<()> {
    if params.len() > MAX_SQL_PARAMS {
        return Err(BridgeError::Sql(format!(
            "too many bound parameters: {} > {MAX_SQL_PARAMS}",
            params.len()
        )));
    }
    let size = |v: &SqlValue| match v {
        SqlValue::Text(t) => t.len(),
        SqlValue::Blob(b) => b.len(),
        SqlValue::Null | SqlValue::Int(_) => 0,
    };
    if let Some(n) = params.iter().map(size).find(|n| *n > MAX_SQL_VALUE_BYTES) {
        return Err(BridgeError::Sql(format!(
            "bound value too large: {n} > {MAX_SQL_VALUE_BYTES}"
        )));
    }
    Ok(())
}

fn to_js(v: &SqlValue) -> Result<JsValue> {
    Ok(match v {
        SqlValue::Null => JsValue::NULL,
        SqlValue::Int(i) => JsValue::from_f64(int_to_number(*i)?),
        SqlValue::Text(s) => JsValue::from_str(s),
        SqlValue::Blob(b) => Uint8Array::from(b.as_slice()).into(),
    })
}

fn from_js(v: JsValue) -> Result<SqlValue> {
    if v.is_null() || v.is_undefined() {
        return Ok(SqlValue::Null);
    }
    if let Some(s) = v.as_string() {
        return Ok(SqlValue::Text(s));
    }
    if let Some(f) = v.as_f64() {
        return number_to_int(f).map(SqlValue::Int);
    }
    if let Some(buf) = v.dyn_ref::<ArrayBuffer>() {
        return Ok(SqlValue::Blob(Uint8Array::new(buf).to_vec()));
    }
    if let Some(arr) = v.dyn_ref::<Uint8Array>() {
        return Ok(SqlValue::Blob(arr.to_vec()));
    }
    Err(decode_err())
}

/// A rows-changed count from the shim; anything but a whole number is an
/// error, never "0 rows changed" (fenced catalogue calls read 0 as "lease
/// lost").
fn changes(n: &JsValue) -> Result<u64> {
    let f = n.as_f64().ok_or_else(decode_err)?;
    u64::try_from(number_to_int(f)?).map_err(|_| decode_err())
}

fn int_to_number(i: i64) -> Result<f64> {
    if !(-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&i) {
        return Err(BridgeError::Sql("do: integer outside JS safe range".into()));
    }
    Ok(i as f64)
}

fn number_to_int(f: f64) -> Result<i64> {
    let safe = MAX_SAFE_INT as f64;
    if !f.is_finite() || f.fract() != 0.0 || f.abs() > safe {
        return Err(BridgeError::Sql("do: number is not a safe integer".into()));
    }
    Ok(f as i64)
}

fn decode_err() -> BridgeError {
    BridgeError::Sql("do: unexpected result shape".into())
}

/// The runtime's error as a class. The `tx_guard` CHECK is
/// `GuardFailed`; a constraint failure and any other failure keep only
/// their class.
pub(crate) fn runtime_error(e: JsValue) -> BridgeError {
    map_err(e)
}

fn map_err(e: JsValue) -> BridgeError {
    let message = e
        .dyn_ref::<js_sys::Error>()
        .map(|e| String::from(e.message()))
        .or_else(|| e.as_string())
        .unwrap_or_default();
    if is_tx_guard_violation(&message) {
        BridgeError::GuardFailed
    } else if message.contains("constraint failed") {
        BridgeError::Sql("do: constraint violation".into())
    } else {
        BridgeError::Sql("do: statement failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_integers_are_refused_both_ways() {
        assert!(int_to_number(MAX_SAFE_INT).is_ok());
        assert!(int_to_number(-MAX_SAFE_INT).is_ok());
        assert!(int_to_number(MAX_SAFE_INT + 1).is_err());
        assert!(number_to_int(9_007_199_254_740_992.0).is_err());
        assert!(number_to_int(2.5).is_err());
        assert!(number_to_int(f64::NAN).is_err());
        assert_eq!(number_to_int(-42.0).unwrap(), -42);
    }

    #[test]
    fn parameter_limits_match_d1() {
        let many = vec![SqlValue::Null; MAX_SQL_PARAMS + 1];
        assert!(check_params(&many).is_err());
        assert!(check_params(&many[..MAX_SQL_PARAMS]).is_ok());
        let big = vec![SqlValue::Blob(vec![0; MAX_SQL_VALUE_BYTES + 1])];
        assert!(check_params(&big).is_err());
    }
}
