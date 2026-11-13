//! `impl Sql` over D1.
//!
//! Value mapping:
//! - `Null` <-> JS `null` (`undefined` reads as `Null` too).
//! - `Int` <-> JS number. D1 has no BigInt binding, so only integers in
//!   `±(2^53 - 1)` round-trip exactly. A bound `Int` outside that range is
//!   refused, and a returned number that is fractional or outside it is a
//!   decode error: values are never rounded. Every catalogue integer
//!   (millisecond times, sizes, counters, fencing tokens) is far inside it.
//! - `Text` <-> JS string.
//! - `Blob` -> `ArrayBuffer` (D1's BLOB binding). A returned BLOB may be an
//!   array of byte numbers, an `ArrayBuffer` or a `Uint8Array`.
//!
//! Errors: a failure whose text is the `tx_guard` CHECK
//! (`velmora_bridge::is_tx_guard_violation`) is `GuardFailed`. D1 runs a
//! `batch` as one transaction, so a failing statement rolls the whole batch
//! back. Every other failure is `BridgeError::Sql` with a class only: no
//! SQL text, parameter or database message.

use velmora_bridge::{
    is_tx_guard_violation, BridgeError, Result, Row, Sql, SqlValue, MAX_SQL_PARAMS,
};
use worker::js_sys::{self, Array, ArrayBuffer, Uint8Array};
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::{D1Database, D1PreparedStatement, D1Result};

/// Largest integer a JS number holds exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INT: i64 = (1 << 53) - 1;

pub struct D1Sql {
    db: D1Database,
}

impl D1Sql {
    pub fn new(db: D1Database) -> Self {
        D1Sql { db }
    }

    fn statement(&self, sql: &str, params: &[SqlValue]) -> Result<D1PreparedStatement> {
        check_params(params.len())?;
        let values = params.iter().map(to_js).collect::<Result<Vec<_>>>()?;
        self.db
            .prepare(sql)
            .bind(&values)
            .map_err(|_| BridgeError::Sql("d1: bind failed".into()))
    }
}

impl Sql for D1Sql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        let rows = self
            .statement(sql, params)?
            .raw_js_value()
            .await
            .map_err(map_err)?;
        rows.into_iter()
            .map(|row| {
                let row = row.dyn_into::<Array>().map_err(|_| decode_err())?;
                row.iter().map(from_js).collect()
            })
            .collect()
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        let result = self.statement(sql, params)?.run().await.map_err(map_err)?;
        changes(&result)
    }

    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        if stmts.is_empty() {
            return Ok(Vec::new());
        }
        let n = stmts.len();
        let prepared = stmts
            .iter()
            .map(|(sql, params)| self.statement(sql, params))
            .collect::<Result<Vec<_>>>()?;
        let results = self.db.batch(prepared).await.map_err(map_err)?;
        if results.len() != n {
            return Err(decode_err());
        }
        results.iter().map(changes).collect()
    }
}

fn changes(result: &D1Result) -> Result<u64> {
    let meta = result.meta().map_err(|_| decode_err())?;
    Ok(meta.and_then(|m| m.changes).unwrap_or(0) as u64)
}

fn decode_err() -> BridgeError {
    BridgeError::Sql("d1: unexpected result shape".into())
}

/// D1 refuses statements with more than [`MAX_SQL_PARAMS`] bound values;
/// refuse them first, with the same class on every backend.
fn check_params(n: usize) -> Result<()> {
    if n > MAX_SQL_PARAMS {
        return Err(BridgeError::Sql(format!(
            "too many bound parameters: {n} > {MAX_SQL_PARAMS}"
        )));
    }
    Ok(())
}

fn int_to_number(i: i64) -> Result<f64> {
    if !(-MAX_SAFE_INT..=MAX_SAFE_INT).contains(&i) {
        return Err(BridgeError::Sql("d1: integer outside JS safe range".into()));
    }
    Ok(i as f64)
}

fn number_to_int(f: f64) -> Result<i64> {
    let safe = MAX_SAFE_INT as f64;
    if !f.is_finite() || f.fract() != 0.0 || f.abs() > safe {
        return Err(BridgeError::Sql("d1: non-integer or unsafe number".into()));
    }
    Ok(f as i64)
}

fn number_to_byte(f: f64) -> Result<u8> {
    match number_to_int(f) {
        Ok(i) => u8::try_from(i).map_err(|_| decode_err()),
        Err(_) => Err(decode_err()),
    }
}

fn to_js(v: &SqlValue) -> Result<JsValue> {
    Ok(match v {
        SqlValue::Null => JsValue::NULL,
        SqlValue::Int(i) => JsValue::from_f64(int_to_number(*i)?),
        SqlValue::Text(s) => JsValue::from_str(s),
        SqlValue::Blob(b) => Uint8Array::from(b.as_slice()).buffer().into(),
    })
}

fn from_js(v: JsValue) -> Result<SqlValue> {
    if v.is_null() || v.is_undefined() {
        return Ok(SqlValue::Null);
    }
    if let Some(f) = v.as_f64() {
        return Ok(SqlValue::Int(number_to_int(f)?));
    }
    if let Some(s) = v.as_string() {
        return Ok(SqlValue::Text(s));
    }
    if v.is_bigint() {
        return i64::try_from(v)
            .map(SqlValue::Int)
            .map_err(|_| decode_err());
    }
    if let Some(buf) = v.dyn_ref::<ArrayBuffer>() {
        return Ok(SqlValue::Blob(Uint8Array::new(buf).to_vec()));
    }
    if let Some(bytes) = v.dyn_ref::<Uint8Array>() {
        return Ok(SqlValue::Blob(bytes.to_vec()));
    }
    if let Some(arr) = v.dyn_ref::<Array>() {
        let bytes = arr
            .iter()
            .map(|b| b.as_f64().ok_or_else(decode_err).and_then(number_to_byte))
            .collect::<Result<Vec<u8>>>()?;
        return Ok(SqlValue::Blob(bytes));
    }
    Err(decode_err())
}

/// Every message D1 attached to the failure (the thrown error and its
/// cause). Used for classification only; never logged or returned.
fn error_text(e: &worker::Error) -> String {
    match e {
        worker::Error::D1(d) => {
            let err: &js_sys::Error = d.as_ref();
            format!("{} | {}", String::from(err.message()), d.cause())
        }
        other => other.to_string(),
    }
}

fn map_err(e: worker::Error) -> BridgeError {
    classify(&error_text(&e))
}

/// The shared guard rule, then a class-only error.
fn classify(text: &str) -> BridgeError {
    if is_tx_guard_violation(text) {
        BridgeError::GuardFailed
    } else if text.contains("constraint failed") {
        BridgeError::Sql("d1: constraint violation".into())
    } else {
        BridgeError::Sql("d1: statement failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_guard_and_safe_integers() {
        assert!(check_params(MAX_SQL_PARAMS).is_ok());
        assert!(check_params(MAX_SQL_PARAMS + 1).is_err());
        let now = 1_794_000_000_000_i64; // a millisecond timestamp
        assert_eq!(number_to_int(int_to_number(now).unwrap()).unwrap(), now);
        assert!(int_to_number(MAX_SAFE_INT).is_ok() && int_to_number(-MAX_SAFE_INT).is_ok());
        assert!(int_to_number(MAX_SAFE_INT + 1).is_err() && int_to_number(i64::MIN).is_err());
        for bad in [1.5, f64::NAN, f64::INFINITY, 9_007_199_254_740_992.0] {
            assert!(number_to_int(bad).is_err(), "{bad}");
        }
        assert_eq!(number_to_byte(255.0).unwrap(), 255);
        assert!(number_to_byte(256.0).is_err() && number_to_byte(-1.0).is_err());
    }

    #[test]
    fn guard_failure_and_class_only_errors() {
        // Message and cause as local D1 reports a failing tx_guard insert.
        let guard = "D1_ERROR: CHECK constraint failed: ok = 1: SQLITE_CONSTRAINT \
                     (extended: SQLITE_CONSTRAINT_CHECK) | CHECK constraint failed: ok = 1";
        assert!(matches!(classify(guard), BridgeError::GuardFailed));
        for (text, class) in [
            (
                "D1_ERROR: UNIQUE constraint failed: buckets.name",
                "d1: constraint violation",
            ),
            (
                "D1_ERROR: CHECK constraint failed: size >= 0",
                "d1: constraint violation",
            ),
            (
                "D1_ERROR: near \"SELEC\": syntax error | p=secret",
                "d1: statement failed",
            ),
        ] {
            assert!(
                matches!(classify(text), BridgeError::Sql(m) if m == class),
                "{text}"
            );
        }
    }
}
