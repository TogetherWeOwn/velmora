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
//!
//! D1 charges a refused batch in full, and answers the statements after
//! a large one with "D1 DB is overloaded" until the database is back
//! under its budget of the last ten seconds. That answer has its own
//! class, and a read that follows a refused batch
//! (`Sql::query_after_refusal`) waits and asks again.

use std::future::Future;
use std::time::Duration;

use velmora_bridge::{
    is_tx_guard_violation, BridgeError, Result, Row, Sql, SqlValue, MAX_SQL_INT, MAX_SQL_PARAMS,
};
use worker::js_sys::{self, Array, ArrayBuffer, Promise, Reflect, Uint8Array};
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::worker_sys::{D1Database as D1Sys, D1PreparedStatement};
use worker::D1Database;

/// Largest integer a JS number holds exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INT: i64 = MAX_SQL_INT;

/// The class of a statement D1 refused because the database is over its
/// budget of the last ten seconds.
const OVERLOADED: &str = "d1: overloaded";

/// How long a read after a refused batch waits before each further try,
/// in milliseconds: it is asked again 5, 10 and 20 seconds after the
/// first answer. The budget D1 holds a database to covers ten seconds,
/// and a read 15 seconds after a refused batch of 65,536 extents was
/// answered.
const OVERLOADED_PAUSES_MS: [u32; 3] = [5_000, 5_000, 10_000];

/// Talks to the raw binding so that only `meta.changes` is read from a
/// result: the workers-rs `D1ResultMeta` decodes `size_after` as a 32-bit
/// `usize` on wasm and would fail after a committed write once the
/// database passes 4 GiB.
pub struct D1Sql {
    db: D1Sys,
}

impl D1Sql {
    pub fn new(db: D1Database) -> Self {
        let raw: &JsValue = db.as_ref();
        D1Sql {
            db: raw.clone().unchecked_into(),
        }
    }

    fn statement(&self, sql: &str, params: &[SqlValue]) -> Result<D1PreparedStatement> {
        check_params(params.len())?;
        let values = params.iter().map(to_js).collect::<Result<Array>>()?;
        let bind_err = |_| BridgeError::Sql("d1: bind failed".into());
        self.db
            .prepare(sql)
            .map_err(bind_err)?
            .bind(values)
            .map_err(bind_err)
    }
}

impl Sql for D1Sql {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        let rows = settle(self.statement(sql, params)?.raw()).await?;
        let rows = rows.dyn_into::<Array>().map_err(|_| decode_err())?;
        rows.iter()
            .map(|row| {
                let row = row.dyn_into::<Array>().map_err(|_| decode_err())?;
                row.iter().map(from_js).collect()
            })
            .collect()
    }

    async fn query_after_refusal(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        patiently(
            || self.query(sql, params),
            |ms| async move { worker::Delay::from(Duration::from_millis(u64::from(ms))).await },
        )
        .await
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        changes(&settle(self.statement(sql, params)?.run()).await?)
    }

    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        if stmts.is_empty() {
            return Ok(Vec::new());
        }
        let prepared = stmts
            .iter()
            .map(|(sql, params)| self.statement(sql, params))
            .collect::<Result<Array>>()?;
        let results = settle(self.db.batch(prepared)).await?;
        let results = results.dyn_into::<Array>().map_err(|_| decode_err())?;
        if results.length() as usize != stmts.len() {
            return Err(decode_err());
        }
        results.iter().map(|r| changes(&r)).collect()
    }
}

/// What `ask` answers, asked again after each pause of
/// [`OVERLOADED_PAUSES_MS`] for as long as the answer is [`OVERLOADED`].
/// Any other answer, and the overloaded one after the last pause, is
/// returned as it is. For reads only: a statement is run once per try.
async fn patiently<T, A, P>(
    mut ask: impl FnMut() -> A,
    mut pause: impl FnMut(u32) -> P,
) -> Result<T>
where
    A: Future<Output = Result<T>>,
    P: Future<Output = ()>,
{
    let mut pauses = OVERLOADED_PAUSES_MS.iter();
    loop {
        match ask().await {
            Err(BridgeError::Sql(class)) if class == OVERLOADED => match pauses.next() {
                Some(ms) => pause(*ms).await,
                None => return Err(BridgeError::Sql(class)),
            },
            answer => return answer,
        }
    }
}

/// Awaits a D1 call; a throw or rejection is classified.
async fn settle(call: std::result::Result<Promise, JsValue>) -> Result<JsValue> {
    JsFuture::from(call.map_err(map_err)?)
        .await
        .map_err(map_err)
}

/// `meta.changes`; absent reads as 0 (a `SELECT`).
fn changes(result: &JsValue) -> Result<u64> {
    let field = |obj: &JsValue, name: &str| Reflect::get(obj, &JsValue::from_str(name));
    // A missing or malformed count is an error, never "0 rows changed":
    // fenced catalogue calls read 0 as "lease lost", which would turn a
    // committed write into a silent no-op.
    if field(result, "success")
        .map_err(|_| decode_err())?
        .as_bool()
        == Some(false)
    {
        return Err(decode_err());
    }
    let meta = field(result, "meta").map_err(|_| decode_err())?;
    if meta.is_null() || meta.is_undefined() {
        return Err(decode_err());
    }
    let n = field(&meta, "changes").map_err(|_| decode_err())?;
    match n.as_f64() {
        None => Err(decode_err()),
        Some(f) => u64::try_from(number_to_int(f)?).map_err(|_| decode_err()),
    }
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
fn error_text(e: &JsValue) -> String {
    let message = |v: &JsValue| match v.dyn_ref::<js_sys::Error>() {
        Some(err) => String::from(err.message()),
        None => v.as_string().unwrap_or_else(|| {
            // A plain `{message}` rejection must still reach the guard rule.
            Reflect::get(v, &JsValue::from_str("message"))
                .ok()
                .and_then(|m| m.as_string())
                .unwrap_or_default()
        }),
    };
    match e.dyn_ref::<js_sys::Error>() {
        Some(err) => format!("{} | {}", message(e), message(&err.cause())),
        None => message(e),
    }
}

fn map_err(e: JsValue) -> BridgeError {
    classify(&error_text(&e))
}

/// The shared guard rule, then a class-only error. The classes after
/// "overloaded" only name D1's transient failures apart for the request
/// log (`velmora_bridge::metrics::Fault`). Each still ends with
/// `: statement failed`, which is what callers that retry an unanswered
/// catalogue match (`catalogue_unanswered` in the admin drill).
fn classify(text: &str) -> BridgeError {
    let class = if is_tx_guard_violation(text) {
        return BridgeError::GuardFailed;
    } else if text.contains("constraint failed") {
        "d1: constraint violation"
    } else if text.contains("D1 DB is overloaded") {
        OVERLOADED
    } else if text.contains("Network connection lost") {
        "d1: network lost: statement failed"
    } else if text.contains("client disconnected") {
        "d1: client disconnected: statement failed"
    } else if text.contains("transient issue") {
        "d1: transient: statement failed"
    } else if text.contains("was reset") || text.contains("to be reset") {
        "d1: storage reset: statement failed"
    } else if text.contains("timed out") || text.contains("timeout") {
        "d1: timeout: statement failed"
    } else {
        "d1: statement failed"
    };
    BridgeError::Sql(class.into())
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
            // D1's transient failures, as its documentation lists them.
            (
                "D1_ERROR: Network connection lost.",
                "d1: network lost: statement failed",
            ),
            (
                "D1_ERROR: D1 DB storage operation exceeded timeout which caused object \
                 to be reset.",
                "d1: storage reset: statement failed",
            ),
            (
                "D1_ERROR: D1 DB's isolate exceeded its memory limit and was reset.",
                "d1: storage reset: statement failed",
            ),
            (
                "D1_ERROR: Cannot resolve D1 DB due to transient issue on remote node.",
                "d1: transient: statement failed",
            ),
            (
                "D1_ERROR: Can't read from request stream because client disconnected.",
                "d1: client disconnected: statement failed",
            ),
            // As D1 answered the first read after a refused batch of
            // 65,536 extents.
            (
                "D1_ERROR: D1 DB is overloaded. Too many resources consumed within a 10 \
                 second window.",
                OVERLOADED,
            ),
        ] {
            assert!(
                matches!(classify(text), BridgeError::Sql(m) if m == class),
                "{text}"
            );
            // A catalogue that did not answer stays one: the admin drill
            // retries on this suffix.
            if !class.contains("constraint") && class != OVERLOADED {
                assert!(class.ends_with(": statement failed"), "{class}");
            }
        }
    }

    /// `patiently` over a database that answers "overloaded" `busy`
    /// times: the answer, how often it was asked, and the pauses.
    fn asked(busy: u32, then: Result<u8>) -> (Result<u8>, u32, Vec<u32>) {
        use futures_util::FutureExt;
        let calls = std::cell::Cell::new(0u32);
        let pauses = std::cell::RefCell::new(Vec::new());
        let mut then = Some(then);
        let answer = patiently(
            || {
                calls.set(calls.get() + 1);
                let answer = if calls.get() <= busy {
                    Err(BridgeError::Sql(OVERLOADED.into()))
                } else {
                    then.take().expect("asked again after an answer")
                };
                async move { answer }
            },
            |ms| {
                pauses.borrow_mut().push(ms);
                async {}
            },
        )
        .now_or_never()
        .expect("nothing here waits");
        (answer, calls.get(), pauses.into_inner())
    }

    #[test]
    fn a_read_after_a_refused_batch_waits_out_an_overloaded_database() {
        // Answered at once: asked once, no pause.
        let (answer, calls, pauses) = asked(0, Ok(7));
        assert!(matches!(answer, Ok(7)) && calls == 1 && pauses.is_empty());
        // Overloaded twice, then answered.
        let (answer, calls, pauses) = asked(2, Ok(7));
        assert!(matches!(answer, Ok(7)) && calls == 3);
        assert_eq!(pauses, [5_000, 5_000]);
        // Another failure ends it at once, also after a pause: only
        // "overloaded" is waited out.
        for busy in [0, 1] {
            let (answer, calls, _) =
                asked(busy, Err(BridgeError::Sql("d1: statement failed".into())));
            assert!(matches!(answer, Err(BridgeError::Sql(m)) if m == "d1: statement failed"));
            assert_eq!(calls, busy + 1);
            let (answer, calls, _) = asked(busy, Err(BridgeError::GuardFailed));
            assert!(matches!(answer, Err(BridgeError::GuardFailed)) && calls == busy + 1);
        }
        // Still overloaded after the last pause: the error, after a
        // bounded number of tries.
        let (answer, calls, pauses) = asked(u32::MAX, Ok(7));
        assert!(matches!(answer, Err(BridgeError::Sql(m)) if m == OVERLOADED));
        assert_eq!(calls, 4);
        assert_eq!(pauses, OVERLOADED_PAUSES_MS);
    }
}
