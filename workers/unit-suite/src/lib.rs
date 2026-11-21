//! Test Worker for the unit's database adapter and its object class.
//!
//! `POST /db/<name>` reaches the SQLite Durable Object `<name>` and runs
//! one call of the [`Sql`] port on it through the production adapter
//! [`DoSql`]: the native test suite's twin (`testkit_shadow.rs` in
//! `velmora-bridge`). One object per native database, so every test has
//! a fresh one.
//!
//! The body is JSON: `{"op":"apply","script":…}`,
//! `{"op":"query"|"exec","sql":…,"params":[…]}` or
//! `{"op":"batch","stmts":[[sql,[…]],…]}`, or `{"op":"rebuild",
//! "stmts":…}`: the object is emptied (`deleteAll`) and the statements
//! run as one batch with foreign keys checked at its end (a copy of the
//! native database, made by the twin). A value is `{"n":0}`,
//! `{"i":<int>}`, `{"t":<text>}` or `{"b":<base64>}`. The answer is
//! `{"ok":…}`, `{"err":"guard"}` or `{"err":"sql","class":…}`.
//!
//! `POST /unit/<tenant>/<unit>` reaches the unit object of that name
//! ([`velmora_unit_do::UnitObject`], the real class), and
//! `POST /unit-unnamed` one made without a name (`newUniqueId`).
//! `POST /atomic/<name>` runs the whole-call transaction of `DoSql`
//! (`UnitSql::atomically`) through three cases and answers what each
//! left (`unit-smoke.py`).
//!
//! Never deployed with production bindings: it binds only its own
//! object classes.

use std::cell::RefCell;
use std::collections::HashMap;

use base64::Engine as _;
use serde_json::{json, Value};
use velmora_bridge::unit::{poll_once, UnitSql};
use velmora_bridge::{BridgeError, Row, Sql, SqlValue};
use velmora_unit_do::{DoSql, PointInTime};
pub use velmora_unit_do::UnitObject;
// The class macro names `wasm_bindgen` at the crate root.
use worker::wasm_bindgen;
use worker::{durable_object, event, Context, DurableObject, Env, Request, Response, State};

const BINDING: &str = "SUITE_DB";
const UNIT_BINDING: &str = "UNIT";

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    let url = req.url()?;
    let path = url.path().to_string();
    if let Some(name) = path.strip_prefix("/unit/") {
        let stub = env
            .durable_object(UNIT_BINDING)?
            .id_from_name(name)?
            .get_stub()?;
        return stub.fetch_with_request(req).await;
    }
    if path == "/unit-unnamed" {
        let stub = env.durable_object(UNIT_BINDING)?.unique_id()?.get_stub()?;
        return stub.fetch_with_request(req).await;
    }
    let (op, name) = if let Some(name) = path.strip_prefix("/atomic/") {
        ("atomic", name.to_string())
    } else if let Some(name) = path.strip_prefix("/db/") {
        ("db", name.to_string())
    } else {
        return Response::error("not found", 404);
    };
    if op == "atomic" {
        let stub = env
            .durable_object(BINDING)?
            .id_from_name(&format!("atomic-{name}"))?
            .get_stub()?;
        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Post);
        init.with_body(Some(r#"{"op":"atomic"}"#.into()));
        return stub
            .fetch_with_request(Request::new_with_init("https://suite/atomic", &init)?)
            .await;
    }
    if name.is_empty() || name.contains('/') {
        return Response::error("bad name", 400);
    }
    let stub = env
        .durable_object(BINDING)?
        .id_from_name(&name)?
        .get_stub()?;
    stub.fetch_with_request(req).await
}

#[durable_object]
pub struct SuiteDb {
    state: State,
    sql: DoSql,
}

impl DurableObject for SuiteDb {
    fn new(state: State, _env: Env) -> Self {
        let sql = DoSql::new(&state.storage());
        SuiteDb { state, sql }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        let body: Value = match req
            .text()
            .await
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
        {
            Some(v) => v,
            None => return Response::error("body is not JSON", 400),
        };
        let answer = match self.run(&body).await {
            Ok(Some(v)) => json!({ "ok": v }),
            Ok(None) => return Response::error("bad call", 400),
            Err(BridgeError::GuardFailed) => json!({ "err": "guard" }),
            Err(BridgeError::Sql(class)) => json!({ "err": "sql", "class": class }),
            Err(other) => json!({ "err": "other", "class": other.to_string() }),
        };
        Response::from_json(&answer)
    }
}

impl SuiteDb {
    /// The point-in-time bridge where workerd has no history: a bookmark
    /// for now, and the local refusal of a time and of a restore (on
    /// Cloudflare both work; this checks the bridge reaches the calls).
    async fn pitr(&self) -> Value {
        let pitr = PointInTime::new(&self.state);
        let current = pitr.current().await;
        let at = pitr.at(0).await;
        let restore = pitr.restore_now("not-a-bookmark").await;
        json!({
            "current": current.as_ref().map(|b| !b.is_empty()).unwrap_or(false),
            "at": at.err().map(|e| e.to_string()),
            "restore": restore.err().map(|e| e.to_string()),
        })
    }

    async fn run(&self, body: &Value) -> velmora_bridge::Result<Option<Value>> {
        let text = |k: &str| body.get(k).and_then(Value::as_str);
        Ok(Some(match text("op") {
            Some("apply") => {
                let Some(script) = text("script") else {
                    return Ok(None);
                };
                self.sql.apply(script)?;
                Value::Null
            }
            Some("query") => {
                let (Some(sql), Some(params)) = (text("sql"), params(body.get("params"))) else {
                    return Ok(None);
                };
                encode_rows(&self.sql.query(sql, &params).await?)
            }
            Some("exec") => {
                let (Some(sql), Some(params)) = (text("sql"), params(body.get("params"))) else {
                    return Ok(None);
                };
                json!(self.sql.exec(sql, &params).await?)
            }
            Some("pitr") => self.pitr().await,
            Some(op @ ("batch" | "rebuild")) => {
                let Some(list) = body.get("stmts").and_then(Value::as_array) else {
                    return Ok(None);
                };
                let mut stmts = Vec::with_capacity(list.len() + 1);
                if op == "rebuild" {
                    self.state
                        .storage()
                        .delete_all()
                        .await
                        .map_err(|_| BridgeError::Sql("suite: deleteAll failed".into()))?;
                    stmts.push((intern("PRAGMA defer_foreign_keys = ON"), Vec::new()));
                }
                for pair in list {
                    let sql = pair.get(0).and_then(Value::as_str);
                    let p = params(pair.get(1));
                    let (Some(sql), Some(p)) = (sql, p) else {
                        return Ok(None);
                    };
                    stmts.push((intern(sql), p));
                }
                json!(self.sql.batch(stmts).await?)
            }
            Some("atomic") => self.atomic()?,
            _ => return Ok(None),
        }))
    }

    /// The whole-call transaction of `DoSql`, in three cases: a call that
    /// keeps its writes; one that fails after a write (nothing kept); and
    /// one whose inner batch is refused by its guard (only the batch is
    /// rolled back). Answers the rows each left.
    fn atomic(&self) -> velmora_bridge::Result<Value> {
        let sql = &self.sql;
        sql.apply(
            "CREATE TABLE IF NOT EXISTS t (n INTEGER NOT NULL); \
             CREATE TABLE IF NOT EXISTS tx_guard (ok INTEGER NOT NULL CHECK (ok = 1)); \
             DELETE FROM t;",
        )?;
        let rows = || -> velmora_bridge::Result<Value> {
            let r = poll_once(sql.query("SELECT n FROM t ORDER BY n", &[]))??;
            Ok(json!(r
                .iter()
                .map(|row| match row[0] {
                    SqlValue::Int(n) => n,
                    _ => -1,
                })
                .collect::<Vec<_>>()))
        };
        let insert = |n: i64| -> velmora_bridge::Result<()> {
            poll_once(sql.exec("INSERT INTO t(n) VALUES (?1)", &[SqlValue::Int(n)]))??;
            Ok(())
        };
        let kept = sql.atomically(&mut || insert(1));
        let after_kept = rows()?;
        let failed = sql.atomically(&mut || {
            insert(2)?;
            Err(BridgeError::Invalid("the call fails after a write"))
        });
        let after_failed = rows()?;
        let inner = sql.atomically(&mut || {
            insert(3)?;
            let refused = poll_once(sql.batch(vec![
                ("INSERT INTO t(n) VALUES (4)", vec![]),
                ("INSERT INTO tx_guard(ok) VALUES (0)", vec![]),
            ]))?;
            match refused {
                Err(BridgeError::GuardFailed) => Ok(()),
                _ => Err(BridgeError::Invalid("the guard did not refuse the batch")),
            }
        });
        let after_inner = rows()?;
        Ok(json!({
            "kept": { "ok": kept.is_ok(), "rows": after_kept },
            "failed": { "error": failed.err().map(|e| e.to_string()), "rows": after_failed },
            "inner": { "ok": inner.is_ok(), "rows": after_inner },
        }))
    }
}

thread_local! {
    /// The catalogue's statements are a fixed set of texts, so each is
    /// kept once: `Sql::batch` takes `&'static str`.
    static INTERNED: RefCell<HashMap<String, &'static str>> = RefCell::new(HashMap::new());
}

fn intern(sql: &str) -> &'static str {
    INTERNED.with(|m| {
        let mut m = m.borrow_mut();
        if let Some(s) = m.get(sql) {
            return *s;
        }
        let s: &'static str = Box::leak(sql.to_string().into_boxed_str());
        m.insert(sql.to_string(), s);
        s
    })
}

fn params(v: Option<&Value>) -> Option<Vec<SqlValue>> {
    v?.as_array()?.iter().map(decode_value).collect()
}

fn decode_value(v: &Value) -> Option<SqlValue> {
    if v.get("n").is_some() {
        Some(SqlValue::Null)
    } else if let Some(i) = v.get("i") {
        i.as_i64().map(SqlValue::Int)
    } else if let Some(t) = v.get("t") {
        t.as_str().map(|t| SqlValue::Text(t.to_string()))
    } else if let Some(b) = v.get("b") {
        base64::engine::general_purpose::STANDARD
            .decode(b.as_str()?)
            .ok()
            .map(SqlValue::Blob)
    } else {
        None
    }
}

fn encode_rows(rows: &[Row]) -> Value {
    Value::Array(
        rows.iter()
            .map(|row| Value::Array(row.iter().map(encode_value).collect()))
            .collect(),
    )
}

fn encode_value(v: &SqlValue) -> Value {
    match v {
        SqlValue::Null => json!({"n": 0}),
        SqlValue::Int(i) => json!({"i": i}),
        SqlValue::Text(t) => json!({"t": t}),
        SqlValue::Blob(b) => json!({"b": base64::engine::general_purpose::STANDARD.encode(b)}),
    }
}
