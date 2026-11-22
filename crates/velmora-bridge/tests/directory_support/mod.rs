//! The directory database of the directory tests: native SQLite, or D1.
//!
//! With `VELMORA_D1_PROBE` set to the base URL of the probe Worker
//! (`workers/directory-d1-probe`, under `wrangler dev` for local D1 or
//! `wrangler dev --remote` for a throwaway D1), every database of these
//! tests is a D1 database instead, reached through the probe. The probe
//! binds values and reads answers as the Worker's D1 adapter does
//! (`workers/s3-bridge/src/d1.rs`), so the directory's real statements and
//! batches run on D1 as they would in production. The probe holds two
//! databases, so a D1 run takes `--test-threads=1`; each database is
//! emptied and given the schema again when a test takes it.

#![allow(dead_code)]

use std::cell::Cell;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Mutex, MutexGuard};

use base64::Engine as _;
use serde_json::{json, Value};
use velmora_bridge::ports::{Row, Sql, SqlValue};
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::{BridgeError, Result};

/// The directory's migrations, in order. A test checks that this is every
/// file of the folder.
pub const MIGRATIONS: [(&str, &str); 2] = [
    (
        "0001_directory.sql",
        include_str!("../../../../workers/s3-bridge/migrations-directory/0001_directory.sql"),
    ),
    (
        "0002_tenant_events.sql",
        include_str!("../../../../workers/s3-bridge/migrations-directory/0002_tenant_events.sql"),
    ),
];

/// Every table of the schema, children before parents, for the probe's
/// reset.
const TABLES: [&str; 12] = [
    "units",
    "key_routes",
    "bucket_index",
    "tenants",
    "key_locations",
    "pending_ops",
    "shred_slots",
    "registry",
    "directory_gate",
    "tenant_events",
    "feed_epoch",
    "tenant_feed_pruned",
];

/// A directory database for one test.
#[allow(clippy::large_enum_variant)]
pub enum Db {
    Native(RusqliteSql),
    D1(D1Probe),
}

/// Whether this run is on D1.
pub fn on_d1() -> bool {
    std::env::var("VELMORA_D1_PROBE").is_ok_and(|v| !v.is_empty())
}

/// Whether this run has the unit suite's workerd twin (every native
/// database is also a Durable Object SQLite database, compared call by
/// call; `crates/velmora-bridge/src/testkit_shadow.rs` where it exists).
pub fn under_twin() -> bool {
    std::env::var("VELMORA_SQL_SHADOW").is_ok_and(|v| !v.is_empty())
}

/// A fresh directory database with the whole schema.
pub fn database() -> Db {
    match std::env::var("VELMORA_D1_PROBE") {
        Ok(base) if !base.is_empty() => Db::D1(D1Probe::take(&base)),
        _ => {
            let db = RusqliteSql::open_in_memory().unwrap();
            for (_, sql) in MIGRATIONS {
                db.apply(sql).unwrap();
            }
            Db::Native(db)
        }
    }
}

impl Db {
    /// A statement through the port, on either database: the tests that
    /// damage a row on purpose.
    pub async fn raw_exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        self.exec(sql, params).await
    }
}

impl Sql for Db {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        match self {
            Db::Native(db) => db.query(sql, params).await,
            Db::D1(db) => db.query(sql, params),
        }
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        match self {
            Db::Native(db) => db.exec(sql, params).await,
            Db::D1(db) => db.exec(sql, params),
        }
    }

    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        match self {
            Db::Native(db) => db.batch(stmts).await,
            Db::D1(db) => db.batch(stmts),
        }
    }
}

/// The schema as single statements: the probe runs each one on its own
/// (D1's `exec` takes one statement per line). The directory's
/// migrations hold no trigger, so a statement ends at the first `;`.
pub fn statements() -> Vec<String> {
    let mut out = Vec::new();
    for (name, sql) in MIGRATIONS {
        assert!(
            !sql.to_ascii_uppercase().contains("CREATE TRIGGER"),
            "{name}: the probe's split takes no trigger"
        );
        let body: String = sql
            .lines()
            .map(|l| l.split("--").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        for stmt in body.split(';') {
            let stmt = stmt.trim();
            if !stmt.is_empty() {
                out.push(stmt.to_string());
            }
        }
    }
    out
}

/// One test at a time holds the probe's databases.
static PROBE: Mutex<()> = Mutex::new(());

thread_local! {
    /// The probe databases this thread holds now.
    static HELD: Cell<usize> = const { Cell::new(0) };
}

/// One database of the probe Worker.
pub struct D1Probe {
    host: String,
    slot: usize,
    _lock: Option<MutexGuard<'static, ()>>,
}

impl Drop for D1Probe {
    fn drop(&mut self) {
        HELD.with(|h| h.set(h.get() - 1));
    }
}

fn sql_err(msg: &str) -> BridgeError {
    BridgeError::Sql(format!("d1 probe: {msg}"))
}

impl D1Probe {
    fn take(base: &str) -> D1Probe {
        let held = HELD.with(|h| h.get());
        assert!(held < 2, "the probe holds two databases");
        let lock = match held {
            0 => Some(PROBE.lock().unwrap_or_else(|e| e.into_inner())),
            _ => None,
        };
        HELD.with(|h| h.set(held + 1));
        let host = base
            .strip_prefix("http://")
            .expect("VELMORA_D1_PROBE is http://host:port")
            .trim_end_matches('/')
            .to_string();
        let probe = D1Probe {
            host,
            slot: held,
            _lock: lock,
        };
        let answer = probe
            .call("/reset", &json!({"drop": TABLES, "schema": statements()}))
            .expect("probe reset");
        assert_eq!(answer["ok"], json!(true), "probe reset: {answer}");
        probe
    }

    fn call(&self, path: &str, body: &Value) -> Result<Value> {
        let body = serde_json::to_vec(body).map_err(|_| sql_err("encode"))?;
        let mut stream = TcpStream::connect(&self.host).map_err(|_| sql_err("connect"))?;
        let head = format!(
            "POST {path}?db=DB{} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.slot,
            self.host,
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|_| stream.write_all(&body))
            .map_err(|_| sql_err("write"))?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).map_err(|_| sql_err("read"))?;
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| sql_err("no header end"))?;
        let header = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
        let mut payload = raw[split + 4..].to_vec();
        if header.contains("transfer-encoding: chunked") {
            payload = dechunk(&payload).ok_or_else(|| sql_err("chunked body"))?;
        }
        let value: Value = serde_json::from_slice(&payload).map_err(|_| sql_err("answer"))?;
        if let Some(e) = value.get("error") {
            return Err(BridgeError::Sql(format!(
                "d1: {}",
                e.as_str().unwrap_or("?")
            )));
        }
        Ok(value)
    }

    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        let answer = self.call("/query", &statement(sql, params)?)?;
        answer["rows"]
            .as_array()
            .ok_or_else(|| sql_err("rows"))?
            .iter()
            .map(|row| {
                row.as_array()
                    .ok_or_else(|| sql_err("row"))?
                    .iter()
                    .map(from_wire)
                    .collect()
            })
            .collect()
    }

    fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        let answer = self.call("/exec", &statement(sql, params)?)?;
        answer["changed"].as_u64().ok_or_else(|| sql_err("changed"))
    }

    fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        if stmts.is_empty() {
            return Ok(Vec::new());
        }
        let stmts = stmts
            .iter()
            .map(|(sql, params)| statement(sql, params))
            .collect::<Result<Vec<_>>>()?;
        let answer = self.call("/batch", &json!({ "stmts": stmts }))?;
        answer["changed"]
            .as_array()
            .ok_or_else(|| sql_err("changed"))?
            .iter()
            .map(|n| n.as_u64().ok_or_else(|| sql_err("changed")))
            .collect()
    }
}

fn statement(sql: &str, params: &[SqlValue]) -> Result<Value> {
    // The adapter's own bound: more is refused before D1 sees it.
    if params.len() > velmora_bridge::MAX_SQL_PARAMS {
        return Err(sql_err("too many bound parameters"));
    }
    let params: Vec<Value> = params.iter().map(to_wire).collect();
    Ok(json!({ "sql": sql, "params": params }))
}

fn to_wire(v: &SqlValue) -> Value {
    match v {
        SqlValue::Null => Value::Null,
        SqlValue::Int(i) => json!({"t": "i", "v": i.to_string()}),
        SqlValue::Text(s) => json!({"t": "s", "v": s}),
        SqlValue::Blob(b) => {
            json!({"t": "b", "v": base64::engine::general_purpose::STANDARD.encode(b)})
        }
    }
}

fn from_wire(v: &Value) -> Result<SqlValue> {
    if v.is_null() {
        return Ok(SqlValue::Null);
    }
    let s = v["v"].as_str().ok_or_else(|| sql_err("value"))?;
    match v["t"].as_str() {
        Some("i") => s.parse().map(SqlValue::Int).map_err(|_| sql_err("int")),
        Some("s") => Ok(SqlValue::Text(s.to_string())),
        Some("b") => base64::engine::general_purpose::STANDARD
            .decode(s)
            .map(SqlValue::Blob)
            .map_err(|_| sql_err("blob")),
        _ => Err(sql_err("tag")),
    }
}

fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line = body.windows(2).position(|w| w == b"\r\n")?;
        let size =
            usize::from_str_radix(std::str::from_utf8(&body[..line]).ok()?.trim(), 16).ok()?;
        body = &body[line + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(body.get(..size)?);
        body = body.get(size + 2..)?;
    }
}
