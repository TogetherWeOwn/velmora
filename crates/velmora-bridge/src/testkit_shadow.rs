//! The catalogue test suite on Durable Object SQLite in workerd.
//!
//! With `VELMORA_SQL_SHADOW` set to the base URL of the suite Worker
//! (`workers/unit-suite`, served by workerd; a comma-separated list
//! spreads the databases over several processes), every
//! [`super::RusqliteSql`] gets a twin: a fresh SQLite Durable Object in
//! workerd, reached through the production adapter `DoSql` and its
//! JavaScript transaction shim. Every migration and every `query`,
//! `exec` and `batch` runs on both, and the two answers are compared:
//!
//! - rows: equal value for value; rows changed: equal per statement;
//! - errors: the same kind (`GuardFailed` against `GuardFailed`, `Sql`
//!   against `Sql`). The message text is the backend's own and is not
//!   compared.
//!
//! A difference panics with the statement and both answers, so the test
//! that made the call fails.
//!
//! `VELMORA_SQL_SHADOW_PRIMARY=do` hands the catalogue the Durable
//! Object's answer instead of SQLite's: the suite then runs **on** the
//! object, with SQLite as the referee. An error is compared by its class
//! (a difference fails the run) and keeps SQLite's message, because the
//! adapter keeps only a class and some tests read the message of a
//! trigger.
//!
//! A test that changes the database through
//! [`super::RusqliteSql::with_conn`] bypasses the port. Before the next
//! call the twin is then **rebuilt** from the native database: the
//! object is emptied (`deleteAll`), and the schema, every row (with its
//! rowid) and then the indexes and triggers are written in one
//! transaction, so no trigger fires on the copy. Comparing goes on from
//! there. A call that meets a state with a broken foreign key (which the
//! object cannot hold) runs on SQLite alone and is counted; the twin is
//! rebuilt at the next call that meets a whole state. A rebuild that
//! fails for any other reason marks the twin `desynced`. Every twin writes one line to the file named by
//! `VELMORA_SQL_SHADOW_LOG` when it is dropped: the test (the thread's
//! name), the calls compared, the rebuilds, and whether it desynced.

use std::cell::{Cell, RefCell};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use serde_json::{json, Value};

use crate::ports::{Row, SqlValue};
use crate::types::{BridgeError, Result};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// The twin of one native database.
pub(crate) struct Shadow {
    host: String,
    path: String,
    primary_do: bool,
    compared: Cell<u64>,
    /// Plain `EXPLAIN` answers: engine bytecode, not compared.
    skipped: Cell<u64>,
    rebuilds: Cell<u64>,
    /// A test changed the database behind the port: the twin is rebuilt
    /// before the next call.
    dirty: Cell<bool>,
    /// Calls that ran on SQLite alone because the state they met broke a
    /// foreign key (a state the object cannot hold; a later call may find
    /// it whole again, and the twin is rebuilt then).
    uncompared: Cell<u64>,
    /// Why the twin stopped being compared for good, if it did.
    desynced: RefCell<Option<String>>,
    diverged: Cell<bool>,
    log: Option<String>,
}

/// What one call answered.
#[derive(Debug, PartialEq)]
enum Answer {
    Rows(Vec<Row>),
    Changed(u64),
    Batch(Vec<u64>),
    Applied,
    Guard,
    Sql(String),
}

impl Shadow {
    /// A twin, when `VELMORA_SQL_SHADOW` is set.
    pub(crate) fn from_env() -> Option<Shadow> {
        let bases = std::env::var("VELMORA_SQL_SHADOW").ok()?;
        let bases: Vec<&str> = bases
            .split(',')
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .collect();
        assert!(
            !bases.is_empty(),
            "VELMORA_SQL_SHADOW is set but names no URL"
        );
        let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        // Several workerd processes share the load, one database each.
        let base = bases[n as usize % bases.len()];
        let host = base
            .trim_end_matches('/')
            .strip_prefix("http://")
            .expect("VELMORA_SQL_SHADOW must be http://host:port[,…]")
            .to_string();
        let id = format!(
            "{}-{}-{}",
            std::process::id(),
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        Some(Shadow {
            host,
            path: format!("/db/{id}"),
            primary_do: std::env::var("VELMORA_SQL_SHADOW_PRIMARY").as_deref() == Ok("do"),
            compared: Cell::new(0),
            skipped: Cell::new(0),
            rebuilds: Cell::new(0),
            dirty: Cell::new(false),
            uncompared: Cell::new(0),
            desynced: RefCell::new(None),
            diverged: Cell::new(false),
            log: std::env::var("VELMORA_SQL_SHADOW_LOG").ok(),
        })
    }

    /// A change behind the port (`with_conn`, a rolled-back unit call):
    /// the twin is rebuilt from the native database before the next call.
    pub(crate) fn mark_dirty(&self) {
        self.dirty.set(true);
    }

    /// Called before a call runs natively: whether the twin is to be asked
    /// too. A dirty twin is rebuilt from `conn` first.
    pub(crate) fn ready(&self, conn: &rusqlite::Connection) -> bool {
        if self.is_desynced() {
            return false;
        }
        if !self.dirty.get() {
            return true;
        }
        // A Durable Object cannot hold rows that break a foreign key: it
        // resets itself when its transaction ends with one. A test that
        // switched the keys off may pass through such a state (a table
        // restored one at a time): that call runs on SQLite alone, and the
        // twin is rebuilt at the next call that meets a whole state. Any
        // other reason to stop fails the run (run-suite.sh).
        let body = match dump(conn) {
            Ok(body) => body,
            Err(reason) if reason == "fk-broken" => {
                self.uncompared.set(self.uncompared.get() + 1);
                return false;
            }
            Err(reason) => {
                self.desync(reason);
                return false;
            }
        };
        let reply = match self.post(&body.to_string()) {
            Ok(reply) => reply,
            Err(e) => {
                self.desync(format!("rebuild-unreachable:{}", e.kind()));
                return false;
            }
        };
        match serde_json::from_str::<Value>(&reply) {
            Ok(v) if v.get("ok").is_some() => {
                self.rebuilds.set(self.rebuilds.get() + 1);
                self.dirty.set(false);
                true
            }
            Ok(v) => {
                self.desync(format!(
                    "rebuild-refused:{}",
                    v.get("class").and_then(Value::as_str).unwrap_or("?")
                ));
                false
            }
            Err(_) => {
                self.desync("rebuild-unreadable".into());
                false
            }
        }
    }

    fn is_desynced(&self) -> bool {
        self.desynced.borrow().is_some()
    }

    fn desync(&self, reason: String) {
        *self.desynced.borrow_mut() = Some(reason);
    }

    /// A script, after it ran natively with `local`; a script SQLite
    /// refused is asked of the object too, and the error classes compared.
    pub(crate) fn apply(&self, script: &str, local: &Result<()>) {
        let answer = self.call(json!({"op": "apply", "script": script}), |_| {
            Answer::Applied
        });
        let mine = match local {
            Ok(()) => Answer::Applied,
            Err(e) => error_answer(e),
        };
        self.check("apply", script, &[], &mine, &answer);
        // A failed script keeps the statements before the failure natively
        // (as D1 does) and none in the object (one `transactionSync`): the
        // twin is rebuilt from the native state before the next call.
        if local.is_err() {
            self.mark_dirty();
        }
    }

    pub(crate) fn query(
        &self,
        sql: &str,
        params: &[SqlValue],
        local: Result<Vec<Row>>,
    ) -> Result<Vec<Row>> {
        let remote = self.call(
            json!({"op": "query", "sql": sql, "params": encode_params(params)}),
            |v| Answer::Rows(decode_rows(v)),
        );
        let mine = match &local {
            Ok(rows) => Answer::Rows(rows.clone()),
            Err(e) => error_answer(e),
        };
        self.check("query", sql, params, &mine, &remote);
        match (self.primary_do, remote) {
            (true, Answer::Rows(rows)) => Ok(rows),
            _ => local,
        }
    }

    pub(crate) fn exec(&self, sql: &str, params: &[SqlValue], local: Result<u64>) -> Result<u64> {
        let remote = self.call(
            json!({"op": "exec", "sql": sql, "params": encode_params(params)}),
            |v| Answer::Changed(v.as_u64().expect("rows changed")),
        );
        let mine = match &local {
            Ok(n) => Answer::Changed(*n),
            Err(e) => error_answer(e),
        };
        self.check("exec", sql, params, &mine, &remote);
        match (self.primary_do, remote) {
            (true, Answer::Changed(n)) => Ok(n),
            _ => local,
        }
    }

    pub(crate) fn batch(
        &self,
        stmts: &[(&'static str, Vec<SqlValue>)],
        local: Result<Vec<u64>>,
    ) -> Result<Vec<u64>> {
        let list: Vec<Value> = stmts
            .iter()
            .map(|(sql, params)| json!([sql, encode_params(params)]))
            .collect();
        let remote = self.call(json!({"op": "batch", "stmts": list}), |v| {
            Answer::Batch(
                v.as_array()
                    .expect("batch answer")
                    .iter()
                    .map(|n| n.as_u64().expect("rows changed"))
                    .collect(),
            )
        });
        let mine = match &local {
            Ok(n) => Answer::Batch(n.clone()),
            Err(e) => error_answer(e),
        };
        let mut text = String::new();
        for (sql, _) in stmts {
            let _ = writeln!(text, "{sql};");
        }
        self.check("batch", &text, &[], &mine, &remote);
        match (self.primary_do, remote) {
            (true, Answer::Batch(n)) => Ok(n),
            _ => local,
        }
    }

    fn check(&self, op: &str, sql: &str, params: &[SqlValue], mine: &Answer, theirs: &Answer) {
        let same = match (mine, theirs) {
            // Errors are compared by class, the class the adapters give
            // (`<store>: constraint violation`, `<store>: statement
            // failed`): the message text is each engine's own.
            (Answer::Sql(a), Answer::Sql(b)) => error_class(a) == error_class(b),
            // A connection's own counters (`total_changes()`) differ
            // between two databases; only their differences are used.
            (Answer::Rows(_), Answer::Rows(_)) if engine_counter(sql) => true,
            // A plain EXPLAIN lists the engine's bytecode, which differs
            // between two SQLite builds: counted as skipped.
            (Answer::Rows(_), Answer::Rows(_)) if is_bytecode_explain(sql) => {
                self.skipped.set(self.skipped.get() + 1);
                return;
            }
            // A query plan's node ids are the engine's own; its text is
            // what a test reads.
            (Answer::Rows(a), Answer::Rows(b)) if is_explain(sql) => {
                let text = |rows: &Vec<Row>| -> Vec<Option<SqlValue>> {
                    rows.iter().map(|r| r.last().cloned()).collect()
                };
                text(a) == text(b)
            }
            (a, b) => a == b,
        };
        if !same {
            let report = format!(
                "SHADOW DIVERGENCE ({op}) on {}\n  sql: {sql}\n  params: {params:?}\n  sqlite: {mine:?}\n  durable object: {theirs:?}",
                self.path
            );
            // A panic inside a task a test spawned can be swallowed, so
            // the divergence is written down before it is raised.
            self.diverged.set(true);
            self.append(&format!("DIVERGENCE\t{}\n", report.replace('\n', " | ")));
            panic!("{report}");
        }
        self.compared.set(self.compared.get() + 1);
    }

    fn append(&self, line: &str) {
        let Some(log) = &self.log else { return };
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }

    /// One request to the twin; the answer's `ok` is read with `ok`.
    fn call(&self, body: Value, ok: impl FnOnce(&Value) -> Answer) -> Answer {
        let body = body.to_string();
        let reply = self.post(&body).unwrap_or_else(|e| {
            self.diverged.set(true);
            self.append(&format!("UNREACHABLE\t{}\t{e}\n", self.path));
            panic!("shadow unreachable at {}: {e}", self.host)
        });
        let reply: Value = serde_json::from_str(&reply).expect("shadow answer is JSON");
        if let Some(v) = reply.get("ok") {
            return ok(v);
        }
        match reply.get("err").and_then(Value::as_str) {
            Some("guard") => Answer::Guard,
            Some("sql") => Answer::Sql(
                reply
                    .get("class")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            ),
            _ => panic!("shadow answered {reply}"),
        }
    }

    /// One request on a connection of its own, so that nothing is ever
    /// sent twice: only a failed connect is tried again.
    fn post(&self, body: &str) -> std::io::Result<String> {
        let mut tries = 0;
        let stream = loop {
            match TcpStream::connect(&self.host) {
                Ok(stream) => break stream,
                Err(e) if tries < 5 => {
                    tries += 1;
                    let _ = e;
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                Err(e) => return Err(e),
            }
        };
        stream.set_nodelay(true)?;
        let limit = Some(std::time::Duration::from_secs(120));
        stream.set_read_timeout(limit)?;
        stream.set_write_timeout(limit)?;
        let mut reader = BufReader::new(stream);
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.path,
            self.host,
            body.len()
        );
        let stream = reader.get_mut();
        stream.write_all(head.as_bytes())?;
        stream.write_all(body.as_bytes())?;
        stream.flush()?;
        read_response(&mut reader)
    }
}

impl Drop for Shadow {
    fn drop(&mut self) {
        let test = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string();
        let status = match (self.diverged.get(), self.desynced.borrow().as_deref()) {
            (true, _) => "diverged".to_string(),
            (false, Some(reason)) => format!("desynced:{reason}"),
            (false, None) => "in-sync".to_string(),
        };
        // test, twin, calls compared, status, rebuilds, skipped,
        // calls that met a state with a broken foreign key
        let line = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            test,
            self.path,
            self.compared.get(),
            status,
            self.rebuilds.get(),
            self.skipped.get(),
            self.uncompared.get()
        );
        self.append(&line);
    }
}

fn read_response(reader: &mut BufReader<TcpStream>) -> std::io::Result<String> {
    let bad = |what: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_string());
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(bad("connection closed"));
    }
    if !line.starts_with("HTTP/1.1 200") {
        return Err(bad(&format!("status {}", line.trim())));
    }
    let mut length = None;
    let mut chunked = false;
    loop {
        line.clear();
        reader.read_line(&mut line)?;
        let header = line.trim_end();
        if header.is_empty() {
            break;
        }
        let lower = header.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            length = v.trim().parse::<usize>().ok();
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            line.clear();
            reader.read_line(&mut line)?;
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| bad("chunk size"))?;
            let mut chunk = vec![0; size + 2];
            reader.read_exact(&mut chunk)?;
            if size == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else {
        let n = length.ok_or_else(|| bad("no length"))?;
        body.resize(n, 0);
        reader.read_exact(&mut body)?;
    }
    String::from_utf8(body).map_err(|_| bad("utf-8"))
}

/// `EXPLAIN` without `QUERY PLAN`: the bytecode listing.
fn is_bytecode_explain(sql: &str) -> bool {
    let words: Vec<String> = sql
        .split_whitespace()
        .take(2)
        .map(str::to_ascii_uppercase)
        .collect();
    words.first().is_some_and(|w| w == "EXPLAIN") && words.get(1).is_none_or(|w| w != "QUERY")
}

/// The class of an error as the adapters give it: the tx_guard is not
/// here (it is `GuardFailed`); a constraint, any other statement
/// failure, and the adapters' own refusals of a value by their message.
fn error_class(message: &str) -> String {
    let own = [
        "too many bound parameters",
        "bound value too large",
        "do: integer outside JS safe range",
        "do: number is not a safe integer",
        "do: named parameter",
        "do: placeholder number",
        "do: more than one statement",
        "do: unexpected result shape",
    ];
    if let Some(o) = own.iter().find(|o| message.starts_with(*o)) {
        return (*o).to_string();
    }
    if message.contains("constraint failed") || message.ends_with("constraint violation") {
        "constraint".into()
    } else {
        "statement".into()
    }
}

fn is_explain(sql: &str) -> bool {
    sql.trim_start()
        .get(..7)
        .is_some_and(|w| w.eq_ignore_ascii_case("explain"))
}

/// Whether a query reads only a connection's own counters
/// (`SELECT total_changes()`, `SELECT last_insert_rowid()`, or both): a
/// query that reads anything else beside them is compared.
fn engine_counter(sql: &str) -> bool {
    let lower = sql.trim().trim_end_matches(';').to_ascii_lowercase();
    let Some(list) = lower.strip_prefix("select") else {
        return false;
    };
    list.split(',')
        .all(|c| matches!(c.trim(), "total_changes()" | "last_insert_rowid()"))
}

/// An identifier in double quotes, with its own quotes doubled.
fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn error_answer(e: &BridgeError) -> Answer {
    match e {
        BridgeError::GuardFailed => Answer::Guard,
        BridgeError::Sql(m) => Answer::Sql(m.clone()),
        other => panic!("a Sql adapter answered {other:?}"),
    }
}

pub(crate) fn encode_params(params: &[SqlValue]) -> Vec<Value> {
    params.iter().map(encode_value).collect()
}

fn encode_value(v: &SqlValue) -> Value {
    match v {
        SqlValue::Null => json!({"n": 0}),
        SqlValue::Int(i) => json!({"i": i}),
        SqlValue::Text(t) => json!({"t": t}),
        SqlValue::Blob(b) => json!({"b": base64::engine::general_purpose::STANDARD.encode(b)}),
    }
}

fn decode_rows(v: &Value) -> Vec<Row> {
    v.as_array()
        .expect("rows")
        .iter()
        .map(|row| {
            row.as_array()
                .expect("row")
                .iter()
                .map(decode_value)
                .collect()
        })
        .collect()
}

fn decode_value(v: &Value) -> SqlValue {
    if v.get("n").is_some() {
        SqlValue::Null
    } else if let Some(i) = v.get("i") {
        SqlValue::Int(i.as_i64().expect("integer"))
    } else if let Some(t) = v.get("t") {
        SqlValue::Text(t.as_str().expect("text").to_string())
    } else if let Some(b) = v.get("b") {
        SqlValue::Blob(
            base64::engine::general_purpose::STANDARD
                .decode(b.as_str().expect("blob"))
                .expect("base64"),
        )
    } else {
        panic!("shadow value {v}")
    }
}

/// The `rebuild` call that makes a twin equal to `conn`: the tables in
/// the order they were made, their rows in rowid order (with the rowid,
/// for a rowid table), then the indexes and the triggers. `None` if the
/// database cannot be read.
fn dump(conn: &rusqlite::Connection) -> std::result::Result<Value, String> {
    dump_rows(conn).ok_or_else(|| "rebuild-unreadable".to_string())?
}

fn dump_rows(conn: &rusqlite::Connection) -> Option<std::result::Result<Value, String>> {
    let broken = conn
        .prepare("SELECT count(*) FROM pragma_foreign_key_check")
        .ok()?
        .query_row([], |r| r.get::<_, i64>(0))
        .ok()?;
    if broken > 0 {
        return Some(Err("fk-broken".into()));
    }
    let mut objects = conn
        .prepare(
            "SELECT type, name, sql FROM sqlite_master \
              WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY rowid",
        )
        .ok()?;
    let objects: Vec<(String, String, String)> = objects
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .ok()?
        .collect::<std::result::Result<_, _>>()
        .ok()?;
    let mut stmts = Vec::new();
    let mut later = Vec::new();
    let mut rows = Vec::new();
    for (kind, name, sql) in &objects {
        match kind.as_str() {
            "table" => {
                stmts.push(json!([sql, []]));
                let rowid = !sql.to_ascii_uppercase().contains("WITHOUT ROWID");
                let mut cols: Vec<String> = conn
                    .prepare("SELECT name FROM pragma_table_info(?1)")
                    .ok()?
                    .query_map([name], |r| r.get::<_, String>(0))
                    .ok()?
                    .collect::<std::result::Result<_, _>>()
                    .ok()?;
                cols = cols.into_iter().map(|c| quoted(&c)).collect();
                if rowid {
                    cols.insert(0, "rowid".into());
                }
                let list = cols.join(", ");
                let order = if rowid { " ORDER BY rowid" } else { "" };
                let marks = vec!["?"; cols.len()].join(", ");
                let table = quoted(name);
                let insert = format!("INSERT INTO {table} ({list}) VALUES ({marks})");
                let mut select = conn
                    .prepare(&format!("SELECT {list} FROM {table}{order}"))
                    .ok()?;
                let n = cols.len();
                let mut found = select.query([]).ok()?;
                while let Some(row) = found.next().ok()? {
                    let mut values = Vec::with_capacity(n);
                    for i in 0..n {
                        values.push(super::from_ref(row.get_ref(i).ok()?).ok()?);
                    }
                    rows.push(json!([insert, encode_params(&values)]));
                }
            }
            _ => later.push(json!([sql, []])),
        }
    }
    stmts.extend(rows);
    stmts.extend(later);
    Some(Ok(json!({"op": "rebuild", "stmts": stmts})))
}
