//! "Rows written" meter for the native rig (feature `testkit`).
//!
//! D1 bills rows written, and an index entry counts as a row. The counter
//! D1 reports (`meta.rows_written`) follows SQLite's write opcodes, which
//! this meter reproduces from the outside:
//!
//! - one for every table row inserted, updated or deleted (the primary
//!   key b-tree of a `WITHOUT ROWID` table is the table);
//! - one for every index entry written: at an insert, each index the new
//!   row belongs to; at an update, each index the statement may change
//!   (one of its key columns, or a column of its `WHERE`, is assigned) and
//!   the new row belongs to;
//! - nothing for an index entry removed, nothing for the row a `REPLACE`
//!   displaces (only a `DELETE` statement's rows count), and nothing for
//!   a statement that changes no row.
//!
//! Rows changed by triggers count like any other. The rules were measured
//! against the local D1 runtime, statement by statement, over this schema;
//! `tests/rows_written.rs` pins the measured figures.
//!
//! How it sees the writes: SQLite's pre-update hook reports every row
//! change with the new row, and the authorizer reports, when a statement
//! is prepared, the columns it assigns (trigger bodies included). Which
//! indexes exist, and what their `WHERE` says, is read from the schema.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use rusqlite::hooks::{AuthAction, AuthContext, Authorization, PreUpdateCase};
use rusqlite::types::Value;
use rusqlite::{params_from_iter, Connection};

/// What a row change was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WriteOp {
    Insert,
    Update,
    Delete,
}

/// Billed writes: table rows and index entries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Table rows inserted, updated or deleted.
    pub rows: u64,
    /// Index entries written.
    pub index_entries: u64,
}

impl Tally {
    /// What D1 bills: rows plus index entries.
    pub fn billed(&self) -> u64 {
        self.rows + self.index_entries
    }

    fn add(&mut self, other: Tally) {
        self.rows += other.rows;
        self.index_entries += other.index_entries;
    }
}

/// Everything metered since the last reset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteReport {
    /// By table and operation.
    pub by_table: BTreeMap<(String, WriteOp), Tally>,
    /// By statement text (whitespace collapsed); a trigger's writes are
    /// charged to the statement that fired it.
    pub by_statement: BTreeMap<String, Tally>,
    /// Statements that wrote at least one row.
    pub writing_statements: u64,
}

impl WriteReport {
    /// Rows written as D1 bills them.
    pub fn billed(&self) -> u64 {
        self.by_table.values().map(Tally::billed).sum()
    }

    /// Billed rows of one table, every operation.
    pub fn table(&self, table: &str) -> u64 {
        self.by_table
            .iter()
            .filter(|((t, _), _)| t == table)
            .map(|(_, tally)| tally.billed())
            .sum()
    }

    /// What was metered after `earlier` was taken.
    pub fn since(&self, earlier: &WriteReport) -> WriteReport {
        let mut out = WriteReport {
            writing_statements: self.writing_statements - earlier.writing_statements,
            ..WriteReport::default()
        };
        for (k, v) in &self.by_table {
            let e = earlier.by_table.get(k).copied().unwrap_or_default();
            let d = Tally {
                rows: v.rows - e.rows,
                index_entries: v.index_entries - e.index_entries,
            };
            if d.billed() > 0 {
                out.by_table.insert(k.clone(), d);
            }
        }
        for (k, v) in &self.by_statement {
            let e = earlier.by_statement.get(k).copied().unwrap_or_default();
            let d = Tally {
                rows: v.rows - e.rows,
                index_entries: v.index_entries - e.index_entries,
            };
            if d.billed() > 0 {
                out.by_statement.insert(k.clone(), d);
            }
        }
        out
    }

    /// One line per table and operation, then per statement, largest
    /// first: for a test's failure message.
    pub fn render(&self) -> String {
        let mut out = format!("billed rows written: {}\n", self.billed());
        let mut tables: Vec<_> = self.by_table.iter().collect();
        tables.sort_by_key(|(_, t)| std::cmp::Reverse(t.billed()));
        for ((table, op), t) in tables {
            out.push_str(&format!(
                "  {:>6}  {table} {op:?} (rows {}, index entries {})\n",
                t.billed(),
                t.rows,
                t.index_entries
            ));
        }
        let mut stmts: Vec<_> = self.by_statement.iter().collect();
        stmts.sort_by_key(|(_, t)| std::cmp::Reverse(t.billed()));
        for (sql, t) in stmts {
            let short: String = sql.chars().take(110).collect();
            out.push_str(&format!("  {:>6}  {short}\n", t.billed()));
        }
        out
    }
}

struct Event {
    table: String,
    op: WriteOp,
    /// The row after the change (insert, update).
    new: Vec<Value>,
}

#[derive(Default)]
struct Seen {
    events: Vec<Event>,
    /// `(table, column)` the statement being prepared assigns.
    assigned: BTreeSet<(String, String)>,
    /// Tables the statement being prepared deletes from with `DELETE`.
    deleted: BTreeSet<String>,
}

struct IndexModel {
    /// Key columns plus the columns its `WHERE` names.
    columns: BTreeSet<String>,
    /// An index over an expression: assume any assignment changes it.
    expression: bool,
    /// The partial index's `WHERE`, as SQL over the table's columns.
    predicate: Option<String>,
}

struct TableModel {
    columns: Vec<String>,
    indexes: Vec<IndexModel>,
}

/// The meter of one connection.
pub(crate) struct Meter {
    seen: Arc<Mutex<Seen>>,
    tables: BTreeMap<String, TableModel>,
    report: WriteReport,
}

fn lock(seen: &Arc<Mutex<Seen>>) -> std::sync::MutexGuard<'_, Seen> {
    seen.lock().unwrap_or_else(|e| e.into_inner())
}

impl Meter {
    /// Installs the hooks on `conn`.
    pub(crate) fn install(conn: &mut Connection) -> rusqlite::Result<Meter> {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let hook = Arc::clone(&seen);
        conn.preupdate_hook(Some(
            move |_action, _db: &str, table: &str, case: &PreUpdateCase| {
                let (op, new) = match case {
                    PreUpdateCase::Insert(new) => (WriteOp::Insert, Some(new)),
                    PreUpdateCase::Update {
                        new_value_accessor, ..
                    } => (WriteOp::Update, Some(new_value_accessor)),
                    PreUpdateCase::Delete(_) => (WriteOp::Delete, None),
                    PreUpdateCase::Unknown => return,
                };
                let mut row = Vec::new();
                if let Some(new) = new {
                    for i in 0..new.get_column_count() {
                        row.push(
                            new.get_new_column_value(i)
                                .ok()
                                .and_then(|v| Value::try_from(v).ok())
                                .unwrap_or(Value::Null),
                        );
                    }
                }
                lock(&hook).events.push(Event {
                    table: table.to_string(),
                    op,
                    new: row,
                });
            },
        ))?;
        let auth = Arc::clone(&seen);
        conn.authorizer(Some(move |ctx: AuthContext<'_>| {
            match ctx.action {
                AuthAction::Update {
                    table_name,
                    column_name,
                } => {
                    lock(&auth)
                        .assigned
                        .insert((table_name.to_string(), column_name.to_string()));
                }
                AuthAction::Delete { table_name } => {
                    lock(&auth).deleted.insert(table_name.to_string());
                }
                _ => {}
            }
            Authorization::Allow
        }))?;
        Ok(Meter {
            seen,
            tables: BTreeMap::new(),
            report: WriteReport::default(),
        })
    }

    /// Forgets what a statement that failed, or a batch that rolled back,
    /// reported: nothing was written.
    pub(crate) fn discard(&mut self) {
        let mut seen = lock(&self.seen);
        seen.events.clear();
        seen.assigned.clear();
        seen.deleted.clear();
    }

    /// Prices the row changes of the statement that just ran. Returns the
    /// tallies instead of committing them, so a batch can drop them all
    /// when it rolls back.
    pub(crate) fn price(
        &mut self,
        conn: &Connection,
    ) -> rusqlite::Result<Vec<(String, WriteOp, Tally)>> {
        let (events, assigned, deleted) = {
            let mut seen = lock(&self.seen);
            (
                std::mem::take(&mut seen.events),
                std::mem::take(&mut seen.assigned),
                std::mem::take(&mut seen.deleted),
            )
        };
        let mut out = Vec::new();
        for ev in events {
            if ev.op == WriteOp::Delete && !deleted.contains(&ev.table) {
                // The row a REPLACE displaced: not billed.
                continue;
            }
            if !self.tables.contains_key(&ev.table) {
                let model = load_table(conn, &ev.table)?;
                self.tables.insert(ev.table.clone(), model);
            }
            let model = &self.tables[&ev.table];
            let mut tally = Tally {
                rows: 1,
                index_entries: 0,
            };
            if ev.op != WriteOp::Delete {
                for ix in &model.indexes {
                    let touched = ev.op == WriteOp::Insert
                        || ix.expression
                        || ix
                            .columns
                            .iter()
                            .any(|c| assigned.contains(&(ev.table.clone(), c.clone())));
                    if touched && belongs(conn, model, ix, &ev.new)? {
                        tally.index_entries += 1;
                    }
                }
            }
            out.push((ev.table, ev.op, tally));
        }
        // The predicate probes above were prepared on this connection and
        // may have left authorizer notes; they assign nothing, but keep
        // the next statement's slate clean.
        self.discard();
        Ok(out)
    }

    /// Adds priced writes to the report under `sql`.
    pub(crate) fn commit(&mut self, sql: &str, priced: Vec<(String, WriteOp, Tally)>) {
        if priced.is_empty() {
            return;
        }
        self.report.writing_statements += 1;
        let key = sql.split_whitespace().collect::<Vec<_>>().join(" ");
        for (table, op, tally) in priced {
            self.report
                .by_table
                .entry((table, op))
                .or_default()
                .add(tally);
            self.report
                .by_statement
                .entry(key.clone())
                .or_default()
                .add(tally);
        }
    }

    pub(crate) fn report(&self) -> WriteReport {
        self.report.clone()
    }

    pub(crate) fn reset(&mut self) {
        self.report = WriteReport::default();
        self.tables.clear();
        self.discard();
    }
}

/// Whether the row is in the index: always for a full index, by its
/// `WHERE` for a partial one.
fn belongs(
    conn: &Connection,
    table: &TableModel,
    ix: &IndexModel,
    row: &[Value],
) -> rusqlite::Result<bool> {
    let Some(predicate) = &ix.predicate else {
        return Ok(true);
    };
    if row.len() != table.columns.len() {
        // Cannot evaluate: count the entry (the meter must not undercount).
        return Ok(true);
    }
    let cols: Vec<String> = table
        .columns
        .iter()
        .enumerate()
        .map(|(i, c)| format!("?{} AS \"{}\"", i + 1, c.replace('"', "\"\"")))
        .collect();
    let sql = format!(
        "SELECT COALESCE(({predicate}), 0) FROM (SELECT {})",
        cols.join(", ")
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let hit: i64 = stmt.query_row(params_from_iter(row.iter()), |r| r.get(0))?;
    Ok(hit != 0)
}

fn load_table(conn: &Connection, table: &str) -> rusqlite::Result<TableModel> {
    let quoted = table.replace('"', "\"\"");
    let mut columns = Vec::new();
    {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{quoted}\")"))?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            columns.push(r.get::<_, String>(1)?);
        }
    }
    let without_rowid: bool = conn
        .query_row(
            "SELECT wr FROM pragma_table_list WHERE name = ?1 AND schema = 'main'",
            [table],
            |r| r.get::<_, i64>(0),
        )
        .map(|wr| wr != 0)?;
    let mut listed = Vec::new();
    {
        let mut stmt = conn.prepare(&format!("PRAGMA index_list(\"{quoted}\")"))?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            // seq, name, unique, origin, partial
            listed.push((
                r.get::<_, String>(1)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)? != 0,
            ));
        }
    }
    let mut indexes = Vec::new();
    for (name, origin, partial) in listed {
        if without_rowid && origin == "pk" {
            // The table itself.
            continue;
        }
        let mut cols = BTreeSet::new();
        let mut expression = false;
        {
            let iq = name.replace('"', "\"\"");
            let mut stmt = conn.prepare(&format!("PRAGMA index_xinfo(\"{iq}\")"))?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                // seqno, cid, name, desc, coll, key
                let cid: i64 = r.get(1)?;
                let key: i64 = r.get(5)?;
                if key == 0 {
                    continue;
                }
                match (cid, r.get::<_, Option<String>>(2)?) {
                    (-2, _) => expression = true,
                    (_, Some(c)) => {
                        cols.insert(c);
                    }
                    _ => {}
                }
            }
        }
        let mut predicate = None;
        if partial {
            let sql: String = conn.query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?1",
                [&name],
                |r| r.get(0),
            )?;
            let where_sql = partial_where(&sql).unwrap_or("1").to_string();
            for word in identifiers(&where_sql) {
                if columns.iter().any(|c| c.eq_ignore_ascii_case(&word)) {
                    cols.insert(
                        columns
                            .iter()
                            .find(|c| c.eq_ignore_ascii_case(&word))
                            .cloned()
                            .unwrap_or(word),
                    );
                }
            }
            predicate = Some(where_sql);
        }
        indexes.push(IndexModel {
            columns: cols,
            expression,
            predicate,
        });
    }
    Ok(TableModel { columns, indexes })
}

/// The text after the `WHERE` of a `CREATE INDEX` (the first `WHERE`
/// outside parentheses and quotes).
fn partial_where(create_sql: &str) -> Option<&str> {
    let bytes = create_sql.as_bytes();
    let mut depth = 0i32;
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
        } else {
            match b {
                b'\'' | b'"' | b'`' => quote = Some(b),
                b'(' => depth += 1,
                b')' => depth -= 1,
                b'w' | b'W'
                    if depth == 0
                        && bytes.len() >= i + 5
                        && bytes[i..i + 5].eq_ignore_ascii_case(b"where")
                        && (i == 0 || !is_ident(bytes[i - 1]))
                        && bytes.get(i + 5).is_none_or(|c| !is_ident(*c)) =>
                {
                    return Some(create_sql[i + 5..].trim());
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Bare and double-quoted identifiers of an expression; string literals
/// are skipped.
fn identifiers(expr: &str) -> Vec<String> {
    let bytes = expr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
                i += 1;
            }
            b'"' => {
                let start = i + 1;
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += 1;
                }
                out.push(expr[start..i.min(bytes.len())].to_string());
                i += 1;
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                let start = i;
                while i < bytes.len() && is_ident(bytes[i]) {
                    i += 1;
                }
                out.push(expr[start..i].to_string());
            }
            _ => i += 1,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn where_clause_is_found_outside_parentheses_and_quotes() {
        assert_eq!(
            partial_where("CREATE INDEX i ON t(a, b) WHERE s = 'held'"),
            Some("s = 'held'")
        );
        assert_eq!(
            partial_where("CREATE INDEX i ON t(\"where\", b)\n  WHERE s IN ('a','b')"),
            Some("s IN ('a','b')")
        );
        assert_eq!(partial_where("CREATE INDEX i ON t(a)"), None);
    }

    #[test]
    fn identifiers_skip_string_literals() {
        assert_eq!(
            identifiers("safety_state IN ('held', 'state') AND \"n\" > 0"),
            vec!["safety_state", "IN", "AND", "n"]
        );
    }
}
