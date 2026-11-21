//! The write mark of a unit (ADR-TENANCY §8.6, "A dump is not a
//! snapshot", RD-8).
//!
//! A dump pages rows out of a live unit over many calls. Whether every
//! page saw the same database cannot be told from the stamp or the two
//! seqs: verify, the outbox, intents, leases and counters change rows
//! with no stamp raise, and a commit whose raise came before the first
//! page lands between pages with the counter unchanged. So the unit
//! keeps, in memory and at no row cost:
//!
//! - `wake_id`: random, set at each wake (the unit object makes it from
//!   the platform's random source when it is constructed);
//! - `writes`: a count raised by **the one function through which every
//!   write of the unit goes**, [`MarkedSql`].
//!
//! Every page of a dump carries the [`Mark`]. A dump is `exact` only when
//! the mark is the same on every page: no write of any kind ran and the
//! unit did not sleep and wake in between. Anything else is `fuzzy`.
//!
//! **Which calls count.** Every `exec` and every `batch`, whatever their
//! statements, and every `query` whose text can write
//! ([`statement_may_write`]: the catalogue writes through `query` too,
//! with `RETURNING`). The rule errs one way only: a read counted as a
//! write makes a dump `fuzzy`, which is safe; a write that is not
//! counted would make a torn dump `exact`, which is not. The count is
//! raised **before** the statement runs and **again after** it answers
//! (also when it fails, and when the call is dropped half-way): a page read during a write that yields before it
//! applies sees a count that the next page no longer sees, whichever side
//! of the write it fell on.
//!
//! **How it is held.** The unit builds its catalogue only over
//! `MarkedSql<its Sql>`, and the inner database is a private field: no
//! catalogue code can reach it past the mark. `tests/unit_lease_mark.rs`
//! drives the S3 paths and the jobs over an auditing database and fails
//! when any call changes a row without the mark moving.

use std::cell::Cell;
use std::rc::Rc;

use crate::ports::{Row, Sql, SqlLimits, SqlValue};
use crate::types::Result;

/// The mark at one moment: which wake, and how many writes in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Mark {
    pub wake_id: [u8; 16],
    pub writes: u64,
    /// A write was under way when the mark was read. A page read then may
    /// hold part of it, so a dump with such a page is never `exact`.
    pub writing: bool,
}

/// The unit's write mark. One per wake of the unit object.
#[derive(Debug)]
pub struct WriteMark {
    wake_id: [u8; 16],
    writes: Cell<u64>,
    /// Writes that have begun and not yet answered.
    in_flight: Cell<u32>,
}

impl WriteMark {
    /// A new wake. `wake_id` must be random (16 bytes of the platform's
    /// random source): two wakes with the same id would let a dump
    /// across a sleep pass as `exact`.
    pub fn new(wake_id: [u8; 16]) -> WriteMark {
        WriteMark {
            wake_id,
            writes: Cell::new(0),
            in_flight: Cell::new(0),
        }
    }

    /// The mark now.
    pub fn mark(&self) -> Mark {
        Mark {
            wake_id: self.wake_id,
            writes: self.writes.get(),
            writing: self.writing(),
        }
    }

    /// Whether a write is under way: between its two raises. An audit
    /// below the mark asks this for every call that changed a row.
    pub fn writing(&self) -> bool {
        self.in_flight.get() > 0
    }

    fn raise(&self) {
        // A wake that reached 2^64 writes is not a case; saturating keeps
        // the count from wrapping back to a value a page already saw.
        self.writes.set(self.writes.get().saturating_add(1));
    }

    /// Raises the mark and holds it raised until the guard is dropped,
    /// which raises it again: after the answer, after an error, and when
    /// the call is dropped half-way.
    fn begin(&self) -> Writing<'_> {
        self.raise();
        self.in_flight.set(self.in_flight.get().saturating_add(1));
        Writing(self)
    }
}

/// One write under way. See [`WriteMark::begin`].
struct Writing<'a>(&'a WriteMark);

impl Drop for Writing<'_> {
    fn drop(&mut self) {
        self.0
            .in_flight
            .set(self.0.in_flight.get().saturating_sub(1));
        self.0.raise();
    }
}

/// Whether a dump whose pages carried `marks` is `exact`: one mark on
/// every page, and no page read while a write was under way. An empty
/// list is not exact (there was no page to compare).
pub fn exact(marks: &[Mark]) -> bool {
    marks
        .first()
        .is_some_and(|first| marks.iter().all(|m| m == first && !m.writing))
}

/// Words that make a statement one that can change the database.
const WRITE_WORDS: [&str; 21] = [
    "INSERT",
    "UPDATE",
    "DELETE",
    "REPLACE",
    "UPSERT",
    "RETURNING",
    "CREATE",
    "DROP",
    "ALTER",
    "PRAGMA",
    "VACUUM",
    "REINDEX",
    "ANALYZE",
    "ATTACH",
    "DETACH",
    "BEGIN",
    "COMMIT",
    "ROLLBACK",
    "SAVEPOINT",
    "RELEASE",
    "END",
];

/// Whether `sql` may change the database: it holds one of the write
/// words as a word of its own (case-insensitive; `updated_at` is not
/// `UPDATE`). A word inside a string literal or a comment counts too:
/// see the module text for why that error is the safe one.
pub fn statement_may_write(sql: &str) -> bool {
    sql.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|word| WRITE_WORDS.iter().any(|w| w.eq_ignore_ascii_case(word)))
}

/// The unit's database behind the write mark. See the [module](self).
pub struct MarkedSql<S: Sql> {
    inner: S,
    mark: Rc<WriteMark>,
}

impl<S: Sql> MarkedSql<S> {
    /// `inner` behind `mark`. The unit keeps a second `Rc` of the mark
    /// for the pages of a dump.
    pub fn new(inner: S, mark: Rc<WriteMark>) -> MarkedSql<S> {
        MarkedSql { inner, mark }
    }

    /// The mark now.
    pub fn mark(&self) -> Mark {
        self.mark.mark()
    }

    /// The shared mark.
    pub fn write_mark(&self) -> &Rc<WriteMark> {
        &self.mark
    }

    /// The database past the mark, for native tests only: a test that
    /// shows the audit catches a write that bypasses the mark needs one.
    #[cfg(feature = "testkit")]
    pub fn unmarked(&self) -> &S {
        &self.inner
    }
}

impl<S: Sql> Sql for MarkedSql<S> {
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        if !statement_may_write(sql) {
            return self.inner.query(sql, params).await;
        }
        let _writing = self.mark.begin();
        self.inner.query(sql, params).await
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        let _writing = self.mark.begin();
        self.inner.exec(sql, params).await
    }

    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        let _writing = self.mark.begin();
        self.inner.batch(stmts).await
    }

    async fn query_after_refusal(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        if !statement_may_write(sql) {
            return self.inner.query_after_refusal(sql, params).await;
        }
        let _writing = self.mark.begin();
        self.inner.query_after_refusal(sql, params).await
    }

    fn limits(&self) -> SqlLimits {
        self.inner.limits()
    }
}
