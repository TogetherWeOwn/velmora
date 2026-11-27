//! Postgres implementation of the catalogue SQL port.

mod batch;
mod error;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod finish_tests;
mod params;
#[cfg(feature = "pg-test-record")]
mod registry;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod single_sync_tests;
#[cfg(test)]
mod tests;
mod value;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod wire_tests;

use crate::{Dialect, Result, Row, Sql, SqlValue};
use batch::Prepared;
use params::Kind;

pub use batch::{oversize_fallbacks, MAX_SINGLE_SYNC_BYTES};

/// Lets the Worker reject even a transitively enabled test escape hatch.
#[doc(hidden)]
pub const TEST_UNLOCKED: bool = cfg!(feature = "pg-test-unlocked");

/// Whether this catalogue SQL is a single read without a locking or DML
/// clause. Includes SQLite inputs for the frozen D1 adapter.
pub fn is_read_only(sql: &str) -> bool {
    params::is_read_only(sql)
}

/// Like [`is_read_only`], with PostgreSQL literal and denylist semantics.
pub fn is_postgres_read_only(sql: &str) -> bool {
    params::statement(sql).is_ok_and(|s| s.kind == Kind::Read)
}

/// Test only: the encoded size of the single-Sync request for `stmts`.
#[cfg(feature = "testkit-pg")]
#[doc(hidden)]
pub fn single_sync_request_bytes(
    lock_key: Option<i64>,
    stmts: &[(&str, Vec<SqlValue>)],
) -> Result<usize> {
    let prepared = stmts
        .iter()
        .map(|(sql, args)| Prepared::new(sql, args))
        .collect::<Result<Vec<_>>>()?;
    Ok(batch::single_sync_bytes(lock_key, &prepared, batch::COMMIT))
}

/// Redact connection failures before they leave a runtime connector.
pub fn classify_connect_error(error: tokio_postgres::Error) -> crate::BridgeError {
    error::before_catalogue(error)
}

/// Canonical SQL used by PostgreSQL, also used to compare coverage entries.
pub fn normalize_statement(sql: &str) -> Result<String> {
    params::statement(sql).map(|s| s.text)
}
/// Request-owned connection; dropping it stops the driver, even on cancellation.
pub struct PgConnection {
    client: Option<tokio_postgres::Client>,
    close: Option<Box<dyn FnOnce()>>,
    #[cfg(all(feature = "testkit-pg", not(target_arch = "wasm32")))]
    recycle: Option<Box<dyn FnOnce(tokio_postgres::Client)>>,
}
impl PgConnection {
    pub fn new(client: tokio_postgres::Client, close: impl FnOnce() + 'static) -> Self {
        Self {
            client: Some(client),
            close: Some(Box::new(close)),
            #[cfg(all(feature = "testkit-pg", not(target_arch = "wasm32")))]
            recycle: None,
        }
    }
    pub fn client(&self) -> &tokio_postgres::Client {
        self.client.as_ref().expect("connection still open")
    }

    /// Teardown without waiting. Callers take their result first and
    /// return it right after this, so nothing that happens to the socket
    /// can delay, fail or retry a confirmed COMMIT. The close hook stops
    /// the driver; the runtime's transport requests the socket close on
    /// drop and does not wait for it. No Terminate is sent: the server
    /// sees an ordinary disconnect, the same as for a cancelled request.
    fn finish(mut self) {
        drop(self.client.take());
    }
}

impl Drop for PgConnection {
    fn drop(&mut self) {
        if let Some(close) = self.close.take() {
            close();
        }
    }
}

/// A runtime-specific factory, not a pool or an open socket.
#[allow(async_fn_in_trait)]
pub trait PgConnect {
    async fn connect(&self) -> Result<PgConnection>;
}

/// How a W1-guarded write transaction travels to the server.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WriteTx {
    /// One extended-protocol request with a single Sync: BEGIN, the prelude
    /// and the W1 lock, every statement with its typed binds, COMMIT. The
    /// server runs it without waiting on the client between statements.
    #[default]
    SingleSync,
    /// Typed parameters, one Sync per statement, every request enqueued
    /// before the first reply. A proxy that forwards one request at a time
    /// holds W1 across each request's wait.
    Pipeline,
}

impl WriteTx {
    /// `PG_WRITE_TX`: unset or `single-sync`, or `pipeline`.
    pub fn parse(value: Option<&str>) -> core::result::Result<Self, &'static str> {
        match value {
            None | Some("single-sync") => Ok(Self::SingleSync),
            Some("pipeline") => Ok(Self::Pipeline),
            _ => Err("invalid PG_WRITE_TX"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PgConfig {
    pub lock_key: i64,
    pub write_tx: WriteTx,
    /// Called with the statement count when a write transaction exceeds
    /// [`MAX_SINGLE_SYNC_BYTES`] and uses the one-Sync-per-statement
    /// transport. It receives no SQL and no values.
    pub on_oversize: Option<fn(usize)>,
}

impl Default for PgConfig {
    fn default() -> Self {
        Self {
            lock_key: 7_413_000_001,
            write_tx: WriteTx::SingleSync,
            on_oversize: None,
        }
    }
}

/// Accepts a write and a read connector. The backend itself never owns a
/// connection, so it is safe to share across Worker I/O contexts.
pub struct PgSql<C: PgConnect> {
    writer: C,
    reader: C,
    config: PgConfig,
    #[cfg(feature = "pg-test-unlocked")]
    unlocked: bool,
    #[cfg(feature = "pg-test-record")]
    record: bool,
}

impl<C: PgConnect> PgSql<C> {
    pub fn new(writer: C, reader: C, config: PgConfig) -> Self {
        Self {
            writer,
            reader,
            config,
            #[cfg(feature = "pg-test-unlocked")]
            unlocked: false,
            #[cfg(feature = "pg-test-record")]
            record: false,
        }
    }

    /// Negative-control test and drill only. Not enabled in the S3 Worker.
    #[cfg(feature = "pg-test-unlocked")]
    pub fn without_write_lock_for_test(mut self) -> Self {
        self.unlocked = true;
        self
    }

    #[cfg(feature = "pg-test-record")]
    pub fn with_statement_recording(mut self) -> Self {
        self.record = true;
        self
    }

    fn recording(&self) -> bool {
        #[cfg(feature = "pg-test-record")]
        {
            self.record
        }
        #[cfg(not(feature = "pg-test-record"))]
        {
            false
        }
    }

    fn lock_key(&self) -> Option<i64> {
        #[cfg(feature = "pg-test-unlocked")]
        let lock_key = (!self.unlocked).then_some(self.config.lock_key);
        #[cfg(not(feature = "pg-test-unlocked"))]
        let lock_key = Some(self.config.lock_key);
        lock_key
    }

    async fn write(&self, prepared: &[Prepared], collect_rows: bool) -> Result<Vec<batch::Reply>> {
        self.write_ending(prepared, collect_rows, self.config.write_tx, batch::COMMIT)
            .await
    }

    async fn write_ending(
        &self,
        prepared: &[Prepared],
        collect_rows: bool,
        write_tx: WriteTx,
        end: &'static str,
    ) -> Result<Vec<batch::Reply>> {
        let lock_key = self.lock_key();
        let conn = self.writer.connect().await.map_err(error::without_guard)?;
        let result = batch::transaction(
            conn.client(),
            lock_key,
            write_tx,
            prepared,
            collect_rows,
            self.recording(),
            end,
            self.config.on_oversize,
        )
        .await;
        finish_connection!(write conn, result);
        result
    }
}

/// What one write transaction returned: each statement's count and, when
/// rows were collected, its decoded rows.
#[cfg(feature = "testkit-pg")]
#[doc(hidden)]
pub type ProbeOutcome = Result<(Vec<u64>, Vec<Vec<Row>>)>;

#[cfg(feature = "testkit-pg")]
impl<C: PgConnect> PgSql<C> {
    /// Test only: run one write transaction on `write_tx`, ending it with
    /// ROLLBACK instead of COMMIT, and return what the caller would get.
    /// Used to compare the two transports on the same catalogue state.
    #[doc(hidden)]
    pub async fn rolled_back(
        &self,
        write_tx: WriteTx,
        stmts: &[(&str, Vec<SqlValue>)],
        collect_rows: bool,
    ) -> ProbeOutcome {
        let prepared = stmts
            .iter()
            .map(|(sql, args)| Prepared::new(sql, args))
            .collect::<Result<Vec<_>>>()?;
        let replies = self
            .write_ending(&prepared, collect_rows, write_tx, "ROLLBACK")
            .await?;
        let counts = replies
            .iter()
            .map(batch::Reply::changed)
            .collect::<Result<Vec<_>>>()?;
        let rows = if collect_rows {
            replies
                .into_iter()
                .map(batch::Reply::rows)
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        Ok((counts, rows))
    }
}

impl<C: PgConnect> Sql for PgSql<C> {
    // Keep the connector handshake and pipeline state out of the enclosing
    // service futures' stack layout. These futures are nested several deep.
    async fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        Box::pin(async {
            let prepared = Prepared::new(sql, params)?;
            if prepared.statement.kind == Kind::Read {
                let conn = self.reader.connect().await.map_err(error::without_guard)?;
                let result = prepared.run(conn.client(), true, self.recording()).await;
                finish_connection!(read conn, result);
                result.map_err(error::without_guard)?.rows()
            } else {
                self.write(&[prepared], true)
                    .await?
                    .pop()
                    .ok_or_else(error::shape)?
                    .rows()
            }
        })
        .await
    }

    async fn exec(&self, sql: &str, params: &[SqlValue]) -> Result<u64> {
        Box::pin(async {
            let stmt = Prepared::new(sql, params)?;
            self.write(&[stmt], false)
                .await?
                .first()
                .ok_or_else(error::shape)?
                .changed()
        })
        .await
    }

    async fn batch(&self, stmts: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        if stmts.is_empty() {
            return Ok(Vec::new());
        }
        Box::pin(async {
            let all = stmts
                .into_iter()
                .map(|(sql, args)| Prepared::new(sql, &args))
                .collect::<Result<Vec<_>>>()?;
            self.write(&all, false)
                .await?
                .iter()
                .map(batch::Reply::changed)
                .collect()
        })
        .await
    }

    fn dialect(&self) -> Dialect {
        Dialect::Postgres
    }
}

// Keep the Worker's close-before-decode ordering and panic locations.
macro_rules! finish_connection {
    (write $conn:ident, $result:ident) => {{
        #[cfg(all(feature = "testkit-pg", not(target_arch = "wasm32")))]
        let $conn = $conn.recycle_if_clean(|| {
            $result
                .as_ref()
                .is_ok_and(|replies| replies.iter().all(batch::Reply::can_recycle))
        });
        $conn.finish()
    }};
    (read $conn:ident, $result:ident) => {{
        #[cfg(all(feature = "testkit-pg", not(target_arch = "wasm32")))]
        let $conn =
            $conn.recycle_if_clean(|| $result.as_ref().is_ok_and(batch::Reply::can_recycle));
        $conn.finish()
    }};
}
use finish_connection;

#[cfg(all(feature = "testkit-pg", not(target_arch = "wasm32")))]
impl PgConnection {
    // The recycler owns the driver: dropping it without calling it aborts
    // the driver, including when an operation is cancelled before finish.
    pub(crate) fn recyclable(
        client: tokio_postgres::Client,
        recycle: impl FnOnce(tokio_postgres::Client) + 'static,
    ) -> Self {
        Self {
            client: Some(client),
            close: None,
            recycle: Some(Box::new(recycle)),
        }
    }

    fn recycle_if_clean(mut self, clean: impl FnOnce() -> bool) -> Self {
        if let Some(recycle) = self.recycle.take() {
            if clean() {
                recycle(self.client.take().expect("connection still open"));
            }
        }
        self
    }
}
