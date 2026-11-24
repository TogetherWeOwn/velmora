//! Postgres implementation of the catalogue SQL port.

mod batch;
mod error;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod finish_tests;
mod params;
#[cfg(feature = "pg-test-record")]
mod registry;
#[cfg(test)]
mod tests;
mod value;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod wire_tests;

use crate::{Dialect, Result, Row, Sql, SqlValue};
use batch::Prepared;
use params::Kind;

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

#[derive(Clone, Copy, Debug)]
pub struct PgConfig {
    pub lock_key: i64,
    pub pipeline: bool,
}

impl Default for PgConfig {
    fn default() -> Self {
        Self {
            lock_key: 7_413_000_001,
            pipeline: true,
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

    async fn write(&self, prepared: &[Prepared], collect_rows: bool) -> Result<Vec<batch::Reply>> {
        #[cfg(feature = "pg-test-unlocked")]
        let lock_key = (!self.unlocked).then_some(self.config.lock_key);
        #[cfg(not(feature = "pg-test-unlocked"))]
        let lock_key = Some(self.config.lock_key);
        let conn = self.writer.connect().await.map_err(error::without_guard)?;
        let result = batch::transaction(
            conn.client(),
            lock_key,
            self.config.pipeline,
            prepared,
            collect_rows,
            self.recording(),
        )
        .await;
        finish_connection!(conn, result);
        result
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
                finish_connection!(conn, result);
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

// Outside native PG tests this expands to the original finish call. Keeping
// the call sites on one line also preserves the Worker's panic locations.
macro_rules! finish_connection {
    ($conn:ident, $result:ident) => {{
        #[cfg(all(feature = "testkit-pg", not(target_arch = "wasm32")))]
        let $conn = $conn.recycle_if_clean($result.is_ok());
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

    fn recycle_if_clean(mut self, clean: bool) -> Self {
        if clean {
            if let Some(recycle) = self.recycle.take() {
                recycle(self.client.take().expect("connection still open"));
            }
        }
        self
    }
}
