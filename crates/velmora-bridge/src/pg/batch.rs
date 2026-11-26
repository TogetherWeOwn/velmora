use std::future::Future;
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::task::Poll;

use futures_util::future::{join, join_all, poll_fn};
use futures_util::StreamExt;
use tokio_postgres::{Client, Row, SimpleColumn, SimpleQueryMessage, SimpleQueryRow};

use super::{error, literal, params, results, value, WriteTx};
use crate::{BridgeError, Result, SqlValue};

pub(super) struct Prepared {
    pub(super) statement: params::Statement,
    values: value::Params,
}

impl Prepared {
    pub(super) fn new(text: &str, values: &[SqlValue]) -> Result<Self> {
        let statement = params::statement(text)?;
        let values = value::Params::encode(values)?;
        // The server refused a missing value before; the literal transport
        // must refuse it itself. Both transports refuse it before any I/O.
        if statement.max_bind() > values.len() {
            return Err(BridgeError::Sql("pg: bind failed".into()));
        }
        Ok(Self { statement, values })
    }

    pub(super) fn values(&self) -> &value::Params {
        &self.values
    }

    #[cfg(feature = "pg-test-record")]
    fn record(&self) {
        super::registry::record(&self.statement.text, self.values.oids());
    }

    pub(super) async fn run(
        &self,
        client: &Client,
        collect_rows: bool,
        _record: bool,
    ) -> Result<Reply> {
        let raw = self.raw(client, collect_rows).await;
        #[cfg(feature = "pg-test-record")]
        if _record
            && (raw.is_ok()
                || raw.as_ref().err().and_then(|e| e.code()).is_some_and(|c| {
                    *c != tokio_postgres::error::SqlState::IN_FAILED_SQL_TRANSACTION
                }))
        {
            self.record();
        }
        raw.map_err(error::from_driver)
    }

    async fn raw(
        &self,
        client: &Client,
        collect_rows: bool,
    ) -> core::result::Result<Reply, tokio_postgres::Error> {
        #[cfg(test)]
        if self.statement.text == REJECT_BIND_SQL {
            use tokio_postgres::types::{ToSql, Type};
            let invalid = (&RejectBind as &(dyn ToSql + Sync), Type::INT8);
            // Fail in the real driver's pre-enqueue encoder, not a mock
            // future. All normally prepared catalogue values are infallible.
            return client
                .query_typed(&self.statement.text, &[invalid])
                .await
                .map(|_| Reply {
                    rows: Rows::Typed(Vec::new()),
                    changed: None,
                });
        }
        let mut stream = pin!(
            client
                .query_typed_raw(&self.statement.text, self.values.typed())
                .await?
        );
        let mut rows = Vec::new();
        while let Some(row) = stream.next().await {
            let row = row?;
            if collect_rows {
                rows.push(row)
            }
        }
        let changed = stream
            .rows_affected()
            .map(|count| if self.statement.select { 0 } else { count });
        Ok(Reply {
            rows: Rows::Typed(rows),
            changed,
        })
    }
}

#[cfg(test)]
pub(super) const REJECT_BIND_SQL: &str = "SELECT $1::bigint /* test: reject this bind */";

#[cfg(test)]
#[derive(Debug)]
struct RejectBind;

#[cfg(test)]
impl tokio_postgres::types::ToSql for RejectBind {
    fn to_sql(
        &self,
        _: &tokio_postgres::types::Type,
        _: &mut bytes::BytesMut,
    ) -> core::result::Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Send + Sync>>
    {
        Err(std::io::Error::other("injected encode failure").into())
    }

    fn accepts(_: &tokio_postgres::types::Type) -> bool {
        true
    }
    tokio_postgres::types::to_sql_checked!();
}

pub(super) struct Reply {
    rows: Rows,
    changed: Option<u64>,
}

/// Rows are decoded only when the caller takes them, after the outcome of
/// the transaction is known, on both transports.
enum Rows {
    /// Binary rows of the typed transport, with their column OIDs.
    Typed(Vec<Row>),
    /// Text rows of the one-message transport, for a declared statement.
    Text {
        declared: Option<&'static results::Declared>,
        columns: Option<Arc<[SimpleColumn]>>,
        rows: Vec<SimpleQueryRow>,
    },
}

impl Reply {
    pub(super) fn changed(&self) -> Result<u64> {
        self.changed.ok_or_else(error::shape)
    }

    pub(super) fn rows(self) -> Result<Vec<crate::Row>> {
        self.changed()?;
        match self.rows {
            Rows::Typed(rows) => rows.into_iter().map(value::decode).collect(),
            Rows::Text {
                declared,
                columns,
                rows,
            } => results::decode(
                declared.ok_or_else(results::undeclared)?,
                columns.as_deref(),
                &rows,
            ),
        }
    }
}

/// The prelude statements: BEGIN, four `SET LOCAL`s and, unless the
/// negative-control test build disabled it, the W1 lock.
pub(super) fn prelude_statements(lock_key: Option<i64>) -> usize {
    5 + usize::from(lock_key.is_some())
}

pub(super) fn prelude(lock_key: Option<i64>) -> String {
    // The app role defaults to read-only. If a proxy drops this prelude,
    // later extended requests must not autocommit writes on that role.
    // `bytea_output` sets how the one-message transport's text results
    // write BYTEA, not how SQL is lexed, so it applies in the same message.
    let mut start =
        "BEGIN READ WRITE, ISOLATION LEVEL READ COMMITTED; SET LOCAL lock_timeout = '2s'; \
        SET LOCAL statement_timeout = '20s'; SET LOCAL idle_in_transaction_session_timeout = '5s'; \
        SET LOCAL bytea_output = 'hex'"
            .to_owned();
    if let Some(key) = lock_key {
        // This is the only variable in the prelude and is an i64, not SQL text.
        use std::fmt::Write;
        write!(start, "; SELECT pg_advisory_xact_lock({key}::bigint)")
            .expect("writing to a String does not fail");
    }
    start
}

async fn control(client: &Client, sql: &str) -> Result<()> {
    client
        .simple_query(sql)
        .await
        .map(|_| ())
        .map_err(error::from_driver)
        .map_err(error::without_guard)
}

/// How a write transaction goes to the server, decided before any I/O.
pub(super) enum Plan {
    /// One simple-Query message: prelude, statements with literals, end.
    Message(String),
    /// Typed parameters, every request enqueued before the first reply.
    Pipeline,
}

/// The statement that ends a transaction that succeeded. Only the
/// transport comparison tests end with ROLLBACK.
pub(super) const COMMIT: &str = "COMMIT";

/// Render the message, or choose the typed transport, before any I/O. A
/// render failure sends nothing. A write `query` in message mode must have
/// declared result columns.
pub(super) fn plan(
    write_tx: WriteTx,
    lock_key: Option<i64>,
    prepared: &[Prepared],
    collect_rows: bool,
    end: &str,
    on_oversize: Option<fn(usize)>,
) -> Result<Plan> {
    if write_tx == WriteTx::Pipeline {
        return Ok(Plan::Pipeline);
    }
    if collect_rows
        && prepared
            .iter()
            .any(|p| results::declared(&p.statement.text).is_none())
    {
        return Err(results::undeclared());
    }
    match literal::message(&prelude(lock_key), prepared, end)? {
        Some(message) => Ok(Plan::Message(message)),
        None => {
            OVERSIZE.with(|n| n.set(n.get() + 1));
            if let Some(hook) = on_oversize {
                hook(prepared.len());
            }
            Ok(Plan::Pipeline)
        }
    }
}

std::thread_local! {
    static OVERSIZE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Write transactions on this thread that exceeded the message bound and
/// used the typed transport instead.
pub fn oversize_fallbacks() -> u64 {
    OVERSIZE.with(std::cell::Cell::get)
}

pub(super) async fn transaction(
    client: &Client,
    lock_key: Option<i64>,
    plan: &Plan,
    prepared: &[Prepared],
    collect_rows: bool,
    record: bool,
    end: &'static str,
) -> Result<Vec<Reply>> {
    let message = match plan {
        Plan::Message(message) => message,
        Plan::Pipeline => {
            return pipelined(client, lock_key, prepared, collect_rows, record, end).await
        }
    };
    let expected = prelude_statements(lock_key);
    match one_message(client, message, expected, prepared, collect_rows, record).await {
        Ok(replies) => Ok(replies),
        Err(err) => {
            // W1 is released when the error aborts the transaction; this
            // returns the origin connection clean. Its outcome changes
            // nothing: the connection is dropped next.
            let _ = client.simple_query("ROLLBACK").await;
            Err(err)
        }
    }
}

/// Error class of a one-message transaction by reply position: `done` is
/// the number of CommandCompletes received before the error, `server` the
/// SQLSTATE and constraint of a server ErrorResponse, if it was one. Only a
/// server statement's own SQLSTATE after BEGIN and before COMMIT is a known
/// rollback. Anything that may hide a committed write is `statement failed`.
pub(super) fn message_error(
    server: Option<(&str, Option<&str>)>,
    done: usize,
    prelude: usize,
    n: usize,
) -> BridgeError {
    let Some((code, constraint)) = server else {
        // EOF, connection loss, or a protocol error: unknown outcome.
        return error::statement_failed();
    };
    if done == 0 {
        // Before BEGIN completed. Hyperdrive's 58000 is a known refusal
        // only once it is shown to precede forwarding in message mode.
        return if code == "58000" && error::MESSAGE_58000_BEFORE_FORWARD {
            error::overloaded()
        } else {
            error::statement_failed()
        };
    }
    if done >= prelude + n || !error::server_statement_code(code) {
        // The COMMIT position is classed exactly as a COMMIT failure on the
        // typed transport. A code no statement raises is unknown too.
        return error::statement_failed();
    }
    let class = error::classify(code, constraint);
    if done < prelude {
        // A prelude statement is never a guard refusal.
        error::without_guard(class)
    } else {
        class
    }
}

async fn one_message(
    client: &Client,
    message: &str,
    prelude: usize,
    prepared: &[Prepared],
    collect_rows: bool,
    _record: bool,
) -> Result<Vec<Reply>> {
    let n = prepared.len();
    let mut stream = pin!(client
        .simple_query_raw(message)
        .await
        .map_err(|_| error::statement_failed())?);
    let mut done = 0;
    let mut replies = Vec::with_capacity(n);
    let mut columns = None;
    let mut rows = Vec::new();
    while let Some(item) = stream.next().await {
        let catalogue = (prelude..prelude + n).contains(&done);
        match item {
            Ok(SimpleQueryMessage::CommandComplete(count)) => {
                if catalogue {
                    let p = &prepared[done - prelude];
                    replies.push(Reply {
                        rows: Rows::Text {
                            declared: results::declared(&p.statement.text),
                            columns: columns.take(),
                            rows: std::mem::take(&mut rows),
                        },
                        changed: Some(if p.statement.select { 0 } else { count }),
                    });
                }
                columns = None;
                done += 1;
            }
            Ok(SimpleQueryMessage::RowDescription(described)) => {
                if catalogue && collect_rows {
                    columns = Some(described);
                }
            }
            Ok(SimpleQueryMessage::Row(row)) => {
                if catalogue && collect_rows {
                    rows.push(row);
                }
            }
            Ok(_) => return Err(error::shape()),
            Err(err) => {
                #[cfg(feature = "pg-test-record")]
                if _record {
                    // As the typed transport records: every statement that
                    // ran, including the one that failed.
                    let ran = done.saturating_sub(prelude) + usize::from(catalogue);
                    prepared[..ran.min(n)].iter().for_each(Prepared::record);
                }
                let server = err
                    .as_db_error()
                    .map(|db| (db.code().code(), db.constraint()));
                return Err(message_error(server, done, prelude, n));
            }
        }
    }
    if done != prelude + n + 1 {
        // Possibly committed: never a known refusal.
        return Err(error::shape());
    }
    #[cfg(feature = "pg-test-record")]
    if _record {
        prepared.iter().for_each(Prepared::record);
    }
    Ok(replies)
}

async fn pipelined(
    client: &Client,
    lock_key: Option<i64>,
    prepared: &[Prepared],
    collect_rows: bool,
    record: bool,
    end: &'static str,
) -> Result<Vec<Reply>> {
    let start = prelude(lock_key);
    let begin = async {
        client
            .simple_query(&start)
            .await
            .map(|_| ())
            .map_err(error::before_catalogue)
    };
    let stmts = prepared.iter().map(|s| s.run(client, collect_rows, record));
    let finish = |commit| control(client, if commit { end } else { "ROLLBACK" });
    pipeline(begin, stmts.collect(), finish).await
}

async fn first_poll<F: Future>(mut step: Pin<&mut F>) -> Poll<F::Output> {
    poll_fn(|cx| Poll::Ready(step.as_mut().poll(cx))).await
}

/// The 0.7.18 driver encodes/enqueues in the first poll, before waiting on
/// a response. A first-poll error may mean nothing was sent, so COMMIT may
/// only be constructed after all statement futures have cleared that poll.
/// Collect replies in wire order, not in readiness order: a later 25P02 or
/// a COMMIT that implicitly rolled back must not mask the original refusal.
pub(super) async fn pipeline<T, B, S, F, End>(begin: B, stmts: Vec<S>, finish: F) -> Result<Vec<T>>
where
    B: Future<Output = Result<()>>,
    S: Future<Output = Result<T>>,
    F: FnOnce(bool) -> End,
    End: Future<Output = Result<()>>,
{
    let mut begin = Box::pin(begin);
    let began = match first_poll(begin.as_mut()).await {
        Poll::Ready(Ok(())) => true,
        Poll::Pending => false,
        Poll::Ready(Err(err)) => {
            drop(begin);
            let _ = finish(false).await;
            return Err(err);
        }
    };
    let mut sent = Vec::with_capacity(stmts.len());
    for s in stmts {
        let mut s = Box::pin(s);
        let instant = match first_poll(s.as_mut()).await {
            Poll::Pending => None,
            Poll::Ready(Ok(reply)) => Some(reply),
            Poll::Ready(Err(err)) => {
                // Dropping response receivers doesn't unsend requests. It
                // lets the driver drain replies even if a prelude was split
                // into multiple response chunks, then process ROLLBACK.
                drop(s);
                drop(sent);
                drop(begin);
                let _ = finish(false).await;
                return Err(err);
            }
        };
        sent.push(async move {
            match instant {
                Some(reply) => Ok(reply),
                None => s.await,
            }
        });
    }
    let begin = async {
        if began {
            Ok(())
        } else {
            begin.await
        }
    };
    let (commit, (start, replies)) = join(finish(true), join(begin, join_all(sent))).await;
    let mut first_error = start.err();
    let mut values = Vec::with_capacity(replies.len());
    for reply in replies {
        match reply {
            // After a server error aborts a transaction, another statement
            // can't succeed. A proxy may have omitted the prelude or changed
            // transaction state; do not call this a known refusal or overload.
            Ok(_) if first_error.is_some() => return Err(error::statement_failed()),
            Ok(value) => values.push(value),
            Err(err) => {
                first_error.get_or_insert(err);
            }
        }
    }
    if let Some(err) = first_error {
        return Err(err);
    }
    commit.map_err(|_| error::statement_failed())?;
    Ok(values)
}

#[cfg(all(feature = "testkit-pg", not(target_arch = "wasm32")))]
impl Reply {
    /// Check the count and run the real decoder before offering the native
    /// test session for reuse. The caller still owns the reply; ordinary
    /// exec/batch replies have no collected rows.
    pub(super) fn can_recycle(&self) -> bool {
        self.changed().is_ok()
            && match &self.rows {
                Rows::Typed(rows) => rows.iter().all(|row| value::decode(row.clone()).is_ok()),
                Rows::Text {
                    declared,
                    columns,
                    rows,
                } => {
                    rows.is_empty()
                        || declared
                            .is_some_and(|d| results::decode(d, columns.as_deref(), rows).is_ok())
                }
            }
    }
}
