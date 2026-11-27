use std::future::Future;
use std::pin::{pin, Pin};
use std::task::Poll;

use futures_util::future::{join, join_all, poll_fn};
use futures_util::StreamExt;
use tokio_postgres::types::{ToSql, Type};
use tokio_postgres::{Client, PipelineStatement, Row};

use super::{error, params, value, WriteTx};
use crate::{BridgeError, Result, SqlValue};

pub(super) struct Prepared {
    pub(super) statement: params::Statement,
    values: value::Params,
}

impl Prepared {
    pub(super) fn new(text: &str, values: &[SqlValue]) -> Result<Self> {
        Ok(Self {
            statement: params::statement(text)?,
            values: value::Params::encode(values)?,
        })
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
                    rows: Vec::new(),
                    changed: None,
                    tag: None,
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
        let tag = stream.command_tag().map(str::to_owned);
        Ok(Reply { rows, changed, tag })
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
    rows: Vec<Row>,
    changed: Option<u64>,
    /// The command tag, for comparing the two transports in tests.
    #[cfg_attr(not(feature = "testkit-pg"), allow(dead_code))]
    tag: Option<String>,
}

impl Reply {
    #[cfg(feature = "testkit-pg")]
    pub(super) fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    pub(super) fn changed(&self) -> Result<u64> {
        self.changed.ok_or_else(error::shape)
    }

    pub(super) fn rows(self) -> Result<Vec<crate::Row>> {
        self.changed()?;
        self.rows.into_iter().map(value::decode).collect()
    }
}

/// The prelude statements: BEGIN, four `SET LOCAL`s and, unless the
/// negative-control test build disabled it, the W1 lock.
pub(super) fn prelude_statements(lock_key: Option<i64>) -> usize {
    PRELUDE.len() + usize::from(lock_key.is_some())
}

/// The prelude of the single-Sync transport, one statement each. The app
/// role defaults to read-only, so a write without BEGIN READ WRITE fails.
/// `log_parameter_max_length_on_error = 0` keeps bind values out of the
/// server's error log whatever the role or session says.
const PRELUDE: [&str; 5] = [
    "BEGIN READ WRITE, ISOLATION LEVEL READ COMMITTED",
    "SET LOCAL lock_timeout = '2s'",
    "SET LOCAL statement_timeout = '20s'",
    "SET LOCAL idle_in_transaction_session_timeout = '5s'",
    "SET LOCAL log_parameter_max_length_on_error = 0",
];

const LOCK: &str = "SELECT pg_advisory_xact_lock($1::bigint)";

pub(super) fn prelude(lock_key: Option<i64>) -> String {
    // The app role defaults to read-only. If a proxy drops this prelude,
    // later extended requests must not autocommit writes on that role.
    let mut start = PRELUDE.join("; ");
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

/// Where a write transaction's first error happened, for comparing the two
/// transports in tests. Not used otherwise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorPosition {
    Prelude,
    Statement(usize),
    Commit,
}

std::thread_local! {
    static ERROR_POSITION: std::cell::Cell<Option<ErrorPosition>> =
        const { std::cell::Cell::new(None) };
}

fn set_error_position(position: ErrorPosition) {
    ERROR_POSITION.with(|p| p.set(Some(position)));
}

/// The position of the last write transaction error on this thread, taken.
#[cfg(feature = "testkit-pg")]
pub(super) fn take_error_position() -> Option<ErrorPosition> {
    ERROR_POSITION.with(std::cell::Cell::take)
}

/// The statement that ends a transaction that succeeded. Only the
/// transport comparison tests end with ROLLBACK.
pub(super) const COMMIT: &str = "COMMIT";

/// The largest single-Sync request. The driver encodes the whole request
/// into one buffer before it sends it, and the Worker's socket writes it in
/// one piece: both must stay well inside the isolate's 128 MB. The largest
/// catalogue batch is a multipart Complete with a 2 MB placement value
/// (about 2 MB); 16 MiB leaves room for several values at the 2 MB limit.
/// A larger transaction uses the one-Sync-per-statement transport, which
/// has the same statements and binds.
pub const MAX_SINGLE_SYNC_BYTES: usize = 16 * 1024 * 1024;

/// The encoded size of the single-Sync request: Parse, Bind, Describe and
/// Execute per statement (unnamed, binary results), then one Sync.
pub(super) fn single_sync_bytes(lock_key: Option<i64>, prepared: &[Prepared], end: &str) -> usize {
    fn statement(text: usize, params: usize, bytes: usize) -> usize {
        let parse = 1 + 4 + 1 + text + 1 + 2 + 4 * params;
        let bind = 1 + 4 + 1 + 1 + 2 + 2 * params + 2 + 4 * params + bytes + 2 + 2;
        parse + bind + 7 + 10
    }
    let mut total = PRELUDE
        .iter()
        .map(|q| statement(q.len(), 0, 0))
        .sum::<usize>()
        + statement(end.len(), 0, 0)
        + 5;
    if lock_key.is_some() {
        total += statement(LOCK.len(), 1, 8);
    }
    for p in prepared {
        let (params, bytes) = p.values.wire_size();
        total = total.saturating_add(statement(p.statement.text.len(), params, bytes));
    }
    total
}

std::thread_local! {
    static OVERSIZE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Write transactions on this thread that exceeded
/// [`MAX_SINGLE_SYNC_BYTES`] and used the one-Sync-per-statement transport.
pub fn oversize_fallbacks() -> u64 {
    OVERSIZE.with(std::cell::Cell::get)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn transaction(
    client: &Client,
    lock_key: Option<i64>,
    write_tx: WriteTx,
    prepared: &[Prepared],
    collect_rows: bool,
    record: bool,
    end: &'static str,
    on_oversize: Option<fn(usize)>,
) -> Result<Vec<Reply>> {
    let write_tx = if write_tx == WriteTx::SingleSync
        && single_sync_bytes(lock_key, prepared, end) > MAX_SINGLE_SYNC_BYTES
    {
        OVERSIZE.with(|n| n.set(n.get() + 1));
        if let Some(hook) = on_oversize {
            hook(prepared.len());
        }
        WriteTx::Pipeline
    } else {
        write_tx
    };
    match write_tx {
        WriteTx::Pipeline => pipelined(client, lock_key, prepared, collect_rows, record, end).await,
        WriteTx::SingleSync => {
            match single_sync(client, lock_key, prepared, collect_rows, record, end).await {
                Ok(replies) => Ok(replies),
                Err((sent, err)) => {
                    if sent {
                        // W1 is released when the error aborts the transaction;
                        // this returns the origin connection clean. Its outcome
                        // changes nothing: the connection is dropped next.
                        let _ = client.simple_query("ROLLBACK").await;
                    }
                    Err(err)
                }
            }
        }
    }
}

/// Error class of a single-Sync transaction by position: `done` is the
/// index of the statement the error belongs to (the number of statements
/// that completed before it), `server` the SQLSTATE and constraint of a
/// server ErrorResponse, if it was one, and `status` the transaction status
/// of the final ReadyForQuery. Only a server statement's own SQLSTATE after
/// BEGIN and before COMMIT, followed by ReadyForQuery E, is a known
/// rollback. Anything that may hide a committed write is `statement
/// failed`.
pub(super) fn message_error(
    server: Option<(&str, Option<&str>)>,
    done: usize,
    prelude: usize,
    n: usize,
    status: Option<u8>,
) -> BridgeError {
    let Some((code, constraint)) = server else {
        // EOF, connection loss, or a protocol error: unknown outcome.
        return error::statement_failed();
    };
    if done == 0 {
        // Before BEGIN completed. Hyperdrive's 58000 is a known refusal
        // only once it is shown to precede forwarding of a Sync group.
        return if code == "58000" && error::SINGLE_SYNC_58000_BEFORE_FORWARD {
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
    if status != Some(b'E') {
        // Only the server's own ReadyForQuery in a failed transaction shows
        // that it skipped the rest, COMMIT included. Without it (the reply
        // ended, or a pooler said idle) the write may have committed.
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

/// The whole transaction as one request with one Sync. `Err((sent, _))`
/// says whether anything reached the connection: an encode error or a
/// closed connection sends nothing.
async fn single_sync(
    client: &Client,
    lock_key: Option<i64>,
    prepared: &[Prepared],
    collect_rows: bool,
    _record: bool,
    end: &'static str,
) -> core::result::Result<Vec<Reply>, (bool, BridgeError)> {
    let key = lock_key.unwrap_or_default();
    let mut stmts: Vec<PipelineStatement<'_>> = PRELUDE
        .iter()
        .map(|query| PipelineStatement {
            query,
            params: Vec::new(),
        })
        .collect();
    if lock_key.is_some() {
        stmts.push(PipelineStatement {
            query: LOCK,
            params: vec![(&key as &(dyn ToSql + Sync), Type::INT8)],
        });
    }
    let prelude = stmts.len();
    debug_assert_eq!(prelude, prelude_statements(lock_key));
    stmts.extend(prepared.iter().map(|p| PipelineStatement {
        query: &p.statement.text,
        params: p.values.typed().collect(),
    }));
    stmts.push(PipelineStatement {
        query: end,
        params: Vec::new(),
    });
    let n = prepared.len();
    let outcome = client
        .pipeline_typed(&stmts, collect_rows)
        .await
        .map_err(|_| (false, error::statement_failed()))?;
    if let Some((done, err)) = outcome.error {
        #[cfg(feature = "pg-test-record")]
        if _record {
            // As the typed transport records: every statement that ran,
            // including the one that failed.
            let ran = (done + 1).saturating_sub(prelude).min(n);
            prepared[..ran].iter().for_each(Prepared::record);
        }
        let server = err
            .as_db_error()
            .map(|db| (db.code().code(), db.constraint()));
        set_error_position(if done < prelude {
            ErrorPosition::Prelude
        } else if done < prelude + n {
            ErrorPosition::Statement(done - prelude)
        } else {
            ErrorPosition::Commit
        });
        return Err((
            true,
            message_error(server, done, prelude, n, outcome.status),
        ));
    }
    // Committed only if every statement completed, the last with exactly
    // the end tag, and the session is out of the transaction.
    let mut replies = outcome.replies;
    if replies.len() != prelude + n + 1
        || replies.last().map(|r| r.tag.as_str()) != Some(end)
        || outcome.status != Some(b'I')
    {
        return Err((true, error::shape()));
    }
    #[cfg(feature = "pg-test-record")]
    if _record {
        prepared.iter().for_each(Prepared::record);
    }
    replies.truncate(prelude + n);
    Ok(replies
        .drain(prelude..)
        .zip(prepared)
        .map(|(reply, p)| Reply {
            rows: reply.rows,
            changed: Some(if p.statement.select {
                0
            } else {
                reply.rows_affected
            }),
            tag: Some(reply.tag),
        })
        .collect())
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
            set_error_position(ErrorPosition::Prelude);
            return Err(err);
        }
    };
    let mut sent = Vec::with_capacity(stmts.len());
    for (i, s) in stmts.into_iter().enumerate() {
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
                set_error_position(ErrorPosition::Statement(i));
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
    let mut first_error = start.err().map(|err| (ErrorPosition::Prelude, err));
    let mut values = Vec::with_capacity(replies.len());
    for (i, reply) in replies.into_iter().enumerate() {
        match reply {
            // After a server error aborts a transaction, another statement
            // can't succeed. A proxy may have omitted the prelude or changed
            // transaction state; do not call this a known refusal or overload.
            Ok(_) if first_error.is_some() => return Err(error::statement_failed()),
            Ok(value) => values.push(value),
            Err(err) => {
                first_error.get_or_insert((ErrorPosition::Statement(i), err));
            }
        }
    }
    if let Some((position, err)) = first_error {
        set_error_position(position);
        return Err(err);
    }
    if commit.is_err() {
        set_error_position(ErrorPosition::Commit);
        return Err(error::statement_failed());
    }
    Ok(values)
}

#[cfg(all(feature = "testkit-pg", not(target_arch = "wasm32")))]
impl Reply {
    /// Check the count and run the real decoder before offering the native
    /// test session for reuse. The caller still owns the reply; ordinary
    /// exec/batch replies have no collected rows.
    pub(super) fn can_recycle(&self) -> bool {
        self.changed().is_ok()
            && self
                .rows
                .iter()
                .all(|row| value::decode(row.clone()).is_ok())
    }
}
