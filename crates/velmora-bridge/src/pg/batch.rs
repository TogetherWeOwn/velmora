use std::future::Future;
use std::pin::{pin, Pin};
use std::task::Poll;

use futures_util::future::{join, join_all, poll_fn};
use futures_util::StreamExt;
use tokio_postgres::{Client, Row};

use super::{error, params, value};
use crate::{Result, SqlValue};

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
            super::registry::record(&self.statement.text, self.values.oids());
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
        Ok(Reply { rows, changed })
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
}

impl Reply {
    pub(super) fn changed(&self) -> Result<u64> {
        self.changed.ok_or_else(error::shape)
    }

    pub(super) fn rows(self) -> Result<Vec<crate::Row>> {
        self.changed()?;
        self.rows.into_iter().map(value::decode).collect()
    }
}

fn prelude(lock_key: Option<i64>) -> String {
    // The app role defaults to read-only. If a proxy drops this prelude,
    // later extended requests must not autocommit writes on that role.
    let mut start =
        "BEGIN READ WRITE, ISOLATION LEVEL READ COMMITTED; SET LOCAL lock_timeout = '2s'; \
        SET LOCAL statement_timeout = '20s'; SET LOCAL idle_in_transaction_session_timeout = '5s'"
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

pub(super) async fn transaction(
    client: &Client,
    lock_key: Option<i64>,
    pipelined: bool,
    prepared: &[Prepared],
    collect_rows: bool,
    record: bool,
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
    let finish = |commit| control(client, if commit { "COMMIT" } else { "ROLLBACK" });
    if pipelined {
        pipeline(begin, stmts.collect(), finish).await
    } else {
        if let Err(err) = begin.await {
            let _ = finish(false).await;
            return Err(err);
        }
        let mut replies = Vec::with_capacity(prepared.len());
        for s in stmts {
            match s.await {
                Ok(reply) => replies.push(reply),
                Err(err) => {
                    let _ = finish(false).await;
                    return Err(err);
                }
            }
        }
        finish(true).await.map_err(|_| error::statement_failed())?;
        Ok(replies)
    }
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
