use crate::{
    fixture::{self, OpError, Read},
    Runtime,
};
use futures_channel::oneshot;
use std::cell::RefCell;
use tokio_postgres::{
    types::{ToSql, Type},
    Client,
};
use velmora_bridge::{
    pg::{
        classify_connect_error, is_postgres_read_only, normalize_statement, PgConnect, PgConnection,
    },
    ports::{Dialect, Row, Sql, SqlValue},
    sql::SqlCatalog,
    BridgeError, Result,
};

/// The local and Worker drivers also expose graceful close to the raw read
/// probe; the product adapter continues to use PgConnection unchanged.
pub trait DrillConnect: PgConnect {
    #[allow(async_fn_in_trait)]
    async fn open(&self) -> Result<DrillSession>;
}

pub struct DrillSession {
    client: Option<Client>,
    stop: Option<Box<dyn FnOnce()>>,
    done: Option<oneshot::Receiver<()>>,
}

impl DrillSession {
    pub fn new(client: Client, stop: impl FnOnce() + 'static, done: oneshot::Receiver<()>) -> Self {
        Self {
            client: Some(client),
            stop: Some(Box::new(stop)),
            done: Some(done),
        }
    }
    pub fn into_pg(mut self) -> PgConnection {
        // PgConnection stops its driver without waiting. Only raw probes
        // await `done` through DrillSession::close.
        PgConnection::new(
            self.client.take().expect("open client"),
            self.stop.take().expect("open driver"),
        )
    }
    fn client(&self) -> &Client {
        self.client.as_ref().expect("open client")
    }
    async fn close(mut self) {
        drop(self.client.take());
        let _ = self.done.take().expect("unconsumed driver").await;
    }
}

impl Drop for DrillSession {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop();
        }
    }
}

pub(crate) struct Statement {
    sql: String,
    params: Vec<SqlValue>,
}

struct Capture<'a>(&'a RefCell<Option<Statement>>);
impl Sql for Capture<'_> {
    fn dialect(&self) -> Dialect {
        Dialect::Postgres
    }
    async fn query(&self, sql: &str, values: &[SqlValue]) -> Result<Vec<Row>> {
        if self.0.borrow().is_some() || !is_postgres_read_only(sql) {
            return Err(unexpected());
        }
        self.0.replace(Some(Statement {
            sql: normalize_statement(sql)?,
            params: values.to_vec(),
        }));
        Ok(Vec::new()) // only retrieve this catalogue method's actual statement and bind values
    }
    async fn exec(&self, _: &str, _: &[SqlValue]) -> Result<u64> {
        Err(unexpected())
    }
    async fn batch(&self, _: Vec<(&'static str, Vec<SqlValue>)>) -> Result<Vec<u64>> {
        Err(unexpected())
    }
}

fn unexpected() -> BridgeError {
    BridgeError::Invalid("read probe must be a single SELECT")
}

pub(crate) async fn statements() -> std::result::Result<[Vec<Statement>; 3], String> {
    let mut entries: [Vec<Statement>; 3] = Default::default();
    for (i, operation) in [Read::Get, Read::Head, Read::List].into_iter().enumerate() {
        for key in 0..if i == 2 { 1 } else { fixture::READ_KEYS } {
            let probe = RefCell::new(None);
            let captured = fixture::read(&SqlCatalog::new(Capture(&probe)), operation, key).await;
            if !matches!(captured, Err(OpError::Refused)) {
                return Err("read statement capture failed".into());
            }
            entries[i].push(
                probe
                    .into_inner()
                    .ok_or("read statement capture was empty")?,
            );
        }
    }
    Ok(entries)
}

/// Timing around the same unnamed typed query the catalogue selects.
/// Returns when the result rows are received, before connection shutdown.
pub(crate) async fn execute<C: DrillConnect, R: Runtime>(
    reader: &C,
    rt: &R,
    statement: &Statement,
) -> std::result::Result<f64, OpError> {
    let null: Option<String> = None;
    let binds: Vec<(&(dyn ToSql + Sync), Type)> = statement
        .params
        .iter()
        .map(|p| match p {
            SqlValue::Text(v) => (v as &(dyn ToSql + Sync), Type::TEXT),
            SqlValue::Int(v) => (v as &(dyn ToSql + Sync), Type::INT8),
            SqlValue::Blob(v) => (v as &(dyn ToSql + Sync), Type::BYTEA),
            SqlValue::Null => (&null as &(dyn ToSql + Sync), Type::UNKNOWN),
        })
        .collect();
    let session = reader.open().await?;
    let start = rt.monotonic_ms();
    let rows = session.client().query_typed(&statement.sql, &binds).await;
    let latency = (rt.monotonic_ms() - start).max(0.0);
    session.close().await;
    let rows = rows.map_err(classify_connect_error)?;
    if rows.is_empty() {
        Err(OpError::Refused)
    } else {
        Ok(latency)
    }
}
