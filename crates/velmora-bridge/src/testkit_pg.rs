//! Disposable PostgreSQL schemas for native tests only.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use sha2::{Digest, Sha256};
use tokio::runtime::Builder;
use tokio::task::JoinHandle;
use tokio_postgres::{config::SslMode, Client, Config, NoTls};

use crate::pg::{PgConfig, PgConnect, PgConnection, PgSql};
use crate::ports::{Row, Sql, SqlValue};
use crate::types::{BridgeError, Result};

use super::ARM_USAGE;

const PRE: &str = include_str!("../../../workers/s3-bridge/pg/0001_baseline_pre.sql");
const POST: &str = include_str!("../../../workers/s3-bridge/pg/0002_baseline_post.sql");
const SEED: &str = "INSERT INTO usage_global(id) VALUES (1),(2)";
static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

pub const URL_VAR: &str = "VELMORA_TEST_PG_URL";

fn pg_error(context: &str, error: tokio_postgres::Error) -> BridgeError {
    // Never print a connection URL, server message, or bound parameter.
    use std::error::Error as _;
    if let Some(code) = error.code() {
        return BridgeError::Sql(format!("pg testkit: {context} ({})", code.code()));
    }
    let mut source = error.source();
    while let Some(cause) = source {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return BridgeError::Sql(format!("pg testkit: {context} (I/O {:?})", io.kind()));
        }
        source = cause.source();
    }
    BridgeError::Sql(format!("pg testkit: {context} (no SQLSTATE)"))
}

pub(crate) async fn connect(config: &Config) -> Result<(Client, JoinHandle<()>)> {
    if config.get_ssl_mode() == SslMode::Disable {
        let (client, connection) = config
            .connect(NoTls)
            .await
            .map_err(|error| pg_error("connect", error))?;
        Ok((
            client,
            tokio::spawn(async move {
                let _ = connection.await;
            }),
        ))
    } else {
        let tls = TlsConnector::new()
            .map(MakeTlsConnector::new)
            .map_err(|_| BridgeError::Sql("pg testkit: initialize TLS".into()))?;
        let (client, connection) = config
            .connect(tls)
            .await
            .map_err(|error| pg_error("connect with TLS", error))?;
        Ok((
            client,
            tokio::spawn(async move {
                let _ = connection.await;
            }),
        ))
    }
}

#[derive(Clone)]
pub struct NativePgConnect(Config);

impl PgConnect for NativePgConnect {
    async fn connect(&self) -> Result<PgConnection> {
        let (client, task) = connect(&self.0).await?;
        Ok(PgConnection::new(client, move || task.abort()))
    }
}

/// Owns a unique schema and its advisory lock key. The startup search path
/// has no fallback to `public`, and teardown cannot target any other schema.
/// The configured role needs CREATE on the disposable test database.
#[doc(hidden)]
pub struct TestPostgres {
    base: Config,
    schema: String,
    connector: NativePgConnect,
    lock_key: i64,
    pub(super) sql: PgSql<NativePgConnect>,
    pub(super) fixture_sql: PgSql<NativePgConnect>,
}

impl TestPostgres {
    pub(super) fn new(armed: bool, _record: bool) -> Result<Self> {
        let url = std::env::var(URL_VAR)
            .map_err(|_| BridgeError::Sql(format!("pg testkit: {URL_VAR} must be UTF-8")))?;
        let base: Config = url
            .parse()
            .map_err(|_| BridgeError::Sql(format!("pg testkit: invalid {URL_VAR}")))?;
        let serial = NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!("velmora_wp4_{:x}_{time:x}_{serial:x}", std::process::id());
        let hash = Sha256::digest(schema.as_bytes());
        let lock_key = i64::from_be_bytes(hash[..8].try_into().unwrap());
        let mut scoped = base.clone();
        scoped.options(format!("-c search_path={schema},pg_temp"));
        let connector = NativePgConnect(scoped);
        let sql = || {
            PgSql::new(
                connector.clone(),
                connector.clone(),
                PgConfig {
                    lock_key,
                    ..PgConfig::default()
                },
            )
        };
        let catalog = sql();
        #[cfg(feature = "pg-test-record")]
        let catalog = if _record {
            catalog.with_statement_recording()
        } else {
            catalog
        };
        let setup_config = base.clone();
        let setup_schema = schema.clone();
        management(move || async move {
            let (client, _) = connect(&setup_config).await?;
            // One transaction: if setup fails, no partially migrated schema survives.
            let arm = if armed { ARM_USAGE } else { "" };
            client.batch_execute(&format!(
                "BEGIN; CREATE SCHEMA {setup_schema}; SET LOCAL search_path = {setup_schema}, pg_temp; \
                 {PRE}\n{SEED};\n{POST}\n{arm}; COMMIT;"
            )).await.map_err(|error| pg_error("apply baseline", error))
        })?;
        Ok(Self {
            base,
            schema,
            lock_key,
            sql: catalog,
            fixture_sql: sql(),
            connector,
        })
    }

    pub fn lock_key(&self) -> i64 {
        self.lock_key
    }

    /// Open a session for typed PREPARE and fixture setup. The connection is
    /// closed when the current test runtime shuts down or the client is dropped.
    pub async fn client(&self) -> Result<Client> {
        connect(&self.connector.0).await.map(|(client, _)| client)
    }

    pub(super) fn fixture_query_now(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Row>> {
        let connector = self.connector.clone();
        let lock_key = self.lock_key;
        let sql = sql.to_owned();
        let params = params.to_vec();
        management(move || async move {
            let db = PgSql::new(
                connector.clone(),
                connector,
                PgConfig {
                    lock_key,
                    ..PgConfig::default()
                },
            );
            db.query(&sql, &params).await
        })
    }

    pub(super) fn fixture_script(&self, script: &str) -> Result<()> {
        let config = self.connector.0.clone();
        let script = script.to_owned();
        management(move || async move {
            let (client, _) = connect(&config).await?;
            client
                .batch_execute(&format!(
                    "SET lock_timeout = '3s'; SET statement_timeout = '20s'; {script}"
                ))
                .await
                .map_err(|error| pg_error("run fixture script", error))
        })
    }
}

impl Drop for TestPostgres {
    fn drop(&mut self) {
        let config = self.base.clone();
        let schema = self.schema.clone();
        let result = management(move || async move {
            let (client, _) = connect(&config).await?;
            client
                .batch_execute(&format!(
                    "SET lock_timeout = '3s'; DROP SCHEMA {schema} CASCADE"
                ))
                .await
                .map_err(|error| pg_error("drop isolated schema", error))
        });
        if let Err(error) = result {
            if std::thread::panicking() {
                eprintln!("could not clean up test schema {}: {error}", self.schema);
            } else {
                panic!("could not clean up test schema {}: {error}", self.schema);
            }
        }
    }
}

// Existing native test constructors and destructors are synchronous and run
// inside current-thread runtimes. Keep schema I/O off that runtime rather
// than attempting to run a nested Tokio executor.
fn management<F, Fut, T>(f: F) -> Result<T>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T>>,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| BridgeError::Sql("pg testkit: initialize management runtime".into()))?;
        rt.block_on(f())
    })
    .join()
    .map_err(|_| BridgeError::Sql("pg testkit: management thread panicked".into()))?
}
