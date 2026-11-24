//! Disposable PostgreSQL schemas for native tests only.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use sha2::{Digest, Sha256};
use tokio::runtime::{Builder, Handle, Id};
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

fn prepare_config(config: &Config) -> Result<Config> {
    let mut config = config.clone();
    if config.get_ssl_mode() == SslMode::Disable {
        let loopback = matches!(config.get_hosts(),
            [tokio_postgres::config::Host::Tcp(host)]
                if host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()));
        if !loopback || !config.get_hostaddrs().is_empty() {
            return Err(BridgeError::Sql(
                "pg testkit: cleartext requires a single numeric loopback host without hostaddr"
                    .into(),
            ));
        }
    } else {
        // Prefer can silently negotiate cleartext. Always require verified TLS.
        config.ssl_mode(SslMode::Require);
    }
    Ok(config)
}

pub(crate) async fn connect(config: &Config) -> Result<(Client, JoinHandle<()>)> {
    let config = prepare_config(config)?;
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

// Bound cached sessions, not concurrent operations: if every session is
// leased, connect as before rather than serializing tests through the pool.
const MAX_IDLE_SESSIONS: usize = 4;

struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct IdleSession {
    client: Client,
    driver: Driver,
    runtime: Id,
}

#[derive(Clone)]
pub struct NativePgConnect {
    config: Config,
    idle: Arc<Mutex<Vec<IdleSession>>>,
}

impl NativePgConnect {
    fn new(config: Config) -> Self {
        Self {
            config,
            idle: Arc::default(),
        }
    }

    fn take_idle(&self, runtime: Id) -> Option<IdleSession> {
        let mut idle = self.idle.lock().unwrap();
        idle.retain(|session| !session.client.is_closed());
        // A current-thread runtime drives its sockets only while it runs.
        // In particular, a synchronous fixture query uses its own runtime.
        let index = idle
            .iter()
            .rposition(|session| session.runtime == runtime)?;
        Some(idle.swap_remove(index))
    }
}

impl PgConnect for NativePgConnect {
    async fn connect(&self) -> Result<PgConnection> {
        let runtime = Handle::current().id();
        let (client, driver) = if let Some(session) = self.take_idle(runtime) {
            // Await a successful reset before handing out the session. A
            // rejected or cancelled reset retires it via the driver guard.
            if session.client.batch_execute("DISCARD ALL").await.is_ok() {
                (session.client, session.driver)
            } else {
                drop(session);
                let (client, task) = connect(&self.config).await?;
                (client, Driver(task))
            }
        } else {
            let (client, task) = connect(&self.config).await?;
            (client, Driver(task))
        };
        let idle = Arc::clone(&self.idle);
        Ok(PgConnection::recyclable(client, move |client| {
            let session = IdleSession {
                client,
                driver,
                runtime,
            };
            let mut idle = idle.lock().unwrap();
            if idle.len() < MAX_IDLE_SESSIONS {
                idle.push(session);
            }
        }))
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
        let connector = NativePgConnect::new(scoped);
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
        connect(&self.connector.config)
            .await
            .map(|(client, _)| client)
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
        let config = self.connector.config.clone();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cleartext_fixture() -> Option<Config> {
        let url = std::env::var(URL_VAR).ok()?;
        let config: Config = url
            .parse()
            .unwrap_or_else(|_| panic!("invalid PostgreSQL test configuration"));
        (config.get_ssl_mode() == SslMode::Disable).then_some(config)
    }

    #[test]
    fn cleartext_requires_a_single_numeric_loopback_without_hostaddr() {
        for input in [
            "host=192.0.2.1 sslmode=disable",
            "host=localhost sslmode=disable",
            "host=127.0.0.1,127.0.0.2 sslmode=disable",
            "host=127.0.0.1 hostaddr=127.0.0.1 sslmode=disable",
        ] {
            let config = input.parse::<Config>().unwrap();
            assert!(prepare_config(&config).is_err(), "accepted {input}");
        }
    }

    #[tokio::test]
    async fn implicit_tls_mode_does_not_fall_back_on_a_tls_off_server() {
        let Some(mut config) = cleartext_fixture() else {
            return;
        };
        let (db, driver) = connect(&config).await.unwrap();
        let server_ssl: String = db.query_one("SHOW ssl", &[]).await.unwrap().get(0);
        drop(db);
        driver.abort();
        if server_ssl != "off" {
            return;
        }
        // Preserve the test endpoint, but restore the mode of a config with no sslmode.
        config.ssl_mode(Config::new().get_ssl_mode());
        assert!(
            connect(&config).await.is_err(),
            "implicit sslmode accepted a TLS-off PostgreSQL server"
        );
    }

    #[tokio::test]
    async fn explicit_cleartext_connects_to_the_loopback_fixture() {
        let Some(config) = cleartext_fixture() else {
            return;
        };
        let (db, driver) = connect(&config).await.unwrap();
        assert_eq!(
            db.query_one("SELECT 1", &[])
                .await
                .unwrap()
                .get::<_, i32>(0),
            1
        );
        drop(db);
        driver.abort();
    }
}
