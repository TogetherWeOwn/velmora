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

use crate::pg::{PgConfig, PgConnect, PgConnection, PgSql, ProbeOutcome, WriteTx};
use crate::ports::{Row, Sql, SqlValue};
use crate::types::{BridgeError, Result};

use super::ARM_USAGE;

/// Every shipped PostgreSQL stage, in order. The fresh-test seed runs
/// between the first two, as `pg-migrate.sh` does. A test checks that this
/// list matches the stage files.
pub(crate) const STAGES: &[(&str, &str)] = &[
    (
        "0001_baseline_pre.sql",
        include_str!("../../../workers/s3-bridge/pg/0001_baseline_pre.sql"),
    ),
    (
        "0002_baseline_post.sql",
        include_str!("../../../workers/s3-bridge/pg/0002_baseline_post.sql"),
    ),
    (
        "0003_usage_statement_triggers.sql",
        include_str!("../../../workers/s3-bridge/pg/0003_usage_statement_triggers.sql"),
    ),
    (
        "0004_bucket_cors.sql",
        include_str!("../../../workers/s3-bridge/pg/0004_bucket_cors.sql"),
    ),
    (
        "0005_scrub.sql",
        include_str!("../../../workers/s3-bridge/pg/0005_scrub.sql"),
    ),
    (
        "0006_scrub_indexes.sql",
        include_str!("../../../workers/s3-bridge/pg/0006_scrub_indexes.sql"),
    ),
    (
        "0007_tenants.sql",
        include_str!("../../../workers/s3-bridge/pg/0007_tenants.sql"),
    ),
    (
        "0008_tenant_indexes.sql",
        include_str!("../../../workers/s3-bridge/pg/0008_tenant_indexes.sql"),
    ),
];
const SEED: &str = "INSERT INTO usage_global(id) VALUES (1),(2)";

/// The stages through `last` (a `NNNN` version), with the fresh seed.
fn schema_script(last: &str) -> Result<String> {
    if !STAGES.iter().any(|(name, _)| name.starts_with(last)) || last.len() != 4 {
        return Err(BridgeError::Sql(format!(
            "pg testkit: unknown stage {last}"
        )));
    }
    let mut script = String::new();
    for (index, (name, sql)) in STAGES.iter().enumerate() {
        if name[..4] > *last {
            break;
        }
        // The testkit applies every stage in one transaction, where a
        // concurrent index build is not allowed.
        if sql.starts_with("-- velmora: no-transaction\n") {
            script.push_str(&sql.replace("INDEX CONCURRENTLY", "INDEX"));
        } else {
            script.push_str(sql);
        }
        script.push('\n');
        if index == 0 {
            script.push_str(SEED);
            script.push_str(";\n");
        }
    }
    Ok(script)
}

static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

pub const URL_VAR: &str = "VELMORA_TEST_PG_URL";

/// `VELMORA_TEST_PG_WRITE_TX=pipeline` runs the suite on the one-Sync-per-
/// statement transport; unset or `single-sync` on the default transport.
pub const WRITE_TX_VAR: &str = "VELMORA_TEST_PG_WRITE_TX";

/// Run the transport comparison on every catalogue write (see
/// [`TestPostgres::differential`]).
pub const DIFFERENTIAL_VAR: &str = "VELMORA_TEST_PG_DIFFERENTIAL";

fn write_tx() -> WriteTx {
    let value = std::env::var(WRITE_TX_VAR).ok();
    WriteTx::parse(value.as_deref()).unwrap_or_else(|e| panic!("{WRITE_TX_VAR}: {e}"))
}

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

// Unlike DISCARD ALL, this preserves the driver's internal type-lookup
// prepared statements. Catalogue operations do not change authorization.
const RESET_SESSION: &str = "CLOSE ALL; RESET ALL; UNLISTEN *; \
    SELECT pg_advisory_unlock_all(); DISCARD PLANS; DISCARD TEMP; DISCARD SEQUENCES";

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

type Session = (Client, AbortOnDrop<()>);

struct PendingSession {
    runtime: Id,
    reset: AbortOnDrop<Option<Session>>,
}

#[derive(Default)]
struct SessionPool(Mutex<Vec<PendingSession>>);

impl SessionPool {
    fn take_pending(&self, runtime: Id) -> Option<PendingSession> {
        let mut pending = self.0.lock().unwrap();
        // Only the originating runtime can drive the socket and reset task.
        let index = pending
            .iter()
            .rposition(|session| session.runtime == runtime)?;
        Some(pending.swap_remove(index))
    }

    async fn checkout(&self, config: &Config, runtime: Id) -> Result<Session> {
        while let Some(mut pending) = self.take_pending(runtime) {
            // A failed reset is never reused. If checkout is cancelled while
            // waiting, dropping the reset task also retires its driver.
            if let Ok(Some(session)) = (&mut pending.reset.0).await {
                if !session.0.is_closed() {
                    return Ok(session);
                }
            }
        }
        let (client, driver) = connect(config).await?;
        Ok((client, AbortOnDrop(driver)))
    }

    fn checkin(&self, runtime: Id, session: Session) {
        let mut pending = self.0.lock().unwrap();
        if pending.len() < MAX_IDLE_SESSIONS {
            // Start reset now, even if no later operation checks out this
            // session. Do not delay the caller of an already confirmed write.
            let reset = tokio::spawn(async move {
                session.0.batch_execute(RESET_SESSION).await.ok()?;
                Some(session)
            });
            pending.push(PendingSession {
                runtime,
                reset: AbortOnDrop(reset),
            });
        }
    }
}

#[derive(Clone)]
pub struct NativePgConnect {
    config: Config,
    pool: Option<Arc<SessionPool>>,
}

impl PgConnect for NativePgConnect {
    async fn connect(&self) -> Result<PgConnection> {
        let Some(pool) = &self.pool else {
            let (client, driver) = connect(&self.config).await?;
            return Ok(PgConnection::new(client, move || driver.abort()));
        };
        let runtime = Handle::current().id();
        let (client, driver) = pool.checkout(&self.config, runtime).await?;
        let pool = Arc::clone(pool);
        Ok(PgConnection::recyclable(client, move |client| {
            pool.checkin(runtime, (client, driver));
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
        let last = &STAGES[STAGES.len() - 1].0[..4];
        Self::through(last, armed, _record, write_tx())
    }

    /// A schema with the stages through `last` only, to compare a
    /// superseded stage's behaviour with the shipped one.
    pub fn through_stage(last: &str, armed: bool) -> Result<Self> {
        Self::through(last, armed, false, write_tx())
    }

    /// A schema whose catalogue writes use the one-Sync-per-statement
    /// transport, for tests of the pooled session's driver state (type
    /// lookups) that the single-Sync transport never creates.
    pub fn with_typed_writes() -> Result<Self> {
        let last = &STAGES[STAGES.len() - 1].0[..4];
        Self::through(last, true, false, WriteTx::Pipeline)
    }

    fn through(last: &str, armed: bool, _record: bool, catalog_write_tx: WriteTx) -> Result<Self> {
        let script = schema_script(last)?;
        // Read the switch before the schema exists, so an invalid value
        // cannot leave a schema without an owner to drop it.
        let fixture_write_tx = write_tx();
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
        // Arbitrary fixture SQL can leave session state that RESET cannot
        // erase (for example, a custom GUC placeholder). Never pool it.
        let connector = NativePgConnect {
            config: scoped,
            pool: None,
        };
        let sql = |connector: NativePgConnect, write_tx| {
            PgSql::new(
                connector.clone(),
                connector,
                PgConfig {
                    lock_key,
                    write_tx,
                    ..PgConfig::default()
                },
            )
        };
        let catalog = sql(
            NativePgConnect {
                config: connector.config.clone(),
                pool: Some(Arc::default()),
            },
            catalog_write_tx,
        );
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
                 {script}{arm}; COMMIT;"
            )).await.map_err(|error| pg_error("apply baseline", error))
        })?;
        Ok(Self {
            base,
            schema,
            lock_key,
            sql: catalog,
            fixture_sql: sql(connector.clone(), fixture_write_tx),
            connector,
        })
    }

    pub fn lock_key(&self) -> i64 {
        self.lock_key
    }

    /// Run one write transaction on each transport against the current
    /// catalogue state, rolling both back: (pipelined, single Sync). The
    /// second is `None` when the transaction is over the single-Sync size
    /// bound and so ran one Sync per statement too: nothing was compared.
    pub async fn compare_transports(
        &self,
        stmts: &[(&str, Vec<SqlValue>)],
        collect_rows: bool,
    ) -> (ProbeOutcome, Option<ProbeOutcome>) {
        let pipelined = self
            .sql
            .rolled_back(WriteTx::Pipeline, stmts, collect_rows)
            .await;
        let before = crate::pg::oversize_fallbacks();
        let single_sync = self
            .sql
            .rolled_back(WriteTx::SingleSync, stmts, collect_rows)
            .await;
        let compared = crate::pg::oversize_fallbacks() == before;
        (pipelined, compared.then_some(single_sync))
    }

    /// With `VELMORA_TEST_PG_DIFFERENTIAL=1`, every catalogue write of the
    /// suite first runs rolled back on both transports, with its own
    /// values and again with NULL in every position, and the results must
    /// be equal. Statement text, never values, goes into a failure.
    pub(super) async fn differential(&self, stmts: &[(&str, Vec<SqlValue>)], collect_rows: bool) {
        if std::env::var_os(DIFFERENTIAL_VAR).is_none() {
            return;
        }
        let nulls: Vec<(&str, Vec<SqlValue>)> = stmts
            .iter()
            .map(|(sql, args)| (*sql, vec![SqlValue::Null; args.len()]))
            .collect();
        for (variant, stmts) in [("values", stmts), ("nulls", &nulls[..])] {
            let (typed, message) = self.compare_transports(stmts, collect_rows).await;
            // Over the size bound both sides ran one Sync per statement.
            let Some(message) = message else { continue };
            let same = match (&typed, &message) {
                (Ok(a), Ok(b)) => a == b,
                (Err(a), Err(b)) => format!("{a:?}") == format!("{b:?}"),
                _ => false,
            };
            if !same {
                let texts: Vec<&str> = stmts.iter().map(|(sql, _)| *sql).collect();
                let class = |o: &ProbeOutcome| match o {
                    Ok((counts, tags, rows)) => {
                        format!(
                            "Ok(counts {counts:?}, tags {tags:?}, {} row sets)",
                            rows.len()
                        )
                    }
                    Err(e) => format!("Err({e:?})"),
                };
                panic!(
                    "transport difference ({variant}): pipelined {}, single Sync {}: {texts:?}",
                    class(&typed),
                    class(&message)
                );
            }
        }
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
                    write_tx: write_tx(),
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
    fn stages_are_every_shipped_postgres_stage_in_order() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../workers/s3-bridge/pg");
        let mut shipped: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| {
                name.len() > 9
                    && name.as_bytes()[..4].iter().all(u8::is_ascii_digit)
                    && name.as_bytes()[4] == b'_'
                    && name.ends_with(".sql")
            })
            .collect();
        shipped.sort();
        let listed: Vec<&str> = STAGES.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            listed, shipped,
            "testkit_pg::STAGES must list every pg/NNNN_*.sql stage"
        );
        let fresh = schema_script("0003").unwrap();
        let seed = fresh.find(SEED).unwrap();
        assert!(seed > fresh.find(STAGES[0].1).unwrap() && seed < fresh.find(STAGES[1].1).unwrap());
        assert!(fresh.contains(STAGES[2].1));
        assert!(!schema_script("0002").unwrap().contains(STAGES[2].1));
        assert!(schema_script("0009").is_err());
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
