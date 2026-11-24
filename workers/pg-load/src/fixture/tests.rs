use super::*;
use std::{env, future::Future, path::PathBuf};
use tokio_postgres::{Config, NoTls};
use velmora_bridge::pg::{classify_connect_error, PgConfig, PgConnection};

#[derive(Clone)]
struct Local(Config);

impl PgConnect for Local {
    async fn connect(&self) -> Result<PgConnection> {
        let (client, connection) = self
            .0
            .connect(NoTls)
            .await
            .map_err(classify_connect_error)?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(PgConnection::new(client, move || driver.abort()))
    }
}

fn local_test(test: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

async fn fixture(schema: &str, families: &[Family]) -> (PgConnection, Cat<Local>) {
    let socket =
        PathBuf::from(env::var_os("PG_LOAD_TEST_SOCKET_DIR").expect("disposable PG socket"));
    assert!(socket.is_absolute());
    let mut config = Config::new();
    config
        .host_path(socket)
        .dbname("postgres")
        .user(env::var("USER").expect("local PostgreSQL role"))
        .options(format!("-c search_path={schema},pg_catalog,pg_temp"));
    let local = Local(config);
    let conn = local.connect().await.unwrap();
    let db = conn.client();
    db.batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    db.batch_execute(include_str!("../../../s3-bridge/pg/0001_baseline_pre.sql"))
        .await
        .unwrap();
    db.batch_execute("INSERT INTO usage_global(id) VALUES (1),(2)")
        .await
        .unwrap();
    db.batch_execute(include_str!("../../../s3-bridge/pg/0002_baseline_post.sql"))
        .await
        .unwrap();
    let jobs: Vec<_> = families
        .iter()
        .map(|&family| Job { family, at_ms: 0 })
        .collect();
    seed(db, &jobs).await.unwrap();
    let cat = SqlCatalog::new(PgSql::new(
        local.clone(),
        local,
        PgConfig {
            lock_key: 7_413_000_317,
            ..PgConfig::default()
        },
    ));
    (conn, cat)
}

#[test]
#[ignore = "requires a disposable local PostgreSQL 18 server on PG_LOAD_TEST_SOCKET_DIR"]
fn body_verification_stamps_the_extent() {
    local_test(async {
        let schema = "velmora_pg_load_test_verify";
        let (conn, cat) = fixture(schema, &[Family::OutboxVerifyRecord]).await;
        let result = write(
            &cat,
            &provider(),
            Family::OutboxVerifyRecord,
            0,
            UnixMs(1234),
            || {},
        )
        .await;
        let db = conn.client();
        let stamp: Option<i64> = db.query_one(
            "SELECT e.last_verified_at FROM extents e JOIN outbox o ON o.extent_id = e.id WHERE o.stage = 'verify'",
            &[],
        ).await.unwrap().get(0);
        db.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
        assert!(
            result.is_ok(),
            "the verification write must be acknowledged"
        );
        assert_eq!(stamp, Some(1234));
    });
}

#[test]
#[ignore = "requires a disposable local PostgreSQL 18 server on PG_LOAD_TEST_SOCKET_DIR"]
fn consecutive_dispatches_mark_different_rows() {
    local_test(async {
        let schema = "velmora_pg_load_test_dispatch";
        let (conn, cat) = fixture(schema, &[Family::Dispatch, Family::Dispatch]).await;
        let first = write(&cat, &provider(), Family::Dispatch, 0, UnixMs(1234), || {}).await;
        let second = write(&cat, &provider(), Family::Dispatch, 1, UnixMs(1235), || {}).await;
        let db = conn.client();
        let stamps: Vec<(i64, i64)> = db.query(
            "SELECT sent_at, count(*) FROM outbox WHERE sent_at IS NOT NULL GROUP BY sent_at ORDER BY sent_at",
            &[],
        ).await.unwrap().into_iter().map(|row| (row.get(0), row.get(1))).collect();
        db.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
        assert!(
            first.is_ok() && second.is_ok(),
            "both dispatch writes must be acknowledged"
        );
        assert_eq!(stamps, [(1234, 100), (1235, 100)]);
    });
}
