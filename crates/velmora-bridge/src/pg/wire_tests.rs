//! Run with `VELMORA_PG_WP1_PORT=<disposable loopback Postgres port>` and
//! `cargo test -p velmora-bridge --features pg --lib pg::wire_tests -- --ignored`.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_postgres::{config::SslMode, Client, Config, NoTls};

use super::{batch::REJECT_BIND_SQL, PgConfig, PgConnect, PgConnection, PgSql};
use crate::{BridgeError, Result, Sql, SqlValue};

const INSERT: &str = "INSERT INTO wp1_fault_marker VALUES (?1)";

#[derive(Clone, Copy)]
enum Fault {
    ChunkReplies,
    DropCommitReply,
    RejectPrelude,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wire {
    BeginReadWrite,
    Parse,
    Commit,
    Rollback,
    CommitApplied,
    ReadOnly,
}

type Trace = Arc<Mutex<Vec<Wire>>>;

#[derive(Clone)]
struct Connector(Config);

impl PgConnect for Connector {
    async fn connect(&self) -> Result<PgConnection> {
        let (client, connection) = self
            .0
            .connect(NoTls)
            .await
            .map_err(super::classify_connect_error)?;
        let worker = tokio::spawn(connection);
        Ok(PgConnection::new(client, move || worker.abort()))
    }
}

fn config(port: u16, user: &str) -> Config {
    let mut c = Config::new();
    c.host("127.0.0.1")
        .port(port)
        .user(user)
        .dbname("postgres")
        .ssl_mode(SslMode::Disable);
    c
}

async fn frame(input: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let tag = input.read_u8().await?;
    let total = input.read_u32().await?;
    if !(4..=8_000_000).contains(&total) {
        return Err(io::Error::other("unexpected PG frame length"));
    }
    let mut out = vec![0; 1 + total as usize];
    out[0] = tag;
    out[1..5].copy_from_slice(&total.to_be_bytes());
    input.read_exact(&mut out[5..]).await?;
    Ok(out)
}

async fn proxy(listener: TcpListener, port: u16, fault: Fault, trace: Trace) -> io::Result<()> {
    let (downstream, _) = listener.accept().await?;
    let mut upstream = TcpStream::connect(("127.0.0.1", port)).await?;
    let (mut reader, writer) = downstream.into_split();
    let writer = tokio::sync::Mutex::new(writer);
    // Startup is the one untagged frame; the fixture explicitly disables TLS.
    let startup = reader.read_u32().await?;
    if !(8..=4096).contains(&startup) {
        return Err(io::Error::other("unexpected PG startup length"));
    }
    let mut buf = vec![0; startup as usize - 4];
    reader.read_exact(&mut buf).await?;
    upstream.write_u32(startup).await?;
    upstream.write_all(&buf).await?;
    let (mut pg_read, mut pg_write) = upstream.into_split();
    let to_pg = async {
        loop {
            let packet = frame(&mut reader).await?;
            let sql = if packet[0] == b'Q' { &packet[5..] } else { &[] };
            if sql.starts_with(b"BEGIN ") {
                if sql.starts_with(b"BEGIN READ WRITE,") {
                    trace.lock().unwrap().push(Wire::BeginReadWrite);
                }
                if matches!(fault, Fault::RejectPrelude) {
                    // Reject only this Q. Keep forwarding subsequent independent
                    // Parse/Bind/Execute/Sync requests to the real server.
                    let err = b"SERROR\0C53300\0Mfixture proxy refused prelude\0\0";
                    let mut downstream = writer.lock().await;
                    downstream.write_u8(b'E').await?;
                    downstream.write_u32((4 + err.len()) as u32).await?;
                    downstream.write_all(err).await?;
                    downstream.write_all(b"Z\0\0\0\x05I").await?;
                    continue;
                }
            }
            let action = match (packet[0], sql) {
                (b'P', _) => Some(Wire::Parse),
                (b'Q', b"COMMIT\0") => Some(Wire::Commit),
                (b'Q', b"ROLLBACK\0") => Some(Wire::Rollback),
                _ => None,
            };
            if let Some(action) = action {
                trace.lock().unwrap().push(action);
            }
            pg_write.write_all(&packet).await?;
            if packet[0] == b'X' {
                return Ok::<(), io::Error>(());
            }
        }
    };
    let from_pg = async {
        loop {
            let packet = frame(&mut pg_read).await?;
            if packet[0] == b'E' && packet[5..].windows(7).any(|w| w == b"C25006\0") {
                trace.lock().unwrap().push(Wire::ReadOnly);
            }
            if packet[0] == b'C' && &packet[5..] == b"COMMIT\0" {
                trace.lock().unwrap().push(Wire::CommitApplied);
                if matches!(fault, Fault::DropCommitReply) {
                    return Ok::<(), io::Error>(());
                }
            }
            let mut downstream = writer.lock().await;
            if matches!(fault, Fault::ChunkReplies) {
                // Force distinct transport frames for lengths and bodies.
                downstream.write_all(&packet[..3]).await?;
                tokio::task::yield_now().await;
                downstream.write_all(&packet[3..]).await?;
            } else {
                downstream.write_all(&packet).await?;
            }
        }
    };
    tokio::select! { res=to_pg=>res, res=from_pg=>res }
}

async fn fixture(
    port: u16,
) -> (
    Client,
    tokio::task::JoinHandle<core::result::Result<(), tokio_postgres::Error>>,
) {
    let user = std::env::var("USER").expect("local fixture superuser");
    let (client, driver) = config(port, &user)
        .connect(NoTls)
        .await
        .expect("connect disposable local PG");
    let handle = tokio::spawn(driver);
    client.batch_execute("DROP TABLE IF EXISTS wp1_fault_marker; DROP ROLE IF EXISTS wp1_fault_writer;
        CREATE ROLE wp1_fault_writer LOGIN; ALTER ROLE wp1_fault_writer SET default_transaction_read_only=on;
        CREATE TABLE wp1_fault_marker(n bigint PRIMARY KEY); GRANT SELECT, INSERT ON wp1_fault_marker TO wp1_fault_writer;").await.expect("create fixture role and table");
    (client, handle)
}

async fn through_proxy(
    port: u16,
    fault: Fault,
    stmts: Vec<(&'static str, Vec<SqlValue>)>,
) -> (Result<Vec<u64>>, Vec<Wire>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let trace = Trace::default();
    let task = tokio::spawn(proxy(listener, port, fault, trace.clone()));
    let c = Connector(config(proxy_port, "wp1_fault_writer"));
    let pg = PgSql::new(
        c.clone(),
        c,
        PgConfig {
            lock_key: 7_413_000_011,
            ..PgConfig::default()
        },
    );
    let result = tokio::time::timeout(Duration::from_secs(5), pg.batch(stmts))
        .await
        .expect("transaction or rollback timed out");
    // The connection may close before Terminate on this disposable proxy.
    task.abort();
    let wire = trace.lock().unwrap().clone();
    (result, wire)
}

#[tokio::test]
#[ignore = "requires a disposable loopback PostgreSQL 18 instance"]
async fn pg_sql_faults_preserve_transaction_outcomes_on_the_wire() {
    let port = std::env::var("VELMORA_PG_WP1_PORT")
        .expect("set a disposable loopback port")
        .parse()
        .unwrap();
    let (root, driver) = fixture(port).await;
    async fn stored(client: &Client) -> i64 {
        client
            .query_one("SELECT count(*) FROM wp1_fault_marker", &[])
            .await
            .unwrap()
            .get(0)
    }
    let insert = |v| (INSERT, vec![SqlValue::Int(v)]);
    let (res, trace) = through_proxy(
        port,
        Fault::RejectPrelude,
        vec![insert(1), insert(2), ("SELECT 1", vec![])],
    )
    .await;
    assert!(matches!(res,Err(BridgeError::Sql(s)) if s=="pg: statement failed"));
    assert_eq!(stored(&root).await, 0);
    assert_eq!(
        trace.iter().filter(|x| **x == Wire::ReadOnly).count(),
        2,
        "{trace:?}"
    );

    // Negative control: without the role default, dropping the same prelude
    // allows an extended write to autocommit. Classification alone cannot
    // turn this into a known rollback.
    root.batch_execute("ALTER ROLE wp1_fault_writer RESET default_transaction_read_only")
        .await
        .unwrap();
    let (res, trace) = through_proxy(port, Fault::RejectPrelude, vec![insert(9)]).await;
    assert!(matches!(res,Err(BridgeError::Sql(s)) if s=="pg: statement failed"));
    assert!(!trace.contains(&Wire::ReadOnly));
    assert_eq!(stored(&root).await, 1);
    root.batch_execute("TRUNCATE wp1_fault_marker; ALTER ROLE wp1_fault_writer SET default_transaction_read_only=on").await.unwrap();

    let (res, trace) = through_proxy(
        port,
        Fault::ChunkReplies,
        vec![
            insert(3),
            (REJECT_BIND_SQL, vec![SqlValue::Int(1)]),
            insert(4),
        ],
    )
    .await;
    assert!(matches!(res,Err(BridgeError::Sql(s)) if s=="pg: statement failed"));
    assert_eq!(trace, [Wire::BeginReadWrite, Wire::Parse, Wire::Rollback]);
    assert_eq!(stored(&root).await, 0);

    let (res, trace) = through_proxy(port, Fault::DropCommitReply, vec![insert(5)]).await;
    assert!(matches!(res,Err(BridgeError::Sql(s)) if s=="pg: statement failed"));
    assert_eq!(
        trace,
        [
            Wire::BeginReadWrite,
            Wire::Parse,
            Wire::Commit,
            Wire::CommitApplied
        ]
    );
    assert_eq!(stored(&root).await, 1);

    let (res, _) = through_proxy(port, Fault::ChunkReplies, vec![insert(6)]).await;
    assert_eq!(res.unwrap(), [1]);
    assert_eq!(stored(&root).await, 2);
    for pipelined in [false, true] {
        let c = Connector(config(port, "wp1_fault_writer"));
        let pg = PgSql::new(
            c.clone(),
            c,
            PgConfig {
                lock_key: 7_413_000_011,
                pipeline: pipelined,
            },
        );
        assert_eq!(
            pg.exec(INSERT, &[SqlValue::Int(if pipelined { 7 } else { 8 })])
                .await
                .unwrap(),
            1
        );
    }
    assert_eq!(stored(&root).await, 4);
    root.batch_execute("DROP TABLE wp1_fault_marker; DROP ROLE wp1_fault_writer;")
        .await
        .unwrap();
    driver.abort();
}
