//! Connection teardown after the transaction outcome is known. A scripted
//! in-memory backend answers the real driver; the client side of the pipe
//! fails or never finishes its close. The in-memory exchange takes
//! milliseconds; a result that waited on such a close would hit the
//! deadline instead.

use std::cell::Cell;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio_postgres::{config::SslMode, Config, NoTls};

use super::{PgConfig, PgConnect, PgConnection, PgSql, WriteTx};
use crate::{BridgeError, Result, Sql, SqlValue};

#[derive(Clone, Copy)]
enum Close {
    /// `poll_shutdown` never resolves, as a socket close that hangs.
    Hang,
    /// `poll_shutdown` fails.
    Fail,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CommitReply {
    /// CommandComplete and ReadyForQuery for COMMIT.
    Confirm,
    /// The backend goes away after COMMIT arrives and before any reply.
    Vanish,
}

struct Teardown {
    io: DuplexStream,
    close: Close,
    closing: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
}

impl Drop for Teardown {
    fn drop(&mut self) {
        // Where the Worker transport requests the socket close.
        self.released.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for Teardown {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Teardown {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closing.store(true, Ordering::SeqCst);
        match self.close {
            Close::Hang => Poll::Pending,
            Close::Fail => Poll::Ready(Err(io::Error::other("injected close failure"))),
        }
    }
}

async fn send(out: &mut DuplexStream, tag: u8, body: &[u8]) -> io::Result<()> {
    out.write_u8(tag).await?;
    out.write_u32(4 + body.len() as u32).await?;
    out.write_all(body).await
}

/// Just enough of a backend for the adapter's statements: trust startup,
/// simple queries, and extended Parse/Bind/Describe/Execute/Sync, one
/// statement per Sync or several (the single-Sync transaction).
async fn backend(mut io: DuplexStream, commit: CommitReply) {
    let _ = serve(&mut io, commit).await;
}

async fn serve(io: &mut DuplexStream, commit: CommitReply) -> io::Result<()> {
    let startup = io.read_u32().await?;
    let mut skip = vec![0; startup as usize - 4];
    io.read_exact(&mut skip).await?;
    send(io, b'R', &0_u32.to_be_bytes()).await?;
    send(io, b'Z', b"I").await?;
    let mut text = Vec::new();
    loop {
        let tag = io.read_u8().await?;
        let len = io.read_u32().await?;
        let mut body = vec![0; len as usize - 4];
        io.read_exact(&mut body).await?;
        match tag {
            b'Q' if body == b"COMMIT\0" => {
                if commit == CommitReply::Vanish {
                    return Ok(());
                }
                send(io, b'C', b"COMMIT\0").await?;
                send(io, b'Z', b"I").await?;
            }
            b'Q' if body == b"ROLLBACK\0" => {
                send(io, b'C', b"ROLLBACK\0").await?;
                send(io, b'Z', b"I").await?;
            }
            b'Q' => {
                send(io, b'C', b"BEGIN\0").await?;
                send(io, b'Z', b"T").await?;
            }
            b'P' => {
                // Unnamed statement: an empty name, then the SQL text.
                text = body[1..].split(|&b| b == 0).next().unwrap_or(&[]).to_vec();
                send(io, b'1', b"").await?;
            }
            b'B' => send(io, b'2', b"").await?,
            b'D' => send(io, b'n', b"").await?,
            b'E' => {
                let tag: &[u8] = match () {
                    _ if text.starts_with(b"COMMIT") => {
                        if commit == CommitReply::Vanish {
                            return Ok(());
                        }
                        b"COMMIT\0"
                    }
                    _ if text.starts_with(b"BEGIN") => b"BEGIN\0",
                    _ if text.starts_with(b"SET") => b"SET\0",
                    _ if text.starts_with(b"SELECT") => b"SELECT 1\0",
                    _ => b"INSERT 0 1\0",
                };
                send(io, b'C', tag).await?;
            }
            // After a single-Sync COMMIT the session is idle again.
            b'S' if text.starts_with(b"COMMIT") => send(io, b'Z', b"I").await?,
            b'S' => send(io, b'Z', b"T").await?,
            b'X' => {
                // Keep the pipe open: the client's close is what is tested.
                std::future::pending::<()>().await;
            }
            _ => return Err(io::Error::other("unexpected frontend message")),
        }
    }
}

struct Fake {
    close: Close,
    commit: CommitReply,
    connects: Cell<u32>,
    closing: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
}

impl Fake {
    fn new(close: Close, commit: CommitReply) -> Self {
        Self {
            close,
            commit,
            connects: Cell::new(0),
            closing: Arc::default(),
            released: Arc::default(),
            stopped: Arc::default(),
        }
    }

    /// The transport is dropped soon after the driver is stopped, without
    /// anyone waiting for its close.
    async fn transport_released(&self) -> bool {
        for _ in 0..100 {
            if self.released.load(Ordering::SeqCst) {
                return true;
            }
            tokio::task::yield_now().await;
        }
        false
    }
}

impl PgConnect for &Fake {
    async fn connect(&self) -> Result<PgConnection> {
        self.connects.set(self.connects.get() + 1);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(backend(server_io, self.commit));
        let socket = Teardown {
            io: client_io,
            close: self.close,
            closing: self.closing.clone(),
            released: self.released.clone(),
        };
        let mut config = Config::new();
        config
            .user("fake")
            .dbname("fake")
            .ssl_mode(SslMode::Disable);
        let (client, connection) = config
            .connect_raw(socket, NoTls)
            .await
            .map_err(super::classify_connect_error)?;
        let driver = tokio::spawn(connection);
        let stopped = self.stopped.clone();
        Ok(PgConnection::new(client, move || {
            stopped.store(true, Ordering::SeqCst);
            driver.abort();
        }))
    }
}

fn pg(fake: &Fake, write_tx: WriteTx) -> PgSql<&Fake> {
    PgSql::new(
        fake,
        fake,
        PgConfig {
            write_tx,
            ..PgConfig::default()
        },
    )
}

const BOTH: [WriteTx; 2] = [WriteTx::SingleSync, WriteTx::Pipeline];

/// Far beyond the in-memory exchange, even on a loaded runner.
const DEADLINE: Duration = Duration::from_secs(5);

async fn insert(fake: &Fake, write_tx: WriteTx) -> Result<Vec<u64>> {
    let stmts = vec![("INSERT INTO t VALUES (?1)", vec![SqlValue::Int(1)])];
    tokio::time::timeout(DEADLINE, pg(fake, write_tx).batch(stmts))
        .await
        .expect("the result must not wait for the connection to close")
}

#[tokio::test]
async fn a_close_that_never_resolves_does_not_delay_a_confirmed_commit() {
    for write_tx in BOTH {
        let fake = Fake::new(Close::Hang, CommitReply::Confirm);
        let result = insert(&fake, write_tx).await;
        assert_eq!(result.unwrap(), [1], "{write_tx:?}");
        // Returned with the driver stopped and before the graceful close
        // (Terminate, then the socket's shutdown) was even started.
        assert!(fake.stopped.load(Ordering::SeqCst));
        assert!(!fake.closing.load(Ordering::SeqCst));
        assert!(fake.transport_released().await);
        assert_eq!(fake.connects.get(), 1, "a committed batch is never retried");
    }
}

#[tokio::test]
async fn a_close_error_after_a_confirmed_commit_is_success() {
    for write_tx in BOTH {
        let fake = Fake::new(Close::Fail, CommitReply::Confirm);
        assert_eq!(insert(&fake, write_tx).await.unwrap(), [1]);
        assert!(fake.transport_released().await);
        assert_eq!(fake.connects.get(), 1);
    }
}

#[tokio::test]
async fn an_error_before_the_commit_is_confirmed_still_propagates() {
    for close in [Close::Hang, Close::Fail] {
        for write_tx in BOTH {
            let fake = Fake::new(close, CommitReply::Vanish);
            let result = insert(&fake, write_tx).await;
            assert!(
                matches!(&result, Err(BridgeError::Sql(s)) if s == "pg: statement failed"),
                "{write_tx:?}"
            );
            assert_eq!(fake.connects.get(), 1);
        }
    }
}

#[tokio::test]
async fn a_read_does_not_wait_for_the_connection_to_close() {
    let fake = Fake::new(Close::Hang, CommitReply::Confirm);
    let rows = tokio::time::timeout(
        DEADLINE,
        pg(&fake, WriteTx::SingleSync).query("SELECT 1", &[]),
    )
    .await
    .expect("the result must not wait for the connection to close");
    assert!(rows.unwrap().is_empty());
    assert!(fake.transport_released().await);
}
