//! Connection teardown after the transaction outcome is known. A scripted
//! in-memory backend answers the real driver; the client side of the pipe
//! fails or never finishes its close.

use std::cell::Cell;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio_postgres::{config::SslMode, Config, NoTls};

use super::{PgConfig, PgConnect, PgConnection, PgSql, SHUTDOWN_LIMIT_MS};
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
/// simple queries, and extended Parse/Bind/Describe/Execute/Sync.
async fn backend(mut io: DuplexStream, commit: CommitReply, terminated: Arc<AtomicBool>) {
    let _ = serve(&mut io, commit, &terminated).await;
}

async fn serve(
    io: &mut DuplexStream,
    commit: CommitReply,
    terminated: &AtomicBool,
) -> io::Result<()> {
    let startup = io.read_u32().await?;
    let mut skip = vec![0; startup as usize - 4];
    io.read_exact(&mut skip).await?;
    send(io, b'R', &0_u32.to_be_bytes()).await?;
    send(io, b'Z', b"I").await?;
    let mut select = false;
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
                select = body.get(1..7) == Some(b"SELECT");
                send(io, b'1', b"").await?;
            }
            b'B' => send(io, b'2', b"").await?,
            b'D' => send(io, b'n', b"").await?,
            b'E' if select => send(io, b'C', b"SELECT 0\0").await?,
            b'E' => send(io, b'C', b"INSERT 0 1\0").await?,
            b'S' => send(io, b'Z', b"T").await?,
            b'X' => {
                terminated.store(true, Ordering::SeqCst);
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
    terminated: Arc<AtomicBool>,
}

impl Fake {
    fn new(close: Close, commit: CommitReply) -> Self {
        Self {
            close,
            commit,
            connects: Cell::new(0),
            closing: Arc::default(),
            terminated: Arc::default(),
        }
    }
}

impl PgConnect for &Fake {
    async fn connect(&self) -> Result<PgConnection> {
        self.connects.set(self.connects.get() + 1);
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(backend(server_io, self.commit, self.terminated.clone()));
        let socket = Teardown {
            io: client_io,
            close: self.close,
            closing: self.closing.clone(),
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
        let (closed, done) = tokio::sync::oneshot::channel();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
            let _ = closed.send(());
        });
        Ok(
            PgConnection::new(client, move || driver.abort()).with_shutdown(
                async move {
                    let _ = done.await;
                },
                || tokio::time::sleep(Duration::from_millis(u64::from(SHUTDOWN_LIMIT_MS))),
            ),
        )
    }
}

fn pg(fake: &Fake, pipeline: bool) -> PgSql<&Fake> {
    PgSql::new(
        fake,
        fake,
        PgConfig {
            pipeline,
            ..PgConfig::default()
        },
    )
}

/// Generous for a loaded runner, far below an unbounded wait.
fn bound() -> Duration {
    Duration::from_millis(u64::from(SHUTDOWN_LIMIT_MS)) + Duration::from_secs(5)
}

async fn insert(fake: &Fake, pipeline: bool) -> (Result<Vec<u64>>, Duration) {
    let start = Instant::now();
    let stmts = vec![("INSERT INTO t VALUES (?1)", vec![SqlValue::Int(1)])];
    let result = tokio::time::timeout(bound(), pg(fake, pipeline).batch(stmts))
        .await
        .expect("teardown after the COMMIT reply must be bounded");
    (result, start.elapsed())
}

#[tokio::test]
async fn a_close_that_never_resolves_after_a_confirmed_commit_is_bounded_success() {
    for pipeline in [true, false] {
        let fake = Fake::new(Close::Hang, CommitReply::Confirm);
        let (result, took) = insert(&fake, pipeline).await;
        assert_eq!(result.unwrap(), [1], "pipeline={pipeline}");
        // The hang was really reached: Terminate went out, then the close.
        assert!(fake.terminated.load(Ordering::SeqCst));
        assert!(fake.closing.load(Ordering::SeqCst));
        assert!(took >= Duration::from_millis(u64::from(SHUTDOWN_LIMIT_MS)));
        assert!(took < bound());
        assert_eq!(fake.connects.get(), 1, "a committed batch is never retried");
    }
}

#[tokio::test]
async fn a_close_error_after_a_confirmed_commit_is_success() {
    for pipeline in [true, false] {
        let fake = Fake::new(Close::Fail, CommitReply::Confirm);
        let (result, took) = insert(&fake, pipeline).await;
        assert_eq!(result.unwrap(), [1], "pipeline={pipeline}");
        assert!(fake.closing.load(Ordering::SeqCst));
        // A failed close ends the driver at once; no wait for the limit.
        assert!(took < Duration::from_millis(u64::from(SHUTDOWN_LIMIT_MS)));
        assert_eq!(fake.connects.get(), 1);
    }
}

#[tokio::test]
async fn an_error_before_the_commit_is_confirmed_still_propagates() {
    for close in [Close::Hang, Close::Fail] {
        for pipeline in [true, false] {
            let fake = Fake::new(close, CommitReply::Vanish);
            let (result, _) = insert(&fake, pipeline).await;
            assert!(
                matches!(&result, Err(BridgeError::Sql(s)) if s == "pg: statement failed"),
                "pipeline={pipeline}"
            );
            assert_eq!(fake.connects.get(), 1);
        }
    }
}

#[tokio::test]
async fn a_read_is_not_held_by_a_close_that_never_resolves() {
    let fake = Fake::new(Close::Hang, CommitReply::Confirm);
    let rows = tokio::time::timeout(bound(), pg(&fake, true).query("SELECT 1", &[]))
        .await
        .expect("teardown after a read must be bounded");
    assert!(rows.unwrap().is_empty());
    assert!(fake.closing.load(Ordering::SeqCst));
}
