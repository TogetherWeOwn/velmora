//! A test-only client transport that suppresses the real server COMMIT
//! response. TLS traffic is inspected after the client's verified handshake;
//! the origin's credentials and channel binding are unchanged.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::BytesMut;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_postgres::config::{Host, SslMode};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream};
use tokio_postgres::{Config, NoTls};
use velmora_bridge::pg::{PgConnect, PgConnection};
use velmora_bridge::{BridgeError, Result};

#[derive(Clone)]
pub struct DropCommitAck {
    config: Config,
    cleartext: Option<SocketAddr>,
    dropped: Arc<AtomicBool>,
}

impl DropCommitAck {
    pub fn for_schema(schema: &str) -> Self {
        let url = std::env::var("VELMORA_TEST_PG_URL").expect("configured test database required");
        let mut config: Config = url
            .parse()
            .unwrap_or_else(|_| panic!("invalid Postgres test configuration"));
        let cleartext = if config.get_ssl_mode() == SslMode::Disable {
            assert!(
                config.get_hostaddrs().is_empty(),
                "cleartext PG fault transport requires loopback"
            );
            let [Host::Tcp(host)] = config.get_hosts() else {
                panic!("cleartext PG fault transport requires one loopback host")
            };
            let ip: IpAddr = host
                .parse()
                .expect("cleartext PG fault transport requires a loopback IP");
            assert!(
                ip.is_loopback(),
                "cleartext PG fault transport requires loopback"
            );
            Some(SocketAddr::new(
                ip,
                config.get_ports().first().copied().unwrap_or(5432),
            ))
        } else {
            // The TLS stream wrapper must never be silently bypassed.
            config.ssl_mode(SslMode::Require);
            None
        };
        config.options(format!("-c search_path={schema},pg_temp"));
        Self {
            config,
            cleartext,
            dropped: Arc::default(),
        }
    }

    pub fn saw_commit(&self) -> bool {
        self.dropped.load(Ordering::Acquire)
    }
}

impl PgConnect for DropCommitAck {
    async fn connect(&self) -> Result<PgConnection> {
        let handshake = |_| BridgeError::Sql("pg test transport: PostgreSQL handshake".into());
        if let Some(target) = self.cleartext {
            let socket = TcpStream::connect(target)
                .await
                .map_err(|_| BridgeError::Sql("pg test transport: connect".into()))?;
            let (client, connection) = self
                .config
                .connect_raw(FaultStream::new(socket, self.dropped.clone()), NoTls)
                .await
                .map_err(handshake)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(PgConnection::new(client, move || driver.abort()))
        } else {
            let tls = native_tls::TlsConnector::new().map_err(|_| {
                BridgeError::Sql("pg test transport: initialize verified TLS".into())
            })?;
            let (client, connection) = self
                .config
                .connect(FaultMakeTls(tls, self.dropped.clone()))
                .await
                .map_err(handshake)?;
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            Ok(PgConnection::new(client, move || driver.abort()))
        }
    }
}

struct FaultMakeTls(native_tls::TlsConnector, Arc<AtomicBool>);
struct FaultTls(postgres_native_tls::TlsConnector, Arc<AtomicBool>);

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> MakeTlsConnect<S> for FaultMakeTls {
    type Stream = FaultStream<postgres_native_tls::TlsStream<S>>;
    type TlsConnect = FaultTls;
    type Error = native_tls::Error;

    fn make_tls_connect(
        &mut self,
        domain: &str,
    ) -> std::result::Result<Self::TlsConnect, Self::Error> {
        Ok(FaultTls(
            postgres_native_tls::TlsConnector::new(self.0.clone(), domain),
            self.1.clone(),
        ))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> TlsConnect<S> for FaultTls {
    type Stream = FaultStream<postgres_native_tls::TlsStream<S>>;
    type Error = native_tls::Error;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Stream, Self::Error>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            let stream = self.0.connect(stream).await?;
            Ok(FaultStream::new(stream, self.1))
        })
    }
}

struct FaultStream<S> {
    stream: S,
    pending: BytesMut,
    delivering: usize,
    eof: bool,
    dropped: Arc<AtomicBool>,
}

impl<S> FaultStream<S> {
    fn new(stream: S, dropped: Arc<AtomicBool>) -> Self {
        Self {
            stream,
            pending: BytesMut::new(),
            delivering: 0,
            eof: false,
            dropped,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FaultStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.eof || output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.delivering != 0 {
                let count = self.delivering.min(output.remaining());
                output.put_slice(&self.pending.split_to(count));
                self.delivering -= count;
                return Poll::Ready(Ok(()));
            }
            if self.pending.len() >= 5 {
                let length = u32::from_be_bytes(self.pending[1..5].try_into().unwrap()) as usize;
                if !(4..=16 * 1024 * 1024).contains(&length) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid fixture frame length",
                    )));
                }
                let total = length + 1;
                if self.pending.len() >= total {
                    if self.pending[0] == b'C' && &self.pending[5..total] == b"COMMIT\0" {
                        self.dropped.store(true, Ordering::Release);
                        self.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    self.delivering = total;
                    continue;
                }
            }
            let mut scratch = [0; 1024];
            let mut input = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut self.stream).poll_read(cx, &mut input))?;
            if input.filled().is_empty() {
                self.eof = true;
                return if self.pending.is_empty() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "partial PG fixture frame",
                    )))
                };
            }
            self.pending.extend_from_slice(input.filled());
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FaultStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl<S: TlsStream + Unpin> TlsStream for FaultStream<S> {
    fn channel_binding(&self) -> ChannelBinding {
        self.stream.channel_binding()
    }
}
