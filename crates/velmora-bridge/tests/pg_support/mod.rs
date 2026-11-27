//! A disposable schema on `VELMORA_TEST_PG_URL` and an in-process proxy
//! that frames PostgreSQL frontend and backend messages, for the write
//! transport tests. Nothing here prints a URL, SQL text with values, or a
//! server message.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio_postgres::config::Host;
use tokio_postgres::{Client, Config, NoTls};
use velmora_bridge::pg::{
    classify_connect_error, PgConfig, PgConnect, PgConnection, PgSql, WriteTx,
};
use velmora_bridge::Result;

pub const URL_VAR: &str = "VELMORA_TEST_PG_URL";

static NEXT: AtomicU64 = AtomicU64::new(0);

pub fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{:x}_{nanos:x}_{n:x}", std::process::id())
}

/// The test server, which must be a cleartext loopback server: these tests
/// and their proxy speak PostgreSQL without TLS.
pub fn base_config() -> Option<Config> {
    let url = std::env::var(URL_VAR).ok()?;
    let config: Config = url.parse().expect("a valid PostgreSQL test configuration");
    let loopback = matches!(config.get_hosts(),
        [Host::Tcp(host)] if host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()));
    assert!(
        loopback
            && config.get_hostaddrs().is_empty()
            && config.get_ssl_mode() == tokio_postgres::config::SslMode::Disable,
        "the write transport tests need a numeric loopback host with sslmode=disable"
    );
    Some(config)
}

pub async fn connect(config: &Config) -> Client {
    let (client, connection) = config
        .connect(NoTls)
        .await
        .expect("connect to the test PostgreSQL");
    tokio::spawn(connection);
    client
}

/// A schema of its own with the setup SQL applied, dropped on drop.
pub struct Schema {
    pub base: Config,
    pub name: String,
    pub admin: Client,
    pub lock_key: i64,
}

impl Schema {
    pub async fn new(setup: &str) -> Option<Self> {
        let base = base_config()?;
        let name = unique("velmora_a1");
        let admin = connect(&base).await;
        admin
            .batch_execute(&format!(
                "CREATE SCHEMA {name}; SET search_path = {name}; {setup}"
            ))
            .await
            .expect("create the test schema");
        let lock_key = 7_413_100_000
            + (NEXT.fetch_add(1, Ordering::Relaxed) as i64) * 7
            + i64::from(std::process::id() % 1000) * 1_000;
        Some(Self {
            base,
            name,
            admin,
            lock_key,
        })
    }

    /// Connection settings scoped to this schema.
    pub fn config(&self) -> Config {
        let mut c = self.base.clone();
        c.options(format!("-c search_path={},pg_temp", self.name));
        c
    }

    pub fn pg<C: PgConnect + Clone>(&self, connect: C, write_tx: WriteTx) -> PgSql<C> {
        PgSql::new(
            connect.clone(),
            connect,
            PgConfig {
                lock_key: self.lock_key,
                write_tx,
                ..PgConfig::default()
            },
        )
    }

    pub async fn count(&self, table: &str) -> i64 {
        self.admin
            .query_one(&format!("SELECT count(*) FROM {}.{table}", self.name), &[])
            .await
            .unwrap()
            .get(0)
    }
}

impl Drop for Schema {
    fn drop(&mut self) {
        let base = self.base.clone();
        let name = self.name.clone();
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let admin = connect(&base).await;
                let _ = admin
                    .batch_execute(&format!(
                        "SET lock_timeout = '3s'; DROP SCHEMA {name} CASCADE"
                    ))
                    .await;
            });
        })
        .join();
    }
}

/// Connects straight to the server.
#[derive(Clone)]
pub struct Direct(pub Config);

impl PgConnect for Direct {
    async fn connect(&self) -> Result<PgConnection> {
        let (client, connection) = self
            .0
            .connect(NoTls)
            .await
            .map_err(classify_connect_error)?;
        let driver = tokio::spawn(connection);
        Ok(PgConnection::new(client, move || driver.abort()))
    }
}

/// How the proxy forwards requests (a request is one Query, or the
/// extended messages through Sync).
#[derive(Clone, Copy, Debug)]
pub enum Delay {
    None,
    /// Every frame is delayed by `d` in each direction; requests still
    /// flow in one flight.
    Faithful(Duration),
    /// The next request is forwarded only after the previous request's
    /// ReadyForQuery was relayed, plus `d`. This is what Hyperdrive did in
    /// the E0 probe.
    PerRequest(Duration),
}

/// A fault applied to the first single-Sync write transaction (a request
/// that starts with `BEGIN READ WRITE` and ends with COMMIT and one Sync).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    None,
    /// Reply 58000 without forwarding the request.
    Refuse58000,
    /// Forward it, swallow every reply, then send 08006 and close: the
    /// server committed and the client saw no reply.
    LostAfterForward,
    /// Forward it and close the client connection at once.
    CutAfterForward,
    /// Drop the first CommandComplete of the reply.
    DropOneComplete,
    /// Replace COMMIT's CommandComplete with an error 57014.
    RejectCommit,
    /// Replace the first DataRow with one that has no fields, which no row
    /// description of the tests matches.
    BadDataRow,
    /// Relay every reply, but with ReadyForQuery status T (in a
    /// transaction) instead of the server's.
    StatusInTransaction,
    /// Put a NoticeResponse, a ParameterStatus and a NotificationResponse
    /// before every reply message, and after the last one.
    InjectAsync,
    /// Answer the Describe of the statement after BEGIN with an error, then
    /// discard the server's replies up to its ReadyForQuery (status E).
    DescribeError,
}

#[derive(Default)]
pub struct Trace {
    /// Frontend message tags, in order, after startup.
    pub frontend: Vec<u8>,
    /// Query strings that were exactly ROLLBACK.
    pub rollbacks: usize,
    /// ROLLBACK replies (CommandComplete) relayed back.
    pub rollbacks_done: usize,
    /// Requests that were single-Sync write transactions.
    pub single_syncs: usize,
    /// Sync messages.
    pub syncs: usize,
    /// Query (simple protocol) messages.
    pub queries: usize,
    /// Parse messages with a statement name.
    pub named_parses: usize,
    /// Bytes of the last single-Sync write transaction request.
    pub last_request_bytes: usize,
}

pub struct Proxy {
    pub port: u16,
    pub trace: Arc<Mutex<Trace>>,
    /// Set to hold every ROLLBACK at the proxy until `release` is notified.
    pub hold_rollback: Arc<Mutex<bool>>,
    pub held: Arc<Notify>,
    pub release: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Proxy {
    pub async fn start(upstream: &Config, delay: Delay, fault: Fault) -> Self {
        let (host, port) = match (upstream.get_hosts(), upstream.get_ports()) {
            ([Host::Tcp(host)], [port]) => (host.clone(), *port),
            ([Host::Tcp(host)], []) => (host.clone(), 5432),
            _ => panic!("the proxy needs one TCP host"),
        };
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let local = listener.local_addr().unwrap().port();
        let trace = Arc::new(Mutex::new(Trace::default()));
        let hold_rollback = Arc::new(Mutex::new(false));
        let held = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let faulted = Arc::new(Mutex::new(fault == Fault::None));
        let ctx = Ctx {
            host,
            port,
            delay,
            fault,
            faulted,
            trace: trace.clone(),
            hold_rollback: hold_rollback.clone(),
            held: held.clone(),
            release: release.clone(),
        };
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let _ = ctx.serve(socket).await;
                });
            }
        });
        Self {
            port: local,
            trace,
            hold_rollback,
            held,
            release,
            task,
        }
    }

    /// `config` with its host and port replaced by this proxy.
    pub fn config(&self, config: &Config) -> Config {
        let mut c = Config::new();
        c.host("127.0.0.1").port(self.port);
        if let Some(user) = config.get_user() {
            c.user(user);
        }
        if let Some(db) = config.get_dbname() {
            c.dbname(db);
        }
        if let Some(password) = config.get_password() {
            c.password(password);
        }
        if let Some(options) = config.get_options() {
            c.options(options);
        }
        c.ssl_mode(tokio_postgres::config::SslMode::Disable);
        c
    }
}

#[derive(Clone)]
struct Ctx {
    host: String,
    port: u16,
    delay: Delay,
    fault: Fault,
    faulted: Arc<Mutex<bool>>,
    trace: Arc<Mutex<Trace>>,
    hold_rollback: Arc<Mutex<bool>>,
    held: Arc<Notify>,
    release: Arc<Notify>,
}

async fn frame(input: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let tag = input.read_u8().await?;
    let total = input.read_u32().await?;
    if !(4..=64 * 1024 * 1024).contains(&total) {
        return Err(io::Error::other("unexpected PG frame length"));
    }
    let mut out = vec![0; 1 + total as usize];
    out[0] = tag;
    out[1..5].copy_from_slice(&total.to_be_bytes());
    input.read_exact(&mut out[5..]).await?;
    Ok(out)
}

fn frame_of(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(((4 + body.len()) as u32).to_be_bytes());
    out.extend(body);
    out
}

/// A NoticeResponse, a ParameterStatus and a NotificationResponse.
fn async_frames() -> Vec<u8> {
    let mut out = frame_of(b'N', b"SNOTICE\0C00000\0Mtest proxy notice\0\0");
    out.extend(frame_of(b'S', b"application_name\0proxy\0"));
    let mut notify = 4242_i32.to_be_bytes().to_vec();
    notify.extend(b"proxy_channel\0payload\0");
    out.extend(frame_of(b'A', &notify));
    out
}

fn error_frame(code: &str) -> Vec<u8> {
    let fields = format!("SERROR\0C{code}\0Mtest proxy fault\0\0");
    let mut out = vec![b'E'];
    out.extend(((4 + fields.len()) as u32).to_be_bytes());
    out.extend(fields.as_bytes());
    out
}

const READY_IDLE: &[u8] = b"Z\0\0\0\x05I";

/// The query text of an unnamed Parse frame.
fn parse_text(packet: &[u8]) -> Option<&[u8]> {
    (packet[0] == b'P' && packet[5] == 0).then(|| {
        let text = &packet[6..];
        &text[..text.iter().position(|&b| b == 0).unwrap_or(text.len())]
    })
}

/// A write transaction sent as one request: it begins with BEGIN READ
/// WRITE and ends with COMMIT before its only Sync.
fn is_single_sync_tx(request: &[Vec<u8>]) -> bool {
    let texts: Vec<&[u8]> = request.iter().filter_map(|p| parse_text(p)).collect();
    request.last().is_some_and(|p| p[0] == b'S')
        && texts
            .first()
            .is_some_and(|t| t.starts_with(b"BEGIN READ WRITE"))
        && texts.last() == Some(&&b"COMMIT"[..])
}

/// Writes frames in order, each no earlier than its due time.
async fn delayed_writer(
    mut out: impl AsyncWrite + Unpin,
    mut rx: mpsc::UnboundedReceiver<(Instant, Vec<u8>)>,
) -> io::Result<()> {
    while let Some((due, bytes)) = rx.recv().await {
        tokio::time::sleep_until(due.into()).await;
        out.write_all(&bytes).await?;
    }
    Ok(())
}

impl Ctx {
    fn take_fault(&self) -> Fault {
        let mut done = self.faulted.lock().unwrap();
        if *done {
            Fault::None
        } else {
            *done = true;
            self.fault
        }
    }

    async fn serve(self, downstream: TcpStream) -> io::Result<()> {
        downstream.set_nodelay(true)?;
        let upstream = TcpStream::connect((self.host.as_str(), self.port)).await?;
        upstream.set_nodelay(true)?;
        let (mut client_read, client_write) = downstream.into_split();
        let (mut server_read, server_write) = upstream.into_split();
        // Startup is the one untagged frame; the tests disable TLS.
        let len = client_read.read_u32().await?;
        let mut startup = vec![0; len as usize - 4];
        client_read.read_exact(&mut startup).await?;
        let mut first = len.to_be_bytes().to_vec();
        first.extend(&startup);
        let lag = match self.delay {
            Delay::Faithful(d) => d,
            _ => Duration::ZERO,
        };
        let (to_server, server_rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
        let (to_client, client_rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
        let mut writers = tokio::spawn(async move {
            let _ = tokio::join!(
                delayed_writer(server_write, server_rx),
                delayed_writer(client_write, client_rx)
            );
        });
        let send_server = |bytes: Vec<u8>| {
            to_server
                .send((Instant::now() + lag, bytes))
                .map_err(|_| io::Error::other("closed"))
        };
        let send_client = |bytes: Vec<u8>| {
            to_client
                .send((Instant::now() + lag, bytes))
                .map_err(|_| io::Error::other("closed"))
        };
        send_server(first)?;
        // One permit: the next request may go (PerRequest only).
        let turn = Arc::new(Semaphore::new(0));
        let per_request = match self.delay {
            Delay::PerRequest(d) => Some(d),
            _ => None,
        };
        // Faults on the reply side, armed by the frontend side.
        let reply_fault = Arc::new(Mutex::new(VecDeque::<Fault>::new()));
        let close = Arc::new(Notify::new());
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let front = async {
            // A request is one Query, or the extended messages through Sync;
            // the proxy decides on and forwards whole requests.
            let mut request: Vec<Vec<u8>> = Vec::new();
            loop {
                let packet = frame(&mut client_read).await?;
                let tag = packet[0];
                {
                    let mut trace = self.trace.lock().unwrap();
                    trace.frontend.push(tag);
                    match tag {
                        b'S' => trace.syncs += 1,
                        b'Q' => trace.queries += 1,
                        // An unnamed Parse starts with an empty name.
                        b'P' if packet[5] != 0 => trace.named_parses += 1,
                        _ => {}
                    }
                }
                if tag == b'X' {
                    send_server(packet)?;
                    return Ok::<(), io::Error>(());
                }
                if !started.load(Ordering::SeqCst) {
                    // Authentication replies (SASL, password) go at once:
                    // the server waits for them before its ReadyForQuery.
                    send_server(packet)?;
                    continue;
                }
                request.push(packet);
                if !(tag == b'Q' || tag == b'S') {
                    continue;
                }
                let request = std::mem::take(&mut request);
                if per_request.is_some() {
                    turn.acquire().await.unwrap().forget();
                }
                if request.len() == 1 && &request[0][5..] == b"ROLLBACK\0" {
                    self.trace.lock().unwrap().rollbacks += 1;
                    if *self.hold_rollback.lock().unwrap() {
                        self.held.notify_one();
                        self.release.notified().await;
                    }
                }
                if is_single_sync_tx(&request) {
                    {
                        let mut trace = self.trace.lock().unwrap();
                        trace.single_syncs += 1;
                        trace.last_request_bytes = request.iter().map(Vec::len).sum();
                    }
                    match self.take_fault() {
                        Fault::None => {}
                        Fault::Refuse58000 => {
                            let mut reply = error_frame("58000");
                            reply.extend(READY_IDLE);
                            send_client(reply)?;
                            if per_request.is_some() {
                                turn.add_permits(1);
                            }
                            continue;
                        }
                        Fault::CutAfterForward => {
                            send_server(request.concat())?;
                            close.notify_one();
                            return Ok(());
                        }
                        fault => reply_fault.lock().unwrap().push_back(fault),
                    }
                }
                send_server(request.concat())?;
            }
        };
        let back = async {
            let mut active = Fault::None;
            let mut dropped = false;
            let mut completes = 0;
            loop {
                let packet = frame(&mut server_read).await?;
                let tag = packet[0];
                if tag == b'C' && &packet[5..] == b"ROLLBACK\0" {
                    self.trace.lock().unwrap().rollbacks_done += 1;
                }
                if active == Fault::None && tag != b'Z' {
                    if let Some(f) = reply_fault.lock().unwrap().pop_front() {
                        active = f;
                        dropped = false;
                        completes = 0;
                    }
                }
                // What goes to the client for this server message. Every
                // ReadyForQuery relayed, real or not, ends a request.
                let out: Option<Vec<u8>> = match active {
                    Fault::StatusInTransaction if tag == b'Z' => Some(b"Z\0\0\0\x05T".to_vec()),
                    Fault::BadDataRow if tag == b'D' && !dropped => {
                        dropped = true;
                        Some(frame_of(b'D', &0_i16.to_be_bytes()))
                    }
                    Fault::InjectAsync => {
                        let mut out = async_frames();
                        out.extend(&packet);
                        if tag == b'Z' {
                            out.extend(async_frames());
                        }
                        Some(out)
                    }
                    Fault::DescribeError => {
                        // Fail the Describe of the statement after BEGIN
                        // (the first ParameterDescription after a
                        // CommandComplete), then end the request as the
                        // server would after an error: ReadyForQuery E.
                        if tag == b'C' && !dropped {
                            completes += 1;
                        }
                        if tag == b't' && !dropped && completes >= 1 {
                            dropped = true;
                            Some(error_frame("42P18"))
                        } else if dropped {
                            (tag == b'Z').then(|| b"Z\0\0\0\x05E".to_vec())
                        } else {
                            Some(packet.clone())
                        }
                    }
                    Fault::LostAfterForward => {
                        if tag == b'Z' {
                            send_client(error_frame("08006"))?;
                            close.notify_one();
                            return Ok(());
                        }
                        None
                    }
                    Fault::DropOneComplete if tag == b'C' && !dropped => {
                        dropped = true;
                        None
                    }
                    Fault::RejectCommit if tag == b'C' && &packet[5..] == b"COMMIT\0" => {
                        Some(error_frame("57014"))
                    }
                    _ => Some(packet.clone()),
                };
                if tag == b'Z' {
                    active = Fault::None;
                }
                let Some(out) = out else { continue };
                send_client(out)?;
                if tag == b'Z' {
                    // Startup is over at the first ReadyForQuery.
                    started.store(true, Ordering::SeqCst);
                    if let Some(d) = per_request {
                        let turn = turn.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(d + lag).await;
                            turn.add_permits(1);
                        });
                    }
                }
            }
        };
        let result = tokio::select! {
            r = front => r,
            r = back => r,
            _ = close.notified() => Ok(()),
        };
        // Let queued frames go out before the sockets close.
        drop(to_server);
        drop(to_client);
        if tokio::time::timeout(Duration::from_secs(5), &mut writers)
            .await
            .is_err()
        {
            writers.abort();
        }
        result
    }
}
