//! Synthetic NNTP server (RFC 3977 subset) for CI.
//!
//! Supported commands: `CAPABILITIES`, `MODE READER`, `AUTHINFO USER/PASS`,
//! `GROUP`, `LIST`, `XOVER`, `ARTICLE`/`BODY`/`HEAD`/`STAT`, `QUIT`.
//! Anything else is `500`. Responses are CRLF terminated and dot-stuffed.
//!
//! Fault injection (all configurable per [`ServerConfig`]):
//! - per-credential connection caps (`502` + close when exceeded),
//! - `430` for unknown or explicitly-missing message-IDs,
//! - `481` on bad credentials,
//! - throttled ("slow link") article bodies,
//! - mid-body disconnects (partial write, then TCP reset by close).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex};

use crate::fixtures::Article;

/// Credentials + connection cap for one login.
#[derive(Clone, Debug)]
pub struct UserConfig {
    pub password: String,
    pub max_connections: usize,
}

/// Full server configuration. Built by hand or via [`ServerConfig::for_test`].
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub users: HashMap<String, UserConfig>,
    pub articles: Vec<Article>,
    pub group: String,
    pub require_auth: bool,
    /// Explicitly-missing IDs: always `430`, even if present in `articles`.
    pub missing_ids: HashSet<String>,
    /// Throttle article bodies to this many bytes/sec (None = unthrottled).
    pub slow_bytes_per_sec: Option<u64>,
    /// Extra latency before each article response.
    pub latency_ms: u64,
    /// Per-message-ID mid-body disconnect: write only N bytes then close.
    pub drop_after_bytes: HashMap<String, usize>,
}

impl ServerConfig {
    /// Default config used by integration tests: two users, full corpus.
    pub fn for_test() -> Self {
        let articles = crate::fixtures::default_corpus();
        let mut users = HashMap::new();
        users.insert(
            "testuser".to_string(),
            UserConfig {
                password: "testpass".to_string(),
                max_connections: 2,
            },
        );
        users.insert(
            "otheruser".to_string(),
            UserConfig {
                password: "otherpass".to_string(),
                max_connections: 8,
            },
        );
        Self {
            users,
            articles,
            group: "alt.binaries.nntune.test".to_string(),
            require_auth: true,
            missing_ids: crate::fixtures::always_missing_ids().into_iter().collect(),
            slow_bytes_per_sec: None,
            latency_ms: 0,
            drop_after_bytes: HashMap::new(),
        }
    }

    fn find_by_id(&self, id: &str) -> Option<&Article> {
        let normalized = if id.starts_with('<') {
            id.to_string()
        } else {
            format!("<{id}>")
        };
        self.articles.iter().find(|a| a.message_id == normalized)
    }

    fn find_by_number(&self, n: u32) -> Option<&Article> {
        self.articles.iter().find(|a| a.number == n)
    }
}

struct Shared {
    config: ServerConfig,
    /// Active authenticated connections per user.
    active: Mutex<HashMap<String, usize>>,
}

/// A running test server. Binds an ephemeral loopback port; `shutdown` on drop.
pub struct TestNntpServer {
    addr: SocketAddr,
    // Held so the accept loop stays alive; aborted on drop.
    _task: tokio::task::JoinHandle<()>,
    // Signalled on drop so already-open sessions close too, not just the
    // accept loop (aborting the accept task alone detaches session tasks).
    shutdown: watch::Sender<bool>,
}

impl TestNntpServer {
    /// Spawn with the default test config.
    pub async fn spawn_for_test() -> Self {
        Self::spawn(ServerConfig::for_test()).await
    }

    /// Spawn with an explicit config.
    pub async fn spawn(config: ServerConfig) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test nntp");
        let addr = listener.local_addr().expect("local addr");
        let (shutdown, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(serve_with_shutdown(listener, config, shutdown_rx));
        Self {
            addr,
            _task: task,
            shutdown,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for TestNntpServer {
    fn drop(&mut self) {
        // Signal every open session to close, then abort the accept loop
        // (which owns the listener) so the port refuses new connections.
        // Dropping a JoinHandle alone detaches; abort is required.
        let _ = self.shutdown.send(true);
        self._task.abort();
    }
}

/// Serve forever on an already-bound listener (used by the standalone binary).
pub async fn serve(listener: TcpListener, config: ServerConfig) {
    // The standalone binary serves until killed, so its shutdown signal is
    // never sent; dropping the receiver also closes sessions (see below).
    let (_shutdown, shutdown_rx) = watch::channel(false);
    serve_with_shutdown(listener, config, shutdown_rx).await;
}

async fn serve_with_shutdown(
    listener: TcpListener,
    config: ServerConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    let shared = Arc::new(Shared {
        config,
        active: Mutex::new(HashMap::new()),
    });
    loop {
        let (stream, _) = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(_) => break,
            },
        };
        let shared = Arc::clone(&shared);
        let session_shutdown = shutdown.clone();
        tokio::spawn(async move {
            handle_connection(stream, shared, session_shutdown).await;
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader);
    let mut authed: Option<String> = None;
    let mut pending_user: Option<String> = None;
    // Guard released on disconnect so caps are per *concurrent* connection.
    let mut held_user: Option<String> = None;

    let _ = writer
        .write_all(b"200 fake-nntp.test NNTune synthetic server ready\r\n")
        .await;

    let mut buf = String::new();
    // Group selected by a successful GROUP (RFC 3977 s5.1): XOVER with a
    // range requires one, otherwise the server answers 412.
    let mut selected: Option<String> = None;
    loop {
        buf.clear();
        // Select on the shutdown signal so dropping the server closes this
        // session instead of leaving it served by a detached task.
        let read = tokio::select! {
            _ = shutdown.changed() => break,
            read = lines.read_line(&mut buf) => read,
        };
        let n = match read {
            Ok(0) => break, // client closed
            Ok(n) => n,
            Err(_) => break,
        };
        let _ = n;
        let line = buf.trim_end_matches(['\r', '\n']).to_string();
        if line.is_empty() {
            continue;
        }
        let (cmd, arg) = split_cmd(&line);

        match cmd.as_str() {
            "CAPABILITIES" => {
                let _ = writer
                    .write_all(b"101 Capability list follows\r\nVERSION 2\r\nREADER\r\nAUTHINFO USER\r\n.\r\n")
                    .await;
            }
            "MODE" => {
                let _ = writer.write_all(b"200 Reader mode\r\n").await;
            }
            "AUTHINFO" => {
                // RFC 4643: AUTHINFO after successful authentication gets 502,
                // and must not consume another connection-cap slot.
                if authed.is_some() {
                    let _ = writer.write_all(b"502 Command unavailable\r\n").await;
                    continue;
                }
                let upper = arg.to_ascii_uppercase();
                if upper.starts_with("USER ") {
                    let user = arg[5..].trim().to_string();
                    pending_user = Some(user);
                    let _ = writer.write_all(b"381 Password required\r\n").await;
                } else if upper.starts_with("PASS ") {
                    let pass = arg[5..].trim();
                    // RFC 4643 s2.3.2: PASS with no preceding USER is out
                    // of sequence (482), not a credential failure (481).
                    let Some(user) = pending_user.clone() else {
                        let _ = writer
                            .write_all(b"482 Authentication commands issued out of sequence\r\n")
                            .await;
                        continue;
                    };
                    let ok = shared
                        .config
                        .users
                        .get(&user)
                        .map(|u| u.password == pass)
                        .unwrap_or(false);
                    if !ok {
                        pending_user = None;
                        let _ = writer.write_all(b"481 Authentication failed\r\n").await;
                        continue;
                    }
                    // Enforce per-credential cap.
                    let max = shared
                        .config
                        .users
                        .get(&user)
                        .map(|u| u.max_connections)
                        .unwrap_or(0);
                    let mut active = shared.active.lock().await;
                    let count = active.get(&user).copied().unwrap_or(0);
                    if count >= max {
                        drop(active);
                        let _ = writer
                            .write_all(b"502 Too many connections for user\r\n")
                            .await;
                        break;
                    }
                    active.insert(user.clone(), count + 1);
                    drop(active);
                    authed = Some(user.clone());
                    held_user = Some(user);
                    pending_user = None;
                    let _ = writer.write_all(b"281 Authentication accepted\r\n").await;
                } else {
                    let _ = writer.write_all(b"500 Unknown AUTHINFO variant\r\n").await;
                }
            }
            "GROUP" => {
                if !check_auth(&shared.config, &authed, &mut writer).await {
                    continue;
                }
                let g = if arg.is_empty() {
                    shared.config.group.clone()
                } else {
                    arg.clone()
                };
                // RFC 3977 s3.1.2: a group that is neither the configured
                // group nor carried by any article does not exist.
                let known =
                    g == shared.config.group || shared.config.articles.iter().any(|a| a.group == g);
                if !known {
                    let _ = writer.write_all(b"411 No such newsgroup\r\n").await;
                    continue;
                }
                let count = shared
                    .config
                    .articles
                    .iter()
                    .filter(|a| a.group == g)
                    .count();
                let (low, high) = shared
                    .config
                    .articles
                    .iter()
                    .filter(|a| a.group == g)
                    .map(|a| a.number)
                    .fold((u32::MAX, 0u32), |(lo, hi), n| (lo.min(n), hi.max(n)));
                let (low, high) = if count == 0 { (0, 0) } else { (low, high) };
                let _ = writer
                    .write_all(format!("211 {count} {low} {high} {g}\r\n").as_bytes())
                    .await;
                selected = Some(g);
            }
            "LIST" => {
                if !check_auth(&shared.config, &authed, &mut writer).await {
                    continue;
                }
                // RFC 3977 §7.6.3: `group high low status` (high first).
                let g = shared.config.group.clone();
                let (low, high) = shared
                    .config
                    .articles
                    .iter()
                    .filter(|a| a.group == g)
                    .map(|a| a.number)
                    .fold((u32::MAX, 0u32), |(lo, hi), n| (lo.min(n), hi.max(n)));
                let (low, high) = if low == u32::MAX { (0, 0) } else { (low, high) };
                let _ = writer
                    .write_all(
                        format!("215 List follows\r\n{g} {high} {low} y\r\n.\r\n").as_bytes(),
                    )
                    .await;
            }
            "XOVER" => {
                if !check_auth(&shared.config, &authed, &mut writer).await {
                    continue;
                }
                // RFC 3977 s8.3.2: collect matches first. A range that
                // matches nothing (including a reversed range) gets 423; a
                // range with no selected group gets 412; an unparseable
                // range gets 501. Only then is 224 written.
                let range = parse_xover_arg(&arg);
                if matches!(range, XoverRange::Invalid) {
                    let _ = writer
                        .write_all(b"501 Syntax error in XOVER range\r\n")
                        .await;
                    continue;
                }
                let group = match (&range, &selected) {
                    (XoverRange::All, _) => None,
                    (_, Some(g)) => Some(g.clone()),
                    (_, None) => {
                        let _ = writer.write_all(b"412 No newsgroup selected\r\n").await;
                        continue;
                    }
                };
                let matches: Vec<_> = shared
                    .config
                    .articles
                    .iter()
                    .filter(|a| {
                        if let Some(g) = group.as_deref() {
                            if a.group != g {
                                return false;
                            }
                        }
                        xover_range_matches(&range, a.number)
                    })
                    .collect();
                if !matches!(range, XoverRange::All) && matches.is_empty() {
                    let _ = writer.write_all(b"423 No articles in that range\r\n").await;
                    continue;
                }
                let _ = writer.write_all(b"224 Overview follows\r\n").await;
                for a in matches {
                    let overview = format!(
                        "{}\t{}\t{}\t{}\t{}\t\t0\t0\r\n",
                        a.number, a.subject, a.from, a.date, a.message_id
                    );
                    // Abort mid-list if the server was dropped: an in-flight
                    // XOVER must not keep serving after shutdown.
                    let write = tokio::select! {
                        _ = shutdown.changed() => None,
                        res = writer.write_all(overview.as_bytes()) => Some(res),
                    };
                    match write {
                        Some(Ok(())) => {}
                        // Shutdown signalled (None) or client gone: close.
                        _ => break,
                    }
                    if *shutdown.borrow() {
                        break;
                    }
                }
                if *shutdown.borrow() {
                    break;
                }
                let _ = writer.write_all(b".\r\n").await;
            }
            "ARTICLE" | "BODY" | "HEAD" | "STAT" => {
                if !check_auth(&shared.config, &authed, &mut writer).await {
                    continue;
                }
                let article = if arg.starts_with('<') {
                    shared.config.find_by_id(&arg)
                } else if let Ok(n) = arg.parse::<u32>() {
                    shared.config.find_by_number(n)
                } else if arg.is_empty() {
                    None
                } else {
                    shared.config.find_by_id(&arg)
                };
                let Some(article) = article else {
                    let _ = writer.write_all(b"430 No such article\r\n").await;
                    continue;
                };
                if shared.config.missing_ids.contains(&article.message_id) {
                    let _ = writer.write_all(b"430 No such article\r\n").await;
                    continue;
                }
                if shared.config.latency_ms > 0 {
                    let aborted = tokio::select! {
                        _ = shutdown.changed() => true,
                        _ = tokio::time::sleep(Duration::from_millis(shared.config.latency_ms)) => false,
                    };
                    if aborted || *shutdown.borrow() {
                        break;
                    }
                }
                let code = match cmd.as_str() {
                    "ARTICLE" => 220,
                    "BODY" => 222,
                    "HEAD" => 221,
                    _ => 223,
                };
                let head_end = find_header_end(&article.raw);
                let payload: &[u8] = match cmd.as_str() {
                    "BODY" => &article.raw[head_end..],
                    "HEAD" => &article.raw[..head_end],
                    _ => &article.raw,
                };
                let header_line = format!("{code} {} {}\r\n", article.number, article.message_id);
                // Mid-body disconnect: partial write then abrupt close.
                if let Some(&cut) = shared.config.drop_after_bytes.get(&article.message_id) {
                    let _ = writer.write_all(header_line.as_bytes()).await;
                    let cut = cut.min(payload.len());
                    let _ = writer.write_all(&payload[..cut]).await;
                    break;
                }
                let _ = writer.write_all(header_line.as_bytes()).await;
                if cmd.as_str() == "STAT" {
                    continue;
                }
                if let Some(bps) = shared.config.slow_bytes_per_sec {
                    if !write_throttled(&mut writer, payload, bps, &mut shutdown).await {
                        break;
                    }
                } else {
                    let stuffed = dot_stuff(payload);
                    let _ = writer.write_all(&stuffed).await;
                }
                if *shutdown.borrow() {
                    break;
                }
                let _ = writer.write_all(b".\r\n").await;
            }
            "QUIT" => {
                let _ = writer.write_all(b"205 Bye\r\n").await;
                break;
            }
            _ => {
                let _ = writer.write_all(b"500 Unknown command\r\n").await;
            }
        }
    }

    // Release the per-user slot.
    if let Some(user) = held_user {
        let mut active = shared.active.lock().await;
        if let Some(c) = active.get_mut(&user) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                active.remove(&user);
            }
        }
    }
}

async fn check_auth(
    config: &ServerConfig,
    authed: &Option<String>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
) -> bool {
    if config.require_auth && authed.is_none() {
        // RFC 4643 s2.3.1: authentication is required (480); 481 means the
        // credentials that were presented were rejected.
        let _ = writer.write_all(b"480 Authentication required\r\n").await;
        return false;
    }
    true
}

fn split_cmd(line: &str) -> (String, String) {
    match line.find(' ') {
        Some(i) => (
            line[..i].to_ascii_uppercase(),
            line[i + 1..].trim().to_string(),
        ),
        None => (line.to_ascii_uppercase(), String::new()),
    }
}

fn find_header_end(raw: &[u8]) -> usize {
    for i in 0..raw.len().saturating_sub(3) {
        if &raw[i..i + 4] == b"\r\n\r\n" {
            return i + 4;
        }
    }
    raw.len()
}

/// Dot-stuff (byte-oriented): prefix any CRLF-delimited line starting with
/// `.` with an extra `.`. Never decodes the payload as UTF-8 — yEnc bodies
/// are arbitrary bytes and `from_utf8_lossy` would corrupt them.
fn dot_stuff(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    let mut start = 0usize;
    loop {
        let rel = find_crlf(&data[start..]);
        match rel {
            Some(pos) => {
                let line = &data[start..start + pos];
                if line.first() == Some(&b'.') {
                    out.push(b'.');
                }
                out.extend_from_slice(line);
                out.extend_from_slice(b"\r\n");
                start += pos + 2;
            }
            None => {
                let line = &data[start..];
                if !line.is_empty() {
                    if line.first() == Some(&b'.') {
                        out.push(b'.');
                    }
                    out.extend_from_slice(line);
                    out.extend_from_slice(b"\r\n");
                }
                break;
            }
        }
    }
    out
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\r\n")
}

/// Throttled body write that aborts promptly on server shutdown.
/// Returns true when the full body was written, false when shutdown was
/// signalled (the caller must then close the session without a terminator).
async fn write_throttled(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    data: &[u8],
    bytes_per_sec: u64,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    let bps = bytes_per_sec.max(1) as usize;
    let stuffed = dot_stuff(data);
    let mut offset = 0;
    while offset < stuffed.len() {
        // Fast-path abort before each chunk (covers an already-signalled drop).
        if *shutdown.borrow() {
            return false;
        }
        let end = (offset + bps).min(stuffed.len());
        let wrote = tokio::select! {
            _ = shutdown.changed() => return false,
            res = writer.write_all(&stuffed[offset..end]) => res,
        };
        if wrote.is_err() {
            return false;
        }
        // Treat a shutdown that raced the write as an abort too: the chunk
        // may have been partially flushed, but the session must close now.
        if *shutdown.borrow() {
            return false;
        }
        offset = end;
        if offset < stuffed.len() {
            let aborted = tokio::select! {
                _ = shutdown.changed() => true,
                _ = tokio::time::sleep(Duration::from_secs(1)) => false,
            };
            if aborted || *shutdown.borrow() {
                return false;
            }
        }
    }
    true
}

/// Parsed XOVER range argument (RFC 3977 §8.3). Accepted forms: `n`,
/// `n-`, `n-m` (first token only).
enum XoverRange {
    /// No argument: legacy list-all for callers that pass no range.
    All,
    /// A parsed range. May match nothing — including a reversed range —
    /// which the caller reports as 423.
    Span(u32, u32),
    /// Non-empty but unparseable: the caller reports 501 instead of
    /// treating it as list-all.
    Invalid,
}

fn parse_xover_arg(arg: &str) -> XoverRange {
    let Some(token) = arg.split_whitespace().next() else {
        return XoverRange::All;
    };
    if token.is_empty() {
        return XoverRange::All;
    }
    if let Some((start_s, end_s)) = token.split_once('-') {
        if start_s.is_empty() && end_s.is_empty() {
            return XoverRange::Invalid;
        }
        if start_s.is_empty() {
            // "-m": articles 1..=m.
            return end_s
                .parse()
                .map(|end| XoverRange::Span(1, end))
                .unwrap_or(XoverRange::Invalid);
        }
        let Ok(start): Result<u32, _> = start_s.parse() else {
            return XoverRange::Invalid;
        };
        if end_s.is_empty() {
            // "n-": n..=MAX.
            return XoverRange::Span(start, u32::MAX);
        }
        return end_s
            .parse()
            .map(|end| XoverRange::Span(start, end))
            .unwrap_or(XoverRange::Invalid);
    }
    token
        .parse()
        .map(|n| XoverRange::Span(n, n))
        .unwrap_or(XoverRange::Invalid)
}

/// Whether `number` falls inside a parsed XOVER range.
fn xover_range_matches(range: &XoverRange, number: u32) -> bool {
    match range {
        XoverRange::All => true,
        XoverRange::Span(lo, hi) => number >= *lo && number <= *hi,
        XoverRange::Invalid => false,
    }
}
