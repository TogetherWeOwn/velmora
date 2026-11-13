//! Synthetic NNTP server (RFC 3977 subset) for CI.
//!
//! Supported commands: `CAPABILITIES`, `MODE READER`, `AUTHINFO USER/PASS`,
//! `GROUP`, `LIST`, `XOVER`, `ARTICLE`/`BODY`/`HEAD`/`STAT`, `POST`, `QUIT`.
//! Anything else is `500`. Responses are CRLF terminated and dot-stuffed.
//!
//! Fault injection (all configurable per [`ServerConfig`]):
//! - per-credential connection caps (`502` + close when exceeded),
//! - `430` for unknown or explicitly-missing message-IDs,
//! - `481` on bad credentials,
//! - throttled ("slow link") article bodies,
//! - mid-body disconnects (partial write, then TCP reset by close).
//!
//! Posting: `POST` (340/240) stores articles in a per-instance in-memory
//! spool keyed by message-ID, served back via the retrieval commands.
//! Re-posting a stored visible ID is a duplicate (`435`); posting can be
//! disabled per instance (`440`). Message-IDs can be hidden at runtime so
//! tests simulate propagation gaps and article loss (`430` until unhidden);
//! re-posting a hidden ID succeeds and repairs it.

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
    /// These seed the per-instance runtime hidden set (see
    /// [`TestNntpServer::hide`]); the set itself is mutable at runtime.
    pub missing_ids: HashSet<String>,
    /// Whether the instance accepts `POST` (default true). When false the
    /// server answers `440`. Toggleable at runtime via
    /// [`TestNntpServer::set_posting_allowed`].
    pub posting_allowed: bool,
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
            posting_allowed: true,
            slow_bytes_per_sec: None,
            latency_ms: 0,
            drop_after_bytes: HashMap::new(),
        }
    }
}

/// Mutable per-instance spool state. Each [`TestNntpServer`] owns one;
/// two instances never share it, so spool-A/spool-B tests stay isolated.
struct Spool {
    /// Articles accepted via `POST`, in arrival order.
    posted: Vec<Article>,
    /// IDs answered `430` for (propagation gaps / article loss). Seeded
    /// from [`ServerConfig::missing_ids`]; mutated at runtime via
    /// [`TestNntpServer::hide`] / [`TestNntpServer::unhide`].
    hidden: HashSet<String>,
    /// Next article number to assign to a posted article.
    next_number: u32,
    /// Runtime posting switch; `POST` answers `440` while false.
    posting_allowed: bool,
    /// Remaining `POST`s to store and then drop without a reply.
    drop_posts: usize,
    /// Remaining `BODY` replies to cut mid-body.
    drop_bodies: usize,
    /// While true, `STAT` answers `430` for articles in the `POST` spool.
    stat_lag: bool,
    /// While true, a login over the connection cap is answered `482`
    /// instead of `502`.
    limit_482: bool,
}

struct Shared {
    config: ServerConfig,
    spool: Mutex<Spool>,
    /// Active authenticated connections per user.
    active: Mutex<HashMap<String, usize>>,
}

impl Shared {
    fn new(config: ServerConfig) -> Self {
        let next_number = config
            .articles
            .iter()
            .map(|a| a.number)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let spool = Spool {
            posted: Vec::new(),
            hidden: config.missing_ids.clone(),
            next_number,
            posting_allowed: config.posting_allowed,
            drop_posts: 0,
            drop_bodies: 0,
            stat_lag: false,
            limit_482: false,
        };
        Self {
            config,
            spool: Mutex::new(spool),
            active: Mutex::new(HashMap::new()),
        }
    }
}

/// Normalize a message-ID argument to bracketed form (`x` -> `<x>`).
fn normalize_id(id: &str) -> String {
    let id = id.trim();
    if id.starts_with('<') {
        id.to_string()
    } else {
        format!("<{id}>")
    }
}

/// A running test server. Binds an ephemeral loopback port; `shutdown` on drop.
///
/// Each instance owns an independent in-memory spool: posting to one server
/// is invisible to every other server, so two instances work as spool-A /
/// spool-B in a single test.
pub struct TestNntpServer {
    addr: SocketAddr,
    // Held so the accept loop stays alive; aborted on drop.
    _task: tokio::task::JoinHandle<()>,
    // Signalled on drop so already-open sessions close too, not just the
    // accept loop (aborting the accept task alone detaches session tasks).
    shutdown: watch::Sender<bool>,
    shared: Arc<Shared>,
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
        let shared = Arc::new(Shared::new(config));
        let task = tokio::spawn(serve_with_shutdown(
            listener,
            Arc::clone(&shared),
            shutdown_rx,
        ));
        Self {
            addr,
            _task: task,
            shutdown,
            shared,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Number of articles accepted via `POST` on this instance.
    pub async fn posted_count(&self) -> usize {
        self.shared.spool.lock().await.posted.len()
    }

    /// Message-IDs accepted via `POST`, in arrival order.
    pub async fn posted_ids(&self) -> Vec<String> {
        self.shared
            .spool
            .lock()
            .await
            .posted
            .iter()
            .map(|a| a.message_id.clone())
            .collect()
    }

    /// How many of `ids` are present in this instance's `POST` spool.
    /// For duplicate assertions: post a file/manifest, then assert the
    /// count for its IDs is unchanged after a resumed second pass.
    pub async fn posted_count_for(&self, ids: &[&str]) -> usize {
        let spool = self.shared.spool.lock().await;
        ids.iter()
            .filter(|id| {
                let want = normalize_id(id);
                spool.posted.iter().any(|a| a.message_id == want)
            })
            .count()
    }

    /// Physical presence: in the fixture corpus or the `POST` spool,
    /// regardless of runtime hiding (hidden IDs are stored but answer 430).
    pub async fn is_stored(&self, id: &str) -> bool {
        let want = normalize_id(id);
        let spool = self.shared.spool.lock().await;
        self.shared
            .config
            .articles
            .iter()
            .any(|a| a.message_id == want)
            || spool.posted.iter().any(|a| a.message_id == want)
    }

    /// Hide a message-ID: retrieval answers `430` until [`Self::unhide`].
    /// Simulates propagation gaps and article loss per spool.
    pub async fn hide(&self, id: &str) {
        self.shared
            .spool
            .lock()
            .await
            .hidden
            .insert(normalize_id(id));
    }

    /// Reveal a previously hidden message-ID.
    pub async fn unhide(&self, id: &str) {
        self.shared
            .spool
            .lock()
            .await
            .hidden
            .remove(&normalize_id(id));
    }

    /// Replace the whole hidden set (e.g. hide one file's segments).
    pub async fn set_hidden(&self, ids: impl IntoIterator<Item = String>) {
        let mut spool = self.shared.spool.lock().await;
        spool.hidden = ids.into_iter().map(|id| normalize_id(&id)).collect();
    }

    /// Currently hidden message-IDs on this instance.
    pub async fn hidden_ids(&self) -> HashSet<String> {
        self.shared.spool.lock().await.hidden.clone()
    }

    /// Whether this message-ID is currently hidden on this instance.
    pub async fn is_hidden(&self, id: &str) -> bool {
        self.shared
            .spool
            .lock()
            .await
            .hidden
            .contains(&normalize_id(id))
    }

    /// Toggle whether `POST` is accepted (`440` while disabled).
    pub async fn set_posting_allowed(&self, allowed: bool) {
        self.shared.spool.lock().await.posting_allowed = allowed;
    }

    /// The next `n` `POST`s are stored, then the connection closes without
    /// a reply: the client cannot tell whether the article landed.
    pub async fn drop_next_posts(&self, n: usize) {
        self.shared.spool.lock().await.drop_posts = n;
    }

    /// The next `n` `BODY` replies stop mid-body and close the connection.
    pub async fn drop_next_bodies(&self, n: usize) {
        self.shared.spool.lock().await.drop_bodies = n;
    }

    /// While set, `STAT` answers `430` for posted articles although `BODY`
    /// serves them (a provider whose `STAT` lags right after a `POST`).
    pub async fn set_stat_lag(&self, lag: bool) {
        self.shared.spool.lock().await.stat_lag = lag;
    }

    /// While set, a login over the per-user connection cap is answered
    /// `482` (as some providers do) instead of `502`.
    pub async fn set_limit_reply_482(&self, on: bool) {
        self.shared.spool.lock().await.limit_482 = on;
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
    let shared = Arc::new(Shared::new(config));
    serve_with_shutdown(listener, shared, shutdown_rx).await;
}

async fn serve_with_shutdown(
    listener: TcpListener,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
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
                        let reply: &[u8] = match shared.spool.lock().await.limit_482 {
                            true => b"482 Too many connections for user\r\n",
                            false => b"502 Too many connections for user\r\n",
                        };
                        let _ = writer.write_all(reply).await;
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
                let spool = shared.spool.lock().await;
                // RFC 3977 s3.1.2: a group that is neither the configured
                // group nor carried by any stored article does not exist.
                // Stored, not visible: a group whose articles are all hidden
                // is still available, just empty (`211 0 0 0` below).
                let known = g == shared.config.group
                    || shared.config.articles.iter().any(|a| a.group == g)
                    || spool.posted.iter().any(|a| a.group == g);
                if !known {
                    drop(spool);
                    let _ = writer.write_all(b"411 No such newsgroup\r\n").await;
                    continue;
                }
                let mut count = 0;
                let (mut low, mut high) = (u32::MAX, 0u32);
                for a in visible_iter(&shared.config, &spool) {
                    if a.group == g {
                        count += 1;
                        low = low.min(a.number);
                        high = high.max(a.number);
                    }
                }
                drop(spool);
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
                // RFC 3977 §7.6.3: `group high low status` (high first), one
                // line per group. Advertise the configured group plus every
                // group carried by stored articles (fixtures or spool), so a
                // group introduced by POST is discoverable. Bounds cover
                // visible articles only, matching GROUP (a fully-hidden group
                // reports 0 0).
                let spool = shared.spool.lock().await;
                let mut names: Vec<String> = shared
                    .config
                    .articles
                    .iter()
                    .chain(spool.posted.iter())
                    .map(|a| a.group.clone())
                    .collect();
                names.push(shared.config.group.clone());
                names.sort();
                names.dedup();
                let mut out = String::from("215 List follows\r\n");
                for name in &names {
                    let (low, high) = visible_iter(&shared.config, &spool)
                        .filter(|a| &a.group == name)
                        .map(|a| a.number)
                        .fold((u32::MAX, 0u32), |(lo, hi), n| (lo.min(n), hi.max(n)));
                    let (low, high) = if low == u32::MAX { (0, 0) } else { (low, high) };
                    out.push_str(&format!("{name} {high} {low} y\r\n"));
                }
                drop(spool);
                out.push_str(".\r\n");
                let _ = writer.write_all(out.as_bytes()).await;
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
                // Posted spool articles appear in XOVER; hidden IDs are
                // omitted (simulated loss), like the ARTICLE family.
                let spool = shared.spool.lock().await;
                let matches: Vec<Article> = visible_iter(&shared.config, &spool)
                    .filter(|a| {
                        if let Some(g) = group.as_deref() {
                            if a.group != g {
                                return false;
                            }
                        }
                        xover_range_matches(&range, a.number)
                    })
                    .cloned()
                    .collect();
                drop(spool);
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
                // Fixture corpus first, then the per-instance POST spool;
                // hidden IDs answer 430 as if missing (propagation gaps).
                let article = if arg.is_empty() {
                    None
                } else if arg.starts_with('<') || arg.parse::<u32>().is_err() {
                    find_visible_by_id(&shared, &normalize_id(&arg)).await
                } else {
                    let n: u32 = arg.parse().unwrap_or(0);
                    find_visible_by_number(&shared, n).await
                };
                let Some(article) = article else {
                    let _ = writer.write_all(b"430 No such article\r\n").await;
                    continue;
                };
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
                // Runtime hooks: a lagging STAT and a one-shot mid-body drop.
                {
                    let mut spool = shared.spool.lock().await;
                    if cmd.as_str() == "STAT"
                        && spool.stat_lag
                        && spool
                            .posted
                            .iter()
                            .any(|a| a.message_id == article.message_id)
                    {
                        drop(spool);
                        let _ = writer.write_all(b"430 No such article\r\n").await;
                        continue;
                    }
                    if cmd.as_str() == "BODY" && spool.drop_bodies > 0 {
                        spool.drop_bodies -= 1;
                        drop(spool);
                        let _ = writer.write_all(header_line.as_bytes()).await;
                        let _ = writer.write_all(&payload[..payload.len() / 2]).await;
                        break;
                    }
                }
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
            "POST" => {
                if !check_auth(&shared.config, &authed, &mut writer).await {
                    continue;
                }
                if !shared.spool.lock().await.posting_allowed {
                    let _ = writer.write_all(b"440 Posting not allowed\r\n").await;
                    continue;
                }
                let _ = writer.write_all(b"340 Send article\r\n").await;
                match read_post_block(&mut lines, &mut shutdown).await {
                    PostBody::Complete(raw) => {
                        let reply =
                            store_posted(&shared, authed.as_deref().unwrap_or("poster"), &raw)
                                .await;
                        // Runtime hook: the article is stored, the reply lost.
                        {
                            let mut spool = shared.spool.lock().await;
                            if spool.drop_posts > 0 {
                                spool.drop_posts -= 1;
                                break;
                            }
                        }
                        let _ = writer.write_all(reply.as_bytes()).await;
                    }
                    PostBody::Empty => {
                        let _ = writer.write_all(b"441 Posting failed\r\n").await;
                    }
                    PostBody::TooBig | PostBody::Aborted => {
                        if *shutdown.borrow() {
                            break;
                        }
                        let _ = writer.write_all(b"441 Posting failed\r\n").await;
                    }
                }
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

/// Visible articles: fixture corpus plus the per-instance `POST` spool,
/// minus runtime-hidden IDs. A fixture whose Message-ID has a spool
/// replacement (hide → re-post repair) is served from the spool copy only,
/// so `GROUP`/`XOVER` never list one ID twice. The caller holds the spool
/// lock; the returned iterator borrows both.
fn visible_iter<'a>(
    config: &'a ServerConfig,
    spool: &'a Spool,
) -> impl Iterator<Item = &'a Article> {
    config
        .articles
        .iter()
        .filter(|a| !spool.posted.iter().any(|p| p.message_id == a.message_id))
        .chain(spool.posted.iter())
        .filter(|a| !spool.hidden.contains(&a.message_id))
}

async fn find_visible_by_id(shared: &Arc<Shared>, id: &str) -> Option<Article> {
    let spool = shared.spool.lock().await;
    if spool.hidden.contains(id) {
        return None;
    }
    if let Some(a) = spool.posted.iter().find(|a| a.message_id == id) {
        return Some(a.clone());
    }
    shared
        .config
        .articles
        .iter()
        .find(|a| a.message_id == id)
        .cloned()
}

async fn find_visible_by_number(shared: &Arc<Shared>, n: u32) -> Option<Article> {
    // Resolve through the same visible set as the listings, so a numeric
    // lookup can never return a shadowed (repaired) fixture or a hidden ID.
    let spool = shared.spool.lock().await;
    let found = visible_iter(&shared.config, &spool)
        .find(|a| a.number == n)
        .cloned();
    found
}

/// Outcome of reading a `POST` body (dot-terminated block, RFC 3977 §6.3).
enum PostBody {
    /// At least one line received and terminated by `.`.
    Complete(Vec<u8>),
    /// Immediate `.`: nothing to store.
    Empty,
    /// Over [`MAX_POST_BYTES`]: drained to the terminator, then rejected.
    TooBig,
    /// Client went away or the server is shutting down: caller closes.
    Aborted,
}

/// Hard cap on one posted article; keeps a runaway sender from growing the
/// in-memory spool without bound. Rejected with `441`.
const MAX_POST_BYTES: usize = 8 * 1024 * 1024;

/// Read the dot-terminated `POST` block, dot-unstuffing into CRLF bytes.
///
/// Byte-oriented (`read_until`): posted bodies (yEnc) are arbitrary bytes and
/// must never be decoded as UTF-8 mid-transfer — `read_line` would fail
/// closed on non-UTF-8 payloads and drop the session.
async fn read_post_block(
    lines: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    shutdown: &mut watch::Receiver<bool>,
) -> PostBody {
    let mut out = Vec::new();
    let mut line = Vec::new();
    let mut lines_seen = 0usize;
    let mut over_cap = false;
    loop {
        line.clear();
        let read = tokio::select! {
            _ = shutdown.changed() => return PostBody::Aborted,
            read = lines.read_until(b'\n', &mut line) => read,
        };
        match read {
            Ok(0) => return PostBody::Aborted,
            Ok(_) => {}
            Err(_) => return PostBody::Aborted,
        }
        // Strip one CRLF/LF terminator.
        if line.ends_with(b"\n") {
            line.pop();
            if line.ends_with(b"\r") {
                line.pop();
            }
        }
        if line == b"." {
            break;
        }
        // Dot-unstuff: a stuffed line starts with ".."; strip one dot from
        // any dotted line (tolerant of a lone leading dot).
        let start = usize::from(line.first() == Some(&b'.'));
        lines_seen += 1;
        if over_cap {
            continue;
        }
        if out.len() + line.len() - start + 2 > MAX_POST_BYTES {
            over_cap = true;
            continue;
        }
        out.extend_from_slice(&line[start..]);
        out.extend_from_slice(b"\r\n");
    }
    if lines_seen == 0 {
        PostBody::Empty
    } else if over_cap {
        PostBody::TooBig
    } else {
        PostBody::Complete(out)
    }
}

/// Case-insensitive header lookup with RFC 5322 unfolding: continuation
/// lines (leading WSP) are joined to the field with a space, so a folded
/// `Subject` reads whole in `XOVER` just as `HEAD` serves it.
fn header_field(head: &str, name: &str) -> Option<String> {
    let mut found: Option<String> = None;
    for line in head.split("\r\n") {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(ref mut f) = found {
                f.push(' ');
                f.push_str(line.trim());
            }
            continue;
        }
        if found.is_some() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                found = Some(v.trim().to_string());
            }
        }
    }
    found
}

/// Store a posted article and render the `240`/`435` reply.
///
/// - Unknown ID: stored under a fresh article number, `240`.
/// - Known visible ID (corpus or spool): duplicate, `435`.
/// - Known hidden ID: the re-post repairs the simulated loss — the bytes
///   are stored (replacing any same-ID spool copy), the ID is revealed,
///   and the reply is `240`, so same-ID re-posts converge and
///   `posted_count` grows once per repaired ID.
async fn store_posted(shared: &Arc<Shared>, poster: &str, raw: &[u8]) -> String {
    let head_end = find_header_end(raw);
    let head = String::from_utf8_lossy(&raw[..head_end]);
    let body = &raw[head_end..];
    let mut spool = shared.spool.lock().await;
    let (generated_id, message_id) = match header_field(&head, "message-id") {
        Some(id) => (false, normalize_id(&id)),
        None => (true, format!("<posted-{}@nntune.test>", spool.next_number)),
    };
    let in_corpus = shared
        .config
        .articles
        .iter()
        .any(|a| a.message_id == message_id);
    let in_spool = spool.posted.iter().any(|a| a.message_id == message_id);
    // Duplicates only count when visible: re-posting a hidden ID is the
    // repair path, not a duplicate. The re-posted bytes are stored (same-ID
    // re-posts converge: a later identical POST then hits the 435 below)
    // and the ID is revealed, so `posted_count` grows once per repaired ID.
    if !spool.hidden.contains(&message_id) && (in_corpus || in_spool) {
        return format!("435 Duplicate article {message_id}\r\n");
    }
    // Same-ID convergence: never keep two spool copies of one ID (a
    // hide → post → hide → post cycle replaces the earlier bytes).
    spool.posted.retain(|a| a.message_id != message_id);
    spool.hidden.remove(&message_id);
    // Production renders Newsgroups comma-separated (`a, b`): split on
    // commas and whitespace and take the first group. (This fake models one
    // group per article; cross-post fan-out would need a model change.)
    let group = header_field(&head, "newsgroups")
        .as_deref()
        .and_then(|g| {
            g.split(|c: char| c == ',' || c.is_whitespace())
                .find(|s| !s.is_empty())
        })
        .map(|s| s.to_string())
        .unwrap_or_else(|| shared.config.group.clone());
    // A generated ID must also land in the stored headers, or HEAD/ARTICLE
    // would disagree with the STAT reply that reports it.
    let raw: Vec<u8> = if generated_id && raw[..head_end].ends_with(b"\r\n\r\n") {
        let mut fixed = Vec::with_capacity(raw.len() + message_id.len() + 16);
        fixed.extend_from_slice(&raw[..head_end - 2]);
        fixed.extend_from_slice(format!("Message-ID: {message_id}\r\n").as_bytes());
        fixed.extend_from_slice(b"\r\n");
        fixed.extend_from_slice(&raw[head_end..]);
        fixed
    } else {
        raw.to_vec()
    };
    let article = Article {
        number: spool.next_number,
        message_id: message_id.clone(),
        group,
        subject: header_field(&head, "subject").unwrap_or_else(|| "(posted article)".to_string()),
        from: header_field(&head, "from").unwrap_or_else(|| format!("{poster}@nntune.test")),
        date: header_field(&head, "date")
            .unwrap_or_else(|| "Mon, 13 Oct 2026 00:00:00 +0000".to_string()),
        raw,
        payload: body.to_vec(),
    };
    spool.next_number = spool.next_number.saturating_add(1);
    spool.posted.push(article);
    format!("240 Article received {message_id}\r\n")
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
