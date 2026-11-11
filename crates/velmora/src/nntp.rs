//! NNTP client (RFC 3977) over a [`crate::transport::Transport`].
//!
//! Supported commands: greeting + `MODE READER`, `AUTHINFO USER/PASS`,
//! `GROUP`, `STAT`, `ARTICLE`, `BODY`, `POST`, `QUIT`. Responses are parsed
//! into numeric codes; the reply codes this client acts on are:
//!
//! - `430` — no such article → [`Error::ArticleNotFound`].
//! - `480` (authentication required, RFC 4643) / `481` (rejected), and
//!   `482` on `AUTHINFO` replies → [`Error::AuthFailed`]. A `482` on a
//!   non-auth command is an out-of-sequence protocol error, not stale
//!   credentials, and stays a generic [`Error::NntpReply`].
//! - `502` — no permission → [`Error::NoPermission`] (never a re-auth
//!   signal). Reply text from the `AUTHINFO` exchange — including a
//!   malformed reply line that never parses to a code — is redacted at
//!   construction: it is attacker-influenced and may reflect credentials.
//! - `POST` flow: `340` (send the article) then `240` (accepted) →
//!   [`PostOutcome::Posted`]; a `435`/`441` duplicate reply is confirmed
//!   with `STAT` and counts as success ([`PostOutcome::Duplicate`]); `440`
//!   (posting not permitted) → [`Error::PostProhibited`]. Retry discipline
//!   is postie-style: stale-connection (transport I/O) errors only, see
//!   [`is_retryable_post_error`] and [`MAX_POST_ATTEMPTS`].
//!
//! NNTP is lock-step ordered, so pipelining is simply writing several
//! commands before reading their replies in order ([`NntpClient::fetch_many`]
//! batches `ARTICLE` this way, chunked by `max_pipelined`).

use std::fmt;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::transport::{
    check_dot_block_framing, is_article_limit_error, BufferedTransport, Transport,
};

/// Total `POST` tries per article (the initial try plus reconnect retries),
/// postie discipline: retries happen on stale-connection errors only (see
/// [`is_retryable_post_error`]). Reply errors — `440` prohibited,
/// `435`/`441` duplicates, `480` auth, `5xx` — never retry on their own: the
/// caller reconnects (a fresh handshake re-authenticates) and retries only
/// when the error is retryable, stopping after this many tries.
pub const MAX_POST_ATTEMPTS: u32 = 3;

/// Whether a failed `POST` may be retried after a reconnect: true only for
/// stale-connection transport I/O (dropped connections, timeouts). The
/// article byte-limit refusal is local, not a stale connection, and reply
/// errors carry a server verdict that redialing cannot change.
pub fn is_retryable_post_error(err: &Error) -> bool {
    matches!(err, Error::Io(io) if !is_article_limit_error(io))
}

/// Connection settings. `timeout` is enforced per transport operation by the
/// [`Transport`] implementation (see its contract).
///
/// `Debug` is manual, not derived: `username`/`password` are credential
/// material and must never reach logs or error bodies, so `{:?}` (ordinary
/// and pretty) renders only their presence, as `Some("<redacted>")`.
#[derive(Clone)]
pub struct NntpConfig {
    /// Server hostname (TLS SNI + certificate name when `tls` is set).
    pub host: String,
    /// Server port (119 plaintext, 563 implicit TLS by convention).
    pub port: u16,
    /// Use implicit TLS from the first byte (NNTPS).
    pub tls: bool,
    /// Explicit opt-in to dial without TLS, mirroring the vault's
    /// `allow_insecure_plaintext` acknowledgment (the user accepted the
    /// cleartext warning at save time). Default `false`.
    ///
    /// The pinned transport gate still enforces the NNTP port allowlist for
    /// acknowledged-plaintext configs; only the TLS requirement is lifted.
    /// Paths that never carry a vault acknowledgment (NZB fetch) leave this
    /// `false` and stay TLS-only.
    pub allow_insecure_plaintext: bool,
    /// AUTHINFO username. `None` means unauthenticated access.
    pub username: Option<String>,
    /// AUTHINFO password. Required when `username` is set.
    pub password: Option<String>,
    /// Per-operation read/write timeout, enforced by the transport.
    pub timeout: Duration,
    /// Maximum `ARTICLE` commands in flight in [`NntpClient::fetch_many`].
    pub max_pipelined: usize,
    /// Maximum bytes appended per ARTICLE/BODY/raw dot-block, including CRLF.
    /// A limit violation makes the connection unusable; reconnect to retry.
    pub max_article_bytes: usize,
}

impl fmt::Debug for NntpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted: only presence is shown, never the credential value
        // (populated, empty-string, or absent alike).
        f.debug_struct("NntpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("allow_insecure_plaintext", &self.allow_insecure_plaintext)
            .field("username", &self.username.as_ref().map(|_| "<redacted>"))
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("timeout", &self.timeout)
            .field("max_pipelined", &self.max_pipelined)
            .field("max_article_bytes", &self.max_article_bytes)
            .finish()
    }
}

impl Default for NntpConfig {
    fn default() -> Self {
        NntpConfig {
            host: String::new(),
            port: 563,
            tls: true,
            allow_insecure_plaintext: false,
            username: None,
            password: None,
            timeout: Duration::from_secs(20),
            max_pipelined: 16,
            max_article_bytes: crate::transport::MAX_ARTICLE_BYTES,
        }
    }
}

/// One parsed server reply line.
#[derive(Debug, Clone)]
pub struct Reply {
    /// Numeric reply code (e.g. 220).
    pub code: u16,
    /// Remainder of the line after the code.
    pub text: String,
}

fn parse_reply(line: &[u8]) -> Result<Reply> {
    if line.len() < 3 || !line[..3].iter().all(|b| b.is_ascii_digit()) {
        return Err(Error::Malformed(format!(
            "NNTP reply is not a 3-digit code: {:?}",
            String::from_utf8_lossy(line)
        )));
    }
    // The three digits must be followed by end-of-line or a space before
    // the reply text. A fourth digit or attached suffix (`2000`, `281x`)
    // is a different, malformed frame — never truncate it to a 3-digit
    // code. The diagnostic is generic: the reply line is untrusted and
    // must not be echoed.
    match line.get(3) {
        None | Some(b' ') => {}
        Some(_) => {
            return Err(Error::Malformed(
                "NNTP reply code is not followed by a space or end of line".into(),
            ))
        }
    }
    let code = std::str::from_utf8(&line[..3])
        .map_err(|_| Error::Malformed("NNTP reply code is not UTF-8".into()))?
        .parse()
        .map_err(|_| Error::Malformed("NNTP reply code out of range".into()))?;
    let text = String::from_utf8_lossy(line.get(4..).unwrap_or(b"")).into_owned();
    Ok(Reply { code, text })
}

/// Validates a caller-supplied NNTP command argument (message-id or group
/// name) before it reaches the wire. Message-ids are framed as `<id>` and
/// group names are a bare token, so `<`, `>`, whitespace or control
/// characters would break out of the framing (`STAT <a> ARTICLE <b>`, an
/// injected second command line via CRLF). Rejects with [`Error::Malformed`]
/// before any byte is written. The diagnostic is generic: the argument may
/// carry control characters that must not reach logs verbatim.
fn validate_argument(arg: &str) -> Result<()> {
    if arg
        .chars()
        .any(|c| c == '<' || c == '>' || c.is_whitespace() || c.is_control())
    {
        return Err(Error::Malformed(
            "NNTP command argument contains a delimiter-escaping character".into(),
        ));
    }
    Ok(())
}

/// Validates a successful article-envelope reply (`223`/`220`/`222`) against
/// the requested Message-ID and returns the article number.
///
/// RFC 3977 envelopes carry `<number> <message-id>` ahead of any trailing
/// prose. The number must be unsigned decimal that fits `u64` (a bare digit
/// string: no sign, hex, suffix, or overflow), and the very next token must
/// be exactly `<{message_id}>` — byte-identical, including case — so a reply
/// naming another article is never accepted under the requested ID.
/// Trailing explanatory text after the ID is not identity and is ignored.
/// Article number 0 is valid: servers report it when fetching by Message-ID.
///
/// Every failure is [`Error::Malformed`] with a fixed diagnostic. Neither
/// the envelope text nor the requested ID is echoed: both are untrusted
/// bytes that must not reach logs or error bodies.
fn parse_envelope(text: &str, message_id: &str) -> Result<u64> {
    let mut parts = text.split_whitespace();
    let invalid = || {
        Error::Malformed("NNTP article envelope is missing the article number or Message-ID".into())
    };
    match (parts.next(), parts.next()) {
        (Some(number), Some(id)) => {
            if !number.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            let article = number.parse().map_err(|_| invalid())?;
            if id.len() != message_id.len() + 2
                || !id.starts_with('<')
                || !id.ends_with('>')
                || &id[1..id.len() - 1] != message_id
            {
                return Err(Error::Malformed(
                    "NNTP article envelope names a different article".into(),
                ));
            }
            Ok(article)
        }
        _ => Err(invalid()),
    }
}

/// Summary returned by `GROUP`.
#[derive(Debug, Clone)]
pub struct GroupInfo {
    /// Estimated article count.
    pub count: u64,
    /// First article number.
    pub first: u64,
    /// Last article number.
    pub last: u64,
    /// Group name as confirmed by the server.
    pub name: String,
}

/// Outcome of one pipelined `ARTICLE` fetch.
#[derive(Debug)]
pub struct FetchOutcome {
    /// Requested Message-ID (without brackets).
    pub message_id: String,
    /// Raw article bytes (headers + body) on success.
    pub article: Vec<u8>,
}

/// Outcome of [`NntpClient::post_article`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostOutcome {
    /// `240`: the server accepted the article.
    Posted,
    /// `435`/`441` followed by a `STAT` confirming the Message-ID is
    /// present: the article is already there, which counts as success (the
    /// verify stage treats both outcomes as posted).
    Duplicate,
}

/// NNTP client. Obtain a connected [`Transport`] from
/// [`crate::transports`], then [`NntpClient::connect`] performs the greeting,
/// `MODE READER`, and `AUTHINFO` handshake.
///
/// Dropping an in-flight command future (an outer timeout/select abandoning
/// `POST`, `BODY`, `STAT`, …) poisons the session synchronously: the next
/// operation fails instead of consuming an abandoned reply. Poisoning is
/// not physical closure — the caller still owns shutdown and close proof
/// (see [`NntpClient::shutdown_unusable`]).
pub struct NntpClient<T: Transport> {
    transport: BufferedTransport<T>,
    max_pipelined: usize,
}

impl<T: Transport> NntpClient<T> {
    /// Runs the opening handshake on an already-connected transport:
    /// greeting (`200`/`201`), `MODE READER` (any well-formed reply code
    /// is tolerated because some servers reject it pre-auth, but a broken
    /// exchange fails setup), and `AUTHINFO` when the config carries
    /// credentials. This compatibility entry point has no authorization gate;
    /// service-account callers must use [`Self::connect_with_auth_guard`].
    pub async fn connect(transport: T, config: &NntpConfig) -> Result<Self> {
        Self::connect_with_auth_guard(transport, config, || Ok(())).await
    }

    /// Opening handshake with a synchronous gate at each credential write.
    /// The gate runs after greeting and MODE READER, immediately before USER
    /// and again before PASS (the USER reply can consume the remaining proof
    /// lifetime). It must check the admitted account/configuration identity,
    /// resolution expiry, cancellation and revocation without awaiting.
    ///
    /// This hook does not establish TLS, vet peers or own capacity. Its caller
    /// must supply an authenticated transport and retain independent physical
    /// socket-close authority across errors and cancellation. Dropping this
    /// future is not closure evidence and must not release an account slot.
    /// A transport write may remain pending after the check; the supervisor
    /// must force-close that socket if cancellation/revocation or its deadline
    /// arrives while writing. The hook alone cannot enforce physical closure.
    /// Guard diagnostics are redacted, preserving only the I/O error kind.
    pub async fn connect_with_auth_guard(
        transport: T,
        config: &NntpConfig,
        mut auth_guard: impl FnMut() -> std::io::Result<()>,
    ) -> Result<Self> {
        if config.max_pipelined == 0 {
            return Err(Error::Malformed(
                "NntpConfig.max_pipelined must be at least 1".into(),
            ));
        }
        if config.max_article_bytes == 0
            || config.max_article_bytes > crate::transport::MAX_ARTICLE_BYTES
        {
            return Err(Error::Malformed(
                "NntpConfig.max_article_bytes must be between 1 and 64 MiB".into(),
            ));
        }
        let mut client = NntpClient {
            transport: BufferedTransport::with_article_limit(transport, config.max_article_bytes),
            max_pipelined: config.max_pipelined,
        };
        let greeting = client.read_reply().await?;
        match greeting.code {
            200 | 201 => {}
            502 => return Err(Error::NoPermission(greeting.text)),
            code => {
                return Err(Error::NntpReply {
                    code,
                    text: greeting.text,
                })
            }
        }
        // Best-effort on the reply code only: servers that require auth
        // first answer 482 here, and the AUTHINFO exchange below resolves
        // it, so any well-formed reply is tolerated. A broken exchange
        // (write/read error, EOF, malformed reply) leaves the session
        // state unknown and fails setup instead of handing back an
        // unusable client.
        let _ = client.command("MODE READER").await?;
        if let Some(username) = &config.username {
            let password = config
                .password
                .as_deref()
                .ok_or_else(|| Error::Malformed("NNTP username set without a password".into()))?;
            client.auth(username, password, &mut auth_guard).await?;
        }
        Ok(client)
    }

    /// Sends `QUIT` and shuts the transport down. Errors are swallowed: quit
    /// is a courtesy, not a guarantee.
    pub async fn quit(mut self) {
        let _ = self.transport.write_line(b"QUIT").await;
        let _ = self.transport.shutdown().await;
    }

    /// Invalidates the session, then attempts transport shutdown without a
    /// protocol command. Use when invocation revocation interrupts an
    /// exchange: QUIT would race an incomplete command or article body.
    ///
    /// The attempt's outcome is never physical-close proof. A transport
    /// shutdown can succeed by completing only a write-half shutdown while
    /// the socket — still owned by this borrowed client — keeps a live read
    /// half, and an error or a dropped shutdown future proves even less.
    /// The caller MUST retain the pool lease/account charge until closure is
    /// independently verified or the client (and its transport) is destroyed,
    /// *even after this method returns `Ok`*. Success here only means the
    /// shutdown attempt completed and the session will refuse further use.
    /// Invalidation happens synchronously on the future's first poll, before
    /// the shutdown attempt, so an interrupted attempt still leaves the
    /// session unusable.
    pub async fn shutdown_unusable(&mut self) -> std::io::Result<()> {
        self.transport.invalidate();
        self.transport.shutdown().await
    }

    /// The configured per-article receive cap in bytes (hard maximum 64 MiB),
    /// as enforced while reading ARTICLE/BODY dot-blocks. Adapters admitting
    /// outbound articles against a readback bound must use this effective
    /// cap, not the hard ceiling.
    pub fn max_article_bytes(&self) -> usize {
        self.transport.max_article_bytes()
    }

    /// Returns the wrapped transport without QUIT (for connection reuse by
    /// the caller after a failed handshake, e.g. to surface raw replies).
    pub fn into_inner(self) -> T {
        self.transport.into_inner()
    }

    /// `STAT <message-id>`: returns the article number after correlating the
    /// `223` envelope (article number + bracketed Message-ID) with the
    /// requested article. An uncorrelated envelope is [`Error::Malformed`];
    /// `430` becomes [`Error::ArticleNotFound`].
    pub async fn stat(&mut self, message_id: &str) -> Result<u64> {
        validate_argument(message_id)?;
        let reply = self.command(&format!("STAT <{message_id}>")).await?;
        match reply.code {
            223 => parse_envelope(&reply.text, message_id),
            _ => Err(self.classify(&reply, message_id)),
        }
    }

    /// `ARTICLE <message-id>`: appends the raw article (headers + body) to
    /// `out`. The `220` envelope is correlated with the requested article
    /// before any byte is read: a rejection appends nothing and invalidates
    /// the connection, because the promised dot-block is still unread on the
    /// wire and the stream is no longer at a command boundary. `430` becomes
    /// [`Error::ArticleNotFound`].
    pub async fn article_to(&mut self, message_id: &str, out: &mut Vec<u8>) -> Result<()> {
        validate_argument(message_id)?;
        let reply = self.command(&format!("ARTICLE <{message_id}>")).await?;
        match reply.code {
            220 => {
                if let Err(err) = parse_envelope(&reply.text, message_id) {
                    self.transport.invalidate();
                    return Err(err);
                }
                self.transport.read_dot_block(out).await.map_err(Error::Io)
            }
            _ => Err(self.classify(&reply, message_id)),
        }
    }

    /// `BODY <message-id>`: appends just the body to `out`. Like
    /// [`NntpClient::article_to`], the `222` envelope is correlated before
    /// any byte is read, and a rejection appends nothing and invalidates
    /// the connection.
    pub async fn body_to(&mut self, message_id: &str, out: &mut Vec<u8>) -> Result<()> {
        validate_argument(message_id)?;
        let reply = self.command(&format!("BODY <{message_id}>")).await?;
        match reply.code {
            222 => {
                if let Err(err) = parse_envelope(&reply.text, message_id) {
                    self.transport.invalidate();
                    return Err(err);
                }
                self.transport.read_dot_block(out).await.map_err(Error::Io)
            }
            _ => Err(self.classify(&reply, message_id)),
        }
    }

    /// `POST` one article: sends `POST`, dot-stuffs `article` with the
    /// `.` terminator on a `340`, and maps the final reply:
    ///
    /// - `240` → [`PostOutcome::Posted`].
    /// - `435`/`441` → `STAT <message-id>`; present (`223`, envelope
    ///   correlated) → [`PostOutcome::Duplicate`], which counts as success.
    ///   A `430` there means the server claims a duplicate it does not have:
    ///   the original `435`/`441` is returned as [`Error::NntpReply`] so the
    ///   caller can re-post (same Message-ID) through the verify stage.
    /// - `440` → [`Error::PostProhibited`] (permanent for this account).
    /// - `480`/`481` → [`Error::AuthFailed`] (stale credentials, re-auth).
    ///
    /// `message_id` is the article's Message-ID (without brackets), used
    /// only for the duplicate-confirming `STAT`. `article` is the complete
    /// article (headers, blank line, body) with CRLF line endings; a bare CR
    /// or LF fails closed with [`Error::Malformed`] before anything is sent.
    /// An empty article is likewise refused.
    ///
    /// A transport failure after the article bytes start flowing invalidates
    /// the connection (reconnect before retrying, honouring
    /// [`is_retryable_post_error`] and [`MAX_POST_ATTEMPTS`]): the server
    /// may or may not have stored the article, and a blind re-POST on the
    /// same broken stream would corrupt framing. Refusals that arrive as
    /// well-formed replies (`240`/`435`/`441`/`440`/…) leave the connection
    /// usable — the reply is only sent after the terminator is consumed.
    pub async fn post_article(&mut self, message_id: &str, article: &[u8]) -> Result<PostOutcome> {
        validate_argument(message_id)?;
        if article.is_empty() {
            return Err(Error::Malformed("POST article is empty".into()));
        }
        // Framing is validated before the POST command: a refused article
        // leaves zero bytes on the wire, so the server never enters
        // send-article state and the connection stays usable.
        check_dot_block_framing(article).map_err(|_| {
            Error::Malformed("POST article holds a bare CR or LF outside CRLF".into())
        })?;
        let greeting = self.command("POST").await?;
        if greeting.code != 340 {
            // Not yet in send-article state: map the bare-POST reply
            // without the post-send 240 → Posted arm (no article byte has
            // gone on the wire, so 240 here is a protocol error, not a
            // posting).
            return self.initial_refusal(greeting, message_id).await;
        }
        match self
            .transport
            .write_dot_block(article)
            .await
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::InvalidInput {
                    Error::Malformed("POST article holds a bare CR or LF outside CRLF".into())
                } else {
                    Error::Io(err)
                }
            }) {
            Ok(()) => {}
            Err(err) => {
                // Nothing was written on a framing refusal (write_dot_block
                // validates first), so the connection stays usable; anything
                // else is a stale connection.
                if !matches!(err, Error::Malformed(_)) {
                    self.transport.invalidate();
                }
                return Err(err);
            }
        }
        let reply = self.read_reply().await?;
        self.refusal_after_reply(reply, message_id).await
    }

    /// Maps the reply to the bare `POST` command — before any article byte
    /// is sent — onto an outcome. `435`/`441` mean "already have it, do not
    /// send" and confirm via `STAT` like a post-send duplicate; `440` is
    /// prohibited; everything else follows [`classify`]. `240` is
    /// deliberately not success here: the server answered before the article
    /// went on the wire (RFC 3977 admits only 340/440 as the initial POST
    /// reply), so reporting `Posted` would record an article that was never
    /// sent.
    async fn initial_refusal(&mut self, reply: Reply, message_id: &str) -> Result<PostOutcome> {
        match reply.code {
            435 | 441 => self.confirm_duplicate(reply, message_id).await,
            440 => Err(Error::PostProhibited(reply.text)),
            _ => Err(self.classify(&reply, message_id)),
        }
    }

    /// Maps the reply after the sent article onto an outcome. `240` posts;
    /// `435`/`441` confirm via `STAT`; `440` is prohibited; everything else
    /// follows [`classify`] (`480`/`481` stay stale-credential signals).
    async fn refusal_after_reply(&mut self, reply: Reply, message_id: &str) -> Result<PostOutcome> {
        match reply.code {
            240 => Ok(PostOutcome::Posted),
            435 | 441 => self.confirm_duplicate(reply, message_id).await,
            440 => Err(Error::PostProhibited(reply.text)),
            _ => Err(self.classify(&reply, message_id)),
        }
    }

    /// Confirms a `435`/`441` duplicate with `STAT <message_id>`: `223`
    /// (envelope correlated) counts as success; `430` returns the original
    /// duplicate reply for a same-ID re-post; any other `STAT` outcome is
    /// classified normally.
    async fn confirm_duplicate(
        &mut self,
        duplicate: Reply,
        message_id: &str,
    ) -> Result<PostOutcome> {
        let stat = self.command(&format!("STAT <{message_id}>")).await?;
        match stat.code {
            223 => {
                parse_envelope(&stat.text, message_id)?;
                Ok(PostOutcome::Duplicate)
            }
            430 => Err(Error::NntpReply {
                code: duplicate.code,
                text: duplicate.text,
            }),
            _ => Err(self.classify(&stat, message_id)),
        }
    }

    /// `GROUP <name>`: selects a group and returns its counters.
    pub async fn group(&mut self, name: &str) -> Result<GroupInfo> {
        validate_argument(name)?;
        let reply = self.command(&format!("GROUP {name}")).await?;
        match reply.code {
            211 => {
                let mut parts = reply.text.split_whitespace();
                let (count, first, last, gname) =
                    (parts.next(), parts.next(), parts.next(), parts.next());
                match (count, first, last, gname) {
                    (Some(c), Some(f), Some(l), Some(g)) => Ok(GroupInfo {
                        count: c.parse().map_err(|_| {
                            Error::Malformed(format!("GROUP count is not a number: {}", reply.text))
                        })?,
                        first: f.parse().map_err(|_| {
                            Error::Malformed(format!("GROUP first is not a number: {}", reply.text))
                        })?,
                        last: l.parse().map_err(|_| {
                            Error::Malformed(format!("GROUP last is not a number: {}", reply.text))
                        })?,
                        name: g.to_string(),
                    }),
                    _ => Err(Error::Malformed(format!(
                        "GROUP reply is truncated: {}",
                        reply.text
                    ))),
                }
            }
            _ => Err(self.classify(&reply, name)),
        }
    }

    /// Pipelined `ARTICLE` fetch: writes up to `max_pipelined` commands
    /// back-to-back (NNTP replies arrive in command order), then reads each
    /// reply + dot-block in turn. On any error after the first byte is
    /// written, the batch is discarded and the client becomes unusable:
    /// later pipelined replies may still be on the wire. Reconnect before
    /// retrying; never reuse `into_inner()` after a failed batch. A
    /// pre-write argument refusal ([`Error::Malformed`]) writes nothing
    /// and leaves the connection usable. A per-article `430` returns
    /// [`Error::ArticleNotFound`]. Every `220` envelope is correlated with
    /// its requested article before its dot-block is read: one uncorrelated
    /// reply discards the whole batch (no partial success) and invalidates
    /// the client.
    pub async fn fetch_many(&mut self, message_ids: &[&str]) -> Result<Vec<FetchOutcome>> {
        // Pre-write refusal must not poison the connection: nothing is on
        // the wire yet, so return before entering the invalidating path.
        // (`fetch_many_inner` re-validates as defence in depth.)
        for id in message_ids {
            validate_argument(id)?;
        }
        let result = self.fetch_many_inner(message_ids).await;
        if result.is_err() {
            self.transport.invalidate();
        }
        result
    }

    async fn fetch_many_inner(&mut self, message_ids: &[&str]) -> Result<Vec<FetchOutcome>> {
        // Validate the whole batch before writing: commands are written
        // ahead of their replies, so a late escaping id must not leave a
        // valid prefix on the wire with unread replies outstanding.
        for id in message_ids {
            validate_argument(id)?;
        }
        let mut out = Vec::with_capacity(message_ids.len());
        for chunk in message_ids.chunks(self.max_pipelined()) {
            for id in chunk {
                self.transport
                    .write_line(format!("ARTICLE <{id}>").as_bytes())
                    .await
                    .map_err(Error::Io)?;
            }
            for id in chunk {
                let reply = self.read_reply().await?;
                match reply.code {
                    220 => {
                        // Correlate before reading: a mismatched envelope
                        // must never relabel foreign bytes, and the error
                        // path in `fetch_many` invalidates the client.
                        parse_envelope(&reply.text, id)?;
                        let mut article = Vec::new();
                        self.transport
                            .read_dot_block(&mut article)
                            .await
                            .map_err(Error::Io)?;
                        out.push(FetchOutcome {
                            message_id: id.to_string(),
                            article,
                        });
                    }
                    _ => return Err(self.classify(&reply, id)),
                }
            }
        }
        Ok(out)
    }

    fn max_pipelined(&self) -> usize {
        // `connect` rejects 0; this is defence in depth.
        self.max_pipelined.max(1)
    }

    async fn auth(
        &mut self,
        username: &str,
        password: &str,
        auth_guard: &mut impl FnMut() -> std::io::Result<()>,
    ) -> Result<()> {
        // Every reply inside the AUTHINFO exchange is mapped through
        // `auth_reply_error`, which drops the server text before it can
        // reach logs or error bodies (see module docs). A reply that is
        // not a parseable 3-digit code never reaches that mapping —
        // `parse_reply` fails first and its `Malformed` payload echoes
        // the raw line — so both commands go through `auth_command`,
        // which replaces that payload with a fixed redacted message.
        let user_reply = self
            .auth_command(&format!("AUTHINFO USER {username}"), auth_guard)
            .await?;
        match user_reply.code {
            381 => {
                let pass_reply = self
                    .auth_command(&format!("AUTHINFO PASS {password}"), auth_guard)
                    .await?;
                match pass_reply.code {
                    281 => Ok(()),
                    code => Err(auth_reply_error(code, pass_reply.text)),
                }
            }
            281 => Ok(()),
            code => Err(auth_reply_error(code, user_reply.text)),
        }
    }

    /// [`NntpClient::command`] for the `AUTHINFO` exchange: a malformed
    /// reply line stays [`Error::Malformed`], exactly as for other
    /// commands, but its payload — the reflected server line, which may
    /// carry the credentials just sent — is replaced with a fixed
    /// redacted message. Transport I/O (including timeouts) is
    /// untouched: it carries no reply text.
    async fn auth_command(
        &mut self,
        cmd: &str,
        auth_guard: &mut impl FnMut() -> std::io::Result<()>,
    ) -> Result<Reply> {
        auth_guard().map_err(|err| {
            Error::Io(std::io::Error::new(
                err.kind(),
                "NNTP authentication gate refused",
            ))
        })?;
        self.command(cmd).await.map_err(|err| match err {
            Error::Malformed(_) => {
                Error::Malformed("NNTP reply to AUTHINFO is not a 3-digit code: <redacted>".into())
            }
            other => other,
        })
    }

    async fn command(&mut self, cmd: &str) -> Result<Reply> {
        self.transport
            .write_line(cmd.as_bytes())
            .await
            .map_err(Error::Io)?;
        self.read_reply().await
    }

    async fn read_reply(&mut self) -> Result<Reply> {
        let line = self.transport.read_line().await.map_err(Error::Io)?;
        parse_reply(&line)
    }

    /// Maps the reply codes this client acts on; anything else is a
    /// generic protocol error carrying its code. `480` (authentication
    /// required — the standard reply to a command on a no-longer
    /// authenticated session) and `481` are the stale-credential signals
    /// here; a `482` off the AUTHINFO exchange is out-of-sequence, not
    /// expired credentials.
    fn classify(&self, reply: &Reply, subject: &str) -> Error {
        match reply.code {
            430 => Error::ArticleNotFound(subject.to_string()),
            480 | 481 => Error::AuthFailed(reply.text.clone()),
            502 => Error::NoPermission(reply.text.clone()),
            code => Error::NntpReply {
                code,
                text: reply.text.clone(),
            },
        }
    }
}

/// Maps a non-success `AUTHINFO USER`/`PASS` reply to an error, dropping
/// the server reply text: `AuthFailed`/`NoPermission` redact at format
/// time, and the generic arm replaces the text outright so no
/// credential-adjacent text survives in the error value. `502` stays
/// [`Error::NoPermission`] — it is not proof of stale credentials and
/// must not surface the re-auth code.
fn auth_reply_error(code: u16, text: String) -> Error {
    match code {
        480..=482 => Error::AuthFailed(text),
        502 => Error::NoPermission(text),
        code => Error::NntpReply {
            code,
            text: "<redacted>".into(),
        },
    }
}

impl<T: Transport> NntpClient<T> {
    /// Sends a raw command and returns the parsed reply (escape hatch for
    /// commands this client does not model, e.g. `DATE`, `CAPABILITIES`).
    pub async fn raw_command(&mut self, cmd: &str) -> Result<Reply> {
        self.command(cmd).await
    }

    /// Reads the dot-block following a `2xx` reply to [`NntpClient::raw_command`].
    pub async fn raw_dot_block(&mut self, out: &mut Vec<u8>) -> Result<()> {
        self.transport.read_dot_block(out).await.map_err(Error::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_accepts_zero_max_and_trailing_prose() {
        for (text, want) in [
            ("0 <a@x>", 0),
            ("42 <a@x>", 42),
            ("18446744073709551615 <a@x> exists", u64::MAX),
            ("42 <a@x> article follows; <b@x> is only prose", 42),
            ("  42   <a@x>  ", 42),
        ] {
            assert_eq!(parse_envelope(text, "a@x").unwrap(), want, "{text:?}");
        }
    }

    #[test]
    fn envelope_rejects_malformed_numbers() {
        for text in [
            "",
            "<a@x>",
            "42",
            "-1 <a@x>",
            "+1 <a@x>",
            "0x2a <a@x>",
            "42x <a@x>",
            "4_2 <a@x>",
            "18446744073709551616 <a@x>",
        ] {
            assert!(
                matches!(parse_envelope(text, "a@x"), Err(Error::Malformed(_))),
                "{text:?} must be a malformed envelope"
            );
        }
    }

    #[test]
    fn envelope_rejects_unmatched_ids() {
        for text in [
            "42 <b@x>",
            "42 <A@x>",
            "42 <a@x.extra>",
            "42 a@x",
            "42 <a@x",
            "42 <>",
            "42 <a@x>>",
            "42 <<a@x>>",
            "42 <b@x> explanation <a@x>",
        ] {
            assert!(
                matches!(parse_envelope(text, "a@x"), Err(Error::Malformed(_))),
                "{text:?} must not correlate with a@x"
            );
        }
    }

    #[test]
    fn envelope_diagnostics_echo_neither_side() {
        let hostile = "42 <\x1b[31mcanary> untrusted-explanation";
        for err in [
            parse_envelope(hostile, "wanted@x").unwrap_err(),
            parse_envelope("no-number-here", "wanted@x").unwrap_err(),
        ] {
            assert!(!err.is_auth_failure());
            for rendered in [err.to_string(), format!("{err:?}"), format!("{err:#?}")] {
                for forbidden in ["\x1b", "canary", "untrusted-explanation", "wanted@x"] {
                    assert!(
                        !rendered.contains(forbidden),
                        "diagnostic echoes untrusted text: {rendered:?}"
                    );
                }
                assert!(rendered.len() <= 256, "unbounded: {rendered:?}");
            }
        }
    }
}
