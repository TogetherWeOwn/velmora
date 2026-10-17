//! NNTP client (RFC 3977) over a [`crate::transport::Transport`].
//!
//! Supported commands: greeting + `MODE READER`, `AUTHINFO USER/PASS`,
//! `GROUP`, `STAT`, `ARTICLE`, `BODY`, `QUIT`. Responses are parsed into
//! numeric codes; the reply codes this client acts on are:
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
//!
//! NNTP is lock-step ordered, so pipelining is simply writing several
//! commands before reading their replies in order ([`NntpClient::fetch_many`]
//! batches `ARTICLE` this way, chunked by `max_pipelined`).

use std::fmt;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::transport::{BufferedTransport, Transport};

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
    let code = std::str::from_utf8(&line[..3])
        .map_err(|_| Error::Malformed("NNTP reply code is not UTF-8".into()))?
        .parse()
        .map_err(|_| Error::Malformed("NNTP reply code out of range".into()))?;
    let text = String::from_utf8_lossy(line.get(4..).unwrap_or(b"")).into_owned();
    Ok(Reply { code, text })
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

/// NNTP client. Obtain a connected [`Transport`] from
/// [`crate::transports`], then [`NntpClient::connect`] performs the greeting,
/// `MODE READER`, and `AUTHINFO` handshake.
pub struct NntpClient<T: Transport> {
    transport: BufferedTransport<T>,
    max_pipelined: usize,
}

impl<T: Transport> NntpClient<T> {
    /// Runs the opening handshake on an already-connected transport:
    /// greeting (`200`/`201`), `MODE READER` (any well-formed reply code
    /// is tolerated because some servers reject it pre-auth, but a broken
    /// exchange fails setup), and `AUTHINFO` when the config carries
    /// credentials.
    pub async fn connect(transport: T, config: &NntpConfig) -> Result<Self> {
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
            client.auth(username, password).await?;
        }
        Ok(client)
    }

    /// Sends `QUIT` and shuts the transport down. Errors are swallowed: quit
    /// is a courtesy, not a guarantee.
    pub async fn quit(mut self) {
        let _ = self.transport.write_line(b"QUIT").await;
        let _ = self.transport.shutdown().await;
    }

    /// Returns the wrapped transport without QUIT (for connection reuse by
    /// the caller after a failed handshake, e.g. to surface raw replies).
    pub fn into_inner(self) -> T {
        self.transport.into_inner()
    }

    /// `STAT <message-id>`: returns the article number. `430` becomes
    /// [`Error::ArticleNotFound`].
    pub async fn stat(&mut self, message_id: &str) -> Result<u64> {
        let reply = self.command(&format!("STAT <{message_id}>")).await?;
        match reply.code {
            223 => reply
                .text
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| {
                    Error::Malformed(format!("STAT reply has no article number: {}", reply.text))
                }),
            _ => Err(self.classify(&reply, message_id)),
        }
    }

    /// `ARTICLE <message-id>`: appends the raw article (headers + body) to
    /// `out`. `430` becomes [`Error::ArticleNotFound`].
    pub async fn article_to(&mut self, message_id: &str, out: &mut Vec<u8>) -> Result<()> {
        let reply = self.command(&format!("ARTICLE <{message_id}>")).await?;
        match reply.code {
            220 => self.transport.read_dot_block(out).await.map_err(Error::Io),
            _ => Err(self.classify(&reply, message_id)),
        }
    }

    /// `BODY <message-id>`: appends just the body to `out`.
    pub async fn body_to(&mut self, message_id: &str, out: &mut Vec<u8>) -> Result<()> {
        let reply = self.command(&format!("BODY <{message_id}>")).await?;
        match reply.code {
            222 => self.transport.read_dot_block(out).await.map_err(Error::Io),
            _ => Err(self.classify(&reply, message_id)),
        }
    }

    /// `GROUP <name>`: selects a group and returns its counters.
    pub async fn group(&mut self, name: &str) -> Result<GroupInfo> {
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
    /// reply + dot-block in turn. On any error, the batch is discarded and
    /// the client becomes unusable: later pipelined replies may still be on
    /// the wire. Reconnect before retrying; never reuse `into_inner()` after
    /// a failed batch. A per-article `430` returns [`Error::ArticleNotFound`].
    pub async fn fetch_many(&mut self, message_ids: &[&str]) -> Result<Vec<FetchOutcome>> {
        let result = self.fetch_many_inner(message_ids).await;
        if result.is_err() {
            self.transport.invalidate();
        }
        result
    }

    async fn fetch_many_inner(&mut self, message_ids: &[&str]) -> Result<Vec<FetchOutcome>> {
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

    async fn auth(&mut self, username: &str, password: &str) -> Result<()> {
        // Every reply inside the AUTHINFO exchange is mapped through
        // `auth_reply_error`, which drops the server text before it can
        // reach logs or error bodies (see module docs). A reply that is
        // not a parseable 3-digit code never reaches that mapping —
        // `parse_reply` fails first and its `Malformed` payload echoes
        // the raw line — so both commands go through `auth_command`,
        // which replaces that payload with a fixed redacted message.
        let user_reply = self
            .auth_command(&format!("AUTHINFO USER {username}"))
            .await?;
        match user_reply.code {
            381 => {
                let pass_reply = self
                    .auth_command(&format!("AUTHINFO PASS {password}"))
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
    async fn auth_command(&mut self, cmd: &str) -> Result<Reply> {
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
