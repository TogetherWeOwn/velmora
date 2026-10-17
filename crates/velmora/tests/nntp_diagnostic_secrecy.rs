//! Acceptance tests: NNTP credentials must stay out of configuration
//! formatting and malformed-auth diagnostics.
//!
//! Contract for the implementation:
//!
//! - `NntpConfig`'s `Debug` (ordinary and pretty) never renders the
//!   configured username or password verbatim — populated, empty-string
//!   or absent — while useful nonsecret settings (host, …) and `Clone`
//!   semantics stay intact.
//! - A malformed reply to `AUTHINFO USER` or `AUTHINFO PASS` (short,
//!   non-numeric or non-UTF-8 line) fails the connect without retaining
//!   any reflected reply text — and never the configured credentials —
//!   in the returned error's `Display` or `Debug` rendering. The error
//!   stays `Error::Malformed` for well-formed UTF-8 input, exactly as
//!   for other commands: this is a secrecy fix, not a reclassification.
//! - Successful USER-only and USER/PASS exchanges, existing numeric
//!   auth/no-permission classification and redaction, timeout
//!   behaviour, and non-auth command semantics are unchanged.
//!
//! All tests run over scripted in-memory transports with synthetic
//! sentinel credentials: no sockets, no real credentials, no log
//! infrastructure.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nntune_core::error::Error;
use nntune_core::nntp::{NntpClient, NntpConfig};
use nntune_core::transport::Transport;

const HOST: &str = "news.fixture.invalid";
/// Synthetic credential sentinels. Distinctive enough that they cannot
/// appear in a rendering by accident.
const USER_SENTINEL: &str = "synthetic-nntp-user-9c41";
const PASS_SENTINEL: &str = "synthetic-nntp-password-9c41";
/// Marker the scripted server "reflects" inside its malformed or
/// numeric reply text. None of it may survive into an error rendering.
const REFLECTED: &str = "reflected-auth-marker-9c41";

const GREETING_AND_MODE: &str = "200 fixture ready\r\n500 MODE READER unsupported\r\n";
const PASS_REQUIRED: &str = "381 password required\r\n";

// ---------------------------------------------------------------------
// Scripted transport: byte script in, shared write log out, optional
// read failure once a byte cap has been served (for the timeout pin).
// ---------------------------------------------------------------------

struct Script {
    to_client: VecDeque<u8>,
    write_log: Arc<Mutex<Vec<String>>>,
    read_cap: Option<usize>,
    served: usize,
    read_failure: Option<io::ErrorKind>,
}

impl Script {
    fn new(readable: &[u8]) -> (Self, Arc<Mutex<Vec<String>>>) {
        let write_log = Arc::new(Mutex::new(Vec::new()));
        (
            Script {
                to_client: readable.iter().copied().collect(),
                write_log: Arc::clone(&write_log),
                read_cap: None,
                served: 0,
                read_failure: None,
            },
            write_log,
        )
    }

    /// Serve `cap` bytes normally, then fail reads with `kind`.
    fn fail_read_after(mut self, cap: usize, kind: io::ErrorKind) -> Self {
        self.read_cap = Some(cap);
        self.read_failure = Some(kind);
        self
    }
}

impl Transport for Script {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let capped = match self.read_cap {
            Some(cap) => cap.saturating_sub(self.served),
            None => usize::MAX,
        };
        let n = buf.len().min(self.to_client.len()).min(capped);
        if n == 0 {
            return match self.read_failure {
                Some(kind) => Err(io::Error::new(kind, "scripted read failure")),
                None => Ok(0),
            };
        }
        for (i, slot) in buf[..n].iter_mut().enumerate() {
            *slot = self.to_client[i];
        }
        self.to_client.drain(..n);
        self.served += n;
        Ok(n)
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_log
            .lock()
            .expect("write log")
            .push(String::from_utf8_lossy(buf).into_owned());
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn config_with(username: Option<&str>, password: Option<&str>) -> NntpConfig {
    NntpConfig {
        host: HOST.into(),
        port: 563,
        tls: true,
        username: username.map(Into::into),
        password: password.map(Into::into),
        timeout: Duration::from_secs(5),
        max_pipelined: 4,
        ..NntpConfig::default()
    }
}

fn credentialed_config() -> NntpConfig {
    config_with(Some(USER_SENTINEL), Some(PASS_SENTINEL))
}

fn writes(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    log.lock().expect("write log").clone()
}

fn expected_writes(through_pass: bool, extra: &[&str]) -> Vec<String> {
    let mut want = vec![
        "MODE READER\r\n".to_string(),
        format!("AUTHINFO USER {USER_SENTINEL}\r\n"),
    ];
    if through_pass {
        want.push(format!("AUTHINFO PASS {PASS_SENTINEL}\r\n"));
    }
    want.extend(extra.iter().map(|s| s.to_string()));
    want
}

/// Every rendering of `err` must be free of each forbidden fragment.
fn assert_error_renderings_hide(err: &Error, forbidden: &[&str]) {
    for rendered in [err.to_string(), format!("{err:?}"), format!("{err:#?}")] {
        for needle in forbidden {
            assert!(
                !rendered.contains(needle),
                "diagnostic rendering retains {needle:?}: {rendered}"
            );
        }
    }
}

const CREDENTIALS_AND_REFLECTED: &[&str] = &[USER_SENTINEL, PASS_SENTINEL, REFLECTED];

/// Script that reaches the AUTHINFO stage under test, then answers it
/// with `stage_reply` (the malformed bytes).
fn auth_stage_script(stage_reply: &[u8], at_pass: bool) -> Vec<u8> {
    let mut readable = GREETING_AND_MODE.as_bytes().to_vec();
    if at_pass {
        readable.extend_from_slice(PASS_REQUIRED.as_bytes());
    }
    readable.extend_from_slice(stage_reply);
    readable
}

async fn assert_malformed_auth_reply_fails_secretly(
    stage_reply: &[u8],
    at_pass: bool,
    extra_forbidden: &[&str],
) -> Error {
    let (script, log) = Script::new(&auth_stage_script(stage_reply, at_pass));
    let Err(err) = NntpClient::connect(script, &credentialed_config()).await else {
        panic!("malformed AUTHINFO reply must fail connect, got Ok(client)");
    };
    assert_eq!(
        writes(&log),
        expected_writes(at_pass, &[]),
        "no command beyond the failed AUTHINFO stage may be issued"
    );
    let mut forbidden: Vec<&str> = CREDENTIALS_AND_REFLECTED.to_vec();
    forbidden.extend_from_slice(extra_forbidden);
    assert_error_renderings_hide(&err, &forbidden);
    err
}

fn nonnumeric_reflected_reply() -> Vec<u8> {
    format!("NOPE echoed {USER_SENTINEL} {PASS_SENTINEL} {REFLECTED}\r\n").into_bytes()
}

fn non_utf8_reflected_reply() -> Vec<u8> {
    let mut reply = vec![0xFF, 0xFE];
    reply.extend_from_slice(format!(" {USER_SENTINEL} {PASS_SENTINEL} {REFLECTED}\r\n").as_bytes());
    reply
}

// ---------------------------------------------------------------------
// NntpConfig Debug: credentials never render; nonsecret settings and
// Clone behaviour stay intact.
// ---------------------------------------------------------------------

fn assert_config_debug_hides(config: &NntpConfig, forbidden: &[&str]) {
    for rendered in [format!("{config:?}"), format!("{config:#?}")] {
        for needle in forbidden {
            assert!(
                !rendered.contains(needle),
                "NntpConfig Debug retains {needle:?}: {rendered}"
            );
        }
        assert!(
            rendered.contains(HOST),
            "NntpConfig Debug must keep useful nonsecret settings: {rendered}"
        );
    }
}

#[test]
fn config_debug_hides_populated_credentials() {
    assert_config_debug_hides(&credentialed_config(), &[USER_SENTINEL, PASS_SENTINEL]);
}

#[test]
fn config_debug_hides_password_when_username_is_empty() {
    // An empty-string username must not be rendered verbatim either
    // (`Some("")`): credential fields are not formatted at all.
    assert_config_debug_hides(
        &config_with(Some(""), Some(PASS_SENTINEL)),
        &[PASS_SENTINEL, "Some(\"\")"],
    );
}

#[test]
fn config_debug_hides_username_when_password_is_empty() {
    assert_config_debug_hides(
        &config_with(Some(USER_SENTINEL), Some("")),
        &[USER_SENTINEL, "Some(\"\")"],
    );
}

#[test]
fn config_debug_absent_credentials_keeps_nonsecret_settings() {
    let config = config_with(None, None);
    assert_config_debug_hides(&config, &[USER_SENTINEL, PASS_SENTINEL]);
    assert_eq!(config.username, None);
    assert_eq!(config.password, None);
}

#[test]
fn config_clone_preserves_credentials_and_settings() {
    let config = credentialed_config();
    let cloned = config.clone();
    assert_eq!(cloned.host, config.host);
    assert_eq!(cloned.port, config.port);
    assert_eq!(cloned.tls, config.tls);
    assert_eq!(cloned.username.as_deref(), Some(USER_SENTINEL));
    assert_eq!(cloned.password.as_deref(), Some(PASS_SENTINEL));
    assert_eq!(cloned.timeout, config.timeout);
    assert_eq!(cloned.max_pipelined, config.max_pipelined);
    // The clone is just as safe to format as the original.
    assert_config_debug_hides(&cloned, &[USER_SENTINEL, PASS_SENTINEL]);
}

// ---------------------------------------------------------------------
// Malformed replies to AUTHINFO USER: connect fails, AUTHINFO PASS is
// never issued, and no reflected text or credential survives.
// ---------------------------------------------------------------------

#[tokio::test]
async fn malformed_user_reply_nonnumeric_fails_without_reflected_text() {
    let err =
        assert_malformed_auth_reply_fails_secretly(&nonnumeric_reflected_reply(), false, &["NOPE"])
            .await;
    assert!(
        matches!(err, Error::Malformed(_)),
        "non-numeric AUTHINFO USER reply must stay Malformed, got {err:?}"
    );
}

#[tokio::test]
async fn malformed_user_reply_short_fails_without_reflected_text() {
    let err = assert_malformed_auth_reply_fails_secretly(b"Q7\r\n", false, &["Q7"]).await;
    assert!(
        matches!(err, Error::Malformed(_)),
        "short AUTHINFO USER reply must stay Malformed, got {err:?}"
    );
}

#[tokio::test]
async fn malformed_user_reply_non_utf8_fails_without_reflected_text() {
    // Variant intentionally unpinned: depending on where UTF-8
    // validation lives this may surface as Malformed or Io — either is
    // fine as long as nothing reflected is retained.
    assert_malformed_auth_reply_fails_secretly(&non_utf8_reflected_reply(), false, &[]).await;
}

// ---------------------------------------------------------------------
// Malformed replies to AUTHINFO PASS.
// ---------------------------------------------------------------------

#[tokio::test]
async fn malformed_pass_reply_nonnumeric_fails_without_reflected_text() {
    let err =
        assert_malformed_auth_reply_fails_secretly(&nonnumeric_reflected_reply(), true, &["NOPE"])
            .await;
    assert!(
        matches!(err, Error::Malformed(_)),
        "non-numeric AUTHINFO PASS reply must stay Malformed, got {err:?}"
    );
}

#[tokio::test]
async fn malformed_pass_reply_short_fails_without_reflected_text() {
    let err = assert_malformed_auth_reply_fails_secretly(b"Q7\r\n", true, &["Q7"]).await;
    assert!(
        matches!(err, Error::Malformed(_)),
        "short AUTHINFO PASS reply must stay Malformed, got {err:?}"
    );
}

#[tokio::test]
async fn malformed_pass_reply_non_utf8_fails_without_reflected_text() {
    assert_malformed_auth_reply_fails_secretly(&non_utf8_reflected_reply(), true, &[]).await;
}

#[tokio::test]
async fn malformed_pass_reply_empty_line_fails_without_credentials() {
    assert_malformed_auth_reply_fails_secretly(b"\r\n", true, &[]).await;
}

// ---------------------------------------------------------------------
// Positive compatibility controls: everything that works today keeps
// working, with today's classification.
// ---------------------------------------------------------------------

#[tokio::test]
async fn auth_user_only_exchange_still_succeeds() {
    // 281 straight to AUTHINFO USER: no password round-trip.
    let readable = format!("{GREETING_AND_MODE}281 authentication accepted\r\n");
    let (script, log) = Script::new(readable.as_bytes());
    NntpClient::connect(script, &credentialed_config())
        .await
        .expect("USER-only auth must still connect");
    assert_eq!(writes(&log), expected_writes(false, &[]));
}

#[tokio::test]
async fn auth_user_pass_exchange_still_succeeds() {
    let readable = format!("{GREETING_AND_MODE}{PASS_REQUIRED}281 authentication accepted\r\n");
    let (script, log) = Script::new(readable.as_bytes());
    NntpClient::connect(script, &credentialed_config())
        .await
        .expect("USER/PASS auth must still connect");
    assert_eq!(writes(&log), expected_writes(true, &[]));
}

#[tokio::test]
async fn numeric_481_at_pass_stays_auth_failed_and_redacted() {
    let readable = format!("{GREETING_AND_MODE}{PASS_REQUIRED}481 {REFLECTED} {PASS_SENTINEL}\r\n");
    let (script, log) = Script::new(readable.as_bytes());
    let Err(err) = NntpClient::connect(script, &credentialed_config()).await else {
        panic!("481 must fail connect");
    };
    assert!(
        matches!(err, Error::AuthFailed(_)),
        "481 must stay AuthFailed, got {err:?}"
    );
    assert!(err.is_auth_failure());
    assert_error_renderings_hide(&err, CREDENTIALS_AND_REFLECTED);
    assert_eq!(writes(&log), expected_writes(true, &[]));
}

#[tokio::test]
async fn numeric_502_at_pass_stays_no_permission_and_redacted() {
    let readable = format!("{GREETING_AND_MODE}{PASS_REQUIRED}502 {REFLECTED} {PASS_SENTINEL}\r\n");
    let (script, log) = Script::new(readable.as_bytes());
    let Err(err) = NntpClient::connect(script, &credentialed_config()).await else {
        panic!("502 must fail connect");
    };
    assert!(
        matches!(err, Error::NoPermission(_)),
        "502 must stay NoPermission, got {err:?}"
    );
    assert!(!err.is_auth_failure());
    assert_error_renderings_hide(&err, CREDENTIALS_AND_REFLECTED);
    assert_eq!(writes(&log), expected_writes(true, &[]));
}

#[tokio::test]
async fn auth_pass_read_timeout_still_surfaces_without_credentials() {
    // Greeting, MODE READER reply and 381 read normally; the read for
    // the AUTHINFO PASS reply times out at the transport.
    let readable = format!("{GREETING_AND_MODE}{PASS_REQUIRED}");
    let (script, log) = Script::new(readable.as_bytes());
    let script = script.fail_read_after(readable.len(), io::ErrorKind::TimedOut);
    let Err(err) = NntpClient::connect(script, &credentialed_config()).await else {
        panic!("timed-out AUTHINFO PASS reply must fail connect");
    };
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::TimedOut),
        "transport timeout must surface as Io/TimedOut, got {err:?}"
    );
    assert_error_renderings_hide(&err, &[USER_SENTINEL, PASS_SENTINEL]);
    assert_eq!(writes(&log), expected_writes(true, &[]));
}

#[tokio::test]
async fn non_auth_stat_semantics_are_unchanged() {
    // Successful STAT after auth.
    let readable = format!("{GREETING_AND_MODE}281 ok\r\n223 42 <a@x> article exists\r\n");
    let (script, log) = Script::new(readable.as_bytes());
    let mut client = NntpClient::connect(script, &credentialed_config())
        .await
        .expect("handshake");
    assert_eq!(client.stat("a@x").await.expect("STAT 223"), 42);
    assert_eq!(writes(&log), expected_writes(false, &["STAT <a@x>\r\n"]));

    // 430 on STAT stays ArticleNotFound.
    let readable = format!("{GREETING_AND_MODE}281 ok\r\n430 no such article\r\n");
    let (script, log) = Script::new(readable.as_bytes());
    let mut client = NntpClient::connect(script, &credentialed_config())
        .await
        .expect("handshake");
    let err = client.stat("missing@x").await.expect_err("430 must fail");
    assert!(
        matches!(err, Error::ArticleNotFound(_)),
        "430 must stay ArticleNotFound, got {err:?}"
    );
    assert_eq!(
        writes(&log),
        expected_writes(false, &["STAT <missing@x>\r\n"])
    );
}
