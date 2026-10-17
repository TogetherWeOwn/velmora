//! Acceptance tests: a reply line must have a valid boundary after its
//! three ASCII response-code digits.
//!
//! Contract for the implementation:
//!
//! - After the three digits, only end-of-line (code-only reply) or a
//!   space separator followed by reply text is well-formed. A fourth
//!   digit (`2000`, `2810`, ...) or an attached non-separator suffix
//!   (`201x`, `281x`, ...) is malformed and must be rejected instead of
//!   being silently truncated to the first three digits.
//! - Rejection applies on every success path that parses a reply:
//!   greeting, `MODE READER`, `AUTHINFO USER`/`PASS`, and ordinary
//!   commands. A rejected frame never continues the corresponding
//!   success path and no further command is issued for it (in
//!   particular, `AUTHINFO PASS` is never sent after a malformed
//!   `381x`, and a malformed `281x` is never authentication success).
//! - Well-formed code-only and space-separated replies keep working,
//!   and numeric classification (`430`, `480`, `502`, ...) is unchanged
//!   for well-formed replies. A malformed-boundary frame must not fall
//!   into the classification of its first three digits.
//! - The new validation diagnostic is a bounded, generic
//!   [`Error::Malformed`] reason: it must not echo the untrusted reply
//!   line (or any part of its text) in `Display` or `Debug`, and must
//!   never carry credential material.
//!
//! All tests run over scripted in-memory transports: no sockets, no
//! real credentials (the synthetic password below is a fixture).

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nntune_core::error::{Error, PROVIDER_AUTH_EXPIRED_CODE};
use nntune_core::nntp::{NntpClient, NntpConfig};
use nntune_core::transport::Transport;

const GREETING: &str = "200 news.example.com ready\r\n";
const MODE_READER_OK: &str = "200 reader mode on\r\n";
const SYNTHETIC_PASSWORD: &str = "synthetic-fixture-password";
/// Marker planted inside malformed reply lines; a bounded generic
/// diagnostic must never echo it back.
const CANARY: &str = "untrusted-reply-canary-7f3a";

/// Scripted transport with a shared write log, so command sequencing
/// can be asserted even when `connect` fails and consumes the client.
struct Script {
    to_client: VecDeque<u8>,
    write_log: Arc<Mutex<Vec<String>>>,
}

impl Script {
    fn new(readable: &str) -> (Self, Arc<Mutex<Vec<String>>>) {
        let write_log = Arc::new(Mutex::new(Vec::new()));
        (
            Script {
                to_client: readable.bytes().collect(),
                write_log: Arc::clone(&write_log),
            },
            write_log,
        )
    }
}

impl Transport for Script {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.to_client.len());
        if n == 0 {
            return Ok(0);
        }
        for (i, slot) in buf[..n].iter_mut().enumerate() {
            *slot = self.to_client[i];
        }
        self.to_client.drain(..n);
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

fn config_without_credentials() -> NntpConfig {
    NntpConfig {
        host: "nntp.example.com".into(),
        tls: true,
        username: None,
        password: None,
        timeout: Duration::from_secs(5),
        max_pipelined: 4,
        ..NntpConfig::default()
    }
}

fn config_with_credentials() -> NntpConfig {
    NntpConfig {
        username: Some("fixture-user".into()),
        password: Some(SYNTHETIC_PASSWORD.into()),
        ..config_without_credentials()
    }
}

fn writes(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    log.lock().expect("write log").clone()
}

/// Every malformed-boundary rejection must surface as a bounded generic
/// `Malformed` that echoes neither the untrusted reply text nor any
/// credential material, in either rendered form.
fn assert_bounded_malformed(err: &Error) {
    assert!(
        matches!(err, Error::Malformed(_)),
        "malformed reply boundary must surface as Malformed, got {err:?}"
    );
    assert!(
        !err.is_auth_failure(),
        "malformed boundary must not be classified as an auth failure: {err:?}"
    );
    assert_ne!(
        err.code(),
        PROVIDER_AUTH_EXPIRED_CODE,
        "malformed boundary must not carry the provider-auth-expired code"
    );
    for rendered in [err.to_string(), format!("{err:?}")] {
        assert!(
            !rendered.contains(CANARY),
            "diagnostic must not echo the untrusted reply line: {rendered}"
        );
        assert!(
            !rendered.contains(SYNTHETIC_PASSWORD),
            "diagnostic must never carry credential material: {rendered}"
        );
        assert!(
            rendered.len() <= 256,
            "diagnostic must be bounded, got {} bytes: {rendered}",
            rendered.len()
        );
    }
}

/// Connects expecting failure, then pins the exact commands issued.
async fn connect_err(readable: &str, config: &NntpConfig, expected_writes: &[String]) -> Error {
    let (script, log) = Script::new(readable);
    let Err(err) = NntpClient::connect(script, config).await else {
        panic!("malformed reply boundary must fail connect, got Ok(client)");
    };
    assert_eq!(
        writes(&log).as_slice(),
        expected_writes,
        "no command may follow a rejected reply frame"
    );
    err
}

/// Well-formed handshake answering `281` to `AUTHINFO USER` directly,
/// followed by `extra` scripted replies for ordinary commands.
async fn connected_client(extra: &str) -> (NntpClient<Script>, Arc<Mutex<Vec<String>>>) {
    let readable = format!("{GREETING}{MODE_READER_OK}281 authentication accepted\r\n{extra}");
    let (script, log) = Script::new(&readable);
    let client = NntpClient::connect(script, &config_with_credentials())
        .await
        .expect("well-formed handshake must connect");
    (client, log)
}

// ---------------------------------------------------------------------
// Greeting: a malformed boundary must not be read as 200/201 success
// (or as any other greeting classification), and nothing is written.
// ---------------------------------------------------------------------

#[tokio::test]
async fn greeting_with_fourth_digit_is_rejected() {
    let err = connect_err(
        &format!("2000 {CANARY}\r\n{MODE_READER_OK}"),
        &config_without_credentials(),
        &[],
    )
    .await;
    assert_bounded_malformed(&err);
}

#[tokio::test]
async fn greeting_with_attached_letter_suffix_is_rejected() {
    let err = connect_err(
        &format!("201x{CANARY}\r\n{MODE_READER_OK}"),
        &config_without_credentials(),
        &[],
    )
    .await;
    assert_bounded_malformed(&err);
}

#[tokio::test]
async fn greeting_200_with_attached_suffix_is_rejected() {
    let err = connect_err(
        &format!("200x {CANARY}\r\n{MODE_READER_OK}"),
        &config_without_credentials(),
        &[],
    )
    .await;
    assert_bounded_malformed(&err);
}

#[tokio::test]
async fn greeting_with_fourth_digit_is_not_no_permission() {
    // `5020` must not collapse into the well-formed `502` classification.
    let err = connect_err(
        &format!("5020 {CANARY}\r\n"),
        &config_without_credentials(),
        &[],
    )
    .await;
    assert_bounded_malformed(&err);
}

// ---------------------------------------------------------------------
// MODE READER: the tolerated-reply contract covers only well-formed
// replies; a malformed boundary fails setup before AUTHINFO.
// ---------------------------------------------------------------------

#[tokio::test]
async fn mode_reader_reply_with_fourth_digit_is_rejected_before_authinfo() {
    let err = connect_err(
        &format!(
            "{GREETING}2000 {CANARY}\r\n381 more authentication required\r\n281 authentication accepted\r\n"
        ),
        &config_with_credentials(),
        &["MODE READER\r\n".to_string()],
    )
    .await;
    assert_bounded_malformed(&err);
}

// ---------------------------------------------------------------------
// AUTHINFO: a malformed `381` must not elicit the password, and a
// malformed `281` is never authentication success.
// ---------------------------------------------------------------------

#[tokio::test]
async fn authinfo_user_381_with_attached_suffix_is_rejected_without_sending_password() {
    let err = connect_err(
        &format!("{GREETING}{MODE_READER_OK}381x{CANARY}\r\n281 authentication accepted\r\n"),
        &config_with_credentials(),
        &[
            "MODE READER\r\n".to_string(),
            "AUTHINFO USER fixture-user\r\n".to_string(),
        ],
    )
    .await;
    assert_bounded_malformed(&err);
}

#[tokio::test]
async fn authinfo_user_281_with_attached_suffix_is_not_auth_success() {
    let err = connect_err(
        &format!("{GREETING}{MODE_READER_OK}281x{CANARY}\r\n"),
        &config_with_credentials(),
        &[
            "MODE READER\r\n".to_string(),
            "AUTHINFO USER fixture-user\r\n".to_string(),
        ],
    )
    .await;
    assert_bounded_malformed(&err);
}

#[tokio::test]
async fn authinfo_user_281_with_fourth_digit_is_not_auth_success() {
    let err = connect_err(
        &format!("{GREETING}{MODE_READER_OK}2810 {CANARY}\r\n"),
        &config_with_credentials(),
        &[
            "MODE READER\r\n".to_string(),
            "AUTHINFO USER fixture-user\r\n".to_string(),
        ],
    )
    .await;
    assert_bounded_malformed(&err);
}

#[tokio::test]
async fn authinfo_pass_281_with_attached_suffix_is_not_auth_success() {
    let err = connect_err(
        &format!("{GREETING}{MODE_READER_OK}381 more authentication required\r\n281x{CANARY}\r\n"),
        &config_with_credentials(),
        &[
            "MODE READER\r\n".to_string(),
            "AUTHINFO USER fixture-user\r\n".to_string(),
            format!("AUTHINFO PASS {SYNTHETIC_PASSWORD}\r\n"),
        ],
    )
    .await;
    assert_bounded_malformed(&err);
}

#[tokio::test]
async fn authinfo_pass_281_with_fourth_digit_is_not_auth_success() {
    let err = connect_err(
        &format!("{GREETING}{MODE_READER_OK}381 more authentication required\r\n2810 {CANARY}\r\n"),
        &config_with_credentials(),
        &[
            "MODE READER\r\n".to_string(),
            "AUTHINFO USER fixture-user\r\n".to_string(),
            format!("AUTHINFO PASS {SYNTHETIC_PASSWORD}\r\n"),
        ],
    )
    .await;
    assert_bounded_malformed(&err);
}

// ---------------------------------------------------------------------
// Ordinary commands: a malformed boundary must not continue the
// success path, nor fall into the classification of its first three
// digits.
// ---------------------------------------------------------------------

#[tokio::test]
async fn stat_223_with_fourth_digit_is_rejected() {
    let (mut client, _log) = connected_client(&format!("2230 42 <a@x> {CANARY}\r\n")).await;
    let err = client
        .stat("a@x")
        .await
        .expect_err("2230 must not be read as a successful 223");
    assert_bounded_malformed(&err);
}

#[tokio::test]
async fn stat_223_with_attached_suffix_is_rejected() {
    let (mut client, _log) = connected_client(&format!("223x 42 <a@x> {CANARY}\r\n")).await;
    let err = client
        .stat("a@x")
        .await
        .expect_err("223x must not be read as a successful 223");
    assert_bounded_malformed(&err);
}

#[tokio::test]
async fn stat_430_with_fourth_digit_is_not_article_not_found() {
    let (mut client, _log) = connected_client(&format!("4300 {CANARY}\r\n")).await;
    let err = client
        .stat("a@x")
        .await
        .expect_err("4300 must not be classified as 430");
    assert_bounded_malformed(&err);
}

#[tokio::test]
async fn stat_480_with_attached_suffix_is_not_auth_failure() {
    let (mut client, _log) = connected_client(&format!("480x{CANARY}\r\n")).await;
    let err = client
        .stat("a@x")
        .await
        .expect_err("480x must not be classified as 480");
    assert_bounded_malformed(&err);
}

#[tokio::test]
async fn raw_command_reply_with_attached_suffix_is_rejected() {
    let (mut client, _log) = connected_client(&format!("111x{CANARY}\r\n")).await;
    let err = client
        .raw_command("DATE")
        .await
        .expect_err("111x must not be parsed as reply 111");
    assert_bounded_malformed(&err);
}

// ---------------------------------------------------------------------
// Positive controls: code-only and space-separated forms, plus the
// existing numeric classification, are preserved exactly.
// ---------------------------------------------------------------------

#[tokio::test]
async fn code_only_greeting_and_mode_reader_connect() {
    let (script, log) = Script::new("200\r\n200\r\n");
    NntpClient::connect(script, &config_without_credentials())
        .await
        .expect("code-only replies must stay accepted");
    assert_eq!(writes(&log), vec!["MODE READER\r\n".to_string()]);
}

#[tokio::test]
async fn code_only_281_to_authinfo_user_connects_without_password_round_trip() {
    let (script, log) = Script::new(&format!("{GREETING}{MODE_READER_OK}281\r\n"));
    NntpClient::connect(script, &config_with_credentials())
        .await
        .expect("code-only 281 must stay accepted as auth success");
    assert_eq!(
        writes(&log),
        vec![
            "MODE READER\r\n".to_string(),
            "AUTHINFO USER fixture-user\r\n".to_string(),
        ]
    );
}

#[tokio::test]
async fn space_separated_auth_handshake_still_connects() {
    let (script, log) = Script::new(&format!(
        "{GREETING}{MODE_READER_OK}381 more authentication required\r\n281 authentication accepted\r\n"
    ));
    NntpClient::connect(script, &config_with_credentials())
        .await
        .expect("space-separated replies must stay accepted");
    assert_eq!(
        writes(&log),
        vec![
            "MODE READER\r\n".to_string(),
            "AUTHINFO USER fixture-user\r\n".to_string(),
            format!("AUTHINFO PASS {SYNTHETIC_PASSWORD}\r\n"),
        ]
    );
}

#[tokio::test]
async fn stat_valid_223_space_separated_reply_still_succeeds() {
    let (mut client, _log) = connected_client("223 42 <a@x> article exists\r\n").await;
    assert_eq!(client.stat("a@x").await.expect("valid 223"), 42);
}

#[tokio::test]
async fn stat_valid_430_still_classifies_as_article_not_found() {
    let (mut client, _log) = connected_client("430 no such article\r\n").await;
    let err = client
        .stat("a@x")
        .await
        .expect_err("well-formed 430 must fail");
    assert!(
        matches!(err, Error::ArticleNotFound(_)),
        "well-formed 430 classification must be preserved, got {err:?}"
    );
}

#[tokio::test]
async fn stat_valid_480_still_classifies_as_auth_failure() {
    let (mut client, _log) = connected_client("480 authentication required\r\n").await;
    let err = client
        .stat("a@x")
        .await
        .expect_err("well-formed 480 must fail");
    assert!(
        matches!(err, Error::AuthFailed(_)),
        "well-formed 480 classification must be preserved, got {err:?}"
    );
    assert!(err.is_auth_failure());
    assert_eq!(err.code(), PROVIDER_AUTH_EXPIRED_CODE);
}

#[tokio::test]
async fn raw_command_code_only_reply_has_empty_text() {
    let (mut client, _log) = connected_client("111\r\n").await;
    let reply = client.raw_command("DATE").await.expect("valid 111");
    assert_eq!(reply.code, 111);
    assert_eq!(reply.text, "");
}

#[tokio::test]
async fn raw_command_space_separated_reply_preserves_text() {
    let (mut client, _log) = connected_client("111 20261017120000\r\n").await;
    let reply = client.raw_command("DATE").await.expect("valid 111");
    assert_eq!(reply.code, 111);
    assert_eq!(reply.text, "20261017120000");
}
