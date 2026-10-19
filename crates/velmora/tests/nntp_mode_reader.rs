//! Acceptance tests: a broken `MODE READER` exchange must fail
//! `NntpClient::connect`, while any well-formed reply stays tolerated.
//!
//! Contract for the implementation:
//!
//! - A `MODE READER` write error, read error, EOF, transport timeout or
//!   malformed (non-`NNN`) reply makes `connect` return `Err` — it must
//!   never hand back a client whose session state is unknown.
//! - Any well-formed reply code to `MODE READER` (200, 480, 482, 500, …)
//!   remains best-effort tolerated, exactly as today: no code is
//!   required, and reply-code classification does not change.
//! - After a failed `MODE READER` exchange, no further command
//!   (`AUTHINFO` or anything else) is issued on the transport.
//! - Existing successful `AUTHINFO` sequencing and error redaction are
//!   preserved.
//!
//! All tests run over scripted in-memory transports: no sockets, no
//! real credentials (the synthetic password below is a fixture).

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nntune_core::error::Error;
use nntune_core::nntp::{NntpClient, NntpConfig};
use nntune_core::transport::Transport;

const GREETING: &str = "200 news.example.com ready\r\n";
const SYNTHETIC_PASSWORD: &str = "synthetic-fixture-password";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadFailure {
    /// `read` returns `Ok(0)`: clean EOF.
    Eof,
    /// `read` returns an error of this kind.
    Error(io::ErrorKind),
}

/// Scripted transport with a shared write log (so command sequencing can
/// be asserted even when `connect` fails and consumes the transport)
/// plus injectable read/write failures positioned after the greeting.
struct Script {
    to_client: VecDeque<u8>,
    write_log: Arc<Mutex<Vec<String>>>,
    /// Serve at most this many bytes in total, then apply `read_failure`
    /// on the next read. `None` serves the whole script.
    read_cap: Option<usize>,
    served: usize,
    read_failure: ReadFailure,
    /// 0-based index of the `write_all` call that fails, if any.
    fail_write_at: Option<usize>,
    write_error_kind: io::ErrorKind,
    writes: usize,
}

impl Script {
    fn new(readable: &str) -> (Self, Arc<Mutex<Vec<String>>>) {
        let write_log = Arc::new(Mutex::new(Vec::new()));
        (
            Script {
                to_client: readable.bytes().collect(),
                write_log: Arc::clone(&write_log),
                read_cap: None,
                served: 0,
                read_failure: ReadFailure::Eof,
                fail_write_at: None,
                write_error_kind: io::ErrorKind::BrokenPipe,
                writes: 0,
            },
            write_log,
        )
    }

    /// Greeting reads normally; the first read past it fails as given.
    fn fail_mode_reader_read(mut self, failure: ReadFailure) -> Self {
        self.read_cap = Some(GREETING.len());
        self.read_failure = failure;
        self
    }

    /// The `MODE READER` write (the first write) fails with `kind`.
    fn fail_mode_reader_write(mut self, kind: io::ErrorKind) -> Self {
        self.fail_write_at = Some(0);
        self.write_error_kind = kind;
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
                ReadFailure::Eof => Ok(0),
                ReadFailure::Error(kind) => Err(io::Error::new(kind, "scripted read failure")),
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
        let index = self.writes;
        self.writes += 1;
        if self.fail_write_at == Some(index) {
            return Err(io::Error::new(
                self.write_error_kind,
                "scripted write failure",
            ));
        }
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

/// Runs a broken-MODE-READER scenario and asserts: `connect` fails,
/// exactly `expected_writes` were attempted, and no `AUTHINFO` (or
/// later command) ever reached the transport.
async fn assert_connect_fails_without_further_commands(
    script: Script,
    log: Arc<Mutex<Vec<String>>>,
    config: &NntpConfig,
) -> Error {
    let Err(err) = NntpClient::connect(script, config).await else {
        panic!("broken MODE READER exchange must fail connect, got Ok(client)");
    };
    assert_eq!(
        writes(&log),
        vec!["MODE READER\r\n".to_string()],
        "no command after the failed MODE READER exchange may be issued"
    );
    assert!(
        !format!("{err} {err:?}").contains(SYNTHETIC_PASSWORD),
        "error must never carry credential material: {err}"
    );
    err
}

// ---------------------------------------------------------------------
// Broken exchanges, no credentials configured. These are the sharpest
// cases: with nothing after MODE READER, a discarded error returns a
// seemingly usable client.
// ---------------------------------------------------------------------

#[tokio::test]
async fn mode_reader_write_failure_fails_connect_without_credentials() {
    let (script, log) = Script::new(GREETING);
    let err = assert_connect_fails_without_further_commands(
        script.fail_mode_reader_write(io::ErrorKind::BrokenPipe),
        log,
        &config_without_credentials(),
    )
    .await;
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::BrokenPipe),
        "transport write error must surface as Io, got {err:?}"
    );
}

#[tokio::test]
async fn mode_reader_write_timeout_fails_connect_without_credentials() {
    let (script, log) = Script::new(GREETING);
    let err = assert_connect_fails_without_further_commands(
        script.fail_mode_reader_write(io::ErrorKind::TimedOut),
        log,
        &config_without_credentials(),
    )
    .await;
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::TimedOut),
        "write timeout must surface as Io/TimedOut, got {err:?}"
    );
}

#[tokio::test]
async fn mode_reader_reply_eof_fails_connect_without_credentials() {
    let (script, log) = Script::new(GREETING);
    assert_connect_fails_without_further_commands(
        script.fail_mode_reader_read(ReadFailure::Eof),
        log,
        &config_without_credentials(),
    )
    .await;
}

#[tokio::test]
async fn mode_reader_reply_read_error_fails_connect_without_credentials() {
    let (script, log) = Script::new(GREETING);
    let err = assert_connect_fails_without_further_commands(
        script.fail_mode_reader_read(ReadFailure::Error(io::ErrorKind::ConnectionReset)),
        log,
        &config_without_credentials(),
    )
    .await;
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::ConnectionReset),
        "transport read error must surface as Io, got {err:?}"
    );
}

#[tokio::test]
async fn mode_reader_reply_timeout_fails_connect_without_credentials() {
    let (script, log) = Script::new(GREETING);
    let err = assert_connect_fails_without_further_commands(
        script.fail_mode_reader_read(ReadFailure::Error(io::ErrorKind::TimedOut)),
        log,
        &config_without_credentials(),
    )
    .await;
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::TimedOut),
        "read timeout must surface as Io/TimedOut, got {err:?}"
    );
}

#[tokio::test]
async fn mode_reader_reply_eof_mid_line_fails_connect_without_credentials() {
    // Partial reply line, then EOF before any CRLF: framing is broken,
    // so session state is unknowable.
    let (script, log) = Script::new(&format!("{GREETING}200 mode rea"));
    assert_connect_fails_without_further_commands(script, log, &config_without_credentials()).await;
}

#[tokio::test]
async fn mode_reader_malformed_reply_fails_connect_without_credentials() {
    let (script, log) = Script::new(&format!("{GREETING}WELCOME FRIEND\r\n"));
    let err =
        assert_connect_fails_without_further_commands(script, log, &config_without_credentials())
            .await;
    assert!(
        matches!(err, Error::Malformed(_)),
        "non-numeric reply must surface as Malformed, got {err:?}"
    );
}

#[tokio::test]
async fn mode_reader_short_reply_fails_connect_without_credentials() {
    let (script, log) = Script::new(&format!("{GREETING}20\r\n"));
    let err =
        assert_connect_fails_without_further_commands(script, log, &config_without_credentials())
            .await;
    assert!(
        matches!(err, Error::Malformed(_)),
        "truncated reply code must surface as Malformed, got {err:?}"
    );
}

#[tokio::test]
async fn mode_reader_empty_reply_line_fails_connect_without_credentials() {
    let (script, log) = Script::new(&format!("{GREETING}\r\n"));
    assert_connect_fails_without_further_commands(script, log, &config_without_credentials()).await;
}

#[tokio::test]
async fn mode_reader_overlong_reply_line_fails_connect_without_credentials() {
    // Exceeds the transport's per-line framing limit without a CRLF.
    let readable = format!("{GREETING}{}", "2".repeat(20 * 1024));
    let (script, log) = Script::new(&readable);
    let err =
        assert_connect_fails_without_further_commands(script, log, &config_without_credentials())
            .await;
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::InvalidData),
        "framing-limit breach must surface as Io/InvalidData, got {err:?}"
    );
}

// ---------------------------------------------------------------------
// Broken exchanges with credentials configured: connect must fail AND
// AUTHINFO must not be issued into an unknown session state. Only the
// malformed-reply case scripts waiting 381/281 replies (a desync case:
// they answer a session whose framing already broke); the write-failure,
// EOF, and timeout cases fail with nothing scripted after the greeting.
// ---------------------------------------------------------------------

#[tokio::test]
async fn mode_reader_malformed_reply_fails_connect_with_credentials() {
    let (script, log) = Script::new(&format!(
        "{GREETING}WELCOME FRIEND\r\n381 more authentication required\r\n281 authentication accepted\r\n"
    ));
    let err =
        assert_connect_fails_without_further_commands(script, log, &config_with_credentials())
            .await;
    assert!(
        matches!(err, Error::Malformed(_)),
        "non-numeric reply must surface as Malformed, got {err:?}"
    );
}

#[tokio::test]
async fn mode_reader_write_failure_fails_connect_with_credentials() {
    let (script, log) = Script::new(GREETING);
    assert_connect_fails_without_further_commands(
        script.fail_mode_reader_write(io::ErrorKind::BrokenPipe),
        log,
        &config_with_credentials(),
    )
    .await;
}

#[tokio::test]
async fn mode_reader_reply_eof_fails_connect_with_credentials() {
    let (script, log) = Script::new(GREETING);
    assert_connect_fails_without_further_commands(
        script.fail_mode_reader_read(ReadFailure::Eof),
        log,
        &config_with_credentials(),
    )
    .await;
}

#[tokio::test]
async fn mode_reader_reply_timeout_fails_connect_with_credentials() {
    let (script, log) = Script::new(GREETING);
    let err = assert_connect_fails_without_further_commands(
        script.fail_mode_reader_read(ReadFailure::Error(io::ErrorKind::TimedOut)),
        log,
        &config_with_credentials(),
    )
    .await;
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::TimedOut),
        "read timeout must surface as Io/TimedOut, got {err:?}"
    );
}

// ---------------------------------------------------------------------
// Positive controls: well-formed replies of any code stay tolerated
// under the existing best-effort contract, and successful AUTHINFO
// sequencing is unchanged.
// ---------------------------------------------------------------------

#[tokio::test]
async fn mode_reader_200_succeeds_without_credentials() {
    let (script, log) = Script::new(&format!("{GREETING}200 reader mode on\r\n"));
    NntpClient::connect(script, &config_without_credentials())
        .await
        .expect("200 MODE READER reply must connect");
    assert_eq!(writes(&log), vec!["MODE READER\r\n".to_string()]);
}

#[tokio::test]
async fn mode_reader_500_stays_tolerated_without_credentials() {
    let (script, log) = Script::new(&format!("{GREETING}500 MODE READER unsupported\r\n"));
    NntpClient::connect(script, &config_without_credentials())
        .await
        .expect("well-formed 500 must stay tolerated");
    assert_eq!(writes(&log), vec!["MODE READER\r\n".to_string()]);
}

#[tokio::test]
async fn mode_reader_500_stays_tolerated_then_authinfo_succeeds() {
    let (script, log) = Script::new(&format!(
        "{GREETING}500 MODE READER unsupported\r\n381 more authentication required\r\n281 authentication accepted\r\n"
    ));
    NntpClient::connect(script, &config_with_credentials())
        .await
        .expect("well-formed 500 must stay tolerated and auth must proceed");
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
async fn mode_reader_482_stays_tolerated_then_authinfo_succeeds() {
    let (script, log) = Script::new(&format!(
        "{GREETING}482 authentication commands out of sequence\r\n381 more authentication required\r\n281 authentication accepted\r\n"
    ));
    NntpClient::connect(script, &config_with_credentials())
        .await
        .expect("well-formed 482 must stay tolerated and auth must proceed");
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
async fn mode_reader_480_stays_tolerated_then_authinfo_succeeds() {
    // Provider demands authentication next: the well-formed 480 reply
    // to MODE READER does not fail setup; AUTHINFO follows as usual.
    let (script, log) = Script::new(&format!(
        "{GREETING}480 authentication required\r\n381 more authentication required\r\n281 authentication accepted\r\n"
    ));
    NntpClient::connect(script, &config_with_credentials())
        .await
        .expect("well-formed 480 must stay tolerated and auth must proceed");
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
async fn mode_reader_200_then_authinfo_succeeds() {
    let (script, log) = Script::new(&format!(
        "{GREETING}200 reader mode on\r\n381 more authentication required\r\n281 authentication accepted\r\n"
    ));
    NntpClient::connect(script, &config_with_credentials())
        .await
        .expect("200 MODE READER reply must connect and auth must proceed");
    assert_eq!(
        writes(&log),
        vec![
            "MODE READER\r\n".to_string(),
            "AUTHINFO USER fixture-user\r\n".to_string(),
            format!("AUTHINFO PASS {SYNTHETIC_PASSWORD}\r\n"),
        ]
    );
}
