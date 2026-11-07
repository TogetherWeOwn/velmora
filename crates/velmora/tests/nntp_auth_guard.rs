//! Acceptance tests: `NntpClient::connect_with_auth_guard` runs a
//! synchronous guard immediately before each `AUTHINFO` command.
//!
//! Contract for the implementation:
//!
//! - The guard is called once before `AUTHINFO USER` and once before
//!   `AUTHINFO PASS`, always after the greeting and the `MODE READER`
//!   exchange have completed, so a proof that expires while those replies
//!   are read is caught before any credential leaves the process.
//! - A guard refusal fails `connect_with_auth_guard` with `Error::Io`
//!   carrying the guard's original `ErrorKind` and a fixed, redacted
//!   message: nothing from the guard's own diagnostic is retained. The
//!   refused command is never written, and nothing is written after it.
//! - The guard is never called when no username is configured, or when
//!   setup fails before authentication (broken `MODE READER` exchange).
//! - `connect` behaves as a guard that always allows.
//!
//! Timing is proven with a shared fake clock and revocation flag that the
//! scripted transport advances on a chosen read: no real sleeps, no
//! sockets, and the credentials are synthetic fixtures.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use velmora::error::Error;
use velmora::nntp::{NntpClient, NntpConfig};
use velmora::transport::Transport;

const USER: &str = "fixture-user";
const PASS_SENTINEL: &str = "synthetic-nntp-password-5e2a";
/// Marker placed in the guard's own refusal text; must never surface.
const GUARD_SENTINEL: &str = "guard-diagnostic-sentinel-5e2a";

const GREETING: &str = "200 fixture ready\r\n";
const MODE_REPLY: &str = "200 reader mode on\r\n";
const PASS_REQUIRED: &str = "381 password required\r\n";
const ACCEPTED: &str = "281 authentication accepted\r\n";

/// The proof is valid while the fake clock is below this instant.
const PROOF_EXPIRES_AT: u64 = 100;

// Read indexes in a credentialed handshake; each scripted reply line is
// served by exactly one `read`.
const READ_GREETING: usize = 0;
const READ_MODE_REPLY: usize = 1;
const READ_USER_REPLY: usize = 2;
const READ_PASS_REPLY: usize = 3;

/// Shared fake clock and revocation switch, plus the guard's call count.
#[derive(Clone, Default)]
struct Proof {
    now: Arc<AtomicU64>,
    revoked: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}

impl Proof {
    fn guard(&self) -> impl FnMut() -> io::Result<()> {
        let proof = self.clone();
        move || {
            proof.calls.fetch_add(1, Ordering::SeqCst);
            if proof.revoked.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("revoked {GUARD_SENTINEL}"),
                ));
            }
            if proof.now.load(Ordering::SeqCst) >= PROOF_EXPIRES_AT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("expired {GUARD_SENTINEL}"),
                ));
            }
            Ok(())
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Copy)]
enum Effect {
    /// Advance the fake clock past the proof expiry.
    Expire,
    /// Flip the revocation flag.
    Revoke,
}

/// Scripted transport: one reply line per `read`, a shared write log, and
/// an optional effect applied to the shared proof when a given read runs.
struct Script {
    replies: VecDeque<Vec<u8>>,
    write_log: Arc<Mutex<Vec<String>>>,
    reads: usize,
    effect: Option<(usize, Effect)>,
    proof: Proof,
    /// Fail the read at this index with EOF instead of serving a line.
    eof_at: Option<usize>,
}

impl Script {
    fn new(lines: &[&str], proof: &Proof) -> (Self, Arc<Mutex<Vec<String>>>) {
        let write_log = Arc::new(Mutex::new(Vec::new()));
        (
            Script {
                replies: lines.iter().map(|l| l.as_bytes().to_vec()).collect(),
                write_log: Arc::clone(&write_log),
                reads: 0,
                effect: None,
                proof: proof.clone(),
                eof_at: None,
            },
            write_log,
        )
    }

    fn effect_on_read(mut self, index: usize, effect: Effect) -> Self {
        self.effect = Some((index, effect));
        self
    }

    fn eof_on_read(mut self, index: usize) -> Self {
        self.eof_at = Some(index);
        self
    }
}

impl Transport for Script {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let index = self.reads;
        self.reads += 1;
        if let Some((at, effect)) = self.effect {
            if at == index {
                match effect {
                    Effect::Expire => self.proof.now.store(PROOF_EXPIRES_AT, Ordering::SeqCst),
                    Effect::Revoke => self.proof.revoked.store(true, Ordering::SeqCst),
                }
            }
        }
        if self.eof_at == Some(index) {
            return Ok(0);
        }
        let Some(line) = self.replies.pop_front() else {
            return Ok(0);
        };
        assert!(line.len() <= buf.len(), "scripted line exceeds read buffer");
        buf[..line.len()].copy_from_slice(&line);
        Ok(line.len())
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

fn config(username: Option<&str>, password: Option<&str>) -> NntpConfig {
    NntpConfig {
        host: "nntp.example.com".into(),
        tls: true,
        username: username.map(Into::into),
        password: password.map(Into::into),
        timeout: Duration::from_secs(5),
        max_pipelined: 4,
        ..NntpConfig::default()
    }
}

fn credentialed_config() -> NntpConfig {
    config(Some(USER), Some(PASS_SENTINEL))
}

fn writes(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    log.lock().expect("write log").clone()
}

fn mode_reader() -> String {
    "MODE READER\r\n".to_string()
}

fn auth_user() -> String {
    format!("AUTHINFO USER {USER}\r\n")
}

fn auth_pass() -> String {
    format!("AUTHINFO PASS {PASS_SENTINEL}\r\n")
}

/// Asserts a guard refusal: `Error::Io` with the guard's kind, and no
/// trace of the guard's diagnostic or any credential in any rendering.
fn assert_redacted_refusal(err: &Error, kind: io::ErrorKind) {
    assert!(
        matches!(err, Error::Io(e) if e.kind() == kind),
        "guard refusal must surface as Io/{kind:?}, got {err:?}"
    );
    for rendered in [err.to_string(), format!("{err:?}"), format!("{err:#?}")] {
        for needle in [GUARD_SENTINEL, PASS_SENTINEL, USER] {
            assert!(
                !rendered.contains(needle),
                "refusal retains {needle:?}: {rendered}"
            );
        }
    }
}

// ---------------------------------------------------------------------
// Fresh proof: both gates open.
// ---------------------------------------------------------------------

#[tokio::test]
async fn fresh_proof_gates_user_and_pass() {
    let proof = Proof::default();
    let (script, log) = Script::new(&[GREETING, MODE_REPLY, PASS_REQUIRED, ACCEPTED], &proof);
    NntpClient::connect_with_auth_guard(script, &credentialed_config(), proof.guard())
        .await
        .expect("fresh proof must connect");
    assert_eq!(proof.calls(), 2, "one guard call per AUTHINFO command");
    assert_eq!(writes(&log), vec![mode_reader(), auth_user(), auth_pass()]);
}

#[tokio::test]
async fn fresh_proof_user_only_exchange_gates_once() {
    let proof = Proof::default();
    let (script, log) = Script::new(&[GREETING, MODE_REPLY, ACCEPTED], &proof);
    NntpClient::connect_with_auth_guard(script, &credentialed_config(), proof.guard())
        .await
        .expect("USER-only auth must connect");
    assert_eq!(proof.calls(), 1, "no PASS command, so no second gate");
    assert_eq!(writes(&log), vec![mode_reader(), auth_user()]);
}

#[tokio::test]
async fn expiry_after_last_gate_does_not_fail_connect() {
    let proof = Proof::default();
    let (script, _log) = Script::new(&[GREETING, MODE_REPLY, PASS_REQUIRED, ACCEPTED], &proof);
    // Expiry lands on the PASS reply read, after both gates have passed.
    let script = script.effect_on_read(READ_PASS_REPLY, Effect::Expire);
    NntpClient::connect_with_auth_guard(script, &credentialed_config(), proof.guard())
        .await
        .expect("expiry after the last gate must not fail connect");
    assert_eq!(proof.calls(), 2);
}

// ---------------------------------------------------------------------
// Proof lost before USER: nothing credential-bearing is written.
// ---------------------------------------------------------------------

#[tokio::test]
async fn expiry_while_reading_greeting_blocks_user() {
    let proof = Proof::default();
    let (script, log) = Script::new(&[GREETING, MODE_REPLY, PASS_REQUIRED, ACCEPTED], &proof);
    let script = script.effect_on_read(READ_GREETING, Effect::Expire);
    let Err(err) =
        NntpClient::connect_with_auth_guard(script, &credentialed_config(), proof.guard()).await
    else {
        panic!("expired proof must fail connect");
    };
    assert_redacted_refusal(&err, io::ErrorKind::TimedOut);
    assert_eq!(proof.calls(), 1);
    assert_eq!(writes(&log), vec![mode_reader()], "no USER after expiry");
}

#[tokio::test]
async fn expiry_while_reading_mode_reply_blocks_user() {
    let proof = Proof::default();
    let (script, log) = Script::new(&[GREETING, MODE_REPLY, PASS_REQUIRED, ACCEPTED], &proof);
    let script = script.effect_on_read(READ_MODE_REPLY, Effect::Expire);
    let Err(err) =
        NntpClient::connect_with_auth_guard(script, &credentialed_config(), proof.guard()).await
    else {
        panic!("expired proof must fail connect");
    };
    assert_redacted_refusal(&err, io::ErrorKind::TimedOut);
    assert_eq!(proof.calls(), 1);
    assert_eq!(writes(&log), vec![mode_reader()], "no USER after expiry");
}

#[tokio::test]
async fn already_revoked_blocks_user() {
    let proof = Proof::default();
    proof.revoked.store(true, Ordering::SeqCst);
    let (script, log) = Script::new(&[GREETING, MODE_REPLY, PASS_REQUIRED, ACCEPTED], &proof);
    let Err(err) =
        NntpClient::connect_with_auth_guard(script, &credentialed_config(), proof.guard()).await
    else {
        panic!("revoked proof must fail connect");
    };
    assert_redacted_refusal(&err, io::ErrorKind::PermissionDenied);
    assert_eq!(proof.calls(), 1);
    assert_eq!(writes(&log), vec![mode_reader()], "no USER when revoked");
}

// ---------------------------------------------------------------------
// Proof lost between USER and PASS: the password is never written.
// ---------------------------------------------------------------------

#[tokio::test]
async fn expiry_after_user_reply_blocks_pass() {
    let proof = Proof::default();
    let (script, log) = Script::new(&[GREETING, MODE_REPLY, PASS_REQUIRED, ACCEPTED], &proof);
    let script = script.effect_on_read(READ_USER_REPLY, Effect::Expire);
    let Err(err) =
        NntpClient::connect_with_auth_guard(script, &credentialed_config(), proof.guard()).await
    else {
        panic!("expiry before PASS must fail connect");
    };
    assert_redacted_refusal(&err, io::ErrorKind::TimedOut);
    assert_eq!(proof.calls(), 2);
    assert_eq!(writes(&log), vec![mode_reader(), auth_user()], "no PASS");
}

#[tokio::test]
async fn revocation_after_user_reply_blocks_pass() {
    let proof = Proof::default();
    let (script, log) = Script::new(&[GREETING, MODE_REPLY, PASS_REQUIRED, ACCEPTED], &proof);
    let script = script.effect_on_read(READ_USER_REPLY, Effect::Revoke);
    let Err(err) =
        NntpClient::connect_with_auth_guard(script, &credentialed_config(), proof.guard()).await
    else {
        panic!("revocation before PASS must fail connect");
    };
    assert_redacted_refusal(&err, io::ErrorKind::PermissionDenied);
    assert_eq!(proof.calls(), 2);
    assert_eq!(writes(&log), vec![mode_reader(), auth_user()], "no PASS");
}

// ---------------------------------------------------------------------
// Guard is not consulted when there is nothing to gate.
// ---------------------------------------------------------------------

#[tokio::test]
async fn guard_not_called_without_credentials() {
    let proof = Proof::default();
    // Even a revoked proof cannot matter: no AUTHINFO is ever sent.
    proof.revoked.store(true, Ordering::SeqCst);
    let (script, log) = Script::new(&[GREETING, MODE_REPLY], &proof);
    NntpClient::connect_with_auth_guard(script, &config(None, None), proof.guard())
        .await
        .expect("anonymous connect must not consult the guard");
    assert_eq!(proof.calls(), 0);
    assert_eq!(writes(&log), vec![mode_reader()]);
}

#[tokio::test]
async fn guard_not_called_for_password_without_username() {
    let proof = Proof::default();
    let (script, log) = Script::new(&[GREETING, MODE_REPLY], &proof);
    NntpClient::connect_with_auth_guard(script, &config(None, Some(PASS_SENTINEL)), proof.guard())
        .await
        .expect("no username means no AUTHINFO");
    assert_eq!(proof.calls(), 0);
    assert_eq!(writes(&log), vec![mode_reader()]);
}

#[tokio::test]
async fn guard_not_called_when_mode_reader_exchange_breaks() {
    let proof = Proof::default();
    // EOF on the MODE READER reply read: setup fails before auth.
    let (script, log) = Script::new(&[GREETING], &proof);
    let script = script.eof_on_read(READ_MODE_REPLY);
    let Err(err) =
        NntpClient::connect_with_auth_guard(script, &credentialed_config(), proof.guard()).await
    else {
        panic!("broken MODE READER exchange must fail connect");
    };
    assert!(
        !format!("{err} {err:?}").contains(PASS_SENTINEL),
        "error must not carry credentials: {err}"
    );
    assert_eq!(proof.calls(), 0, "guard must not run before auth");
    assert_eq!(writes(&log), vec![mode_reader()]);
}

#[tokio::test]
async fn guard_not_called_when_mode_reader_reply_is_malformed() {
    let proof = Proof::default();
    let (script, log) = Script::new(
        &[GREETING, "WELCOME FRIEND\r\n", PASS_REQUIRED, ACCEPTED],
        &proof,
    );
    let Err(err) =
        NntpClient::connect_with_auth_guard(script, &credentialed_config(), proof.guard()).await
    else {
        panic!("malformed MODE READER reply must fail connect");
    };
    assert!(matches!(err, Error::Malformed(_)), "got {err:?}");
    assert_eq!(proof.calls(), 0);
    assert_eq!(writes(&log), vec![mode_reader()]);
}

// ---------------------------------------------------------------------
// Compatibility: plain `connect` is an always-allow guard.
// ---------------------------------------------------------------------

#[tokio::test]
async fn plain_connect_ignores_revoked_proof() {
    let proof = Proof::default();
    proof.revoked.store(true, Ordering::SeqCst);
    let (script, log) = Script::new(&[GREETING, MODE_REPLY, PASS_REQUIRED, ACCEPTED], &proof);
    NntpClient::connect(script, &credentialed_config())
        .await
        .expect("connect has no guard to refuse it");
    assert_eq!(proof.calls(), 0);
    assert_eq!(writes(&log), vec![mode_reader(), auth_user(), auth_pass()]);
}
