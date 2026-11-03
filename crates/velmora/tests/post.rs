//! `POST` state machine over the scripted in-memory transport.
//!
//! Covers the re-post pipeline contract: `340`/`240` success with exact
//! dot-stuffed bytes on the wire (including a leading `.` on the first body
//! line, which the yEnc layer never escapes), `435`/`441` duplicates
//! confirmed via `STAT` (present counts as success, missing surfaces the
//! original duplicate code for a same-ID re-post), `440` prohibited, `480`
//! stale credentials, generic refusals, fail-closed framing validation, and
//! the stale-connection-only retry policy. All IDs, subjects and groups are
//! synthetic placeholders. No real provider is contacted.

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

use nntune_core::error::Error;
use nntune_core::nntp::{is_retryable_post_error, PostOutcome, MAX_POST_ATTEMPTS};
use nntune_core::nntp::{NntpClient, NntpConfig};
use nntune_core::transport::Transport;

/// Scripted transport: reads come from `to_client`, writes are asserted
/// against `expect_writes` in order (same harness as `tests/nntp.rs`).
struct Script {
    to_client: VecDeque<u8>,
    expect_writes: VecDeque<Vec<u8>>,
}

impl Script {
    fn new(readable: &str, writes: &[&str]) -> Self {
        Script {
            to_client: readable.as_bytes().iter().cloned().collect(),
            expect_writes: writes.iter().map(|w| w.as_bytes().to_vec()).collect(),
        }
    }
}

impl Transport for Script {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.to_client.len());
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "script exhausted",
            ));
        }
        for (i, slot) in buf[..n].iter_mut().enumerate() {
            *slot = self.to_client[i];
        }
        self.to_client.drain(..n);
        Ok(n)
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self.expect_writes.pop_front() {
            Some(want) => {
                assert_eq!(buf, &want, "client sent unexpected bytes");
                Ok(())
            }
            None => panic!("client wrote unexpected {:?}", String::from_utf8_lossy(buf)),
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn config() -> NntpConfig {
    NntpConfig {
        host: "nntp.example.com".into(),
        tls: true,
        username: Some("user".into()),
        password: Some("pass".into()),
        timeout: Duration::from_secs(5),
        max_pipelined: 4,
        ..NntpConfig::default()
    }
}

// Server answers 281 to AUTHINFO USER directly (no password round-trip).
const HANDSHAKE: &str = "200 ready\r\n500 no\r\n281 ok\r\n";
const HANDSHAKE_WRITES: &[&str] = &["MODE READER\r\n", "AUTHINFO USER user\r\n"];

async fn connected(script: Script) -> NntpClient<Script> {
    NntpClient::connect(script, &config())
        .await
        .expect("handshake")
}

const ARTICLE: &str = "From: poster@example.invalid\r\n\
    Subject: synthetic-post-001\r\n\
    Newsgroups: example.test.posting\r\n\
    Message-ID: <post-id-001@example.invalid>\r\n\
    Date: Tue, 03 Nov 2026 12:00:00 +0000\r\n\
    \r\n\
    =ybegin line=128 size=11 name=abcdefgh\r\n\
    .leading-dot-body-line\r\n\
    plain-body-line\r\n\
    .\r\n\
    =yend size=11 crc32=00000000\r\n";

/// `ARTICLE` with the first body line starting with `.` and a lone-dot body
/// line, dot-stuffed, plus the `.` terminator.
const STUFFED: &str = "From: poster@example.invalid\r\n\
    Subject: synthetic-post-001\r\n\
    Newsgroups: example.test.posting\r\n\
    Message-ID: <post-id-001@example.invalid>\r\n\
    Date: Tue, 03 Nov 2026 12:00:00 +0000\r\n\
    \r\n\
    =ybegin line=128 size=11 name=abcdefgh\r\n\
    ..leading-dot-body-line\r\n\
    plain-body-line\r\n\
    ..\r\n\
    =yend size=11 crc32=00000000\r\n\
    .\r\n";

#[tokio::test]
async fn post_success_sends_stuffed_article_and_stays_usable() {
    let script = Script::new(
        &format!("{HANDSHAKE}340 send article\r\n240 article received\r\n223 7 <post-id-001@example.invalid>\r\n"),
        &[HANDSHAKE_WRITES, &["POST\r\n", STUFFED], &["STAT <post-id-001@example.invalid>\r\n"]].concat(),
    );
    let mut client = connected(script).await;
    let outcome = client
        .post_article("post-id-001@example.invalid", ARTICLE.as_bytes())
        .await
        .expect("post succeeds");
    assert_eq!(outcome, PostOutcome::Posted);
    // A well-formed 240 reply leaves the connection at a command boundary.
    assert_eq!(client.stat("post-id-001@example.invalid").await.unwrap(), 7);
    let script = client.into_inner();
    assert!(script.expect_writes.is_empty(), "all writes consumed");
}

#[tokio::test]
async fn post_appends_terminator_when_article_lacks_trailing_crlf() {
    let article = "From: poster@example.invalid\r\n\r\nbody-without-trailer";
    let script = Script::new(
        &format!("{HANDSHAKE}340 send article\r\n240 ok\r\n"),
        &[
            HANDSHAKE_WRITES,
            &[
                "POST\r\n",
                "From: poster@example.invalid\r\n\r\nbody-without-trailer\r\n.\r\n",
            ],
        ]
        .concat(),
    );
    let mut client = connected(script).await;
    let outcome = client
        .post_article("post-id-002@example.invalid", article.as_bytes())
        .await
        .expect("post succeeds");
    assert_eq!(outcome, PostOutcome::Posted);
}

#[tokio::test]
async fn duplicate_441_confirmed_by_stat_counts_as_success() {
    // The 441 answers the bare POST itself ("already have it, do not
    // send"): the article bytes never go on the wire; STAT confirms.
    let script = Script::new(
        &format!("{HANDSHAKE}441 duplicate\r\n223 9 <post-id-001@example.invalid> stored\r\n"),
        &[
            HANDSHAKE_WRITES,
            &["POST\r\n", "STAT <post-id-001@example.invalid>\r\n"],
        ]
        .concat(),
    );
    let mut client = connected(script).await;
    let outcome = client
        .post_article("post-id-001@example.invalid", ARTICLE.as_bytes())
        .await
        .expect("confirmed duplicate counts as success");
    assert_eq!(outcome, PostOutcome::Duplicate);
}

#[tokio::test]
async fn duplicate_after_send_confirmed_by_stat() {
    // The duplicate verdict can also arrive after the article bytes (340,
    // send, 441): STAT still confirms and the outcome is Duplicate.
    let script = Script::new(
        &format!("{HANDSHAKE}340 send article\r\n441 duplicate\r\n223 9 <post-id-001@example.invalid> stored\r\n"),
        &[
            HANDSHAKE_WRITES,
            &["POST\r\n", STUFFED],
            &["STAT <post-id-001@example.invalid>\r\n"],
        ]
        .concat(),
    );
    let mut client = connected(script).await;
    let outcome = client
        .post_article("post-id-001@example.invalid", ARTICLE.as_bytes())
        .await
        .expect("confirmed post-send duplicate counts as success");
    assert_eq!(outcome, PostOutcome::Duplicate);
}

#[tokio::test]
async fn duplicate_435_with_missing_stat_surfaces_original_code() {
    // The server claims a duplicate it does not have (430 on STAT): the
    // original 435 is returned so the verify stage can re-post the same ID.
    // Like the 441 case, the 435 answers the bare POST, so no article bytes
    // are written.
    let script = Script::new(
        &format!("{HANDSHAKE}435 duplicate\r\n430 no such article\r\n"),
        &[
            HANDSHAKE_WRITES,
            &["POST\r\n", "STAT <post-id-001@example.invalid>\r\n"],
        ]
        .concat(),
    );
    let mut client = connected(script).await;
    let err = client
        .post_article("post-id-001@example.invalid", ARTICLE.as_bytes())
        .await
        .expect_err("unconfirmed duplicate must fail");
    assert!(
        matches!(err, Error::NntpReply { code: 435, .. }),
        "got {err}"
    );
}

#[tokio::test]
async fn initial_post_refusals_map_to_typed_errors() {
    // 440 to the bare POST: prohibited, connection stays usable.
    let script = Script::new(
        &format!("{HANDSHAKE}440 posting not allowed\r\n223 1 <a@example.invalid>\r\n"),
        &[
            HANDSHAKE_WRITES,
            &["POST\r\n", "STAT <a@example.invalid>\r\n"],
        ]
        .concat(),
    );
    let mut client = connected(script).await;
    let err = client
        .post_article("a@example.invalid", ARTICLE.as_bytes())
        .await
        .expect_err("440 must fail");
    assert!(matches!(err, Error::PostProhibited(_)), "got {err}");
    assert!(!err.is_auth_failure());
    for rendered in [err.to_string(), format!("{err:?}")] {
        assert!(
            !rendered.contains("posting not allowed"),
            "440 reply text echoed: {rendered}"
        );
    }
    client.stat("a@example.invalid").await.unwrap();

    // 480 to the bare POST: stale credentials.
    let script = Script::new(
        &format!("{HANDSHAKE}480 authentication required\r\n"),
        &[HANDSHAKE_WRITES, &["POST\r\n"]].concat(),
    );
    let mut client = connected(script).await;
    let err = client
        .post_article("a@example.invalid", ARTICLE.as_bytes())
        .await
        .expect_err("480 must fail");
    assert!(matches!(err, Error::AuthFailed(_)), "got {err}");
    assert!(err.is_auth_failure());

    // Anything else is a generic protocol error.
    let script = Script::new(
        &format!("{HANDSHAKE}500 unknown\r\n"),
        &[HANDSHAKE_WRITES, &["POST\r\n"]].concat(),
    );
    let mut client = connected(script).await;
    let err = client
        .post_article("a@example.invalid", ARTICLE.as_bytes())
        .await
        .expect_err("500 must fail");
    assert!(
        matches!(err, Error::NntpReply { code: 500, .. }),
        "got {err}"
    );
    assert!(!is_retryable_post_error(&err));
}

#[tokio::test]
async fn bare_post_240_is_a_protocol_error_not_success() {
    // A 240 to the bare POST answers before any article byte is sent:
    // reporting Posted would record an article that never went on the
    // wire (RFC 3977 admits only 340/440 as the initial POST reply).
    // It must surface as a generic reply error with zero article bytes
    // written, leaving the connection usable.
    let script = Script::new(
        &format!("{HANDSHAKE}240 premature ok\r\n223 1 <a@example.invalid>\r\n"),
        &[
            HANDSHAKE_WRITES,
            &["POST\r\n", "STAT <a@example.invalid>\r\n"],
        ]
        .concat(),
    );
    let mut client = connected(script).await;
    let err = client
        .post_article("a@example.invalid", ARTICLE.as_bytes())
        .await
        .expect_err("bare-POST 240 must fail");
    assert!(
        matches!(err, Error::NntpReply { code: 240, .. }),
        "got {err}"
    );
    assert!(!is_retryable_post_error(&err));
    // Well-formed reply at a command boundary: still usable.
    client.stat("a@example.invalid").await.unwrap();
    let script = client.into_inner();
    assert!(script.expect_writes.is_empty(), "all writes consumed");
}

#[tokio::test]
async fn framing_refusals_write_nothing() {
    // Empty article, bare LF, and a delimiter-escaping Message-ID are all
    // refused before any POST byte reaches the wire.
    for (id, article) in [
        ("a@example.invalid", ""),
        (
            "a@example.invalid",
            "From: x@example.invalid\r\n\r\nbare\nlf\r\n",
        ),
        (
            "a@example.invalid",
            "From: x@example.invalid\r\n\r\nbare\rcr\r\n",
        ),
        ("not an id", ARTICLE),
    ] {
        let script = Script::new(HANDSHAKE, HANDSHAKE_WRITES);
        let mut client = connected(script).await;
        let err = client
            .post_article(id, article.as_bytes())
            .await
            .expect_err("must refuse");
        assert!(matches!(err, Error::Malformed(_)), "got {err} for {id:?}");
        let script = client.into_inner();
        assert!(
            script.expect_writes.is_empty(),
            "refused post wrote bytes for {id:?}"
        );
    }
}

#[tokio::test]
async fn stale_connection_is_retryable_and_poisoned() {
    // EOF after the 340: the server may or may not have the article — the
    // connection is unusable, the error is retryable, and a second try on
    // the same client fails without touching the wire.
    let script = Script::new(
        &format!("{HANDSHAKE}340 send article\r\n"),
        &[HANDSHAKE_WRITES, &["POST\r\n", STUFFED]].concat(),
    );
    let mut client = connected(script).await;
    let err = client
        .post_article("post-id-001@example.invalid", ARTICLE.as_bytes())
        .await
        .expect_err("EOF must fail");
    assert!(matches!(err, Error::Io(_)), "got {err}");
    assert!(is_retryable_post_error(&err));
    let err2 = client
        .post_article("post-id-001@example.invalid", ARTICLE.as_bytes())
        .await
        .expect_err("poisoned connection must fail");
    assert!(matches!(err2, Error::Io(_)), "got {err2}");
}

#[test]
fn retry_policy_only_stale_connections() {
    assert_eq!(MAX_POST_ATTEMPTS, 3);
    let retryable = [
        Error::Io(io::Error::new(io::ErrorKind::TimedOut, "deadline")),
        Error::Io(io::Error::new(io::ErrorKind::ConnectionReset, "reset")),
        Error::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "eof")),
    ];
    for err in &retryable {
        assert!(is_retryable_post_error(err), "must be retryable: {err}");
    }
    let fatal = [
        Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "NNTP article exceeds byte limit",
        )),
        Error::NntpReply {
            code: 441,
            text: "dup".into(),
        },
        Error::PostProhibited("440".into()),
        Error::AuthFailed("480".into()),
        Error::NoPermission("502".into()),
        Error::ArticleNotFound("a@example.invalid".into()),
        Error::Malformed("bad".into()),
    ];
    for err in &fatal {
        assert!(!is_retryable_post_error(err), "must not retry: {err}");
    }
}
