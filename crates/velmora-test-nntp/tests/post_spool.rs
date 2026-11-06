//! `POST` spool + runtime article hiding acceptance.
//!
//! Proves the M2 stage-test / B7-leg contract: POST round-trips into
//! ARTICLE/BODY/HEAD/STAT, duplicates are rejected, hidden IDs read 430
//! until unhidden, and two instances hold fully independent spools.
//! Synthetic content only; no checked-in NZBs.

use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use velmora_test_nntp::{ServerConfig, TestNntpServer};

/// Fail fast instead of hanging to the CI job timeout when the server stops
/// replying with the socket still open.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Client {
    async fn connect(server: &TestNntpServer) -> Self {
        let stream = TcpStream::connect(server.addr()).await.unwrap();
        let (r, w) = stream.into_split();
        let mut c = Self {
            reader: BufReader::new(r),
            writer: w,
        };
        let greeting = c.read_line().await;
        assert!(greeting.starts_with("200"), "greeting: {greeting:?}");
        c
    }

    async fn read_line(&mut self) -> String {
        let mut s = String::new();
        let n = tokio::time::timeout(READ_TIMEOUT, self.reader.read_line(&mut s))
            .await
            .expect("timed out waiting for a response line")
            .unwrap();
        assert!(n > 0, "connection closed while reading line");
        s
    }

    async fn cmd(&mut self, cmd: &str) -> String {
        self.writer
            .write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .unwrap();
        self.read_line().await
    }

    /// Send a command, return (first line, dot-terminated block, unstuffed).
    async fn cmd_block(&mut self, cmd: &str) -> (String, Vec<u8>) {
        self.writer
            .write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .unwrap();
        let first = self.read_line().await;
        (first, Self::read_block(&mut self.reader).await)
    }

    async fn read_block(reader: &mut BufReader<OwnedReadHalf>) -> Vec<u8> {
        let mut raw = Vec::new();
        loop {
            let mut line: Vec<u8> = Vec::new();
            let n = tokio::time::timeout(READ_TIMEOUT, reader.read_until(b'\n', &mut line))
                .await
                .expect("timed out waiting for a block line")
                .unwrap();
            assert!(n > 0, "connection closed mid-block");
            if line.ends_with(b"\n") {
                line.pop();
                if line.ends_with(b"\r") {
                    line.pop();
                }
            }
            if line == b"." {
                break;
            }
            if line.starts_with(b"..") {
                raw.extend_from_slice(&line[1..]);
            } else {
                raw.extend_from_slice(&line);
            }
            raw.extend_from_slice(b"\r\n");
        }
        raw
    }

    async fn auth(&mut self, user: &str, pass: &str) -> (String, String) {
        let u = self.cmd(&format!("AUTHINFO USER {user}")).await;
        let p = self.cmd(&format!("AUTHINFO PASS {pass}")).await;
        (u, p)
    }

    /// Full `POST` exchange: `POST` -> 340, then article lines + `.`.
    /// Lines must already be dot-stuffed by the caller where needed.
    async fn post(&mut self, lines: &[&str]) -> String {
        let raw: Vec<&[u8]> = lines.iter().map(|s| s.as_bytes()).collect();
        self.post_raw(&raw).await
    }

    /// Byte-oriented `POST` for non-UTF-8 bodies (yEnc): raw lines + `.`.
    async fn post_raw(&mut self, lines: &[&[u8]]) -> String {
        self.writer.write_all(b"POST\r\n").await.unwrap();
        let go = self.read_line().await;
        assert!(go.starts_with("340"), "POST greeting: {go:?}");
        for line in lines {
            self.writer.write_all(line).await.unwrap();
            self.writer.write_all(b"\r\n").await.unwrap();
        }
        self.writer.write_all(b".\r\n").await.unwrap();
        self.read_line().await
    }
}

fn article_lines(id: &str, subject: &str, body: &[&str]) -> Vec<String> {
    let mut lines = vec![
        "From: poster@nntune.test".to_string(),
        "Newsgroups: alt.binaries.nntune.test".to_string(),
        format!("Subject: {subject}"),
        "Date: Mon, 13 Oct 2026 00:00:00 +0000".to_string(),
        format!("Message-ID: {id}"),
        String::new(),
    ];
    lines.extend(body.iter().map(|s| s.to_string()));
    lines
}

#[tokio::test]
async fn post_then_stat_article_round_trip() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let id = "<roundtrip-001@nntune.test>";
    let reply = c
        .post(
            &article_lines(id, "roundtrip", &["hello spool"])
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
        )
        .await;
    assert!(reply.starts_with("240"), "got {reply:?}");
    assert!(reply.contains(id), "240 names the ID: {reply:?}");

    let s = c.cmd(&format!("STAT {id}")).await;
    assert!(s.starts_with("223"), "got {s:?}");

    let (first, block) = c.cmd_block(&format!("ARTICLE {id}")).await;
    assert!(first.starts_with("220"), "got {first:?}");
    let text = String::from_utf8_lossy(&block);
    assert!(text.contains("hello spool"), "body missing: {text:?}");

    let (head_first, head) = c.cmd_block(&format!("HEAD {id}")).await;
    assert!(head_first.starts_with("221"), "got {head_first:?}");
    assert!(String::from_utf8_lossy(&head).contains("Subject: roundtrip"));

    let (body_first, body) = c.cmd_block(&format!("BODY {id}")).await;
    assert!(body_first.starts_with("222"), "got {body_first:?}");
    let body_text = String::from_utf8_lossy(&body);
    assert!(
        body_text.contains("hello spool"),
        "BODY missing body: {body_text:?}"
    );
    assert!(
        !body_text.contains("Subject: roundtrip"),
        "BODY sent headers: {body_text:?}"
    );

    assert_eq!(server.posted_count().await, 1);
    assert!(server.is_stored(id).await);
    assert_eq!(server.posted_ids().await, vec![id.to_string()]);
}

#[tokio::test]
async fn duplicate_post_gets_435_and_stores_once() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    // Re-posting a fixture corpus ID is a duplicate.
    let dup = c
        .post(
            &article_lines("<single-yenc-001@nntune.test>", "dup", &["x"])
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
        )
        .await;
    assert!(dup.starts_with("435"), "corpus re-post: got {dup:?}");

    // So is re-posting an ID this spool already accepted.
    let id = "<dup-posted-001@nntune.test>";
    let lines: Vec<String> = article_lines(id, "dup", &["first"]);
    let first = c
        .post(&lines.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .await;
    assert!(first.starts_with("240"), "got {first:?}");
    let second = c
        .post(&lines.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .await;
    assert!(second.starts_with("435"), "re-post: got {second:?}");

    assert_eq!(server.posted_count().await, 1);
    assert_eq!(server.posted_count_for(&[id]).await, 1);
}

#[tokio::test]
async fn post_dot_unstuffing_round_trip() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let id = "<dot-001@nntune.test>";
    // NNTP sender stuffing: content line ".leading" travels as "..leading".
    let reply = c
        .post(&[
            "From: poster@nntune.test",
            "Newsgroups: alt.binaries.nntune.test",
            "Subject: dots",
            "Date: Mon, 13 Oct 2026 00:00:00 +0000",
            &format!("Message-ID: {id}"),
            "",
            "..leading",
            "plain",
        ])
        .await;
    assert!(reply.starts_with("240"), "got {reply:?}");

    let (first, block) = c.cmd_block(&format!("ARTICLE {id}")).await;
    assert!(first.starts_with("220"), "got {first:?}");
    // Client-side unstuffing must recover the single-dot content line.
    let text = String::from_utf8_lossy(&block);
    assert!(text.contains("\r\n.leading\r\n"), "dot line lost: {text:?}");
    assert!(!text.contains("..leading"), "double-stuffed: {text:?}");
}

#[tokio::test]
async fn post_binary_body_round_trip_byte_exact() {
    // yEnc bodies are arbitrary bytes: the server must never decode them as
    // UTF-8 mid-transfer, and ARTICLE must serve them back byte-identical.
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let id = "<binary-001@nntune.test>";
    let binary: Vec<u8> = (0x80u8..=0xFF).collect();
    let mut lines: Vec<&[u8]> = vec![
        b"From: poster@nntune.test",
        b"Newsgroups: alt.binaries.nntune.test",
        b"Subject: binary",
        b"Date: Mon, 13 Oct 2026 00:00:00 +0000",
        b"Message-ID: <binary-001@nntune.test>",
        b"",
    ];
    lines.push(&binary);
    let reply = c.post_raw(&lines).await;
    assert!(reply.starts_with("240"), "got {reply:?}");

    let (first, block) = c.cmd_block(&format!("ARTICLE {id}")).await;
    assert!(first.starts_with("220"), "got {first:?}");
    let sep = block
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header sep");
    assert_eq!(&block[sep + 4..block.len() - 2], binary.as_slice());
}

#[tokio::test]
async fn hidden_ids_stat_430_and_unhide_restores() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let id = "<single-yenc-001@nntune.test>";
    let ok = c.cmd(&format!("STAT {id}")).await;
    assert!(ok.starts_with("223"), "pre-hide: {ok:?}");

    // Resolve the article number via XOVER (needs a selected group).
    let g = c.cmd("GROUP alt.binaries.nntune.test").await;
    assert!(g.starts_with("211"), "select: {g:?}");
    let (xfirst, xblock) = c.cmd_block("XOVER 1-").await;
    assert!(xfirst.starts_with("224"), "got {xfirst:?}");
    let xtext = String::from_utf8_lossy(&xblock);
    let number: u32 = xtext
        .lines()
        .find(|l| l.contains(id))
        .expect("fixture in XOVER")
        .split('\t')
        .next()
        .unwrap()
        .parse()
        .unwrap();

    server.hide(id).await;
    assert!(server.is_hidden(id).await);
    // Physically stored, but reads as missing while hidden.
    assert!(server.is_stored(id).await);

    let missing = c.cmd(&format!("STAT {id}")).await;
    assert!(missing.starts_with("430"), "hidden STAT: {missing:?}");
    // A 430 is a single line with no dot-terminated block; cmd_block would
    // wait for a `.` terminator that never comes.
    let first = c.cmd(&format!("ARTICLE {id}")).await;
    assert!(first.starts_with("430"), "hidden ARTICLE: {first:?}");
    // Numeric lookups hit the same guard as Message-ID lookups.
    let num_stat = c.cmd(&format!("STAT {number}")).await;
    assert!(
        num_stat.starts_with("430"),
        "hidden numeric STAT: {num_stat:?}"
    );
    let num_art = c.cmd(&format!("ARTICLE {number}")).await;
    assert!(
        num_art.starts_with("430"),
        "hidden numeric ARTICLE: {num_art:?}"
    );

    server.unhide(id).await;
    let back = c.cmd(&format!("STAT {id}")).await;
    assert!(back.starts_with("223"), "unhidden STAT: {back:?}");
}

#[tokio::test]
async fn repost_of_hidden_id_repairs_instead_of_duplicating() {
    // Same-ID re-post after simulated loss must succeed (repair path).
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let id = "<single-yenc-001@nntune.test>";
    let before = c.cmd("GROUP alt.binaries.nntune.test").await;
    assert!(before.starts_with("211"), "pre-hide GROUP: {before:?}");
    let count_before: u64 = before.split_whitespace().nth(1).unwrap().parse().unwrap();
    // The fixture's original article number, for the stale-number check below.
    let (rx_first, rx_block) = c.cmd_block("XOVER 1-").await;
    assert!(rx_first.starts_with("224"), "got {rx_first:?}");
    let number: u32 = String::from_utf8_lossy(&rx_block)
        .lines()
        .find(|l| l.contains(id))
        .expect("fixture in XOVER")
        .split('\t')
        .next()
        .unwrap()
        .parse()
        .unwrap();

    server.hide(id).await;
    let reply = c
        .post(
            &article_lines(id, "repaired", &["same content"])
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
        )
        .await;
    assert!(reply.starts_with("240"), "repair re-post: got {reply:?}");

    let s = c.cmd(&format!("STAT {id}")).await;
    assert!(s.starts_with("223"), "repaired STAT: {s:?}");
    // Listings show the repaired ID exactly once: the fixture is shadowed by
    // the spool replacement, not counted alongside it.
    let g = c.cmd("GROUP alt.binaries.nntune.test").await;
    let count_after: u64 = g.split_whitespace().nth(1).unwrap().parse().unwrap();
    assert_eq!(
        count_after, count_before,
        "repaired GROUP double-count: {g:?}"
    );
    let (xfirst, xblock) = c.cmd_block("XOVER 1-").await;
    assert!(xfirst.starts_with("224"), "got {xfirst:?}");
    let hits = String::from_utf8_lossy(&xblock)
        .lines()
        .filter(|l| l.contains(id))
        .count();
    assert_eq!(hits, 1, "repaired ID listed {hits}x");
    // The fixture's original number retires with it: a numeric lookup of the
    // stale number is 430, pinning the `find_visible_by_number` shadowing.
    let stale = c.cmd(&format!("STAT {number}")).await;
    assert!(stale.starts_with("430"), "stale number resolves: {stale:?}");
    // The repaired bytes are stored once and served back.
    assert_eq!(server.posted_count().await, 1);
    let (first, block) = c.cmd_block(&format!("ARTICLE {id}")).await;
    assert!(first.starts_with("220"), "got {first:?}");
    assert!(String::from_utf8_lossy(&block).contains("same content"));
    // A further identical POST is now a duplicate, not a second copy.
    let dup = c
        .post(
            &article_lines(id, "repaired", &["same content"])
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
        )
        .await;
    assert!(dup.starts_with("435"), "got {dup:?}");
    assert_eq!(server.posted_count().await, 1);
}

#[tokio::test]
async fn posting_disallowed_gets_440_then_recovers() {
    let mut config = ServerConfig::for_test();
    config.posting_allowed = false;
    let server = TestNntpServer::spawn(config).await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let r = c.cmd("POST").await;
    assert!(r.starts_with("440"), "got {r:?}");

    server.set_posting_allowed(true).await;
    let reply = c
        .post(
            &article_lines("<allowed-001@nntune.test>", "ok", &["b"])
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
        )
        .await;
    assert!(reply.starts_with("240"), "got {reply:?}");
}

#[tokio::test]
async fn unauthenticated_and_empty_posts_fail() {
    let server = TestNntpServer::spawn_for_test().await;

    // 480 without auth (require_auth), not 481.
    let mut anon = Client::connect(&server).await;
    let r = anon.cmd("POST").await;
    assert!(r.starts_with("480"), "got {r:?}");

    // Empty submission (immediate terminator) is 441, not stored.
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    c.writer.write_all(b"POST\r\n").await.unwrap();
    let go = c.read_line().await;
    assert!(go.starts_with("340"), "got {go:?}");
    c.writer.write_all(b".\r\n").await.unwrap();
    let reply = c.read_line().await;
    assert!(reply.starts_with("441"), "got {reply:?}");
    assert_eq!(server.posted_count().await, 0);
}

#[tokio::test]
async fn two_instances_hold_independent_spools() {
    let a = TestNntpServer::spawn_for_test().await;
    let b = TestNntpServer::spawn_for_test().await;
    let mut ca = Client::connect(&a).await;
    let mut cb = Client::connect(&b).await;
    ca.auth("testuser", "testpass").await;
    cb.auth("testuser", "testpass").await;

    let id = "<spool-a-only-001@nntune.test>";
    let reply = ca
        .post(
            &article_lines(id, "a-only", &["from a"])
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
        )
        .await;
    assert!(reply.starts_with("240"), "got {reply:?}");

    // B never saw it: no shared global state.
    let missing = cb.cmd(&format!("STAT {id}")).await;
    assert!(missing.starts_with("430"), "spool B leaked: {missing:?}");
    assert_eq!(a.posted_count().await, 1);
    assert_eq!(b.posted_count().await, 0);

    // Hiding on A does not affect B's view of the corpus.
    a.hide("<single-yenc-001@nntune.test>").await;
    let gone_a = ca.cmd("STAT <single-yenc-001@nntune.test>").await;
    assert!(gone_a.starts_with("430"), "got {gone_a:?}");
    let still_b = cb.cmd("STAT <single-yenc-001@nntune.test>").await;
    assert!(
        still_b.starts_with("223"),
        "B affected by A's hide: {still_b:?}"
    );
}

#[tokio::test]
async fn group_and_xover_include_posted_omit_hidden() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let before = c.cmd("GROUP alt.binaries.nntune.test").await;
    assert!(before.starts_with("211"), "got {before:?}");
    let count_before: u64 = before.split_whitespace().nth(1).unwrap().parse().unwrap();

    let id = "<listed-001@nntune.test>";
    let reply = c
        .post(
            &article_lines(id, "listed", &["visible"])
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
        )
        .await;
    assert!(reply.starts_with("240"), "got {reply:?}");

    let after = c.cmd("GROUP alt.binaries.nntune.test").await;
    let count_after: u64 = after.split_whitespace().nth(1).unwrap().parse().unwrap();
    assert_eq!(count_after, count_before + 1);
    // LIST bounds track GROUP bounds for the posted article's group.
    assert_list_matches_group(&mut c, "alt.binaries.nntune.test", &after).await;

    let (first, block) = c.cmd_block("XOVER 1-").await;
    assert!(first.starts_with("224"), "got {first:?}");
    assert!(String::from_utf8_lossy(&block).contains(id));

    // Hidden articles vanish from GROUP/XOVER too (loss simulation).
    server.hide(id).await;
    let hidden_group = c.cmd("GROUP alt.binaries.nntune.test").await;
    let count_hidden: u64 = hidden_group
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(count_hidden, count_before);
    let (xfirst, xblock) = c.cmd_block("XOVER 1-").await;
    assert!(xfirst.starts_with("224"), "got {xfirst:?}");
    assert!(!String::from_utf8_lossy(&xblock).contains(id));
    // LIST bounds still track GROUP after the hide.
    assert_list_matches_group(&mut c, "alt.binaries.nntune.test", &hidden_group).await;
}

/// `LIST` line for `group` reports the same low/high as a `GROUP` reply.
async fn assert_list_matches_group(c: &mut Client, group: &str, group_reply: &str) {
    let gparts: Vec<&str> = group_reply.split_whitespace().collect();
    let (glow, ghigh) = (gparts[2], gparts[3]);
    let (first, block) = c.cmd_block("LIST").await;
    assert!(first.starts_with("215"), "got {first:?}");
    let text = String::from_utf8_lossy(&block);
    let line = text
        .lines()
        .find(|l| l.split_whitespace().next() == Some(group))
        .unwrap_or_else(|| panic!("LIST missing {group}: {text:?}"));
    let cols: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(
        (cols[2], cols[1]),
        (glow, ghigh),
        "LIST/GROUP mismatch: {line:?}"
    );
}

#[tokio::test]
async fn posted_count_for_manifest_duplicate_assertion() {
    // Mirrors the consumer-resume check: post a file's segments, re-drive
    // the same pass, assert the manifest count does not grow.
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let manifest = [
        "<manifest-seg-1@nntune.test>",
        "<manifest-seg-2@nntune.test>",
        "<manifest-seg-3@nntune.test>",
    ];
    for id in manifest {
        let reply = c
            .post(
                &article_lines(id, "manifest", &["seg"])
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>(),
            )
            .await;
        assert!(reply.starts_with("240"), "{id}: got {reply:?}");
    }
    assert_eq!(server.posted_count_for(&manifest).await, 3);

    // Resumed pass re-posts the same IDs: all duplicates, count unchanged.
    for id in manifest {
        let reply = c
            .post(
                &article_lines(id, "manifest", &["seg"])
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>(),
            )
            .await;
        assert!(reply.starts_with("435"), "{id}: got {reply:?}");
    }
    assert_eq!(server.posted_count_for(&manifest).await, 3);
    assert_eq!(server.posted_count().await, 3);
}

#[tokio::test]
async fn post_with_comma_separated_newsgroups_selects_first_group() {
    // Production renders Newsgroups comma-separated (`a, b`); the first group
    // wins (no stray comma stored, no 411 on the plain name).
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let id = "<cross-001@nntune.test>";
    let mut lines = vec![
        "From: poster@nntune.test".to_string(),
        "Newsgroups: alt.binaries.nntune.test, alt.binaries.other.test".to_string(),
        "Subject: cross".to_string(),
        "Date: Mon, 13 Oct 2026 00:00:00 +0000".to_string(),
        format!("Message-ID: {id}"),
        String::new(),
    ];
    lines.push("x".to_string());
    let reply = c
        .post(&lines.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .await;
    assert!(reply.starts_with("240"), "got {reply:?}");

    let g = c.cmd("GROUP alt.binaries.nntune.test").await;
    assert!(g.starts_with("211"), "first group not selected: {g:?}");
    let (first, block) = c.cmd_block("XOVER 1-").await;
    assert!(first.starts_with("224"), "got {first:?}");
    assert!(String::from_utf8_lossy(&block).contains(id));
}

#[tokio::test]
async fn list_discovers_posted_group_and_reports_hidden_empty() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let group = "alt.binaries.posted-only.test";
    let id = "<posted-group-001@nntune.test>";
    let mut lines = vec![
        "From: poster@nntune.test".to_string(),
        format!("Newsgroups: {group}"),
        "Subject: new group".to_string(),
        "Date: Mon, 13 Oct 2026 00:00:00 +0000".to_string(),
        format!("Message-ID: {id}"),
        String::new(),
    ];
    lines.push("x".to_string());
    let reply = c
        .post(&lines.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .await;
    assert!(reply.starts_with("240"), "got {reply:?}");

    // GROUP recognizes the posted group and LIST advertises it with matching
    // bounds.
    let g = c.cmd(&format!("GROUP {group}")).await;
    assert!(g.starts_with("211"), "got {g:?}");
    assert_list_matches_group(&mut c, group, &g).await;

    // Hiding the only article leaves the group available but empty, in both
    // GROUP and LIST.
    server.hide(id).await;
    let empty = c.cmd(&format!("GROUP {group}")).await;
    assert!(
        empty.starts_with("211 0 0 0 "),
        "hidden-only group not empty: {empty:?}"
    );
    assert_list_matches_group(&mut c, group, &empty).await;
}

#[tokio::test]
async fn folded_subject_unfolds_in_xover() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let id = "<folded-001@nntune.test>";
    let reply = c
        .post(&[
            "From: poster@nntune.test",
            "Newsgroups: alt.binaries.nntune.test",
            "Subject: alpha alpha alpha alpha alpha alpha alpha alpha",
            " continued words here",
            "Date: Mon, 13 Oct 2026 00:00:00 +0000",
            &format!("Message-ID: {id}"),
            "",
            "x",
        ])
        .await;
    assert!(reply.starts_with("240"), "got {reply:?}");

    let g = c.cmd("GROUP alt.binaries.nntune.test").await;
    assert!(g.starts_with("211"), "got {g:?}");
    let (first, block) = c.cmd_block("XOVER 1-").await;
    assert!(first.starts_with("224"), "got {first:?}");
    let text = String::from_utf8_lossy(&block);
    assert!(
        text.contains("continued words here"),
        "fold lost in XOVER: {text:?}"
    );
}

#[tokio::test]
async fn post_without_message_id_stores_generated_id_in_headers() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let reply = c
        .post(&[
            "From: poster@nntune.test",
            "Newsgroups: alt.binaries.nntune.test",
            "Subject: no id",
            "Date: Mon, 13 Oct 2026 00:00:00 +0000",
            "",
            "x",
        ])
        .await;
    assert!(reply.starts_with("240"), "got {reply:?}");
    let id = reply.split_whitespace().last().unwrap().to_string();
    assert!(id.starts_with("<posted-"), "generated ID: {reply:?}");

    // HEAD serves the generated Message-ID, agreeing with STAT.
    let s = c.cmd(&format!("STAT {id}")).await;
    assert!(s.starts_with("223"), "got {s:?}");
    let (first, head) = c.cmd_block(&format!("HEAD {id}")).await;
    assert!(first.starts_with("221"), "got {first:?}");
    let text = String::from_utf8_lossy(&head);
    assert!(
        text.contains(&format!("Message-ID: {id}")),
        "generated ID missing from HEAD: {text:?}"
    );
}

#[tokio::test]
async fn oversized_post_gets_441_and_stores_nothing() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    // One line past the 8 MiB cap: the server drains to the terminator, then
    // rejects with 441 and stores nothing.
    let big = vec![b'x'; 8 * 1024 * 1024 + 1];
    let lines: Vec<&[u8]> = vec![
        b"From: poster@nntune.test",
        b"Newsgroups: alt.binaries.nntune.test",
        b"Subject: big",
        b"Date: Mon, 13 Oct 2026 00:00:00 +0000",
        b"Message-ID: <oversize-001@nntune.test>",
        b"",
        &big,
    ];
    let reply = c.post_raw(&lines).await;
    assert!(reply.starts_with("441"), "got {reply:?}");
    assert_eq!(server.posted_count().await, 0);
    assert!(!server.is_stored("<oversize-001@nntune.test>").await);
}
