//! Core NNTP client integration tests against the synthetic server.
//!
//! These run in CI with no real Usenet: every test spawns an in-process
//! `TestNntpServer` on an ephemeral loopback port and speaks raw NNTP.
//! They are the acceptance proof for the fixture server — `nntune-core`
//! (and stream/ingest harnesses) reuse the same spawn helpers.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use nntune_test_nntp::{ServerConfig, TestNntpServer};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

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
        let n = self.reader.read_line(&mut s).await.unwrap();
        assert!(n > 0, "connection closed while reading line");
        s
    }

    /// Send a command, return the single-line response.
    async fn cmd(&mut self, cmd: &str) -> String {
        self.writer
            .write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .unwrap();
        self.read_line().await
    }

    /// Send a command, return (first line, dot-terminated block, unstuffed).
    ///
    /// Byte-oriented (`read_until`): yEnc bodies are arbitrary bytes, so the
    /// block must never be decoded as UTF-8 mid-transfer.
    async fn cmd_block(&mut self, cmd: &str) -> (String, Vec<u8>) {
        self.writer
            .write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .unwrap();
        let first = self.read_line().await;
        let mut raw = Vec::new();
        loop {
            let mut line: Vec<u8> = Vec::new();
            let n = self.reader.read_until(b'\n', &mut line).await.unwrap();
            assert!(n > 0, "connection closed mid-block for {cmd:?}");
            // Strip CRLF/LF terminator.
            if line.ends_with(b"\n") {
                line.pop();
                if line.ends_with(b"\r") {
                    line.pop();
                }
            }
            if line == b"." {
                break;
            }
            // Un-dot-stuff: a stuffed line starts with "..".
            if line.starts_with(b"..") {
                raw.extend_from_slice(&line[1..]);
            } else {
                raw.extend_from_slice(&line);
            }
            raw.extend_from_slice(b"\r\n");
        }
        (first, raw)
    }

    async fn auth(&mut self, user: &str, pass: &str) -> (String, String) {
        let u = self.cmd(&format!("AUTHINFO USER {user}")).await;
        let p = self.cmd(&format!("AUTHINFO PASS {pass}")).await;
        (u, p)
    }
}

fn article_body(block: &[u8]) -> &[u8] {
    let pos = block
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header/body sep");
    &block[pos + 4..]
}

#[tokio::test]
async fn greets_and_lists_capabilities() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    let first = c.cmd("CAPABILITIES").await;
    assert!(first.starts_with("101"), "got {first:?}");
    // Drain capability block.
    loop {
        let l = c.read_line().await;
        if l.trim_end() == "." {
            break;
        }
    }
}

#[tokio::test]
async fn auth_flow_accepts_valid_rejects_invalid() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    let (u, p) = c.auth("testuser", "testpass").await;
    assert!(u.starts_with("381"), "got {u:?}");
    assert!(p.starts_with("281"), "got {p:?}");

    let mut bad = Client::connect(&server).await;
    let (_, p2) = bad.auth("testuser", "wrongpass").await;
    assert!(p2.starts_with("481"), "got {p2:?}");

    let mut unknown = Client::connect(&server).await;
    let (_, p3) = unknown.auth("nosuchuser", "x").await;
    assert!(p3.starts_with("481"), "got {p3:?}");
}

#[tokio::test]
async fn requires_auth_before_group() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    let r = c.cmd("GROUP alt.binaries.nntune.test").await;
    assert!(r.starts_with("480"), "got {r:?}");
}

#[tokio::test]
async fn group_article_body_head_stat_by_id_and_number() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let g = c.cmd("GROUP alt.binaries.nntune.test").await;
    assert!(g.starts_with("211"), "got {g:?}");

    let (a1, block) = c.cmd_block("ARTICLE <single-yenc-001@nntune.test>").await;
    assert!(a1.starts_with("220"), "got {a1:?}");
    assert!(
        block.windows(12).any(|w| w == b"sine-440.wav"),
        "yEnc filename missing"
    );

    let (a2, _) = c.cmd_block("ARTICLE 1").await;
    assert!(a2.starts_with("220"), "by number: {a2:?}");

    let (b, _) = c.cmd_block("BODY <single-yenc-001@nntune.test>").await;
    assert!(b.starts_with("222"), "got {b:?}");

    let (h, head) = c.cmd_block("HEAD <single-yenc-001@nntune.test>").await;
    assert!(h.starts_with("221"), "got {h:?}");
    assert!(
        head.windows(8).any(|w| w == b"Subject:"),
        "HEAD missing Subject"
    );

    let s = c.cmd("STAT <single-yenc-001@nntune.test>").await;
    assert!(s.starts_with("223"), "got {s:?}");

    let q = c.cmd("QUIT").await;
    assert!(q.starts_with("205"), "got {q:?}");
}

#[tokio::test]
async fn xover_lists_all_articles() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    // A ranged XOVER requires a selected group (412 otherwise).
    let g = c.cmd("GROUP alt.binaries.nntune.test").await;
    assert!(g.starts_with("211"), "GROUP: {g:?}");
    let (first, block) = c.cmd_block("XOVER 1-").await;
    assert!(first.starts_with("224"), "got {first:?}");
    let text = String::from_utf8_lossy(&block);
    for id in [
        "<single-yenc-001@nntune.test>",
        "<multi-660-part1-of-3@nntune.test>",
        "<obf-550-part1-of-3@nntune.test>",
        "<enc-rar-001@nntune.test>",
        "<enc-7z-001@nntune.test>",
    ] {
        assert!(text.contains(id), "XOVER missing {id}");
    }
}

#[tokio::test]
async fn yenc_single_part_decodes_to_wav() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    let (first, block) = c.cmd_block("ARTICLE <single-yenc-001@nntune.test>").await;
    assert!(first.starts_with("220"));
    let decoded = nntune_test_nntp::yenc::decode(article_body(&block));
    assert_eq!(&decoded[0..4], b"RIFF");
    assert_eq!(&decoded[8..12], b"WAVE");
    // Matches the locally generated reference tone byte-for-byte.
    let expected = nntune_test_nntp::generate_wav_bytes(440.0, 120, 8000);
    assert_eq!(decoded, expected);
}

#[tokio::test]
async fn multipart_reassembles_original() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    let mut joined = Vec::new();
    for n in 1..=3 {
        let id = format!("<multi-660-part{n}-of-3@nntune.test>");
        let (first, block) = c.cmd_block(&format!("ARTICLE {id}")).await;
        assert!(first.starts_with("220"), "part {n}: {first:?}");
        joined.extend(nntune_test_nntp::yenc::decode(article_body(&block)));
    }
    assert_eq!(
        joined,
        nntune_test_nntp::generate_wav_bytes(660.0, 210, 8000)
    );
}

#[tokio::test]
async fn obfuscated_subjects_served() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    let (first, block) = c
        .cmd_block("ARTICLE <obf-550-part2-of-3@nntune.test>")
        .await;
    assert!(first.starts_with("220"));
    // Served under an opaque subject, but the payload still decodes.
    assert!(block.windows(12).any(|w| w == b"q7w2e9r4t6y1"));
    let decoded = nntune_test_nntp::yenc::decode(article_body(&block));
    assert!(!decoded.is_empty());
}

#[tokio::test]
async fn rar_and_7z_markers_present() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let (_, rar_block) = c.cmd_block("ARTICLE <enc-rar-001@nntune.test>").await;
    let rar = nntune_test_nntp::yenc::decode(article_body(&rar_block));
    assert_eq!(&rar[0..4], b"Rar!");

    let (_, seven_block) = c.cmd_block("ARTICLE <enc-7z-001@nntune.test>").await;
    let seven = nntune_test_nntp::yenc::decode(article_body(&seven_block));
    assert_eq!(&seven[0..2], b"7z");
}

#[tokio::test]
async fn missing_article_returns_430() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let r1 = c.cmd("ARTICLE <does-not-exist@nntune.test>").await;
    assert!(r1.starts_with("430"), "unknown id: {r1:?}");

    let r2 = c.cmd("ARTICLE <missing-430@nntune.test>").await;
    assert!(r2.starts_with("430"), "injected missing: {r2:?}");

    let r3 = c.cmd("ARTICLE 9999").await;
    assert!(r3.starts_with("430"), "unknown number: {r3:?}");
}

#[tokio::test]
async fn connection_cap_per_credential() {
    // testuser allows 2 concurrent connections.
    let server = TestNntpServer::spawn_for_test().await;
    let mut c1 = Client::connect(&server).await;
    let mut c2 = Client::connect(&server).await;
    c1.auth("testuser", "testpass").await;
    c2.auth("testuser", "testpass").await;

    // Third connection for the same credential is rejected with 502.
    let stream = TcpStream::connect(server.addr()).await.unwrap();
    let (r, w) = stream.into_split();
    let mut c3 = Client {
        reader: BufReader::new(r),
        writer: w,
    };
    let greeting = c3.read_line().await;
    assert!(greeting.starts_with("200"));
    let u = c3.cmd("AUTHINFO USER testuser").await;
    assert!(u.starts_with("381"));
    c3.writer
        .write_all(b"AUTHINFO PASS testpass\r\n")
        .await
        .unwrap();
    let verdict = c3.read_line().await;
    assert!(
        verdict.starts_with("502"),
        "expected cap rejection, got {verdict:?}"
    );

    // A different credential with headroom still works.
    let mut other = Client::connect(&server).await;
    let (_, p) = other.auth("otheruser", "otherpass").await;
    assert!(p.starts_with("281"), "other credential blocked: {p:?}");
}

#[tokio::test]
async fn slow_link_throttles_article_body() {
    let mut config = ServerConfig::for_test();
    config.slow_bytes_per_sec = Some(400);
    let server = TestNntpServer::spawn(config).await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let start = Instant::now();
    let (first, _) = c.cmd_block("ARTICLE <single-yenc-001@nntune.test>").await;
    assert!(first.starts_with("220"));
    let elapsed = start.elapsed();
    // ~1.3 KB stuffed body at 400 B/s must take well over a second.
    assert!(
        elapsed >= Duration::from_millis(1500),
        "throttle ineffective: {elapsed:?}"
    );
}

#[tokio::test]
async fn mid_body_disconnect_drops_connection() {
    let mut config = ServerConfig::for_test();
    config
        .drop_after_bytes
        .insert("<single-yenc-001@nntune.test>".to_string(), 16);
    let server = TestNntpServer::spawn(config).await;

    let stream = TcpStream::connect(server.addr()).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap(); // greeting
    w.write_all(b"AUTHINFO USER testuser\r\n").await.unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    w.write_all(b"AUTHINFO PASS testpass\r\n").await.unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    w.write_all(b"ARTICLE <single-yenc-001@nntune.test>\r\n")
        .await
        .unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap(); // 220 header
    assert!(line.starts_with("220"), "got {line:?}");

    // Server closes mid-body: read until EOF, expect a truncated body.
    let mut got = Vec::new();
    let _ = reader.read_to_end(&mut got).await;
    assert!(
        got.len() < 1004,
        "expected truncated body, got {} bytes",
        got.len()
    );
}

#[tokio::test]
async fn nzb_fixtures_match_served_ids() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/nzb");
    let mut referenced = HashSet::new();
    // message-id -> declared segment bytes (NZB `bytes=` attribute).
    let mut declared_bytes: HashMap<String, u64> = HashMap::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        // Parse each <segment bytes="N" ...>&lt;id&gt;</segment>.
        let mut rest = text.as_str();
        while let Some(seg) = rest.find("<segment") {
            rest = &rest[seg..];
            let bytes_start = rest.find("bytes=\"").expect("segment bytes=");
            let bytes_rest = &rest[bytes_start + 7..];
            let bytes_end = bytes_rest.find('"').expect("closing quote");
            let bytes: u64 = bytes_rest[..bytes_end].parse().expect("bytes number");
            let lt = rest.find("&lt;").expect("segment id");
            let gt = rest[lt..].find("&gt;").expect("segment id end");
            let id = format!("<{}>", &rest[lt + 4..lt + gt]);
            referenced.insert(id.clone());
            declared_bytes.insert(id, bytes);
            rest = &rest[lt + gt + 4..];
        }
        // Fallback for files without <segment> (should not happen, but keeps
        // the old ID-only extraction working).
        if referenced.is_empty() {
            let mut r2 = text.as_str();
            while let Some(i) = r2.find("&lt;") {
                r2 = &r2[i + 4..];
                if let Some(j) = r2.find("&gt;") {
                    referenced.insert(format!("<{}>", &r2[..j]));
                    r2 = &r2[j + 4..];
                } else {
                    break;
                }
            }
        }
    }
    assert!(
        !referenced.is_empty(),
        "no message-ids found in fixtures/nzb"
    );
    // Every referenced ID except the intentionally-missing one must be servable.
    let corpus: HashMap<_, _> = nntune_test_nntp::default_corpus()
        .into_iter()
        .map(|a| (a.message_id.clone(), a))
        .collect();
    for id in &referenced {
        assert!(
            corpus.contains_key(id),
            "NZB references unknown article {id}"
        );
    }
    // Declared segment bytes must match the served decoded payload size.
    for (id, bytes) in &declared_bytes {
        let article = corpus.get(id).expect("known id");
        assert_eq!(
            *bytes,
            article.payload.len() as u64,
            "NZB bytes mismatch for {id}"
        );
    }

    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    for id in &referenced {
        let r = c.cmd(&format!("STAT {id}")).await;
        assert!(r.starts_with("223"), "{id}: {r:?}");
    }
}

// --- Regression tests for Paperclip Review findings (PR #7, head 42c6b82) ---

fn framing_lines(body: &[u8]) -> (String, Option<String>, String) {
    let text = String::from_utf8_lossy(body);
    let mut ybegin = None;
    let mut ypart = None;
    let mut yend = None;
    for line in text.lines() {
        if line.starts_with("=ybegin") {
            ybegin = Some(line.to_string());
        } else if line.starts_with("=ypart") {
            ypart = Some(line.to_string());
        } else if line.starts_with("=yend") {
            yend = Some(line.to_string());
        }
    }
    (
        ybegin.expect("missing =ybegin"),
        ypart,
        yend.expect("missing =yend"),
    )
}

fn param(line: &str, key: &str) -> Option<String> {
    for token in line.split_whitespace() {
        if let Some(v) = token.strip_prefix(&format!("{key}=")) {
            return Some(v.to_string());
        }
    }
    None
}

#[tokio::test]
async fn multipart_framing_uses_file_offsets_and_crc() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;

    let expected = nntune_test_nntp::generate_wav_bytes(660.0, 210, 8000);
    let full_size = expected.len().to_string();
    let mut names = Vec::new();
    let mut reassembled = vec![0u8; expected.len()];

    // Parts are 575, 575, 574 bytes at offsets 0, 575, 1150.
    let ranges = [(1u64, 575u64), (576, 1150), (1151, 1724)];
    for n in 1..=3u32 {
        let n_s = n.to_string();
        let id = format!("<multi-660-part{n}-of-3@nntune.test>");
        let (first, block) = c.cmd_block(&format!("ARTICLE {id}")).await;
        assert!(first.starts_with("220"), "part {n}: {first:?}");
        let body = article_body(&block);
        let (ybegin, ypart, yend) = framing_lines(body);
        // =ybegin carries the whole file size, not the part size.
        assert_eq!(param(&ybegin, "size").as_deref(), Some(full_size.as_str()));
        assert_eq!(param(&ybegin, "part").as_deref(), Some(n_s.as_str()));
        assert_eq!(param(&ybegin, "total").as_deref(), Some("3"));
        names.push(param(&ybegin, "name").expect("ybegin name"));
        // =ypart carries this part's 1-based offset range.
        let yp = ypart.expect("multipart must have =ypart");
        let (exp_begin, exp_end) = ranges[(n - 1) as usize];
        let exp_begin_s = exp_begin.to_string();
        let exp_end_s = exp_end.to_string();
        assert_eq!(
            param(&yp, "begin").as_deref(),
            Some(exp_begin_s.as_str()),
            "part {n} begin"
        );
        assert_eq!(
            param(&yp, "end").as_deref(),
            Some(exp_end_s.as_str()),
            "part {n} end"
        );
        // =yend carries part length + pcrc32.
        let part_len = (exp_end - exp_begin + 1).to_string();
        assert_eq!(param(&yend, "size").as_deref(), Some(part_len.as_str()));
        assert_eq!(
            param(&yend, "part").as_deref(),
            Some(n_s.as_str()),
            "yend part {n}"
        );
        let decoded = nntune_test_nntp::yenc::decode(body);
        assert_eq!(decoded.len() as u64, exp_end - exp_begin + 1);
        let expect_pcrc = format!("{:08x}", nntune_test_nntp::yenc::crc32(&decoded));
        assert_eq!(
            param(&yend, "pcrc32").as_deref(),
            Some(expect_pcrc.as_str())
        );
        // Reassemble strictly by the advertised offset.
        let begin: usize = param(&yp, "begin").unwrap().parse().unwrap();
        reassembled[begin - 1..begin - 1 + decoded.len()].copy_from_slice(&decoded);
    }
    // All parts share one yEnc file name for name-based grouping.
    assert_eq!(names.len(), 3);
    assert!(
        names.iter().all(|n| n == &names[0]),
        "multipart yEnc names diverge: {names:?}"
    );
    assert_eq!(reassembled, expected);
}

#[tokio::test]
async fn obfuscated_parts_share_yenc_name() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    let mut names = Vec::new();
    for n in 1..=3 {
        let id = format!("<obf-550-part{n}-of-3@nntune.test>");
        let (first, block) = c.cmd_block(&format!("ARTICLE {id}")).await;
        assert!(first.starts_with("220"));
        let (ybegin, _, _) = framing_lines(article_body(&block));
        names.push(param(&ybegin, "name").expect("ybegin name"));
    }
    assert!(
        names.iter().all(|n| n == &names[0]),
        "obfuscated yEnc names diverge: {names:?}"
    );
}

#[tokio::test]
async fn served_corpus_has_no_dangling_yenc_escapes() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    for id in [
        "<single-yenc-001@nntune.test>",
        "<multi-660-part2-of-3@nntune.test>",
        "<enc-rar-001@nntune.test>",
    ] {
        let (first, block) = c.cmd_block(&format!("ARTICLE {id}")).await;
        assert!(first.starts_with("220"), "{id}: {first:?}");
        let body = article_body(&block);
        // Encoded lines (non-framing) must not end with a bare '='.
        for line in body.split(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let line = line.strip_suffix(b"\n").unwrap_or(line);
            if line.is_empty() || line.starts_with(b"=y") {
                continue;
            }
            assert!(
                !line.ends_with(b"="),
                "{id}: encoded line ends with dangling escape"
            );
        }
    }
}

#[tokio::test]
async fn server_stops_serving_after_drop() {
    let server = TestNntpServer::spawn_for_test().await;
    let addr = server.addr();
    let _ = Client::connect(&server).await;
    drop(server);
    // Drop requests cancellation; the accept task releases its listener when
    // the runtime next polls it. Observe closure rather than a fixed delay.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if TcpStream::connect(addr).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("server still accepts connections after drop");
}

#[tokio::test]
async fn server_drop_closes_open_sessions() {
    let server = TestNntpServer::spawn_for_test().await;
    // Hold an authenticated session across the drop.
    let stream = TcpStream::connect(server.addr()).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap(); // greeting
    assert!(line.starts_with("200"), "greeting: {line:?}");
    w.write_all(b"AUTHINFO USER testuser\r\n").await.unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("381"), "got {line:?}");
    w.write_all(b"AUTHINFO PASS testpass\r\n").await.unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("281"), "got {line:?}");

    drop(server);
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The open session must be closed: no further command may be served.
    let _ = w.write_all(b"STAT <single-yenc-001@nntune.test>\r\n").await;
    let mut buf = [0u8; 1024];
    let res = tokio::time::timeout(Duration::from_secs(5), reader.read(&mut buf))
        .await
        .expect("timed out waiting for session close");
    match res {
        Ok(0) => {} // EOF: session closed as required.
        Ok(n) => panic!(
            "open session still served after drop: {:?}",
            String::from_utf8_lossy(&buf[..n])
        ),
        Err(_) => {} // Connection error/reset: also a closed session.
    }
}

#[tokio::test]
async fn unauthenticated_commands_get_480() {
    // RFC 4643 s2.3.1: missing auth is 480, not 481 (which means
    // credentials were rejected).
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    for cmd in [
        "GROUP alt.binaries.nntune.test",
        "LIST",
        "XOVER 1-",
        "ARTICLE <single-yenc-001@nntune.test>",
        "STAT <single-yenc-001@nntune.test>",
    ] {
        let r = c.cmd(cmd).await;
        assert!(r.starts_with("480"), "{cmd}: got {r:?}");
    }
}

#[tokio::test]
async fn pass_without_user_gets_482() {
    // RFC 4643 s2.3.2: AUTHINFO PASS with no preceding USER is 482
    // (out of sequence), not 481.
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    let r = c.cmd("AUTHINFO PASS testpass").await;
    assert!(r.starts_with("482"), "got {r:?}");
}

#[tokio::test]
async fn unknown_group_gets_411() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    let r = c.cmd("GROUP nosuchgroup.example.invalid").await;
    assert!(r.starts_with("411"), "got {r:?}");
}

#[tokio::test]
async fn reauth_does_not_consume_cap_slot() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    let (_, p1) = c.auth("testuser", "testpass").await;
    assert!(p1.starts_with("281"), "first auth: {p1:?}");
    // RFC 4643: second AUTHINFO on an authenticated connection gets 502.
    let u2 = c.cmd("AUTHINFO USER testuser").await;
    assert!(
        u2.starts_with("502"),
        "re-auth USER should be 502, got {u2:?}"
    );
    let _ = c.cmd("QUIT").await;
    // Both cap slots must still be free: two fresh logins succeed.
    let mut a = Client::connect(&server).await;
    let (_, pa) = a.auth("testuser", "testpass").await;
    assert!(pa.starts_with("281"), "slot leaked: {pa:?}");
    let mut b = Client::connect(&server).await;
    let (_, pb) = b.auth("testuser", "testpass").await;
    assert!(pb.starts_with("281"), "slot leaked: {pb:?}");
}

#[tokio::test]
async fn list_reports_high_before_low() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    let g = c.cmd("GROUP alt.binaries.nntune.test").await;
    assert!(g.starts_with("211"), "GROUP: {g:?}");
    let parts: Vec<_> = g.split_whitespace().collect();
    // 211 count low high group
    let (low, high) = (
        parts[2].parse::<u32>().unwrap(),
        parts[3].parse::<u32>().unwrap(),
    );
    let (first, block) = c.cmd_block("LIST").await;
    assert!(first.starts_with("215"), "LIST: {first:?}");
    let text = String::from_utf8_lossy(&block);
    let line = text
        .lines()
        .find(|l| l.starts_with("alt.binaries.nntune.test"))
        .expect("LIST active line");
    let cols: Vec<_> = line.split_whitespace().collect();
    let (list_high, list_low) = (
        cols[1].parse::<u32>().unwrap(),
        cols[2].parse::<u32>().unwrap(),
    );
    assert_eq!((list_low, list_high), (low, high));
    assert!(list_high >= list_low, "LIST high/low reversed: {line:?}");
}

#[tokio::test]
async fn server_drop_interrupts_in_flight_throttled_article() {
    let mut config = ServerConfig::for_test();
    config.slow_bytes_per_sec = Some(200);
    let server = TestNntpServer::spawn(config).await;
    let stream = TcpStream::connect(server.addr()).await.unwrap();
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    w.write_all(b"AUTHINFO USER testuser\r\n").await.unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    w.write_all(b"AUTHINFO PASS testpass\r\n").await.unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    w.write_all(b"ARTICLE <single-yenc-001@nntune.test>\r\n")
        .await
        .unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("220"), "got {line:?}");

    drop(server);
    let mut body = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), reader.read_to_end(&mut body))
        .await
        .expect("in-flight response continued after server drop")
        .unwrap();
}

#[tokio::test]
async fn xover_returns_only_requested_range() {
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    c.cmd("GROUP alt.binaries.nntune.test").await;

    let (first, block) = c.cmd_block("XOVER 3-4").await;
    assert!(first.starts_with("224"), "got {first:?}");
    let text = String::from_utf8_lossy(&block);
    let rows: Vec<_> = text.lines().collect();
    assert_eq!(rows.len(), 2, "XOVER 3-4 returned: {rows:?}");
    let numbers: Vec<_> = rows
        .iter()
        .map(|row| row.split('\t').next().expect("article number"))
        .collect();
    assert_eq!(numbers, ["3", "4"]);
}

#[tokio::test]
async fn xover_empty_and_reversed_ranges_get_423() {
    // RFC 3977 s8.3.2: a range matching nothing in the selected group —
    // including a reversed range — gets 423, not an empty 224 list, so a
    // batching header scan can stop at the end of the group.
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    let g = c.cmd("GROUP alt.binaries.nntune.test").await;
    assert!(g.starts_with("211"), "GROUP: {g:?}");
    for range in ["XOVER 500-600", "XOVER 4-3", "XOVER 11"] {
        let r = c.cmd(range).await;
        assert!(r.starts_with("423"), "{range}: got {r:?}");
    }
}

#[tokio::test]
async fn xover_range_without_selected_group_gets_412() {
    // RFC 3977 s8.3.2: a range request before any successful GROUP gets
    // 412, so callers cannot mistake unscoped rows for group rows.
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    let r = c.cmd("XOVER 3-4").await;
    assert!(r.starts_with("412"), "got {r:?}");
}

#[tokio::test]
async fn xover_unparseable_range_gets_501() {
    // An unparseable range must not silently degrade to list-all: a
    // scanner typo would otherwise see the whole corpus as one batch.
    let server = TestNntpServer::spawn_for_test().await;
    let mut c = Client::connect(&server).await;
    c.auth("testuser", "testpass").await;
    let g = c.cmd("GROUP alt.binaries.nntune.test").await;
    assert!(g.starts_with("211"), "GROUP: {g:?}");
    for range in ["XOVER abc", "XOVER 99999999999-", "XOVER -"] {
        let r = c.cmd(range).await;
        assert!(r.starts_with("501"), "{range}: got {r:?}");
    }
}
