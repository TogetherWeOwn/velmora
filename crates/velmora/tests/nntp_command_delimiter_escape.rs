//! Acceptance: NNTP command arguments that escape their delimiters are
//! refused before any byte is written.
//!
//! Message-ids are framed as `<id>` and group names are a bare token, so
//! an argument containing `<`, `>`, space, tab, CR, LF or NUL would break
//! out of its framing on the wire (e.g. `STAT <a> ARTICLE <b>` or an
//! injected second command line). Every command path that formats a
//! caller-supplied id or name -- `STAT`, `ARTICLE`, `BODY`, `GROUP` and
//! the pipelined `ARTICLE`s in `fetch_many` -- must refuse such an
//! argument with [`Error::Malformed`] and write nothing for that call.
//!
//! The fake transport records every write instead of asserting inline,
//! so a refused call can be checked after the fact: the only bytes on
//! the wire may be the connect handshake (`MODE READER` + `AUTHINFO`).

use std::collections::VecDeque;
use std::io;

use nntune_core::error::Error;
use nntune_core::nntp::{NntpClient, NntpConfig};
use nntune_core::transport::Transport;

/// Transport that serves scripted reads and records every write.
struct Recorder {
    to_client: VecDeque<u8>,
    writes: Vec<Vec<u8>>,
}

impl Recorder {
    fn new(readable: &str) -> Self {
        Recorder {
            to_client: readable.as_bytes().iter().cloned().collect(),
            writes: Vec::new(),
        }
    }
}

impl Transport for Recorder {
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
        self.writes.push(buf.to_vec());
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Bytes the connect handshake writes (server accepts at AUTHINFO USER).
const HANDSHAKE_WRITES: &[&[u8]] = &[b"MODE READER\r\n", b"AUTHINFO USER user\r\n"];

fn config() -> NntpConfig {
    NntpConfig {
        host: "nntp.example.com".into(),
        tls: false,
        username: Some("user".into()),
        password: Some("pass".into()),
        timeout: std::time::Duration::from_secs(5),
        max_pipelined: 4,
        ..NntpConfig::default()
    }
}

/// Connects a client whose post-handshake reads are `extra_read`.
async fn connected(extra_read: &str) -> NntpClient<Recorder> {
    let readable = format!("200 ready\r\n500 no\r\n281 ok\r\n{extra_read}");
    NntpClient::connect(Recorder::new(&readable), &config())
        .await
        .expect("handshake")
}

/// The seven characters that escape an argument's delimiters.
const ESCAPES: [char; 7] = ['<', '>', ' ', '\t', '\r', '\n', '\0'];

/// Asserts the call wrote nothing beyond the handshake and returns the
/// error classification check to the caller via the recorded writes.
fn assert_no_command_bytes(client: NntpClient<Recorder>, ctx: &str) {
    let recorder = client.into_inner();
    assert_eq!(
        recorder.writes.len(),
        HANDSHAKE_WRITES.len(),
        "{ctx}: refused call must write nothing, wrote {:?}",
        recorder
            .writes
            .iter()
            .map(|w| String::from_utf8_lossy(w).into_owned())
            .collect::<Vec<_>>()
    );
    for (got, want) in recorder.writes.iter().zip(HANDSHAKE_WRITES) {
        assert_eq!(got.as_slice(), *want, "{ctx}: handshake write changed");
    }
}

fn assert_malformed<T: std::fmt::Debug>(result: Result<T, Error>, ctx: &str) {
    let err = result.expect_err(ctx);
    assert!(
        matches!(err, Error::Malformed(_)),
        "{ctx}: expected Error::Malformed, got {err:?}"
    );
}

#[tokio::test]
async fn stat_refuses_message_ids_that_escape_the_angle_brackets() {
    for ch in ESCAPES {
        let id = format!("a{ch}b@x");
        let ctx = format!("STAT id containing {ch:?}");
        let mut client = connected("").await;
        assert_malformed(client.stat(&id).await, &ctx);
        assert_no_command_bytes(client, &ctx);
    }
    // A full injection shape: close the bracket, then a second command.
    let mut client = connected("").await;
    assert_malformed(
        client.stat("a@x> ARTICLE <victim@x").await,
        "STAT injected second command",
    );
    assert_no_command_bytes(client, "STAT injected second command");
}

#[tokio::test]
async fn article_refuses_message_ids_that_escape_the_angle_brackets() {
    for ch in ESCAPES {
        let id = format!("a{ch}b@x");
        let ctx = format!("ARTICLE id containing {ch:?}");
        let mut client = connected("").await;
        let mut out = Vec::new();
        assert_malformed(client.article_to(&id, &mut out).await, &ctx);
        assert!(out.is_empty(), "{ctx}: refusal must produce no article");
        assert_no_command_bytes(client, &ctx);
    }
}

#[tokio::test]
async fn body_refuses_message_ids_that_escape_the_angle_brackets() {
    for ch in ESCAPES {
        let id = format!("a{ch}b@x");
        let ctx = format!("BODY id containing {ch:?}");
        let mut client = connected("").await;
        let mut out = Vec::new();
        assert_malformed(client.body_to(&id, &mut out).await, &ctx);
        assert!(out.is_empty(), "{ctx}: refusal must produce no body");
        assert_no_command_bytes(client, &ctx);
    }
}

#[tokio::test]
async fn group_refuses_names_that_escape_the_bare_token() {
    for ch in ESCAPES {
        let name = format!("alt{ch}binaries.test");
        let ctx = format!("GROUP name containing {ch:?}");
        let mut client = connected("").await;
        assert_malformed(client.group(&name).await, &ctx);
        assert_no_command_bytes(client, &ctx);
    }
    // A trailing escape breaks the token just as an embedded one does.
    let mut client = connected("").await;
    assert_malformed(
        client.group("alt.binaries.test ").await,
        "GROUP trailing space",
    );
    assert_no_command_bytes(client, "GROUP trailing space");
}

#[tokio::test]
async fn pipelined_article_refuses_message_ids_that_escape_the_angle_brackets() {
    for ch in ESCAPES {
        let id = format!("a{ch}b@x");
        let ctx = format!("pipelined ARTICLE id containing {ch:?}");
        let mut client = connected("").await;
        assert_malformed(client.fetch_many(&[id.as_str()]).await, &ctx);
        assert_no_command_bytes(client, &ctx);
    }
}

#[tokio::test]
async fn pipelined_article_validates_the_whole_batch_before_writing() {
    // A batch is written ahead of its replies, so validating each id as
    // it is written would put the valid prefix on the wire and then
    // fail with unread replies outstanding. One escaping id anywhere
    // in the batch must refuse the call before any ARTICLE is sent.
    for ids in [
        vec!["one@x", "bad id@x"],
        vec!["bad\tid@x", "two@x"],
        vec!["one@x", "two@x", "bad\nid@x"],
    ] {
        let ctx = format!("pipelined batch {ids:?}");
        let mut client = connected("").await;
        assert_malformed(client.fetch_many(&ids).await, &ctx);
        assert_no_command_bytes(client, &ctx);
    }
}

/// Green control: ordinary ids and names -- including the punctuation
/// real message-ids carry -- still reach the wire unchanged on every
/// command path, so refusal cannot be implemented by over-blocking.
#[tokio::test]
async fn valid_ids_and_names_still_work_on_every_command_path() {
    let id = "a.b-c_d+e%f@x-y.example";
    let read = format!(
        "223 42 <{id}> article exists\r\n\
         220 42 <{id}> article follows\r\nfull article\r\n.\r\n\
         222 42 <{id}> body follows\r\njust the body\r\n.\r\n\
         211 100 1 100 alt.binaries.test group selected\r\n\
         220 1 <one@x>\r\none-body\r\n.\r\n\
         220 2 <{id}>\r\ntwo-body\r\n.\r\n"
    );
    let mut client = connected(&read).await;

    assert_eq!(client.stat(id).await.unwrap(), 42);

    let mut article = Vec::new();
    client.article_to(id, &mut article).await.unwrap();
    assert_eq!(article, b"full article\r\n");

    let mut body = Vec::new();
    client.body_to(id, &mut body).await.unwrap();
    assert_eq!(body, b"just the body\r\n");

    let group = client.group("alt.binaries.test").await.unwrap();
    assert_eq!((group.count, group.first, group.last), (100, 1, 100));
    assert_eq!(group.name, "alt.binaries.test");

    let out = client.fetch_many(&["one@x", id]).await.unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].message_id, "one@x");
    assert_eq!(out[1].message_id, id);
    assert_eq!(out[1].article, b"two-body\r\n");

    let recorder = client.into_inner();
    let sent: Vec<String> = recorder
        .writes
        .iter()
        .map(|w| String::from_utf8_lossy(w).into_owned())
        .collect();
    assert_eq!(
        sent,
        [
            "MODE READER\r\n",
            "AUTHINFO USER user\r\n",
            &format!("STAT <{id}>\r\n"),
            &format!("ARTICLE <{id}>\r\n"),
            &format!("BODY <{id}>\r\n"),
            "GROUP alt.binaries.test\r\n",
            "ARTICLE <one@x>\r\n",
            &format!("ARTICLE <{id}>\r\n"),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>(),
        "valid commands must reach the wire byte-for-byte"
    );
}
