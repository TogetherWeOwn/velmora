//! NNTP client tests over a scripted in-memory transport, plus a live
//! loopback test of the native TCP transport.

use std::collections::VecDeque;
use std::io;

use nntune_core::error::Error;
use nntune_core::nntp::{NntpClient, NntpConfig};
use nntune_core::transport::Transport;

/// Scripted transport: reads come from `to_client`, writes are asserted
/// against `expect_writes` in order.
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
        timeout: std::time::Duration::from_secs(5),
        max_pipelined: 4,
        ..NntpConfig::default()
    }
}

const HANDSHAKE: &str = "200 news.example.com ready\r\n\
    500 MODE READER unsupported here\r\n\
    381 more authentication required\r\n\
    281 authentication accepted\r\n";
const HANDSHAKE_WRITES: &[&str] = &[
    "MODE READER\r\n",
    "AUTHINFO USER user\r\n",
    "AUTHINFO PASS pass\r\n",
];

#[tokio::test]
async fn handshake_with_auth() {
    let client = NntpClient::connect(Script::new(HANDSHAKE, HANDSHAKE_WRITES), &config())
        .await
        .expect("handshake");
    let script = client.into_inner();
    assert!(script.expect_writes.is_empty(), "all commands consumed");
}

#[tokio::test]
async fn auth_failure_surfaces_481() {
    let script = Script::new(
        "200 ready\r\n500 no\r\n381 more\r\n481 bad login\r\n",
        &[
            "MODE READER\r\n",
            "AUTHINFO USER user\r\n",
            "AUTHINFO PASS pass\r\n",
        ],
    );
    let Err(err) = NntpClient::connect(script, &config()).await else {
        panic!("expected NNTP error")
    };
    assert!(matches!(err, Error::AuthFailed(_)), "got {err}");
}

#[tokio::test]
async fn greeting_502_is_no_permission() {
    let Err(err) = NntpClient::connect(Script::new("502 access denied\r\n", &[]), &config()).await
    else {
        panic!("expected NNTP error")
    };
    assert!(matches!(err, Error::NoPermission(_)), "got {err}");
}

#[tokio::test]
async fn article_stat_body_and_group() {
    // Server answers 281 to AUTHINFO USER directly (no password round-trip).
    let script = Script::new(
        "200 ready\r\n500 no\r\n281 ok\r\n\
         223 42 <a@x> article follows\r\n\
         220 42 <a@x> article follows\r\n\
         From: p@example.com\r\nSubject: t\r\n\r\nbody line 1\r\n..stuffed dots\r\n.\r\n\
         222 42 <a@x> body follows\r\n\
         just the body\r\n.\r\n\
         211 100 1 100 alt.binaries.test group selected\r\n",
        &[
            "MODE READER\r\n",
            "AUTHINFO USER user\r\n",
            "STAT <a@x>\r\n",
            "ARTICLE <a@x>\r\n",
            "BODY <a@x>\r\n",
            "GROUP alt.binaries.test\r\n",
        ],
    );
    let mut client = NntpClient::connect(script, &config_auth_user_only())
        .await
        .expect("connect");

    assert_eq!(client.stat("a@x").await.unwrap(), 42);

    let mut article = Vec::new();
    client.article_to("a@x", &mut article).await.unwrap();
    // Dot-unstuffing: "..stuffed" arrives as ".stuffed".
    assert_eq!(
        article,
        b"From: p@example.com\r\nSubject: t\r\n\r\nbody line 1\r\n.stuffed dots\r\n"
    );

    let mut body = Vec::new();
    client.body_to("a@x", &mut body).await.unwrap();
    assert_eq!(body, b"just the body\r\n");

    let g = client.group("alt.binaries.test").await.unwrap();
    assert_eq!((g.count, g.first, g.last), (100, 1, 100));
    assert_eq!(g.name, "alt.binaries.test");
}

fn config_auth_user_only() -> NntpConfig {
    // Server answers 281 to AUTHINFO USER directly (no password needed).
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

#[tokio::test]
async fn article_430_is_not_found() {
    let script = Script::new(
        "200 ready\r\n500 no\r\n281 ok\r\n430 no such article\r\n",
        &[
            "MODE READER\r\n",
            "AUTHINFO USER user\r\n",
            "STAT <missing@x>\r\n",
        ],
    );
    let mut client = NntpClient::connect(script, &config_auth_user_only())
        .await
        .unwrap();
    let err = client.stat("missing@x").await.unwrap_err();
    assert!(matches!(err, Error::ArticleNotFound(_)), "got {err}");
}

#[tokio::test]
async fn auth_required_480_surfaces_auth_failed() {
    // RFC 4643 s2.3.1: 480 means authentication is required. The client
    // must surface it as an auth error (same class as 481/482), so the
    // synthetic harness can exercise the 480 path real providers send.
    let script = Script::new(
        "200 ready\r\n500 no\r\n281 ok\r\n480 authentication required\r\n",
        &[
            "MODE READER\r\n",
            "AUTHINFO USER user\r\n",
            "STAT <a@x>\r\n",
        ],
    );
    let mut client = NntpClient::connect(script, &config_auth_user_only())
        .await
        .unwrap();
    let err = client.stat("a@x").await.unwrap_err();
    assert!(matches!(err, Error::AuthFailed(_)), "got {err}");
}

#[tokio::test]
async fn pipelined_fetch_many_reads_in_order() {
    let script = Script::new(
        "200 ready\r\n500 no\r\n281 ok\r\n\
         220 1 <one@x>\r\none-body\r\n.\r\n\
         220 2 <two@x>\r\ntwo-body\r\n.\r\n",
        &[
            "MODE READER\r\n",
            "AUTHINFO USER user\r\n",
            "ARTICLE <one@x>\r\n",
            "ARTICLE <two@x>\r\n",
        ],
    );
    let mut client = NntpClient::connect(script, &config_auth_user_only())
        .await
        .unwrap();
    let out = client.fetch_many(&["one@x", "two@x"]).await.unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].message_id, "one@x");
    assert_eq!(out[0].article, b"one-body\r\n");
    assert_eq!(out[1].message_id, "two@x");
    assert_eq!(out[1].article, b"two-body\r\n");
}

#[tokio::test]
async fn max_pipelined_zero_is_rejected() {
    let mut cfg = config();
    cfg.max_pipelined = 0;
    let Err(err) = NntpClient::connect(Script::new("", &[]), &cfg).await else {
        panic!("expected NNTP error")
    };
    assert!(err.to_string().contains("max_pipelined"));
}

/// Live loopback: the native TCP transport against a scripted fake server.
#[tokio::test]
async fn native_transport_against_loopback_server() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        sock.write_all(b"200 fake ready\r\n").await.unwrap();
        let mut buf = [0u8; 1024];
        // MODE READER
        let n = sock.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"MODE READER\r\n");
        sock.write_all(b"500 unknown\r\n").await.unwrap();
        // AUTHINFO USER
        let n = sock.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"AUTHINFO USER user\r\n");
        sock.write_all(b"281 ok\r\n").await.unwrap();
        // STAT
        let n = sock.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"STAT <a@x>\r\n");
        sock.write_all(b"223 7 <a@x>\r\n").await.unwrap();
    });

    let cfg = NntpConfig {
        host: "127.0.0.1".into(),
        port,
        ..config_auth_user_only()
    };
    let transport = nntune_core::transports::connect_native(&cfg)
        .await
        .expect("connect");
    let mut client = NntpClient::connect(transport, &cfg)
        .await
        .expect("handshake");
    assert_eq!(client.stat("a@x").await.unwrap(), 7);
    server.await.unwrap();
}
