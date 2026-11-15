//! The SOCKS5 handshake of `velmora::socks5` over real TCP, against the
//! synthetic proxy, and an NNTP session through the relayed connection.
//!
//! The servers here speak plaintext on loopback, so these tests cover
//! the proxy stage and the hand-over to the target's stream. The TLS
//! that production starts on the proxied connection is the runtime's.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use velmora::nntp::{NntpClient, NntpConfig};
use velmora::socks5::{self, is_proxy_failure, is_target_failure};
use velmora::transport::Transport;
use velmora_test_nntp::{ProxyMode, TestNntpServer, TestSocks5Proxy};

/// The proxy login of a test run, made at run time: no login is written
/// in the source.
fn login() -> &'static (String, String) {
    static LOGIN: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
    LOGIN.get_or_init(|| {
        let id = std::process::id();
        (format!("user-{id}"), format!("word-{id}"))
    })
}

fn proxy_user() -> &'static str {
    &login().0
}

fn proxy_pass() -> &'static str {
    &login().1
}

/// A plain TCP stream as the engine's transport.
struct Tcp(TcpStream);

impl Transport for Tcp {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).await
    }
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf).await
    }
    async fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}

async fn to_proxy(proxy: &TestSocks5Proxy) -> Tcp {
    Tcp(TcpStream::connect(proxy.addr()).await.unwrap())
}

fn nntp_config(server: &TestNntpServer) -> NntpConfig {
    NntpConfig {
        host: server.addr().ip().to_string(),
        port: server.addr().port(),
        tls: false,
        allow_insecure_plaintext: true,
        username: Some("testuser".into()),
        password: Some("testpass".into()),
        timeout: Duration::from_secs(10),
        ..NntpConfig::default()
    }
}

/// Runs the handshake for `server` with the given login.
async fn handshake(
    proxy: &TestSocks5Proxy,
    server: &TestNntpServer,
    user: &str,
    pass: &str,
) -> (io::Result<()>, Tcp) {
    let mut tcp = to_proxy(proxy).await;
    let cfg = nntp_config(server);
    let out = socks5::connect(&mut tcp, user, pass, &cfg.host, cfg.port).await;
    (out, tcp)
}

/// Through a correct proxy the engine logs in to the server and reads an
/// article: the proxy was asked for exactly the server, by name, and
/// nothing of the server's stream was lost to the handshake.
#[tokio::test]
async fn an_nntp_session_runs_through_the_proxy() {
    let server = TestNntpServer::spawn_for_test().await;
    let proxy = TestSocks5Proxy::spawn(proxy_user(), proxy_pass(), ProxyMode::Relay).await;
    let (out, tcp) = handshake(&proxy, &server, proxy_user(), proxy_pass()).await;
    out.unwrap();

    let cfg = nntp_config(&server);
    let mut client = NntpClient::connect(tcp, &cfg).await.unwrap();
    let id = velmora_test_nntp::default_corpus()[0].message_id.clone();
    let id = id.trim_matches(['<', '>']);
    let mut body = Vec::new();
    client.body_to(id, &mut body).await.unwrap();
    assert!(!body.is_empty());
    client.quit().await;

    assert_eq!(proxy.targets(), [(cfg.host.clone(), cfg.port)]);
    assert_eq!(proxy.connections(), 1);
}

/// A wrong login is refused by the proxy: a proxy failure, and the
/// proxy was never asked to connect anywhere.
#[tokio::test]
async fn a_wrong_login_is_a_proxy_failure() {
    let server = TestNntpServer::spawn_for_test().await;
    let proxy = TestSocks5Proxy::spawn(proxy_user(), proxy_pass(), ProxyMode::Relay).await;
    let other = format!("other-{}", std::process::id());
    for (user, pass) in [
        (proxy_user(), other.as_str()),
        (other.as_str(), proxy_pass()),
    ] {
        let (out, _tcp) = handshake(&proxy, &server, user, pass).await;
        let e = out.unwrap_err();
        assert_eq!(e.to_string(), socks5::ERR_AUTH);
        assert!(is_proxy_failure(&e) && !is_target_failure(&e));
    }
    assert!(proxy.targets().is_empty());
}

/// A target nothing listens on: the proxy works and says so. That is the
/// target's failure, not the proxy's.
#[tokio::test]
async fn a_dead_target_is_a_target_failure() {
    let proxy = TestSocks5Proxy::spawn(proxy_user(), proxy_pass(), ProxyMode::Relay).await;
    // A port that was free a moment ago.
    let dead = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let mut tcp = to_proxy(&proxy).await;
    let e = socks5::connect(&mut tcp, proxy_user(), proxy_pass(), "127.0.0.1", dead)
        .await
        .unwrap_err();
    assert_eq!(e.to_string(), socks5::ERR_CONNECT);
    assert!(is_target_failure(&e) && !is_proxy_failure(&e));
}

/// Every way the proxy can misbehave ends the handshake with the fixed
/// error for it, as a proxy failure, and with no secret in its text.
#[tokio::test]
async fn a_misbehaving_proxy_is_refused() {
    let server = TestNntpServer::spawn_for_test().await;
    // The last column: the failure is the proxy's own. A connection that
    // ends after the login was accepted, while the proxy was connecting,
    // counts against the target: a proxy that reaches no host often just
    // closes.
    let cases = [
        (ProxyMode::SelectsNoAuth, socks5::ERR_METHOD, true),
        (ProxyMode::NoAcceptableMethod, socks5::ERR_METHOD, true),
        (ProxyMode::RefuseLogin, socks5::ERR_AUTH, true),
        (ProxyMode::RefuseConnect(2), socks5::ERR_REQUEST, true),
        (ProxyMode::MalformedReply, socks5::ERR_MALFORMED, true),
        (ProxyMode::TruncatedReply, socks5::ERR_CLOSED, false),
        (ProxyMode::CloseEarly, socks5::ERR_CLOSED, true),
    ];
    for (mode, message, own) in cases {
        let proxy = TestSocks5Proxy::spawn(proxy_user(), proxy_pass(), mode).await;
        let (out, _tcp) = handshake(&proxy, &server, proxy_user(), proxy_pass()).await;
        let e = out.expect_err("handshake must fail");
        assert_eq!(e.to_string(), message, "{mode:?}");
        assert_eq!(
            (is_proxy_failure(&e), is_target_failure(&e)),
            (own, !own),
            "{mode:?}"
        );
        let text = format!("{e} {e:?}");
        for secret in [proxy_user(), proxy_pass(), "127.0.0.1"] {
            assert!(!text.contains(secret), "{mode:?}: {text}");
        }
    }
    // The proxy that connects nowhere by its own reply code 5.
    let proxy =
        TestSocks5Proxy::spawn(proxy_user(), proxy_pass(), ProxyMode::RefuseConnect(5)).await;
    let (out, _tcp) = handshake(&proxy, &server, proxy_user(), proxy_pass()).await;
    assert!(is_target_failure(&out.unwrap_err()));
}

/// A reply with more bytes than its header says, in one segment: the
/// handshake refuses it. The extra bytes would otherwise be taken for
/// the start of the server's stream.
#[tokio::test]
async fn bytes_after_the_reply_are_refused() {
    let server = TestNntpServer::spawn_for_test().await;
    let mode = ProxyMode::TrailingBytes(b"200 injected greeting\r\n");
    let proxy = TestSocks5Proxy::spawn(proxy_user(), proxy_pass(), mode).await;
    let (out, _tcp) = handshake(&proxy, &server, proxy_user(), proxy_pass()).await;
    let e = out.unwrap_err();
    assert_eq!(e.to_string(), socks5::ERR_TRAILING);
    assert!(is_proxy_failure(&e));
}
