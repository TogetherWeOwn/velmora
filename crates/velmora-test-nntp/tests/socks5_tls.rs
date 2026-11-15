//! TLS to the server on a connection a SOCKS5 proxy opened
//! (`velmora::transports::proxy_tls`), over real TCP: the synthetic
//! proxy, a TLS server behind it, and the NNTP server behind that.
//!
//! The Workers connector runs these same steps over the runtime's
//! socket. Here the client trusts the fixture CA and reads a fixed
//! clock; production trusts the public roots.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use velmora::nntp::{NntpClient, NntpConfig};
use velmora::socks5::{self, is_proxy_failure, is_target_failure, Progress, Socks5Proxy};
use velmora::transport::Transport;
use velmora::transports::proxy_tls;
use velmora_test_nntp::{ProxyMode, TestNntpServer, TestSocks5Proxy};

const CA: &[u8] = include_bytes!("../../velmora/tests/fixtures/peer_tls/ca.der");
const CERT: &[u8] = include_bytes!("../../velmora/tests/fixtures/peer_tls/server.der");
const KEY: &[u8] = include_bytes!("../../velmora/tests/fixtures/peer_tls/server-key.der");
/// The name in the fixture certificate.
const NAME: &str = "nntp.fixture.invalid";
/// Inside the fixture certificate's validity.
const NOW: u64 = 1_800_000_000;

#[derive(Debug)]
struct FixedTime(u64);

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A client that trusts the fixture CA (or nothing).
fn connector(trusted: bool) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    if trusted {
        roots.add(CertificateDer::from(CA.to_vec())).unwrap();
    }
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.time_provider = Arc::new(FixedTime(NOW));
    TlsConnector::from(Arc::new(config))
}

/// What the TLS server saw.
#[derive(Default)]
struct Seen {
    /// TLS handshakes that completed.
    handshakes: usize,
    /// The names the clients asked for (SNI).
    names: Vec<String>,
    /// Bytes clients sent under TLS.
    bytes: usize,
}

/// A TLS server with the fixture certificate in front of `server`: what
/// a provider's NNTPS port is.
async fn tls_front(server: &TestNntpServer) -> (SocketAddr, Arc<Mutex<Seen>>) {
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(CERT.to_vec())],
            PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let target = server.addr();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let record = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let record = Arc::clone(&record);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                {
                    let mut seen = record.lock().unwrap();
                    seen.handshakes += 1;
                    let name = tls.get_ref().1.server_name().unwrap_or_default();
                    seen.names.push(name.to_string());
                }
                let Ok(backend) = TcpStream::connect(target).await else {
                    return;
                };
                let (mut from_client, mut to_client) = tokio::io::split(tls);
                let (mut from_backend, mut to_backend) = backend.into_split();
                let up = async {
                    let mut buf = [0u8; 4096];
                    loop {
                        match from_client.read(&mut buf).await {
                            Ok(n) if n > 0 => {
                                record.lock().unwrap().bytes += n;
                                if to_backend.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                            _ => return,
                        }
                    }
                };
                let down = async {
                    let _ = tokio::io::copy(&mut from_backend, &mut to_client).await;
                };
                tokio::join!(up, down);
            });
        }
    });
    (addr, seen)
}

/// The TLS stream as the engine's transport.
struct Tls(TlsStream<TcpStream>);

impl Transport for Tls {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).await
    }
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        proxy_tls::write_all_flushed(&mut self.0, buf).await
    }
    async fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}

/// A correct proxy, and the login for it (made at run time).
async fn proxy() -> (TestSocks5Proxy, Socks5Proxy) {
    let id = std::process::id();
    let (username, password) = (format!("user-{id}"), format!("word-{id}"));
    let proxy = TestSocks5Proxy::spawn(&username, &password, ProxyMode::Relay).await;
    let login = Socks5Proxy {
        host: proxy.addr().ip().to_string(),
        port: proxy.addr().port(),
        username,
        password,
    };
    (proxy, login)
}

fn nntp_config(host: &str) -> NntpConfig {
    NntpConfig {
        host: host.to_string(),
        port: 563,
        tls: true,
        username: Some("testuser".into()),
        password: Some("testpass".into()),
        timeout: Duration::from_secs(10),
        ..NntpConfig::default()
    }
}

/// Never ends: a connect with no limit of its own.
fn no_limit() -> std::future::Pending<()> {
    std::future::pending()
}

async fn connect(
    proxy: &TestSocks5Proxy,
    login: &Socks5Proxy,
    connector: &TlsConnector,
    cfg: &NntpConfig,
    progress: &Progress,
) -> io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(proxy.addr()).await.unwrap();
    proxy_tls::connect(tcp, connector, cfg, login, progress, no_limit()).await
}

/// Through the proxy and under TLS the engine logs in and reads an
/// article. The proxy was asked for the server by name, the TLS server
/// was asked for the same name, and its certificate carries it.
#[tokio::test]
async fn an_nntp_session_runs_under_tls_through_the_proxy() {
    let server = TestNntpServer::spawn_for_test().await;
    let (front, seen) = tls_front(&server).await;
    let (proxy, login) = proxy().await;
    proxy.resolve(NAME, front);
    let cfg = nntp_config(NAME);
    let progress = Progress::new();

    let tls = connect(&proxy, &login, &connector(true), &cfg, &progress)
        .await
        .unwrap();
    assert!(progress.logged_in());
    let mut client = NntpClient::connect(Tls(tls), &cfg).await.unwrap();
    let id = velmora_test_nntp::default_corpus()[0].message_id.clone();
    let mut body = Vec::new();
    client
        .body_to(id.trim_matches(['<', '>']), &mut body)
        .await
        .unwrap();
    assert!(!body.is_empty());
    client.quit().await;

    assert_eq!(proxy.targets(), [(NAME.to_string(), 563)]);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.names, [NAME]);
    assert!(seen.bytes > 0);
}

/// The proxy connects to a server whose certificate is for another name
/// than the one asked for (a proxy that sends the connection elsewhere,
/// or a host that is not the provider's). The connect fails as the
/// host's failure, with the fixed text, and nothing was sent under TLS:
/// no greeting was read and no login written.
#[tokio::test]
async fn a_certificate_for_another_name_fails_closed() {
    let server = TestNntpServer::spawn_for_test().await;
    let (front, seen) = tls_front(&server).await;
    let (proxy, login) = proxy().await;
    let other = "other.fixture.invalid";
    proxy.resolve(other, front);
    let cfg = nntp_config(other);
    let progress = Progress::new();

    let e = connect(&proxy, &login, &connector(true), &cfg, &progress)
        .await
        .expect_err("a certificate for another name must not pass");
    assert_eq!(e.to_string(), socks5::ERR_TLS);
    assert!(is_target_failure(&e) && !is_proxy_failure(&e));
    assert!(progress.logged_in());
    assert_eq!(proxy.targets(), [(other.to_string(), 563)]);
    // Give the server time to count a handshake, had one completed.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let seen = seen.lock().unwrap();
    assert_eq!((seen.handshakes, seen.bytes), (0, 0));
}

/// The right name on a chain the client does not trust fails the same
/// way.
#[tokio::test]
async fn an_untrusted_chain_fails_closed() {
    let server = TestNntpServer::spawn_for_test().await;
    let (front, seen) = tls_front(&server).await;
    let (proxy, login) = proxy().await;
    proxy.resolve(NAME, front);
    let cfg = nntp_config(NAME);

    let e = connect(&proxy, &login, &connector(false), &cfg, &Progress::new())
        .await
        .expect_err("an untrusted chain must not pass");
    assert_eq!(e.to_string(), socks5::ERR_TLS);
    assert!(is_target_failure(&e));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let seen = seen.lock().unwrap();
    assert_eq!((seen.handshakes, seen.bytes), (0, 0));
}

/// A server that does not speak TLS (the plaintext NNTP port) is not
/// talked to in plaintext: the connect fails, and no login was sent.
#[tokio::test]
async fn a_server_without_tls_is_not_talked_to() {
    let server = TestNntpServer::spawn_for_test().await;
    let (proxy, login) = proxy().await;
    proxy.resolve(NAME, server.addr());
    let cfg = nntp_config(NAME);

    let e = connect(&proxy, &login, &connector(true), &cfg, &Progress::new())
        .await
        .expect_err("plaintext must not pass for TLS");
    // The greeting came with the proxy's reply (refused there) or after
    // it (refused by TLS).
    let text = e.to_string();
    assert!(
        text == socks5::ERR_TLS || text == socks5::ERR_TRAILING,
        "{text}"
    );
}

/// A configuration without TLS, or with an address for a host, is
/// refused before a byte goes to the proxy.
#[tokio::test]
async fn no_tls_or_no_name_sends_nothing() {
    let (proxy, login) = proxy().await;
    let plain = NntpConfig {
        tls: false,
        allow_insecure_plaintext: true,
        ..nntp_config(NAME)
    };
    let address = nntp_config("127.0.0.1");
    let address6 = nntp_config("::1");
    for cfg in [plain, address, address6] {
        let progress = Progress::new();
        let e = connect(&proxy, &login, &connector(true), &cfg, &progress)
            .await
            .expect_err("refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().starts_with("transport_tls_required"));
        assert!(!is_proxy_failure(&e) && !is_target_failure(&e));
        assert!(!progress.logged_in());
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(proxy.targets().is_empty());
}

/// The limit ends a connect that hangs, and says whose wait it was: the
/// host's when the proxy had accepted the login, the proxy's before.
#[tokio::test]
async fn the_limit_ends_a_connect_that_hangs() {
    // Accepts and never answers.
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    let held = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = silent.accept().await {
            held.push(tcp);
        }
    });
    let cfg = nntp_config(NAME);
    let limit = || tokio::time::sleep(Duration::from_millis(200));

    // A host that accepts the connection and does not answer TLS.
    let (proxy, login) = proxy().await;
    proxy.resolve(NAME, silent_addr);
    let progress = Progress::new();
    let tcp = TcpStream::connect(proxy.addr()).await.unwrap();
    let e = proxy_tls::connect(tcp, &connector(true), &cfg, &login, &progress, limit())
        .await
        .expect_err("out of time");
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert!(is_target_failure(&e) && progress.logged_in());

    // A proxy that accepts the connection and does not answer.
    let progress = Progress::new();
    let tcp = TcpStream::connect(silent_addr).await.unwrap();
    let e = proxy_tls::connect(tcp, &connector(true), &cfg, &login, &progress, limit())
        .await
        .expect_err("out of time");
    assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    assert_eq!(e.to_string(), socks5::ERR_TIMEOUT);
    assert!(is_proxy_failure(&e) && !progress.logged_in());
    held.abort();
}

/// A proxy that refuses the login is the proxy's failure, and no TLS
/// was tried with anyone.
#[tokio::test]
async fn a_refused_login_is_the_proxys_failure() {
    let server = TestNntpServer::spawn_for_test().await;
    let (front, seen) = tls_front(&server).await;
    let (proxy, mut login) = proxy().await;
    proxy.resolve(NAME, front);
    login.password.push('x');
    let progress = Progress::new();
    let e = connect(
        &proxy,
        &login,
        &connector(true),
        &nntp_config(NAME),
        &progress,
    )
    .await
    .expect_err("refused");
    assert_eq!(e.to_string(), socks5::ERR_AUTH);
    assert!(is_proxy_failure(&e) && !progress.logged_in());
    assert!(proxy.targets().is_empty());
    assert_eq!(seen.lock().unwrap().handshakes, 0);
}
