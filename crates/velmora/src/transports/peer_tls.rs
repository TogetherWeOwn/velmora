//! TLS identity kept separate from a literal TCP destination. This module
//! does not resolve DNS or authenticate resolver evidence: its caller must
//! validate the full answer set, account/configuration binding and freshness.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// A public literal peer plus an independent DNS certificate identity.
/// Construction checks the selected peer only; it is not a resolver proof,
/// an admission token or permission to send credentials.
#[derive(Clone, Debug)]
pub struct PeerTlsTarget {
    peer: SocketAddr,
    server_name: ServerName<'static>,
}

impl PeerTlsTarget {
    pub fn new(peer: SocketAddr, dns_name: String) -> io::Result<Self> {
        if !matches!(peer.port(), 119 | 563)
            || velmora_ssrf_guard::ip_is_forbidden(&peer.ip())
            || matches!(peer, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NNTP TLS peer is not allowed",
            ));
        }
        let server_name = ServerName::try_from(dns_name).map_err(|_| invalid_name())?;
        if !matches!(server_name, ServerName::DnsName(_)) {
            return Err(invalid_name());
        }
        Ok(Self { peer, server_name })
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn server_name(&self) -> ServerName<'static> {
        self.server_name.clone()
    }
}

fn invalid_name() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "NNTP TLS DNS name is invalid")
}

pub(crate) fn public_connector() -> io::Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(TlsConnector::from(Arc::new(tls_config(roots)?)))
}

pub(crate) async fn write_all_flushed(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    buf: &[u8],
) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    // tokio-rustls is buffered: a subsequent read does not drain ciphertext.
    // Callers keep both awaits inside one per-write timeout.
    stream.write_all(buf).await?;
    stream.flush().await
}

/// ring's default provider with the ChaCha20-Poly1305 suites offered
/// first, within each protocol version (TLS 1.3 suites stay ahead of TLS
/// 1.2 ones, as in the default). Nothing is added or removed: the AES-GCM
/// suites stay as fallback for a server that does not take ChaCha20, and
/// key exchange groups, signature algorithms and the protocol versions are
/// ring's defaults. In wasm there is no AES instruction, so AES-GCM costs
/// several times the CPU of ChaCha20-Poly1305 per byte; a server that
/// honours the client's order then picks the cheaper one.
fn nntp_crypto_provider() -> rustls::crypto::CryptoProvider {
    use rustls::{CipherSuite, SupportedCipherSuite};
    let mut provider = rustls::crypto::ring::default_provider();
    // Stable sort: the default order is kept inside each group.
    provider.cipher_suites.sort_by_key(|suite| {
        let tls12 = matches!(suite, SupportedCipherSuite::Tls12(_));
        let chacha = matches!(
            suite.suite(),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                | CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        );
        (tls12, !chacha)
    });
    provider
}

fn tls_config(roots: RootCertStore) -> io::Result<ClientConfig> {
    // Explicit selection also works when another crate enables a second
    // provider. Never use a global install or a permissive verifier.
    ClientConfig::builder_with_provider(Arc::new(nntp_crypto_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| io::Error::other("NNTP TLS configuration unavailable"))
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::time::Duration;

    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime};
    use rustls::time_provider::TimeProvider;
    use rustls::ServerConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;

    const CA: &[u8] = include_bytes!("../../tests/fixtures/peer_tls/ca.der");
    const CERT: &[u8] = include_bytes!("../../tests/fixtures/peer_tls/server.der");
    const KEY: &[u8] = include_bytes!("../../tests/fixtures/peer_tls/server-key.der");
    const FIXTURE_AUTH: &[u8] = b"AUTHINFO USER synthetic-fixture-user\r\n";

    #[derive(Debug)]
    struct FixedTime(u64);

    impl TimeProvider for FixedTime {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
        }
    }

    // Test-only roots, clock and loopback/ephemeral-port injection. The real
    // adapter exposes neither arbitrary roots nor this target constructor.
    async fn exchange(
        name: &str,
        trusted: bool,
        now: u64,
        broken: bool,
    ) -> (io::Result<()>, Option<String>, Vec<u8>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = PeerTlsTarget {
                peer: listener.local_addr().unwrap(),
                server_name: ServerName::try_from(name.to_string()).unwrap(),
            };
            let server_config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(CERT.to_vec())],
                PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
            )
            .unwrap();
            let server = async move {
                let (tcp, _) = listener.accept().await.unwrap();
                if broken {
                    return (None, Vec::new());
                }
                let Ok(mut tls) = TlsAcceptor::from(Arc::new(server_config)).accept(tcp).await
                else {
                    return (None, Vec::new());
                };
                let sni = tls.get_ref().1.server_name().map(str::to_string);
                let mut bytes = Vec::new();
                let _ = tls.read_to_end(&mut bytes).await;
                (sni, bytes)
            };
            let mut roots = RootCertStore::empty();
            if trusted {
                roots.add(CertificateDer::from(CA.to_vec())).unwrap();
            }
            let mut config = tls_config(roots).unwrap();
            config.time_provider = Arc::new(FixedTime(now));
            let client = async move {
                // SocketAddr never invokes a hostname resolver. The DNS name
                // goes only to rustls, exactly as in the Worker adapter.
                let tcp = TcpStream::connect(target.peer()).await?;
                let mut tls = TlsConnector::from(Arc::new(config))
                    .connect(target.server_name(), tcp)
                    .await?;
                tls.write_all(FIXTURE_AUTH).await?;
                tls.shutdown().await
            };
            let (result, (sni, bytes)) = tokio::join!(client, server);
            (result, sni, bytes)
        })
        .await
        .expect("TLS fixture must not hang")
    }

    #[tokio::test]
    async fn tls_to_literal_peer_validates_independent_dns_name_and_sni() {
        let (result, sni, bytes) =
            exchange("nntp.fixture.invalid", true, 1_800_000_000, false).await;
        result.unwrap();
        assert_eq!(sni.as_deref(), Some("nntp.fixture.invalid"));
        assert_eq!(bytes, FIXTURE_AUTH);
    }

    #[tokio::test]
    async fn tls_rejects_wrong_dns_name_before_auth() {
        let (result, _, bytes) =
            exchange("wrong.fixture.invalid", true, 1_800_000_000, false).await;
        assert!(result.is_err());
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn tls_rejects_untrusted_chain_before_auth() {
        let (result, _, bytes) =
            exchange("nntp.fixture.invalid", false, 1_800_000_000, false).await;
        assert!(result.is_err());
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn tls_rejects_not_yet_valid_certificate_before_auth() {
        let (result, _, bytes) = exchange("nntp.fixture.invalid", true, 1, false).await;
        assert!(result.is_err());
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn tls_rejects_expired_certificate_before_auth() {
        let (result, _, bytes) = exchange("nntp.fixture.invalid", true, 8_000_000_000, false).await;
        assert!(result.is_err());
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn broken_tls_handshake_sends_no_auth() {
        let (result, _, bytes) = exchange("nntp.fixture.invalid", true, 1_800_000_000, true).await;
        assert!(result.is_err());
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn multi_record_write_then_read_flushes_under_backpressure() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client_io, server_io) = tokio::io::duplex(1024);
            let server_config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(CERT.to_vec())],
                PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
            )
            .unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(CertificateDer::from(CA.to_vec())).unwrap();
            let mut client_config = tls_config(roots).unwrap();
            client_config.time_provider = Arc::new(FixedTime(1_800_000_000));
            let payload = vec![b'x'; 100_000];
            let expected = payload.clone();
            let server = async move {
                let mut tls = TlsAcceptor::from(Arc::new(server_config))
                    .accept(server_io)
                    .await
                    .unwrap();
                let mut actual = vec![0; expected.len()];
                tls.read_exact(&mut actual).await.unwrap();
                assert_eq!(actual, expected);
                tls.write_all(b"ACK").await.unwrap();
                tls.flush().await.unwrap();
            };
            let client = async move {
                let mut tls = TlsConnector::from(Arc::new(client_config))
                    .connect(
                        ServerName::try_from("nntp.fixture.invalid").unwrap(),
                        client_io,
                    )
                    .await
                    .unwrap();
                write_all_flushed(&mut tls, &payload).await.unwrap();
                // No shutdown or further writes to accidentally flush records.
                let mut ack = [0; 3];
                tls.read_exact(&mut ack).await.unwrap();
                assert_eq!(&ack, b"ACK");
            };
            tokio::join!(client, server);
        })
        .await
        .expect("buffered TLS writes must reach the server before reading its reply");
    }

    /// Handshakes the production client config (fixture CA, fixed clock)
    /// with a server built from `provider` and `versions`, and returns the
    /// suite both ends agreed on.
    async fn negotiated_suite(
        provider: rustls::crypto::CryptoProvider,
        versions: &[&'static rustls::SupportedProtocolVersion],
        ignore_client_order: bool,
    ) -> rustls::CipherSuite {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            let mut server_config = ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(versions)
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(CERT.to_vec())],
                    PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
                )
                .unwrap();
            server_config.ignore_client_order = ignore_client_order;
            let mut roots = RootCertStore::empty();
            roots.add(CertificateDer::from(CA.to_vec())).unwrap();
            let mut client_config = tls_config(roots).unwrap();
            client_config.time_provider = Arc::new(FixedTime(1_800_000_000));
            let server = async move {
                let mut tls = TlsAcceptor::from(Arc::new(server_config))
                    .accept(server_io)
                    .await
                    .unwrap();
                let suite = tls.get_ref().1.negotiated_cipher_suite().unwrap().suite();
                tls.write_all(b"200 ok\r\n").await.unwrap();
                tls.flush().await.unwrap();
                suite
            };
            let client = async move {
                let mut tls = TlsConnector::from(Arc::new(client_config))
                    .connect(
                        ServerName::try_from("nntp.fixture.invalid").unwrap(),
                        client_io,
                    )
                    .await
                    .unwrap();
                let mut greeting = [0; 8];
                tls.read_exact(&mut greeting).await.unwrap();
                assert_eq!(&greeting, b"200 ok\r\n");
                tls.get_ref().1.negotiated_cipher_suite().unwrap().suite()
            };
            let (client_suite, server_suite) = tokio::join!(client, server);
            assert_eq!(client_suite, server_suite);
            client_suite
        })
        .await
        .expect("TLS fixture must not hang")
    }

    fn suites(provider: &rustls::crypto::CryptoProvider) -> Vec<rustls::CipherSuite> {
        provider.cipher_suites.iter().map(|s| s.suite()).collect()
    }

    /// ring's default provider without its ChaCha20-Poly1305 suites: a
    /// server that does not offer ChaCha20.
    fn aes_only_provider() -> rustls::crypto::CryptoProvider {
        let mut provider = rustls::crypto::ring::default_provider();
        provider
            .cipher_suites
            .retain(|s| !format!("{:?}", s.suite()).contains("CHACHA20"));
        assert!(!provider.cipher_suites.is_empty());
        provider
    }

    #[test]
    fn chacha20_suites_are_offered_first_and_aes_stays_as_fallback() {
        use rustls::CipherSuite as S;
        let config = tls_config(RootCertStore::empty()).unwrap();
        assert_eq!(
            suites(config.crypto_provider()),
            [
                S::TLS13_CHACHA20_POLY1305_SHA256,
                S::TLS13_AES_256_GCM_SHA384,
                S::TLS13_AES_128_GCM_SHA256,
                S::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                S::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                S::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                S::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                S::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                S::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ]
        );
    }

    #[test]
    fn only_the_suite_order_differs_from_ring_defaults() {
        let ours = nntp_crypto_provider();
        let ring = rustls::crypto::ring::default_provider();
        // Same suites, none added or dropped.
        let mut a = suites(&ours);
        let mut b = suites(&ring);
        a.sort_by_key(|s| u16::from(*s));
        b.sort_by_key(|s| u16::from(*s));
        assert_eq!(a, b);
        // Same key exchange groups, in the same order.
        let groups = |p: &rustls::crypto::CryptoProvider| {
            p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>()
        };
        assert_eq!(groups(&ours), groups(&ring));
        // Same signature verification algorithms.
        assert_eq!(
            format!("{:?}", ours.signature_verification_algorithms),
            format!("{:?}", ring.signature_verification_algorithms)
        );
        // The protocol versions stay `with_safe_default_protocol_versions`
        // (TLS 1.3 and 1.2): the handshake tests below run both.
    }

    #[tokio::test]
    async fn a_server_that_honours_client_order_negotiates_chacha20() {
        use rustls::CipherSuite as S;
        let ring = rustls::crypto::ring::default_provider;
        assert_eq!(
            negotiated_suite(ring(), rustls::DEFAULT_VERSIONS, false).await,
            S::TLS13_CHACHA20_POLY1305_SHA256
        );
        let tls12 = negotiated_suite(ring(), &[&rustls::version::TLS12], false).await;
        assert!(
            matches!(
                tls12,
                S::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                    | S::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            ),
            "{tls12:?}"
        );
    }

    #[tokio::test]
    async fn a_server_without_chacha20_falls_back_to_aes_gcm() {
        use rustls::CipherSuite as S;
        assert_eq!(
            negotiated_suite(aes_only_provider(), rustls::DEFAULT_VERSIONS, false).await,
            S::TLS13_AES_256_GCM_SHA384
        );
        let tls12 = negotiated_suite(aes_only_provider(), &[&rustls::version::TLS12], false).await;
        assert!(
            matches!(
                tls12,
                S::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                    | S::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            ),
            "{tls12:?}"
        );
    }

    #[tokio::test]
    async fn a_server_that_imposes_its_own_order_still_connects() {
        // ring's default order puts AES-256-GCM first; a server that ignores
        // the client's order picks it, and the session works as before.
        assert_eq!(
            negotiated_suite(
                rustls::crypto::ring::default_provider(),
                rustls::DEFAULT_VERSIONS,
                true
            )
            .await,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
        );
    }

    #[test]
    fn literal_peer_and_dns_identity_are_independent() {
        let peer = "93.184.216.34:563".parse().unwrap();
        let target = PeerTlsTarget::new(peer, "nntp.fixture.invalid".into()).unwrap();
        assert_eq!(target.peer(), peer);
        assert!(matches!(target.server_name(), ServerName::DnsName(_)));
    }

    #[test]
    fn forbidden_peers_ports_and_non_dns_identities_refuse() {
        for peer in [
            "127.0.0.1:563".parse().unwrap(),
            ([10, 0, 0, 1], 563).into(),
            ([169, 254, 169, 254], 563).into(),
            "[::1]:563".parse().unwrap(),
            "[::ffff:127.0.0.1]:563".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            "93.184.216.34:0".parse().unwrap(),
        ] {
            assert!(PeerTlsTarget::new(peer, "nntp.fixture.invalid".into()).is_err());
        }
        for name in ["127.0.0.1", "93.184.216.34", "::1", "", "not a dns name"] {
            assert!(PeerTlsTarget::new("93.184.216.34:563".parse().unwrap(), name.into()).is_err());
        }
    }
}
