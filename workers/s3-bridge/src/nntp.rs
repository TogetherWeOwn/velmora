//! `impl NntpConnector` over `velmora::transports::WorkerTransport`.
//!
//! TLS policy (fail closed, checked before any socket opens):
//! - A TLS provider passes the engine's pinned policy
//!   (`velmora::pinned_transport`: TLS, port 119 or 563) and is opened with
//!   `WorkerTransport::connect_pinned`.
//! - A plaintext provider is accepted only on a loopback host: the local
//!   fake server under `wrangler dev`. `BridgeConfig` already refuses
//!   `tls: false` outside `ENVIRONMENT=dev`, and the deployed runtime cannot
//!   reach loopback.
//!
//! Sessions read at most 1 MiB per article body. Policy refusals and
//! socket-open failures are class-only (no host or credential). Later
//! session errors are the engine's own: their `Debug` redacts auth reply
//! text, but `Display` may carry a runtime I/O message or a server reply.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use futures_util::future::{select, Either};
use velmora::nntp::{NntpClient, NntpConfig, PostOutcome};
use velmora::pinned_transport::pinned_rejection_message;
use velmora_bridge::{
    BodyOutcome, BridgeError, NntpConnector, NntpSession, Permit, PermitClass, ProviderConfig,
    Result, QUIT_SECS,
};

/// Largest article the bridge reads or posts (velmora articles are about
/// 744 KB on the wire).
pub const MAX_ARTICLE_BYTES: usize = 1024 * 1024;

/// Per-operation socket timeout; one 1 MiB POST is a single write.
const OP_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(target_arch = "wasm32")]
type Socket = velmora::transports::WorkerTransport;
#[cfg(not(target_arch = "wasm32"))]
type Socket = native::NoSocket;

/// The port's bound on one whole call. The per-operation timeout alone
/// does not give it: a POST is several operations, each of which may
/// take almost [`OP_TIMEOUT`]. A call that runs out of time is dropped,
/// which poisons its session, and ends as a timed-out transport error:
/// the caller reconnects and looks the article up before sending again.
async fn within_call<T>(secs: u32, call: impl Future<Output = Result<T>>) -> Result<T> {
    within(after(secs), call).await
}

/// `call`, unless `limit` ends first. A call that is done when the limit
/// is too counts as done.
async fn within<T>(
    limit: impl Future<Output = ()>,
    call: impl Future<Output = Result<T>>,
) -> Result<T> {
    let call = std::pin::pin!(call);
    let limit = std::pin::pin!(limit);
    match select(call, limit).await {
        Either::Left((out, _)) => out,
        Either::Right(_) => Err(BridgeError::Nntp(velmora::Error::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "nntp call ran out of time",
        )))),
    }
}

/// Ends after `secs` on the runtime's timer.
#[cfg(target_arch = "wasm32")]
async fn after(secs: u32) {
    worker::Delay::from(Duration::from_secs(u64::from(secs))).await;
}

/// Native builds open no socket, so there is nothing to bound.
#[cfg(not(target_arch = "wasm32"))]
async fn after(_secs: u32) {
    std::future::pending().await
}

/// One authenticated session, and the class of the permit it was opened
/// under, which bounds its calls. A thin wrapper: the port is foreign to
/// this crate, so it cannot be implemented on `NntpClient` here.
pub struct WorkerSession(NntpClient<Socket>, PermitClass);

impl NntpSession for WorkerSession {
    async fn post(&mut self, message_id: &str, article: &[u8]) -> Result<PostOutcome> {
        let call = async { Ok(self.0.post_article(message_id, article).await?) };
        within_call(self.1.call_secs(), call).await
    }

    async fn stat(&mut self, message_id: &str) -> Result<bool> {
        within_call(self.1.call_secs(), async {
            match self.0.stat(message_id).await {
                Ok(_) => Ok(true),
                Err(velmora::Error::ArticleNotFound(_)) => Ok(false),
                Err(e) => Err(e.into()),
            }
        })
        .await
    }

    async fn body(&mut self, message_id: &str, out: &mut Vec<u8>) -> Result<BodyOutcome> {
        within_call(self.1.call_secs(), async {
            match self.0.body_to(message_id, out).await {
                Ok(()) => Ok(BodyOutcome::Found),
                Err(velmora::Error::ArticleNotFound(_)) => Ok(BodyOutcome::Missing),
                Err(e) => Err(e.into()),
            }
        })
        .await
    }

    async fn quit(self) {
        // A goodbye nobody answers must not hold the job either.
        let _ = within_call(QUIT_SECS, async {
            self.0.quit().await;
            Ok(())
        })
        .await;
    }
}

pub struct WorkerConnector;

impl WorkerConnector {
    pub fn new() -> Self {
        WorkerConnector
    }
}

impl NntpConnector for WorkerConnector {
    type Session = WorkerSession;

    async fn connect(&self, provider: &ProviderConfig, permit: &Permit) -> Result<WorkerSession> {
        if permit.provider != provider.id {
            return Err(BridgeError::Invalid("permit is for another provider"));
        }
        let cfg = nntp_config(provider)?;
        let socket = open(&cfg)?;
        let class = permit.class;
        within_call(class.call_secs(), async {
            Ok(WorkerSession(
                NntpClient::connect(socket, &cfg).await?,
                class,
            ))
        })
        .await
    }
}

fn is_loopback(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn refused(msg: String) -> BridgeError {
    BridgeError::Nntp(velmora::Error::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        msg,
    )))
}

/// The engine config for one provider, after the TLS policy.
fn nntp_config(p: &ProviderConfig) -> Result<NntpConfig> {
    let with_auth = !p.user.is_empty();
    let cfg = NntpConfig {
        host: p.host.clone(),
        port: p.port,
        tls: p.tls,
        allow_insecure_plaintext: !p.tls,
        username: with_auth.then(|| p.user.clone()),
        password: with_auth.then(|| p.pass.clone()),
        timeout: OP_TIMEOUT,
        max_article_bytes: MAX_ARTICLE_BYTES,
        ..NntpConfig::default()
    };
    if !p.tls {
        if !is_loopback(&p.host) {
            return Err(refused(
                "transport_tls_required: plaintext only on loopback".into(),
            ));
        }
    } else if let Some(msg) = pinned_rejection_message(&cfg) {
        return Err(refused(msg));
    }
    Ok(cfg)
}

#[cfg(target_arch = "wasm32")]
fn open(cfg: &NntpConfig) -> Result<Socket> {
    let socket = if cfg.tls {
        Socket::connect_pinned(cfg)
    } else {
        Socket::connect(cfg)
    };
    // The runtime's message may name the host: keep the class only.
    socket.map_err(|_| {
        BridgeError::Nntp(velmora::Error::Io(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "workers socket open failed",
        )))
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn open(_cfg: &NntpConfig) -> Result<Socket> {
    Err(BridgeError::NotImplemented(
        "nntp: sockets exist only on wasm32",
    ))
}

/// Native builds (`cargo check`, unit tests) have no Workers socket.
#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::io;
    use velmora::transport::Transport;

    pub enum NoSocket {}

    impl Transport for NoSocket {
        async fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            match *self {}
        }
        async fn write_all(&mut self, _buf: &[u8]) -> io::Result<()> {
            match *self {}
        }
        async fn shutdown(&mut self) -> io::Result<()> {
            match *self {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(host: &str, port: u16, tls: bool) -> ProviderConfig {
        serde_json::from_value(serde_json::json!({
            "id": "p1", "host": host, "port": port, "tls": tls, "user": "u", "pass": "pw",
            "backbone": "bb", "post": true, "read": true, "max_conns": 2
        }))
        .unwrap()
    }

    fn timed_out<T: std::fmt::Debug>(out: Option<Result<T>>) -> bool {
        matches!(
            out,
            Some(Err(BridgeError::Nntp(velmora::Error::Io(e)))) if e.kind() == io::ErrorKind::TimedOut
        )
    }

    /// A call that outlasts its limit ends as a timed-out transport
    /// error; one that is done in time, or with the limit, is returned.
    #[test]
    fn a_call_is_cut_at_its_limit() {
        use futures_util::FutureExt;
        use std::future::{pending, ready};

        let hung = within(ready(()), pending::<Result<u8>>());
        assert!(timed_out(hung.now_or_never()));
        let done = within(pending(), ready(Ok(7u8)));
        assert!(matches!(done.now_or_never(), Some(Ok(7))));
        let tie = within(ready(()), ready(Ok(7u8)));
        assert!(matches!(tie.now_or_never(), Some(Ok(7))));
        // Natively nothing is cut: there is no socket to hold.
        let native = within_call(0, ready(Ok(7u8)));
        assert!(matches!(native.now_or_never(), Some(Ok(7))));
    }

    /// The bounds the sessions are wired to: a read's calls are short
    /// enough for its permit, and the goodbye is short for every class.
    #[test]
    fn the_bounds_follow_the_class_of_the_permit() {
        use velmora_bridge::{NNTP_CALL_SECS, READ_CALL_SECS};
        assert_eq!(PermitClass::Read.call_secs(), READ_CALL_SECS);
        assert_eq!(PermitClass::Background.call_secs(), NNTP_CALL_SECS);
        assert!(READ_CALL_SECS + QUIT_SECS < PermitClass::Read.permit_secs());
        assert!(NNTP_CALL_SECS + QUIT_SECS < PermitClass::Background.permit_secs());
    }

    #[test]
    fn tls_provider_follows_the_pinned_policy() {
        let cfg = nntp_config(&provider("news.example", 563, true)).unwrap();
        assert!(cfg.tls && !cfg.allow_insecure_plaintext);
        assert_eq!(cfg.max_article_bytes, 1 << 20);
        assert_eq!(
            (cfg.username.as_deref(), cfg.password.as_deref()),
            (Some("u"), Some("pw"))
        );
        assert!(nntp_config(&provider("news.example", 8080, true)).is_err());
    }

    #[test]
    fn plaintext_only_on_loopback_and_refusals_are_redacted() {
        for host in ["127.0.0.1", "localhost", "::1", "[::1]"] {
            assert!(
                nntp_config(&provider(host, 11119, false))
                    .unwrap()
                    .allow_insecure_plaintext
            );
        }
        for host in ["secret-host.example", "10.0.0.1", "127.0.0.1.example"] {
            let err = nntp_config(&provider(host, 119, false)).unwrap_err();
            let text = format!("{err} {err:?}");
            assert!(!text.contains(host) && !text.contains("pw"), "{text}");
        }
    }
}
