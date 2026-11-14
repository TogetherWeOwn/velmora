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
//! A provider with several host names (`hosts`) is connected through
//! `velmora_bridge::hosts::HostPicker`: the fastest endpoint by a TLS and
//! greeting probe, kept per isolate, with fallback to the others. The TLS
//! policy is checked for every endpoint before any socket opens.
//!
//! Sessions read at most 1 MiB per article body. Policy refusals and
//! socket-open failures are class-only (no host or credential). Later
//! session errors are the engine's own: their `Debug` redacts auth reply
//! text, but `Display` may carry a runtime I/O message or a server reply.

use std::cell::Cell;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use futures_util::future::{select, Either};
use velmora::nntp::{NntpClient, NntpConfig, PostOutcome};
use velmora::pinned_transport::pinned_rejection_message;
use velmora_bridge::hosts::{
    self, DialError, Dialer, HostPicker, Picked, HOST_CONNECT_SECS, PROBE_GOODBYE_MS,
};
use velmora_bridge::{
    BodyOutcome, BridgeError, NntpConnector, NntpSession, Permit, PermitClass, ProviderConfig,
    Result, UnixMs, QUIT_SECS,
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
async fn after(secs: u32) {
    after_ms(secs.saturating_mul(1000)).await
}

/// Ends after `ms` milliseconds on the runtime's timer.
#[cfg(target_arch = "wasm32")]
async fn after_ms(ms: u32) {
    worker::Delay::from(Duration::from_millis(u64::from(ms))).await;
}

/// Native builds open no socket, so there is nothing to bound.
#[cfg(not(target_arch = "wasm32"))]
async fn after_ms(_ms: u32) {
    std::future::pending().await
}

/// The runtime's clock. It moves on with I/O, which is what a probe times.
#[cfg(target_arch = "wasm32")]
fn now() -> UnixMs {
    UnixMs(worker::Date::now().as_millis() as i64)
}

#[cfg(not(target_arch = "wasm32"))]
fn now() -> UnixMs {
    UnixMs(0)
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

/// Opens sessions; keeps, per isolate, which host of a provider with
/// several answered fastest.
pub struct WorkerConnector {
    hosts: HostPicker,
}

impl WorkerConnector {
    pub fn new() -> Self {
        WorkerConnector {
            hosts: HostPicker::new(),
        }
    }
}

impl WorkerConnector {
    /// `connect`, and which endpoint it got. A provider with several
    /// endpoints logs the pick when this connect probed or fell back: the
    /// endpoint's index, never its name.
    pub async fn connect_traced(
        &self,
        provider: &ProviderConfig,
        permit: &Permit,
    ) -> Result<(WorkerSession, Picked)> {
        if permit.provider != provider.id {
            return Err(BridgeError::Invalid("permit is for another provider"));
        }
        // Every endpoint passes the policy before any socket opens.
        for host in provider.endpoints() {
            nntp_config(provider, host)?;
        }
        let class = permit.class;
        let dial = Dial { provider, class };
        let (session, picked) =
            within_call(class.call_secs(), self.hosts.connect(provider, &dial)).await?;
        if picked.probed || picked.fallback {
            log_pick(&provider.id, &picked);
        }
        Ok((session, picked))
    }
}

#[cfg(target_arch = "wasm32")]
fn log_pick(provider: &str, picked: &Picked) {
    worker::console_log!("nntp connect provider={provider} {picked}");
}

#[cfg(not(target_arch = "wasm32"))]
fn log_pick(_provider: &str, _picked: &Picked) {}

impl NntpConnector for WorkerConnector {
    type Session = WorkerSession;

    async fn connect(&self, provider: &ProviderConfig, permit: &Permit) -> Result<WorkerSession> {
        Ok(self.connect_traced(provider, permit).await?.0)
    }
}

/// One `connect`'s access to the network, for the host picker. Its
/// sockets are opened under the caller's permit, one at a time.
struct Dial<'a> {
    provider: &'a ProviderConfig,
    class: PermitClass,
}

impl Dialer for Dial<'_> {
    type Session = WorkerSession;

    async fn probe(&self, host: &str, limit_ms: u32) -> Option<u32> {
        let cfg = nntp_config(self.provider, host).ok()?;
        let start = now();
        // The socket is dropped, which closes it, at the end of this
        // block: also after a probe that was cut off.
        let (code, ms) = {
            let mut socket = open(&cfg).ok()?;
            let code = within(after_ms(limit_ms), async {
                Ok(hosts::greeting(&mut socket).await)
            })
            .await
            .ok()
            .flatten();
            // Timed to the greeting; the goodbye is not measured.
            let ms = now().0.saturating_sub(start.0);
            let _ = within(after_ms(PROBE_GOODBYE_MS), async {
                hosts::goodbye(&mut socket, code.is_some()).await;
                Ok(())
            })
            .await;
            (code, ms)
        };
        if hosts::ready(code) {
            u32::try_from(ms).ok()
        } else {
            None
        }
    }

    async fn dial(
        &self,
        host: &str,
        bounded: bool,
    ) -> core::result::Result<WorkerSession, DialError> {
        let cfg = nntp_config(self.provider, host).map_err(DialError::Account)?;
        let socket = open(&cfg).map_err(DialError::Unreachable)?;
        let class = self.class;
        // Set when the engine is about to log in: the greeting was
        // accepted. A refusal before that is the host's, as a probe
        // would count it; one after it is the account's.
        let greeted = Cell::new(false);
        let handshake = async {
            let client = NntpClient::connect_with_auth_guard(socket, &cfg, || {
                greeted.set(true);
                Ok(())
            })
            .await?;
            Ok(WorkerSession(client, class))
        };
        let out = if bounded {
            within_call(HOST_CONNECT_SECS, handshake).await
        } else {
            handshake.await
        };
        out.map_err(|e| DialError::classify(e, greeted.get()))
    }

    async fn pause(&self, ms: u32) {
        after_ms(ms).await
    }

    fn now(&self) -> UnixMs {
        now()
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

/// The engine config for one provider on one of its hosts, after the TLS
/// policy.
fn nntp_config(p: &ProviderConfig, host: &str) -> Result<NntpConfig> {
    let with_auth = !p.user.is_empty();
    let cfg = NntpConfig {
        host: host.to_string(),
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
        if !is_loopback(host) {
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
        let cfg = nntp_config(&provider("news.example", 563, true), "news.example").unwrap();
        assert!(cfg.tls && !cfg.allow_insecure_plaintext);
        assert_eq!(cfg.max_article_bytes, 1 << 20);
        assert_eq!(
            (cfg.username.as_deref(), cfg.password.as_deref()),
            (Some("u"), Some("pw"))
        );
        assert!(nntp_config(&provider("news.example", 8080, true), "news.example").is_err());
    }

    #[test]
    fn plaintext_only_on_loopback_and_refusals_are_redacted() {
        for host in ["127.0.0.1", "localhost", "::1", "[::1]"] {
            assert!(
                nntp_config(&provider(host, 11119, false), host)
                    .unwrap()
                    .allow_insecure_plaintext
            );
        }
        for host in ["secret-host.example", "10.0.0.1", "127.0.0.1.example"] {
            let err = nntp_config(&provider(host, 119, false), host).unwrap_err();
            let text = format!("{err} {err:?}");
            assert!(!text.contains(host) && !text.contains("pw"), "{text}");
        }
    }
}
