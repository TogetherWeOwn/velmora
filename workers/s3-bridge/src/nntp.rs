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
//! A provider with `proxies` is reached through them only ([`open_routed`]):
//! each in order, TLS to the provider inside the proxied connection. When
//! none can be used the connect fails as a proxy failure. No direct
//! socket is ever opened for such a provider.
//!
//! Sessions read at most 1 MiB per article body. Policy refusals and
//! socket-open failures are class-only (no host or credential). Later
//! session errors are the engine's own: their `Debug` redacts auth reply
//! text, but `Display` may carry a runtime I/O message or a server reply.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;

use futures_util::future::{select, Either};
use velmora::nntp::{NntpClient, NntpConfig, PostOutcome};
use velmora::pinned_transport::pinned_rejection_message;
use velmora::socks5::{self, Progress, Socks5Proxy};
use velmora_bridge::hosts::{
    self, DialError, Dialer, HostPicker, Picked, HOST_CONNECT_SECS, PROBE_GOODBYE_MS,
    PROXY_CONNECT_SECS, PROXY_DOWN_MS,
};
use velmora_bridge::{
    BodyOutcome, BridgeError, NntpConnector, NntpSession, Permit, PermitClass, ProviderConfig,
    ProxyConfig, Result, UnixMs, QUIT_SECS,
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
        let memory = proxy_memory();
        // No proxy could be used a moment ago: a probe would measure
        // the proxies, not the host, and cost its whole limit.
        if memory.all_down(&self.provider.proxies, start.0) {
            return None;
        }
        let (code, ms) = {
            // One limit for opening and greeting. The proxy stage of a
            // provider with proxies counts into the time.
            let mut opened = None;
            let code = within(after_ms(limit_ms), async {
                let socket = open_routed(&WorkerNet, &memory, &self.provider.proxies, &cfg).await?;
                Ok(hosts::greeting(opened.insert(socket)).await)
            })
            .await
            .ok()
            .flatten();
            let mut socket = opened?;
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
        // A failure of the proxy stage is the proxies' or the host's,
        // never the account's: no login was sent.
        let socket = open_routed(&WorkerNet, &proxy_memory(), &self.provider.proxies, &cfg)
            .await
            .map_err(|e| DialError::classify(e, false))?;
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
        if !p.proxies.is_empty() {
            return Err(refused(
                "transport_tls_required: no plaintext through a proxy".into(),
            ));
        }
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

/// A socket could not be opened, or a proxy reported that it did not
/// connect to the host. The runtime's message may name the host: the
/// class only.
fn open_failed() -> BridgeError {
    BridgeError::Nntp(velmora::Error::Io(io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "workers socket open failed",
    )))
}

/// None of the provider's proxies could be used
/// (`velmora_bridge::hosts::proxy_failure`).
fn proxies_failed() -> BridgeError {
    BridgeError::Nntp(velmora::Error::Io(socks5::proxy_failure(
        io::ErrorKind::ConnectionRefused,
        socks5::ERR_IO,
    )))
}

fn socks5_proxy(p: &ProxyConfig) -> Socks5Proxy {
    Socks5Proxy {
        host: p.host.clone(),
        port: p.port,
        username: p.user.clone(),
        password: p.pass.clone(),
    }
}

/// The two ways a socket to a provider is opened, and the timer that
/// bounds the proxy stage. A trait so that the routing rule
/// ([`open_routed`]) is tested without a socket.
trait Net {
    type Socket;

    /// A socket straight to the host of `cfg`.
    fn direct(&self, cfg: &NntpConfig) -> Result<Self::Socket>;

    /// A socket to the host of `cfg` through `proxy`, with TLS to the
    /// host started on it. `progress` is set once the proxy accepted
    /// the login.
    async fn via_proxy(
        &self,
        cfg: &NntpConfig,
        proxy: &Socks5Proxy,
        progress: &Progress,
    ) -> io::Result<Self::Socket>;

    /// Ends after `secs`.
    async fn limit(&self, secs: u32);

    /// The time, in Unix milliseconds.
    fn now_ms(&self) -> i64;
}

/// The proxies that could not be used a moment ago, by host and port,
/// with the time until which each is tried after the others. Kept per
/// isolate, so that one proxy that does not answer costs its time limit
/// once and not on every connect. It only changes the order: a proxy in
/// here is still tried, and a provider with proxies has no other way.
#[derive(Default)]
struct ProxyMemory(RefCell<Vec<(String, u16, i64)>>);

impl ProxyMemory {
    fn is_down(&self, proxy: &ProxyConfig, now_ms: i64) -> bool {
        self.0.borrow().iter().any(|(host, port, until)| {
            *host == proxy.host && *port == proxy.port && now_ms < *until
        })
    }

    /// Whether there are proxies and every one is down.
    fn all_down(&self, proxies: &[ProxyConfig], now_ms: i64) -> bool {
        !proxies.is_empty() && proxies.iter().all(|p| self.is_down(p, now_ms))
    }

    /// Records whether `proxy` could be used at `now_ms`. Entries whose
    /// time is over are dropped on the way.
    fn set(&self, proxy: &ProxyConfig, usable: bool, now_ms: i64) {
        let mut down = self.0.borrow_mut();
        down.retain(|(host, port, until)| {
            now_ms < *until && !(*host == proxy.host && *port == proxy.port)
        });
        if !usable {
            down.push((proxy.host.clone(), proxy.port, now_ms + PROXY_DOWN_MS));
        }
    }
}

thread_local! {
    static PROXY_MEMORY: Rc<ProxyMemory> = Rc::default();
}

/// This isolate's [`ProxyMemory`].
fn proxy_memory() -> Rc<ProxyMemory> {
    PROXY_MEMORY.with(Rc::clone)
}

/// One try of one proxy. When it ends, also by being dropped half way
/// (the caller's own time limit), the memory learns whether the proxy
/// could be used: it connected, or at least accepted the login.
struct Try<'a, N: Net> {
    net: &'a N,
    memory: &'a ProxyMemory,
    proxy: &'a ProxyConfig,
    progress: Progress,
    connected: bool,
}

impl<N: Net> Drop for Try<'_, N> {
    fn drop(&mut self) {
        let usable = self.connected || self.progress.logged_in();
        self.memory.set(self.proxy, usable, self.net.now_ms());
    }
}

/// Opens the socket of one connect. A provider without proxies is
/// connected directly. One with proxies is connected through them and
/// in no other way: each in order, each within [`PROXY_CONNECT_SECS`],
/// the first that connects wins. The proxies that `memory` holds as
/// unusable come after the others, in order too.
///
/// When none connects, the failure says whose it was. If a proxy worked
/// and did not connect to the host, it is the host's, and the next host
/// is worth a try: the proxy reported so, or it accepted the login and
/// the host did not answer in time. Otherwise it is the proxies'
/// (`hosts::proxy_failure`). The direct route is not taken in either
/// case.
async fn open_routed<N: Net>(
    net: &N,
    memory: &ProxyMemory,
    proxies: &[ProxyConfig],
    cfg: &NntpConfig,
) -> Result<N::Socket> {
    if proxies.is_empty() {
        return net.direct(cfg);
    }
    if !cfg.tls {
        return Err(refused(
            "transport_tls_required: no plaintext through a proxy".into(),
        ));
    }
    let start = net.now_ms();
    let (usable, down): (Vec<_>, Vec<_>) = proxies.iter().partition(|p| !memory.is_down(p, start));
    let mut host_refused = false;
    for proxy in usable.into_iter().chain(down) {
        let mut attempt = Try {
            net,
            memory,
            proxy,
            progress: Progress::new(),
            connected: false,
        };
        let login = socks5_proxy(proxy);
        let stage = async { Ok(net.via_proxy(cfg, &login, &attempt.progress).await) };
        let out = within(net.limit(PROXY_CONNECT_SECS), stage).await;
        match out {
            Ok(Ok(socket)) => {
                attempt.connected = true;
                return Ok(socket);
            }
            Ok(Err(e)) if socks5::is_target_failure(&e) => host_refused = true,
            // Out of time while the proxy was connecting to the host.
            Err(_) if attempt.progress.logged_in() => host_refused = true,
            // The proxy failed, or did not get as far as the login in
            // time.
            Ok(Err(_)) | Err(_) => {}
        }
    }
    Err(if host_refused {
        open_failed()
    } else {
        proxies_failed()
    })
}

/// The Workers runtime's sockets.
struct WorkerNet;

#[cfg(target_arch = "wasm32")]
impl Net for WorkerNet {
    type Socket = Socket;

    fn direct(&self, cfg: &NntpConfig) -> Result<Socket> {
        let socket = if cfg.tls {
            Socket::connect_pinned(cfg)
        } else {
            Socket::connect(cfg)
        };
        socket.map_err(|_| open_failed())
    }

    async fn via_proxy(
        &self,
        cfg: &NntpConfig,
        proxy: &Socks5Proxy,
        progress: &Progress,
    ) -> io::Result<Socket> {
        Socket::connect_pinned_via_socks5(cfg, proxy, progress).await
    }

    async fn limit(&self, secs: u32) {
        after(secs).await
    }

    fn now_ms(&self) -> i64 {
        now().0
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Net for WorkerNet {
    type Socket = Socket;

    fn direct(&self, _cfg: &NntpConfig) -> Result<Socket> {
        Err(BridgeError::NotImplemented(
            "nntp: sockets exist only on wasm32",
        ))
    }

    async fn via_proxy(
        &self,
        _cfg: &NntpConfig,
        _proxy: &Socks5Proxy,
        _progress: &Progress,
    ) -> io::Result<Socket> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "nntp: sockets exist only on wasm32",
        ))
    }

    async fn limit(&self, secs: u32) {
        after(secs).await
    }

    fn now_ms(&self) -> i64 {
        now().0
    }
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

    /// What a fake proxy does with a connect.
    #[derive(Clone, Copy)]
    enum Via {
        Connects,
        /// The proxy cannot be reached, or refuses the bridge.
        Down,
        /// The proxy works and did not connect to the host.
        HostRefused,
        /// The proxy accepts the login, and then waits for a host that
        /// does not answer.
        HostSilent,
        /// The proxy never answers.
        Hangs,
    }

    /// A network that counts what was opened. `via` holds one entry per
    /// proxy host.
    struct FakeNet {
        via: Vec<(&'static str, Via)>,
        direct: Cell<u32>,
        proxied: std::cell::RefCell<Vec<String>>,
        /// Whether the bound on a proxy stage ends at once.
        cut: bool,
        now_ms: Cell<i64>,
        memory: ProxyMemory,
    }

    impl FakeNet {
        fn new(via: &[(&'static str, Via)]) -> Self {
            FakeNet {
                via: via.to_vec(),
                direct: Cell::new(0),
                proxied: Default::default(),
                cut: false,
                now_ms: Cell::new(1_000),
                memory: ProxyMemory::default(),
            }
        }
    }

    impl Net for FakeNet {
        type Socket = String;

        fn direct(&self, _cfg: &NntpConfig) -> Result<String> {
            self.direct.set(self.direct.get() + 1);
            Ok("direct".into())
        }

        async fn via_proxy(
            &self,
            cfg: &NntpConfig,
            proxy: &Socks5Proxy,
            progress: &Progress,
        ) -> io::Result<String> {
            self.proxied.borrow_mut().push(proxy.host.clone());
            // The handshake itself, against a scripted proxy.
            let handshake = |replies: &'static [u8], hangs: bool| async move {
                let mut script = Script(replies, hangs);
                let (user, pass) = (proxy.username.as_str(), proxy.password.as_str());
                socks5::connect_tracked(&mut script, user, pass, &cfg.host, cfg.port, progress)
                    .await
            };
            let (_, via) = self.via.iter().find(|(h, _)| *h == proxy.host).unwrap();
            match via {
                Via::Connects => Ok(format!("{} via {}", cfg.host, proxy.host)),
                Via::Down => Err(socks5::proxy_failure(
                    io::ErrorKind::ConnectionRefused,
                    socks5::ERR_IO,
                )),
                Via::HostRefused => {
                    // What the handshake returns for a refused CONNECT.
                    let e = handshake(&[5, 2, 1, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0], false)
                        .await
                        .unwrap_err();
                    assert!(socks5::is_target_failure(&e));
                    Err(e)
                }
                Via::HostSilent => {
                    handshake(&[5, 2, 1, 0], true).await?;
                    unreachable!("the proxy never answers the request")
                }
                Via::Hangs => std::future::pending().await,
            }
        }

        async fn limit(&self, _secs: u32) {
            if !self.cut {
                std::future::pending().await
            }
        }

        fn now_ms(&self) -> i64 {
            self.now_ms.get()
        }
    }

    /// A proxy's answers, and whether it then goes silent instead of
    /// closing.
    struct Script(&'static [u8], bool);

    impl velmora::transport::Transport for Script {
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() && self.1 {
                std::future::pending::<()>().await;
            }
            // One reply per read: method (2 bytes), login (2), connect (10).
            let n = if self.0.len() != 10 {
                self.0.len().min(2)
            } else {
                10
            };
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
        async fn write_all(&mut self, _buf: &[u8]) -> io::Result<()> {
            Ok(())
        }
        async fn shutdown(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    use futures_util::FutureExt;

    fn proxied(proxy_hosts: &[&str]) -> (ProviderConfig, NntpConfig) {
        let mut p = provider("news.example", 563, true);
        p.proxies = proxy_hosts
            .iter()
            .map(|host| {
                serde_json::from_value(serde_json::json!({
                    "host": host, "port": 1080, "user": "proxy-user", "pass": "proxy-pass"
                }))
                .unwrap()
            })
            .collect();
        let cfg = nntp_config(&p, "news.example").unwrap();
        (p, cfg)
    }

    fn route(net: &FakeNet, p: &ProviderConfig, cfg: &NntpConfig) -> Result<String> {
        open_routed(net, &net.memory, &p.proxies, cfg)
            .now_or_never()
            .unwrap()
    }

    /// What was opened through proxies since the last look.
    fn tried(net: &FakeNet) -> Vec<String> {
        std::mem::take(&mut *net.proxied.borrow_mut())
    }

    /// A provider without proxies is connected directly, and one with
    /// proxies through the first that connects.
    #[test]
    fn a_provider_goes_the_way_it_is_configured() {
        let (p, cfg) = proxied(&[]);
        let net = FakeNet::new(&[]);
        assert_eq!(route(&net, &p, &cfg).unwrap(), "direct");
        assert_eq!((net.direct.get(), net.proxied.borrow().len()), (1, 0));

        let (p, cfg) = proxied(&["a.proxy.example", "b.proxy.example"]);
        let net = FakeNet::new(&[
            ("a.proxy.example", Via::Connects),
            ("b.proxy.example", Via::Connects),
        ]);
        assert_eq!(
            route(&net, &p, &cfg).unwrap(),
            "news.example via a.proxy.example"
        );
        assert_eq!(*net.proxied.borrow(), ["a.proxy.example"]);
        assert_eq!(net.direct.get(), 0);
    }

    /// The proxies are tried in order; the next one takes over from one
    /// that is down, hangs or did not connect to the host.
    #[test]
    fn the_next_proxy_takes_over() {
        for first in [Via::Down, Via::Hangs, Via::HostRefused, Via::HostSilent] {
            let (p, cfg) = proxied(&["a.proxy.example", "b.proxy.example"]);
            let mut net = FakeNet::new(&[
                ("a.proxy.example", first),
                ("b.proxy.example", Via::Connects),
            ]);
            // Only a proxy that waits runs into the bound.
            net.cut = matches!(first, Via::Hangs | Via::HostSilent);
            assert_eq!(
                route(&net, &p, &cfg).unwrap(),
                "news.example via b.proxy.example"
            );
            assert_eq!(
                *net.proxied.borrow(),
                ["a.proxy.example", "b.proxy.example"]
            );
            assert_eq!(net.direct.get(), 0);
        }
    }

    /// Every proxy of the provider is down, or hangs: the connect fails
    /// as a proxy failure, and no direct socket was opened. The failure
    /// names no proxy and no login.
    #[test]
    fn no_direct_connect_when_every_proxy_is_down() {
        for down in [Via::Down, Via::Hangs] {
            let (p, cfg) = proxied(&["a.proxy.example", "b.proxy.example"]);
            let mut net = FakeNet::new(&[("a.proxy.example", down), ("b.proxy.example", down)]);
            net.cut = true;
            let err = route(&net, &p, &cfg).unwrap_err();
            assert_eq!(net.direct.get(), 0, "a direct socket was opened");
            assert_eq!(
                *net.proxied.borrow(),
                ["a.proxy.example", "b.proxy.example"]
            );
            assert!(hosts::proxy_failure(&err));
            assert!(matches!(
                DialError::classify(err, false),
                DialError::Proxy(_)
            ));
            // Again, with both proxies known as down: both are tried,
            // and still nothing goes direct.
            let err = route(&net, &p, &cfg).unwrap_err();
            assert_eq!(net.direct.get(), 0, "a direct socket was opened");
            assert_eq!(net.proxied.borrow().len(), 4);
            let text = format!("{err} {err:?}");
            for secret in ["proxy.example", "proxy-user", "proxy-pass", "news.example"] {
                assert!(!text.contains(secret), "{text}");
            }
        }
    }

    /// A proxy that works and did not connect to the host: the failure is
    /// the host's (the next host is tried), not the proxies', and still
    /// nothing was opened directly. The proxy said so, or it accepted
    /// the login and the host did not answer before the bound.
    #[test]
    fn a_host_the_proxy_cannot_reach_is_a_host_failure() {
        for unreached in [Via::HostRefused, Via::HostSilent] {
            let (p, cfg) = proxied(&["a.proxy.example", "b.proxy.example"]);
            let mut net = FakeNet::new(&[
                ("a.proxy.example", Via::Down),
                ("b.proxy.example", unreached),
            ]);
            net.cut = matches!(unreached, Via::HostSilent);
            let err = route(&net, &p, &cfg).unwrap_err();
            assert_eq!(net.direct.get(), 0);
            assert!(!hosts::proxy_failure(&err) && hosts::host_failure(&err));
            assert!(matches!(
                DialError::classify(err, false),
                DialError::Unreachable(_)
            ));
            // The proxy that got as far as the login is not held as
            // down; the one that failed is.
            assert!(net.memory.is_down(&p.proxies[0], net.now_ms()));
            assert!(!net.memory.is_down(&p.proxies[1], net.now_ms()));
        }
    }

    /// A proxy that could not be used is tried after the others for a
    /// while, so that it costs its time limit once. It is still tried
    /// when the others fail, and comes first again when the time is
    /// over or when it connected.
    #[test]
    fn a_proxy_that_failed_is_tried_last_for_a_while() {
        let (a, b) = ("a.proxy.example", "b.proxy.example");
        for failed in [Via::Down, Via::Hangs] {
            let (p, cfg) = proxied(&[a, b]);
            let mut net = FakeNet::new(&[(a, failed), (b, Via::Connects)]);
            net.cut = matches!(failed, Via::Hangs);
            route(&net, &p, &cfg).unwrap();
            assert_eq!(tried(&net), [a, b]);
            assert!(!net.memory.all_down(&p.proxies, net.now_ms()));
            // The next connects go to the one that works, at once.
            for _ in 0..3 {
                route(&net, &p, &cfg).unwrap();
                assert_eq!(tried(&net), [b]);
            }
            // That one fails too: the first is tried again, not skipped.
            net.via[1].1 = Via::Down;
            assert!(route(&net, &p, &cfg).is_err());
            assert_eq!(tried(&net), [b, a]);
            assert!(net.memory.all_down(&p.proxies, net.now_ms()));
            // Both down: the configured order.
            assert!(route(&net, &p, &cfg).is_err());
            assert_eq!(tried(&net), [a, b]);
            // The time is over: forgotten.
            net.now_ms.set(net.now_ms() + PROXY_DOWN_MS);
            assert!(!net.memory.is_down(&p.proxies[0], net.now_ms()));
            // A proxy that connects is not held as down any longer.
            net.via = vec![(a, Via::Down), (b, Via::Connects)];
            route(&net, &p, &cfg).unwrap();
            net.via[0].1 = Via::Connects;
            net.via[1].1 = Via::Down;
            route(&net, &p, &cfg).unwrap();
            assert_eq!(tried(&net), [a, b, b, a]);
            assert!(!net.memory.is_down(&p.proxies[0], net.now_ms()));
            assert!(net.memory.is_down(&p.proxies[1], net.now_ms()));
        }
        // No proxies: nothing is "all down".
        assert!(!ProxyMemory::default().all_down(&[], 0));
    }

    /// A caller that gives up on the connect half way (a probe at its
    /// limit) leaves the proxy it was waiting for marked: the next
    /// connect starts with another one.
    #[test]
    fn a_connect_cut_off_from_outside_marks_the_proxy() {
        let (a, b) = ("a.proxy.example", "b.proxy.example");
        for (waits, marked) in [(Via::Hangs, true), (Via::HostSilent, false)] {
            let (p, cfg) = proxied(&[a, b]);
            let mut net = FakeNet::new(&[(a, waits), (b, Via::Connects)]);
            // The proxy's own bound never ends; the caller drops it.
            let pending = open_routed(&net, &net.memory, &p.proxies, &cfg).now_or_never();
            assert!(pending.is_none());
            assert_eq!(tried(&net), [a]);
            assert_eq!(net.memory.is_down(&p.proxies[0], net.now_ms()), marked);
            // The next connect: past the marked proxy at once; a proxy
            // that had accepted the login keeps its place.
            net.cut = true;
            route(&net, &p, &cfg).unwrap();
            assert_eq!(tried(&net), if marked { vec![b] } else { vec![a, b] });
        }
    }

    /// Plaintext never goes through a proxy: refused before any socket.
    #[test]
    fn no_plaintext_through_a_proxy() {
        let (mut p, _) = proxied(&["a.proxy.example"]);
        (p.tls, p.host, p.port) = (false, "127.0.0.1".into(), 11119);
        assert!(nntp_config(&p, "127.0.0.1").is_err());
        // The routing refuses it too, whatever built the config.
        let mut cfg = nntp_config(&provider("127.0.0.1", 11119, false), "127.0.0.1").unwrap();
        cfg.tls = false;
        let net = FakeNet::new(&[("a.proxy.example", Via::Connects)]);
        assert!(route(&net, &p, &cfg).is_err());
        assert_eq!((net.direct.get(), net.proxied.borrow().len()), (0, 0));
    }

    /// The real network, natively: a provider with proxies fails as a
    /// proxy failure there as well (no socket exists), and not as the
    /// direct route's error.
    #[test]
    fn the_worker_network_routes_through_the_proxies() {
        let (p, cfg) = proxied(&["a.proxy.example"]);
        let net = WorkerNet;
        // Natively the timer never ends, and no proxy answers: at once.
        let err = open_routed(&net, &ProxyMemory::default(), &p.proxies, &cfg)
            .now_or_never()
            .unwrap()
            .err()
            .unwrap();
        assert!(hosts::proxy_failure(&err), "{err:?}");
    }
}
