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
    PROBE_TIMEOUT_MS, PROXY_CONNECT_SECS, PROXY_DOWN_MS,
};
use velmora_bridge::{
    BodyOutcome, BridgeError, NntpConnector, NntpSession, Permit, PermitClass, ProviderConfig,
    ProxyConfig, Result, SizeCommand, SizeOutcome, UnixMs, QUIT_SECS,
};

/// Largest article the bridge reads or posts (velmora articles are about
/// 744 KB on the wire).
pub const MAX_ARTICLE_BYTES: usize = 1024 * 1024;

/// Per-operation socket timeout; one 1 MiB POST is a single write.
const OP_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(target_arch = "wasm32")]
type Socket = routed::Socket;
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

    async fn size(&mut self, message_id: &str, how: SizeCommand) -> Result<SizeOutcome> {
        let call = velmora_bridge::post::stored_size(&mut self.0, message_id, how);
        within_call(self.1.call_secs(), call).await
    }

    async fn ask_many(
        &mut self,
        message_ids: &[&str],
        how: Option<SizeCommand>,
    ) -> Result<Vec<SizeOutcome>> {
        let call = velmora_bridge::post::stored_sizes(&mut self.0, message_ids, how);
        within_call(self.1.call_secs(), call).await
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

/// One line for a proxy that was found unusable: the provider's id, the
/// proxy's place in its `proxies` (from 0) and the outcome. Never the
/// proxy's host or login.
#[cfg(target_arch = "wasm32")]
fn log_proxy(provider: &str, index: usize, outcome: &str) {
    worker::console_log!("nntp proxy provider={provider} index={index} outcome={outcome}");
}

#[cfg(not(target_arch = "wasm32"))]
fn log_proxy(_provider: &str, _index: usize, _outcome: &str) {}

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
        let net = WorkerNet(&self.provider.id);
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
                let socket = open_routed(&net, &memory, &self.provider.proxies, &cfg).await?;
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
        let net = WorkerNet(&self.provider.id);
        let socket = open_routed(&net, &proxy_memory(), &self.provider.proxies, &cfg)
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

    /// A socket to the host of `cfg` through `proxy`, under TLS with
    /// the host. `progress` is set once the proxy accepted
    /// the login.
    async fn via_proxy(
        &self,
        cfg: &NntpConfig,
        proxy: &Socks5Proxy,
        progress: &Progress,
    ) -> io::Result<Self::Socket>;

    /// Ends after `ms` milliseconds.
    async fn limit(&self, ms: u32);

    /// The time, in Unix milliseconds.
    fn now_ms(&self) -> i64;

    /// The proxy at `index` of the configured list was found unusable,
    /// and why. For the log, which names no proxy host and no login.
    fn note(&self, index: usize, outcome: &'static str);
}

/// Why a proxy is in the [`ProxyMemory`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hold {
    /// The proxy itself could not be used: it did not answer, or
    /// refused. Tried after the others.
    Failed,
    /// The proxy accepted the login and did not get to the host. Tried
    /// after the others as well, and not counted as down: what failed
    /// may have been the host.
    Demoted,
    /// Callers gave up on the proxy before its time limit was over,
    /// after waiting this long in all (ms). It keeps its place, and has
    /// that much less time on the next try.
    Waited(u32),
}

/// What is known about the proxies from the connects of a moment ago,
/// by host and port, each with the time until which it holds. Kept per
/// isolate, so that one proxy that does not answer costs its time limit
/// once and not on every connect. It only changes the order: a proxy in
/// here is still tried, and a provider with proxies has no other way.
#[derive(Default)]
struct ProxyMemory(RefCell<Vec<(String, u16, i64, Hold)>>);

impl ProxyMemory {
    fn hold(&self, proxy: &ProxyConfig, now_ms: i64) -> Option<Hold> {
        self.0
            .borrow()
            .iter()
            .find(|(host, port, until, _)| {
                *host == proxy.host && *port == proxy.port && now_ms < *until
            })
            .map(|(_, _, _, hold)| *hold)
    }

    /// Whether the proxy itself could not be used a moment ago.
    fn is_down(&self, proxy: &ProxyConfig, now_ms: i64) -> bool {
        self.hold(proxy, now_ms) == Some(Hold::Failed)
    }

    /// Whether the proxy is tried after the others.
    fn is_last(&self, proxy: &ProxyConfig, now_ms: i64) -> bool {
        matches!(self.hold(proxy, now_ms), Some(Hold::Failed | Hold::Demoted))
    }

    /// Whether there are proxies and every one is down.
    fn all_down(&self, proxies: &[ProxyConfig], now_ms: i64) -> bool {
        !proxies.is_empty() && proxies.iter().all(|p| self.is_down(p, now_ms))
    }

    /// Records what is known about `proxy` at `now_ms`; `None` = it
    /// connected. Entries whose time is over are dropped on the way.
    fn set(&self, proxy: &ProxyConfig, hold: Option<Hold>, now_ms: i64) {
        let mut held = self.0.borrow_mut();
        held.retain(|(host, port, until, _)| {
            now_ms < *until && !(*host == proxy.host && *port == proxy.port)
        });
        if let Some(hold) = hold {
            held.push((proxy.host.clone(), proxy.port, now_ms + PROXY_DOWN_MS, hold));
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

/// The time one proxy has to connect, in milliseconds.
const PROXY_CONNECT_MS: u32 = PROXY_CONNECT_SECS * 1_000;

/// How many proxies must answer that the host cannot be reached before
/// a connect stops trying the others.
const NAMED_REPLIES_END: u32 = 2;

/// How one try of one proxy ended.
#[derive(Clone, Copy)]
enum End {
    Connected,
    /// The proxy could not be used.
    Failed,
    /// The proxy accepted the login and did not get to the host.
    Target,
}

/// One try of one proxy. When it ends the memory learns what came of
/// it. A try that is dropped half way (the caller's own time limit, as
/// a probe's) says little about the proxy: the limit may have been a
/// short one. Only the time is counted then, and the proxy is held as
/// unusable once callers waited [`PROXY_CONNECT_SECS`] for it in all.
struct Try<'a, N: Net> {
    net: &'a N,
    memory: &'a ProxyMemory,
    proxy: &'a ProxyConfig,
    /// The proxy's place in the configured list, for the log.
    index: usize,
    progress: Progress,
    /// What the memory held when the try began, and the time.
    before: Option<Hold>,
    start_ms: i64,
    end: Option<End>,
}

impl<N: Net> Try<'_, N> {
    /// The time callers waited for the proxy before this try.
    fn waited_ms(&self) -> u32 {
        match self.before {
            Some(Hold::Waited(ms)) => ms,
            _ => 0,
        }
    }
}

impl<N: Net> Drop for Try<'_, N> {
    fn drop(&mut self) {
        let now_ms = self.net.now_ms();
        let unreached = if self.progress.logged_in() {
            Hold::Demoted
        } else {
            Hold::Failed
        };
        let hold = match self.end {
            Some(End::Connected) => None,
            Some(End::Failed) => Some(Hold::Failed),
            Some(End::Target) => Some(Hold::Demoted),
            // Dropped from outside. A proxy that is tried last already
            // stays so.
            // The memory as it is now: another connect of the isolate
            // may have learnt more while this one waited.
            None => {
                let waited = match self.memory.hold(self.proxy, now_ms) {
                    Some(Hold::Failed | Hold::Demoted) => return,
                    Some(Hold::Waited(ms)) => ms,
                    None => 0,
                };
                let this = u32::try_from(now_ms.saturating_sub(self.start_ms)).unwrap_or(0);
                match waited.saturating_add(this) {
                    ms if ms < PROXY_CONNECT_MS => Some(Hold::Waited(ms)),
                    _ => Some(unreached),
                }
            }
        };
        match hold {
            Some(Hold::Failed) => self.net.note(self.index, "proxy_failed"),
            Some(Hold::Demoted) => self.net.note(self.index, "host_unreached"),
            Some(Hold::Waited(_)) | None => {}
        }
        self.memory.set(self.proxy, hold, now_ms);
    }
}

/// Opens the socket of one connect. A provider without proxies is
/// connected directly. One with proxies is connected through them and
/// in no other way: each in order, each within [`PROXY_CONNECT_SECS`],
/// the first that connects wins. The proxies that `memory` holds as
/// tried last come after the others, in order too.
///
/// When none connects, the failure says whose it was. If a proxy worked
/// and did not connect to the host, it is the host's, and the next host
/// is worth a try: the proxy reported so, or it accepted the login and
/// the host did not answer in time. Otherwise it is the proxies'
/// (`hosts::proxy_failure`). The direct route is not taken in either
/// case.
///
/// One proxy answering that the host itself cannot be reached (RFC
/// 1928, replies 4 and 5) does not end the connect: that proxy may be
/// the one at fault, and the next may connect. When a second proxy
/// says the same, the connect ends: a third would be told the same,
/// and the next host is tried sooner. A reply about the proxy's own
/// way to the host (3 and 6) is not counted.
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
    let (first, last): (Vec<_>, Vec<_>) = proxies
        .iter()
        .enumerate()
        .partition(|(_, p)| !memory.is_last(p, start));
    let mut host_refused = false;
    let mut named = 0;
    for (index, proxy) in first.into_iter().chain(last) {
        let start_ms = net.now_ms();
        let mut attempt = Try {
            net,
            memory,
            proxy,
            index,
            progress: Progress::new(),
            before: memory.hold(proxy, start_ms),
            start_ms,
            end: None,
        };
        let login = socks5_proxy(proxy);
        let stage = async { Ok(net.via_proxy(cfg, &login, &attempt.progress).await) };
        // What callers waited for this proxy before counts into its time.
        // Never less than a probe's time: a try a probe could not cut
        // short is long enough to connect.
        let left_ms = PROXY_CONNECT_MS
            .saturating_sub(attempt.waited_ms())
            .max(PROBE_TIMEOUT_MS);
        let out = within(net.limit(left_ms), stage).await;
        match out {
            Ok(Ok(socket)) => {
                attempt.end = Some(End::Connected);
                return Ok(socket);
            }
            Ok(Err(e)) if socks5::is_target_failure(&e) => {
                attempt.end = Some(End::Target);
                host_refused = true;
                named += u32::from(socks5::is_target_reply(&e));
                if named >= NAMED_REPLIES_END {
                    break;
                }
            }
            // Out of time while the proxy was connecting to the host.
            Err(_) if attempt.progress.logged_in() => {
                attempt.end = Some(End::Target);
                host_refused = true;
            }
            // The proxy failed, or did not get as far as the login in
            // time.
            Ok(Err(_)) | Err(_) => attempt.end = Some(End::Failed),
        }
    }
    Err(if host_refused {
        open_failed()
    } else {
        proxies_failed()
    })
}

/// The Workers runtime's sockets, for the provider of this id.
struct WorkerNet<'a>(&'a str);

#[cfg(target_arch = "wasm32")]
use velmora::transports::{WorkerProxiedTransport, WorkerTransport};

#[cfg(target_arch = "wasm32")]
impl Net for WorkerNet<'_> {
    type Socket = Socket;

    fn direct(&self, cfg: &NntpConfig) -> Result<Socket> {
        let socket = if cfg.tls {
            WorkerTransport::connect_pinned(cfg)
        } else {
            WorkerTransport::connect(cfg)
        };
        socket.map(Socket::Direct).map_err(|_| open_failed())
    }

    async fn via_proxy(
        &self,
        cfg: &NntpConfig,
        proxy: &Socks5Proxy,
        progress: &Progress,
    ) -> io::Result<Socket> {
        WorkerProxiedTransport::connect_pinned(cfg, proxy, progress)
            .await
            .map(|t| Socket::Proxied(Box::new(t)))
    }

    async fn limit(&self, ms: u32) {
        after_ms(ms).await
    }

    fn now_ms(&self) -> i64 {
        now().0
    }

    fn note(&self, index: usize, outcome: &'static str) {
        log_proxy(self.0, index, outcome);
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Net for WorkerNet<'_> {
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

    async fn limit(&self, ms: u32) {
        after_ms(ms).await
    }

    fn now_ms(&self) -> i64 {
        now().0
    }

    fn note(&self, index: usize, outcome: &'static str) {
        log_proxy(self.0, index, outcome);
    }
}

/// The socket of a session: the runtime's own for a direct connection
/// (TLS by the runtime), or the one through a proxy (TLS made in the
/// Worker, see `velmora::transports::worker_socks5`).
#[cfg(target_arch = "wasm32")]
mod routed {
    use std::io;
    use velmora::transport::Transport;
    use velmora::transports::{WorkerProxiedTransport, WorkerTransport};

    pub enum Socket {
        Direct(WorkerTransport),
        // Boxed: the TLS state is some hundred bytes, the direct socket
        // a few.
        Proxied(Box<WorkerProxiedTransport>),
    }

    impl Transport for Socket {
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self {
                Socket::Direct(t) => t.read(buf).await,
                Socket::Proxied(t) => t.read(buf).await,
            }
        }
        async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            match self {
                Socket::Direct(t) => t.write_all(buf).await,
                Socket::Proxied(t) => t.write_all(buf).await,
            }
        }
        async fn shutdown(&mut self) -> io::Result<()> {
            match self {
                Socket::Direct(t) => t.shutdown().await,
                Socket::Proxied(t) => t.shutdown().await,
            }
        }
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
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Via {
        Connects,
        /// The proxy cannot be reached, or refuses the bridge.
        Down,
        /// The proxy works and did not connect to the host: its reply
        /// to the request, with this code.
        Reply(u8),
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
        /// The bounds the proxy stages were given, in milliseconds.
        limits: std::cell::RefCell<Vec<u32>>,
        /// What was logged: the proxy's index and the outcome.
        notes: std::cell::RefCell<Vec<(usize, &'static str)>>,
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
                limits: Default::default(),
                notes: Default::default(),
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
                Via::Reply(code) => {
                    // What the handshake returns for a refused CONNECT.
                    let replies = vec![5, 2, 1, 0, 5, *code, 0, 1, 0, 0, 0, 0, 0, 0];
                    let e = handshake(replies.leak(), false).await.unwrap_err();
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

        async fn limit(&self, ms: u32) {
            self.limits.borrow_mut().push(ms);
            if !self.cut {
                std::future::pending().await
            }
        }

        fn now_ms(&self) -> i64 {
            self.now_ms.get()
        }

        fn note(&self, index: usize, outcome: &'static str) {
            self.notes.borrow_mut().push((index, outcome));
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
    /// that is down, hangs or did not connect to the host without
    /// naming it (the general failure, or silence).
    #[test]
    fn the_next_proxy_takes_over() {
        for first in [
            Via::Down,
            Via::Hangs,
            Via::Reply(1),
            Via::Reply(3),
            Via::Reply(6),
            Via::HostSilent,
        ] {
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
        for unreached in [Via::Reply(5), Via::Reply(1), Via::HostSilent] {
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
            // down; the one that failed is. Both are logged, by their
            // place in the list.
            assert!(net.memory.is_down(&p.proxies[0], net.now_ms()));
            assert!(!net.memory.is_down(&p.proxies[1], net.now_ms()));
            assert!(!net.memory.all_down(&p.proxies, net.now_ms()));
            assert_eq!(
                *net.notes.borrow(),
                [(0, "proxy_failed"), (1, "host_unreached")]
            );
        }
    }

    /// A proxy that accepts the login and does not get to the host is
    /// tried after the others from then on: the connects that follow do
    /// not wait for it again. It comes first again once it connected.
    #[test]
    fn a_proxy_that_does_not_reach_the_host_is_tried_last() {
        let (a, b) = ("a.proxy.example", "b.proxy.example");
        for unreached in [Via::HostSilent, Via::Reply(1)] {
            let (p, cfg) = proxied(&[a, b]);
            let mut net = FakeNet::new(&[(a, unreached), (b, Via::Connects)]);
            net.cut = matches!(unreached, Via::HostSilent);
            route(&net, &p, &cfg).unwrap();
            assert_eq!(tried(&net), [a, b]);
            assert_eq!(*net.notes.borrow(), [(0, "host_unreached")]);
            // Tried last, and not counted as down.
            assert!(net.memory.is_last(&p.proxies[0], net.now_ms()));
            assert!(!net.memory.is_down(&p.proxies[0], net.now_ms()));
            for _ in 0..3 {
                route(&net, &p, &cfg).unwrap();
                assert_eq!(tried(&net), [b]);
            }
            // The other one fails: this one is tried, connects, and is
            // first again.
            net.via = vec![(a, Via::Connects), (b, Via::Down)];
            route(&net, &p, &cfg).unwrap();
            assert_eq!(tried(&net), [b, a]);
            assert!(!net.memory.is_last(&p.proxies[0], net.now_ms()));
            route(&net, &p, &cfg).unwrap();
            assert_eq!(tried(&net), [a]);
        }
        // The time is over: forgotten.
        let (p, cfg) = proxied(&[a, b]);
        let mut net = FakeNet::new(&[(a, Via::HostSilent), (b, Via::Connects)]);
        net.cut = true;
        route(&net, &p, &cfg).unwrap();
        net.now_ms.set(net.now_ms() + PROXY_DOWN_MS);
        assert!(!net.memory.is_last(&p.proxies[0], net.now_ms()));
    }

    /// One proxy answering that the host itself cannot be reached
    /// (replies 4 and 5) does not end the connect: the next proxy is
    /// tried and may connect. A second one saying the same ends it: the
    /// third is not asked, and the failure is the host's. Both are
    /// tried last on the next connect. The general failure (1) names
    /// nothing, and 3 and 6 are about that proxy's way to the host:
    /// they are not counted.
    #[test]
    fn a_second_reply_that_names_the_host_ends_the_connect() {
        let (a, b, c) = ("a.proxy.example", "b.proxy.example", "c.proxy.example");
        for code in [1, 3, 4, 5, 6] {
            let (p, cfg) = proxied(&[a, b, c]);
            let net = FakeNet::new(&[
                (a, Via::Reply(code)),
                (b, Via::Connects),
                (c, Via::Connects),
            ]);
            assert_eq!(
                route(&net, &p, &cfg).unwrap(),
                "news.example via b.proxy.example",
                "reply {code}"
            );
            assert_eq!(tried(&net), [a, b]);
            // And that proxy is tried last from then on.
            route(&net, &p, &cfg).unwrap();
            assert_eq!(tried(&net), [b]);
        }
        for (first, second) in [(4, 4), (4, 5), (5, 4), (5, 5)] {
            let (p, cfg) = proxied(&[a, b, c]);
            let net = FakeNet::new(&[
                (a, Via::Reply(first)),
                (b, Via::Reply(second)),
                (c, Via::Connects),
            ]);
            let err = route(&net, &p, &cfg).unwrap_err();
            assert_eq!(tried(&net), [a, b], "replies {first}, {second}");
            assert!(!hosts::proxy_failure(&err) && hosts::host_failure(&err));
            assert_eq!(net.direct.get(), 0);
            assert_eq!(
                *net.notes.borrow(),
                [(0, "host_unreached"), (1, "host_unreached")]
            );
            // Proxies that say so of every host are not in the way.
            route(&net, &p, &cfg).unwrap();
            assert_eq!(tried(&net), [c]);
        }
        // One that names the host and one that does not: the third is
        // still tried.
        for (first, second) in [(4, 1), (3, 5), (6, 3), (1, 4)] {
            let (p, cfg) = proxied(&[a, b, c]);
            let net = FakeNet::new(&[
                (a, Via::Reply(first)),
                (b, Via::Reply(second)),
                (c, Via::Connects),
            ]);
            route(&net, &p, &cfg).unwrap();
            assert_eq!(tried(&net), [a, b, c], "replies {first}, {second}");
        }
        let (p, cfg) = proxied(&[a, b, c]);
        let net = FakeNet::new(&[(a, Via::Reply(1)), (b, Via::Reply(1)), (c, Via::Connects)]);
        route(&net, &p, &cfg).unwrap();
        assert_eq!(tried(&net), [a, b, c]);
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
            // The log names each by its place in the list, not by the
            // order of the tries.
            assert_eq!(
                net.notes.borrow()[1..],
                [(1, "proxy_failed"), (0, "proxy_failed")]
            );
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
    /// limit, which may be a short one) does not mark the proxy it was
    /// waiting for. The time is counted: once callers waited the
    /// proxy's whole time limit in all, it is held as unusable, and a
    /// try in between has only what is left of the limit.
    #[test]
    fn a_connect_cut_off_from_outside_counts_the_time() {
        let (a, b) = ("a.proxy.example", "b.proxy.example");
        let half = i64::from(PROXY_CONNECT_MS / 2);
        for (waits, outcome) in [
            (Via::Hangs, "proxy_failed"),
            (Via::HostSilent, "host_unreached"),
        ] {
            let (p, cfg) = proxied(&[a, b]);
            let net = FakeNet::new(&[(a, waits), (b, Via::Connects)]);
            // The proxy's own bound never ends; the caller drops the
            // connect after `ms`.
            let cut_after = |ms: i64| {
                let mut connect = Box::pin(open_routed(&net, &net.memory, &p.proxies, &cfg));
                assert!(connect.as_mut().now_or_never().is_none());
                net.now_ms.set(net.now_ms() + ms);
                drop(connect);
                assert_eq!(tried(&net), [a]);
            };
            cut_after(half - 1);
            assert!(!net.memory.is_last(&p.proxies[0], net.now_ms()));
            assert!(net.notes.borrow().is_empty());
            // One more cut, and the whole limit was waited.
            cut_after(1);
            assert!(!net.memory.is_last(&p.proxies[0], net.now_ms()));
            cut_after(half - 1);
            assert!(!net.memory.is_last(&p.proxies[0], net.now_ms()));
            cut_after(1);
            assert!(net.memory.is_last(&p.proxies[0], net.now_ms()));
            assert_eq!(
                net.memory.is_down(&p.proxies[0], net.now_ms()),
                waits == Via::Hangs
            );
            assert_eq!(*net.notes.borrow(), [(0, outcome)]);
            // Each try had what was left of the limit.
            let m = PROXY_CONNECT_MS;
            // and never less than a probe's time.
            let floor = PROBE_TIMEOUT_MS;
            assert!(floor > 1 && floor <= m / 2);
            assert_eq!(
                *net.limits.borrow(),
                [m, m / 2 + 1, m / 2, floor],
                "{waits:?}"
            );
            // The next connect goes past it at once.
            route(&net, &p, &cfg).unwrap();
            assert_eq!(tried(&net), [b]);
        }
    }

    /// A cut from outside leaves a proxy that is tried last as it is,
    /// and a proxy that connects in between starts from nothing.
    #[test]
    fn a_cut_does_not_undo_what_is_known() {
        let (a, b) = ("a.proxy.example", "b.proxy.example");
        let (p, cfg) = proxied(&[a, b]);
        let mut net = FakeNet::new(&[(a, Via::Down), (b, Via::Hangs)]);
        let cut_after = |net: &FakeNet, ms: i64| {
            let mut connect = Box::pin(open_routed(net, &net.memory, &p.proxies, &cfg));
            assert!(connect.as_mut().now_or_never().is_none());
            net.now_ms.set(net.now_ms() + ms);
        };
        // The first is down; the caller gives up on the second.
        cut_after(&net, 10);
        assert_eq!(tried(&net), [a, b]);
        assert!(net.memory.is_down(&p.proxies[0], net.now_ms()));
        // Now the second is down and the first hangs: tried last, cut.
        net.via = vec![(a, Via::Hangs), (b, Via::Down)];
        cut_after(&net, 10);
        assert_eq!(tried(&net), [b, a]);
        assert!(net.memory.is_down(&p.proxies[0], net.now_ms()));
        assert!(net.memory.all_down(&p.proxies, net.now_ms()));

        // Two connects wait for one proxy at the same time. One learns
        // that it is down; the other, cut after that, leaves it so.
        let (p, cfg) = proxied(&[a]);
        let net = FakeNet::new(&[(a, Via::Hangs)]);
        let mut cut = Box::pin(open_routed(&net, &net.memory, &p.proxies, &cfg));
        assert!(cut.as_mut().now_or_never().is_none());
        for (known, down) in [(Hold::Failed, true), (Hold::Demoted, false)] {
            net.memory.set(&p.proxies[0], Some(known), net.now_ms());
            let mut cut = Box::pin(open_routed(&net, &net.memory, &p.proxies, &cfg));
            assert!(cut.as_mut().now_or_never().is_none());
            drop(cut);
            assert!(net.memory.is_last(&p.proxies[0], net.now_ms()));
            assert_eq!(net.memory.is_down(&p.proxies[0], net.now_ms()), down);
            net.memory.set(&p.proxies[0], None, net.now_ms());
        }
        net.memory
            .set(&p.proxies[0], Some(Hold::Failed), net.now_ms());
        net.now_ms.set(net.now_ms() + 10);
        drop(cut);
        assert!(net.memory.is_down(&p.proxies[0], net.now_ms()));
        // Both are cut: the time of both counts.
        let net = FakeNet::new(&[(a, Via::Hangs)]);
        let mut one = Box::pin(open_routed(&net, &net.memory, &p.proxies, &cfg));
        let mut two = Box::pin(open_routed(&net, &net.memory, &p.proxies, &cfg));
        assert!(one.as_mut().now_or_never().is_none());
        assert!(two.as_mut().now_or_never().is_none());
        net.now_ms
            .set(net.now_ms() + i64::from(PROXY_CONNECT_MS / 2));
        drop(one);
        assert!(!net.memory.is_last(&p.proxies[0], net.now_ms()));
        drop(two);
        assert!(net.memory.is_down(&p.proxies[0], net.now_ms()));

        // Waited for, then connected: the time waited is forgotten.
        let (p, cfg) = proxied(&[a]);
        let mut net = FakeNet::new(&[(a, Via::Hangs)]);
        let mut connect = Box::pin(open_routed(&net, &net.memory, &p.proxies, &cfg));
        assert!(connect.as_mut().now_or_never().is_none());
        net.now_ms.set(net.now_ms() + 1_000);
        drop(connect);
        net.via[0].1 = Via::Connects;
        route(&net, &p, &cfg).unwrap();
        net.via[0].1 = Via::Hangs;
        let mut connect = Box::pin(open_routed(&net, &net.memory, &p.proxies, &cfg));
        assert!(connect.as_mut().now_or_never().is_none());
        drop(connect);
        // The try that connected never got to its bound; the one after
        // it has the whole limit again.
        assert_eq!(*net.limits.borrow(), [PROXY_CONNECT_MS, PROXY_CONNECT_MS]);
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
        let net = WorkerNet("p1");
        // Natively the timer never ends, and no proxy answers: at once.
        let err = open_routed(&net, &ProxyMemory::default(), &p.proxies, &cfg)
            .now_or_never()
            .unwrap()
            .err()
            .unwrap();
        assert!(hosts::proxy_failure(&err), "{err:?}");
    }
}
