//! Nearest-host selection for a provider with several host names.
//!
//! A provider may list more host names of one account (`hosts`, next to
//! `host`): the regional servers of one service. The fastest from where
//! the code runs is not known in advance, and a queue consumer has no
//! `request.cf` to guess from, so it is measured:
//!
//! - **On first use in an isolate** the connector probes up to
//!   [`PROBE_HOSTS`] endpoints one after the other: the time to TLS and a
//!   `200`/`201` greeting, then `QUIT` (not timed). A probe is cut once it
//!   is slower than the best so far, or after [`PROBE_TIMEOUT_MS`]. The
//!   fastest wins; a tie goes to the earlier one. A host that greets with
//!   a refusal (`400`, `502`) does not win.
//! - **The winner is kept** for [`HOST_PICK_TTL_MS`] per provider per
//!   isolate. Connects in that time go straight to it: no probing on
//!   every connect.
//! - **Fallback:** a connect that fails at the transport (socket, TLS,
//!   timeout, a dropped connection) moves on to the next endpoint, in
//!   configuration order; one that gets through becomes the winner for
//!   [`SHORT_PICK_TTL_MS`], so that one failure does not pin a slower
//!   host for long. A
//!   reply from the provider (a refused login, a full account) is the
//!   account's answer, not the host's, and is returned as it is.
//! - **Concurrent connects** of one isolate do not probe again while a
//!   probe runs: they wait for its result, at most [`PROBE_WAIT_MS`]. A
//!   probe whose connect is dropped withdraws itself, so nobody waits for
//!   it.
//!
//! Probing runs inside the caller's `connect`, so under its permit, one
//! socket at a time, from the address of the same invocation: it counts
//! against `max_conns` and `max_ips` like the connect it is part of. A
//! provider with one host name is never probed.

// No `Send` bound is intended, as in `ports`: workers-rs futures are `!Send`.
#![allow(async_fn_in_trait)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;

use velmora::transport::Transport;

use crate::types::{BridgeError, ProviderConfig, Result, UnixMs};

/// Endpoints probed at most: `host` and the first `hosts` entries. Later
/// entries are fallbacks only.
pub const PROBE_HOSTS: usize = 4;

/// Longest one probe may take, in milliseconds.
pub const PROBE_TIMEOUT_MS: u32 = 2_000;

/// How long a winner is kept, in milliseconds (10 minutes).
pub const HOST_PICK_TTL_MS: i64 = 600_000;

/// How long a pick is kept that no probe made: the configuration order
/// when no endpoint answered (the provider may be down, and probing it on
/// every connect would only add delay), or the endpoint a fallback got
/// through to.
pub const SHORT_PICK_TTL_MS: i64 = 60_000;

/// Longest a connect waits for another connect's probe of the same
/// provider, in milliseconds: the longest a whole probe may run (every
/// endpoint at its time limit and its goodbye limit), and a margin. A
/// probe older than this is treated as lost.
pub const PROBE_WAIT_MS: i64 =
    PROBE_HOSTS as i64 * (PROBE_TIMEOUT_MS as i64 + PROBE_GOODBYE_MS as i64) + 500;

/// How often a waiting connect looks again, in milliseconds.
pub const PROBE_POLL_MS: u32 = 50;

/// Bound on one connect attempt that has another endpoint to fall back
/// to, in seconds. The last endpoint runs under the caller's bound only.
pub const HOST_CONNECT_SECS: u32 = 10;

/// Longest a probe's goodbye (`QUIT`, close) may take, in milliseconds.
/// It is not part of the measured time.
pub const PROBE_GOODBYE_MS: u32 = 1_000;

/// Longest greeting line a probe reads, in bytes.
const MAX_GREETING_BYTES: usize = 512;

/// What a connector does for [`HostPicker::connect`].
pub trait Dialer {
    type Session;
    /// Opens a socket to `host`, reads the greeting, says `QUIT`. The
    /// milliseconds until a `200`/`201` greeting ([`ready`]), or `None`
    /// when there was none within `limit_ms`.
    async fn probe(&self, host: &str, limit_ms: u32) -> Option<u32>;
    /// The whole handshake on `host`. `bounded` = give up after
    /// [`HOST_CONNECT_SECS`] (another endpoint is left to try).
    async fn dial(&self, host: &str, bounded: bool) -> Result<Self::Session>;
    /// Waits `ms` milliseconds.
    async fn pause(&self, ms: u32);
    fn now(&self) -> UnixMs;
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Pick {
    /// A connect is probing since this time.
    Probing(UnixMs),
    /// Connect to this host first until the time.
    Chosen { host: String, until: UnixMs },
}

/// The winners of one isolate, by provider id.
#[derive(Debug, Default)]
pub struct HostPicker {
    picks: RefCell<BTreeMap<String, Pick>>,
}

/// Whether a failed connect says the host cannot be reached (try the
/// next one), rather than that the account refused (do not).
pub fn host_failure(e: &BridgeError) -> bool {
    match e {
        // `InvalidInput` is the transport policy refusing the
        // configuration: no other host would pass it either.
        BridgeError::Nntp(velmora::Error::Io(io)) => io.kind() != io::ErrorKind::InvalidInput,
        _ => false,
    }
}

impl HostPicker {
    pub fn new() -> Self {
        HostPicker::default()
    }

    /// The host `provider` is connected to first right now, if one was
    /// picked (tests and diagnostics).
    pub fn chosen(&self, provider: &str, now: UnixMs) -> Option<String> {
        match self.picks.borrow().get(provider) {
            Some(Pick::Chosen { host, until }) if *until > now => Some(host.clone()),
            _ => None,
        }
    }

    /// Connects to the fastest reachable endpoint of `provider`.
    pub async fn connect<D: Dialer>(&self, provider: &ProviderConfig, d: &D) -> Result<D::Session> {
        let endpoints = provider.endpoints();
        if endpoints.len() == 1 {
            return d.dial(endpoints[0], false).await;
        }
        let order = self.order(provider, &endpoints, d).await;
        let mut failure = None;
        for (i, host) in order.iter().enumerate() {
            let last = i + 1 == order.len();
            match d.dial(host, !last).await {
                Ok(session) => {
                    if i > 0 {
                        // The preferred host failed and this one answered:
                        // used for now, probed again soon.
                        self.choose(&provider.id, host, d.now(), SHORT_PICK_TTL_MS);
                    }
                    return Ok(session);
                }
                Err(e) if host_failure(&e) => failure = Some(e),
                Err(e) => return Err(e),
            }
        }
        // `order` holds every endpoint, at least two.
        Err(failure.unwrap_or(BridgeError::Invalid("no endpoint")))
    }

    fn choose(&self, provider: &str, host: &str, now: UnixMs, ttl: i64) {
        self.picks.borrow_mut().insert(
            provider.to_string(),
            Pick::Chosen {
                host: host.to_string(),
                until: UnixMs(now.0.saturating_add(ttl)),
            },
        );
    }

    /// Every endpoint, the one to try first in front and the others in
    /// configuration order.
    async fn order<'e, D: Dialer>(
        &self,
        provider: &ProviderConfig,
        endpoints: &[&'e str],
        d: &D,
    ) -> Vec<&'e str> {
        let first = loop {
            let now = d.now();
            let pick = self.picks.borrow().get(&provider.id).cloned();
            match pick {
                Some(Pick::Chosen { host, until }) if until > now => {
                    if let Some(i) = endpoints.iter().position(|e| *e == host) {
                        break i;
                    }
                }
                // A probe from the future (the clock stepped back) is lost.
                Some(Pick::Probing(since))
                    if (0..PROBE_WAIT_MS).contains(&now.0.saturating_sub(since.0)) =>
                {
                    d.pause(PROBE_POLL_MS).await;
                    continue;
                }
                _ => {}
            }
            break self.probe(provider, endpoints, d).await;
        };
        let mut order = vec![endpoints[first]];
        order.extend(
            endpoints
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != first)
                .map(|(_, e)| *e),
        );
        order
    }

    /// Probes the endpoints and records the winner; its index.
    async fn probe<D: Dialer>(
        &self,
        provider: &ProviderConfig,
        endpoints: &[&str],
        d: &D,
    ) -> usize {
        let since = d.now();
        self.picks
            .borrow_mut()
            .insert(provider.id.clone(), Pick::Probing(since));
        // Withdraws the mark if this connect is dropped mid-probe.
        let mut guard = ProbeGuard {
            picks: &self.picks,
            provider: &provider.id,
            since,
            done: false,
        };
        let mut best: Option<(usize, u32)> = None;
        for (i, host) in endpoints.iter().enumerate().take(PROBE_HOSTS) {
            // A host slower than the best so far cannot win: cut it there.
            let limit = best.map_or(PROBE_TIMEOUT_MS, |(_, ms)| ms.min(PROBE_TIMEOUT_MS));
            if let Some(ms) = d.probe(host, limit).await {
                if ms <= limit && best.is_none_or(|(_, b)| ms < b) {
                    best = Some((i, ms));
                }
            }
        }
        guard.done = true;
        let now = d.now();
        match best {
            Some((i, _)) => {
                self.choose(&provider.id, endpoints[i], now, HOST_PICK_TTL_MS);
                i
            }
            None => {
                self.choose(&provider.id, endpoints[0], now, SHORT_PICK_TTL_MS);
                0
            }
        }
    }
}

/// Removes a provider's `Probing` mark when the probe that set it ends
/// without a result (its future was dropped).
struct ProbeGuard<'a> {
    picks: &'a RefCell<BTreeMap<String, Pick>>,
    provider: &'a str,
    since: UnixMs,
    done: bool,
}

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let mut picks = self.picks.borrow_mut();
        if picks.get(self.provider) == Some(&Pick::Probing(self.since)) {
            picks.remove(self.provider);
        }
    }
}

/// Reads one reply line from a fresh socket: the greeting's code, or
/// `None` when no well-formed line came. The time limit is the caller's.
pub async fn greeting<T: Transport>(socket: &mut T) -> Option<u16> {
    let mut line = Vec::with_capacity(64);
    let mut buf = [0u8; 128];
    loop {
        match socket.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => {
                line.extend_from_slice(&buf[..n]);
                if line.windows(2).any(|w| w == b"\r\n") {
                    let code = line.get(..3)?;
                    if !code.iter().all(u8::is_ascii_digit) {
                        return None;
                    }
                    return core::str::from_utf8(code).ok()?.parse().ok();
                }
                if line.len() > MAX_GREETING_BYTES {
                    return None;
                }
            }
        }
    }
}

/// Whether a greeting offers a session: `200` or `201`. A host that
/// refuses at the greeting (`400`, `502`) is no candidate, however fast.
pub fn ready(code: Option<u16>) -> bool {
    matches!(code, Some(200 | 201))
}

/// Ends a probe: `QUIT` when the server spoke, then close. The time limit
/// is the caller's ([`PROBE_GOODBYE_MS`]).
pub async fn goodbye<T: Transport>(socket: &mut T, greeted: bool) {
    if greeted {
        let _ = socket.write_all(b"QUIT\r\n").await;
    }
    let _ = socket.shutdown().await;
}

/// `io::Error` for a probe or connect attempt that ran out of time.
pub fn timed_out() -> BridgeError {
    BridgeError::Nntp(velmora::Error::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "nntp connect ran out of time",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    use std::cell::Cell;
    use std::collections::VecDeque;

    fn provider(host: &str, hosts: &[&str]) -> ProviderConfig {
        let mut p: ProviderConfig = serde_json::from_value(serde_json::json!({
            "id": "p6", "host": host, "port": 563, "tls": true, "user": "u", "pass": "pw",
            "backbone": "bb", "post": true, "read": false, "max_conns": 8
        }))
        .unwrap();
        p.hosts = hosts.iter().map(|h| h.to_string()).collect();
        p
    }

    /// A fake network: per host, the probe time (`None` = no answer) and
    /// whether a connect gets through. Records every call.
    #[derive(Default)]
    struct Net {
        probe_ms: BTreeMap<&'static str, Option<u32>>,
        down: RefCell<Vec<&'static str>>,
        refuses: Vec<&'static str>,
        now: Cell<i64>,
        calls: RefCell<Vec<String>>,
        /// Milliseconds spent in `pause`.
        paused: Cell<u32>,
        /// Finishes another connect's probe on the first pause: picks
        /// this host in that picker.
        finish_probe: RefCell<Option<(std::rc::Rc<HostPicker>, &'static str)>>,
        /// Probes and pauses give the executor a turn, as real I/O does.
        yields: bool,
    }

    impl Net {
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
        fn probes(&self) -> usize {
            self.calls()
                .iter()
                .filter(|c| c.starts_with("probe"))
                .count()
        }
    }

    impl Dialer for Net {
        type Session = String;
        async fn probe(&self, host: &str, limit_ms: u32) -> Option<u32> {
            self.calls
                .borrow_mut()
                .push(format!("probe {host} {limit_ms}"));
            if self.yields {
                tokio::task::yield_now().await;
            }
            let ms = self.probe_ms.get(host).copied().flatten();
            match ms {
                Some(ms) if ms <= limit_ms => {
                    self.now.set(self.now.get() + i64::from(ms));
                    Some(ms)
                }
                _ => {
                    self.now.set(self.now.get() + i64::from(limit_ms));
                    None
                }
            }
        }
        async fn dial(&self, host: &str, bounded: bool) -> Result<String> {
            self.calls
                .borrow_mut()
                .push(format!("dial {host} {bounded}"));
            if self.down.borrow().contains(&host) {
                return Err(timed_out());
            }
            if self.refuses.contains(&host) {
                return Err(BridgeError::Nntp(velmora::Error::NoPermission(
                    "502".into(),
                )));
            }
            Ok(host.to_string())
        }
        async fn pause(&self, ms: u32) {
            if let Some((picker, host)) = self.finish_probe.borrow_mut().take() {
                picker.choose("p6", host, self.now(), HOST_PICK_TTL_MS);
            }
            if self.yields {
                tokio::task::yield_now().await;
            }
            self.paused.set(self.paused.get() + ms);
            self.now.set(self.now.get() + i64::from(ms));
        }
        fn now(&self) -> UnixMs {
            UnixMs(self.now.get())
        }
    }

    fn run<T>(f: impl std::future::Future<Output = T>) -> T {
        f.now_or_never().expect("the fake network never waits")
    }

    fn net(probes: &[(&'static str, Option<u32>)]) -> Net {
        Net {
            probe_ms: probes.iter().copied().collect(),
            now: Cell::new(1_000_000),
            ..Net::default()
        }
    }

    #[test]
    fn one_host_is_dialled_without_a_probe() {
        let n = net(&[]);
        let picker = HostPicker::new();
        let s = run(picker.connect(&provider("a", &[]), &n)).unwrap();
        assert_eq!(s, "a");
        assert_eq!(n.calls(), ["dial a false"]);
        assert_eq!(picker.chosen("p6", n.now()), None);
    }

    #[test]
    fn the_fastest_host_wins_and_slower_probes_are_cut_at_the_best() {
        let n = net(&[("a", Some(400)), ("b", Some(150)), ("c", Some(300))]);
        let picker = HostPicker::new();
        let s = run(picker.connect(&provider("a", &["b", "c"]), &n)).unwrap();
        assert_eq!(s, "b");
        assert_eq!(
            n.calls(),
            ["probe a 2000", "probe b 400", "probe c 150", "dial b true"]
        );
        assert_eq!(picker.chosen("p6", n.now()).as_deref(), Some("b"));
    }

    #[test]
    fn a_tie_goes_to_the_earlier_host() {
        let n = net(&[("a", Some(200)), ("b", Some(200))]);
        let picker = HostPicker::new();
        assert_eq!(
            run(picker.connect(&provider("a", &["b"]), &n)).unwrap(),
            "a"
        );
    }

    #[test]
    fn the_winner_is_kept_for_the_ttl_then_probed_again() {
        let n = net(&[("a", Some(400)), ("b", Some(150))]);
        let picker = HostPicker::new();
        let p = provider("a", &["b"]);
        run(picker.connect(&p, &n)).unwrap();
        assert_eq!(n.probes(), 2);
        // Within the TTL: straight to the winner, no probe.
        n.now.set(n.now.get() + HOST_PICK_TTL_MS - 1_000);
        assert_eq!(run(picker.connect(&p, &n)).unwrap(), "b");
        assert_eq!(n.probes(), 2);
        assert_eq!(n.calls().last().unwrap(), "dial b true");
        // After it: probed again.
        n.now.set(n.now.get() + 2_000);
        run(picker.connect(&p, &n)).unwrap();
        assert_eq!(n.probes(), 4);
    }

    #[test]
    fn the_cache_is_per_provider() {
        let n = net(&[("a", Some(400)), ("b", Some(150))]);
        let picker = HostPicker::new();
        run(picker.connect(&provider("a", &["b"]), &n)).unwrap();
        let mut other = provider("a", &["b"]);
        other.id = "p7".into();
        run(picker.connect(&other, &n)).unwrap();
        assert_eq!(n.probes(), 4);
    }

    #[test]
    fn a_failed_winner_falls_back_in_order_and_the_next_becomes_the_winner() {
        let n = net(&[("a", Some(300)), ("b", Some(100)), ("c", Some(200))]);
        let picker = HostPicker::new();
        let p = provider("a", &["b", "c"]);
        run(picker.connect(&p, &n)).unwrap();
        n.down.borrow_mut().push("b");
        n.calls.borrow_mut().clear();
        // `b` is down: `a` (configuration order) is next and gets through.
        assert_eq!(run(picker.connect(&p, &n)).unwrap(), "a");
        assert_eq!(n.calls(), ["dial b true", "dial a true"]);
        assert_eq!(picker.chosen("p6", n.now()).as_deref(), Some("a"));
        // The new winner is used without a probe...
        n.calls.borrow_mut().clear();
        run(picker.connect(&p, &n)).unwrap();
        assert_eq!(n.calls(), ["dial a true"]);
        // ...but only briefly: one failure does not pin it for the TTL.
        n.down.borrow_mut().clear();
        n.now.set(n.now.get() + SHORT_PICK_TTL_MS);
        assert_eq!(run(picker.connect(&p, &n)).unwrap(), "b");
        assert_eq!(n.probes(), 3);
    }

    #[test]
    fn only_the_last_attempt_runs_unbounded_and_every_host_down_is_the_last_error() {
        let n = net(&[("a", Some(100)), ("b", Some(200))]);
        n.down.borrow_mut().extend(["a", "b"]);
        let picker = HostPicker::new();
        let err = run(picker.connect(&provider("a", &["b"]), &n)).unwrap_err();
        assert!(host_failure(&err));
        assert_eq!(
            n.calls(),
            ["probe a 2000", "probe b 100", "dial a true", "dial b false"]
        );
    }

    #[test]
    fn a_refusal_by_the_account_is_not_a_host_failure() {
        let mut n = net(&[("a", Some(100)), ("b", Some(200))]);
        n.refuses = vec!["a"];
        let picker = HostPicker::new();
        let err = run(picker.connect(&provider("a", &["b"]), &n)).unwrap_err();
        assert!(!host_failure(&err));
        // No second connection: `b` would only be refused the same way.
        assert_eq!(n.calls().last().unwrap(), "dial a true");
        assert_eq!(picker.chosen("p6", n.now()).as_deref(), Some("a"));
    }

    #[test]
    fn no_answer_keeps_configuration_order_briefly() {
        let n = net(&[("a", None), ("b", None)]);
        let picker = HostPicker::new();
        let p = provider("a", &["b"]);
        assert_eq!(run(picker.connect(&p, &n)).unwrap(), "a");
        assert_eq!(n.probes(), 2);
        // Not probed on every connect...
        n.now.set(n.now.get() + SHORT_PICK_TTL_MS - 1_000);
        run(picker.connect(&p, &n)).unwrap();
        assert_eq!(n.probes(), 2);
        // ...but again after the short TTL.
        n.now.set(n.now.get() + 2_000);
        run(picker.connect(&p, &n)).unwrap();
        assert_eq!(n.probes(), 4);
    }

    #[test]
    fn at_most_probe_hosts_are_probed_and_later_ones_are_fallbacks() {
        let n = net(&[
            ("a", Some(500)),
            ("b", Some(400)),
            ("c", Some(300)),
            ("d", Some(200)),
            ("e", Some(10)),
        ]);
        let picker = HostPicker::new();
        let p = provider("a", &["b", "c", "d", "e"]);
        assert_eq!(run(picker.connect(&p, &n)).unwrap(), "d");
        assert_eq!(n.probes(), PROBE_HOSTS);
        assert!(!n.calls().iter().any(|c| c.starts_with("probe e")));
        n.down.borrow_mut().extend(["a", "b", "c", "d"]);
        n.calls.borrow_mut().clear();
        assert_eq!(run(picker.connect(&p, &n)).unwrap(), "e");
        assert_eq!(
            n.calls(),
            [
                "dial d true",
                "dial a true",
                "dial b true",
                "dial c true",
                "dial e false"
            ]
        );
    }

    #[test]
    fn a_connect_waits_for_a_running_probe_and_uses_its_winner() {
        let n = net(&[("a", Some(400)), ("b", Some(150))]);
        let picker = std::rc::Rc::new(HostPicker::new());
        // Another connect is probing, and picks `b` while this one waits.
        picker
            .picks
            .borrow_mut()
            .insert("p6".into(), Pick::Probing(n.now()));
        *n.finish_probe.borrow_mut() = Some((picker.clone(), "b"));
        assert_eq!(
            run(picker.connect(&provider("a", &["b"]), &n)).unwrap(),
            "b"
        );
        assert_eq!(n.paused.get(), PROBE_POLL_MS);
        assert_eq!(n.probes(), 0);
        assert_eq!(n.calls(), ["dial b true"]);
    }

    #[test]
    fn a_lost_probe_is_given_up_after_the_wait() {
        let n = net(&[("a", Some(400)), ("b", Some(150))]);
        let picker = HostPicker::new();
        let p = provider("a", &["b"]);
        // A probe that never finishes (its connect was dropped).
        picker
            .picks
            .borrow_mut()
            .insert("p6".into(), Pick::Probing(n.now()));
        assert_eq!(run(picker.connect(&p, &n)).unwrap(), "b");
        assert!(n.paused.get() as i64 >= PROBE_WAIT_MS - i64::from(PROBE_POLL_MS));
        assert!((n.paused.get() as i64) < PROBE_WAIT_MS + i64::from(PROBE_POLL_MS));
        assert_eq!(n.probes(), 2);
    }

    #[test]
    fn a_cached_host_no_longer_listed_is_probed_again() {
        let n = net(&[("a", Some(400)), ("b", Some(150))]);
        let picker = HostPicker::new();
        picker.choose("p6", "gone", n.now(), HOST_PICK_TTL_MS);
        assert_eq!(
            run(picker.connect(&provider("a", &["b"]), &n)).unwrap(),
            "b"
        );
        assert_eq!(n.probes(), 2);
    }

    /// A probe at every limit ends before its waiters give up on it, and
    /// waiting for it still leaves a read time to connect.
    #[test]
    fn the_wait_covers_a_whole_probe_and_fits_a_read() {
        let probe = PROBE_HOSTS as i64 * i64::from(PROBE_TIMEOUT_MS + PROBE_GOODBYE_MS);
        assert!(probe < PROBE_WAIT_MS);
        let read_ms = i64::from(crate::ports::READ_CALL_SECS) * 1000;
        assert!(PROBE_WAIT_MS + i64::from(HOST_CONNECT_SECS) * 1000 / 2 < read_ms);
    }

    #[test]
    fn host_failure_classes() {
        assert!(host_failure(&timed_out()));
        let refused_policy = BridgeError::Nntp(velmora::Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "policy",
        )));
        assert!(!host_failure(&refused_policy));
        let eof = BridgeError::Nntp(velmora::Error::Io(io::ErrorKind::UnexpectedEof.into()));
        assert!(host_failure(&eof));
        assert!(!host_failure(&BridgeError::Nntp(
            velmora::Error::AuthFailed("481".into())
        )));
        assert!(!host_failure(&BridgeError::Nntp(
            velmora::Error::NntpReply {
                code: 400,
                text: "busy".into()
            }
        )));
    }

    /// A socket that replays chunks and records what was written.
    struct Script {
        reads: VecDeque<io::Result<Vec<u8>>>,
        written: Vec<u8>,
        shut: bool,
    }

    impl Script {
        fn new(reads: Vec<io::Result<&[u8]>>) -> Self {
            Script {
                reads: reads.into_iter().map(|r| r.map(<[u8]>::to_vec)).collect(),
                written: Vec::new(),
                shut: false,
            }
        }
    }

    impl Transport for Script {
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.reads.pop_front() {
                None => Ok(0),
                Some(Err(e)) => Err(e),
                Some(Ok(chunk)) => {
                    let n = chunk.len().min(buf.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    if n < chunk.len() {
                        self.reads.push_front(Ok(chunk[n..].to_vec()));
                    }
                    Ok(n)
                }
            }
        }
        async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            self.written.extend_from_slice(buf);
            Ok(())
        }
        async fn shutdown(&mut self) -> io::Result<()> {
            self.shut = true;
            Ok(())
        }
    }

    #[test]
    fn greeting_reads_one_reply_line_and_goodbye_says_quit() {
        let mut s = Script::new(vec![Ok(b"200 news.example rea"), Ok(b"dy\r\n")]);
        let code = run(greeting(&mut s));
        assert_eq!(code, Some(200));
        assert!(ready(code));
        run(goodbye(&mut s, code.is_some()));
        assert_eq!(s.written, b"QUIT\r\n");
        assert!(s.shut);
        assert!(ready(Some(201)));
    }

    /// A host that refuses at the greeting is no candidate: it would win
    /// every probe (a refusal is quick) and serve no session.
    #[test]
    fn a_refusing_greeting_is_not_ready() {
        for (line, code) in [
            (&b"502 too many connections\r\n"[..], 502),
            (&b"400 service unavailable\r\n"[..], 400),
        ] {
            let mut s = Script::new(vec![Ok(line)]);
            assert_eq!(run(greeting(&mut s)), Some(code));
            assert!(!ready(Some(code)));
        }
        assert!(!ready(None));
    }

    #[test]
    fn greeting_refuses_silence_garbage_and_errors() {
        for reads in [
            vec![],
            vec![Ok(&b"HTTP/1.1 400 Bad\r\n"[..])],
            vec![Ok(&b"2\r\n"[..])],
            vec![Err(io::ErrorKind::ConnectionReset.into())],
            vec![Ok(&[b'2'; 600][..])],
        ] {
            let mut s = Script::new(reads);
            assert_eq!(run(greeting(&mut s)), None);
            run(goodbye(&mut s, false));
            assert!(s.written.is_empty());
            assert!(s.shut);
        }
    }

    fn yielding(probes: &[(&'static str, Option<u32>)]) -> Net {
        Net {
            yields: true,
            ..net(probes)
        }
    }

    /// The connects of one post job start together: one probes, the
    /// others wait for it, and every one lands on the winner.
    #[tokio::test]
    async fn concurrent_connects_probe_once() {
        let n = yielding(&[("a", Some(400)), ("b", Some(150))]);
        let picker = HostPicker::new();
        let p = provider("a", &["b"]);
        let (x, y, z) = tokio::join!(
            picker.connect(&p, &n),
            picker.connect(&p, &n),
            picker.connect(&p, &n)
        );
        assert_eq!(
            (x.unwrap(), y.unwrap(), z.unwrap()),
            ("b".into(), "b".into(), "b".into())
        );
        assert_eq!(n.probes(), 2, "{:?}", n.calls());
        assert!(n.paused.get() > 0);
    }

    /// A connect dropped mid-probe (its caller gave up) withdraws its
    /// mark: the next connect probes at once instead of waiting.
    #[tokio::test]
    async fn a_dropped_probe_does_not_hold_up_the_next_connect() {
        let n = yielding(&[("a", Some(400)), ("b", Some(150))]);
        let picker = HostPicker::new();
        let p = provider("a", &["b"]);
        {
            let first = picker.connect(&p, &n);
            let mut first = std::pin::pin!(first);
            assert!(first.as_mut().now_or_never().is_none());
            assert!(matches!(
                picker.picks.borrow().get("p6"),
                Some(Pick::Probing(_))
            ));
        }
        assert!(picker.picks.borrow().get("p6").is_none());
        assert_eq!(picker.connect(&p, &n).await.unwrap(), "b");
        assert_eq!(n.paused.get(), 0);
        assert_eq!(n.probes(), 3);
    }

    /// A probe mark from the future (the clock stepped back) is lost, not
    /// waited for.
    #[test]
    fn a_probe_from_the_future_is_not_waited_for() {
        let n = net(&[("a", Some(400)), ("b", Some(150))]);
        let picker = HostPicker::new();
        picker
            .picks
            .borrow_mut()
            .insert("p6".into(), Pick::Probing(UnixMs(n.now().0 + 60_000)));
        assert_eq!(
            run(picker.connect(&provider("a", &["b"]), &n)).unwrap(),
            "b"
        );
        assert_eq!(n.paused.get(), 0);
    }
}
