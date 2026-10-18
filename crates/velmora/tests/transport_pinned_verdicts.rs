//! Pinned, cancellable NNTP transport verdicts (acceptance).
//!
//! Paired acceptance tests for the pinned, cancellable transport build slice
//! (roadmap M3); the NZB intake wiring stays untouched: this file pins the
//! transport contract the intake will consume.
//!
//! Acceptance mapping:
//!
//! - TLS-off config rejected before connect:
//!   [`tls_off_rejected_before_connect`],
//!   [`tls_off_rejected_regardless_of_port`].
//! - Port allowlist (119/563) enforced: [`port_allowlist_enforced`].
//! - Cancellation aborts an in-flight fetch within a bound:
//!   [`cancellation_aborts_in_flight_fetch_within_bound`],
//!   [`successful_fetch_unaffected_when_cancel_never_fires`].
//! - Fail-closed names-only diagnostics (never credentials):
//!   [`rejections_never_carry_credentials`],
//!   [`validated_endpoint_carries_no_secrets`].
//! - Contract numbers + stable codes: [`contract_numbers_and_stable_codes_are_pinned`].
//! - Fail-closed before any I/O: [`validation_touches_no_network`].
//!
//! Run only this file (the rest of the crate stays green until the build
//! lands):
//!
//! ```sh
//! cargo test -p nntune-core --test transport_pinned_verdicts
//! ```
//!
//! Fixtures are synthetic and `std`-only plus the crate's `tokio` dev
//! dependency (host tests only): a scripted in-memory [`Transport`] that
//! pends instead of dialling, and futures that never touch the network.
//! No sockets, no DNS, no real credentials.
//!
//! # BUILDER CONTRACT (implement to make this file compile green)
//!
//! Add one module to `crates/nntune-core/src` and re-export it from `lib.rs`:
//!
//! ```text
//! nntune_core::pinned_transport
//! ```
//!
//! Minimum shapes used below (you may extend, never narrow). The shared
//! path must stay wasm-safe: `std` only, no `tokio` (not even
//! `tokio::select!`), no sockets, no new crates — implement cancellation
//! with `std::future::poll_fn` so
//! `cargo check -p nntune-core --target wasm32-unknown-unknown` keeps
//! passing. `tokio` appears in this test file only (host-only dev
//! dependency for the sleep clock).
//!
//! ```text
//! pub const ALLOWED_NNTP_PORTS: [u16; 2] = [119, 563];
//! pub const CANCEL_BOUND_MS: u64 = 1_000;
//!
//! #[derive(Clone, Copy, Debug, PartialEq, Eq)]
//! pub enum TransportRejection {
//!     TlsRequired,
//!     PortNotAllowed(u16),
//!     Cancelled,
//! }
//! impl TransportRejection {
//!     /// Stable machine code, e.g. "transport_tls_required".
//!     pub fn code(&self) -> &'static str;
//! }
//! // Display + Debug render names only (host, port, code): never the
//! // configured username or password.
//!
//! #[derive(Clone, Debug, PartialEq, Eq)]
//! pub struct ValidatedEndpoint {
//!     pub host: String, // preserved verbatim for TLS SNI + dial
//!     pub port: u16,    // always one of ALLOWED_NNTP_PORTS
//! }
//!
//! /// Pure, fail-closed validation: no I/O, no DNS, no clock. Checks TLS
//! /// FIRST (a TLS-off config is rejected whatever the port), then the
//! /// port allowlist. Credentials on the config are ignored, never echoed.
//! pub fn validate_nntp_endpoint(config: &NntpConfig) -> Result<ValidatedEndpoint, TransportRejection>;
//!
//! /// Cooperative cancellation combinator for the fetch path: resolves the
//! /// fetch unless `cancel` resolves first. A cancelled NNTP session has
//! /// unknown wire state (the command was sent, the reply was abandoned):
//! /// the caller must discard the client and reconnect, never reuse it.
//! /// No partial output contract: the fetch future is dropped at cancel.
//! pub async fn with_cancel<F, C>(fetch: F, cancel: C) -> Result<F::Output, TransportRejection>
//! where F: Future, C: Future<Output = ()>;
//! ```
//!
//! Wire `validate_nntp_endpoint` into the native `connect` path so a
//! TLS-off or off-allowlist config fails before any TCP dial, keeping the
//! same stable codes. Document the allowlist, the TLS-first order, the
//! cancel bound and every stable code in `crates/nntune-core/README.md`.
//!
//! EXPECTED STATE: this file does NOT compile until the build lands
//! (unresolved `pinned_transport` import). That red target is the
//! acceptance proof; `--lib` and the other integration targets stay green
//! around it. Do not merge this branch to main while it is red.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use nntune_core::nntp::{NntpClient, NntpConfig};
use nntune_core::pinned_transport::{
    validate_nntp_endpoint, with_cancel, TransportRejection, ValidatedEndpoint, ALLOWED_NNTP_PORTS,
    CANCEL_BOUND_MS,
};
use nntune_core::transport::Transport;

/// Transport that serves scripted reads, records writes, and — once the
/// script is exhausted — pends forever instead of failing. That models an
/// in-flight fetch stalled on the wire with no real network involved.
struct StallTransport {
    to_client: VecDeque<u8>,
    written: Vec<u8>,
}

impl StallTransport {
    fn new(readable: &[u8]) -> Self {
        StallTransport {
            to_client: readable.iter().cloned().collect(),
            written: Vec::new(),
        }
    }
}

impl Transport for StallTransport {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.to_client.is_empty() {
            // Stalled wire: pend until the future is dropped (cancelled).
            std::future::pending::<()>().await;
            unreachable!("pending never resolves");
        }
        let n = buf.len().min(self.to_client.len());
        for (i, slot) in buf[..n].iter_mut().enumerate() {
            *slot = self.to_client[i];
        }
        self.to_client.drain(..n);
        Ok(n)
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.written.extend_from_slice(buf);
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A future that never resolves (the "cancel never fires" leg).
struct Never;

impl Future for Never {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

fn config_with(host: &str, port: u16, tls: bool) -> NntpConfig {
    NntpConfig {
        host: host.into(),
        port,
        tls,
        username: Some("sentinel-user-9x".into()),
        password: Some("sentinel-pass-9x".into()),
        timeout: Duration::from_secs(5),
        max_pipelined: 4,
        ..NntpConfig::default()
    }
}

/// Pinned contract numbers + stable-code taxonomy (mirrored in the crate
/// README by the build). The ports are the NNTP conventions (119 plaintext
/// by convention, 563 implicit TLS); the policy additionally requires
/// TLS-on, so 119 is only valid as a TLS port here, never as plaintext.
#[test]
fn contract_numbers_and_stable_codes_are_pinned() {
    assert_eq!(ALLOWED_NNTP_PORTS, [119, 563]);
    assert_eq!(CANCEL_BOUND_MS, 1_000);

    let cases = [
        (TransportRejection::TlsRequired, "transport_tls_required"),
        (
            TransportRejection::PortNotAllowed(80),
            "transport_port_not_allowed",
        ),
        (TransportRejection::Cancelled, "transport_cancelled"),
    ];
    for (rejection, code) in cases {
        assert_eq!(rejection.code(), code, "stable code for {rejection:?}");
    }
    // The port payload must not change the machine code.
    assert_eq!(
        TransportRejection::PortNotAllowed(22).code(),
        "transport_port_not_allowed"
    );
}

/// A TLS-off config is rejected before connect: pure validation, no dial,
/// no DNS, no clock — even against the conventional TLS port.
#[test]
fn tls_off_rejected_before_connect() {
    let err = validate_nntp_endpoint(&config_with("nntp.example.com", 563, false))
        .expect_err("TLS-off must be rejected before connect");
    assert_eq!(err, TransportRejection::TlsRequired);
    assert_eq!(err.code(), "transport_tls_required");
}

/// TLS is checked FIRST (fail-closed): a TLS-off config is `TlsRequired`
/// whatever the port — even an off-allowlist one. Port policy never gets
/// to launder a plaintext config into a port error.
#[test]
fn tls_off_rejected_regardless_of_port() {
    for port in [119, 563, 80, 443, 8080] {
        let err = validate_nntp_endpoint(&config_with("nntp.example.com", port, false))
            .expect_err("TLS-off must be rejected on any port");
        assert_eq!(
            err,
            TransportRejection::TlsRequired,
            "port {port}: TLS check must win"
        );
    }
}

/// With TLS on, exactly 119/563 validate (host preserved verbatim for SNI);
/// every other port — including HTTPS 443 — is rejected with the offending
/// port attached and a stable code.
#[test]
fn port_allowlist_enforced() {
    for port in [119, 563] {
        let endpoint = validate_nntp_endpoint(&config_with("nntp.example.com", port, true))
            .expect("allowlisted port must validate");
        assert_eq!(
            endpoint,
            ValidatedEndpoint {
                host: "nntp.example.com".into(),
                port,
            }
        );
    }
    for port in [0, 22, 80, 443, 444, 8080, 8000, 65535] {
        let err = validate_nntp_endpoint(&config_with("nntp.example.com", port, true))
            .expect_err("off-allowlist port must be rejected");
        assert_eq!(
            err,
            TransportRejection::PortNotAllowed(port),
            "port {port} must echo the offending value"
        );
        assert_eq!(err.code(), "transport_port_not_allowed");
    }
}

/// Rejections are names-only: Display + Debug never carry the configured
/// username or password, only host/port/code material.
#[test]
fn rejections_never_carry_credentials() {
    let rejections = [
        TransportRejection::TlsRequired,
        TransportRejection::PortNotAllowed(8080),
        TransportRejection::Cancelled,
    ];
    for rejection in rejections {
        for rendered in [rejection.to_string(), format!("{rejection:?}")] {
            assert!(
                !rendered.contains("sentinel-user-9x"),
                "username leaked in {rendered:?}"
            );
            assert!(
                !rendered.contains("sentinel-pass-9x"),
                "password leaked in {rendered:?}"
            );
        }
    }
    // The validation itself must not leak either, even when fed credentials.
    let err = validate_nntp_endpoint(&config_with("nntp.example.com", 80, false))
        .expect_err("must reject");
    for rendered in [err.to_string(), format!("{err:?}")] {
        assert!(
            !rendered.contains("sentinel-user-9x") && !rendered.contains("sentinel-pass-9x"),
            "validation rejection leaked credentials: {rendered:?}"
        );
    }
}

/// The pinned verdict carries addressing only — Debug never renders
/// credentials that were on the validated config.
#[test]
fn validated_endpoint_carries_no_secrets() {
    let endpoint = validate_nntp_endpoint(&config_with("nntp.example.com", 563, true))
        .expect("allowlisted config must validate");
    let rendered = format!("{endpoint:?}");
    assert!(
        rendered.contains("nntp.example.com"),
        "host pinned: {rendered:?}"
    );
    assert!(
        !rendered.contains("sentinel-user-9x") && !rendered.contains("sentinel-pass-9x"),
        "endpoint leaked credentials: {rendered:?}"
    );
}

/// Validation is pure: it resolves against an unroutable host with no
/// server behind it and returns synchronously — proof nothing was dialled.
#[test]
fn validation_touches_no_network() {
    let start = Instant::now();
    let err = validate_nntp_endpoint(&config_with("invalid.invalid", 80, false))
        .expect_err("must reject without I/O");
    assert_eq!(err, TransportRejection::TlsRequired);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "validation must not perform network I/O"
    );
}

/// Cancellation aborts an in-flight ARTICLE fetch within the bound: the
/// wire stalls mid-reply, the cancel fires at 50 ms, and the combinator
/// returns `Cancelled` (stable code) promptly with no bytes appended.
#[tokio::test]
async fn cancellation_aborts_in_flight_fetch_within_bound() {
    let handshake = b"200 news.example.com ready\r\n200 reader mode\r\n";
    let transport = StallTransport::new(handshake);
    let plain = NntpConfig {
        host: "nntp.example.com".into(),
        port: 563,
        tls: true,
        username: None,
        password: None,
        timeout: Duration::from_secs(5),
        max_pipelined: 4,
        ..NntpConfig::default()
    };
    let mut client = NntpClient::connect(transport, &plain)
        .await
        .expect("handshake over stalled transport");

    let mut out = Vec::new();
    let cancel = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let start = Instant::now();
    let err = with_cancel(client.article_to("stalled@example", &mut out), cancel)
        .await
        .expect_err("stalled fetch must be cancellable");
    let elapsed = start.elapsed();
    assert_eq!(err, TransportRejection::Cancelled);
    assert_eq!(err.code(), "transport_cancelled");
    assert!(
        elapsed < Duration::from_millis(CANCEL_BOUND_MS),
        "cancel took {elapsed:?}, bound is {CANCEL_BOUND_MS} ms"
    );
    assert!(out.is_empty(), "cancelled fetch must append no bytes");
    // The ARTICLE command did go out before the stall: the abort happened
    // in flight, not before connect.
    let wire = client.into_inner().written;
    assert!(
        wire.windows(b"ARTICLE <stalled@example>".len())
            .any(|w| w == b"ARTICLE <stalled@example>"),
        "ARTICLE must have been sent before the stall"
    );
}

/// No false cancellation: a fetch that completes before any cancel signal
/// resolves normally through the combinator with intact bytes.
#[tokio::test]
async fn successful_fetch_unaffected_when_cancel_never_fires() {
    let script = b"200 news.example.com ready\r\n\
        200 reader mode\r\n\
        220 42 <a@x> article follows\r\n\
        Subject: t\r\n\
        \r\n\
        hello\r\n\
        .\r\n";
    let transport = StallTransport::new(script);
    let plain = NntpConfig {
        host: "nntp.example.com".into(),
        port: 119,
        tls: true,
        username: None,
        password: None,
        timeout: Duration::from_secs(5),
        max_pipelined: 4,
        ..NntpConfig::default()
    };
    let mut client = NntpClient::connect(transport, &plain)
        .await
        .expect("handshake");

    let mut out = Vec::new();
    let inner = with_cancel(client.article_to("a@x", &mut out), Never)
        .await
        .expect("cancel never fires: combinator must resolve the fetch");
    inner.expect("scripted fetch must succeed");
    assert_eq!(out, b"Subject: t\r\n\r\nhello\r\n");
}
