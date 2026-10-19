//! Pinned, cancellable NNTP transport proof for NZB fetch.
//!
//! Fail-closed policy consumed by the NZB intake wiring (separate intake
//! card, untouched here) and the stream pool dial sites: TLS-on unless the
//! plaintext acknowledgment is set, NNTP port allowlist, cooperative
//! cancellation, names-only diagnostics.
//!
//! - **Allowlist:** [`ALLOWED_NNTP_PORTS`] (`119`, `563` — the NNTP
//!   conventions; the policy additionally requires TLS-on unless the
//!   plaintext acknowledgment is set, so `119` is only valid as a TLS
//!   port here for unacknowledged configs, never as unacknowledged
//!   plaintext).
//! - **TLS-first order:** [`validate_nntp_endpoint`] checks `tls` BEFORE the
//!   port allowlist. A TLS-off config without the plaintext acknowledgment
//!   ([`NntpConfig::allow_insecure_plaintext`]) is
//!   [`TransportRejection::TlsRequired`] whatever the port — port policy
//!   never launders a plaintext config into a port error. An
//!   acknowledged-plaintext config (the vault's explicit opt-in, mirrored
//!   onto the dial config by the pool's vault-read slice) skips only the
//!   TLS check; the port allowlist still applies.
//! - **Cancel bound:** [`CANCEL_BOUND_MS`] (`1_000` ms). [`with_cancel`]
//!   resolves the fetch unless the cancel future resolves first; a cancelled
//!   session has unknown wire state, so the caller must discard the client
//!   and reconnect, never reuse it. The fetch future is dropped at cancel
//!   (no partial-output contract).
//! - **Stable codes:** [`TransportRejection::code`] returns
//!   `transport_tls_required`, `transport_port_not_allowed`
//!   (port payload never changes the code), `transport_cancelled`. The
//!   pinned entry points funnel through [`pinned_rejection_message`] before
//!   any dial and embed the same codes: native `connect_pinned`
//!   (`io::Error`, `InvalidInput`) and wasm32
//!   `WorkerTransport::connect_pinned` (`worker::Error::RustError`), with a
//!   natively-run wiring guard failing if either entry stops calling the
//!   helper first. The general `connect` entry points stay
//!   permissive on purpose: the stream/ingest fixture harnesses and the
//!   client unit tests dial plaintext loopback servers through them
//!   (pool/stream call-site changes are out of scope); the NZB fetch path
//!   must use the pinned entry point for its target (native or Workers).
//!   This is an NNTP dial policy for NZB fetch, not the HTTPS pinned-443
//!   contract.
//! - **Diagnostics are names-only:** `Display`/`Debug` render host, port and
//!   code material only — never the configured username or password.
//!
//! The shared path is `std`-only (no `tokio`, no sockets, no new crates) so
//! `cargo check -p nntune-core --target wasm32-unknown-unknown` keeps
//! passing; cancellation is implemented with [`std::future::poll_fn`].

use std::fmt;
use std::future::Future;

use crate::nntp::NntpConfig;

/// NNTP ports the fetch path accepts: `119` and `563` (TLS required
/// separately unless the plaintext acknowledgment is set — `119` is never
/// unacknowledged plaintext here).
pub const ALLOWED_NNTP_PORTS: [u16; 2] = [119, 563];

/// Bound (ms) within which [`with_cancel`] must surface a fired cancel.
/// Mirrored by the acceptance verdicts; the combinator itself resolves as
/// soon as either side resolves.
pub const CANCEL_BOUND_MS: u64 = 1_000;

/// Fail-closed transport rejection with a stable machine code.
///
/// Carries addressing only (at most the offending port): never credentials,
/// so `Display` and `Debug` are safe for logs by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportRejection {
    /// TLS-off config without the plaintext acknowledgment
    /// (`tls == false`, `allow_insecure_plaintext == false`): rejected
    /// before connect on any port.
    TlsRequired,
    /// TLS-on config with an off-allowlist port; carries the offending port.
    PortNotAllowed(u16),
    /// The cancel future resolved before the fetch completed.
    Cancelled,
}

impl TransportRejection {
    /// Stable machine code for logs/metrics:
    /// `transport_tls_required` | `transport_port_not_allowed` |
    /// `transport_cancelled`. The port payload never changes the code.
    pub fn code(&self) -> &'static str {
        match self {
            TransportRejection::TlsRequired => "transport_tls_required",
            TransportRejection::PortNotAllowed(_) => "transport_port_not_allowed",
            TransportRejection::Cancelled => "transport_cancelled",
        }
    }
}

impl fmt::Display for TransportRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportRejection::TlsRequired => {
                write!(f, "transport_tls_required: NNTP connection requires TLS")
            }
            TransportRejection::PortNotAllowed(port) => write!(
                f,
                "transport_port_not_allowed: port {port} not in [119, 563]"
            ),
            TransportRejection::Cancelled => {
                write!(f, "transport_cancelled: NNTP fetch cancelled")
            }
        }
    }
}

impl std::error::Error for TransportRejection {}

/// Validated NNTP endpoint: addressing only (host preserved verbatim for TLS
/// SNI + dial; port always one of [`ALLOWED_NNTP_PORTS`]). Carries no
/// secrets: `Debug` renders the host/port only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedEndpoint {
    /// Server hostname, preserved verbatim for TLS SNI + dial.
    pub host: String,
    /// Validated port: always one of [`ALLOWED_NNTP_PORTS`].
    pub port: u16,
}

/// Pure, fail-closed validation: no I/O, no DNS, no clock.
///
/// Checks TLS FIRST (a TLS-off config without the plaintext acknowledgment
/// is [`TransportRejection::TlsRequired`] whatever the port), then the
/// port allowlist. An acknowledged-plaintext config
/// (`allow_insecure_plaintext == true`, the vault's explicit opt-in)
/// skips only the TLS check so the pool can dial providers the vault
/// accepted with the cleartext acknowledgment; the port allowlist still
/// applies to that cohort. Credentials on the config are ignored, never
/// echoed.
pub fn validate_nntp_endpoint(
    config: &NntpConfig,
) -> Result<ValidatedEndpoint, TransportRejection> {
    if !config.tls && !config.allow_insecure_plaintext {
        return Err(TransportRejection::TlsRequired);
    }
    if !ALLOWED_NNTP_PORTS.contains(&config.port) {
        return Err(TransportRejection::PortNotAllowed(config.port));
    }
    Ok(ValidatedEndpoint {
        host: config.host.clone(),
        port: config.port,
    })
}

/// Shared rejection renderer for the pinned entry points.
///
/// Returns the names-only rejection message when `config` fails
/// [`validate_nntp_endpoint`], `None` when it passes. Both the native
/// `connect_pinned` (`io::Error`, `InvalidInput`) and the wasm32
/// `WorkerTransport::connect_pinned` (`worker::Error::RustError`) delegate to
/// this, so the two entries embed the same stable codes by construction.
/// `std`-only: natively unit-tested (the Workers socket open itself stays
/// wasm32 compile-checked — CI has no wasm test runner).
pub fn pinned_rejection_message(config: &NntpConfig) -> Option<String> {
    validate_nntp_endpoint(config)
        .err()
        .map(|rejection| rejection.to_string())
}

/// Cooperative cancellation combinator for the fetch path: resolves the
/// fetch unless `cancel` resolves first.
///
/// A cancelled NNTP session has unknown wire state (the command was sent,
/// the reply was abandoned): the caller must discard the client and
/// reconnect, never reuse it. No partial-output contract: the fetch future
/// is dropped at cancel. When both sides are ready, the fetch wins.
///
/// `std`-only (no `tokio::select!`) so the shared path stays wasm-safe.
pub async fn with_cancel<F, C>(fetch: F, cancel: C) -> Result<F::Output, TransportRejection>
where
    F: Future,
    C: Future<Output = ()>,
{
    let mut fetch = std::pin::pin!(fetch);
    let mut cancel = std::pin::pin!(cancel);
    std::future::poll_fn(|cx| {
        if let std::task::Poll::Ready(out) = fetch.as_mut().poll(cx) {
            std::task::Poll::Ready(Ok(out))
        } else if cancel.as_mut().poll(cx).is_ready() {
            std::task::Poll::Ready(Err(TransportRejection::Cancelled))
        } else {
            std::task::Poll::Pending
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const SENTINEL_USER: &str = "sentinel-user-9f3c";
    const SENTINEL_PASS: &str = "sentinel-pass-7a1e";

    fn config(host: &str, port: u16, tls: bool) -> NntpConfig {
        NntpConfig {
            host: host.to_owned(),
            port,
            tls,
            allow_insecure_plaintext: false,
            username: Some(SENTINEL_USER.to_owned()),
            password: Some(SENTINEL_PASS.to_owned()),
            timeout: Duration::from_millis(200),
            max_pipelined: 1,
            max_article_bytes: crate::transport::MAX_ARTICLE_BYTES,
        }
    }

    /// An acknowledged-plaintext config: `tls: false` with the vault's
    /// explicit opt-in mirrored on, as the pool's vault-read slice must
    /// produce for providers saved with the cleartext acknowledgment.
    fn config_ack(host: &str, port: u16) -> NntpConfig {
        NntpConfig {
            allow_insecure_plaintext: true,
            ..config(host, port, false)
        }
    }

    fn assert_names_only(msg: &str, code: &str) {
        assert!(
            msg.contains(code),
            "rejection message must carry stable code {code}: {msg}"
        );
        assert!(
            !msg.contains(SENTINEL_USER) && !msg.contains(SENTINEL_PASS),
            "rejection message must stay names-only: {msg}"
        );
    }

    /// The shared helper rejects unacknowledged TLS-off configs on any port
    /// (kills a mutant that weakens the helper: the mutant would return
    /// `None` and the pinned entries would dial plaintext).
    #[test]
    fn pinned_helper_rejects_unacknowledged_tls_off_on_any_port() {
        for port in [80, 119, 563] {
            let msg = pinned_rejection_message(&config("127.0.0.1", port, false))
                .expect("TLS-off config must be rejected");
            assert_names_only(&msg, "transport_tls_required");
        }
    }

    /// Acknowledged-plaintext configs (the vault's explicit opt-in mirrored
    /// on the dial config) pass the TLS check on allowlisted ports, so the
    /// pool can dial providers the vault accepted with the cleartext
    /// acknowledgment. Kills a mutant that drops the acknowledgment read:
    /// the mutant would reject this cohort with `transport_tls_required`.
    #[test]
    fn pinned_helper_allows_acknowledged_plaintext_on_allowlisted_ports() {
        for port in ALLOWED_NNTP_PORTS {
            let endpoint = validate_nntp_endpoint(&config_ack("news.example", port))
                .expect("acknowledged plaintext on allowlisted port must pass");
            assert_eq!(endpoint.port, port);
            assert!(
                pinned_rejection_message(&config_ack("news.example", port)).is_none(),
                "acknowledged plaintext on allowlisted port {port} must pass"
            );
        }
    }

    /// The port allowlist still applies to the acknowledged cohort: an
    /// acknowledged-plaintext config on an off-allowlist port is a port
    /// rejection, never a dial (kills a mutant that lets the acknowledgment
    /// bypass port policy).
    #[test]
    fn pinned_helper_still_enforces_port_allowlist_for_acknowledged_plaintext() {
        let msg = pinned_rejection_message(&config_ack("127.0.0.1", 80))
            .expect("off-allowlist port must be rejected even when acknowledged");
        assert_names_only(&msg, "transport_port_not_allowed");
    }

    /// The shared helper rejects TLS-on configs on off-allowlist ports and
    /// accepts the allowlist (kills a mutant that weakens port policy).
    #[test]
    fn pinned_helper_enforces_port_allowlist() {
        let msg = pinned_rejection_message(&config("127.0.0.1", 80, true))
            .expect("port-80 config must be rejected");
        assert_names_only(&msg, "transport_port_not_allowed");

        for port in ALLOWED_NNTP_PORTS {
            assert!(
                pinned_rejection_message(&config("news.example", port, true)).is_none(),
                "allowlisted TLS port {port} must pass"
            );
        }
    }

    /// TLS-first order through the shared helper: a TLS-off config on an
    /// off-allowlist port is a TLS rejection, never a port rejection.
    #[test]
    fn pinned_helper_checks_tls_before_ports() {
        let msg = pinned_rejection_message(&config("127.0.0.1", 80, false))
            .expect("TLS-off config must be rejected");
        assert_names_only(&msg, "transport_tls_required");
    }

    /// Wiring guard: fails if a pinned entry point stops funnelling through
    /// the shared helper before its dial. Kills the bypass mutant (validation
    /// dropped or reordered after the dial) on targets CI cannot execute
    /// (the Workers entry is wasm32-only; CI compile-checks it).
    fn assert_pinned_entry_wires_through_helper(source: &str, file: &str, dial: &str) {
        let fn_start = source.find("fn connect_pinned").unwrap_or_else(|| {
            panic!("{file} must define connect_pinned");
        });
        let body = &source[fn_start..];
        let helper_pos = body.find("pinned_rejection_message").unwrap_or_else(|| {
            panic!("{file} connect_pinned must call pinned_rejection_message");
        });
        let dial_pos = body.find(dial).unwrap_or_else(|| {
            panic!("{file} connect_pinned must delegate to {dial}");
        });
        assert!(
            helper_pos < dial_pos,
            "{file} connect_pinned must validate before dialling"
        );
    }

    #[test]
    fn worker_pinned_entry_wires_through_shared_helper_before_dial() {
        assert_pinned_entry_wires_through_helper(
            include_str!("transports/worker_socket.rs"),
            "worker_socket.rs",
            "Self::connect(config)",
        );
    }

    #[test]
    fn native_pinned_entry_wires_through_shared_helper_before_dial() {
        assert_pinned_entry_wires_through_helper(
            include_str!("transports/tokio_tls.rs"),
            "tokio_tls.rs",
            "connect(config).await",
        );
    }
}
