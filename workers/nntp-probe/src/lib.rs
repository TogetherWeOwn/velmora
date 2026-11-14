//! Throwaway reachability probe: can a Cloudflare Worker reach a Usenet
//! provider over implicit TLS, authenticate, POST one velmora-shaped article,
//! and read it back with STAT + BODY? Also reports what the runtime preserves
//! of the raw request target (for SigV4 canonical-request reconstruction).
//!
//! Routes (every route requires `Authorization: Bearer <PROBE_TOKEN>`).
//! `p=<n>` (1-9) selects the account `NNTP_P<n>_*`; without it the legacy
//! single-account secrets `NNTP_*` are used.
//!
//! - `POST /probe/post?p=&size=<bytes>&payload=media|random`: connect, auth,
//!   POST, STAT, BODY, yEnc decode, SHA-256 compare.
//! - `GET /probe/body?p=&mid=<message-id>`: STAT + BODY of an earlier post.
//! - `GET /probe/caps?p=`: greeting code (200 posting allowed / 201 not),
//!   CAPABILITIES before and after auth, MODE READER and AUTHINFO codes.
//! - `GET /probe/head?p=&mid=<id>[&mid=<id>...]` (at most 3): HEAD of each,
//!   returning only `Path`, `Xref`, `Injection-Info`, `NNTP-Posting-Host`,
//!   redacted.
//! - `POST /probe/postrun?p=&n=<1-30>&secs=<1-60>&size=&max_mb=&arts=`: opens
//!   `n` sockets and POSTs fresh random articles back to back on each until
//!   the time or byte budget ends. Reports throughput and POST timings.
//! - `GET /probe/ramp?p=&n=<1-30>&hold=<0-30>`: opens `n` sessions at once,
//!   authenticates each, holds them `hold` seconds, checks they are still
//!   alive with `DATE`, then QUITs. Reports per-session codes and timings.
//! - `GET|PUT /raw/<anything>`: echoes the request target as seen.
//!
//! Responses carry reply codes, timings and redacted header values. Free
//! text from the provider (greeting, capability lines) is returned only
//! after every configured host and account value and every IP-shaped token
//! is replaced. Credentials never reach a response body or a log line.

// Used only by the wasm32 routes; native builds compile it for the tests.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod discovery;

// The Worker itself only builds for wasm32; `discovery` holds the pure
// helpers and is unit-tested natively with `cargo test`.
#[cfg(target_arch = "wasm32")]
mod probe;
