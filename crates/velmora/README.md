# velmora

Shared Usenet data-plane engine (extracted from NNTune v2). Compiles for
`wasm32-unknown-unknown` (Cloudflare Workers via `workers-rs`) **and**
native targets (services, Container batch jobs).

| Module | What |
|---|---|
| `nntp` | NNTP client (RFC 3977): greeting, `MODE READER`, `AUTHINFO`, `GROUP`, `STAT`, `ARTICLE`, `BODY`, `QUIT`, pipelined `fetch_many`; `430`/`480`/`481`/`502` (plus `482` on `AUTHINFO`) mapped to typed errors |
| `transport` | Portable `Transport` byte-pipe trait + CRLF/dot-block framing; every impl enforces per-op timeouts as `TimedOut` |
| `pinned_transport` | Pinned, cancellable fetch policy for NZB fetch: TLS-on only, port allowlist, cooperative cancellation, names-only diagnostics (see below) |
| `transports::tokio_tls` | Native transport: tokio TCP with optional rustls (Mozilla roots), feature `native-tls` |
| `transports::worker_socket` | Workers transport over `connect()`, timeouts via `worker::Delay`, feature `worker-transport` (wasm32) |
| `yenc` | yEnc encode/decode, byte-identical to v1; explicit SIMD fast path (x86_64 SSE2, wasm simd128 with `RUSTFLAGS="-C target-feature=+simd128"`), scalar fallback |
| `nzb` | Streaming NZB parser (quick-xml) with hard bounds on files, segments, bytes, nesting; SHA-256 segment digest identical to v1 |
| `media` | `velmora.media.v1`, the only format velmora products write: age v1 STREAM payload with a 48-byte committing header, three key modes, commitment-gated ranged reads and full verification (see below) |
| `par2` | PAR2 recovery-set parse + `verify` + CRC-recombine `precheck` (all wasm-safe); `repair` shells out to `par2cmdline-turbo` and is Linux-only |

(Table sources: `nntp` commands and codes `src/nntp.rs:1-19`, `QUIT` `src/nntp.rs:204-207`,
`fetch_many` `src/nntp.rs:284-296`, code mapping `src/nntp.rs:393-403`;
`transport` trait and framing `src/transport.rs:27-43,119,173-182`, timeout contract
`src/transport.rs:22-26`; `tokio_tls` `src/transports/tokio_tls.rs:1-7,56-80`,
Mozilla roots `src/transports/tokio_tls.rs:57-58`, gating `src/transports/mod.rs:11-15`;
`worker_socket` `src/transports/worker_socket.rs:1-9,50-65`, timeouts
`src/transports/worker_socket.rs:37-48`, gating `src/transports/mod.rs:17-21`;
`yenc` `src/yenc.rs:1-12`; `nzb` `src/nzb.rs:1-6,129-131`; `media`
`src/media.rs` module docs; `par2`
`src/par2.rs:9-21`, Linux-only repair `src/par2/repair.rs:70-107`.)

## Media encryption: `velmora.media.v1`

Chosen by the media-format decision (Applied Cryptography Reviewer, approved
by the Security Engineer, 2026-11-07). Every object NNTune or the Cloudflare Drive writes to
Usenet uses this format and nothing else. velmora has no rclone-crypt or
AES-CBC code; reading third-party encrypted releases would need its own
decision and a separate read-only `velmora::compat` module.

**Layout.** `N` (16 B) ‖ `commitment` (32 B) ‖ chunks. Each chunk is the age
v1 STREAM construction unchanged: ChaCha20-Poly1305 under
`payload_key = HKDF-SHA256(salt = N, ikm = K, info = "payload")`, 64 KiB of
plaintext plus a 16-byte tag, nonce = 11-byte big-endian counter ‖
last-chunk flag. `L = max(1, ceil(P / 65536))`; the object is
`48 + P + 16·L` bytes. A full chunk is 65,552 B, so
`ARTICLE_CIPHER_BLOCKS = 11` still gives 721,072 B articles; article 0 is
721,120 B.

**Key commitment and binding.** `commitment = HKDF-Expand(PRK,
"velmora.media.v1/commit" ‖ 0x00 ‖ mode ‖ ctx)` with `PRK =
HKDF-Extract(N, K)`. Format version, key mode and product context (`ctx`:
`nntune/media` or `drive/media`) are not on the wire: they are stored with
the record and bound only through the commitment (and the derived `N` in
convergent modes). `VerifiedHeader::verify` is the only way to a
`ChunkReader`; it checks the profile's mode allow-list, the derived `N`, and
the commitment in constant time before deriving the payload key, so a wrong
key, mode, ctx or version fails with one generic error and no AEAD call.

**Key modes** (`KeyMode`, stored as one byte):

| Mode | `K` | `N` | Used by |
|---|---|---|---|
| `Random` (1) | fresh CSPRNG per file (`FileKey::generate`) | fresh CSPRNG | NNTune (only mode its profile allows); Drive private files without dedupe |
| `VaultConvergent` (2) | `HMAC-SHA256(vault_dedupe_key, "velmora.media.v1/vault-K" ‖ 0 ‖ ctx ‖ 0 ‖ BE64(P) ‖ SHA-256(content))` (`ConvergentKey::vault`) | derived from `(K, mode, ctx)` | Drive private files (default) |
| `PublicConvergent` (3) | `HKDF(OPRF output, "velmora.media.v1/public-K")` over `public_oprf_input` (`ConvergentKey::public`) | derived | Drive public share links only |

The convergent `Sealer` re-hashes the plaintext while sealing and withholds
the final chunk unless it matches the `(P, D)` the key came from (TOCTOU
gate). The OPRF, `vault_dedupe_key` custody and the dedupe service rules
(always upload full ciphertext, no existence signal, server-computed dedupe
ID) belong to the Drive crypto design, not this crate.

**Reader rules.** The header and `P` come from the trusted record, so ranged
reads never need article 0; when article 0 is fetched,
`ChunkReader::check_wire_header` must pass. Only chunks whose tag verified
release plaintext (a failed chunk's buffer is wiped). `verify_all` (post-verify,
backup drill) also requires the flagged final chunk at `L-1` and end of
source right after it, and returns the plaintext SHA-256. Keys and payload
keys are zeroized on drop; errors carry no key- or nonce-derived bytes.

**Threat model delta (vs the rclone-crypt layout it replaces).**

| Property | rclone-crypt | `velmora.media.v1` |
|---|---|---|
| Whole-chunk truncation, appended chunks | only via the DB length | detected in band (final flag) and via the trusted length |
| Reorder, duplicate, cross-file splice | detected | detected (counter nonce, per-file HKDF payload key) |
| Key commitment / multi-key ciphertexts | none | 32-byte commitment checked before any decrypt |
| Version, mode, product separation | fixed `RCLONE` magic | bound into the commitment; fails closed |
| Deterministic (dedupe) modes | undefined | per-vault (no provider confirmation) and public-share only; no cross-user convergence of private files |
| Wire fingerprint | constant 8-byte magic | no constant bytes (sizes still reveal the scheme) |

Unchanged residuals: Usenet observers see sizes, timing and article
relationships and can withhold articles (PAR2 and backbones handle
availability); there is no rollback protection beyond the trusted record;
key custody is governed by each product.

**Vectors.** `src/media.rs` runs every C2SP CCTV age `stream_*` vector (Go
reference) through the STREAM layer; `tests/media_vectors.rs` checks
`testdata/media-v1/vectors.txt`, generated by an independent pyca
`cryptography` script, for all three modes; `tests/media_rejections.rs`
covers truncation, extension, reorder, splice, wrong key/ctx/mode, bit
flips, convergent determinism, the TOCTOU gate and ranged-read coordinates.

## Pinned transport proof (NZB fetch)

`velmora::pinned_transport` is the fail-closed policy the NZB intake
wiring consumes (separate intake card, untouched here):

- **Allowlist:** `ALLOWED_NNTP_PORTS = [119, 563]` (the NNTP conventions).
  The policy additionally requires TLS-on, so `119` is only valid as a TLS
  port here, never as plaintext.
- **TLS-first order:** `validate_nntp_endpoint` checks `tls` BEFORE the port
  allowlist. A TLS-off config is `TlsRequired` whatever the port — even an
  off-allowlist one — so port policy never launders a plaintext config into
  a port error. Pure validation: no I/O, no DNS, no clock.
- **Cancel bound:** `CANCEL_BOUND_MS = 1_000`. `with_cancel(fetch, cancel)`
  resolves the fetch unless `cancel` resolves first (fetch wins ties). A
  cancelled session has unknown wire state: discard the client and
  reconnect, never reuse it. The fetch future is dropped at cancel. The
  pinned entry points run the same validation before any dial — native
  `transports::tokio_tls::connect_pinned` and wasm32
  `WorkerTransport::connect_pinned` (the general `connect` entry points stay
  permissive for the plaintext loopback fixtures used by the stream/ingest
  harnesses and client unit tests; NZB fetch must use the pinned entry point
  for its target). This is an NNTP dial policy for NZB fetch, not the HTTPS
  pinned-443 contract.
- **Stable codes:** `TransportRejection::code()` returns
  `transport_tls_required` (`TlsRequired`), `transport_port_not_allowed`
  (`PortNotAllowed(port)` — the payload never changes the code), and
  `transport_cancelled` (`Cancelled`). Both pinned entries funnel through
  the shared `pinned_rejection_message` helper before any dial, so they
  embed the same codes by construction: native `connect_pinned` in its
  `io::Error` message (`InvalidInput`), Workers `connect_pinned` in
  `worker::Error::RustError`. The helper's mapping is unit-tested natively
  and a wiring guard fails if either entry stops calling it first (the
  Workers socket open itself stays wasm32 compile-checked — CI has no wasm
  test runner).
- **Names-only diagnostics:** `Display`/`Debug` for `TransportRejection` and
  `ValidatedEndpoint` render host, port and code material only — never the
  configured username or password. Shared path is `std`-only (cancellation
  via `std::future::poll_fn`, no `tokio`), so the wasm32 check keeps
  passing.

## Features

- `default = ["native-tls"]` — what services and tests build.
- `native-tls` — tokio + rustls transport (non-wasm).
- `worker-transport` — Workers `connect()` socket transport (wasm32 only).

(Sources: `crates/velmora/Cargo.toml:11-13`; gating `src/transports/mod.rs:11-21`;
wasm32 tokio `io-util`-only `Cargo.toml:43-44`.)

The protocol/parser core uses injected transports; the transport implementations
and the native repair runner own network I/O and deadlines.

## Resource limits and lookup behavior

- **NNTP:** `NntpConfig.max_article_bytes` defaults to 64 MiB, counting CRLF
  but excluding bytes already in the output buffer. Overflow rolls back partial
  output and makes the connection unusable. A failed `fetch_many` also poisons
  the client; reconnect before retrying. Successful results are all buffered, so
  limit the requested batch size to your runtime's memory budget.
(Sources: 64 MiB ceiling `src/transport.rs:50`, default `src/nntp.rs:71-83`,
CRLF counting and rollback `src/transport.rs:168-182`, `fetch_many` poisoning
`src/nntp.rs:284-296`.)
- **NZB:** `document_bytes` is enforced at the `BufRead` boundary, including
  during buffering of a single XML event. The input's own buffer is separate.
  (Sources: `src/nzb.rs:145-152`, bounded events and separate caller buffering
  `src/nzb.rs:205-208`.)
- **PAR2:** Original `filename_bytes` determine identity. Ambiguous display-name
  lookups return `None`; use `file_by_name_bytes`, `verify_bytes`, and
  `precheck_bytes` for byte-precise selection and verification.
  (Sources: `file_by_name` ambiguity `src/par2.rs:336-347`, `file_by_name_bytes`
  `src/par2.rs:350-354`, `verify_bytes` `src/par2.rs:387-392`, `precheck_bytes`
  `src/par2.rs:485-490`.)

**Native repair is Linux-only**, requiring `/usr/bin/prlimit`, a trusted
image-pinned binary, and an exclusive scratch directory. Default ceilings are
120 seconds wall time, 60 seconds CPU, 1 MiB combined output, 8 GiB workspace
(and per-file size), and 512 MiB address space. `repair_with_limits` accepts
smaller budgets. The wrapper runs `par2 repair -q` (single `-q`: `Repair
complete.` / `All files are correct, repair is not required.` kept, progress
suppressed; `-q -q` would silence the real binary entirely; the `<N> recovery
blocks` count line is suppressed at `-q`, so `repaired_blocks` is 0 when
nothing was needed and -1 when repair completed or the count is unknown).
(Sources: budgets `src/par2/repair.rs:14-37`, exit-code semantics
`src/par2/repair.rs:41-63`, `/usr/bin/prlimit` and single `-q`
`src/par2/repair/linux.rs:168-186`, `parse_repaired`
`src/par2/repair/linux.rs:233-255`.)
`RepairReport` carries `exit_code`/`signal` for retry vs dead-letter decisions
(par2cmdline-turbo: 0 success; 1/2/4 permanently unusable inputs and 6 with
`Recovery will not be possible` a corrupt set — dead-letter, do not retry;
only 8 and signal kills are resource failures. Any other code (e.g. 3, 5, 7,
or 6 without that line) is unexpected: bound retries and run `par2 verify`
first to separate unusable sets from transient failures). The calling Container must
remain unprivileged with quota-backed scratch: aggregate-size polling is
neither a sandbox nor a hard disk quota.

## Checks

```sh
cargo test -p velmora                    # incl. Go-vector interop and age CCTV vectors
cargo clippy -p velmora --all-targets    # clean, `-D warnings` in CI
cargo bench -p velmora                   # yEnc ms/MB for the bench gate
cargo check -p velmora --target wasm32-unknown-unknown --no-default-features [--features worker-transport]
RUSTFLAGS="-C target-feature=+simd128" cargo check -p velmora --target wasm32-unknown-unknown --no-default-features
```

## Bench gate (this PR)

Native x86_64 (`cargo bench`, 1 MiB buffers):

| Case | Time | ms/MB |
|---|---|---|
| decode, clean (SIMD path) | 0.37 ms | **0.37** |
| decode, escape-heavy (scalar lanes) | 1.19 ms | **1.19** |
| encode | 2.54 ms | 2.54 |

Baseline: TS/V8 implementation at 1.2 ms/MB **on Workers**. Native Rust
decode beats it (0.37–1.19 ms/MB), but these are different machines and
runtimes — wasm-on-Workers was NOT measured here. The `workers/bench`
sibling card should run the same 1 MiB buffers through the deployed
simd128 build and report `Date.now()` deltas before this gate is called
fully closed.
