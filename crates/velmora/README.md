# nntune-core

Shared Usenet data-plane core for NNTune v2. Compiles for
`wasm32-unknown-unknown` (Cloudflare Workers via `workers-rs`) **and**
native targets (services, Container batch jobs).

| Module | What |
|---|---|
| `nntp` | NNTP client (RFC 3977): greeting, `MODE READER`, `AUTHINFO`, `GROUP`, `STAT`, `ARTICLE`, `BODY`, `QUIT`, pipelined `fetch_many`; `430`/`480`/`481`/`502` (plus `482` on `AUTHINFO`) mapped to typed errors |
| `transport` | Portable `Transport` byte-pipe trait + CRLF/dot-block framing; every impl enforces per-op timeouts as `TimedOut` |
| `transports::tokio_tls` | Native transport: tokio TCP with optional rustls (Mozilla roots), feature `native-tls` |
| `transports::worker_socket` | Workers transport over `connect()`, timeouts via `worker::Delay`, feature `worker-transport` (wasm32) |
| `yenc` | yEnc encode/decode, byte-identical to v1; explicit SIMD fast path (x86_64 SSE2, wasm simd128 with `RUSTFLAGS="-C target-feature=+simd128"`), scalar fallback |
| `nzb` | Streaming NZB parser (quick-xml) with hard bounds on files, segments, bytes, nesting; SHA-256 segment digest identical to v1 |
| `decrypt` | Ranged AES-CBC and rclone-crypt (`seal_block` helper for tests/tooling) |
| `par2` | PAR2 recovery-set parse + `verify` + CRC-recombine `precheck` (all wasm-safe); `repair` shells out to `par2cmdline-turbo` and is Linux-only |

(Table sources: `nntp` commands and codes `src/nntp.rs:1-19`, `QUIT` `src/nntp.rs:204-207`,
`fetch_many` `src/nntp.rs:284-296`, code mapping `src/nntp.rs:393-403`;
`transport` trait and framing `src/transport.rs:27-43,119,173-182`, timeout contract
`src/transport.rs:22-26`; `tokio_tls` `src/transports/tokio_tls.rs:1-7,56-80`,
Mozilla roots `src/transports/tokio_tls.rs:57-58`, gating `src/transports/mod.rs:11-15`;
`worker_socket` `src/transports/worker_socket.rs:1-9,50-65`, timeouts
`src/transports/worker_socket.rs:37-48`, gating `src/transports/mod.rs:17-21`;
`yenc` `src/yenc.rs:1-12`; `nzb` `src/nzb.rs:1-6,129-131`; `decrypt`
`src/decrypt.rs:1-11`, `seal_block` `src/decrypt.rs:310-318`; `par2`
`src/par2.rs:9-21`, Linux-only repair `src/par2/repair.rs:70-107`.)

## Features

- `default = ["native-tls"]` — what services and tests build.
- `native-tls` — tokio + rustls transport (non-wasm).
- `worker-transport` — Workers `connect()` socket transport (wasm32 only).

(Sources: `crates/nntune-core/Cargo.toml:10-12`; gating `src/transports/mod.rs:11-21`;
wasm32 tokio `io-util`-only `Cargo.toml:36-37`.)

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
  (Sources: `file_by_name` ambiguity `src/par2.rs:270-281`, `file_by_name_bytes`
  `src/par2.rs:286-290`, `verify_bytes` `src/par2.rs:321-328`, `precheck_bytes`
  `src/par2.rs:422-427`.)

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
cargo test -p nntune-core                    # incl. Go-vector interop
cargo clippy -p nntune-core --all-targets    # clean, `-D warnings` in CI
cargo bench -p nntune-core                   # yEnc ms/MB for the bench gate
cargo check -p nntune-core --target wasm32-unknown-unknown --no-default-features [--features worker-transport]
RUSTFLAGS="-C target-feature=+simd128" cargo check -p nntune-core --target wasm32-unknown-unknown --no-default-features
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
