# nntune-test-nntp

Synthetic NNTP test server + fixture corpus for NNTune v2 CI. **No real Usenet is used in CI.**

## What it is

- Async Tokio NNTP server (RFC 3977 subset): `CAPABILITIES`, `MODE READER`,
  `AUTHINFO USER/PASS`, `GROUP`, `LIST`, `XOVER`, `ARTICLE`/`BODY`/`HEAD`/`STAT`, `QUIT`.
- Fixture corpus generated at runtime from **synthesized sine tones** (8-bit PCM WAV,
  8 kHz, ≤ 0.25 s): single-part yEnc, 3-part multi-part, obfuscated subjects,
  `Rar!`-style and `7z`-style payloads (marker + deterministic filler — not real
  archives), plus a plain-text control. CC0 by construction; nothing to license.
- Fault injection: per-credential connection caps (`502`), `430` missing articles,
  `481` auth failures, throttled slow links, mid-body disconnects, latency.
- Checked-in NZBs in `fixtures/nzb/` reference the served message-IDs.

## Use from integration tests

```rust
let server = nntune_test_nntp::TestNntpServer::spawn_for_test().await;
// connect a raw TCP NNTP client to server.addr(), AUTHINFO testuser/testpass
```

Custom fault configs via `ServerConfig`:

```rust
let mut cfg = nntune_test_nntp::ServerConfig::for_test();
cfg.slow_bytes_per_sec = Some(400);
cfg.drop_after_bytes.insert("<single-yenc-001@nntune.test>".into(), 16);
let server = nntune_test_nntp::TestNntpServer::spawn(cfg).await;
```

Default credentials: `testuser/testpass` (max 2 connections),
`otheruser/otherpass` (max 8). Auth is required for `GROUP`/`ARTICLE`/etc.

## Standalone binary

```sh
cargo run -p nntune-test-nntp --bin nntp-fixture-server -- --port 9119
cargo run -p nntune-test-nntp --bin nntp-fixture-server -- --slow-bps 400 --drop-after '<id>:16'
```

## Tests

```sh
cargo test -p nntune-test-nntp
cargo clippy -p nntune-test-nntp --all-targets -- -D warnings
cargo fmt -p nntune-test-nntp -- --check
```

`tests/integration_nntp.rs` is the acceptance suite: auth, group/article/body/head/stat,
XOVER, yEnc decode, multi-part reassembly, obfuscated subjects, rar/7z markers, 430s,
connection caps, slow links, mid-body disconnects, NZB/ID consistency.
