# nntune-test-nntp

Synthetic NNTP test server + fixture corpus for NNTune v2 CI. **No real Usenet is used in CI.**

## What it is

- Async Tokio NNTP server (RFC 3977 subset): `CAPABILITIES`, `MODE READER`,
  `AUTHINFO USER/PASS`, `GROUP`, `LIST`, `XOVER`, `ARTICLE`/`BODY`/`HEAD`/`STAT`,
  `POST`, `QUIT`.
- Fixture corpus generated at runtime from **synthesized sine tones** (8-bit PCM WAV,
  8 kHz, ≤ 0.25 s): single-part yEnc, two 3-part multi-part sets (plain +
  obfuscated subjects),
  `Rar!`-style and `7z`-style payloads (marker + deterministic filler — not real
  archives), plus a plain-text control. CC0 by construction; nothing to license.
- Fault injection: per-credential connection caps (`502`), `430` missing articles,
  `481` auth failures, throttled slow links, mid-body disconnects, latency.
- No checked-in NZB files anywhere: tests that need an NZB build it in memory
  with `nzb_for()` from the served corpus (see `tests/integration_nntp.rs`).
  The staging E2E never touches this corpus: it ingests a secret-held real
  NZB rebuilt into `RUNNER_TEMP` only (see `e2e/`).

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

## POST spool + runtime hiding (M2 stage tests / B7 legs)

- `POST` (`340`/`240`): stores articles in a per-instance in-memory spool
  keyed by message-ID, served back via `ARTICLE`/`BODY`/`HEAD`/`STAT`
  (and included in `GROUP`/`LIST`/`XOVER`). Re-posting a visible ID is a
  duplicate (`435`); `440` while `posting_allowed` is off, `480` without
  auth, `441` on empty/oversize submissions. Dot-unstuffing and the `.`
  terminator follow RFC 3977 §6.3. A missing `Message-ID` is generated
  (`<posted-N@nntune.test>`) and stored in the headers; comma-separated
  `Newsgroups` selects the first group; folded headers are unfolded for
  the overview.
- Runtime hiding: `server.hide(id)` / `unhide(id)` / `set_hidden(ids)`
  make retrieval answer `430` for those IDs (propagation gaps, article
  loss); re-posting a hidden ID succeeds (`240`) and repairs it without
  storing a second copy.
- Two `TestNntpServer` instances hold fully independent spools
  (spool-A/spool-B); `posted_count()`, `posted_ids()`,
  `posted_count_for(ids)` and `is_stored(id)` support per-file/manifest
  duplicate assertions.
- `ServerConfig::posting_allowed` seeds the per-instance switch;
  `missing_ids` seeds the hidden set.

## Tests

Local Rust builds go through the bounded Cargo pool (see repo `AGENTS.md`):

```sh
python3 scripts/cargo_cache.py run -- test -p nntune-test-nntp
python3 scripts/cargo_cache.py run -- clippy -p nntune-test-nntp --all-targets -- -D warnings
python3 scripts/cargo_cache.py run -- fmt -p nntune-test-nntp -- --check
```

`tests/integration_nntp.rs` is the acceptance suite: auth, group/article/body/head/stat,
XOVER, yEnc decode, multi-part reassembly, obfuscated subjects, rar/7z markers, 430s,
connection caps, slow links, mid-body disconnects, in-memory NZB/ID consistency.
