# velmora

Shared Usenet data-plane engine in Rust, for native targets and for
`wasm32-unknown-unknown` (Cloudflare Workers via `workers-rs`).

| Crate | Library | What |
|---|---|---|
| [`crates/velmora`](crates/velmora/README.md) | `velmora` | NNTP client and transports (native rustls, Workers sockets), pinned/cancellable fetch policy, yEnc (SIMD + scalar), NZB parser, ranged AES-CBC and rclone-crypt decrypt, PAR2 parse/verify/create and Linux repair, segment identity, posting article assembly |
| [`crates/velmora-test-nntp`](crates/velmora-test-nntp/README.md) | `velmora_test_nntp` | Synthetic in-process NNTP server and fixture corpus, so no CI run touches real Usenet |

## Scope

Velmora holds the engine only: protocol, codecs, parsers and transports
that any Usenet-backed product can share. Product-specific contracts stay
in the product. NNTune's `transcode`, `original_source` and
`provider_authority_store` modules, for example, live in nntunev2's
`nntune-core` shim, which re-exports this crate.

The code was extracted from `TogetherWeOwn/nntunev2` at `f7c9f6d` with its
history preserved. The tag `nntunev2-extract-f7c9f6d` points at the
filtered history, which stays reachable even though this repo merges by
squash.

## Consumer pin policy

Depend on velmora by git `rev`, never by branch or tag:

```toml
velmora = { git = "https://github.com/TogetherWeOwn/velmora", rev = "<full 40-char commit SHA on main>", default-features = false, features = ["native-tls"] }
```

- **Immutable.** Pin a full commit SHA that is on `main`. Branches move and
  tags can be re-pointed; a `rev` cannot.
- **Deliberate bumps.** Moving to a newer engine is a one-line PR in the
  consumer that changes the `rev` and refreshes its `Cargo.lock`. Each
  consumer's own CI then gates the bump.
- **Reviewed source.** Consumers that run cargo-deny list exactly this
  repository in `[sources] allow-git`, nothing broader.

## Features (`velmora`)

- `default = ["native-tls"]`: tokio + rustls transport (non-wasm).
- `worker-transport`: Workers `connect()` socket transport (wasm32).

## Checks

CI (`.github/workflows/ci.yml`, aggregated as `ci-ok`) runs `cargo fmt`,
`cargo clippy -D warnings`, the native test suite with and without default
features, `cargo check --target wasm32-unknown-unknown` (scalar,
`worker-transport` and simd128), and `cargo-deny` against `deny.toml`.
`gitleaks` scans the full history.

## License

MIT, see [LICENSE](LICENSE).
