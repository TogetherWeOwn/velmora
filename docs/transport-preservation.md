# Preserved SSRF guard and peer-pinned TLS

## Source and contribution provenance

This is a relocation of the existing MIT-licensed implementation from
[TogetherWeOwn/nntunev2](https://github.com/TogetherWeOwn/nntunev2/tree/5bcff30cb54a4f39e5fceeccc9ecc2d9dee54a83),
immutable source commit `5bcff30cb54a4f39e5fceeccc9ecc2d9dee54a83` (PR #953).
It is not a replacement predicate or a new transport qualification harness.

Source contribution history is retained by reference:

- Rick7C2's SSRF extraction, commit
  [`6b52276ae6d84e5c095a50f75f37d612c9511fc2`](https://github.com/TogetherWeOwn/nntunev2/commit/6b52276ae6d84e5c095a50f75f37d612c9511fc2).
- Rick7C2's peer-pinned TLS implementation and synthetic fixtures, commit
  [`82dfeea1820a703064fe78863b0558c5f18efbd9`](https://github.com/TogetherWeOwn/nntunev2/commit/82dfeea1820a703064fe78863b0558c5f18efbd9),
  with Claude Code contribution credit in that source commit.
- Subsequent source fixture-address and Wasm toolchain reconciliation, commit
  [`c192ea07a6ee4b6b1b9f28ecc421b893c14ba5ed`](https://github.com/TogetherWeOwn/nntunev2/commit/c192ea07a6ee4b6b1b9f28ecc421b893c14ba5ed).

## Content comparison

Compared on 2026-11-07 against the immutable source above. Source prefix
`crates/nntune-core/` maps to `crates/velmora/`;
`crates/nntune-ssrf-guard/` maps to `crates/velmora-ssrf-guard/`.
All hashes below are SHA-256 of file bytes, not Git object hashes.

| Destination (relative to `crates/`) | SHA-256 | Comparison |
| --- | --- | --- |
| `velmora-ssrf-guard/src/lib.rs` | `a027eb3f1ddafe6aec55e01dbf6736688e68f869bc5e0344f78f2e40bde40997` | Byte-identical predicate, vectors and tests |
| `velmora/src/transports/mod.rs` | `17896cd32b9bc23b88889004f67fc97e38976bb584486387f4ca23a91c58a30d` | Byte-identical |
| `velmora/src/transports/peer_tls.rs` | `93846315476f0132cbf90db3b109fbdcc6be833809925050c55b8f3b411f5ebb` | Only `nntune_ssrf_guard` → `velmora_ssrf_guard` |
| `velmora/src/transports/tokio_tls.rs` | `a85904f74b7741df9f0f5aa254483301895466301460da9269c26c3ba95080b0` | Byte-identical |
| `velmora/src/transports/worker_pinned_tls.rs` | `397aac7929c5a862ac0b0a794bf95f5486a2a7d8eb8a8583fe62b353e54bcacc` | Byte-identical |
| `velmora/src/transports/worker_socket.rs` | `0720b9455ce9e5abc3ebc84957fe451596e3b98a897293821005767d3c8d8608` | Byte-identical |
| `velmora/tests/fixtures/peer_tls/README.md` | `cbd539dbcba7183d27b1966bab630c4f7fec90fe0693596a41f5a84aebd9e926` | Byte-identical |
| `velmora/tests/fixtures/peer_tls/ca.der` | `bbfb04f3867caca38b21d157fe6fe8a084068909e94b2b21b38f540dd6451eeb` | Byte-identical |
| `velmora/tests/fixtures/peer_tls/server-key.der` | `080982fbd94977236b37188850c5d04d95bd443fc816d544942e8d80cf0e0673` | Byte-identical public test key |
| `velmora/tests/fixtures/peer_tls/server.der` | `f4489c01b2d72fa50cc96fed7d45cf0a062c489e13eab4d79ed626af50efccb5` | Byte-identical |
| `velmora-ssrf-guard/Cargo.toml` | `eee57918a82fb4a62df6f0be5956114eaa068858523f3ffb855f6d83d5501361` | Package/library name and repository URL only |

The source `peer_tls.rs` hash is
`c53e18716d67424be5c5f6315ded6a8a2aa6c5f18cffb456f53676ee3875a0c0`;
reversing the single import rename reproduces those exact bytes. The source
SSRF manifest hash is
`8cf0944c65f87a04229fd8c34a90d0a8debe4042957a7f596a37cd5163209a86`.
The manifest's historical description and predicate's historical call-site
comments are deliberately unchanged, not new product dependencies.

## Boundaries

`PeerTlsTarget` validates the selected literal public peer and allowed port
independently of the DNS certificate identity. It does **not** authenticate a
resolver answer set, account binding, admission token or permission to send
credentials. Callers retain those obligations and the existing NNTP
credential-write authorization guard.

Production connectors retain Mozilla roots, chain/name/time validation, the
explicit ring provider, per-operation deadlines and buffered-write flushing.
Only unit tests inject a private CA, fixed clock or loopback/ephemeral peer.
The four fixed fixtures retain their original README and limitations.

`worker-pinned-tls` remains **qualification-only and opt-in**. No runtime call
site, provider/account operation, background task, binding, migration or
activation is added. The caller retains the independent `WorkerSocketControl`
outside operation futures. Dropping, timeout, errors or initiating close do not
prove physical closure; capacity stays fenced until explicit close confirmation.
Native synthetic tests and Wasm compilation do not qualify Worker runtime
entropy, clocks, dialing or physical closure.

## Dependency and build review

Cargo 1.99.1 was used only for offline workspace lock reconciliation and
non-compiling manifest metadata. No local build or test suite was run. Cargo
has no stable native release-age filter or blanket build-script/proc-macro
refusal. `--locked` is reproducibility, not either of those protections.
No blanket exception or global tool configuration is introduced.

The preserved manifest disables rustls/tokio-rustls default providers and selects
ring explicitly. Existing locked ring 0.17.14, rustls 0.23.46,
tokio-rustls 0.26.6 and rustls-pki-types 1.15.1 versions are retained.
AWS-LC and its now-unreachable build dependencies disappear. HMAC and product
pool modules are not added; rustls's existing transitive `subtle` remains.

The only added registry package is the preserved source lock's web-time 1.1.0,
checksum `5a6580f308b1fad9207618087a65c04e7a10bc77e02c8e84e9b00dd4b12fa0bb`.
Its exact registry archive has no build.rs or proc-macro; it uses the already
locked js-sys/wasm-bindgen graph for the `rustls-pki-types/web` clock backend.
The exact rustls-pki-types archive (checksum
`2f4925028c7eb5d1fcdaf196971378ed9d2c1c4efc7dc5d011256f76c99c0a96`)
declares `build = false` and no proc-macro.

The exact ring 0.17.14 archive (checksum
`a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7`)
retains its required build.rs: it compiles bundled C/assembly through the locked
cc crate into Cargo output directories, uses packaged pregenerated assembly,
and does not download executables. Its Wasm entropy feature selects getrandom/js;
no custom RNG is introduced. This pre-existing native hook is necessary for the
preserved ring provider; the new scope is compilation for wasm32 with the same
source's clang-18/llvm-ar-18 tool selection. No root workspace build hooks or new
proc-macro packages are introduced. Hook authority is limited to the locked
build graph in GitHub Actions; removal condition is removal of this backend,
not permission to enable arbitrary hooks.

GitHub Actions performs locked dependency fetch/build and all suite/gate runs.
The Worker-pinned-TLS compile job uses a fresh runner with no restored Cargo
build cache and no deployment credentials. It compiles default-only, opt-in-only
and all-features Wasm combinations, runs clippy, and checks the SSRF crate on Wasm.
The default `native-tls` feature also activates the existing wasm-only ring
dependency so its `wasm32_unknown_unknown_js` cfg is enabled independently of
Worker features. ring 0.17.14's `SystemRandom` implementation requires that cfg;
the existing getrandom/js dependency alone does not enable it.
Native CI runs both preserved SSRF tests, all nine peer/TLS tests and the two
existing native pre-dial refusal tests through the workspace suite, preserves
no-default-feature tests (including the 13 auth-guard tests), and reruns library
tests with the qualification feature enabled. MSRV and dependency/security gates
remain required. Exact-head run/job results and any unrun cases belong in the PR
verification receipt; the commands configured here are not a claim they passed.

The default native-TLS and no-default-feature core, plus the SSRF crate, keep
Rust 1.89 compatibility. The already-locked Worker SDK 0.8.7 (including its
macros/sys crates) requires Rust 1.91. Worker feature checks therefore use 1.91
on native and in the fresh Wasm qualification job, without changing dependency
versions or raising the core's declared MSRV. The initial Actions run exposed
this feature-specific toolchain requirement; it is not a transport test failure
or evidence of Worker runtime qualification.
