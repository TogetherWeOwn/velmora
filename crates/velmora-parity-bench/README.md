# velmora-parity-bench

Self-check and CPU benchmark of the repair-parity codec (`velmora::rs`:
Reed-Solomon over article-sized shards, on the engine's GF(2^16) kernel).

The crate builds as a plain `wasm32-unknown-unknown` module with the
release profile of the Worker and runs under node, which is the same
engine (V8). It does no I/O.

## Run it

```sh
# Scalar kernel.
cargo build --locked --release -p velmora-parity-bench --target wasm32-unknown-unknown
node crates/velmora-parity-bench/run.mjs \
  target/wasm32-unknown-unknown/release/velmora_parity_bench.wasm --expect-simd off

# simd128 kernel.
RUSTFLAGS="-C target-feature=+simd128" \
  cargo build --locked --release -p velmora-parity-bench --target wasm32-unknown-unknown
node crates/velmora-parity-bench/run.mjs \
  target/wasm32-unknown-unknown/release/velmora_parity_bench.wasm --expect-simd on
```

## The self-check

`run.mjs` first calls the module's `selfcheck` and exits 1 if it fails.
The self-check

1. compares the kernel's dispatching `madd` (simd128 in a simd128 build)
   with the scalar loop and with the field multiplication, on word counts
   around the 8-word vector chunk and on a shard-sized buffer;
2. encodes and rebuilds fixed stripes (every loss pattern up to the parity
   count at 1+1, 12+2, 24+3 and 24+4 shards with small shards shaped like the
   real cuts, then the real 8 MiB and 16 MiB article sizes), requires
   every rebuilt shard to equal the original, and hashes every parity and
   rebuilt byte;
3. compares the hash with `FINGERPRINT`, which the native test pins.

CI runs it on the scalar and on the simd128 wasm build, so both kernels
are checked against the native bytes on every change. The native bytes
themselves are pinned to an independent model by
`crates/velmora/tests/rs_parity.rs`.

## Results

node 24 (V8), x86_64 host, elapsed ms per MiB of extent plaintext (ms
per call in brackets), best of two runs of the median of 21. The module
is single threaded and does no I/O, so elapsed time is an upper bound on
its CPU time. The host was busy; single figures moved by up to 25%
between runs.

| extent | step | scalar | simd128 |
|---|---|---:|---:|
| 8 MiB (12+2) | encode 2 parity shards | 1.74 (13.9) | 0.33 (2.6) |
| 8 MiB (12+2) | rebuild 1 lost article | 0.86 (6.8) | 0.17 (1.3) |
| 8 MiB (12+2) | rebuild 2 lost articles | 1.72 (13.8) | 0.33 (2.6) |
| 16 MiB (24+3) | encode 3 parity shards | 2.67 (42.7) | 0.47 (7.5) |
| 16 MiB (24+3) | rebuild 1 lost article | 0.93 (14.9) | 0.17 (2.8) |
| 16 MiB (24+3) | rebuild 2 lost articles | 1.77 (28.3) | 0.33 (5.3) |
| 16 MiB (24+3) | rebuild 3 lost articles | 2.64 (42.3) | 0.48 (7.5) |
| 16 MiB (24+4) | encode 4 parity shards | 3.44 (55.0) | 0.61 (9.7) |
| 16 MiB (24+4) | rebuild 1 lost article | 0.85 (13.6) | 0.16 (2.6) |
| 16 MiB (24+4) | rebuild 2 lost articles | 1.68 (27.0) | 0.31 (5.0) |
| 16 MiB (24+4) | rebuild 3 lost articles | 2.54 (40.6) | 0.45 (7.2) |
| 16 MiB (24+4) | rebuild 4 lost articles | 3.36 (53.8) | 0.60 (9.7) |

These are compute inside the module on a desktop CPU. A Worker's CPU for
the same work has not been measured.
