# velmora-cpu-bench

CPU cost of the bridge's hot paths, per MiB of object data and per stage:
ingest (seal and hash), post (check, yEnc, send), verify (read, decode,
hash) and cold read (read, decode, hash, decrypt).

The stages call the code the Worker runs. The crate builds as a plain
`wasm32-unknown-unknown` module with the release profile of the Worker
and is timed under node, which runs the same engine (V8). The network is
an in-memory transport that hands bytes over the way the Workers socket
does. Nothing here talks to a server.

## Run it

```sh
# As the Worker bundle is built (workers/s3-bridge/bundle.sh): simd128.
RUSTFLAGS="-C target-feature=+simd128" \
  cargo build --locked --release -p velmora-cpu-bench --target wasm32-unknown-unknown
node crates/velmora-cpu-bench/run.mjs \
  target/wasm32-unknown-unknown/release/velmora_cpu_bench.wasm

# Rank functions by self time.
node --cpu-prof --cpu-prof-dir=prof crates/velmora-cpu-bench/run.mjs \
  target/wasm32-unknown-unknown/release/velmora_cpu_bench.wasm
node crates/velmora-cpu-bench/top.mjs prof/*.cpuprofile
```

`run.mjs` first runs the module's self-check and refuses to time a build
that fails it. The self-check hashes every byte the hot paths produce for
a fixed extent (ciphertext, digests, rendered articles, bytes read back,
opened plaintext), compares the fast yEnc encoder with the byte-at-a-time
reference on a few hundred lengths, and compares the result with the
value the native test pins (`FINGERPRINT`). CI runs it on the simd128
build, so the bytes of that build are checked against the native ones on
every change.

## What it measures, and what it does not

It measures compute inside the wasm module. A Worker also spends CPU in
the runtime glue around it: handing socket chunks from JavaScript to
wasm, D1 and R2 calls, promise and stream plumbing. In a CPU profile of
the local end-to-end slice under workerd, wasm self time was about a
third of the Worker's busy time before this work. So a stage that gets
50% faster here gets less than that faster in production; the profile of
the running Worker is the measure of the whole.

## Results

node 24 (V8), x86_64 host, 16 MiB extent (24 articles), ms of CPU per MiB,
best of two runs of the median of 11. "Before" is the tree before the
hot-path work, scalar build, which is what was deployed. "After" is this
tree built with simd128, which is what `bundle.sh` now builds.

| stage | before | after, scalar | after, simd128 | saved |
|---|---:|---:|---:|---:|
| ingest (`seal_extent`: seal, MD5, 2x SHA-256) | 6.41 | 6.44 | 6.25 | 3% |
| post, whole stage | 8.51 | 6.38 | 4.29 | 50% |
| post: SHA-256 of the loaded ciphertext | 1.81 | 1.76 | 1.60 | 11% |
| post: SHA-256 of each article payload | 1.73 | 1.75 | 1.55 | 10% |
| post: yEnc, CRC-32, assemble | 2.67 | 2.03 | 0.75 | 72% |
| post: framing check, dot-stuffing, write | 2.31 | 1.01 | 0.28 | 88% |
| verify, whole stage (4 KiB socket chunks) | 3.86 | 3.11 | 2.46 | 36% |
| verify: `BODY` read, framing, unstuffing | 1.01 | 0.36 | 0.29 | 71% |
| verify: yEnc decode, CRC-32, SHA-256 | 2.95 | 2.62 | 2.21 | 25% |
| cold read, whole (64 KiB socket chunks) | 7.94 | 6.53 | 5.38 | 32% |
| decrypt (`open_range`) | 1.79 | 1.77 | 1.46 | 18% |

The host was busy during these runs; single stages move by about 0.2 ms
from run to run.

What is left after this work is mostly hashing and the cipher: SHA-256
is about three quarters of the post stage (the loaded ciphertext, then
each payload) and most of the verify check; ingest is MD5, two SHA-256
passes and XChaCha20-Poly1305, none of which simd128 speeds up much in
the crates in use.
