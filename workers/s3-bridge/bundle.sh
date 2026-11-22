#!/usr/bin/env bash
# Builds the Worker bundle into build/. This is the only build of it: the
# wrangler.toml [build] command (wrangler dev, the local e2e), CI's size
# check (tools/size_check.sh) and the deploy artifact all run this script,
# so the check measures the bundle that ships.
#
# After worker-build, the `name` custom section (function names, about
# 800 KB) is dropped from build/index_bg.wasm (tools/strip_wasm.py). The
# Worker never reads it; without it, stack traces show
# `wasm-function[N]` instead of Rust function names. The unstripped wasm
# is kept in symbols/ (outside build/, so it is never uploaded) to
# resolve such frames (ops/README.md, "Naming a wasm frame").
#
# The wasm is built with fixed-width SIMD (`simd128`): the yEnc codec and
# SHA-256 take their 128-bit paths. Workers support Wasm SIMD
# (https://developers.cloudflare.com/workers/runtime-apis/webassembly/,
# "Supported proposals"). A runtime without it rejects the module at
# load, so the local e2e (workerd) fails loudly rather than run slowly.
# RUSTFLAGS in the environment replaces any `rustflags` of a cargo config
# file; the repo has none. Add flags here, not there.
#
# A panic message names the source file it came from. For a dependency
# that is the absolute path of its unpacked registry copy
# (`$CARGO_HOME/registry/src/index.crates.io-<hash>/ring-0.17.14/src/..`),
# about 66 bytes of build-host path per file, kept in the wasm data
# section. Each registry source directory is remapped to `crates.io`, so
# the message reads `crates.io/ring-0.17.14/src/..`: about 8 KB less
# wasm, and no build-host path in the bundle. The directories come from
# `cargo metadata`, which also unpacks a dependency missing from them.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
remap=$(cargo metadata --locked --format-version 1 | python3 -I tools/registry_src_dirs.py)
RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+simd128${remap}" worker-build --release
python3 -I tools/strip_wasm.py strip build/index_bg.wasm --unstripped symbols/index_bg.unstripped.wasm
