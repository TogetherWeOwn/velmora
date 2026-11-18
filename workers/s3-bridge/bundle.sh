#!/usr/bin/env bash
# Builds the Worker bundle into build/. This is the only build of it: the
# wrangler.toml [build] command (wrangler dev, the local e2e), CI's size
# budget and the deploy artifact all run this script, so the budget
# measures the wasm that ships.
#
# After worker-build, the `name` custom section (function names, about
# 600 KB) is dropped from build/index_bg.wasm (tools/strip_wasm.py). The
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
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+simd128" worker-build --release
python3 -I tools/strip_wasm.py strip build/index_bg.wasm --unstripped symbols/index_bg.unstripped.wasm
