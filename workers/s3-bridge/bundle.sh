#!/usr/bin/env bash
# Builds the Worker bundle into build/. This is the only build of it: the
# wrangler.toml [build] command (wrangler dev, the local e2e), CI's size
# budget and the deploy artifact all run this script, so the budget
# measures the wasm that ships.
#
# After worker-build, the `name` and `producers` custom sections are
# dropped from build/index_bg.wasm (tools/strip_wasm.py). The Worker
# never reads them; without `name`, stack traces show
# `wasm-function[N]` instead of Rust function names. The unstripped wasm
# is kept in symbols/ (outside build/, so it is never uploaded) to
# resolve such frames.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
worker-build --release
python3 -I tools/strip_wasm.py strip build/index_bg.wasm --unstripped symbols/index_bg.unstripped.wasm
