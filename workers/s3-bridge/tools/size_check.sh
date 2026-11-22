#!/usr/bin/env bash
# The blocking size check: Cloudflare's 64 MiB uncompressed Worker size
# limit, measured on what `wrangler deploy` would upload for the bundle
# already in build/ (bundle.sh). Writes the measurement to $1 (JSON) for
# the non-blocking report. See tools/bundle_size.py. Needs wrangler from
# `npm ci`; a dry run reads no credential and calls no API.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
out_json=$1
work=$(mktemp -d)
trap 'rm -r -- "$work"; [ ! -e wrangler.size.toml ] || rm -- wrangler.size.toml' EXIT
# The config sits next to wrangler.toml: its paths are relative to it.
python3 -I tools/bundle_size.py config wrangler.toml wrangler.size.toml
WRANGLER_SEND_METRICS=false ./node_modules/.bin/wrangler deploy --dry-run --env="" \
  --outdir "$work/out" -c wrangler.size.toml >"$work/log" 2>&1 || {
  cat "$work/log"
  echo "::error::wrangler deploy --dry-run failed"
  exit 1
}
python3 -I tools/bundle_size.py measure "$work/out" "$work/log" "$out_json"
