#!/usr/bin/env bash
# Snapshots the D1 catalogue into an R2 bucket that is separate from the
# data buckets: ops/catalog-export.sh [wrangler args, e.g. --env dev]
#
# The object is stored as `d1/<database>/<restore point ms>.sql`. The
# restore point is taken before the export starts, so every commit the
# snapshot misses has a recovery record that is newer than it; a restore
# passes that number to ops/catalog-replay.sh.
#
# D1 does not answer queries while an export runs: requests fail and
# clients retry. Run it from cron at a quiet hour.
#
# The snapshot holds wrapped keys only (bucket keys and access key
# secrets are sealed under the KEK). Still treat the bucket as private.
#
# Environment:
#   VELMORA_D1             database name (default velmora-catalog)
#   VELMORA_EXPORT_BUCKET  R2 bucket (default velmora-catalog-export)
#   CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID  for wrangler
#
# wrangler uploads at most 315 MB in one `r2 object put`; a larger
# snapshot must be uploaded with an S3 client instead.

set -euo pipefail
set +x
umask 077

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$HERE/.."
DB=${VELMORA_D1:-velmora-catalog}
BUCKET=${VELMORA_EXPORT_BUCKET:-velmora-catalog-export}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

since_ms=$(($(date +%s) * 1000))
file="$WORK/catalog.sql"
npx wrangler d1 export "$DB" --remote --output "$file" "$@" >"$WORK/export.log" 2>&1 || {
  echo "catalog-export: wrangler d1 export failed:" >&2
  tail -n 20 "$WORK/export.log" >&2
  exit 1
}
[ -s "$file" ] || { echo "catalog-export: the export is empty" >&2; exit 1; }
grep -q 'CREATE TABLE' "$file" || { echo "catalog-export: the export has no schema" >&2; exit 1; }

key="d1/$DB/$since_ms.sql"
npx wrangler r2 object put "$BUCKET/$key" --file "$file" --remote \
  --content-type application/sql "$@" >"$WORK/put.log" 2>&1 || {
  echo "catalog-export: wrangler r2 object put failed:" >&2
  tail -n 20 "$WORK/put.log" >&2
  exit 1
}
printf 'catalog-export: %s bytes, sha256 %s, stored as %s/%s\n' \
  "$(wc -c <"$file" | tr -d ' ')" "$(sha256sum "$file" | cut -d' ' -f1)" "$BUCKET" "$key"
printf 'restore point: %s\n' "$since_ms"
