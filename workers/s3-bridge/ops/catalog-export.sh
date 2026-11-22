#!/usr/bin/env bash
# Snapshots the D1 catalogue into an R2 bucket that is separate from the
# data buckets: ops/catalog-export.sh [wrangler args, e.g. --env dev]
#
# Compressed SQL parts and their manifest are stored under d1/<database>/.
# The restore point is taken before the export starts, so every commit the
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
#   VELMORA_EXPORT_PART_BYTES     maximum part size (default 268435456)
#   VELMORA_EXPORT_RCLONE_REMOTE  optional configured rclone remote
#   CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID  for wrangler
#
# The manifest is uploaded last. Without it the parts are incomplete.

set -euo pipefail
set +x
umask 077

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
source "$HERE/catalog-common.sh"
cd "$HERE/.."
DB=${VELMORA_D1:-velmora-catalog}
BUCKET=${VELMORA_EXPORT_BUCKET:-velmora-catalog-export}
remote=${VELMORA_EXPORT_RCLONE_REMOTE-}
part_bytes=${VELMORA_EXPORT_PART_BYTES-268435456}

for tool in zstd jq split sha256sum python3; do
  command -v "$tool" >/dev/null || { echo "catalog-export: missing tool: $tool" >&2; exit 1; }
done
catalog_require_sqlite
catalog_init_sql_limits
if [[ ${VELMORA_EXPORT_RCLONE_REMOTE+x} && ! $remote =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "catalog-export: invalid VELMORA_EXPORT_RCLONE_REMOTE" >&2
  exit 1
fi
if [[ $part_bytes =~ ^0*([1-9][0-9]{0,8})$ ]] && (( BASH_REMATCH[1] <= 300000000 )); then
  part_bytes=${BASH_REMATCH[1]}
else
  echo "catalog-export: VELMORA_EXPORT_PART_BYTES must be an integer from 1 to 300000000" >&2
  exit 1
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/velmora-export.XXXXXX")
trap 'rm -r -- "$WORK"' EXIT

if ! since_ms=$(date +%s%3N) || [[ ! $since_ms =~ ^[0-9]+$ ]]; then
  since_ms=$(($(date +%s) * 1000))
fi
prefix="d1/$DB/$since_ms"
manifest="$prefix.manifest.json"

get() {
  local key=$1 out=$2
  shift 2
  if [[ -n $remote ]]; then
    # --ignore-times: parts of one size can share a modification time,
    # and rclone would skip a download onto the previous part's file.
    if [[ -e $out ]]; then rm -- "$out" || return 1; fi
    rclone copyto "$remote:$BUCKET/$key" "$out" --ignore-times </dev/null
  else
    npx wrangler r2 object get "$BUCKET/$key" --file "$out" --remote "$@" </dev/null
  fi >"$WORK/get.log" 2>&1
}

manifest_check_failed() {
  local log
  # Keep just the private lookup log after the work directory is removed.
  log=$(mktemp "${TMPDIR:-/tmp}/velmora-catalog-get.XXXXXX")
  mv -- "$WORK/get.log" "$log"
  echo "catalog-export: could not check $BUCKET/$manifest, see $log" >&2
  exit 1
}

if [[ -n $remote ]]; then
  listing=$(rclone lsf "$remote:$BUCKET/$manifest" </dev/null 2>"$WORK/get.log") ||
    manifest_check_failed
elif get "$manifest" "$WORK/existing.json" "$@"; then
  listing=$manifest
# Any 404 means there is no readable manifest at this key with these
# credentials. If the bucket itself is missing, the first put fails and
# the manifest is never written.
elif catalog_wrangler_get_is_404 "$WORK/get.log"; then
  listing=
else
  manifest_check_failed
fi
if [[ -n $listing ]]; then
  echo "catalog-export: an export at restore point $since_ms exists already" >&2
  exit 1
fi

file="$WORK/catalog.sql"
npx wrangler d1 export "$DB" --remote --output "$file" "$@" </dev/null >"$WORK/export.log" 2>&1 || {
  echo "catalog-export: wrangler d1 export failed:" >&2
  tail -n 20 "$WORK/export.log" >&2
  exit 1
}
[ -s "$file" ] || { echo "catalog-export: the export is empty" >&2; exit 1; }
sql_bytes=$(( $(wc -c <"$file") ))
catalog_check_sql_size "$sql_bytes"
grep -q 'CREATE TABLE' "$file" || { echo "catalog-export: the export has no schema" >&2; exit 1; }
catalog_check_sql_statements "$file"

put() {
  local key=$1 path=$2 type=$3
  shift 3
  if [[ -n $remote ]]; then
    rclone copyto "$path" "$remote:$BUCKET/$key" --s3-upload-cutoff 64M \
      --header-upload "Content-Type: $type" </dev/null
  else
    npx wrangler r2 object put "$BUCKET/$key" --file "$path" --remote \
      --content-type "$type" "$@" </dev/null
  fi >"$WORK/put.log" 2>&1 || {
    echo "catalog-export: put of $key failed:" >&2
    tail -n 20 "$WORK/put.log" >&2
    exit 1
  }
}

zstd -q -T0 -10 "$file" -o "$file.zst"
zstd -q -t "$file.zst"
# Part names have three digits: at most 1000 parts.
if (( ($(wc -c <"$file.zst") + part_bytes - 1) / part_bytes > 1000 )); then
  echo "catalog-export: VELMORA_EXPORT_PART_BYTES $part_bytes makes more than 1000 parts for this export" >&2
  exit 1
fi
split -b "$part_bytes" -d -a 3 "$file.zst" "$file.zst.part-"

sql_sha256=$(sha256sum <"$file")
sql_sha256=${sql_sha256%% *}
zst_bytes=$(( $(wc -c <"$file.zst") ))
zst_sha256=$(sha256sum <"$file.zst")
zst_sha256=${zst_sha256%% *}
parts=("$file.zst.part-"*)
for part in "${parts[@]}"; do
  key="$prefix.sql.zst.part-${part##*-}"
  bytes=$(( $(wc -c <"$part") ))
  sha256=$(sha256sum <"$part")
  jq -n --arg key "$key" --argjson bytes "$bytes" --arg sha256 "${sha256%% *}" \
    '{$key, $bytes, $sha256}' >>"$WORK/parts.json"
  put "$key" "$part" application/zstd "$@"
done

jq -n --argjson restore_point_ms "$since_ms" --arg database "$DB" \
  --argjson sql_bytes "$sql_bytes" --arg sql_sha256 "$sql_sha256" \
  --argjson zst_bytes "$zst_bytes" --arg zst_sha256 "$zst_sha256" \
  --slurpfile parts "$WORK/parts.json" \
  '{format: 1, $restore_point_ms, $database, $sql_bytes, $sql_sha256,
    $zst_bytes, $zst_sha256, $parts}' >"$WORK/manifest.json"
put "$manifest" "$WORK/manifest.json" application/json "$@"
if ! get "$manifest" "$WORK/readback.json" "$@" ||
   ! cmp -s "$WORK/manifest.json" "$WORK/readback.json"; then
  echo "catalog-export: the manifest read back from $BUCKET/$manifest differs" >&2
  exit 1
fi

printf 'catalog-export: sql %s bytes, sha256 %s, zst %s bytes in %s part(s), manifest %s/%s\n' \
  "$sql_bytes" "$sql_sha256" "$zst_bytes" "${#parts[@]}" "$BUCKET" "$manifest"
printf 'restore point: %s\n' "$since_ms"
