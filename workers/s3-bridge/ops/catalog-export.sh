#!/usr/bin/env bash
# Snapshots the D1 catalogue into an R2 bucket that is separate from the
# data buckets: ops/catalog-export.sh [wrangler configuration args, e.g. --env dev]
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
#   VELMORA_EXPORT_SIZES_LOG      optional file for JSON lines of export sizes
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
# 1000 parts at the default hold over 268 GB of compressed SQL.
part_bytes=${VELMORA_EXPORT_PART_BYTES-268435456}
part_limit=$(catalog_part_max_bytes)
readonly D1_PAID_MAX_DB_BYTES=10000000000

# Keep export mode, format, and scope under this script's control. Wrangler
# accepts alternate boolean spellings (e.g. --data=0), so fail closed.
wrangler_args=()
while (( $# )); do
  arg=$1
  shift
  case "$arg" in
    --env-file|--env-file=?*)
      if [[ $arg == *=* ]]; then
        wrangler_args+=("$arg")
      else
        [[ -n ${1-} && $1 != -* ]] || catalog_error '--env-file requires a value'
      fi
      # Pass array elements explicitly and leave the next flag for validation.
      while [[ -n ${1-} && $1 != -* ]]; do
        wrangler_args+=("--env-file=$1")
        shift
      done ;;
    -c/*) wrangler_args+=("--config=${arg:2}") ;;
    --config|-c|--cwd|--env|-e|--profile)
      [[ -n ${1-} && $1 != -* ]] || catalog_error "$arg requires a value"
      wrangler_args+=("$arg" "$1")
      shift ;;
    --config=?*|-c=?*|--cwd=?*|--env=?*|-e=?*|--profile=?*) wrangler_args+=("$arg") ;;
    *) catalog_error 'catalogue backups must include schema and data for every table from remote D1; only Wrangler configuration options are allowed' ;;
  esac
done
set -- "${wrangler_args[@]}"

for tool in zstd jq split sha256sum python3 od flock; do
  command -v "$tool" >/dev/null || { echo "catalog-export: missing tool: $tool" >&2; exit 1; }
done
catalog_require_sqlite
catalog_init_sql_limits
if [[ ${VELMORA_EXPORT_RCLONE_REMOTE+x} && ! $remote =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "catalog-export: invalid VELMORA_EXPORT_RCLONE_REMOTE" >&2
  exit 1
fi
if [[ $part_bytes =~ ^0*([1-9][0-9]{0,8})$ ]] && (( BASH_REMATCH[1] <= part_limit )); then
  part_bytes=${BASH_REMATCH[1]}
else
  echo "catalog-export: VELMORA_EXPORT_PART_BYTES must be an integer from 1 to $part_limit" >&2
  exit 1
fi
catalog_init_wrangler
lock_key=$(printf '%s' "$DB" | sha256sum)
catalog_lock export "$DB" "${lock_key%% *}"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/velmora-export.XXXXXX")
trap 'catalog_cleanup "$?"' EXIT
LOG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/velmora-catalog-export-logs.XXXXXX")

if ! since_ms=$(date +%s%3N) || [[ ! $since_ms =~ ^[0-9]+$ ]]; then
  since_ms=$(($(date +%s) * 1000))
fi
prefix="d1/$DB/$since_ms"
manifest="$prefix.manifest.json"
attempt=$(od -An -N8 -tx1 /dev/urandom | tr -d '[:space:]')
if [[ ! $attempt =~ ^[0-9a-f]{16}$ ]]; then
  catalog_error 'could not generate an export attempt ID'
fi

get() {
  local key=$1 out=$2 log=$3
  shift 3
  if [[ -n $remote ]]; then
    # --ignore-times: parts of one size can share a modification time,
    # and rclone would skip a download onto the previous part's file.
    if [[ -e $out ]]; then rm -- "$out" || return 1; fi
    rclone copyto "$remote:$BUCKET/$key" "$out" --ignore-times </dev/null
  else
    "$wrangler" r2 object get "$BUCKET/$key" --file "$out" --remote "$@" </dev/null
  fi 2>&1 | catalog_redact_log >"$log"
}

check_log="$LOG_DIR/manifest.check.log"
if [[ -n $remote ]]; then
  catalog_capture "$WORK/listing" "$check_log" rclone lsf "$remote:$BUCKET/$manifest" ||
    catalog_error "could not check $BUCKET/$manifest, see $check_log"
  listing=$(<"$WORK/listing")
elif get "$manifest" "$WORK/existing.json" "$check_log" "$@"; then
  listing=$manifest
# Any 404 means there is no readable manifest at this key with these
# credentials. If the bucket itself is missing, the first put fails and
# the manifest is never written.
elif catalog_wrangler_get_is_404 "$check_log"; then
  listing=
else
  catalog_error "could not check $BUCKET/$manifest, see $check_log"
fi
if [[ -n $listing ]]; then
  echo "catalog-export: an export at restore point $since_ms exists already" >&2
  exit 1
fi

file="$WORK/catalog.sql"
export_log="$LOG_DIR/d1-export.log"
catalog_logged "$export_log" "$wrangler" d1 export "$DB" --remote --output "$file" "$@" ||
  catalog_error "wrangler d1 export failed, see $export_log"
[[ -s $file ]] || catalog_error "the export is empty, see $export_log"
sql_bytes=$(( $(wc -c <"$file") ))
catalog_longest_statement_bytes=$(catalog_check_sql_statements "$file" --require-schema)
info_log="$LOG_DIR/d1-info.log"
size_unavailable=
if ! catalog_capture "$WORK/info.json" "$info_log" "$wrangler" d1 info "$DB" --json "$@"; then
  size_unavailable='wrangler d1 info failed'
elif ! database_size=$(jq -ers 'select(length == 1) | .[0] | (.database_size // .file_size) |
    select(type == "number" and . >= 0 and . < 1000000000000 and floor == .)' "$WORK/info.json" 2>>"$info_log"); then
  size_unavailable='missing or invalid size in d1 info'
fi
catalog_warn_at_sixty_percent sql_statement_bytes "$catalog_longest_statement_bytes" "$D1_SQL_STATEMENT_MAX_BYTES"
if [[ -n $size_unavailable ]]; then
  printf 'catalog-export: WARNING database size unavailable (%s)\n' "$size_unavailable" >&2
  database_size=null
  database_size_summary='size unavailable'
else
  catalog_warn_at_sixty_percent database_size_bytes "$database_size" "$D1_PAID_MAX_DB_BYTES"
  database_size_summary="$database_size bytes"
fi

put() {
  local key=$1 path=$2 type=$3 log="$LOG_DIR/${2##*/}.put.log"
  shift 3
  if [[ -n $remote ]]; then
    rclone copyto "$path" "$remote:$BUCKET/$key" --s3-upload-cutoff 64M \
      --header-upload "Content-Type: $type" </dev/null
  else
    "$wrangler" r2 object put "$BUCKET/$key" --file "$path" --remote \
      --content-type "$type" "$@" </dev/null
  fi 2>&1 | catalog_redact_log >"$log" || catalog_error "put of $key failed, see $log"
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
  key="$prefix.$attempt.part-${part##*-}"
  bytes=$(( $(wc -c <"$part") ))
  sha256=$(sha256sum <"$part")
  jq -n --arg key "$key" --argjson bytes "$bytes" --arg sha256 "${sha256%% *}" \
    '{$key, $bytes, $sha256}' >>"$WORK/parts.json"
  put "$key" "$part" application/zstd "$@"
done

jq -n --argjson restore_point_ms "$since_ms" --arg database "$DB" --arg attempt "$attempt" \
  --argjson sql_bytes "$sql_bytes" --arg sql_sha256 "$sql_sha256" \
  --argjson zst_bytes "$zst_bytes" --arg zst_sha256 "$zst_sha256" \
  --slurpfile parts "$WORK/parts.json" \
  '{format: 2, $restore_point_ms, $database, $attempt, $sql_bytes, $sql_sha256,
    $zst_bytes, $zst_sha256, $parts}' >"$WORK/manifest.json"
put "$manifest" "$WORK/manifest.json" application/json "$@"
readback_log="$LOG_DIR/manifest.readback.log"
get "$manifest" "$WORK/readback.json" "$readback_log" "$@" ||
  catalog_error "could not read $manifest, see $readback_log"
if ! cmp -s "$WORK/manifest.json" "$WORK/readback.json"; then
  if jq -es --arg attempt "$attempt" --arg database "$DB" --argjson ms "$since_ms" '
    length == 1 and (.[0] | .format == 2 and .database == $database and .restore_point_ms == $ms and
      (.attempt | type == "string" and length == 16 and test("^[0-9a-f]{16}$") and . != $attempt))
  ' "$WORK/readback.json" >/dev/null 2>&1; then
    catalog_error "another export published restore point $since_ms, see $readback_log"
  fi
  catalog_error "the manifest read back from $BUCKET/$manifest differs, see $readback_log"
fi

if [[ -n ${VELMORA_EXPORT_SIZES_LOG:-} ]]; then
  size_entry=$(jq -cn --argjson restore_point_ms "$since_ms" --argjson sql_bytes "$sql_bytes" \
    --argjson zst_bytes "$zst_bytes" --argjson parts "${#parts[@]}" \
    --argjson longest_statement_bytes "$catalog_longest_statement_bytes" --argjson database_size_bytes "$database_size" \
    '{$restore_point_ms, $sql_bytes, $zst_bytes, $parts, $longest_statement_bytes, $database_size_bytes}')
  printf '%s\n' "$size_entry" >>"$VELMORA_EXPORT_SIZES_LOG"
fi
printf 'catalog-export: sql %s bytes, sha256 %s, zst %s bytes in %s part(s), manifest %s/%s, longest statement %s bytes, database %s\n' \
  "$sql_bytes" "$sql_sha256" "$zst_bytes" "${#parts[@]}" "$BUCKET" "$manifest" "$catalog_longest_statement_bytes" "$database_size_summary"
printf 'restore point: %s\n' "$since_ms"
