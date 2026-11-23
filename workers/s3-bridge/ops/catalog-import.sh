#!/usr/bin/env bash
# Loads a D1 catalogue export into an empty database:
# ops/catalog-import.sh <target database> <restore point ms> [wrangler args]
#
# Environment:
#   VELMORA_D1                    source database (default velmora-catalog)
#   VELMORA_EXPORT_BUCKET         R2 bucket (default velmora-catalog-export)
#   VELMORA_EXPORT_RCLONE_REMOTE  optional configured rclone remote
#   VELMORA_IMPORT_DATABASE_ID    required UUID of the resolved target database
#   VELMORA_IMPORT_PRODUCTION     set to yes to allow a production catalogue target
#   VELMORA_IMPORT_BATCH_BYTES    maximum SQL bytes per batch (default 1000000000)
#   VELMORA_IMPORT_SKIP_ROW_COUNTS set to yes to skip the post-load row-count scan
#   CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID  for wrangler

set -euo pipefail
set +x
umask 077

die() {
  echo "catalog-import: $*" >&2
  exit 1
}

(( $# >= 2 )) || die 'usage: ops/catalog-import.sh <target database> <restore point ms> [wrangler args]'
target=$1
since_ms=$2
shift 2
DB=${VELMORA_D1:-velmora-catalog}
[[ $since_ms =~ ^[0-9]+$ ]] || die 'restore point must contain only digits'

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
source "$HERE/catalog-common.sh"
cd "$HERE/.."
BUCKET=${VELMORA_EXPORT_BUCKET:-velmora-catalog-export}
remote=${VELMORA_EXPORT_RCLONE_REMOTE-}
if [[ ${VELMORA_EXPORT_RCLONE_REMOTE+x} && ! $remote =~ ^[A-Za-z0-9_-]+$ ]]; then
  die 'invalid VELMORA_EXPORT_RCLONE_REMOTE'
fi
for tool in zstd jq sha256sum python3 head flock; do
  command -v "$tool" >/dev/null || die "missing tool: $tool"
done
catalog_require_sqlite
catalog_init_sql_limits
catalog_init_wrangler
batch_bytes=${VELMORA_IMPORT_BATCH_BYTES-1000000000}
if [[ ! $batch_bytes =~ ^[1-9][0-9]{0,9}$ ]] || (( batch_bytes > D1_SQL_FILE_MAX_BYTES )); then
  die "VELMORA_IMPORT_BATCH_BYTES must be an integer from 1 to $D1_SQL_FILE_MAX_BYTES"
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/velmora-import.XXXXXX")
trap 'catalog_cleanup "$?"' EXIT
LOG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/velmora-catalog-import-logs.XXXXXX")

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
  fi >>"$log" 2>&1 || return 1
  [[ -s $out ]] || die "empty download for $key, see $log"
}

# Return 2 only when the exact listing is empty or Wrangler reports R2 HTTP 404.
get_restore_object() {
  local key=$1 out=$2 log=$3 listing
  shift 3
  if [[ -n $remote ]]; then
    listing=$(rclone lsf "$remote:$BUCKET/$key" </dev/null 2>"$log") || return 1
    [[ -n $listing ]] || return 2
  fi
  if get "$key" "$out" "$log" "$@"; then
    return 0
  fi
  if [[ -z $remote ]] && catalog_wrangler_get_is_404 "$log"; then
    return 2
  fi
  return 1
}

verify() {
  local path=$1 key=$2 expected_bytes=$3 expected_sha256=$4 bytes sha256
  bytes=$(( $(wc -c <"$path") ))
  [[ $bytes == "$expected_bytes" ]] || die "size mismatch for $key"
  sha256=$(sha256sum <"$path")
  [[ ${sha256%% *} == "$expected_sha256" ]] || die "sha256 mismatch for $key"
}

# Resolve the target first; contending processes stop here after metadata only.
info_log="$LOG_DIR/d1-info.log"
"$wrangler" d1 info "$target" --json "$@" </dev/null >"$WORK/info.json" 2>"$info_log" ||
  die "could not resolve $target, see $info_log"
resolved=$(jq -ers '
  select(length == 1) | .[0] | select(
    (.uuid | type == "string" and length == 36 and
      test("^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")) and
    (.name | type == "string" and length > 0 and (test("[[:cntrl:]]") | not))) |
  [.uuid, .name] | @tsv
' "$WORK/info.json" 2>>"$info_log") || die "could not read UUID and name for $target, see $info_log"
IFS=$'\t' read -r resolved_id resolved_name <<<"$resolved"
expected_id=${VELMORA_IMPORT_DATABASE_ID:-<unset>}
[[ $expected_id == "$resolved_id" ]] ||
  die "refusing to load into $resolved_name: resolved UUID $resolved_id, VELMORA_IMPORT_DATABASE_ID=$expected_id"
catalog_lock import "$resolved_id" "${resolved_id,,}"
if [[ ${VELMORA_IMPORT_PRODUCTION:-} != yes &&
      ( $resolved_name == velmora-catalog || $resolved_name == CATALOG || $resolved_name == "$DB" ) ]]; then
  die "refusing to load into $resolved_name without VELMORA_IMPORT_PRODUCTION=yes"
fi

prefix="d1/$DB/$since_ms"
manifest="$prefix.manifest.json"
sql="$WORK/catalog.sql"
manifest_log="$LOG_DIR/manifest.get.log"
if get_restore_object "$manifest" "$WORK/manifest.json" "$manifest_log" "$@"; then
  jq -ers --arg db "$DB" --arg ms "$since_ms" --arg prefix "$prefix" \
    --argjson part_limit "$(catalog_part_max_bytes)" '
    def bytes: type == "number" and . >= 0 and floor == .;
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    def part_prefix:
      if (.format // 1) == 1 then $prefix + ".sql.zst.part-"
      elif .format == 2 and (.attempt | type == "string" and length == 16 and test("^[0-9a-f]{16}$"))
      then $prefix + "." + .attempt + ".part-"
      else null end;
    length == 1 and (.[0] | part_prefix as $part_prefix |
      $part_prefix != null and .database == $db and
      (.restore_point_ms | type == "number" and tostring == $ms) and
      (.sql_bytes | bytes) and (.sql_sha256 | sha256) and
      (.zst_bytes | bytes) and (.zst_sha256 | sha256) and
      (.parts | type == "array" and length > 0 and length <= 1000 and all(.[];
        (.key | type == "string" and startswith($part_prefix) and
          (ltrimstr($part_prefix) | length == 3 and test("^[0-9]{3}$"))) and
        (.bytes | bytes and . > 0 and . <= $part_limit) and (.sha256 | sha256))) and
      ([.parts[].bytes] | add) == .zst_bytes)
  ' "$WORK/manifest.json" >/dev/null 2>&1 || die "invalid manifest $manifest, see $manifest_log"
  manifest_sql_bytes=$(jq -er '.sql_bytes + 0' "$WORK/manifest.json")
  catalog_check_sql_size "$manifest_sql_bytes"

  jq -r '.parts[] | [.key, .bytes, .sha256] | @tsv' "$WORK/manifest.json" >"$WORK/parts.tsv"
  part_index=0
  while IFS=$'\t' read -r key bytes sha256; do
    part_log="$LOG_DIR/part-$part_index.get.log"
    get "$key" "$WORK/part" "$part_log" "$@" || die "could not read $key, see $part_log"
    verify "$WORK/part" "$key" "$bytes" "$sha256"
    cat "$WORK/part"
    part_index=$((part_index + 1))
  done <"$WORK/parts.tsv" >"$sql.zst"

  IFS=$'\t' read -r zst_bytes zst_sha256 sql_sha256 < <(
    jq -r '[.zst_bytes, .zst_sha256, .sql_sha256] | @tsv' "$WORK/manifest.json"
  )
  verify "$sql.zst" "$prefix.sql.zst (from $manifest)" "$zst_bytes" "$zst_sha256"
  # The manifest declares the verified SQL size even for multi-batch dumps.
  bound=$manifest_sql_bytes
  decompress_log="$LOG_DIR/decompress.log"
  decompress_status=0
  zstd -q -dc "$sql.zst" 2>"$decompress_log" | head -c "$((bound + 1))" >"$sql" || decompress_status=$?
  # If head stopped the decoder, report the exceeded bound even if zstd
  # also failed (e.g. SIGPIPE). Nothing else reads the oversized SQL.
  if (( $(wc -c <"$sql") > bound )); then
    die "decompressed SQL exceeds $bound bytes (from $manifest), see $decompress_log"
  fi
  (( decompress_status == 0 )) || die "decompression failed for $prefix.sql.zst (from $manifest), see $decompress_log"
  verify "$sql" "$prefix.sql (from $manifest)" "$manifest_sql_bytes" "$sql_sha256"
else
  [[ $? == 2 ]] || die "could not read $manifest, see $manifest_log"
  legacy="$prefix.sql"
  legacy_log="$LOG_DIR/legacy.get.log"
  if get_restore_object "$legacy" "$sql" "$legacy_log" "$@"; then
    grep -q 'CREATE TABLE' "$sql" || die "no schema in $legacy, see $legacy_log"
  elif [[ $? == 2 ]]; then
    die "no export at restore point $since_ms (neither $manifest nor $legacy)"
  else
    die "could not read $legacy, see $legacy_log"
  fi
  echo 'catalog-import: legacy export without a manifest; no checksum to check'
fi

loaded_bytes=$(( $(wc -c <"$sql") ))
catalog_check_sql_size "$loaded_bytes"
catalog_check_sql_statements "$sql" >/dev/null
python3 -I "$HERE/sql_longest_statement.py" split "$sql" "$WORK" "$batch_bytes" "$catalog_sql_statement_limit"

count_log="$LOG_DIR/d1-count.log"
"$wrangler" d1 execute "$target" --remote --json \
  --command "SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND substr(name, 1, 4) <> '_cf_' AND substr(name, 1, 7) <> 'sqlite_'" \
  "$@" </dev/null >"$WORK/count.json" 2>"$count_log" ||
  die "could not check whether $target is empty, see $count_log"
count=$(jq -er '.[0].results[0].n | select(type == "number" and . >= 0 and floor == .)' "$WORK/count.json" 2>>"$count_log") ||
  die "could not read table count for $target, see $count_log"
[[ $count == 0 ]] || die "$target is not empty, see $count_log"

jq -er '.batches[] | [.file, .bytes, .sha256] | @tsv' "$WORK/split.json" >"$WORK/batches.tsv"
batch=0
while IFS=$'\t' read -r file bytes sha256; do
  [[ $file =~ ^batch-[0-9]{8}\.sql$ ]] || die 'invalid batch file name in split manifest'
  path="$WORK/$file"
  load_log="$LOG_DIR/d1-load-$batch.log"
  actual_sha=$(sha256sum <"$path")
  if [[ ${actual_sha%% *} != "$sha256" || $(( $(wc -c <"$path") )) != "$bytes" ]]; then
    die "batch $batch failed its pre-load checksum; if any batch was loaded, the target holds a partial load and must be deleted and recreated before retry"
  fi
  "$wrangler" d1 execute "$target" --remote --yes --file "$path" "$@" </dev/null >"$load_log" 2>&1 ||
    die "batch $batch failed, see $load_log; the target may hold a partial load and must be deleted and recreated before retry"
  batch=$((batch + 1))
done <"$WORK/batches.tsv"

if [[ ${VELMORA_IMPORT_SKIP_ROW_COUNTS:-} == yes ]]; then
  echo 'catalog-import: WARNING skipping restored table row counts (VELMORA_IMPORT_SKIP_ROW_COUNTS=yes)' >&2
else
  jq -c '.tables[]' "$WORK/split.json" >"$WORK/rows.jsonl"
  count_index=0
  while IFS= read -r table_row; do
    table=$(jq -er '.name' <<<"$table_row")
    expected=$(jq -er '.expected' <<<"$table_row")
    query=$(jq -er '.query' <<<"$table_row")
    row_log="$LOG_DIR/d1-row-count-$count_index.log"
    "$wrangler" d1 execute "$target" --remote --json --command "$query" "$@" \
      </dev/null >"$WORK/rows.json" 2>"$row_log" || die "could not count rows in $table, see $row_log"
    found=$(jq -er '.[0].results[0].n | select(type == "number" and . >= 0 and floor == .)' \
      "$WORK/rows.json" 2>>"$row_log") || die "invalid row count for $table, see $row_log"
    printf 'catalog-import: row count for %s: expected %s, found %s\n' "$table" "$expected" "$found"
    [[ $found == "$expected" ]] || die "row count for $table: expected $expected, found $found; restore not verified"
    count_index=$((count_index + 1))
  done <"$WORK/rows.jsonl"
fi
printf 'catalog-import: loaded %s bytes into %s from restore point %s\n' "$loaded_bytes" "$target" "$since_ms"
echo 'catalog-import: next: migrations apply, then ops/restore-arm.sql (README, Restore step 2)'
