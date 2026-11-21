#!/usr/bin/env bash
# Loads a D1 catalogue export into an empty database:
# ops/catalog-import.sh <target database> <restore point ms> [wrangler args]
#
# Environment:
#   VELMORA_D1                    source database (default velmora-catalog)
#   VELMORA_EXPORT_BUCKET         R2 bucket (default velmora-catalog-export)
#   VELMORA_EXPORT_RCLONE_REMOTE  optional configured rclone remote
#   VELMORA_IMPORT_PRODUCTION     set to yes to allow the velmora-catalog target
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
if [[ $target == velmora-catalog && ${VELMORA_IMPORT_PRODUCTION:-} != yes ]]; then
  die 'refusing to load into velmora-catalog without VELMORA_IMPORT_PRODUCTION=yes'
fi
[[ $since_ms =~ ^[0-9]+$ ]] || die 'restore point must contain only digits'

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$HERE/.."
DB=${VELMORA_D1:-velmora-catalog}
BUCKET=${VELMORA_EXPORT_BUCKET:-velmora-catalog-export}
remote=${VELMORA_EXPORT_RCLONE_REMOTE-}
if [[ ${VELMORA_EXPORT_RCLONE_REMOTE+x} && ! $remote =~ ^[A-Za-z0-9_-]+$ ]]; then
  die 'invalid VELMORA_EXPORT_RCLONE_REMOTE'
fi
for tool in zstd jq sha256sum; do
  command -v "$tool" >/dev/null || die "missing tool: $tool"
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/velmora-import.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

get() {
  local key=$1 out=$2
  shift 2
  if [[ -n $remote ]]; then
    rclone copyto "$remote:$BUCKET/$key" "$out"
  else
    npx wrangler r2 object get "$BUCKET/$key" --file "$out" --remote "$@"
  fi >"$WORK/get.log" 2>&1
}

verify() {
  local path=$1 key=$2 expected_bytes=$3 expected_sha256=$4 bytes sha256
  bytes=$(wc -c <"$path")
  [[ $bytes == "$expected_bytes" ]] || die "size mismatch for $key"
  sha256=$(sha256sum <"$path")
  [[ ${sha256%% *} == "$expected_sha256" ]] || die "sha256 mismatch for $key"
}

prefix="d1/$DB/$since_ms"
manifest="$prefix.manifest.json"
sql="$WORK/catalog.sql"
if get "$manifest" "$WORK/manifest.json" "$@"; then
  jq -ers --arg db "$DB" --arg ms "$since_ms" --arg prefix "$prefix.sql.zst.part-" '
    def bytes: type == "number" and . >= 0 and floor == .;
    def sha256: type == "string" and test("^[0-9a-f]{64}$");
    length == 1 and (.[0] |
      (.format // 1) == 1 and .database == $db and
      (.restore_point_ms | type == "number" and tostring == $ms) and
      (.sql_bytes | bytes) and (.sql_sha256 | sha256) and
      (.zst_bytes | bytes) and (.zst_sha256 | sha256) and
      (.parts | type == "array" and length > 0 and all(.[];
        (.key | startswith($prefix) and (ltrimstr($prefix) | test("^[0-9]{3}$"))) and
        (.bytes | bytes) and (.sha256 | sha256))))
  ' "$WORK/manifest.json" >/dev/null || die "invalid manifest $manifest"

  jq -r '.parts[] | [.key, .bytes, .sha256] | @tsv' "$WORK/manifest.json" >"$WORK/parts.tsv"
  while IFS=$'\t' read -r key bytes sha256; do
    get "$key" "$WORK/part" "$@" || die "download failed for $key"
    verify "$WORK/part" "$key" "$bytes" "$sha256"
    cat "$WORK/part"
  done <"$WORK/parts.tsv" >"$sql.zst"

  IFS=$'\t' read -r zst_bytes zst_sha256 sql_bytes sql_sha256 < <(
    jq -r '[.zst_bytes, .zst_sha256, .sql_bytes, .sql_sha256] | @tsv' "$WORK/manifest.json"
  )
  verify "$sql.zst" "$prefix.sql.zst (from $manifest)" "$zst_bytes" "$zst_sha256"
  zstd -q -d "$sql.zst" -o "$sql" || die "decompression failed for $prefix.sql.zst (from $manifest)"
  verify "$sql" "$prefix.sql (from $manifest)" "$sql_bytes" "$sql_sha256"
else
  get "$prefix.sql" "$sql" "$@" || die "download failed for both $manifest and $prefix.sql"
  echo 'catalog-import: legacy export without a manifest; no checksum to check'
fi

npx wrangler d1 execute "$target" --remote --json \
  --command "SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND substr(name, 1, 4) <> '_cf_' AND substr(name, 1, 7) <> 'sqlite_'" \
  "$@" >"$WORK/count.json" 2>"$WORK/count.log" || {
  tail -n 20 "$WORK/count.log" >&2
  die "could not check whether $target is empty"
}
count=$(jq -er '.[0].results[0].n | select(type == "number" and . >= 0 and floor == .)' "$WORK/count.json") ||
  die "could not read table count for $target"
[[ $count == 0 ]] || die "$target is not empty"

npx wrangler d1 execute "$target" --remote --yes --file "$sql" "$@" >"$WORK/load.log" 2>&1 || {
  tail -n 20 "$WORK/load.log" >&2
  die "load into $target failed"
}
printf 'catalog-import: loaded %s bytes into %s from restore point %s\n' "$(wc -c <"$sql")" "$target" "$since_ms"
echo 'catalog-import: next: migrations apply, then ops/restore-arm.sql (README, Restore step 2)'
