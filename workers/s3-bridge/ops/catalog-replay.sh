#!/usr/bin/env bash
# Replays the recovery records into the catalogue:
#   ops/catalog-replay.sh <base-url> <restore point ms> [margin ms]
#
# The Worker must run with MAINTENANCE=restore (the route answers 409
# otherwise). The restore point is the number ops/catalog-export.sh
# printed for the snapshot that was loaded, or 0 to replay every record
# (an empty catalogue). Records up to the margin older than the restore
# point are replayed too (default: one hour).
#
# The script calls POST /_admin/restore until the Worker reports the end,
# and prints the summed counts. It can be stopped and started again at any
# time: every step is idempotent.
#
# Environment:
#   VELMORA_ADMIN_TOKEN_FILE  admin bearer file, mode 0600
#
# The bearer reaches curl through a 0600 header file, never through argv.
# Exit status: 0 = complete and no damage; 2 = complete, but some records
# did not open, some generations were refused or some objects have no
# copy (the lists are printed); 1 = the replay did not finish.

set -euo pipefail
set +x
umask 077

BASE=${1:?usage: ops/catalog-replay.sh <base-url> <restore point ms> [margin ms]}
BASE=${BASE%/}
SINCE=${2:?restore point in ms (0 = every record)}
MARGIN=${3:-}
case "$SINCE$MARGIN" in *[!0-9]*) echo "catalog-replay: times are whole milliseconds" >&2; exit 1 ;; esac
: "${VELMORA_ADMIN_TOKEN_FILE:?file with the admin bearer}"
[ "$(stat -c %a "$VELMORA_ADMIN_TOKEN_FILE")" = 600 ] || {
  echo "catalog-replay: $VELMORA_ADMIN_TOKEN_FILE must have mode 0600" >&2
  exit 1
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
{
  printf 'authorization: Bearer '
  tr -d '\r\n' <"$VELMORA_ADMIN_TOKEN_FILE"
  printf '\n'
} >"$WORK/auth"

if [ -n "$MARGIN" ]; then
  body=$(jq -cn --argjson s "$SINCE" --argjson m "$MARGIN" '{since_ms: $s, margin_ms: $m}')
else
  body=$(jq -cn --argjson s "$SINCE" '{since_ms: $s}')
fi

total='{}'
calls=0
while :; do
  calls=$((calls + 1))
  status=$(curl -sS -o "$WORK/step.json" -w '%{http_code}' --max-time 300 \
    -X POST -H @"$WORK/auth" -H 'content-type: application/json' \
    --data-binary "$body" "$BASE/_admin/restore") || status=000
  if [ "$status" != 200 ]; then
    echo "catalog-replay: call $calls answered $status:" >&2
    head -c 600 "$WORK/step.json" >&2 2>/dev/null || true
    echo >&2
    echo "catalog-replay: run the same command again to continue" >&2
    exit 1
  fi
  total=$(jq -c --argjson t "$total" '
    . as $s
    | reduce ("manifests","published","present","superseded","extents","article_plans",
              "safety_missing","tombstones","deleted","duplicate","other_bucket_total",
              "held_checked","held_missing_total") as $k
        ($t; .[$k] = ((.[$k] // 0) + $s[$k]))
    | .unpublishable = ((.unpublishable // []) + $s.unpublishable)
    | .unreadable = ((.unreadable // []) + $s.unreadable)
    | .other_bucket = ((.other_bucket // []) + $s.other_bucket)
    | .held_missing = ((.held_missing // []) + $s.held_missing)
    | .damaged_total = $s.damaged_total
    | .damaged = $s.damaged' "$WORK/step.json")
  if [ "$(jq -r '.next == null' "$WORK/step.json")" = true ]; then
    break
  fi
  body=$(jq -c '{cursor: .next}' "$WORK/step.json")
done

echo "catalog-replay: complete after $calls calls"
jq . <<<"$total"
if [ "$(jq -r '.held_missing_total' <<<"$total")" != 0 ]; then
  echo "catalog-replay: the catalogue is older than the release of some pinned copies" >&2
  echo "catalog-replay: run it again with restore point 0 before leaving maintenance" >&2
  exit 2
fi
if [ "$(jq -r '(.unpublishable | length) + (.unreadable | length) + .damaged_total + .other_bucket_total' <<<"$total")" != 0 ]; then
  echo "catalog-replay: finished with damage, see the lists above" >&2
  exit 2
fi
