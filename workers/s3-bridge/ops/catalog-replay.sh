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
# time: every step is idempotent. For the same reason a call that gets no
# answer, or a 5xx one, is sent again as it was, a few times, before the
# script gives up; any other answer than 200 ends it at once. A call is
# sent again after more than 30 seconds: the Worker can go on with a
# call for that long after the connection is lost, and the next call
# starts when it has stopped.
#
# The calls go one after the other: each starts where the one before
# ended, and the catalogue takes a step only from the place it has
# reached. One line of progress per call goes to stderr.
#
# Environment:
#   VELMORA_ADMIN_TOKEN_FILE  admin bearer file, mode 0600
#   VELMORA_REPLAY_RETRIES    times one call is sent again (default 5)
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

RETRIES=${VELMORA_REPLAY_RETRIES:-5}
case "$RETRIES" in '' | *[!0-9]*) echo "catalog-replay: VELMORA_REPLAY_RETRIES is a whole number" >&2; exit 1 ;; esac

# The running total stays in a file: its lists can outgrow what one
# command-line argument may hold.
echo '{}' >"$WORK/total.json"
calls=0
started=$(date +%s)
while :; do
  calls=$((calls + 1))
  tries=0
  while :; do
    : >"$WORK/step.json"
    status=$(curl -sS -o "$WORK/step.json" -w '%{http_code}' --max-time 300 \
      -X POST -H @"$WORK/auth" -H 'content-type: application/json' \
      --data-binary "$body" "$BASE/_admin/restore") || status=000
    case "$status" in 000 | 5??) ;; *) break ;; esac
    [ "$tries" -lt "$RETRIES" ] || break
    tries=$((tries + 1))
    wait=$((30 + tries * 5))
    echo "catalog-replay: call $calls answered $status; sent again in $wait s ($tries of $RETRIES)" >&2
    sleep "$wait"
  done
  if [ "$status" != 200 ]; then
    echo "catalog-replay: call $calls answered $status:" >&2
    head -c 600 "$WORK/step.json" >&2 2>/dev/null || true
    echo >&2
    # A replay that is on record as unfinished started at an earlier
    # restore point: the same command would answer 409 again.
    unfinished=$(jq -r '.unfinished_since_ms // empty' "$WORK/step.json" 2>/dev/null) || unfinished=
    case "$unfinished" in
    '' | *[!0-9]*)
      if [ "$status" = 409 ]; then
        echo "catalog-replay: refused; do what the message above says, then run the same command again" >&2
      else
        echo "catalog-replay: run the same command again to continue" >&2
      fi
      ;;
    *)
      echo "catalog-replay: a replay from an earlier restore point is unfinished; run:" >&2
      echo "catalog-replay:   ops/catalog-replay.sh $BASE $unfinished 0" >&2
      ;;
    esac
    exit 1
  fi
  jq -c --slurpfile t "$WORK/total.json" '
    . as $s
    | reduce ("manifests","published","present","superseded","extents","article_plans",
              "safety_missing","tombstones","deleted","duplicate","other_bucket_total",
              "held_checked","held_missing_total") as $k
        ($t[0]; .[$k] = ((.[$k] // 0) + $s[$k]))
    | .unpublishable = ((.unpublishable // []) + $s.unpublishable)
    | .damaged_unpublished = ((.damaged_unpublished // []) + $s.damaged_unpublished)
    | .unreadable = (((.unreadable // []) + $s.unreadable) | unique)
    | .other_bucket = ((.other_bucket // []) + $s.other_bucket)
    | .twins = (((.twins // []) + ($s.twins // [])) | unique)
    | .held_missing = ((.held_missing // []) + $s.held_missing)
    | .damaged_total = $s.damaged_total
    | .damaged = $s.damaged' "$WORK/step.json" >"$WORK/total.next"
  mv "$WORK/total.next" "$WORK/total.json"
  jq -r --argjson c "$calls" --argjson t "$(($(date +%s) - started))" --slurpfile s "$WORK/step.json" '
    "catalog-replay: call \($c), \($t) s: \(.manifests) records, \(.extents) extents, \(.tombstones) tombstones, \(.held_checked) pinned copies checked"
    + (if $t > 0 then " (\(.extents / $t * 10 | round / 10) extents/s)" else "" end)
    + "; now in \($s[0].next.phase // "the end")"' "$WORK/total.json" >&2
  if [ "$(jq -r '.next == null' "$WORK/step.json")" = true ]; then
    break
  fi
  body=$(jq -c '{cursor: .next}' "$WORK/step.json")
done

echo "catalog-replay: complete after $calls calls"
jq . "$WORK/total.json"
if [ "$(jq -r '.held_missing_total' "$WORK/total.json")" != 0 ]; then
  echo "catalog-replay: the catalogue is older than the release of some pinned copies" >&2
  echo "catalog-replay: run it again with restore point 0 before leaving maintenance" >&2
  exit 2
fi
if [ "$(jq -r '(.unpublishable | length) + (.damaged_unpublished | length) + (.unreadable | length) + (.twins | length) + .damaged_total + .other_bucket_total' "$WORK/total.json")" != 0 ]; then
  echo "catalog-replay: finished with damage, see the lists above" >&2
  exit 2
fi
