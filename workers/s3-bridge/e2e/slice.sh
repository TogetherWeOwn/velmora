#!/usr/bin/env bash
# Slice acceptance through aws-cli: e2e/slice.sh <base-url>
#
# Local (base URL on 127.0.0.1 or localhost): starts fakesrv, applies the D1
# migrations to a throwaway local state, writes a throwaway .dev.vars, starts
# `wrangler dev --env dev --local --test-scheduled` on the URL's port, then
# runs the steps. Step 7 restarts it with DEV_DROP_NOTIFY_N=1 so the next
# queue send is lost, then calls the scheduled handler. Everything it started
# or wrote is removed on exit.
#
# Remote (any other base URL): runs against a deployed Worker. The admin
# bearer comes from the 0600 file named by VELMORA_ADMIN_TOKEN_FILE. Step 4
# accepts `verify` (release waits for a second backbone) and step 7 waits for
# the real cron instead of calling the scheduled handler.
#
# No secret ever appears in argv, in xtrace output or in the log: the bearer
# reaches curl through a 0600 header file (`-H @file`), the S3 key reaches
# aws-cli through a 0600 credentials file, and wrangler output is redacted
# before it is shown.
#
# Environment:
#   FAKESRV_BIN               fakesrv binary (local; default: target/debug/fakesrv)
#   FAKESRV_PORT              loopback port for fakesrv (local; default 11119)
#   READY_TIMEOUT_SECS        wait for `wrangler dev` to answer (default 1200;
#                             the first run compiles the Worker)
#   VELMORA_ADMIN_TOKEN_FILE  admin bearer file, mode 0600 (remote only)
#
# Every failure prints `SLICE FAILED at step <n>: <what>` with the expected
# and the actual value, and the script exits non-zero.

set -euo pipefail
set +x
umask 077

BASE=${1:?usage: e2e/slice.sh <base-url>, e.g. http://127.0.0.1:8787}
BASE=${BASE%/}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORKER_DIR=$(cd "$HERE/.." && pwd)
REPO_DIR=$(cd "$WORKER_DIR/../.." && pwd)
STEP=prereq

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

log() { printf '[slice %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

# fail <what> <expected> <actual>
fail() {
  printf '\nSLICE FAILED at step %s: %s\n  expected: %s\n  actual:   %s\n\n' \
    "$STEP" "$1" "$2" "$(printf '%s' "$3" | head -c 2000)" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Base URL, mode, prerequisites
# ---------------------------------------------------------------------------

if [[ ! $BASE =~ ^(https?)://([^/:]+)(:([0-9]+))?$ ]]; then
  fail "base URL" "scheme://host[:port] with no path" "$BASE"
fi
SCHEME=${BASH_REMATCH[1]}
HOST=${BASH_REMATCH[2]}
PORT=${BASH_REMATCH[4]:-}
case $HOST in
  127.0.0.1 | localhost) MODE=local ;;
  *) MODE=remote ;;
esac
if [[ $MODE == local ]]; then
  [[ $SCHEME == http && -n $PORT ]] || fail "local base URL" "http://127.0.0.1:<port>" "$BASE"
fi

for tool in aws curl jq openssl; do
  command -v "$tool" >/dev/null || fail "prerequisite" "$tool on PATH" "not found"
done

T=$(mktemp -d /tmp/velmora-e2e.XXXXXX)
WRANGLER_PID=
FAKESRV_PID=
DEV_VARS_WRITTEN=0
SECRETS=()

# Kills a process and its whole process group (wrangler spawns workerd).
stop_group() {
  local pid=$1
  [[ -n $pid ]] || return 0
  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  poll 5 0.1 not_running "$pid" && return 0
  kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
}

not_running() { ! kill -0 "$1" 2>/dev/null; }

cleanup() {
  local rc=$?
  set +e
  stop_group "$WRANGLER_PID"
  stop_group "$FAKESRV_PID"
  if [[ $DEV_VARS_WRITTEN == 1 ]]; then rm -f "$WORKER_DIR/.dev.vars"; fi
  rm -rf "$T"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Prints a log file with every known secret value replaced. Parameter
# expansion is a builtin, so no secret reaches argv.
redacted_tail() {
  local file=$1 line s
  [[ -f $file ]] || return 0
  tail -n 40 "$file" | while IFS= read -r line; do
    for s in "${SECRETS[@]}"; do
      [[ -n $s ]] && line=${line//"$s"/<redacted>}
    done
    printf '    %s\n' "$line"
  done >&2
}

# poll <timeout-secs> <interval-secs> <command...>: true once the command
# succeeds; false when the timeout passes, or at once when the command
# returns 2 (give up: e.g. the awaited process has exited).
poll() {
  local timeout=$1 interval=$2 rc
  shift 2
  local deadline=$((SECONDS + timeout))
  while true; do
    rc=0
    "$@" || rc=$?
    ((rc == 0)) && return 0
    ((rc == 2)) && return 2
    ((SECONDS < deadline)) || return 1
    sleep "$interval"
  done
}

port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# ---------------------------------------------------------------------------
# Local environment: fakesrv, migrations, .dev.vars, wrangler dev
# ---------------------------------------------------------------------------

if [[ $MODE == local ]]; then
  STEP=local-setup
  command -v npx >/dev/null || fail "prerequisite" "npx on PATH" "not found"
  FAKESRV_BIN=${FAKESRV_BIN:-$REPO_DIR/target/debug/fakesrv}
  FAKESRV_PORT=${FAKESRV_PORT:-11119}
  [[ -x $FAKESRV_BIN ]] || fail "prerequisite" "an executable fakesrv (FAKESRV_BIN)" "$FAKESRV_BIN"
  [[ ! -e $WORKER_DIR/.dev.vars ]] ||
    fail "workers/s3-bridge/.dev.vars" "absent (the script writes a throwaway one)" "a file exists; move it away first"
  port_open "$PORT" && fail "port $PORT" "free for wrangler dev" "already in use"
  port_open "$FAKESRV_PORT" && fail "port $FAKESRV_PORT" "free for fakesrv" "already in use"

  # Throwaway values, generated here and never printed.
  KEK=$(openssl rand -base64 32)
  ADMIN_TOKEN=$(openssl rand -hex 32)
  NNTP_PASS=$(openssl rand -hex 16)
  SECRETS=("$KEK" "$ADMIN_TOKEN" "$NNTP_PASS")

  log "starting fakesrv on 127.0.0.1:$FAKESRV_PORT"
  FAKESRV_USER=slice FAKESRV_PASS=$NNTP_PASS \
    setsid "$FAKESRV_BIN" --listen "127.0.0.1:$FAKESRV_PORT" --max-conns 2 \
    >"$T/fakesrv.log" 2>&1 &
  FAKESRV_PID=$!
  poll 30 0.2 port_open "$FAKESRV_PORT" ||
    { redacted_tail "$T/fakesrv.log"; fail "fakesrv listening" "port $FAKESRV_PORT open within 30 s" "closed"; }

  # write_dev_vars <drop-notify-n>: the throwaway .dev.vars (0600). printf
  # is a builtin, so the values never reach argv.
  write_dev_vars() {
    DEV_VARS_WRITTEN=1
    {
      printf 'VELMORA_KEK_1=%s\n' "$KEK"
      printf 'ADMIN_TOKEN=%s\n' "$ADMIN_TOKEN"
      printf 'NNTP_PROVIDERS=[{"id":"fake1","host":"127.0.0.1","port":%s,"tls":false,"user":"slice","pass":"%s","backbone":"fake","post":true,"read":true,"max_conns":2}]\n' \
        "$FAKESRV_PORT" "$NNTP_PASS"
      # The host clients sign is this run's port, not the default in wrangler.toml.
      printf 'S3_HOST=%s:%s\n' "$HOST" "$PORT"
      # Dev only: the first n queue sends of the isolate are lost (step 7).
      printf 'DEV_DROP_NOTIFY_N=%s\n' "$1"
    } >"$WORKER_DIR/.dev.vars"
    chmod 600 "$WORKER_DIR/.dev.vars"
  }
  write_dev_vars 0
  printf 'Authorization: Bearer %s\n' "$ADMIN_TOKEN" >"$T/admin.hdr"

  cd "$WORKER_DIR"
  log "applying D1 migrations to a throwaway local state"
  if ! npx --yes wrangler@4 d1 migrations apply velmora-catalog-dev --local --env dev \
    --persist-to "$T/state" >"$T/migrate.log" 2>&1 </dev/null; then
    redacted_tail "$T/migrate.log"
    fail "d1 migrations apply" "exit 0" "non-zero exit (log above)"
  fi

  wrangler_ready() {
    kill -0 "$WRANGLER_PID" 2>/dev/null || return 2
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/" || true)
    [[ $code != 000 ]]
  }

  # Starts `wrangler dev` on the persisted local state and waits until it
  # answers (or exits, which fails at once).
  start_wrangler() {
    local rc=0
    setsid npx --yes wrangler@4 dev --env dev --local --test-scheduled \
      --ip 127.0.0.1 --port "$PORT" --persist-to "$T/state" --show-interactive-dev-session=false \
      >>"$T/wrangler.log" 2>&1 </dev/null &
    WRANGLER_PID=$!
    poll "${READY_TIMEOUT_SECS:-1200}" 2 wrangler_ready || rc=$?
    if ! kill -0 "$WRANGLER_PID" 2>/dev/null; then
      redacted_tail "$T/wrangler.log"
      fail "wrangler dev" "running and answering on $BASE" "the process exited (log above)"
    elif ((rc != 0)); then
      redacted_tail "$T/wrangler.log"
      fail "wrangler dev" "answering on $BASE within ${READY_TIMEOUT_SECS:-1200} s" "no answer (log above)"
    fi
    log "wrangler dev is answering"
  }

  # Stops `wrangler dev` and waits until its port is free again.
  stop_wrangler() {
    stop_group "$WRANGLER_PID"
    WRANGLER_PID=
    port_closed() { ! port_open "$PORT"; }
    poll 30 0.2 port_closed || fail "wrangler dev stopped" "port $PORT free within 30 s" "still in use"
  }

  log "starting wrangler dev on port $PORT (the first run compiles the Worker)"
  start_wrangler
else
  STEP=remote-setup
  TOKEN_FILE=${VELMORA_ADMIN_TOKEN_FILE:-}
  [[ -n $TOKEN_FILE && -f $TOKEN_FILE ]] ||
    fail "VELMORA_ADMIN_TOKEN_FILE" "a readable file with the admin bearer" "${TOKEN_FILE:-unset}"
  mode=$(stat -c '%a' "$TOKEN_FILE")
  [[ $mode == 600 || $mode == 400 ]] || fail "admin token file mode" "0600 or 0400" "$mode"
  ADMIN_TOKEN=$(<"$TOKEN_FILE")
  SECRETS=("$ADMIN_TOKEN")
  printf 'Authorization: Bearer %s\n' "$ADMIN_TOKEN" >"$T/admin.hdr"
  unset ADMIN_TOKEN
fi

# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

# adm <what> <curl args...>: admin call; prints the body; fails on HTTP >= 300.
adm() {
  local what=$1 code
  shift
  code=$(curl -sS -o "$T/adm.out" -w '%{http_code}' --max-time 300 -H @"$T/admin.hdr" "$@" 2>"$T/adm.err") ||
    fail "$what" "an HTTP answer" "curl: $(<"$T/adm.err")"
  if ((code < 200 || code >= 300)); then
    fail "$what" "HTTP 2xx" "HTTP $code $(<"$T/adm.out")"
  fi
  cat "$T/adm.out"
}

# adm_try: like adm, but returns non-zero instead of failing (for polls).
adm_try() {
  local code
  code=$(curl -sS -o "$T/adm.out" -w '%{http_code}' --max-time 60 -H @"$T/admin.hdr" "$@" 2>/dev/null) || return 1
  ((code >= 200 && code < 300)) || return 1
  cat "$T/adm.out"
}

# jcheck <what> <jq filter> <json>: the filter must yield true.
jcheck() {
  jq -e "$2" >/dev/null 2>&1 <<<"$3" || fail "$1" "jq: $2" "$3"
}

# expect_err <what> <pattern> <command...>: the command must fail and its
# output must match the pattern (`! cmd` is not an assertion under set -e).
expect_err() {
  local what=$1 want=$2 out
  shift 2
  if out=$("$@" 2>&1); then
    fail "$what" "a failure matching '$want'" "success: $out"
  fi
  grep -Eq -- "$want" <<<"$out" || fail "$what" "a failure matching '$want'" "$out"
}

# same_bytes <what> <expected-file> <actual-file>
same_bytes() {
  cmp -s "$2" "$3" && return 0
  fail "$1" "$(stat -c %s "$2") bytes, sha256 $(sha256sum <"$2" | cut -c1-64)" \
    "$(stat -c %s "$3" 2>/dev/null || echo 0) bytes, sha256 $(sha256sum <"$3" | cut -c1-64), $(cmp "$2" "$3" 2>&1 | head -1)"
}

# Runs aws and fails the step with its output if it fails.
run_aws() {
  local what=$1 out
  shift
  out=$("$@" 2>&1) || fail "$what" "aws exits 0" "$out"
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# Setup: buckets, key, aws-cli
# ---------------------------------------------------------------------------

STEP=0-setup
log "step $STEP"
adm "POST /_admin/buckets slice" -XPOST "$BASE/_admin/buckets" -H 'content-type: application/json' \
  -d '{"name":"slice","disposable":true}' >/dev/null
adm "POST /_admin/buckets other" -XPOST "$BASE/_admin/buckets" -H 'content-type: application/json' \
  -d '{"name":"other","disposable":true}' >/dev/null
# The key secret goes straight from curl through jq into a 0600 file.
adm "POST /_admin/keys" -XPOST "$BASE/_admin/keys" -H 'content-type: application/json' \
  -d '{"buckets":["slice","other"],"perm":"rw"}' >"$T/key.json"
jq -e '(.access_key_id|type=="string") and (.secret|type=="string")' "$T/key.json" >/dev/null ||
  fail "POST /_admin/keys response" "{access_key_id, secret} strings" "keys: $(jq -c 'keys' "$T/key.json" 2>&1)"
jq -r '"[default]\naws_access_key_id=\(.access_key_id)\naws_secret_access_key=\(.secret)"' \
  "$T/key.json" >"$T/aws-credentials"
rm -f "$T/key.json"

export AWS_SHARED_CREDENTIALS_FILE="$T/aws-credentials" AWS_CONFIG_FILE="$T/aws-config"
export AWS_DEFAULT_REGION=auto AWS_EC2_METADATA_DISABLED=true AWS_PAGER=''
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
aws configure set default.s3.addressing_style path
# Multipart stays at the aws-cli defaults: 8 MiB parts, 10 concurrent.
S3=(aws s3 --endpoint-url "$BASE" --only-show-errors)
S3API=(aws s3api --endpoint-url "$BASE")

head -c 1048576 /dev/urandom >"$T/small.bin"
head -c 100663296 /dev/urandom >"$T/big.bin" # 96 MiB: 12 parts, 10 in flight
run_aws "PUT a/small.bin" "${S3[@]}" cp "$T/small.bin" s3://slice/a/small.bin >/dev/null
run_aws "multipart PUT a/big.bin" "${S3[@]}" cp "$T/big.bin" s3://slice/a/big.bin >/dev/null
json=$(adm "GET /_admin/status" "$BASE/_admin/status")
jcheck "inflight_peak_bytes within the 48 MiB budget" \
  '(.inflight_peak_bytes | type == "number") and .inflight_peak_bytes > 0 and .inflight_peak_bytes <= 50331648' "$json"
if [[ $MODE == local ]]; then
  json=$(adm "POST /_admin/dev/guard-selftest" -XPOST "$BASE/_admin/dev/guard-selftest")
  jcheck "guard self-test rolls back" '.rolled_back == true' "$json"
fi

# ---------------------------------------------------------------------------
# 1 read-after-write (served from SAFETY)
# ---------------------------------------------------------------------------

STEP=1-read-after-write
log "step $STEP"
run_aws "GET a/big.bin" "${S3[@]}" cp s3://slice/a/big.bin "$T/got-big.bin" >/dev/null
same_bytes "GET a/big.bin equals the upload" "$T/big.bin" "$T/got-big.bin"
run_aws "GET a/small.bin" "${S3[@]}" cp s3://slice/a/small.bin "$T/got-small.bin" >/dev/null
same_bytes "GET a/small.bin equals the upload" "$T/small.bin" "$T/got-small.bin"

# ---------------------------------------------------------------------------
# 2 HEAD / LIST / multipart ETag shape / a key with reserved characters
# ---------------------------------------------------------------------------

STEP=2-head-list-etag
log "step $STEP"
json=$(run_aws "HEAD a/big.bin" "${S3API[@]}" head-object --bucket slice --key a/big.bin)
jcheck "HEAD a/big.bin: 96 MiB and a 12-part ETag" '.ContentLength == 100663296 and (.ETag | test("^\"[0-9a-f]{32}-12\"$"))' "$json"
ODD='a/sp ace+plus%25/ü.bin'
run_aws "PUT a key with reserved characters" "${S3[@]}" cp "$T/small.bin" "s3://slice/$ODD" >/dev/null
run_aws "HEAD a key with reserved characters" "${S3API[@]}" head-object --bucket slice --key "$ODD" >/dev/null
json=$(run_aws "ListObjectsV2 prefix=a/ delimiter=/" "${S3API[@]}" list-objects-v2 --bucket slice --prefix a/ --delimiter /)
jcheck "LIST keys and one common prefix" \
  '[.Contents[].Key] == ["a/big.bin","a/small.bin"] and ([.CommonPrefixes[].Prefix] == ["a/sp ace+plus%25/"])' "$json"
json=$(run_aws "ListObjectsV2 continuation" "${S3API[@]}" list-objects-v2 --bucket slice --prefix a/ --page-size 1)
jcheck "LIST across pages of one key" \
  '[.Contents[].Key] == ["a/big.bin","a/small.bin","a/sp ace+plus%25/ü.bin"]' "$json"

# ---------------------------------------------------------------------------
# 3 range across an extent boundary (8 MiB)
# ---------------------------------------------------------------------------

STEP=3-range-across-extents
log "step $STEP"
run_aws "GET a/big.bin bytes=8388000-8389000" "${S3API[@]}" get-object --bucket slice --key a/big.bin \
  --range bytes=8388000-8389000 "$T/range.bin" >/dev/null
dd if="$T/big.bin" of="$T/range-want.bin" bs=1 skip=8388000 count=1001 status=none
same_bytes "range body equals bytes 8388000-8389000" "$T/range-want.bin" "$T/range.bin"

# 3b safety rules: conditional write refused before storing; upload ID is
# bound to its bucket and key.
STEP=3b-safety-rules
log "step $STEP"
expect_err "conditional PUT is refused" NotImplemented \
  "${S3API[@]}" put-object --bucket slice --key a/cond --body "$T/small.bin" --if-none-match '*'
expect_err "nothing was stored by the refused PUT" '\(404\)' \
  "${S3API[@]}" head-object --bucket slice --key a/cond
json=$(run_aws "CreateMultipartUpload a/mp" "${S3API[@]}" create-multipart-upload --bucket slice --key a/mp)
UP=$(jq -r .UploadId <<<"$json")
expect_err "UploadPart under another bucket" NoSuchUpload \
  "${S3API[@]}" upload-part --bucket other --key a/mp --part-number 1 --upload-id "$UP" --body "$T/small.bin"
expect_err "Abort under another bucket" NoSuchUpload \
  "${S3API[@]}" abort-multipart-upload --bucket other --key a/mp --upload-id "$UP"
expect_err "UploadPart under another key" NoSuchUpload \
  "${S3API[@]}" upload-part --bucket slice --key a/mp2 --part-number 1 --upload-id "$UP" --body "$T/small.bin"
run_aws "Abort a/mp under its own bucket and key" \
  "${S3API[@]}" abort-multipart-upload --bucket slice --key a/mp --upload-id "$UP" >/dev/null

# ---------------------------------------------------------------------------
# 4 posting + verification reached (poll <= 180 s)
# ---------------------------------------------------------------------------

STEP=4-post-and-verify
log "step $STEP"
if [[ $MODE == local ]]; then
  REACHED='.extents | length > 0 and all(.stage == "release" or .stage == "done")'
else
  # One backbone: release waits for the second, which is correct.
  REACHED='.extents | length > 0 and all(.stage == "verify" or .stage == "release" or .stage == "done")'
fi
COUNTED='.extents | length > 0 and all(.backbones | any(.counts))'
stage_reached() {
  local j
  j=$(adm_try "$BASE/_admin/objects/slice/a/$1") || return 1
  jq -e "($REACHED) and ($COUNTED)" >/dev/null 2>&1 <<<"$j" || return 1
}
# Any progress past a fresh commit (used by step 7).
stage_moved() {
  local j
  j=$(adm_try "$BASE/_admin/objects/slice/a/$1") || return 1
  jq -e '.extents | any(.stage != "post" or .attempts != 0)' >/dev/null 2>&1 <<<"$j" || return 1
}
if ! poll 180 2 stage_reached big.bin; then
  json=$(adm "GET /_admin/objects/slice/a/big.bin" "$BASE/_admin/objects/slice/a/big.bin")
  fail "a/big.bin posted and verified within 180 s" "jq: ($REACHED) and ($COUNTED)" "$json"
fi

# ---------------------------------------------------------------------------
# 5 cold read: wipe CACHE + SAFETY (disposable bucket only), GET from NNTP
# ---------------------------------------------------------------------------

STEP=5-cold-read
log "step $STEP"
json=$(adm "POST /_admin/evict a/big.bin" -XPOST "$BASE/_admin/evict/slice/a/big.bin?include_safety=1")
jcheck "evict removed blobs" '.evicted > 0' "$json"
# NNTP BODY -> yEnc -> sha256 -> R2 refill -> decrypt
run_aws "cold GET a/big.bin" "${S3[@]}" cp s3://slice/a/big.bin "$T/cold-big.bin" >/dev/null
same_bytes "cold GET a/big.bin equals the upload" "$T/big.bin" "$T/cold-big.bin"
json=$(adm "GET /_admin/objects/slice/a/big.bin" "$BASE/_admin/objects/slice/a/big.bin")
jcheck "every extent refilled into the cache" '.extents | length > 0 and all(.cache == "present")' "$json"

# ---------------------------------------------------------------------------
# 6 delete
# ---------------------------------------------------------------------------

STEP=6-delete
log "step $STEP"
run_aws "DELETE a/small.bin" "${S3[@]}" rm s3://slice/a/small.bin >/dev/null
expect_err "HEAD a/small.bin after delete" '\(404\)' \
  "${S3API[@]}" head-object --bucket slice --key a/small.bin

# ---------------------------------------------------------------------------
# 7 dispatcher recovery
# ---------------------------------------------------------------------------

STEP=7-dispatcher-recovery
log "step $STEP"
if [[ $MODE == local ]]; then
  # Let earlier work settle, so the dropped send is this PUT's notification.
  settled() {
    local j
    j=$(adm_try "$BASE/_admin/status") || return 1
    jq -e '((.outbox.post // 0) == 0) and ((.outbox.verify // 0) == 0)' >/dev/null 2>&1 <<<"$j" || return 1
  }
  if ! poll 180 2 settled; then
    json=$(adm "GET /_admin/status" "$BASE/_admin/status")
    fail "earlier objects settled within 180 s" "no outbox row in post or verify" "$json"
  fi
  # Restart with the first queue send of the new isolate dropped.
  log "restarting wrangler dev with DEV_DROP_NOTIFY_N=1"
  stop_wrangler
  write_dev_vars 1
  start_wrangler
  run_aws "PUT a/lost.bin" "${S3[@]}" cp "$T/small.bin" s3://slice/a/lost.bin >/dev/null
  json=$(adm "GET /_admin/objects/slice/a/lost.bin" "$BASE/_admin/objects/slice/a/lost.bin")
  jcheck "a/lost.bin is committed but never enqueued" \
    '.extents | length > 0 and all(.stage == "post" and .attempts == 0)' "$json"
  # No queue delivery can move it: it stays at post until the cron runs.
  if poll 10 2 stage_moved lost.bin; then
    json=$(adm "GET /_admin/objects/slice/a/lost.bin" "$BASE/_admin/objects/slice/a/lost.bin")
    fail "a/lost.bin stays at post without a queue message" "stage post, 0 attempts for 10 s" "$json"
  fi
  cron_then_check() {
    curl -sf --max-time 60 "$BASE/__scheduled?cron=*/5+*+*+*+*" >/dev/null || return 1
    stage_reached lost.bin
  }
  if ! poll 90 2 cron_then_check; then
    json=$(adm "GET /_admin/objects/slice/a/lost.bin" "$BASE/_admin/objects/slice/a/lost.bin")
    fail "a/lost.bin recovered by the scheduled handler within 90 s" "jq: ($REACHED) and ($COUNTED)" "$json"
  fi
else
  # The drop counter is dev-only: prove the real cron runs after deploy.
  START_MS=$(($(date +%s) * 1000))
  dispatched() {
    local j
    j=$(adm_try "$BASE/_admin/status") || return 1
    jq -e --argjson t "$START_MS" '(.last_dispatch_at // 0) >= $t' >/dev/null 2>&1 <<<"$j" || return 1
  }
  if ! poll 360 10 dispatched; then
    json=$(adm "GET /_admin/status" "$BASE/_admin/status")
    fail "a dispatcher run within 6 min" "last_dispatch_at >= $START_MS" "$json"
  fi
fi

STEP=finished
log "slice acceptance passed ($MODE, $BASE)"
