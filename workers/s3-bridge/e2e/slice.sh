#!/usr/bin/env bash
# Slice acceptance through aws-cli: e2e/slice.sh <base-url>
#
# Local (base URL on 127.0.0.1 or localhost): starts fakesrv, applies the D1
# migrations to a throwaway local state, writes a throwaway .dev.vars, starts
# `wrangler dev --env dev --local --test-scheduled` on the URL's port, then
# runs the steps. An `https://` local URL serves TLS with a throwaway
# self-signed certificate that aws-cli and curl are told to trust.
#
# aws-cli runs with its default checksum settings (CRC64NVME; over HTTPS the
# bodies are aws-chunked with a trailing checksum, over HTTP the checksum is
# a header). Step 0b repeats uploads with `when_required` (no checksum, no
# aws-chunked), so both client settings are covered in every run. Step 7 restarts it with DEV_DROP_NOTIFY_N=1 so the next
# queue send is lost, then calls the scheduled handler. Everything it started
# or wrote is removed on exit.
#
# Remote (any other base URL): runs against a deployed Worker. Nothing is
# started or migrated. The admin bearer comes from the 0600 file named by
# VELMORA_ADMIN_TOKEN_FILE. Differences from local, per the prod setup with
# one backbone:
#   - setup creates run-unique buckets (slice-<8 hex>, other-<8 hex>) and
#     fails if a name is taken; the in-flight peak may be 0 (the status call
#     can land on another isolate);
#   - step 4 accepts `verify` (release waits for a second backbone) and polls
#     up to STEP4_TIMEOUT_SECS (default 900: posting plus VERIFY_DELAY_SECS).
#     In both modes each extent's stage must agree with required_backbones
#     from /_admin/status: fewer counting backbones than required means no
#     release and the pinned copy held;
#   - step 5 also requires every pinned copy deleted and every cache copy
#     absent before the cold GET, so it can only be served from Usenet, and
#     logs the cold-read latency;
#   - step 5b runs POST /_admin/drill (read from Usenet only, no cache) and
#     requires match:true and the upload's sha256;
#   - step 7 waits for CRON_RUNS (default 2) runs of the real cron, each one
#     advancing last_dispatch_at, instead of calling the scheduled handler.
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
#   STEP4_TIMEOUT_SECS        step 4 poll limit (default 180 local, 900 remote)
#   CRON_RUNS                 cron runs step 7 waits for (remote; default 2)
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
  [[ -n $PORT ]] || fail "local base URL" "http(s)://127.0.0.1:<port>" "$BASE"
fi

for tool in aws curl jq openssl; do
  command -v "$tool" >/dev/null || fail "prerequisite" "$tool on PATH" "not found"
done

T=$(mktemp -d /tmp/velmora-e2e.XXXXXX)
WRANGLER_PID=
FAKESRV_PID=
DEV_VARS_WRITTEN=0
SECRETS=()
# Extra curl arguments (the local TLS trust anchor).
CURL_TLS=()

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
    code=$(curl -s "${CURL_TLS[@]}" -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/" || true)
    [[ $code != 000 ]]
  }

  # Local TLS: a throwaway self-signed certificate for 127.0.0.1/localhost.
  TLS_ARGS=()
  if [[ $SCHEME == https ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$HOST" \
      -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
      -keyout "$T/tls-key.pem" -out "$T/tls-cert.pem" >"$T/openssl.log" 2>&1 ||
      { redacted_tail "$T/openssl.log"; fail "local TLS certificate" "openssl exits 0" "non-zero exit (log above)"; }
    TLS_ARGS=(--local-protocol https --https-key-path "$T/tls-key.pem" --https-cert-path "$T/tls-cert.pem")
    CURL_TLS=(--cacert "$T/tls-cert.pem")
    export AWS_CA_BUNDLE="$T/tls-cert.pem"
  fi

  # Starts `wrangler dev` on the persisted local state and waits until it
  # answers (or exits, which fails at once).
  start_wrangler() {
    local rc=0
    setsid npx --yes wrangler@4 dev --env dev --local --test-scheduled \
      --ip 127.0.0.1 --port "$PORT" --persist-to "$T/state" --show-interactive-dev-session=false \
      "${TLS_ARGS[@]}" >>"$T/wrangler.log" 2>&1 </dev/null &
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
  code=$(curl -sS "${CURL_TLS[@]}" -o "$T/adm.out" -w '%{http_code}' --max-time 300 -H @"$T/admin.hdr" "$@" 2>"$T/adm.err") ||
    fail "$what" "an HTTP answer" "curl: $(<"$T/adm.err")"
  if ((code < 200 || code >= 300)); then
    fail "$what" "HTTP 2xx" "HTTP $code $(<"$T/adm.out")"
  fi
  cat "$T/adm.out"
}

# adm_try: like adm, but returns non-zero instead of failing (for polls).
adm_try() {
  local code
  code=$(curl -sS "${CURL_TLS[@]}" -o "$T/adm.out" -w '%{http_code}' --max-time 60 -H @"$T/admin.hdr" "$@" 2>/dev/null) || return 1
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
  if cmp -s "$2" "$3"; then
    log "$1: equal, $(stat -c %s "$3") bytes, sha256 $(sha256sum <"$3" | cut -c1-64)"
    return 0
  fi
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

now_ms() { date +%s%3N; }

# make_bucket <name>: a new disposable bucket. Any answer but 2xx fails the
# run, a 409 (name taken) included: a run never reuses a bucket.
make_bucket() {
  adm "POST /_admin/buckets $1" -XPOST "$BASE/_admin/buckets" -H 'content-type: application/json' \
    -d "{\"name\":\"$1\",\"disposable\":true}" >/dev/null
}

# ---------------------------------------------------------------------------
# Setup: buckets, key, aws-cli
# ---------------------------------------------------------------------------

STEP=0-setup
log "step $STEP"
# Remote runs get their own buckets, so a run never touches data it did
# not write and overlapping runs cannot see each other's objects. Local
# runs start from an empty throwaway state.
if [[ $MODE == local ]]; then
  SB=slice OB=other
else
  RUN_ID=$(openssl rand -hex 4)
  SB=slice-$RUN_ID OB=other-$RUN_ID
fi
log "buckets: $SB, $OB"
make_bucket "$SB"
make_bucket "$OB"
# The key secret goes straight from curl through jq into a 0600 file.
adm "POST /_admin/keys" -XPOST "$BASE/_admin/keys" -H 'content-type: application/json' \
  -d "{\"buckets\":[\"$SB\",\"$OB\"],\"perm\":\"rw\"}" >"$T/key.json"
jq -e '(.access_key_id|type=="string") and (.secret|type=="string")' "$T/key.json" >/dev/null ||
  fail "POST /_admin/keys response" "{access_key_id, secret} strings" "keys: $(jq -c 'keys' "$T/key.json" 2>&1)"
jq -r '"[default]\naws_access_key_id=\(.access_key_id)\naws_secret_access_key=\(.secret)"' \
  "$T/key.json" >"$T/aws-credentials"
rm -f "$T/key.json"

export AWS_SHARED_CREDENTIALS_FILE="$T/aws-credentials" AWS_CONFIG_FILE="$T/aws-config"
export AWS_DEFAULT_REGION=auto AWS_EC2_METADATA_DISABLED=true AWS_PAGER=''
# The client's default checksum settings: no AWS_*_CHECKSUM_* override.
unset AWS_REQUEST_CHECKSUM_CALCULATION AWS_RESPONSE_CHECKSUM_VALIDATION
aws configure set default.s3.addressing_style path
# Multipart stays at the aws-cli defaults: 8 MiB parts, 10 concurrent.
S3=(aws s3 --endpoint-url "$BASE" --only-show-errors)
S3API=(aws s3api --endpoint-url "$BASE")

head -c 1048576 /dev/urandom >"$T/small.bin"
head -c 100663296 /dev/urandom >"$T/big.bin" # 96 MiB: 12 parts, 10 in flight
run_aws "PUT a/small.bin" "${S3[@]}" cp "$T/small.bin" "s3://$SB/a/small.bin" >/dev/null
run_aws "multipart PUT a/big.bin" "${S3[@]}" cp "$T/big.bin" "s3://$SB/a/big.bin" >/dev/null
json=$(adm "GET /_admin/status" "$BASE/_admin/status")
if [[ $MODE == local ]]; then
  jcheck "inflight_peak_bytes within the 48 MiB budget" \
    '(.inflight_peak_bytes | type == "number") and .inflight_peak_bytes > 0 and .inflight_peak_bytes <= 50331648' "$json"
else
  # The answering isolate may not be one that served the uploads.
  jcheck "inflight_peak_bytes within the 48 MiB budget" \
    '(.inflight_peak_bytes | type == "number") and .inflight_peak_bytes <= 50331648' "$json"
  log "inflight_peak_bytes of the answering isolate: $(jq -r .inflight_peak_bytes <<<"$json")"
fi
if [[ $MODE == local ]]; then
  json=$(adm "POST /_admin/dev/guard-selftest" -XPOST "$BASE/_admin/dev/guard-selftest")
  jcheck "guard self-test rolls back" '.rolled_back == true' "$json"
fi
# Prove which framing the default client used: aws-chunked with a trailing
# checksum over HTTPS, a checksum header over HTTP. The debug log stays in
# the 0600 scratch directory and only a fixed verdict is ever printed.
if [[ $SCHEME == https ]]; then
  WANT_FRAMING='aws-chunked.*STREAMING-UNSIGNED-PAYLOAD-TRAILER|STREAMING-UNSIGNED-PAYLOAD-TRAILER.*aws-chunked'
else
  WANT_FRAMING="'x-amz-checksum-crc64nvme'"
fi
"${S3API[@]}" put-object --bucket "$SB" --key a/framing.bin --body "$T/small.bin" --debug \
  >/dev/null 2>"$T/framing.log" || fail "PUT a/framing.bin" "aws exits 0" "non-zero exit"
grep -Eq -- "$WANT_FRAMING" "$T/framing.log" ||
  fail "default client framing over $SCHEME" "request headers matching $WANT_FRAMING" "not found in the aws-cli debug log"
rm -f "$T/framing.log"
run_aws "DELETE a/framing.bin" "${S3API[@]}" delete-object --bucket "$SB" --key a/framing.bin >/dev/null
# The default single PUT stored the client's CRC64NVME and returns it.
json=$(run_aws "HEAD a/small.bin with checksum mode" "${S3API[@]}" head-object --bucket "$SB" --key a/small.bin --checksum-mode ENABLED)
jcheck "HEAD a/small.bin returns the stored CRC64NVME" '(.ChecksumCRC64NVME | type == "string") and (.ChecksumCRC64NVME | length == 12)' "$json"

# ---------------------------------------------------------------------------
# 0b the same uploads with checksums only when required (no aws-chunked)
# ---------------------------------------------------------------------------

STEP=0b-when-required
log "step $STEP"
WHEN_REQUIRED=(env AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required)
head -c 20971520 /dev/urandom >"$T/mid.bin" # 20 MiB: 3 parts
run_aws "PUT w/small.bin (when_required)" "${WHEN_REQUIRED[@]}" "${S3[@]}" cp "$T/small.bin" "s3://$SB/w/small.bin" >/dev/null
run_aws "multipart PUT w/mid.bin (when_required)" "${WHEN_REQUIRED[@]}" "${S3[@]}" cp "$T/mid.bin" "s3://$SB/w/mid.bin" >/dev/null
run_aws "GET w/small.bin (when_required)" "${WHEN_REQUIRED[@]}" "${S3[@]}" cp "s3://$SB/w/small.bin" "$T/got-w-small.bin" >/dev/null
same_bytes "GET w/small.bin equals the upload" "$T/small.bin" "$T/got-w-small.bin"
run_aws "GET w/mid.bin (when_required)" "${WHEN_REQUIRED[@]}" "${S3[@]}" cp "s3://$SB/w/mid.bin" "$T/got-w-mid.bin" >/dev/null
same_bytes "GET w/mid.bin equals the upload" "$T/mid.bin" "$T/got-w-mid.bin"
rm -f "$T/mid.bin" "$T/got-w-mid.bin" "$T/got-w-small.bin"

# ---------------------------------------------------------------------------
# 1 read-after-write (served from SAFETY)
# ---------------------------------------------------------------------------

STEP=1-read-after-write
log "step $STEP"
run_aws "GET a/big.bin" "${S3[@]}" cp "s3://$SB/a/big.bin" "$T/got-big.bin" >/dev/null
same_bytes "GET a/big.bin equals the upload" "$T/big.bin" "$T/got-big.bin"
run_aws "GET a/small.bin" "${S3[@]}" cp "s3://$SB/a/small.bin" "$T/got-small.bin" >/dev/null
same_bytes "GET a/small.bin equals the upload" "$T/small.bin" "$T/got-small.bin"

# ---------------------------------------------------------------------------
# 2 HEAD / LIST / multipart ETag shape / a key with reserved characters
# ---------------------------------------------------------------------------

STEP=2-head-list-etag
log "step $STEP"
json=$(run_aws "HEAD a/big.bin" "${S3API[@]}" head-object --bucket "$SB" --key a/big.bin)
jcheck "HEAD a/big.bin: 96 MiB and a 12-part ETag" '.ContentLength == 100663296 and (.ETag | test("^\"[0-9a-f]{32}-12\"$"))' "$json"
ODD='a/sp ace+plus%25/ü.bin'
run_aws "PUT a key with reserved characters" "${S3[@]}" cp "$T/small.bin" "s3://$SB/$ODD" >/dev/null
run_aws "HEAD a key with reserved characters" "${S3API[@]}" head-object --bucket "$SB" --key "$ODD" >/dev/null
json=$(run_aws "ListObjectsV2 prefix=a/ delimiter=/" "${S3API[@]}" list-objects-v2 --bucket "$SB" --prefix a/ --delimiter /)
jcheck "LIST keys and one common prefix" \
  '[.Contents[].Key] == ["a/big.bin","a/small.bin"] and ([.CommonPrefixes[].Prefix] == ["a/sp ace+plus%25/"])' "$json"
json=$(run_aws "ListObjectsV2 continuation" "${S3API[@]}" list-objects-v2 --bucket "$SB" --prefix a/ --page-size 1)
jcheck "LIST across pages of one key" \
  '[.Contents[].Key] == ["a/big.bin","a/small.bin","a/sp ace+plus%25/ü.bin"]' "$json"

# ---------------------------------------------------------------------------
# 3 range across an extent boundary (8 MiB)
# ---------------------------------------------------------------------------

STEP=3-range-across-extents
log "step $STEP"
run_aws "GET a/big.bin bytes=8388000-8389000" "${S3API[@]}" get-object --bucket "$SB" --key a/big.bin \
  --range bytes=8388000-8389000 "$T/range.bin" >/dev/null
dd if="$T/big.bin" of="$T/range-want.bin" bs=1 skip=8388000 count=1001 status=none
same_bytes "range body equals bytes 8388000-8389000" "$T/range-want.bin" "$T/range.bin"

# 3b safety rules: conditional write refused before storing; upload ID is
# bound to its bucket and key.
STEP=3b-safety-rules
log "step $STEP"
expect_err "conditional PUT is refused" NotImplemented \
  "${S3API[@]}" put-object --bucket "$SB" --key a/cond --body "$T/small.bin" --if-none-match '*'
expect_err "nothing was stored by the refused PUT" '\(404\)' \
  "${S3API[@]}" head-object --bucket "$SB" --key a/cond
json=$(run_aws "CreateMultipartUpload a/mp" "${S3API[@]}" create-multipart-upload --bucket "$SB" --key a/mp)
UP=$(jq -r .UploadId <<<"$json")
expect_err "UploadPart under another bucket" NoSuchUpload \
  "${S3API[@]}" upload-part --bucket "$OB" --key a/mp --part-number 1 --upload-id "$UP" --body "$T/small.bin"
expect_err "Abort under another bucket" NoSuchUpload \
  "${S3API[@]}" abort-multipart-upload --bucket "$OB" --key a/mp --upload-id "$UP"
expect_err "UploadPart under another key" NoSuchUpload \
  "${S3API[@]}" upload-part --bucket "$SB" --key a/mp2 --part-number 1 --upload-id "$UP" --body "$T/small.bin"
run_aws "Abort a/mp under its own bucket and key" \
  "${S3API[@]}" abort-multipart-upload --bucket "$SB" --key a/mp --upload-id "$UP" >/dev/null

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
# The stage must agree with the Worker's required_backbones: with fewer
# counting backbones than required, release never starts and the pinned
# copy stays held; with enough, the extent goes on to release.
json=$(adm "GET /_admin/status" "$BASE/_admin/status")
REQUIRED=$(jq -r '.required_backbones' <<<"$json")
[[ $REQUIRED =~ ^[1-9][0-9]*$ ]] || fail "required_backbones in /_admin/status" "a positive integer" "$json"
log "required_backbones=$REQUIRED"
# shellcheck disable=SC2016 # $n and $required are jq variables, not shell ones
CONSISTENT='.extents | all(([.backbones[] | select(.counts) | .backbone] | unique | length) as $n
  | if $n < $required then (.stage == "verify" or .stage == "done") and .safety_state == "held"
    else .stage == "release" or .stage == "done" end)'
stage_reached() {
  local j
  j=$(adm_try "$BASE/_admin/objects/$SB/a/$1") || return 1
  jq -e --argjson required "$REQUIRED" "($REACHED) and ($COUNTED) and ($CONSISTENT)" >/dev/null 2>&1 <<<"$j" || return 1
}
# Any progress past a fresh commit (used by step 7).
stage_moved() {
  local j
  j=$(adm_try "$BASE/_admin/objects/$SB/a/$1") || return 1
  jq -e '.extents | any(.stage != "post" or .attempts != 0)' >/dev/null 2>&1 <<<"$j" || return 1
}
if [[ $MODE == local ]]; then
  STEP4_TIMEOUT=${STEP4_TIMEOUT_SECS:-180}
  STEP4_EVERY=2
else
  STEP4_TIMEOUT=${STEP4_TIMEOUT_SECS:-900}
  STEP4_EVERY=10
fi
[[ $STEP4_TIMEOUT =~ ^[1-9][0-9]*$ ]] || fail "STEP4_TIMEOUT_SECS" "a positive integer" "$STEP4_TIMEOUT"
t0=$(now_ms)
if ! poll "$STEP4_TIMEOUT" "$STEP4_EVERY" stage_reached big.bin; then
  json=$(adm "GET /_admin/objects/$SB/a/big.bin" "$BASE/_admin/objects/$SB/a/big.bin")
  fail "a/big.bin posted and verified within $STEP4_TIMEOUT s" \
    "jq: ($REACHED) and ($COUNTED) and ($CONSISTENT), required=$REQUIRED" "$json"
fi
json=$(adm "GET /_admin/objects/$SB/a/big.bin" "$BASE/_admin/objects/$SB/a/big.bin")
log "a/big.bin verified $(($(now_ms) - t0)) ms after the step started:" \
  "$(jq -c '{extents: (.extents | length), stages: ([.extents[].stage] | group_by(.) | map({(.[0]): length}) | add),
    counting: ([.extents[].backbones[] | select(.counts) | .backbone] | group_by(.) | map({(.[0]): length}) | add),
    safety: ([.extents[].safety_state] | group_by(.) | map({(.[0]): length}) | add)}' <<<"$json")"

# ---------------------------------------------------------------------------
# 5 cold read: wipe CACHE + SAFETY (disposable bucket only), GET from NNTP
# ---------------------------------------------------------------------------

STEP=5-cold-read
log "step $STEP"
json=$(adm "POST /_admin/evict a/big.bin" -XPOST "$BASE/_admin/evict/$SB/a/big.bin?include_safety=1")
jcheck "evict removed blobs" '.evicted > 0' "$json"
log "evict: $(jq -c . <<<"$json")"
if [[ $MODE == remote ]]; then
  # Nothing but Usenet may hold the bytes now.
  jcheck "evict gave up every pinned copy" '.safety_kept == 0 and .safety_deleted == .evicted' "$json"
  json=$(adm "GET /_admin/objects/$SB/a/big.bin" "$BASE/_admin/objects/$SB/a/big.bin")
  jcheck "no extent in the cache before the cold GET" '.extents | length > 0 and all(.cache == "absent")' "$json"
fi
# NNTP BODY -> yEnc -> sha256 -> R2 refill -> decrypt
t0=$(now_ms)
run_aws "cold GET a/big.bin" "${S3[@]}" cp "s3://$SB/a/big.bin" "$T/cold-big.bin" >/dev/null
log "cold GET a/big.bin: $(($(now_ms) - t0)) ms for $(stat -c %s "$T/cold-big.bin") bytes"
same_bytes "cold GET a/big.bin equals the upload" "$T/big.bin" "$T/cold-big.bin"
json=$(adm "GET /_admin/objects/$SB/a/big.bin" "$BASE/_admin/objects/$SB/a/big.bin")
jcheck "every extent refilled into the cache" '.extents | length > 0 and all(.cache == "present")' "$json"

if [[ $MODE == remote ]]; then
  # 5b drill: read back from Usenet only, without the cache.
  STEP=5b-drill
  log "step $STEP"
  WANT_SHA=$(sha256sum <"$T/big.bin" | cut -c1-64)
  t0=$(now_ms)
  json=$(adm "POST /_admin/drill/$SB/a/big.bin" -XPOST "$BASE/_admin/drill/$SB/a/big.bin")
  log "drill: $(($(now_ms) - t0)) ms: $(jq -c . <<<"$json")"
  jcheck "drill reads the upload back from Usenet" \
    ".source == \"nntp\" and .match == true and .plaintext_sha256 == \"$WANT_SHA\"" "$json"
fi

# ---------------------------------------------------------------------------
# 5c move within the bucket (CopyObject, then DeleteObject of the source)
# ---------------------------------------------------------------------------

STEP=5c-move
SMALL_KEY=a/small.bin
# The shipped production vars keep SERVER_SIDE_COPY off; the dev ones turn
# it on. E2E_COPY=1 runs the step against a remote that has it on.
if [[ ${E2E_COPY:-$([[ $MODE == local ]] && echo 1 || echo 0)} == 1 ]]; then
  log "step $STEP"
  run_aws "MOVE a/small.bin to a/moved.bin" "${S3[@]}" mv "s3://$SB/a/small.bin" "s3://$SB/a/moved.bin" >/dev/null
  run_aws "GET a/moved.bin" "${S3[@]}" cp "s3://$SB/a/moved.bin" "$T/got-moved.bin" >/dev/null
  same_bytes "GET a/moved.bin equals the upload" "$T/small.bin" "$T/got-moved.bin"
  expect_err "HEAD a/small.bin after the move" '\(404\)' \
    "${S3API[@]}" head-object --bucket "$SB" --key a/small.bin
  SMALL_KEY=a/moved.bin
else
  log "step $STEP skipped (E2E_COPY is not 1)"
fi

# ---------------------------------------------------------------------------
# 6 delete
# ---------------------------------------------------------------------------

STEP=6-delete
log "step $STEP"
run_aws "DELETE $SMALL_KEY" "${S3[@]}" rm "s3://$SB/$SMALL_KEY" >/dev/null
expect_err "HEAD $SMALL_KEY after delete" '\(404\)' \
  "${S3API[@]}" head-object --bucket "$SB" --key "$SMALL_KEY"

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
  run_aws "PUT a/lost.bin" "${S3[@]}" cp "$T/small.bin" "s3://$SB/a/lost.bin" >/dev/null
  json=$(adm "GET /_admin/objects/$SB/a/lost.bin" "$BASE/_admin/objects/$SB/a/lost.bin")
  jcheck "a/lost.bin is committed but never enqueued" \
    '.extents | length > 0 and all(.stage == "post" and .attempts == 0)' "$json"
  # No queue delivery can move it: it stays at post until the cron runs.
  if poll 10 2 stage_moved lost.bin; then
    json=$(adm "GET /_admin/objects/$SB/a/lost.bin" "$BASE/_admin/objects/$SB/a/lost.bin")
    fail "a/lost.bin stays at post without a queue message" "stage post, 0 attempts for 10 s" "$json"
  fi
  cron_then_check() {
    curl -sf "${CURL_TLS[@]}" --max-time 60 "$BASE/__scheduled?cron=*/5+*+*+*+*" >/dev/null || return 1
    stage_reached lost.bin
  }
  # 180 s, not 90: provider slots held by sessions of the stopped isolate
  # stay claimed until their 120 s lease expires, and only then can the
  # re-driven post job get a connection.
  if ! poll 180 2 cron_then_check; then
    json=$(adm "GET /_admin/objects/$SB/a/lost.bin" "$BASE/_admin/objects/$SB/a/lost.bin")
    fail "a/lost.bin recovered by the scheduled handler within 180 s" "jq: ($REACHED) and ($COUNTED)" "$json"
  fi
else
  # The drop counter is dev-only: prove the real cron runs after deploy,
  # CRON_RUNS times, each run advancing last_dispatch_at.
  CRON_RUNS=${CRON_RUNS:-2}
  [[ $CRON_RUNS =~ ^[1-9][0-9]*$ ]] || fail "CRON_RUNS" "a positive integer" "$CRON_RUNS"
  json=$(adm "GET /_admin/status" "$BASE/_admin/status")
  SEEN=$(jq -r '.last_dispatch_at // 0' <<<"$json")
  log "last_dispatch_at before: $SEEN"
  dispatched_after() {
    local j
    j=$(adm_try "$BASE/_admin/status") || return 1
    jq -e --argjson t "$1" '(.last_dispatch_at // 0) > $t' >/dev/null 2>&1 <<<"$j" || return 1
  }
  for ((run = 1; run <= CRON_RUNS; run++)); do
    if ! poll 360 10 dispatched_after "$SEEN"; then
      json=$(adm "GET /_admin/status" "$BASE/_admin/status")
      fail "dispatcher run $run of $CRON_RUNS within 6 min" "last_dispatch_at > $SEEN" "$json"
    fi
    json=$(adm "GET /_admin/status" "$BASE/_admin/status")
    SEEN=$(jq -r '.last_dispatch_at' <<<"$json")
    log "dispatcher run $run of $CRON_RUNS: last_dispatch_at=$SEEN ($(date -u -d "@$((SEEN / 1000))" +%H:%M:%SZ))"
  done
  log "status: $(jq -c '{environment, gc_mode, required_backbones, real_data_ready, outbox, dead, last_dispatch_at}' <<<"$json")"
fi

STEP=finished
log "slice acceptance passed ($MODE, $BASE)"
