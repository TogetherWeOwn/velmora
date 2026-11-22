#!/usr/bin/env bash
# WebDAV end to end, local: e2e/dav.sh
#
# Starts fakesrv, the storage Worker (workers/s3-bridge, `wrangler dev
# --env dev`) and this gateway (`wrangler dev --env dev`), bound through
# the storage Worker's `DavEntry` entrypoint over wrangler's local dev
# registry. Creates a bucket, an app password and an S3 key through the
# admin API, then:
#
#   1. the kind binding at the storage Worker's own door: the app password
#      is refused there, also with a forged entry marker; the S3 key is
#      refused by the gateway;
#   2. litmus (basic copymove props locks http), when LITMUS_ROOT points at
#      an unpacked litmus (usr/bin/litmus, usr/libexec/litmus, the neon
#      library under usr/lib);
#   3. rclone's webdav backend (vendor other): upload 1 MiB and 40 MiB
#      (40 MiB goes up in parts), list, check the bytes, server-side move
#      of a folder, delete;
#   4. the same bucket through S3 and WebDAV: the same names and sizes.
#
# Every result line goes to stdout; the run's numbers are in the last
# lines. Nothing it starts or writes outlives it. The throwaway admin
# token, KEK and keys exist for this run only and never reach the log.
#
# Environment:
#   FAKESRV_BIN   fakesrv binary (default: <target>/debug/fakesrv)
#   S3_PORT       storage Worker port (default 8787)
#   DAV_PORT      gateway port (default 8790)
#   LITMUS_ROOT   unpacked litmus (optional; litmus is skipped without it)
#   READY_TIMEOUT_SECS  wait for each `wrangler dev` (default 1200)

set -euo pipefail
set +x
umask 077

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DAV_DIR=$(cd "$HERE/.." && pwd)
REPO_DIR=$(cd "$DAV_DIR/../.." && pwd)
S3_DIR="$REPO_DIR/workers/s3-bridge"
S3_PORT=${S3_PORT:-8787}
DAV_PORT=${DAV_PORT:-8790}
S3="http://127.0.0.1:$S3_PORT"
DAV="http://127.0.0.1:$DAV_PORT"
BUCKET=dav-e2e
STEP=prereq
FAILS=0

log() { printf '[dav-e2e %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() {
  printf '\nDAV E2E FAILED at step %s: %s\n  expected: %s\n  actual:   %s\n\n' \
    "$STEP" "$1" "$2" "$(printf '%s' "$3" | head -c 2000)" >&2
  exit 1
}
# check <label> <want> <got>
check() {
  if [[ $2 == "$3" ]]; then
    printf 'ok   %-60s %s\n' "$1" "$3"
  else
    printf 'FAIL %-60s got %s, want %s\n' "$1" "$3" "$2"
    FAILS=$((FAILS + 1))
  fi
}

for tool in curl jq openssl rclone python3 npx; do
  command -v "$tool" >/dev/null || fail "prerequisite" "$tool on PATH" "not found"
done
TARGET_DIR=${CARGO_TARGET_DIR:-$REPO_DIR/target}
FAKESRV_BIN=${FAKESRV_BIN:-$TARGET_DIR/debug/fakesrv}
[[ -x $FAKESRV_BIN ]] || fail "prerequisite" "an executable fakesrv (FAKESRV_BIN)" "$FAKESRV_BIN"
[[ ! -e $S3_DIR/.dev.vars ]] || fail "workers/s3-bridge/.dev.vars" "absent" "a file exists; move it away first"
port_free() { ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for p in "$S3_PORT" "$DAV_PORT" "${FAKESRV_PORT:-11129}"; do
  port_free "$p" || fail "port $p" "free" "in use"
done

T=$(mktemp -d /tmp/velmora-dav-e2e.XXXXXX)
PIDS=()
SECRETS=()
stop_group() {
  local pid=$1
  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 50); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.1; done
  kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
}
cleanup() {
  local rc=$?
  set +e
  for pid in "${PIDS[@]}"; do stop_group "$pid"; done
  if [[ -e $S3_DIR/.dev.vars ]]; then
    rm -- "$S3_DIR/.dev.vars"
  fi
  rm -r -- "$T"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
wait_port() {
  local port=$1 pid=$2 log=$3 deadline=$((SECONDS + ${READY_TIMEOUT_SECS:-1200}))
  until port_open "$port"; do
    kill -0 "$pid" 2>/dev/null || { redacted_tail "$log"; fail "wrangler dev on $port" "running" "exited (log above)"; }
    ((SECONDS < deadline)) || { redacted_tail "$log"; fail "wrangler dev on $port" "answering" "no answer"; }
    sleep 2
  done
}

# ---------------------------------------------------------------------------
STEP=setup
KEK=$(openssl rand -base64 32)
ADMIN_TOKEN=$(openssl rand -hex 32)
NNTP_PASS=$(openssl rand -hex 16)
SECRETS=("$KEK" "$ADMIN_TOKEN" "$NNTP_PASS")
FAKESRV_PORT=${FAKESRV_PORT:-11129}
FAKESRV_USER=dav FAKESRV_PASS=$NNTP_PASS setsid "$FAKESRV_BIN" --listen "127.0.0.1:$FAKESRV_PORT" \
  --max-conns 2 >"$T/fakesrv.log" 2>&1 </dev/null &
PIDS+=($!)
{
  printf 'VELMORA_KEK_1=%s\n' "$KEK"
  printf 'ADMIN_TOKEN=%s\n' "$ADMIN_TOKEN"
  printf 'NNTP_PROVIDERS=[{"id":"fake1","host":"127.0.0.1","port":%s,"tls":false,"user":"dav","pass":"%s","backbone":"fake","post":true,"read":true,"max_conns":2,"max_ips":2}]\n' \
    "$FAKESRV_PORT" "$NNTP_PASS"
  printf 'S3_HOST=127.0.0.1:%s\n' "$S3_PORT"
  printf 'DEV_DROP_NOTIFY_N=0\n'
} >"$S3_DIR/.dev.vars"
printf 'Authorization: Bearer %s\n' "$ADMIN_TOKEN" >"$T/admin.hdr"
unset KEK NNTP_PASS

log "applying D1 migrations to a throwaway local state"
(cd "$S3_DIR" && npx --yes wrangler@4 d1 migrations apply velmora-catalog-dev --local --env dev \
  --persist-to "$T/state" >"$T/migrate.log" 2>&1 </dev/null) ||
  { redacted_tail "$T/migrate.log"; fail "d1 migrations apply" "exit 0" "non-zero"; }

log "starting the storage Worker on $S3_PORT (the first run compiles it)"
# `exec setsid`: the background job itself leads the new process group, so
# cleanup stops wrangler and workerd with it.
(cd "$S3_DIR" && exec setsid npx --yes wrangler@4 dev --env dev --local --ip 127.0.0.1 --port "$S3_PORT" \
  --persist-to "$T/state" --show-interactive-dev-session=false >"$T/s3.log" 2>&1 </dev/null) &
PIDS+=($!)
wait_port "$S3_PORT" "${PIDS[-1]}" "$T/s3.log"
log "starting the gateway on $DAV_PORT"
(cd "$DAV_DIR" && exec setsid npx --yes wrangler@4 dev --env dev --local --ip 127.0.0.1 --port "$DAV_PORT" \
  --var DAV_ENABLED:true --var "S3_HOST:127.0.0.1:$S3_PORT" --persist-to "$T/state" --show-interactive-dev-session=false \
  >"$T/dav.log" 2>&1 </dev/null) &
PIDS+=($!)
wait_port "$DAV_PORT" "${PIDS[-1]}" "$T/dav.log"

admin() { curl -sS -H @"$T/admin.hdr" -H 'content-type: application/json' "$@"; }
admin -o /dev/null -X POST "$S3/_admin/buckets" -d "{\"name\":\"$BUCKET\",\"disposable\":true}"
admin -o "$T/app.json" -X POST "$S3/_admin/keys" \
  -d "{\"buckets\":[\"$BUCKET\"],\"perm\":\"rw\",\"kind\":\"app_password\"}"
admin -o "$T/s3.json" -X POST "$S3/_admin/keys" -d "{\"buckets\":[\"$BUCKET\"],\"perm\":\"rw\"}"
APP_ID=$(jq -r .access_key_id "$T/app.json")
APP_SECRET=$(jq -r .secret "$T/app.json")
S3_ID=$(jq -r .access_key_id "$T/s3.json")
S3_SECRET=$(jq -r .secret "$T/s3.json")
SECRETS+=("$APP_SECRET" "$S3_SECRET")
[[ $APP_ID == APVL* && $S3_ID == AKVL* ]] || fail "admin keys" "an APVL and an AKVL key" "$APP_ID $S3_ID"
rm -- "$T/app.json" "$T/s3.json"

# rclone remotes, configured from the environment only.
export RCLONE_CONFIG="$T/rclone.conf"
: >"$RCLONE_CONFIG"
export RCLONE_CONFIG_DAV_TYPE=webdav RCLONE_CONFIG_DAV_URL="$DAV" RCLONE_CONFIG_DAV_VENDOR=other
export RCLONE_CONFIG_DAV_USER="$APP_ID"
RCLONE_CONFIG_DAV_PASS=$(printf '%s' "$APP_SECRET" | rclone obscure -)
export RCLONE_CONFIG_DAV_PASS
s3_remote() { # s3_remote <NAME> <id> <secret>
  export "RCLONE_CONFIG_$1_TYPE=s3" "RCLONE_CONFIG_$1_PROVIDER=Other" \
    "RCLONE_CONFIG_$1_ENDPOINT=$S3" "RCLONE_CONFIG_$1_ACCESS_KEY_ID=$2" \
    "RCLONE_CONFIG_$1_SECRET_ACCESS_KEY=$3" "RCLONE_CONFIG_$1_REGION=auto" \
    "RCLONE_CONFIG_$1_FORCE_PATH_STYLE=true"
}
s3_remote S3 "$S3_ID" "$S3_SECRET"
s3_remote APPS3 "$APP_ID" "$APP_SECRET"

# ---------------------------------------------------------------------------
STEP=1-kind-binding
code() { "$@" -s -o /dev/null -w '%{http_code}'; }
basic() { printf 'Authorization: Basic %s\n' "$(printf '%s:%s' "$1" "$2" | base64 -w0)" >"$T/basic.hdr"; }
basic "$APP_ID" "$APP_SECRET"
check "app password, WebDAV PROPFIND /" 207 "$(code curl -X PROPFIND -H @"$T/basic.hdr" -H 'Depth: 1' "$DAV/")"
basic "$S3_ID" "$S3_SECRET"
check "S3 key at the gateway" 401 "$(code curl -X PROPFIND -H @"$T/basic.hdr" -H 'Depth: 0' "$DAV/")"
basic "$APP_ID" "wrong"
check "wrong secret at the gateway" 401 "$(code curl -X PROPFIND -H @"$T/basic.hdr" -H 'Depth: 0' "$DAV/")"
out=$(rclone lsd APPS3: 2>&1 || true)
check "app password on the S3 entry point (rclone s3)" refused \
  "$(grep -q 'InvalidAccessKeyId' <<<"$out" && echo refused || echo "accepted: ${out:0:80}")"
out=$(rclone lsd APPS3: --header 'x-velmora-entry: webdav' 2>&1 || true)
check "app password with a forged entry marker" refused \
  "$(grep -q 'InvalidAccessKeyId' <<<"$out" && echo refused || echo "accepted: ${out:0:80}")"
out=$(rclone lsd S3: 2>&1 || true)
check "S3 key on the S3 entry point" "$BUCKET" "$(awk '{print $NF}' <<<"$out" | grep -x "$BUCKET" || echo "${out:0:80}")"

# ---------------------------------------------------------------------------
STEP=2-litmus
if [[ -n ${LITMUS_ROOT:-} ]]; then
  log "running litmus"
  set +e
  # litmus writes debug.log and child.log where it runs: in the temp dir.
  cd "$T"
  LD_LIBRARY_PATH="$LITMUS_ROOT/usr/lib/x86_64-linux-gnu" \
    HTDOCS="$LITMUS_ROOT/usr/share/litmus/htdocs" TESTROOT="$LITMUS_ROOT/usr/libexec/litmus" \
    sh "$LITMUS_ROOT/usr/bin/litmus" -k "$DAV/$BUCKET/" "$APP_ID" "$APP_SECRET" >"$T/litmus.log" 2>&1
  set -e
  cd "$REPO_DIR"
  for s in "${SECRETS[@]}"; do sed -i "s|$s|<redacted>|g" "$T/litmus.log"; done
  cat "$T/litmus.log"
  grep -E '^<- summary' "$T/litmus.log" | sed 's/^/litmus /'
  # Every group ran and none failed.
  clean=$(grep -cE "^<- summary for \`(basic|copymove|props|locks|http)': of [0-9]+ tests run: [0-9]+ passed, 0 failed" "$T/litmus.log" || true)
  check "litmus groups with 0 failures" 5 "$clean"
else
  echo "skip litmus (LITMUS_ROOT unset)"
fi

# ---------------------------------------------------------------------------
STEP=3-rclone-webdav
mkdir -p "$T/up/sub" "$T/down"
head -c $((1024 * 1024)) /dev/urandom >"$T/up/one.bin"
head -c $((40 * 1024 * 1024)) /dev/urandom >"$T/up/sub/forty.bin"
printf 'hello\n' >"$T/up/sub/"$'caf\xc3\xa9 & co.txt'
t0=$(date +%s.%N)
rclone copy "$T/up" DAV:$BUCKET/r --transfers 4 2>"$T/rclone.log" || { cat "$T/rclone.log"; fail "rclone copy up" "exit 0" "non-zero"; }
t1=$(date +%s.%N)
check "rclone webdav upload (41 MiB, 3 files)" ok ok
printf 'rclone upload seconds %.2f\n' "$(echo "$t1 - $t0" | bc)"
# 40 MiB went up in 16 MiB parts: a multipart ETag of 3 parts. The S3 key
# signs the HEAD (curl reads it from a 0600 config file, not argv).
printf 'user = "%s:%s"\n' "$S3_ID" "$S3_SECRET" >"$T/s3.curl"
etag=$(curl -sS -K "$T/s3.curl" --aws-sigv4 "aws:amz:auto:s3" -I "$S3/$BUCKET/r/sub/forty.bin" |
  tr -d '\r' | sed -n 's/^[Ee][Tt]ag: //p')
check "40 MiB stored in 3 parts (ETag suffix)" '-3"' "${etag: -3}"
check "rclone check (download and compare)" 0 "$(rclone check "$T/up" DAV:$BUCKET/r --download >/dev/null 2>&1; echo $?)"
rclone copy DAV:$BUCKET/r "$T/down" 2>/dev/null
check "downloaded bytes equal (forty.bin)" same "$(cmp -s "$T/up/sub/forty.bin" "$T/down/sub/forty.bin" && echo same || echo differ)"
check "listing (rclone lsf -R)" "one.bin sub/ sub/"$'caf\xc3\xa9 & co.txt'" sub/forty.bin" \
  "$(rclone lsf -R DAV:$BUCKET/r | sort | tr '\n' ' ' | sed 's/ $//')"
rclone moveto DAV:$BUCKET/r/sub DAV:$BUCKET/r/moved 2>"$T/rclone.log" || { cat "$T/rclone.log"; fail "rclone moveto" "exit 0" "non-zero"; }
check "folder moved" "moved/ one.bin" "$(rclone lsf DAV:$BUCKET/r | sort | tr '\n' ' ' | sed 's/ $//')"

# ---------------------------------------------------------------------------
STEP=4-two-views
dav_view=$(rclone lsjson -R --files-only DAV:$BUCKET/r | jq -r '.[] | "\(.Path) \(.Size)"' | sort)
s3_view=$(rclone lsjson -R --files-only S3:$BUCKET/r | jq -r '.[] | "\(.Path) \(.Size)"' | sort)
check "S3 and WebDAV list the same names and sizes" "$s3_view" "$dav_view"
rclone purge DAV:$BUCKET/r 2>/dev/null
check "purge through WebDAV leaves nothing in S3" "" "$(rclone lsf -R S3:$BUCKET/r 2>/dev/null)"

printf 'gateway log lines: %s; storage log lines: %s\n' "$(wc -l <"$T/dav.log")" "$(wc -l <"$T/s3.log")"
if ((FAILS > 0)); then
  redacted_tail "$T/dav.log"
  fail "checks" "0 failed" "$FAILS failed"
fi
echo "DAV E2E OK"
