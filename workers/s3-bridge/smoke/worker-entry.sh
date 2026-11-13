#!/usr/bin/env bash
# Worker entry smoke: ingress checks, then a signed PUT -> GET round trip.
#
#   smoke/worker-entry.sh <base-url> [dev-vars-file]
#
# Run against `npx wrangler@4 dev --env dev --local --port <p>` with a
# throwaway `.dev.vars`. The round trip needs the base URL's host:port to
# equal S3_HOST (the host clients sign), the S3 handlers and the admin
# routes; until those exist it prints SKIP and exits 0.
#
# Secrets never reach argv, `set -x` output or the log: the admin bearer
# and the S3 key live in 0600 temp files read by curl (`-H @file`, `-K`).
set -euo pipefail
set +x

BASE=${1:?usage: smoke/worker-entry.sh <base-url> [dev-vars-file]}
VARS=${2:-.dev.vars}
HOSTPORT=${BASE#*://}
HOSTPORT=${HOSTPORT%%/*}

TMP=$(mktemp -d)
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT
umask 077

printf 'Authorization: Bearer %s\n' "$(sed -n 's/^ADMIN_TOKEN=//p' "$VARS")" > "$TMP/admin.hdr"
printf 'Authorization: Bearer %s\n' "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$TMP/wrong.hdr"
# Shape-valid SigV4 header with a bogus signature: passes the presence gate only.
SIG='Authorization: AWS4-HMAC-SHA256 Credential=AKVLSMOKE0000000000/20261113/auto/s3/aws4_request, SignedHeaders=host, Signature=00'

fails=0
expect() { # label, want-status, want-code ('-' = any), curl args...
  local label=$1 want=$2 want_code=$3
  shift 3
  local got code
  got=$(curl -sS -o "$TMP/body" -w '%{http_code}' "$@")
  code=$(tr -d '\n' < "$TMP/body" | sed -n 's/.*<Code>\([^<]*\)<\/Code>.*/\1/p')
  if [[ $got == "$want" && ( $want_code == - || $code == "$want_code" ) ]]; then
    printf 'ok   %-58s %s %s\n' "$label" "$got" "${code:--}"
  else
    printf 'FAIL %-58s got %s %s, want %s %s\n' "$label" "$got" "${code:--}" "$want" "$want_code"
    fails=$((fails + 1))
  fi
}

echo "== ingress"
expect "unsigned GET object"                 403 AccessDenied "$BASE/smoke-bucket/key"
expect "unsigned GET / (service root)"       403 AccessDenied "$BASE/"
expect "unsigned PUT with body"              403 AccessDenied -X PUT --data-binary abcd "$BASE/smoke-bucket/key"
expect "unsigned POST ?uploads"              403 AccessDenied -X POST "$BASE/smoke-bucket/key?uploads"
expect "signed-shape PUT, no Content-Length" 411 MissingContentLength -X PUT -H "$SIG" \
  -H 'Transfer-Encoding: chunked' -H 'Expect:' --data-binary abcd "$BASE/smoke-bucket/key"
# The runtime itself refuses this one (plain 400) before the Worker runs.
expect "signed-shape PUT, merged Content-Length" 400 - -X PUT -H "$SIG" \
  -H 'Content-Length: 4, 4' -H 'Expect:' --data-binary abcd "$BASE/smoke-bucket/key"
expect "/_admin without bearer"              401 Unauthorized "$BASE/_admin/status"
expect "/_admin with wrong bearer"           403 AccessDenied -H @"$TMP/wrong.hdr" "$BASE/_admin/status"

# Declared length over the cap with the body withheld: the answer must
# arrive while the client has sent 16 bytes of 16777217.
echo "== oversized declared length, body withheld"
python3 -I - "$HOSTPORT" <<'PY' || fails=$((fails + 1))
import socket, sys, time
host, _, port = sys.argv[1].rpartition(":")
s = socket.create_connection((host, int(port)))
s.settimeout(10)
s.sendall((
    "PUT /smoke-bucket/key HTTP/1.1\r\nHost: %s\r\n"
    "Authorization: AWS4-HMAC-SHA256 Credential=AKVLSMOKE0000000000/20261113/auto/s3/aws4_request, SignedHeaders=host, Signature=00\r\n"
    "Content-Length: 16777217\r\nConnection: close\r\n\r\n" % sys.argv[1]).encode() + b"\0" * 16)
t0 = time.time()
try:
    data = s.recv(4096)
except socket.timeout:
    print("FAIL no answer within 10 s with the body withheld"); sys.exit(1)
line = data.split(b"\r\n", 1)[0].decode()
ok = line.startswith("HTTP/1.1 400") and b"EntityTooLarge" in data
print("%s 400 EntityTooLarge after %.3f s, 16 of 16777217 body bytes sent (%s)"
      % ("ok  " if ok else "FAIL", time.time() - t0, line))
sys.exit(0 if ok else 1)
PY

echo "== deployed_signed_put_get"
round_trip() {
  local bucket status
  bucket="smoke-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  status=$(curl -sS -o "$TMP/bucket.json" -w '%{http_code}' -H @"$TMP/admin.hdr" \
    -H 'content-type: application/json' -X POST \
    --data "{\"name\":\"$bucket\",\"disposable\":true}" "$BASE/_admin/buckets")
  if [[ $status == 501 ]]; then
    echo "SKIP deployed_signed_put_get: admin routes not implemented yet"
    return 0
  fi
  [[ $status == 2* ]] || { echo "FAIL create bucket: HTTP $status"; return 1; }
  status=$(curl -sS -o "$TMP/key.json" -w '%{http_code}' -H @"$TMP/admin.hdr" \
    -H 'content-type: application/json' -X POST \
    --data "{\"buckets\":[\"$bucket\"],\"perm\":\"rw\"}" "$BASE/_admin/keys")
  [[ $status == 2* ]] || { echo "FAIL create key: HTTP $status"; return 1; }
  jq -r '"user = \"" + .access_key_id + ":" + .secret_access_key + "\""' "$TMP/key.json" > "$TMP/s3.curlrc"
  rm -f "$TMP/key.json"
  head -c 1048577 /dev/urandom > "$TMP/obj"
  local key="dir/a%20b%2Bc.bin" sign=(--aws-sigv4 "aws:amz:auto:s3" -K "$TMP/s3.curlrc")
  status=$(curl -sS -o "$TMP/put.out" -w '%{http_code}' "${sign[@]}" -X PUT \
    -H "x-amz-content-sha256: $(sha256sum "$TMP/obj" | cut -d' ' -f1)" \
    --data-binary @"$TMP/obj" "$BASE/$bucket/$key")
  if [[ $status == 501 ]]; then
    echo "SKIP deployed_signed_put_get: S3 handlers not implemented yet"
    return 0
  fi
  [[ $status == 200 ]] || { echo "FAIL signed PUT: HTTP $status"; return 1; }
  status=$(curl -sS -o "$TMP/got" -w '%{http_code}' "${sign[@]}" \
    -H 'x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
    "$BASE/$bucket/$key")
  [[ $status == 200 ]] || { echo "FAIL signed GET: HTTP $status"; return 1; }
  cmp -s "$TMP/obj" "$TMP/got" || { echo "FAIL GET bytes differ from PUT"; return 1; }
  echo "ok   signed PUT then GET round-trips 1048577 bytes"
}
round_trip || fails=$((fails + 1))

if ((fails)); then
  echo "$fails check(s) failed"
  exit 1
fi
echo "all checks passed"
