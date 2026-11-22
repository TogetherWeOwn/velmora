#!/usr/bin/env bash
# The catalogue test suite on Durable Object SQLite in workerd:
# run-suite.sh [cargo test arguments]
#
# Builds this Worker, serves it with the pinned workerd (the binary that
# wrangler 4.161.0 ships, from ../s3-bridge/node_modules) on loopback
# ports, and runs the velmora-bridge tests with VELMORA_SQL_SHADOW
# pointing at them: every RusqliteSql of every test gets a fresh SQLite
# Durable Object behind DoSql, and every call is compared
# (crates/velmora-bridge/src/testkit_shadow.rs). workerd is run
# directly, not through `wrangler dev`: the dev proxy costs about 9 ms a
# call, workerd about 0.8 ms.
#
# Environment:
#   SUITE_PORT       first loopback port (default 18922)
#   SUITE_INSTANCES  workerd processes on consecutive ports (default 4);
#                    each test database lives in one of them
#   SUITE_PRIMARY    do (default): the tests get the object's answers;
#                    sqlite: they get SQLite's, the object is compared only
#   SUITE_REPORT     file for the summary (default: stdout only)
#   SUITE_KEEP       directory to keep the logs in (cargo, twin, workerd)
#   CARGO_TARGET_DIR and the other cargo variables are passed through.
#
# Without arguments every test target of velmora-bridge runs
# (`--no-fail-fast --lib --tests`). Then unit-smoke.py drives the unit's
# Durable Object class itself in the same workerd. The script exits
# non-zero when cargo or the smoke does, and also on any divergence, any
# twin it could not reach, and any twin that stopped being compared for
# a reason other than a state with broken foreign keys. The summary counts the databases, the calls
# compared, the twins rebuilt after a test changed its database behind
# the port (`with_conn`), and names the tests whose twin stopped.

set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
PORT=${SUITE_PORT:-18922}
INSTANCES=${SUITE_INSTANCES:-4}
PRIMARY=${SUITE_PRIMARY:-do}
WORKERD=$REPO/workers/s3-bridge/node_modules/@cloudflare/workerd-linux-64/bin/workerd

log() { printf '[unit-suite %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

for tool in cargo curl jq python3; do
  command -v "$tool" >/dev/null || { log "needs $tool on PATH"; exit 1; }
done

if [ ! -x "$WORKERD" ]; then
  log "installing the pinned deploy tooling (npm ci in workers/s3-bridge)"
  (cd "$REPO/workers/s3-bridge" && npm ci --silent)
fi

log "building the suite Worker"
(cd "$HERE" && cargo install -q --locked worker-build@0.8.7 && worker-build --release >&2)

RUN=$(mktemp -d "${TMPDIR:-/tmp}/velmora-unit-suite.XXXXXX")
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  if [ -n "${SUITE_KEEP:-}" ]; then
    mkdir -p "$SUITE_KEEP"
    cp "$RUN"/*.log "$SUITE_KEEP"/ 2>/dev/null || true
  fi
  rm -rf "$RUN"
}
trap cleanup EXIT

# One workerd configuration per process: its storage and its port.
config() {
  cat <<CAPNP
using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "main", worker = .suite),
    (name = "disk", disk = (path = "$RUN/do$1", writable = true)),
  ],
  sockets = [ (name = "http", address = "127.0.0.1:$2", http = (), service = "main") ],
);
const suite :Workerd.Worker = (
  modules = [
    (name = "index.js", esModule = embed "build/index.js"),
    (name = "index_bg.wasm", wasm = embed "build/index_bg.wasm"),
  ],
  compatibilityDate = "2026-11-01",
  durableObjectNamespaces = [
    (className = "SuiteDb", uniqueKey = "velmora-unit-suite", enableSql = true),
    (className = "UnitObject", uniqueKey = "velmora-unit-object", enableSql = true),
  ],
  durableObjectStorage = (localDisk = "disk"),
  bindings = [
    (name = "SUITE_DB", durableObjectNamespace = "SuiteDb"),
    (name = "UNIT", durableObjectNamespace = "UnitObject"),
  ],
);
CAPNP
}

# Every port must be free: a workerd left over from another run would
# answer the readiness check, and the run would test an old build.
for i in $(seq 0 $((INSTANCES - 1))); do
  if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$((PORT + i))/"; then
    log "port $((PORT + i)) already answers: stop the other run, or set SUITE_PORT"
    exit 1
  fi
done

cp -r "$HERE/build" "$RUN/build"
URLS=
for i in $(seq 0 $((INSTANCES - 1))); do
  port=$((PORT + i))
  mkdir -p "$RUN/do$i"
  config "$i" "$port" > "$RUN/suite$i.capnp"
  (cd "$RUN" && exec "$WORKERD" serve "suite$i.capnp" --experimental >"$RUN/workerd$i.log" 2>&1) &
  PIDS+=($!)
  URLS="${URLS:+$URLS,}http://127.0.0.1:$port"
done
log "workerd $("$WORKERD" --version): $INSTANCES processes from 127.0.0.1:$PORT"

for i in $(seq 0 $((INSTANCES - 1))); do
  ready=
  for _ in $(seq 1 100); do
    kill -0 "${PIDS[$i]}" 2>/dev/null || break
    if curl -sf --max-time 5 -X POST "http://127.0.0.1:$((PORT + i))/db/ready" \
        -d '{"op":"query","sql":"SELECT ?","params":[{"i":1}]}' | grep -q '"ok"'; then
      ready=1
      break
    fi
    sleep 0.2
  done
  if [ -z "$ready" ] || ! kill -0 "${PIDS[$i]}" 2>/dev/null; then
    log "workerd $i did not answer, or is not the one this run started"
    cat "$RUN/workerd$i.log" >&2
    exit 1
  fi
done

# The point-in-time bridge reaches the runtime's calls: workerd keeps no
# history, so a time and a restore are refused there (they work on
# Cloudflare), and a bookmark for now is given.
pitr=$(curl -sf --max-time 30 -X POST "http://127.0.0.1:$PORT/db/pitr-check" -d '{"op":"pitr"}' || true)
# Each of the two refusals is checked on its own field.
if ! printf '%s' "$pitr" | jq -e '.ok.current == true
    and (.ok.at | type == "string" and contains("does not implement point-in-time recovery"))
    and (.ok.restore | type == "string" and contains("does not implement point-in-time recovery"))' \
    >/dev/null 2>&1; then
  log "point-in-time bridge check failed: $pitr"
  exit 1
fi
log "point-in-time bridge: $pitr"

[ $# -gt 0 ] || set -- --no-fail-fast --lib --tests
status=0
log "cargo test -p velmora-bridge $* (primary: $PRIMARY)"
VELMORA_SQL_SHADOW="$URLS" \
VELMORA_SQL_SHADOW_PRIMARY="$PRIMARY" \
VELMORA_SQL_SHADOW_LOG="$RUN/shadow.log" \
  cargo test -p velmora-bridge "$@" 2>&1 | tee "$RUN/cargo.log" || status=$?

log "unit object smoke in workerd"
smoke=0
python3 -I "$HERE/unit-smoke.py" "http://127.0.0.1:$PORT" > "$RUN/smoke.log" 2>&1 || smoke=$?
cat "$RUN/smoke.log" >&2
[ "$smoke" -eq 0 ] || [ "$status" -ne 0 ] || status=$smoke

touch "$RUN/shadow.log"
# Lines of the twin log: DIVERGENCE / UNREACHABLE (written when they
# happen, so a panic that a test's own task swallowed still counts), and
# one line per database: test, twin, calls compared, status (in-sync,
# desynced:<reason>, diverged), rebuilds, plain EXPLAINs skipped, and
# calls that met a state with a broken foreign key (run on SQLite alone;
# the twin is rebuilt at the next whole state).
DB_LINES=$(grep -Ev '^(DIVERGENCE|UNREACHABLE)' "$RUN/shadow.log" || true)
divergences=$(grep -c '^DIVERGENCE' "$RUN/shadow.log" || true)
unreachable=$(grep -c '^UNREACHABLE' "$RUN/shadow.log" || true)
# A twin that stops being compared fails the run.
bad_desync=$(printf '%s\n' "$DB_LINES" | awk -F'\t' '$4 ~ /^desynced:/' | wc -l)
if [ "$divergences" -gt 0 ] || [ "$unreachable" -gt 0 ] || [ "$bad_desync" -gt 0 ]; then
  [ "$status" -ne 0 ] || status=3
fi
{
  echo "UNIT SUITE SUMMARY"
  echo "workerd: $("$WORKERD" --version) x $INSTANCES; primary: $PRIMARY; args: $*"
  { grep -E '^test result:' "$RUN/cargo.log" || true; } | awk '{p+=$4; f+=$6; i+=$8} END {printf "tests: %d passed, %d failed, %d ignored\n", p, f, i}'
  printf '%s\n' "$DB_LINES" | awk -F'\t' 'NF>=4 {n++; c+=$3; r+=$5; k+=$6; u+=$7} NF>=4 && $5>0 {rb++} END {printf "databases: %d; calls compared: %d; plain EXPLAINs skipped: %d; rebuilt after a change behind the port: %d databases, %d rebuilds; calls run on SQLite alone at a state with a broken foreign key: %d\n", n, c, k, rb+0, r+0, u+0}'
  echo "divergences: $divergences; twin unreachable: $unreachable"
  echo "tests with calls at a state with a broken foreign key (allowed):"
  printf '%s\n' "$DB_LINES" | awk -F'\t' '$7>0 {u[$1]+=$7} END {for (t in u) printf "  %6d %s\n", u[t], t}' | sort -rn
  echo "twins stopped (fail the run): $bad_desync"
  printf '%s\n' "$DB_LINES" | awk -F'\t' '$4 ~ /^desynced:/ {print "  " $1 " " $4}' | sort | uniq -c
  echo "failed tests:"
  grep -E '^test .* FAILED$' "$RUN/cargo.log" | sed 's/^/  /' || true
  echo "unit object smoke: $(tail -1 "$RUN/smoke.log")"
  echo "exit status: $status"
} | tee ${SUITE_REPORT:+"$SUITE_REPORT"}
exit "$status"
