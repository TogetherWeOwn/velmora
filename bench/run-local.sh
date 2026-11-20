#!/usr/bin/env bash
# run-local.sh: layer 1 of the benchmark, one command.
#
#   bench/run-local.sh [--ref <git ref>] [--name <name>] [--out <dir>] [--tiny <n>] [--cpu <cpu.json>]
#
# Runs the scenario of crates/velmora-bridge/tests/bench_counts.rs (native
# rig, fake NNTP, the production [vars]), replays its D1 trace through the
# local D1 runtime for D1's own rows read and written, and writes
# <out>/results.json and <out>/results.md (bench/report.py).
#
# BENCH_VARS=KEY=VALUE,KEY=VALUE in the environment changes Worker
# variables for this run only (after the rig's own overrides; a value may
# hold commas, a new pair starts only at ",KEY="). The variables that run
# the rig itself (ENVIRONMENT, S3_HOST, NNTP_PROVIDERS, ADMIN_TOKEN, the
# KEKs) are refused, and so is a key the configuration never reads (a typo,
# or a variable the measured commit does not have). results.json records
# them under "bench_vars"; without --name or --out the run is named
# <sha>-vars-<BENCH_VARS>, apart from the plain run of the commit.
#
# --ref measures another commit with this checkout's harness: the ref is
# checked out in a temporary worktree, this checkout's
# tests/bench_counts.rs is copied into it, and the worktree is removed at
# the end. Without --ref the working tree itself is measured.
#
# Nothing here touches the network except `npm ci` (pinned by
# workers/s3-bridge/package-lock.json) on the first run. Scratch and build
# output go under $BENCH_WORK (default /var/tmp/velmora-bench); a --ref run
# has its own directory there (checkout and cargo target), removed at the
# end, so runs of the same ref may overlap.
set -euo pipefail
umask 022

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
WORK=${BENCH_WORK:-/var/tmp/velmora-bench}
REF='' NAME='' OUT='' TINY='' CPU=''
while (($#)); do
  case $1 in
    --ref) REF=$2; shift 2 ;;
    --name) NAME=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --tiny) TINY=$2; shift 2 ;;
    --cpu) CPU=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
log() { printf '[bench %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
mkdir -p "$WORK"

SRC=$REPO
RUN=''
# A --ref run works in a directory of its own (checkout and cargo target),
# removed at the end. Two runs of the same ref at the same time would
# otherwise remove each other's checkout and build.
cleanup() {
  [[ -n $RUN ]] || return 0
  git -C "$REPO" worktree remove --force "$RUN/src" 2>/dev/null || true
  rm -rf "$RUN"
}
trap cleanup EXIT
if [[ -n $REF ]]; then
  SHA=$(git -C "$REPO" rev-parse --short=7 "$REF^{commit}")
  RUN=$(mktemp -d "$WORK/run-$SHA.XXXXXX")
  SRC=$RUN/src
  git -C "$REPO" worktree add --detach "$SRC" "$SHA" >/dev/null \
    || { log "FAILED: no checkout of $REF ($SHA) in $SRC"; exit 1; }
  cp "$REPO/crates/velmora-bridge/tests/bench_counts.rs" "$SRC/crates/velmora-bridge/tests/bench_counts.rs"
  TARGET=$RUN/target
else
  SHA=$(git -C "$REPO" rev-parse --short=7 HEAD)
  [[ -z $(git -C "$REPO" status --porcelain --untracked-files=no) ]] || SHA="$SHA-dirty"
  TARGET=${CARGO_TARGET_DIR:-$WORK/target-worktree}
fi
# A BENCH_VARS run without --name or --out gets its own name, so it never
# overwrites the plain run of the same commit it is compared against.
# The readable part is cut at 60 characters; a hash of the whole value keeps
# two different values apart.
if [[ -n ${BENCH_VARS//[[:space:]]/} && -z $NAME && -z $OUT ]]; then
  NAME="$SHA-vars-$(printf '%s' "$BENCH_VARS" | tr -c 'A-Za-z0-9._=-' '_' | cut -c1-60)-$(printf '%s' "$BENCH_VARS" | sha256sum | cut -c1-8)"
fi
NAME=${NAME:-$SHA}
OUT=${OUT:-$WORK/runs/$NAME}
mkdir -p "$OUT"
log "measuring $NAME ($SRC) into $OUT${BENCH_VARS:+ with BENCH_VARS=$BENCH_VARS}"

# Pinned wrangler (local D1 runtime), installed once. One run installs at a
# time: two `npm ci` in one directory leave it half written.
NODE_DIR=$WORK/node
install_wrangler() {
  if ! cmp -s "$REPO/workers/s3-bridge/package-lock.json" "$NODE_DIR/package-lock.json" 2>/dev/null \
    || [[ ! -x $NODE_DIR/node_modules/.bin/wrangler ]]; then
    log "installing the pinned wrangler into $NODE_DIR"
    mkdir -p "$NODE_DIR"
    cp "$REPO/workers/s3-bridge/package.json" "$REPO/workers/s3-bridge/package-lock.json" "$NODE_DIR/"
    (cd "$NODE_DIR" && npm ci --no-audit --no-fund >/dev/null)
  fi
}
if command -v flock >/dev/null; then
  (flock 9; install_wrangler) 9>"$WORK/node.lock"
else
  install_wrangler
fi

t=$(date +%s)
(
  cd "$SRC"
  export CARGO_TARGET_DIR=$TARGET CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
  export VELMORA_BENCH_OUT=$OUT ${TINY:+VELMORA_BENCH_TINY=$TINY} VELMORA_BENCH_VARS=${BENCH_VARS:-}
  cargo test -q -p velmora-bridge --test bench_counts -- --ignored --exact bench_counts_full >"$OUT/cargo.log" 2>&1
) || { tail -n 40 "$OUT/cargo.log" >&2; log "FAILED: the native run (log: $OUT/cargo.log)"; exit 1; }
log "native run done in $(($(date +%s) - t)) s"

t=$(date +%s)
D1_WORK=$(mktemp -d "$WORK/d1.XXXXXX")
NODE_DIR=$NODE_DIR node "$HERE/d1-replay.mjs" "$OUT/d1-trace.jsonl" "$SRC/workers/s3-bridge/migrations" \
  "$D1_WORK" "$OUT/d1.json" 2>"$OUT/replay.log" || { rm -rf "$D1_WORK"; cat "$OUT/replay.log" >&2; log "FAILED: the D1 replay"; exit 1; }
rm -rf "$D1_WORK"
log "D1 replay done in $(($(date +%s) - t)) s: $(tail -n 1 "$OUT/replay.log")"
gzip -f "$OUT/d1-trace.jsonl"

python3 -I "$HERE/report.py" "$OUT" --name "$NAME" ${CPU:+--cpu "$CPU"} >&2
echo "$OUT/results.md"
