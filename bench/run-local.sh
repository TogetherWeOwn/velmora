#!/usr/bin/env bash
# run-local.sh: layer 1 of the benchmark, one command.
#
#   bench/run-local.sh [--ref <git ref>] [--name <name>] [--out <dir>] [--tiny <n>] [--late-queue] [--cpu <cpu.json>]
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
# <sha>-vars-<keys>-<hash>, apart from the plain run of the commit.
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
unset CDPATH

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
WORK=${BENCH_WORK:-/var/tmp/velmora-bench}
REF='' NAME='' OUT='' TINY='' CPU='' LATE=''
while (($#)); do
  case $1 in
    --ref) REF=$2; shift 2 ;;
    --name) NAME=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --tiny) TINY=$2; shift 2 ;;
    --late-queue) LATE=1; shift ;;
    --cpu) CPU=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
log() { printf '[bench %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
# The scratch directory holds the wrangler this script runs: it must be
# ours and closed to other users, or another local user could put code
# there that runs as us. A new one is made 700; an existing one of ours is
# closed to others (chmod go-w), and the wrangler install inside it is
# checked on its own below (owner, not writable by others).
while [[ $WORK == */ && $WORK != / ]]; do WORK=${WORK%/}; done
# Two first runs may race to make it: whichever loses goes on to the checks.
if [[ ! -e $WORK ]]; then mkdir -p -- "$(dirname -- "$WORK")"; mkdir -m 700 -- "$WORK" 2>/dev/null || true; fi
writable_by_others() { [[ -n $(find "$1" -maxdepth 0 -perm /022 2>/dev/null) ]]; }
if [[ -L $WORK || ! -d $WORK || ! -O $WORK ]]; then
  log "FAILED: $WORK is a symlink, not a directory or not owned by $(id -un)"; exit 1
fi
if writable_by_others "$WORK"; then
  log "closing $WORK to other users (chmod go-w)"; chmod go-w -- "$WORK"
fi
# What another user may have left there while it was open: anything near
# the top not owned by us is refused (the run opens paths there).
# (Another run may remove its scratch meanwhile: a vanished entry is no error.)
foreign=$(find "$WORK" -mindepth 1 -maxdepth 2 ! -user "$(id -u)" -print -quit 2>/dev/null || true)
if [[ -n $foreign ]]; then
  log "FAILED: $foreign in $WORK is not owned by $(id -un)"; exit 1
fi
WORK=$(cd -P -- "$WORK" && pwd)

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
# The readable part is the keys only (a value never reaches a name or the
# log); a hash of the whole value keeps two different values apart.
BV=${BENCH_VARS:-}
BV_KEYS=$(printf '%s' "$BV" | grep -oE '(^|,)[A-Z][A-Z0-9_]*=' | tr -d ',=' | paste -sd+ - || true)
AUTO_NAME=0
[[ -n $NAME || -n $OUT ]] || AUTO_NAME=1
if [[ -n ${BV//[[:space:]]/} && $AUTO_NAME == 1 ]]; then
  NAME="$SHA-vars-$(printf '%s' "$BV_KEYS" | cut -c1-60)-$(printf '%s' "$BENCH_VARS" | sha256sum | cut -c1-8)"
fi
# A --tiny run is named apart from the full run of the same commit.
if [[ -n $TINY && $AUTO_NAME == 1 ]]; then
  NAME="${NAME:-$SHA}-tiny$TINY"
fi
# So is a --late-queue run.
if [[ -n $LATE && $AUTO_NAME == 1 ]]; then
  NAME="${NAME:-$SHA}-late"
fi
NAME=${NAME:-$SHA}
OUT=${OUT:-$WORK/runs/$NAME}
mkdir -p "$OUT"
# One run at a time per output directory: two would mix their traces.
# The lock is on the directory itself (opened read-only): no file is
# created or followed.
# Where the filesystem cannot lock (some NFS setups), the run goes on and
# says so; only a lock held by another run stops it.
if command -v flock >/dev/null; then
  exec 8<"$OUT"
  rc=0; flock -n -E 75 8 || rc=$?
  if ((rc == 75)); then log "FAILED: another run writes $OUT"; exit 1; fi
  ((rc == 0)) || log "warning: $OUT cannot be locked here (flock rc $rc); not guarded against a second run"
fi
# The native run works in the checkout and cargo runs it from the package
# directory: every path handed on is absolute.
OUT=$(cd -- "$OUT" && pwd)
if [[ -n $CPU ]]; then
  [[ -f $CPU ]] || { log "FAILED: --cpu $CPU: no such file"; exit 1; }
  CPU=$(realpath -- "$CPU")
  case $CPU in "$OUT/results.json" | "$OUT/results.md") log "FAILED: --cpu is this run's own report"; exit 1 ;; esac
  # Checked before the run, not after it has replaced the measurements.
  python3 -I "$HERE/report.py" --check-cpu "$CPU" || { log "FAILED: --cpu $CPU"; exit 1; }
fi
log "measuring $NAME ($SRC) into $OUT${BV_KEYS:+ with BENCH_VARS keys $BV_KEYS}"

# Pinned wrangler (local D1 runtime), installed once per lockfile: runs of
# checkouts that pin different versions never share an install. One run
# installs at a time: two `npm ci` in one directory leave it half written.
NODE_DIR=$WORK/node-$(sha256sum "$REPO/workers/s3-bridge/package-lock.json" | cut -c1-12)
install_wrangler() {
  for d in "$NODE_DIR" "$NODE_DIR/node_modules"; do
    if [[ -e $d ]] && { [[ -L $d || ! -O $d ]] || writable_by_others "$d"; }; then
      log "FAILED: $d is a symlink, not owned by $(id -un) or writable by others"; exit 1
    fi
  done
  if ! cmp -s "$REPO/workers/s3-bridge/package-lock.json" "$NODE_DIR/package-lock.json" 2>/dev/null \
    || [[ ! -x $NODE_DIR/node_modules/.bin/wrangler ]]; then
    log "installing the pinned wrangler into $NODE_DIR"
    mkdir -p "$NODE_DIR"
    cp "$REPO/workers/s3-bridge/package.json" "$REPO/workers/s3-bridge/package-lock.json" "$NODE_DIR/"
    (cd "$NODE_DIR" && npm ci --no-audit --no-fund >/dev/null)
  fi
}
if command -v flock >/dev/null; then
  (flock 9; install_wrangler) 9>"$NODE_DIR.lock"
else
  install_wrangler
fi

t=$(date +%s)
(
  cd "$SRC"
  export CARGO_TARGET_DIR=$TARGET CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
  export VELMORA_BENCH_OUT=$OUT ${TINY:+VELMORA_BENCH_TINY=$TINY} ${LATE:+VELMORA_BENCH_LATE_QUEUE=1} VELMORA_BENCH_VARS=${BENCH_VARS:-}
  cargo test -q -p velmora-bridge --test bench_counts -- --ignored --exact bench_counts_full >"$OUT/cargo.log" 2>&1
) || { tail -n 40 "$OUT/cargo.log" >&2; log "FAILED: the native run (log: $OUT/cargo.log)"; exit 1; }
log "native run done in $(($(date +%s) - t)) s"
# New measurements are in: a report from an earlier run here must not sit
# beside them. (A run refused before this point leaves the old one.)
rm -f "$OUT/results.json" "$OUT/results.md"

t=$(date +%s)
D1_WORK=$(mktemp -d "$WORK/d1.XXXXXX")
NODE_DIR=$NODE_DIR node "$HERE/d1-replay.mjs" "$OUT/d1-trace.jsonl" "$SRC/workers/s3-bridge/migrations" \
  "$D1_WORK" "$OUT/d1.json" 2>"$OUT/replay.log" || { rm -rf "$D1_WORK"; cat "$OUT/replay.log" >&2; log "FAILED: the D1 replay"; exit 1; }
rm -rf "$D1_WORK"
log "D1 replay done in $(($(date +%s) - t)) s: $(tail -n 1 "$OUT/replay.log")"
gzip -f "$OUT/d1-trace.jsonl"

python3 -I "$HERE/report.py" "$OUT" --name "$NAME" ${CPU:+--cpu "$CPU"} >&2
echo "$OUT/results.md"
