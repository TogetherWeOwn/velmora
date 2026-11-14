#!/usr/bin/env bash
# Sets the Worker's KEK secrets from the escrow file:
#   ops/kek-restore.sh <escrow file> [wrangler args, e.g. --env dev]
#
# The escrow file is the one written when the KEK was generated: mode
# 0600, one `VELMORA_KEK_<version>=<base64 of 32 bytes>` line per KEK
# version. Each value goes to `wrangler secret put` on stdin; it is never
# in argv, in the environment of a child, or in this script's output.
#
# The file is parsed, not sourced. A line that is not a KEK line, or a
# value that is not 32 bytes of base64, stops the script before any
# secret is set.

set -euo pipefail
set +x
umask 077

FILE=${1:?usage: ops/kek-restore.sh <escrow file> [wrangler args]}
shift
[ -f "$FILE" ] || { echo "kek-restore: no such file" >&2; exit 1; }
[ "$(stat -c %a "$FILE")" = 600 ] || { echo "kek-restore: the escrow file must have mode 0600" >&2; exit 1; }

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$HERE/.."

names=()
n=0
while IFS= read -r line || [ -n "$line" ]; do
  n=$((n + 1))
  case "$line" in '' | '#'*) continue ;; esac
  name=${line%%=*}
  if ! [[ "$name" =~ ^VELMORA_KEK_[1-9][0-9]*$ ]] || [ "$name" = "$line" ]; then
    echo "kek-restore: line $n is not VELMORA_KEK_<version>=<value>" >&2
    exit 1
  fi
  # 32 bytes of base64: 43 characters and one pad.
  if ! [[ "${line#*=}" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    echo "kek-restore: the value of $name is not base64 of 32 bytes" >&2
    exit 1
  fi
  names+=("$name")
done <"$FILE"
[ "${#names[@]}" -gt 0 ] || { echo "kek-restore: the file names no KEK" >&2; exit 1; }

LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT
for name in "${names[@]}"; do
  # The value goes to wrangler on stdin.
  if ! sed -n "s/^$name=//p" "$FILE" | head -n 1 | tr -d '\r\n' |
    npx wrangler secret put "$name" "$@" >"$LOG" 2>&1; then
    echo "kek-restore: wrangler secret put $name failed:" >&2
    grep -v -e '^$' "$LOG" | tail -n 10 >&2
    exit 1
  fi
  echo "kek-restore: set $name"
done
