#!/usr/bin/env bash
# Prove that vendor/tokio-postgres-0.7.18 is the crate published on
# crates.io (pinned SHA-256) plus exactly the changes in its upstream.diff.
# Not vendored (nothing here builds or runs them): the crate's own
# Cargo.lock, tests/ and benches/.
# Usage: vendor/check-tokio-postgres.sh [--write] [path/to/tokio-postgres-0.7.18.crate]
#   --write  regenerate upstream.diff instead of checking it (after a reviewed change).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
name=tokio-postgres-0.7.18
dir="$root/vendor/$name"
sha256=a528f7d280f6d5b9cd149635c8705b0dd049754bc67d81d31fa25169a93809d3
# The reviewed patch. A change to upstream.diff must change this line too,
# so it cannot pass review unseen.
diff_sha256=cbbd8c9208feb1e67a948e2a78c4b197b9a9f6979a7775eef005e0088ae931b0
write=0
if [ "${1:-}" = "--write" ]; then write=1; shift; fi
tmp=$(mktemp -d)
trap 'rm -r -- "$tmp"' EXIT
crate=${1:-}
if [ -z "$crate" ]; then
  crate="$tmp/$name.crate"
  curl -fsSL --connect-timeout 10 --max-time 60 --retry 3 -o "$crate" \
    "https://static.crates.io/crates/tokio-postgres/$name.crate"
fi
echo "$sha256  $crate" | sha256sum -c - >/dev/null
tar -xzf "$crate" -C "$tmp"
# Not vendored: nothing here builds or runs them.
rm -r -- "$tmp/$name/Cargo.lock" "$tmp/$name/tests" "$tmp/$name/benches"
# Relative paths and no timestamps, so the diff is the same on every host.
rc=0
(cd "$tmp" && cp -r "$dir" "vendored" && diff -ruN --exclude=VENDORED.md --exclude=upstream.diff \
  "$name" vendored) > "$tmp/raw.diff" || rc=$?
[ "$rc" -le 1 ] || { echo "diff failed ($rc)" >&2; exit 1; }
sed -E -e 's#^(---|\+\+\+) ([^\t]*)\t.*#\1 \2#' -e "s#(^| )$name/#\\1a/#g" -e 's#(^| )vendored/#\1b/#g' \
  "$tmp/raw.diff" > "$tmp/upstream.diff"
if [ "$write" = 1 ]; then
  cp "$tmp/upstream.diff" "$dir/upstream.diff"
  echo "wrote $dir/upstream.diff; set diff_sha256=$(sha256sum < "$dir/upstream.diff" | cut -d' ' -f1)"
  exit 0
fi
echo "$diff_sha256  $dir/upstream.diff" | sha256sum -c - >/dev/null || {
  echo "upstream.diff does not match the pinned diff_sha256" >&2
  exit 1
}
if ! cmp -s "$tmp/upstream.diff" "$dir/upstream.diff"; then
  echo "vendor/$name differs from crates.io $name plus upstream.diff:" >&2
  diff -u "$dir/upstream.diff" "$tmp/upstream.diff" >&2 || true
  exit 1
fi
echo "vendor/$name = crates.io $name (sha256 $sha256) + upstream.diff (sha256 $diff_sha256)"
