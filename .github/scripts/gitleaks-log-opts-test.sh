#!/usr/bin/env bash
# Regression test for the history scan's git log options.
#
# Usage: gitleaks-log-opts-test.sh <gitleaks-binary> <config> <log-opts>
# Needs git and jq.
#
# Builds a throwaway repository with two known bypasses of a plain
# `--log-opts=HEAD` history scan and asserts that <log-opts> catches both:
#   1. a secret in a file marked `-diff` in .gitattributes (git log -p prints
#      "Binary files differ" instead of the patch, so gitleaks sees nothing);
#   2. a secret added only while resolving a merge conflict (git log -p prints
#      no patch for merge commits by default).
# It also asserts that `HEAD` alone misses each case, so the test proves the
# options matter rather than passing on some unrelated finding.
#
# The scan uses <config> (the repo's .gitleaks.toml), so an allowlist there
# that hid these findings would fail this test too. The fake token is
# assembled at run time so this file itself is not a finding.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <gitleaks-binary> <config> <log-opts>" >&2
  exit 2
fi
gitleaks_bin="$1"
config="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
log_opts="$3"

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/gitleaks-log-opts-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# Fake GitHub PAT shape (rule github-pat). Clearly fake, never valid.
fake_token="ghp""_FakeTestSecretDoNotUse0123456789abcd"

new_repo() {
  local dir="$work/$1"
  git init -q -b main "$dir"
  git -C "$dir" config user.name "gitleaks test"
  git -C "$dir" config user.email "gitleaks-test@example.invalid"
  git -C "$dir" config commit.gpgsign false
  printf 'base\n' > "$dir/README"
  git -C "$dir" add README
  git -C "$dir" commit -q -m base
  printf '%s\n' "$dir"
}

# scan <repo> <log-opts> <file>: prints "<exit code> <n>", where n counts
# github-pat findings in <file> at the repo's HEAD commit. Exit code 1 alone
# is not proof: gitleaks also exits 1 on a scan error.
scan() {
  local rc=0 report="$work/report.json" head
  rm -f "$report"
  head="$(git -C "$1" rev-parse HEAD)"
  "$gitleaks_bin" git "$1" --redact --no-banner --log-level error \
    --exit-code 1 --log-opts="$2" --ignore-gitleaks-allow \
    --config "$config" \
    --gitleaks-ignore-path "$work/empty-ignore" \
    --report-format json --report-path "$report" >/dev/null 2>&1 || rc=$?
  local n=0
  if [ -s "$report" ]; then
    n="$(jq --arg f "$3" --arg c "$head" \
      '[.[] | select(.RuleID == "github-pat" and .File == $f and .Commit == $c)] | length' \
      "$report")"
  fi
  printf '%s %s\n' "$rc" "$n"
}
: > "$work/empty-ignore"

# Case 1: secret hidden behind a `-diff` attribute.
r1="$(new_repo diff-attr)"
printf 'creds.env -diff\n' > "$r1/.gitattributes"
git -C "$r1" add .gitattributes
git -C "$r1" commit -q -m attrs
printf 'TOKEN=%s\n' "$fake_token" > "$r1/creds.env"
git -C "$r1" add creds.env
git -C "$r1" commit -q -m creds

# Case 2: secret added only in a merge-conflict resolution.
r2="$(new_repo merge-resolution)"
printf 'value=base\n' > "$r2/conf"
git -C "$r2" add conf
git -C "$r2" commit -q -m conf
git -C "$r2" checkout -q -b side
printf 'value=side\n' > "$r2/conf"
git -C "$r2" commit -q -am side
git -C "$r2" checkout -q main
printf 'value=main\n' > "$r2/conf"
git -C "$r2" commit -q -am main
if git -C "$r2" merge -q side >/dev/null 2>&1; then
  echo "setup error: expected a merge conflict" >&2
  exit 2
fi
printf 'value=%s\n' "$fake_token" > "$r2/conf"
git -C "$r2" add conf
git -C "$r2" commit -q --no-edit
# Neither parent holds the token: only the resolution adds it.
for parent in HEAD^1 HEAD^2; do
  # Capture first: `git log | grep -q` can lose to SIGPIPE under pipefail.
  parent_log="$(git -C "$r2" log -p "$parent")"
  if grep -qF "$fake_token" <<<"$parent_log"; then
    echo "setup error: token reachable from $parent" >&2
    exit 2
  fi
done

fail=0
check() {
  local name="$1" repo="$2" file="$3" got
  got="$(scan "$repo" HEAD "$file")"
  if [ "$got" != "0 0" ]; then
    echo "FAIL $name: --log-opts=HEAD gave '$got' (exit, findings), expected '0 0' (the bypass no longer reproduces; test is not proving anything)"
    fail=1
  fi
  got="$(scan "$repo" "$log_opts" "$file")"
  if [ "$got" = "1 1" ]; then
    echo "ok   $name: caught with --log-opts=\"$log_opts\""
  else
    echo "FAIL $name: --log-opts=\"$log_opts\" gave '$got' (exit, findings), expected '1 1' (secret missed)"
    fail=1
  fi
}
check "-diff attribute" "$r1" creds.env
check "merge-conflict resolution" "$r2" conf
exit "$fail"
