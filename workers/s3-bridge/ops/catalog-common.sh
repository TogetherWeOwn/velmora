#!/usr/bin/env bash
# Shared checks for catalog-export.sh and catalog-import.sh.

# Wrangler 4.161.0 turns a remote R2 GET's HTTP 404 into null, then emits
# this exact error line. If the Wrangler pin changes, re-check this line.
# https://github.com/cloudflare/workers-sdk/blob/wrangler%404.161.0/packages/wrangler/src/cfetch/internal.ts#L276-L280
# https://github.com/cloudflare/workers-sdk/blob/wrangler%404.161.0/packages/wrangler/src/r2/object.ts#L153-L156
# Call only after a failed Wrangler GET. Strip ANSI colour before matching.
catalog_wrangler_get_is_404() {
  LC_ALL=C sed -E $'s/\033\\[[0-9;]*m//g' "$1" |
    grep -Fx '✘ [ERROR] The specified key does not exist.' >/dev/null
}

# Remove staged SQL and parts regardless of the result. On failure, leave
# only tool output in the separate private diagnostics directory.
catalog_cleanup() {
  local status=$1 logs
  rm -r -- "$WORK"
  if [[ -n ${LOG_DIR:-} ]]; then
    logs=("$LOG_DIR"/*.log)
    if (( status == 0 )) || [[ ! -e ${logs[0]} ]]; then
      rm -r -- "$LOG_DIR"
    else
      printf 'catalogue transfer logs kept in %s\n' "$LOG_DIR" >&2
    fi
  fi
}

# Limits are decimal, as published in the D1 platform limits table.
readonly D1_LIMITS_URL=https://developers.cloudflare.com/d1/platform/limits/
readonly D1_SQL_FILE_MAX_BYTES=5000000000 # Per batch, not per snapshot.
readonly D1_SQL_STATEMENT_MAX_BYTES=100000

catalog_part_max_bytes() { printf '300000000\n'; }

# Wrangler can print a presigned URL even on a successful transfer. Strip
# query strings in the pipe, before bytes reach a persistent diagnostic.
catalog_redact_log() {
  LC_ALL=C sed -E 's@(https?://[^?[:space:]"<>]+)\?[^[:space:]"<>]*@\1@g'
}

catalog_logged() {
  local log=$1
  shift
  "$@" </dev/null 2>&1 | catalog_redact_log >>"$log"
}

catalog_capture() {
  local output=$1 log=$2
  shift 2
  "$@" </dev/null 2>&1 >"$output" | catalog_redact_log >>"$log"
}

catalog_init_wrangler() {
  local pin version
  # The pinned CLI checks this independently of its console log level.
  export WRANGLER_WRITE_LOGS=false
  pin=$(jq -er '.packages["node_modules/wrangler"].version | strings | select(length > 0)' package-lock.json) ||
    { catalog_error 'could not read the Wrangler pin from package-lock.json'; return 1; }
  wrangler=./node_modules/.bin/wrangler
  if [[ ! -x $wrangler ]] || ! version=$("$wrangler" --version </dev/null 2>/dev/null) || [[ $version != "$pin" ]]; then
    catalog_error "Wrangler $pin must be installed locally; run npm ci"
  fi
}

# Keep the lock inode (do not unlink it after an operation). Locks exclude
# same-host invocations using the same TMPDIR and user, not remote writers.
catalog_lock() {
  local operation=$1 id=$2 key=$3 dir=${TMPDIR:-/tmp}/velmora-catalog-locks-$UID
  mkdir -p -- "$dir" || return 1
  if [[ ! -O $dir || ! -d $dir || -L $dir ]]; then
    catalog_error "invalid catalogue lock directory $dir"
    return 1
  fi
  exec {catalog_lock_fd}>"$dir/$operation-$key.lock" || return 1
  if ! flock -n "$catalog_lock_fd"; then
    catalog_error "another $operation of $id is running"
  fi
}

catalog_warn_at_sixty_percent() {
  local metric=$1 value=$2 limit=$3
  if (( value >= limit * 60 / 100 )); then
    printf 'catalog-export: WARNING %s %s is %s%% of %s (%s)\n' \
      "$metric" "$value" "$((100 * value / limit))" "$limit" "$D1_LIMITS_URL" >&2
  fi
}

catalog_test_limit() {
  local name=$1 ceiling=$2 limit
  limit=${!name-$ceiling}
  # Test overrides may only lower the caps. Validate before Bash arithmetic.
  if [[ ! $limit =~ ^[1-9][0-9]{0,9}$ ]] || (( limit > ceiling )); then
    printf '%s must be an integer from 1 to %s\n' "$name" "$ceiling" >&2
    return 1
  fi
  printf '%s\n' "$limit"
}

catalog_init_sql_limits() {
  catalog_sql_file_limit=
  if [[ ${VELMORA_TEST_SQL_FILE_BYTES+x} ]]; then
    catalog_sql_file_limit=$(catalog_test_limit VELMORA_TEST_SQL_FILE_BYTES "$D1_SQL_FILE_MAX_BYTES") || return 1
  fi
  catalog_sql_statement_limit=$(catalog_test_limit VELMORA_TEST_SQL_STATEMENT_BYTES "$D1_SQL_STATEMENT_MAX_BYTES")
}

catalog_error() {
  local command=${0##*/}
  printf '%s: %s\n' "${command%.sh}" "$*" >&2
  return 1
}

catalog_require_sqlite() {
  python3 -I -c 'import sqlite3' 2>/dev/null || catalog_error 'python3 requires sqlite3 support'
}

catalog_limit_error() {
  catalog_error "$*; this export could not be restored by catalog-import.sh"
}

catalog_check_sql_size() {
  # A validated manifest can still declare a number too large for Bash
  # arithmetic (jq may render it in scientific notation). Reject it too.
  if [[ ! $1 =~ ^[0-9]{1,18}$ ]]; then
    catalog_error "invalid SQL byte count: $1"
    return 1
  fi
  if [[ -n $catalog_sql_file_limit ]] && (( 10#$1 > catalog_sql_file_limit )); then
    catalog_limit_error "the SQL export is $1 bytes, over the $catalog_sql_file_limit bytes allowed for this test"
  fi
}

catalog_check_sql_statements() {
  local measurement longest line more observed
  measurement=$(python3 -I "$HERE/sql_longest_statement.py" "$1" "$catalog_sql_statement_limit") || return 1
  read -r longest line more <<<"$measurement"
  if (( longest > catalog_sql_statement_limit )); then
    observed=$longest
    if [[ $more == + ]]; then observed="at least $longest"; fi
    catalog_limit_error "statement starting at line $line is $observed bytes, over the D1 statement limit of $catalog_sql_statement_limit bytes"
  else
    printf '%s\n' "$longest"
  fi
}
