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

# Use the smallest advertised one-file limit: D1's 5 GB, the import guide's
# 5 GiB, and R2's single PUT limit of 5 GiB minus 5 MiB.
# https://developers.cloudflare.com/d1/platform/limits/
# https://developers.cloudflare.com/d1/best-practices/import-export-data/
# https://developers.cloudflare.com/r2/platform/limits/
readonly D1_SQL_FILE_MAX_BYTES=5000000000
# D1's maximum SQL statement length, also listed in the D1 limits above.
readonly D1_SQL_STATEMENT_MAX_BYTES=100000

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
  catalog_sql_file_limit=$(catalog_test_limit VELMORA_TEST_SQL_FILE_BYTES "$D1_SQL_FILE_MAX_BYTES") || return 1
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
  if [[ ! $1 =~ ^[0-9]{1,10}$ ]] || (( 10#$1 > catalog_sql_file_limit )); then
    catalog_limit_error "the SQL export is $1 bytes, over the $catalog_sql_file_limit bytes one D1 import takes"
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
  fi
}
