#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "19-session-timeout-activity"

perform_login cookies.txt login.headers login.body.html
printf '===== login.headers =====\n'
sed -n '1,40p' login.headers
for i in $(seq 0 $((SESSION_PROBE_COUNT - 1))); do
  ts="$(date '+%F %T')"
  fetch_get "${MAILBOXES_PATH}" "probe-${i}.html" "probe-${i}.headers" cookies.txt
  printf '%02d | %s | http=%s | location=%s | title=%s\n' "$i" "$ts" "$(header_code "probe-${i}.headers")" "$(header_field "probe-${i}.headers" location)" "$(html_title "probe-${i}.html")"
  [[ "$(header_field "probe-${i}.headers" location)" == '/login' ]] && break
  sleep "${SESSION_PROBE_INTERVAL_SECONDS}"
done

printf '\nSaved in %s\n' "$RUN_DIR"
