#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "20-idle-timeout-spotcheck"

perform_login cookies.txt login.headers login.body.html
printf '===== login.headers =====\n'
sed -n '1,40p' login.headers
for wait_time in 300 600 900 1200; do
  printf '\n===== sleeping %s seconds =====\n' "$wait_time"
  sleep "$wait_time"
  ts="$(date '+%F %T')"
  fetch_get "${MAILBOXES_PATH}" "probe-${wait_time}.html" "probe-${wait_time}.headers" cookies.txt
  printf '%s | wait=%s | http=%s | location=%s | title=%s\n' "$ts" "$wait_time" "$(header_code "probe-${wait_time}.headers")" "$(header_field "probe-${wait_time}.headers" location)" "$(html_title "probe-${wait_time}.html")"
  [[ "$(header_field "probe-${wait_time}.headers" location)" == '/login' ]] && break
done

printf '\nSaved in %s\n' "$RUN_DIR"
