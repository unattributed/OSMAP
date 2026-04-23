#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed wc tr
setup_run_dir "52-business-session-count-limit"

prompt_secret TEST_PASSWORD 'Password: '
for n in 1 2 3; do
  totp="$(prompt_totp_once "TOTP session ${n}: ")"
  curl -sS -o "login${n}.body.html" -D "login${n}.headers" -c "cookies${n}.txt" -X POST "${TARGET_BASE_URL}${LOGIN_PATH}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=${EMAIL}" \
    --data-urlencode "password=${TEST_PASSWORD}" \
    --data-urlencode "totp_code=${totp}"
  consume_totp_env
  fetch_get "${SESSIONS_PATH}" "sessions${n}.html" "sessions${n}.headers" "cookies${n}.txt"
  count="$(grep -Eo '<td>(current|active)</td>' "sessions${n}.html" | wc -l | tr -d ' ')"
  printf '\n===== session %s =====\nlogin_http=%s\nlocation=%s\nactive_or_current_count=%s\n' "$n" "$(header_code "login${n}.headers")" "$(header_field "login${n}.headers" location)" "$count"
done

printf '\n===== count summary =====\n'
for n in 1 2 3; do
  count="$(grep -Eo '<td>(current|active)</td>' "sessions${n}.html" | wc -l | tr -d ' ')"
  printf 'session%s_count=%s\n' "$n" "$count"
done

printf '\nSaved in %s\n' "$RUN_DIR"
