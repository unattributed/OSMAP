#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed wc tr
setup_run_dir "23-concurrent-sessions-baseline"

prompt_secret TEST_PASSWORD 'Password: '
for n in 1 2; do
  totp="$(prompt_totp_once "TOTP session ${n}: ")"
  curl -sS -o "login${n}.body.html" -D "login${n}.headers" -c "cookies${n}.txt" -X POST "${TARGET_BASE_URL}${LOGIN_PATH}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=${EMAIL}" \
    --data-urlencode "password=${TEST_PASSWORD}" \
    --data-urlencode "totp_code=${totp}"
  consume_totp_env
  fetch_get "${SESSIONS_PATH}" "sessions${n}.html" "sessions${n}.headers" "cookies${n}.txt"
done

S1="$(session_cookie_value cookies1.txt)"
S2="$(session_cookie_value cookies2.txt)"
C1="$(grep -Eoc 'name="session_id" value="[^"]+"' sessions1.html || true)"
C2="$(grep -Eoc 'name="session_id" value="[^"]+"' sessions2.html || true)"
printf '===== session cookies =====\nsession1_cookie=%s\nsession2_cookie=%s\nsame_cookie=%s\n' "$S1" "$S2" "$( [[ "$S1" == "$S2" ]] && echo yes || echo no )"
printf '\n===== sessions summary =====\nsession1_visible_entries=%s\nsession2_visible_entries=%s\n' "$C1" "$C2"

printf '\nSaved in %s\n' "$RUN_DIR"
