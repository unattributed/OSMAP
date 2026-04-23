#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "53-business-workflow-circumvention-send"

perform_login cookies.txt login.headers login.body.html
fetch_get "${SETTINGS_PATH}" settings.html settings.headers cookies.txt
SETTINGS_CSRF="$(extract_first_csrf settings.html)"
printf 'SETTINGS_CSRF=%s\n' "$SETTINGS_CSRF"

curl -sS -o send-direct.html -D send-direct.headers -b cookies.txt -c cookies.txt \
  -X POST "${TARGET_BASE_URL}${SEND_PATH}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H "Origin: ${TARGET_BASE_URL}" \
  -H "Referer: ${TARGET_BASE_URL}${SETTINGS_PATH}" \
  --data-urlencode "csrf_token=${SETTINGS_CSRF}" \
  --data-urlencode "to=${INVALID_EMAIL}" \
  --data-urlencode 'subject=WSTG workflow bypass probe' \
  --data-urlencode 'body=workflow bypass probe only'

printf '\n===== send-direct.headers =====\n'
sed -n '1,60p' send-direct.headers
printf '\n===== send-direct markers =====\n'
grep -Eoi '<title>[^<]+|invalid|compose|sent|queued|request failed|forbidden|denied|mailboxes|login' send-direct.html | sed -n '1,40p'

printf '\nSaved in %s\n' "$RUN_DIR"
