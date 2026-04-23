#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "54-business-application-misuse-send-repeat"

perform_login cookies.txt login.headers login.body.html
fetch_get "${COMPOSE_PATH}" compose.html compose.headers cookies.txt
CSRF="$(extract_first_csrf compose.html)"
printf 'CSRF=%s\n' "$CSRF"

for i in 1 2 3 4 5 6 7 8; do
  curl -sS -o "send-${i}.html" -D "send-${i}.headers" -b cookies.txt -c cookies.txt \
    -X POST "${TARGET_BASE_URL}${SEND_PATH}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H "Origin: ${TARGET_BASE_URL}" \
    -H "Referer: ${TARGET_BASE_URL}${COMPOSE_PATH}" \
    --data-urlencode "csrf_token=${CSRF}" \
    --data-urlencode "to=${INVALID_EMAIL}" \
    --data-urlencode "subject=WSTG misuse probe ${i}" \
    --data-urlencode 'body=misuse probe only'
  printf '%02d | http=%s | len=%s | title=%s\n' "$i" "$(header_code "send-${i}.headers")" "$(header_field "send-${i}.headers" content-length)" "$(html_title "send-${i}.html")"
  sleep "${SHORT_SLEEP_SECONDS}"
done

fetch_get "${MAILBOXES_PATH}" post-check.html post-check.headers cookies.txt
printf '\n===== post-check.headers =====\n'
sed -n '1,60p' post-check.headers
printf '\n===== post-check.title =====\n'
printf '<title>%s\n' "$(html_title post-check.html)"
printf '\n===== error markers from final send =====\n'
grep -Eoi 'invalid|request failed|compose|forbidden|denied|too many|rate|temporarily|unavailable|login' send-8.html | sed -n '1,40p'

printf '\nSaved in %s\n' "$RUN_DIR"
