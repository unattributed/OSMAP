#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "01-baseline"

curl -sS -o login-page.html -D login-page.headers "${TARGET_BASE_URL}${LOGIN_PATH}"
printf '===== login page =====\n'
printf 'http=%s\ntitle=%s\n' "$(header_code login-page.headers)" "$(html_title login-page.html)"
sed -n '1,40p' login-page.headers

perform_login cookies.txt login.headers login.body.html
printf '\n===== login submit =====\n'
printf 'http=%s\nlocation=%s\n' "$(header_code login.headers)" "$(header_field login.headers location)"
sed -n '1,40p' login.headers

while read -r label route; do
  fetch_get "$route" "${label}.html" "${label}.headers" cookies.txt
  printf '\n===== %s =====\n' "$label"
  printf 'route=%s\nhttp=%s\ntitle=%s\n' "$route" "$(header_code "${label}.headers")" "$(html_title "${label}.html")"
done <<EOF
mailboxes ${MAILBOXES_PATH}
sessions ${SESSIONS_PATH}
settings ${SETTINGS_PATH}
compose ${COMPOSE_PATH}
message ${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}
attachment ${ATTACHMENT_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}&part=${DEFAULT_ATTACHMENT_PART}
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
