#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "64-clickjacking-check"

perform_login cookies.txt login.headers login.body.html
while read -r label route; do
  fetch_get "$route" "${label}.html" "${label}.headers" cookies.txt
  printf '\n===== %s =====\nroute=%s\nhttp=%s\ntitle=%s\nx_frame_options=%s\ncsp=%s\n' \
    "$label" "$route" "$(header_code "${label}.headers")" "$(html_title "${label}.html")" \
    "$(header_field "${label}.headers" x-frame-options)" "$(header_field "${label}.headers" content-security-policy)"
  printf '\n-- header dump --\n'
  sed -n '1,40p' "${label}.headers"
done <<EOF
login ${LOGIN_PATH}
mailboxes ${MAILBOXES_PATH}
compose ${COMPOSE_PATH}
settings ${SETTINGS_PATH}
sessions ${SESSIONS_PATH}
message ${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}\&uid=${DEFAULT_MESSAGE_UID}
attachment ${ATTACHMENT_PATH}?mailbox=${DEFAULT_MAILBOX}\&uid=${DEFAULT_MESSAGE_UID}\&part=${DEFAULT_ATTACHMENT_PART}
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
