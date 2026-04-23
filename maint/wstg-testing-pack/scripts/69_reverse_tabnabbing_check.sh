#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "69-reverse-tabnabbing-check"

perform_login cookies.txt login.headers login.body.html
while read -r label route; do
  fetch_get "$route" "${label}.html" "${label}.headers" cookies.txt
  printf '\n===== %s =====\nroute=%s\nhttp=%s\ntitle=%s\n' "$label" "$route" "$(header_code "${label}.headers")" "$(html_title "${label}.html")"
  printf '\n-- target blank hits --\n'
  grep -Eoin '<a[^>]*target="_blank"[^>]*' "${label}.html" | sed -n '1,80p'
  printf '\n-- rel protection hits --\n'
  grep -Eoin '<a[^>]*rel="[^"]*(noopener|noreferrer)[^"]*"[^>]*' "${label}.html" | sed -n '1,80p'
  printf '\n-- opener related JS hits --\n'
  grep -Eoin 'window\.open\(|\.opener\b|rel="opener"|target="_blank"' "${label}.html" | sed -n '1,120p'
done <<EOF
login ${LOGIN_PATH}
mailboxes ${MAILBOXES_PATH}
compose ${COMPOSE_PATH}
settings ${SETTINGS_PATH}
sessions ${SESSIONS_PATH}
message ${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}\&uid=${DEFAULT_MESSAGE_UID}
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
