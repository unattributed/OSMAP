#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "39-ssrf-sink-discovery"

perform_login cookies.txt login.headers login.body.html
while read -r label route; do
  fetch_get "$route" "${label}.html" "${label}.headers" cookies.txt
  printf '\n===== %s =====\nroute=%s\nhttp=%s\ntitle=%s\n' "$label" "$route" "$(header_code "${label}.headers")" "$(html_title "${label}.html")"
  printf '\n-- url-like input hits --\n'
  grep -Eoi '<input[^>]*(name|id)="[^"]*(url|uri|link|callback|redirect|target|webhook|src|href)[^"]*"[^>]*|<textarea[^>]*(url|uri|link|callback|redirect|target|webhook)[^>]*' "${label}.html" | sed -n '1,80p'
  printf '\n-- raw URL token hits --\n'
  grep -Eoin 'http://|https://|ftp://|file://|gopher://|dict://|ldap://|ldaps://|mailto:' "${label}.html" | sed -n '1,80p'
done <<EOF
settings ${SETTINGS_PATH}
compose ${COMPOSE_PATH}
sessions ${SESSIONS_PATH}
mailboxes ${MAILBOXES_PATH}
message ${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
