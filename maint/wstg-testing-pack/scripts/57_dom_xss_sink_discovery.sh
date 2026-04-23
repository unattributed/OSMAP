#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "57-dom-xss-sink-discovery"

perform_login cookies.txt login.headers login.body.html
while read -r label route; do
  fetch_get "$route" "${label}.html" "${label}.headers" cookies.txt
  printf '\n===== %s =====\nroute=%s\nhttp=%s\ntitle=%s\n' "$label" "$route" "$(header_code "${label}.headers")" "$(html_title "${label}.html")"
  printf '\n-- script and event handler hits --\n'
  grep -Eoin '<script|on[a-z]+="|javascript:|data:text/html|srcdoc=|<iframe|<object|<embed' "${label}.html" | sed -n '1,80p'
  printf '\n-- client-side sink hits --\n'
  grep -Eoin 'innerHTML|outerHTML|document.write|document.writeln|insertAdjacentHTML|eval\(|new Function|setTimeout\(|setInterval\(|location\.hash|location\.search|URLSearchParams|postMessage|localStorage|sessionStorage|indexedDB|WebSocket|fetch\(|XMLHttpRequest|navigator\.sendBeacon' "${label}.html" | sed -n '1,120p'
done <<EOF
login_page ${LOGIN_PATH}
mailboxes ${MAILBOXES_PATH}
settings ${SETTINGS_PATH}
sessions ${SESSIONS_PATH}
compose ${COMPOSE_PATH}
message ${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
