#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "66-web-messaging-check"

perform_login cookies.txt login.headers login.body.html
while read -r label route; do
  fetch_get "$route" "${label}.html" "${label}.headers" cookies.txt
  printf '\n===== %s =====\nroute=%s\nhttp=%s\ntitle=%s\n' "$label" "$route" "$(header_code "${label}.headers")" "$(html_title "${label}.html")"
  printf '\n-- web messaging hits --\n'
  grep -Eoin 'postMessage|message[[:space:]]*=|onmessage|addEventListener\([[:space:]]*["'"'"']message["'"'"']|MessageChannel|BroadcastChannel|SharedWorker|ServiceWorker|navigator\.serviceWorker|clients\.matchAll|window\.parent|window\.opener|window\.top' "${label}.html" | sed -n '1,120p'
  printf '\n-- attacker reflection hits --\n'
  grep -Ein 'attacker\.invalid|wstg-postmessage' "${label}.html" "${label}.headers" | sed -n '1,40p'
done <<EOF
login ${LOGIN_PATH}
mailboxes ${MAILBOXES_PATH}
compose ${COMPOSE_PATH}
settings ${SETTINGS_PATH}
sessions ${SESSIONS_PATH}
message ${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}\&uid=${DEFAULT_MESSAGE_UID}
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
