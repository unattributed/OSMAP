#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "41-csv-sink-discovery"

perform_login cookies.txt login.headers login.body.html
while read -r label route; do
  fetch_get "$route" "${label}.html" "${label}.headers" cookies.txt
  printf '\n===== %s =====\nroute=%s\nhttp=%s\ntitle=%s\n' "$label" "$route" "$(header_code "${label}.headers")" "$(html_title "${label}.html")"
  printf '\n-- header hits --\n'
  grep -Eoi 'content-disposition:.*|content-type:.*(csv|tsv|spreadsheet|excel)' "${label}.headers" | sed -n '1,40p'
  printf '\n-- link or action hits --\n'
  grep -Eoi '(href|action)="[^"]*(csv|tsv|export|download|report|spreadsheet|excel)[^"]*"' "${label}.html" | sed -n '1,40p'
  printf '\n-- raw token hits --\n'
  grep -Eoin '(csv|tsv|export|download|report|spreadsheet|excel)' "${label}.html" | sed -n '1,40p'
done <<EOF
mailboxes ${MAILBOXES_PATH}
settings ${SETTINGS_PATH}
sessions ${SESSIONS_PATH}
compose ${COMPOSE_PATH}
mailbox_inbox ${MESSAGE_VIEW_PATH/\?*/}?mailbox=${DEFAULT_MAILBOX}
message_156 ${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
