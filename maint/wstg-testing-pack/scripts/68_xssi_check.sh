#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "68-xssi-check"

perform_login cookies.txt login.headers login.body.html
while read -r label route; do
  curl -sS -o "${label}.auth.body" -D "${label}.auth.headers" -b cookies.txt -c cookies.txt \
    -H 'Accept: application/javascript, text/javascript, application/json, text/plain, */*' \
    -H 'Sec-Fetch-Dest: script' -H 'Sec-Fetch-Mode: no-cors' "${TARGET_BASE_URL}${route}"
  curl -sS -o "${label}.anon.body" -D "${label}.anon.headers" \
    -H 'Accept: application/javascript, text/javascript, application/json, text/plain, */*' \
    -H 'Sec-Fetch-Dest: script' -H 'Sec-Fetch-Mode: no-cors' "${TARGET_BASE_URL}${route}"
  printf '\n===== %s =====\nroute=%s\nauth_http=%s\nanon_http=%s\nauth_content_type=%s\nanon_content_type=%s\nauth_nosniff=%s\nauth_corp=%s\n' \
    "$label" "$route" "$(header_code "${label}.auth.headers")" "$(header_code "${label}.anon.headers")" \
    "$(header_field "${label}.auth.headers" content-type)" "$(header_field "${label}.anon.headers" content-type)" \
    "$(header_field "${label}.auth.headers" x-content-type-options)" "$(header_field "${label}.auth.headers" cross-origin-resource-policy)"
  printf '\n-- auth body prefix --\n'
  print_body_prefix "${label}.auth.body"
  printf '\n-- anon body prefix --\n'
  print_body_prefix "${label}.anon.body"
  printf '\n-- possible XSSI markers --\n'
  grep -Eoin '^\)\]\x27|^\]\}\x27|^[[:space:]]*[{[]|callback\(|jsonp|window\.|var[[:space:]]+[A-Za-z0-9_]+[[:space:]]*=|[A-Za-z0-9_]+\(' "${label}.auth.body" | sed -n '1,40p'
done <<EOF
mailboxes ${MAILBOXES_PATH}
sessions ${SESSIONS_PATH}
compose ${COMPOSE_PATH}
message ${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}\&uid=${DEFAULT_MESSAGE_UID}
attachment ${ATTACHMENT_PATH}?mailbox=${DEFAULT_MAILBOX}\&uid=${DEFAULT_MESSAGE_UID}\&part=${DEFAULT_ATTACHMENT_PART}
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
