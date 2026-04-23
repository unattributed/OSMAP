#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "62-resource-manipulation-check"

perform_login cookies.txt login.headers login.body.html
ATT="${ATTACKER_URL}-resource"
while read -r label route; do
  fetch_get "$route" "${label}.html" "${label}.headers" cookies.txt
  printf '\n===== %s =====\nroute=%s\nhttp=%s\ntitle=%s\n' "$label" "$route" "$(header_code "${label}.headers")" "$(html_title "${label}.html")"
  printf '\n-- resource tag hits --\n'
  grep -Eoin '<img|<script|<link|<iframe|<object|<embed|<audio|<video|<source|<track|src=|href=|poster=' "${label}.html" | sed -n '1,80p'
  printf '\n-- attacker reflection hits --\n'
  grep -Ein 'attacker\.invalid|wstg-resource' "${label}.html" "${label}.headers" | sed -n '1,40p'
done <<EOF
login_qs ${LOGIN_PATH}?src=${ATT}\&href=${ATT}\&img=${ATT}
mailboxes_qs ${MAILBOXES_PATH}?src=${ATT}\&href=${ATT}\&img=${ATT}
compose_qs ${COMPOSE_PATH}?src=${ATT}\&href=${ATT}\&img=${ATT}
message_qs ${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}\&uid=${DEFAULT_MESSAGE_UID}\&src=${ATT}\&href=${ATT}\&img=${ATT}
login_hash ${LOGIN_PATH}\#${ATT}
mailboxes_hash ${MAILBOXES_PATH}\#${ATT}
compose_hash ${COMPOSE_PATH}\#${ATT}
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
