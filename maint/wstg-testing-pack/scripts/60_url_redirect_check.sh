#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "60-url-redirect-check"

perform_login cookies.txt login.headers login.body.html
ATT="${ATTACKER_URL}-url-redirect"
while read -r label route; do
  fetch_get "$route" "${label}.html" "${label}.headers" cookies.txt
  printf '\n===== %s =====\nroute=%s\nhttp=%s\ntitle=%s\nlocation=%s\n' "$label" "$route" "$(header_code "${label}.headers")" "$(html_title "${label}.html")" "$(header_field "${label}.headers" location)"
  printf '\n-- redirect sink hits --\n'
  grep -Eoin 'http-equiv=.refresh|window\.location|location\.href|location\.assign|location\.replace|window\.open|open\(|top\.location|self\.location|document\.location|url=|next=|return=|redirect=|continue=' "${label}.html" | sed -n '1,80p'
  printf '\n-- attacker reflection hits --\n'
  grep -Ein 'attacker\.invalid|wstg-url-redirect' "${label}.html" "${label}.headers" | sed -n '1,40p'
done <<EOF
login_next ${LOGIN_PATH}?next=${ATT}\&return=${ATT}\&redirect=${ATT}
mailboxes_next ${MAILBOXES_PATH}?next=${ATT}\&return=${ATT}\&redirect=${ATT}
compose_next ${COMPOSE_PATH}?next=${ATT}\&return=${ATT}\&redirect=${ATT}
message_next ${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}\&uid=${DEFAULT_MESSAGE_UID}\&next=${ATT}\&return=${ATT}\&redirect=${ATT}
login_hash ${LOGIN_PATH}\#${ATT}
mailboxes_hash ${MAILBOXES_PATH}\#${ATT}
compose_hash ${COMPOSE_PATH}\#${ATT}
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
