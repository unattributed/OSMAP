#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "58-javascript-execution-check"

perform_login cookies.txt login.headers login.body.html
while read -r label route; do
  fetch_get "$route" "${label}.html" "${label}.headers" cookies.txt
  printf '\n===== %s =====\nroute=%s\nhttp=%s\ntitle=%s\n' "$label" "$route" "$(header_code "${label}.headers")" "$(html_title "${label}.html")"
  printf '\n-- exact script-like hits --\n'
  grep -Eoin '<script[[:space:]>]|</script>|on[a-z]+[[:space:]]*=|javascript:|data:text/html|srcdoc=|<iframe[[:space:]>]|<object[[:space:]>]|<embed[[:space:]>]' "${label}.html" | sed -n '1,80p'
  printf '\n-- exact JS sink hits --\n'
  grep -Eoin 'innerHTML|outerHTML|document\.write|document\.writeln|insertAdjacentHTML|eval\(|new Function|setTimeout\(|setInterval\(|location\.hash|location\.search|URLSearchParams|postMessage|localStorage|sessionStorage|indexedDB|WebSocket|fetch\(|XMLHttpRequest|navigator\.sendBeacon' "${label}.html" | sed -n '1,120p'
  printf '\n-- payload reflection hits --\n'
  grep -Ein 'javascript:alert\(1\)|WSTGJSX1|WSTGJSX2' "${label}.html" | sed -n '1,40p'
done <<EOF
login_qs ${LOGIN_PATH}?next=javascript:alert(1)\&wstg=WSTGJSX1
mailboxes_qs ${MAILBOXES_PATH}?next=javascript:alert(1)\&wstg=WSTGJSX1
compose_qs ${COMPOSE_PATH}?next=javascript:alert(1)\&wstg=WSTGJSX1
login_hash ${LOGIN_PATH}\#javascript:alert(1)-WSTGJSX2
mailboxes_hash ${MAILBOXES_PATH}\#javascript:alert(1)-WSTGJSX2
compose_hash ${COMPOSE_PATH}\#javascript:alert(1)-WSTGJSX2
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
