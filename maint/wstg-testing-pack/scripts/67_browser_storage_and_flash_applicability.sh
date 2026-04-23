#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "67-browser-storage-and-flash"

perform_login cookies.txt login.headers login.body.html
printf '===== flash applicability probes =====\n'
while read -r label route; do
  curl -sS -o "${label}.body" -D "${label}.headers" "${TARGET_BASE_URL}${route}"
  printf '\n[%s] route=%s http=%s content_type=%s\n' "$label" "$route" "$(header_code "${label}.headers")" "$(header_field "${label}.headers" content-type)"
  sed -n '1,20p' "${label}.headers"
done <<'EOF'
crossdomain_xml /crossdomain.xml
clientaccesspolicy_xml /clientaccesspolicy.xml
flash_probe /flash.swf
EOF

printf '\n===== authenticated HTML storage scan =====\n'
while read -r label route; do
  fetch_get "$route" "${label}.html" "${label}.headers" cookies.txt
  printf '\n===== %s =====\nroute=%s\nhttp=%s\ntitle=%s\n' "$label" "$route" "$(header_code "${label}.headers")" "$(html_title "${label}.html")"
  printf '\n-- browser storage hits --\n'
  grep -Eoin 'localStorage|sessionStorage|indexedDB|openDatabase|document\.cookie|cookieStore|CacheStorage|caches\.|navigator\.storage|storage event' "${label}.html" | sed -n '1,120p'
  printf '\n-- inline persistence markers --\n'
  grep -Eoin 'remember|persist|saved locally|draft saved|autosave|offline|cache' "${label}.html" | sed -n '1,80p'
done <<EOF
login ${LOGIN_PATH}
mailboxes ${MAILBOXES_PATH}
compose ${COMPOSE_PATH}
settings ${SETTINGS_PATH}
sessions ${SESSIONS_PATH}
message ${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}\&uid=${DEFAULT_MESSAGE_UID}
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
