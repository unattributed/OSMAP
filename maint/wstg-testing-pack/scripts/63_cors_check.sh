#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "63-cors-check"

perform_login cookies.txt login.headers login.body.html
while IFS='|' read -r route_label route; do
  for origin in ${CORS_TEST_ORIGINS}; do
    origin_label="$(printf '%s' "$origin" | sed 's/[^A-Za-z0-9]/_/g')"
    label="${origin_label}_${route_label}"
    curl -sS -o "${label}.get.body" -D "${label}.get.headers" -b cookies.txt -c cookies.txt -H "Origin: ${origin}" "${TARGET_BASE_URL}${route}"
    curl -sS -o /dev/null -D "${label}.options.headers" -X OPTIONS -b cookies.txt -c cookies.txt \
      -H "Origin: ${origin}" \
      -H 'Access-Control-Request-Method: GET' \
      -H 'Access-Control-Request-Headers: content-type' \
      "${TARGET_BASE_URL}${route}"
    printf '\n===== %s =====\norigin=%s\nroute=%s\nget_http=%s\noptions_http=%s\nget_acao=%s\nget_acac=%s\noptions_acao=%s\noptions_acac=%s\noptions_acam=%s\noptions_acah=%s\nget_vary=%s\n' \
      "$label" "$origin" "$route" \
      "$(header_code "${label}.get.headers")" "$(header_code "${label}.options.headers")" \
      "$(header_field "${label}.get.headers" access-control-allow-origin)" \
      "$(header_field "${label}.get.headers" access-control-allow-credentials)" \
      "$(header_field "${label}.options.headers" access-control-allow-origin)" \
      "$(header_field "${label}.options.headers" access-control-allow-credentials)" \
      "$(header_field "${label}.options.headers" access-control-allow-methods)" \
      "$(header_field "${label}.options.headers" access-control-allow-headers)" \
      "$(header_field "${label}.get.headers" vary)"
    printf '\n-- GET headers --\n'
    sed -n '1,40p' "${label}.get.headers"
    printf '\n-- OPTIONS headers --\n'
    sed -n '1,60p' "${label}.options.headers"
  done
done <<EOF
mailboxes|${MAILBOXES_PATH}
compose|${COMPOSE_PATH}
message|${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}\&uid=${DEFAULT_MESSAGE_UID}
attachment|${ATTACHMENT_PATH}?mailbox=${DEFAULT_MAILBOX}\&uid=${DEFAULT_MESSAGE_UID}\&part=${DEFAULT_ATTACHMENT_PART}
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
