#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "71-api-reconnaissance"

perform_login cookies.txt login.headers login.body.html
printf '===== authenticated API and JSON probe =====\n'
while read -r label route; do
  curl -sS -o "${label}.body" -D "${label}.headers" -b cookies.txt -c cookies.txt \
    -H 'Accept: application/json, application/*+json, text/plain, */*' "${TARGET_BASE_URL}${route}"
  printf '\n===== %s =====\nroute=%s\nhttp=%s\ncontent_type=%s\n' "$label" "$route" "$(header_code "${label}.headers")" "$(header_field "${label}.headers" content-type)"
  printf '\n-- header dump --\n'
  sed -n '1,40p' "${label}.headers"
  printf '\n-- body prefix --\n'
  print_body_prefix "${label}.body"
done <<'EOF'
root_api /api
openapi_json /openapi.json
swagger_json /swagger.json
api_v1 /api/v1
api_me /api/me
api_mailboxes /api/mailboxes
api_messages /api/messages
api_sessions /api/sessions
api_search /api/search?q=INBOX
well_known_openid /.well-known/openid-configuration
well_known_security /.well-known/security.txt
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
