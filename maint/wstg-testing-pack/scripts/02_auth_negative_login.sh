#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "02-auth-negative"

while IFS='|' read -r label userval passval totpval; do
  curl -sS -o "${label}.html" -D "${label}.headers" -X POST "${TARGET_BASE_URL}${LOGIN_PATH}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=${userval}" \
    --data-urlencode "password=${passval}" \
    --data-urlencode "totp_code=${totpval}"
  printf '\n===== %s =====\n' "$label"
  printf 'http=%s\ntitle=%s\n' "$(header_code "${label}.headers")" "$(html_title "${label}.html")"
  grep -Eoi 'The supplied credentials were not accepted\.|Too many login attempts were observed\. Please try again later\.|Login Failed|Invalid Request|error' "${label}.html" | sed -n '1,20p'
done <<EOF
bad_user|does-not-exist@example.invalid|wrongpass|123456
bad_pass|${EMAIL}|wrongpass|123456
bad_totp|${EMAIL}|${TEST_PASSWORD:-wrongpass}|000000
empty_fields||| 
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
