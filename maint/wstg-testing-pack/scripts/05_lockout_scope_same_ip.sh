#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "05-lockout-scope-same-ip"

OTHER_EMAIL="${OTHER_EMAIL:-other-user@example.invalid}"

for user in "${EMAIL}" "${OTHER_EMAIL}"; do
  slug="$(printf '%s' "$user" | tr -c 'A-Za-z0-9._-' '_')"
  curl -sS -o "${slug}.html" -D "${slug}.headers" -X POST "${TARGET_BASE_URL}${LOGIN_PATH}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=${user}" \
    --data-urlencode "password=wrongpass" \
    --data-urlencode "totp_code=123456"
  printf '%s | http=%s | title=%s\n' "$user" "$(header_code "${slug}.headers")" "$(html_title "${slug}.html")"
  grep -Eoi 'Too many login attempts were observed\. Please try again later\.|The supplied credentials were not accepted\.' "${slug}.html" | head -n1 || true
done

printf '\nSaved in %s\n' "$RUN_DIR"
