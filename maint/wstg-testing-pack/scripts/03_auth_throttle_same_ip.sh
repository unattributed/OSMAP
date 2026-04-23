#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "03-ip-throttle"

for i in $(seq 1 "${THROTTLE_ATTEMPTS}"); do
  curl -sS -o "attempt-${i}.html" -D "attempt-${i}.headers" -X POST "${TARGET_BASE_URL}${LOGIN_PATH}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=${EMAIL}" \
    --data-urlencode "password=wrongpass" \
    --data-urlencode "totp_code=123456"
  printf '%02d | http=%s | title=%s\n' "$i" "$(header_code "attempt-${i}.headers")" "$(html_title "attempt-${i}.html")"
  grep -Eoi 'Too many login attempts were observed\. Please try again later\.|The supplied credentials were not accepted\.' "attempt-${i}.html" | head -n1 || true
done

printf '\nSaved in %s\n' "$RUN_DIR"
