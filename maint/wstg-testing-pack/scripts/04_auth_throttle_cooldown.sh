#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "04-throttle-cooldown"

curl -sS -o prelock.html -D prelock.headers -X POST "${TARGET_BASE_URL}${LOGIN_PATH}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=${EMAIL}" \
  --data-urlencode "password=wrongpass" \
  --data-urlencode "totp_code=123456"
printf 'prelock_http=%s\n' "$(header_code prelock.headers)"
printf 'Sleeping %s seconds to observe cooldown window\n' "${COOLDOWN_SECONDS}"
sleep "${COOLDOWN_SECONDS}"
curl -sS -o postcooldown.html -D postcooldown.headers -X POST "${TARGET_BASE_URL}${LOGIN_PATH}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "username=${EMAIL}" \
  --data-urlencode "password=wrongpass" \
  --data-urlencode "totp_code=123456"
printf 'postcooldown_http=%s\ntitle=%s\n' "$(header_code postcooldown.headers)" "$(html_title postcooldown.html)"
grep -Eoi 'Too many login attempts were observed\. Please try again later\.|The supplied credentials were not accepted\.' postcooldown.html | sed -n '1,20p'

printf '\nSaved in %s\n' "$RUN_DIR"
