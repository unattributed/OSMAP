#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "51-business-revoke-race"

perform_login cookies.txt login.headers login.body.html
fetch_get "${SESSIONS_PATH}" sessions-before.html sessions-before.headers cookies.txt
CSRF="$(extract_first_csrf sessions-before.html)"
TARGET_SESSION_ID="$(python3 -c 'from pathlib import Path; import re; html=Path("sessions-before.html").read_text(errors="ignore"); rows=re.findall(r"<tr><td><code>([^<]+)</code></td><td>([^<]+)</td>.*?</tr>", html, re.I|re.S); print(next((sid for sid,status in rows if status.strip().lower()=="active"), ""))')"
printf 'CSRF=%s\nTARGET_SESSION_ID=%s\n' "$CSRF" "$TARGET_SESSION_ID"

if [[ -n "$TARGET_SESSION_ID" ]]; then
  {
    curl -sS -o revoke1.html -D revoke1.headers -b cookies.txt -c cookies.txt \
      -X POST "${TARGET_BASE_URL}${SESSIONS_PATH}/revoke" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -H "Origin: ${TARGET_BASE_URL}" \
      -H "Referer: ${TARGET_BASE_URL}${SESSIONS_PATH}" \
      --data-urlencode "csrf_token=${CSRF}" \
      --data-urlencode "session_id=${TARGET_SESSION_ID}" &
    pid1=$!
    curl -sS -o revoke2.html -D revoke2.headers -b cookies.txt -c cookies.txt \
      -X POST "${TARGET_BASE_URL}${SESSIONS_PATH}/revoke" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -H "Origin: ${TARGET_BASE_URL}" \
      -H "Referer: ${TARGET_BASE_URL}${SESSIONS_PATH}" \
      --data-urlencode "csrf_token=${CSRF}" \
      --data-urlencode "session_id=${TARGET_SESSION_ID}" &
    pid2=$!
    wait "$pid1" "$pid2"
  }
fi

fetch_get "${SESSIONS_PATH}" sessions-after.html sessions-after.headers cookies.txt
printf '\n===== revoke1.headers =====\n'
sed -n '1,60p' revoke1.headers
printf '\n===== revoke2.headers =====\n'
sed -n '1,60p' revoke2.headers
printf '\n===== revoke1 markers =====\n'
grep -Eoi '<title>[^<]+|revoked|already revoked|invalid|forbidden|denied|sessions|login' revoke1.html | sed -n '1,40p'
printf '\n===== revoke2 markers =====\n'
grep -Eoi '<title>[^<]+|revoked|already revoked|invalid|forbidden|denied|sessions|login' revoke2.html | sed -n '1,40p'
printf '\n===== sessions-after hit =====\n'
grep -nF "$TARGET_SESSION_ID" sessions-after.html | sed -n '1,5p'

printf '\nSaved in %s\n' "$RUN_DIR"
