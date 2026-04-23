#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "49-business-forge-request-revoke"

perform_login cookies.txt login.headers login.body.html
fetch_get "${SETTINGS_PATH}" settings.html settings.headers cookies.txt
SETTINGS_CSRF="$(extract_first_csrf settings.html)"
fetch_get "${SESSIONS_PATH}" sessions-before.html sessions-before.headers cookies.txt
TARGET_SESSION_ID="$(python3 - <<'PY'
from pathlib import Path
import re
html = Path("sessions-before.html").read_text(errors="ignore")
rows = re.findall(r'<tr><td><code>([^<]+)</code></td><td>([^<]+)</td>.*?</tr>', html, re.I | re.S)
chosen = ""
for sid, status in rows:
    s = status.strip().lower()
    if s == "active":
        chosen = sid
        break
print(chosen)
PY
)"
printf 'SETTINGS_CSRF=%s\nTARGET_SESSION_ID=%s\n' "$SETTINGS_CSRF" "$TARGET_SESSION_ID"
if [[ -n "$TARGET_SESSION_ID" ]]; then
  fetch_post_form "${SESSIONS_PATH}/revoke" revoke-response.html revoke-response.headers cookies.txt "${SETTINGS_PATH}" \
    --data-urlencode "csrf_token=${SETTINGS_CSRF}" \
    --data-urlencode "session_id=${TARGET_SESSION_ID}"
  fetch_get "${SESSIONS_PATH}" sessions-after.html sessions-after.headers cookies.txt
fi
printf '\n===== revoke-response.headers =====\n'
sed -n '1,60p' revoke-response.headers
printf '\n===== revoke-response markers =====\n'
grep -Eoi '<title>[^<]+|revoked|already revoked|invalid|forbidden|denied|sessions' revoke-response.html | sed -n '1,40p'
printf '\n===== sessions-after hit =====\n'
grep -nF "$TARGET_SESSION_ID" sessions-after.html | sed -n '1,5p'

printf '\nSaved in %s\n' "$RUN_DIR"
