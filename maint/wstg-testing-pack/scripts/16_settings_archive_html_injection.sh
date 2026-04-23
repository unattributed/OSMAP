#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "16-settings-archive-html-encoding"

PAYLOAD='WSTG_ARCH_"><X&Y'\''Z'
perform_login cookies.txt login.headers login.body.html
fetch_get "${SETTINGS_PATH}" settings-before.html settings-before.headers cookies.txt
CSRF="$(extract_first_csrf settings-before.html)"
fetch_post_form "${SETTINGS_PATH}" settings-post.html settings-post.headers cookies.txt "${SETTINGS_PATH}" \
  --data-urlencode "csrf_token=${CSRF}" \
  --data-urlencode 'html_display_preference=prefer_sanitized_html' \
  --data-urlencode "archive_mailbox_name=${PAYLOAD}"
fetch_get "${SETTINGS_PATH}" settings-after.html settings-after.headers cookies.txt
fetch_get "${MAILBOXES_PATH}" mailboxes-after.html mailboxes-after.headers cookies.txt
fetch_get "${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" inbox-message.html inbox-message.headers cookies.txt

printf '===== settings-post.headers =====\n'
sed -n '1,80p' settings-post.headers
printf '\n===== payload =====\n%s\n' "$PAYLOAD"
python3 - <<'PY'
from pathlib import Path
payload_tokens = ["WSTG_ARCH_", "X&Y'Z"]
for name in ["settings-after.html", "mailboxes-after.html", "inbox-message.html"]:
    html = Path(name).read_text(errors="ignore")
    print(f"\n===== {name} =====")
    for token in payload_tokens:
        pos = html.find(token)
        if pos != -1:
            start = max(0, pos - 220)
            end = min(len(html), pos + 260)
            print(html[start:end])
    for marker in ["&quot;", "&#39;", "&lt;", "&gt;", "&amp;"]:
        if marker in html:
            print(f"found entity {marker}")
PY

printf '\nSaved in %s\n' "$RUN_DIR"
