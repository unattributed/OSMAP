#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "18-reset-archive-mailbox"

perform_login cookies.txt login.headers login.body.html
fetch_get "${SETTINGS_PATH}" settings-before.html settings-before.headers cookies.txt
CSRF="$(extract_first_csrf settings-before.html)"
fetch_post_form "${SETTINGS_PATH}" settings-post.html settings-post.headers cookies.txt "${SETTINGS_PATH}" \
  --data-urlencode "csrf_token=${CSRF}" \
  --data-urlencode 'html_display_preference=prefer_sanitized_html' \
  --data-urlencode "archive_mailbox_name=${DEFAULT_ARCHIVE_MAILBOX}"
fetch_get "${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" mailbox.html mailbox.headers cookies.txt

printf '===== login.headers =====\n'
sed -n '1,40p' login.headers
printf '\n===== settings-post.headers =====\n'
sed -n '1,80p' settings-post.headers
printf '\n===== mailbox archive markers =====\n'
grep -Eo 'Archive shortcut sends messages from this mailbox to <strong>[^<]+' mailbox.html | sed -n '1,20p'

printf '\nSaved in %s\n' "$RUN_DIR"
