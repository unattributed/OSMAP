#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "48-business-invalid-archive-mailbox"

BADBOX="WSTGBUS_INVALID_BOX_$(date +%s)"
perform_login cookies.txt login.headers login.body.html
fetch_get "${SETTINGS_PATH}" settings-pre.html settings-pre.headers cookies.txt
CSRF_SETTINGS="$(extract_first_csrf settings-pre.html)"
fetch_post_form "${SETTINGS_PATH}" settings-post.html settings-post.headers cookies.txt "${SETTINGS_PATH}" \
  --data-urlencode "csrf_token=${CSRF_SETTINGS}" \
  --data-urlencode 'html_display_preference=prefer_sanitized_html' \
  --data-urlencode "archive_mailbox_name=${BADBOX}"
fetch_get "${SETTINGS_PATH}" settings-after.html settings-after.headers cookies.txt
fetch_get "${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" message.html message.headers cookies.txt
MSG_CSRF="$(extract_first_csrf message.html)"
MSG_MAILBOX="$(extract_hidden_value message.html mailbox)"
MSG_UID="$(extract_hidden_value message.html uid)"
ARCHIVE_DEST="$(extract_hidden_value message.html destination_mailbox)"
fetch_post_form "${MESSAGE_MOVE_PATH}" archive-attempt.html archive-attempt.headers cookies.txt "${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" \
  --data-urlencode "csrf_token=${MSG_CSRF}" \
  --data-urlencode "mailbox=${MSG_MAILBOX}" \
  --data-urlencode "uid=${MSG_UID}" \
  --data-urlencode "destination_mailbox=${ARCHIVE_DEST}"

printf '===== settings-post.headers =====\n'
sed -n '1,60p' settings-post.headers
printf '\n===== BADBOX =====\n%s\n' "$BADBOX"
printf '\n===== settings-after hit =====\n'
grep -nF "$BADBOX" settings-after.html | sed -n '1,20p'
printf '\n===== message archive destination hit =====\n'
grep -nF "$BADBOX" message.html | sed -n '1,20p'
printf '\n===== archive-attempt.headers =====\n'
sed -n '1,60p' archive-attempt.headers
printf '\n===== archive-attempt title/body markers =====\n'
grep -Eoi '<title>[^<]+|service could not complete the request at this time|invalid|unavailable|moved_to=' archive-attempt.html | sed -n '1,40p'

printf '\nSaved in %s\n' "$RUN_DIR"
