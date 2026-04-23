#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "50-business-integrity-message-move"

perform_login cookies.txt login.headers login.body.html
fetch_get "${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" message.html message.headers cookies.txt
MSG_CSRF="$(extract_first_csrf message.html)"
REAL_MAILBOX="$(extract_hidden_value message.html mailbox)"
REAL_MSG_UID="$(extract_hidden_value message.html uid)"
DEST="${DEFAULT_ARCHIVE_MAILBOX}"

printf 'MSG_CSRF=%s\nREAL_MAILBOX=%s\nREAL_MSG_UID=%s\nDEST=%s\n' "$MSG_CSRF" "$REAL_MAILBOX" "$REAL_MSG_UID" "$DEST"
printf '%s\n' \
  "tamper_mailbox|Junk|${REAL_MSG_UID}|${DEST}" \
  "tamper_uid|${REAL_MAILBOX}|100156|${DEST}" \
  "tamper_both|Junk|100156|${DEST}" \
  "tamper_uid_alpha|${REAL_MAILBOX}|abc|${DEST}" \
  "tamper_destination_empty|${REAL_MAILBOX}|${REAL_MSG_UID}|" > cases.txt

while IFS='|' read -r label mbox uidval destbox; do
  curl -sS -o "${label}.html" -D "${label}.headers" -b cookies.txt -c cookies.txt \
    -X POST "${TARGET_BASE_URL}${MESSAGE_MOVE_PATH}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H "Origin: ${TARGET_BASE_URL}" \
    -H "Referer: ${TARGET_BASE_URL}${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" \
    --data-urlencode "csrf_token=${MSG_CSRF}" \
    --data-urlencode "mailbox=${mbox}" \
    --data-urlencode "uid=${uidval}" \
    --data-urlencode "destination_mailbox=${destbox}"
  printf '\n===== %s =====\nmailbox=%s\nuid=%s\ndestination=%s\nhttp=%s\nlen=%s\ntitle=%s\n' \
    "$label" "$mbox" "$uidval" "$destbox" "$(header_code "${label}.headers")" "$(header_field "${label}.headers" content-length)" "$(html_title "${label}.html")"
  printf '\n-- headers --\n'
  sed -n '1,40p' "${label}.headers"
  printf '\n-- markers --\n'
  grep -Eoi 'invalid|unavailable|moved_to=|forbidden|denied|csrf|request' "${label}.html" | sed -n '1,40p'
done < cases.txt

printf '\nSaved in %s\n' "$RUN_DIR"
