#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "17-archive-hidden-field-tamper"

perform_login cookies.txt login.headers login.body.html
fetch_get "${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" message.html message.headers cookies.txt
CSRF="$(extract_first_csrf message.html)"
MAILBOX="$(extract_hidden_value message.html mailbox)"
REAL_UID="$(extract_hidden_value message.html uid)"
ORIG_DEST="$(extract_hidden_value message.html destination_mailbox)"
TAMPER_DEST="WSTG_INVALID_DEST_$(date +%s)"

fetch_post_form "${MESSAGE_MOVE_PATH}" tamper-response.html tamper-response.headers cookies.txt "${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" \
  --data-urlencode "csrf_token=${CSRF}" \
  --data-urlencode "mailbox=${MAILBOX}" \
  --data-urlencode "uid=${REAL_UID}" \
  --data-urlencode "destination_mailbox=${TAMPER_DEST}"
fetch_get "${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" message-after.html message-after.headers cookies.txt

printf '===== parsed archive form =====\n'
printf 'mailbox=%s\nuid=%s\noriginal_destination=%s\ntampered_destination=%s\n' "$MAILBOX" "$REAL_UID" "$ORIG_DEST" "$TAMPER_DEST"
printf '\n===== tamper_response.headers =====\n'
sed -n '1,80p' tamper-response.headers
printf '\n===== tamper_response markers =====\n'
grep -Eoi '<title>[^<]+|revoked|already revoked|invalid|forbidden|denied|unavailable|request' tamper-response.html | sed -n '1,40p'

printf '\nSaved in %s\n' "$RUN_DIR"
