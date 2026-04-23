#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "12-logout-missing-csrf"

perform_login cookies.txt login.headers login.body.html
curl -sS -o logout-response.html -D logout-response.headers -b cookies.txt -c cookies.txt -X POST "${TARGET_BASE_URL}${LOGOUT_PATH}"
fetch_get "${MAILBOXES_PATH}" post-logout-mailboxes.html post-logout-mailboxes.headers cookies.txt

printf '===== logout-response.headers =====\n'
sed -n '1,80p' logout-response.headers
printf '\n===== logout markers =====\n'
grep -Eo 'csrf|forbidden|denied|invalid|missing|error|login|sign in|logged out' logout-response.html | sed -n '1,40p'
printf '\n===== post-logout-mailboxes.headers =====\n'
sed -n '1,80p' post-logout-mailboxes.headers
printf '\n===== post-logout-mailboxes markers =====\n'
grep -Eo 'OSMAP Login|Sign In|Mailbox|Compose|Search|Sessions|Settings' post-logout-mailboxes.html | sed -n '1,40p'

printf '\nSaved in %s\n' "$RUN_DIR"
