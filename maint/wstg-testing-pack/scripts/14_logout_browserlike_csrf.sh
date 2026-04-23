#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "14-logout-browserlike-csrf"

perform_login cookies.txt login.headers login.body.html
fetch_get "${SESSIONS_PATH}" sessions.html sessions.headers cookies.txt
CSRF="$(extract_first_csrf sessions.html)"
fetch_post_form "${LOGOUT_PATH}" logout-response.html logout-response.headers cookies.txt "${SESSIONS_PATH}" --data-urlencode "csrf_token=${CSRF}"
fetch_get "${MAILBOXES_PATH}" post-logout-mailboxes.html post-logout-mailboxes.headers cookies.txt

printf 'CSRF=%s\n' "$CSRF"
printf '\n===== logout-response.headers =====\n'
sed -n '1,80p' logout-response.headers
printf '\n===== logout markers =====\n'
grep -Eo 'forbidden|denied|invalid|missing|logout|logged out|login|sign in' logout-response.html | sed -n '1,40p'
printf '\n===== cookies.txt after logout =====\n'
sed -n '1,120p' cookies.txt
printf '\n===== post-logout-mailboxes.headers =====\n'
sed -n '1,80p' post-logout-mailboxes.headers

printf '\nSaved in %s\n' "$RUN_DIR"
