#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "09-success-login-and-session"

perform_login cookies.txt login.headers login.body.html
fetch_get "${SESSIONS_PATH}" sessions.html sessions.headers cookies.txt
printf 'login_http=%s\nlogin_location=%s\nsession_cookie=%s\n' "$(header_code login.headers)" "$(header_field login.headers location)" "$(session_cookie_value cookies.txt)"
printf 'sessions_http=%s\ntitle=%s\n' "$(header_code sessions.headers)" "$(html_title sessions.html)"
grep -Eoi 'name="session_id" value="[^"]+"|Current|Created|Last Seen|Revoke' sessions.html | sed -n '1,80p'

printf '\nSaved in %s\n' "$RUN_DIR"
