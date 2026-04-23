#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "11-auth-form-map"

perform_login cookies.txt login.headers login.body.html
fetch_get "${MAILBOXES_PATH}" mailboxes.html mailboxes.headers cookies.txt
fetch_get "${SESSIONS_PATH}" sessions.html sessions.headers cookies.txt

printf '===== mailboxes.headers =====\n'
sed -n '1,80p' mailboxes.headers
printf '\n===== sessions.headers =====\n'
sed -n '1,80p' sessions.headers
printf '\n===== mailboxes forms/links =====\n'
grep -Eoi '<form[^>]*|<input[^>]*type="hidden"[^>]*|<input[^>]*name="[^"]+"[^>]*|<button[^>]*|<a[^>]*href="[^"]+"' mailboxes.html | sed -n '1,200p'
printf '\n===== sessions forms/links =====\n'
grep -Eoi '<form[^>]*|<input[^>]*type="hidden"[^>]*|<input[^>]*name="[^"]+"[^>]*|<button[^>]*|<a[^>]*href="[^"]+"' sessions.html | sed -n '1,240p'

printf '\nSaved in %s\n' "$RUN_DIR"
