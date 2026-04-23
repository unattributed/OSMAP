#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "29-compose-surface-map"

perform_login cookies.txt login.headers login.body.html
fetch_get "${COMPOSE_PATH}" compose.html compose.headers cookies.txt
printf '===== compose.headers =====\n'
sed -n '1,80p' compose.headers
printf '\n===== compose title =====\n'
printf '<title>%s\n' "$(html_title compose.html)"
printf '\n===== compose forms/inputs =====\n'
grep -Eoi '<form[^>]*|<input[^>]*|<textarea[^>]*|<select[^>]*|<option[^>]*|<button[^>]*' compose.html | sed -n '1,260p'
printf '\n===== compose markers =====\n'
grep -Eoi 'to|cc|bcc|subject|body|attachment|draft|send|csrf|reply|forward|compose' compose.html | sed -n '1,120p'

printf '\nSaved in %s\n' "$RUN_DIR"
