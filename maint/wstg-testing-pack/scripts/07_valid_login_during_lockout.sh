#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "07-valid-login-during-lockout"

perform_login cookies.txt login.headers login.body.html
printf 'http=%s\nlocation=%s\ntitle=%s\n' "$(header_code login.headers)" "$(header_field login.headers location)" "$(html_title login.body.html)"
sed -n '1,40p' login.headers

printf '\nSaved in %s\n' "$RUN_DIR"
