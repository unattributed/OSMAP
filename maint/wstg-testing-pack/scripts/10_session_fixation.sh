#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "10-session-fixation"

cat > preseed-cookies.txt <<'EOF'
# Netscape HTTP Cookie File
EOF
printf '#HttpOnly_%s\tFALSE\t/\tTRUE\t0\tosmap_session\tfixedsessionvalue\n' "${HOSTNAME}" >> preseed-cookies.txt

perform_login postlogin-cookies.txt login.headers login.body.html
printf 'preseed_cookie=fixedsessionvalue\nactual_cookie=%s\n' "$(session_cookie_value postlogin-cookies.txt)"
printf 'same_cookie=%s\n' "$( [[ "$(session_cookie_value postlogin-cookies.txt)" == "fixedsessionvalue" ]] && echo yes || echo no )"
sed -n '1,40p' login.headers

printf '\nSaved in %s\n' "$RUN_DIR"
