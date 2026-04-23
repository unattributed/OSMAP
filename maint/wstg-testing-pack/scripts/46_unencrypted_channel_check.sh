#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "46-unencrypted-channel-check"

perform_login cookies.txt login.headers login.body.html
curl -sS -o login-page.html -D login-page.headers "${TARGET_BASE_URL}${LOGIN_PATH}"
fetch_get "${MAILBOXES_PATH}" mailboxes.html mailboxes.headers cookies.txt

printf '===== login-page.headers =====\n'
sed -n '1,60p' login-page.headers
printf '\n===== login-post.headers =====\n'
sed -n '1,60p' login.headers
printf '\n===== insecure URL/token scan =====\n'
grep -Ein 'http://|ws://|ftp://|file://|mailto:|action="http://|src="http://|href="http://|content="http://|password|totp|authorization|bearer|token|secret|session' login-page.html mailboxes.html | sed -n '1,120p'
for port in ${HTTP_ALT_PORTS}; do
  outfile="curl-http-${port}.txt"
  curl -svI --max-time 8 "http://${HOSTNAME}:${port}/" > "$outfile" 2>&1 || true
  printf '\n--- http:// port %s ---\n' "$port"
  sed -n '1,120p' "$outfile"
done

printf '\nSaved in %s\n' "$RUN_DIR"
