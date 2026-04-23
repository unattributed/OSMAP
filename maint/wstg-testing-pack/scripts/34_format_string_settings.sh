#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "34-format-string-settings"

perform_login cookies.txt login.headers login.body.html
cat > payloads.txt <<'EOF'
percent_s|WSTGFMT1-%s%s%s
percent_x|WSTGFMT2-%x-%x-%x
printf_n|WSTGFMT3-%n
java_fmt|WSTGFMT4-%1$s-%2$x
mixed|WSTGFMT5-%s-%x-{{7*7}}
EOF
while IFS='|' read -r label payload; do
  fetch_get "${SETTINGS_PATH}" settings-pre.html settings-pre.headers cookies.txt
  csrf="$(extract_first_csrf settings-pre.html)"
  fetch_post_form "${SETTINGS_PATH}" "${label}-post.html" "${label}-post.headers" cookies.txt "${SETTINGS_PATH}" \
    --data-urlencode "csrf_token=${csrf}" \
    --data-urlencode 'html_display_preference=prefer_sanitized_html' \
    --data-urlencode "archive_mailbox_name=${payload}"
  fetch_get "${SETTINGS_PATH}" "${label}-after.html" "${label}-after.headers" cookies.txt
  printf '\n===== %s =====\npayload=%s\nhttp=%s\ntitle=%s\n' "$label" "$payload" "$(header_code "${label}-post.headers")" "$(html_title "${label}-after.html")"
  grep -Ein 'WSTGFMT[1-5]|%s|%x|%n' "${label}-after.html" | sed -n '1,40p'
done < payloads.txt

printf '\nSaved in %s\n' "$RUN_DIR"
