#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "61-css-injection-check"

perform_login cookies.txt login.headers login.body.html
printf '%s\n' \
  'control|WSTGCSS1-safe' \
  'style_tag|WSTGCSS2-<style>body{background:red}</style>' \
  'style_attr|WSTGCSS3-" style="background:red' \
  'css_comment|WSTGCSS4-*/body{background:red}/*' \
  'css_url|WSTGCSS5-url(https://attacker.invalid/wstg-css)' > payloads.txt

while IFS='|' read -r label payload; do
  fetch_get "${SETTINGS_PATH}" settings-pre.html settings-pre.headers cookies.txt
  csrf="$(extract_first_csrf settings-pre.html)"
  fetch_post_form "${SETTINGS_PATH}" "${label}-post.html" "${label}-post.headers" cookies.txt "${SETTINGS_PATH}" \
    --data-urlencode "csrf_token=${csrf}" \
    --data-urlencode 'html_display_preference=prefer_sanitized_html' \
    --data-urlencode "archive_mailbox_name=${payload}"
  fetch_get "${SETTINGS_PATH}" "${label}-settings-after.html" "${label}-settings-after.headers" cookies.txt
  fetch_get "${MESSAGE_VIEW_PATH}?mailbox=${DEFAULT_MAILBOX}&uid=${DEFAULT_MESSAGE_UID}" "${label}-message-after.html" "${label}-message-after.headers" cookies.txt
  printf '\n===== %s =====\npayload=%s\npost_http=%s\nlocation=%s\nsettings_title=%s\nmessage_title=%s\n' \
    "$label" "$payload" "$(header_code "${label}-post.headers")" "$(header_field "${label}-post.headers" location)" "$(html_title "${label}-settings-after.html")" "$(html_title "${label}-message-after.html")"
  printf '\n-- style context hits --\n'
  grep -Ein '<style>|</style>|style=|background:red|url\(https://attacker\.invalid/wstg-css\)' "${label}-settings-after.html" "${label}-message-after.html" | sed -n '1,80p'
  printf '\n-- encoded payload hits --\n'
  grep -Ein '&lt;style&gt;|&lt;/style&gt;|&quot; style=&quot;background:red|url\(https://attacker\.invalid/wstg-css\)|WSTGCSS[1-5]' "${label}-settings-after.html" "${label}-message-after.html" | sed -n '1,120p'
done < payloads.txt

fetch_get "${SETTINGS_PATH}" reset-pre.html reset-pre.headers cookies.txt
reset_csrf="$(extract_first_csrf reset-pre.html)"
fetch_post_form "${SETTINGS_PATH}" reset-post.html reset-post.headers cookies.txt "${SETTINGS_PATH}" \
  --data-urlencode "csrf_token=${reset_csrf}" \
  --data-urlencode 'html_display_preference=prefer_sanitized_html' \
  --data-urlencode "archive_mailbox_name=${DEFAULT_ARCHIVE_MAILBOX}"

printf '\nSaved in %s\n' "$RUN_DIR"
