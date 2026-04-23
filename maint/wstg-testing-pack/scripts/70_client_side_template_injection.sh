#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "70-client-side-template-injection"

perform_login cookies.txt login.headers login.body.html
printf '%s\n' \
  'mustache|WSTGTPL1-{{7*7}}' \
  'es_template|WSTGTPL2-${7*7}' \
  'angular|WSTGTPL3-{{constructor.constructor("return 7*7")()}}' \
  'erb_like|WSTGTPL4-<%= 7*7 %>' \
  'hash_expr|WSTGTPL5-#{7*7}' > payloads.txt

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
  printf '\n-- literal payload hits --\n'
  grep -Ein 'WSTGTPL[1-5]|\{\{7\*7\}\}|\$\{7\*7\}|<%= 7\*7 %>|#\{7\*7\}' "${label}-settings-after.html" "${label}-message-after.html" | sed -n '1,80p'
  printf '\n-- evaluated 49 hits --\n'
  grep -Ein 'WSTGTPL[1-5].*49|>49<|value="49"|destination_mailbox" value="49"' "${label}-settings-after.html" "${label}-message-after.html" | sed -n '1,40p'
done < payloads.txt

fetch_get "${SETTINGS_PATH}" reset-pre.html reset-pre.headers cookies.txt
reset_csrf="$(extract_first_csrf reset-pre.html)"
fetch_post_form "${SETTINGS_PATH}" reset-post.html reset-post.headers cookies.txt "${SETTINGS_PATH}" \
  --data-urlencode "csrf_token=${reset_csrf}" \
  --data-urlencode 'html_display_preference=prefer_sanitized_html' \
  --data-urlencode "archive_mailbox_name=${DEFAULT_ARCHIVE_MAILBOX}"

printf '\nSaved in %s\n' "$RUN_DIR"
