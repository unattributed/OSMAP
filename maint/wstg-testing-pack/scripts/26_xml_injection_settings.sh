#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed python3
setup_run_dir "26-xml-injection-settings"

perform_login cookies.txt login.headers login.body.html
cat > payloads.txt <<'EOF'
control|WSTGXML1-safe
single_quote|WSTGXML2'
angle_brackets|WSTGXML3-<tag attr="x">
doctype_like|WSTGXML4-<!DOCTYPE test>
cdata_like|WSTGXML5-<![CDATA[wstg]]>
entity_like|WSTGXML6-&xxe;
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
  python3 - "${label}-after.html" <<'PY'
from pathlib import Path
import sys
html = Path(sys.argv[1]).read_text(errors="ignore")
for token in ["WSTGXML1","WSTGXML2","WSTGXML3","WSTGXML4","WSTGXML5","WSTGXML6"]:
    pos = html.find(token)
    if pos != -1:
        start = max(0, pos - 180)
        end = min(len(html), pos + 260)
        print(f"\n--- context around {token} ---")
        print(html[start:end])
for marker in ["&quot;","&#39;","&lt;","&gt;","&amp;"]:
    if marker in html:
        print(f"found entity {marker}")
PY
done < payloads.txt

printf '\nSaved in %s\n' "$RUN_DIR"
