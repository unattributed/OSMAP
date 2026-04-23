#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "56-upload-malicious-files"

cat > safe.txt <<'EOF'
This is a harmless text attachment used as the control file for WSTG malicious upload testing.
EOF
cat > eicar.txt <<'EOF'
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
EOF
cat > script.txt <<'EOF'
<script>alert("wstg")</script>
EOF

perform_login cookies.txt login.headers login.body.html
fetch_get "${COMPOSE_PATH}" compose.html compose.headers cookies.txt
CSRF="$(extract_first_csrf compose.html)"
printf 'CSRF=%s\n' "$CSRF"

while read -r label file mime; do
  curl -sS -o "${label}.html" -D "${label}.headers" -b cookies.txt -c cookies.txt \
    -X POST "${TARGET_BASE_URL}${SEND_PATH}" \
    -H "Origin: ${TARGET_BASE_URL}" \
    -H "Referer: ${TARGET_BASE_URL}${COMPOSE_PATH}" \
    -F "csrf_token=${CSRF}" \
    -F "to=${INVALID_EMAIL}" \
    -F "subject=WSTG malicious upload ${label}" \
    -F 'body=malicious file probe only' \
    -F "attachment=@${file};type=${mime}"
  printf '\n===== %s =====\nfile=%s\nmime=%s\nhttp=%s\nlen=%s\ntitle=%s\n' \
    "$label" "$file" "$mime" "$(header_code "${label}.headers")" "$(header_field "${label}.headers" content-length)" "$(html_title "${label}.html")"
  grep -Eoi 'invalid|request failed|compose|attachment|upload|file type|forbidden|denied|blocked|malicious|virus|scan|quarantine|mailboxes|login' "${label}.html" | sed -n '1,60p'
done <<'EOF'
control safe.txt text/plain
eicar eicar.txt text/plain
script script.txt text/plain
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
