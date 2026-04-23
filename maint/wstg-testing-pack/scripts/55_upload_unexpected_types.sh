#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed chmod
setup_run_dir "55-upload-unexpected-file-types"

printf '<?php echo "wstg"; ?>\n' > sample.php
printf '<svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">wstg</text></svg>\n' > sample.svg
printf '<html><body>wstg</body></html>\n' > sample.html
printf 'console.log("wstg");\n' > sample.js
printf '#!/bin/sh\necho wstg\n' > sample.sh
chmod 0644 sample.*

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
    -F "subject=WSTG unexpected upload ${label}" \
    -F 'body=unexpected file type probe only' \
    -F "attachment=@${file};type=${mime}"
  printf '\n===== %s =====\nfile=%s\nmime=%s\nhttp=%s\nlen=%s\ntitle=%s\n' \
    "$label" "$file" "$mime" "$(header_code "${label}.headers")" "$(header_field "${label}.headers" content-length)" "$(html_title "${label}.html")"
  grep -Eoi 'invalid|request failed|compose|attachment|upload|file type|forbidden|denied|blocked|mailboxes|login' "${label}.html" | sed -n '1,50p'
done <<'EOF'
php sample.php application/x-php
svg sample.svg image/svg+xml
html sample.html text/html
js sample.js application/javascript
sh sample.sh text/x-shellscript
EOF

printf '\nSaved in %s\n' "$RUN_DIR"
