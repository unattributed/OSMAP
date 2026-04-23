#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds curl awk grep sed
setup_run_dir "30-send-header-injection"

perform_login cookies.txt login.headers login.body.html
for case_name in control_invalid_to subject_header_injection to_header_injection; do
  fetch_get "${COMPOSE_PATH}" compose-pre.html compose-pre.headers cookies.txt
  csrf="$(extract_first_csrf compose-pre.html)"
  case "$case_name" in
    control_invalid_to)
      to_value="${INVALID_EMAIL}"
      subject='WSTGSMTP1-control'
      ;;
    subject_header_injection)
      to_value="${INVALID_EMAIL}"
      subject=$'WSTGSMTP2-subject\r\nBcc: nobody@invalid.invalid'
      ;;
    to_header_injection)
      to_value=$'nobody@invalid.invalid\r\nBcc: nobody2@invalid.invalid'
      subject='WSTGSMTP3-to'
      ;;
  esac

  curl -sS -o "${case_name}.html" -D "${case_name}.headers" -b cookies.txt -c cookies.txt \
    -X POST "${TARGET_BASE_URL}${SEND_PATH}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H "Origin: ${TARGET_BASE_URL}" \
    -H "Referer: ${TARGET_BASE_URL}${COMPOSE_PATH}" \
    --data-urlencode "csrf_token=${csrf}" \
    --data-urlencode "to=${to_value}" \
    --data-urlencode "subject=${subject}" \
    --data-urlencode $'body=WSTG SMTP injection probe\r\nsafe body only'

  printf '\n===== %s =====\nhttp=%s\nlocation=%s\ntitle=%s\n' "$case_name" "$(header_code "${case_name}.headers")" "$(header_field "${case_name}.headers" location)" "$(html_title "${case_name}.html")"
  printf 'headers:\n'
  sed -n '1,60p' "${case_name}.headers"
  printf '\nmarkers:\n'
  grep -Eoi 'invalid|failed|error|queued|sent|compose|mailboxes|login|forbidden|denied|unavailable|request' "${case_name}.html" | sed -n '1,40p'
done

printf '\nSaved in %s\n' "$RUN_DIR"
