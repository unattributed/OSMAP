#!/bin/sh
#
# Validate the V3 MIME and HTML proof plan on a live OpenBSD host.
#
# This validator is built to avoid storing secrets, cookies, CSRF tokens, raw
# session identifiers, full message bodies, or full attachment bodies in repo
# evidence.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REPORT_PATH="${PROJECT_ROOT}/maint/live/latest-host-v3-mime-html-proof-report.txt"

WORK_ROOT="${OSMAP_LIVE_WORK_ROOT:-/home/osmap-live-v3-mime-html-proof-$$}"
STATE_ROOT="${WORK_ROOT}/state"
HELPER_RUNTIME_DIR="${WORK_ROOT}/helper-runtime"
HELPER_STATE_RUNTIME_DIR="${STATE_ROOT}/helper-runtime-state"
SESSION_DIR="${STATE_ROOT}/sessions"
RUNTIME_DIR="${STATE_ROOT}/runtime"
SETTINGS_DIR="${STATE_ROOT}/settings"
AUDIT_DIR="${STATE_ROOT}/audit"
CACHE_DIR="${STATE_ROOT}/cache"
TOTP_DIR="${STATE_ROOT}/totp"
TMPDIR_PATH="${WORK_ROOT}/tmp"
CARGO_HOME_PATH="${WORK_ROOT}/cargo-home"
CARGO_TARGET_DIR_PATH="${WORK_ROOT}/target"
BIN_PATH="${WORK_ROOT}/osmap"
HTTP_LOG_PATH="${RUNTIME_DIR}/serve.log"
HTTP_PID_PATH="${RUNTIME_DIR}/serve.pid"
HELPER_LOG_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.log"
HELPER_PID_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.pid"
HELPER_SOCKET_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.sock"

VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
LISTEN_PORT="${OSMAP_LIVE_V3_MIME_HTML_PROOF_PORT:-}"
SESSION_TOKEN="${OSMAP_LIVE_SESSION_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
USER_AGENT="osmap-live-v3-mime-html-proof"
AUTH_SOCKET_PATH="${OSMAP_DOVEADM_AUTH_SOCKET_PATH:-/var/run/osmap-auth}"
TRUSTED_WEB_RUNTIME_UID="${OSMAP_TRUSTED_WEB_RUNTIME_UID:-$(id -u _osmap)}"
USERDB_SOCKET_PATH="${OSMAP_DOVEADM_USERDB_SOCKET_PATH:-/var/run/osmap-userdb}"
KEEP_WORK_ROOT="${OSMAP_KEEP_WORK_ROOT:-0}"

log() {
  printf '%s\n' "$*"
}

write_report() {
  key="$1"
  value="$2"
  printf '%s=%s\n' "$key" "$value" >> "${REPORT_PATH}"
}

fail() {
  log "failed: $*"
  {
    printf '%s\n' "result=failed"
    printf '%s\n' "failure_reason=$*"
    printf '%s\n' "failed_work_root=${WORK_ROOT}"
  } >> "${REPORT_PATH}"
  exit 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"
}

terminate_pid_path() {
  pid_path="$1"
  doas test -f "${pid_path}" 2>/dev/null || return 0

  target_pid="$(doas cat "${pid_path}" 2>/dev/null || true)"
  case "${target_pid}" in
    ""|*[!0-9]*)
      return 0
      ;;
  esac

  doas kill "${target_pid}" 2>/dev/null || true
  sleep 1
  doas kill -KILL "${target_pid}" 2>/dev/null || true
}

cleanup() {
  terminate_pid_path "${HTTP_PID_PATH}"
  terminate_pid_path "${HELPER_PID_PATH}"

  if [ "${KEEP_WORK_ROOT}" = "1" ]; then
    log "keeping live validation root at ${WORK_ROOT}"
  else
    doas rm -rf "${WORK_ROOT}" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

require_tool awk
require_tool cargo
require_tool doas
require_tool grep
require_tool nc
require_tool sed
require_tool sha256

if [ -z "${LISTEN_PORT}" ]; then
  LISTEN_PORT="$((19000 + ($$ % 1000)))"
fi

case "${SESSION_TOKEN}" in
  [0-9a-fA-F][0-9a-fA-F]*)
    ;;
  *)
    fail "session token must be hex"
    ;;
esac

if [ "${#SESSION_TOKEN}" -ne 64 ]; then
  fail "session token must be exactly 64 hex characters"
fi

SESSION_ID="$(printf 'session-id:%s' "${SESSION_TOKEN}" | sha256 -q)"
CSRF_TOKEN="$(printf 'csrf:%s' "${SESSION_TOKEN}" | sha256 -q)"
NOW="$(date +%s)"
EXPIRES_AT="$((NOW + 3600))"

log "preparing isolated live validation root under ${WORK_ROOT}"

doas rm -rf "${WORK_ROOT}"
doas install -d -o foo -g foo -m 755 "${WORK_ROOT}"
install -d "${TMPDIR_PATH}" "${CARGO_HOME_PATH}" "${CARGO_TARGET_DIR_PATH}"

doas install -d -o _osmap -g _osmap -m 755 "${STATE_ROOT}"
doas install -d -o _osmap -g _osmap -m 700 \
  "${SESSION_DIR}" \
  "${RUNTIME_DIR}" \
  "${SETTINGS_DIR}" \
  "${AUDIT_DIR}" \
  "${CACHE_DIR}" \
  "${TOTP_DIR}"

doas install -d -o vmail -g vmail -m 755 "${HELPER_RUNTIME_DIR}"
doas install -d -o vmail -g vmail -m 700 "${HELPER_STATE_RUNTIME_DIR}"

: > "${REPORT_PATH}"
write_report "osmap_v3_mime_html_proof_result" "running"
write_report "host" "$(hostname)"
write_report "project_root" "${PROJECT_ROOT}"
write_report "commit" "$(cd "${PROJECT_ROOT}" && git rev-parse --short HEAD)"
write_report "validation_user" "${VALIDATION_USER}"
write_report "work_root" "${WORK_ROOT}"
write_report "listen_port" "${LISTEN_PORT}"

log "verifying target mailbox layout for validation user"
doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
  mailbox list -u "${VALIDATION_USER}" | grep -Fxq "INBOX" || {
  fail "validation mailbox INBOX does not exist for ${VALIDATION_USER}"
}
write_report "validation_mailbox" "present"

log "building current OSMAP tree"
cd "${PROJECT_ROOT}"
TMPDIR="${TMPDIR_PATH}" \
  CARGO_HOME="${CARGO_HOME_PATH}" \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR_PATH}" \
  cargo build --quiet
doas install -o _osmap -g _osmap -m 755 "${CARGO_TARGET_DIR_PATH}/debug/osmap" "${BIN_PATH}"
write_report "build_result" "passed"

log "writing synthetic validated session"
doas sh -c "cat > '${SESSION_DIR}/${SESSION_ID}.session' <<'EOF'
session_id=${SESSION_ID}
csrf_token=${CSRF_TOKEN}
canonical_username=${VALIDATION_USER}
issued_at=${NOW}
expires_at=${EXPIRES_AT}
last_seen_at=${NOW}
revoked_at=
remote_addr=127.0.0.1
user_agent=${USER_AGENT}
factor=totp
EOF
chmod 600 '${SESSION_DIR}/${SESSION_ID}.session'
chown _osmap:_osmap '${SESSION_DIR}/${SESSION_ID}.session'"

log "starting enforced mailbox helper as vmail"
doas -u vmail sh -c "
  umask 077
  echo \$\$ > '${HELPER_PID_PATH}'
  exec env \
    OSMAP_RUN_MODE=mailbox-helper \
    OSMAP_ENV=production \
    OSMAP_STATE_DIR='${STATE_ROOT}' \
    OSMAP_RUNTIME_DIR='${HELPER_STATE_RUNTIME_DIR}' \
    OSMAP_SESSION_DIR='${SESSION_DIR}' \
    OSMAP_SETTINGS_DIR='${SETTINGS_DIR}' \
    OSMAP_AUDIT_DIR='${AUDIT_DIR}' \
    OSMAP_CACHE_DIR='${CACHE_DIR}' \
    OSMAP_TOTP_SECRET_DIR='${TOTP_DIR}' \
    OSMAP_MAILBOX_HELPER_SOCKET_PATH='${HELPER_SOCKET_PATH}' \
    OSMAP_DOVEADM_AUTH_SOCKET_PATH='${AUTH_SOCKET_PATH}' \
    OSMAP_TRUSTED_WEB_RUNTIME_UID='${TRUSTED_WEB_RUNTIME_UID}' \
    OSMAP_DOVEADM_USERDB_SOCKET_PATH='${USERDB_SOCKET_PATH}' \
    OSMAP_LOG_LEVEL=info \
    OSMAP_OPENBSD_CONFINEMENT_MODE=enforce \
    '${BIN_PATH}' >'${HELPER_LOG_PATH}' 2>&1
" &

wait_for_helper_socket() {
  tries=0
  while [ "${tries}" -lt 20 ]; do
    if doas test -S "${HELPER_SOCKET_PATH}"; then
      doas chown vmail:_osmap "${HELPER_SOCKET_PATH}"
      doas chmod 660 "${HELPER_SOCKET_PATH}"
      write_report "helper_runtime_result" "passed"
      return 0
    fi
    sleep 1
    tries="$((tries + 1))"
  done

  [ -f "${HELPER_LOG_PATH}" ] && doas tail -n 40 "${HELPER_LOG_PATH}" || true
  fail "mailbox helper did not become ready"
}

log "starting enforced browser runtime as _osmap"
doas -u _osmap sh -c "
  umask 077
  echo \$\$ > '${HTTP_PID_PATH}'
  exec env \
    OSMAP_RUN_MODE=serve \
    OSMAP_ENV=production \
    OSMAP_LISTEN_ADDR=127.0.0.1:${LISTEN_PORT} \
    OSMAP_STATE_DIR='${STATE_ROOT}' \
    OSMAP_RUNTIME_DIR='${RUNTIME_DIR}' \
    OSMAP_SESSION_DIR='${SESSION_DIR}' \
    OSMAP_SETTINGS_DIR='${SETTINGS_DIR}' \
    OSMAP_AUDIT_DIR='${AUDIT_DIR}' \
    OSMAP_CACHE_DIR='${CACHE_DIR}' \
    OSMAP_TOTP_SECRET_DIR='${TOTP_DIR}' \
    OSMAP_MAILBOX_HELPER_SOCKET_PATH='${HELPER_SOCKET_PATH}' \
    OSMAP_LOG_LEVEL=info \
    OSMAP_SESSION_LIFETIME_SECS=3600 \
    OSMAP_OPENBSD_CONFINEMENT_MODE=enforce \
    '${BIN_PATH}' >'${HTTP_LOG_PATH}' 2>&1
" &

wait_for_healthz() {
  tries=0
  while [ "${tries}" -lt 40 ]; do
    response="$(
      {
        printf 'GET /healthz HTTP/1.1\r\n'
        printf 'Host: 127.0.0.1\r\n'
        printf 'Connection: close\r\n'
        printf '\r\n'
      } | nc -N 127.0.0.1 "${LISTEN_PORT}" 2>/dev/null || true
    )"

    if printf '%s' "${response}" | grep -q '^HTTP/1.1 200 OK'; then
      write_report "browser_runtime_result" "passed"
      write_report "healthz_status" "HTTP/1.1 200 OK"
      return 0
    fi

    sleep 1
    tries="$((tries + 1))"
  done

  [ -f "${HTTP_LOG_PATH}" ] && doas tail -n 40 "${HTTP_LOG_PATH}" || true
  fail "http runtime did not become ready"
}

request_get() {
  path_value="$1"
  {
    printf 'GET %s HTTP/1.1\r\n' "${path_value}"
    printf 'Host: 127.0.0.1\r\n'
    printf 'User-Agent: %s\r\n' "${USER_AGENT}"
    printf 'Cookie: osmap_session=%s\r\n' "${SESSION_TOKEN}"
    printf 'Connection: close\r\n'
    printf '\r\n'
  } | nc -N 127.0.0.1 "${LISTEN_PORT}"
}

status_line() {
  printf '%s' "$1" | sed -n '1p' | tr -d '\r'
}

response_body() {
  printf '%s' "$1" | awk '
    BEGIN { body = 0 }
    /^\r?$/ { body = 1; next }
    body { gsub("\r", ""); print }
  '
}

lookup_uid() {
  subject="$1"
  doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
    search -u "${VALIDATION_USER}" mailbox INBOX header Subject "${subject}" \
    | awk 'NF > 0 { print $NF; exit }'
}

wait_for_uid() {
  label="$1"
  subject="$2"

  found_uid=""
  tries=0
  while [ -z "${found_uid}" ] && [ "${tries}" -lt 30 ]; do
    sleep 1
    found_uid="$(lookup_uid "${subject}" || true)"
    tries="$((tries + 1))"
  done

  [ -n "${found_uid}" ] || fail "failed to locate injected ${label} message uid"

  write_report "${label}_uid" "${found_uid}"
  printf '%s\n' "${found_uid}"
}

assert_contains() {
  label="$1"
  haystack="$2"
  needle="$3"

  printf '%s' "${haystack}" | grep -Fq "${needle}" || fail "${label} missing expected marker"
  write_report "${label}" "present"
}

assert_status_ok() {
  label="$1"
  status="$2"

  [ "${status}" = "HTTP/1.1 200 OK" ] || fail "${label} status was ${status}"
  write_report "${label}_status" "${status}"
}

cleanup_one_subject() {
  subject="$1"
  [ -n "${subject}" ] || return 0

  doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
    expunge -u "${VALIDATION_USER}" mailbox INBOX header Subject "${subject}" \
    >/dev/null 2>&1 || true
}

ENCODED_SUBJECT_FILTER="OSMAP V3 MIME encoded header proof ${NOW}-$$"
ENCODED_SUBJECT="${ENCODED_SUBJECT_FILTER} =?UTF-8?Q?=E2=9C=93_Header_r=C3=A9sum=C3=A9?="
EXPECTED_ENCODED_SUBJECT="${ENCODED_SUBJECT_FILTER} ✓ Header résumé"
ENCODED_FROM="=?UTF-8?Q?Andr=C3=A9_Proof?= <alice@example.com>"
EXPECTED_FROM_HTML="from André Proof &lt;alice@example.com&gt;"
ENCODED_BODY_MARKER="encoded header body marker ${NOW}-$$"
HTML_SUBJECT="OSMAP V3 MIME hostile HTML proof ${NOW}-$$"
HTML_SAFE_TEXT="safe visible html proof text ${NOW}-$$"
HTML_REMOTE_MARKER="evil-v3-proof.example"
HTML_UNSAFE_MARKER="unsafe-active-marker-${NOW}-$$"


inject_encoded_message() {
  {
    printf 'From: %s\n' "${ENCODED_FROM}"
    printf 'To: %s\n' "${VALIDATION_USER}"
    printf 'Subject: %s\n' "${ENCODED_SUBJECT}"
    printf 'Date: =?US-ASCII?Q?Fri,_27_Mar_2026_12:30:00_+0000?=\n'
    printf 'Content-Type: text/plain; charset=utf-8\n'
    printf '\n'
    printf '%s\n' "${ENCODED_BODY_MARKER}"
  } | /usr/sbin/sendmail -t
}

inject_html_message() {
  {
    printf 'From: OSMAP HTML Proof <%s>\n' "${VALIDATION_USER}"
    printf 'To: %s\n' "${VALIDATION_USER}"
    printf 'Subject: %s\n' "${HTML_SUBJECT}"
    printf 'MIME-Version: 1.0\n'
    printf 'Content-Type: text/html; charset=utf-8\n'
    printf '\n'
    printf '<html><head>'
    printf '<meta http-equiv="refresh" content="0; url=https://%s/">\n' "${HTML_REMOTE_MARKER}"
    printf '<style>@import url("https://%s/style.css");</style>' "${HTML_REMOTE_MARKER}"
    printf '</head><body>'
    printf '<p style="background-image:url(https://%s/bg.png)" onclick="alert(1)">%s</p>' "${HTML_REMOTE_MARKER}" "${HTML_SAFE_TEXT}"
    printf '<a href="https://example.com/safe">safe link</a>'
    printf '<a href="/relative/path">relative link</a>'
    printf '<a href="//%s/protocol-relative">protocol relative link</a>' "${HTML_REMOTE_MARKER}"
    printf '<a href="cid:logo@example.com">cid link</a>'
    printf '<a href="data:text/html;base64,PHNjcmlwdA==">data link</a>'
    printf '<a href="javascript:alert(1)">javascript link</a>'
    printf '<form action="https://%s/post"><input name="secret" value="%s"></form>' "${HTML_REMOTE_MARKER}" "${HTML_UNSAFE_MARKER}"
    printf '<img src="https://%s/tracker.png">' "${HTML_REMOTE_MARKER}"
    printf '<svg><a href="https://%s/svg">svg text</a></svg>' "${HTML_REMOTE_MARKER}"
    printf '<iframe src="https://%s/frame">frame text</iframe>' "${HTML_REMOTE_MARKER}"
    printf '<object data="https://%s/object">object text</object>' "${HTML_REMOTE_MARKER}"
    printf '<embed src="https://%s/embed">' "${HTML_REMOTE_MARKER}"
    printf '<template><p>template text</p></template>'
    printf '<!-- hidden operator note -->'
    printf '</body></html>\n'
  } | /usr/sbin/sendmail -t
}

assert_absent() {
  label="$1"
  haystack="$2"
  needle="$3"

  if printf '%s' "${haystack}" | grep -Fq "${needle}"; then
    fail "${label} contained forbidden marker"
  fi
  write_report "${label}" "absent"
}

wait_for_helper_socket
wait_for_healthz

log "injecting controlled encoded-header proof message"
inject_encoded_message
write_report "encoded_header_injection" "attempted"

encoded_uid="$(wait_for_uid encoded_header "${ENCODED_SUBJECT_FILTER}")"

log "validating encoded-header message view"
encoded_response="$(request_get "/message?mailbox=INBOX&uid=${encoded_uid}")"
printf '%s' "${encoded_response}" > "${WORK_ROOT}/encoded-header-response.txt"
encoded_status="$(status_line "${encoded_response}")"
encoded_body="$(response_body "${encoded_response}")"

assert_status_ok "encoded_header_message_view" "${encoded_status}"
assert_contains "encoded_subject_summary" "${encoded_body}" "${EXPECTED_ENCODED_SUBJECT}"
assert_contains "encoded_from_summary" "${encoded_body}" "${EXPECTED_FROM_HTML}"
assert_contains "encoded_plain_text_mode" "${encoded_body}" "<dd>plain_text_preformatted</dd>"

if doas grep -Fq "${ENCODED_BODY_MARKER}" "${HTTP_LOG_PATH}" 2>/dev/null; then
  fail "audit log contained encoded body marker"
fi
write_report "encoded_body_marker_audit_leakage" "absent"

log "injecting controlled sanitized HTML proof message"
inject_html_message
write_report "sanitized_html_injection" "attempted"

html_uid="$(wait_for_uid sanitized_html "${HTML_SUBJECT}")"

log "validating sanitized HTML message view"
html_response="$(request_get "/message?mailbox=INBOX&uid=${html_uid}")"
printf '%s' "${html_response}" > "${WORK_ROOT}/sanitized-html-response.txt"
html_status="$(status_line "${html_response}")"
html_body="$(response_body "${html_response}")"

assert_status_ok "sanitized_html_message_view" "${html_status}"
assert_contains "sanitized_html_mode" "${html_body}" "<dd>sanitized_html</dd>"
assert_contains "sanitized_html_safe_text" "${html_body}" "${HTML_SAFE_TEXT}"
assert_contains "sanitized_html_safe_link" "${html_body}" 'href="https://example.com/safe"'
assert_contains "sanitized_html_link_rel" "${html_body}" 'rel="noopener noreferrer nofollow"'
assert_absent "sanitized_html_remote_marker" "${html_body}" "${HTML_REMOTE_MARKER}"
assert_absent "sanitized_html_unsafe_marker" "${html_body}" "${HTML_UNSAFE_MARKER}"
assert_absent "sanitized_html_javascript_scheme" "${html_body}" 'href="javascript:'
assert_absent "sanitized_html_data_scheme" "${html_body}" 'href="data:'
assert_absent "sanitized_html_cid_scheme" "${html_body}" 'href="cid:'
assert_absent "sanitized_html_form" "${html_body}" "<form"
assert_absent "sanitized_html_img" "${html_body}" "<img"
assert_absent "sanitized_html_iframe" "${html_body}" "<iframe"
assert_absent "sanitized_html_object" "${html_body}" "<object"
assert_absent "sanitized_html_embed" "${html_body}" "<embed"
assert_absent "sanitized_html_template" "${html_body}" "<template"
assert_absent "sanitized_html_svg" "${html_body}" "<svg"

if doas grep -Fq "${HTML_SAFE_TEXT}" "${HTTP_LOG_PATH}" 2>/dev/null; then
  fail "audit log contained sanitized HTML body marker"
fi
write_report "sanitized_html_body_marker_audit_leakage" "absent"

cleanup_one_subject "${ENCODED_SUBJECT_FILTER}"
cleanup_one_subject "${HTML_SUBJECT}"
write_report "message_cleanup" "attempted"

write_report "result" "encoded_and_sanitized_html_proof_passed"

log "live V3 MIME encoded-header and sanitized HTML proof passed"
log "report=${REPORT_PATH}"
