#!/bin/sh
#
# Validate V3 reply/forward selected source-attachment handling on a live
# OpenBSD host with a real password-plus-TOTP browser login.
#
# The script applies a temporary validation mailbox password hash, starts an
# isolated enforced OSMAP runtime, injects controlled attachment-bearing source
# messages, and proves:
#
# - a selected source attachment is re-fetched and included in a sent message
# - selected source attachments require CSRF and same-origin metadata
# - tampered mailbox, UID, part path, duplicate selection, and stale source
#   references fail before submission
# - the emitted report does not contain password, TOTP, session, CSRF, message
#   body, or attachment body material

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_ROOT="${OSMAP_LIVE_WORK_ROOT:-/home/osmap-live-v3-source-attachments-$$}"
STATE_ROOT="${WORK_ROOT}/state"
HELPER_RUNTIME_DIR="${WORK_ROOT}/helper-runtime"
HELPER_STATE_RUNTIME_DIR="${STATE_ROOT}/helper-runtime-state"
SESSION_DIR="${STATE_ROOT}/sessions"
RUNTIME_DIR="${STATE_ROOT}/runtime"
SETTINGS_DIR="${STATE_ROOT}/settings"
AUDIT_DIR="${STATE_ROOT}/audit"
CACHE_DIR="${STATE_ROOT}/cache"
TOTP_DIR="${STATE_ROOT}/totp"
SECRET_DIR="${STATE_ROOT}/secrets"
HELPER_SECRET_DIR="${HELPER_STATE_RUNTIME_DIR}/secrets"
WEB_GRANT_KEY_PATH="${SECRET_DIR}/mailbox-helper-grant.key"
HELPER_GRANT_KEY_PATH="${HELPER_SECRET_DIR}/mailbox-helper-grant.key"
TMPDIR_PATH="${WORK_ROOT}/tmp"
CARGO_HOME_PATH="${WORK_ROOT}/cargo-home"
CARGO_TARGET_DIR_PATH="${WORK_ROOT}/target"
BIN_PATH="${WORK_ROOT}/osmap"
HTTP_LOG_PATH="${RUNTIME_DIR}/serve.log"
HTTP_PID_PATH="${RUNTIME_DIR}/serve.pid"
HELPER_LOG_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.log"
HELPER_PID_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.pid"
HELPER_SOCKET_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.sock"
LISTEN_PORT="${OSMAP_LIVE_V3_SOURCE_ATTACHMENT_PORT:-}"
VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
AUTH_SOCKET_PATH="${OSMAP_DOVEADM_AUTH_SOCKET_PATH:-/var/run/osmap-auth}"
TRUSTED_WEB_RUNTIME_UID="${OSMAP_TRUSTED_WEB_RUNTIME_UID:-$(id -u _osmap)}"
USERDB_SOCKET_PATH="${OSMAP_DOVEADM_USERDB_SOCKET_PATH:-/var/run/osmap-userdb}"
USER_AGENT="osmap-live-v3-source-attachments"
KEEP_WORK_ROOT="${OSMAP_KEEP_WORK_ROOT:-0}"
REPORT_PATH=""
RESTORE_PENDING=0
ORIGINAL_HASH=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --report)
      REPORT_PATH="$2"
      shift 2
      ;;
    *)
      printf 'usage: %s [--report PATH]\n' "$0" >&2
      exit 2
      ;;
  esac
done

log() {
  printf '%s\n' "$*"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing required tool: $1"
    exit 1
  }
}

sql_quote() {
  printf '%s' "$1" | sed "s/'/''/g"
}

update_mailbox_hash() {
  next_hash="$1"
  quoted_hash="$(sql_quote "${next_hash}")"
  quoted_user="$(sql_quote "${VALIDATION_USER}")"

  doas mariadb postfixadmin <<SQL
UPDATE mailbox
SET password='${quoted_hash}'
WHERE username='${quoted_user}' AND active='1';
SQL
}

restore_original_hash() {
  [ "${RESTORE_PENDING}" = "1" ] || return 0
  update_mailbox_hash "${ORIGINAL_HASH}" || true
  RESTORE_PENDING=0
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

cleanup_subject() {
  subject="$1"
  [ -n "${subject}" ] || return 0
  doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
    expunge -u "${VALIDATION_USER}" mailbox INBOX header Subject "${subject}" \
    >/dev/null 2>&1 || true
}

cleanup() {
  terminate_pid_path "${HTTP_PID_PATH}"
  terminate_pid_path "${HELPER_PID_PATH}"
  cleanup_subject "${SOURCE_SUBJECT:-}"
  cleanup_subject "${STALE_SUBJECT:-}"
  cleanup_subject "${SEND_SUBJECT:-}"
  cleanup_subject "${DUPLICATE_SUBJECT:-}"
  cleanup_subject "${TAMPER_MAILBOX_SUBJECT:-}"
  cleanup_subject "${TAMPER_UID_SUBJECT:-}"
  cleanup_subject "${TAMPER_PART_SUBJECT:-}"
  cleanup_subject "${MISSING_CSRF_SUBJECT:-}"
  cleanup_subject "${CROSS_ORIGIN_SUBJECT:-}"
  restore_original_hash
  if [ "${KEEP_WORK_ROOT}" = "1" ]; then
    log "keeping live validation root at ${WORK_ROOT}"
  else
    doas rm -rf "${WORK_ROOT}" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM HUP

require_tool awk
require_tool cargo
require_tool doas
require_tool grep
require_tool hexdump
require_tool nc
require_tool openssl
require_tool python3
require_tool sed
require_tool sha256

if [ -z "${LISTEN_PORT}" ]; then
  LISTEN_PORT="$((19100 + ($$ % 1000)))"
fi

if [ -z "${REPORT_PATH}" ]; then
  REPORT_PATH="${WORK_ROOT}/v3-source-attachment-report.txt"
fi

NOW="$(date +%s)"
SOURCE_SUBJECT="OSMAP V3 source attachment proof ${NOW}-$$"
STALE_SUBJECT="OSMAP V3 stale source attachment proof ${NOW}-$$"
SEND_SUBJECT="OSMAP V3 selected source send proof ${NOW}-$$"
DUPLICATE_SUBJECT="OSMAP V3 duplicate source selection proof ${NOW}-$$"
TAMPER_MAILBOX_SUBJECT="OSMAP V3 tamper mailbox source proof ${NOW}-$$"
TAMPER_UID_SUBJECT="OSMAP V3 tamper uid source proof ${NOW}-$$"
TAMPER_PART_SUBJECT="OSMAP V3 tamper part source proof ${NOW}-$$"
MISSING_CSRF_SUBJECT="OSMAP V3 source missing csrf proof ${NOW}-$$"
CROSS_ORIGIN_SUBJECT="OSMAP V3 source cross origin proof ${NOW}-$$"
SOURCE_ATTACHMENT_MARKER="osmap selected source attachment marker ${NOW}-$$"
STALE_ATTACHMENT_MARKER="osmap stale source attachment marker ${NOW}-$$"
SOURCE_ATTACHMENT_FILENAME="source-proof.txt"
SOURCE_PART_PATH="1.2"

ORIGINAL_HASH="$(doas mariadb -N -B postfixadmin -e "SELECT password FROM mailbox WHERE username='$(sql_quote "${VALIDATION_USER}")' AND active='1';")"
[ -n "${ORIGINAL_HASH}" ] || {
  log "no active mailbox password hash found for ${VALIDATION_USER}"
  exit 1
}

TEMP_PASSWORD="$(openssl rand -hex 16)"
[ -n "${TEMP_PASSWORD}" ] || {
  log "failed to generate temporary validation password"
  exit 1
}

TEMP_HASH="$(doas doveadm pw -s BLF-CRYPT -p "${TEMP_PASSWORD}")"
[ -n "${TEMP_HASH}" ] || {
  log "failed to generate temporary validation password hash"
  exit 1
}

TOTP_SECRET_BASE32="$(
  python3 - <<'PY'
import base64
import os

print(base64.b32encode(os.urandom(20)).decode("ascii").rstrip("="))
PY
)"

USERNAME_HEX="$(printf '%s' "${VALIDATION_USER}" | hexdump -ve '/1 "%02x"')"
TOTP_SECRET_PATH="${TOTP_DIR}/${USERNAME_HEX}.totp"

log "installing temporary validation credential for ${VALIDATION_USER}"
update_mailbox_hash "${TEMP_HASH}"
RESTORE_PENDING=1

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
  "${TOTP_DIR}" \
  "${SECRET_DIR}"
doas install -d -o vmail -g vmail -m 755 "${HELPER_RUNTIME_DIR}"
doas install -d -o vmail -g vmail -m 700 "${HELPER_STATE_RUNTIME_DIR}" "${HELPER_SECRET_DIR}"

log "building current OSMAP tree"
cd "${PROJECT_ROOT}"
TMPDIR="${TMPDIR_PATH}" \
  CARGO_HOME="${CARGO_HOME_PATH}" \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR_PATH}" \
  cargo build --quiet
doas install -o _osmap -g _osmap -m 755 "${CARGO_TARGET_DIR_PATH}/debug/osmap" "${BIN_PATH}"

log "verifying target mailbox layout for validation user"
doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
  mailbox list -u "${VALIDATION_USER}" | grep -Fxq "INBOX" || {
  log "validation mailbox INBOX does not exist for ${VALIDATION_USER}"
  exit 1
}

log "writing isolated validation TOTP secret"
doas sh -c "cat > '${TOTP_SECRET_PATH}' <<'EOF'
secret=${TOTP_SECRET_BASE32}
EOF
chmod 600 '${TOTP_SECRET_PATH}'
chown _osmap:_osmap '${TOTP_SECRET_PATH}'"

log "writing isolated helper request grant keys"
GRANT_KEY="$(
  openssl rand -base64 48
)"
doas sh -c "cat > '${WEB_GRANT_KEY_PATH}' <<'EOF'
${GRANT_KEY}
EOF
chmod 600 '${WEB_GRANT_KEY_PATH}'
chown _osmap:_osmap '${WEB_GRANT_KEY_PATH}'
cat > '${HELPER_GRANT_KEY_PATH}' <<'EOF'
${GRANT_KEY}
EOF
chmod 600 '${HELPER_GRANT_KEY_PATH}'
chown vmail:vmail '${HELPER_GRANT_KEY_PATH}'"

generate_totp_code() {
  python3 - "$TOTP_SECRET_BASE32" <<'PY'
import base64
import hashlib
import hmac
import struct
import sys
import time

secret = sys.argv[1].strip().replace(" ", "").replace("-", "").upper()
padding = "=" * ((8 - len(secret) % 8) % 8)
key = base64.b32decode(secret + padding, casefold=True)
counter = int(time.time()) // 30
digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[19] & 0x0F
binary = ((digest[offset] & 0x7F) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]
print(f"{binary % 1000000:06d}")
PY
}

urlencode_login_body() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys
import urllib.parse

print(urllib.parse.urlencode({
    "username": sys.argv[1],
    "password": sys.argv[2],
    "totp_code": sys.argv[3],
}))
PY
}

urlencode_send_with_source() {
  python3 - "$1" "$2" "$3" "$4" "$5" "$6" "$7" "${8:-}" <<'PY'
import sys
import urllib.parse

values = {
    "csrf_token": sys.argv[1],
    "to": sys.argv[2],
    "subject": sys.argv[3],
    "body": sys.argv[4],
    "source_mailbox": sys.argv[5],
    "source_uid": sys.argv[6],
    "include_original_attachment_1": sys.argv[7],
}
if sys.argv[8]:
    values["include_original_attachment_2"] = sys.argv[8]
print(urllib.parse.urlencode(values))
PY
}

urlencode_send_missing_csrf() {
  python3 - "$1" "$2" "$3" "$4" "$5" "$6" <<'PY'
import sys
import urllib.parse

print(urllib.parse.urlencode({
    "to": sys.argv[1],
    "subject": sys.argv[2],
    "body": sys.argv[3],
    "source_mailbox": sys.argv[4],
    "source_uid": sys.argv[5],
    "include_original_attachment_1": sys.argv[6],
}))
PY
}

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
    OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH='${HELPER_GRANT_KEY_PATH}' \
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
      return 0
    fi
    sleep 1
    tries="$((tries + 1))"
  done
  log "mailbox helper did not become ready"
  [ -f "${HELPER_LOG_PATH}" ] && doas cat "${HELPER_LOG_PATH}"
  return 1
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
    OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH='${WEB_GRANT_KEY_PATH}' \
    OSMAP_DOVEADM_AUTH_SOCKET_PATH='${AUTH_SOCKET_PATH}' \
    OSMAP_LOG_LEVEL=info \
    OSMAP_SESSION_LIFETIME_SECS=3600 \
    OSMAP_MAILBOX_WORKER_BUDGET=1 \
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
      return 0
    fi
    sleep 1
    tries="$((tries + 1))"
  done
  log "http runtime did not become ready"
  [ -f "${HTTP_LOG_PATH}" ] && doas cat "${HTTP_LOG_PATH}"
  return 1
}

request_get() {
  path="$1"
  cookie_value="${2:-}"
  {
    printf 'GET %s HTTP/1.1\r\n' "${path}"
    printf 'Host: 127.0.0.1\r\n'
    printf 'User-Agent: %s\r\n' "${USER_AGENT}"
    if [ -n "${cookie_value}" ]; then
      printf 'Cookie: osmap_session=%s\r\n' "${cookie_value}"
    fi
    printf 'Connection: close\r\n'
    printf '\r\n'
  } | nc -N 127.0.0.1 "${LISTEN_PORT}"
}

request_post_origin() {
  path="$1"
  body="$2"
  cookie_value="${3:-}"
  origin="${4:-https://127.0.0.1}"
  content_length="$(printf '%s' "${body}" | wc -c | tr -d ' ')"
  {
    printf 'POST %s HTTP/1.1\r\n' "${path}"
    printf 'Host: 127.0.0.1\r\n'
    printf 'User-Agent: %s\r\n' "${USER_AGENT}"
    if [ -n "${cookie_value}" ]; then
      printf 'Cookie: osmap_session=%s\r\n' "${cookie_value}"
    fi
    printf 'Origin: %s\r\n' "${origin}"
    printf 'Content-Type: application/x-www-form-urlencoded\r\n'
    printf 'Content-Length: %s\r\n' "${content_length}"
    printf 'Connection: close\r\n'
    printf '\r\n'
    printf '%s' "${body}"
  } | nc -N 127.0.0.1 "${LISTEN_PORT}"
}

status_line() {
  printf '%s' "$1" | sed -n '1p' | tr -d '\r'
}

header_value() {
  printf '%s\n' "$1" | awk -F': ' -v target="$2" '
    tolower($1) == tolower(target) {
      gsub("\r", "", $2)
      print $2
      exit
    }
  '
}

response_body() {
  printf '%s' "$1" | awk '
    BEGIN { body = 0 }
    /^\r?$/ { body = 1; next }
    body { gsub("\r", ""); print }
  '
}

inject_message() {
  subject="$1"
  marker="$2"
  boundary="osmap-v3-source-${NOW}-$$-$3"
  {
    printf 'From: OSMAP V3 Source Attachment Proof <%s>\n' "${VALIDATION_USER}"
    printf 'To: %s\n' "${VALIDATION_USER}"
    printf 'Subject: %s\n' "${subject}"
    printf 'MIME-Version: 1.0\n'
    printf 'Content-Type: multipart/mixed; boundary="%s"\n' "${boundary}"
    printf '\n'
    printf -- '--%s\n' "${boundary}"
    printf 'Content-Type: text/plain; charset=utf-8\n'
    printf '\n'
    printf 'selected source attachment proof message\n'
    printf -- '--%s\n' "${boundary}"
    printf 'Content-Type: text/plain; name="%s"\n' "${SOURCE_ATTACHMENT_FILENAME}"
    printf 'Content-Disposition: attachment; filename="%s"\n' "${SOURCE_ATTACHMENT_FILENAME}"
    printf '\n'
    printf '%s\n' "${marker}"
    printf -- '--%s--\n' "${boundary}"
  } | /usr/sbin/sendmail -t
}

lookup_uid() {
  subject="$1"
  doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
    search -u "${VALIDATION_USER}" mailbox INBOX header Subject "${subject}" \
    | awk 'NF > 0 { print $NF; exit }'
}

wait_for_uid() {
  subject="$1"
  uid=""
  tries=0
  while [ -z "${uid}" ] && [ "${tries}" -lt 20 ]; do
    sleep 1
    uid="$(lookup_uid "${subject}" || true)"
    tries="$((tries + 1))"
  done
  [ -n "${uid}" ] || return 1
  printf '%s' "${uid}"
}

require_status() {
  label="$1"
  actual="$2"
  expected="$3"
  [ "${actual}" = "${expected}" ] || {
    log "${label} returned ${actual}, expected ${expected}"
    exit 1
  }
}

require_not_submitted_status() {
  label="$1"
  actual="$2"
  case "${actual}" in
    "HTTP/1.1 400 Bad Request"|"HTTP/1.1 403 Forbidden"|"HTTP/1.1 503 Service Unavailable")
      return 0
      ;;
  esac
  log "${label} was not safely rejected: ${actual}"
  exit 1
}

wait_for_helper_socket
wait_for_healthz

doas grep -Fq 'mailbox_boundary_mode="local_helper_socket"' "${HTTP_LOG_PATH}" || {
  log "serve startup did not report helper-backed mailbox boundary"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}

log "verifying login form renders"
LOGIN_FORM_RESPONSE="$(request_get "/login")"
LOGIN_FORM_STATUS="$(status_line "${LOGIN_FORM_RESPONSE}")"
require_status "login form" "${LOGIN_FORM_STATUS}" "HTTP/1.1 200 OK"

TOTP_CODE="$(generate_totp_code)"
LOGIN_BODY="$(urlencode_login_body "${VALIDATION_USER}" "${TEMP_PASSWORD}" "${TOTP_CODE}")"

log "performing real password-plus-TOTP login"
LOGIN_RESPONSE="$(request_post_origin "/login" "${LOGIN_BODY}")"
LOGIN_STATUS="$(status_line "${LOGIN_RESPONSE}")"
LOGIN_LOCATION="$(header_value "${LOGIN_RESPONSE}" "Location")"
LOGIN_SET_COOKIE="$(header_value "${LOGIN_RESPONSE}" "Set-Cookie")"
require_status "login" "${LOGIN_STATUS}" "HTTP/1.1 303 See Other"
[ "${LOGIN_LOCATION}" = "/mailboxes" ] || {
  log "login redirect was unexpected"
  exit 1
}

SESSION_TOKEN="$(printf '%s' "${LOGIN_SET_COOKIE}" | sed -n 's/^osmap_session=\([^;]*\).*$/\1/p')"
[ -n "${SESSION_TOKEN}" ] || {
  log "login response did not issue an OSMAP session cookie"
  exit 1
}

MAILBOXES_RESPONSE="$(request_get "/mailboxes" "${SESSION_TOKEN}")"
MAILBOXES_STATUS="$(status_line "${MAILBOXES_RESPONSE}")"
require_status "authenticated mailboxes" "${MAILBOXES_STATUS}" "HTTP/1.1 200 OK"

log "injecting source attachment fixtures"
inject_message "${SOURCE_SUBJECT}" "${SOURCE_ATTACHMENT_MARKER}" source
SOURCE_UID="$(wait_for_uid "${SOURCE_SUBJECT}")" || {
  log "failed to locate source validation message"
  exit 1
}
inject_message "${STALE_SUBJECT}" "${STALE_ATTACHMENT_MARKER}" stale
STALE_UID="$(wait_for_uid "${STALE_SUBJECT}")" || {
  log "failed to locate stale validation message"
  exit 1
}

log "loading forward compose page with surfaced source attachment"
COMPOSE_RESPONSE="$(request_get "/compose?mode=forward&mailbox=INBOX&uid=${SOURCE_UID}" "${SESSION_TOKEN}")"
COMPOSE_STATUS="$(status_line "${COMPOSE_RESPONSE}")"
COMPOSE_BODY="$(response_body "${COMPOSE_RESPONSE}")"
require_status "forward compose source" "${COMPOSE_STATUS}" "HTTP/1.1 200 OK"
printf '%s\n' "${COMPOSE_BODY}" | grep -Fq 'Source Attachments' || {
  log "forward compose did not render source attachment controls"
  exit 1
}
printf '%s\n' "${COMPOSE_BODY}" | grep -Fq "value=\"${SOURCE_PART_PATH}\"" || {
  log "forward compose did not render expected source attachment part"
  exit 1
}
CSRF_TOKEN="$(printf '%s\n' "${COMPOSE_BODY}" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' | head -n 1)"
[ -n "${CSRF_TOKEN}" ] || {
  log "forward compose page did not expose a CSRF token"
  exit 1
}

log "sending selected source attachment"
POSITIVE_BODY="$(urlencode_send_with_source "${CSRF_TOKEN}" "${VALIDATION_USER}" "${SEND_SUBJECT}" "selected source attachment proof body" INBOX "${SOURCE_UID}" "${SOURCE_PART_PATH}")"
POSITIVE_RESPONSE="$(request_post_origin "/send" "${POSITIVE_BODY}" "${SESSION_TOKEN}")"
POSITIVE_STATUS="$(status_line "${POSITIVE_RESPONSE}")"
POSITIVE_LOCATION="$(header_value "${POSITIVE_RESPONSE}" "Location")"
require_status "selected source attachment send" "${POSITIVE_STATUS}" "HTTP/1.1 303 See Other"
[ "${POSITIVE_LOCATION}" = "/compose?sent=1" ] || {
  log "selected source send redirect was unexpected"
  exit 1
}

DELIVERED_UID="$(wait_for_uid "${SEND_SUBJECT}")" || {
  log "selected source send was not delivered"
  [ -f "${HTTP_LOG_PATH}" ] && doas cat "${HTTP_LOG_PATH}"
  exit 1
}

DELIVERED_MESSAGE_RESPONSE="$(request_get "/message?mailbox=INBOX&uid=${DELIVERED_UID}" "${SESSION_TOKEN}")"
DELIVERED_MESSAGE_STATUS="$(status_line "${DELIVERED_MESSAGE_RESPONSE}")"
DELIVERED_MESSAGE_BODY="$(response_body "${DELIVERED_MESSAGE_RESPONSE}")"
require_status "delivered selected source message view" "${DELIVERED_MESSAGE_STATUS}" "HTTP/1.1 200 OK"
printf '%s\n' "${DELIVERED_MESSAGE_BODY}" | grep -Fq "${SOURCE_ATTACHMENT_FILENAME}" || {
  log "delivered message did not surface selected source attachment filename"
  exit 1
}

DELIVERED_ATTACHMENT_RESPONSE="$(request_get "/attachment?mailbox=INBOX&uid=${DELIVERED_UID}&part=${SOURCE_PART_PATH}" "${SESSION_TOKEN}")"
DELIVERED_ATTACHMENT_STATUS="$(status_line "${DELIVERED_ATTACHMENT_RESPONSE}")"
DELIVERED_ATTACHMENT_DISPOSITION="$(header_value "${DELIVERED_ATTACHMENT_RESPONSE}" "Content-Disposition")"
DELIVERED_ATTACHMENT_BODY="$(response_body "${DELIVERED_ATTACHMENT_RESPONSE}")"
require_status "delivered selected source attachment download" "${DELIVERED_ATTACHMENT_STATUS}" "HTTP/1.1 200 OK"
printf '%s\n' "${DELIVERED_ATTACHMENT_DISPOSITION}" | grep -Fq "attachment; filename=\"${SOURCE_ATTACHMENT_FILENAME}\"" || {
  log "delivered selected source attachment did not force download"
  exit 1
}
printf '%s\n' "${DELIVERED_ATTACHMENT_BODY}" | grep -Fq "${SOURCE_ATTACHMENT_MARKER}" || {
  log "delivered selected source attachment body marker was not preserved"
  exit 1
}

log "checking duplicate selection rejection"
DUPLICATE_BODY="$(urlencode_send_with_source "${CSRF_TOKEN}" "${VALIDATION_USER}" "${DUPLICATE_SUBJECT}" "duplicate selected source attachment proof body" INBOX "${SOURCE_UID}" "${SOURCE_PART_PATH}" "${SOURCE_PART_PATH}")"
DUPLICATE_RESPONSE="$(request_post_origin "/send" "${DUPLICATE_BODY}" "${SESSION_TOKEN}")"
DUPLICATE_STATUS="$(status_line "${DUPLICATE_RESPONSE}")"
require_status "duplicate selected source attachment" "${DUPLICATE_STATUS}" "HTTP/1.1 400 Bad Request"

log "checking tampered mailbox rejection"
TAMPER_MAILBOX_BODY="$(urlencode_send_with_source "${CSRF_TOKEN}" "${VALIDATION_USER}" "${TAMPER_MAILBOX_SUBJECT}" "tampered source mailbox proof body" "NotARealMailbox" "${SOURCE_UID}" "${SOURCE_PART_PATH}")"
TAMPER_MAILBOX_RESPONSE="$(request_post_origin "/send" "${TAMPER_MAILBOX_BODY}" "${SESSION_TOKEN}")"
TAMPER_MAILBOX_STATUS="$(status_line "${TAMPER_MAILBOX_RESPONSE}")"
require_not_submitted_status "tampered source mailbox" "${TAMPER_MAILBOX_STATUS}"

log "checking tampered UID rejection"
TAMPER_UID_BODY="$(urlencode_send_with_source "${CSRF_TOKEN}" "${VALIDATION_USER}" "${TAMPER_UID_SUBJECT}" "tampered source uid proof body" INBOX "$((SOURCE_UID + 999999))" "${SOURCE_PART_PATH}")"
TAMPER_UID_RESPONSE="$(request_post_origin "/send" "${TAMPER_UID_BODY}" "${SESSION_TOKEN}")"
TAMPER_UID_STATUS="$(status_line "${TAMPER_UID_RESPONSE}")"
require_not_submitted_status "tampered source uid" "${TAMPER_UID_STATUS}"

log "checking tampered part-path rejection"
TAMPER_PART_BODY="$(urlencode_send_with_source "${CSRF_TOKEN}" "${VALIDATION_USER}" "${TAMPER_PART_SUBJECT}" "tampered source part proof body" INBOX "${SOURCE_UID}" "1.99")"
TAMPER_PART_RESPONSE="$(request_post_origin "/send" "${TAMPER_PART_BODY}" "${SESSION_TOKEN}")"
TAMPER_PART_STATUS="$(status_line "${TAMPER_PART_RESPONSE}")"
require_not_submitted_status "tampered source part" "${TAMPER_PART_STATUS}"

log "checking missing CSRF rejection"
MISSING_CSRF_BODY="$(urlencode_send_missing_csrf "${VALIDATION_USER}" "${MISSING_CSRF_SUBJECT}" "missing csrf selected source proof body" INBOX "${SOURCE_UID}" "${SOURCE_PART_PATH}")"
MISSING_CSRF_RESPONSE="$(request_post_origin "/send" "${MISSING_CSRF_BODY}" "${SESSION_TOKEN}")"
MISSING_CSRF_STATUS="$(status_line "${MISSING_CSRF_RESPONSE}")"
require_status "missing csrf selected source attachment" "${MISSING_CSRF_STATUS}" "HTTP/1.1 403 Forbidden"

log "checking cross-origin rejection"
CROSS_ORIGIN_BODY="$(urlencode_send_with_source "${CSRF_TOKEN}" "${VALIDATION_USER}" "${CROSS_ORIGIN_SUBJECT}" "cross origin selected source proof body" INBOX "${SOURCE_UID}" "${SOURCE_PART_PATH}")"
CROSS_ORIGIN_RESPONSE="$(request_post_origin "/send" "${CROSS_ORIGIN_BODY}" "${SESSION_TOKEN}" "https://attacker.invalid")"
CROSS_ORIGIN_STATUS="$(status_line "${CROSS_ORIGIN_RESPONSE}")"
require_status "cross-origin selected source attachment" "${CROSS_ORIGIN_STATUS}" "HTTP/1.1 403 Forbidden"

log "checking stale source rejection"
cleanup_subject "${STALE_SUBJECT}"
STALE_BODY="$(urlencode_send_with_source "${CSRF_TOKEN}" "${VALIDATION_USER}" "${STALE_SUBJECT}" "stale selected source proof body" INBOX "${STALE_UID}" "${SOURCE_PART_PATH}")"
STALE_RESPONSE="$(request_post_origin "/send" "${STALE_BODY}" "${SESSION_TOKEN}")"
STALE_STATUS="$(status_line "${STALE_RESPONSE}")"
require_not_submitted_status "stale selected source attachment" "${STALE_STATUS}"

for subject in \
  "${DUPLICATE_SUBJECT}" \
  "${TAMPER_MAILBOX_SUBJECT}" \
  "${TAMPER_UID_SUBJECT}" \
  "${TAMPER_PART_SUBJECT}" \
  "${MISSING_CSRF_SUBJECT}" \
  "${CROSS_ORIGIN_SUBJECT}" \
  "${STALE_SUBJECT}"
do
  failed_uid="$(lookup_uid "${subject}" || true)"
  [ -z "${failed_uid}" ] || {
    log "rejected source-attachment request unexpectedly delivered subject ${subject}"
    exit 1
  }
done

doas grep -q 'action=session_issued' "${HTTP_LOG_PATH}" || {
  log "session issuance event missing from runtime log"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}
doas grep -q 'action=message_submitted' "${HTTP_LOG_PATH}" || {
  log "message submitted event missing from runtime log"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}
doas grep -F 'action=request_budget_acquired' "${HTTP_LOG_PATH}" |
  grep -F 'route_class="original_attachment_send"' >/dev/null || {
  log "original attachment send budget acquisition event missing"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}
doas grep -F 'action=request_budget_released' "${HTTP_LOG_PATH}" |
  grep -F 'route_class="original_attachment_send"' >/dev/null || {
  log "original attachment send budget release event missing"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}
doas grep -q 'action=http_send_original_attachment_selection_rejected' "${HTTP_LOG_PATH}" || {
  log "duplicate-selection rejection event missing"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}
doas grep -q 'action=http_send_original_attachment_fetch_failed' "${HTTP_LOG_PATH}" || {
  log "source attachment fetch-failure event missing"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}

ASSESSED_AT_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
ASSESSED_REF="$(cd "${PROJECT_ROOT}" && git rev-parse HEAD)"
ASSESSED_HOST="$(hostname)"

{
  printf 'osmap_wstg_busl_003_result=passed\n'
  printf 'assessed_at_utc=%s\n' "${ASSESSED_AT_UTC}"
  printf 'assessed_host=%s\n' "${ASSESSED_HOST}"
  printf 'assessed_ref=%s\n' "${ASSESSED_REF}"
  printf 'validation_user=%s\n' "${VALIDATION_USER}"
  printf 'credential_proof=real_password_plus_totp_with_temporary_mailbox_hash\n'
  printf 'mailbox_boundary_mode=local_helper_socket\n'
  printf 'positive_compose_status=%s\n' "${COMPOSE_STATUS}"
  printf 'positive_send_status=%s\n' "${POSITIVE_STATUS}"
  printf 'positive_delivered_message_status=%s\n' "${DELIVERED_MESSAGE_STATUS}"
  printf 'positive_delivered_attachment_status=%s\n' "${DELIVERED_ATTACHMENT_STATUS}"
  printf 'duplicate_selection_status=%s\n' "${DUPLICATE_STATUS}"
  printf 'tampered_mailbox_status=%s\n' "${TAMPER_MAILBOX_STATUS}"
  printf 'tampered_uid_status=%s\n' "${TAMPER_UID_STATUS}"
  printf 'tampered_part_status=%s\n' "${TAMPER_PART_STATUS}"
  printf 'missing_csrf_status=%s\n' "${MISSING_CSRF_STATUS}"
  printf 'cross_origin_status=%s\n' "${CROSS_ORIGIN_STATUS}"
  printf 'stale_source_status=%s\n' "${STALE_STATUS}"
  printf 'delivered_uid_observed=yes\n'
  printf 'selected_attachment_filename_observed=yes\n'
  printf 'selected_attachment_body_marker_preserved=yes\n'
  printf 'rejected_cases_delivered=no\n'
  printf 'audit_session_issued_observed=yes\n'
  printf 'audit_message_submitted_observed=yes\n'
  printf 'audit_original_attachment_budget_observed=yes\n'
  printf 'audit_duplicate_rejection_observed=yes\n'
  printf 'audit_fetch_failure_observed=yes\n'
  printf 'secret_review=No password, password hash, TOTP material, session cookie, CSRF token, private message body, attachment body, provider secret, or host secret is included.\n'
} > "${REPORT_PATH}"

for forbidden in \
  "${TEMP_PASSWORD}" \
  "${TEMP_HASH}" \
  "${ORIGINAL_HASH}" \
  "${TOTP_SECRET_BASE32}" \
  "${TOTP_CODE}" \
  "${SESSION_TOKEN}" \
  "${CSRF_TOKEN}" \
  "${SOURCE_ATTACHMENT_MARKER}" \
  "${STALE_ATTACHMENT_MARKER}" \
  "selected source attachment proof body" \
  "duplicate selected source attachment proof body" \
  "tampered source mailbox proof body" \
  "tampered source uid proof body" \
  "tampered source part proof body" \
  "missing csrf selected source proof body" \
  "cross origin selected source proof body" \
  "stale selected source proof body"
do
  [ -n "${forbidden}" ] || continue
  if grep -Fq "${forbidden}" "${REPORT_PATH}"; then
    log "report unexpectedly contains sensitive evidence material"
    rm -f "${REPORT_PATH}"
    exit 1
  fi
done

log "live V3 selected source-attachment validation passed"
log "report_path=${REPORT_PATH}"
log "positive_send_status=${POSITIVE_STATUS}"
log "duplicate_selection_status=${DUPLICATE_STATUS}"
log "tampered_mailbox_status=${TAMPER_MAILBOX_STATUS}"
log "tampered_uid_status=${TAMPER_UID_STATUS}"
log "tampered_part_status=${TAMPER_PART_STATUS}"
log "stale_source_status=${STALE_STATUS}"
