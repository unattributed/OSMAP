#!/bin/sh
#
# Validate real browser login plus one real browser send on a live OpenBSD host.
#
# This script is intended to run on a host like mail.blackbagsecurity.com where
# `doas -u _osmap` and `doas -u vmail` are available. It builds the current
# OSMAP tree, starts an isolated enforced mailbox helper and browser runtime,
# provisions a temporary TOTP secret in the isolated OSMAP state tree, performs
# a real password-plus-TOTP login, then sends one message through the browser
# route and confirms delivery to the validation mailbox.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_ROOT="${OSMAP_LIVE_WORK_ROOT:-/home/osmap-live-login-send-$$}"
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
LOGIN_RESPONSE_PATH="${WORK_ROOT}/login-response.txt"
MAILBOXES_RESPONSE_PATH="${WORK_ROOT}/mailboxes-response.txt"
COMPOSE_RESPONSE_PATH="${WORK_ROOT}/compose-response.txt"
SEND_RESPONSE_PATH="${WORK_ROOT}/send-response.txt"
LISTEN_PORT="${OSMAP_LIVE_LOGIN_SEND_PORT:-}"
VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
VALIDATION_PASSWORD="${OSMAP_VALIDATION_PASSWORD:-}"
TOTP_SECRET_BASE32="${OSMAP_VALIDATION_TOTP_SECRET_BASE32:-JBSWY3DPEHPK3PXP}"
AUTH_SOCKET_PATH="${OSMAP_DOVEADM_AUTH_SOCKET_PATH:-/var/run/osmap-auth}"
USERDB_SOCKET_PATH="${OSMAP_DOVEADM_USERDB_SOCKET_PATH:-/var/run/osmap-userdb}"
USER_AGENT="osmap-live-login-send"
KEEP_WORK_ROOT="${OSMAP_KEEP_WORK_ROOT:-0}"

log() {
  printf '%s\n' "$*"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing required tool: $1"
    exit 1
  }
}

cleanup_injected_message() {
  if [ -n "${SEND_SUBJECT:-}" ]; then
    doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
      expunge -u "${VALIDATION_USER}" mailbox INBOX header Subject "${SEND_SUBJECT}" \
      >/dev/null 2>&1 || true
  fi
}

cleanup() {
  if [ -f "${HTTP_PID_PATH}" ]; then
    doas kill "$(doas cat "${HTTP_PID_PATH}")" 2>/dev/null || true
  fi
  if [ -f "${HELPER_PID_PATH}" ]; then
    doas kill "$(doas cat "${HELPER_PID_PATH}")" 2>/dev/null || true
  fi
  cleanup_injected_message
  if [ "${KEEP_WORK_ROOT}" = "1" ]; then
    log "keeping live validation root at ${WORK_ROOT}"
  else
    doas rm -rf "${WORK_ROOT}" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

require_tool cargo
require_tool doas
require_tool nc
require_tool awk
require_tool grep
require_tool sed
require_tool python3
require_tool hexdump

[ -n "${VALIDATION_PASSWORD}" ] || {
  log "OSMAP_VALIDATION_PASSWORD must be set for real login validation"
  exit 1
}

if [ -z "${LISTEN_PORT}" ]; then
  LISTEN_PORT="$((18700 + ($$ % 1000)))"
fi

NOW="$(date +%s)"
SEND_SUBJECT="OSMAP login-send proof ${NOW}-$$"
USERNAME_HEX="$(printf '%s' "${VALIDATION_USER}" | hexdump -ve '/1 "%02x"')"
TOTP_SECRET_PATH="${TOTP_DIR}/${USERNAME_HEX}.totp"

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

generate_totp_code() {
  python3 - "$TOTP_SECRET_BASE32" <<'PY'
import base64
import hashlib
import hmac
import struct
import sys
import time

secret = sys.argv[1].strip().replace(" ", "").replace("-", "").upper()
key = base64.b32decode(secret, casefold=True)
counter = int(time.time()) // 30
digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[19] & 0x0F
binary = ((digest[offset] & 0x7F) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]
print(f"{binary % 1000000:06d}")
PY
}

urlencode_triplet() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys
import urllib.parse

print(
    urllib.parse.urlencode(
        {
            "username": sys.argv[1],
            "password": sys.argv[2],
            "totp_code": sys.argv[3],
        }
    )
)
PY
}

urlencode_send_body() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys
import urllib.parse

print(
    urllib.parse.urlencode(
        {
            "csrf_token": sys.argv[1],
            "to": sys.argv[2],
            "subject": sys.argv[3],
            "body": "real browser send validation",
        }
    )
)
PY
}

log "starting enforced mailbox helper as vmail"
doas -u vmail sh -c "
  umask 077
  echo \$$ > '${HELPER_PID_PATH}'
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
  echo \$$ > '${HTTP_PID_PATH}'
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
    OSMAP_DOVEADM_AUTH_SOCKET_PATH='${AUTH_SOCKET_PATH}' \
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

request_post() {
  path="$1"
  body="$2"
  cookie_value="${3:-}"
  content_length="$(printf '%s' "${body}" | wc -c | tr -d ' ')"
  {
    printf 'POST %s HTTP/1.1\r\n' "${path}"
    printf 'Host: 127.0.0.1\r\n'
    printf 'User-Agent: %s\r\n' "${USER_AGENT}"
    if [ -n "${cookie_value}" ]; then
      printf 'Cookie: osmap_session=%s\r\n' "${cookie_value}"
    fi
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

wait_for_delivery() {
  tries=0
  while [ "${tries}" -lt 20 ]; do
    uid="$(
      doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
        search -u "${VALIDATION_USER}" mailbox INBOX header Subject "${SEND_SUBJECT}" \
        | awk 'NF > 0 { print $NF; exit }'
    )"
    if [ -n "${uid}" ]; then
      printf '%s' "${uid}"
      return 0
    fi
    sleep 1
    tries="$((tries + 1))"
  done
  return 1
}

wait_for_helper_socket
wait_for_healthz

log "verifying login form renders"
LOGIN_FORM_RESPONSE="$(request_get "/login")"
printf '%s\n' "${LOGIN_FORM_RESPONSE}" > "${LOGIN_RESPONSE_PATH}"
printf '%s' "${LOGIN_FORM_RESPONSE}" | grep -q '^HTTP/1.1 200 OK' || {
  log "login form did not render"
  printf '%s\n' "${LOGIN_FORM_RESPONSE}"
  exit 1
}

TOTP_CODE="$(generate_totp_code)"
LOGIN_BODY="$(urlencode_triplet "${VALIDATION_USER}" "${VALIDATION_PASSWORD}" "${TOTP_CODE}")"

log "performing real password-plus-TOTP login"
LOGIN_RESPONSE="$(request_post "/login" "${LOGIN_BODY}")"
printf '%s\n' "${LOGIN_RESPONSE}" > "${LOGIN_RESPONSE_PATH}"
LOGIN_STATUS="$(status_line "${LOGIN_RESPONSE}")"
LOGIN_LOCATION="$(header_value "${LOGIN_RESPONSE}" "Location")"
LOGIN_SET_COOKIE="$(header_value "${LOGIN_RESPONSE}" "Set-Cookie")"

[ "${LOGIN_STATUS}" = "HTTP/1.1 303 See Other" ] || {
  log "login did not succeed"
  printf '%s\n' "${LOGIN_RESPONSE}"
  exit 1
}
[ "${LOGIN_LOCATION}" = "/mailboxes" ] || {
  log "login redirect was unexpected"
  printf '%s\n' "${LOGIN_RESPONSE}"
  exit 1
}

SESSION_TOKEN="$(printf '%s' "${LOGIN_SET_COOKIE}" | sed -n 's/^osmap_session=\([^;]*\).*$/\1/p')"
[ -n "${SESSION_TOKEN}" ] || {
  log "login response did not issue an OSMAP session cookie"
  printf '%s\n' "${LOGIN_RESPONSE}"
  exit 1
}

log "verifying issued session reaches the mailboxes page"
MAILBOXES_RESPONSE="$(request_get "/mailboxes" "${SESSION_TOKEN}")"
printf '%s\n' "${MAILBOXES_RESPONSE}" > "${MAILBOXES_RESPONSE_PATH}"
printf '%s' "${MAILBOXES_RESPONSE}" | grep -q '^HTTP/1.1 200 OK' || {
  log "mailboxes page did not load after login"
  printf '%s\n' "${MAILBOXES_RESPONSE}"
  exit 1
}
response_body "${MAILBOXES_RESPONSE}" | grep -q 'Signed in as' || {
  log "mailboxes page did not render signed-in state"
  printf '%s\n' "${MAILBOXES_RESPONSE}"
  exit 1
}

log "loading compose page to extract CSRF token"
COMPOSE_RESPONSE="$(request_get "/compose" "${SESSION_TOKEN}")"
printf '%s\n' "${COMPOSE_RESPONSE}" > "${COMPOSE_RESPONSE_PATH}"
printf '%s' "${COMPOSE_RESPONSE}" | grep -q '^HTTP/1.1 200 OK' || {
  log "compose page did not load"
  printf '%s\n' "${COMPOSE_RESPONSE}"
  exit 1
}
COMPOSE_BODY="$(response_body "${COMPOSE_RESPONSE}")"
CSRF_TOKEN="$(printf '%s\n' "${COMPOSE_BODY}" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' | head -n 1)"
[ -n "${CSRF_TOKEN}" ] || {
  log "compose page did not expose a CSRF token"
  printf '%s\n' "${COMPOSE_RESPONSE}"
  exit 1
}

SEND_BODY="$(urlencode_send_body "${CSRF_TOKEN}" "${VALIDATION_USER}" "${SEND_SUBJECT}")"

log "sending one real browser message"
SEND_RESPONSE="$(request_post "/send" "${SEND_BODY}" "${SESSION_TOKEN}")"
printf '%s\n' "${SEND_RESPONSE}" > "${SEND_RESPONSE_PATH}"
SEND_STATUS="$(status_line "${SEND_RESPONSE}")"
SEND_LOCATION="$(header_value "${SEND_RESPONSE}" "Location")"

[ "${SEND_STATUS}" = "HTTP/1.1 303 See Other" ] || {
  log "send route did not succeed"
  printf '%s\n' "${SEND_RESPONSE}"
  exit 1
}
[ "${SEND_LOCATION}" = "/compose?sent=1" ] || {
  log "send redirect was unexpected"
  printf '%s\n' "${SEND_RESPONSE}"
  exit 1
}

log "verifying message delivery into the validation mailbox"
DELIVERED_UID="$(wait_for_delivery)" || {
  log "sent validation message did not appear in INBOX"
  [ -f "${HTTP_LOG_PATH}" ] && doas cat "${HTTP_LOG_PATH}"
  exit 1
}

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

log "live login-plus-send validation passed"
log "login_status=${LOGIN_STATUS}"
log "send_status=${SEND_STATUS}"
log "delivered_uid=${DELIVERED_UID}"
