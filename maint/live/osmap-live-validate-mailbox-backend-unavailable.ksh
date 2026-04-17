#!/bin/sh
#
# Validate bounded mailbox behavior when the helper backend is unavailable.
#
# This script starts an isolated enforced browser runtime with a synthetic
# validated session but points the required mailbox-helper socket path at a
# non-existent socket. It then verifies that mailbox access fails as a bounded
# `503 Service Unavailable` response rather than widening privilege, crashing,
# or leaking backend details.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_ROOT="${OSMAP_LIVE_WORK_ROOT:-/home/osmap-live-mailbox-backend-unavailable-$$}"
STATE_ROOT="${WORK_ROOT}/state"
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
LOG_PATH="${RUNTIME_DIR}/serve.log"
PID_PATH="${RUNTIME_DIR}/serve.pid"
LISTEN_PORT="${OSMAP_LIVE_MAILBOX_BACKEND_UNAVAILABLE_PORT:-}"
VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
AUTH_SOCKET_PATH="${OSMAP_DOVEADM_AUTH_SOCKET_PATH:-/var/run/osmap-auth}"
UNAVAILABLE_HELPER_SOCKET_PATH="${WORK_ROOT}/missing-helper.sock"
SESSION_TOKEN="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SESSION_ID="${SESSION_TOKEN}"
CSRF_TOKEN="$(printf 'csrf:%s' "${SESSION_TOKEN}" | sha256 -q)"
USER_AGENT="osmap-live-mailbox-backend-unavailable"
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

cleanup() {
  if [ -f "${PID_PATH}" ]; then
    doas kill "$(doas cat "${PID_PATH}")" 2>/dev/null || true
  fi
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
require_tool grep
require_tool sed
require_tool awk

if [ -z "${LISTEN_PORT}" ]; then
  LISTEN_PORT="$((19200 + ($$ % 1000)))"
fi

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

log "building current OSMAP tree"
cd "${PROJECT_ROOT}"
TMPDIR="${TMPDIR_PATH}" \
  CARGO_HOME="${CARGO_HOME_PATH}" \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR_PATH}" \
  cargo build --quiet
doas install -o _osmap -g _osmap -m 755 "${CARGO_TARGET_DIR_PATH}/debug/osmap" "${BIN_PATH}"

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

log "starting enforced browser runtime as _osmap with unavailable helper socket"
doas -u _osmap sh -c "
  umask 077
  echo \$$ > '${PID_PATH}'
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
    OSMAP_MAILBOX_HELPER_SOCKET_PATH='${UNAVAILABLE_HELPER_SOCKET_PATH}' \
    OSMAP_DOVEADM_AUTH_SOCKET_PATH='${AUTH_SOCKET_PATH}' \
    OSMAP_LOG_LEVEL=info \
    OSMAP_SESSION_LIFETIME_SECS=3600 \
    OSMAP_OPENBSD_CONFINEMENT_MODE=enforce \
    '${BIN_PATH}' >'${LOG_PATH}' 2>&1
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
  [ -f "${LOG_PATH}" ] && doas cat "${LOG_PATH}"
  return 1
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

request_get() {
  path="$1"
  {
    printf 'GET %s HTTP/1.1\r\n' "${path}"
    printf 'Host: 127.0.0.1\r\n'
    printf 'User-Agent: %s\r\n' "${USER_AGENT}"
    printf 'Cookie: osmap_session=%s\r\n' "${SESSION_TOKEN}"
    printf 'Connection: close\r\n'
    printf '\r\n'
  } | nc -N 127.0.0.1 "${LISTEN_PORT}"
}

wait_for_healthz

log "verifying bounded mailbox failure when helper backend is unavailable"
MAILBOX_RESPONSE="$(request_get "/mailboxes")"
[ "$(status_line "${MAILBOX_RESPONSE}")" = "HTTP/1.1 503 Service Unavailable" ] || {
  log "/mailboxes did not return 503 when helper backend was unavailable"
  printf '%s\n' "${MAILBOX_RESPONSE}"
  exit 1
}

MAILBOX_BODY="$(response_body "${MAILBOX_RESPONSE}")"
printf '%s\n' "${MAILBOX_BODY}" | grep -Fq "Mailbox Access Unavailable" || {
  log "/mailboxes did not render the bounded unavailable title"
  printf '%s\n' "${MAILBOX_RESPONSE}"
  exit 1
}
printf '%s\n' "${MAILBOX_BODY}" | grep -Fq "The service could not complete the request at this time." || {
  log "/mailboxes did not render the bounded public failure message"
  printf '%s\n' "${MAILBOX_RESPONSE}"
  exit 1
}

doas grep -q 'mailbox_list_failed' "${LOG_PATH}" || {
  log "mailbox_list_failed not found in runtime log"
  doas cat "${LOG_PATH}"
  exit 1
}
doas grep -q 'failed to connect to mailbox helper' "${LOG_PATH}" || {
  log "mailbox helper connect failure not found in runtime log"
  doas cat "${LOG_PATH}"
  exit 1
}

log "live mailbox-backend-unavailable validation succeeded"
