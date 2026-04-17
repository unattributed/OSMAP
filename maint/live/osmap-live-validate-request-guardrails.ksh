#!/bin/sh
#
# Validate CSRF and same-origin rejection behavior on a live OpenBSD host.
#
# This script starts an isolated enforced helper-backed OSMAP runtime with a
# synthetic validated session, then verifies that:
# - missing CSRF on an authenticated POST is rejected
# - invalid CSRF on an authenticated POST is rejected
# - cross-origin authenticated POST requests are rejected
# - authenticated POST requests without same-origin metadata are rejected

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_ROOT="${OSMAP_LIVE_WORK_ROOT:-/home/osmap-live-request-guardrails-$$}"
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
LOG_PATH="${RUNTIME_DIR}/serve.log"
PID_PATH="${RUNTIME_DIR}/serve.pid"
HELPER_LOG_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.log"
HELPER_PID_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.pid"
HELPER_SOCKET_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.sock"
LISTEN_PORT="${OSMAP_LIVE_REQUEST_GUARDRAILS_PORT:-}"
VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
AUTH_SOCKET_PATH="${OSMAP_DOVEADM_AUTH_SOCKET_PATH:-/var/run/osmap-auth}"
TRUSTED_WEB_RUNTIME_UID="${OSMAP_TRUSTED_WEB_RUNTIME_UID:-$(id -u _osmap)}"
USERDB_SOCKET_PATH="${OSMAP_DOVEADM_USERDB_SOCKET_PATH:-/var/run/osmap-userdb}"
SESSION_TOKEN="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SESSION_ID="$(printf 'session-id:%s' "${SESSION_TOKEN}" | sha256 -q)"
CSRF_TOKEN="$(printf 'csrf:%s' "${SESSION_TOKEN}" | sha256 -q)"
INVALID_CSRF_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
USER_AGENT="osmap-live-request-guardrails"
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
  if [ -f "${HELPER_PID_PATH}" ]; then
    doas kill "$(doas cat "${HELPER_PID_PATH}")" 2>/dev/null || true
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
require_tool sha256
require_tool grep
require_tool sed
require_tool awk

if [ -z "${LISTEN_PORT}" ]; then
  LISTEN_PORT="$((19100 + ($$ % 1000)))"
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
doas install -d -o vmail -g vmail -m 755 "${HELPER_RUNTIME_DIR}"
doas install -d -o vmail -g vmail -m 700 "${HELPER_STATE_RUNTIME_DIR}"

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
    OSMAP_LOG_LEVEL=info \
    OSMAP_MAILBOX_HELPER_SOCKET_PATH='${HELPER_SOCKET_PATH}' \
    OSMAP_DOVEADM_AUTH_SOCKET_PATH='${AUTH_SOCKET_PATH}' \
    OSMAP_TRUSTED_WEB_RUNTIME_UID='${TRUSTED_WEB_RUNTIME_UID}' \
    OSMAP_DOVEADM_USERDB_SOCKET_PATH='${USERDB_SOCKET_PATH}' \
    OSMAP_OPENBSD_CONFINEMENT_MODE=enforce \
    '${BIN_PATH}' >'${HELPER_LOG_PATH}' 2>&1
" &

wait_for_helper_socket() {
  tries=0
  while [ "${tries}" -lt 40 ]; do
    if doas test -S "${HELPER_SOCKET_PATH}"; then
      doas chown vmail:_osmap "${HELPER_SOCKET_PATH}"
      doas chmod 660 "${HELPER_SOCKET_PATH}"
      return 0
    fi
    sleep 1
    tries="$((tries + 1))"
  done
  log "mailbox helper socket did not become ready"
  [ -f "${HELPER_LOG_PATH}" ] && doas cat "${HELPER_LOG_PATH}"
  return 1
}

log "starting enforced browser runtime as _osmap"
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
    OSMAP_MAILBOX_HELPER_SOCKET_PATH='${HELPER_SOCKET_PATH}' \
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

post_request() {
  path="$1"
  body="$2"
  origin_value="${3:-}"
  referer_value="${4:-}"
  content_length="$(printf '%s' "${body}" | wc -c | tr -d ' ')"
  {
    printf 'POST %s HTTP/1.1\r\n' "${path}"
    printf 'Host: 127.0.0.1\r\n'
    printf 'User-Agent: %s\r\n' "${USER_AGENT}"
    printf 'Cookie: osmap_session=%s\r\n' "${SESSION_TOKEN}"
    if [ -n "${origin_value}" ]; then
      printf 'Origin: %s\r\n' "${origin_value}"
    fi
    if [ -n "${referer_value}" ]; then
      printf 'Referer: %s\r\n' "${referer_value}"
    fi
    printf 'Content-Type: application/x-www-form-urlencoded\r\n'
    printf 'Content-Length: %s\r\n' "${content_length}"
    printf 'Connection: close\r\n'
    printf '\r\n'
    printf '%s' "${body}"
  } | nc -N 127.0.0.1 "${LISTEN_PORT}"
}

wait_for_helper_socket
wait_for_healthz

log "verifying missing CSRF rejection on /settings"
MISSING_CSRF_RESPONSE="$(post_request "/settings" "html_display_preference=prefer_plain_text" "https://127.0.0.1")"
[ "$(status_line "${MISSING_CSRF_RESPONSE}")" = "HTTP/1.1 403 Forbidden" ] || {
  log "missing CSRF request did not return 403"
  printf '%s\n' "${MISSING_CSRF_RESPONSE}"
  exit 1
}
printf '%s\n' "$(response_body "${MISSING_CSRF_RESPONSE}")" | grep -Fq "CSRF Validation Failed" || {
  log "missing CSRF response did not render the expected body"
  printf '%s\n' "${MISSING_CSRF_RESPONSE}"
  exit 1
}

log "verifying invalid CSRF rejection on /settings"
INVALID_CSRF_RESPONSE="$(post_request "/settings" "csrf_token=${INVALID_CSRF_TOKEN}&html_display_preference=prefer_plain_text" "https://127.0.0.1")"
[ "$(status_line "${INVALID_CSRF_RESPONSE}")" = "HTTP/1.1 403 Forbidden" ] || {
  log "invalid CSRF request did not return 403"
  printf '%s\n' "${INVALID_CSRF_RESPONSE}"
  exit 1
}
printf '%s\n' "$(response_body "${INVALID_CSRF_RESPONSE}")" | grep -Fq "CSRF Validation Failed" || {
  log "invalid CSRF response did not render the expected body"
  printf '%s\n' "${INVALID_CSRF_RESPONSE}"
  exit 1
}

log "verifying cross-origin rejection on /logout"
CROSS_ORIGIN_RESPONSE="$(post_request "/logout" "csrf_token=${CSRF_TOKEN}" "https://evil.example")"
[ "$(status_line "${CROSS_ORIGIN_RESPONSE}")" = "HTTP/1.1 403 Forbidden" ] || {
  log "cross-origin request did not return 403"
  printf '%s\n' "${CROSS_ORIGIN_RESPONSE}"
  exit 1
}
printf '%s\n' "$(response_body "${CROSS_ORIGIN_RESPONSE}")" | grep -Fq "Request Origin Rejected" || {
  log "cross-origin response did not render the expected body"
  printf '%s\n' "${CROSS_ORIGIN_RESPONSE}"
  exit 1
}

log "verifying missing same-origin metadata rejection on /logout"
MISSING_ORIGIN_RESPONSE="$(post_request "/logout" "csrf_token=${CSRF_TOKEN}")"
[ "$(status_line "${MISSING_ORIGIN_RESPONSE}")" = "HTTP/1.1 403 Forbidden" ] || {
  log "missing same-origin metadata request did not return 403"
  printf '%s\n' "${MISSING_ORIGIN_RESPONSE}"
  exit 1
}
printf '%s\n' "$(response_body "${MISSING_ORIGIN_RESPONSE}")" | grep -Fq "Request Origin Rejected" || {
  log "missing same-origin metadata response did not render the expected body"
  printf '%s\n' "${MISSING_ORIGIN_RESPONSE}"
  exit 1
}

doas grep -q 'http_csrf_missing' "${LOG_PATH}" || {
  log "http_csrf_missing not found in runtime log"
  doas cat "${LOG_PATH}"
  exit 1
}
doas grep -q 'http_csrf_invalid' "${LOG_PATH}" || {
  log "http_csrf_invalid not found in runtime log"
  doas cat "${LOG_PATH}"
  exit 1
}
doas grep -q 'http_origin_mismatch' "${LOG_PATH}" || {
  log "http_origin_mismatch not found in runtime log"
  doas cat "${LOG_PATH}"
  exit 1
}
doas grep -q 'http_same_origin_missing' "${LOG_PATH}" || {
  log "http_same_origin_missing not found in runtime log"
  doas cat "${LOG_PATH}"
  exit 1
}

log "live request-guardrails validation succeeded"
