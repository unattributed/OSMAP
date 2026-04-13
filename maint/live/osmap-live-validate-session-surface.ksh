#!/bin/sh
#
# Validate the bounded browser session-management surface on a live OpenBSD host.
#
# This script is intended to run on a host like mail.blackbagsecurity.com where
# `doas -u _osmap` is available. It builds the current OSMAP tree, starts an
# isolated enforced browser runtime with a synthetic persisted session store,
# verifies `/sessions`, revokes a non-current session through the browser route,
# then logs out the current session and confirms the cookie and persisted state
# are both invalidated.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_ROOT="${OSMAP_LIVE_WORK_ROOT:-/home/osmap-live-session-surface-$$}"
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
SESSIONS_RESPONSE_PATH="${WORK_ROOT}/sessions-response.txt"
SESSIONS_REVOKED_RESPONSE_PATH="${WORK_ROOT}/sessions-revoked-response.txt"
REVOKE_RESPONSE_PATH="${WORK_ROOT}/revoke-response.txt"
LOGOUT_RESPONSE_PATH="${WORK_ROOT}/logout-response.txt"
STALE_RESPONSE_PATH="${WORK_ROOT}/stale-sessions-response.txt"
LISTEN_PORT="${OSMAP_LIVE_SESSION_SURFACE_PORT:-}"
VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
SESSION_TOKEN="${OSMAP_LIVE_SESSION_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
OTHER_SESSION_ID="${OSMAP_LIVE_OTHER_SESSION_ID:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}"
USER_AGENT="osmap-live-session-surface"
AUTH_SOCKET_PATH="${OSMAP_DOVEADM_AUTH_SOCKET_PATH:-/var/run/osmap-auth}"
TRUSTED_WEB_RUNTIME_UID="${OSMAP_TRUSTED_WEB_RUNTIME_UID:-$(id -u _osmap)}"
USERDB_SOCKET_PATH="${OSMAP_DOVEADM_USERDB_SOCKET_PATH:-/var/run/osmap-userdb}"
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
require_tool awk
require_tool grep
require_tool sed

if [ -z "${LISTEN_PORT}" ]; then
  LISTEN_PORT="$((18600 + ($$ % 1000)))"
fi

case "${SESSION_TOKEN}" in
  [0-9a-fA-F][0-9a-fA-F]*)
    ;;
  *)
    log "session token must be hex"
    exit 1
    ;;
esac

if [ "${#SESSION_TOKEN}" -ne 64 ]; then
  log "session token must be exactly 64 hex characters"
  exit 1
fi

case "${OTHER_SESSION_ID}" in
  [0-9a-fA-F][0-9a-fA-F]*)
    ;;
  *)
    log "other session id must be hex"
    exit 1
    ;;
esac

if [ "${#OTHER_SESSION_ID}" -ne 64 ]; then
  log "other session id must be exactly 64 hex characters"
  exit 1
fi

CURRENT_SESSION_ID="$(printf 'session-id:%s' "${SESSION_TOKEN}" | sha256 -q)"
CSRF_TOKEN="$(printf 'csrf:%s' "${SESSION_TOKEN}" | sha256 -q)"
NOW="$(date +%s)"
EXPIRES_AT="$((NOW + 3600))"
OTHER_ISSUED_AT="$((NOW - 120))"
OTHER_LAST_SEEN_AT="$((NOW - 30))"

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

log "writing synthetic session records"
doas sh -c "cat > '${SESSION_DIR}/${CURRENT_SESSION_ID}.session' <<'EOF'
session_id=${CURRENT_SESSION_ID}
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
chmod 600 '${SESSION_DIR}/${CURRENT_SESSION_ID}.session'
chown _osmap:_osmap '${SESSION_DIR}/${CURRENT_SESSION_ID}.session'"

doas sh -c "cat > '${SESSION_DIR}/${OTHER_SESSION_ID}.session' <<'EOF'
session_id=${OTHER_SESSION_ID}
csrf_token=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
canonical_username=${VALIDATION_USER}
issued_at=${OTHER_ISSUED_AT}
expires_at=${EXPIRES_AT}
last_seen_at=${OTHER_LAST_SEEN_AT}
revoked_at=
remote_addr=203.0.113.9
user_agent=Firefox/Other
factor=totp
EOF
chmod 600 '${SESSION_DIR}/${OTHER_SESSION_ID}.session'
chown _osmap:_osmap '${SESSION_DIR}/${OTHER_SESSION_ID}.session'"

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

wait_for_helper_socket

request_get() {
  path="$1"
  cookie_value="$2"
  {
    printf 'GET %s HTTP/1.1\r\n' "${path}"
    printf 'Host: 127.0.0.1\r\n'
    printf 'User-Agent: %s\r\n' "${USER_AGENT}"
    printf 'Cookie: osmap_session=%s\r\n' "${cookie_value}"
    printf 'Connection: close\r\n'
    printf '\r\n'
  } | nc -N 127.0.0.1 "${LISTEN_PORT}"
}

request_post() {
  path="$1"
  body="$2"
  cookie_value="$3"
  content_length="$(printf '%s' "${body}" | wc -c | tr -d ' ')"
  {
    printf 'POST %s HTTP/1.1\r\n' "${path}"
    printf 'Host: 127.0.0.1\r\n'
    printf 'User-Agent: %s\r\n' "${USER_AGENT}"
    printf 'Cookie: osmap_session=%s\r\n' "${cookie_value}"
    printf 'Origin: https://127.0.0.1\r\n'
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

session_revoked_at() {
  doas awk -F= '$1 == "revoked_at" { print $2; exit }' "$1"
}

wait_for_healthz

log "verifying /sessions page"
SESSIONS_RESPONSE="$(request_get "/sessions" "${SESSION_TOKEN}")"
printf '%s' "${SESSIONS_RESPONSE}" > "${SESSIONS_RESPONSE_PATH}"
SESSIONS_STATUS="$(status_line "${SESSIONS_RESPONSE}")"
SESSIONS_BODY="$(response_body "${SESSIONS_RESPONSE}")"

[ "${SESSIONS_STATUS}" = "HTTP/1.1 200 OK" ] || {
  log "/sessions did not succeed"
  printf '%s\n' "${SESSIONS_RESPONSE}"
  exit 1
}
printf '%s\n' "${SESSIONS_BODY}" | grep -Fq "<h1>Sessions</h1>" || {
  log "/sessions did not render sessions heading"
  printf '%s\n' "${SESSIONS_RESPONSE}"
  exit 1
}
printf '%s\n' "${SESSIONS_BODY}" | grep -Fq "203.0.113.9" || {
  log "/sessions did not render non-current session metadata"
  printf '%s\n' "${SESSIONS_RESPONSE}"
  exit 1
}
printf '%s\n' "${SESSIONS_BODY}" | grep -Fq "Revoke This Session" || {
  log "/sessions did not render current-session revoke action"
  printf '%s\n' "${SESSIONS_RESPONSE}"
  exit 1
}
printf '%s\n' "${SESSIONS_BODY}" | grep -Fq "name=\"session_id\" value=\"${OTHER_SESSION_ID}\"" || {
  log "/sessions did not render revoke form for non-current session"
  printf '%s\n' "${SESSIONS_RESPONSE}"
  exit 1
}

log "revoking non-current session through browser route"
REVOKE_BODY="csrf_token=${CSRF_TOKEN}&session_id=${OTHER_SESSION_ID}"
REVOKE_RESPONSE="$(request_post "/sessions/revoke" "${REVOKE_BODY}" "${SESSION_TOKEN}")"
printf '%s' "${REVOKE_RESPONSE}" > "${REVOKE_RESPONSE_PATH}"
REVOKE_STATUS="$(status_line "${REVOKE_RESPONSE}")"
REVOKE_LOCATION="$(header_value "${REVOKE_RESPONSE}" "Location")"

[ "${REVOKE_STATUS}" = "HTTP/1.1 303 See Other" ] || {
  log "non-current session revoke did not succeed"
  printf '%s\n' "${REVOKE_RESPONSE}"
  exit 1
}
[ "${REVOKE_LOCATION}" = "/sessions?revoked=1" ] || {
  log "non-current session revoke redirect was unexpected"
  printf '%s\n' "${REVOKE_RESPONSE}"
  exit 1
}

OTHER_REVOKED_AT="$(session_revoked_at "${SESSION_DIR}/${OTHER_SESSION_ID}.session")"
[ -n "${OTHER_REVOKED_AT}" ] || {
  log "non-current session record was not marked revoked"
  doas cat "${SESSION_DIR}/${OTHER_SESSION_ID}.session"
  exit 1
}

log "verifying success banner after non-current revoke"
SESSIONS_REVOKED_RESPONSE="$(request_get "/sessions?revoked=1" "${SESSION_TOKEN}")"
printf '%s' "${SESSIONS_REVOKED_RESPONSE}" > "${SESSIONS_REVOKED_RESPONSE_PATH}"
SESSIONS_REVOKED_BODY="$(response_body "${SESSIONS_REVOKED_RESPONSE}")"
printf '%s\n' "${SESSIONS_REVOKED_BODY}" | grep -Fq "The selected session was revoked." || {
  log "/sessions?revoked=1 did not render success banner"
  printf '%s\n' "${SESSIONS_REVOKED_RESPONSE}"
  exit 1
}

log "logging out current session"
LOGOUT_BODY="csrf_token=${CSRF_TOKEN}"
LOGOUT_RESPONSE="$(request_post "/logout" "${LOGOUT_BODY}" "${SESSION_TOKEN}")"
printf '%s' "${LOGOUT_RESPONSE}" > "${LOGOUT_RESPONSE_PATH}"
LOGOUT_STATUS="$(status_line "${LOGOUT_RESPONSE}")"
LOGOUT_LOCATION="$(header_value "${LOGOUT_RESPONSE}" "Location")"
LOGOUT_SET_COOKIE="$(header_value "${LOGOUT_RESPONSE}" "Set-Cookie")"

[ "${LOGOUT_STATUS}" = "HTTP/1.1 303 See Other" ] || {
  log "logout did not succeed"
  printf '%s\n' "${LOGOUT_RESPONSE}"
  exit 1
}
[ "${LOGOUT_LOCATION}" = "/login" ] || {
  log "logout redirect was unexpected"
  printf '%s\n' "${LOGOUT_RESPONSE}"
  exit 1
}
printf '%s\n' "${LOGOUT_SET_COOKIE}" | grep -Fq "Max-Age=0" || {
  log "logout did not clear the session cookie"
  printf '%s\n' "${LOGOUT_RESPONSE}"
  exit 1
}

CURRENT_REVOKED_AT="$(session_revoked_at "${SESSION_DIR}/${CURRENT_SESSION_ID}.session")"
[ -n "${CURRENT_REVOKED_AT}" ] || {
  log "current session record was not marked revoked by logout"
  doas cat "${SESSION_DIR}/${CURRENT_SESSION_ID}.session"
  exit 1
}

log "verifying stale session is redirected after logout"
STALE_RESPONSE="$(request_get "/sessions" "${SESSION_TOKEN}")"
printf '%s' "${STALE_RESPONSE}" > "${STALE_RESPONSE_PATH}"
STALE_STATUS="$(status_line "${STALE_RESPONSE}")"
STALE_LOCATION="$(header_value "${STALE_RESPONSE}" "Location")"

[ "${STALE_STATUS}" = "HTTP/1.1 303 See Other" ] || {
  log "stale post-logout session did not redirect"
  printf '%s\n' "${STALE_RESPONSE}"
  exit 1
}
[ "${STALE_LOCATION}" = "/login" ] || {
  log "stale post-logout session redirected unexpectedly"
  printf '%s\n' "${STALE_RESPONSE}"
  exit 1
}

doas grep -q 'action=session_listed' "${LOG_PATH}" || {
  log "session_listed event missing from runtime log"
  doas cat "${LOG_PATH}"
  exit 1
}
SESSION_REVOKED_COUNT="$(doas grep -c 'action=session_revoked' "${LOG_PATH}" || true)"
[ "${SESSION_REVOKED_COUNT}" -ge 2 ] || {
  log "expected at least two session_revoked events in runtime log"
  doas cat "${LOG_PATH}"
  exit 1
}

log "live session surface validation passed"
log "sessions_status=${SESSIONS_STATUS}"
log "revoke_status=${REVOKE_STATUS}"
log "logout_status=${LOGOUT_STATUS}"
