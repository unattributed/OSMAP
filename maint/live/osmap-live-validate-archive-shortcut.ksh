#!/bin/sh
#
# Validate the settings-backed archive shortcut on a live OpenBSD host.
#
# This script is intended to run on a host like mail.blackbagsecurity.com where
# `doas -u _osmap` and `doas -u vmail` are available. It builds the current
# OSMAP tree, starts an isolated enforced mailbox helper and browser runtime
# with a synthetic validated session, configures an archive mailbox through the
# browser settings route, verifies that archive shortcuts render on mailbox and
# message pages, then archives one injected message through the existing move
# route and confirms the message lands in the configured destination mailbox.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_ROOT="${OSMAP_LIVE_WORK_ROOT:-/home/osmap-live-archive-shortcut-$$}"
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
LISTEN_PORT="${OSMAP_LIVE_ARCHIVE_SHORTCUT_PORT:-}"
VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
SESSION_TOKEN="${OSMAP_LIVE_SESSION_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
USER_AGENT="osmap-live-archive-shortcut"
AUTH_SOCKET_PATH="${OSMAP_DOVEADM_AUTH_SOCKET_PATH:-/var/run/osmap-auth}"
USERDB_SOCKET_PATH="${OSMAP_DOVEADM_USERDB_SOCKET_PATH:-/var/run/osmap-userdb}"
ARCHIVE_MAILBOX="${OSMAP_ARCHIVE_SHORTCUT_MAILBOX:-Junk}"
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
  if [ -n "${MESSAGE_SUBJECT:-}" ]; then
    doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
      expunge -u "${VALIDATION_USER}" mailbox INBOX header Subject "${MESSAGE_SUBJECT}" \
      >/dev/null 2>&1 || true
    doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
      expunge -u "${VALIDATION_USER}" mailbox "${ARCHIVE_MAILBOX}" header Subject "${MESSAGE_SUBJECT}" \
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
require_tool sha256
require_tool awk
require_tool grep
require_tool sed

if [ -z "${LISTEN_PORT}" ]; then
  LISTEN_PORT="$((18400 + ($$ % 1000)))"
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

SESSION_ID="$(printf 'session-id:%s' "${SESSION_TOKEN}" | sha256 -q)"
CSRF_TOKEN="$(printf 'csrf:%s' "${SESSION_TOKEN}" | sha256 -q)"
NOW="$(date +%s)"
EXPIRES_AT="$((NOW + 3600))"
MESSAGE_SUBJECT="OSMAP archive shortcut proof ${NOW}-$$"

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

inject_message() {
  {
    printf 'From: OSMAP Archive Proof <%s>\n' "${VALIDATION_USER}"
    printf 'To: %s\n' "${VALIDATION_USER}"
    printf 'Subject: %s\n' "${MESSAGE_SUBJECT}"
    printf '\n'
    printf 'archive shortcut validation\n'
  } | /usr/sbin/sendmail -t
}

lookup_uid() {
  doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
    search -u "${VALIDATION_USER}" mailbox "$1" header Subject "${MESSAGE_SUBJECT}" \
    | awk 'NF > 0 { print $NF; exit }'
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

request_post() {
  path="$1"
  body="$2"
  content_length="$(printf '%s' "${body}" | wc -c | tr -d ' ')"
  {
    printf 'POST %s HTTP/1.1\r\n' "${path}"
    printf 'Host: 127.0.0.1\r\n'
    printf 'User-Agent: %s\r\n' "${USER_AGENT}"
    printf 'Cookie: osmap_session=%s\r\n' "${SESSION_TOKEN}"
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

wait_for_helper_socket
wait_for_healthz

log "configuring archive shortcut through the browser settings route"
SETTINGS_BODY="csrf_token=${CSRF_TOKEN}&html_display_preference=prefer_sanitized_html&archive_mailbox_name=${ARCHIVE_MAILBOX}"
SETTINGS_RESPONSE="$(request_post "/settings" "${SETTINGS_BODY}")"
SETTINGS_STATUS="$(status_line "${SETTINGS_RESPONSE}")"
SETTINGS_LOCATION="$(header_value "${SETTINGS_RESPONSE}" "Location")"

[ "${SETTINGS_STATUS}" = "HTTP/1.1 303 See Other" ] || {
  log "settings update did not succeed"
  printf '%s\n' "${SETTINGS_RESPONSE}"
  exit 1
}
[ "${SETTINGS_LOCATION}" = "/settings?updated=1" ] || {
  log "settings update redirect was unexpected"
  printf '%s\n' "${SETTINGS_RESPONSE}"
  exit 1
}

log "verifying persisted archive mailbox on the settings page"
SETTINGS_PAGE_RESPONSE="$(request_get "/settings")"
SETTINGS_PAGE_BODY="$(response_body "${SETTINGS_PAGE_RESPONSE}")"
printf '%s\n' "${SETTINGS_PAGE_BODY}" | grep -Fq "name=\"archive_mailbox_name\" value=\"${ARCHIVE_MAILBOX}\"" || {
  log "settings page did not render the configured archive mailbox"
  printf '%s\n' "${SETTINGS_PAGE_RESPONSE}"
  exit 1
}

log "injecting controlled validation message into INBOX"
inject_message

uid=""
tries=0
while [ -z "${uid}" ] && [ "${tries}" -lt 20 ]; do
  sleep 1
  uid="$(lookup_uid INBOX || true)"
  tries="$((tries + 1))"
done

[ -n "${uid}" ] || {
  log "failed to locate injected message uid"
  [ -f "${HELPER_LOG_PATH}" ] && doas cat "${HELPER_LOG_PATH}"
  exit 1
}

log "verifying archive shortcut renders on the mailbox page"
MAILBOX_RESPONSE="$(request_get "/mailbox?name=INBOX")"
MAILBOX_BODY="$(response_body "${MAILBOX_RESPONSE}")"
printf '%s\n' "${MAILBOX_BODY}" | grep -Fq ">Archive</button>" || {
  log "mailbox page did not render archive shortcut button"
  printf '%s\n' "${MAILBOX_RESPONSE}"
  exit 1
}
printf '%s\n' "${MAILBOX_BODY}" | grep -Fq "name=\"destination_mailbox\" value=\"${ARCHIVE_MAILBOX}\"" || {
  log "mailbox page did not render the configured archive mailbox in shortcut form"
  printf '%s\n' "${MAILBOX_RESPONSE}"
  exit 1
}

log "verifying archive shortcut renders on the message view page"
MESSAGE_RESPONSE="$(request_get "/message?mailbox=INBOX&uid=${uid}")"
MESSAGE_BODY="$(response_body "${MESSAGE_RESPONSE}")"
printf '%s\n' "${MESSAGE_BODY}" | grep -Fq "Archive Message" || {
  log "message view did not render archive shortcut heading"
  printf '%s\n' "${MESSAGE_RESPONSE}"
  exit 1
}
printf '%s\n' "${MESSAGE_BODY}" | grep -Fq "name=\"destination_mailbox\" value=\"${ARCHIVE_MAILBOX}\"" || {
  log "message view did not render the configured archive mailbox in shortcut form"
  printf '%s\n' "${MESSAGE_RESPONSE}"
  exit 1
}

log "archiving the injected message through the existing move route"
MOVE_BODY="csrf_token=${CSRF_TOKEN}&mailbox=INBOX&uid=${uid}&destination_mailbox=${ARCHIVE_MAILBOX}"
MOVE_RESPONSE="$(request_post "/message/move" "${MOVE_BODY}")"
MOVE_STATUS="$(status_line "${MOVE_RESPONSE}")"
MOVE_LOCATION="$(header_value "${MOVE_RESPONSE}" "Location")"

[ "${MOVE_STATUS}" = "HTTP/1.1 303 See Other" ] || {
  log "archive shortcut move did not succeed"
  printf '%s\n' "${MOVE_RESPONSE}"
  exit 1
}
[ "${MOVE_LOCATION}" = "/mailbox?name=INBOX&moved_to=${ARCHIVE_MAILBOX}" ] || {
  log "archive shortcut redirect was unexpected"
  printf '%s\n' "${MOVE_RESPONSE}"
  exit 1
}

sleep 1
INBOX_UID="$(lookup_uid INBOX || true)"
ARCHIVE_UID="$(lookup_uid "${ARCHIVE_MAILBOX}" || true)"

[ -z "${INBOX_UID}" ] || {
  log "message remained in INBOX after archive shortcut move"
  exit 1
}
[ -n "${ARCHIVE_UID}" ] || {
  log "message did not appear in archive mailbox after shortcut move"
  exit 1
}

doas grep -q 'action=user_settings_updated' "${HTTP_LOG_PATH}" || {
  log "settings update event missing from runtime log"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}
doas grep -q 'action=message_moved' "${HTTP_LOG_PATH}" || {
  log "message move event missing from runtime log"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}

log "live archive shortcut validation passed"
log "settings_status=${SETTINGS_STATUS}"
log "move_status=${MOVE_STATUS}"
log "archive_mailbox=${ARCHIVE_MAILBOX}"
