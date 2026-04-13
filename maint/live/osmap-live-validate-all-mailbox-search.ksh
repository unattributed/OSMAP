#!/bin/sh
#
# Validate bounded all-mailbox search on a live OpenBSD host.
#
# This script is intended to run on a host like mail.blackbagsecurity.com where
# `doas -u _osmap` and `doas -u vmail` are available. It builds the current
# OSMAP tree, starts an isolated enforced mailbox helper and browser runtime
# with a synthetic validated session, injects two controlled messages that end
# up in different visible mailboxes, then verifies that the browser search path
# can retrieve both through one all-mailboxes query.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_ROOT="${OSMAP_LIVE_WORK_ROOT:-/home/osmap-live-all-mailbox-search-$$}"
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
MAILBOXES_RESPONSE_PATH="${WORK_ROOT}/mailboxes-response.txt"
MAILBOX_RESPONSE_PATH="${WORK_ROOT}/mailbox-response.txt"
SEARCH_RESPONSE_PATH="${WORK_ROOT}/search-response.txt"
LISTEN_PORT="${OSMAP_LIVE_ALL_MAILBOX_SEARCH_PORT:-}"
VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
SESSION_TOKEN="${OSMAP_LIVE_SESSION_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
USER_AGENT="osmap-live-all-mailbox-search"
AUTH_SOCKET_PATH="${OSMAP_DOVEADM_AUTH_SOCKET_PATH:-/var/run/osmap-auth}"
TRUSTED_WEB_RUNTIME_UID="${OSMAP_TRUSTED_WEB_RUNTIME_UID:-$(id -u _osmap)}"
USERDB_SOCKET_PATH="${OSMAP_DOVEADM_USERDB_SOCKET_PATH:-/var/run/osmap-userdb}"
SECONDARY_MAILBOX="${OSMAP_SEARCH_PROOF_SECONDARY_MAILBOX:-Junk}"
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

cleanup_injected_messages() {
  if [ -n "${INBOX_SUBJECT:-}" ]; then
    doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
      expunge -u "${VALIDATION_USER}" mailbox INBOX header Subject "${INBOX_SUBJECT}" \
      >/dev/null 2>&1 || true
  fi
  if [ -n "${SECONDARY_SUBJECT:-}" ]; then
    doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
      expunge -u "${VALIDATION_USER}" mailbox INBOX header Subject "${SECONDARY_SUBJECT}" \
      >/dev/null 2>&1 || true
    doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
      expunge -u "${VALIDATION_USER}" mailbox "${SECONDARY_MAILBOX}" header Subject "${SECONDARY_SUBJECT}" \
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
  cleanup_injected_messages
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
  LISTEN_PORT="$((18500 + ($$ % 1000)))"
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
QUERY_TOKEN="osmap-search-proof-${NOW}-$$"
INBOX_SUBJECT="${QUERY_TOKEN}-inbox"
SECONDARY_SUBJECT="${QUERY_TOKEN}-secondary"

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
  mailbox list -u "${VALIDATION_USER}" | grep -Fxq "${SECONDARY_MAILBOX}" || {
  log "validation mailbox ${SECONDARY_MAILBOX} does not exist for ${VALIDATION_USER}"
  exit 1
}

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
  subject="$1"
  body_label="$2"
  {
    printf 'From: OSMAP Search Proof <%s>\n' "${VALIDATION_USER}"
    printf 'To: %s\n' "${VALIDATION_USER}"
    printf 'Subject: %s\n' "${subject}"
    printf '\n'
    printf 'query token: %s\n' "${QUERY_TOKEN}"
    printf 'mailbox label: %s\n' "${body_label}"
  } | /usr/sbin/sendmail -t
}

lookup_uid() {
  mailbox_name="$1"
  subject="$2"
  doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
    search -u "${VALIDATION_USER}" mailbox "${mailbox_name}" header Subject "${subject}" \
    | awk 'NF > 0 { print $NF; exit }'
}

move_message_to_secondary() {
  uid="$1"
  doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
    move -u "${VALIDATION_USER}" "${SECONDARY_MAILBOX}" mailbox INBOX uid "${uid}"
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

wait_for_helper_socket
wait_for_healthz

log "verifying global search form renders on the mailboxes page"
MAILBOXES_RESPONSE="$(request_get "/mailboxes")"
printf '%s' "${MAILBOXES_RESPONSE}" > "${MAILBOXES_RESPONSE_PATH}"
MAILBOXES_BODY="$(response_body "${MAILBOXES_RESPONSE}")"
printf '%s\n' "${MAILBOXES_BODY}" | grep -Fq "Search all mailboxes" || {
  log "mailboxes page did not render all-mailboxes search form"
  printf '%s\n' "${MAILBOXES_RESPONSE}"
  exit 1
}

log "injecting controlled INBOX search message"
inject_message "${INBOX_SUBJECT}" "inbox"

log "injecting controlled secondary-mailbox search message"
inject_message "${SECONDARY_SUBJECT}" "secondary"

INBOX_UID=""
SECONDARY_SOURCE_UID=""
tries=0
while { [ -z "${INBOX_UID}" ] || [ -z "${SECONDARY_SOURCE_UID}" ]; } && [ "${tries}" -lt 20 ]; do
  sleep 1
  if [ -z "${INBOX_UID}" ]; then
    INBOX_UID="$(lookup_uid INBOX "${INBOX_SUBJECT}" || true)"
  fi
  if [ -z "${SECONDARY_SOURCE_UID}" ]; then
    SECONDARY_SOURCE_UID="$(lookup_uid INBOX "${SECONDARY_SUBJECT}" || true)"
  fi
  tries="$((tries + 1))"
done

[ -n "${INBOX_UID}" ] || {
  log "failed to locate INBOX validation message uid"
  [ -f "${HELPER_LOG_PATH}" ] && doas cat "${HELPER_LOG_PATH}"
  exit 1
}
[ -n "${SECONDARY_SOURCE_UID}" ] || {
  log "failed to locate secondary validation message uid before move"
  [ -f "${HELPER_LOG_PATH}" ] && doas cat "${HELPER_LOG_PATH}"
  exit 1
}

log "moving secondary validation message into ${SECONDARY_MAILBOX}"
move_message_to_secondary "${SECONDARY_SOURCE_UID}"

SECONDARY_UID=""
tries=0
while [ -z "${SECONDARY_UID}" ] && [ "${tries}" -lt 20 ]; do
  sleep 1
  SECONDARY_UID="$(lookup_uid "${SECONDARY_MAILBOX}" "${SECONDARY_SUBJECT}" || true)"
  tries="$((tries + 1))"
done

[ -n "${SECONDARY_UID}" ] || {
  log "secondary validation message did not appear in ${SECONDARY_MAILBOX}"
  exit 1
}

log "verifying mailbox page exposes the all-mailboxes search option"
MAILBOX_RESPONSE="$(request_get "/mailbox?name=INBOX")"
printf '%s' "${MAILBOX_RESPONSE}" > "${MAILBOX_RESPONSE_PATH}"
MAILBOX_BODY="$(response_body "${MAILBOX_RESPONSE}")"
printf '%s\n' "${MAILBOX_BODY}" | grep -Fq 'name="scope" value="all"' || {
  log "mailbox page did not render all-mailboxes search toggle"
  printf '%s\n' "${MAILBOX_RESPONSE}"
  exit 1
}

log "executing all-mailboxes search through the browser route"
SEARCH_RESPONSE="$(request_get "/search?q=${QUERY_TOKEN}")"
printf '%s' "${SEARCH_RESPONSE}" > "${SEARCH_RESPONSE_PATH}"
SEARCH_STATUS="$(status_line "${SEARCH_RESPONSE}")"
SEARCH_BODY="$(response_body "${SEARCH_RESPONSE}")"

[ "${SEARCH_STATUS}" = "HTTP/1.1 200 OK" ] || {
  log "all-mailboxes search did not succeed"
  printf '%s\n' "${SEARCH_RESPONSE}"
  exit 1
}

printf '%s\n' "${SEARCH_BODY}" | grep -Fq '<strong>Scope:</strong> All mailboxes' || {
  log "search page did not report all-mailboxes scope"
  printf '%s\n' "${SEARCH_RESPONSE}"
  exit 1
}
printf '%s\n' "${SEARCH_BODY}" | grep -Fq 'name="scope" value="all" checked' || {
  log "search page did not preserve checked all-mailboxes toggle"
  printf '%s\n' "${SEARCH_RESPONSE}"
  exit 1
}
printf '%s\n' "${SEARCH_BODY}" | grep -Fq "${INBOX_SUBJECT}" || {
  log "search page did not render INBOX validation result"
  printf '%s\n' "${SEARCH_RESPONSE}"
  exit 1
}
printf '%s\n' "${SEARCH_BODY}" | grep -Fq "${SECONDARY_SUBJECT}" || {
  log "search page did not render secondary-mailbox validation result"
  printf '%s\n' "${SEARCH_RESPONSE}"
  exit 1
}
printf '%s\n' "${SEARCH_BODY}" | grep -Fq ">INBOX<" || {
  log "search page did not render INBOX mailbox label"
  printf '%s\n' "${SEARCH_RESPONSE}"
  exit 1
}
printf '%s\n' "${SEARCH_BODY}" | grep -Fq ">${SECONDARY_MAILBOX}<" || {
  log "search page did not render secondary mailbox label"
  printf '%s\n' "${SEARCH_RESPONSE}"
  exit 1
}
printf '%s\n' "${SEARCH_BODY}" | grep -Fq "/message?mailbox=INBOX&amp;uid=${INBOX_UID}" || {
  log "search page did not render INBOX message link"
  printf '%s\n' "${SEARCH_RESPONSE}"
  exit 1
}
printf '%s\n' "${SEARCH_BODY}" | grep -Fq "/message?mailbox=${SECONDARY_MAILBOX}&amp;uid=${SECONDARY_UID}" || {
  log "search page did not render secondary mailbox message link"
  printf '%s\n' "${SEARCH_RESPONSE}"
  exit 1
}

doas grep -Fq 'action=mailbox_listed' "${HTTP_LOG_PATH}" || {
  log "mailbox listing event missing from runtime log"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}
doas grep -F 'action=message_searched' "${HTTP_LOG_PATH}" | grep -Fq "mailbox_name=\"INBOX\"" || {
  log "INBOX search event missing from runtime log"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}
doas grep -F 'action=message_searched' "${HTTP_LOG_PATH}" | grep -Fq "mailbox_name=\"${SECONDARY_MAILBOX}\"" || {
  log "secondary mailbox search event missing from runtime log"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}
doas grep -F 'action=message_searched' "${HTTP_LOG_PATH}" | grep -Fq "query=\"${QUERY_TOKEN}\"" || {
  log "search query token missing from runtime log"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}

log "live all-mailboxes search validation passed"
log "search_status=${SEARCH_STATUS}"
log "query_token=${QUERY_TOKEN}"
log "secondary_mailbox=${SECONDARY_MAILBOX}"
