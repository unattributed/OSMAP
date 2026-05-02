#!/bin/sh
#
# Validate V3 expensive-route resource controls on a live OpenBSD host.
#
# This script is intended to run on a host like mail.blackbagsecurity.com where
# `doas -u _osmap` and `doas -u vmail` are available. It builds the current
# OSMAP tree, starts an isolated enforced mailbox helper and browser runtime
# with a synthetic validated session, injects one controlled attachment-bearing
# message, then proves these helper-backed browser routes emit bounded
# route-budget evidence:
#
# - compose reply source loading
# - attachment download
# - all-mailbox search fanout
# - one-message move
#
# The report deliberately uses synthetic subjects/tokens and does not include
# the browser session token, CSRF token, message body, or attachment body.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_ROOT="${OSMAP_LIVE_WORK_ROOT:-/home/osmap-live-v3-resource-controls-$$}"
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
LISTEN_PORT="${OSMAP_LIVE_V3_RESOURCE_CONTROLS_PORT:-}"
VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
SESSION_TOKEN="${OSMAP_LIVE_SESSION_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
USER_AGENT="osmap-live-v3-resource-controls"
AUTH_SOCKET_PATH="${OSMAP_DOVEADM_AUTH_SOCKET_PATH:-/var/run/osmap-auth}"
TRUSTED_WEB_RUNTIME_UID="${OSMAP_TRUSTED_WEB_RUNTIME_UID:-$(id -u _osmap)}"
USERDB_SOCKET_PATH="${OSMAP_DOVEADM_USERDB_SOCKET_PATH:-/var/run/osmap-userdb}"
MOVE_DESTINATION_MAILBOX="${OSMAP_V3_RESOURCE_MOVE_DESTINATION_MAILBOX:-Junk}"
KEEP_WORK_ROOT="${OSMAP_KEEP_WORK_ROOT:-0}"
REPORT_PATH=""

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

cleanup_subject() {
  subject="$1"
  if [ -n "${subject}" ]; then
    doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
      expunge -u "${VALIDATION_USER}" mailbox INBOX header Subject "${subject}" \
      >/dev/null 2>&1 || true
    doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
      expunge -u "${VALIDATION_USER}" mailbox "${MOVE_DESTINATION_MAILBOX}" header Subject "${subject}" \
      >/dev/null 2>&1 || true
  fi
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
  cleanup_subject "${MESSAGE_SUBJECT:-}"
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
require_tool hostname

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

SESSION_ID="$(printf 'session-id:%s' "${SESSION_TOKEN}" | sha256 -q)"
CSRF_TOKEN="$(printf 'csrf:%s' "${SESSION_TOKEN}" | sha256 -q)"
NOW="$(date +%s)"
EXPIRES_AT="$((NOW + 3600))"
QUERY_TOKEN="osmap-v3-resource-proof-${NOW}-$$"
MESSAGE_SUBJECT="OSMAP V3 resource proof ${NOW}-$$"
ATTACHMENT_MARKER="osmap attachment marker ${NOW}-$$"

if [ -z "${REPORT_PATH}" ]; then
  REPORT_PATH="${WORK_ROOT}/v3-resource-controls-report.txt"
fi

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

log "verifying destination mailbox layout for validation user"
doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
  mailbox list -u "${VALIDATION_USER}" | grep -Fxq "${MOVE_DESTINATION_MAILBOX}" || {
  log "validation mailbox ${MOVE_DESTINATION_MAILBOX} does not exist for ${VALIDATION_USER}"
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
    OSMAP_LOG_LEVEL=info \
    OSMAP_SESSION_LIFETIME_SECS=3600 \
    OSMAP_MAILBOX_WORKER_BUDGET=1 \
    OSMAP_SEARCH_WORKER_BUDGET=1 \
    OSMAP_EXPENSIVE_REQUEST_TIMEOUT_SECONDS=5 \
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
  boundary="osmap-v3-resource-${NOW}-$$"
  {
    printf 'From: OSMAP V3 Resource Proof <%s>\n' "${VALIDATION_USER}"
    printf 'To: %s\n' "${VALIDATION_USER}"
    printf 'Subject: %s\n' "${MESSAGE_SUBJECT}"
    printf 'MIME-Version: 1.0\n'
    printf 'Content-Type: multipart/mixed; boundary="%s"\n' "${boundary}"
    printf '\n'
    printf -- '--%s\n' "${boundary}"
    printf 'Content-Type: text/plain; charset=utf-8\n'
    printf '\n'
    printf 'resource-control query token: %s\n' "${QUERY_TOKEN}"
    printf 'compose source and search proof message\n'
    printf -- '--%s\n' "${boundary}"
    printf 'Content-Type: text/plain; name="resource-proof.txt"\n'
    printf 'Content-Disposition: attachment; filename="resource-proof.txt"\n'
    printf '\n'
    printf '%s\n' "${ATTACHMENT_MARKER}"
    printf -- '--%s--\n' "${boundary}"
  } | /usr/sbin/sendmail -t
}

lookup_uid() {
  mailbox_name="$1"
  subject="$2"
  doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
    search -u "${VALIDATION_USER}" mailbox "${mailbox_name}" header Subject "${subject}" \
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

require_budget_event() {
  action="$1"
  route_class="$2"
  budget_name="$3"
  doas grep -F "action=${action}" "${HTTP_LOG_PATH}" |
    grep -F "route_class=\"${route_class}\"" |
    grep -F "budget_name=\"${budget_name}\"" |
    grep -F "canonical_username=\"${VALIDATION_USER}\"" >/dev/null || {
      log "missing ${action} budget event for ${route_class}"
      doas cat "${HTTP_LOG_PATH}"
      exit 1
    }
}

first_budget_event() {
  action="$1"
  route_class="$2"
  budget_name="$3"
  doas grep -F "action=${action}" "${HTTP_LOG_PATH}" |
    grep -F "route_class=\"${route_class}\"" |
    grep -F "budget_name=\"${budget_name}\"" |
    sed -n '1p'
}

wait_for_helper_socket
wait_for_healthz

doas grep -Fq 'mailbox_boundary_mode="local_helper_socket"' "${HTTP_LOG_PATH}" || {
  log "serve startup did not report helper-backed mailbox boundary"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}
doas grep -Fq 'mailbox_worker_budget="1"' "${HTTP_LOG_PATH}" || {
  log "serve startup did not report mailbox worker budget 1"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}
doas grep -Fq 'search_worker_budget="1"' "${HTTP_LOG_PATH}" || {
  log "serve startup did not report search worker budget 1"
  doas cat "${HTTP_LOG_PATH}"
  exit 1
}

log "injecting controlled attachment-bearing validation message"
inject_message

uid=""
tries=0
while [ -z "${uid}" ] && [ "${tries}" -lt 20 ]; do
  sleep 1
  uid="$(lookup_uid INBOX "${MESSAGE_SUBJECT}" || true)"
  tries="$((tries + 1))"
done

[ -n "${uid}" ] || {
  log "failed to locate injected validation message uid"
  [ -f "${HELPER_LOG_PATH}" ] && doas cat "${HELPER_LOG_PATH}"
  exit 1
}

log "exercising compose reply source loading"
COMPOSE_RESPONSE="$(request_get "/compose?mode=reply&mailbox=INBOX&uid=${uid}")"
COMPOSE_STATUS="$(status_line "${COMPOSE_RESPONSE}")"
COMPOSE_BODY="$(response_body "${COMPOSE_RESPONSE}")"
[ "${COMPOSE_STATUS}" = "HTTP/1.1 200 OK" ] || {
  log "compose source route did not return 200"
  printf '%s\n' "${COMPOSE_RESPONSE}"
  exit 1
}
printf '%s\n' "${COMPOSE_BODY}" | grep -Fq '<h1>Reply</h1>' || {
  log "compose source response did not render reply heading"
  printf '%s\n' "${COMPOSE_RESPONSE}"
  exit 1
}

log "exercising attachment metadata and download"
MESSAGE_RESPONSE="$(request_get "/message?mailbox=INBOX&uid=${uid}")"
MESSAGE_STATUS="$(status_line "${MESSAGE_RESPONSE}")"
MESSAGE_BODY="$(response_body "${MESSAGE_RESPONSE}")"
[ "${MESSAGE_STATUS}" = "HTTP/1.1 200 OK" ] || {
  log "message view route did not return 200"
  printf '%s\n' "${MESSAGE_RESPONSE}"
  exit 1
}
printf '%s\n' "${MESSAGE_BODY}" | grep -Fq "resource-proof.txt" || {
  log "message view did not surface validation attachment"
  printf '%s\n' "${MESSAGE_RESPONSE}"
  exit 1
}
printf '%s\n' "${MESSAGE_BODY}" | grep -Fq "/attachment?mailbox=INBOX&amp;uid=${uid}&amp;part=1.2" || {
  log "message view did not render expected attachment link"
  printf '%s\n' "${MESSAGE_RESPONSE}"
  exit 1
}

ATTACHMENT_RESPONSE="$(request_get "/attachment?mailbox=INBOX&uid=${uid}&part=1.2")"
ATTACHMENT_STATUS="$(status_line "${ATTACHMENT_RESPONSE}")"
ATTACHMENT_DISPOSITION="$(header_value "${ATTACHMENT_RESPONSE}" "Content-Disposition")"
ATTACHMENT_BODY="$(response_body "${ATTACHMENT_RESPONSE}")"
[ "${ATTACHMENT_STATUS}" = "HTTP/1.1 200 OK" ] || {
  log "attachment download route did not return 200"
  printf '%s\n' "${ATTACHMENT_RESPONSE}"
  exit 1
}
printf '%s\n' "${ATTACHMENT_DISPOSITION}" | grep -Fq 'attachment; filename="resource-proof.txt"' || {
  log "attachment download did not force expected attachment disposition"
  printf '%s\n' "${ATTACHMENT_RESPONSE}"
  exit 1
}
printf '%s\n' "${ATTACHMENT_BODY}" | grep -Fq "${ATTACHMENT_MARKER}" || {
  log "attachment download did not return synthetic attachment marker"
  printf '%s\n' "${ATTACHMENT_RESPONSE}"
  exit 1
}

log "exercising all-mailbox search fanout"
SEARCH_RESPONSE="$(request_get "/search?q=${QUERY_TOKEN}")"
SEARCH_STATUS="$(status_line "${SEARCH_RESPONSE}")"
SEARCH_BODY="$(response_body "${SEARCH_RESPONSE}")"
[ "${SEARCH_STATUS}" = "HTTP/1.1 200 OK" ] || {
  log "all-mailbox search route did not return 200"
  printf '%s\n' "${SEARCH_RESPONSE}"
  exit 1
}
printf '%s\n' "${SEARCH_BODY}" | grep -Fq '<strong>Scope:</strong> All mailboxes' || {
  log "search response did not report all-mailbox scope"
  printf '%s\n' "${SEARCH_RESPONSE}"
  exit 1
}
printf '%s\n' "${SEARCH_BODY}" | grep -Fq "${MESSAGE_SUBJECT}" || {
  log "search response did not include validation message"
  printf '%s\n' "${SEARCH_RESPONSE}"
  exit 1
}

log "exercising one-message move"
MOVE_BODY="csrf_token=${CSRF_TOKEN}&mailbox=INBOX&uid=${uid}&destination_mailbox=${MOVE_DESTINATION_MAILBOX}"
MOVE_RESPONSE="$(request_post "/message/move" "${MOVE_BODY}")"
MOVE_STATUS="$(status_line "${MOVE_RESPONSE}")"
MOVE_LOCATION="$(header_value "${MOVE_RESPONSE}" "Location")"
[ "${MOVE_STATUS}" = "HTTP/1.1 303 See Other" ] || {
  log "message move route did not return 303"
  printf '%s\n' "${MOVE_RESPONSE}"
  exit 1
}
[ "${MOVE_LOCATION}" = "/mailbox?name=INBOX&moved_to=${MOVE_DESTINATION_MAILBOX}" ] || {
  log "message move redirect was unexpected"
  printf '%s\n' "${MOVE_RESPONSE}"
  exit 1
}

sleep 1
INBOX_UID_AFTER_MOVE="$(lookup_uid INBOX "${MESSAGE_SUBJECT}" || true)"
DEST_UID_AFTER_MOVE="$(lookup_uid "${MOVE_DESTINATION_MAILBOX}" "${MESSAGE_SUBJECT}" || true)"
[ -z "${INBOX_UID_AFTER_MOVE}" ] || {
  log "message remained in INBOX after move"
  exit 1
}
[ -n "${DEST_UID_AFTER_MOVE}" ] || {
  log "message did not appear in ${MOVE_DESTINATION_MAILBOX} after move"
  exit 1
}

require_budget_event request_budget_acquired compose_source mailbox_workers
require_budget_event request_budget_released compose_source mailbox_workers
require_budget_event request_budget_acquired attachment_download mailbox_workers
require_budget_event request_budget_released attachment_download mailbox_workers
require_budget_event request_budget_acquired message_move mailbox_workers
require_budget_event request_budget_released message_move mailbox_workers
require_budget_event request_budget_acquired message_search search_workers
require_budget_event request_budget_released message_search search_workers

doas grep -F 'action=attachment_downloaded' "${HTTP_LOG_PATH}" |
  grep -F 'msg="attachment download completed through mailbox helper"' >/dev/null || {
    log "helper-backed attachment download event missing from runtime log"
    doas cat "${HTTP_LOG_PATH}"
    exit 1
  }
doas grep -F 'action=message_moved' "${HTTP_LOG_PATH}" |
  grep -F "destination_mailbox_name=\"${MOVE_DESTINATION_MAILBOX}\"" >/dev/null || {
    log "message move event missing from runtime log"
    doas cat "${HTTP_LOG_PATH}"
    exit 1
  }
doas grep -F 'action=message_searched' "${HTTP_LOG_PATH}" |
  grep -F "query=\"${QUERY_TOKEN}\"" >/dev/null || {
    log "all-mailbox search event missing from runtime log"
    doas cat "${HTTP_LOG_PATH}"
    exit 1
  }

ASSESSED_AT_UTC="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
ASSESSED_REF="$(cd "${PROJECT_ROOT}" && git rev-parse HEAD)"
ASSESSED_HOST="$(hostname)"
COMPOSE_ACQUIRED="$(first_budget_event request_budget_acquired compose_source mailbox_workers)"
COMPOSE_RELEASED="$(first_budget_event request_budget_released compose_source mailbox_workers)"
ATTACHMENT_ACQUIRED="$(first_budget_event request_budget_acquired attachment_download mailbox_workers)"
ATTACHMENT_RELEASED="$(first_budget_event request_budget_released attachment_download mailbox_workers)"
MOVE_ACQUIRED="$(first_budget_event request_budget_acquired message_move mailbox_workers)"
MOVE_RELEASED="$(first_budget_event request_budget_released message_move mailbox_workers)"
SEARCH_ACQUIRED="$(first_budget_event request_budget_acquired message_search search_workers)"
SEARCH_RELEASED="$(first_budget_event request_budget_released message_search search_workers)"

{
  printf 'osmap_v3_resource_controls_result=passed\n'
  printf 'assessed_at_utc=%s\n' "${ASSESSED_AT_UTC}"
  printf 'assessed_host=%s\n' "${ASSESSED_HOST}"
  printf 'assessed_ref=%s\n' "${ASSESSED_REF}"
  printf 'validation_user=%s\n' "${VALIDATION_USER}"
  printf 'mailbox_boundary_mode=local_helper_socket\n'
  printf 'mailbox_worker_budget=1\n'
  printf 'search_worker_budget=1\n'
  printf 'expensive_request_timeout_seconds=5\n'
  printf 'compose_source_status=%s\n' "${COMPOSE_STATUS}"
  printf 'attachment_download_status=%s\n' "${ATTACHMENT_STATUS}"
  printf 'all_mailbox_search_status=%s\n' "${SEARCH_STATUS}"
  printf 'message_move_status=%s\n' "${MOVE_STATUS}"
  printf 'move_destination_mailbox=%s\n' "${MOVE_DESTINATION_MAILBOX}"
  printf 'synthetic_query_token=%s\n' "${QUERY_TOKEN}"
  printf 'synthetic_subject=%s\n' "${MESSAGE_SUBJECT}"
  printf 'matched_compose_source_acquired=%s\n' "${COMPOSE_ACQUIRED}"
  printf 'matched_compose_source_released=%s\n' "${COMPOSE_RELEASED}"
  printf 'matched_attachment_download_acquired=%s\n' "${ATTACHMENT_ACQUIRED}"
  printf 'matched_attachment_download_released=%s\n' "${ATTACHMENT_RELEASED}"
  printf 'matched_message_move_acquired=%s\n' "${MOVE_ACQUIRED}"
  printf 'matched_message_move_released=%s\n' "${MOVE_RELEASED}"
  printf 'matched_message_search_acquired=%s\n' "${SEARCH_ACQUIRED}"
  printf 'matched_message_search_released=%s\n' "${SEARCH_RELEASED}"
  printf 'secret_review=No passwords, TOTP material, session cookie, CSRF token, private message body, attachment body, provider secret, or host secret is included.\n'
} > "${REPORT_PATH}"

if grep -Fq "${SESSION_TOKEN}" "${REPORT_PATH}" || grep -Fq "${CSRF_TOKEN}" "${REPORT_PATH}"; then
  log "report unexpectedly contains bearer or CSRF material"
  rm -f "${REPORT_PATH}"
  exit 1
fi

log "live V3 resource-control validation passed"
log "report_path=${REPORT_PATH}"
log "compose_source_status=${COMPOSE_STATUS}"
log "attachment_download_status=${ATTACHMENT_STATUS}"
log "all_mailbox_search_status=${SEARCH_STATUS}"
log "message_move_status=${MOVE_STATUS}"
