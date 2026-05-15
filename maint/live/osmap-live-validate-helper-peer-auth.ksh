#!/bin/sh
#
# Validate mailbox-helper peer authorization on a live OpenBSD host.
#
# This script is intended to run on a host like mail.blackbagsecurity.com where
# `doas -u _osmap` and `doas -u vmail` are available. It builds the current
# OSMAP tree, starts an isolated enforced mailbox helper, verifies that the
# trusted `_osmap` caller can reach the helper boundary, then temporarily opens
# the isolated helper socket permissions and confirms an unrelated local caller
# is still rejected by peer-credential enforcement.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_ROOT="${OSMAP_LIVE_WORK_ROOT:-/home/osmap-live-helper-peer-auth-$$}"
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
HELPER_LOG_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.log"
HELPER_PID_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.pid"
HELPER_SOCKET_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.sock"
HELPER_GRANT_KEY_PATH="${STATE_ROOT}/secrets/mailbox-helper-grant.key"
AUTH_SOCKET_PATH="${OSMAP_DOVEADM_AUTH_SOCKET_PATH:-/var/run/osmap-auth}"
TRUSTED_WEB_RUNTIME_UID="${OSMAP_TRUSTED_WEB_RUNTIME_UID:-$(id -u _osmap)}"
USERDB_SOCKET_PATH="${OSMAP_DOVEADM_USERDB_SOCKET_PATH:-/var/run/osmap-userdb}"
KEEP_WORK_ROOT="${OSMAP_KEEP_WORK_ROOT:-0}"
REPORT_PATH="${OSMAP_HELPER_BOUNDARY_REPORT_PATH:-${PROJECT_ROOT}/maint/live/latest-host-helper-boundary-report.txt}"

log() {
  printf '%s\n' "$*"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing required tool: $1"
    exit 1
  }
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
  terminate_pid_path "${HELPER_PID_PATH}"
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
require_tool stat
require_tool id
require_tool openssl
require_tool od

CURRENT_UID="$(id -u)"
TRUSTED_UID="$(doas stat -f '%u' "${AUTH_SOCKET_PATH}")"
if [ "${CURRENT_UID}" = "${TRUSTED_UID}" ]; then
  log "current user unexpectedly matches trusted auth-socket owner uid ${TRUSTED_UID}"
  exit 1
fi

log "preparing isolated live validation root under ${WORK_ROOT}"
doas rm -rf "${WORK_ROOT}"
doas install -d -o foo -g foo -m 755 "${WORK_ROOT}"
install -d "${TMPDIR_PATH}" "${CARGO_HOME_PATH}" "${CARGO_TARGET_DIR_PATH}"
doas install -d -o vmail -g vmail -m 755 "${STATE_ROOT}"
doas install -d -o vmail -g vmail -m 755 "${HELPER_RUNTIME_DIR}"
doas install -d -o vmail -g vmail -m 700 \
  "${HELPER_STATE_RUNTIME_DIR}" \
  "${SESSION_DIR}" \
  "${RUNTIME_DIR}" \
  "${SETTINGS_DIR}" \
  "${AUDIT_DIR}" \
  "${CACHE_DIR}" \
  "${TOTP_DIR}"
doas install -d -o vmail -g vmail -m 700 "${STATE_ROOT}/secrets"
grant_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
printf '%s' "${grant_key}" > "${TMPDIR_PATH}/mailbox-helper-grant.key"
doas install -o vmail -g vmail -m 600 "${TMPDIR_PATH}/mailbox-helper-grant.key" "${HELPER_GRANT_KEY_PATH}"

b64() {
  printf '%s' "$1" | openssl base64 -A
}

helper_request() {
  operation="$1"
  username="$2"
  issued_at="$(date +%s)"
  expires_at="$((issued_at + 60))"
  nonce="00112233445566778899aabbccddeeff"
  signature="$(
    {
      printf 'v1\0%s\0%s\0%s\0%s\0%s' \
        "${operation}" "${issued_at}" "${expires_at}" "${nonce}" "${username}"
    } | openssl dgst -sha256 -mac HMAC -macopt "key:${grant_key}" -binary | od -An -tx1 | tr -d ' \n'
  )"
  {
    printf '%s\n' "operation=${operation}"
    printf '%s\n' "canonical_username_b64=$(b64 "${username}")"
    printf '%s\n' "grant_issued_at=${issued_at}"
    printf '%s\n' "grant_expires_at=${expires_at}"
    printf '%s\n' "grant_nonce=${nonce}"
    printf '%s\n' "grant_signature=${signature}"
    printf '\n'
  }
}

log "building current OSMAP tree"
cd "${PROJECT_ROOT}"
TMPDIR="${TMPDIR_PATH}" \
  CARGO_HOME="${CARGO_HOME_PATH}" \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR_PATH}" \
  cargo build --quiet
install -m 755 "${CARGO_TARGET_DIR_PATH}/debug/osmap" "${BIN_PATH}"

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
    OSMAP_LOG_LEVEL=info \
    OSMAP_MAILBOX_HELPER_SOCKET_PATH='${HELPER_SOCKET_PATH}' \
    OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH='${HELPER_GRANT_KEY_PATH}' \
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

wait_for_helper_socket

log "verifying trusted _osmap caller reaches the helper boundary"
TRUSTED_REQUEST_PATH="${TMPDIR_PATH}/trusted-helper-request.txt"
helper_request mailbox_list does-not-exist@example.com > "${TRUSTED_REQUEST_PATH}"
chmod 644 "${TRUSTED_REQUEST_PATH}"
trusted_response="$(
  doas -u _osmap sh -c "
    cat '${TRUSTED_REQUEST_PATH}' | nc -N -U '${HELPER_SOCKET_PATH}'
  " 2>/dev/null || true
)"
printf '%s' "${trusted_response}" | grep -Fq 'backend_b64=ZG92ZWFkbS1tYWlsYm94LWxpc3Q=' || {
  log "trusted caller did not reach doveadm-backed helper path"
  [ -f "${HELPER_LOG_PATH}" ] && doas cat "${HELPER_LOG_PATH}"
  exit 1
}

log "temporarily widening the isolated socket path to prove peer auth enforcement"
doas chmod 666 "${HELPER_SOCKET_PATH}"

untrusted_response="$(
  helper_request mailbox_list does-not-exist@example.com | nc -N -U "${HELPER_SOCKET_PATH}" 2>/dev/null || true
)"
printf '%s' "${untrusted_response}" | grep -Fq 'backend_b64=bWFpbGJveC1oZWxwZXItYXV0aHo=' || {
  log "untrusted caller was not rejected by mailbox-helper authz"
  printf '%s\n' "${untrusted_response}"
  [ -f "${HELPER_LOG_PATH}" ] && doas cat "${HELPER_LOG_PATH}"
  exit 1
}
printf '%s' "${untrusted_response}" | grep -Fq 'reason_b64=aGVscGVyIHBlZXIgY3JlZGVudGlhbHMgd2VyZSBub3QgYXV0aG9yaXplZA==' || {
  log "untrusted caller did not receive expected helper authz response"
  printf '%s\n' "${untrusted_response}"
  exit 1
}

log "trusted_status=ok"
log "untrusted_status=rejected"
{
  printf '%s\n' "result=helper_boundary_passed"
  printf '%s\n' "trusted_status=ok"
  printf '%s\n' "untrusted_status=rejected"
  printf '%s\n' "socket_mode=660_then_666_negative_test"
  printf '%s\n' "missing_or_invalid_grant_rejected=covered_by_unit_tests"
  printf '%s\n' "confinement_mode=enforce"
} > "${REPORT_PATH}"
