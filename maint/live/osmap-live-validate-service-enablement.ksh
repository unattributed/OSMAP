#!/bin/sh
#
# Validate that the validated mail host has the reviewed persistent OSMAP
# service install in place before any browser-edge cutover is attempted.

set -eu

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
DEFAULT_REPORT_PATH="${PROJECT_ROOT}/maint/live/osmap-live-validate-service-enablement-report.txt"
REPORT_PATH="${OSMAP_SERVICE_ENABLEMENT_REPORT_PATH:-}"
OSMAP_BIN_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_BIN_PATH:-/usr/local/bin/osmap}"
GROUP_FILE_PATH="${OSMAP_SERVICE_GROUP_FILE_PATH:-/etc/group}"
SHARED_RUNTIME_GROUP="${OSMAP_SHARED_RUNTIME_GROUP:-osmaprt}"
SERVE_ENV_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH:-/etc/osmap/osmap-serve.env}"
HELPER_ENV_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH:-/etc/osmap/osmap-mailbox-helper.env}"
SERVE_RUN_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH:-/usr/local/libexec/osmap/osmap-serve-run.ksh}"
HELPER_RUN_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH:-/usr/local/libexec/osmap/osmap-mailbox-helper-run.ksh}"
SERVE_RC_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH:-/etc/rc.d/osmap_serve}"
HELPER_RC_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH:-/etc/rc.d/osmap_mailbox_helper}"
HELPER_SOCKET_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_SOCKET_PATH:-/var/lib/osmap-helper/run/mailbox-helper.sock}"
FAILED_CHECKS=""

log() {
  printf '%s\n' "$*"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing required tool: $1"
    exit 1
  }
}

usage() {
  cat <<EOF
usage: $(basename "$0") [--report <path>]

examples:
  ksh ./maint/live/osmap-live-validate-service-enablement.ksh
  ksh ./maint/live/osmap-live-validate-service-enablement.ksh --report "\$HOME/osmap-service-enablement-report.txt"
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h)
        usage
        exit 0
        ;;
      --report)
        [ "$#" -ge 2 ] || {
          log "--report requires a path"
          exit 1
        }
        REPORT_PATH="$2"
        shift 2
        ;;
      --report=*)
        REPORT_PATH="${1#--report=}"
        shift
        ;;
      *)
        log "unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done

  if [ -z "${REPORT_PATH}" ]; then
    REPORT_PATH="${DEFAULT_REPORT_PATH}"
  fi
}

append_failed_check() {
  failed_check="$1"
  if [ -z "${FAILED_CHECKS}" ]; then
    FAILED_CHECKS="${failed_check}"
  else
    FAILED_CHECKS="${FAILED_CHECKS}
${failed_check}"
  fi
}

read_privileged_file() {
  doas cat "$1"
}

capture_file_excerpt() {
  file_path="$1"
  if doas test -f "${file_path}"; then
    read_privileged_file "${file_path}"
  else
    printf 'missing:%s\n' "${file_path}"
  fi
}

capture_file_mode() {
  file_path="$1"
  if doas test -e "${file_path}"; then
    doas ls -ld "${file_path}" 2>/dev/null || true
  else
    printf 'missing:%s\n' "${file_path}"
  fi
}

capture_listener_lines() {
  netstat -na -f inet 2>/dev/null | awk '
    /LISTEN/ && ($4 ~ /\.8080$/ || $4 ~ /\.443$/) {
      print $0
    }
  '
}

listener_bindings_for_port() {
  port="$1"
  printf '%s\n' "${LISTENER_LINES}" | awk -v port="${port}" '
    $4 ~ ("\\." port "$") { print $4 }
  ' | sort -u | paste -sd ',' -
}

capture_group_line() {
  doas grep -E "^${SHARED_RUNTIME_GROUP}:" "${GROUP_FILE_PATH}" 2>/dev/null || true
}

capture_user_membership() {
  user_name="$1"
  doas id -Gn "${user_name}" 2>/dev/null || true
}

capture_service_check_status() {
  service_name="$1"
  if doas rcctl check "${service_name}" >/dev/null 2>&1; then
    printf '%s' "0"
  else
    printf '%s' "$?"
  fi
}

write_report() {
  {
    printf 'osmap_service_enablement_result=%s\n' "${VALIDATION_RESULT}"
    printf 'project_root=%s\n' "${PROJECT_ROOT}"
    printf 'assessed_host=%s\n' "${ASSESSED_HOST}"
    printf 'assessed_snapshot=%s\n' "${ASSESSED_SNAPSHOT}"
    printf 'shared_runtime_group=%s\n' "${SHARED_RUNTIME_GROUP}"
    printf 'service_binary_state=%s\n' "${OSMAP_BIN_STATE}"
    printf 'shared_group_line=%s\n' "${SHARED_GROUP_LINE:-missing}"
    printf 'osmap_group_membership=%s\n' "${OSMAP_GROUP_MEMBERSHIP:-missing}"
    printf 'serve_service_check_rc=%s\n' "${SERVE_SERVICE_CHECK_RC}"
    printf 'helper_service_check_rc=%s\n' "${HELPER_SERVICE_CHECK_RC}"
    printf 'http_listener_bindings=%s\n' "${HTTP_BINDINGS:-none}"
    printf 'https_listener_bindings=%s\n' "${HTTPS_BINDINGS:-none}"
    printf 'failed_checks=\n'
    if [ -n "${FAILED_CHECKS}" ]; then
      printf '%s\n' "${FAILED_CHECKS}"
    fi
    printf 'service_binary_listing=\n'
    printf '%s\n' "${OSMAP_BIN_LISTING}"
    printf 'serve_env=\n'
    printf '%s\n' "${SERVE_ENV_CONTENT}"
    printf 'helper_env=\n'
    printf '%s\n' "${HELPER_ENV_CONTENT}"
    printf 'serve_run=\n'
    printf '%s\n' "${SERVE_RUN_LISTING}"
    printf 'helper_run=\n'
    printf '%s\n' "${HELPER_RUN_LISTING}"
    printf 'serve_rc=\n'
    printf '%s\n' "${SERVE_RC_LISTING}"
    printf 'helper_rc=\n'
    printf '%s\n' "${HELPER_RC_LISTING}"
    printf 'helper_socket=\n'
    printf '%s\n' "${HELPER_SOCKET_LISTING}"
    printf 'listener_lines=\n'
    printf '%s\n' "${LISTENER_LINES}"
  } > "${REPORT_PATH}"
}

parse_args "$@"

require_tool awk
require_tool doas
require_tool git
require_tool grep
require_tool hostname
require_tool netstat
require_tool paste
require_tool sort

ASSESSED_HOST="$(hostname)"
ASSESSED_SNAPSHOT="$(git -C "${PROJECT_ROOT}" rev-parse --short HEAD)"
LISTENER_LINES="$(capture_listener_lines)"
HTTP_BINDINGS="$(listener_bindings_for_port 8080)"
HTTPS_BINDINGS="$(listener_bindings_for_port 443)"

OSMAP_BIN_LISTING="$(capture_file_mode "${OSMAP_BIN_PATH}")"
SERVE_ENV_CONTENT="$(capture_file_excerpt "${SERVE_ENV_PATH}")"
HELPER_ENV_CONTENT="$(capture_file_excerpt "${HELPER_ENV_PATH}")"
SERVE_RUN_LISTING="$(capture_file_mode "${SERVE_RUN_PATH}")"
HELPER_RUN_LISTING="$(capture_file_mode "${HELPER_RUN_PATH}")"
SERVE_RC_LISTING="$(capture_file_mode "${SERVE_RC_PATH}")"
HELPER_RC_LISTING="$(capture_file_mode "${HELPER_RC_PATH}")"
HELPER_SOCKET_LISTING="$(capture_file_mode "${HELPER_SOCKET_PATH}")"
SHARED_GROUP_LINE="$(capture_group_line)"
OSMAP_GROUP_MEMBERSHIP="$(capture_user_membership _osmap)"
SERVE_SERVICE_CHECK_RC="$(capture_service_check_status osmap_serve)"
HELPER_SERVICE_CHECK_RC="$(capture_service_check_status osmap_mailbox_helper)"

VALIDATION_RESULT="passed"
OSMAP_BIN_STATE="missing"
if doas test -x "${OSMAP_BIN_PATH}"; then
  OSMAP_BIN_STATE="installed"
else
  append_failed_check "missing_osmap_binary"
fi

if [ -z "${SHARED_GROUP_LINE}" ]; then
  append_failed_check "missing_shared_runtime_group"
fi

if ! printf '%s\n' "${OSMAP_GROUP_MEMBERSHIP}" | tr ' ' '\n' | grep -Fxq "${SHARED_RUNTIME_GROUP}"; then
  append_failed_check "osmap_user_missing_shared_runtime_group_membership"
fi

if ! doas test -f "${SERVE_ENV_PATH}"; then
  append_failed_check "missing_serve_env_file"
fi

if ! doas test -f "${HELPER_ENV_PATH}"; then
  append_failed_check "missing_helper_env_file"
fi

if ! doas test -x "${SERVE_RUN_PATH}"; then
  append_failed_check "missing_serve_launcher"
fi

if ! doas test -x "${HELPER_RUN_PATH}"; then
  append_failed_check "missing_helper_launcher"
fi

if ! doas test -x "${SERVE_RC_PATH}"; then
  append_failed_check "missing_serve_rc_script"
fi

if ! doas test -x "${HELPER_RC_PATH}"; then
  append_failed_check "missing_helper_rc_script"
fi

if [ "${HELPER_SERVICE_CHECK_RC}" != "0" ]; then
  append_failed_check "mailbox_helper_service_not_healthy"
fi

if [ "${SERVE_SERVICE_CHECK_RC}" != "0" ]; then
  append_failed_check "serve_service_not_healthy"
fi

if ! doas test -S "${HELPER_SOCKET_PATH}"; then
  append_failed_check "missing_helper_socket"
fi

if [ "${HTTP_BINDINGS:-}" != "127.0.0.1.8080" ]; then
  append_failed_check "loopback_http_listener_not_ready"
fi

if [ -n "${FAILED_CHECKS}" ]; then
  VALIDATION_RESULT="failed"
fi

write_report
log "wrote service enablement report to ${REPORT_PATH}"
log "service enablement validation result: ${VALIDATION_RESULT}"

if [ "${VALIDATION_RESULT}" != "passed" ]; then
  exit 1
fi
