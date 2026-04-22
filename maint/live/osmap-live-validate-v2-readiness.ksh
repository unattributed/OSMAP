#!/bin/sh
#
# Run the current repo-owned Version 2 readiness proof set on a live OpenBSD
# host.
#
# This wrapper keeps the authoritative Version 2 gate in one operator-friendly
# place. By default it runs the exact proof set named in
# docs/V2_ACCEPTANCE_CRITERIA.md. Operators may also pass one or more step
# names to rerun a narrower subset, list the current gate steps, or capture a
# small summary report.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEFAULT_REPORT_PATH="${PROJECT_ROOT}/maint/live/osmap-live-validate-v2-readiness-report.txt"
REPORT_PATH="${OSMAP_V2_READINESS_REPORT_PATH:-}"
SERVICE_GUARD_MODE="${OSMAP_V2_READINESS_SERVICE_GUARD:-auto}"
SERVICE_GUARD_REPORT_PATH="${OSMAP_V2_READINESS_SERVICE_GUARD_REPORT_PATH:-}"
SERVICE_GUARD_RESULT="not_run"
SERVICE_GUARD_ARMED=0
STEP_RESULTS=""
STEP_COUNT=0
STEP_NAMES=""

log() {
  printf '%s\n' "$*"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing required tool: $1"
    exit 1
  }
}

require_tool ksh

on_exit() {
  exit_status="$?"
  if [ "${SERVICE_GUARD_ARMED}" = "1" ]; then
    if ! ensure_persistent_service_health; then
      [ "${exit_status}" -eq 0 ] && exit_status=1
    fi
  fi
  exit "${exit_status}"
}

trap on_exit EXIT INT TERM HUP

usage() {
  cat <<EOF
usage: $(basename "$0") [--list] [--report <path>] [step ...]

steps:
  security-check
  login-send
  safe-html-attachment-download
  login-failure-normalization
  all-mailbox-search
  archive-shortcut
  session-surface
  send-throttle
  move-throttle
  helper-peer-auth
  request-guardrails
  mailbox-backend-unavailable

examples:
  ksh ./maint/live/osmap-live-validate-v2-readiness.ksh
  ksh ./maint/live/osmap-live-validate-v2-readiness.ksh --list
  ksh ./maint/live/osmap-live-validate-v2-readiness.ksh --report /tmp/osmap-v2.txt login-send helper-peer-auth
EOF
}

append_result() {
  step_name="$1"
  if [ -z "${STEP_RESULTS}" ]; then
    STEP_RESULTS="${step_name}"
  else
    STEP_RESULTS="${STEP_RESULTS}
${step_name}"
  fi
  STEP_COUNT="$((STEP_COUNT + 1))"
}

list_steps() {
  printf '%s\n' \
    security-check \
    login-send \
    safe-html-attachment-download \
    login-failure-normalization \
    all-mailbox-search \
    archive-shortcut \
    session-surface \
    send-throttle \
    move-throttle \
    helper-peer-auth \
    request-guardrails \
    mailbox-backend-unavailable
}

write_report() {
  [ -n "${REPORT_PATH}" ] || return 0
  {
    printf 'osmap_v2_readiness_result=passed\n'
    printf 'project_root=%s\n' "${PROJECT_ROOT}"
    printf 'step_count=%s\n' "${STEP_COUNT}"
    printf 'service_guard_result=%s\n' "${SERVICE_GUARD_RESULT}"
    printf 'service_guard_report=%s\n' "${SERVICE_GUARD_REPORT_PATH:-<none>}"
    printf 'steps=\n'
    printf '%s\n' "${STEP_RESULTS}"
  } > "${REPORT_PATH}"
  log "wrote v2 readiness report to ${REPORT_PATH}"
}

run_step() {
  step_name="$1"
  shift
  log "==> ${step_name}"
  (
    cd "${PROJECT_ROOT}"
    "$@"
  )
}

service_guard_can_run() {
  case "${SERVICE_GUARD_MODE}" in
    never)
      return 1
      ;;
    auto|always)
      ;;
    *)
      log "unsupported service guard mode: ${SERVICE_GUARD_MODE}"
      return 2
      ;;
  esac

  if ! command -v doas >/dev/null 2>&1 || ! command -v rcctl >/dev/null 2>&1; then
    [ "${SERVICE_GUARD_MODE}" = "always" ] && {
      log "service guard requested but doas or rcctl is unavailable"
      return 2
    }
    return 1
  fi

  if ! doas test -x /etc/rc.d/osmap_mailbox_helper >/dev/null 2>&1 ||
    ! doas test -x /etc/rc.d/osmap_serve >/dev/null 2>&1; then
    [ "${SERVICE_GUARD_MODE}" = "always" ] && {
      log "service guard requested but OSMAP rc.d scripts are not installed"
      return 2
    }
    return 1
  fi

  return 0
}

ensure_service_started() {
  service_name="$1"

  if doas rcctl check "${service_name}" >/dev/null 2>&1; then
    return 0
  fi

  log "persistent service ${service_name} is not healthy; attempting rcctl start"
  doas rcctl start "${service_name}" >/dev/null 2>&1 || true

  if doas rcctl check "${service_name}" >/dev/null 2>&1; then
    return 0
  fi

  log "persistent service ${service_name} is still not healthy after rcctl start"
  return 1
}

ensure_persistent_service_health() {
  SERVICE_GUARD_ARMED=0

  set +e
  service_guard_can_run
  guard_rc="$?"
  set -e
  if [ "${guard_rc}" -ne 0 ]; then
    if [ "${guard_rc}" -eq 2 ]; then
      SERVICE_GUARD_RESULT="failed"
      return 1
    fi
    SERVICE_GUARD_RESULT="skipped"
    return 0
  fi

  log "checking persistent OSMAP service health after readiness proof set"

  if [ -z "${SERVICE_GUARD_REPORT_PATH}" ]; then
    if [ -n "${REPORT_PATH}" ]; then
      SERVICE_GUARD_REPORT_PATH="${REPORT_PATH}.service-enablement"
    else
      SERVICE_GUARD_REPORT_PATH="${DEFAULT_REPORT_PATH}.service-enablement"
    fi
  fi

  if ! ensure_service_started osmap_mailbox_helper; then
    SERVICE_GUARD_RESULT="failed"
    return 1
  fi

  if ! ensure_service_started osmap_serve; then
    SERVICE_GUARD_RESULT="failed"
    return 1
  fi

  if ! ksh "${PROJECT_ROOT}/maint/live/osmap-live-validate-service-enablement.ksh" \
    --report "${SERVICE_GUARD_REPORT_PATH}"; then
    SERVICE_GUARD_RESULT="failed"
    return 1
  fi

  SERVICE_GUARD_RESULT="passed"
  log "persistent OSMAP service guard passed"
}

require_login_secret_if_needed() {
  for requested_step in "$@"; do
    if [ "${requested_step}" = "login-send" ]; then
      [ -n "${OSMAP_VALIDATION_PASSWORD:-}" ] || {
        log "OSMAP_VALIDATION_PASSWORD must be set when running login-send"
        exit 1
      }
      return 0
    fi
  done
}

set_default_steps() {
  STEP_NAMES="security-check
login-send
safe-html-attachment-download
login-failure-normalization
all-mailbox-search
archive-shortcut
session-surface
send-throttle
move-throttle
helper-peer-auth
request-guardrails
mailbox-backend-unavailable"
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h)
        usage
        exit 0
        ;;
      --list)
        list_steps
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
      --)
        shift
        break
        ;;
      -*)
        log "unknown option: $1"
        usage
        exit 1
        ;;
      *)
        break
        ;;
    esac
  done

  if [ "$#" -eq 0 ]; then
    set_default_steps
  else
    STEP_NAMES=""
    for requested_step in "$@"; do
      case "${requested_step}" in
        security-check|login-send|safe-html-attachment-download|login-failure-normalization|all-mailbox-search|archive-shortcut|session-surface|send-throttle|move-throttle|helper-peer-auth|request-guardrails|mailbox-backend-unavailable)
          ;;
        *)
          log "unknown v2 readiness step: ${requested_step}"
          log "valid steps: security-check login-send safe-html-attachment-download login-failure-normalization all-mailbox-search archive-shortcut session-surface send-throttle move-throttle helper-peer-auth request-guardrails mailbox-backend-unavailable"
          exit 1
          ;;
      esac

      if [ -z "${STEP_NAMES}" ]; then
        STEP_NAMES="${requested_step}"
      else
        STEP_NAMES="${STEP_NAMES}
${requested_step}"
      fi
    done
  fi

  if [ -n "${REPORT_PATH}" ]; then
    :
  elif [ -n "${OSMAP_V2_READINESS_REPORT_PATH:-}" ]; then
    REPORT_PATH="${OSMAP_V2_READINESS_REPORT_PATH}"
  elif [ "$(printf '%s\n' "${STEP_NAMES}" | awk 'NF { count += 1 } END { print count + 0 }')" -gt 1 ]; then
    REPORT_PATH="${DEFAULT_REPORT_PATH}"
  fi
}

parse_args "$@"

# shellcheck disable=SC2086
require_login_secret_if_needed ${STEP_NAMES}

log "running Version 2 readiness proof set from ${PROJECT_ROOT}"
SERVICE_GUARD_ARMED=1

for step_name in ${STEP_NAMES}; do
  case "${step_name}" in
    security-check)
      run_step "${step_name}" ./maint/live/osmap-host-validate.ksh make security-check
      ;;
    login-send)
      run_step "${step_name}" ksh ./maint/live/osmap-live-validate-login-send.ksh
      ;;
    safe-html-attachment-download)
      run_step "${step_name}" ksh ./maint/live/osmap-live-validate-inline-image-metadata.ksh
      ;;
    login-failure-normalization)
      run_step "${step_name}" ksh ./maint/live/osmap-live-validate-login-failure-normalization.ksh
      ;;
    all-mailbox-search)
      run_step "${step_name}" ksh ./maint/live/osmap-live-validate-all-mailbox-search.ksh
      ;;
    archive-shortcut)
      run_step "${step_name}" ksh ./maint/live/osmap-live-validate-archive-shortcut.ksh
      ;;
    session-surface)
      run_step "${step_name}" ksh ./maint/live/osmap-live-validate-session-surface.ksh
      ;;
    send-throttle)
      run_step "${step_name}" ksh ./maint/live/osmap-live-validate-send-throttle.ksh
      ;;
    move-throttle)
      run_step "${step_name}" ksh ./maint/live/osmap-live-validate-move-throttle.ksh
      ;;
    helper-peer-auth)
      run_step "${step_name}" ksh ./maint/live/osmap-live-validate-helper-peer-auth.ksh
      ;;
    request-guardrails)
      run_step "${step_name}" ksh ./maint/live/osmap-live-validate-request-guardrails.ksh
      ;;
    mailbox-backend-unavailable)
      run_step "${step_name}" ksh ./maint/live/osmap-live-validate-mailbox-backend-unavailable.ksh
      ;;
  esac
  append_result "${step_name}=passed"
done

ensure_persistent_service_health
write_report
log "Version 2 readiness proof set passed"
