#!/bin/sh
#
# Run the current repo-owned Version 1 closeout proof set on a live OpenBSD
# host.
#
# This wrapper keeps the authoritative gate in one operator-friendly place
# without teaching the repository to store mailbox secrets. By default it runs
# the exact proof set named in docs/ACCEPTANCE_CRITERIA.md. Operators may also
# pass one or more step names to rerun a narrower subset after a targeted
# change, list the current gate steps, or capture a small summary report.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEFAULT_REPORT_PATH="${PROJECT_ROOT}/maint/live/osmap-live-validate-v1-closeout-report.txt"
REPORT_PATH="${OSMAP_V1_CLOSEOUT_REPORT_PATH:-}"
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

usage() {
  cat <<EOF
usage: $(basename "$0") [--list] [--report <path>] [step ...]

steps:
  security-check
  login-send
  all-mailbox-search
  archive-shortcut
  session-surface
  send-throttle
  move-throttle

examples:
  ksh ./maint/live/osmap-live-validate-v1-closeout.ksh
  ksh ./maint/live/osmap-live-validate-v1-closeout.ksh --list
  ksh ./maint/live/osmap-live-validate-v1-closeout.ksh --report /tmp/osmap-v1.txt login-send
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
    all-mailbox-search \
    archive-shortcut \
    session-surface \
    send-throttle \
    move-throttle
}

write_report() {
  [ -n "${REPORT_PATH}" ] || return 0
  {
    printf 'osmap_v1_closeout_result=passed\n'
    printf 'project_root=%s\n' "${PROJECT_ROOT}"
    printf 'step_count=%s\n' "${STEP_COUNT}"
    printf 'steps=\n'
    printf '%s\n' "${STEP_RESULTS}"
  } > "${REPORT_PATH}"
  log "wrote closeout report to ${REPORT_PATH}"
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
all-mailbox-search
archive-shortcut
session-surface
send-throttle
move-throttle"
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
        security-check|login-send|all-mailbox-search|archive-shortcut|session-surface|send-throttle|move-throttle)
          ;;
        *)
          log "unknown closeout step: ${requested_step}"
          log "valid steps: security-check login-send all-mailbox-search archive-shortcut session-surface send-throttle move-throttle"
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
  elif [ -n "${OSMAP_V1_CLOSEOUT_REPORT_PATH:-}" ]; then
    REPORT_PATH="${OSMAP_V1_CLOSEOUT_REPORT_PATH}"
  elif [ "$(printf '%s\n' "${STEP_NAMES}" | awk 'NF { count += 1 } END { print count + 0 }')" -gt 1 ]; then
    REPORT_PATH="${DEFAULT_REPORT_PATH}"
  fi
}

parse_args "$@"

# shellcheck disable=SC2086
require_login_secret_if_needed ${STEP_NAMES}

log "running Version 1 closeout proof set from ${PROJECT_ROOT}"

for step_name in ${STEP_NAMES}; do
  case "${step_name}" in
    security-check)
      run_step "${step_name}" ./maint/live/osmap-host-validate.ksh make security-check
      ;;
    login-send)
      run_step "${step_name}" ksh ./maint/live/osmap-live-validate-login-send.ksh
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
  esac
  append_result "${step_name}=passed"
done

write_report
log "Version 1 closeout proof set passed"
