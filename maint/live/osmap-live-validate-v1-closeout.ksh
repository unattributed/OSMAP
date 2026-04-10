#!/bin/sh
#
# Run the current repo-owned Version 1 closeout proof set on a live OpenBSD
# host.
#
# This wrapper keeps the authoritative gate in one operator-friendly place
# without teaching the repository to store mailbox secrets. By default it runs
# the exact proof set named in docs/ACCEPTANCE_CRITERIA.md. Operators may also
# pass one or more step names to rerun a narrower subset after a targeted
# change.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

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

resolve_steps() {
  if [ "$#" -eq 0 ]; then
    set -- \
      security-check \
      login-send \
      all-mailbox-search \
      archive-shortcut \
      session-surface \
      send-throttle \
      move-throttle
  fi

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
  done

  printf '%s\n' "$@"
}

STEPS="$(resolve_steps "$@")"

# shellcheck disable=SC2086
require_login_secret_if_needed ${STEPS}

log "running Version 1 closeout proof set from ${PROJECT_ROOT}"

for step_name in ${STEPS}; do
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
done

log "Version 1 closeout proof set passed"
