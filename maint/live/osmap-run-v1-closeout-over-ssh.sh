#!/bin/sh
#
# Run the authoritative Version 1 closeout proof set on the live OpenBSD host
# through SSH from a machine that can reach that host.
#
# This wrapper does not store mailbox secrets. If the selected proof steps
# include `login-send`, operators should export OSMAP_VALIDATION_PASSWORD
# locally before invoking this script; the value is forwarded only for that
# remote command invocation.

set -eu

SSH_TARGET="${OSMAP_V1_CLOSEOUT_SSH_TARGET:-mail.blackbagsecurity.com}"
REMOTE_PROJECT_ROOT="${OSMAP_V1_CLOSEOUT_REMOTE_PROJECT_ROOT:-~/OSMAP}"
REMOTE_REPORT_PATH="${OSMAP_V1_CLOSEOUT_REMOTE_REPORT_PATH:-~/osmap-v1-closeout-report.txt}"
LOCAL_REPORT_PATH="${OSMAP_V1_CLOSEOUT_LOCAL_REPORT_PATH:-}"
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

quote_sh() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

usage() {
  cat <<EOF
usage: $(basename "$0") [--host <ssh-target>] [--remote-project-root <path>] [--remote-report <path>] [--local-report <path>] [step ...]

examples:
  ./maint/live/osmap-run-v1-closeout-over-ssh.sh
  ./maint/live/osmap-run-v1-closeout-over-ssh.sh login-send
  ./maint/live/osmap-run-v1-closeout-over-ssh.sh --local-report ./maint/live/latest-host-report.txt security-check
EOF
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

validate_steps() {
  for requested_step in "$@"; do
    case "${requested_step}" in
      security-check|login-send|all-mailbox-search|archive-shortcut|session-surface|send-throttle|move-throttle)
        ;;
      *)
        log "unknown closeout step: ${requested_step}"
        exit 1
        ;;
    esac
  done
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h)
        usage
        exit 0
        ;;
      --host)
        [ "$#" -ge 2 ] || {
          log "--host requires a value"
          exit 1
        }
        SSH_TARGET="$2"
        shift 2
        ;;
      --remote-project-root)
        [ "$#" -ge 2 ] || {
          log "--remote-project-root requires a value"
          exit 1
        }
        REMOTE_PROJECT_ROOT="$2"
        shift 2
        ;;
      --remote-report)
        [ "$#" -ge 2 ] || {
          log "--remote-report requires a value"
          exit 1
        }
        REMOTE_REPORT_PATH="$2"
        shift 2
        ;;
      --local-report)
        [ "$#" -ge 2 ] || {
          log "--local-report requires a value"
          exit 1
        }
        LOCAL_REPORT_PATH="$2"
        shift 2
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
    validate_steps "$@"
    STEP_NAMES="$(printf '%s\n' "$@")"
  fi

  if [ -z "${LOCAL_REPORT_PATH}" ]; then
    LOCAL_REPORT_PATH="${PWD}/osmap-v1-closeout-report.txt"
  fi
}

build_remote_command() {
  steps_csv="$1"
  command_prefix=""

  if printf '%s\n' "${steps_csv}" | grep -Fxq "login-send"; then
    [ -n "${OSMAP_VALIDATION_PASSWORD:-}" ] || {
      log "OSMAP_VALIDATION_PASSWORD must be set when running login-send over SSH"
      exit 1
    }
    command_prefix="OSMAP_VALIDATION_PASSWORD=$(quote_sh "${OSMAP_VALIDATION_PASSWORD}") "
  fi

  printf '%s' \
    "cd $(quote_sh "${REMOTE_PROJECT_ROOT}") && " \
    "${command_prefix}" \
    "ksh ./maint/live/osmap-live-validate-v1-closeout.ksh --report $(quote_sh "${REMOTE_REPORT_PATH}")"

  printf ' %s' $(printf '%s\n' "${steps_csv}" | while IFS= read -r step_name; do quote_sh "${step_name}"; done)
}

parse_args "$@"

require_tool ssh
require_tool sed

REMOTE_COMMAND="$(build_remote_command "${STEP_NAMES}")"

log "running remote V1 closeout proof set on ${SSH_TARGET}"
ssh "${SSH_TARGET}" "${REMOTE_COMMAND}"

log "fetching remote report from ${SSH_TARGET}:${REMOTE_REPORT_PATH}"
ssh "${SSH_TARGET}" "cat $(quote_sh "${REMOTE_REPORT_PATH}")" > "${LOCAL_REPORT_PATH}"
log "wrote local closeout report to ${LOCAL_REPORT_PATH}"
