#!/bin/sh
#
# Run the V2 readiness wrapper with a temporary validation password override
# when the selected step set includes the real login-send proof.
#
# This keeps the authoritative V2 gate in
# maint/live/osmap-live-validate-v2-readiness.ksh while moving the guarded
# mailbox-hash swap and restoration into one repo-owned operator path.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
READINESS_WRAPPER="${PROJECT_ROOT}/maint/live/osmap-live-validate-v2-readiness.ksh"
VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
TMPDIR_PATH="${OSMAP_V2_READINESS_TMPDIR:-${HOME}/tmp-osmap-v2-readiness}"
RESTORE_PENDING=0
ORIGINAL_HASH=""

log() {
  printf '%s\n' "$*"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing required tool: $1"
    exit 1
  }
}

sql_quote() {
  printf '%s' "$1" | sed "s/'/''/g"
}

update_mailbox_hash() {
  next_hash="$1"
  quoted_hash="$(sql_quote "${next_hash}")"
  quoted_user="$(sql_quote "${VALIDATION_USER}")"

  doas mariadb postfixadmin <<SQL
UPDATE mailbox
SET password='${quoted_hash}'
WHERE username='${quoted_user}' AND active='1';
SQL
}

restore_original_hash() {
  [ "${RESTORE_PENDING}" = "1" ] || return 0
  update_mailbox_hash "${ORIGINAL_HASH}"
  RESTORE_PENDING=0
}

steps_require_validation_password() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h|--list)
        return 1
        ;;
      --report)
        [ "$#" -ge 2 ] || return 1
        shift 2
        ;;
      --report=*)
        shift
        ;;
      --)
        shift
        break
        ;;
      -*)
        return 1
        ;;
      *)
        break
        ;;
    esac
  done

  if [ "$#" -eq 0 ]; then
    return 0
  fi

  for requested_step in "$@"; do
    [ "${requested_step}" = "login-send" ] && return 0
  done

  return 1
}

usage() {
  cat <<EOF
usage: $(basename "$0") [v2-readiness-wrapper options and steps]

examples:
  sh ./maint/live/osmap-run-v2-readiness-with-temporary-validation-password.sh
  sh ./maint/live/osmap-run-v2-readiness-with-temporary-validation-password.sh --report "\$HOME/osmap-v2-readiness-report.txt"
  sh ./maint/live/osmap-run-v2-readiness-with-temporary-validation-password.sh login-send

This helper only applies the temporary validation-password override when the
selected proof set includes login-send. Other Version 2 subsets are passed
through directly to maint/live/osmap-live-validate-v2-readiness.ksh.
EOF
}

case "${1:-}" in
  --help|-h)
    usage
    exit 0
    ;;
esac

require_tool doas
require_tool ksh
require_tool mkdir
require_tool openssl
require_tool sed

mkdir -p "${TMPDIR_PATH}"
chmod 700 "${TMPDIR_PATH}"
export TMPDIR="${TMPDIR_PATH}"

if ! steps_require_validation_password "$@"; then
  exec ksh "${READINESS_WRAPPER}" "$@"
fi

ORIGINAL_HASH="$(doas mariadb -N -B postfixadmin -e "SELECT password FROM mailbox WHERE username='${VALIDATION_USER}' AND active='1';")"
[ -n "${ORIGINAL_HASH}" ] || {
  log "no active mailbox password hash found for ${VALIDATION_USER}"
  exit 1
}

trap restore_original_hash EXIT INT TERM HUP

TEMP_PASSWORD="$(openssl rand -hex 16)"
[ -n "${TEMP_PASSWORD}" ] || {
  log "failed to generate temporary validation password"
  exit 1
}

TEMP_HASH="$(doas doveadm pw -s BLF-CRYPT -p "${TEMP_PASSWORD}")"
[ -n "${TEMP_HASH}" ] || {
  log "failed to generate temporary validation password hash"
  exit 1
}

update_mailbox_hash "${TEMP_HASH}"
RESTORE_PENDING=1

log "running V2 readiness wrapper with temporary validation password override"
OSMAP_VALIDATION_PASSWORD="${TEMP_PASSWORD}" \
  ksh "${READINESS_WRAPPER}" "$@"
