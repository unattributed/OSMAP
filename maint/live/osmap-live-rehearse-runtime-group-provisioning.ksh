#!/bin/sh
#
# Prepare a reviewed runtime-group provisioning rehearsal or execute the staged
# apply path for mail.blackbagsecurity.com from the standard host checkout.

set -eu

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
MODE="rehearse"
SESSION_DIR="${OSMAP_RUNTIME_GROUP_SESSION_DIR:-}"
TARGET_USER="${OSMAP_RUNTIME_GROUP_TARGET_USER:-_osmap}"
SHARED_RUNTIME_GROUP="${OSMAP_SHARED_RUNTIME_GROUP:-osmaprt}"
GROUP_FILE_PATH="${OSMAP_SERVICE_GROUP_FILE_PATH:-/etc/group}"
REPORT_NAME="service-enablement-after-runtime-group.txt"

log() {
  printf '%s\n' "$*"
}

quote_sh() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing required tool: $1"
    exit 1
  }
}

usage() {
  cat <<EOF
usage: $(basename "$0") [--mode rehearse|apply] [--session-dir <path>]
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h)
        usage
        exit 0
        ;;
      --mode)
        [ "$#" -ge 2 ] || {
          log "--mode requires a value"
          exit 1
        }
        MODE="$2"
        shift 2
        ;;
      --mode=*)
        MODE="${1#--mode=}"
        shift
        ;;
      --session-dir)
        [ "$#" -ge 2 ] || {
          log "--session-dir requires a path"
          exit 1
        }
        SESSION_DIR="$2"
        shift 2
        ;;
      --session-dir=*)
        SESSION_DIR="${1#--session-dir=}"
        shift
        ;;
      *)
        log "unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done

  case "${MODE}" in
    rehearse|apply) ;;
    *)
      log "unsupported mode: ${MODE}"
      exit 1
      ;;
  esac

  if [ -z "${SESSION_DIR}" ]; then
    SESSION_DIR="${HOME}/osmap-runtime-group/$(date +%Y%m%d-%H%M%S)"
  fi
}

capture_group_line() {
  doas grep -E "^${SHARED_RUNTIME_GROUP}:" "${GROUP_FILE_PATH}" 2>/dev/null || true
}

capture_primary_group() {
  doas id -gn "${TARGET_USER}"
}

capture_secondary_groups() {
  primary_group="$1"
  group_list="$(doas id -Gn "${TARGET_USER}" 2>/dev/null || true)"

  if [ -z "${group_list}" ]; then
    return 0
  fi

  printf '%s\n' "${group_list}" | tr ' ' '\n' | awk -v primary="${primary_group}" '
    NF && $0 != primary { print $0 }
  ' | paste -sd ',' -
}

write_apply_script() {
  cat > "${APPLY_SCRIPT_PATH}" <<EOF
#!/bin/sh
set -eu

target_user=$(quote_sh "${TARGET_USER}")
runtime_group=$(quote_sh "${SHARED_RUNTIME_GROUP}")
group_file=$(quote_sh "${GROUP_FILE_PATH}")
validator_script=$(quote_sh "${SERVICE_VALIDATOR_PATH}")
validator_report=$(quote_sh "${VALIDATOR_REPORT_PATH}")

doas id "\$target_user" >/dev/null 2>&1 || {
  printf '%s\n' "missing required user: \$target_user" >&2
  exit 1
}

if ! doas grep -Eq "^\${runtime_group}:" "\$group_file" 2>/dev/null; then
  doas groupadd "\$runtime_group"
fi

if ! doas id -Gn "\$target_user" | tr ' ' '\n' | grep -Fx "\$runtime_group" >/dev/null 2>&1; then
  doas usermod -G "\$runtime_group" "\$target_user"
fi

validator_rc=0
if ! OSMAP_SHARED_RUNTIME_GROUP="\$runtime_group" OSMAP_SERVICE_GROUP_FILE_PATH="\$group_file" \
  ksh "\$validator_script" --report "\$validator_report"; then
  validator_rc=\$?
fi

case "\$validator_rc" in
  0|1) ;;
  *)
    printf '%s\n' "service validator exited unexpectedly: \$validator_rc" >&2
    exit "\$validator_rc"
    ;;
esac

if grep -Fq 'missing_shared_runtime_group' "\$validator_report"; then
  printf '%s\n' 'service validator still reports missing_shared_runtime_group after runtime-group provisioning' >&2
  exit 1
fi

if grep -Fq 'osmap_user_missing_shared_runtime_group_membership' "\$validator_report"; then
  printf '%s\n' 'service validator still reports missing shared-runtime-group membership after provisioning' >&2
  exit 1
fi

grep -Eq "^shared_group_line=\${runtime_group}:" "\$validator_report" || {
  printf '%s\n' 'service validator did not confirm the shared runtime group line' >&2
  exit 1
}

grep -Eq "^osmap_group_membership=.*\${runtime_group}([ ,]|\$)" "\$validator_report" || {
  printf '%s\n' 'service validator did not confirm _osmap runtime-group membership' >&2
  exit 1
}
EOF

  chmod 0755 "${APPLY_SCRIPT_PATH}"
}

write_restore_script() {
  if [ -n "${ORIGINAL_SECONDARY_GROUPS}" ]; then
    restore_groups_command="doas usermod -S $(quote_sh "${ORIGINAL_SECONDARY_GROUPS}") $(quote_sh "${TARGET_USER}")"
  else
    restore_groups_command="doas usermod -S '' $(quote_sh "${TARGET_USER}")"
  fi

  remove_group_command="# shared runtime group existed before rehearsal"
  if [ "${GROUP_EXISTS_BEFORE}" = "0" ]; then
    remove_group_command="doas groupdel $(quote_sh "${SHARED_RUNTIME_GROUP}") >/dev/null 2>&1 || true"
  fi

  cat > "${RESTORE_SCRIPT_PATH}" <<EOF
#!/bin/sh
set -eu

${restore_groups_command}
${remove_group_command}
EOF

  chmod 0755 "${RESTORE_SCRIPT_PATH}"
}

write_session_report() {
  {
    printf 'osmap_runtime_group_session_mode=%s\n' "${MODE}"
    printf 'session_dir=%s\n' "${SESSION_DIR}"
    printf 'project_root=%s\n' "${PROJECT_ROOT}"
    printf 'assessed_snapshot=%s\n' "${ASSESSED_SNAPSHOT}"
    printf 'target_user=%s\n' "${TARGET_USER}"
    printf 'shared_runtime_group=%s\n' "${SHARED_RUNTIME_GROUP}"
    printf 'group_file=%s\n' "${GROUP_FILE_PATH}"
    printf 'original_primary_group=%s\n' "${ORIGINAL_PRIMARY_GROUP}"
    printf 'original_secondary_groups=%s\n' "${ORIGINAL_SECONDARY_GROUPS}"
    printf 'group_exists_before=%s\n' "${GROUP_EXISTS_BEFORE}"
    printf 'group_line_before=%s\n' "${GROUP_LINE_BEFORE:-missing}"
    printf 'apply_script=%s\n' "${APPLY_SCRIPT_PATH}"
    printf 'restore_script=%s\n' "${RESTORE_SCRIPT_PATH}"
    printf 'validator_report=%s\n' "${VALIDATOR_REPORT_PATH}"
  } > "${SESSION_REPORT_PATH}"
}

parse_args "$@"

require_tool awk
require_tool date
require_tool doas
require_tool git
require_tool grep
require_tool groupadd
require_tool groupdel
require_tool id
require_tool ksh
require_tool mkdir
require_tool paste
require_tool sed
require_tool tr
require_tool usermod

SERVICE_VALIDATOR_PATH="${PROJECT_ROOT}/maint/live/osmap-live-validate-service-enablement.ksh"
[ -f "${SERVICE_VALIDATOR_PATH}" ] || {
  log "missing service validator: ${SERVICE_VALIDATOR_PATH}"
  exit 1
}

ASSESSED_SNAPSHOT="$(git -C "${PROJECT_ROOT}" rev-parse --short HEAD)"
SCRIPTS_ROOT="${SESSION_DIR}/scripts"
REPORTS_ROOT="${SESSION_DIR}/reports"
SESSION_REPORT_PATH="${SESSION_DIR}/runtime-group-session.txt"
APPLY_SCRIPT_PATH="${SCRIPTS_ROOT}/apply-runtime-group-provisioning.sh"
RESTORE_SCRIPT_PATH="${SCRIPTS_ROOT}/restore-runtime-group-provisioning.sh"
VALIDATOR_REPORT_PATH="${REPORTS_ROOT}/${REPORT_NAME}"

mkdir -p "${SCRIPTS_ROOT}" "${REPORTS_ROOT}"

GROUP_LINE_BEFORE="$(capture_group_line)"
GROUP_EXISTS_BEFORE=0
if [ -n "${GROUP_LINE_BEFORE}" ]; then
  GROUP_EXISTS_BEFORE=1
fi

ORIGINAL_PRIMARY_GROUP="$(capture_primary_group)"
ORIGINAL_SECONDARY_GROUPS="$(capture_secondary_groups "${ORIGINAL_PRIMARY_GROUP}")"

write_apply_script
write_restore_script
write_session_report

log "prepared runtime-group provisioning session in ${SESSION_DIR}"
log "apply script: ${APPLY_SCRIPT_PATH}"
log "restore script: ${RESTORE_SCRIPT_PATH}"

if [ "${MODE}" = "apply" ]; then
  sh "${APPLY_SCRIPT_PATH}"
  log "runtime-group provisioning apply completed"
  log "validator report: ${VALIDATOR_REPORT_PATH}"
else
  log "rehearsal mode did not modify the live group database"
fi
