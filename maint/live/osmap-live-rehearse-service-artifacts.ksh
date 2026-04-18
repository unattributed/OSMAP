#!/bin/sh
#
# Prepare a reviewed service-artifact rehearsal or execute the staged apply
# path for mail.blackbagsecurity.com from the standard host checkout.

set -eu

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
GENERIC_ARTIFACT_ROOT="${PROJECT_ROOT}/maint/openbsd"
HOST_ARTIFACT_ROOT="${PROJECT_ROOT}/maint/openbsd/mail.blackbagsecurity.com"
MODE="rehearse"
SESSION_DIR="${OSMAP_SERVICE_ARTIFACTS_SESSION_DIR:-}"

LIVE_SERVE_ENV_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH:-/etc/osmap/osmap-serve.env}"
LIVE_HELPER_ENV_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH:-/etc/osmap/osmap-mailbox-helper.env}"
LIVE_SERVE_RUN_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH:-/usr/local/libexec/osmap/osmap-serve-run.ksh}"
LIVE_HELPER_RUN_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH:-/usr/local/libexec/osmap/osmap-mailbox-helper-run.ksh}"
LIVE_SERVE_RC_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH:-/etc/rc.d/osmap_serve}"
LIVE_HELPER_RC_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH:-/etc/rc.d/osmap_mailbox_helper}"

SERVE_ENV_RELATIVE_PATH="etc/osmap/osmap-serve.env"
HELPER_ENV_RELATIVE_PATH="etc/osmap/osmap-mailbox-helper.env"
SERVE_RUN_RELATIVE_PATH="usr/local/libexec/osmap/osmap-serve-run.ksh"
HELPER_RUN_RELATIVE_PATH="usr/local/libexec/osmap/osmap-mailbox-helper-run.ksh"
SERVE_RC_RELATIVE_PATH="etc/rc.d/osmap_serve"
HELPER_RC_RELATIVE_PATH="etc/rc.d/osmap_mailbox_helper"
REPORT_NAME="service-enablement-after-service-artifacts.txt"

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
    SESSION_DIR="${HOME}/osmap-service-artifacts/$(date +%Y%m%d-%H%M%S)"
  fi
}

assert_repo_artifact_exists() {
  [ -f "$1" ] || {
    log "missing reviewed artifact: $1"
    exit 1
  }
}

backup_optional_live_file() {
  live_path="$1"
  backup_path="$2"

  if doas test -f "${live_path}"; then
    mkdir -p "$(dirname "${backup_path}")"
    doas cat "${live_path}" > "${backup_path}"
  fi
}

stage_repo_artifact() {
  source_path="$1"
  staged_path="$2"

  mkdir -p "$(dirname "${staged_path}")"
  cp "${source_path}" "${staged_path}"
}

write_apply_script() {
  cat > "${APPLY_SCRIPT_PATH}" <<EOF
#!/bin/sh
set -eu

osmap_env_dir=$(quote_sh "$(dirname "${LIVE_SERVE_ENV_PATH}")")
osmap_libexec_dir=$(quote_sh "$(dirname "${LIVE_SERVE_RUN_PATH}")")
osmap_rc_dir=$(quote_sh "$(dirname "${LIVE_SERVE_RC_PATH}")")
validator_script=$(quote_sh "${SERVICE_VALIDATOR_PATH}")
validator_report=$(quote_sh "${VALIDATOR_REPORT_PATH}")

doas install -d "\$osmap_env_dir" "\$osmap_libexec_dir" "\$osmap_rc_dir"
doas install -m 0640 $(quote_sh "${STAGED_ROOT}/${SERVE_ENV_RELATIVE_PATH}") $(quote_sh "${LIVE_SERVE_ENV_PATH}")
doas install -m 0640 $(quote_sh "${STAGED_ROOT}/${HELPER_ENV_RELATIVE_PATH}") $(quote_sh "${LIVE_HELPER_ENV_PATH}")
doas install -m 0555 $(quote_sh "${STAGED_ROOT}/${SERVE_RUN_RELATIVE_PATH}") $(quote_sh "${LIVE_SERVE_RUN_PATH}")
doas install -m 0555 $(quote_sh "${STAGED_ROOT}/${HELPER_RUN_RELATIVE_PATH}") $(quote_sh "${LIVE_HELPER_RUN_PATH}")
doas install -m 0555 $(quote_sh "${STAGED_ROOT}/${SERVE_RC_RELATIVE_PATH}") $(quote_sh "${LIVE_SERVE_RC_PATH}")
doas install -m 0555 $(quote_sh "${STAGED_ROOT}/${HELPER_RC_RELATIVE_PATH}") $(quote_sh "${LIVE_HELPER_RC_PATH}")

validator_rc=0
if ! ksh "\$validator_script" --report "\$validator_report"; then
  validator_rc=\$?
fi

case "\$validator_rc" in
  0|1) ;;
  *)
    printf '%s\n' "service validator exited unexpectedly: \$validator_rc" >&2
    exit "\$validator_rc"
    ;;
esac

for failed_check in \
  missing_serve_env_file \
  missing_helper_env_file \
  missing_serve_launcher \
  missing_helper_launcher \
  missing_serve_rc_script \
  missing_helper_rc_script
do
  if grep -Fq "\${failed_check}" "\$validator_report"; then
    printf '%s\n' "service validator still reports \${failed_check} after service-artifact apply" >&2
    exit 1
  fi
done
EOF

  chmod 0755 "${APPLY_SCRIPT_PATH}"
}

write_restore_install_or_remove() {
  backup_path="$1"
  live_path="$2"
  restore_path="$3"
  mode="$4"

  if [ -f "${backup_path}" ]; then
    cat >> "${restore_path}" <<EOF
doas install -m ${mode} $(quote_sh "${backup_path}") $(quote_sh "${live_path}")
EOF
  else
    cat >> "${restore_path}" <<EOF
doas rm -f $(quote_sh "${live_path}")
EOF
  fi
}

write_restore_script() {
  cat > "${RESTORE_SCRIPT_PATH}" <<EOF
#!/bin/sh
set -eu
EOF

  write_restore_install_or_remove "${BACKUP_ROOT}/${SERVE_ENV_RELATIVE_PATH}" "${LIVE_SERVE_ENV_PATH}" "${RESTORE_SCRIPT_PATH}" "0640"
  write_restore_install_or_remove "${BACKUP_ROOT}/${HELPER_ENV_RELATIVE_PATH}" "${LIVE_HELPER_ENV_PATH}" "${RESTORE_SCRIPT_PATH}" "0640"
  write_restore_install_or_remove "${BACKUP_ROOT}/${SERVE_RUN_RELATIVE_PATH}" "${LIVE_SERVE_RUN_PATH}" "${RESTORE_SCRIPT_PATH}" "0555"
  write_restore_install_or_remove "${BACKUP_ROOT}/${HELPER_RUN_RELATIVE_PATH}" "${LIVE_HELPER_RUN_PATH}" "${RESTORE_SCRIPT_PATH}" "0555"
  write_restore_install_or_remove "${BACKUP_ROOT}/${SERVE_RC_RELATIVE_PATH}" "${LIVE_SERVE_RC_PATH}" "${RESTORE_SCRIPT_PATH}" "0555"
  write_restore_install_or_remove "${BACKUP_ROOT}/${HELPER_RC_RELATIVE_PATH}" "${LIVE_HELPER_RC_PATH}" "${RESTORE_SCRIPT_PATH}" "0555"

  chmod 0755 "${RESTORE_SCRIPT_PATH}"
}

write_session_report() {
  {
    printf 'osmap_service_artifacts_session_mode=%s\n' "${MODE}"
    printf 'session_dir=%s\n' "${SESSION_DIR}"
    printf 'backup_root=%s\n' "${BACKUP_ROOT}"
    printf 'staged_root=%s\n' "${STAGED_ROOT}"
    printf 'apply_script=%s\n' "${APPLY_SCRIPT_PATH}"
    printf 'restore_script=%s\n' "${RESTORE_SCRIPT_PATH}"
    printf 'validator_report=%s\n' "${VALIDATOR_REPORT_PATH}"
  } > "${SESSION_REPORT_PATH}"
}

parse_args "$@"

require_tool cp
require_tool date
require_tool dirname
require_tool doas
require_tool mkdir
require_tool sed

SERVICE_VALIDATOR_PATH="${PROJECT_ROOT}/maint/live/osmap-live-validate-service-enablement.ksh"
[ -f "${SERVICE_VALIDATOR_PATH}" ] || {
  log "missing service validator: ${SERVICE_VALIDATOR_PATH}"
  exit 1
}

SERVE_ENV_SOURCE="${HOST_ARTIFACT_ROOT}/${SERVE_ENV_RELATIVE_PATH}"
HELPER_ENV_SOURCE="${HOST_ARTIFACT_ROOT}/${HELPER_ENV_RELATIVE_PATH}"
SERVE_RUN_SOURCE="${GENERIC_ARTIFACT_ROOT}/libexec/osmap-serve-run.ksh"
HELPER_RUN_SOURCE="${GENERIC_ARTIFACT_ROOT}/libexec/osmap-mailbox-helper-run.ksh"
SERVE_RC_SOURCE="${GENERIC_ARTIFACT_ROOT}/rc.d/osmap_serve"
HELPER_RC_SOURCE="${GENERIC_ARTIFACT_ROOT}/rc.d/osmap_mailbox_helper"

assert_repo_artifact_exists "${SERVE_ENV_SOURCE}"
assert_repo_artifact_exists "${HELPER_ENV_SOURCE}"
assert_repo_artifact_exists "${SERVE_RUN_SOURCE}"
assert_repo_artifact_exists "${HELPER_RUN_SOURCE}"
assert_repo_artifact_exists "${SERVE_RC_SOURCE}"
assert_repo_artifact_exists "${HELPER_RC_SOURCE}"

BACKUP_ROOT="${SESSION_DIR}/backup"
STAGED_ROOT="${SESSION_DIR}/staged"
SCRIPTS_ROOT="${SESSION_DIR}/scripts"
REPORTS_ROOT="${SESSION_DIR}/reports"
SESSION_REPORT_PATH="${SESSION_DIR}/service-artifacts-session.txt"
APPLY_SCRIPT_PATH="${SCRIPTS_ROOT}/apply-service-artifacts.sh"
RESTORE_SCRIPT_PATH="${SCRIPTS_ROOT}/restore-service-artifacts.sh"
VALIDATOR_REPORT_PATH="${REPORTS_ROOT}/${REPORT_NAME}"

mkdir -p "${BACKUP_ROOT}" "${STAGED_ROOT}" "${SCRIPTS_ROOT}" "${REPORTS_ROOT}"

backup_optional_live_file "${LIVE_SERVE_ENV_PATH}" "${BACKUP_ROOT}/${SERVE_ENV_RELATIVE_PATH}"
backup_optional_live_file "${LIVE_HELPER_ENV_PATH}" "${BACKUP_ROOT}/${HELPER_ENV_RELATIVE_PATH}"
backup_optional_live_file "${LIVE_SERVE_RUN_PATH}" "${BACKUP_ROOT}/${SERVE_RUN_RELATIVE_PATH}"
backup_optional_live_file "${LIVE_HELPER_RUN_PATH}" "${BACKUP_ROOT}/${HELPER_RUN_RELATIVE_PATH}"
backup_optional_live_file "${LIVE_SERVE_RC_PATH}" "${BACKUP_ROOT}/${SERVE_RC_RELATIVE_PATH}"
backup_optional_live_file "${LIVE_HELPER_RC_PATH}" "${BACKUP_ROOT}/${HELPER_RC_RELATIVE_PATH}"

stage_repo_artifact "${SERVE_ENV_SOURCE}" "${STAGED_ROOT}/${SERVE_ENV_RELATIVE_PATH}"
stage_repo_artifact "${HELPER_ENV_SOURCE}" "${STAGED_ROOT}/${HELPER_ENV_RELATIVE_PATH}"
stage_repo_artifact "${SERVE_RUN_SOURCE}" "${STAGED_ROOT}/${SERVE_RUN_RELATIVE_PATH}"
stage_repo_artifact "${HELPER_RUN_SOURCE}" "${STAGED_ROOT}/${HELPER_RUN_RELATIVE_PATH}"
stage_repo_artifact "${SERVE_RC_SOURCE}" "${STAGED_ROOT}/${SERVE_RC_RELATIVE_PATH}"
stage_repo_artifact "${HELPER_RC_SOURCE}" "${STAGED_ROOT}/${HELPER_RC_RELATIVE_PATH}"

write_apply_script
write_restore_script
write_session_report

log "prepared service-artifact session in ${SESSION_DIR}"
log "apply script: ${APPLY_SCRIPT_PATH}"
log "restore script: ${RESTORE_SCRIPT_PATH}"

if [ "${MODE}" = "apply" ]; then
  sh "${APPLY_SCRIPT_PATH}"
  log "service-artifact apply completed"
  log "validator report: ${VALIDATOR_REPORT_PATH}"
else
  log "rehearsal mode did not modify live service artifacts"
fi
