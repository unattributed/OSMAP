#!/bin/sh
#
# Prepare a reviewed OpenBSD service-enablement rehearsal or execute the staged
# apply path for mail.blackbagsecurity.com from the standard host checkout.

set -eu

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
GENERIC_ARTIFACT_ROOT="${PROJECT_ROOT}/maint/openbsd"
HOST_ARTIFACT_ROOT="${PROJECT_ROOT}/maint/openbsd/mail.blackbagsecurity.com"
MODE="rehearse"
SESSION_DIR="${OSMAP_SERVICE_ENABLEMENT_SESSION_DIR:-}"

LIVE_OSMAP_BIN_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_BIN_PATH:-/usr/local/bin/osmap}"
LIVE_GROUP_FILE_PATH="${OSMAP_SERVICE_GROUP_FILE_PATH:-/etc/group}"
SHARED_RUNTIME_GROUP="${OSMAP_SHARED_RUNTIME_GROUP:-osmaprt}"

LIVE_SERVE_ENV_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH:-/etc/osmap/osmap-serve.env}"
LIVE_HELPER_ENV_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH:-/etc/osmap/osmap-mailbox-helper.env}"
LIVE_SERVE_RUN_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH:-/usr/local/libexec/osmap/osmap-serve-run.ksh}"
LIVE_HELPER_RUN_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH:-/usr/local/libexec/osmap/osmap-mailbox-helper-run.ksh}"
LIVE_SERVE_RC_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH:-/etc/rc.d/osmap_serve}"
LIVE_HELPER_RC_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH:-/etc/rc.d/osmap_mailbox_helper}"

LIVE_OSMAP_STATE_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_STATE_DIR:-/var/lib/osmap}"
LIVE_OSMAP_RUNTIME_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_RUNTIME_DIR:-/var/lib/osmap/run}"
LIVE_OSMAP_SESSION_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_SESSION_DIR:-/var/lib/osmap/sessions}"
LIVE_OSMAP_SETTINGS_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_SETTINGS_DIR:-/var/lib/osmap/settings}"
LIVE_OSMAP_AUDIT_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_AUDIT_DIR:-/var/lib/osmap/audit}"
LIVE_OSMAP_CACHE_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_CACHE_DIR:-/var/lib/osmap/cache}"
LIVE_OSMAP_TOTP_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_TOTP_DIR:-/var/lib/osmap/secrets/totp}"

LIVE_HELPER_STATE_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_STATE_DIR:-/var/lib/osmap-helper}"
LIVE_HELPER_RUNTIME_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUNTIME_DIR:-/var/lib/osmap-helper/run}"
LIVE_HELPER_SESSION_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_SESSION_DIR:-/var/lib/osmap-helper/sessions}"
LIVE_HELPER_SETTINGS_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_SETTINGS_DIR:-/var/lib/osmap-helper/settings}"
LIVE_HELPER_AUDIT_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_AUDIT_DIR:-/var/lib/osmap-helper/audit}"
LIVE_HELPER_CACHE_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_CACHE_DIR:-/var/lib/osmap-helper/cache}"
LIVE_HELPER_TOTP_DIR="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_TOTP_DIR:-/var/lib/osmap-helper/secrets/totp}"

SERVE_ENV_RELATIVE_PATH="etc/osmap/osmap-serve.env"
HELPER_ENV_RELATIVE_PATH="etc/osmap/osmap-mailbox-helper.env"
SERVE_RUN_RELATIVE_PATH="usr/local/libexec/osmap/osmap-serve-run.ksh"
HELPER_RUN_RELATIVE_PATH="usr/local/libexec/osmap/osmap-mailbox-helper-run.ksh"
SERVE_RC_RELATIVE_PATH="etc/rc.d/osmap_serve"
HELPER_RC_RELATIVE_PATH="etc/rc.d/osmap_mailbox_helper"

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
    SESSION_DIR="${HOME}/osmap-service-enablement/$(date +%Y%m%d-%H%M%S)"
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

shared_group=$(quote_sh "${SHARED_RUNTIME_GROUP}")
group_file=$(quote_sh "${LIVE_GROUP_FILE_PATH}")
osmap_bin=$(quote_sh "${LIVE_OSMAP_BIN_PATH}")
osmap_env_dir=$(quote_sh "$(dirname "${LIVE_SERVE_ENV_PATH}")")
osmap_libexec_dir=$(quote_sh "$(dirname "${LIVE_SERVE_RUN_PATH}")")
osmap_rc_dir=$(quote_sh "$(dirname "${LIVE_SERVE_RC_PATH}")")
helper_socket_path=$(quote_sh "${LIVE_HELPER_RUNTIME_DIR}/mailbox-helper.sock")
serve_state_dir=$(quote_sh "${LIVE_OSMAP_STATE_DIR}")
serve_runtime_dir=$(quote_sh "${LIVE_OSMAP_RUNTIME_DIR}")
serve_session_dir=$(quote_sh "${LIVE_OSMAP_SESSION_DIR}")
serve_settings_dir=$(quote_sh "${LIVE_OSMAP_SETTINGS_DIR}")
serve_audit_dir=$(quote_sh "${LIVE_OSMAP_AUDIT_DIR}")
serve_cache_dir=$(quote_sh "${LIVE_OSMAP_CACHE_DIR}")
serve_totp_dir=$(quote_sh "${LIVE_OSMAP_TOTP_DIR}")
helper_state_dir=$(quote_sh "${LIVE_HELPER_STATE_DIR}")
helper_runtime_dir=$(quote_sh "${LIVE_HELPER_RUNTIME_DIR}")
helper_session_dir=$(quote_sh "${LIVE_HELPER_SESSION_DIR}")
helper_settings_dir=$(quote_sh "${LIVE_HELPER_SETTINGS_DIR}")
helper_audit_dir=$(quote_sh "${LIVE_HELPER_AUDIT_DIR}")
helper_cache_dir=$(quote_sh "${LIVE_HELPER_CACHE_DIR}")
helper_totp_dir=$(quote_sh "${LIVE_HELPER_TOTP_DIR}")

doas test -x "\$osmap_bin" || {
  printf '%s\n' "missing required OSMAP binary: \$osmap_bin" >&2
  exit 1
}
doas id _osmap >/dev/null 2>&1 || {
  printf '%s\n' 'missing required _osmap user' >&2
  exit 1
}
doas id vmail >/dev/null 2>&1 || {
  printf '%s\n' 'missing required vmail user' >&2
  exit 1
}
doas grep -q "^\${shared_group}:" "\$group_file" || {
  printf '%s\n' "missing required shared runtime group: \${shared_group}" >&2
  exit 1
}
doas id -Gn _osmap | tr ' ' '\\n' | grep -Fx "\${shared_group}" >/dev/null || {
  printf '%s\n' "_osmap is not in required shared runtime group: \${shared_group}" >&2
  exit 1
}

doas install -d "\$osmap_env_dir" "\$osmap_libexec_dir" "\$osmap_rc_dir"
doas install -d -o _osmap -g _osmap -m 0750 "\$serve_state_dir" "\$serve_runtime_dir" "\$serve_session_dir" "\$serve_settings_dir" "\$serve_audit_dir" "\$serve_cache_dir"
doas install -d -o _osmap -g _osmap -m 0700 "\$(dirname "\$serve_totp_dir")" "\$serve_totp_dir"
doas install -d -o vmail -g "\$shared_group" -m 0710 "\$helper_state_dir"
doas install -d -o vmail -g "\$shared_group" -m 2770 "\$helper_runtime_dir"
doas install -d -o vmail -g vmail -m 0750 "\$helper_session_dir" "\$helper_settings_dir" "\$helper_audit_dir" "\$helper_cache_dir"
doas install -d -o vmail -g vmail -m 0700 "\$(dirname "\$helper_totp_dir")" "\$helper_totp_dir"

doas install -m 0640 $(quote_sh "${STAGED_ROOT}/${SERVE_ENV_RELATIVE_PATH}") $(quote_sh "${LIVE_SERVE_ENV_PATH}")
doas install -m 0640 $(quote_sh "${STAGED_ROOT}/${HELPER_ENV_RELATIVE_PATH}") $(quote_sh "${LIVE_HELPER_ENV_PATH}")
doas install -m 0555 $(quote_sh "${STAGED_ROOT}/${SERVE_RUN_RELATIVE_PATH}") $(quote_sh "${LIVE_SERVE_RUN_PATH}")
doas install -m 0555 $(quote_sh "${STAGED_ROOT}/${HELPER_RUN_RELATIVE_PATH}") $(quote_sh "${LIVE_HELPER_RUN_PATH}")
doas install -m 0555 $(quote_sh "${STAGED_ROOT}/${SERVE_RC_RELATIVE_PATH}") $(quote_sh "${LIVE_SERVE_RC_PATH}")
doas install -m 0555 $(quote_sh "${STAGED_ROOT}/${HELPER_RC_RELATIVE_PATH}") $(quote_sh "${LIVE_HELPER_RC_PATH}")

doas rm -f "\$helper_socket_path"
doas rcctl configtest osmap_mailbox_helper
doas rcctl start osmap_mailbox_helper
doas rcctl check osmap_mailbox_helper
doas rcctl configtest osmap_serve
doas rcctl start osmap_serve
doas rcctl check osmap_serve
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

doas rcctl stop osmap_serve >/dev/null 2>&1 || true
doas rcctl stop osmap_mailbox_helper >/dev/null 2>&1 || true
doas rm -f $(quote_sh "${LIVE_HELPER_RUNTIME_DIR}/mailbox-helper.sock")
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
    printf 'osmap_service_enablement_session_mode=%s\n' "${MODE}"
    printf 'session_dir=%s\n' "${SESSION_DIR}"
    printf 'backup_root=%s\n' "${BACKUP_ROOT}"
    printf 'staged_root=%s\n' "${STAGED_ROOT}"
    printf 'apply_script=%s\n' "${APPLY_SCRIPT_PATH}"
    printf 'restore_script=%s\n' "${RESTORE_SCRIPT_PATH}"
    printf 'shared_runtime_group=%s\n' "${SHARED_RUNTIME_GROUP}"
    printf 'group_file=%s\n' "${LIVE_GROUP_FILE_PATH}"
    printf 'live_osmap_bin_path=%s\n' "${LIVE_OSMAP_BIN_PATH}"
  } > "${SESSION_REPORT_PATH}"
}

parse_args "$@"

require_tool cp
require_tool date
require_tool dirname
require_tool doas
require_tool mkdir
require_tool sed

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
SESSION_REPORT_PATH="${SESSION_DIR}/service-enablement-session.txt"
APPLY_SCRIPT_PATH="${SCRIPTS_ROOT}/apply-service-enablement.sh"
RESTORE_SCRIPT_PATH="${SCRIPTS_ROOT}/restore-service-enablement.sh"

mkdir -p "${BACKUP_ROOT}" "${STAGED_ROOT}" "${SCRIPTS_ROOT}"

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

log "prepared service enablement session in ${SESSION_DIR}"
log "apply script: ${APPLY_SCRIPT_PATH}"
log "restore script: ${RESTORE_SCRIPT_PATH}"

if [ "${MODE}" = "apply" ]; then
  sh "${APPLY_SCRIPT_PATH}"
  log "service enablement apply completed"
else
  log "rehearsal mode did not modify live service files"
fi
