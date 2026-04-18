#!/bin/sh
#
# Prepare a reviewed service-activation rehearsal or execute the staged apply
# path for mail.blackbagsecurity.com from the standard host checkout.

set -eu

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
MODE="rehearse"
SESSION_DIR="${OSMAP_SERVICE_ACTIVATION_SESSION_DIR:-}"

LIVE_OSMAP_BIN_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_BIN_PATH:-/usr/local/bin/osmap}"
LIVE_GROUP_FILE_PATH="${OSMAP_SERVICE_GROUP_FILE_PATH:-/etc/group}"
SHARED_RUNTIME_GROUP="${OSMAP_SHARED_RUNTIME_GROUP:-osmaprt}"

LIVE_SERVE_ENV_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH:-/etc/osmap/osmap-serve.env}"
LIVE_HELPER_ENV_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH:-/etc/osmap/osmap-mailbox-helper.env}"
LIVE_SERVE_RUN_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH:-/usr/local/libexec/osmap/osmap-serve-run.ksh}"
LIVE_HELPER_RUN_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH:-/usr/local/libexec/osmap/osmap-mailbox-helper-run.ksh}"
LIVE_SERVE_RC_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH:-/etc/rc.d/osmap_serve}"
LIVE_HELPER_RC_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH:-/etc/rc.d/osmap_mailbox_helper}"
LIVE_SERVE_RUNFILE_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUNFILE_PATH:-/var/run/rc.d/osmap_serve}"
LIVE_HELPER_RUNFILE_PATH="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUNFILE_PATH:-/var/run/rc.d/osmap_mailbox_helper}"

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

REPORT_NAME="service-enablement-after-service-activation.txt"

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
    SESSION_DIR="${HOME}/osmap-service-activation/$(date +%Y%m%d-%H%M%S)"
  fi
}

write_apply_script() {
  cat > "${APPLY_SCRIPT_PATH}" <<EOF
#!/bin/sh
set -eu

shared_group=$(quote_sh "${SHARED_RUNTIME_GROUP}")
group_file=$(quote_sh "${LIVE_GROUP_FILE_PATH}")
osmap_bin=$(quote_sh "${LIVE_OSMAP_BIN_PATH}")
serve_env=$(quote_sh "${LIVE_SERVE_ENV_PATH}")
helper_env=$(quote_sh "${LIVE_HELPER_ENV_PATH}")
serve_run=$(quote_sh "${LIVE_SERVE_RUN_PATH}")
helper_run=$(quote_sh "${LIVE_HELPER_RUN_PATH}")
serve_rc=$(quote_sh "${LIVE_SERVE_RC_PATH}")
helper_rc=$(quote_sh "${LIVE_HELPER_RC_PATH}")
serve_runfile=$(quote_sh "${LIVE_SERVE_RUNFILE_PATH}")
helper_runfile=$(quote_sh "${LIVE_HELPER_RUNFILE_PATH}")
helper_socket_path=$(quote_sh "${LIVE_HELPER_RUNTIME_DIR}/mailbox-helper.sock")
serve_state_dir=$(quote_sh "${LIVE_OSMAP_STATE_DIR}")
serve_runtime_dir=$(quote_sh "${LIVE_OSMAP_RUNTIME_DIR}")
serve_session_dir=$(quote_sh "${LIVE_OSMAP_SESSION_DIR}")
serve_settings_dir=$(quote_sh "${LIVE_OSMAP_SETTINGS_DIR}")
serve_audit_dir=$(quote_sh "${LIVE_OSMAP_AUDIT_DIR}")
serve_cache_dir=$(quote_sh "${LIVE_OSMAP_CACHE_DIR}")
serve_totp_parent=$(quote_sh "$(dirname "${LIVE_OSMAP_TOTP_DIR}")")
serve_totp_dir=$(quote_sh "${LIVE_OSMAP_TOTP_DIR}")
helper_state_dir=$(quote_sh "${LIVE_HELPER_STATE_DIR}")
helper_runtime_dir=$(quote_sh "${LIVE_HELPER_RUNTIME_DIR}")
helper_session_dir=$(quote_sh "${LIVE_HELPER_SESSION_DIR}")
helper_settings_dir=$(quote_sh "${LIVE_HELPER_SETTINGS_DIR}")
helper_audit_dir=$(quote_sh "${LIVE_HELPER_AUDIT_DIR}")
helper_cache_dir=$(quote_sh "${LIVE_HELPER_CACHE_DIR}")
helper_totp_parent=$(quote_sh "$(dirname "${LIVE_HELPER_TOTP_DIR}")")
helper_totp_dir=$(quote_sh "${LIVE_HELPER_TOTP_DIR}")
validator_script=$(quote_sh "${SERVICE_VALIDATOR_PATH}")
validator_report=$(quote_sh "${VALIDATOR_REPORT_PATH}")
runtime_failed=0

run_or_note_failure() {
  if ! "\$@"; then
    :
  fi
}

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
doas sh -lc "id -Gn _osmap | tr ' ' '\\n' | grep -Fx \"\${shared_group}\" >/dev/null" || {
  printf '%s\n' "_osmap is not in required shared runtime group: \${shared_group}" >&2
  exit 1
}

for required_path in "\$serve_env" "\$helper_env" "\$serve_run" "\$helper_run" "\$serve_rc" "\$helper_rc"
do
  doas test -e "\$required_path" || {
    printf '%s\n' "missing required reviewed service artifact: \$required_path" >&2
    exit 1
  }
done

doas chgrp _osmap "\$serve_env"
doas chmod 0640 "\$serve_env"
doas chgrp vmail "\$helper_env"
doas chmod 0640 "\$helper_env"
doas install -d -o _osmap -g _osmap -m 0750 "\$serve_state_dir" "\$serve_runtime_dir" "\$serve_session_dir" "\$serve_settings_dir" "\$serve_audit_dir" "\$serve_cache_dir"
doas install -d -o _osmap -g _osmap -m 0700 "\$serve_totp_parent" "\$serve_totp_dir"
doas install -d -o vmail -g "\$shared_group" -m 0710 "\$helper_state_dir"
doas install -d -o vmail -g "\$shared_group" -m 2770 "\$helper_runtime_dir"
doas install -d -o vmail -g vmail -m 0750 "\$helper_session_dir" "\$helper_settings_dir" "\$helper_audit_dir" "\$helper_cache_dir"
doas install -d -o vmail -g vmail -m 0700 "\$helper_totp_parent" "\$helper_totp_dir"
doas pkill -T 0 -xf "/usr/local/bin/osmap serve" >/dev/null 2>&1 || true
doas pkill -T 0 -xf "/usr/local/bin/osmap mailbox-helper" >/dev/null 2>&1 || true
doas rm -f "\$serve_runfile" "\$helper_runfile"
doas rm -f "\$helper_socket_path"

run_or_note_failure doas rcctl configtest osmap_mailbox_helper
run_or_note_failure doas rcctl start osmap_mailbox_helper
run_or_note_failure doas rcctl check osmap_mailbox_helper
run_or_note_failure doas rcctl configtest osmap_serve
run_or_note_failure doas rcctl start osmap_serve
run_or_note_failure doas rcctl check osmap_serve

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
  mailbox_helper_service_not_healthy \
  serve_service_not_healthy \
  missing_helper_socket \
  loopback_http_listener_not_ready
do
  if grep -Fq "\${failed_check}" "\$validator_report"; then
    printf '%s\n' "service validator still reports \${failed_check} after service activation" >&2
    runtime_failed=1
  fi
done

if [ "\$runtime_failed" -ne 0 ]; then
  exit 1
fi
EOF

  chmod 0755 "${APPLY_SCRIPT_PATH}"
}

write_restore_script() {
  cat > "${RESTORE_SCRIPT_PATH}" <<EOF
#!/bin/sh
set -eu

doas rcctl stop osmap_serve >/dev/null 2>&1 || true
doas rcctl stop osmap_mailbox_helper >/dev/null 2>&1 || true
doas pkill -T 0 -xf "/usr/local/bin/osmap serve" >/dev/null 2>&1 || true
doas pkill -T 0 -xf "/usr/local/bin/osmap mailbox-helper" >/dev/null 2>&1 || true
doas rm -f $(quote_sh "${LIVE_SERVE_RUNFILE_PATH}") $(quote_sh "${LIVE_HELPER_RUNFILE_PATH}")
doas rm -f $(quote_sh "${LIVE_HELPER_RUNTIME_DIR}/mailbox-helper.sock")
EOF

  chmod 0755 "${RESTORE_SCRIPT_PATH}"
}

write_session_report() {
  {
    printf 'osmap_service_activation_session_mode=%s\n' "${MODE}"
    printf 'session_dir=%s\n' "${SESSION_DIR}"
    printf 'apply_script=%s\n' "${APPLY_SCRIPT_PATH}"
    printf 'restore_script=%s\n' "${RESTORE_SCRIPT_PATH}"
    printf 'validator_report=%s\n' "${VALIDATOR_REPORT_PATH}"
    printf 'shared_runtime_group=%s\n' "${SHARED_RUNTIME_GROUP}"
    printf 'serve_runfile=%s\n' "${LIVE_SERVE_RUNFILE_PATH}"
    printf 'helper_runfile=%s\n' "${LIVE_HELPER_RUNFILE_PATH}"
    printf 'serve_state_dir=%s\n' "${LIVE_OSMAP_STATE_DIR}"
    printf 'helper_state_dir=%s\n' "${LIVE_HELPER_STATE_DIR}"
  } > "${SESSION_REPORT_PATH}"
}

parse_args "$@"

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

SCRIPTS_ROOT="${SESSION_DIR}/scripts"
REPORTS_ROOT="${SESSION_DIR}/reports"
SESSION_REPORT_PATH="${SESSION_DIR}/service-activation-session.txt"
APPLY_SCRIPT_PATH="${SCRIPTS_ROOT}/apply-service-activation.sh"
RESTORE_SCRIPT_PATH="${SCRIPTS_ROOT}/restore-service-activation.sh"
VALIDATOR_REPORT_PATH="${REPORTS_ROOT}/${REPORT_NAME}"

mkdir -p "${SCRIPTS_ROOT}" "${REPORTS_ROOT}"

write_apply_script
write_restore_script
write_session_report

log "prepared service activation session in ${SESSION_DIR}"
log "apply script: ${APPLY_SCRIPT_PATH}"
log "restore script: ${RESTORE_SCRIPT_PATH}"

if [ "${MODE}" = "apply" ]; then
  if sh "${APPLY_SCRIPT_PATH}"; then
    log "service activation apply completed"
  else
    log "service activation apply failed"
    log "validator report: ${VALIDATOR_REPORT_PATH}"
    exit 1
  fi
else
  log "rehearsal mode did not modify live service state"
fi
