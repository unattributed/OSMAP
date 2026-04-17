#!/bin/sh
#
# Prepare a reviewed binary-deployment rehearsal or execute the staged apply
# path for mail.blackbagsecurity.com from the standard host checkout.

set -eu

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
MODE="rehearse"
SESSION_DIR="${OSMAP_BINARY_DEPLOYMENT_SESSION_DIR:-}"
LIVE_OSMAP_BIN_PATH="${OSMAP_BINARY_DEPLOYMENT_LIVE_OSMAP_BIN_PATH:-/usr/local/bin/osmap}"
BUILD_PROFILE="${OSMAP_BINARY_DEPLOYMENT_BUILD_PROFILE:-debug}"
REPORT_NAME="service-enablement-after-binary-install.txt"

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

  case "${BUILD_PROFILE}" in
    debug|release) ;;
    *)
      log "unsupported build profile: ${BUILD_PROFILE}"
      exit 1
      ;;
  esac

  if [ -z "${SESSION_DIR}" ]; then
    SESSION_DIR="${HOME}/osmap-binary-deployment/$(date +%Y%m%d-%H%M%S)"
  fi
}

backup_optional_live_file() {
  live_path="$1"
  backup_path="$2"

  if doas test -f "${live_path}"; then
    mkdir -p "$(dirname "${backup_path}")"
    doas cat "${live_path}" > "${backup_path}"
  fi
}

build_staged_binary() {
  mkdir -p "${BUILD_TMPDIR}" "${BUILD_CARGO_HOME}" "${BUILD_TARGET_DIR}"

  build_args="build --quiet"
  build_subdir="debug"
  if [ "${BUILD_PROFILE}" = "release" ]; then
    build_args="${build_args} --release"
    build_subdir="release"
  fi

  env \
    TMPDIR="${BUILD_TMPDIR}" \
    CARGO_HOME="${BUILD_CARGO_HOME}" \
    CARGO_TARGET_DIR="${BUILD_TARGET_DIR}" \
    cargo ${build_args}

  BUILT_BINARY_PATH="${BUILD_TARGET_DIR}/${build_subdir}/osmap"
  [ -x "${BUILT_BINARY_PATH}" ] || {
    log "built binary is not executable: ${BUILT_BINARY_PATH}"
    exit 1
  }

  mkdir -p "$(dirname "${STAGED_BINARY_PATH}")"
  cp "${BUILT_BINARY_PATH}" "${STAGED_BINARY_PATH}"
  chmod 0755 "${STAGED_BINARY_PATH}"
}

write_apply_script() {
  cat > "${APPLY_SCRIPT_PATH}" <<EOF
#!/bin/sh
set -eu

staged_binary=$(quote_sh "${STAGED_BINARY_PATH}")
live_binary=$(quote_sh "${LIVE_OSMAP_BIN_PATH}")
validator_script=$(quote_sh "${SERVICE_VALIDATOR_PATH}")
validator_report=$(quote_sh "${VALIDATOR_REPORT_PATH}")

[ -x "\$staged_binary" ] || {
  printf '%s\n' "staged OSMAP binary is not executable: \$staged_binary" >&2
  exit 1
}

doas install -d $(quote_sh "$(dirname "${LIVE_OSMAP_BIN_PATH}")")
doas install -m 0755 "\$staged_binary" "\$live_binary"
doas test -x "\$live_binary" || {
  printf '%s\n' "installed OSMAP binary is not executable: \$live_binary" >&2
  exit 1
}

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

grep -Fqx 'service_binary_state=installed' "\$validator_report" || {
  printf '%s\n' 'service validator did not confirm installed binary state' >&2
  exit 1
}

if grep -Fq 'missing_osmap_binary' "\$validator_report"; then
  printf '%s\n' 'service validator still reports missing_osmap_binary after binary install' >&2
  exit 1
fi
EOF

  chmod 0755 "${APPLY_SCRIPT_PATH}"
}

write_restore_script() {
  if [ -f "${BACKUP_BINARY_PATH}" ]; then
    restore_body="doas install -m 0755 $(quote_sh "${BACKUP_BINARY_PATH}") $(quote_sh "${LIVE_OSMAP_BIN_PATH}")"
  else
    restore_body="doas rm -f $(quote_sh "${LIVE_OSMAP_BIN_PATH}")"
  fi

  cat > "${RESTORE_SCRIPT_PATH}" <<EOF
#!/bin/sh
set -eu

${restore_body}
EOF

  chmod 0755 "${RESTORE_SCRIPT_PATH}"
}

write_session_report() {
  {
    printf 'osmap_binary_deployment_session_mode=%s\n' "${MODE}"
    printf 'session_dir=%s\n' "${SESSION_DIR}"
    printf 'project_root=%s\n' "${PROJECT_ROOT}"
    printf 'assessed_snapshot=%s\n' "${ASSESSED_SNAPSHOT}"
    printf 'build_profile=%s\n' "${BUILD_PROFILE}"
    printf 'built_binary_path=%s\n' "${BUILT_BINARY_PATH}"
    printf 'staged_binary_path=%s\n' "${STAGED_BINARY_PATH}"
    printf 'live_osmap_bin_path=%s\n' "${LIVE_OSMAP_BIN_PATH}"
    printf 'apply_script=%s\n' "${APPLY_SCRIPT_PATH}"
    printf 'restore_script=%s\n' "${RESTORE_SCRIPT_PATH}"
    printf 'validator_report=%s\n' "${VALIDATOR_REPORT_PATH}"
  } > "${SESSION_REPORT_PATH}"
}

parse_args "$@"

require_tool cargo
require_tool cp
require_tool date
require_tool dirname
require_tool doas
require_tool git
require_tool grep
require_tool install
require_tool ksh
require_tool mkdir
require_tool sed

SERVICE_VALIDATOR_PATH="${PROJECT_ROOT}/maint/live/osmap-live-validate-service-enablement.ksh"
[ -f "${SERVICE_VALIDATOR_PATH}" ] || {
  log "missing service validator: ${SERVICE_VALIDATOR_PATH}"
  exit 1
}

ASSESSED_SNAPSHOT="$(git -C "${PROJECT_ROOT}" rev-parse --short HEAD)"
BACKUP_ROOT="${SESSION_DIR}/backup"
STAGED_ROOT="${SESSION_DIR}/staged"
SCRIPTS_ROOT="${SESSION_DIR}/scripts"
REPORTS_ROOT="${SESSION_DIR}/reports"
BUILD_ROOT="${SESSION_DIR}/build"
SESSION_REPORT_PATH="${SESSION_DIR}/binary-deployment-session.txt"
APPLY_SCRIPT_PATH="${SCRIPTS_ROOT}/apply-binary-deployment.sh"
RESTORE_SCRIPT_PATH="${SCRIPTS_ROOT}/restore-binary-deployment.sh"
VALIDATOR_REPORT_PATH="${REPORTS_ROOT}/${REPORT_NAME}"
BACKUP_BINARY_PATH="${BACKUP_ROOT}/usr/local/bin/osmap"
STAGED_BINARY_PATH="${STAGED_ROOT}/usr/local/bin/osmap"
BUILD_TMPDIR="${BUILD_ROOT}/tmp"
BUILD_CARGO_HOME="${BUILD_ROOT}/cargo-home"
BUILD_TARGET_DIR="${BUILD_ROOT}/cargo-target"

mkdir -p "${BACKUP_ROOT}" "${STAGED_ROOT}" "${SCRIPTS_ROOT}" "${REPORTS_ROOT}" "${BUILD_ROOT}"

backup_optional_live_file "${LIVE_OSMAP_BIN_PATH}" "${BACKUP_BINARY_PATH}"
build_staged_binary
write_apply_script
write_restore_script
write_session_report

log "prepared binary deployment session in ${SESSION_DIR}"
log "apply script: ${APPLY_SCRIPT_PATH}"
log "restore script: ${RESTORE_SCRIPT_PATH}"

if [ "${MODE}" = "apply" ]; then
  sh "${APPLY_SCRIPT_PATH}"
  log "binary deployment apply completed"
  log "validator report: ${VALIDATOR_REPORT_PATH}"
else
  log "rehearsal mode did not modify the live binary"
fi
