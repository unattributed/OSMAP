#!/bin/sh
#
# Prepare a reviewed edge-cutover rehearsal or execute the staged apply path on
# the validated host.
#
# The default mode is non-destructive rehearsal: capture backups of the current
# live files, stage the reviewed repo-owned replacements into a session
# directory, and generate exact apply and restore scripts. An explicit apply
# mode runs the generated apply script after the rehearsal is prepared.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_ROOT="${PROJECT_ROOT}/maint/openbsd/mail.blackbagsecurity.com"
MODE="rehearse"
SESSION_DIR="${OSMAP_EDGE_CUTOVER_SESSION_DIR:-}"

LIVE_NGINX_MAIN_SSL_PATH="${OSMAP_EDGE_CUTOVER_LIVE_NGINX_MAIN_SSL_PATH:-/etc/nginx/sites-enabled/main-ssl.conf}"
LIVE_NGINX_OSMAP_ROOT_TEMPLATE_PATH="${OSMAP_EDGE_CUTOVER_LIVE_NGINX_OSMAP_ROOT_TEMPLATE_PATH:-/etc/nginx/templates/osmap-root.tmpl}"
LIVE_PF_MACROS_PATH="${OSMAP_EDGE_CUTOVER_LIVE_PF_MACROS_PATH:-/etc/pf.anchors/macros.pf}"
LIVE_PF_SELFHOST_PATH="${OSMAP_EDGE_CUTOVER_LIVE_PF_SELFHOST_PATH:-/etc/pf.anchors/selfhost.pf}"
LIVE_PF_CONF_PATH="${OSMAP_EDGE_CUTOVER_LIVE_PF_CONF_PATH:-/etc/pf.conf}"

MAIN_SSL_RELATIVE_PATH="nginx/sites-enabled/main-ssl.conf"
OSMAP_ROOT_RELATIVE_PATH="nginx/templates/osmap-root.tmpl"
PF_MACROS_RELATIVE_PATH="pf.anchors/macros.pf"
PF_SELFHOST_RELATIVE_PATH="pf.anchors/selfhost.pf"

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
usage: $(basename "$0") [--mode rehearse|apply] [--session-dir <path>]

examples:
  ksh ./maint/live/osmap-live-rehearse-edge-cutover.ksh
  ksh ./maint/live/osmap-live-rehearse-edge-cutover.ksh --session-dir "\$HOME/osmap-edge-cutover/20260417-rehearsal"
  ksh ./maint/live/osmap-live-rehearse-edge-cutover.ksh --mode apply --session-dir "\$HOME/osmap-edge-cutover/20260417-cutover"
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
    rehearse|apply)
      ;;
    *)
      log "unsupported mode: ${MODE}"
      exit 1
      ;;
  esac

  if [ -z "${SESSION_DIR}" ]; then
    SESSION_DIR="${HOME}/osmap-edge-cutover/$(date +%Y%m%d-%H%M%S)"
  fi
}

assert_repo_artifact_exists() {
  artifact_path="$1"

  [ -f "${artifact_path}" ] || {
    log "missing reviewed artifact: ${artifact_path}"
    exit 1
  }
}

backup_required_live_file() {
  live_path="$1"
  backup_path="$2"

  doas test -f "${live_path}" || {
    log "missing required live file: ${live_path}"
    exit 1
  }

  mkdir -p "$(dirname "${backup_path}")"
  doas cat "${live_path}" > "${backup_path}"
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

doas install -d $(quote_sh "$(dirname "${LIVE_NGINX_MAIN_SSL_PATH}")") $(quote_sh "$(dirname "${LIVE_NGINX_OSMAP_ROOT_TEMPLATE_PATH}")") $(quote_sh "$(dirname "${LIVE_PF_MACROS_PATH}")")
doas install -m 0644 $(quote_sh "${STAGED_ROOT}/${MAIN_SSL_RELATIVE_PATH}") $(quote_sh "${LIVE_NGINX_MAIN_SSL_PATH}")
doas install -m 0644 $(quote_sh "${STAGED_ROOT}/${OSMAP_ROOT_RELATIVE_PATH}") $(quote_sh "${LIVE_NGINX_OSMAP_ROOT_TEMPLATE_PATH}")
doas install -m 0644 $(quote_sh "${STAGED_ROOT}/${PF_MACROS_RELATIVE_PATH}") $(quote_sh "${LIVE_PF_MACROS_PATH}")
doas install -m 0644 $(quote_sh "${STAGED_ROOT}/${PF_SELFHOST_RELATIVE_PATH}") $(quote_sh "${LIVE_PF_SELFHOST_PATH}")
doas nginx -t
doas pfctl -nf $(quote_sh "${LIVE_PF_CONF_PATH}")
doas rcctl reload nginx
doas pfctl -f $(quote_sh "${LIVE_PF_CONF_PATH}")
EOF

  chmod 0755 "${APPLY_SCRIPT_PATH}"
}

write_restore_script() {
  cat > "${RESTORE_SCRIPT_PATH}" <<EOF
#!/bin/sh
set -eu

doas install -m 0644 $(quote_sh "${BACKUP_ROOT}/${MAIN_SSL_RELATIVE_PATH}") $(quote_sh "${LIVE_NGINX_MAIN_SSL_PATH}")
EOF

  if [ -f "${BACKUP_ROOT}/${OSMAP_ROOT_RELATIVE_PATH}" ]; then
    cat >> "${RESTORE_SCRIPT_PATH}" <<EOF
doas install -m 0644 $(quote_sh "${BACKUP_ROOT}/${OSMAP_ROOT_RELATIVE_PATH}") $(quote_sh "${LIVE_NGINX_OSMAP_ROOT_TEMPLATE_PATH}")
EOF
  else
    cat >> "${RESTORE_SCRIPT_PATH}" <<EOF
doas rm -f $(quote_sh "${LIVE_NGINX_OSMAP_ROOT_TEMPLATE_PATH}")
EOF
  fi

  cat >> "${RESTORE_SCRIPT_PATH}" <<EOF
doas install -m 0644 $(quote_sh "${BACKUP_ROOT}/${PF_MACROS_RELATIVE_PATH}") $(quote_sh "${LIVE_PF_MACROS_PATH}")
doas install -m 0644 $(quote_sh "${BACKUP_ROOT}/${PF_SELFHOST_RELATIVE_PATH}") $(quote_sh "${LIVE_PF_SELFHOST_PATH}")
doas nginx -t
doas pfctl -nf $(quote_sh "${LIVE_PF_CONF_PATH}")
doas rcctl reload nginx
doas pfctl -f $(quote_sh "${LIVE_PF_CONF_PATH}")
EOF

  chmod 0755 "${RESTORE_SCRIPT_PATH}"
}

write_session_report() {
  {
    printf 'osmap_edge_cutover_session_mode=%s\n' "${MODE}"
    printf 'project_root=%s\n' "${PROJECT_ROOT}"
    printf 'artifact_root=%s\n' "${ARTIFACT_ROOT}"
    printf 'session_dir=%s\n' "${SESSION_DIR}"
    printf 'backup_root=%s\n' "${BACKUP_ROOT}"
    printf 'staged_root=%s\n' "${STAGED_ROOT}"
    printf 'scripts_root=%s\n' "${SCRIPTS_ROOT}"
    printf 'apply_script=%s\n' "${APPLY_SCRIPT_PATH}"
    printf 'restore_script=%s\n' "${RESTORE_SCRIPT_PATH}"
    printf 'live_nginx_main_ssl_path=%s\n' "${LIVE_NGINX_MAIN_SSL_PATH}"
    printf 'live_nginx_osmap_root_template_path=%s\n' "${LIVE_NGINX_OSMAP_ROOT_TEMPLATE_PATH}"
    printf 'live_pf_macros_path=%s\n' "${LIVE_PF_MACROS_PATH}"
    printf 'live_pf_selfhost_path=%s\n' "${LIVE_PF_SELFHOST_PATH}"
    printf 'live_pf_conf_path=%s\n' "${LIVE_PF_CONF_PATH}"
  } > "${SESSION_REPORT_PATH}"
}

parse_args "$@"

require_tool cp
require_tool date
require_tool dirname
require_tool doas
require_tool install
require_tool mkdir
require_tool sed

assert_repo_artifact_exists "${ARTIFACT_ROOT}/${MAIN_SSL_RELATIVE_PATH}"
assert_repo_artifact_exists "${ARTIFACT_ROOT}/${OSMAP_ROOT_RELATIVE_PATH}"
assert_repo_artifact_exists "${ARTIFACT_ROOT}/${PF_MACROS_RELATIVE_PATH}"
assert_repo_artifact_exists "${ARTIFACT_ROOT}/${PF_SELFHOST_RELATIVE_PATH}"

BACKUP_ROOT="${SESSION_DIR}/backup"
STAGED_ROOT="${SESSION_DIR}/staged"
SCRIPTS_ROOT="${SESSION_DIR}/scripts"
SESSION_REPORT_PATH="${SESSION_DIR}/edge-cutover-session.txt"
APPLY_SCRIPT_PATH="${SCRIPTS_ROOT}/apply-edge-cutover.sh"
RESTORE_SCRIPT_PATH="${SCRIPTS_ROOT}/restore-edge-cutover.sh"

mkdir -p "${BACKUP_ROOT}" "${STAGED_ROOT}" "${SCRIPTS_ROOT}"

backup_required_live_file "${LIVE_NGINX_MAIN_SSL_PATH}" "${BACKUP_ROOT}/${MAIN_SSL_RELATIVE_PATH}"
backup_optional_live_file "${LIVE_NGINX_OSMAP_ROOT_TEMPLATE_PATH}" "${BACKUP_ROOT}/${OSMAP_ROOT_RELATIVE_PATH}"
backup_required_live_file "${LIVE_PF_MACROS_PATH}" "${BACKUP_ROOT}/${PF_MACROS_RELATIVE_PATH}"
backup_required_live_file "${LIVE_PF_SELFHOST_PATH}" "${BACKUP_ROOT}/${PF_SELFHOST_RELATIVE_PATH}"

stage_repo_artifact "${ARTIFACT_ROOT}/${MAIN_SSL_RELATIVE_PATH}" "${STAGED_ROOT}/${MAIN_SSL_RELATIVE_PATH}"
stage_repo_artifact "${ARTIFACT_ROOT}/${OSMAP_ROOT_RELATIVE_PATH}" "${STAGED_ROOT}/${OSMAP_ROOT_RELATIVE_PATH}"
stage_repo_artifact "${ARTIFACT_ROOT}/${PF_MACROS_RELATIVE_PATH}" "${STAGED_ROOT}/${PF_MACROS_RELATIVE_PATH}"
stage_repo_artifact "${ARTIFACT_ROOT}/${PF_SELFHOST_RELATIVE_PATH}" "${STAGED_ROOT}/${PF_SELFHOST_RELATIVE_PATH}"

write_apply_script
write_restore_script
write_session_report

log "prepared edge cutover session in ${SESSION_DIR}"
log "apply script: ${APPLY_SCRIPT_PATH}"
log "restore script: ${RESTORE_SCRIPT_PATH}"

if [ "${MODE}" = "apply" ]; then
  log "executing reviewed edge cutover apply script"
  sh "${APPLY_SCRIPT_PATH}"
fi
