#!/bin/sh
#
# Validate that the validated mail host has applied the repo-owned OSMAP edge
# cutover described in docs/EDGE_CUTOVER_PLAN.md.
#
# This wrapper verifies the canonical nginx include change, the expected OSMAP
# root template shape, the intended HTTPS listener bindings, and the PF rule
# change that permits public HTTPS without widening OSMAP authority.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEFAULT_REPORT_PATH="${PROJECT_ROOT}/maint/live/osmap-live-validate-edge-cutover-report.txt"
REPORT_PATH="${OSMAP_EDGE_CUTOVER_REPORT_PATH:-}"
NGINX_MAIN_SSL_PATH="${OSMAP_EDGE_CUTOVER_NGINX_MAIN_SSL_PATH:-/etc/nginx/sites-enabled/main-ssl.conf}"
NGINX_OSMAP_ROOT_TEMPLATE_PATH="${OSMAP_EDGE_CUTOVER_NGINX_OSMAP_ROOT_TEMPLATE_PATH:-/etc/nginx/templates/osmap-root.tmpl}"
PF_MACROS_PATH="${OSMAP_EDGE_CUTOVER_PF_MACROS_PATH:-/etc/pf.anchors/macros.pf}"
PF_SELFHOST_FILE_PATH="${OSMAP_EDGE_CUTOVER_PF_SELFHOST_FILE_PATH:-/etc/pf.anchors/selfhost.pf}"
PF_SELFHOST_ANCHOR="${OSMAP_EDGE_CUTOVER_PF_SELFHOST_ANCHOR:-selfhost}"
EXPECTED_HTTPS_BINDINGS="${OSMAP_EDGE_CUTOVER_EXPECTED_HTTPS_BINDINGS:-10.44.0.1.443,127.0.0.1.443,192.168.1.44.443}"
FAILED_CHECKS=""

log() {
  printf '%s\n' "$*"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing required tool: $1"
    exit 1
  }
}

usage() {
  cat <<EOF
usage: $(basename "$0") [--report <path>]

examples:
  ksh ./maint/live/osmap-live-validate-edge-cutover.ksh
  ksh ./maint/live/osmap-live-validate-edge-cutover.ksh --report "\$HOME/osmap-edge-cutover-report.txt"
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h)
        usage
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
      *)
        log "unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done

  if [ -z "${REPORT_PATH}" ]; then
    REPORT_PATH="${DEFAULT_REPORT_PATH}"
  fi
}

read_privileged_file() {
  doas cat "$1"
}

capture_file_excerpt() {
  file_path="$1"
  if doas test -f "${file_path}"; then
    read_privileged_file "${file_path}"
  else
    printf 'missing:%s\n' "${file_path}"
  fi
}

capture_pf_anchor_rules() {
  doas pfctl -a "${PF_SELFHOST_ANCHOR}" -sr 2>/dev/null || true
}

capture_listener_lines() {
  netstat -na -f inet 2>/dev/null | awk '
    /LISTEN/ && ($4 ~ /\.443$/ || $4 ~ /\.8080$/) {
      print $0
    }
  '
}

listener_bindings_for_port() {
  port="$1"
  printf '%s\n' "${LISTENER_LINES}" | awk -v port="${port}" '
    $4 ~ ("\\." port "$") { print $4 }
  ' | sort -u | paste -sd ',' -
}

extract_include_targets() {
  printf '%s\n' "$1" | awk '
    $1 == "include" {
      path = $2
      sub(/;$/, "", path)
      print path
    }
  '
}

append_failed_check() {
  failed_check="$1"
  if [ -z "${FAILED_CHECKS}" ]; then
    FAILED_CHECKS="${failed_check}"
  else
    FAILED_CHECKS="${FAILED_CHECKS}
${failed_check}"
  fi
}

write_report() {
  {
    printf 'osmap_edge_cutover_result=%s\n' "${VALIDATION_RESULT}"
    printf 'project_root=%s\n' "${PROJECT_ROOT}"
    printf 'assessed_host=%s\n' "${ASSESSED_HOST}"
    printf 'assessed_snapshot=%s\n' "${ASSESSED_SNAPSHOT}"
    printf 'expected_https_listener_bindings=%s\n' "${EXPECTED_HTTPS_BINDINGS}"
    printf 'https_listener_bindings=%s\n' "${HTTPS_BINDINGS:-none}"
    printf 'osmap_listener_bindings=%s\n' "${OSMAP_BINDINGS:-none}"
    printf 'canonical_https_includes=%s\n' "${MAIN_SSL_INCLUDE_TARGETS:-none}"
    printf 'failed_checks=\n'
    if [ -n "${FAILED_CHECKS}" ]; then
      printf '%s\n' "${FAILED_CHECKS}"
    fi
    printf 'listener_lines=\n'
    printf '%s\n' "${LISTENER_LINES}"
    printf 'nginx_main_ssl=\n'
    printf '%s\n' "${MAIN_SSL_CONTENT}"
    printf 'nginx_osmap_root_template=\n'
    printf '%s\n' "${OSMAP_ROOT_TEMPLATE_CONTENT}"
    printf 'pf_macros=\n'
    printf '%s\n' "${PF_MACROS_CONTENT}"
    printf 'pf_selfhost_config=\n'
    printf '%s\n' "${PF_SELFHOST_FILE_CONTENT}"
    printf 'pf_selfhost_runtime_rules=\n'
    printf '%s\n' "${PF_SELFHOST_RUNTIME_RULES}"
  } > "${REPORT_PATH}"
}

parse_args "$@"

require_tool doas
require_tool git
require_tool hostname
require_tool netstat
require_tool pfctl
require_tool awk
require_tool grep
require_tool sort
require_tool paste

ASSESSED_HOST="$(hostname)"
ASSESSED_SNAPSHOT="$(git -C "${PROJECT_ROOT}" rev-parse --short HEAD)"
LISTENER_LINES="$(capture_listener_lines)"
MAIN_SSL_CONTENT="$(capture_file_excerpt "${NGINX_MAIN_SSL_PATH}")"
OSMAP_ROOT_TEMPLATE_CONTENT="$(capture_file_excerpt "${NGINX_OSMAP_ROOT_TEMPLATE_PATH}")"
PF_MACROS_CONTENT="$(capture_file_excerpt "${PF_MACROS_PATH}")"
PF_SELFHOST_FILE_CONTENT="$(capture_file_excerpt "${PF_SELFHOST_FILE_PATH}")"
PF_SELFHOST_RUNTIME_RULES="$(capture_pf_anchor_rules)"
HTTPS_BINDINGS="$(listener_bindings_for_port 443)"
OSMAP_BINDINGS="$(listener_bindings_for_port 8080)"
MAIN_SSL_INCLUDE_TARGETS="$(extract_include_targets "${MAIN_SSL_CONTENT}" | paste -sd ',' -)"
VALIDATION_RESULT="passed"

if ! printf '%s\n' "${MAIN_SSL_CONTENT}" | grep -Fq 'include /etc/nginx/templates/osmap-root.tmpl;'; then
  append_failed_check "canonical_https_vhost_missing_osmap_root_template_include"
fi

if printf '%s\n' "${MAIN_SSL_CONTENT}" | grep -Fq 'include /etc/nginx/templates/roundcube.tmpl;'; then
  append_failed_check "canonical_https_vhost_still_includes_roundcube_template"
fi

if ! printf '%s\n' "${OSMAP_ROOT_TEMPLATE_CONTENT}" | grep -Fq 'location = /mail { return 301 /; }'; then
  append_failed_check "osmap_root_template_missing_mail_redirect"
fi

if ! printf '%s\n' "${OSMAP_ROOT_TEMPLATE_CONTENT}" | grep -Fq 'location = /webmail { return 301 /; }'; then
  append_failed_check "osmap_root_template_missing_webmail_redirect"
fi

if ! printf '%s\n' "${OSMAP_ROOT_TEMPLATE_CONTENT}" | grep -Fq 'location / {'; then
  append_failed_check "osmap_root_template_missing_root_location"
fi

if ! printf '%s\n' "${OSMAP_ROOT_TEMPLATE_CONTENT}" | grep -Fq 'limit_except GET POST { deny all; }'; then
  append_failed_check "osmap_root_template_missing_method_restriction"
fi

if ! printf '%s\n' "${OSMAP_ROOT_TEMPLATE_CONTENT}" | grep -Fq 'proxy_pass http://127.0.0.1:8080;'; then
  append_failed_check "osmap_root_template_missing_loopback_proxy_pass"
fi

if ! printf '%s\n' "${OSMAP_ROOT_TEMPLATE_CONTENT}" | grep -Fq 'proxy_set_header Host $host;'; then
  append_failed_check "osmap_root_template_missing_host_forwarding"
fi

if ! printf '%s\n' "${OSMAP_ROOT_TEMPLATE_CONTENT}" | grep -Fq 'proxy_set_header X-Real-IP $remote_addr;'; then
  append_failed_check "osmap_root_template_missing_real_ip_forwarding"
fi

if ! printf '%s\n' "${OSMAP_ROOT_TEMPLATE_CONTENT}" | grep -Fq 'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'; then
  append_failed_check "osmap_root_template_missing_forwarded_for_header"
fi

if ! printf '%s\n' "${OSMAP_ROOT_TEMPLATE_CONTENT}" | grep -Fq 'proxy_set_header X-Forwarded-Proto https;'; then
  append_failed_check "osmap_root_template_missing_forwarded_proto_header"
fi

if ! printf '%s\n' "${OSMAP_ROOT_TEMPLATE_CONTENT}" | grep -Fq 'proxy_buffering off;'; then
  append_failed_check "osmap_root_template_missing_proxy_buffering_policy"
fi

if printf '%s\n' "${OSMAP_ROOT_TEMPLATE_CONTENT}" | grep -Fq 'control-plane-allow.tmpl'; then
  append_failed_check "osmap_root_template_unexpectedly_uses_control_plane_allowlist"
fi

if [ "${HTTPS_BINDINGS:-}" != "${EXPECTED_HTTPS_BINDINGS}" ]; then
  append_failed_check "https_listener_bindings_do_not_match_edge_cutover_plan"
fi

if printf '%s\n' "${PF_MACROS_CONTENT}" | awk '/wan_blocked_tcp_svcs/ { print; exit }' | grep -Eq '(^|[^0-9])443([^0-9]|$)'; then
  append_failed_check "pf_macros_still_block_wan_tcp_443"
fi

if ! printf '%s\n' "${PF_SELFHOST_FILE_CONTENT}" | grep -Fq 'port = 443'; then
  append_failed_check "pf_selfhost_config_missing_public_https_rule"
fi

if ! printf '%s\n' "${PF_SELFHOST_RUNTIME_RULES}" | grep -Fq 'pass in quick on egress inet proto tcp from any to (egress) port = 443'; then
  append_failed_check "pf_selfhost_runtime_missing_public_https_rule"
fi

if printf '%s\n' "${PF_SELFHOST_RUNTIME_RULES}" | grep -Fq 'block drop in log quick on egress inet proto tcp from any to (egress) port = 443'; then
  append_failed_check "pf_selfhost_runtime_still_blocks_public_https"
fi

if [ -n "${FAILED_CHECKS}" ]; then
  VALIDATION_RESULT="failed"
fi

write_report
log "wrote edge cutover report to ${REPORT_PATH}"
log "edge cutover validation result: ${VALIDATION_RESULT}"

if [ "${VALIDATION_RESULT}" != "passed" ]; then
  exit 1
fi
