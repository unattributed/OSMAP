#!/bin/sh
#
# Assess the current internet-exposure posture of the validated OSMAP host.
#
# This wrapper does not claim that the host is approved for direct public
# browser exposure automatically. It collects the current repo snapshot,
# listener shape, PF selfhost anchor posture, and canonical nginx HTTPS route
# ownership into one repo-owned report so the current exposure gate can be
# reviewed consistently on the real host.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEFAULT_REPORT_PATH="${PROJECT_ROOT}/maint/live/osmap-live-assess-internet-exposure-report.txt"
REPORT_PATH="${OSMAP_INTERNET_EXPOSURE_REPORT_PATH:-}"
NGINX_MAIN_SSL_PATH="${OSMAP_EXPOSURE_NGINX_MAIN_SSL_PATH:-/etc/nginx/sites-enabled/main-ssl.conf}"
NGINX_MAIN_HTTP_PATH="${OSMAP_EXPOSURE_NGINX_MAIN_HTTP_PATH:-/etc/nginx/sites-enabled/main.conf}"
NGINX_SSL_TEMPLATE_PATH="${OSMAP_EXPOSURE_NGINX_SSL_TEMPLATE_PATH:-/etc/nginx/templates/ssl.tmpl}"
NGINX_CONTROL_PLANE_ALLOW_PATH="${OSMAP_EXPOSURE_NGINX_CONTROL_PLANE_ALLOW_PATH:-/etc/nginx/control-plane.allow}"
PF_SELFHOST_ANCHOR="${OSMAP_EXPOSURE_PF_SELFHOST_ANCHOR:-selfhost}"

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
  ksh ./maint/live/osmap-live-assess-internet-exposure.ksh
  ksh ./maint/live/osmap-live-assess-internet-exposure.ksh --report "\$HOME/osmap-internet-exposure-report.txt"
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
    /LISTEN/ &&
    ($4 ~ /\.22$/ || $4 ~ /\.25$/ || $4 ~ /\.80$/ || $4 ~ /\.443$/ ||
     $4 ~ /\.465$/ || $4 ~ /\.587$/ || $4 ~ /\.993$/ || $4 ~ /\.4190$/) {
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

extract_allow_entries() {
  printf '%s\n' "$1" | awk '
    $1 == "allow" {
      entry = $2
      sub(/;$/, "", entry)
      print entry
    }
  ' | paste -sd ',' -
}

append_reason() {
  reason="$1"
  if [ -z "${BLOCKING_REASONS}" ]; then
    BLOCKING_REASONS="${reason}"
  else
    BLOCKING_REASONS="${BLOCKING_REASONS}
${reason}"
  fi
}

write_report() {
  {
    printf 'osmap_internet_exposure_result=%s\n' "${ASSESSMENT_RESULT}"
    printf 'project_root=%s\n' "${PROJECT_ROOT}"
    printf 'assessed_host=%s\n' "${ASSESSED_HOST}"
    printf 'assessed_snapshot=%s\n' "${ASSESSED_SNAPSHOT}"
    printf 'https_listener_bindings=%s\n' "${HTTPS_BINDINGS:-none}"
    printf 'http_listener_bindings=%s\n' "${HTTP_BINDINGS:-none}"
    printf 'imap_tls_listener_bindings=%s\n' "${IMAPS_BINDINGS:-none}"
    printf 'submission_tls_listener_bindings=%s\n' "${SUBMISSION_TLS_BINDINGS:-none}"
    printf 'submission_listener_bindings=%s\n' "${SUBMISSION_BINDINGS:-none}"
    printf 'control_plane_allow_entries=%s\n' "${CONTROL_PLANE_ALLOW_ENTRIES:-none}"
    printf 'canonical_https_includes=%s\n' "${MAIN_SSL_INCLUDE_TARGETS:-none}"
    printf 'blocking_reasons=\n'
    if [ -n "${BLOCKING_REASONS}" ]; then
      printf '%s\n' "${BLOCKING_REASONS}"
    fi
    printf 'listener_lines=\n'
    printf '%s\n' "${LISTENER_LINES}"
    printf 'pf_selfhost_rules=\n'
    printf '%s\n' "${PF_SELFHOST_RULES}"
    printf 'nginx_main_http=\n'
    printf '%s\n' "${MAIN_HTTP_CONTENT}"
    printf 'nginx_main_ssl=\n'
    printf '%s\n' "${MAIN_SSL_CONTENT}"
    printf 'nginx_ssl_template=\n'
    printf '%s\n' "${SSL_TEMPLATE_CONTENT}"
    printf 'nginx_control_plane_allow=\n'
    printf '%s\n' "${CONTROL_PLANE_ALLOW_CONTENT}"
  } > "${REPORT_PATH}"
}

parse_args "$@"

require_tool doas
require_tool git
require_tool hostname
require_tool netstat
require_tool pfctl
require_tool awk
require_tool sed
require_tool sort
require_tool paste

ASSESSED_HOST="$(hostname)"
ASSESSED_SNAPSHOT="$(git -C "${PROJECT_ROOT}" rev-parse --short HEAD)"
LISTENER_LINES="$(capture_listener_lines)"
PF_SELFHOST_RULES="$(capture_pf_anchor_rules)"
MAIN_HTTP_CONTENT="$(capture_file_excerpt "${NGINX_MAIN_HTTP_PATH}")"
MAIN_SSL_CONTENT="$(capture_file_excerpt "${NGINX_MAIN_SSL_PATH}")"
SSL_TEMPLATE_CONTENT="$(capture_file_excerpt "${NGINX_SSL_TEMPLATE_PATH}")"
CONTROL_PLANE_ALLOW_CONTENT="$(capture_file_excerpt "${NGINX_CONTROL_PLANE_ALLOW_PATH}")"
HTTPS_BINDINGS="$(listener_bindings_for_port 443)"
HTTP_BINDINGS="$(listener_bindings_for_port 80)"
IMAPS_BINDINGS="$(listener_bindings_for_port 993)"
SUBMISSION_TLS_BINDINGS="$(listener_bindings_for_port 465)"
SUBMISSION_BINDINGS="$(listener_bindings_for_port 587)"
MAIN_SSL_INCLUDE_TARGETS="$(extract_include_targets "${MAIN_SSL_CONTENT}" | paste -sd ',' -)"
CONTROL_PLANE_ALLOW_ENTRIES="$(extract_allow_entries "${CONTROL_PLANE_ALLOW_CONTENT}")"
BLOCKING_REASONS=""
ASSESSMENT_RESULT="not_approved_for_direct_public_browser_exposure"

if printf '%s\n' "${MAIN_SSL_CONTENT}" | grep -Fq '/etc/nginx/templates/roundcube.tmpl'; then
  append_reason "canonical_https_vhost_still_includes_roundcube_template"
fi

if [ "${HTTPS_BINDINGS:-}" = "127.0.0.1.443,10.44.0.1.443" ] || [ "${HTTPS_BINDINGS:-}" = "10.44.0.1.443,127.0.0.1.443" ]; then
  append_reason "https_listeners_are_limited_to_loopback_and_wireguard_addresses"
fi

if [ "${CONTROL_PLANE_ALLOW_ENTRIES:-}" = "10.44.0.0/24,127.0.0.1" ] || [ "${CONTROL_PLANE_ALLOW_ENTRIES:-}" = "127.0.0.1,10.44.0.0/24" ]; then
  append_reason "nginx_control_plane_allowlist_is_limited_to_wireguard_and_loopback"
fi

if printf '%s\n' "${PF_SELFHOST_RULES}" | grep -Fq 'block drop in log quick on egress inet proto tcp from any to (egress) port = 443'; then
  append_reason "pf_selfhost_anchor_blocks_public_ingress_to_tcp_443"
fi

write_report
log "wrote internet exposure report to ${REPORT_PATH}"
log "internet exposure result: ${ASSESSMENT_RESULT}"
