#!/bin/sh
#
# Validate whether the current HTTPS certificate supports OCSP stapling and,
# when it does, whether the live nginx endpoint is serving a stapled response.

set -eu

REPORT_PATH="${OSMAP_NGINX_OCSP_REPORT_PATH:-}"
CERT_PATH="${OSMAP_NGINX_OCSP_CERT_PATH:-/etc/ssl/mail.blackbagsecurity.com.fullchain.pem}"
CONNECT_HOST="${OSMAP_NGINX_OCSP_CONNECT_HOST:-mail.blackbagsecurity.com}"
CONNECT_PORT="${OSMAP_NGINX_OCSP_CONNECT_PORT:-443}"
SERVER_NAME="${OSMAP_NGINX_OCSP_SERVER_NAME:-mail.blackbagsecurity.com}"
OPENSSL_BIN="${OSMAP_NGINX_OCSP_OPENSSL_BIN:-openssl}"
DOAS_BIN="${OSMAP_NGINX_OCSP_DOAS_BIN:-doas}"
TMPDIR_BASE="${TMPDIR:-/tmp}"
TMPDIR_PATH="$(mktemp -d "${TMPDIR_BASE%/}/osmap-nginx-ocsp.XXXXXX")"
SCLIENT_OUTPUT_PATH="${TMPDIR_PATH}/s_client.txt"

cleanup() {
	rm -rf "${TMPDIR_PATH}"
}
trap cleanup EXIT INT TERM

log() {
	printf '%s\n' "$*"
}

usage() {
	cat <<EOF
usage: $(basename "$0") [--report <path>]
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
		REPORT_PATH="${PWD}/nginx-ocsp-stapling-report.txt"
	fi
}

run_privileged() {
	if [ -n "${DOAS_BIN}" ] && command -v "${DOAS_BIN}" >/dev/null 2>&1; then
		"${DOAS_BIN}" "$@"
	else
		"$@"
	fi
}

write_report() {
	result=$1
	reason=$2
	ocsp_url=$3
	stapling_line=$4

	mkdir -p "$(dirname "${REPORT_PATH}")"
	{
		printf 'nginx_ocsp_stapling_result=%s\n' "${result}"
		printf 'cert_path=%s\n' "${CERT_PATH}"
		printf 'connect_host=%s\n' "${CONNECT_HOST}"
		printf 'connect_port=%s\n' "${CONNECT_PORT}"
		printf 'server_name=%s\n' "${SERVER_NAME}"
		printf 'ocsp_responder_url=%s\n' "${ocsp_url}"
		printf 'failure_reason=%s\n' "${reason}"
		printf 's_client_status_line=%s\n' "${stapling_line}"
	} > "${REPORT_PATH}"
}

parse_args "$@"

command -v "${OPENSSL_BIN}" >/dev/null 2>&1 || {
	log "missing required tool: ${OPENSSL_BIN}"
	exit 1
}

run_privileged test -r "${CERT_PATH}" || {
	log "certificate is not readable: ${CERT_PATH}"
	exit 1
}

ocsp_url="$(run_privileged "${OPENSSL_BIN}" x509 -in "${CERT_PATH}" -ocsp_uri -noout | tr -d '\r' | sed '/^[[:space:]]*$/d' | head -n 1)"

if [ -z "${ocsp_url}" ]; then
	write_report \
		"unsupported_by_certificate" \
		"leaf_certificate_has_no_ocsp_responder_url" \
		"" \
		"no_ocsp_status_check_attempted"
	log "wrote nginx OCSP stapling report to ${REPORT_PATH}"
	log "nginx OCSP stapling result: unsupported_by_certificate"
	exit 1
fi

printf '' | "${OPENSSL_BIN}" s_client \
	-connect "${CONNECT_HOST}:${CONNECT_PORT}" \
	-servername "${SERVER_NAME}" \
	-status > "${SCLIENT_OUTPUT_PATH}" 2>/dev/null

status_line="$(awk '/OCSP response:/ { print; exit }' "${SCLIENT_OUTPUT_PATH}" | tr -d '\r')"

if grep -Fq 'OCSP response: no response sent' "${SCLIENT_OUTPUT_PATH}"; then
	write_report \
		"failed" \
		"nginx_did_not_staple_an_ocsp_response" \
		"${ocsp_url}" \
		"${status_line:-OCSP response: no response sent}"
	log "wrote nginx OCSP stapling report to ${REPORT_PATH}"
	log "nginx OCSP stapling result: failed"
	exit 1
fi

if ! grep -Fq 'OCSP Response Status: successful' "${SCLIENT_OUTPUT_PATH}"; then
	write_report \
		"failed" \
		"openssl_s_client_did_not_report_a_successful_ocsp_response" \
		"${ocsp_url}" \
		"${status_line:-missing}"
	log "wrote nginx OCSP stapling report to ${REPORT_PATH}"
	log "nginx OCSP stapling result: failed"
	exit 1
fi

write_report \
	"passed" \
	"" \
	"${ocsp_url}" \
	"${status_line:-present}"
log "wrote nginx OCSP stapling report to ${REPORT_PATH}"
log "nginx OCSP stapling result: passed"
