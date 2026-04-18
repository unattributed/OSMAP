#!/bin/sh
#
# Validate that low-level HTTP telemetry uses the same effective client IP as
# request-scoped route events when a loopback proxy supplies X-Real-IP.

set -eu

REPORT_PATH="${OSMAP_EFFECTIVE_CLIENT_IP_REPORT_PATH:-}"
LOGIN_URL="${OSMAP_EFFECTIVE_CLIENT_IP_LOGIN_URL:-http://127.0.0.1:8080/login}"
SERVE_LOG_PATH="${OSMAP_EFFECTIVE_CLIENT_IP_SERVE_LOG_PATH:-/var/lib/osmap/audit/serve.log}"
EXPECTED_REMOTE_ADDR="${OSMAP_EFFECTIVE_CLIENT_IP_EXPECTED_REMOTE_ADDR:-198.51.100.24}"
USER_AGENT="${OSMAP_EFFECTIVE_CLIENT_IP_USER_AGENT:-OSMAP-Effective-Client-IP-Probe/20260418}"
CURL_BIN="${OSMAP_EFFECTIVE_CLIENT_IP_CURL_BIN:-curl}"
DOAS_BIN="${OSMAP_EFFECTIVE_CLIENT_IP_DOAS_BIN:-doas}"
TMPDIR_BASE="${TMPDIR:-/tmp}"
TMPDIR_PATH="$(mktemp -d "${TMPDIR_BASE%/}/osmap-effective-client-ip.XXXXXX")"
BODY_PATH="${TMPDIR_PATH}/body.txt"
EXCERPT_PATH="${TMPDIR_PATH}/excerpt.txt"

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
		REPORT_PATH="${PWD}/effective-client-ip-telemetry-report.txt"
	fi
}

run_privileged_sh() {
	command="$1"

	if [ -n "${DOAS_BIN}" ] && command -v "${DOAS_BIN}" >/dev/null 2>&1; then
		"${DOAS_BIN}" sh -c "${command}"
	else
		sh -c "${command}"
	fi
}

quote_sh() {
	printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

parse_args "$@"

command -v "${CURL_BIN}" >/dev/null 2>&1 || {
	log "missing required tool: ${CURL_BIN}"
	exit 1
}

if ! run_privileged_sh "test -f $(quote_sh "${SERVE_LOG_PATH}")"; then
	log "serve log file does not exist: ${SERVE_LOG_PATH}"
	exit 1
fi

before_lines="$(run_privileged_sh "wc -l < $(quote_sh "${SERVE_LOG_PATH}")" | tr -d '[:space:]')"

http_code="$("${CURL_BIN}" -sS -o "${BODY_PATH}" -w '%{http_code}' \
	-H "User-Agent: ${USER_AGENT}" \
	-H "X-Real-IP: ${EXPECTED_REMOTE_ADDR}" \
	"${LOGIN_URL}")"

[ "${http_code}" = "200" ] || {
	log "unexpected login probe status: ${http_code}"
	exit 1
}

after_lines="$(run_privileged_sh "wc -l < $(quote_sh "${SERVE_LOG_PATH}")" | tr -d '[:space:]')"
[ "${after_lines}" -gt "${before_lines}" ] || {
	log "no new lines were written to ${SERVE_LOG_PATH}"
	exit 1
}

run_privileged_sh "awk 'NR > ${before_lines}' $(quote_sh "${SERVE_LOG_PATH}")" > "${EXCERPT_PATH}"

matched_route_line="$(grep 'category=http action=http_login_form_served' "${EXCERPT_PATH}" | grep "remote_addr=\"${EXPECTED_REMOTE_ADDR}\"" | grep "user_agent=\"${USER_AGENT}\"" | tail -n 1 || true)"
[ -n "${matched_route_line}" ] || {
	log "no matching login-form event captured with effective client IP"
	exit 1
}

matched_completion_line="$(grep 'category=http action=http_request_completed' "${EXCERPT_PATH}" | grep 'method="GET"' | grep 'path="/login"' | grep "remote_addr=\"${EXPECTED_REMOTE_ADDR}\"" | tail -n 1 || true)"
[ -n "${matched_completion_line}" ] || {
	log "no matching request-completion event captured with effective client IP"
	exit 1
}

mkdir -p "$(dirname "${REPORT_PATH}")"
{
	printf 'osmap_effective_client_ip_result=passed\n'
	printf 'login_url=%s\n' "${LOGIN_URL}"
	printf 'serve_log_path=%s\n' "${SERVE_LOG_PATH}"
	printf 'expected_remote_addr=%s\n' "${EXPECTED_REMOTE_ADDR}"
	printf 'user_agent=%s\n' "${USER_AGENT}"
	printf 'http_code=%s\n' "${http_code}"
	printf 'log_lines_before=%s\n' "${before_lines}"
	printf 'log_lines_after=%s\n' "${after_lines}"
	printf 'matched_route_event=%s\n' "${matched_route_line}"
	printf 'matched_completion_event=%s\n' "${matched_completion_line}"
} > "${REPORT_PATH}"

log "wrote effective client IP report to ${REPORT_PATH}"
