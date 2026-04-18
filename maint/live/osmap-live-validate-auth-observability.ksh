#!/bin/sh
#
# Validate that the live browser-facing OSMAP runtime captures structured auth
# events into the reviewed audit log instead of discarding them to /dev/null.

set -eu

REPORT_PATH="${OSMAP_AUTH_OBSERVABILITY_REPORT_PATH:-}"
LOGIN_URL="${OSMAP_AUTH_OBSERVABILITY_LOGIN_URL:-http://127.0.0.1:8080/login}"
SERVE_LOG_PATH="${OSMAP_AUTH_OBSERVABILITY_SERVE_LOG_PATH:-/var/lib/osmap/audit/serve.log}"
PROBE_USERNAME="${OSMAP_AUTH_OBSERVABILITY_PROBE_USERNAME:-osmap-log-probe@example.invalid}"
PROBE_PASSWORD="${OSMAP_AUTH_OBSERVABILITY_PROBE_PASSWORD:-wrong-password}"
PROBE_TOTP_CODE="${OSMAP_AUTH_OBSERVABILITY_PROBE_TOTP_CODE:-123456}"
CURL_BIN="${OSMAP_AUTH_OBSERVABILITY_CURL_BIN:-curl}"
DOAS_BIN="${OSMAP_AUTH_OBSERVABILITY_DOAS_BIN:-doas}"
TMPDIR_BASE="${TMPDIR:-/tmp}"
TMPDIR_PATH="$(mktemp -d "${TMPDIR_BASE%/}/osmap-auth-observability.XXXXXX")"
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
		REPORT_PATH="${PWD}/auth-observability-report.txt"
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
	-X POST \
	-H 'Content-Type: application/x-www-form-urlencoded' \
	--data-urlencode "username=${PROBE_USERNAME}" \
	--data-urlencode "password=${PROBE_PASSWORD}" \
	--data-urlencode "totp_code=${PROBE_TOTP_CODE}" \
	"${LOGIN_URL}")"

[ "${http_code}" = "401" ] || {
	log "unexpected login probe status: ${http_code}"
	exit 1
}

after_lines="$(run_privileged_sh "wc -l < $(quote_sh "${SERVE_LOG_PATH}")" | tr -d '[:space:]')"
[ "${after_lines}" -gt "${before_lines}" ] || {
	log "no new lines were written to ${SERVE_LOG_PATH}"
	exit 1
}

run_privileged_sh "awk 'NR > ${before_lines}' $(quote_sh "${SERVE_LOG_PATH}")" > "${EXCERPT_PATH}"

matched_line="$(grep 'category=auth action=login_denied' "${EXCERPT_PATH}" | grep "submitted_username=\"${PROBE_USERNAME}\"" | tail -n 1 || true)"
[ -n "${matched_line}" ] || {
	log "no matching structured auth denial event was captured"
	exit 1
}

mkdir -p "$(dirname "${REPORT_PATH}")"
{
	printf 'osmap_auth_observability_result=passed\n'
	printf 'login_url=%s\n' "${LOGIN_URL}"
	printf 'serve_log_path=%s\n' "${SERVE_LOG_PATH}"
	printf 'probe_username=%s\n' "${PROBE_USERNAME}"
	printf 'http_code=%s\n' "${http_code}"
	printf 'log_lines_before=%s\n' "${before_lines}"
	printf 'log_lines_after=%s\n' "${after_lines}"
	printf 'matched_auth_event=%s\n' "${matched_line}"
} > "${REPORT_PATH}"

log "wrote auth observability report to ${REPORT_PATH}"
