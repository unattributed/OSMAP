#!/bin/sh
#
# Validate that the persistent public HTTPS send workflow emits one consistent
# effective client IP across auth, session, mailbox, submission, and generic
# HTTP completion audit events.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REPORT_PATH="${OSMAP_PUBLIC_SEND_AUDIT_REPORT_PATH:-}"
PUBLIC_BASE_URL="${OSMAP_PUBLIC_SEND_AUDIT_BASE_URL:-https://mail.blackbagsecurity.com}"
SERVE_LOG_PATH="${OSMAP_PUBLIC_SEND_AUDIT_SERVE_LOG_PATH:-/var/lib/osmap/audit/serve.log}"
LIVE_TOTP_DIR="${OSMAP_PUBLIC_SEND_AUDIT_TOTP_DIR:-/var/lib/osmap/secrets/totp}"
VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
VALIDATION_RECIPIENT="${OSMAP_PUBLIC_SEND_AUDIT_RECIPIENT:-${VALIDATION_USER}}"
TOTP_SECRET_BASE32="${OSMAP_VALIDATION_TOTP_SECRET_BASE32:-JBSWY3DPEHPK3PXP}"
USER_AGENT="${OSMAP_PUBLIC_SEND_AUDIT_USER_AGENT:-OSMAP-Public-Send-Audit-Correlation/20260419}"
CURL_BIN="${OSMAP_PUBLIC_SEND_AUDIT_CURL_BIN:-curl}"
SSH_HOST="${OSMAP_PUBLIC_SEND_AUDIT_SSH_HOST:-}"
SSH_BIN="${OSMAP_PUBLIC_SEND_AUDIT_SSH_BIN:-ssh}"
if [ "${OSMAP_PUBLIC_SEND_AUDIT_DOAS_BIN+x}" ]; then
	DOAS_BIN="${OSMAP_PUBLIC_SEND_AUDIT_DOAS_BIN}"
else
	DOAS_BIN="doas"
fi
OPENSSL_BIN="${OSMAP_PUBLIC_SEND_AUDIT_OPENSSL_BIN:-openssl}"
DOVEADM_BIN="${OSMAP_PUBLIC_SEND_AUDIT_DOVEADM_BIN:-doveadm}"
MARIADB_BIN="${OSMAP_PUBLIC_SEND_AUDIT_MARIADB_BIN:-mariadb}"
HEXDUMP_BIN="${OSMAP_PUBLIC_SEND_AUDIT_HEXDUMP_BIN:-hexdump}"
SKIP_CHOWN="${OSMAP_PUBLIC_SEND_AUDIT_SKIP_CHOWN:-0}"
TMPDIR_BASE="${TMPDIR:-/tmp}"
TMPDIR_PATH="$(mktemp -d "${TMPDIR_BASE%/}/osmap-public-send-audit.XXXXXX")"
COOKIE_JAR="${TMPDIR_PATH}/cookies.txt"
LOGIN_FORM_BODY="${TMPDIR_PATH}/login-form-body.txt"
LOGIN_HEADERS="${TMPDIR_PATH}/login-headers.txt"
LOGIN_BODY_FILE="${TMPDIR_PATH}/login-body.txt"
MAILBOXES_BODY="${TMPDIR_PATH}/mailboxes-body.txt"
MAILBOXES_HEADERS="${TMPDIR_PATH}/mailboxes-headers.txt"
COMPOSE_BODY="${TMPDIR_PATH}/compose-body.txt"
COMPOSE_HEADERS="${TMPDIR_PATH}/compose-headers.txt"
SEND_BODY_FILE="${TMPDIR_PATH}/send-body.txt"
SEND_BODY="${TMPDIR_PATH}/send-response-body.txt"
SEND_HEADERS="${TMPDIR_PATH}/send-headers.txt"
EXCERPT_PATH="${TMPDIR_PATH}/serve-log-excerpt.txt"
TOTP_BACKUP_PATH="${TMPDIR_PATH}/validation.totp.backup"
RESTORE_PASSWORD_PENDING=0
RESTORE_TOTP_PENDING=0
TOTP_PREEXISTED=0
ORIGINAL_HASH=""
SEND_SUBJECT="OSMAP public send audit correlation $(date +%s)-$$"

cleanup() {
	cleanup_injected_message
	restore_totp_secret
	restore_original_hash
	rm -rf "${TMPDIR_PATH}"
}

trap cleanup EXIT INT TERM HUP

log() {
	printf '%s\n' "$*"
}

usage() {
	cat <<EOF
usage: $(basename "$0") [--report <path>]

Runs one real public HTTPS login, mailbox listing, compose, and send workflow
against ${PUBLIC_BASE_URL}, then checks the persistent serve audit log for one
consistent effective client IP across auth, session, mailbox, submission, and
http_request_completed events.
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
		REPORT_PATH="${PWD}/public-send-audit-correlation-report.txt"
	fi
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

run_privileged_sh() {
	command="$1"

	if [ -n "${SSH_HOST}" ]; then
		"${SSH_BIN}" "${SSH_HOST}" "doas sh -c $(quote_sh "${command}")"
	elif [ -n "${DOAS_BIN}" ]; then
		"${DOAS_BIN}" sh -c "${command}"
	else
		sh -c "${command}"
	fi
}

run_privileged_as_sh() {
	user="$1"
	command="$2"

	if [ -n "${SSH_HOST}" ]; then
		"${SSH_BIN}" "${SSH_HOST}" "doas -u ${user} sh -c $(quote_sh "${command}")"
	elif [ -n "${DOAS_BIN}" ]; then
		"${DOAS_BIN}" -u "${user}" sh -c "${command}"
	else
		sh -c "${command}"
	fi
}

sql_quote() {
	printf '%s' "$1" | sed "s/'/''/g"
}

trim_trailing_slash() {
	printf '%s' "$1" | sed 's:/*$::'
}

origin_from_base_url() {
	printf '%s' "$1" | sed -E 's#^(https?://[^/]+).*$#\1#'
}

url_for_path() {
	printf '%s%s' "${BASE_URL}" "$1"
}

extract_status_code() {
	awk 'BEGIN { code = "" } /^HTTP\// { code = $2 } END { gsub("\r", "", code); print code }' "$1"
}

extract_header_value() {
	header_name="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
	awk -F': ' -v target="${header_name}" '
		tolower($1) == target {
			gsub("\r", "", $2)
			print $2
		}
	' "$2" | tail -n 1
}

extract_remote_addr() {
	printf '%s\n' "$1" | sed -n 's/.*remote_addr="\([^"]*\)".*/\1/p'
}

generate_totp_code() {
	python3 - "$TOTP_SECRET_BASE32" <<'PY'
import base64
import hashlib
import hmac
import struct
import sys
import time

secret = sys.argv[1].strip().replace(" ", "").replace("-", "").upper()
key = base64.b32decode(secret, casefold=True)
counter = int(time.time()) // 30
digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[19] & 0x0F
binary = ((digest[offset] & 0x7F) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]
print(f"{binary % 1000000:06d}")
PY
}

write_urlencoded_login() {
	output_path="$1"
	password="$2"
	totp_code="$3"

	python3 - "$VALIDATION_USER" "$password" "$totp_code" > "${output_path}" <<'PY'
import sys
import urllib.parse

print(urllib.parse.urlencode({
    "username": sys.argv[1],
    "password": sys.argv[2],
    "totp_code": sys.argv[3],
}), end="")
PY
}

write_urlencoded_send() {
	output_path="$1"
	csrf_token="$2"

	python3 - "$csrf_token" "$VALIDATION_RECIPIENT" "$SEND_SUBJECT" > "${output_path}" <<'PY'
import sys
import urllib.parse

print(urllib.parse.urlencode({
    "csrf_token": sys.argv[1],
    "to": sys.argv[2],
    "subject": sys.argv[3],
    "body": "public send audit correlation validation",
}), end="")
PY
}

select_original_hash() {
	quoted_user="$(sql_quote "${VALIDATION_USER}")"
	sql="SELECT password FROM mailbox WHERE username='${quoted_user}' AND active='1';"
	run_privileged_sh "${MARIADB_BIN} -N -B postfixadmin -e $(quote_sh "${sql}")" | sed -n '1p'
}

update_mailbox_hash() {
	next_hash="$1"
	quoted_hash="$(sql_quote "${next_hash}")"
	quoted_user="$(sql_quote "${VALIDATION_USER}")"

	sql="UPDATE mailbox SET password='${quoted_hash}' WHERE username='${quoted_user}' AND active='1';"
	run_privileged_sh "printf '%s\n' $(quote_sh "${sql}") | ${MARIADB_BIN} postfixadmin >/dev/null"
}

restore_original_hash() {
	[ "${RESTORE_PASSWORD_PENDING}" = "1" ] || return 0
	update_mailbox_hash "${ORIGINAL_HASH}"
	RESTORE_PASSWORD_PENDING=0
}

validation_totp_path() {
	username_hex="$(printf '%s' "${VALIDATION_USER}" | "${HEXDUMP_BIN}" -ve '/1 "%02x"')"
	printf '%s/%s.totp' "${LIVE_TOTP_DIR%/}" "${username_hex}"
}

write_live_totp_secret() {
	secret_path="$1"
	secret_dir="$(dirname "${secret_path}")"
	quoted_dir="$(quote_sh "${secret_dir}")"
	quoted_path="$(quote_sh "${secret_path}")"
	quoted_secret="$(quote_sh "secret=${TOTP_SECRET_BASE32}")"

	run_privileged_sh "install -d -m 700 ${quoted_dir} && printf '%s\n' ${quoted_secret} > ${quoted_path} && chmod 600 ${quoted_path}"
	if [ "${SKIP_CHOWN}" != "1" ]; then
		run_privileged_sh "chown _osmap:_osmap ${quoted_path}"
	fi
}

backup_and_replace_totp_secret() {
	secret_path="$1"

	if run_privileged_sh "test -f $(quote_sh "${secret_path}")"; then
		TOTP_PREEXISTED=1
		run_privileged_sh "cat $(quote_sh "${secret_path}")" > "${TOTP_BACKUP_PATH}"
	else
		TOTP_PREEXISTED=0
	fi

	write_live_totp_secret "${secret_path}"
	RESTORE_TOTP_PENDING=1
}

restore_totp_secret() {
	[ "${RESTORE_TOTP_PENDING}" = "1" ] || return 0

	if [ "${TOTP_PREEXISTED}" = "1" ]; then
		secret_path="$(validation_totp_path)"
		quoted_path="$(quote_sh "${secret_path}")"
		quoted_backup="$(quote_sh "${TOTP_BACKUP_PATH}")"
		run_privileged_sh "cat ${quoted_backup} > ${quoted_path} && chmod 600 ${quoted_path}"
		if [ "${SKIP_CHOWN}" != "1" ]; then
			run_privileged_sh "chown _osmap:_osmap ${quoted_path}"
		fi
	else
		run_privileged_sh "rm -f $(quote_sh "$(validation_totp_path)")"
	fi

	RESTORE_TOTP_PENDING=0
}

cleanup_injected_message() {
	if [ -n "${SEND_SUBJECT:-}" ]; then
		run_privileged_as_sh vmail "${DOVEADM_BIN} -o stats_writer_socket_path= expunge -u $(quote_sh "${VALIDATION_RECIPIENT}") mailbox INBOX header Subject $(quote_sh "${SEND_SUBJECT}")" >/dev/null 2>&1 || true
	fi
}

curl_get() {
	path="$1"
	headers_path="$2"
	body_path="$3"

	"${CURL_BIN}" -sS -L \
		-A "${USER_AGENT}" \
		-b "${COOKIE_JAR}" \
		-c "${COOKIE_JAR}" \
		-D "${headers_path}" \
		-o "${body_path}" \
		"$(url_for_path "${path}")"
}

curl_post_form() {
	path="$1"
	form_path="$2"
	headers_path="$3"
	body_path="$4"
	referer_path="$5"

	"${CURL_BIN}" -sS \
		-A "${USER_AGENT}" \
		-b "${COOKIE_JAR}" \
		-c "${COOKIE_JAR}" \
		-D "${headers_path}" \
		-o "${body_path}" \
		-H "Origin: ${BASE_ORIGIN}" \
		-H "Referer: $(url_for_path "${referer_path}")" \
		-H "Sec-Fetch-Site: same-origin" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		--data-binary @"${form_path}" \
		"$(url_for_path "${path}")"
}

require_matching_line() {
	description="$1"
	pattern="$2"
	remote_addr="$3"
	require_user_agent="$4"

	line="$(grep "${pattern}" "${EXCERPT_PATH}" | grep "remote_addr=\"${remote_addr}\"" || true)"
	if [ "${require_user_agent}" = "1" ]; then
		line="$(printf '%s\n' "${line}" | grep "user_agent=\"${USER_AGENT}\"" || true)"
	fi
	line="$(printf '%s\n' "${line}" | tail -n 1)"
	[ -n "${line}" ] || {
		log "missing correlated audit event: ${description}"
		exit 1
	}
	printf '%s\n' "${line}"
}

parse_args "$@"
BASE_URL="$(trim_trailing_slash "${PUBLIC_BASE_URL}")"
BASE_ORIGIN="$(origin_from_base_url "${BASE_URL}")"

umask 077

require_tool "${CURL_BIN}"
require_tool "${OPENSSL_BIN}"
require_tool "${HEXDUMP_BIN}"
require_tool python3
if [ -n "${SSH_HOST}" ]; then
	require_tool "${SSH_BIN}"
elif [ -n "${DOAS_BIN}" ]; then
	require_tool "${DOAS_BIN}"
	require_tool "${MARIADB_BIN}"
	require_tool "${DOVEADM_BIN}"
else
	require_tool "${MARIADB_BIN}"
	require_tool "${DOVEADM_BIN}"
fi

if ! run_privileged_sh "test -f $(quote_sh "${SERVE_LOG_PATH}")"; then
	log "serve log file does not exist: ${SERVE_LOG_PATH}"
	exit 1
fi

ORIGINAL_HASH="$(select_original_hash)"
[ -n "${ORIGINAL_HASH}" ] || {
	log "no active mailbox password hash found for ${VALIDATION_USER}"
	exit 1
}

TEMP_PASSWORD="$("${OPENSSL_BIN}" rand -hex 16)"
[ -n "${TEMP_PASSWORD}" ] || {
	log "failed to generate temporary validation password"
	exit 1
}

TEMP_HASH="$(run_privileged_sh "${DOVEADM_BIN} pw -s BLF-CRYPT -p $(quote_sh "${TEMP_PASSWORD}")")"
[ -n "${TEMP_HASH}" ] || {
	log "failed to generate temporary validation password hash"
	exit 1
}

TOTP_SECRET_PATH="$(validation_totp_path)"

log "installing temporary validation credential and TOTP secret for ${VALIDATION_USER}"
update_mailbox_hash "${TEMP_HASH}"
RESTORE_PASSWORD_PENDING=1
backup_and_replace_totp_secret "${TOTP_SECRET_PATH}"

before_lines="$(run_privileged_sh "wc -l < $(quote_sh "${SERVE_LOG_PATH}")" | tr -d '[:space:]')"

log "loading public login form"
curl_get "/login" "${LOGIN_HEADERS}" "${LOGIN_FORM_BODY}" >/dev/null
login_form_status="$(extract_status_code "${LOGIN_HEADERS}")"
[ "${login_form_status}" = "200" ] || {
	log "login form returned unexpected status: ${login_form_status}"
	exit 1
}

totp_code="$(generate_totp_code)"
write_urlencoded_login "${LOGIN_BODY_FILE}" "${TEMP_PASSWORD}" "${totp_code}"

log "performing public password-plus-TOTP login"
curl_post_form "/login" "${LOGIN_BODY_FILE}" "${LOGIN_HEADERS}" "${LOGIN_FORM_BODY}" "/login" >/dev/null
login_status="$(extract_status_code "${LOGIN_HEADERS}")"
login_location="$(extract_header_value Location "${LOGIN_HEADERS}")"
[ "${login_status}" = "303" ] || {
	log "login returned unexpected status: ${login_status}"
	exit 1
}
[ "${login_location}" = "/mailboxes" ] || {
	log "login redirect was unexpected: ${login_location}"
	exit 1
}

log "loading public mailboxes page with issued session"
curl_get "/mailboxes" "${MAILBOXES_HEADERS}" "${MAILBOXES_BODY}" >/dev/null
mailboxes_status="$(extract_status_code "${MAILBOXES_HEADERS}")"
[ "${mailboxes_status}" = "200" ] || {
	log "mailboxes returned unexpected status: ${mailboxes_status}"
	exit 1
}

log "loading public compose page"
curl_get "/compose" "${COMPOSE_HEADERS}" "${COMPOSE_BODY}" >/dev/null
compose_status="$(extract_status_code "${COMPOSE_HEADERS}")"
[ "${compose_status}" = "200" ] || {
	log "compose returned unexpected status: ${compose_status}"
	exit 1
}

csrf_token="$(sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' "${COMPOSE_BODY}" | head -n 1)"
[ -n "${csrf_token}" ] || {
	log "compose page did not expose a csrf token"
	exit 1
}

write_urlencoded_send "${SEND_BODY_FILE}" "${csrf_token}"

log "submitting one real public browser-send request"
curl_post_form "/send" "${SEND_BODY_FILE}" "${SEND_HEADERS}" "${SEND_BODY}" "/compose" >/dev/null
send_status="$(extract_status_code "${SEND_HEADERS}")"
send_location="$(extract_header_value Location "${SEND_HEADERS}")"
[ "${send_status}" = "303" ] || {
	log "send returned unexpected status: ${send_status}"
	exit 1
}
[ "${send_location}" = "/compose?sent=1" ] || {
	log "send redirect was unexpected: ${send_location}"
	exit 1
}

sleep 1
after_lines="$(run_privileged_sh "wc -l < $(quote_sh "${SERVE_LOG_PATH}")" | tr -d '[:space:]')"
[ "${after_lines}" -gt "${before_lines}" ] || {
	log "no new audit lines were written to ${SERVE_LOG_PATH}"
	exit 1
}

run_privileged_sh "awk 'NR > ${before_lines}' $(quote_sh "${SERVE_LOG_PATH}")" > "${EXCERPT_PATH}"

auth_line="$(grep 'category=auth action=second_factor_accepted' "${EXCERPT_PATH}" | grep "canonical_username=\"${VALIDATION_USER}\"" | grep "user_agent=\"${USER_AGENT}\"" | tail -n 1 || true)"
[ -n "${auth_line}" ] || {
	log "missing correlated auth event"
	exit 1
}

effective_remote_addr="$(extract_remote_addr "${auth_line}")"
[ -n "${effective_remote_addr}" ] || {
	log "could not extract effective remote address from auth event"
	exit 1
}

session_line="$(require_matching_line "session issuance" 'category=session action=session_issued' "${effective_remote_addr}" 1)"
session_validated_line="$(require_matching_line "session validation" 'category=session action=session_validated' "${effective_remote_addr}" 1)"
mailbox_line="$(require_matching_line "mailbox listing" 'category=mailbox action=mailbox_listed' "${effective_remote_addr}" 1)"
submission_line="$(require_matching_line "message submission" 'category=submission action=message_submitted' "${effective_remote_addr}" 1)"
completion_line="$(require_matching_line "send request completion" 'category=http action=http_request_completed.*method="POST".*path="/send".*status_code="303"' "${effective_remote_addr}" 0)"

mkdir -p "$(dirname "${REPORT_PATH}")"
{
	printf 'osmap_public_send_audit_correlation_result=passed\n'
	printf 'public_base_url=%s\n' "${BASE_URL}"
	printf 'serve_log_path=%s\n' "${SERVE_LOG_PATH}"
	printf 'validation_user=%s\n' "${VALIDATION_USER}"
	printf 'validation_recipient=%s\n' "${VALIDATION_RECIPIENT}"
	printf 'expected_remote_addr=%s\n' "${effective_remote_addr}"
	printf 'user_agent=%s\n' "${USER_AGENT}"
	printf 'login_status=%s\n' "${login_status}"
	printf 'mailboxes_status=%s\n' "${mailboxes_status}"
	printf 'compose_status=%s\n' "${compose_status}"
	printf 'send_status=%s\n' "${send_status}"
	printf 'send_location=%s\n' "${send_location}"
	printf 'log_lines_before=%s\n' "${before_lines}"
	printf 'log_lines_after=%s\n' "${after_lines}"
	printf 'matched_auth_event=%s\n' "${auth_line}"
	printf 'matched_session_issued_event=%s\n' "${session_line}"
	printf 'matched_session_validated_event=%s\n' "${session_validated_line}"
	printf 'matched_mailbox_event=%s\n' "${mailbox_line}"
	printf 'matched_submission_event=%s\n' "${submission_line}"
	printf 'matched_completion_event=%s\n' "${completion_line}"
} > "${REPORT_PATH}"

log "wrote public send audit correlation report to ${REPORT_PATH}"
