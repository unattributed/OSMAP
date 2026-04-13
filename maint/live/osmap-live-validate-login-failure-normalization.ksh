#!/bin/sh
#
# Validate that browser-visible login failures do not distinguish password
# rejection from second-factor rejection on a live OpenBSD host.
#
# This script is intended to run on a host like mail.blackbagsecurity.com where
# `doas -u _osmap` is available. It builds the current OSMAP tree, starts an
# isolated enforced browser runtime against the dedicated Dovecot auth socket,
# applies a temporary validation-mailbox password override with guaranteed
# restoration, then verifies that wrong-password and wrong-TOTP login attempts
# both return the same browser-visible failure banner while a correct password
# plus correct TOTP still succeeds.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK_ROOT="${OSMAP_LIVE_WORK_ROOT:-/home/osmap-live-login-failure-normalization-$$}"
STATE_ROOT="${WORK_ROOT}/state"
SESSION_DIR="${STATE_ROOT}/sessions"
RUNTIME_DIR="${STATE_ROOT}/runtime"
SETTINGS_DIR="${STATE_ROOT}/settings"
AUDIT_DIR="${STATE_ROOT}/audit"
CACHE_DIR="${STATE_ROOT}/cache"
TOTP_DIR="${STATE_ROOT}/totp"
TMPDIR_PATH="${WORK_ROOT}/tmp"
CARGO_HOME_PATH="${WORK_ROOT}/cargo-home"
CARGO_TARGET_DIR_PATH="${WORK_ROOT}/target"
BIN_PATH="${WORK_ROOT}/osmap"
HTTP_LOG_PATH="${RUNTIME_DIR}/serve.log"
HTTP_PID_PATH="${RUNTIME_DIR}/serve.pid"
WRONG_PASSWORD_RESPONSE_PATH="${WORK_ROOT}/wrong-password-response.txt"
WRONG_TOTP_RESPONSE_PATH="${WORK_ROOT}/wrong-totp-response.txt"
GOOD_LOGIN_RESPONSE_PATH="${WORK_ROOT}/good-login-response.txt"
LISTEN_PORT="${OSMAP_LIVE_LOGIN_FAILURE_NORMALIZATION_PORT:-}"
VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
AUTH_SOCKET_PATH="${OSMAP_DOVEADM_AUTH_SOCKET_PATH:-/var/run/osmap-auth}"
TOTP_SECRET_BASE32="${OSMAP_VALIDATION_TOTP_SECRET_BASE32:-JBSWY3DPEHPK3PXP}"
KEEP_WORK_ROOT="${OSMAP_KEEP_WORK_ROOT:-0}"
RESTORE_PENDING=0
ORIGINAL_HASH=""

log() {
  printf '%s\n' "$*"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    log "missing required tool: $1"
    exit 1
  }
}

sql_quote() {
  printf '%s' "$1" | sed "s/'/''/g"
}

update_mailbox_hash() {
  next_hash="$1"
  quoted_hash="$(sql_quote "${next_hash}")"
  quoted_user="$(sql_quote "${VALIDATION_USER}")"

  doas mariadb postfixadmin <<SQL
UPDATE mailbox
SET password='${quoted_hash}'
WHERE username='${quoted_user}' AND active='1';
SQL
}

restore_original_hash() {
  [ "${RESTORE_PENDING}" = "1" ] || return 0
  update_mailbox_hash "${ORIGINAL_HASH}"
  RESTORE_PENDING=0
}

cleanup() {
  if [ -f "${HTTP_PID_PATH}" ]; then
    doas kill "$(doas cat "${HTTP_PID_PATH}")" 2>/dev/null || true
  fi
  restore_original_hash
  if [ "${KEEP_WORK_ROOT}" = "1" ]; then
    log "keeping live validation root at ${WORK_ROOT}"
  else
    doas rm -rf "${WORK_ROOT}" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM HUP

require_tool cargo
require_tool doas
require_tool nc
require_tool openssl
require_tool python3
require_tool sed
require_tool grep
require_tool hexdump

if [ -z "${LISTEN_PORT}" ]; then
  LISTEN_PORT="$((18800 + ($$ % 1000)))"
fi

ORIGINAL_HASH="$(doas mariadb -N -B postfixadmin -e "SELECT password FROM mailbox WHERE username='${VALIDATION_USER}' AND active='1';")"
[ -n "${ORIGINAL_HASH}" ] || {
  log "no active mailbox password hash found for ${VALIDATION_USER}"
  exit 1
}

TEMP_PASSWORD="$(openssl rand -hex 16)"
[ -n "${TEMP_PASSWORD}" ] || {
  log "failed to generate temporary validation password"
  exit 1
}

TEMP_HASH="$(doas doveadm pw -s BLF-CRYPT -p "${TEMP_PASSWORD}")"
[ -n "${TEMP_HASH}" ] || {
  log "failed to generate temporary validation password hash"
  exit 1
}

update_mailbox_hash "${TEMP_HASH}"
RESTORE_PENDING=1

USERNAME_HEX="$(printf '%s' "${VALIDATION_USER}" | hexdump -ve '/1 "%02x"')"
TOTP_SECRET_PATH="${TOTP_DIR}/${USERNAME_HEX}.totp"

log "preparing isolated live validation root under ${WORK_ROOT}"
doas rm -rf "${WORK_ROOT}"
doas install -d -o foo -g foo -m 755 "${WORK_ROOT}"
install -d "${TMPDIR_PATH}" "${CARGO_HOME_PATH}" "${CARGO_TARGET_DIR_PATH}"
doas install -d -o _osmap -g _osmap -m 755 "${STATE_ROOT}"
doas install -d -o _osmap -g _osmap -m 700 \
  "${SESSION_DIR}" \
  "${RUNTIME_DIR}" \
  "${SETTINGS_DIR}" \
  "${AUDIT_DIR}" \
  "${CACHE_DIR}" \
  "${TOTP_DIR}"

log "building current OSMAP tree"
cd "${PROJECT_ROOT}"
TMPDIR="${TMPDIR_PATH}" \
  CARGO_HOME="${CARGO_HOME_PATH}" \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR_PATH}" \
  cargo build --quiet
doas install -o _osmap -g _osmap -m 755 "${CARGO_TARGET_DIR_PATH}/debug/osmap" "${BIN_PATH}"

log "writing isolated validation TOTP secret"
doas sh -c "cat > '${TOTP_SECRET_PATH}' <<'EOF'
secret=${TOTP_SECRET_BASE32}
EOF
chmod 600 '${TOTP_SECRET_PATH}'
chown _osmap:_osmap '${TOTP_SECRET_PATH}'"

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

urlencode_triplet() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys
import urllib.parse

print(
    urllib.parse.urlencode(
        {
            "username": sys.argv[1],
            "password": sys.argv[2],
            "totp_code": sys.argv[3],
        }
    )
)
PY
}

log "starting enforced browser runtime as _osmap"
doas -u _osmap sh -c "
  umask 077
  echo \$$ > '${HTTP_PID_PATH}'
  exec env \
    OSMAP_RUN_MODE=serve \
    OSMAP_ENV=production \
    OSMAP_LISTEN_ADDR=127.0.0.1:${LISTEN_PORT} \
    OSMAP_STATE_DIR='${STATE_ROOT}' \
    OSMAP_RUNTIME_DIR='${RUNTIME_DIR}' \
    OSMAP_SESSION_DIR='${SESSION_DIR}' \
    OSMAP_SETTINGS_DIR='${SETTINGS_DIR}' \
    OSMAP_AUDIT_DIR='${AUDIT_DIR}' \
    OSMAP_CACHE_DIR='${CACHE_DIR}' \
    OSMAP_TOTP_SECRET_DIR='${TOTP_DIR}' \
    OSMAP_DOVEADM_AUTH_SOCKET_PATH='${AUTH_SOCKET_PATH}' \
    OSMAP_MAILBOX_HELPER_SOCKET_PATH='${RUNTIME_DIR}/unused-mailbox-helper.sock' \
    OSMAP_LOG_LEVEL=info \
    OSMAP_OPENBSD_CONFINEMENT_MODE=enforce \
    '${BIN_PATH}' >'${HTTP_LOG_PATH}' 2>&1
" &

wait_for_healthz() {
  tries=0
  while [ "${tries}" -lt 40 ]; do
    response="$(
      {
        printf 'GET /healthz HTTP/1.1\r\n'
        printf 'Host: localhost\r\n'
        printf 'Connection: close\r\n'
        printf '\r\n'
      } | nc -N 127.0.0.1 "${LISTEN_PORT}" 2>/dev/null || true
    )"
    if printf '%s' "${response}" | grep -q '^HTTP/1.1 200 OK'; then
      return 0
    fi
    sleep 1
    tries="$((tries + 1))"
  done
  log "http runtime did not become ready"
  [ -f "${HTTP_LOG_PATH}" ] && doas cat "${HTTP_LOG_PATH}"
  return 1
}

submit_login() {
  body="$1"
  output_path="$2"
  {
    printf 'POST /login HTTP/1.1\r\n'
    printf 'Host: localhost\r\n'
    printf 'Content-Type: application/x-www-form-urlencoded\r\n'
    printf 'Content-Length: %s\r\n' "$(printf '%s' "${body}" | wc -c | awk '{print $1}')"
    printf 'Connection: close\r\n'
    printf '\r\n'
    printf '%s' "${body}"
  } | nc -N 127.0.0.1 "${LISTEN_PORT}" >"${output_path}"
}

wait_for_healthz

WRONG_PASSWORD_BODY="$(urlencode_triplet "${VALIDATION_USER}" "wrong-password" "123456")"
submit_login "${WRONG_PASSWORD_BODY}" "${WRONG_PASSWORD_RESPONSE_PATH}"

WRONG_TOTP_BODY="$(urlencode_triplet "${VALIDATION_USER}" "${TEMP_PASSWORD}" "000000")"
submit_login "${WRONG_TOTP_BODY}" "${WRONG_TOTP_RESPONSE_PATH}"

TOTP_CODE="$(generate_totp_code)"
GOOD_LOGIN_BODY="$(urlencode_triplet "${VALIDATION_USER}" "${TEMP_PASSWORD}" "${TOTP_CODE}")"
submit_login "${GOOD_LOGIN_BODY}" "${GOOD_LOGIN_RESPONSE_PATH}"

grep -q '^HTTP/1.1 401 Unauthorized' "${WRONG_PASSWORD_RESPONSE_PATH}" || {
  log "wrong-password login did not return 401"
  cat "${WRONG_PASSWORD_RESPONSE_PATH}"
  exit 1
}
grep -q '^HTTP/1.1 401 Unauthorized' "${WRONG_TOTP_RESPONSE_PATH}" || {
  log "wrong-TOTP login did not return 401"
  cat "${WRONG_TOTP_RESPONSE_PATH}"
  exit 1
}
grep -q '^HTTP/1.1 303 See Other' "${GOOD_LOGIN_RESPONSE_PATH}" || {
  log "good login did not succeed"
  cat "${GOOD_LOGIN_RESPONSE_PATH}"
  exit 1
}

GENERIC_FAILURE='The supplied credentials were not accepted.'
grep -Fq "${GENERIC_FAILURE}" "${WRONG_PASSWORD_RESPONSE_PATH}" || {
  log "wrong-password response did not contain the generic failure banner"
  cat "${WRONG_PASSWORD_RESPONSE_PATH}"
  exit 1
}
grep -Fq "${GENERIC_FAILURE}" "${WRONG_TOTP_RESPONSE_PATH}" || {
  log "wrong-TOTP response did not contain the generic failure banner"
  cat "${WRONG_TOTP_RESPONSE_PATH}"
  exit 1
}
if grep -Fq 'second-factor code was not accepted' "${WRONG_TOTP_RESPONSE_PATH}"; then
  log "wrong-TOTP response still exposed a second-factor-specific banner"
  cat "${WRONG_TOTP_RESPONSE_PATH}"
  exit 1
fi

log "wrong_password_status=normalized"
log "wrong_totp_status=normalized"
log "good_login_status=ok"
