#!/usr/bin/env bash
set -euo pipefail

PACK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

load_env() {
  local env_candidates=(
    ".env"
    "$PACK_ROOT/.env"
    "$PWD/.env"
  )
  local env_file=""
  local env_sets_hostname=0
  for candidate in "${env_candidates[@]}"; do
    if [[ -f "$candidate" ]]; then
      env_file="$candidate"
      break
    fi
  done
  if [[ -n "$env_file" ]]; then
    if grep -Eq '^[[:space:]]*(export[[:space:]]+)?HOSTNAME=' "$env_file"; then
      env_sets_hostname=1
    fi
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
  fi

  local configured_base_url="${TARGET_BASE_URL:-}"
  local configured_scheme="${SCHEME:-}"
  if [[ -z "$configured_scheme" && -n "$configured_base_url" ]]; then
    case "$configured_base_url" in
      http://*) configured_scheme="http" ;;
      https://*) configured_scheme="https" ;;
    esac
  fi

  export SCHEME="${configured_scheme:-https}"

  local configured_hostname="${TARGET_HOSTNAME:-}"
  if [[ -z "$configured_hostname" && "$env_sets_hostname" -eq 1 ]]; then
    configured_hostname="${HOSTNAME:-}"
  fi
  if [[ -z "$configured_hostname" && -n "$configured_base_url" ]]; then
    configured_hostname="$(host_from_url "$configured_base_url")"
  fi

  export HOSTNAME="$configured_hostname"
  export TARGET_HOSTNAME="$configured_hostname"
  export EMAIL="${TARGET_EMAIL:-${EMAIL:-}}"
  export TARGET_EMAIL="$EMAIL"
  export TARGET_BASE_URL="${configured_base_url:-${SCHEME}://${HOSTNAME}}"
  export TARGET_PORT="${TARGET_PORT:-$(port_from_url "$TARGET_BASE_URL")}"
  if [[ -z "$TARGET_PORT" ]]; then
    case "$SCHEME" in
      http) TARGET_PORT=80 ;;
      *) TARGET_PORT=443 ;;
    esac
  fi
  export TARGET_TLS="${TARGET_TLS:-}"
  if [[ -z "$TARGET_TLS" ]]; then
    case "$SCHEME" in
      https) TARGET_TLS=1 ;;
      *) TARGET_TLS=0 ;;
    esac
  fi

  export OUT_ROOT="${OUT_ROOT:-$HOME/webmail-wstg}"
  export LOGIN_PATH="${LOGIN_PATH:-/login}"
  export LOGOUT_PATH="${LOGOUT_PATH:-/logout}"
  export SETTINGS_PATH="${SETTINGS_PATH:-/settings}"
  export SESSIONS_PATH="${SESSIONS_PATH:-/sessions}"
  export MAILBOXES_PATH="${MAILBOXES_PATH:-/mailboxes}"
  export COMPOSE_PATH="${COMPOSE_PATH:-/compose}"
  export SEND_PATH="${SEND_PATH:-/send}"
  export SEARCH_PATH="${SEARCH_PATH:-/search}"
  export MESSAGE_VIEW_PATH="${MESSAGE_VIEW_PATH:-/message}"
  export MESSAGE_MOVE_PATH="${MESSAGE_MOVE_PATH:-/message/move}"
  export MESSAGES_ARCHIVE_PATH="${MESSAGES_ARCHIVE_PATH:-/messages/archive}"
  export ATTACHMENT_PATH="${ATTACHMENT_PATH:-/attachment}"

  export DEFAULT_MAILBOX="${DEFAULT_MAILBOX:-INBOX}"
  export DEFAULT_MESSAGE_UID="${DEFAULT_MESSAGE_UID:-156}"
  export DEFAULT_ATTACHMENT_PART="${DEFAULT_ATTACHMENT_PART:-1.2}"
  export DEFAULT_ARCHIVE_MAILBOX="${DEFAULT_ARCHIVE_MAILBOX:-Junk}"
  export SEARCH_QUERY="${SEARCH_QUERY:-INBOX}"
  export INVALID_EMAIL="${INVALID_EMAIL:-nobody@@invalid.invalid}"
  export ATTACKER_URL="${ATTACKER_URL:-https://attacker.invalid/wstg}"
  export THROTTLE_ATTEMPTS="${THROTTLE_ATTEMPTS:-6}"
  export COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-60}"
  export SHORT_SLEEP_SECONDS="${SHORT_SLEEP_SECONDS:-1}"
  export SESSION_PROBE_COUNT="${SESSION_PROBE_COUNT:-10}"
  export SESSION_PROBE_INTERVAL_SECONDS="${SESSION_PROBE_INTERVAL_SECONDS:-120}"
  export LONG_IDLE_SECONDS="${LONG_IDLE_SECONDS:-1800}"
  export HTTP_ALT_PORTS="${HTTP_ALT_PORTS:-80 8080}"
  export WEBSOCKET_PATHS="${WEBSOCKET_PATHS:-/ws /socket /websocket /notifications /live /api/ws /sockjs /socket.io/}"
  export CORS_TEST_ORIGINS="${CORS_TEST_ORIGINS:-https://attacker.invalid null}"
  export TEST_PASSWORD="${TEST_PASSWORD:-}"
  export TEST_TOTP_CODE="${TEST_TOTP_CODE:-}"
}

url_authority() {
  local url="$1"
  case "$url" in
    *://*) url="${url#*://}" ;;
  esac
  url="${url%%/*}"
  url="${url##*@}"
  printf '%s' "$url"
}

host_from_url() {
  local authority
  authority="$(url_authority "$1")"
  case "$authority" in
    \[*\]*) printf '%s' "${authority%%]*}]" ;;
    *:*) printf '%s' "${authority%%:*}" ;;
    *) printf '%s' "$authority" ;;
  esac
}

port_from_url() {
  local authority
  authority="$(url_authority "$1")"
  case "$authority" in
    \[*\]:*) printf '%s' "${authority##*:}" ;;
    *:*) printf '%s' "${authority##*:}" ;;
  esac
}

require_target_host() {
  if [[ -z "${HOSTNAME:-}" ]]; then
    echo "ERROR: TARGET_HOSTNAME is not set. Put TARGET_HOSTNAME in .env or set TARGET_BASE_URL." >&2
    exit 1
  fi
}

require_basic_env() {
  require_target_host
  if [[ -z "${EMAIL:-}" ]]; then
    echo "ERROR: TARGET_EMAIL is not set. Put TARGET_EMAIL in .env or export EMAIL." >&2
    exit 1
  fi
}

require_cmds() {
  local missing=()
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if (( ${#missing[@]} > 0 )); then
    echo "ERROR: missing required commands: ${missing[*]}" >&2
    exit 1
  fi
}

timestamp() {
  date +%Y%m%d-%H%M%S
}

setup_run_dir() {
  local test_name="$1"
  require_target_host
  export RUN_DIR="${OUT_ROOT}/${test_name}-$(timestamp)"
  mkdir -p "$RUN_DIR"
  cd "$RUN_DIR"
  echo "Working directory: $RUN_DIR"
}

prompt_secret() {
  local var_name="$1"
  local prompt_text="$2"
  local current="${!var_name:-}"
  if [[ -z "$current" ]]; then
    read -rsp "$prompt_text" current
    echo
    export "$var_name=$current"
  fi
}

prompt_totp_once() {
  local prompt_text="${1:-Current TOTP: }"
  local code="${TEST_TOTP_CODE:-}"
  if [[ -z "$code" ]]; then
    printf 'Generate a fresh TOTP now, then enter it immediately.\n'
    read -rsp "$prompt_text" code
    echo
  fi
  printf '%s' "$code"
}

consume_totp_env() {
  unset TEST_TOTP_CODE || true
}

perform_login() {
  local cookie_file="${1:-cookies.txt}"
  local headers_file="${2:-login.headers}"
  local body_file="${3:-login.body.html}"
  local totp_prompt="${4:-Current TOTP: }"

  require_basic_env
  prompt_secret TEST_PASSWORD 'Password: '
  local totp
  totp="$(prompt_totp_once "$totp_prompt")"

  curl -sS \
    -o "$body_file" \
    -D "$headers_file" \
    -c "$cookie_file" \
    -X POST "${TARGET_BASE_URL}${LOGIN_PATH}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "username=${EMAIL}" \
    --data-urlencode "password=${TEST_PASSWORD}" \
    --data-urlencode "totp_code=${totp}"

  consume_totp_env
}

fetch_get() {
  local route="$1"
  local body_file="$2"
  local headers_file="$3"
  local cookie_file="${4:-cookies.txt}"
  shift 4 || true
  curl -sS -o "$body_file" -D "$headers_file" -b "$cookie_file" -c "$cookie_file" "$@" "${TARGET_BASE_URL}${route}"
}

fetch_post_form() {
  local route="$1"
  local body_file="$2"
  local headers_file="$3"
  local cookie_file="${4:-cookies.txt}"
  local referer="${5:-}"
  shift 5 || true
  local extra=(-X POST -H 'Content-Type: application/x-www-form-urlencoded')
  if [[ -n "$referer" ]]; then
    extra+=(-H "Origin: ${TARGET_BASE_URL}" -H "Referer: ${TARGET_BASE_URL}${referer}")
  fi
  curl -sS -o "$body_file" -D "$headers_file" -b "$cookie_file" -c "$cookie_file" "${extra[@]}" "$@" "${TARGET_BASE_URL}${route}"
}

extract_first_csrf() {
  local html_file="$1"
  grep -Eo 'name="csrf_token" value="[^"]+"' "$html_file" | head -n1 | sed 's/^name="csrf_token" value="//; s/"$//'
}

extract_hidden_value() {
  local html_file="$1"
  local field_name="$2"
  grep -Eo "name=\"${field_name}\" value=\"[^\"]*\"" "$html_file" | head -n1 | sed "s/^name=\"${field_name}\" value=\"//; s/\"$//"
}

header_code() {
  local headers_file="$1"
  awk 'NR==1{print $2}' "$headers_file"
}

header_field() {
  local headers_file="$1"
  local field_name="$2"
  awk -v field="${field_name}" 'BEGIN{IGNORECASE=1} $0 ~ "^" field ":" {gsub("\r",""); sub("^[^:]+:[[:space:]]*",""); print; exit}' "$headers_file"
}

html_title() {
  local html_file="$1"
  grep -Eoi '<title>[^<]+' "$html_file" | head -n1 | sed 's/<title>//I'
}

session_cookie_value() {
  local cookie_file="$1"
  awk '$6=="osmap_session"{print $7}' "$cookie_file" | tail -n1
}

print_body_prefix() {
  local file="$1"
  python3 - "$file" <<'PY'
from pathlib import Path
import sys
data = Path(sys.argv[1]).read_bytes()[:400]
print(data.decode("utf-8", errors="replace"))
PY
}

ensure_cookie_source() {
  local cookie_src="$1"
  if [[ ! -f "$cookie_src" ]]; then
    echo "ERROR: cookie source not found: $cookie_src" >&2
    exit 1
  fi
}

clone_testssl_if_needed() {
  local target_dir="$1"
  if command -v testssl.sh >/dev/null 2>&1; then
    command -v testssl.sh
    return 0
  fi
  if command -v testssl >/dev/null 2>&1; then
    command -v testssl
    return 0
  fi
  if [[ ! -d "${target_dir}/testssl.sh" ]]; then
    git clone --depth 1 https://github.com/testssl/testssl.sh "${target_dir}/testssl.sh" >/dev/null 2>&1
  fi
  printf '%s' "${target_dir}/testssl.sh/testssl.sh"
}

separator() {
  printf '\n%s\n' "============================================================"
}

log_kv() {
  printf '%s=%s\n' "$1" "$2"
}
