#!/bin/sh
#
# Validate the V4 hostile-content safety proof on a live OpenBSD host.
#
# This validator avoids storing passwords, TOTP material, cookies, CSRF tokens,
# raw session identifiers, full message bodies, or full attachment bodies in
# committed evidence.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REPORT_PATH="${OSMAP_LIVE_V4_HOSTILE_CONTENT_REPORT_PATH:-${PROJECT_ROOT}/maint/live/latest-host-v4-hostile-content-report.txt}"

WORK_ROOT="${OSMAP_LIVE_WORK_ROOT:-/home/osmap-live-v4-hostile-content-$$}"
STATE_ROOT="${WORK_ROOT}/state"
HELPER_RUNTIME_DIR="${WORK_ROOT}/helper-runtime"
HELPER_STATE_RUNTIME_DIR="${STATE_ROOT}/helper-runtime-state"
SESSION_DIR="${STATE_ROOT}/sessions"
RUNTIME_DIR="${STATE_ROOT}/runtime"
SETTINGS_DIR="${STATE_ROOT}/settings"
AUDIT_DIR="${STATE_ROOT}/audit"
CACHE_DIR="${STATE_ROOT}/cache"
TOTP_DIR="${STATE_ROOT}/totp"
SECRET_DIR="${STATE_ROOT}/secrets"
HELPER_SECRET_DIR="${HELPER_STATE_RUNTIME_DIR}/secrets"
WEB_GRANT_KEY_PATH="${SECRET_DIR}/mailbox-helper-grant.key"
HELPER_GRANT_KEY_PATH="${HELPER_SECRET_DIR}/mailbox-helper-grant.key"
TMPDIR_PATH="${WORK_ROOT}/tmp"
CARGO_HOME_PATH="${WORK_ROOT}/cargo-home"
CARGO_TARGET_DIR_PATH="${WORK_ROOT}/target"
BIN_PATH="${WORK_ROOT}/osmap"
HTTP_LOG_PATH="${RUNTIME_DIR}/serve.log"
HTTP_PID_PATH="${RUNTIME_DIR}/serve.pid"
HELPER_LOG_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.log"
HELPER_PID_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.pid"
HELPER_SOCKET_PATH="${HELPER_RUNTIME_DIR}/mailbox-helper.sock"

VALIDATION_USER="${OSMAP_VALIDATION_USER:-osmap-helper-validation@blackbagsecurity.com}"
LISTEN_PORT="${OSMAP_LIVE_V4_HOSTILE_CONTENT_PORT:-}"
SESSION_TOKEN="${OSMAP_LIVE_SESSION_TOKEN:-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}"
USER_AGENT="osmap-live-v4-hostile-content"
AUTH_SOCKET_PATH="${OSMAP_DOVEADM_AUTH_SOCKET_PATH:-/var/run/osmap-auth}"
TRUSTED_WEB_RUNTIME_UID="${OSMAP_TRUSTED_WEB_RUNTIME_UID:-$(id -u _osmap)}"
USERDB_SOCKET_PATH="${OSMAP_DOVEADM_USERDB_SOCKET_PATH:-/var/run/osmap-userdb}"
KEEP_WORK_ROOT="${OSMAP_KEEP_WORK_ROOT:-0}"

log() {
  printf '%s\n' "$*"
}

write_report() {
  key="$1"
  value="$2"
  printf '%s=%s\n' "$key" "$value" >> "${REPORT_PATH}"
}

fail() {
  log "failed: $*"
  {
    printf '%s\n' "result=failed"
    printf '%s\n' "failure_reason=$*"
    printf '%s\n' "failed_work_root=${WORK_ROOT}"
  } >> "${REPORT_PATH}"
  exit 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"
}

terminate_pid_path() {
  pid_path="$1"
  doas test -f "${pid_path}" 2>/dev/null || return 0

  target_pid="$(doas cat "${pid_path}" 2>/dev/null || true)"
  case "${target_pid}" in
    ""|*[!0-9]*)
      return 0
      ;;
  esac

  doas kill "${target_pid}" 2>/dev/null || true
  sleep 1
  doas kill -KILL "${target_pid}" 2>/dev/null || true
}

cleanup() {
  terminate_pid_path "${HTTP_PID_PATH}"
  terminate_pid_path "${HELPER_PID_PATH}"

  if [ "${KEEP_WORK_ROOT}" = "1" ]; then
    log "keeping live validation root at ${WORK_ROOT}"
  else
    doas rm -rf "${WORK_ROOT}" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

require_tool awk
require_tool cargo
require_tool doas
require_tool grep
require_tool nc
require_tool openssl
require_tool sed
require_tool sha256

if [ -z "${LISTEN_PORT}" ]; then
  LISTEN_PORT="$((20000 + ($$ % 1000)))"
fi

case "${SESSION_TOKEN}" in
  [0-9a-fA-F][0-9a-fA-F]*)
    ;;
  *)
    fail "session token must be hex"
    ;;
esac

if [ "${#SESSION_TOKEN}" -ne 64 ]; then
  fail "session token must be exactly 64 hex characters"
fi

SESSION_ID="$(printf 'session-id:%s' "${SESSION_TOKEN}" | sha256 -q)"
CSRF_TOKEN="$(printf 'csrf:%s' "${SESSION_TOKEN}" | sha256 -q)"
NOW="$(date +%s)"
EXPIRES_AT="$((NOW + 3600))"

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
  "${TOTP_DIR}" \
  "${SECRET_DIR}"

doas install -d -o vmail -g vmail -m 755 "${HELPER_RUNTIME_DIR}"
doas install -d -o vmail -g vmail -m 700 "${HELPER_STATE_RUNTIME_DIR}" "${HELPER_SECRET_DIR}"

: > "${REPORT_PATH}"
write_report "osmap_v4_hostile_content_result" "running"
write_report "host" "$(hostname)"
write_report "project_root" "${PROJECT_ROOT}"
write_report "commit" "$(cd "${PROJECT_ROOT}" && git rev-parse --short HEAD)"
write_report "validation_user" "${VALIDATION_USER}"
write_report "work_root" "${WORK_ROOT}"
write_report "listen_port" "${LISTEN_PORT}"

log "verifying target mailbox layout for validation user"
doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
  mailbox list -u "${VALIDATION_USER}" | grep -Fxq "INBOX" || {
  fail "validation mailbox INBOX does not exist for ${VALIDATION_USER}"
}
write_report "validation_mailbox" "present"

log "building current OSMAP tree"
cd "${PROJECT_ROOT}"
TMPDIR="${TMPDIR_PATH}" \
  CARGO_HOME="${CARGO_HOME_PATH}" \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR_PATH}" \
  cargo build --quiet
doas install -o _osmap -g _osmap -m 755 "${CARGO_TARGET_DIR_PATH}/debug/osmap" "${BIN_PATH}"
write_report "build_result" "passed"

log "writing synthetic validated session"
doas sh -c "cat > '${SESSION_DIR}/${SESSION_ID}.session' <<'EOF'
session_id=${SESSION_ID}
csrf_token=${CSRF_TOKEN}
canonical_username=${VALIDATION_USER}
issued_at=${NOW}
expires_at=${EXPIRES_AT}
last_seen_at=${NOW}
revoked_at=
remote_addr=127.0.0.1
user_agent=${USER_AGENT}
factor=totp
EOF
chmod 600 '${SESSION_DIR}/${SESSION_ID}.session'
chown _osmap:_osmap '${SESSION_DIR}/${SESSION_ID}.session'"

log "writing isolated helper request grant keys"
GRANT_KEY="$(openssl rand -base64 48)"
doas sh -c "cat > '${WEB_GRANT_KEY_PATH}' <<'EOF'
${GRANT_KEY}
EOF
chmod 600 '${WEB_GRANT_KEY_PATH}'
chown _osmap:_osmap '${WEB_GRANT_KEY_PATH}'
cat > '${HELPER_GRANT_KEY_PATH}' <<'EOF'
${GRANT_KEY}
EOF
chmod 600 '${HELPER_GRANT_KEY_PATH}'
chown vmail:vmail '${HELPER_GRANT_KEY_PATH}'"

log "starting enforced mailbox helper as vmail"
doas -u vmail sh -c "
  umask 077
  echo \$\$ > '${HELPER_PID_PATH}'
  exec env \
    OSMAP_RUN_MODE=mailbox-helper \
    OSMAP_ENV=production \
    OSMAP_STATE_DIR='${STATE_ROOT}' \
    OSMAP_RUNTIME_DIR='${HELPER_STATE_RUNTIME_DIR}' \
    OSMAP_SESSION_DIR='${SESSION_DIR}' \
    OSMAP_SETTINGS_DIR='${SETTINGS_DIR}' \
    OSMAP_AUDIT_DIR='${AUDIT_DIR}' \
    OSMAP_CACHE_DIR='${CACHE_DIR}' \
    OSMAP_TOTP_SECRET_DIR='${TOTP_DIR}' \
    OSMAP_MAILBOX_HELPER_SOCKET_PATH='${HELPER_SOCKET_PATH}' \
    OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH='${HELPER_GRANT_KEY_PATH}' \
    OSMAP_DOVEADM_AUTH_SOCKET_PATH='${AUTH_SOCKET_PATH}' \
    OSMAP_TRUSTED_WEB_RUNTIME_UID='${TRUSTED_WEB_RUNTIME_UID}' \
    OSMAP_DOVEADM_USERDB_SOCKET_PATH='${USERDB_SOCKET_PATH}' \
    OSMAP_LOG_LEVEL=info \
    OSMAP_OPENBSD_CONFINEMENT_MODE=enforce \
    '${BIN_PATH}' >'${HELPER_LOG_PATH}' 2>&1
" &

wait_for_helper_socket() {
  tries=0
  while [ "${tries}" -lt 20 ]; do
    if doas test -S "${HELPER_SOCKET_PATH}"; then
      doas chown vmail:_osmap "${HELPER_SOCKET_PATH}"
      doas chmod 660 "${HELPER_SOCKET_PATH}"
      write_report "helper_runtime_result" "passed"
      return 0
    fi
    sleep 1
    tries="$((tries + 1))"
  done

  [ -f "${HELPER_LOG_PATH}" ] && doas tail -n 40 "${HELPER_LOG_PATH}" || true
  fail "mailbox helper did not become ready"
}

log "starting enforced browser runtime as _osmap"
doas -u _osmap sh -c "
  umask 077
  echo \$\$ > '${HTTP_PID_PATH}'
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
    OSMAP_MAILBOX_HELPER_SOCKET_PATH='${HELPER_SOCKET_PATH}' \
    OSMAP_MAILBOX_HELPER_GRANT_KEY_PATH='${WEB_GRANT_KEY_PATH}' \
    OSMAP_LOG_LEVEL=info \
    OSMAP_SESSION_LIFETIME_SECS=3600 \
    OSMAP_OPENBSD_CONFINEMENT_MODE=enforce \
    '${BIN_PATH}' >'${HTTP_LOG_PATH}' 2>&1
" &

wait_for_healthz() {
  tries=0
  while [ "${tries}" -lt 40 ]; do
    response="$(
      {
        printf 'GET /healthz HTTP/1.1\r\n'
        printf 'Host: 127.0.0.1\r\n'
        printf 'Connection: close\r\n'
        printf '\r\n'
      } | nc -N 127.0.0.1 "${LISTEN_PORT}" 2>/dev/null || true
    )"

    if printf '%s' "${response}" | grep -q '^HTTP/1.1 200 OK'; then
      write_report "browser_runtime_result" "passed"
      write_report "healthz_status" "HTTP/1.1 200 OK"
      return 0
    fi

    sleep 1
    tries="$((tries + 1))"
  done

  [ -f "${HTTP_LOG_PATH}" ] && doas tail -n 40 "${HTTP_LOG_PATH}" || true
  fail "http runtime did not become ready"
}

request_get() {
  path_value="$1"
  {
    printf 'GET %s HTTP/1.1\r\n' "${path_value}"
    printf 'Host: 127.0.0.1\r\n'
    printf 'User-Agent: %s\r\n' "${USER_AGENT}"
    printf 'Cookie: osmap_session=%s\r\n' "${SESSION_TOKEN}"
    printf 'Connection: close\r\n'
    printf '\r\n'
  } | nc -N 127.0.0.1 "${LISTEN_PORT}"
}

status_line() {
  printf '%s' "$1" | sed -n '1p' | tr -d '\r'
}

response_body() {
  printf '%s' "$1" | awk '
    BEGIN { body = 0 }
    /^\r?$/ { body = 1; next }
    body { gsub("\r", ""); print }
  '
}

response_headers() {
  printf '%s' "$1" | awk '
    BEGIN { body = 0 }
    /^\r?$/ { body = 1 }
    body == 0 { gsub("\r", ""); print }
  '
}

lookup_uid() {
  mailbox_name="$1"
  subject="$2"

  doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
    search -u "${VALIDATION_USER}" mailbox "${mailbox_name}" header Subject "${subject}" \
    | awk 'NF > 0 { print $NF; exit }'
}

wait_for_message_location() {
  label="$1"
  subject="$2"

  found_mailbox=""
  found_uid=""
  tries=0

  while [ -z "${found_uid}" ] && [ "${tries}" -lt 30 ]; do
    for mailbox_name in INBOX Junk; do
      found_uid="$(lookup_uid "${mailbox_name}" "${subject}" || true)"
      if [ -n "${found_uid}" ]; then
        found_mailbox="${mailbox_name}"
        break
      fi
    done

    [ -n "${found_uid}" ] || sleep 1
    tries="$((tries + 1))"
  done

  [ -n "${found_uid}" ] || fail "failed to locate injected ${label} message uid"

  write_report "${label}_mailbox" "${found_mailbox}"
  write_report "${label}_uid" "${found_uid}"
  printf '%s:%s\n' "${found_mailbox}" "${found_uid}"
}

assert_contains() {
  label="$1"
  haystack="$2"
  needle="$3"

  printf '%s' "${haystack}" | grep -Fq "${needle}" || fail "${label} missing expected marker"
  write_report "${label}" "present"
}

assert_absent() {
  label="$1"
  haystack="$2"
  needle="$3"

  if printf '%s' "${haystack}" | grep -Fq "${needle}"; then
    fail "${label} contained forbidden marker"
  fi
  write_report "${label}" "absent"
}

assert_status_ok() {
  label="$1"
  status="$2"

  [ "${status}" = "HTTP/1.1 200 OK" ] || fail "${label} status was ${status}"
  write_report "${label}_status" "${status}"
}

cleanup_one_subject() {
  subject="$1"
  [ -n "${subject}" ] || return 0

  for mailbox_name in INBOX Junk; do
    doas -u vmail /usr/local/bin/doveadm -o stats_writer_socket_path= \
      expunge -u "${VALIDATION_USER}" mailbox "${mailbox_name}" header Subject "${subject}" \
      >/dev/null 2>&1 || true
  done
}

HTML_SUBJECT="OSMAP V4 hostile HTML proof ${NOW}-$$"
HTML_SAFE_TEXT="v4 safe visible hostile-content text ${NOW}-$$"
HTML_REMOTE_MARKER="evil-v4-proof.example"
HTML_SECRET_MARKER="v4-secret-marker-${NOW}-$$"
HTML_SRC_DOC_MARKER="v4-srcdoc-marker-${NOW}-$$"

ATTACHMENT_SUBJECT="OSMAP V4 executable attachment proof ${NOW}-$$"
ATTACHMENT_BOUNDARY="osmap-v4-attachment-${NOW}-$$"
HTML_ATTACHMENT_MARKER="v4 html attachment marker ${NOW}-$$"
SVG_ATTACHMENT_MARKER="v4 svg attachment marker ${NOW}-$$"
SCRIPT_ATTACHMENT_MARKER="v4 script attachment marker ${NOW}-$$"

inject_hostile_html_message() {
  {
    printf 'From: OSMAP V4 Hostile HTML Proof <%s>\n' "${VALIDATION_USER}"
    printf 'To: %s\n' "${VALIDATION_USER}"
    printf 'Subject: %s\n' "${HTML_SUBJECT}"
    printf 'MIME-Version: 1.0\n'
    printf 'Content-Type: text/html; charset=utf-8\n'
    printf '\n'
    printf '<html><head>'
    printf '<meta http-equiv="refresh" content="0; url=https://%s/">\n' "${HTML_REMOTE_MARKER}"
    printf '<style>@import url("https://%s/style.css");</style>' "${HTML_REMOTE_MARKER}"
    printf '</head><body>'
    printf '<p style="background-image:url(https://%s/bg.png)" onclick="alert(1)">%s</p>' "${HTML_REMOTE_MARKER}" "${HTML_SAFE_TEXT}"
    printf '<a href="https://example.com/v4-safe">safe link</a>'
    printf '<a href="JaVaScRiPt:alert(1)">mixed case javascript</a>'
    printf '<a href="&#x6a;avascript:alert(1)">entity javascript</a>'
    printf '<a href="blob:https://example.com/id">blob link</a>'
    printf '<a href="vbscript:msgbox(1)">vbscript link</a>'
    printf '<a href="file:///etc/passwd">file link</a>'
    printf '<a href="/relative/path">relative link</a>'
    printf '<a href="//%s/protocol-relative">protocol relative link</a>' "${HTML_REMOTE_MARKER}"
    printf '<a href="cid:logo@example.com">cid link</a>'
    printf '<a href="data:text/html;base64,PHNjcmlwdA==">data link</a>'
    printf '<form action="https://%s/post"><input autofocus onfocus="alert(1)" name="secret" value="%s"></form>' "${HTML_REMOTE_MARKER}" "${HTML_SECRET_MARKER}"
    printf '<iframe srcdoc="<script>%s</script>">srcdoc text</iframe>' "${HTML_SRC_DOC_MARKER}"
    printf '<svg><script>alert(1)</script><text>svg text</text></svg>'
    printf '<math><mi>math text</mi></math>'
    printf '<object data="https://%s/object">object text</object>' "${HTML_REMOTE_MARKER}"
    printf '<embed src="https://%s/embed">' "${HTML_REMOTE_MARKER}"
    printf '<template><p>template text</p></template>'
    printf '<video poster="https://%s/poster.png"><source src="https://%s/movie.mp4"></video>' "${HTML_REMOTE_MARKER}" "${HTML_REMOTE_MARKER}"
    printf '<audio src="https://%s/sound.mp3"></audio>' "${HTML_REMOTE_MARKER}"
    printf '<img src="https://%s/tracker.png">' "${HTML_REMOTE_MARKER}"
    printf '</body></html>\n'
  } | /usr/sbin/sendmail -t
}

inject_executable_attachment_message() {
  {
    printf 'From: OSMAP V4 Attachment Proof <%s>\n' "${VALIDATION_USER}"
    printf 'To: %s\n' "${VALIDATION_USER}"
    printf 'Subject: %s\n' "${ATTACHMENT_SUBJECT}"
    printf 'MIME-Version: 1.0\n'
    printf 'Content-Type: multipart/mixed; boundary="%s"\n' "${ATTACHMENT_BOUNDARY}"
    printf '\n'
    printf -- '--%s\n' "${ATTACHMENT_BOUNDARY}"
    printf 'Content-Type: text/plain; charset=utf-8\n'
    printf '\n'
    printf 'V4 executable attachment proof text.\n'
    printf -- '--%s\n' "${ATTACHMENT_BOUNDARY}"
    printf 'Content-Type: text/html\n'
    printf 'Content-Disposition: attachment; filename="v4-active.html"\n'
    printf '\n'
    printf '<html><script>%s</script></html>\n' "${HTML_ATTACHMENT_MARKER}"
    printf -- '--%s\n' "${ATTACHMENT_BOUNDARY}"
    printf 'Content-Type: image/svg+xml\n'
    printf 'Content-Disposition: attachment; filename="v4-active.svg"\n'
    printf '\n'
    printf '<svg><script>%s</script></svg>\n' "${SVG_ATTACHMENT_MARKER}"
    printf -- '--%s\n' "${ATTACHMENT_BOUNDARY}"
    printf 'Content-Type: application/javascript\n'
    printf 'Content-Disposition: attachment; filename="v4-active.js"\n'
    printf '\n'
    printf 'console.log("%s");\n' "${SCRIPT_ATTACHMENT_MARKER}"
    printf -- '--%s--\n' "${ATTACHMENT_BOUNDARY}"
  } | /usr/sbin/sendmail -t
}

assert_attachment_octet_stream() {
  label="$1"
  mailbox_name="$2"
  uid="$3"
  part_path="$4"
  filename="$5"
  marker="$6"

  response="$(request_get "/attachment?mailbox=${mailbox_name}&uid=${uid}&part=${part_path}")"
  printf '%s' "${response}" > "${WORK_ROOT}/${label}-attachment-response.txt"
  status="$(status_line "${response}")"
  headers="$(response_headers "${response}")"

  assert_status_ok "${label}_download" "${status}"
  assert_contains "${label}_forced_download" "${headers}" "Content-Disposition: attachment; filename=\"${filename}\""
  assert_contains "${label}_octet_stream" "${headers}" "Content-Type: application/octet-stream"
  assert_contains "${label}_nosniff" "${headers}" "X-Content-Type-Options: nosniff"
  assert_contains "${label}_corp" "${headers}" "Cross-Origin-Resource-Policy: same-origin"

  if doas grep -Fq "${marker}" "${HTTP_LOG_PATH}" 2>/dev/null; then
    fail "audit log contained ${label} attachment marker"
  fi
  write_report "${label}_body_marker_audit_leakage" "absent"
}

wait_for_helper_socket
wait_for_healthz

log "injecting V4 hostile HTML proof message"
inject_hostile_html_message
write_report "hostile_html_injection" "attempted"

html_location="$(wait_for_message_location hostile_html "${HTML_SUBJECT}")"
html_mailbox="${html_location%%:*}"
html_uid="${html_location#*:}"

log "validating V4 hostile HTML message view"
html_response="$(request_get "/message?mailbox=${html_mailbox}&uid=${html_uid}")"
printf '%s' "${html_response}" > "${WORK_ROOT}/hostile-html-response.txt"
html_status="$(status_line "${html_response}")"
html_body="$(response_body "${html_response}")"

assert_status_ok "hostile_html_message_view" "${html_status}"
assert_contains "hostile_html_sanitized_mode" "${html_body}" "<dd>sanitized_html</dd>"
assert_contains "hostile_html_safe_text" "${html_body}" "${HTML_SAFE_TEXT}"
assert_contains "hostile_html_safe_link" "${html_body}" 'href="https://example.com/v4-safe"'
assert_contains "hostile_html_link_rel" "${html_body}" 'rel="noopener noreferrer nofollow"'
assert_contains "hostile_html_destination_disclosure_css" "${html_response}" '.message-html a[href]::after'
assert_contains "hostile_html_destination_disclosure_attr" "${html_response}" 'attr(href)'
assert_absent "hostile_html_remote_marker" "${html_body}" "${HTML_REMOTE_MARKER}"
assert_absent "hostile_html_secret_marker" "${html_body}" "${HTML_SECRET_MARKER}"
assert_absent "hostile_html_srcdoc_marker" "${html_body}" "${HTML_SRC_DOC_MARKER}"
assert_absent "hostile_html_javascript_scheme" "${html_body}" 'href="javascript:'
assert_absent "hostile_html_mixed_javascript_scheme" "${html_body}" 'href="JaVaScRiPt:'
assert_absent "hostile_html_blob_scheme" "${html_body}" 'href="blob:'
assert_absent "hostile_html_vbscript_scheme" "${html_body}" 'href="vbscript:'
assert_absent "hostile_html_file_scheme" "${html_body}" 'href="file:'
assert_absent "hostile_html_data_scheme" "${html_body}" 'href="data:'
assert_absent "hostile_html_cid_scheme" "${html_body}" 'href="cid:'
assert_absent "hostile_html_relative_url" "${html_body}" 'href="/relative/path"'
assert_absent "hostile_html_protocol_relative_url" "${html_body}" 'protocol-relative'
assert_absent "hostile_html_form_action_payload" "${html_body}" "https://${HTML_REMOTE_MARKER}/post"
assert_absent "hostile_html_input_secret_payload" "${html_body}" "name=\"secret\""
assert_absent "hostile_html_iframe_payload" "${html_body}" "<iframe"
assert_absent "hostile_html_svg_payload" "${html_body}" "<svg"
assert_absent "hostile_html_math_payload" "${html_body}" "<math"
assert_absent "hostile_html_object_payload" "${html_body}" "<object"
assert_absent "hostile_html_embed_payload" "${html_body}" "<embed"
assert_absent "hostile_html_template_payload" "${html_body}" "<template"
assert_absent "hostile_html_video_payload" "${html_body}" "<video"
assert_absent "hostile_html_audio_payload" "${html_body}" "<audio"
assert_absent "hostile_html_source_payload" "${html_body}" "<source"
assert_absent "hostile_html_img_payload" "${html_body}" "<img"
assert_absent "hostile_html_autofocus_payload" "${html_body}" "autofocus"
assert_absent "hostile_html_onfocus_payload" "${html_body}" "onfocus"

if doas grep -Fq "${HTML_SAFE_TEXT}" "${HTTP_LOG_PATH}" 2>/dev/null; then
  fail "audit log contained hostile HTML body marker"
fi
write_report "hostile_html_body_marker_audit_leakage" "absent"

log "injecting V4 executable attachment proof message"
inject_executable_attachment_message
write_report "executable_attachment_injection" "attempted"

attachment_location="$(wait_for_message_location executable_attachment "${ATTACHMENT_SUBJECT}")"
attachment_mailbox="${attachment_location%%:*}"
attachment_uid="${attachment_location#*:}"

log "validating V4 executable attachment message view"
attachment_response="$(request_get "/message?mailbox=${attachment_mailbox}&uid=${attachment_uid}")"
printf '%s' "${attachment_response}" > "${WORK_ROOT}/executable-attachment-response.txt"
attachment_status="$(status_line "${attachment_response}")"
attachment_body="$(response_body "${attachment_response}")"

assert_status_ok "executable_attachment_message_view" "${attachment_status}"
assert_contains "html_attachment_filename" "${attachment_body}" "v4-active.html"
assert_contains "svg_attachment_filename" "${attachment_body}" "v4-active.svg"
assert_contains "script_attachment_filename" "${attachment_body}" "v4-active.js"
assert_contains "html_attachment_link" "${attachment_body}" "/attachment?mailbox=${attachment_mailbox}&amp;uid=${attachment_uid}&amp;part=1.2"
assert_contains "svg_attachment_link" "${attachment_body}" "/attachment?mailbox=${attachment_mailbox}&amp;uid=${attachment_uid}&amp;part=1.3"
assert_contains "script_attachment_link" "${attachment_body}" "/attachment?mailbox=${attachment_mailbox}&amp;uid=${attachment_uid}&amp;part=1.4"

log "validating V4 executable attachment download hardening"
assert_attachment_octet_stream "html_attachment" "${attachment_mailbox}" "${attachment_uid}" "1.2" "v4-active.html" "${HTML_ATTACHMENT_MARKER}"
assert_attachment_octet_stream "svg_attachment" "${attachment_mailbox}" "${attachment_uid}" "1.3" "v4-active.svg" "${SVG_ATTACHMENT_MARKER}"
assert_attachment_octet_stream "script_attachment" "${attachment_mailbox}" "${attachment_uid}" "1.4" "v4-active.js" "${SCRIPT_ATTACHMENT_MARKER}"

cleanup_one_subject "${HTML_SUBJECT}"
cleanup_one_subject "${ATTACHMENT_SUBJECT}"
write_report "message_cleanup" "attempted"

for forbidden in \
  "${SESSION_TOKEN}" \
  "${CSRF_TOKEN}" \
  "${HTML_SECRET_MARKER}" \
  "${HTML_SRC_DOC_MARKER}" \
  "${HTML_ATTACHMENT_MARKER}" \
  "${SVG_ATTACHMENT_MARKER}" \
  "${SCRIPT_ATTACHMENT_MARKER}"
do
  if grep -Fq "${forbidden}" "${REPORT_PATH}"; then
    fail "sanitized report contained forbidden secret or body marker"
  fi
done

write_report "secret_review" "No password, TOTP material, session cookie, CSRF token, private message body, attachment body, provider secret, or host secret is included."
write_report "result" "v4_hostile_content_live_proof_passed"

log "live V4 hostile-content proof passed"
log "report=${REPORT_PATH}"
