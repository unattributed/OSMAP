#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_wrapper="${repo_root}/maint/live/osmap-live-rehearse-service-activation.ksh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-service-activation-test.XXXXXX")
fake_repo="${tmp_root}/repo"
fake_live_dir="${tmp_root}/live"
fake_live_etc_dir="${fake_live_dir}/etc"
fake_live_usr_local_dir="${fake_live_dir}/usr/local"
fake_live_var_lib_dir="${fake_live_dir}/var/lib"
fake_bin_dir="${tmp_root}/bin"
session_dir="${tmp_root}/session"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p \
  "${fake_repo}/maint/live" \
  "${fake_live_etc_dir}/osmap" \
  "${fake_live_etc_dir}/rc.d" \
  "${fake_live_usr_local_dir}/bin" \
  "${fake_live_usr_local_dir}/libexec/osmap" \
  "${fake_live_var_lib_dir}" \
  "${fake_bin_dir}"

cp "${source_wrapper}" "${fake_repo}/maint/live/osmap-live-rehearse-service-activation.ksh"

cat > "${fake_repo}/maint/live/osmap-live-validate-service-enablement.ksh" <<'EOF'
#!/bin/sh

set -eu

report_path=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --report)
      report_path=$2
      shift 2
      ;;
    --report=*)
      report_path=${1#--report=}
      shift
      ;;
    *)
      shift
      ;;
  esac
done

[ -n "${report_path}" ] || exit 1

root="${OSMAP_TEST_SERVICE_ACTIVATION_ROOT:?}"
failed_checks=

append_failed() {
  if [ -z "${failed_checks}" ]; then
    failed_checks=$1
  else
    failed_checks="${failed_checks}
$1"
  fi
}

[ -d "${root}/var/lib/osmap" ] || append_failed serve_state_dir_missing
[ -d "${root}/var/lib/osmap-helper" ] || append_failed helper_state_dir_missing
[ -f "${root}/run/mailbox-helper.sock" ] || append_failed missing_helper_socket
[ -f "${root}/run/http-listener.ready" ] || append_failed loopback_http_listener_not_ready
[ -f "${root}/run/helper-service.running" ] || append_failed mailbox_helper_service_not_healthy
[ -f "${root}/run/serve-service.running" ] || append_failed serve_service_not_healthy

{
  if [ -z "${failed_checks}" ]; then
    printf 'osmap_service_enablement_result=passed\n'
  else
    printf 'osmap_service_enablement_result=failed\n'
  fi
  printf 'failed_checks=\n'
  if [ -n "${failed_checks}" ]; then
    printf '%s\n' "${failed_checks}"
  fi
} > "${report_path}"

if [ -n "${failed_checks}" ]; then
  exit 1
fi
EOF

cat > "${fake_live_etc_dir}/osmap/osmap-serve.env" <<'EOF'
serve-env
EOF

cat > "${fake_live_etc_dir}/osmap/osmap-mailbox-helper.env" <<'EOF'
helper-env
EOF

cat > "${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" <<'EOF'
#!/bin/sh
exit 0
EOF

cat > "${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" <<'EOF'
#!/bin/sh
exit 0
EOF

cat > "${fake_live_etc_dir}/rc.d/osmap_serve" <<'EOF'
serve-rc
EOF

cat > "${fake_live_etc_dir}/rc.d/osmap_mailbox_helper" <<'EOF'
helper-rc
EOF

cat > "${fake_live_etc_dir}/group" <<'EOF'
osmaprt:*:3000:_osmap
EOF

cat > "${fake_live_usr_local_dir}/bin/osmap" <<'EOF'
#!/bin/sh
exit 0
EOF

cat > "${fake_bin_dir}/doas" <<'EOF'
#!/bin/sh
if [ "$1" = "test" ]; then
  shift
  exec test "$@"
fi
if [ "$1" = "id" ]; then
  shift
  exec id "$@"
fi
exec "$@"
EOF

cat > "${fake_bin_dir}/install" <<'EOF'
#!/bin/sh
set -eu

make_dir=0
mode=

while [ "$#" -gt 0 ]; do
  case "$1" in
    -d)
      make_dir=1
      shift
      ;;
    -m)
      mode=$2
      shift 2
      ;;
    -o|-g)
      shift 2
      ;;
    *)
      break
      ;;
  esac
done

if [ "$make_dir" = "1" ]; then
  for target in "$@"; do
    mkdir -p "$target"
    [ -z "$mode" ] || chmod "$mode" "$target"
  done
  exit 0
fi

src=$1
dest=$2
mkdir -p "$(dirname "$dest")"
rm -f "$dest"
cp "$src" "$dest"
[ -z "$mode" ] || chmod "$mode" "$dest"
EOF

cat > "${fake_bin_dir}/id" <<'EOF'
#!/bin/sh
case "$*" in
  "_osmap")
    printf '%s\n' 'uid=1001(_osmap) gid=1001(_osmap) groups=1001(_osmap),3000(osmaprt)'
    exit 0
    ;;
  "vmail")
    printf '%s\n' 'uid=2000(vmail) gid=2000(vmail) groups=2000(vmail)'
    exit 0
    ;;
  "-Gn _osmap")
    printf '%s\n' '_osmap osmaprt'
    exit 0
    ;;
esac
exit 1
EOF

cat > "${fake_bin_dir}/chgrp" <<'EOF'
#!/bin/sh
exit 0
EOF

cat > "${fake_bin_dir}/rcctl" <<'EOF'
#!/bin/sh
printf '%s\n' "rcctl $*" >> "${OSMAP_TEST_SERVICE_ACTIVATION_LOG_FILE:?}"
run_root="${OSMAP_TEST_SERVICE_ACTIVATION_ROOT:?}/run"
mkdir -p "${run_root}"
case "$1 $2" in
  "configtest osmap_mailbox_helper"|"configtest osmap_serve")
    exit 0
    ;;
  "start osmap_mailbox_helper")
    : > "${run_root}/helper-service.running"
    if [ "${OSMAP_TEST_SERVICE_ACTIVATION_SKIP_HELPER_SOCKET:-0}" != "1" ]; then
      : > "${run_root}/mailbox-helper.sock"
    fi
    exit 0
    ;;
  "start osmap_serve")
    : > "${run_root}/serve-service.running"
    if [ "${OSMAP_TEST_SERVICE_ACTIVATION_SKIP_HTTP_LISTENER:-0}" != "1" ]; then
      : > "${run_root}/http-listener.ready"
    fi
    exit 0
    ;;
  "check osmap_mailbox_helper")
    [ -f "${run_root}/helper-service.running" ]
    exit $?
    ;;
  "check osmap_serve")
    [ -f "${run_root}/serve-service.running" ]
    exit $?
    ;;
  "stop osmap_mailbox_helper")
    rm -f "${run_root}/helper-service.running" "${run_root}/mailbox-helper.sock"
    exit 0
    ;;
  "stop osmap_serve")
    rm -f "${run_root}/serve-service.running" "${run_root}/http-listener.ready"
    exit 0
    ;;
esac
exit 1
EOF

cat > "${fake_bin_dir}/date" <<'EOF'
#!/bin/sh
printf '%s\n' '20260418-100000'
EOF

cat > "${fake_bin_dir}/ksh" <<'EOF'
#!/bin/sh
exec sh "$@"
EOF

chmod +x \
  "${fake_repo}/maint/live/osmap-live-validate-service-enablement.ksh" \
  "${fake_live_usr_local_dir}/bin/osmap" \
  "${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" \
  "${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" \
  "${fake_bin_dir}/doas" \
  "${fake_bin_dir}/install" \
  "${fake_bin_dir}/id" \
  "${fake_bin_dir}/chgrp" \
  "${fake_bin_dir}/rcctl" \
  "${fake_bin_dir}/date" \
  "${fake_bin_dir}/ksh"

assert_contains() {
  haystack=$1
  needle=$2
  printf '%s' "${haystack}" | grep -Fq "${needle}" || {
    printf 'expected to find "%s" in output:\n%s\n' "${needle}" "${haystack}" >&2
    exit 1
  }
}

assert_file_contains() {
  file_path=$1
  needle=$2
  grep -Fq "${needle}" "${file_path}" || {
    printf 'expected to find "%s" in %s\n' "${needle}" "${file_path}" >&2
    exit 1
  }
}

log_file="${tmp_root}/service-activation-commands.log"

rehearsal_output=$(
  env \
    PATH="${fake_bin_dir}:${PATH}" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_BIN_PATH="${fake_live_usr_local_dir}/bin/osmap" \
    OSMAP_SERVICE_GROUP_FILE_PATH="${fake_live_etc_dir}/group" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-serve.env" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-mailbox-helper.env" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_serve" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_mailbox_helper" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_STATE_DIR="${fake_live_var_lib_dir}/osmap" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_RUNTIME_DIR="${fake_live_var_lib_dir}/osmap/run" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_SESSION_DIR="${fake_live_var_lib_dir}/osmap/sessions" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_SETTINGS_DIR="${fake_live_var_lib_dir}/osmap/settings" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_AUDIT_DIR="${fake_live_var_lib_dir}/osmap/audit" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_CACHE_DIR="${fake_live_var_lib_dir}/osmap/cache" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_TOTP_DIR="${fake_live_var_lib_dir}/osmap/secrets/totp" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_STATE_DIR="${fake_live_var_lib_dir}/osmap-helper" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUNTIME_DIR="${fake_live_var_lib_dir}/osmap-helper/run" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_SESSION_DIR="${fake_live_var_lib_dir}/osmap-helper/sessions" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_SETTINGS_DIR="${fake_live_var_lib_dir}/osmap-helper/settings" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_AUDIT_DIR="${fake_live_var_lib_dir}/osmap-helper/audit" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_CACHE_DIR="${fake_live_var_lib_dir}/osmap-helper/cache" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_TOTP_DIR="${fake_live_var_lib_dir}/osmap-helper/secrets/totp" \
    OSMAP_TEST_SERVICE_ACTIVATION_ROOT="${fake_live_dir}" \
    OSMAP_TEST_SERVICE_ACTIVATION_LOG_FILE="${log_file}" \
    HOME="${tmp_root}" \
    sh "${fake_repo}/maint/live/osmap-live-rehearse-service-activation.ksh" --session-dir "${session_dir}"
)

assert_contains "${rehearsal_output}" "prepared service activation session in ${session_dir}"
assert_contains "${rehearsal_output}" "apply script: ${session_dir}/scripts/apply-service-activation.sh"
assert_contains "${rehearsal_output}" "restore script: ${session_dir}/scripts/restore-service-activation.sh"

report_contents=$(cat "${session_dir}/service-activation-session.txt")
assert_contains "${report_contents}" "osmap_service_activation_session_mode=rehearse"
assert_contains "${report_contents}" "validator_report=${session_dir}/reports/service-enablement-after-service-activation.txt"

env \
  PATH="${fake_bin_dir}:${PATH}" \
  OSMAP_TEST_SERVICE_ACTIVATION_ROOT="${fake_live_dir}" \
  OSMAP_TEST_SERVICE_ACTIVATION_LOG_FILE="${log_file}" \
  sh "${session_dir}/scripts/apply-service-activation.sh"

[ -d "${fake_live_var_lib_dir}/osmap/run" ] || {
  printf 'expected serve runtime directory to be created\n' >&2
  exit 1
}
[ -d "${fake_live_var_lib_dir}/osmap-helper/run" ] || {
  printf 'expected helper runtime directory to be created\n' >&2
  exit 1
}

assert_file_contains "${session_dir}/reports/service-enablement-after-service-activation.txt" "osmap_service_enablement_result=passed"
apply_log=$(cat "${log_file}")
assert_contains "${apply_log}" "rcctl configtest osmap_mailbox_helper"
assert_contains "${apply_log}" "rcctl start osmap_mailbox_helper"
assert_contains "${apply_log}" "rcctl check osmap_mailbox_helper"
assert_contains "${apply_log}" "rcctl configtest osmap_serve"
assert_contains "${apply_log}" "rcctl start osmap_serve"
assert_contains "${apply_log}" "rcctl check osmap_serve"

: > "${log_file}"
env \
  PATH="${fake_bin_dir}:${PATH}" \
  OSMAP_TEST_SERVICE_ACTIVATION_ROOT="${fake_live_dir}" \
  OSMAP_TEST_SERVICE_ACTIVATION_LOG_FILE="${log_file}" \
  sh "${session_dir}/scripts/restore-service-activation.sh"

restore_log=$(cat "${log_file}")
assert_contains "${restore_log}" "rcctl stop osmap_serve"
assert_contains "${restore_log}" "rcctl stop osmap_mailbox_helper"

bad_session_dir="${tmp_root}/bad-session"
env \
  PATH="${fake_bin_dir}:${PATH}" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_BIN_PATH="${fake_live_usr_local_dir}/bin/osmap" \
  OSMAP_SERVICE_GROUP_FILE_PATH="${fake_live_etc_dir}/group" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-serve.env" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-mailbox-helper.env" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_serve" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_mailbox_helper" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_STATE_DIR="${fake_live_var_lib_dir}/osmap-bad" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_RUNTIME_DIR="${fake_live_var_lib_dir}/osmap-bad/run" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_SESSION_DIR="${fake_live_var_lib_dir}/osmap-bad/sessions" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_SETTINGS_DIR="${fake_live_var_lib_dir}/osmap-bad/settings" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_AUDIT_DIR="${fake_live_var_lib_dir}/osmap-bad/audit" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_CACHE_DIR="${fake_live_var_lib_dir}/osmap-bad/cache" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_TOTP_DIR="${fake_live_var_lib_dir}/osmap-bad/secrets/totp" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_STATE_DIR="${fake_live_var_lib_dir}/osmap-helper-bad" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUNTIME_DIR="${fake_live_var_lib_dir}/osmap-helper-bad/run" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_SESSION_DIR="${fake_live_var_lib_dir}/osmap-helper-bad/sessions" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_SETTINGS_DIR="${fake_live_var_lib_dir}/osmap-helper-bad/settings" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_AUDIT_DIR="${fake_live_var_lib_dir}/osmap-helper-bad/audit" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_CACHE_DIR="${fake_live_var_lib_dir}/osmap-helper-bad/cache" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_TOTP_DIR="${fake_live_var_lib_dir}/osmap-helper-bad/secrets/totp" \
  OSMAP_TEST_SERVICE_ACTIVATION_ROOT="${fake_live_dir}" \
  OSMAP_TEST_SERVICE_ACTIVATION_LOG_FILE="${log_file}" \
  HOME="${tmp_root}" \
  sh "${fake_repo}/maint/live/osmap-live-rehearse-service-activation.ksh" --session-dir "${bad_session_dir}" >/dev/null

bad_output=$(
  env \
    PATH="${fake_bin_dir}:${PATH}" \
    OSMAP_TEST_SERVICE_ACTIVATION_ROOT="${fake_live_dir}" \
    OSMAP_TEST_SERVICE_ACTIVATION_LOG_FILE="${log_file}" \
    OSMAP_TEST_SERVICE_ACTIVATION_SKIP_HELPER_SOCKET=1 \
    sh "${bad_session_dir}/scripts/apply-service-activation.sh" 2>&1 || true
)

assert_contains "${bad_output}" "service validator still reports missing_helper_socket after service activation"

printf '%s\n' "service activation rehearsal regression checks passed"
