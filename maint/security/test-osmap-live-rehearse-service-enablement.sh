#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_wrapper="${repo_root}/maint/live/osmap-live-rehearse-service-enablement.ksh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-service-enablement-test.XXXXXX")
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
  "${fake_repo}/maint/openbsd/libexec" \
  "${fake_repo}/maint/openbsd/rc.d" \
  "${fake_repo}/maint/openbsd/mail.blackbagsecurity.com/etc/osmap" \
  "${fake_live_etc_dir}/osmap" \
  "${fake_live_etc_dir}/rc.d" \
  "${fake_live_usr_local_dir}/bin" \
  "${fake_live_usr_local_dir}/libexec/osmap" \
  "${fake_live_var_lib_dir}" \
  "${fake_bin_dir}"

cp "${source_wrapper}" "${fake_repo}/maint/live/osmap-live-rehearse-service-enablement.ksh"

cat > "${fake_repo}/maint/openbsd/mail.blackbagsecurity.com/etc/osmap/osmap-serve.env" <<'EOF'
reviewed-serve-env
EOF

cat > "${fake_repo}/maint/openbsd/mail.blackbagsecurity.com/etc/osmap/osmap-mailbox-helper.env" <<'EOF'
reviewed-helper-env
EOF

cat > "${fake_repo}/maint/openbsd/libexec/osmap-serve-run.ksh" <<'EOF'
reviewed-serve-run
EOF

cat > "${fake_repo}/maint/openbsd/libexec/osmap-mailbox-helper-run.ksh" <<'EOF'
reviewed-helper-run
EOF

cat > "${fake_repo}/maint/openbsd/rc.d/osmap_serve" <<'EOF'
reviewed-serve-rc
EOF

cat > "${fake_repo}/maint/openbsd/rc.d/osmap_mailbox_helper" <<'EOF'
reviewed-helper-rc
EOF

cat > "${fake_live_etc_dir}/osmap/osmap-serve.env" <<'EOF'
live-serve-env
EOF

cat > "${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" <<'EOF'
live-serve-run
EOF

cat > "${fake_live_etc_dir}/rc.d/osmap_serve" <<'EOF'
live-serve-rc
EOF

cat > "${fake_live_etc_dir}/group" <<'EOF'
osmaprt:*:3000:_osmap
EOF

cat > "${fake_live_usr_local_dir}/bin/osmap" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "${fake_live_usr_local_dir}/bin/osmap"

cat > "${fake_bin_dir}/doas" <<'EOF'
#!/bin/sh
if [ "$1" = "test" ]; then
  shift
  exec test "$@"
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

cat > "${fake_bin_dir}/rcctl" <<'EOF'
#!/bin/sh
printf '%s\n' "rcctl $*" >> "${OSMAP_TEST_SERVICE_ENABLEMENT_LOG_FILE:?}"
exit 0
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

cat > "${fake_bin_dir}/date" <<'EOF'
#!/bin/sh
printf '%s\n' '20260417-120000'
EOF

chmod +x \
  "${fake_bin_dir}/doas" \
  "${fake_bin_dir}/install" \
  "${fake_bin_dir}/rcctl" \
  "${fake_bin_dir}/id" \
  "${fake_bin_dir}/date"

assert_contains() {
  haystack=$1
  needle=$2
  printf '%s' "${haystack}" | grep -Fq "${needle}" || {
    printf 'expected to find "%s" in output:\n%s\n' "${needle}" "${haystack}" >&2
    exit 1
  }
}

assert_file_equals() {
  file_path=$1
  expected=$2
  [ "$(cat "${file_path}")" = "${expected}" ] || {
    printf 'unexpected contents in %s\nexpected:\n%s\nactual:\n%s\n' "${file_path}" "${expected}" "$(cat "${file_path}")" >&2
    exit 1
  }
}

log_file="${tmp_root}/service-enablement-commands.log"

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
    OSMAP_TEST_SERVICE_ENABLEMENT_LOG_FILE="${log_file}" \
    HOME="${tmp_root}" \
    sh "${fake_repo}/maint/live/osmap-live-rehearse-service-enablement.ksh" --session-dir "${session_dir}"
)

assert_contains "${rehearsal_output}" "prepared service enablement session in ${session_dir}"
assert_contains "${rehearsal_output}" "apply script: ${session_dir}/scripts/apply-service-enablement.sh"
assert_contains "${rehearsal_output}" "restore script: ${session_dir}/scripts/restore-service-enablement.sh"

assert_file_equals "${session_dir}/backup/etc/osmap/osmap-serve.env" "live-serve-env"
assert_file_equals "${session_dir}/backup/usr/local/libexec/osmap/osmap-serve-run.ksh" "live-serve-run"
assert_file_equals "${session_dir}/backup/etc/rc.d/osmap_serve" "live-serve-rc"
assert_file_equals "${session_dir}/staged/etc/osmap/osmap-serve.env" "reviewed-serve-env"
assert_file_equals "${session_dir}/staged/etc/osmap/osmap-mailbox-helper.env" "reviewed-helper-env"
assert_file_equals "${session_dir}/staged/usr/local/libexec/osmap/osmap-serve-run.ksh" "reviewed-serve-run"
assert_file_equals "${session_dir}/staged/usr/local/libexec/osmap/osmap-mailbox-helper-run.ksh" "reviewed-helper-run"
assert_file_equals "${session_dir}/staged/etc/rc.d/osmap_serve" "reviewed-serve-rc"
assert_file_equals "${session_dir}/staged/etc/rc.d/osmap_mailbox_helper" "reviewed-helper-rc"

report_contents=$(cat "${session_dir}/service-enablement-session.txt")
assert_contains "${report_contents}" "osmap_service_enablement_session_mode=rehearse"
assert_contains "${report_contents}" "shared_runtime_group=osmaprt"
assert_contains "${report_contents}" "apply_script=${session_dir}/scripts/apply-service-enablement.sh"
assert_contains "${report_contents}" "restore_script=${session_dir}/scripts/restore-service-enablement.sh"

env PATH="${fake_bin_dir}:${PATH}" OSMAP_TEST_SERVICE_ENABLEMENT_LOG_FILE="${log_file}" sh "${session_dir}/scripts/apply-service-enablement.sh"

assert_file_equals "${fake_live_etc_dir}/osmap/osmap-serve.env" "reviewed-serve-env"
assert_file_equals "${fake_live_etc_dir}/osmap/osmap-mailbox-helper.env" "reviewed-helper-env"
assert_file_equals "${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" "reviewed-serve-run"
assert_file_equals "${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" "reviewed-helper-run"
assert_file_equals "${fake_live_etc_dir}/rc.d/osmap_serve" "reviewed-serve-rc"
assert_file_equals "${fake_live_etc_dir}/rc.d/osmap_mailbox_helper" "reviewed-helper-rc"

apply_log=$(cat "${log_file}")
assert_contains "${apply_log}" "rcctl configtest osmap_mailbox_helper"
assert_contains "${apply_log}" "rcctl start osmap_mailbox_helper"
assert_contains "${apply_log}" "rcctl check osmap_mailbox_helper"
assert_contains "${apply_log}" "rcctl configtest osmap_serve"
assert_contains "${apply_log}" "rcctl start osmap_serve"
assert_contains "${apply_log}" "rcctl check osmap_serve"

: > "${log_file}"
env PATH="${fake_bin_dir}:${PATH}" OSMAP_TEST_SERVICE_ENABLEMENT_LOG_FILE="${log_file}" sh "${session_dir}/scripts/restore-service-enablement.sh"

assert_file_equals "${fake_live_etc_dir}/osmap/osmap-serve.env" "live-serve-env"
[ ! -f "${fake_live_etc_dir}/osmap/osmap-mailbox-helper.env" ] || {
  printf 'expected helper env to be removed during restore\n' >&2
  exit 1
}
assert_file_equals "${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" "live-serve-run"
[ ! -f "${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" ] || {
  printf 'expected helper run script to be removed during restore\n' >&2
  exit 1
}
assert_file_equals "${fake_live_etc_dir}/rc.d/osmap_serve" "live-serve-rc"
[ ! -f "${fake_live_etc_dir}/rc.d/osmap_mailbox_helper" ] || {
  printf 'expected helper rc script to be removed during restore\n' >&2
  exit 1
}

restore_log=$(cat "${log_file}")
assert_contains "${restore_log}" "rcctl stop osmap_serve"
assert_contains "${restore_log}" "rcctl stop osmap_mailbox_helper"

printf '%s\n' "service enablement rehearsal regression checks passed"
