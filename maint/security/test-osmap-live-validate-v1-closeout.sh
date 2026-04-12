#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_wrapper="${repo_root}/maint/live/osmap-live-validate-v1-closeout.ksh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-closeout-local-test.XXXXXX")
fake_repo="${tmp_root}/repo"
fake_live_dir="${fake_repo}/maint/live"
bin_dir="${tmp_root}/bin"
log_dir="${tmp_root}/log"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p "${fake_live_dir}" "${bin_dir}" "${log_dir}"
cp "${source_wrapper}" "${fake_live_dir}/osmap-live-validate-v1-closeout.ksh"

cat > "${bin_dir}/ksh" <<'EOF'
#!/bin/sh
exec sh "$@"
EOF
chmod +x "${bin_dir}/ksh"

write_stub() {
  stub_path=$1

  cat > "${stub_path}" <<'EOF'
#!/bin/sh

set -eu

log_file=${OSMAP_TEST_CLOSEOUT_LOG_FILE:?}
script_name=$(basename "$0")

if [ "$#" -eq 0 ]; then
  printf '%s\n' "${script_name}" >> "${log_file}"
else
  printf '%s %s\n' "${script_name}" "$*" >> "${log_file}"
fi
EOF

  chmod +x "${stub_path}"
}

write_stub "${fake_live_dir}/osmap-host-validate.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-login-send.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-all-mailbox-search.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-archive-shortcut.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-session-surface.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-send-throttle.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-move-throttle.ksh"

assert_contains() {
  haystack=$1
  needle=$2

  printf '%s' "${haystack}" | grep -Fq "${needle}" || {
    printf 'expected to find "%s" in output:\n%s\n' "${needle}" "${haystack}" >&2
    exit 1
  }
}

assert_equals() {
  left=$1
  right=$2

  [ "${left}" = "${right}" ] || {
    printf 'expected:\n%s\nactual:\n%s\n' "${right}" "${left}" >&2
    exit 1
  }
}

list_output=$(
  PATH="${bin_dir}:${PATH}" \
    sh "${fake_live_dir}/osmap-live-validate-v1-closeout.ksh" --list
)
assert_equals "${list_output}" "security-check
login-send
all-mailbox-search
archive-shortcut
session-surface
send-throttle
move-throttle"

default_log="${log_dir}/default-invocations.txt"
default_report="${fake_live_dir}/osmap-live-validate-v1-closeout-report.txt"
default_output=$(
  env \
    PATH="${bin_dir}:${PATH}" \
    OSMAP_TEST_CLOSEOUT_LOG_FILE="${default_log}" \
    OSMAP_VALIDATION_PASSWORD="local-wrapper-test-secret" \
    sh "${fake_live_dir}/osmap-live-validate-v1-closeout.ksh"
)

assert_contains "${default_output}" "running Version 1 closeout proof set from ${fake_repo}"
assert_contains "${default_output}" "wrote closeout report to ${default_report}"
assert_contains "${default_output}" "Version 1 closeout proof set passed"

default_invocations=$(cat "${default_log}")
assert_equals "${default_invocations}" "osmap-host-validate.ksh make security-check
osmap-live-validate-login-send.ksh
osmap-live-validate-all-mailbox-search.ksh
osmap-live-validate-archive-shortcut.ksh
osmap-live-validate-session-surface.ksh
osmap-live-validate-send-throttle.ksh
osmap-live-validate-move-throttle.ksh"

default_report_contents=$(cat "${default_report}")
assert_contains "${default_report_contents}" "osmap_v1_closeout_result=passed"
assert_contains "${default_report_contents}" "project_root=${fake_repo}"
assert_contains "${default_report_contents}" "step_count=7"
assert_contains "${default_report_contents}" "security-check=passed"
assert_contains "${default_report_contents}" "login-send=passed"
assert_contains "${default_report_contents}" "move-throttle=passed"

single_log="${log_dir}/single-invocations.txt"
single_report="${tmp_root}/single-report.txt"
single_output=$(
  env \
    PATH="${bin_dir}:${PATH}" \
    OSMAP_TEST_CLOSEOUT_LOG_FILE="${single_log}" \
    sh "${fake_live_dir}/osmap-live-validate-v1-closeout.ksh" --report "${single_report}" session-surface
)

assert_contains "${single_output}" "==> session-surface"
assert_contains "${single_output}" "wrote closeout report to ${single_report}"
single_invocations=$(cat "${single_log}")
assert_equals "${single_invocations}" "osmap-live-validate-session-surface.ksh"
single_report_contents=$(cat "${single_report}")
assert_contains "${single_report_contents}" "project_root=${fake_repo}"
assert_contains "${single_report_contents}" "step_count=1"
assert_contains "${single_report_contents}" "session-surface=passed"

printf '%s\n' "local closeout wrapper regression checks passed"
