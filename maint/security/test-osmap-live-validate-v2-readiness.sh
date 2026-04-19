#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_wrapper="${repo_root}/maint/live/osmap-live-validate-v2-readiness.ksh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v2-readiness-local-test.XXXXXX")
fake_repo="${tmp_root}/repo"
fake_live_dir="${fake_repo}/maint/live"
bin_dir="${tmp_root}/bin"
log_dir="${tmp_root}/log"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p "${fake_live_dir}" "${bin_dir}" "${log_dir}"
cp "${source_wrapper}" "${fake_live_dir}/osmap-live-validate-v2-readiness.ksh"

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

log_file=${OSMAP_TEST_V2_READINESS_LOG_FILE:?}
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
write_stub "${fake_live_dir}/osmap-live-validate-login-failure-normalization.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-all-mailbox-search.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-archive-shortcut.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-session-surface.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-send-throttle.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-move-throttle.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-helper-peer-auth.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-request-guardrails.ksh"
write_stub "${fake_live_dir}/osmap-live-validate-mailbox-backend-unavailable.ksh"

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
    sh "${fake_live_dir}/osmap-live-validate-v2-readiness.ksh" --list
)
assert_equals "${list_output}" "security-check
login-send
login-failure-normalization
all-mailbox-search
archive-shortcut
session-surface
send-throttle
move-throttle
helper-peer-auth
request-guardrails
mailbox-backend-unavailable"

default_log="${log_dir}/default-invocations.txt"
default_report="${fake_live_dir}/osmap-live-validate-v2-readiness-report.txt"
default_output=$(
  env \
    PATH="${bin_dir}:${PATH}" \
    OSMAP_TEST_V2_READINESS_LOG_FILE="${default_log}" \
    OSMAP_VALIDATION_PASSWORD="local-wrapper-test-secret" \
    OSMAP_V2_READINESS_SERVICE_GUARD=never \
    sh "${fake_live_dir}/osmap-live-validate-v2-readiness.ksh"
)

assert_contains "${default_output}" "running Version 2 readiness proof set from ${fake_repo}"
assert_contains "${default_output}" "wrote v2 readiness report to ${default_report}"
assert_contains "${default_output}" "Version 2 readiness proof set passed"

default_invocations=$(cat "${default_log}")
assert_equals "${default_invocations}" "osmap-host-validate.ksh make security-check
osmap-live-validate-login-send.ksh
osmap-live-validate-login-failure-normalization.ksh
osmap-live-validate-all-mailbox-search.ksh
osmap-live-validate-archive-shortcut.ksh
osmap-live-validate-session-surface.ksh
osmap-live-validate-send-throttle.ksh
osmap-live-validate-move-throttle.ksh
osmap-live-validate-helper-peer-auth.ksh
osmap-live-validate-request-guardrails.ksh
osmap-live-validate-mailbox-backend-unavailable.ksh"

default_report_contents=$(cat "${default_report}")
assert_contains "${default_report_contents}" "osmap_v2_readiness_result=passed"
assert_contains "${default_report_contents}" "project_root=${fake_repo}"
assert_contains "${default_report_contents}" "step_count=11"
assert_contains "${default_report_contents}" "service_guard_result=skipped"
assert_contains "${default_report_contents}" "login-failure-normalization=passed"
assert_contains "${default_report_contents}" "request-guardrails=passed"
assert_contains "${default_report_contents}" "mailbox-backend-unavailable=passed"

single_log="${log_dir}/single-invocations.txt"
single_report="${tmp_root}/single-v2-report.txt"
single_output=$(
  env \
    PATH="${bin_dir}:${PATH}" \
    OSMAP_TEST_V2_READINESS_LOG_FILE="${single_log}" \
    OSMAP_V2_READINESS_SERVICE_GUARD=never \
    sh "${fake_live_dir}/osmap-live-validate-v2-readiness.ksh" --report "${single_report}" helper-peer-auth request-guardrails
)

assert_contains "${single_output}" "==> helper-peer-auth"
assert_contains "${single_output}" "==> request-guardrails"
assert_contains "${single_output}" "wrote v2 readiness report to ${single_report}"
single_invocations=$(cat "${single_log}")
assert_equals "${single_invocations}" "osmap-live-validate-helper-peer-auth.ksh
osmap-live-validate-request-guardrails.ksh"
single_report_contents=$(cat "${single_report}")
assert_contains "${single_report_contents}" "project_root=${fake_repo}"
assert_contains "${single_report_contents}" "step_count=2"
assert_contains "${single_report_contents}" "helper-peer-auth=passed"
assert_contains "${single_report_contents}" "request-guardrails=passed"

write_stub "${fake_live_dir}/osmap-live-validate-service-enablement.ksh"

cat > "${bin_dir}/doas" <<EOF
#!/bin/sh
set -eu

log_file="${log_dir}/service-guard-doas.txt"
printf '%s\\n' "doas \$*" >> "\${log_file}"

case "\${1:-}" in
  test)
    shift
    if [ "\${1:-}" = "-x" ]; then
      exit 0
    fi
    ;;
  rcctl)
    shift
    exec rcctl "\$@"
    ;;
esac

exec "\$@"
EOF
chmod +x "${bin_dir}/doas"

cat > "${bin_dir}/rcctl" <<EOF
#!/bin/sh
set -eu

log_file="${log_dir}/service-guard-rcctl.txt"
helper_state="${log_dir}/helper-started"
serve_state="${log_dir}/serve-started"
printf '%s\\n' "rcctl \$*" >> "\${log_file}"

case "\${1:-}:\${2:-}" in
  check:osmap_mailbox_helper)
    test -f "\${helper_state}"
    ;;
  start:osmap_mailbox_helper)
    : > "\${helper_state}"
    ;;
  check:osmap_serve)
    test -f "\${serve_state}"
    ;;
  start:osmap_serve)
    : > "\${serve_state}"
    ;;
  *)
    exit 0
    ;;
esac
EOF
chmod +x "${bin_dir}/rcctl"

service_guard_log="${log_dir}/service-guard-invocations.txt"
service_guard_report="${tmp_root}/service-guard-v2-report.txt"
service_guard_output=$(
  env \
    PATH="${bin_dir}:${PATH}" \
    OSMAP_TEST_V2_READINESS_LOG_FILE="${service_guard_log}" \
    OSMAP_V2_READINESS_SERVICE_GUARD=always \
    OSMAP_V2_READINESS_SERVICE_GUARD_REPORT_PATH="${service_guard_report}.service-enablement" \
    sh "${fake_live_dir}/osmap-live-validate-v2-readiness.ksh" \
      --report "${service_guard_report}" helper-peer-auth
)

assert_contains "${service_guard_output}" "checking persistent OSMAP service health after readiness proof set"
assert_contains "${service_guard_output}" "persistent service osmap_mailbox_helper is not healthy; attempting rcctl start"
assert_contains "${service_guard_output}" "persistent service osmap_serve is not healthy; attempting rcctl start"
assert_contains "${service_guard_output}" "persistent OSMAP service guard passed"

service_guard_invocations=$(cat "${service_guard_log}")
assert_equals "${service_guard_invocations}" "osmap-live-validate-helper-peer-auth.ksh
osmap-live-validate-service-enablement.ksh --report ${service_guard_report}.service-enablement"

service_guard_report_contents=$(cat "${service_guard_report}")
assert_contains "${service_guard_report_contents}" "service_guard_result=passed"
assert_contains "${service_guard_report_contents}" "service_guard_report=${service_guard_report}.service-enablement"

printf '%s\n' "local v2 readiness wrapper regression checks passed"
