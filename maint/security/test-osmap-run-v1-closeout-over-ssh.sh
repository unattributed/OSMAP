#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
wrapper_path="${repo_root}/maint/live/osmap-run-v1-closeout-over-ssh.sh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-closeout-ssh-test.XXXXXX")
bin_dir="${tmp_root}/bin"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p "${bin_dir}"

cat > "${bin_dir}/ssh" <<'EOF'
#!/bin/sh

set -eu

log_dir=${OSMAP_TEST_SSH_LOG_DIR:?}
report_content=${OSMAP_TEST_SSH_REPORT_CONTENT:?}
call_count_file="${log_dir}/call-count"

if [ -f "${call_count_file}" ]; then
  call_count=$(cat "${call_count_file}")
else
  call_count=0
fi

call_count=$((call_count + 1))
printf '%s\n' "${call_count}" > "${call_count_file}"
printf '%s\n' "$1" > "${log_dir}/call-${call_count}-host.txt"
printf '%s\n' "$2" > "${log_dir}/call-${call_count}-command.txt"

if [ "${call_count}" -eq 2 ]; then
  printf '%s' "${report_content}"
fi
EOF

chmod +x "${bin_dir}/ssh"

assert_contains() {
  haystack=$1
  needle=$2

  printf '%s' "${haystack}" | grep -Fq "${needle}" || {
    printf 'expected to find "%s" in command:\n%s\n' "${needle}" "${haystack}" >&2
    exit 1
  }
}

assert_not_contains() {
  haystack=$1
  needle=$2

  if printf '%s' "${haystack}" | grep -Fq "${needle}"; then
    printf 'did not expect to find "%s" in command:\n%s\n' "${needle}" "${haystack}" >&2
    exit 1
  fi
}

run_case() {
  case_name=$1
  report_content=$2
  expected_host=$3
  shift 3

  log_dir="${tmp_root}/${case_name}"
  report_path="${tmp_root}/${case_name}.report"

  mkdir -p "${log_dir}"

  (
    env \
      PATH="${bin_dir}:${PATH}" \
      OSMAP_TEST_SSH_LOG_DIR="${log_dir}" \
      OSMAP_TEST_SSH_REPORT_CONTENT="${report_content}" \
      OSMAP_VALIDATION_PASSWORD="wrapper-test-secret" \
      "${wrapper_path}" --host "${expected_host}" --local-report "${report_path}" "$@" >/dev/null 2>&1
  )

  first_host=$(cat "${log_dir}/call-1-host.txt")
  second_host=$(cat "${log_dir}/call-2-host.txt")
  first_command=$(cat "${log_dir}/call-1-command.txt")
  second_command=$(cat "${log_dir}/call-2-command.txt")

  [ "${first_host}" = "${expected_host}" ] || {
    printf 'unexpected first host for %s: %s\n' "${case_name}" "${first_host}" >&2
    exit 1
  }
  [ "${second_host}" = "${expected_host}" ] || {
    printf 'unexpected second host for %s: %s\n' "${case_name}" "${second_host}" >&2
    exit 1
  }
  [ "$(cat "${report_path}")" = "${report_content}" ] || {
    printf 'unexpected fetched report for %s\n' "${case_name}" >&2
    exit 1
  }

  printf '%s\n' "${first_command}"
  printf '=====\n'
  printf '%s\n' "${second_command}"
}

default_output=$(
  run_case \
    default \
    'default-report=passed' \
    default-host
)
default_command=$(printf '%s\n' "${default_output}" | sed -n '1p')
default_fetch_command=$(printf '%s\n' "${default_output}" | sed -n '3p')

assert_contains "${default_command}" "cd \"\$HOME\"/"
assert_contains "${default_command}" "OSMAP"
assert_contains "${default_command}" "OSMAP_VALIDATION_PASSWORD="
assert_contains "${default_command}" "wrapper-test-secret"
assert_contains "${default_command}" "ksh ./maint/live/osmap-live-validate-v1-closeout.ksh --report \"\$HOME\"/"
assert_contains "${default_command}" "osmap-v1-closeout-report.txt"
for step_name in \
  security-check \
  login-send \
  all-mailbox-search \
  archive-shortcut \
  session-surface \
  send-throttle \
  move-throttle; do
  assert_contains "${default_command}" "'${step_name}'"
done
assert_not_contains "${default_command}" "security-checklogin-send"
assert_contains "${default_fetch_command}" "cat \"\$HOME\"/"
assert_contains "${default_fetch_command}" "osmap-v1-closeout-report.txt"

subset_output=$(
  run_case \
    subset \
    'subset-report=passed' \
    subset-host \
    --remote-project-root '~/custom-closeout' \
    --remote-report '~/custom-report.txt' \
    security-check \
    session-surface
)
subset_command=$(printf '%s\n' "${subset_output}" | sed -n '1p')
subset_fetch_command=$(printf '%s\n' "${subset_output}" | sed -n '3p')

assert_contains "${subset_command}" "cd \"\$HOME\"/"
assert_contains "${subset_command}" "custom-closeout"
assert_contains "${subset_command}" "ksh ./maint/live/osmap-live-validate-v1-closeout.ksh --report \"\$HOME\"/"
assert_contains "${subset_command}" "custom-report.txt"
assert_contains "${subset_command}" "security-check"
assert_contains "${subset_command}" "session-surface"
assert_not_contains "${subset_command}" "login-send"
assert_not_contains "${subset_command}" "security-checksession-surface"
assert_contains "${subset_fetch_command}" "cat \"\$HOME\"/"
assert_contains "${subset_fetch_command}" "custom-report.txt"

printf '%s\n' "closeout ssh wrapper regression checks passed"
