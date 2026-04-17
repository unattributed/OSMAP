#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
helper_path="${repo_root}/maint/live/osmap-run-v2-readiness-with-temporary-validation-password.sh"
readiness_wrapper_path="${repo_root}/maint/live/osmap-live-validate-v2-readiness.ksh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v2-validation-password-test.XXXXXX")
bin_dir="${tmp_root}/bin"
state_dir="${tmp_root}/state"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p "${bin_dir}" "${state_dir}"

mailbox_hash_path="${state_dir}/mailbox-password.txt"
expected_temp_hash_path="${state_dir}/expected-temp-hash.txt"
success_marker_path="${state_dir}/success-marker"
failure_marker_path="${state_dir}/failure-marker"
passthrough_marker_path="${state_dir}/passthrough-marker"

cat > "${mailbox_hash_path}" <<'EOF'
{BLF-CRYPT}$2y$05$originalValidationHashForOsmapV2ReadinessFlow
EOF

cat > "${bin_dir}/doas" <<'EOF'
#!/bin/sh
exec "$@"
EOF
chmod +x "${bin_dir}/doas"

cat > "${bin_dir}/openssl" <<'EOF'
#!/bin/sh

set -eu

[ "$#" -eq 3 ] || {
  printf 'unexpected openssl invocation\n' >&2
  exit 1
}
[ "$1" = "rand" ] && [ "$2" = "-hex" ] && [ "$3" = "16" ] || {
  printf 'unexpected openssl invocation\n' >&2
  exit 1
}

printf 'generated-v2-proof-secret\n'
EOF
chmod +x "${bin_dir}/openssl"

cat > "${bin_dir}/doveadm" <<'EOF'
#!/bin/sh

set -eu

if [ "$#" -ne 5 ] || [ "$1" != "pw" ] || [ "$2" != "-s" ] || [ "$3" != "BLF-CRYPT" ] || [ "$4" != "-p" ]; then
  printf 'unexpected doveadm invocation\n' >&2
  exit 1
fi

printf '{BLF-CRYPT}temporary-hash-for-%s\n' "$5"
EOF
chmod +x "${bin_dir}/doveadm"

cat > "${bin_dir}/mariadb" <<'EOF'
#!/bin/sh

set -eu

state_file=${OSMAP_TEST_MAILBOX_HASH_PATH:?}
query=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    -e)
      query=$2
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [ -n "${query}" ]; then
  case "${query}" in
    *"SELECT password FROM mailbox"*)
      cat "${state_file}"
      exit 0
      ;;
    *)
      printf 'unexpected mariadb -e query\n' >&2
      exit 1
      ;;
  esac
fi

query=$(tr '\n' ' ' | sed 's/[[:space:]][[:space:]]*/ /g')
password=$(printf '%s\n' "${query}" | sed -n "s/.*SET password='\\([^']*\\)'.*/\\1/p")
[ -n "${password}" ] || {
  printf 'missing password assignment in mariadb stdin query\n' >&2
  exit 1
}
printf '%s' "${password}" > "${state_file}"
EOF
chmod +x "${bin_dir}/mariadb"

cat > "${bin_dir}/ksh" <<'EOF'
#!/bin/sh

set -eu

real_readiness_wrapper=${OSMAP_TEST_REAL_READINESS_WRAPPER:?}
fake_readiness_path=${OSMAP_TEST_FAKE_READINESS_PATH:?}

[ "$#" -ge 1 ] || {
  printf 'unexpected empty ksh invocation\n' >&2
  exit 1
}

if [ "$1" = "${real_readiness_wrapper}" ]; then
  shift
  exec "${fake_readiness_path}" "$@"
fi

printf 'unexpected ksh invocation: %s\n' "$*" >&2
exit 1
EOF
chmod +x "${bin_dir}/ksh"

cat > "${tmp_root}/readiness-success.sh" <<'EOF'
#!/bin/sh

set -eu

current_hash=$(cat "${OSMAP_TEST_MAILBOX_HASH_PATH}")
expected_hash=$(cat "${OSMAP_TEST_EXPECTED_TEMP_HASH_PATH}")
[ "${current_hash}" = "${expected_hash}" ] || {
  printf 'temporary hash was not active during success path\n' >&2
  exit 1
}
[ "${OSMAP_VALIDATION_PASSWORD:-}" = "generated-v2-proof-secret" ] || {
  printf 'expected helper to export the generated temporary password\n' >&2
  exit 1
}
printf 'ok\n' > "${OSMAP_TEST_SUCCESS_MARKER_PATH}"
EOF
chmod +x "${tmp_root}/readiness-success.sh"

cat > "${tmp_root}/readiness-failure.sh" <<'EOF'
#!/bin/sh

set -eu

current_hash=$(cat "${OSMAP_TEST_MAILBOX_HASH_PATH}")
expected_hash=$(cat "${OSMAP_TEST_EXPECTED_TEMP_HASH_PATH}")
[ "${current_hash}" = "${expected_hash}" ] || {
  printf 'temporary hash was not active during failure path\n' >&2
  exit 1
}
[ "${OSMAP_VALIDATION_PASSWORD:-}" = "generated-v2-proof-secret" ] || {
  printf 'expected helper to export the generated temporary password\n' >&2
  exit 1
}
printf 'ok\n' > "${OSMAP_TEST_FAILURE_MARKER_PATH}"
exit 1
EOF
chmod +x "${tmp_root}/readiness-failure.sh"

cat > "${tmp_root}/readiness-passthrough.sh" <<'EOF'
#!/bin/sh

set -eu

current_hash=$(cat "${OSMAP_TEST_MAILBOX_HASH_PATH}")
original_hash=$(cat "${OSMAP_TEST_ORIGINAL_HASH_PATH}")
[ "${current_hash}" = "${original_hash}" ] || {
  printf 'helper should not change mailbox hash when login-send is absent\n' >&2
  exit 1
}
[ "${OSMAP_VALIDATION_PASSWORD:-}" = "${OSMAP_TEST_EXPECTED_PASSTHROUGH_PASSWORD:-}" ] || {
  printf 'helper should preserve the inherited validation password when login-send is absent\n' >&2
  exit 1
}
[ "$#" -eq 1 ] && [ "$1" = "security-check" ] || {
  printf 'unexpected passthrough arguments\n' >&2
  exit 1
}
printf 'ok\n' > "${OSMAP_TEST_PASSTHROUGH_MARKER_PATH}"
EOF
chmod +x "${tmp_root}/readiness-passthrough.sh"

assert_equals() {
  left=$1
  right=$2

  [ "${left}" = "${right}" ] || {
    printf 'expected:\n%s\nactual:\n%s\n' "${right}" "${left}" >&2
    exit 1
  }
}

run_helper() {
  fake_readiness_path=$1
  expected_passthrough_password=$2
  shift
  shift

  env \
    PATH="${bin_dir}:${PATH}" \
    OSMAP_TEST_MAILBOX_HASH_PATH="${mailbox_hash_path}" \
    OSMAP_TEST_EXPECTED_TEMP_HASH_PATH="${expected_temp_hash_path}" \
    OSMAP_TEST_SUCCESS_MARKER_PATH="${success_marker_path}" \
    OSMAP_TEST_FAILURE_MARKER_PATH="${failure_marker_path}" \
    OSMAP_TEST_PASSTHROUGH_MARKER_PATH="${passthrough_marker_path}" \
    OSMAP_TEST_ORIGINAL_HASH_PATH="${mailbox_hash_path}.orig" \
    OSMAP_TEST_EXPECTED_PASSTHROUGH_PASSWORD="${expected_passthrough_password}" \
    OSMAP_VALIDATION_PASSWORD="${expected_passthrough_password}" \
    OSMAP_TEST_REAL_READINESS_WRAPPER="${readiness_wrapper_path}" \
    OSMAP_TEST_FAKE_READINESS_PATH="${fake_readiness_path}" \
    sh "${helper_path}" "$@"
}

original_hash=$(cat "${mailbox_hash_path}")
printf '%s' "${original_hash}" > "${mailbox_hash_path}.orig"
printf '%s' "{BLF-CRYPT}temporary-hash-for-generated-v2-proof-secret" > "${expected_temp_hash_path}"

run_helper "${tmp_root}/readiness-success.sh" ""
assert_equals "$(cat "${mailbox_hash_path}")" "${original_hash}"
[ -f "${success_marker_path}" ] || {
  printf 'success path did not run the readiness command\n' >&2
  exit 1
}

if run_helper "${tmp_root}/readiness-failure.sh" "" login-send; then
  printf 'expected failure path to return non-zero\n' >&2
  exit 1
fi

assert_equals "$(cat "${mailbox_hash_path}")" "${original_hash}"
[ -f "${failure_marker_path}" ] || {
  printf 'failure path did not run the readiness command\n' >&2
  exit 1
}

run_helper "${tmp_root}/readiness-passthrough.sh" "preexisting-wrapper-secret" security-check
assert_equals "$(cat "${mailbox_hash_path}")" "${original_hash}"
[ -f "${passthrough_marker_path}" ] || {
  printf 'passthrough path did not run the readiness command\n' >&2
  exit 1
}

printf '%s\n' "v2 validation password override regression checks passed"
