#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-validation-password-test.XXXXXX")
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

cat > "${mailbox_hash_path}" <<'EOF'
{BLF-CRYPT}$2y$05$originalValidationHashForOsmapCloseoutFlow
EOF

cat > "${bin_dir}/doas" <<'EOF'
#!/bin/sh
exec "$@"
EOF
chmod +x "${bin_dir}/doas"

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

cat > "${tmp_root}/closeout-success.sh" <<'EOF'
#!/bin/sh

set -eu

current_hash=$(cat "${OSMAP_TEST_MAILBOX_HASH_PATH}")
expected_hash=$(cat "${OSMAP_TEST_EXPECTED_TEMP_HASH_PATH}")
[ "${current_hash}" = "${expected_hash}" ] || {
  printf 'temporary hash was not active during success path\n' >&2
  exit 1
}
printf 'ok\n' > "${OSMAP_TEST_SUCCESS_MARKER_PATH}"
EOF
chmod +x "${tmp_root}/closeout-success.sh"

cat > "${tmp_root}/closeout-failure.sh" <<'EOF'
#!/bin/sh

set -eu

current_hash=$(cat "${OSMAP_TEST_MAILBOX_HASH_PATH}")
expected_hash=$(cat "${OSMAP_TEST_EXPECTED_TEMP_HASH_PATH}")
[ "${current_hash}" = "${expected_hash}" ] || {
  printf 'temporary hash was not active during failure path\n' >&2
  exit 1
}
printf 'ok\n' > "${OSMAP_TEST_FAILURE_MARKER_PATH}"
exit 1
EOF
chmod +x "${tmp_root}/closeout-failure.sh"

assert_equals() {
  left=$1
  right=$2

  [ "${left}" = "${right}" ] || {
    printf 'expected:\n%s\nactual:\n%s\n' "${right}" "${left}" >&2
    exit 1
  }
}

run_validation_password_override() {
  temp_password=$1
  closeout_command=$2

  (
    original_hash="$(doas mariadb -N -B postfixadmin -e "SELECT password FROM mailbox WHERE username='osmap-helper-validation@blackbagsecurity.com' AND active='1';")"

    restore_password() {
      doas mariadb postfixadmin <<SQL
UPDATE mailbox
SET password='${original_hash}'
WHERE username='osmap-helper-validation@blackbagsecurity.com' AND active='1';
SQL
    }

    trap restore_password EXIT INT TERM

    temp_hash="$(doas doveadm pw -s BLF-CRYPT -p "${temp_password}")"
    printf '%s' "${temp_hash}" > "${expected_temp_hash_path}"

    doas mariadb postfixadmin <<SQL
UPDATE mailbox
SET password='${temp_hash}'
WHERE username='osmap-helper-validation@blackbagsecurity.com' AND active='1';
SQL

    "${closeout_command}"
  )
}

original_hash=$(cat "${mailbox_hash_path}")

env \
  PATH="${bin_dir}:${PATH}" \
  OSMAP_TEST_MAILBOX_HASH_PATH="${mailbox_hash_path}" \
  OSMAP_TEST_EXPECTED_TEMP_HASH_PATH="${expected_temp_hash_path}" \
  OSMAP_TEST_SUCCESS_MARKER_PATH="${success_marker_path}" \
  OSMAP_TEST_FAILURE_MARKER_PATH="${failure_marker_path}" \
  sh -c '
    run_validation_password_override() {
      temp_password=$1
      closeout_command=$2

      (
        original_hash="$(doas mariadb -N -B postfixadmin -e "SELECT password FROM mailbox WHERE username='\''osmap-helper-validation@blackbagsecurity.com'\'' AND active='\''1'\'';")"

        restore_password() {
          doas mariadb postfixadmin <<SQL
UPDATE mailbox
SET password='"'"'${original_hash}'"'"'
WHERE username='"'"'osmap-helper-validation@blackbagsecurity.com'"'"' AND active='"'"'1'"'"';
SQL
        }

        trap restore_password EXIT INT TERM

        temp_hash="$(doas doveadm pw -s BLF-CRYPT -p "${temp_password}")"
        printf "%s" "${temp_hash}" > "'"${expected_temp_hash_path}"'"

        doas mariadb postfixadmin <<SQL
UPDATE mailbox
SET password='"'"'${temp_hash}'"'"'
WHERE username='"'"'osmap-helper-validation@blackbagsecurity.com'"'"' AND active='"'"'1'"'"';
SQL

        "${closeout_command}"
      )
    }

    run_validation_password_override success-proof "'"${tmp_root}/closeout-success.sh"'"
  '

assert_equals "$(cat "${mailbox_hash_path}")" "${original_hash}"
[ -f "${success_marker_path}" ] || {
  printf 'success path did not run the closeout command\n' >&2
  exit 1
}
assert_equals "$(cat "${expected_temp_hash_path}")" "{BLF-CRYPT}temporary-hash-for-success-proof"

rm -f "${expected_temp_hash_path}"

if env \
  PATH="${bin_dir}:${PATH}" \
  OSMAP_TEST_MAILBOX_HASH_PATH="${mailbox_hash_path}" \
  OSMAP_TEST_EXPECTED_TEMP_HASH_PATH="${expected_temp_hash_path}" \
  OSMAP_TEST_SUCCESS_MARKER_PATH="${success_marker_path}" \
  OSMAP_TEST_FAILURE_MARKER_PATH="${failure_marker_path}" \
  sh -c '
    run_validation_password_override() {
      temp_password=$1
      closeout_command=$2

      (
        original_hash="$(doas mariadb -N -B postfixadmin -e "SELECT password FROM mailbox WHERE username='\''osmap-helper-validation@blackbagsecurity.com'\'' AND active='\''1'\'';")"

        restore_password() {
          doas mariadb postfixadmin <<SQL
UPDATE mailbox
SET password='"'"'${original_hash}'"'"'
WHERE username='"'"'osmap-helper-validation@blackbagsecurity.com'"'"' AND active='"'"'1'"'"';
SQL
        }

        trap restore_password EXIT INT TERM

        temp_hash="$(doas doveadm pw -s BLF-CRYPT -p "${temp_password}")"
        printf "%s" "${temp_hash}" > "'"${expected_temp_hash_path}"'"

        doas mariadb postfixadmin <<SQL
UPDATE mailbox
SET password='"'"'${temp_hash}'"'"'
WHERE username='"'"'osmap-helper-validation@blackbagsecurity.com'"'"' AND active='"'"'1'"'"';
SQL

        "${closeout_command}"
      )
    }

    run_validation_password_override failure-proof "'"${tmp_root}/closeout-failure.sh"'"
  '; then
  printf 'expected failure path to return non-zero\n' >&2
  exit 1
fi

assert_equals "$(cat "${mailbox_hash_path}")" "${original_hash}"
[ -f "${failure_marker_path}" ] || {
  printf 'failure path did not run the closeout command\n' >&2
  exit 1
}
assert_equals "$(cat "${expected_temp_hash_path}")" "{BLF-CRYPT}temporary-hash-for-failure-proof"

printf '%s\n' "validation password override regression checks passed"
