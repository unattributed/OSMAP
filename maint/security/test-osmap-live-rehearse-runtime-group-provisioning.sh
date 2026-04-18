#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_wrapper="${repo_root}/maint/live/osmap-live-rehearse-runtime-group-provisioning.ksh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-runtime-group-test.XXXXXX")
fake_repo="${tmp_root}/repo"
fake_live_dir="${tmp_root}/live"
fake_etc_dir="${fake_live_dir}/etc"
fake_bin_dir="${tmp_root}/bin"
session_dir="${tmp_root}/session"
state_dir="${tmp_root}/state"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p \
  "${fake_repo}/maint/live" \
  "${fake_etc_dir}" \
  "${fake_bin_dir}" \
  "${state_dir}"

cp "${source_wrapper}" "${fake_repo}/maint/live/osmap-live-rehearse-runtime-group-provisioning.ksh"

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

[ -n "${report_path}" ] || {
  printf '%s\n' 'missing report path' >&2
  exit 2
}

group_file="${OSMAP_SERVICE_GROUP_FILE_PATH:?}"
runtime_group="${OSMAP_SHARED_RUNTIME_GROUP:-osmaprt}"
membership_file="${OSMAP_TEST_GROUP_MEMBERSHIP_FILE:?}"
membership=$(cat "${membership_file}")
group_line=$(grep -E "^${runtime_group}:" "${group_file}" 2>/dev/null || true)
mkdir -p "$(dirname "${report_path}")"

if [ "${OSMAP_TEST_RUNTIME_GROUP_VALIDATOR_MODE:-group-present}" = "still-missing" ]; then
  cat > "${report_path}" <<OUT
osmap_service_enablement_result=failed
shared_group_line=missing
osmap_group_membership=${membership}
failed_checks=
missing_shared_runtime_group
osmap_user_missing_shared_runtime_group_membership
OUT
  exit 1
fi

if [ -n "${group_line}" ] && printf '%s\n' "${membership}" | tr ' ' '\n' | grep -Fxq "${runtime_group}"; then
  cat > "${report_path}" <<OUT
osmap_service_enablement_result=failed
shared_group_line=${group_line}
osmap_group_membership=${membership}
failed_checks=
missing_serve_env_file
OUT
  exit 1
fi

cat > "${report_path}" <<OUT
osmap_service_enablement_result=failed
shared_group_line=missing
osmap_group_membership=${membership}
failed_checks=
missing_shared_runtime_group
osmap_user_missing_shared_runtime_group_membership
OUT
exit 1
EOF

cat > "${fake_etc_dir}/group" <<'EOF'
wheel:*:0:root
EOF

cat > "${state_dir}/primary-group" <<'EOF'
_osmap
EOF

cat > "${state_dir}/secondary-groups" <<'EOF'

EOF

cat > "${fake_bin_dir}/doas" <<'EOF'
#!/bin/sh
exec "$@"
EOF

cat > "${fake_bin_dir}/git" <<'EOF'
#!/bin/sh
printf '%s\n' 'feedface'
EOF

cat > "${fake_bin_dir}/date" <<'EOF'
#!/bin/sh
printf '%s\n' '20260418-130000'
EOF

cat > "${fake_bin_dir}/ksh" <<'EOF'
#!/bin/sh
exec sh "$@"
EOF

cat > "${fake_bin_dir}/groupadd" <<'EOF'
#!/bin/sh
set -eu
group_name=$1
group_file="${OSMAP_TEST_GROUP_FILE:?}"
printf '%s:*:3000:\n' "${group_name}" >> "${group_file}"
EOF

cat > "${fake_bin_dir}/groupdel" <<'EOF'
#!/bin/sh
set -eu
group_name=$1
group_file="${OSMAP_TEST_GROUP_FILE:?}"
grep -Ev "^${group_name}:" "${group_file}" > "${group_file}.tmp"
mv "${group_file}.tmp" "${group_file}"
EOF

cat > "${fake_bin_dir}/id" <<'EOF'
#!/bin/sh
set -eu
primary_group=$(cat "${OSMAP_TEST_PRIMARY_GROUP_FILE:?}")
secondary_groups=$(cat "${OSMAP_TEST_SECONDARY_GROUPS_FILE:?}")

case "$*" in
  "_osmap")
    printf '%s\n' 'uid=1001(_osmap) gid=1001(_osmap) groups=1001(_osmap)'
    exit 0
    ;;
  "-gn _osmap")
    printf '%s\n' "${primary_group}"
    exit 0
    ;;
  "-Gn _osmap")
    if [ -n "${secondary_groups}" ]; then
      printf '%s %s\n' "${primary_group}" "${secondary_groups}"
    else
      printf '%s\n' "${primary_group}"
    fi
    exit 0
    ;;
esac
exit 1
EOF

cat > "${fake_bin_dir}/usermod" <<'EOF'
#!/bin/sh
set -eu
secondary_groups_file="${OSMAP_TEST_SECONDARY_GROUPS_FILE:?}"

mode=$1
group_value=$2
user_name=$3
[ "${user_name}" = "_osmap" ] || exit 1

current=$(cat "${secondary_groups_file}")

case "${mode}" in
  -G)
    if [ -z "${current}" ]; then
      printf '%s\n' "${group_value}" > "${secondary_groups_file}"
    elif printf '%s\n' "${current}" | tr ',' '\n' | grep -Fxq "${group_value}"; then
      :
    else
      printf '%s,%s\n' "${current}" "${group_value}" > "${secondary_groups_file}"
    fi
    ;;
  -S)
    printf '%s\n' "${group_value}" > "${secondary_groups_file}"
    ;;
  *)
    exit 1
    ;;
esac
EOF

chmod +x \
  "${fake_repo}/maint/live/osmap-live-validate-service-enablement.ksh" \
  "${fake_bin_dir}/doas" \
  "${fake_bin_dir}/git" \
  "${fake_bin_dir}/date" \
  "${fake_bin_dir}/ksh" \
  "${fake_bin_dir}/groupadd" \
  "${fake_bin_dir}/groupdel" \
  "${fake_bin_dir}/id" \
  "${fake_bin_dir}/usermod"

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
    printf 'expected %s to contain %s\n' "${file_path}" "${needle}" >&2
    exit 1
  }
}

rehearsal_output=$(
  env \
    PATH="${fake_bin_dir}:${PATH}" \
    OSMAP_SERVICE_GROUP_FILE_PATH="${fake_etc_dir}/group" \
    OSMAP_TEST_GROUP_FILE="${fake_etc_dir}/group" \
    OSMAP_TEST_PRIMARY_GROUP_FILE="${state_dir}/primary-group" \
    OSMAP_TEST_SECONDARY_GROUPS_FILE="${state_dir}/secondary-groups" \
    OSMAP_TEST_GROUP_MEMBERSHIP_FILE="${state_dir}/secondary-groups" \
    HOME="${tmp_root}" \
    sh "${fake_repo}/maint/live/osmap-live-rehearse-runtime-group-provisioning.ksh" --session-dir "${session_dir}"
)

assert_contains "${rehearsal_output}" "prepared runtime-group provisioning session in ${session_dir}"
assert_contains "${rehearsal_output}" "apply script: ${session_dir}/scripts/apply-runtime-group-provisioning.sh"
assert_contains "${rehearsal_output}" "restore script: ${session_dir}/scripts/restore-runtime-group-provisioning.sh"

report_contents=$(cat "${session_dir}/runtime-group-session.txt")
assert_contains "${report_contents}" "osmap_runtime_group_session_mode=rehearse"
assert_contains "${report_contents}" "assessed_snapshot=feedface"
assert_contains "${report_contents}" "original_primary_group=_osmap"
assert_contains "${report_contents}" "group_exists_before=0"
assert_contains "${report_contents}" "validator_report=${session_dir}/reports/service-enablement-after-runtime-group.txt"

env \
  PATH="${fake_bin_dir}:${PATH}" \
  OSMAP_SERVICE_GROUP_FILE_PATH="${fake_etc_dir}/group" \
  OSMAP_TEST_GROUP_FILE="${fake_etc_dir}/group" \
  OSMAP_TEST_PRIMARY_GROUP_FILE="${state_dir}/primary-group" \
  OSMAP_TEST_SECONDARY_GROUPS_FILE="${state_dir}/secondary-groups" \
  OSMAP_TEST_GROUP_MEMBERSHIP_FILE="${state_dir}/secondary-groups" \
  sh "${session_dir}/scripts/apply-runtime-group-provisioning.sh"

assert_file_contains "${fake_etc_dir}/group" "osmaprt:*:3000:"
[ "$(cat "${state_dir}/secondary-groups")" = "osmaprt" ] || {
  printf 'expected runtime group membership after apply\n' >&2
  exit 1
}
assert_file_contains "${session_dir}/reports/service-enablement-after-runtime-group.txt" "shared_group_line=osmaprt:*:3000:"
assert_file_contains "${session_dir}/reports/service-enablement-after-runtime-group.txt" "osmap_group_membership=osmaprt"

env \
  PATH="${fake_bin_dir}:${PATH}" \
  OSMAP_SERVICE_GROUP_FILE_PATH="${fake_etc_dir}/group" \
  OSMAP_TEST_GROUP_FILE="${fake_etc_dir}/group" \
  OSMAP_TEST_PRIMARY_GROUP_FILE="${state_dir}/primary-group" \
  OSMAP_TEST_SECONDARY_GROUPS_FILE="${state_dir}/secondary-groups" \
  OSMAP_TEST_GROUP_MEMBERSHIP_FILE="${state_dir}/secondary-groups" \
  sh "${session_dir}/scripts/restore-runtime-group-provisioning.sh"

[ -z "$(cat "${state_dir}/secondary-groups")" ] || {
  printf 'expected runtime group membership removal after restore\n' >&2
  exit 1
}
if grep -Fq "osmaprt:" "${fake_etc_dir}/group"; then
  printf 'expected osmaprt group removal after restore\n' >&2
  exit 1
fi

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

mkdir -p "$(dirname "${report_path}")"
cat > "${report_path}" <<OUT
osmap_service_enablement_result=failed
shared_group_line=missing
osmap_group_membership=_osmap
failed_checks=
missing_shared_runtime_group
osmap_user_missing_shared_runtime_group_membership
OUT
exit 1
EOF
chmod +x "${fake_repo}/maint/live/osmap-live-validate-service-enablement.ksh"

bad_session_dir="${tmp_root}/bad-session"
env \
  PATH="${fake_bin_dir}:${PATH}" \
  OSMAP_SERVICE_GROUP_FILE_PATH="${fake_etc_dir}/group" \
  OSMAP_TEST_GROUP_FILE="${fake_etc_dir}/group" \
  OSMAP_TEST_PRIMARY_GROUP_FILE="${state_dir}/primary-group" \
  OSMAP_TEST_SECONDARY_GROUPS_FILE="${state_dir}/secondary-groups" \
  OSMAP_TEST_GROUP_MEMBERSHIP_FILE="${state_dir}/secondary-groups" \
  HOME="${tmp_root}" \
  sh "${fake_repo}/maint/live/osmap-live-rehearse-runtime-group-provisioning.ksh" --session-dir "${bad_session_dir}" >/dev/null

set +e
bad_output=$(
  env \
    PATH="${fake_bin_dir}:${PATH}" \
    OSMAP_SERVICE_GROUP_FILE_PATH="${fake_etc_dir}/group" \
    OSMAP_TEST_GROUP_FILE="${fake_etc_dir}/group" \
    OSMAP_TEST_PRIMARY_GROUP_FILE="${state_dir}/primary-group" \
    OSMAP_TEST_SECONDARY_GROUPS_FILE="${state_dir}/secondary-groups" \
    OSMAP_TEST_GROUP_MEMBERSHIP_FILE="${state_dir}/secondary-groups" \
    sh "${bad_session_dir}/scripts/apply-runtime-group-provisioning.sh" 2>&1
)
bad_status=$?
set -e

[ "${bad_status}" -eq 1 ] || {
  printf 'expected failing apply to exit 1, got %s\n' "${bad_status}" >&2
  exit 1
}

assert_contains "${bad_output}" "service validator still reports missing_shared_runtime_group after runtime-group provisioning"

printf '%s\n' "runtime group provisioning regression checks passed"
