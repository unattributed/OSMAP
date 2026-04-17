#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_wrapper="${repo_root}/maint/live/osmap-live-rehearse-binary-deployment.ksh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-binary-deployment-test.XXXXXX")
fake_repo="${tmp_root}/repo"
fake_live_dir="${tmp_root}/live"
fake_usr_local_bin="${fake_live_dir}/usr/local/bin"
fake_bin_dir="${tmp_root}/bin"
session_dir="${tmp_root}/session"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p \
  "${fake_repo}/maint/live" \
  "${fake_usr_local_bin}" \
  "${fake_bin_dir}"

cp "${source_wrapper}" "${fake_repo}/maint/live/osmap-live-rehearse-binary-deployment.ksh"

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

binary_path="${OSMAP_BINARY_DEPLOYMENT_LIVE_OSMAP_BIN_PATH:-/usr/local/bin/osmap}"
mkdir -p "$(dirname "${report_path}")"

if [ "${OSMAP_TEST_BINARY_VALIDATOR_MODE:-installed}" = "missing" ]; then
  cat > "${report_path}" <<OUT
osmap_service_enablement_result=failed
service_binary_state=missing
failed_checks=
missing_osmap_binary
OUT
  exit 1
fi

if [ -x "${binary_path}" ]; then
  cat > "${report_path}" <<OUT
osmap_service_enablement_result=failed
service_binary_state=installed
failed_checks=
missing_shared_runtime_group
OUT
  exit 1
fi

cat > "${report_path}" <<OUT
osmap_service_enablement_result=failed
service_binary_state=missing
failed_checks=
missing_osmap_binary
OUT
exit 1
EOF

cat > "${fake_usr_local_bin}/osmap" <<'EOF'
#!/bin/sh
printf '%s\n' 'old-binary'
EOF
chmod 0755 "${fake_usr_local_bin}/osmap"

cat > "${fake_bin_dir}/doas" <<'EOF'
#!/bin/sh
if [ "$1" = "test" ]; then
  shift
  exec test "$@"
fi
if [ "$1" = "cat" ]; then
  shift
  exec cat "$@"
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

cat > "${fake_bin_dir}/cargo" <<'EOF'
#!/bin/sh
set -eu

profile=debug
for arg in "$@"; do
  if [ "$arg" = "--release" ]; then
    profile=release
  fi
done

target_root="${CARGO_TARGET_DIR:?}"
binary_path="${target_root}/${profile}/osmap"
mkdir -p "$(dirname "${binary_path}")"
cat > "${binary_path}" <<OUT
#!/bin/sh
printf '%s\n' 'built-${profile}'
OUT
chmod 0755 "${binary_path}"
EOF

cat > "${fake_bin_dir}/git" <<'EOF'
#!/bin/sh
printf '%s\n' 'deadbeef'
EOF

cat > "${fake_bin_dir}/date" <<'EOF'
#!/bin/sh
printf '%s\n' '20260418-120000'
EOF

cat > "${fake_bin_dir}/ksh" <<'EOF'
#!/bin/sh
exec sh "$@"
EOF

chmod +x \
  "${fake_repo}/maint/live/osmap-live-validate-service-enablement.ksh" \
  "${fake_bin_dir}/doas" \
  "${fake_bin_dir}/install" \
  "${fake_bin_dir}/cargo" \
  "${fake_bin_dir}/git" \
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

assert_file_equals() {
  file_path=$1
  expected=$2
  [ "$(cat "${file_path}")" = "${expected}" ] || {
    printf 'unexpected contents in %s\nexpected:\n%s\nactual:\n%s\n' "${file_path}" "${expected}" "$(cat "${file_path}")" >&2
    exit 1
  }
}

rehearsal_output=$(
  env \
    PATH="${fake_bin_dir}:${PATH}" \
    OSMAP_BINARY_DEPLOYMENT_LIVE_OSMAP_BIN_PATH="${fake_usr_local_bin}/osmap" \
    HOME="${tmp_root}" \
    sh "${fake_repo}/maint/live/osmap-live-rehearse-binary-deployment.ksh" --session-dir "${session_dir}"
)

assert_contains "${rehearsal_output}" "prepared binary deployment session in ${session_dir}"
assert_contains "${rehearsal_output}" "apply script: ${session_dir}/scripts/apply-binary-deployment.sh"
assert_contains "${rehearsal_output}" "restore script: ${session_dir}/scripts/restore-binary-deployment.sh"

assert_file_equals "${session_dir}/backup/usr/local/bin/osmap" "#!/bin/sh
printf '%s\n' 'old-binary'"
assert_file_equals "${session_dir}/staged/usr/local/bin/osmap" "#!/bin/sh
printf '%s\n' 'built-debug'"

report_contents=$(cat "${session_dir}/binary-deployment-session.txt")
assert_contains "${report_contents}" "osmap_binary_deployment_session_mode=rehearse"
assert_contains "${report_contents}" "assessed_snapshot=deadbeef"
assert_contains "${report_contents}" "build_profile=debug"
assert_contains "${report_contents}" "validator_report=${session_dir}/reports/service-enablement-after-binary-install.txt"

env \
  PATH="${fake_bin_dir}:${PATH}" \
  OSMAP_BINARY_DEPLOYMENT_LIVE_OSMAP_BIN_PATH="${fake_usr_local_bin}/osmap" \
  sh "${session_dir}/scripts/apply-binary-deployment.sh"

assert_file_equals "${fake_usr_local_bin}/osmap" "#!/bin/sh
printf '%s\n' 'built-debug'"
validator_report_contents=$(cat "${session_dir}/reports/service-enablement-after-binary-install.txt")
assert_contains "${validator_report_contents}" "service_binary_state=installed"

if printf '%s' "${validator_report_contents}" | grep -Fq "missing_osmap_binary"; then
  printf 'unexpected missing_osmap_binary in validator report after apply\n' >&2
  exit 1
fi

env \
  PATH="${fake_bin_dir}:${PATH}" \
  OSMAP_BINARY_DEPLOYMENT_LIVE_OSMAP_BIN_PATH="${fake_usr_local_bin}/osmap" \
  sh "${session_dir}/scripts/restore-binary-deployment.sh"

assert_file_equals "${fake_usr_local_bin}/osmap" "#!/bin/sh
printf '%s\n' 'old-binary'"

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
service_binary_state=missing
failed_checks=
missing_osmap_binary
OUT
exit 1
EOF
chmod +x "${fake_repo}/maint/live/osmap-live-validate-service-enablement.ksh"

bad_session_dir="${tmp_root}/bad-session"
env \
  PATH="${fake_bin_dir}:${PATH}" \
  OSMAP_BINARY_DEPLOYMENT_LIVE_OSMAP_BIN_PATH="${fake_usr_local_bin}/osmap" \
  HOME="${tmp_root}" \
  sh "${fake_repo}/maint/live/osmap-live-rehearse-binary-deployment.ksh" --session-dir "${bad_session_dir}" >/dev/null

set +e
bad_output=$(
  env \
    PATH="${fake_bin_dir}:${PATH}" \
    OSMAP_BINARY_DEPLOYMENT_LIVE_OSMAP_BIN_PATH="${fake_usr_local_bin}/osmap" \
    sh "${bad_session_dir}/scripts/apply-binary-deployment.sh" 2>&1
)
bad_status=$?
set -e

[ "${bad_status}" -eq 1 ] || {
  printf 'expected failing apply to exit 1, got %s\n' "${bad_status}" >&2
  exit 1
}

assert_contains "${bad_output}" "service validator did not confirm installed binary state"

printf '%s\n' "binary deployment rehearsal regression checks passed"
