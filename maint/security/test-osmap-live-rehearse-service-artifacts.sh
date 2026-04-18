#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_wrapper="${repo_root}/maint/live/osmap-live-rehearse-service-artifacts.ksh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-service-artifacts-test.XXXXXX")
fake_repo="${tmp_root}/repo"
fake_live_dir="${tmp_root}/live"
fake_live_etc_dir="${fake_live_dir}/etc"
fake_live_usr_local_dir="${fake_live_dir}/usr/local"
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
  "${fake_live_usr_local_dir}/libexec/osmap" \
  "${fake_bin_dir}"

cp "${source_wrapper}" "${fake_repo}/maint/live/osmap-live-rehearse-service-artifacts.ksh"

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

serve_env="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH:?}"
helper_env="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH:?}"
serve_run="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH:?}"
helper_run="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH:?}"
serve_rc="${OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH:?}"
helper_rc="${OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH:?}"

mkdir -p "$(dirname "${report_path}")"
failed_checks=

append_failed() {
  item=$1
  if [ -z "${failed_checks}" ]; then
    failed_checks="${item}"
  else
    failed_checks="${failed_checks}
${item}"
  fi
}

[ -f "${serve_env}" ] || append_failed missing_serve_env_file
[ -f "${helper_env}" ] || append_failed missing_helper_env_file
[ -x "${serve_run}" ] || append_failed missing_serve_launcher
[ -x "${helper_run}" ] || append_failed missing_helper_launcher
[ -x "${serve_rc}" ] || append_failed missing_serve_rc_script
[ -x "${helper_rc}" ] || append_failed missing_helper_rc_script
append_failed mailbox_helper_service_not_healthy

cat > "${report_path}" <<OUT
osmap_service_enablement_result=failed
failed_checks=
${failed_checks}
OUT
exit 1
EOF

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

chmod +x \
  "${fake_repo}/maint/live/osmap-live-validate-service-enablement.ksh"

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

cat > "${fake_bin_dir}/date" <<'EOF'
#!/bin/sh
printf '%s\n' '20260418-150000'
EOF

cat > "${fake_bin_dir}/ksh" <<'EOF'
#!/bin/sh
exec sh "$@"
EOF

chmod +x \
  "${fake_bin_dir}/doas" \
  "${fake_bin_dir}/install" \
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
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-serve.env" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-mailbox-helper.env" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_serve" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_mailbox_helper" \
    HOME="${tmp_root}" \
    sh "${fake_repo}/maint/live/osmap-live-rehearse-service-artifacts.ksh" --session-dir "${session_dir}"
)

assert_contains "${rehearsal_output}" "prepared service-artifact session in ${session_dir}"
assert_contains "${rehearsal_output}" "apply script: ${session_dir}/scripts/apply-service-artifacts.sh"
assert_contains "${rehearsal_output}" "restore script: ${session_dir}/scripts/restore-service-artifacts.sh"

assert_file_equals "${session_dir}/backup/etc/osmap/osmap-serve.env" "live-serve-env"
assert_file_equals "${session_dir}/backup/usr/local/libexec/osmap/osmap-serve-run.ksh" "live-serve-run"
assert_file_equals "${session_dir}/backup/etc/rc.d/osmap_serve" "live-serve-rc"
assert_file_equals "${session_dir}/staged/etc/osmap/osmap-serve.env" "reviewed-serve-env"
assert_file_equals "${session_dir}/staged/etc/osmap/osmap-mailbox-helper.env" "reviewed-helper-env"
assert_file_equals "${session_dir}/staged/usr/local/libexec/osmap/osmap-serve-run.ksh" "reviewed-serve-run"
assert_file_equals "${session_dir}/staged/usr/local/libexec/osmap/osmap-mailbox-helper-run.ksh" "reviewed-helper-run"
assert_file_equals "${session_dir}/staged/etc/rc.d/osmap_serve" "reviewed-serve-rc"
assert_file_equals "${session_dir}/staged/etc/rc.d/osmap_mailbox_helper" "reviewed-helper-rc"

report_contents=$(cat "${session_dir}/service-artifacts-session.txt")
assert_contains "${report_contents}" "osmap_service_artifacts_session_mode=rehearse"
assert_contains "${report_contents}" "apply_script=${session_dir}/scripts/apply-service-artifacts.sh"
assert_contains "${report_contents}" "restore_script=${session_dir}/scripts/restore-service-artifacts.sh"
assert_contains "${report_contents}" "validator_report=${session_dir}/reports/service-enablement-after-service-artifacts.txt"

env \
  PATH="${fake_bin_dir}:${PATH}" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-serve.env" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-mailbox-helper.env" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_serve" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_mailbox_helper" \
  sh "${session_dir}/scripts/apply-service-artifacts.sh"

assert_file_equals "${fake_live_etc_dir}/osmap/osmap-serve.env" "reviewed-serve-env"
assert_file_equals "${fake_live_etc_dir}/osmap/osmap-mailbox-helper.env" "reviewed-helper-env"
assert_file_equals "${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" "reviewed-serve-run"
assert_file_equals "${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" "reviewed-helper-run"
assert_file_equals "${fake_live_etc_dir}/rc.d/osmap_serve" "reviewed-serve-rc"
assert_file_equals "${fake_live_etc_dir}/rc.d/osmap_mailbox_helper" "reviewed-helper-rc"

validator_report=$(cat "${session_dir}/reports/service-enablement-after-service-artifacts.txt")
assert_contains "${validator_report}" "mailbox_helper_service_not_healthy"
if printf '%s' "${validator_report}" | grep -Fq "missing_serve_env_file"; then
  printf 'unexpected missing_serve_env_file after service-artifact apply\n' >&2
  exit 1
fi

env \
  PATH="${fake_bin_dir}:${PATH}" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-serve.env" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-mailbox-helper.env" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_serve" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_mailbox_helper" \
  sh "${session_dir}/scripts/restore-service-artifacts.sh"

assert_file_equals "${fake_live_etc_dir}/osmap/osmap-serve.env" "live-serve-env"
[ ! -f "${fake_live_etc_dir}/osmap/osmap-mailbox-helper.env" ] || {
  printf 'expected helper env removal during restore\n' >&2
  exit 1
}
assert_file_equals "${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" "live-serve-run"
[ ! -f "${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" ] || {
  printf 'expected helper launcher removal during restore\n' >&2
  exit 1
}
assert_file_equals "${fake_live_etc_dir}/rc.d/osmap_serve" "live-serve-rc"
[ ! -f "${fake_live_etc_dir}/rc.d/osmap_mailbox_helper" ] || {
  printf 'expected helper rc removal during restore\n' >&2
  exit 1
}

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
failed_checks=
missing_serve_env_file
OUT
exit 1
EOF
chmod +x "${fake_repo}/maint/live/osmap-live-validate-service-enablement.ksh"

bad_session_dir="${tmp_root}/bad-session"
env \
  PATH="${fake_bin_dir}:${PATH}" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-serve.env" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-mailbox-helper.env" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_serve" \
  OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_mailbox_helper" \
  HOME="${tmp_root}" \
  sh "${fake_repo}/maint/live/osmap-live-rehearse-service-artifacts.ksh" --session-dir "${bad_session_dir}" >/dev/null

set +e
bad_output=$(
  env \
    PATH="${fake_bin_dir}:${PATH}" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-serve.env" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH="${fake_live_etc_dir}/osmap/osmap-mailbox-helper.env" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-serve-run.ksh" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH="${fake_live_usr_local_dir}/libexec/osmap/osmap-mailbox-helper-run.ksh" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_serve" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH="${fake_live_etc_dir}/rc.d/osmap_mailbox_helper" \
    sh "${bad_session_dir}/scripts/apply-service-artifacts.sh" 2>&1
)
bad_status=$?
set -e

[ "${bad_status}" -eq 1 ] || {
  printf 'expected failing apply to exit 1, got %s\n' "${bad_status}" >&2
  exit 1
}

assert_contains "${bad_output}" "service validator still reports missing_serve_env_file after service-artifact apply"

printf '%s\n' "service artifact rehearsal regression checks passed"
