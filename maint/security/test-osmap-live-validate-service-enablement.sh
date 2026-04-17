#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_wrapper="${repo_root}/maint/live/osmap-live-validate-service-enablement.ksh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-service-validate-test.XXXXXX")
fake_repo="${tmp_root}/repo"
fake_live_dir="${tmp_root}/live"
fake_etc_dir="${fake_live_dir}/etc"
fake_osmap_dir="${fake_etc_dir}/osmap"
fake_rcd_dir="${fake_etc_dir}/rc.d"
fake_group_file="${fake_etc_dir}/group"
fake_usr_local_bin="${fake_live_dir}/usr/local/bin"
fake_usr_local_libexec="${fake_live_dir}/usr/local/libexec/osmap"
fake_helper_run_dir="${fake_live_dir}/var/lib/osmap-helper/run"
pass_bin_dir="${tmp_root}/pass-bin"
fail_bin_dir="${tmp_root}/fail-bin"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p \
  "${fake_repo}/maint/live" \
  "${fake_osmap_dir}" \
  "${fake_rcd_dir}" \
  "${fake_usr_local_bin}" \
  "${fake_usr_local_libexec}" \
  "${fake_helper_run_dir}" \
  "${pass_bin_dir}" \
  "${fail_bin_dir}"

cp "${source_wrapper}" "${fake_repo}/maint/live/osmap-live-validate-service-enablement.ksh"

cat > "${fake_osmap_dir}/osmap-serve.env" <<'EOF'
serve-env
EOF

cat > "${fake_osmap_dir}/osmap-mailbox-helper.env" <<'EOF'
helper-env
EOF

cat > "${fake_usr_local_libexec}/osmap-serve-run.ksh" <<'EOF'
#!/bin/sh
exit 0
EOF

cat > "${fake_usr_local_libexec}/osmap-mailbox-helper-run.ksh" <<'EOF'
#!/bin/sh
exit 0
EOF

cat > "${fake_rcd_dir}/osmap_serve" <<'EOF'
#!/bin/sh
exit 0
EOF

cat > "${fake_rcd_dir}/osmap_mailbox_helper" <<'EOF'
#!/bin/sh
exit 0
EOF

cat > "${fake_usr_local_bin}/osmap" <<'EOF'
#!/bin/sh
exit 0
EOF

printf 'socket\n' > "${fake_helper_run_dir}/mailbox-helper.sock"

chmod 0555 \
  "${fake_usr_local_bin}/osmap" \
  "${fake_usr_local_libexec}/osmap-serve-run.ksh" \
  "${fake_usr_local_libexec}/osmap-mailbox-helper-run.ksh" \
  "${fake_rcd_dir}/osmap_serve" \
  "${fake_rcd_dir}/osmap_mailbox_helper"

cat > "${fake_group_file}" <<'EOF'
osmaprt:*:3000:_osmap
EOF

write_common_bins() {
  bin_dir=$1
  group_membership=$2
  serve_rc=$3
  helper_rc=$4
  netstat_mode=$5

  cat > "${bin_dir}/hostname" <<'EOF'
#!/bin/sh
printf '%s\n' 'mail.blackbagsecurity.com'
EOF

  cat > "${bin_dir}/git" <<'EOF'
#!/bin/sh
printf '%s\n' 'cafebabe'
EOF

  cat > "${bin_dir}/doas" <<'EOF'
#!/bin/sh
if [ "$1" = "test" ]; then
  shift
  if [ "$1" = "-S" ]; then
    shift
    file_path=$1
    case "$file_path" in
      */mailbox-helper.sock)
        exec test -f "$file_path"
        ;;
    esac
  fi
  exec test "$@"
fi
exec "$@"
EOF

  cat > "${bin_dir}/id" <<EOF
#!/bin/sh
case "\$*" in
  "_osmap")
    printf '%s\n' 'uid=1001(_osmap) gid=1001(_osmap) groups=1001(_osmap),3000(osmaprt)'
    exit 0
    ;;
  "-Gn _osmap")
    printf '%s\n' '${group_membership}'
    exit 0
    ;;
esac
exit 1
EOF

  cat > "${bin_dir}/rcctl" <<EOF
#!/bin/sh
case "\$*" in
  "check osmap_serve")
    exit ${serve_rc}
    ;;
  "check osmap_mailbox_helper")
    exit ${helper_rc}
    ;;
esac
exit 0
EOF

  case "${netstat_mode}" in
    pass)
      cat > "${bin_dir}/netstat" <<'EOF'
#!/bin/sh
cat <<'OUT'
tcp          0      0  127.0.0.1.8080         *.*                    LISTEN
tcp          0      0  127.0.0.1.443          *.*                    LISTEN
OUT
EOF
      ;;
    fail)
      cat > "${bin_dir}/netstat" <<'EOF'
#!/bin/sh
cat <<'OUT'
tcp          0      0  127.0.0.1.443          *.*                    LISTEN
OUT
EOF
      ;;
  esac

  chmod +x \
    "${bin_dir}/hostname" \
    "${bin_dir}/git" \
    "${bin_dir}/doas" \
    "${bin_dir}/id" \
    "${bin_dir}/rcctl" \
    "${bin_dir}/netstat"
}

write_common_bins "${pass_bin_dir}" "_osmap osmaprt" 0 0 pass
write_common_bins "${fail_bin_dir}" "_osmap" 1 1 fail

assert_contains() {
  haystack=$1
  needle=$2

  printf '%s' "${haystack}" | grep -Fq "${needle}" || {
    printf 'expected to find "%s" in output:\n%s\n' "${needle}" "${haystack}" >&2
    exit 1
  }
}

pass_report="${tmp_root}/service-enable-pass-report.txt"
pass_output=$(
  env \
    PATH="${pass_bin_dir}:${PATH}" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_BIN_PATH="${fake_usr_local_bin}/osmap" \
    OSMAP_SERVICE_GROUP_FILE_PATH="${fake_group_file}" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH="${fake_osmap_dir}/osmap-serve.env" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH="${fake_osmap_dir}/osmap-mailbox-helper.env" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH="${fake_usr_local_libexec}/osmap-serve-run.ksh" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH="${fake_usr_local_libexec}/osmap-mailbox-helper-run.ksh" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH="${fake_rcd_dir}/osmap_serve" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH="${fake_rcd_dir}/osmap_mailbox_helper" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_SOCKET_PATH="${fake_helper_run_dir}/mailbox-helper.sock" \
    sh "${fake_repo}/maint/live/osmap-live-validate-service-enablement.ksh" --report "${pass_report}"
)

assert_contains "${pass_output}" "wrote service enablement report to ${pass_report}"
assert_contains "${pass_output}" "service enablement validation result: passed"
pass_report_contents=$(cat "${pass_report}")
assert_contains "${pass_report_contents}" "osmap_service_enablement_result=passed"
assert_contains "${pass_report_contents}" "service_binary_state=installed"
assert_contains "${pass_report_contents}" "shared_group_line=osmaprt:*:3000:_osmap"
assert_contains "${pass_report_contents}" "serve_service_check_rc=0"
assert_contains "${pass_report_contents}" "helper_service_check_rc=0"
assert_contains "${pass_report_contents}" "http_listener_bindings=127.0.0.1.8080"

fail_report="${tmp_root}/service-enable-fail-report.txt"
rm -f "${fake_usr_local_bin}/osmap"
rm -f "${fake_osmap_dir}/osmap-mailbox-helper.env"
rm -f "${fake_helper_run_dir}/mailbox-helper.sock"

set +e
fail_output=$(
  env \
    PATH="${fail_bin_dir}:${PATH}" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_OSMAP_BIN_PATH="${fake_usr_local_bin}/osmap" \
    OSMAP_SERVICE_GROUP_FILE_PATH="${fake_group_file}" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_ENV_PATH="${fake_osmap_dir}/osmap-serve.env" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_ENV_PATH="${fake_osmap_dir}/osmap-mailbox-helper.env" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RUN_PATH="${fake_usr_local_libexec}/osmap-serve-run.ksh" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RUN_PATH="${fake_usr_local_libexec}/osmap-mailbox-helper-run.ksh" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_SERVE_RC_PATH="${fake_rcd_dir}/osmap_serve" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_RC_PATH="${fake_rcd_dir}/osmap_mailbox_helper" \
    OSMAP_SERVICE_ENABLEMENT_LIVE_HELPER_SOCKET_PATH="${fake_helper_run_dir}/mailbox-helper.sock" \
    sh "${fake_repo}/maint/live/osmap-live-validate-service-enablement.ksh" --report "${fail_report}" 2>&1
)
fail_status=$?
set -e

[ "${fail_status}" -eq 1 ] || {
  printf 'expected failing service validation to exit 1, got %s\n' "${fail_status}" >&2
  exit 1
}

assert_contains "${fail_output}" "wrote service enablement report to ${fail_report}"
assert_contains "${fail_output}" "service enablement validation result: failed"
fail_report_contents=$(cat "${fail_report}")
assert_contains "${fail_report_contents}" "osmap_service_enablement_result=failed"
assert_contains "${fail_report_contents}" "missing_osmap_binary"
assert_contains "${fail_report_contents}" "osmap_user_missing_shared_runtime_group_membership"
assert_contains "${fail_report_contents}" "missing_helper_env_file"
assert_contains "${fail_report_contents}" "mailbox_helper_service_not_healthy"
assert_contains "${fail_report_contents}" "serve_service_not_healthy"
assert_contains "${fail_report_contents}" "missing_helper_socket"
assert_contains "${fail_report_contents}" "loopback_http_listener_not_ready"

printf '%s\n' "service enablement validation regression checks passed"
