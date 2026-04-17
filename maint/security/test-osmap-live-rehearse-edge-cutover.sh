#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_wrapper="${repo_root}/maint/live/osmap-live-rehearse-edge-cutover.ksh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-edge-cutover-rehearse-test.XXXXXX")
fake_repo="${tmp_root}/repo"
fake_live_dir="${tmp_root}/live"
fake_live_etc_dir="${fake_live_dir}/etc"
fake_bin_dir="${tmp_root}/bin"
session_dir="${tmp_root}/session"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p \
  "${fake_repo}/maint/live" \
  "${fake_repo}/maint/openbsd/mail.blackbagsecurity.com/nginx/sites-enabled" \
  "${fake_repo}/maint/openbsd/mail.blackbagsecurity.com/nginx/templates" \
  "${fake_repo}/maint/openbsd/mail.blackbagsecurity.com/pf.anchors" \
  "${fake_live_etc_dir}/nginx/sites-enabled" \
  "${fake_live_etc_dir}/nginx/templates" \
  "${fake_live_etc_dir}/pf.anchors" \
  "${fake_bin_dir}"

cp "${source_wrapper}" "${fake_repo}/maint/live/osmap-live-rehearse-edge-cutover.ksh"

cat > "${fake_repo}/maint/openbsd/mail.blackbagsecurity.com/nginx/sites-enabled/main-ssl.conf" <<'EOF'
reviewed-main-ssl
EOF

cat > "${fake_repo}/maint/openbsd/mail.blackbagsecurity.com/nginx/templates/osmap-root.tmpl" <<'EOF'
reviewed-osmap-root
EOF

cat > "${fake_repo}/maint/openbsd/mail.blackbagsecurity.com/pf.anchors/macros.pf" <<'EOF'
reviewed-macros
EOF

cat > "${fake_repo}/maint/openbsd/mail.blackbagsecurity.com/pf.anchors/selfhost.pf" <<'EOF'
reviewed-selfhost
EOF

cat > "${fake_live_etc_dir}/nginx/sites-enabled/main-ssl.conf" <<'EOF'
live-main-ssl
EOF

cat > "${fake_live_etc_dir}/pf.anchors/macros.pf" <<'EOF'
live-macros
EOF

cat > "${fake_live_etc_dir}/pf.anchors/selfhost.pf" <<'EOF'
live-selfhost
EOF

cat > "${fake_live_etc_dir}/pf.conf" <<'EOF'
set block-policy drop
EOF

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

if [ "$1" = "-d" ]; then
  shift
  for target in "$@"; do
    mkdir -p "$target"
  done
  exit 0
fi

[ "$1" = "-m" ] || exit 1
mode=$2
src=$3
dest=$4
mkdir -p "$(dirname "$dest")"
cp "$src" "$dest"
chmod "$mode" "$dest"
EOF

cat > "${fake_bin_dir}/nginx" <<'EOF'
#!/bin/sh
printf '%s\n' "nginx $*" >> "${OSMAP_TEST_EDGE_CUTOVER_LOG_FILE:?}"
EOF

cat > "${fake_bin_dir}/pfctl" <<'EOF'
#!/bin/sh
printf '%s\n' "pfctl $*" >> "${OSMAP_TEST_EDGE_CUTOVER_LOG_FILE:?}"
EOF

cat > "${fake_bin_dir}/rcctl" <<'EOF'
#!/bin/sh
printf '%s\n' "rcctl $*" >> "${OSMAP_TEST_EDGE_CUTOVER_LOG_FILE:?}"
EOF

cat > "${fake_bin_dir}/date" <<'EOF'
#!/bin/sh
printf '%s\n' "20260417-120000"
EOF

chmod +x \
  "${fake_bin_dir}/doas" \
  "${fake_bin_dir}/install" \
  "${fake_bin_dir}/nginx" \
  "${fake_bin_dir}/pfctl" \
  "${fake_bin_dir}/rcctl" \
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

log_file="${tmp_root}/edge-cutover-commands.log"

rehearsal_output=$(
  env \
    PATH="${fake_bin_dir}:${PATH}" \
    OSMAP_EDGE_CUTOVER_LIVE_NGINX_MAIN_SSL_PATH="${fake_live_etc_dir}/nginx/sites-enabled/main-ssl.conf" \
    OSMAP_EDGE_CUTOVER_LIVE_NGINX_OSMAP_ROOT_TEMPLATE_PATH="${fake_live_etc_dir}/nginx/templates/osmap-root.tmpl" \
    OSMAP_EDGE_CUTOVER_LIVE_PF_MACROS_PATH="${fake_live_etc_dir}/pf.anchors/macros.pf" \
    OSMAP_EDGE_CUTOVER_LIVE_PF_SELFHOST_PATH="${fake_live_etc_dir}/pf.anchors/selfhost.pf" \
    OSMAP_EDGE_CUTOVER_LIVE_PF_CONF_PATH="${fake_live_etc_dir}/pf.conf" \
    OSMAP_TEST_EDGE_CUTOVER_LOG_FILE="${log_file}" \
    HOME="${tmp_root}" \
    sh "${fake_repo}/maint/live/osmap-live-rehearse-edge-cutover.ksh" --session-dir "${session_dir}"
)

assert_contains "${rehearsal_output}" "prepared edge cutover session in ${session_dir}"
assert_contains "${rehearsal_output}" "apply script: ${session_dir}/scripts/apply-edge-cutover.sh"
assert_contains "${rehearsal_output}" "restore script: ${session_dir}/scripts/restore-edge-cutover.sh"

assert_file_equals "${session_dir}/backup/nginx/sites-enabled/main-ssl.conf" "live-main-ssl"
assert_file_equals "${session_dir}/backup/pf.anchors/macros.pf" "live-macros"
assert_file_equals "${session_dir}/backup/pf.anchors/selfhost.pf" "live-selfhost"
assert_file_equals "${session_dir}/staged/nginx/sites-enabled/main-ssl.conf" "reviewed-main-ssl"
assert_file_equals "${session_dir}/staged/nginx/templates/osmap-root.tmpl" "reviewed-osmap-root"
assert_file_equals "${session_dir}/staged/pf.anchors/macros.pf" "reviewed-macros"
assert_file_equals "${session_dir}/staged/pf.anchors/selfhost.pf" "reviewed-selfhost"

report_contents=$(cat "${session_dir}/edge-cutover-session.txt")
assert_contains "${report_contents}" "osmap_edge_cutover_session_mode=rehearse"
assert_contains "${report_contents}" "session_dir=${session_dir}"
assert_contains "${report_contents}" "apply_script=${session_dir}/scripts/apply-edge-cutover.sh"
assert_contains "${report_contents}" "restore_script=${session_dir}/scripts/restore-edge-cutover.sh"

env PATH="${fake_bin_dir}:${PATH}" OSMAP_TEST_EDGE_CUTOVER_LOG_FILE="${log_file}" sh "${session_dir}/scripts/apply-edge-cutover.sh"

assert_file_equals "${fake_live_etc_dir}/nginx/sites-enabled/main-ssl.conf" "reviewed-main-ssl"
assert_file_equals "${fake_live_etc_dir}/nginx/templates/osmap-root.tmpl" "reviewed-osmap-root"
assert_file_equals "${fake_live_etc_dir}/pf.anchors/macros.pf" "reviewed-macros"
assert_file_equals "${fake_live_etc_dir}/pf.anchors/selfhost.pf" "reviewed-selfhost"

apply_log=$(cat "${log_file}")
assert_contains "${apply_log}" "nginx -t"
assert_contains "${apply_log}" "pfctl -nf ${fake_live_etc_dir}/pf.conf"
assert_contains "${apply_log}" "rcctl reload nginx"
assert_contains "${apply_log}" "pfctl -f ${fake_live_etc_dir}/pf.conf"

: > "${log_file}"
env PATH="${fake_bin_dir}:${PATH}" OSMAP_TEST_EDGE_CUTOVER_LOG_FILE="${log_file}" sh "${session_dir}/scripts/restore-edge-cutover.sh"

assert_file_equals "${fake_live_etc_dir}/nginx/sites-enabled/main-ssl.conf" "live-main-ssl"
[ ! -f "${fake_live_etc_dir}/nginx/templates/osmap-root.tmpl" ] || {
  printf 'expected osmap-root template to be removed during restore\n' >&2
  exit 1
}
assert_file_equals "${fake_live_etc_dir}/pf.anchors/macros.pf" "live-macros"
assert_file_equals "${fake_live_etc_dir}/pf.anchors/selfhost.pf" "live-selfhost"

restore_log=$(cat "${log_file}")
assert_contains "${restore_log}" "nginx -t"
assert_contains "${restore_log}" "pfctl -nf ${fake_live_etc_dir}/pf.conf"
assert_contains "${restore_log}" "rcctl reload nginx"
assert_contains "${restore_log}" "pfctl -f ${fake_live_etc_dir}/pf.conf"

printf '%s\n' "edge cutover rehearsal regression checks passed"
