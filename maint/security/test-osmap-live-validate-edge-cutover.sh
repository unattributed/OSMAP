#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_wrapper="${repo_root}/maint/live/osmap-live-validate-edge-cutover.ksh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-edge-cutover-test.XXXXXX")
fake_repo="${tmp_root}/repo"
fake_live_dir="${fake_repo}/maint/live"
fake_etc_dir="${tmp_root}/etc"
fake_nginx_dir="${fake_etc_dir}/nginx"
fake_sites_dir="${fake_nginx_dir}/sites-enabled"
fake_templates_dir="${fake_nginx_dir}/templates"
fake_pf_dir="${fake_etc_dir}/pf.anchors"
pass_bin_dir="${tmp_root}/pass-bin"
fail_bin_dir="${tmp_root}/fail-bin"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p \
  "${fake_live_dir}" \
  "${fake_sites_dir}" \
  "${fake_templates_dir}" \
  "${fake_pf_dir}" \
  "${pass_bin_dir}" \
  "${fail_bin_dir}"
cp "${source_wrapper}" "${fake_live_dir}/osmap-live-validate-edge-cutover.ksh"

cat > "${fake_sites_dir}/main-ssl-pass.conf" <<'EOF'
server {
    listen 127.0.0.1:443 ssl;
    listen 10.44.0.1:443 ssl;
    listen 192.168.1.44:443 ssl;
    include /etc/nginx/templates/ssl.tmpl;
    include /etc/nginx/templates/osmap-root.tmpl;
}
EOF

cat > "${fake_sites_dir}/main-ssl-fail.conf" <<'EOF'
server {
    listen 127.0.0.1:443 ssl;
    listen 10.44.0.1:443 ssl;
    include /etc/nginx/templates/ssl.tmpl;
    include /etc/nginx/templates/roundcube.tmpl;
}
EOF

cat > "${fake_templates_dir}/osmap-root-pass.tmpl" <<'EOF'
location = /mail { return 301 /; }
location = /webmail { return 301 /; }
location ^~ /mail/ { return 301 /; }
location ^~ /webmail/ { return 301 /; }

location / {
    limit_except GET POST { deny all; }

    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_buffering off;
}
EOF

cat > "${fake_templates_dir}/osmap-root-fail.tmpl" <<'EOF'
location / {
    include /etc/nginx/templates/control-plane-allow.tmpl;
    proxy_pass http://127.0.0.1:8080;
}
EOF

cat > "${fake_pf_dir}/macros-pass.pf" <<'EOF'
wan_blocked_tcp_svcs   = "{ 110, 143, 465, 587, 993, 995, 2000, 4190, 8080, 9999 }"
EOF

cat > "${fake_pf_dir}/macros-fail.pf" <<'EOF'
wan_blocked_tcp_svcs   = "{ 110, 143, 443, 465, 587, 993, 995, 2000, 4190, 8080, 9999 }"
EOF

cat > "${fake_pf_dir}/selfhost-pass.pf" <<'EOF'
pass in quick on $ext_if inet proto tcp from any to ($ext_if) port = 443 \
    flags S/SA synproxy state (if-bound)
block drop in log quick on $ext_if inet proto tcp from any \
    to ($ext_if) port $wan_blocked_tcp_svcs
EOF

cat > "${fake_pf_dir}/selfhost-fail.pf" <<'EOF'
block drop in log quick on $ext_if inet proto tcp from any \
    to ($ext_if) port $wan_blocked_tcp_svcs
EOF

write_common_stub_bins() {
  bin_dir=$1

  cat > "${bin_dir}/hostname" <<'EOF'
#!/bin/sh
printf '%s\n' "mail.blackbagsecurity.com"
EOF

  cat > "${bin_dir}/git" <<'EOF'
#!/bin/sh
printf '%s\n' "feedface"
EOF

  cat > "${bin_dir}/doas" <<'EOF'
#!/bin/sh
if [ "$1" = "test" ]; then
  shift
  exec test "$@"
fi
exec "$@"
EOF

  chmod +x "${bin_dir}/hostname" "${bin_dir}/git" "${bin_dir}/doas"
}

write_common_stub_bins "${pass_bin_dir}"
write_common_stub_bins "${fail_bin_dir}"

cat > "${pass_bin_dir}/netstat" <<'EOF'
#!/bin/sh
cat <<'OUT'
tcp          0      0  127.0.0.1.443          *.*                    LISTEN
tcp          0      0  10.44.0.1.443          *.*                    LISTEN
tcp          0      0  192.168.1.44.443       *.*                    LISTEN
tcp          0      0  127.0.0.1.8080         *.*                    LISTEN
OUT
EOF

cat > "${fail_bin_dir}/netstat" <<'EOF'
#!/bin/sh
cat <<'OUT'
tcp          0      0  127.0.0.1.443          *.*                    LISTEN
tcp          0      0  10.44.0.1.443          *.*                    LISTEN
tcp          0      0  127.0.0.1.8080         *.*                    LISTEN
OUT
EOF

cat > "${pass_bin_dir}/pfctl" <<'EOF'
#!/bin/sh
cat <<'OUT'
pass in quick on egress inet proto tcp from any to (egress) port = 443 flags S/SA synproxy state
OUT
EOF

cat > "${fail_bin_dir}/pfctl" <<'EOF'
#!/bin/sh
cat <<'OUT'
block drop in log quick on egress inet proto tcp from any to (egress) port = 443
OUT
EOF

chmod +x \
  "${pass_bin_dir}/netstat" \
  "${fail_bin_dir}/netstat" \
  "${pass_bin_dir}/pfctl" \
  "${fail_bin_dir}/pfctl"

assert_contains() {
  haystack=$1
  needle=$2

  printf '%s' "${haystack}" | grep -Fq "${needle}" || {
    printf 'expected to find "%s" in output:\n%s\n' "${needle}" "${haystack}" >&2
    exit 1
  }
}

pass_report="${tmp_root}/edge-cutover-pass-report.txt"
pass_output=$(
  env \
    PATH="${pass_bin_dir}:${PATH}" \
    OSMAP_EDGE_CUTOVER_NGINX_MAIN_SSL_PATH="${fake_sites_dir}/main-ssl-pass.conf" \
    OSMAP_EDGE_CUTOVER_NGINX_OSMAP_ROOT_TEMPLATE_PATH="${fake_templates_dir}/osmap-root-pass.tmpl" \
    OSMAP_EDGE_CUTOVER_PF_MACROS_PATH="${fake_pf_dir}/macros-pass.pf" \
    OSMAP_EDGE_CUTOVER_PF_SELFHOST_FILE_PATH="${fake_pf_dir}/selfhost-pass.pf" \
    sh "${fake_live_dir}/osmap-live-validate-edge-cutover.ksh" --report "${pass_report}"
)

assert_contains "${pass_output}" "wrote edge cutover report to ${pass_report}"
assert_contains "${pass_output}" "edge cutover validation result: passed"
pass_report_contents=$(cat "${pass_report}")
assert_contains "${pass_report_contents}" "osmap_edge_cutover_result=passed"
assert_contains "${pass_report_contents}" "assessed_host=mail.blackbagsecurity.com"
assert_contains "${pass_report_contents}" "assessed_snapshot=feedface"
assert_contains "${pass_report_contents}" "https_listener_bindings=10.44.0.1.443,127.0.0.1.443,192.168.1.44.443"
assert_contains "${pass_report_contents}" "canonical_https_includes=/etc/nginx/templates/ssl.tmpl,/etc/nginx/templates/osmap-root.tmpl"

fail_report="${tmp_root}/edge-cutover-fail-report.txt"
set +e
fail_output=$(
  env \
    PATH="${fail_bin_dir}:${PATH}" \
    OSMAP_EDGE_CUTOVER_NGINX_MAIN_SSL_PATH="${fake_sites_dir}/main-ssl-fail.conf" \
    OSMAP_EDGE_CUTOVER_NGINX_OSMAP_ROOT_TEMPLATE_PATH="${fake_templates_dir}/osmap-root-fail.tmpl" \
    OSMAP_EDGE_CUTOVER_PF_MACROS_PATH="${fake_pf_dir}/macros-fail.pf" \
    OSMAP_EDGE_CUTOVER_PF_SELFHOST_FILE_PATH="${fake_pf_dir}/selfhost-fail.pf" \
    sh "${fake_live_dir}/osmap-live-validate-edge-cutover.ksh" --report "${fail_report}" 2>&1
)
fail_status=$?
set -e

[ "${fail_status}" -eq 1 ] || {
  printf 'expected failing edge cutover validation to exit 1, got %s\n' "${fail_status}" >&2
  exit 1
}

assert_contains "${fail_output}" "wrote edge cutover report to ${fail_report}"
assert_contains "${fail_output}" "edge cutover validation result: failed"
fail_report_contents=$(cat "${fail_report}")
assert_contains "${fail_report_contents}" "osmap_edge_cutover_result=failed"
assert_contains "${fail_report_contents}" "canonical_https_vhost_missing_osmap_root_template_include"
assert_contains "${fail_report_contents}" "canonical_https_vhost_still_includes_roundcube_template"
assert_contains "${fail_report_contents}" "osmap_root_template_missing_mail_redirect"
assert_contains "${fail_report_contents}" "osmap_root_template_unexpectedly_uses_control_plane_allowlist"
assert_contains "${fail_report_contents}" "https_listener_bindings_do_not_match_edge_cutover_plan"
assert_contains "${fail_report_contents}" "pf_macros_still_block_wan_tcp_443"
assert_contains "${fail_report_contents}" "pf_selfhost_config_missing_public_https_rule"
assert_contains "${fail_report_contents}" "pf_selfhost_runtime_missing_public_https_rule"
assert_contains "${fail_report_contents}" "pf_selfhost_runtime_still_blocks_public_https"

printf '%s\n' "edge cutover validation regression checks passed"
