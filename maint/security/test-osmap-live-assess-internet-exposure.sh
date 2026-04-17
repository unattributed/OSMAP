#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_wrapper="${repo_root}/maint/live/osmap-live-assess-internet-exposure.ksh"
tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/osmap-exposure-assess-test.XXXXXX")
fake_repo="${tmp_root}/repo"
fake_live_dir="${fake_repo}/maint/live"
fake_etc_dir="${tmp_root}/etc"
fake_nginx_dir="${fake_etc_dir}/nginx"
fake_sites_dir="${fake_nginx_dir}/sites-enabled"
fake_templates_dir="${fake_nginx_dir}/templates"
bin_dir="${tmp_root}/bin"

cleanup() {
  rm -rf "${tmp_root}"
}

trap cleanup EXIT INT TERM

mkdir -p "${fake_live_dir}" "${fake_sites_dir}" "${fake_templates_dir}" "${bin_dir}"
cp "${source_wrapper}" "${fake_live_dir}/osmap-live-assess-internet-exposure.ksh"

cat > "${fake_sites_dir}/main.conf" <<'EOF'
server {
    listen 80;
    location / {
        return 301 https://$host$request_uri;
    }
}
EOF

cat > "${fake_sites_dir}/main-ssl.conf" <<'EOF'
server {
    listen 127.0.0.1:443 ssl;
    listen 10.44.0.1:443 ssl;
    include /etc/nginx/templates/ssl.tmpl;
    include /etc/nginx/templates/roundcube.tmpl;
}
EOF

cat > "${fake_templates_dir}/ssl.tmpl" <<'EOF'
ssl_protocols TLSv1.2 TLSv1.3;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
EOF

cat > "${fake_nginx_dir}/control-plane.allow" <<'EOF'
allow 10.44.0.0/24;
allow 127.0.0.1;
EOF

cat > "${bin_dir}/hostname" <<'EOF'
#!/bin/sh
printf '%s\n' "mail.blackbagsecurity.com"
EOF

cat > "${bin_dir}/git" <<'EOF'
#!/bin/sh
printf '%s\n' "deadbeef"
EOF

cat > "${bin_dir}/netstat" <<'EOF'
#!/bin/sh
cat <<'OUT'
tcp          0      0  *.80                   *.*                    LISTEN
tcp          0      0  127.0.0.1.443          *.*                    LISTEN
tcp          0      0  10.44.0.1.443          *.*                    LISTEN
tcp          0      0  127.0.0.1.993          *.*                    LISTEN
tcp          0      0  10.44.0.1.993          *.*                    LISTEN
tcp          0      0  127.0.0.1.465          *.*                    LISTEN
tcp          0      0  10.44.0.1.465          *.*                    LISTEN
tcp          0      0  127.0.0.1.587          *.*                    LISTEN
tcp          0      0  10.44.0.1.587          *.*                    LISTEN
tcp          0      0  *.25                   *.*                    LISTEN
OUT
EOF

cat > "${bin_dir}/pfctl" <<'EOF'
#!/bin/sh
cat <<'OUT'
pass in quick on egress inet proto tcp from any to (egress) port = 22 flags S/SA keep state
pass in quick on egress inet proto udp from any to (egress) port = 51820 keep state
block drop in log quick on egress inet proto tcp from any to (egress) port = 443
pass in quick on wg0 inet proto tcp from 10.44.0.0/24 to any flags S/SA keep state
OUT
EOF

cat > "${bin_dir}/doas" <<'EOF'
#!/bin/sh
if [ "$1" = "test" ]; then
  shift
  exec test "$@"
fi
exec "$@"
EOF

chmod +x \
  "${bin_dir}/hostname" \
  "${bin_dir}/git" \
  "${bin_dir}/netstat" \
  "${bin_dir}/pfctl" \
  "${bin_dir}/doas"

assert_contains() {
  haystack=$1
  needle=$2

  printf '%s' "${haystack}" | grep -Fq "${needle}" || {
    printf 'expected to find "%s" in output:\n%s\n' "${needle}" "${haystack}" >&2
    exit 1
  }
}

report_path="${tmp_root}/internet-exposure-report.txt"
output=$(
  env \
    PATH="${bin_dir}:${PATH}" \
    OSMAP_EXPOSURE_NGINX_MAIN_HTTP_PATH="${fake_sites_dir}/main.conf" \
    OSMAP_EXPOSURE_NGINX_MAIN_SSL_PATH="${fake_sites_dir}/main-ssl.conf" \
    OSMAP_EXPOSURE_NGINX_SSL_TEMPLATE_PATH="${fake_templates_dir}/ssl.tmpl" \
    OSMAP_EXPOSURE_NGINX_CONTROL_PLANE_ALLOW_PATH="${fake_nginx_dir}/control-plane.allow" \
    sh "${fake_live_dir}/osmap-live-assess-internet-exposure.ksh" --report "${report_path}"
)

assert_contains "${output}" "wrote internet exposure report to ${report_path}"
assert_contains "${output}" "internet exposure result: not_approved_for_direct_public_browser_exposure"

report_contents=$(cat "${report_path}")
assert_contains "${report_contents}" "osmap_internet_exposure_result=not_approved_for_direct_public_browser_exposure"
assert_contains "${report_contents}" "assessed_host=mail.blackbagsecurity.com"
assert_contains "${report_contents}" "assessed_snapshot=deadbeef"
assert_contains "${report_contents}" "https_listener_bindings=10.44.0.1.443,127.0.0.1.443"
assert_contains "${report_contents}" "control_plane_allow_entries=10.44.0.0/24,127.0.0.1"
assert_contains "${report_contents}" "canonical_https_vhost_still_includes_roundcube_template"
assert_contains "${report_contents}" "https_listeners_are_limited_to_loopback_and_wireguard_addresses"
assert_contains "${report_contents}" "nginx_control_plane_allowlist_is_limited_to_wireguard_and_loopback"
assert_contains "${report_contents}" "pf_selfhost_anchor_blocks_public_ingress_to_tcp_443"

printf '%s\n' "internet exposure assessment regression checks passed"

