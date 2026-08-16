#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
artifact_root="${repo_root}/maint/openbsd/mail.blackbagsecurity.com"
main_ssl="${artifact_root}/nginx/sites-enabled/main-ssl.conf"
osmap_root="${artifact_root}/nginx/templates/osmap-root.tmpl"
osmap_public_root="${artifact_root}/nginx/templates/osmap-public-root.tmpl"
osmap_edge_http="${artifact_root}/nginx/conf-enabled/10-osmap-public-edge.conf"
osmap_newsyslog="${artifact_root}/newsyslog/osmap-public.conf"
pf_macros="${artifact_root}/pf.anchors/macros.pf"
pf_selfhost="${artifact_root}/pf.anchors/selfhost.pf"

assert_contains_file() {
  file_path=$1
  needle=$2

  grep -Fq "${needle}" "${file_path}" || {
    printf 'expected to find "%s" in %s\n' "${needle}" "${file_path}" >&2
    exit 1
  }
}

assert_not_contains_file() {
  file_path=$1
  needle=$2

  if grep -Fq "${needle}" "${file_path}"; then
    printf 'did not expect to find "%s" in %s\n' "${needle}" "${file_path}" >&2
    exit 1
  fi
}

for required_path in \
  "${artifact_root}/README.md" \
  "${main_ssl}" \
  "${osmap_root}" \
  "${osmap_public_root}" \
  "${osmap_edge_http}" \
  "${osmap_newsyslog}" \
  "${pf_macros}" \
  "${pf_selfhost}"
do
  [ -f "${required_path}" ] || {
    printf 'missing required edge artifact: %s\n' "${required_path}" >&2
    exit 1
  }
done

assert_contains_file "${main_ssl}" "listen 127.0.0.1:443 ssl;"
assert_contains_file "${main_ssl}" "listen 10.44.0.1:443 ssl;"
assert_contains_file "${main_ssl}" "listen 192.168.1.44:443 ssl;"
assert_contains_file "${main_ssl}" "include /etc/nginx/templates/osmap-public-root.tmpl;"
assert_contains_file "${main_ssl}" 'if ($host != "mail.blackbagsecurity.com") {'
assert_contains_file "${main_ssl}" 'if ($host !~ ^(mail\.blackbagsecurity\.com|10\.44\.0\.1|127\.0\.0\.1)$) {'
assert_not_contains_file "${main_ssl}" "include /etc/nginx/templates/roundcube.tmpl;"
assert_contains_file "${main_ssl}" "Public WAN exposure is intentionally limited to OSMAP"
assert_contains_file "${main_ssl}" "Existing private/control applications remain available only"
assert_contains_file "${main_ssl}" "access_log /var/log/nginx/osmap.public.access.log osmap_public_security;"
assert_contains_file "${main_ssl}" "error_log  /var/log/nginx/osmap.public.error.log;"
assert_contains_file "${main_ssl}" "access_log /var/log/nginx/mail.private.access.log;"
assert_contains_file "${main_ssl}" "error_log  /var/log/nginx/mail.private.error.log;"
assert_not_contains_file "${main_ssl}" "access_log /var/log/nginx/mail.access.log;"
assert_not_contains_file "${main_ssl}" "error_log  /var/log/nginx/mail.error.log;"
assert_contains_file "${main_ssl}" "TLS, misc hardening, OSMAP, and private/control application templates"
assert_contains_file "${main_ssl}" "include /etc/nginx/templates/sogo.tmpl;"
assert_contains_file "${main_ssl}" "include /etc/nginx/templates/postfixadmin.tmpl;"
assert_not_contains_file "${main_ssl}" "include /etc/nginx/templates/php-catchall.tmpl;"
assert_contains_file "${main_ssl}" "include /etc/nginx/templates/pf_dashboard.locations.tmpl;"

assert_contains_file "${osmap_root}" "location = /mail { return 301 /; }"
assert_contains_file "${osmap_root}" "location = /webmail { return 301 /; }"
assert_contains_file "${osmap_root}" "limit_except GET POST { deny all; }"
assert_contains_file "${osmap_root}" "proxy_pass http://127.0.0.1:8080;"
assert_contains_file "${osmap_root}" 'proxy_set_header Host $host;'
assert_contains_file "${osmap_root}" 'proxy_set_header X-Real-IP $remote_addr;'
assert_contains_file "${osmap_root}" 'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'
assert_contains_file "${osmap_root}" "keepalive_timeout 0;"
assert_contains_file "${osmap_root}" "osmap.differential.access.log osmap_differential_security"
assert_not_contains_file "${osmap_root}" "control-plane-allow.tmpl"

assert_contains_file "${osmap_public_root}" "limit_req zone=osmap_public_login burst=6 nodelay;"
assert_contains_file "${osmap_public_root}" "limit_req zone=osmap_public_general burst=30 nodelay;"
assert_contains_file "${osmap_public_root}" "limit_conn osmap_public_connections 10;"
assert_contains_file "${osmap_public_root}" "proxy_pass http://127.0.0.1:8080;"
assert_contains_file "${osmap_public_root}" 'proxy_set_header Host $host;'
assert_contains_file "${osmap_public_root}" 'proxy_set_header X-Real-IP $remote_addr;'
assert_contains_file "${osmap_public_root}" "keepalive_timeout 0;"
assert_contains_file "${osmap_public_root}" "osmap.differential.access.log osmap_differential_security"

assert_contains_file "${osmap_edge_http}" "log_format osmap_public_security"
assert_contains_file "${osmap_edge_http}" 'uri="$uri"'
assert_contains_file "${osmap_edge_http}" "map \$request \$osmap_differential_loggable"
assert_contains_file "${osmap_edge_http}" "~OSMAPS04-[A-Za-z0-9_-]+ 1;"
assert_contains_file "${osmap_edge_http}" "log_format osmap_differential_security"
assert_contains_file "${osmap_edge_http}" 'request_uri="$request_uri"'
assert_not_contains_file "${osmap_edge_http}" '$http_referer'
assert_not_contains_file "${osmap_edge_http}" '$http_x_forwarded_for'
assert_contains_file "${osmap_edge_http}" "zone=osmap_public_login:1m rate=12r/m;"

assert_contains_file "${osmap_newsyslog}" "osmap.public.access.log root:wheel 640"
assert_contains_file "${osmap_newsyslog}" "osmap.public.error.log  root:wheel 640"
assert_contains_file "${osmap_newsyslog}" "osmap.differential.access.log root:wheel 640"

assert_contains_file "${pf_macros}" 'wan_blocked_tcp_svcs   = "{ 110, 143, 465, 587, 993, 995, 2000, 4190, 8080, 9999 }"'
assert_not_contains_file "${pf_macros}" 'wan_blocked_tcp_svcs   = "{ 110, 143, 443, 465, 587, 993, 995, 2000, 4190, 8080, 9999 }"'

assert_contains_file "${pf_selfhost}" 'pass in quick on $ext_if inet proto tcp from any to ($ext_if) port = 443 \'
assert_contains_file "${pf_selfhost}" 'flags S/SA synproxy state (if-bound)'
assert_contains_file "${pf_selfhost}" 'to ($ext_if) port $wan_blocked_tcp_svcs'

printf '%s\n' "mail host edge artifact regression checks passed"
