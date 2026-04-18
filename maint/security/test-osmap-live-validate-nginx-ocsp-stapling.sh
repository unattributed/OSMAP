#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-nginx-ocsp-test.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

fake_cert="${tmpdir}/mail.fullchain.pem"
fake_openssl="${tmpdir}/fake-openssl"
report_path="${tmpdir}/report.txt"

printf '%s\n' '-----BEGIN CERTIFICATE-----' 'MIIB' '-----END CERTIFICATE-----' > "${fake_cert}"

cat > "${fake_openssl}" <<EOF
#!/bin/sh
set -eu
if [ "\$1" = "x509" ]; then
  exit 0
fi
if [ "\$1" = "s_client" ]; then
  cat <<'OUT'
OCSP response: successful
OCSP Response Status: successful (0x0)
OUT
  exit 0
fi
printf 'unexpected fake openssl arguments: %s\n' "\$*" >&2
exit 1
EOF
chmod 0755 "${fake_openssl}"

OSMAP_NGINX_OCSP_OPENSSL_BIN="${fake_openssl}" \
OSMAP_NGINX_OCSP_DOAS_BIN="" \
OSMAP_NGINX_OCSP_CERT_PATH="${fake_cert}" \
	sh "${repo_root}/maint/live/osmap-live-validate-nginx-ocsp-stapling.ksh" \
	--report "${report_path}" || true

grep -Fq 'nginx_ocsp_stapling_result=unsupported_by_certificate' "${report_path}"
grep -Fq 'failure_reason=leaf_certificate_has_no_ocsp_responder_url' "${report_path}"
grep -Fq "cert_path=${fake_cert}" "${report_path}"

cat > "${fake_openssl}" <<EOF
#!/bin/sh
set -eu
if [ "\$1" = "x509" ]; then
  printf '%s\n' 'http://ocsp.example.invalid/'
  exit 0
fi
if [ "\$1" = "s_client" ]; then
  cat <<'OUT'
CONNECTED(00000003)
OCSP response: successful
======================================
OCSP Response Data:
    OCSP Response Status: successful (0x0)
OUT
  exit 0
fi
printf 'unexpected fake openssl arguments: %s\n' "\$*" >&2
exit 1
EOF
chmod 0755 "${fake_openssl}"

OSMAP_NGINX_OCSP_OPENSSL_BIN="${fake_openssl}" \
OSMAP_NGINX_OCSP_DOAS_BIN="" \
OSMAP_NGINX_OCSP_CERT_PATH="${fake_cert}" \
	sh "${repo_root}/maint/live/osmap-live-validate-nginx-ocsp-stapling.ksh" \
	--report "${report_path}"

grep -Fq 'nginx_ocsp_stapling_result=passed' "${report_path}"
grep -Fq 'ocsp_responder_url=http://ocsp.example.invalid/' "${report_path}"
grep -Fq 's_client_status_line=OCSP response: successful' "${report_path}"

echo "nginx OCSP stapling validation regression checks passed"
