#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-public-send-audit-test.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

serve_log="${tmpdir}/serve.log"
totp_dir="${tmpdir}/totp"
bin_dir="${tmpdir}/bin"
mkdir -p "${totp_dir}" "${bin_dir}"
printf '%s\n' 'existing line' > "${serve_log}"

fake_curl="${bin_dir}/fake-curl"
cat > "${fake_curl}" <<EOF
#!/bin/sh
set -eu

headers=""
output=""
url=""
method="GET"

while [ "\$#" -gt 0 ]; do
  case "\$1" in
    -D)
      headers="\$2"
      shift 2
      ;;
    -o)
      output="\$2"
      shift 2
      ;;
    --data-binary)
      method="POST"
      shift 2
      ;;
    http://*|https://*)
      url="\$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

path="/\${url#*://*/}"
if [ "\${path}" = "/https://mail.blackbagsecurity.com" ]; then
  path="/"
fi

write_response() {
  status="\$1"
  location="\${2:-}"
  {
    printf 'HTTP/2 %s\\r\\n' "\${status}"
    if [ -n "\${location}" ]; then
      printf 'Location: %s\\r\\n' "\${location}"
    fi
    printf '\\r\\n'
  } > "\${headers}"
}

case "\${method} \${path}" in
  "GET /login")
    write_response 200
    printf '%s\\n' '<h1>OSMAP Login</h1>' > "\${output}"
    ;;
  "POST /login")
    write_response 303 /mailboxes
    printf '%s\\n' '' > "\${output}"
    printf '%s\\n' 'ts=10 level=info category=auth action=second_factor_accepted msg="second factor accepted, session issuance pending" canonical_username="osmap-helper-validation@blackbagsecurity.com" request_id="http-2" remote_addr="198.51.100.44" user_agent="OSMAP-Public-Send-Audit-Correlation/20260419"' >> "${serve_log}"
    printf '%s\\n' 'ts=10 level=info category=session action=session_issued msg="browser session issued" session_id="abc" canonical_username="osmap-helper-validation@blackbagsecurity.com" request_id="http-2" remote_addr="198.51.100.44" user_agent="OSMAP-Public-Send-Audit-Correlation/20260419"' >> "${serve_log}"
    printf '%s\\n' 'ts=10 level=info category=http action=http_request_completed msg="http request completed" remote_addr="198.51.100.44" method="POST" path="/login" status_code="303" response_bytes="648" duration_ms="5"' >> "${serve_log}"
    ;;
  "GET /mailboxes")
    write_response 200
    printf '%s\\n' '<h1>Mailboxes</h1>' > "\${output}"
    printf '%s\\n' 'ts=11 level=info category=session action=session_validated msg="browser session validated" session_id="abc" canonical_username="osmap-helper-validation@blackbagsecurity.com" request_id="http-3" remote_addr="198.51.100.44" user_agent="OSMAP-Public-Send-Audit-Correlation/20260419"' >> "${serve_log}"
    printf '%s\\n' 'ts=11 level=info category=mailbox action=mailbox_listed msg="mailbox listing completed" canonical_username="osmap-helper-validation@blackbagsecurity.com" session_id="abc" mailbox_count="1" request_id="http-3" remote_addr="198.51.100.44" user_agent="OSMAP-Public-Send-Audit-Correlation/20260419"' >> "${serve_log}"
    printf '%s\\n' 'ts=11 level=info category=http action=http_request_completed msg="http request completed" remote_addr="198.51.100.44" method="GET" path="/mailboxes" status_code="200" response_bytes="2000" duration_ms="3"' >> "${serve_log}"
    ;;
  "GET /compose")
    write_response 200
    printf '%s\\n' '<input type="hidden" name="csrf_token" value="csrf-token-1">' > "\${output}"
    printf '%s\\n' 'ts=12 level=info category=session action=session_validated msg="browser session validated" session_id="abc" canonical_username="osmap-helper-validation@blackbagsecurity.com" request_id="http-4" remote_addr="198.51.100.44" user_agent="OSMAP-Public-Send-Audit-Correlation/20260419"' >> "${serve_log}"
    printf '%s\\n' 'ts=12 level=info category=http action=http_request_completed msg="http request completed" remote_addr="198.51.100.44" method="GET" path="/compose" status_code="200" response_bytes="2100" duration_ms="3"' >> "${serve_log}"
    ;;
  "POST /send")
    write_response 303 /compose?sent=1
    printf '%s\\n' '' > "\${output}"
    printf '%s\\n' 'ts=13 level=info category=session action=session_validated msg="browser session validated" session_id="abc" canonical_username="osmap-helper-validation@blackbagsecurity.com" request_id="http-5" remote_addr="198.51.100.44" user_agent="OSMAP-Public-Send-Audit-Correlation/20260419"' >> "${serve_log}"
    printf '%s\\n' 'ts=13 level=info category=submission action=message_submitted msg="outbound message submission completed" canonical_username="osmap-helper-validation@blackbagsecurity.com" session_id="abc" recipient_count="1" attachment_count="0" attachment_bytes_total="0" has_subject="true" request_id="http-5" remote_addr="198.51.100.44" user_agent="OSMAP-Public-Send-Audit-Correlation/20260419"' >> "${serve_log}"
    printf '%s\\n' 'ts=13 level=info category=http action=http_request_completed msg="http request completed" remote_addr="198.51.100.44" method="POST" path="/send" status_code="303" response_bytes="501" duration_ms="9"' >> "${serve_log}"
    ;;
  *)
    printf 'unexpected fake curl request: %s %s\\n' "\${method}" "\${path}" >&2
    exit 1
    ;;
esac
EOF
chmod 0755 "${fake_curl}"

fake_mariadb="${bin_dir}/fake-mariadb"
cat > "${fake_mariadb}" <<'EOF'
#!/bin/sh
set -eu
for arg in "$@"; do
  if [ "$arg" = "-e" ]; then
    printf '%s\n' 'old-mailbox-hash'
    exit 0
  fi
done
cat >/dev/null
EOF
chmod 0755 "${fake_mariadb}"

fake_doveadm="${bin_dir}/fake-doveadm"
cat > "${fake_doveadm}" <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
  pw)
    printf '%s\n' '{BLF-CRYPT}temporary-hash'
    ;;
  -o)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
EOF
chmod 0755 "${fake_doveadm}"

fake_openssl="${bin_dir}/fake-openssl"
cat > "${fake_openssl}" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' 'temporary-password'
EOF
chmod 0755 "${fake_openssl}"

report_path="${tmpdir}/report.txt"

OSMAP_PUBLIC_SEND_AUDIT_CURL_BIN="${fake_curl}" \
OSMAP_PUBLIC_SEND_AUDIT_DOAS_BIN="" \
OSMAP_PUBLIC_SEND_AUDIT_OPENSSL_BIN="${fake_openssl}" \
OSMAP_PUBLIC_SEND_AUDIT_DOVEADM_BIN="${fake_doveadm}" \
OSMAP_PUBLIC_SEND_AUDIT_MARIADB_BIN="${fake_mariadb}" \
OSMAP_PUBLIC_SEND_AUDIT_SERVE_LOG_PATH="${serve_log}" \
OSMAP_PUBLIC_SEND_AUDIT_TOTP_DIR="${totp_dir}" \
OSMAP_PUBLIC_SEND_AUDIT_SKIP_CHOWN=1 \
	sh "${repo_root}/maint/live/osmap-live-validate-public-send-audit-correlation.ksh" \
	--report "${report_path}"

grep -Fq 'osmap_public_send_audit_correlation_result=passed' "${report_path}"
grep -Fq 'expected_remote_addr=198.51.100.44' "${report_path}"
grep -Fq 'matched_auth_event=ts=10 level=info category=auth action=second_factor_accepted' "${report_path}"
grep -Fq 'matched_session_issued_event=ts=10 level=info category=session action=session_issued' "${report_path}"
grep -Fq 'matched_session_validated_event=ts=13 level=info category=session action=session_validated' "${report_path}"
grep -Fq 'matched_mailbox_event=ts=11 level=info category=mailbox action=mailbox_listed' "${report_path}"
grep -Fq 'matched_submission_event=ts=13 level=info category=submission action=message_submitted' "${report_path}"
grep -Fq 'matched_completion_event=ts=13 level=info category=http action=http_request_completed' "${report_path}"

echo "public send audit correlation validation regression checks passed"
