#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-effective-client-ip-test.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

serve_log="${tmpdir}/serve.log"
printf '%s\n' 'existing line' > "${serve_log}"

fake_curl="${tmpdir}/fake-curl"
cat > "${fake_curl}" <<EOF
#!/bin/sh
set -eu
output=""
while [ "\$#" -gt 0 ]; do
  case "\$1" in
    -o)
      output="\$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '%s\n' '<h1>OSMAP Login</h1>' > "\${output}"
printf '%s\n' 'ts=3 level=info category=http action=http_login_form_served msg="login form served" request_id="http-7" remote_addr="198.51.100.24" user_agent="OSMAP-Effective-Client-IP-Probe/20260418"' >> "${serve_log}"
printf '%s\n' 'ts=3 level=info category=http action=http_request_completed msg="http request completed" remote_addr="198.51.100.24" method="GET" path="/login" status_code="200" response_bytes="1807" duration_ms="1"' >> "${serve_log}"
printf '200'
EOF
chmod 0755 "${fake_curl}"

report_path="${tmpdir}/report.txt"

OSMAP_EFFECTIVE_CLIENT_IP_CURL_BIN="${fake_curl}" \
OSMAP_EFFECTIVE_CLIENT_IP_DOAS_BIN="" \
OSMAP_EFFECTIVE_CLIENT_IP_SERVE_LOG_PATH="${serve_log}" \
	sh "${repo_root}/maint/live/osmap-live-validate-effective-client-ip-telemetry.ksh" \
	--report "${report_path}"

grep -Fq 'osmap_effective_client_ip_result=passed' "${report_path}"
grep -Fq "serve_log_path=${serve_log}" "${report_path}"
grep -Fq 'expected_remote_addr=198.51.100.24' "${report_path}"
grep -Fq 'matched_route_event=ts=3 level=info category=http action=http_login_form_served' "${report_path}"
grep -Fq 'matched_completion_event=ts=3 level=info category=http action=http_request_completed' "${report_path}"

echo "effective client ip telemetry regression checks passed"
