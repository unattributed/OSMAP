#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-auth-observability-test.XXXXXX")
trap 'rm -rf "$tmpdir"' EXIT INT TERM

serve_log="${tmpdir}/serve.log"
printf 'existing line\n' > "${serve_log}"

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
printf '%s\n' '<html>login failed</html>' > "\${output}"
printf '%s\n' 'ts=2 level=warn category=auth action=login_denied msg="primary authentication denied" stage="primary" result="denied" public_reason="invalid_credentials" audit_reason="invalid_credentials" submitted_username="osmap-log-probe@example.invalid"' >> "${serve_log}"
printf '401'
EOF
chmod 0755 "${fake_curl}"

report_path="${tmpdir}/report.txt"

OSMAP_AUTH_OBSERVABILITY_CURL_BIN="${fake_curl}" \
OSMAP_AUTH_OBSERVABILITY_DOAS_BIN="" \
OSMAP_AUTH_OBSERVABILITY_SERVE_LOG_PATH="${serve_log}" \
	sh "${repo_root}/maint/live/osmap-live-validate-auth-observability.ksh" \
	--report "${report_path}"

grep -Fq 'osmap_auth_observability_result=passed' "${report_path}"
grep -Fq "serve_log_path=${serve_log}" "${report_path}"
grep -Fq 'matched_auth_event=ts=2 level=warn category=auth action=login_denied' "${report_path}"

echo "auth observability validation regression checks passed"
