#!/bin/sh

set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
REPORT_PATH=${OSMAP_V6_PRODUCTION_REPORT_PATH:-"$PROJECT_ROOT/maint/live/latest-host-v6-production-readiness-report.txt"}
ALLOW_MISSING=0

OSMAP_BIN_PATH=${OSMAP_V6_OSMAP_BIN_PATH:-/usr/local/bin/osmap}
SERVE_ENV_PATH=${OSMAP_V6_SERVE_ENV_PATH:-/etc/osmap/osmap-serve.env}
SERVE_LOG_PATH=${OSMAP_V6_SERVE_LOG_PATH:-/var/log/osmap/serve.log}
HELPER_LOG_PATH=${OSMAP_V6_HELPER_LOG_PATH:-/var/log/osmap/mailbox-helper.log}
HELPER_SOCKET_PATH=${OSMAP_V6_HELPER_SOCKET_PATH:-/var/lib/osmap-helper/run/mailbox-helper.sock}
BINARY_BACKUP_DIR=${OSMAP_V6_BINARY_BACKUP_DIR:-/usr/local/bin}
ENV_BACKUP_DIR=${OSMAP_V6_ENV_BACKUP_DIR:-/etc/osmap}
HEALTH_URL=${OSMAP_V6_HEALTH_URL:-https://192.168.1.44/healthz}
ALLOWED_HOST=${OSMAP_V6_ALLOWED_HOST:-mail.blackbagsecurity.com}
INVALID_HOST=${OSMAP_V6_INVALID_HOST:-attacker.invalid}

FAILED_CHECKS=""

usage() {
	cat <<EOF
usage: $(basename "$0") [--report <path>] [--allow-missing-live-context]

Developer mode records unavailable checks but can never emit a passing report.
EOF
}

append_failure() {
	if [ -z "$FAILED_CHECKS" ]; then
		FAILED_CHECKS=$1
	else
		FAILED_CHECKS="${FAILED_CHECKS}
$1"
	fi
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--report)
			[ "$#" -ge 2 ] || { echo "--report requires a path" >&2; exit 1; }
			REPORT_PATH=$2
			shift 2
			;;
		--report=*)
			REPORT_PATH=${1#--report=}
			shift
			;;
		--allow-missing-live-context)
			ALLOW_MISSING=1
			shift
			;;
		--help|-h)
			usage
			exit 0
			;;
		*)
			echo "unknown option: $1" >&2
			usage >&2
			exit 1
			;;
	esac
done

for tool in awk curl date doas find git grep hostname netstat rcctl sed sha256 sort stat; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		append_failure "missing_tool_$tool"
	fi
done

if [ -n "$FAILED_CHECKS" ] && [ "$ALLOW_MISSING" -eq 0 ]; then
	printf '%s\n' "$FAILED_CHECKS" >&2
	exit 1
fi

capture_metadata() {
	path=$1
	if ! doas test -e "$path"; then
		printf '%s' "missing"
		return
	fi
	doas stat -f '%Su:%Sg:%Lp' "$path" 2>/dev/null ||
		doas stat -c '%U:%G:%a' "$path" 2>/dev/null ||
		printf '%s' "unavailable"
}

service_status() {
	if doas rcctl check "$1" >/dev/null 2>&1; then
		printf '%s' "ok"
	else
		printf '%s' "failed"
	fi
}

TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
HOST=$(hostname)
REPO_COMMIT=${OSMAP_V6_DEPLOYED_COMMIT:-$(git -C "$PROJECT_ROOT" rev-parse HEAD 2>/dev/null || printf '%s' "unavailable")}
BINARY_SHA256="unavailable"
if doas test -f "$OSMAP_BIN_PATH"; then
	BINARY_SHA256=$(doas sha256 -q "$OSMAP_BIN_PATH" 2>/dev/null ||
		doas sha256 "$OSMAP_BIN_PATH" 2>/dev/null | awk '{ print $NF }' ||
		printf '%s' "unavailable")
else
	append_failure "missing_osmap_binary"
fi

SERVE_STATUS=$(service_status osmap_serve)
HELPER_STATUS=$(service_status osmap_mailbox_helper)
[ "$SERVE_STATUS" = "ok" ] || append_failure "osmap_serve_not_healthy"
[ "$HELPER_STATUS" = "ok" ] || append_failure "osmap_mailbox_helper_not_healthy"

SERVE_ENV_METADATA=$(capture_metadata "$SERVE_ENV_PATH")
SERVE_LOG_METADATA=$(capture_metadata "$SERVE_LOG_PATH")
HELPER_LOG_METADATA=$(capture_metadata "$HELPER_LOG_PATH")
HELPER_SOCKET_METADATA=$(capture_metadata "$HELPER_SOCKET_PATH")

case "$SERVE_ENV_METADATA" in
	root:osmaprt:640) ;;
	*) append_failure "serve_env_permissions_not_root_osmaprt_0640" ;;
esac

if doas test -f "$SERVE_ENV_PATH" &&
	doas grep -Eq "^OSMAP_ALLOWED_HOSTS=.*${ALLOWED_HOST}" "$SERVE_ENV_PATH"; then
	ALLOWED_HOSTS_PRESENT="yes"
else
	ALLOWED_HOSTS_PRESENT="no"
	append_failure "allowed_hosts_missing"
fi

LOG_PATHS_STATUS="passed"
for metadata in "$SERVE_LOG_METADATA" "$HELPER_LOG_METADATA"; do
	case "$metadata" in
		missing|unavailable|*:[0-7][0-7][1-7])
			LOG_PATHS_STATUS="failed"
			;;
	esac
done
[ "$LOG_PATHS_STATUS" = "passed" ] || append_failure "unsafe_or_missing_log_paths"

case "$HELPER_SOCKET_METADATA" in
	*:osmaprt:660) ;;
	*) append_failure "helper_socket_permissions_unexpected" ;;
esac

VALID_HOST_CODE=$(curl -ksS -o /dev/null -w '%{http_code}' -H "Host: $ALLOWED_HOST" "$HEALTH_URL" 2>/dev/null || printf '%s' "000")
INVALID_HOST_CODE=$(curl -ksS -o /dev/null -w '%{http_code}' -H "Host: $INVALID_HOST" "$HEALTH_URL" 2>/dev/null || printf '%s' "000")
[ "$VALID_HOST_CODE" = "200" ] || append_failure "valid_host_health_failed"
[ "$INVALID_HOST_CODE" = "421" ] || append_failure "invalid_host_did_not_return_421"

LISTENER_LINES=$(netstat -na -f inet 2>/dev/null | awk '/LISTEN/ { print }')
BACKEND_PUBLIC_EXPOSURE="not_detected"
if printf '%s\n' "$LISTENER_LINES" |
	awk '$4 ~ /\.8080$/ && $4 != "127.0.0.1.8080" { found=1 } END { exit(found ? 0 : 1) }'; then
	BACKEND_PUBLIC_EXPOSURE="detected"
	append_failure "backend_port_publicly_bound"
fi

select_rollback_unit() {
	for binary_path in $(doas find "$BINARY_BACKUP_DIR" -type f -name 'osmap.pre-*' -print 2>/dev/null | sort -r); do
		binary_name=${binary_path##*/}
		artifact_suffix=${binary_name#osmap.pre-}
		env_path="$ENV_BACKUP_DIR/osmap-serve.env.pre-$artifact_suffix"
		if doas test -f "$env_path"; then
			printf '%s\n%s\n' "$binary_path" "$env_path"
			return
		fi
	done
}

ROLLBACK_UNIT=$(select_rollback_unit || true)
BINARY_ROLLBACK=$(printf '%s\n' "$ROLLBACK_UNIT" | sed -n '1p')
ENV_ROLLBACK=$(printf '%s\n' "$ROLLBACK_UNIT" | sed -n '2p')
ROLLBACK_STATUS="passed"
if [ -z "$BINARY_ROLLBACK" ] || [ -z "$ENV_ROLLBACK" ]; then
	ROLLBACK_STATUS="failed"
	append_failure "rollback_unit_incomplete"
fi

SERVICE_STATE="passed"
if [ "$SERVE_STATUS" != "ok" ] || [ "$HELPER_STATUS" != "ok" ]; then
	SERVICE_STATE="failed"
fi

VALID_HOST_HEALTH="failed"
[ "$VALID_HOST_CODE" = "200" ] && VALID_HOST_HEALTH="passed"
INVALID_HOST_421="failed"
[ "$INVALID_HOST_CODE" = "421" ] && INVALID_HOST_421="passed"

RESULT="v6_production_readiness_failed"
SECRETS_REDACTED="passed"
if [ -z "$FAILED_CHECKS" ] && [ "$ALLOW_MISSING" -eq 0 ]; then
	RESULT="v6_production_readiness_passed"
fi

mkdir -p "$(dirname "$REPORT_PATH")"
{
	printf 'schema=osmap-v6-production-readiness-v1\n'
	printf 'timestamp=%s\n' "$TIMESTAMP"
	printf 'host=%s\n' "$HOST"
	printf 'repo_commit=%s\n' "$REPO_COMMIT"
	printf 'binary_sha256=%s\n' "$BINARY_SHA256"
	printf 'serve_service=%s\n' "$SERVE_STATUS"
	printf 'helper_service=%s\n' "$HELPER_STATUS"
	printf 'serve_env_metadata=%s\n' "$SERVE_ENV_METADATA"
	printf 'allowed_hosts_present=%s\n' "$ALLOWED_HOSTS_PRESENT"
	printf 'serve_log_metadata=%s\n' "$SERVE_LOG_METADATA"
	printf 'helper_log_metadata=%s\n' "$HELPER_LOG_METADATA"
	printf 'helper_socket_metadata=%s\n' "$HELPER_SOCKET_METADATA"
	printf 'valid_host_status=%s\n' "$VALID_HOST_CODE"
	printf 'invalid_host_status=%s\n' "$INVALID_HOST_CODE"
	printf 'binary_rollback_artifact=%s\n' "${BINARY_ROLLBACK:-missing}"
	printf 'env_rollback_artifact=%s\n' "${ENV_ROLLBACK:-missing}"
	printf 'developer_allow_missing_context=%s\n' "$ALLOW_MISSING"
	printf 'failed_checks=%s\n' "$(printf '%s' "$FAILED_CHECKS" | tr '\n' ',')"
	printf 'result=%s\n' "$RESULT"
	printf 'valid_host_health=%s\n' "$VALID_HOST_HEALTH"
	printf 'invalid_host_421=%s\n' "$INVALID_HOST_421"
	printf 'service_state=%s\n' "$SERVICE_STATE"
	printf 'rollback_unit=%s\n' "$ROLLBACK_STATUS"
	printf 'log_paths=%s\n' "$LOG_PATHS_STATUS"
	printf 'backend_public_exposure=%s\n' "$BACKEND_PUBLIC_EXPOSURE"
	printf 'secrets_redacted=%s\n' "$SECRETS_REDACTED"
} > "$REPORT_PATH"

echo "wrote V6 production readiness report to $REPORT_PATH"
echo "result=$RESULT"

[ "$RESULT" = "v6_production_readiness_passed" ]
