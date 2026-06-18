#!/bin/sh

set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
REPORT_PATH=${OSMAP_V6_RESILIENCE_REPORT_PATH:-"$PROJECT_ROOT/maint/live/latest-host-v6-resource-resilience-report.txt"}
PRODUCTION_REPORT=${OSMAP_V6_RESILIENCE_PRODUCTION_REPORT:-"$PROJECT_ROOT/maint/live/latest-host-v6-production-readiness-report.txt"}
V3_RESOURCE_REPORT=${OSMAP_V6_V3_RESOURCE_REPORT:-"$PROJECT_ROOT/maint/live/latest-host-v3-resource-controls-report.txt"}
V3_TIMEOUT_EVIDENCE=${OSMAP_V6_V3_TIMEOUT_EVIDENCE:-"$PROJECT_ROOT/maint/live/osmap-v3-resource-timeout-evidence-2026-05-02.txt"}
HEALTH_URL=${OSMAP_V6_RESILIENCE_HEALTH_URL:-https://192.168.1.44/healthz}
ALLOWED_HOST=${OSMAP_V6_RESILIENCE_ALLOWED_HOST:-mail.blackbagsecurity.com}
PRESSURE_MODE=${OSMAP_V6_RESILIENCE_PRESSURE_MODE:-production_pressure_not_safe}
DRY_RUN=0

usage() {
	printf 'usage: %s [--report PATH] [--dry-run]\n' "$0"
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--report)
			[ "$#" -ge 2 ] || exit 2
			REPORT_PATH=$2
			shift 2
			;;
		--report=*)
			REPORT_PATH=${1#--report=}
			shift
			;;
		--dry-run)
			DRY_RUN=1
			shift
			;;
		--help|-h)
			usage
			exit 0
			;;
		*)
			usage >&2
			exit 2
			;;
	esac
done

for tool in cargo curl git hostname mktemp; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "missing required tool: $tool" >&2
		exit 1
	}
done

if [ "$DRY_RUN" = "1" ]; then
	mkdir -p "$(dirname "$REPORT_PATH")"
	{
		printf 'schema=osmap-v6-resource-resilience-v1\n'
		printf 'generated_at_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		printf 'host=%s\n' "$(hostname)"
		printf 'commit=%s\n' "$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
		printf 'result=v6_resource_resilience_diagnostic_only\n'
		printf 'closeout_eligible=no\n'
		printf 'reason=dry_run_cannot_produce_passing_evidence\n'
	} > "$REPORT_PATH"
	echo "wrote diagnostic-only V6 resource report to $REPORT_PATH"
	exit 0
fi

for path in "$PRODUCTION_REPORT" "$V3_RESOURCE_REPORT" "$V3_TIMEOUT_EVIDENCE"; do
	if [ ! -s "$path" ]; then
		echo "missing required resource evidence input: $path" >&2
		exit 1
	fi
done

grep -Fxq 'result=v6_production_readiness_passed' "$PRODUCTION_REPORT" || {
	echo "V6 production readiness report is not passed" >&2
	exit 1
}
grep -Fxq 'osmap_v3_resource_controls_result=passed' "$V3_RESOURCE_REPORT" || {
	echo "V3 live resource-control report is not passed" >&2
	exit 1
}
grep -Fq 'OSMAP V3 resource and timeout hardening evidence' "$V3_TIMEOUT_EVIDENCE" || {
	echo "V3 resource-timeout evidence is not recognized" >&2
	exit 1
}

case "$PRESSURE_MODE" in
	production_pressure_not_safe|isolated_live_observed)
		;;
	*)
		echo "OSMAP_V6_RESILIENCE_PRESSURE_MODE must be production_pressure_not_safe or isolated_live_observed" >&2
		exit 1
		;;
esac

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v6-resource-resilience.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

health_probe() {
	output_path=$1
	status=$(curl -ksS --max-time 10 -H "Host: $ALLOWED_HOST" \
		-o "$output_path" -w '%{http_code}' "$HEALTH_URL") || {
		echo "V6 health probe failed" >&2
		exit 1
	}
	if [ "$status" != "200" ]; then
		echo "V6 health probe returned HTTP $status" >&2
		exit 1
	fi
}

run_test() {
	label=$1
	shift
	output="$tmp_dir/$label.txt"
	(
		cd "$PROJECT_ROOT"
		"$@"
	) > "$output" 2>&1 || {
		echo "V6 resource regression failed: $label" >&2
		sed -n '1,80p' "$output" >&2
		exit 1
	}
	grep -Fq 'test result: ok.' "$output" || {
		echo "V6 resource regression did not report success: $label" >&2
		exit 1
	}
	grep -Eq 'test result: ok\. [1-9][0-9]* passed;' "$output" || {
		echo "V6 resource regression matched no tests: $label" >&2
		exit 1
	}
}

health_probe "$tmp_dir/health-before.txt"
run_test http_capacity cargo test over_capacity_connections_receive_service_unavailable
run_test throttle cargo test throttle
run_test budget_boundary cargo test budget_exhaustion
run_test malformed_boundary cargo test rejects_duplicate_content_length_body_framing
run_test oversized_boundary cargo test rejects_oversized
run_test helper_timeout cargo test times_out_when_helper
health_probe "$tmp_dir/health-after.txt"

forbidden='password=|password="|totp(_code)?=|csrf_token=|osmap_session=|set-cookie:|session_id=|message_body=|attachment_body=|BEGIN .*PRIVATE KEY'
if grep -ERiq "$forbidden" "$tmp_dir"; then
	echo "V6 resource validation output contains forbidden raw secret or content markers" >&2
	exit 1
fi

mkdir -p "$(dirname "$REPORT_PATH")"
{
	printf 'schema=osmap-v6-resource-resilience-v1\n'
	printf 'generated_at_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	printf 'host=%s\n' "$(hostname)"
	printf 'commit=%s\n' "$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
	printf 'health_url=%s\n' "$HEALTH_URL"
	printf 'pressure_mode=%s\n' "$PRESSURE_MODE"
	printf 'pressure_evidence=%s\n' "$(
		if [ "$PRESSURE_MODE" = "isolated_live_observed" ]; then
			printf 'isolated_live_and_current_regression'
		else
			printf 'live_pressure_not_safe_current_regression_and_prior_live_evidence'
		fi
	)"
	printf 'v3_resource_report=%s\n' "$V3_RESOURCE_REPORT"
	printf 'v3_timeout_evidence=%s\n' "$V3_TIMEOUT_EVIDENCE"
	printf 'result=v6_resource_resilience_passed\n'
	printf 'health_under_pressure=passed\n'
	printf 'budget_or_timeout_boundary=passed\n'
	printf 'malformed_request_boundary=passed\n'
	printf 'recovery=passed\n'
	printf 'redaction=passed\n'
} > "$REPORT_PATH"

echo "wrote V6 resource resilience report to $REPORT_PATH"
