#!/bin/sh

set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
REPORT_PATH=${OSMAP_V6_OBSERVABILITY_REPORT_PATH:-"$PROJECT_ROOT/maint/live/latest-host-v6-observability-report.txt"}
SERVE_LOG_PATH=${OSMAP_V6_OBSERVABILITY_SERVE_LOG_PATH:-/var/log/osmap/serve.log}
HELPER_LOG_PATH=${OSMAP_V6_OBSERVABILITY_HELPER_LOG_PATH:-/var/log/osmap/mailbox-helper.log}
PRODUCTION_REPORT=${OSMAP_V6_OBSERVABILITY_PRODUCTION_REPORT:-"$PROJECT_ROOT/maint/live/latest-host-v6-production-readiness-report.txt"}
CAPACITY_EVIDENCE=${OSMAP_V6_CAPACITY_EVIDENCE:-}
OPERATOR_REVIEW=${OSMAP_V6_OBSERVABILITY_OPERATOR_REVIEW:-}

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
		--help|-h)
			printf 'usage: %s [--report PATH]\n' "$0"
			exit 0
			;;
		*)
			printf 'usage: %s [--report PATH]\n' "$0" >&2
			exit 2
			;;
	esac
done

for path in "$SERVE_LOG_PATH" "$HELPER_LOG_PATH"; do
	if ! doas test -f "$path"; then
		echo "missing required OSMAP log: $path" >&2
		exit 1
	fi
done

read_log() {
	doas cat "$1"
}

SERVE_LOG=$(read_log "$SERVE_LOG_PATH")
HELPER_LOG=$(read_log "$HELPER_LOG_PATH")

require_event() {
	log_text=$1
	action=$2
	if ! printf '%s\n' "$log_text" | grep -Eq "action=${action}([[:space:]]|$)"; then
		echo "missing required observability event: $action" >&2
		exit 1
	fi
}

require_event "$SERVE_LOG" "login_denied"
require_event "$SERVE_LOG" "second_factor_accepted"
require_event "$SERVE_LOG" "session_issued"
require_event "$SERVE_LOG" "session_revoked"

if ! printf '%s\n' "$SERVE_LOG" |
	grep -Eq 'action=(message_submitted|message_submit_failed)([[:space:]]|$)'; then
	echo "missing required observability event: send attempt" >&2
	exit 1
fi

if ! printf '%s\n' "$HELPER_LOG" |
	grep -Eq 'action=(mailbox_helper_started|mailbox_helper_accept_failed|mailbox_helper_peer_not_authorized)([[:space:]]|$)'; then
	echo "missing mailbox-helper health or failure evidence" >&2
	exit 1
fi

BOUNDARY_SOURCE="log"
if printf '%s\n' "$SERVE_LOG" | grep -Eq 'action=http_host_rejected([[:space:]]|$)'; then
	:
elif [ -s "$PRODUCTION_REPORT" ] &&
	grep -Fxq 'invalid_host_421=passed' "$PRODUCTION_REPORT"; then
	BOUNDARY_SOURCE="v6_production_readiness_report"
else
	echo "missing invalid Host or same-origin boundary evidence" >&2
	exit 1
fi

case "$CAPACITY_EVIDENCE" in
	observed)
		if ! printf '%s\n' "$SERVE_LOG" |
			grep -Eq 'action=(http_connection_capacity_reached|http_connection_rejected_over_capacity|request_budget_exhausted)([[:space:]]|$)'; then
			echo "capacity evidence was marked observed but no event was present" >&2
			exit 1
		fi
		;;
	negative_live_safe_not_triggered)
		;;
	*)
		echo "OSMAP_V6_CAPACITY_EVIDENCE must be observed or negative_live_safe_not_triggered" >&2
		exit 1
		;;
esac

if [ "$OPERATOR_REVIEW" != "passed" ]; then
	echo "OSMAP_V6_OBSERVABILITY_OPERATOR_REVIEW must be passed" >&2
	exit 1
fi

forbidden='password=|password="|totp(_code)?=|csrf_token=|osmap_session=|set-cookie:|session_id=|message_body=|attachment_body=|BEGIN .*PRIVATE KEY'
if printf '%s\n%s\n' "$SERVE_LOG" "$HELPER_LOG" | grep -Eiq "$forbidden"; then
	echo "OSMAP logs contain forbidden raw secret or content markers" >&2
	exit 1
fi

metadata() {
	path=$1
	doas stat -f '%Su:%Sg:%Lp' "$path" 2>/dev/null ||
		doas stat -c '%U:%G:%a' "$path" 2>/dev/null ||
		printf '%s' "unavailable"
}

SERVE_METADATA=$(metadata "$SERVE_LOG_PATH")
HELPER_METADATA=$(metadata "$HELPER_LOG_PATH")
case "$SERVE_METADATA:$HELPER_METADATA" in
	*unavailable*|*:[0-7][0-7][1-7]*)
		echo "log metadata is unavailable or unsafe" >&2
		exit 1
		;;
esac

mkdir -p "$(dirname "$REPORT_PATH")"
{
	printf 'schema=osmap-v6-observability-v1\n'
	printf 'generated_at_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	printf 'host=%s\n' "$(hostname)"
	printf 'commit=%s\n' "$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
	printf 'serve_log_path=%s\n' "$SERVE_LOG_PATH"
	printf 'serve_log_metadata=%s\n' "$SERVE_METADATA"
	printf 'helper_log_path=%s\n' "$HELPER_LOG_PATH"
	printf 'helper_log_metadata=%s\n' "$HELPER_METADATA"
	printf 'boundary_evidence_source=%s\n' "$BOUNDARY_SOURCE"
	printf 'capacity_evidence=%s\n' "$CAPACITY_EVIDENCE"
	printf 'result=v6_observability_passed\n'
	printf 'auth_events=passed\n'
	printf 'session_events=passed\n'
	printf 'send_events=passed\n'
	printf 'boundary_events=passed\n'
	printf 'redaction=passed\n'
	printf 'operator_review=passed\n'
} > "$REPORT_PATH"

echo "wrote V6 observability report to $REPORT_PATH"
