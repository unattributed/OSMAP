#!/bin/sh

set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
REPORT_PATH=${OSMAP_V6_REHEARSAL_REPORT_PATH:-"$PROJECT_ROOT/maint/live/latest-host-v6-retirement-rehearsal-report.txt"}
HOST=${OSMAP_V6_REHEARSAL_HOST:-mail.blackbagsecurity.com}
COHORT_LABELS=${OSMAP_V6_REHEARSAL_COHORT_LABELS:-selected_cohort}

usage() {
	printf 'usage: %s [--report PATH] [--host HOST] [--cohort-labels LABELS]\n' "$0"
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--report)
			[ "$#" -ge 2 ] || { usage >&2; exit 2; }
			REPORT_PATH=$2
			shift 2
			;;
		--host)
			[ "$#" -ge 2 ] || { usage >&2; exit 2; }
			HOST=$2
			shift 2
			;;
		--cohort-labels)
			[ "$#" -ge 2 ] || { usage >&2; exit 2; }
			COHORT_LABELS=$2
			shift 2
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

case "$COHORT_LABELS" in
	*[@[:space:]]*|'')
		echo "cohort labels must be sanitized aliases without email addresses or whitespace" >&2
		exit 1
		;;
esac
if ! printf '%s' "$COHORT_LABELS" | grep -Eq '^[a-z0-9_,.-]+$'; then
	echo "cohort labels contain unsupported characters" >&2
	exit 1
fi

WORKFLOWS="
password_totp_login:OSMAP_V6_WORKFLOW_PASSWORD_TOTP_LOGIN
mailbox_listing:OSMAP_V6_WORKFLOW_MAILBOX_LISTING
message_listing:OSMAP_V6_WORKFLOW_MESSAGE_LISTING
message_view:OSMAP_V6_WORKFLOW_MESSAGE_VIEW
safe_html_or_plain_text:OSMAP_V6_WORKFLOW_SAFE_HTML_OR_PLAIN_TEXT
search_one_mailbox:OSMAP_V6_WORKFLOW_SEARCH_ONE_MAILBOX
search_all_visible_mailboxes:OSMAP_V6_WORKFLOW_SEARCH_ALL_VISIBLE_MAILBOXES
attachment_download:OSMAP_V6_WORKFLOW_ATTACHMENT_DOWNLOAD
compose_send:OSMAP_V6_WORKFLOW_COMPOSE_SEND
reply:OSMAP_V6_WORKFLOW_REPLY
forward:OSMAP_V6_WORKFLOW_FORWARD
bounded_attachment_upload_send:OSMAP_V6_WORKFLOW_BOUNDED_ATTACHMENT_UPLOAD_SEND
explicit_source_attachment_selection_send:OSMAP_V6_WORKFLOW_EXPLICIT_SOURCE_ATTACHMENT_SELECTION_SEND
draft_save_resume:OSMAP_V6_WORKFLOW_DRAFT_SAVE_RESUME
move_or_archive:OSMAP_V6_WORKFLOW_MOVE_OR_ARCHIVE
session_listing:OSMAP_V6_WORKFLOW_SESSION_LISTING
session_revocation:OSMAP_V6_WORKFLOW_SESSION_REVOCATION
settings_update:OSMAP_V6_WORKFLOW_SETTINGS_UPDATE
logout:OSMAP_V6_WORKFLOW_LOGOUT
"

WORKFLOW_LINES=""
FAILED=0
old_ifs=$IFS
IFS='
'
for item in $WORKFLOWS; do
	[ -n "$item" ] || continue
	name=${item%%:*}
	env_name=${item#*:}
	eval "value=\${$env_name:-}"
	case "$value" in
		passed|not_required_for_selected_cohort) ;;
		failed)
			FAILED=1
			;;
		*)
			echo "$env_name must be passed, not_required_for_selected_cohort, or failed" >&2
			exit 1
			;;
	esac
	WORKFLOW_LINES="${WORKFLOW_LINES}workflow.${name}=${value}
"
done
IFS=$old_ifs

if [ "${OSMAP_V6_ROUNDCUBE_FALLBACK_USED:-}" != "no" ]; then
	echo "OSMAP_V6_ROUNDCUBE_FALLBACK_USED must be no" >&2
	exit 1
fi
if [ "${OSMAP_V6_NATIVE_CLIENTS_UNCHANGED:-}" != "yes" ]; then
	echo "OSMAP_V6_NATIVE_CLIENTS_UNCHANGED must be yes" >&2
	exit 1
fi
if [ "${OSMAP_V6_UNDERLYING_MAIL_STACK_UNCHANGED:-}" != "yes" ]; then
	echo "OSMAP_V6_UNDERLYING_MAIL_STACK_UNCHANGED must be yes" >&2
	exit 1
fi
if [ "${OSMAP_V6_REHEARSAL_SECRETS_REDACTED:-}" != "passed" ]; then
	echo "OSMAP_V6_REHEARSAL_SECRETS_REDACTED must be passed" >&2
	exit 1
fi
if [ "$FAILED" -ne 0 ]; then
	echo "one or more selected-cohort workflows failed" >&2
	exit 1
fi

COMMIT=$(git -C "$PROJECT_ROOT" rev-parse HEAD)
GENERATED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
TMP_REPORT="${REPORT_PATH}.tmp"
mkdir -p "$(dirname "$REPORT_PATH")"

{
	printf 'schema=osmap-v6-retirement-rehearsal-v1\n'
	printf 'host=%s\n' "$HOST"
	printf 'commit=%s\n' "$COMMIT"
	printf 'generated_at_utc=%s\n' "$GENERATED_AT"
	printf 'cohort_labels=%s\n' "$COHORT_LABELS"
	printf 'workflow_inventory=docs/PILOT_WORKFLOW_INVENTORY.md\n'
	printf '%s' "$WORKFLOW_LINES"
	printf 'workflow_status=passed\n'
	printf 'roundcube_fallback_used=no\n'
	printf 'native_clients_unchanged=yes\n'
	printf 'underlying_mail_stack_unchanged=yes\n'
	printf 'secrets_redacted=passed\n'
	printf 'result=v6_retirement_rehearsal_passed\n'
} > "$TMP_REPORT"

if grep -Eiq 'password=|totp(_code)?=|csrf_token=|osmap_session=|set-cookie:|BEGIN .*PRIVATE KEY|mailbox_body=|attachment_body=' "$TMP_REPORT"; then
	rm -f "$TMP_REPORT"
	echo "refusing to write secret-bearing rehearsal evidence" >&2
	exit 1
fi

mv "$TMP_REPORT" "$REPORT_PATH"
echo "wrote sanitized V6 retirement rehearsal report: $REPORT_PATH"
