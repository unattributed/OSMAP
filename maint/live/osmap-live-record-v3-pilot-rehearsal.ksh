#!/bin/sh
#
# Record sanitized V3 selected-cohort pilot rehearsal evidence.
#
# This helper does not automate the human rehearsal. Operators should run the
# selected-cohort daily-driver walkthrough first, then invoke this script with
# explicit passed/not-passed environment confirmations. It writes only sanitized
# status fields accepted by `make release-check`.

set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REPORT_PATH="${PROJECT_ROOT}/maint/live/latest-host-v3-pilot-rehearsal-report.txt"
HOST="mail.blackbagsecurity.com"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --report)
      REPORT_PATH="$2"
      shift 2
      ;;
    --host)
      HOST="$2"
      shift 2
      ;;
    *)
      printf 'usage: %s [--report PATH] [--host HOST]\n' "$0" >&2
      exit 2
      ;;
  esac
done

require_passed() {
  name="$1"
  value="${2:-}"
  if [ "$value" != "passed" ]; then
    printf '%s must be set to passed after the actual rehearsal\n' "$name" >&2
    exit 1
  fi
}

require_passed OSMAP_V3_PILOT_CREDENTIAL_TOTP_LOGIN "${OSMAP_V3_PILOT_CREDENTIAL_TOTP_LOGIN:-}"
require_passed OSMAP_V3_PILOT_MAILBOX_LISTING "${OSMAP_V3_PILOT_MAILBOX_LISTING:-}"
require_passed OSMAP_V3_PILOT_MESSAGE_VIEW "${OSMAP_V3_PILOT_MESSAGE_VIEW:-}"
require_passed OSMAP_V3_PILOT_ATTACHMENT_DOWNLOAD "${OSMAP_V3_PILOT_ATTACHMENT_DOWNLOAD:-}"
require_passed OSMAP_V3_PILOT_BOUNDED_SEARCH "${OSMAP_V3_PILOT_BOUNDED_SEARCH:-}"
require_passed OSMAP_V3_PILOT_COMPOSE_SEND "${OSMAP_V3_PILOT_COMPOSE_SEND:-}"
require_passed OSMAP_V3_PILOT_REPLY_FORWARD "${OSMAP_V3_PILOT_REPLY_FORWARD:-}"
require_passed OSMAP_V3_PILOT_DRAFT_SAVE_RESUME "${OSMAP_V3_PILOT_DRAFT_SAVE_RESUME:-}"
require_passed OSMAP_V3_PILOT_SELECTED_SOURCE_ATTACHMENTS "${OSMAP_V3_PILOT_SELECTED_SOURCE_ATTACHMENTS:-}"
require_passed OSMAP_V3_PILOT_BOUNDED_BULK_FOLDER_ACTIONS "${OSMAP_V3_PILOT_BOUNDED_BULK_FOLDER_ACTIONS:-}"
require_passed OSMAP_V3_PILOT_SESSION_LOGOUT_REVOKE "${OSMAP_V3_PILOT_SESSION_LOGOUT_REVOKE:-}"

if [ "${OSMAP_V3_PILOT_ROUNDCUBE_FALLBACK_REQUIRED:-}" != "none" ]; then
  printf 'OSMAP_V3_PILOT_ROUNDCUBE_FALLBACK_REQUIRED must be none\n' >&2
  exit 1
fi

if [ "${OSMAP_V3_PILOT_SANITIZED_EVIDENCE:-}" != "true" ]; then
  printf 'OSMAP_V3_PILOT_SANITIZED_EVIDENCE must be true\n' >&2
  exit 1
fi

commit="$(git -C "$PROJECT_ROOT" rev-parse --short HEAD)"
generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
tmp="${REPORT_PATH}.tmp"
mkdir -p "$(dirname "$REPORT_PATH")"

{
  printf '%s\n' "host=${HOST}"
  printf '%s\n' "commit=${commit}"
  printf '%s\n' "generated_at_utc=${generated_at}"
  printf '%s\n' "workflow_inventory=docs/PILOT_WORKFLOW_INVENTORY.md"
  printf '%s\n' "credential_totp_login=passed"
  printf '%s\n' "mailbox_listing=passed"
  printf '%s\n' "message_view=passed"
  printf '%s\n' "attachment_download=passed"
  printf '%s\n' "bounded_search=passed"
  printf '%s\n' "compose_send=passed"
  printf '%s\n' "reply_forward=passed"
  printf '%s\n' "draft_save_resume=passed"
  printf '%s\n' "selected_source_attachments=passed"
  printf '%s\n' "bounded_bulk_folder_actions=passed"
  printf '%s\n' "session_logout_revoke=passed"
  printf '%s\n' "roundcube_fallback_required=none"
  printf '%s\n' "sanitized_evidence=true"
  printf '%s\n' "result=v3_pilot_rehearsal_passed"
} > "$tmp"

if grep -E -i 'session_id="|osmap_session=|csrf_token=|totp seed|password|private message body|private attachment|secret=' "$tmp" >/dev/null; then
  rm -f "$tmp"
  printf 'refusing to write report with forbidden sensitive content\n' >&2
  exit 1
fi

mv "$tmp" "$REPORT_PATH"
printf 'wrote sanitized V3 pilot rehearsal report: %s\n' "$REPORT_PATH"
