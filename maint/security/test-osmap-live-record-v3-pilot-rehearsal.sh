#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
script="${repo_root}/maint/live/osmap-live-record-v3-pilot-rehearsal.ksh"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v3-pilot-rehearsal.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT

if OSMAP_V3_PILOT_CREDENTIAL_TOTP_LOGIN=passed \
	sh "$script" --report "$tmp_dir/missing.txt" > "$tmp_dir/missing.out" 2>&1; then
	echo "expected incomplete V3 pilot rehearsal confirmation to fail" >&2
	exit 1
fi
grep -Fq "OSMAP_V3_PILOT_MAILBOX_LISTING must be set to passed" "$tmp_dir/missing.out"

report="$tmp_dir/latest-host-v3-pilot-rehearsal-report.txt"
OSMAP_V3_PILOT_CREDENTIAL_TOTP_LOGIN=passed \
OSMAP_V3_PILOT_MAILBOX_LISTING=passed \
OSMAP_V3_PILOT_MESSAGE_VIEW=passed \
OSMAP_V3_PILOT_ATTACHMENT_DOWNLOAD=passed \
OSMAP_V3_PILOT_BOUNDED_SEARCH=passed \
OSMAP_V3_PILOT_COMPOSE_SEND=passed \
OSMAP_V3_PILOT_REPLY_FORWARD=passed \
OSMAP_V3_PILOT_DRAFT_SAVE_RESUME=passed \
OSMAP_V3_PILOT_SELECTED_SOURCE_ATTACHMENTS=passed \
OSMAP_V3_PILOT_BOUNDED_BULK_FOLDER_ACTIONS=passed \
OSMAP_V3_PILOT_SESSION_LOGOUT_REVOKE=passed \
OSMAP_V3_PILOT_ROUNDCUBE_FALLBACK_REQUIRED=none \
OSMAP_V3_PILOT_SANITIZED_EVIDENCE=true \
	sh "$script" --report "$report" > "$tmp_dir/pass.out"

grep -Fq "result=v3_pilot_rehearsal_passed" "$report"
grep -Fq "workflow_inventory=docs/PILOT_WORKFLOW_INVENTORY.md" "$report"
grep -Fq "roundcube_fallback_required=none" "$report"
grep -Fq "sanitized_evidence=true" "$report"
if grep -E -i 'session_id="|osmap_session=|csrf_token=|totp seed|password|private message body|private attachment|secret=' "$report" >/dev/null; then
	echo "pilot rehearsal report contains forbidden sensitive content" >&2
	exit 1
fi

echo "V3 pilot rehearsal capture checks passed"
