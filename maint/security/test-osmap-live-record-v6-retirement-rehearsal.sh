#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
recorder="$repo_root/maint/live/osmap-live-record-v6-retirement-rehearsal.ksh"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v6-rehearsal.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT

workflow_env() {
	env \
		OSMAP_V6_WORKFLOW_PASSWORD_TOTP_LOGIN=passed \
		OSMAP_V6_WORKFLOW_MAILBOX_LISTING=passed \
		OSMAP_V6_WORKFLOW_MESSAGE_LISTING=passed \
		OSMAP_V6_WORKFLOW_MESSAGE_VIEW=passed \
		OSMAP_V6_WORKFLOW_SAFE_HTML_OR_PLAIN_TEXT=passed \
		OSMAP_V6_WORKFLOW_SEARCH_ONE_MAILBOX=passed \
		OSMAP_V6_WORKFLOW_SEARCH_ALL_VISIBLE_MAILBOXES=not_required_for_selected_cohort \
		OSMAP_V6_WORKFLOW_ATTACHMENT_DOWNLOAD=passed \
		OSMAP_V6_WORKFLOW_COMPOSE_SEND=passed \
		OSMAP_V6_WORKFLOW_REPLY=passed \
		OSMAP_V6_WORKFLOW_FORWARD=passed \
		OSMAP_V6_WORKFLOW_BOUNDED_ATTACHMENT_UPLOAD_SEND=passed \
		OSMAP_V6_WORKFLOW_EXPLICIT_SOURCE_ATTACHMENT_SELECTION_SEND=not_required_for_selected_cohort \
		OSMAP_V6_WORKFLOW_DRAFT_SAVE_RESUME=passed \
		OSMAP_V6_WORKFLOW_MOVE_OR_ARCHIVE=passed \
		OSMAP_V6_WORKFLOW_SESSION_LISTING=passed \
		OSMAP_V6_WORKFLOW_SESSION_REVOCATION=passed \
		OSMAP_V6_WORKFLOW_SETTINGS_UPDATE=passed \
		OSMAP_V6_WORKFLOW_LOGOUT=passed \
		OSMAP_V6_ROUNDCUBE_FALLBACK_USED=no \
		OSMAP_V6_NATIVE_CLIENTS_UNCHANGED=yes \
		OSMAP_V6_UNDERLYING_MAIL_STACK_UNCHANGED=yes \
		OSMAP_V6_REHEARSAL_SECRETS_REDACTED=passed \
		"$@"
}

sh -n "$recorder"

if OSMAP_V6_WORKFLOW_PASSWORD_TOTP_LOGIN=passed \
	sh "$recorder" --report "$tmp_dir/incomplete.txt" > "$tmp_dir/incomplete.out" 2>&1; then
	echo "expected incomplete workflow confirmation to fail" >&2
	exit 1
fi
grep -Fq "OSMAP_V6_WORKFLOW_MAILBOX_LISTING must be" "$tmp_dir/incomplete.out"

workflow_env sh "$recorder" \
	--report "$tmp_dir/pass.txt" \
	--cohort-labels cohort_user_1,cohort_user_2 > "$tmp_dir/pass.out"
grep -Fxq 'result=v6_retirement_rehearsal_passed' "$tmp_dir/pass.txt"
grep -Fxq 'roundcube_fallback_used=no' "$tmp_dir/pass.txt"
grep -Fxq 'workflow.search_all_visible_mailboxes=not_required_for_selected_cohort' "$tmp_dir/pass.txt"

if workflow_env env OSMAP_V6_ROUNDCUBE_FALLBACK_USED=yes \
	sh "$recorder" --report "$tmp_dir/fallback.txt" > "$tmp_dir/fallback.out" 2>&1; then
	echo "expected Roundcube fallback to fail" >&2
	exit 1
fi
grep -Fq "OSMAP_V6_ROUNDCUBE_FALLBACK_USED must be no" "$tmp_dir/fallback.out"

if workflow_env env OSMAP_V6_WORKFLOW_REPLY=failed \
	sh "$recorder" --report "$tmp_dir/failed.txt" > "$tmp_dir/failed.out" 2>&1; then
	echo "expected failed selected workflow to fail" >&2
	exit 1
fi
grep -Fq "one or more selected-cohort workflows failed" "$tmp_dir/failed.out"

if workflow_env sh "$recorder" --report "$tmp_dir/email.txt" \
	--cohort-labels real@example.invalid > "$tmp_dir/email.out" 2>&1; then
	echo "expected email-shaped cohort identifier to fail" >&2
	exit 1
fi
grep -Fq "sanitized aliases" "$tmp_dir/email.out"

if grep -Eiq 'password=|totp(_code)?=|csrf_token=|osmap_session=|set-cookie:' "$tmp_dir/pass.txt"; then
	echo "rehearsal report contained a forbidden secret marker" >&2
	exit 1
fi

echo "V6 retirement rehearsal recorder regression checks passed"
