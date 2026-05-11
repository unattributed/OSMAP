#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
design="${repo_root}/docs/V3_REPLY_FORWARD_ATTACHMENT_HANDLING_DESIGN.md"

require_file() {
	path=$1
	if [ ! -f "$path" ]; then
		echo "missing required file: $path" >&2
		exit 1
	fi
}

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "missing required text in ${path#$repo_root/}: $text" >&2
		exit 1
	fi
}

require_file "$design"

require_text "$design" "Version 3 design gate"
require_text "$design" "explicit original-message"
require_text "$design" "Reply"
require_text "$design" "Forward"
require_text "$design" "GET /compose"
require_text "$design" "POST /send"
require_text "$design" "POST /drafts/save"
require_text "$design" "session, CSRF, and same-origin checks"
require_text "$design" "source mailbox name"
require_text "$design" "source UID"
require_text "$design" "surfaced attachment part path"
require_text "$design" "duplicate selections"
require_text "$design" "helper-backed message-view and attachment-download path"
require_text "$design" "DEFAULT_MAX_ATTACHMENTS"
require_text "$design" "DEFAULT_TOTAL_ATTACHMENT_MAX_BYTES"
require_text "$design" "must not silently drop"
require_text "$design" "Audit events and evidence must not record"
require_text "$design" "authenticated access control"
require_text "$design" "business-logic rejection"
require_text "$design" "inline attachment preview"
require_text "$design" "remote external content loading"
require_text "$design" "automatic original-message attachment reattach"

require_text "${repo_root}/docs/V3_ROADMAP.md" "docs/V3_REPLY_FORWARD_ATTACHMENT_HANDLING_DESIGN.md"
require_text "${repo_root}/docs/V3_ACCEPTANCE_CRITERIA.md" "docs/V3_REPLY_FORWARD_ATTACHMENT_HANDLING_DESIGN.md"
require_text "${repo_root}/docs/V3_SECURITY_GATES.md" "docs/V3_REPLY_FORWARD_ATTACHMENT_HANDLING_DESIGN.md"
require_text "${repo_root}/docs/PILOT_WORKFLOW_INVENTORY.md" "Reply or forward with original attachments preserved explicitly"
require_text "${repo_root}/docs/DECISION_LOG.md" "Define V3 reply and forward attachment boundary"

echo "V3 reply/forward attachment design checks passed"
