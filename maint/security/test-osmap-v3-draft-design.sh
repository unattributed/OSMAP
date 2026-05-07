#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
design="${repo_root}/docs/V3_DRAFT_SAVE_RESUME_DESIGN.md"

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

require_text "$design" "This remains the design gate for the feature."
require_text "$design" "src/draft.rs"
require_text "$design" "authenticated browser routes"
require_text "$design" "browser-local draft storage"
require_text "$design" "remote content loading"
require_text "$design" "<OSMAP_STATE_DIR>/drafts"
require_text "$design" "0700"
require_text "$design" "0600"
require_text "$design" "Every draft operation is scoped to the canonical username from the validated"
require_text "$design" "All state-changing draft routes must require the existing per-session CSRF token"
require_text "$design" "same-origin request metadata"
require_text "$design" '`/drafts/save`'
require_text "$design" '`/drafts/delete`'
require_text "$design" '`/send`'
require_text "$design" "DEFAULT_MAX_ATTACHMENTS"
require_text "$design" "DEFAULT_TOTAL_ATTACHMENT_MAX_BYTES"
require_text "$design" "Persisted draft attachments are limited to newly uploaded compose attachments."
require_text "$design" "send backend failures keep the draft available unless the message was already"
require_text "$design" "CSRF tokens"
require_text "$design" "raw session identifiers"
require_text "$design" "full draft bodies"
require_text "$design" "ASVS as"

require_text "${repo_root}/docs/V3_ROADMAP.md" "docs/V3_DRAFT_SAVE_RESUME_DESIGN.md"
require_text "${repo_root}/docs/V3_ACCEPTANCE_CRITERIA.md" "docs/V3_DRAFT_SAVE_RESUME_DESIGN.md"
require_text "${repo_root}/docs/V3_SECURITY_GATES.md" "docs/V3_DRAFT_SAVE_RESUME_DESIGN.md"
require_text "${repo_root}/docs/PILOT_WORKFLOW_INVENTORY.md" "Draft save and resume later | \`supported_with_limits\`"
require_text "${repo_root}/docs/PILOT_WORKFLOW_INVENTORY.md" "host-safe authenticated WSTG/ASVS evidence in \`OSMAP-WSTG-BUSL-002\`"
require_text "${repo_root}/docs/CONFIGURATION_AND_STATE_MODEL.md" "OSMAP_DRAFT_DIR"
require_text "${repo_root}/docs/DECISION_LOG.md" "Admit limited V3 draft save and resume pilot workflow"
require_text "${repo_root}/docs/DECISION_LOG.md" "Add V3 draft WSTG route evidence"
require_text "${repo_root}/docs/DECISION_LOG.md" "Wire V3 draft browser routes"
require_text "${repo_root}/docs/DECISION_LOG.md" "Define V3 draft save and resume boundary"

echo "V3 draft save/resume design checks passed"
