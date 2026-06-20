#!/bin/sh

set -eu

repo_root=${OSMAP_V7_RENDERING_TEST_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V7 rendering gate test requirement in $path: $text" >&2
		exit 1
	fi
}

sh -n maint/security/osmap-v7-rendering-regression-gate.sh
require_text maint/security/osmap-v7-rendering-regression-gate.sh "command -v cargo"
require_text maint/security/osmap-v7-rendering-regression-gate.sh "error: cargo is required"
require_text maint/security/osmap-v7-rendering-regression-gate.sh "cargo test --quiet --"
require_text maint/security/osmap-v7-rendering-regression-gate.sh "prefer_plain_text_falls_back_to_sanitized_html_without_plain"
require_text maint/security/osmap-v7-rendering-regression-gate.sh "ui_message_view_surfaces_truthful_rendering_labels"
require_text Makefile "v7-rendering-regression-check"
require_text Makefile "sh maint/security/osmap-v7-rendering-regression-gate.sh"
require_text maint/security/osmap-security-check.sh "validating V7 rendering regression close-out gate"
require_text maint/security/osmap-security-check.sh "sh maint/security/osmap-v7-rendering-regression-gate.sh"

echo "V7 rendering regression gate wrapper test passed"
