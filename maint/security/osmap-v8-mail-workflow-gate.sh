#!/bin/sh

set -eu

repo_root=${OSMAP_V8_GATE_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

require_file() {
	path=$1
	if [ ! -s "$path" ]; then
		echo "error: missing V8 mail workflow file: $path" >&2
		exit 1
	fi
}

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V8 mail workflow requirement in $path: $text" >&2
		exit 1
	fi
}

for path in \
	docs/V8_MAIL_WORKFLOW_MATRIX.md \
	tests/v8_mail_workflow_matrix.rs \
	tests/fixtures/mail_workflows/MANIFEST.md \
	tests/fixtures/mail_workflows/text_plain.eml \
	tests/fixtures/mail_workflows/text_html.eml \
	tests/fixtures/mail_workflows/multipart_alternative.eml \
	tests/fixtures/mail_workflows/multipart_mixed.eml \
	tests/fixtures/mail_workflows/nested_multipart.eml \
	tests/fixtures/mail_workflows/attachment_heavy.eml \
	tests/fixtures/mail_workflows/malformed_mime.eml
	do
	require_file "$path"
done

require_text docs/V8_MAIL_WORKFLOW_MATRIX.md "body selection"
require_text docs/V8_MAIL_WORKFLOW_MATRIX.md "body source labels"
require_text docs/V8_MAIL_WORKFLOW_MATRIX.md "rendering mode labels"
require_text docs/V8_MAIL_WORKFLOW_MATRIX.md "remote-content status"
require_text docs/V8_MAIL_WORKFLOW_MATRIX.md "sanitized HTML notices"
require_text docs/V8_MAIL_WORKFLOW_MATRIX.md "safe fallback behavior"
require_text maint/security/osmap-v8-mail-workflow-gate.sh "cargo test --test v8_mail_workflow_matrix"
require_text Makefile "osmap-v8-mail-workflow-gate.sh"

echo "==> cargo test --test v8_mail_workflow_matrix"
cargo test --test v8_mail_workflow_matrix

echo "V8 mail workflow regression gate passed"
