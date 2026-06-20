#!/bin/sh

set -eu

repo_root=${OSMAP_V8_GATE_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

require_file() {
	path=$1
	if [ ! -s "$path" ]; then
		echo "error: missing V8 attachment safety file: $path" >&2
		exit 1
	fi
}

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V8 attachment safety requirement in $path: $text" >&2
		exit 1
	fi
}

for path in \
	docs/V8_ATTACHMENT_SAFETY_MATRIX.md \
	tests/v8_attachment_safety_matrix.rs \
	tests/fixtures/attachments/MANIFEST.md \
	tests/fixtures/attachments/safe_pdf_base64.eml \
	tests/fixtures/attachments/quoted_printable_text.eml \
	tests/fixtures/attachments/suspicious_html_attachment.eml \
	tests/fixtures/attachments/svg_active_attachment.eml \
	tests/fixtures/attachments/generated_filename_fallback.eml \
	tests/fixtures/attachments/unsupported_encoding.eml
	do
	require_file "$path"
done

require_text docs/V8_ATTACHMENT_SAFETY_MATRIX.md "forced-download HTTP headers"
require_text docs/V8_ATTACHMENT_SAFETY_MATRIX.md "filename sanitization"
require_text docs/V8_ATTACHMENT_SAFETY_MATRIX.md "application/octet-stream"
require_text docs/V8_ATTACHMENT_SAFETY_MATRIX.md "unsupported transfer encoding fail-closed behavior"
require_text tests/v8_attachment_safety_matrix.rs "X-Content-Type-Options"
require_text tests/v8_attachment_safety_matrix.rs "attachment_download_response"
require_text tests/v8_attachment_safety_matrix.rs "TemporarilyUnavailable"
require_text maint/security/osmap-v8-attachment-safety-gate.sh "cargo test --test v8_attachment_safety_matrix"
require_text Makefile "osmap-v8-attachment-safety-gate.sh"

echo "==> cargo test --test v8_attachment_safety_matrix"
cargo test --test v8_attachment_safety_matrix

echo "V8 attachment safety regression gate passed"
