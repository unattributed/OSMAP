#!/bin/sh

set -eu

repo_root=${OSMAP_V8_GATE_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

require_file() {
	path=$1
	if [ ! -s "$path" ]; then
		echo "error: missing V8 mailbox operation file: $path" >&2
		exit 1
	fi
}

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V8 mailbox operation requirement in $path: $text" >&2
		exit 1
	fi
}

for path in \
	docs/V8_MAILBOX_OPERATION_MATRIX.md \
	tests/v8_mailbox_operation_matrix.rs \
	tests/fixtures/mailbox_operations/MANIFEST.md \
	tests/fixtures/mailbox_operations/mailboxes.txt \
	tests/fixtures/mailbox_operations/messages.tsv \
	tests/fixtures/mailbox_operations/search_results.tsv \
	tests/fixtures/mailbox_operations/message_view.eml \
	tests/fixtures/mailbox_operations/move_operations.tsv
	do
	require_file "$path"
done

require_text docs/V8_MAILBOX_OPERATION_MATRIX.md "mailbox listing"
require_text docs/V8_MAILBOX_OPERATION_MATRIX.md "message-list sorting"
require_text docs/V8_MAILBOX_OPERATION_MATRIX.md "search result sorting"
require_text docs/V8_MAILBOX_OPERATION_MATRIX.md "one-message move"
require_text docs/V8_MAILBOX_OPERATION_MATRIX.md "audit-event session redaction"
require_text tests/v8_mailbox_operation_matrix.rs "sort_message_summaries"
require_text tests/v8_mailbox_operation_matrix.rs "MessageMoveService"
require_text tests/v8_mailbox_operation_matrix.rs "assert_audit_redacts_raw_session_id"
require_text maint/security/osmap-v8-mailbox-operation-gate.sh "cargo test --test v8_mailbox_operation_matrix"
require_text Makefile "osmap-v8-mailbox-operation-gate.sh"

echo "==> cargo test --test v8_mailbox_operation_matrix"
cargo test --test v8_mailbox_operation_matrix

echo "V8 mailbox operation regression gate passed"
