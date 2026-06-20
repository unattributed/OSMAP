#!/bin/sh

set -eu

repo_root=${OSMAP_V8_GATE_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

require_file() {
	path=$1
	if [ ! -s "$path" ]; then
		echo "error: missing V8 final close-out file: $path" >&2
		exit 1
	fi
}

require_executable() {
	path=$1
	require_file "$path"
	if [ ! -x "$path" ]; then
		echo "error: V8 gate is not executable: $path" >&2
		exit 1
	fi
}

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V8 final close-out requirement in $path: $text" >&2
		exit 1
	fi
}

for path in \
	docs/V8_STABILIZATION_PROGRAM.md \
	docs/V8_MAIL_WORKFLOW_MATRIX.md \
	docs/V8_ATTACHMENT_SAFETY_MATRIX.md \
	docs/V8_MAILBOX_OPERATION_MATRIX.md \
	docs/V8_SESSION_INTEGRITY_MATRIX.md \
	docs/V8_RESOURCE_ROBUSTNESS_MATRIX.md \
	docs/V8_FINAL_REGRESSION_GATE_CLOSEOUT.md
	do
	require_file "$path"
done

for path in \
	tests/v8_mail_workflow_matrix.rs \
	tests/v8_attachment_safety_matrix.rs \
	tests/v8_mailbox_operation_matrix.rs \
	tests/v8_session_integrity_matrix.rs \
	tests/v8_resource_robustness_matrix.rs
	do
	require_file "$path"
done

for path in \
	tests/fixtures/mail_workflows/MANIFEST.md \
	tests/fixtures/attachments/MANIFEST.md \
	tests/fixtures/mailbox_operations/MANIFEST.md \
	tests/fixtures/session_integrity/MANIFEST.md \
	tests/fixtures/resource_robustness/MANIFEST.md
	do
	require_file "$path"
done

for path in \
	maint/security/osmap-v8-stabilization-gate.sh \
	maint/security/osmap-v8-mail-workflow-gate.sh \
	maint/security/osmap-v8-attachment-safety-gate.sh \
	maint/security/osmap-v8-mailbox-operation-gate.sh \
	maint/security/osmap-v8-session-integrity-gate.sh \
	maint/security/osmap-v8-resource-robustness-gate.sh \
	maint/security/osmap-v8-final-regression-gate.sh
	do
	require_executable "$path"
done

require_text Makefile "v8-check:"
require_text Makefile "v8-final-regression-check:"
require_text Makefile "osmap-v8-stabilization-gate.sh"
require_text Makefile "osmap-v8-mail-workflow-gate.sh"
require_text Makefile "osmap-v8-attachment-safety-gate.sh"
require_text Makefile "osmap-v8-mailbox-operation-gate.sh"
require_text Makefile "osmap-v8-session-integrity-gate.sh"
require_text Makefile "osmap-v8-resource-robustness-gate.sh"
require_text Makefile "osmap-v8-final-regression-gate.sh"

require_text maint/security/osmap-security-check.sh "make v8-check"
require_text maint/security/osmap-security-check.sh "validating V8 final regression aggregate gate"

require_text docs/V8_FINAL_REGRESSION_GATE_CLOSEOUT.md "make security-check"
require_text docs/V8_FINAL_REGRESSION_GATE_CLOSEOUT.md "make v8-check"
require_text docs/V8_FINAL_REGRESSION_GATE_CLOSEOUT.md "V8 does not claim feature parity with Roundcube"

echo "V8 final regression close-out gate passed"
