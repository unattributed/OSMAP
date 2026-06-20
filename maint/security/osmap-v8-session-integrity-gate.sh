#!/bin/sh

set -eu

repo_root=${OSMAP_V8_GATE_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

require_file() {
	path=$1
	if [ ! -s "$path" ]; then
		echo "error: missing V8 session integrity file: $path" >&2
		exit 1
	fi
}

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V8 session integrity requirement in $path: $text" >&2
		exit 1
	fi
}

for path in \
	docs/V8_SESSION_INTEGRITY_MATRIX.md \
	tests/v8_session_integrity_matrix.rs \
	tests/fixtures/session_integrity/MANIFEST.md \
	tests/fixtures/session_integrity/lifecycle.env \
	tests/fixtures/session_integrity/timeout_cases.tsv \
	tests/fixtures/session_integrity/revocation_cases.tsv
	do
	require_file "$path"
done

require_text docs/V8_SESSION_INTEGRITY_MATRIX.md "session token validation"
require_text docs/V8_SESSION_INTEGRITY_MATRIX.md "CSRF token derivation"
require_text docs/V8_SESSION_INTEGRITY_MATRIX.md "logout-style revocation"
require_text docs/V8_SESSION_INTEGRITY_MATRIX.md "audit-event session redaction"
require_text tests/v8_session_integrity_matrix.rs "SessionToken"
require_text tests/v8_session_integrity_matrix.rs "revoke_all_for_user_except"
require_text tests/v8_session_integrity_matrix.rs "persisted session record must not contain raw bearer token"
require_text maint/security/osmap-v8-session-integrity-gate.sh "cargo test --test v8_session_integrity_matrix"
require_text Makefile "osmap-v8-session-integrity-gate.sh"

echo "==> cargo test --test v8_session_integrity_matrix"
cargo test --test v8_session_integrity_matrix

echo "V8 session integrity regression gate passed"
