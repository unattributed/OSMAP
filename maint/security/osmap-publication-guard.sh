#!/bin/sh
#
# Guard against committing secrets or high-risk publication artifacts.

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

failures=""

append_failure() {
	if [ -z "$failures" ]; then
		failures=$1
	else
		failures="${failures}
$1"
	fi
}

tracked_files() {
	git ls-files | grep -v '^maint/security/osmap-publication-guard\.sh$'
}

tracked_files_z() {
	tracked_files | tr '\n' '\0'
}

assert_no_tracked_path() {
	pattern=$1
	if tracked_files | grep -Eq "$pattern"; then
		append_failure "tracked generated or private path matched: ${pattern}"
		tracked_files | grep -E "$pattern" || true
	fi
}

assert_no_literal() {
	label=$1
	value=$2
	matches=$(tracked_files_z | xargs -0 grep -InF "$value" 2>/dev/null || true)
	if [ -n "$matches" ]; then
		append_failure "tracked files contain disallowed ${label}"
		printf '%s\n' "$matches"
	fi
}

assert_no_regex() {
	label=$1
	regex=$2
	matches=$(tracked_files_z | xargs -0 grep -InE "$regex" 2>/dev/null || true)
	if [ -n "$matches" ]; then
		append_failure "tracked files match disallowed ${label}"
		printf '%s\n' "$matches"
	fi
}

real_primary="duncan@blackbagsecurity"
real_primary="${real_primary}.com"
real_ops="ops@blackbagsecurity"
real_ops="${real_ops}.io"
legacy_validation_totp="JBSWY3DPEHPK3PXP"

assert_no_tracked_path '^maint/live/latest-.*\.txt$'
assert_no_tracked_path '^maint/.*/output/'

assert_no_literal "real primary mailbox" "$real_primary"
assert_no_literal "real ops mailbox" "$real_ops"
assert_no_literal "legacy static validation TOTP seed" "$legacy_validation_totp"
assert_no_literal "broad doas operator override" "permit nopass foo"
assert_no_literal "doas.conf transcript" "doas cat /etc/doas.conf"

assert_no_regex "private key material" 'BEGIN (RSA|OPENSSH|EC|DSA|PRIVATE) KEY|PRIVATE KEY-----'
assert_no_regex "common cloud or GitHub token material" 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+'
assert_no_regex "authorization header evidence" '[Aa]uthorization:[[:space:]]*(Basic|Bearer)[[:space:]][A-Za-z0-9._~+/=-]+'
assert_no_regex "set-cookie evidence" '[Ss]et-[Cc]ookie:[[:space:]]'
session_matches=$(
	tracked_files_z |
		xargs -0 grep -InE 'osmap_session=[A-Za-z0-9._~+/=-]{20,}' 2>/dev/null |
		grep -Ev 'osmap_session=(a{32,}|b{32,}|c{32,})' || true
)
if [ -n "$session_matches" ]; then
	append_failure "tracked files contain non-synthetic OSMAP session cookie evidence"
	printf '%s\n' "$session_matches"
fi

if [ -n "$failures" ]; then
	printf '%s\n' "publication guard failed:"
	printf '%s\n' "$failures"
	exit 1
fi

printf '%s\n' "publication guard passed"
