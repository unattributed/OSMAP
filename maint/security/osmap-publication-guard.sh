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
	matches=$(
		tracked_files |
			grep -E "$pattern" |
			grep -Ev '^maint/live/latest-host-(v2-readiness-report|v2-readiness-service-guard-report|edge-cutover-report|internet-exposure-report|service-enablement-report|v3-resource-controls-report|helper-boundary-report|v3-mime-html-proof-report|v3-pilot-rehearsal-report|v4-hostile-content-report)\.txt$' || true
	)
	if [ -n "$matches" ]; then
		append_failure "tracked generated or private path matched: ${pattern}"
		printf '%s\n' "$matches"
	fi
}

assert_required_text() {
	path=$1
	text=$2
	if [ -f "$path" ] && ! grep -Fq "$text" "$path"; then
		append_failure "tracked sanitized evidence missing required text: ${path}: ${text}"
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

if git ls-files --error-unmatch maint/live/latest-host-v4-hostile-content-report.txt >/dev/null 2>&1; then
	assert_required_text maint/live/latest-host-v4-hostile-content-report.txt "result=v4_hostile_content_live_proof_passed"
	assert_required_text maint/live/latest-host-v4-hostile-content-report.txt "No password, TOTP material, session cookie, CSRF token, private message body, attachment body, provider secret, or host secret is included."
fi
if git ls-files --error-unmatch maint/live/latest-host-v3-mime-html-proof-report.txt >/dev/null 2>&1; then
	assert_required_text maint/live/latest-host-v3-mime-html-proof-report.txt "result=v3_mime_html_live_proof_passed"
fi
if git ls-files --error-unmatch maint/live/latest-host-v3-pilot-rehearsal-report.txt >/dev/null 2>&1; then
	assert_required_text maint/live/latest-host-v3-pilot-rehearsal-report.txt "result=v3_pilot_rehearsal_passed"
	assert_required_text maint/live/latest-host-v3-pilot-rehearsal-report.txt "sanitized_evidence=true"
fi
if git ls-files --error-unmatch maint/live/latest-host-v3-resource-controls-report.txt >/dev/null 2>&1; then
	assert_required_text maint/live/latest-host-v3-resource-controls-report.txt "osmap_v3_resource_controls_result=passed"
	assert_required_text maint/live/latest-host-v3-resource-controls-report.txt "No passwords, TOTP material, session cookie, CSRF token, private message body, attachment body, provider secret, or host secret is included."
fi

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
