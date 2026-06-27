#!/usr/bin/env sh
set -eu

fail() {
	printf '%s\n' "V13 WSTG assurance gate failed: $*" >&2
	exit 1
}

doc=docs/V13_WSTG_ASSURANCE_INTEGRITY_AND_ADVERSARIAL_VALIDATION.md
[ -s "$doc" ] || fail "missing V13 sprint document"

for marker in \
	"Fail-Closed Runner Core" \
	"Matrix and Reporting Integrity" \
	"Current Attack-Surface Coverage" \
	"Adversarial Protocol and Browser Depth" \
	"Operational and Business Assurance" \
	"Closeout and Deployment"
do
	grep -Fq "$marker" "$doc" || fail "sprint document missing $marker"
done

sh maint/security/test-osmap-wstg-testing-pack.sh
printf '%s\n' "V13 WSTG assurance gate passed"
