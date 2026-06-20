#!/bin/sh

set -eu

repo_root=${OSMAP_V8_GATE_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

require_file() {
	path=$1
	if [ ! -s "$path" ]; then
		echo "error: missing V8 stabilization framework file: $path" >&2
		exit 1
	fi
}

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V8 stabilization requirement in $path: $text" >&2
		exit 1
	fi
}

for path in \
	Makefile \
	docs/V8_STABILIZATION_PROGRAM.md \
	maint/security/osmap-v8-stabilization-gate.sh \
	.github/workflows/security-check.yml
	do
	require_file "$path"
done

require_text docs/V8_STABILIZATION_PROGRAM.md "V8 exists because OSMAP has reached the point where regression risk is more important than feature expansion."
require_text docs/V8_STABILIZATION_PROGRAM.md "The V7 rendering regression close-out showed that an existing daily-driver behavior can fail in production when testing discipline weakens."
require_text docs/V8_STABILIZATION_PROGRAM.md "V8 does not pursue Roundcube feature parity."
require_text docs/V8_STABILIZATION_PROGRAM.md "Every V8 slice must produce evidence outside the repository."
require_text docs/V8_STABILIZATION_PROGRAM.md "mail workflow regression"
require_text docs/V8_STABILIZATION_PROGRAM.md "attachment safety"
require_text docs/V8_STABILIZATION_PROGRAM.md "mailbox operations"
require_text docs/V8_STABILIZATION_PROGRAM.md "session integrity"
require_text docs/V8_STABILIZATION_PROGRAM.md "resource exhaustion and robustness"
require_text docs/V8_STABILIZATION_PROGRAM.md "During Slice 6, CI should be updated so V8 gates are mandatory."

require_text Makefile "v8-check:"
require_text Makefile "osmap-v8-stabilization-gate.sh"
require_text Makefile ".PHONY:"
require_text .github/workflows/security-check.yml "make security-check"

echo "V8 stabilization framework gate passed"
