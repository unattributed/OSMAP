#!/bin/sh
set -eu

failures=0

fail() {
    printf '%s\n' "FAIL: $1" >&2
    failures=$((failures + 1))
}

require_file() {
    if [ ! -f "$1" ]; then
        fail "missing file: $1"
    fi
}

require_pattern() {
    pattern="$1"
    file="$2"
    if ! grep -Eq "$pattern" "$file"; then
        fail "missing required V14 reader trust-strip text in $file: $pattern"
    fi
}

reject_runtime_pattern() {
    pattern="$1"
    shift
    for file in "$@"; do
        if [ -f "$file" ] && grep -Eq "$pattern" "$file"; then
            printf '%s\n' "disallowed V14 reader runtime pattern found in $file" >&2
            grep -nE "$pattern" "$file" >&2 || true
            failures=$((failures + 1))
        fi
    done
}

require_file "src/http_ui.rs"
require_file "src/http_support.rs"
require_file "docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md"
require_file "maint/security/osmap-v14-reader-trust-strip-gate.sh"
require_file "Makefile"

require_pattern "protected-trust-strip" "src/http_ui.rs"
require_pattern "Protected by Default" "src/http_ui.rs"
require_pattern "Verified signatures do not make content safe" "src/http_ui.rs"
require_pattern "future decrypted content must still pass protected rendering" "src/http_ui.rs"
require_pattern "Source view escaped" "src/http_ui.rs"
require_pattern "Protected Reader" "src/http_ui.rs"
require_pattern "data-protected-body-panel" "src/http_ui.rs"
require_pattern "explicit, escaped, authorized, and bounded" "src/http_ui.rs"
require_pattern "remote_content_state" "src/http_ui.rs"

require_pattern "protected-trust-strip" "src/http_support.rs"
require_pattern "trust-strip-badges" "src/http_support.rs"
require_pattern "protected-reading-pane" "src/http_support.rs"
require_pattern "reader-section-heading" "src/http_support.rs"
require_pattern "reader-boundary-note" "src/http_support.rs"
require_pattern "data-protected-body-panel" "src/http_ui.rs"
require_pattern "data-protected-body-panel" "src/http_support.rs"

require_pattern "Functional acceptance" "docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md"
require_pattern "Security acceptance" "docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md"
require_pattern "Governance acceptance" "docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md"
require_pattern "Protected by Default trust strip" "docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md"
require_pattern "Verified signatures do not make content safe" "docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md"
require_pattern "future decrypted content must still pass protected rendering" "docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md"
require_pattern "Remote content remains blocked" "docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md"
require_pattern "explicit, escaped, authorized, and bounded" "docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md"
require_pattern "no OpenPGP runtime capability" "docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md"
require_pattern "no runtime JavaScript" "docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md"
require_pattern "V4 hostile-message route compatibility" "docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md"
require_pattern "osmap-v14-reader-trust-strip-gate.sh" "Makefile"

reject_runtime_pattern '<script|javascript:|onload=|onclick=|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare|package-lock\.json|pnpm-lock\.yaml|yarn\.lock' \
    src/http_ui.rs \
    docs/V14_SLICE_5_MODERN_READER_TRUST_STRIP.md \
    docs/README.md

if [ "$failures" -ne 0 ]; then
    printf '%s\n' "v14 reader trust-strip gate failed: $failures failure(s)" >&2
    exit 1
fi

printf '%s\n' "v14 reader trust-strip gate passed"
