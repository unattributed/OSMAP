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
        fail "missing required V14 CSS/icon foundation text in $file: $pattern"
    fi
}

reject_runtime_pattern() {
    pattern="$1"
    shift
    for file in "$@"; do
        if [ -f "$file" ] && grep -Eq "$pattern" "$file"; then
            printf '%s\n' "disallowed V14 runtime pattern found in $file" >&2
            grep -nE "$pattern" "$file" >&2 || true
            failures=$((failures + 1))
        fi
    done
}

require_file "src/http_support.rs"
require_file "src/http_ui.rs"
require_file "docs/V14_SLICE_2_CSS_ICON_FOUNDATION.md"
require_file "maint/security/osmap-v14-css-icon-foundation-gate.sh"

require_pattern "fn browser_css" "src/http_support.rs"
require_pattern "ui-icon" "src/http_support.rs"
require_pattern "brand-icon" "src/http_support.rs"
require_pattern "currentColor" "src/http_support.rs"
require_pattern "prefers-reduced-motion" "src/http_support.rs"
require_pattern "ui-icon brand-icon" "src/http_ui.rs"

require_pattern "CSS-only" "docs/V14_SLICE_2_CSS_ICON_FOUNDATION.md"
require_pattern "local inline SVG" "docs/V14_SLICE_2_CSS_ICON_FOUNDATION.md"
require_pattern "No JavaScript" "docs/V14_SLICE_2_CSS_ICON_FOUNDATION.md"
require_pattern "no runtime asset fetch" "docs/V14_SLICE_2_CSS_ICON_FOUNDATION.md"

reject_runtime_pattern '<script|javascript:|onload=|onclick=|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare|package-lock\.json|pnpm-lock\.yaml|yarn\.lock' \
    src/http_ui.rs \
    docs/V14_SLICE_2_CSS_ICON_FOUNDATION.md \
    docs/README.md

if [ "$failures" -ne 0 ]; then
    printf '%s\n' "v14 css icon foundation gate failed: $failures failure(s)" >&2
    exit 1
fi

printf '%s\n' "v14 css icon foundation gate passed"
