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
        fail "missing required V14 authenticated shell text in $file: $pattern"
    fi
}

reject_runtime_pattern() {
    pattern="$1"
    shift
    for file in "$@"; do
        if [ -f "$file" ] && grep -Eq "$pattern" "$file"; then
            printf '%s\n' "disallowed V14 authenticated shell pattern found in $file" >&2
            grep -nE "$pattern" "$file" >&2 || true
            failures=$((failures + 1))
        fi
    done
}

require_file "src/http_ui.rs"
require_file "src/http_support.rs"
require_file "docs/V14_SLICE_3_AUTHENTICATED_APP_SHELL.md"
require_file "maint/security/osmap-v14-auth-shell-gate.sh"
require_file "Makefile"

require_pattern "skip-link" "src/http_ui.rs"
require_pattern "main-content" "src/http_ui.rs"
require_pattern "Authenticated OSMAP shell" "src/http_ui.rs"
require_pattern "Primary navigation" "src/http_ui.rs"
require_pattern "auth-status" "src/http_ui.rs"
require_pattern "identity-chip" "src/http_ui.rs"
require_pattern "shell-session-chip" "src/http_ui.rs"
require_pattern "logout-form" "src/http_ui.rs"
require_pattern "logout-button" "src/http_ui.rs"
require_pattern "Sign out of current session" "src/http_ui.rs"

require_pattern "skip-link" "src/http_support.rs"
require_pattern "page-shell:focus" "src/http_support.rs"
require_pattern "auth-status" "src/http_support.rs"
require_pattern "identity-chip" "src/http_support.rs"
require_pattern "shell-session-chip" "src/http_support.rs"
require_pattern "logout-button" "src/http_support.rs"

require_pattern "Functional acceptance" "docs/V14_SLICE_3_AUTHENTICATED_APP_SHELL.md"
require_pattern "Security acceptance" "docs/V14_SLICE_3_AUTHENTICATED_APP_SHELL.md"
require_pattern "Governance acceptance" "docs/V14_SLICE_3_AUTHENTICATED_APP_SHELL.md"
require_pattern "V4 hostile-message route compatibility" "docs/V14_SLICE_3_AUTHENTICATED_APP_SHELL.md"
require_pattern "no runtime JavaScript" "docs/V14_SLICE_3_AUTHENTICATED_APP_SHELL.md"
require_pattern "no OpenPGP runtime capability" "docs/V14_SLICE_3_AUTHENTICATED_APP_SHELL.md"
require_pattern "osmap-v14-auth-shell-gate.sh" "Makefile"

reject_runtime_pattern '<script|javascript:|onload=|onclick=|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare|package-lock\.json|pnpm-lock\.yaml|yarn\.lock' \
    src/http_ui.rs \
    docs/V14_SLICE_3_AUTHENTICATED_APP_SHELL.md \
    docs/README.md

reject_runtime_pattern '<svg class=\\"ui-icon brand-icon|<svg class="ui-icon brand-icon' \
    src/http_ui.rs

if [ "$failures" -ne 0 ]; then
    printf '%s\n' "v14 authenticated shell gate failed: $failures failure(s)" >&2
    exit 1
fi

printf '%s\n' "v14 authenticated shell gate passed"
