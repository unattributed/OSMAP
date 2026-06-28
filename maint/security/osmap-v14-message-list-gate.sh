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
        fail "missing required V14 message-list text in $file: $pattern"
    fi
}

reject_runtime_pattern() {
    pattern="$1"
    shift
    for file in "$@"; do
        if [ -f "$file" ] && grep -Eq "$pattern" "$file"; then
            printf '%s\n' "disallowed V14 message-list pattern found in $file" >&2
            grep -nE "$pattern" "$file" >&2 || true
            failures=$((failures + 1))
        fi
    done
}

require_file "src/http_ui.rs"
require_file "src/http_support.rs"
require_file "docs/V14_SLICE_4_MODERN_INBOX_MESSAGE_LIST.md"
require_file "maint/security/osmap-v14-message-list-gate.sh"
require_file "Makefile"

require_pattern "message-list-summary" "src/http_ui.rs"
require_pattern "Mailbox message list" "src/http_ui.rs"
require_pattern "message-row" "src/http_ui.rs"
require_pattern "message-subject-link" "src/http_ui.rs"
require_pattern "message-preview-meta" "src/http_ui.rs"
require_pattern "message-flags" "src/http_ui.rs"
require_pattern "message-empty-state" "src/http_ui.rs"
require_pattern "bulk actions CSRF-bound" "src/http_ui.rs"

require_pattern "message-list-summary" "src/http_support.rs"
require_pattern "message-row" "src/http_support.rs"
require_pattern "message-subject-cell" "src/http_support.rs"
require_pattern "message-subject-link" "src/http_support.rs"
require_pattern "message-preview-meta" "src/http_support.rs"
require_pattern "message-empty-state" "src/http_support.rs"

require_pattern "Functional acceptance" "docs/V14_SLICE_4_MODERN_INBOX_MESSAGE_LIST.md"
require_pattern "Security acceptance" "docs/V14_SLICE_4_MODERN_INBOX_MESSAGE_LIST.md"
require_pattern "Governance acceptance" "docs/V14_SLICE_4_MODERN_INBOX_MESSAGE_LIST.md"
require_pattern "V4 hostile-message route compatibility" "docs/V14_SLICE_4_MODERN_INBOX_MESSAGE_LIST.md"
require_pattern "no runtime JavaScript" "docs/V14_SLICE_4_MODERN_INBOX_MESSAGE_LIST.md"
require_pattern "no new dependency" "docs/V14_SLICE_4_MODERN_INBOX_MESSAGE_LIST.md"
require_pattern "no OpenPGP runtime capability" "docs/V14_SLICE_4_MODERN_INBOX_MESSAGE_LIST.md"
require_pattern "osmap-v14-message-list-gate.sh" "Makefile"

reject_runtime_pattern '<script|javascript:|onload=|onclick=|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare|package-lock\.json|pnpm-lock\.yaml|yarn\.lock' \
    src/http_ui.rs \
    docs/V14_SLICE_4_MODERN_INBOX_MESSAGE_LIST.md \
    docs/README.md

reject_runtime_pattern '<svg class=\\"message|<svg class="message|<img|<iframe|<object|<embed|<video|<audio|<source|<link rel=\\"stylesheet|<link rel="stylesheet' \
    src/http_ui.rs

if [ "$failures" -ne 0 ]; then
    printf '%s\n' "v14 message-list gate failed: $failures failure(s)" >&2
    exit 1
fi

printf '%s\n' "v14 message-list gate passed"
