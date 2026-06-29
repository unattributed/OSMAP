#!/bin/sh
set -eu

fail() {
    printf '%s\n' "error: $*" >&2
    exit 1
}

require_file() {
    [ -s "$1" ] || fail "missing required file: $1"
}

require_pattern() {
    file="$1"
    pattern="$2"
    label="$3"
    if ! grep -Fq "$pattern" "$file"; then
        printf '%s\n' "error: missing $label in $file" >&2
        printf '%s\n' "pattern: $pattern" >&2
        exit 1
    fi
}

reject_runtime_pattern() {
    file="$1"
    pattern="$2"
    label="$3"
    if grep -Eq "$pattern" "$file"; then
        printf '%s\n' "error: forbidden runtime UI pattern in $file: $label" >&2
        grep -nE "$pattern" "$file" >&2 || true
        exit 1
    fi
}

require_file "src/http_ui.rs"
require_file "src/http_support.rs"
require_file "docs/V14_SLICE_6_OPENPGP_READER_STATES.md"
require_file "maint/security/osmap-v14-openpgp-reader-states-gate.sh"
require_file "Makefile"

require_pattern "Makefile" "osmap-v14-openpgp-reader-states-gate.sh" "v14-check Slice 6 gate wiring"

require_pattern "src/http_ui.rs" "openpgp-reader-states" "OpenPGP reader-state section"
require_pattern "src/http_ui.rs" "data-openpgp-reader-states" "UI-only OpenPGP reader-state marker"
require_pattern "src/http_ui.rs" "ui-only" "UI-only claim boundary"
require_pattern "src/http_ui.rs" "OpenPGP reader state" "reader-state heading"
require_pattern "src/http_ui.rs" "No account OpenPGP capability is configured" "unconfigured-account state"
require_pattern "src/http_ui.rs" "No decrypt, verify, key discovery, private-key access, or passphrase handling was attempted" "no runtime OpenPGP attempt boundary"
require_pattern "src/http_ui.rs" "Encrypted" "encrypted state label"
require_pattern "src/http_ui.rs" "Decrypted locally" "decrypted state label"
require_pattern "src/http_ui.rs" "Signature" "signature state label"
require_pattern "src/http_ui.rs" "not assessed" "not-assessed state"
require_pattern "src/http_ui.rs" "not produced" "not-produced state"
require_pattern "src/http_ui.rs" "not verified" "not-verified state"
require_pattern "src/http_ui.rs" "Verified signatures do not make content safe" "signature safety boundary"
require_pattern "src/http_ui.rs" "Future decrypted content must still pass Protected by Default rendering" "decrypted-content rendering boundary"

require_pattern "src/http_ui.rs" "Reading Pane" "legacy reader regression heading"
require_pattern "src/http_ui.rs" "body-panel" "legacy body-panel marker"
require_pattern "src/http_ui.rs" "data-protected-body-panel" "Protected by Default body marker"

require_pattern "src/http_support.rs" "openpgp-reader-states" "OpenPGP reader-state CSS"
require_pattern "src/http_support.rs" "openpgp-state-list" "OpenPGP state-list CSS"
require_pattern "src/http_support.rs" "openpgp-boundary-note" "OpenPGP boundary-note CSS"

require_pattern "docs/V14_SLICE_6_OPENPGP_READER_STATES.md" "Functional acceptance" "functional acceptance section"
require_pattern "docs/V14_SLICE_6_OPENPGP_READER_STATES.md" "Security acceptance" "security acceptance section"
require_pattern "docs/V14_SLICE_6_OPENPGP_READER_STATES.md" "Governance acceptance" "governance acceptance section"
require_pattern "docs/V14_SLICE_6_OPENPGP_READER_STATES.md" "UI-only" "UI-only scope"
require_pattern "docs/V14_SLICE_6_OPENPGP_READER_STATES.md" "no OpenPGP runtime capability change" "no runtime capability claim"
require_pattern "docs/V14_SLICE_6_OPENPGP_READER_STATES.md" "Verified signatures do not make content safe" "signature safety boundary"
require_pattern "docs/V14_SLICE_6_OPENPGP_READER_STATES.md" "future decrypted content" "future decrypted-content boundary"
require_pattern "docs/V14_SLICE_6_OPENPGP_READER_STATES.md" "no runtime JavaScript" "no JavaScript claim"

reject_runtime_pattern "src/http_ui.rs" '<script|javascript:|onload=|onclick=|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare' "JavaScript or remote frontend asset"

printf '%s\n' "v14 OpenPGP reader states gate passed"
