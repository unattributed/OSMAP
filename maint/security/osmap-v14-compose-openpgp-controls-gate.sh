#!/bin/sh
set -eu

fail() {
    printf '%s
' "error: $*" >&2
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
        printf '%s
' "error: missing $label in $file" >&2
        printf '%s
' "pattern: $pattern" >&2
        exit 1
    fi
}

reject_pattern() {
    file="$1"
    pattern="$2"
    label="$3"
    if grep -Eq "$pattern" "$file"; then
        printf '%s
' "error: forbidden pattern in $file: $label" >&2
        grep -nE "$pattern" "$file" >&2 || true
        exit 1
    fi
}

require_file "src/http_ui.rs"
require_file "src/http_support.rs"
require_file "docs/V14_SLICE_7_COMPOSE_OPENPGP_CONTROLS.md"
require_file "maint/security/osmap-v14-compose-openpgp-controls-gate.sh"
require_file "Makefile"

require_pattern "Makefile" "osmap-v14-compose-openpgp-controls-gate.sh" "v14-check Slice 7 gate wiring"

require_pattern "src/http_ui.rs" "openpgp-compose-controls" "OpenPGP compose controls panel"
require_pattern "src/http_ui.rs" "data-openpgp-compose-controls" "UI-only OpenPGP compose marker"
require_pattern "src/http_ui.rs" "ui-only" "UI-only OpenPGP compose boundary"
require_pattern "src/http_ui.rs" "OpenPGP compose controls" "compose controls heading"
require_pattern "src/http_ui.rs" "No account OpenPGP capability is configured for compose" "unconfigured compose state"
require_pattern "src/http_ui.rs" "No encrypt, sign, key lookup, private-key access, passphrase handling, or message mutation was attempted" "no runtime OpenPGP attempt boundary"
require_pattern "src/http_ui.rs" "Encrypt when configured" "future encrypt control label"
require_pattern "src/http_ui.rs" "Sign when configured" "future sign control label"
require_pattern "src/http_ui.rs" "Require configured recipient keys" "recipient-key control label"
require_pattern "src/http_ui.rs" "Send Message and Save Draft remain unchanged plaintext submission paths" "plaintext submission boundary"
require_pattern "src/http_ui.rs" 'action=\"/send\" enctype=\"multipart/form-data\"' "existing send form"
require_pattern "src/http_ui.rs" "Send Message" "existing send button"
require_pattern "src/http_ui.rs" 'formaction=\"/drafts/save\"' "existing save-draft button"
require_pattern "src/http_ui.rs" "render_source_attachment_controls" "source attachment controls preserved"

reject_pattern "src/http_ui.rs" 'name=\?"openpgp|formaction=\?"/openpgp|action=\?"/openpgp' "runtime OpenPGP form submission surface"
reject_pattern "src/http_ui.rs" '<script|javascript:|onload=|onclick=|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare' "JavaScript or remote frontend asset"

require_pattern "src/http_support.rs" "openpgp-compose-controls" "OpenPGP compose controls CSS"
require_pattern "src/http_support.rs" "openpgp-compose-option-list" "OpenPGP compose option CSS"
require_pattern "src/http_support.rs" "openpgp-compose-boundary-note" "OpenPGP compose boundary-note CSS"

require_pattern "docs/V14_SLICE_7_COMPOSE_OPENPGP_CONTROLS.md" "Functional acceptance" "functional acceptance section"
require_pattern "docs/V14_SLICE_7_COMPOSE_OPENPGP_CONTROLS.md" "Security acceptance" "security acceptance section"
require_pattern "docs/V14_SLICE_7_COMPOSE_OPENPGP_CONTROLS.md" "Governance acceptance" "governance acceptance section"
require_pattern "docs/V14_SLICE_7_COMPOSE_OPENPGP_CONTROLS.md" "UI-only" "UI-only scope"
require_pattern "docs/V14_SLICE_7_COMPOSE_OPENPGP_CONTROLS.md" "no OpenPGP runtime capability change" "no runtime capability claim"
require_pattern "docs/V14_SLICE_7_COMPOSE_OPENPGP_CONTROLS.md" "Send Message and Save Draft remain unchanged plaintext submission paths" "plaintext submission boundary"
require_pattern "docs/V14_SLICE_7_COMPOSE_OPENPGP_CONTROLS.md" "no runtime JavaScript" "no JavaScript claim"
require_pattern "docs/V14_SLICE_7_COMPOSE_OPENPGP_CONTROLS.md" "does not claim encryption" "non-claim boundary"
require_pattern "docs/README.md" "V14_SLICE_7_COMPOSE_OPENPGP_CONTROLS.md" "documentation index entry"

printf '%s
' "v14 compose OpenPGP controls gate passed"
