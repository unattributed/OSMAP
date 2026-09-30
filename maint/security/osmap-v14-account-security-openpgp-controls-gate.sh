#!/bin/sh
set -eu

require_pattern() {
  file="$1"
  pattern="$2"
  description="$3"
  if ! grep -Fq -- "$pattern" "$file"; then
    echo "error: missing ${description} in ${file}" >&2
    echo "pattern: ${pattern}" >&2
    exit 2
  fi
}

reject_pattern() {
  file="$1"
  pattern="$2"
  description="$3"
  if grep -Fq -- "$pattern" "$file"; then
    echo "error: unexpected ${description} in ${file}" >&2
    echo "pattern: ${pattern}" >&2
    exit 2
  fi
}

# Approved General/Reading renderers replace the retired monolithic settings
# renderer. Check the actual controls and rendered route boundary, not dead UI.
require_pattern "src/settings_general_ui.rs" "Account Security" "account security heading"
require_pattern "src/settings_general_ui.rs" 'unavailable_select("general-signing", "OpenPGP signing", "Unavailable")' "unavailable signing control"
require_pattern "src/settings_general_ui.rs" 'unavailable_select("general-encryption", "Encryption", "Unavailable")' "unavailable encryption control"
require_pattern "src/settings_general_ui.rs" "disabled aria-label=" "disabled preference implementation"
require_pattern "src/settings_general_ui.rs" "Source is never active HTML" "protected rendering boundary label"
require_pattern "src/settings_reading_ui.rs" "name=\\\"html_display_preference\\\"" "existing HTML display preference field"
require_pattern "src/settings_reading_ui.rs" "name=\\\"archive_mailbox_name\\\"" "existing archive mailbox field"
require_pattern "src/http/general.css" ".general-status-list" "account security status layout"
require_pattern "docs/V14_SLICE_8_ACCOUNT_SECURITY_OPENPGP_CONTROLS.md" "No OpenPGP runtime capability change" "OpenPGP runtime no-claim boundary"
require_pattern "docs/V14_SLICE_8_ACCOUNT_SECURITY_OPENPGP_CONTROLS.md" "no runtime JavaScript" "no JavaScript boundary"
require_pattern "docs/V14_SLICE_8_ACCOUNT_SECURITY_OPENPGP_CONTROLS.md" "submit no OpenPGP form fields" "no submitted field documentation"
require_pattern "docs/README.md" "V14_SLICE_8_ACCOUNT_SECURITY_OPENPGP_CONTROLS.md" "Slice 8 documentation index entry"
require_pattern "Makefile" "osmap-v14-account-security-openpgp-controls-gate.sh" "Slice 8 v14-check gate registration"

for file in src/http_ui.rs src/settings_general_ui.rs src/settings_reading_ui.rs; do
  reject_pattern "$file" "name=\"openpgp" "rendered-style OpenPGP form field"
  reject_pattern "$file" "name=\\\"openpgp" "escaped OpenPGP form field"
  reject_pattern "$file" "action=\\\"/openpgp" "OpenPGP mutation route"
  reject_pattern "$file" "method=\\\"post\\\" action=\\\"/openpgp" "OpenPGP POST route"
done
cargo test --lib compact_security_states_do_not_claim_undelivered_capabilities

echo "v14 account security OpenPGP controls gate passed"
