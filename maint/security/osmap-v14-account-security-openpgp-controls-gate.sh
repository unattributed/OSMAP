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

# General/Reading replace the retired monolithic settings renderer. Retain the
# unavailable-load boundary and qualify the implemented composition preferences.
require_pattern "src/settings_general_ui.rs" "Account Security" "account security heading"
require_pattern "src/settings_general_ui.rs" 'unavailable_select("general-signing", "OpenPGP signing", "Unavailable")' "unavailable signing control"
require_pattern "src/settings_general_ui.rs" 'unavailable_select("general-encryption", "Encryption", "Unavailable")' "unavailable encryption control"
require_pattern "src/settings_general_ui.rs" '"pgp_sign", value.openpgp.sign' "saved signing preference projection"
require_pattern "src/settings_general_ui.rs" '"pgp_encrypt", value.openpgp.encrypt' "saved encryption preference projection"
require_pattern "src/settings_general_ui.rs" '"pgp_self", value.openpgp.encrypt_to_self' "saved self preference projection"
require_pattern "src/settings_general_ui.rs" 'form=\"general-composition-form\"' "composition preference form association"
require_pattern "src/composition_preferences.rs" 'pub fn update(' "atomic preference merge"
require_pattern "src/http/routes_composition_preferences.rs" 'self.gateway.update_composition_preferences(' "typed preference persistence route"
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
cargo test --lib openpgp_defaults_save_reload_isolate_accounts_and_apply_only_to_fresh_composers
cargo test --lib openpgp_defaults_invalid_or_partial_forms_preserve_record_and_legacy_posts_merge

echo "v14 account security OpenPGP controls gate passed"
