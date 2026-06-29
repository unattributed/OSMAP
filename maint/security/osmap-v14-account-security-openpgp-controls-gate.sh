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

require_pattern "src/http_ui.rs" "data-openpgp-account-controls=\"ui-only\"" "UI-only account OpenPGP control marker"
require_pattern "src/http_ui.rs" "Account Security" "account security heading"
require_pattern "src/http_ui.rs" "OpenPGP not configured" "not-configured OpenPGP account state"
require_pattern "src/http_ui.rs" "Protected by Default preserved" "protected rendering boundary label"
require_pattern "src/http_ui.rs" "They submit no OpenPGP form fields" "no submitted OpenPGP field boundary"
require_pattern "src/http_ui.rs" "action=\\\"/settings\\\" class=\\\"action-stack\\\"" "existing settings form source marker"
require_pattern "src/http_ui.rs" "name=\\\"html_display_preference\\\"" "existing HTML display preference field"
require_pattern "src/http_ui.rs" "name=\\\"archive_mailbox_name\\\"" "existing archive mailbox field"
require_pattern "src/http_support.rs" ".openpgp-account-security" "account OpenPGP control CSS"
require_pattern "src/http_support.rs" ".openpgp-account-control-set" "account OpenPGP disabled control CSS"
require_pattern "docs/V14_SLICE_8_ACCOUNT_SECURITY_OPENPGP_CONTROLS.md" "No OpenPGP runtime capability change" "OpenPGP runtime no-claim boundary"
require_pattern "docs/V14_SLICE_8_ACCOUNT_SECURITY_OPENPGP_CONTROLS.md" "no runtime JavaScript" "no JavaScript boundary"
require_pattern "docs/V14_SLICE_8_ACCOUNT_SECURITY_OPENPGP_CONTROLS.md" "submit no OpenPGP form fields" "no submitted field documentation"
require_pattern "docs/README.md" "V14_SLICE_8_ACCOUNT_SECURITY_OPENPGP_CONTROLS.md" "Slice 8 documentation index entry"
require_pattern "Makefile" "osmap-v14-account-security-openpgp-controls-gate.sh" "Slice 8 v14-check gate registration"

reject_pattern "src/http_ui.rs" "name=\"openpgp" "rendered-style OpenPGP form field"
reject_pattern "src/http_ui.rs" "name=\\\"openpgp" "escaped OpenPGP form field"
reject_pattern "src/http_ui.rs" "action=\\\"/openpgp" "OpenPGP mutation route"
reject_pattern "src/http_ui.rs" "method=\\\"post\\\" action=\\\"/openpgp" "OpenPGP POST route"

echo "v14 account security OpenPGP controls gate passed"
