#!/usr/bin/env sh
set -eu

fail() {
  printf '%s\n' "V14 final closeout gate failed: $*" >&2
  exit 1
}

require_file() {
  [ -s "$1" ] || fail "missing required file: $1"
}

require_text() {
  file="$1"
  text="$2"
  grep -Fq "$text" "$file" || fail "missing required text in $file: $text"
}

require_file docs/V14_FINAL_REGRESSION_EVIDENCE_CLOSEOUT.md
require_file maint/security/osmap-v14-final-regression-closeout-gate.sh
require_file Makefile
require_file docs/README.md

require_text Makefile "osmap-v14-final-regression-closeout-gate.sh"
require_text docs/README.md "V14_FINAL_REGRESSION_EVIDENCE_CLOSEOUT.md"

require_text docs/V14_FINAL_REGRESSION_EVIDENCE_CLOSEOUT.md "V14 Slice 11"
require_text docs/V14_FINAL_REGRESSION_EVIDENCE_CLOSEOUT.md "final regression/evidence closeout"
require_text docs/V14_FINAL_REGRESSION_EVIDENCE_CLOSEOUT.md "does not redefine project supply-chain, SBOM, frontend, or release policy"
require_text docs/V14_FINAL_REGRESSION_EVIDENCE_CLOSEOUT.md "No runtime JavaScript"
require_text docs/V14_FINAL_REGRESSION_EVIDENCE_CLOSEOUT.md "No OpenPGP runtime capability expansion"
require_text docs/V14_FINAL_REGRESSION_EVIDENCE_CLOSEOUT.md "Verified signatures do not make content safe"
require_text docs/V14_FINAL_REGRESSION_EVIDENCE_CLOSEOUT.md "make v14-check"
require_text docs/V14_FINAL_REGRESSION_EVIDENCE_CLOSEOUT.md "make v10-check"
require_text docs/V14_FINAL_REGRESSION_EVIDENCE_CLOSEOUT.md "cargo check"
require_text docs/V14_FINAL_REGRESSION_EVIDENCE_CLOSEOUT.md "make security-check"

for gate in \
  maint/security/osmap-v14-streamline-webui-docs-gate.sh \
  maint/security/osmap-v14-css-icon-foundation-gate.sh \
  maint/security/osmap-v14-auth-shell-gate.sh \
  maint/security/osmap-v14-message-list-gate.sh \
  maint/security/osmap-v14-reader-trust-strip-gate.sh \
  maint/security/osmap-v14-openpgp-reader-states-gate.sh \
  maint/security/osmap-v14-compose-openpgp-controls-gate.sh \
  maint/security/osmap-v14-account-security-openpgp-controls-gate.sh \
  maint/security/osmap-v14-no-js-low-sbom-gate.sh \
  maint/security/osmap-v14-accessibility-responsive-gate.sh
 do
  require_file "$gate"
 done

sh maint/security/osmap-v14-no-js-low-sbom-gate.sh
sh maint/security/osmap-v14-accessibility-responsive-gate.sh

printf '%s\n' 'v14 final regression/evidence closeout gate passed'
