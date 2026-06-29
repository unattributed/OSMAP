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

# Reuse Slice 9 boundary enforcement instead of duplicating policy text here.
sh maint/security/osmap-v14-no-js-low-sbom-gate.sh

require_pattern "src/http_ui.rs" 'class=\"skip-link\" href=\"#main-content\"' "skip link to main content"
require_pattern "src/http_ui.rs" 'id=\"main-content\" class=\"page-shell\" tabindex=\"-1\"' "focusable main content target"
require_pattern "src/http_ui.rs" 'aria-label=\"Primary navigation\"' "primary navigation accessible name"
require_pattern "src/http_ui.rs" 'aria-label=\"Session status and identity\"' "session status accessible name"
require_pattern "src/http_ui.rs" 'aria-label=\"Select message #{} for bulk move\"' "bulk move checkbox accessible name"
require_pattern "src/http_ui.rs" 'aria-label=\"Select message #{} for bulk archive\"' "bulk archive checkbox accessible name"
require_pattern "src/http_support.rs" "a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible" "visible focus rule"
require_pattern "src/http_support.rs" "@media (prefers-reduced-motion:reduce)" "reduced motion media query"
require_pattern "src/http_support.rs" "@media (max-width:40rem)" "small-screen responsive rule"
require_pattern "docs/V14_SLICE_10_ACCESSIBILITY_RESPONSIVE_PASS.md" "No OpenPGP runtime capability change" "OpenPGP runtime non-claim"
require_pattern "docs/V14_SLICE_10_ACCESSIBILITY_RESPONSIVE_PASS.md" "No runtime JavaScript" "no JavaScript boundary"
require_pattern "docs/README.md" "V14_SLICE_10_ACCESSIBILITY_RESPONSIVE_PASS.md" "Slice 10 documentation index entry"
require_pattern "Makefile" "osmap-v14-accessibility-responsive-gate.sh" "Slice 10 v14-check registration"

reject_pattern "src/http_ui.rs" "onclick=" "inline JavaScript event handler"
reject_pattern "src/http_ui.rs" "onchange=" "inline JavaScript event handler"
reject_pattern "src/http_ui.rs" "onload=" "inline JavaScript event handler"
reject_pattern "src/http_ui.rs" "<script" "runtime script tag"

echo "v14 accessibility and responsive gate passed"
