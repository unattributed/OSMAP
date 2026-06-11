#!/bin/sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

require_text() {
  path="$1"
  text="$2"
  if ! grep -Fq "$text" "$path"; then
    echo "missing expected text in $path: $text" >&2
    exit 1
  fi
}

goals="$repo_root/docs/V4_HOSTILE_CONTENT_SAFETY_GOALS.md"
matrix="$repo_root/docs/V4_HOSTILE_CONTENT_TEST_MATRIX.md"
definition="$repo_root/docs/V4_DEFINITION.md"
acceptance="$repo_root/docs/V4_ACCEPTANCE_CRITERIA.md"
security_gates="$repo_root/docs/V4_SECURITY_GATES.md"
roadmap="$repo_root/docs/V4_ROADMAP.md"
closeout="$repo_root/docs/V4_CLOSEOUT_EVIDENCE.md"
html_support="$repo_root/src/http_support.rs"
rendering_html="$repo_root/src/rendering_html.rs"
attachment="$repo_root/src/attachment.rs"

test -f "$definition"
test -f "$acceptance"
test -f "$security_gates"
test -f "$roadmap"
test -f "$closeout"
require_text "$goals" "safe for viewing untrusted messages"
require_text "$goals" "browser-executable attachment media types are downgraded"
require_text "$matrix" "browser-executable attachments"
require_text "$matrix" "application/octet-stream"
require_text "$definition" "Version 4 is a hostile-content safety release"
require_text "$definition" "no-remote-load browser boundary"
require_text "$acceptance" "Browser-executable attachment containment"
require_text "$acceptance" "Evidence Required At Closeout"
require_text "$security_gates" "Version 4 cannot pass by replacing, weakening, or silently skipping any of these gates"
require_text "$security_gates" "live-host proof at release closeout"
require_text "$roadmap" "The live V4 hostile-content proof has now passed"
require_text "$roadmap" "latest-host-v4-hostile-content-report.txt"
require_text "$closeout" "result=v4_hostile_content_live_proof_passed"
require_text "$closeout" "Full V4 closeout still requires"
require_text "$html_support" ".message-html a[href]::after"
require_text "$html_support" "attr(href)"
require_text "$rendering_html" "UrlRelative::Deny"
require_text "$rendering_html" "clean_content_tags"
require_text "$attachment" "is_browser_executable_download_type"
require_text "$attachment" "\"image/svg+xml\""
require_text "$attachment" "\"text/html\""

echo "V4 hostile-content safety gate passed"
