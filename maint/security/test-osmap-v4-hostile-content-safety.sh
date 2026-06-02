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
html_support="$repo_root/src/http_support.rs"
rendering_html="$repo_root/src/rendering_html.rs"
attachment="$repo_root/src/attachment.rs"

require_text "$goals" "safe for viewing untrusted messages"
require_text "$goals" "browser-executable attachment media types are downgraded"
require_text "$matrix" "browser-executable attachments"
require_text "$matrix" "application/octet-stream"
require_text "$html_support" ".message-html a[href]::after"
require_text "$html_support" "attr(href)"
require_text "$rendering_html" "UrlRelative::Deny"
require_text "$rendering_html" "clean_content_tags"
require_text "$attachment" "is_browser_executable_download_type"
require_text "$attachment" "\"image/svg+xml\""
require_text "$attachment" "\"text/html\""

echo "V4 hostile-content safety gate passed"
