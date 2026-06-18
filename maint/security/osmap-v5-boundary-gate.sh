#!/bin/sh

set -eu

repo_root=${OSMAP_V5_BOUNDARY_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

: "${OSMAP_V5_BOUNDARY_EVIDENCE:=docs/V5_BOUNDARY_HARDENING_EVIDENCE.md}"
: "${OSMAP_V5_PRODUCTION_EVIDENCE:=docs/V5_PRODUCTION_DEPLOYMENT_COMPLETE.md}"

require_file() {
	path=$1
	if [ ! -s "$path" ]; then
		echo "error: missing V5 boundary input: $path" >&2
		exit 1
	fi
}

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V5 boundary evidence in $path: $text" >&2
		exit 1
	fi
}

for path in \
	"$OSMAP_V5_BOUNDARY_EVIDENCE" \
	"$OSMAP_V5_PRODUCTION_EVIDENCE" \
	src/html.rs \
	src/http_support.rs \
	src/rendering.rs \
	src/http.rs
do
	require_file "$path"
done

for status in \
	"canonical username validation" \
	"configured host and origin enforcement" \
	"session record identity field validation" \
	"consistent security headers for health and text responses" \
	"strict HTTP framing rejection" \
	"template and trusted HTML boundary review"
do
	require_text "$OSMAP_V5_BOUNDARY_EVIDENCE" "$status"
done

require_text "$OSMAP_V5_PRODUCTION_EVIDENCE" "OSMAP_ALLOWED_HOSTS=mail.blackbagsecurity.com"
require_text "$OSMAP_V5_PRODUCTION_EVIDENCE" "invalid Host: attacker.invalid -> 421"
require_text "$OSMAP_V5_PRODUCTION_EVIDENCE" "osmap_serve(ok)"
require_text "$OSMAP_V5_PRODUCTION_EVIDENCE" "osmap_mailbox_helper(ok)"

require_text src/html.rs "pub struct EscapedHtml"
require_text src/html.rs "pub struct TrustedHtml"
require_text src/http_support.rs "body_html: impl Into<TrustedHtml>"
require_text src/rendering.rs "pub body_html: TrustedHtml"
require_text src/http.rs "rejects_requests_with_unconfigured_host"
require_text src/http.rs "rejects_origin_matching_attacker_host_but_not_configured_host"
require_text src/http.rs "healthz_response_includes_plain_text_security_headers"
require_text src/http.rs "rejects_duplicate_content_length_body_framing"
require_text src/http.rs "rejects_pipelined_second_request_bytes"
require_text src/http.rs "rejects_unsupported_transfer_encoding_headers"

echo "V5 boundary gate passed"
