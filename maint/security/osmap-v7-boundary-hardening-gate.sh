#!/bin/sh

set -eu

repo_root=${OSMAP_V7_GATE_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

require_file() {
	path=$1
	if [ ! -s "$path" ]; then
		echo "error: missing V7 boundary input: $path" >&2
		exit 1
	fi
}

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V7 boundary requirement in $path: $text" >&2
		exit 1
	fi
}

for path in \
	docs/V7_BOUNDARY_HARDENING_DUE_DILIGENCE.md \
	src/http_parse.rs \
	src/totp.rs \
	src/session.rs \
	src/throttle.rs \
	src/http_form.rs
do
	require_file "$path"
done

require_text src/http_parse.rs "else if buffer.len() > policy.max_header_bytes"
if grep -Fq "policy.max_header_bytes + policy.max_upload_body_bytes" src/http_parse.rs; then
	echo "error: headerless HTTP reads still include the upload body allowance" >&2
	exit 1
fi
require_text src/http_parse.rs "rejects_headerless_streams_over_the_header_limit"
require_text src/http_parse.rs "ignores_x_forwarded_for_from_loopback_proxy_requests"

require_text src/totp.rs "pub const MIN_TOTP_SECRET_BYTES: usize = 20;"
require_text src/totp.rs "secret_bytes.len() < MIN_TOTP_SECRET_BYTES"
require_text src/totp.rs "rejects_empty_secret_values"
require_text src/totp.rs "rejects_too_short_decoded_secret_values"

require_text src/session.rs "create_session_temp_file"
require_text src/session.rs "options.write(true).create_new(true);"
require_text src/session.rs "file_session_store_records_use_restrictive_permissions"
require_text src/session.rs "session_temp_file_collision_fails_without_truncating_existing_file"

require_text src/throttle.rs "THROTTLE_TMP_COUNTER"
require_text src/throttle.rs "create_throttle_temp_file"
require_text src/throttle.rs "throttle_temp_names_are_collision_resistant_within_a_process"
require_text src/throttle.rs "throttle_temp_file_collision_fails_without_truncating_existing_file"

require_text src/http_form.rs "Some(value) if is_urlencoded_form_content_type(value)"
require_text src/http_form.rs "parses_urlencoded_compose_forms_with_charset_parameter"
require_text src/http_form.rs "parses_mixed_case_urlencoded_compose_content_type"

echo "V7 boundary hardening gate passed"
