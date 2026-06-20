#!/bin/sh

set -eu

repo_root=${OSMAP_V7_RENDERING_GATE_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

require_file() {
	path=$1
	if [ ! -s "$path" ]; then
		echo "error: missing V7 rendering regression input: $path" >&2
		exit 1
	fi
}

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V7 rendering regression requirement in $path: $text" >&2
		exit 1
	fi
}

run_cargo_test() {
	test_name=$1
	echo "==> cargo test --quiet -- $test_name"
	cargo test --quiet -- "$test_name"
}

if ! command -v cargo >/dev/null 2>&1; then
	echo "error: cargo is required for the V7 rendering regression close-out gate" >&2
	exit 1
fi

if ! command -v rustc >/dev/null 2>&1; then
	echo "error: rustc is required for the V7 rendering regression close-out gate" >&2
	exit 1
fi

for path in \
	Cargo.toml \
	Makefile \
	src/rendering.rs \
	src/rendering_html.rs \
	src/mime.rs \
	src/charset.rs \
	src/http_ui.rs \
	docs/TEST_STRATEGY.md \
	docs/V7_RENDERING_REGRESSION_CLOSEOUT.md \
	tests/fixtures/mime/windows_1252_html_only_forward.eml \
	tests/fixtures/mime/nested_mixed_hostile_html.eml \
	tests/fixtures/mime/malformed_boundary.eml \
	tests/fixtures/mime/html_link_scheme_probe.eml
	do
	require_file "$path"
done

require_text src/rendering.rs "PreferPlainText means render a safe plain-text part when one exists."
require_text src/rendering.rs "fn html_only_singlepart_renders_sanitized_html()"
require_text src/rendering.rs "fn html_only_multipart_without_plain_text_renders_sanitized_html()"
require_text src/rendering.rs "fn prefer_plain_text_renders_plain_when_plain_exists()"
require_text src/rendering.rs "fn prefer_sanitized_html_renders_html_when_html_exists()"
require_text src/rendering.rs "fn prefer_plain_text_falls_back_to_sanitized_html_without_plain()"
require_text src/rendering.rs "fn windows_1252_html_only_forward_renders_decoded_subject_and_body()"
require_text src/rendering.rs "fn hostile_html_sanitization_strips_active_and_remote_content()"
require_text src/rendering.rs "fn malformed_mime_renders_safe_placeholder_or_errors_without_raw_html()"
require_text src/http_ui.rs "fn ui_message_view_surfaces_truthful_rendering_labels()"
require_text src/rendering_html.rs "UrlRelative::Deny"
require_text src/rendering_html.rs '"http", "https", "mailto"'
require_text src/charset.rs '"windows-1252" | "cp1252"'
require_text docs/V7_RENDERING_REGRESSION_CLOSEOUT.md "Feature development remains frozen until this gate passes."
require_text docs/TEST_STRATEGY.md "V7 rendering regression close-out"
require_text Makefile "v7-rendering-regression-check"
require_text maint/security/osmap-security-check.sh "osmap-v7-rendering-regression-gate.sh"

run_cargo_test html_only_singlepart_renders_sanitized_html
run_cargo_test html_only_multipart_without_plain_text_renders_sanitized_html
run_cargo_test prefer_plain_text_renders_plain_when_plain_exists
run_cargo_test prefer_sanitized_html_renders_html_when_html_exists
run_cargo_test prefer_plain_text_falls_back_to_sanitized_html_without_plain
run_cargo_test windows_1252_html_only_forward_renders_decoded_subject_and_body
run_cargo_test hostile_html_sanitization_strips_active_and_remote_content
run_cargo_test malformed_mime_renders_safe_placeholder_or_errors_without_raw_html
run_cargo_test ui_message_view_surfaces_truthful_rendering_labels
run_cargo_test strips_unsafe_link_schemes_and_relative_urls
run_cargo_test strips_obfuscated_and_browser_only_link_schemes
run_cargo_test strips_scriptable_attributes_forms_remote_fetch_surfaces_and_comments
run_cargo_test decodes_windows_1252_and_replaces_undefined_bytes
run_cargo_test decodes_base64_encoded_header_summary_values

cargo test --quiet -- fixture_windows_1252_html_only_forward_renders_sanitized_content
cargo test --quiet -- fixture_hostile_html_strips_active_and_remote_content
cargo test --quiet -- fixture_malformed_boundary_renders_safe_placeholder

echo "V7 rendering regression gate passed"
