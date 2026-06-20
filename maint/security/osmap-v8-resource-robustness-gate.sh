#!/bin/sh

set -eu

repo_root=${OSMAP_V8_GATE_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}
cd "$repo_root"

require_file() {
	path=$1
	if [ ! -s "$path" ]; then
		echo "error: missing V8 resource robustness file: $path" >&2
		exit 1
	fi
}

require_text() {
	path=$1
	text=$2
	if ! grep -Fq "$text" "$path"; then
		echo "error: missing V8 resource robustness requirement in $path: $text" >&2
		exit 1
	fi
}

for path in \
	docs/V8_RESOURCE_ROBUSTNESS_MATRIX.md \
	tests/v8_resource_robustness_matrix.rs \
	tests/fixtures/resource_robustness/MANIFEST.md \
	tests/fixtures/resource_robustness/limits.env \
	tests/fixtures/resource_robustness/sort_matrix.tsv \
	tests/fixtures/resource_robustness/rejection_matrix.tsv
	do
	require_file "$path"
done

require_text docs/V8_RESOURCE_ROBUSTNESS_MATRIX.md "attachment download output bound enforcement"
require_text docs/V8_RESOURCE_ROBUSTNESS_MATRIX.md "audit-event session redaction"
require_text docs/V8_RESOURCE_ROBUSTNESS_MATRIX.md "deterministic sorting over larger synthetic message lists"
require_text tests/v8_resource_robustness_matrix.rs "download_max_bytes: 3"
require_text tests/v8_resource_robustness_matrix.rs "SESSION_TOKEN_HEX_LEN * 2"
require_text tests/v8_resource_robustness_matrix.rs "synthetic_summaries(256)"
require_text maint/security/osmap-v8-resource-robustness-gate.sh "cargo test --test v8_resource_robustness_matrix"
require_text Makefile "osmap-v8-resource-robustness-gate.sh"

echo "==> cargo test --test v8_resource_robustness_matrix"
cargo test --test v8_resource_robustness_matrix

echo "V8 resource robustness regression gate passed"
