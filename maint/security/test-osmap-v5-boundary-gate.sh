#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
gate="$repo_root/maint/security/osmap-v5-boundary-gate.sh"

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-v5-boundary.XXXXXX")
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT

sh -n "$gate"
sh "$gate" > "$tmp_dir/positive.out"
grep -Fq "V5 boundary gate passed" "$tmp_dir/positive.out"

cp "$repo_root/docs/V5_PRODUCTION_DEPLOYMENT_COMPLETE.md" "$tmp_dir/missing-421.md"
sed '/invalid Host: attacker.invalid -> 421/d' \
	"$tmp_dir/missing-421.md" > "$tmp_dir/missing-421.new"
mv "$tmp_dir/missing-421.new" "$tmp_dir/missing-421.md"

if OSMAP_V5_PRODUCTION_EVIDENCE="$tmp_dir/missing-421.md" \
	sh "$gate" > "$tmp_dir/missing-421.out" 2>&1; then
	echo "expected V5 boundary gate to fail without invalid Host proof" >&2
	exit 1
fi
grep -Fq "invalid Host: attacker.invalid -> 421" "$tmp_dir/missing-421.out"

cp "$repo_root/docs/V5_BOUNDARY_HARDENING_EVIDENCE.md" "$tmp_dir/missing-status.md"
sed '/configured host and origin enforcement/d' \
	"$tmp_dir/missing-status.md" > "$tmp_dir/missing-status.new"
mv "$tmp_dir/missing-status.new" "$tmp_dir/missing-status.md"

if OSMAP_V5_BOUNDARY_EVIDENCE="$tmp_dir/missing-status.md" \
	sh "$gate" > "$tmp_dir/missing-status.out" 2>&1; then
	echo "expected V5 boundary gate to fail without finding status" >&2
	exit 1
fi
grep -Fq "configured host and origin enforcement" "$tmp_dir/missing-status.out"

echo "V5 boundary gate regression checks passed"
