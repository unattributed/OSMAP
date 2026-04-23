#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
pack_dir="$repo_root/maint/wstg-testing-pack"

if ! command -v bash >/dev/null 2>&1; then
	echo "note: bash is unavailable; skipping WSTG testing pack validation"
	exit 0
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/osmap-wstg-pack-test.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

echo "validating WSTG testing pack bash syntax"
for script in "$pack_dir"/lib/*.sh "$pack_dir"/scripts/*.sh; do
	bash -n "$script"
done

echo "validating WSTG testing pack manifest"
find "$pack_dir/scripts" -maxdepth 1 -type f -name '*.sh' -exec basename {} \; | sort > "$tmp_dir/scripts.txt"
awk -F, 'NR > 1 { print $1 }' "$pack_dir/MANIFEST.csv" | sort > "$tmp_dir/manifest.txt"
diff -u "$tmp_dir/scripts.txt" "$tmp_dir/manifest.txt"

echo "validating WSTG testing pack sample environment"
mkdir -p "$tmp_dir/home" "$tmp_dir/run"
cp "$pack_dir/.env.example" "$tmp_dir/run/.env"
HOME="$tmp_dir/home" bash -s -- "$pack_dir" "$tmp_dir/run" <<'BASH'
set -euo pipefail

pack_dir="$1"
run_dir="$2"

cd "$run_dir"
source "$pack_dir/lib/common.sh"
load_env

[[ "$HOSTNAME" == "mail.example.com" ]]
[[ "$TARGET_HOSTNAME" == "mail.example.com" ]]
[[ "$EMAIL" == "user@example.com" ]]
[[ "$TARGET_EMAIL" == "user@example.com" ]]
[[ "$TARGET_BASE_URL" == "https://mail.example.com" ]]
[[ "$TARGET_PORT" == "443" ]]
[[ "$TARGET_TLS" == "1" ]]
[[ "$HTTP_ALT_PORTS" == "80 8080" ]]
[[ "$WEBSOCKET_PATHS" == *"/socket.io/"* ]]
[[ "$CORS_TEST_ORIGINS" == "https://attacker.invalid null" ]]
BASH

echo "WSTG testing pack validation passed"
