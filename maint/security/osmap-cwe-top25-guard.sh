#!/bin/sh

set -eu

repo_root=${OSMAP_CWE_SCAN_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)}

python3 "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/osmap-cwe-top25-guard.py" \
	--repo-root "$repo_root"
