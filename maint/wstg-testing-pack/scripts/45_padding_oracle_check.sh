#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds bash
setup_run_dir "45-padding-oracle-check"

tssl="$(clone_testssl_if_needed "$RUN_DIR")"
"$tssl" --color 0 --warnings off --openssl-timeout 10 --lucky13 --poodle "${HOSTNAME}:443" > testssl-padding.txt 2>&1 || true
printf '===== testssl padding-oracle checks =====\n'
sed -n '1,260p' testssl-padding.txt
printf '\nSaved in %s\n' "$RUN_DIR"
