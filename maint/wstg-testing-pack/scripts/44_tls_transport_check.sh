#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
load_env
require_cmds bash
setup_run_dir "44-tls-transport-check"

if command -v testssl.sh >/dev/null 2>&1 || command -v testssl >/dev/null 2>&1 || command -v git >/dev/null 2>&1; then
  tssl="$(clone_testssl_if_needed "$RUN_DIR")"
  "$tssl" --color 0 --warnings off --openssl-timeout 10 "${HOSTNAME}:443" > testssl.txt 2>&1 || true
  sed -n '1,220p' testssl.txt
else
  echo "testssl.sh and git are unavailable, skipping automated TLS transport check"
fi

printf '\nSaved in %s\n' "$RUN_DIR"
