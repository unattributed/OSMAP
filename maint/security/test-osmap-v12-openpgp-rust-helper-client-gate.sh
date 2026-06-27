#!/bin/sh
set -eu
export OSMAP_V12_RUST_HELPER_CLIENT_SKIP_GATE_CARGO_CHECK="${OSMAP_V12_RUST_HELPER_CLIENT_SKIP_GATE_CARGO_CHECK:-0}"
sh maint/security/osmap-v12-openpgp-rust-helper-client-gate.sh >/tmp/osmap-v12-rust-helper-client-gate-test.log 2>&1
grep -F 'V12 OpenPGP Rust helper client boundary gate passed' /tmp/osmap-v12-rust-helper-client-gate-test.log >/dev/null
printf '%s\n' 'V12 OpenPGP Rust helper client boundary gate regression test passed'
