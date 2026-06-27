#!/bin/sh
set -eu
python3 maint/security/osmap-v12-openpgp-rust-helper-client.py --self-test
if [ "${OSMAP_V12_RUST_HELPER_CLIENT_SKIP_GATE_CARGO_CHECK:-0}" != "1" ]; then
  cargo test --lib openpgp_helper_client::tests
fi
python3 maint/security/osmap-v12-openpgp-rust-helper-client.py > /tmp/osmap-v12-openpgp-rust-helper-client-report.json
python3 -m json.tool /tmp/osmap-v12-openpgp-rust-helper-client-report.json >/dev/null
printf '%s\n' 'V12 OpenPGP Rust helper client boundary gate passed'
