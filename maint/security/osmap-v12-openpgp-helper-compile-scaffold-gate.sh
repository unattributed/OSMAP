#!/bin/sh
set -eu

python3 maint/security/osmap-v12-openpgp-helper-compile-scaffold.py --self-test >/dev/null
python3 maint/security/osmap-v12-openpgp-helper-compile-scaffold.py \
  --config maint/security/v12-openpgp-helper-compile-scaffold.example.json \
  --report /tmp/osmap-v12-openpgp-helper-compile-scaffold-report.json >/dev/null

echo "V12 OpenPGP helper compile scaffold self-test passed"
echo "V12 OpenPGP helper compile scaffold gate passed"
