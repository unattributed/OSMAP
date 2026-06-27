#!/bin/sh
set -eu
python3 maint/security/osmap-v12-openpgp-helper-client-integration.py --self-test
python3 maint/security/osmap-v12-openpgp-helper-client-integration.py > /tmp/osmap-v12-openpgp-helper-client-integration-report.json
python3 -m json.tool /tmp/osmap-v12-openpgp-helper-client-integration-report.json >/dev/null
printf '%s\n' 'V12 OpenPGP helper client integration gate passed'
