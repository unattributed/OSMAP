#!/bin/sh
set -eu
python3 maint/security/osmap-v12-openpgp-inbound-security-state.py --self-test
python3 maint/security/osmap-v12-openpgp-inbound-security-state.py > /tmp/osmap-v12-openpgp-inbound-security-state-report.json
python3 -m json.tool /tmp/osmap-v12-openpgp-inbound-security-state-report.json >/dev/null
printf '%s\n' 'V12 OpenPGP inbound security-state model gate passed'
