#!/bin/sh
set -eu
python3 maint/security/osmap-v12-openpgp-capability-policy.py --self-test
python3 maint/security/osmap-v12-openpgp-capability-policy.py > /tmp/osmap-v12-openpgp-capability-policy-report.json
python3 -m json.tool /tmp/osmap-v12-openpgp-capability-policy-report.json >/dev/null
printf '%s\n' 'V12 OpenPGP capability policy model gate passed'
