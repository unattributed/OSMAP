#!/bin/sh
set -eu
python3 maint/security/osmap-v12-openpgp-outbound-preflight-policy.py --self-test
python3 maint/security/osmap-v12-openpgp-outbound-preflight-policy.py > /tmp/osmap-v12-openpgp-outbound-preflight-policy-report.json
python3 -m json.tool /tmp/osmap-v12-openpgp-outbound-preflight-policy-report.json >/dev/null
printf '%s\n' 'V12 OpenPGP outbound preflight policy model gate passed'
