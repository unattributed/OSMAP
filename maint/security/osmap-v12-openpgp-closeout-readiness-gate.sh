#!/bin/sh
set -eu
python3 maint/security/osmap-v12-openpgp-closeout-readiness.py --self-test
python3 maint/security/osmap-v12-openpgp-closeout-readiness.py > /tmp/osmap-v12-openpgp-closeout-readiness-report.json
python3 -m json.tool /tmp/osmap-v12-openpgp-closeout-readiness-report.json >/dev/null
printf '%s\n' 'V12 OpenPGP closeout readiness audit gate passed'
