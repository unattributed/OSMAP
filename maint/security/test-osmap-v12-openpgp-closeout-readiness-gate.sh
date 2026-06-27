#!/bin/sh
set -eu
sh maint/security/osmap-v12-openpgp-closeout-readiness-gate.sh >/tmp/osmap-v12-closeout-readiness-gate-test.log 2>&1
grep -F 'V12 OpenPGP closeout readiness audit gate passed' /tmp/osmap-v12-closeout-readiness-gate-test.log >/dev/null
printf '%s\n' 'V12 OpenPGP closeout readiness audit gate regression test passed'
