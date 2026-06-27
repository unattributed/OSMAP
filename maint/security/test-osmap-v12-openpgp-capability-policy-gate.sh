#!/bin/sh
set -eu
sh maint/security/osmap-v12-openpgp-capability-policy-gate.sh >/tmp/osmap-v12-capability-policy-gate-test.log 2>&1
grep -F 'V12 OpenPGP capability policy model gate passed' /tmp/osmap-v12-capability-policy-gate-test.log >/dev/null
printf '%s\n' 'V12 OpenPGP capability policy model gate regression test passed'
