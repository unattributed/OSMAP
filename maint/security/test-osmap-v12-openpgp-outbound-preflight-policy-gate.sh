#!/bin/sh
set -eu
sh maint/security/osmap-v12-openpgp-outbound-preflight-policy-gate.sh >/tmp/osmap-v12-outbound-preflight-policy-gate-test.log 2>&1
grep -F 'V12 OpenPGP outbound preflight policy model gate passed' /tmp/osmap-v12-outbound-preflight-policy-gate-test.log >/dev/null
printf '%s\n' 'V12 OpenPGP outbound preflight policy model gate regression test passed'
