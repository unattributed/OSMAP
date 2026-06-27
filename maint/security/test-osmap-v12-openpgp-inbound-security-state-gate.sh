#!/bin/sh
set -eu
sh maint/security/osmap-v12-openpgp-inbound-security-state-gate.sh >/tmp/osmap-v12-inbound-security-state-gate-test.log 2>&1
grep -F 'V12 OpenPGP inbound security-state model gate passed' /tmp/osmap-v12-inbound-security-state-gate-test.log >/dev/null
printf '%s\n' 'V12 OpenPGP inbound security-state model gate regression test passed'
