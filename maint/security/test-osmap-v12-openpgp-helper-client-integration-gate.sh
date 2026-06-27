#!/bin/sh
set -eu
sh maint/security/osmap-v12-openpgp-helper-client-integration-gate.sh >/tmp/osmap-v12-helper-client-integration-gate-test.log 2>&1
grep -F 'V12 OpenPGP helper client integration gate passed' /tmp/osmap-v12-helper-client-integration-gate-test.log >/dev/null
printf '%s\n' 'V12 OpenPGP helper client integration gate regression test passed'
