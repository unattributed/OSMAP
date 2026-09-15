# TOTP lifecycle obsd1 integration evidence

## Status and scope

Slice 04 is in progress, not closed. The operator authorized host operations on
obsd1 at `192.168.1.44`, expected hostname `obsd1.blackbagsecurity.com`.
Native synthetic tests passed on OpenBSD 7.9 on 2026-09-15 UTC (2026-09-14 in
the operator's America/Toronto timezone). No live factor was changed and no
real-authenticator acceptance or strict-release qualification is claimed.
Vultr was not contacted for this integration work.

The unchanged lifecycle implementation assessed is signed commit
`cdb8c29cff9b33a1749f406251a4e893e9e89631`, following signed rotation commit
`77dc836b7b8da27ca5c98bf5d7bd25315411227c`. Both were synchronized to main via
PR #61 without rewriting either signed commit. A fresh fetch proved local and
remote main SHA equality. The clean obsd1 `~/OSMAP` checkout was fast-forwarded
to that same candidate; no binary installation or service restart was performed.

## Evidence classes

| Class | Observation | What it does not establish |
| --- | --- | --- |
| Workstation regression | 19 rotation and 17 recovery tests passed; both legacy self-tests passed | Native live-host mutation or a human's authenticator |
| Native synthetic execution | All 19 rotation and 17 recovery tests passed on OpenBSD 7.9 | Real SSH, doas privileges, Dovecot identity, session containment, or QR acceptance |
| Live read-only inspection | Host identity, clean source checkout, factor-store ancestry, and archive directory checked; controlled mailbox exists but has no active factor | Successful rotation or recovery, both of which require an active factor |
| Real authenticator and controlled mutation | Pending | No pass may be inferred from the three evidence classes above |

## Native harness

Run on an OpenBSD copy of the reviewed source:

```sh
python3 maint/security/osmap-totp-native-check.py
```

The runner rejects other operating systems and missing dependencies. Its
temporary `sha256sum` shim supplies the Linux coordinator's one-file checksum
interface only. The remote shell programs use native OpenBSD `stat`, `sha256`,
file modes, links, and filesystem operations. SSH and doas remain synthetic
adapters, the Dovecot mailbox result is synthetic, and enrollment/authorization
are mocked. Test factors live only in disposable private test directories, not
the live factor store. Real signature tests use disposable synthetic GPG keys,
never Shopkeeper recovery approvals. Cleanup occurs after success and failure.

The initial native attempt tried the legacy workstation self-test, which uses
GNU `stat -c` and correctly failed on OpenBSD. Those unchanged legacy tests
were instead run on the Linux workstation. The native runner qualifies the
two Python suites; it does not claim a full OpenBSD port of operator tooling.
No production check or legacy self-test was weakened or bypassed.

## Live read-only findings

The existing controlled validation mailbox is available through Dovecot. Its
active factor is absent. The revocation dry-run returned its documented
no-active-factor disposition; rotation refused before enrollment or mutation.
The factor directories are owned by `_osmap:_osmap` with mode `0700`, and the
checked ancestry has no group/world-writable directories. Passwordless SSH and
noninteractive doas are available. These facts do not establish a valid recovery
approval, a clean session state, or an access-containment procedure.

The missing workstation `qrencode` prerequisite was installed from the existing
configured package repository (version 4.1.1). No other package was upgraded or
removed. No enrollment seed, QR code, URI, or authenticator code was captured.

## Remaining acceptance and human interaction

Use an unrecorded local terminal and a controlled authenticator. Do not paste
seeds, QR images, codes, passwords, session data, or private case evidence into
chat or retained logs. The agent's captured tool terminal is not that surface.

1. Establish the controlled account's authorization and test ownership. Because
   its factor is absent, initial provisioning must first use the reviewed
   provisioning SOP and successful authenticator enrollment; neither rotation
   nor recovery should be repurposed as absent-factor provisioning.
2. Rehearse planned rotation with the human-operated authenticator and exact
   operator confirmation. Retain only sanitized outcome and digest evidence.
3. Establish and record recovery's independent identity, session-revocation,
   access-containment, and serialized-administration controls before approving
   recovery. Host authority and automatic commit signing do not attest them.
4. Use a short-lived signed recovery approval, verify replacement enrollment,
   perform the controlled recovery, and reconcile the result read-only. Do not
   automatically retry or restore a factor after an ambiguous result.
5. Restore or remove temporary validation credentials and test state through a
   bounded reviewed cleanup; verify cleanup, then record operator acceptance.

Real enrollment and the recovery attestations require human participation;
Slice 04 and the sprint remain open until the acceptance evidence exists.
Do not claim strict-release or browser WSTG success from these operator tests.

## Retained records

All retained records use `/home/foo/Downloads/osmap-totp-lifecycle/`:
`slice03-sync-verification.log`, `slice03-pr-fast-forward.log`,
`slice04-native-check-attempt01.log`, `slice04-native-check.log`,
`slice04-native-source-sha256.txt`, and `slice04-host-preflight.log`.
The failed first attempt is retained as such, not as passing evidence.
These are scoped integration records, not validated release-report replacements.
