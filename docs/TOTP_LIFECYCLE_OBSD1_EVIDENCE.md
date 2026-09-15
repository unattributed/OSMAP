# TOTP lifecycle obsd1 integration evidence

## Status and scope

Slice 04 is in progress, not closed. The operator authorized host operations on
obsd1 at `192.168.1.44`, expected hostname `obsd1.blackbagsecurity.com`.
Native synthetic tests passed on OpenBSD 7.9 on 2026-09-15 UTC (2026-09-14 in
the operator's America/Toronto timezone). That checkpoint changed no live
factor. Subsequent operator enrollment/rotation is recorded below; controlled
recovery and strict-release qualification are not claimed.
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
| Live read-only inspection | Initial absent-factor baseline; later exact active/archive digest reconciliation after operator enrollment and rotation | Human QR/code handling or successful controlled recovery |
| Real authenticator and controlled mutation | Operator-reported initial provisioning and planned rotation passed; recovery pending | No real-user recovery or strict-release pass may be inferred |

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

At the initial checkpoint, the controlled validation mailbox was available
through Dovecot but its active factor was absent. The revocation dry-run returned its documented
no-active-factor disposition; rotation refused before enrollment or mutation.
The factor directories are owned by `_osmap:_osmap` with mode `0700`, and the
checked ancestry has no group/world-writable directories. Passwordless SSH and
noninteractive doas are available. These facts do not establish a valid recovery
approval, a clean session state, or an access-containment procedure.

The missing workstation `qrencode` prerequisite was installed from the existing
configured package repository (version 4.1.1). No other package was upgraded or
removed. No enrollment seed, QR code, URI, or authenticator code was captured.

## Subsequent controlled-account progress

At checkpoint `691b9606694080e67e3aa060b449dd510254f230`, the operator reported
successful initial enrollment/provisioning and then planned rotation for the
reserved validation account. Rotation stamp: `20260915T021217Z`. Independent
read-only reconciliation matched the active replacement digest
`5a5060e372462599dccfcdc9e3fa08a836a5edb277e5ae5a0d74298195084b20` and preserved
predecessor digest
`515631e1b035bcba9c941d4b3c05430ef02768b0d7b5a8b6f6bc865bfcd08c19`.
Both were regular non-symlink `_osmap:_osmap` files with mode `0600`. Factor
bodies, QR codes, and authenticator codes were not exported. Do not repeat
provisioning or planned rotation to stand in for recovery.

The operator approved a truthful controlled test-custody rehearsal and a brief
obsd1 browser-maintenance window. The separate rehearsal policy is described in
`TOTP_OPERATOR_RECOVERY_SOP.md`; it is not a real-person identity attestation.
Before maintenance, a non-locking inventory found 16 test-account records,
14 marked revoked and none apparently usable by recorded time limits. This
historical inventory does not establish containment. The new read-only guard
must pass under maintenance before any rehearsal approval is signed.

The approved stop/check/start rehearsal subsequently passed on obsd1. Under
the existing session-store lock, the guard found 16 reserved-account records:
14 already revoked and 2 expired but unrevoked, with zero usable sessions.
The browser service was restored and `/healthz` returned HTTP 200 with the
explicit obsd1 Host header. An IP Host header correctly returned HTTP 421;
it was not used as a positive health result. No factor or session mutation
occurred during this maintenance check. SMTP/IMAP services were not stopped.
This validates the containment procedure, not completed factor recovery.

The candidate's 19 rotation and 30 recovery/rehearsal tests passed locally and
in native synthetic execution. Four native-runner boundary tests, both legacy
workstation self-tests, ShellCheck, and the developer gate also passed. The
developer gate's optional nginx runtime check remains skipped where nginx is
unavailable; no strict release or new authenticated browser WSTG pass is claimed.
Retained source hashes identify the candidate separately from the earlier
signed checkpoint. Real-user identity checks remain outside this rehearsal.

## Remaining acceptance and human interaction

Use an unrecorded local terminal and a controlled authenticator. Do not paste
seeds, QR images, codes, passwords, session data, or private case evidence into
chat or retained logs. The agent's captured tool terminal is not that surface.

1. Preserve completed provisioning and planned-rotation evidence above.
2. Establish the reviewed rehearsal's test-custody, no-usable-session, stopped
   browser-service, and serialized-administration controls. Real-user recovery
   still requires independent identity and session-revocation attestations;
   rehearsal evidence must not substitute for them.
3. Use a short-lived signed rehearsal approval, verify replacement enrollment,
   perform the controlled recovery, and reconcile the result read-only. Do not
   automatically retry or restore a factor after an ambiguous result.
4. Restore or remove temporary validation credentials and test state through a
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

Later retained records include `slice04-post-provision-readonly.log`,
`slice04-post-rotation-readonly.log`, `slice04-rotation-reconciliation.log`,
and `slice04-recovery-preparation.md`. The handoff distinguishes operator
reports, independent read-only observations, and pending acceptance.
The rehearsal adds `slice04-rehearsal-source-sha256.txt`,
`slice04-rehearsal-native-final.log`, and
`slice04-rehearsal-maintenance-check.log`. The maintenance check preceded a
stricter literal-config parser; that parser was subsequently verified against
the live configuration read-only. No second outage was required for that check.
