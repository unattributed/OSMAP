# TOTP Lifecycle Sprint

## Approved scope and current state

The operator approved this bounded continuation on 2026-09-14 after delivery of
initial provisioning (Slice 00, PR #56) and revocation (Slice 01, PR #60).

| Slice | Scope | State |
| --- | --- | --- |
| 02 | Governed planned TOTP rotation | Signed delivery `77dc836`; continuation approved by operator |
| 03 | Governed lost-authenticator recovery | Signed `cdb8c29`; synchronized with Slice 02 through PR #61 |
| 04 | Integration validation on obsd1, operator documentation, closeout | Closed by operator direction on 2026-09-15, with deferred recovery validation and unverified cleanup |

The operator accepted the delivered work and explicitly directed "close and
sync" after being informed of the remaining private-terminal recovery and
cleanup work. Slice 04 and this sprint are administratively closed with the
residuals below; this is not a claim that every original acceptance test passed.
This sprint does not include domain/mailbox/alias administration,
browser administration, or PostfixAdmin replacement.

Slice 02 and Slice 03 are now synchronized to main, with both original
Shopkeeper signatures preserved. The operator authorized continuation. Slice 04
has passed 19 rotation and 17 recovery tests in isolated native OpenBSD
execution. The operator subsequently completed initial enrollment and planned
rotation; read-only digest reconciliation confirmed the replacement and its
preserved predecessor. The later signed checkpoint `87a10da`, synchronized
through PR #63, passed 19 rotation and 30 recovery/rehearsal tests locally and
in native synthetic execution. Its browser-maintenance guard was exercised
and the service restored. The opt-in test-custody policy in `TOTP_OPERATOR_RECOVERY_SOP.md` does
not qualify real-user recovery or relax its identity requirements. See
`TOTP_LIFECYCLE_OBSD1_EVIDENCE.md`. No slices remain open in this sprint.

### Deferred work and retained operational state

- Controlled recovery with a human-operated replacement authenticator was not
  performed. No successful recovery approval/enrollment/mutation is claimed.
- Cleanup of the live validation account's factor state is unverified. The
  last reconciled state has the planned-rotation replacement active and its
  predecessor archived. Administrative closure does not remove those factors,
  revoke sessions, disable the account, or establish current containment.
- These residuals remain operator-owned follow-up work. Reopen validation or
  authorize a separate bounded recovery/cleanup task before claiming full
  lifecycle acceptance. Use fresh state checks, the reviewed SOPs, and private
  authenticator entry; do not reuse historical maintenance attestations.
- No real-user recovery, strict-release, new browser WSTG, or Vultr
  qualification follows from this closeout. Runtime security gates remain
  unchanged. Temporary synthetic test stores and native source copies were
  cleaned separately; that is not live-account cleanup.

All retained sprint artifacts use
`/home/foo/Downloads/osmap-totp-lifecycle/` (owner-only). Temporary synthetic
fixtures and enrollment material use purpose-specific temporary directories;
enrollment material must never enter the artifact root.

## Slice 02 local qualification, 2026-09-14

The candidate is based on `beab168d2b0e04c7885e514a58eaedd090255862`.
The 19 focused regression tests passed, including execution of the real remote
shell bodies through synthetic local adapters. Bash syntax, ShellCheck, both
legacy operator self-tests, documentation governance, and `git diff --check`
passed. The full developer `make security-check` passed; its existing optional
V15 nginx runtime check was skipped because nginx is unavailable locally.
The full pre-commit hook subsequently passed all 19 focused tests and signed
commit `77dc836b7b8da27ca5c98bf5d7bd25315411227c` was verified against the
Shopkeeper identity. The operator authorized continuation to Slice 03.

Retained logs are `slice02-security-check.log` and
`slice02-rotation-tests.log` under the sprint root. These are local source
qualification records, not a commit-pinned production release report.
The unrelated local host environment edit is excluded from the delivery.
Interactive QR enrollment additionally
requires the missing workstation `qrencode` dependency; no production rotation
or real-authenticator rehearsal has been performed.

## Slice 03 recovery boundary

The recovery candidate builds on signed Slice 02. It requires a detached
Shopkeeper-signed approval, bound to the exact account, SSH target, expected
hostname, and active-factor digest, with a maximum 15-minute lifetime. Approval
attests independently established identity, externally revoked sessions, and
contained account access. These are operator controls, not runtime actions or
independently verified facts. The tool does not sign approvals. It verifies the
same approval before enrollment and again immediately before mutation.

The candidate shares the preservation/no-overwrite replacement engine with
rotation and inherits its serialized-operation, non-atomic, no-auto-retry,
no-auto-restore, and replay-preservation limits. There is no browser recovery,
missing-factor recovery, session mutation, or PostfixAdmin retirement. See
`TOTP_OPERATOR_RECOVERY_SOP.md`. Native and production qualification remain
pending on the selected obsd1 host; local signatures use disposable synthetic
test identities only.

The 17 focused recovery tests and all 19 rotation regressions passed, including
real detached-signature verification with disposable test keys. ShellCheck,
documentation governance, `git diff --check`, and the full developer
`make security-check` passed. The existing optional nginx runtime check was
skipped because nginx is unavailable locally. The exact signed delivery and
review checkout are recorded in
`/home/foo/Downloads/osmap-totp-lifecycle/slice03-handoff.md`; retained gate
output is `slice03-security-check.log` in that same sprint root. This is local
source qualification, not a fresh strict-release or live-recovery claim.

## Host identity after migration

The operator reports that `mail.blackbagsecurity.com` now names the Vultr mail
instance. On this workstation it resolves to the private VPN address
`10.44.0.1`; the SSH test on 2026-09-14 timed out. The former on-premises host is
`obsd1.blackbagsecurity.com`, reachable on the LAN at `192.168.1.44`, also mapped
locally as `mail-source-grace`. Its running and persistent hostname were changed
to `obsd1.blackbagsecurity.com` on 2026-09-14.

The operator subsequently clarified that the TOTP lifecycle sprint must use
**obsd1 at `192.168.1.44`**, not Vultr. A fresh SSH check confirmed OpenBSD,
hostname `obsd1.blackbagsecurity.com`, and operator access on that IP. This is
the controlling target selection for Slices 03–04. Vultr connectivity is not a
blocker or validation dependency for this sprint, and no further Vultr checks
are required. The operator subsequently granted full authority to operate on
obsd1 for this work. That covers in-scope host preparation and controlled
validation; it does not attest a real claimant's identity or satisfy recovery's
session and containment controls. Use controlled validation accounts, preserve
unrelated host state, and do not treat host authority as a signed approval for
recovery of an unspecified existing user.

Historical evidence using the old mail hostname and LAN address remains
historical evidence. It does not qualify the Vultr deployment. New lifecycle
operations require explicit `--host` and `--expected-hostname` arguments and
strict known-host verification. A remote hostname match is a routing safeguard,
not a substitute for the trusted SSH host key.

## Slice acceptance and evidence

Each implementation slice requires focused failure-path tests, Bash syntax and
ShellCheck, legacy operator-tool regressions, documentation governance,
`git diff --check`, the full `make security-check`, a Shopkeeper-signed commit,
signature verification, and operator review before synchronization.

Slice 04 must distinguish local source qualification, synthetic OpenBSD
execution, obsd1 read-only qualification, and separately authorized controlled
mutation evidence. It cannot report host recovery acceptance while a controlled
validation account or required external recovery controls are unavailable.
No existing factor may
be changed to obtain test evidence without a separate operator decision.

The strict release gate remains `OSMAP_SECURITY_PROFILE=release make release-check`.
Local lifecycle tests cannot refresh or replace credentialed WSTG, TLS,
supply-chain, resource, MIME/HTML, pilot, or archive evidence. This sprint does
not claim qualification of the migrated Vultr instance.

## WSTG impact and validation boundary

| Area | Slice 02 coverage | Remaining evidence |
| --- | --- | --- |
| Authentication and MFA lifecycle | Existing factor/mailbox required; enrollment and operator authorization precede revocation | Controlled real-authenticator rotation on the intended host |
| Authorization | SSH operator authority and exact account/host confirmation; no web route introduced | Operator review of privilege and identity procedures |
| Session management | Existing browser sessions and replay counters are preserved | Recovery-specific session disposition in Slice 03; no session-revocation claim |
| Error handling | Stale factor, missing mailbox, failed enrollment, denied authorization, ambiguous revocation/install, final mismatch fail closed | Host transport/failure rehearsal and manual reconciliation |
| Secret handling | No seed/code/URI in subprocess arguments; enrollment via private TTY, temporary files cleaned | Operator must use an unrecorded local terminal |

Slice 03 extends local authentication/authorization coverage with signer pinning,
approval lifetime and schema checks, exact identity/host/state binding, and
revalidation after operator interaction. It requires signed session and access-
containment attestations without claiming to enforce those external controls.
Regression tests cover invalid signatures, alternate signers, expired or
substituted approvals, denied authorization, stale factors, and partial failure.

These are operator-tool regression checks, not new passing browser WSTG
scenarios. Existing committed WSTG matrix outcomes are unchanged.

The Slice 04 rehearsal adds negative coverage for production/rehearsal schema
separation, exact reserved target, fresh signed controls, loss of maintenance
containment, bounded session parsing, and distinct partial/success labels.
The read-only session guard checks usable sessions; it does not perform session
revocation. Human enrollment and restored-service acceptance remain separate.
