# TOTP Lifecycle Sprint

## Approved scope and current state

The operator approved this bounded continuation on 2026-09-14 after delivery of
initial provisioning (Slice 00, PR #56) and revocation (Slice 01, PR #60).

| Slice | Scope | State |
| --- | --- | --- |
| 02 | Governed planned TOTP rotation | Implemented; local checks passed; signing and review pending |
| 03 | Governed lost-authenticator recovery | Planned; stronger identity and authorization evidence required |
| 04 | Integration validation, operator documentation, closeout | Planned; production qualification remains separate |

Three slices remain open until their gates and signed delivery records are
complete. This sprint does not include domain/mailbox/alias administration,
browser administration, or PostfixAdmin replacement.

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
The additional focused test cases were rerun after the full gate; the required
pre-commit hook will run the full gate again before signing.

Retained logs are `slice02-security-check.log` and
`slice02-rotation-tests.log` under the sprint root. These are local source
qualification records, not a commit-pinned production release report.
The unrelated local host environment edit is excluded from the delivery.
Signing and review are still required. Interactive QR enrollment additionally
requires the missing workstation `qrencode` dependency; no production rotation
or real-authenticator rehearsal has been performed.

## Host identity after migration

The operator reports that `mail.blackbagsecurity.com` now names the Vultr mail
instance. On this workstation it resolves to the private VPN address
`10.44.0.1`; the SSH test on 2026-09-14 timed out. The former on-premises host is
`obsd1.blackbagsecurity.com`, reachable on the LAN at `192.168.1.44`, also mapped
locally as `mail-source-grace`. Its running and persistent hostname were changed
to `obsd1.blackbagsecurity.com` on 2026-09-14.

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
execution, production read-only qualification, and separately authorized live
mutation evidence. It cannot report production acceptance while SSH or a
controlled validation account is unavailable. No current production factor may
be changed to obtain test evidence without a separate operator decision.

The strict release gate remains `OSMAP_SECURITY_PROFILE=release make release-check`.
Local lifecycle tests cannot refresh or replace credentialed WSTG, TLS,
supply-chain, resource, MIME/HTML, pilot, or archive evidence for the new host.

## WSTG impact and validation boundary

| Area | Slice 02 coverage | Remaining evidence |
| --- | --- | --- |
| Authentication and MFA lifecycle | Existing factor/mailbox required; enrollment and operator authorization precede revocation | Controlled real-authenticator rotation on the intended host |
| Authorization | SSH operator authority and exact account/host confirmation; no web route introduced | Operator review of privilege and identity procedures |
| Session management | Existing browser sessions and replay counters are preserved | Recovery-specific session disposition in Slice 03; no session-revocation claim |
| Error handling | Stale factor, missing mailbox, failed enrollment, denied authorization, ambiguous revocation/install, final mismatch fail closed | Host transport/failure rehearsal and manual reconciliation |
| Secret handling | No seed/code/URI in subprocess arguments; enrollment via private TTY, temporary files cleaned | Operator must use an unrecorded local terminal |

These are operator-tool regression checks, not new passing browser WSTG
scenarios. Existing committed WSTG matrix outcomes are unchanged.
