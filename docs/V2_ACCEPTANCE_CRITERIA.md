# Version 2 Acceptance Criteria

## Purpose

This document defines the authoritative Version 2 release gate for OSMAP.

Version 2 should not be declared ready because it has "enough features." It is
ready only when the real deployment shape, the real trust boundary, the real
public-exposure posture, and the real migration path are all proven together.

The repo-owned wrappers:

- `maint/live/osmap-live-validate-v2-readiness.ksh`
- `maint/live/osmap-run-v2-readiness-over-ssh.sh`

are the authoritative operator entrypoints for that gate.

## Version 2 Release Gate

Version 2 is acceptable only when all of the following are true:

- `docs/V2_DEFINITION.md` is the clear source of truth for the Version 2
  product boundary
- `README.md`, `KNOWN_LIMITATIONS.md`, `MIGRATION_PLAN_ROUNDCUBE.md`,
  `PILOT_DEPLOYMENT_PLAN.md`, and the latest relevant `DECISION_LOG.md`
  entries all match that Version 2 boundary
- the existing Version 1 closeout wrapper still passes on
  `mail.blackbagsecurity.com` for the candidate snapshot
- the candidate snapshot preserves the deliberate `_osmap` plus `vmail`
  least-privilege split, dedicated Dovecot socket model, and OpenBSD
  confinement posture
- the repo-defined internet-exposure gate is satisfied before the candidate is
  described as suitable for direct public browser access
- the migration, rollback, and pilot runbooks are concrete enough that a small
  operator team can execute them under pressure

## Required Positive-Path Proof

The Version 2 candidate must have current repo-owned evidence on
`mail.blackbagsecurity.com` or an equivalent reviewed host posture for:

- real mailbox-password-plus-TOTP browser login
- issued browser session cookie and normal authenticated navigation
- helper-backed mailbox listing
- helper-backed message view
- attachment download through the bounded forced-download path
- bounded search across one mailbox and all visible mailboxes
- browser compose/send through the existing submission path
- one-message move and the archive shortcut
- session listing, revocation, and logout
- safe HTML rendering through the narrow sanitizer path

## Required Negative-Path And Abuse-Path Proof

The Version 2 candidate must also have current repo-owned evidence for:

- invalid-login normalization without credential or factor leakage
- login throttle enforcement with operator-visible audit evidence
- send throttle enforcement with operator-visible audit evidence
- move throttle enforcement with operator-visible audit evidence
- helper peer rejection when the caller UID does not match the trusted web
  runtime boundary
- CSRF rejection on state-changing routes
- same-origin enforcement on authenticated POST routes
- bounded failure handling when backend helpers or dependencies are unavailable
- no requirement for request-path privilege escalation

## Internet Exposure Gate

Before Version 2 is described as suitable for direct public browser access, all
of the following must be true:

- the criteria in `INTERNET_EXPOSURE_CHECKLIST.md` are satisfied
- TLS-only browser access through the hardened edge is configured and validated
- operators have usable auth, session, send, and error visibility for suspected
  hostile activity
- incident handling and rollback from the public browser path are rehearsed
- the project can still recommend a narrower fallback posture if operators have
  not met those prerequisites

## Migration And Pilot Gate

Before Version 2 is considered complete, the repo must also show:

- a workflow inventory for the intended pilot users
- explicit disposition of current Roundcube-dependent habits and features
- a rollback path that restores the previous browser access path without
  widening OSMAP authority
- a pilot plan with entry, abort, rollback, and exit criteria
- documentation that makes the remaining unsupported workflows obvious up front

## Required Operator Truthfulness

Version 2 documentation must continue to tell the truth about:

- what OSMAP does not do
- what public exposure depends on
- what trust remains with the operator and the host mail stack
- what workflows still require Roundcube fallback or are intentionally deferred

## Version 2 Is Not Complete If

- public exposure is described as safe by default without the exposure gate
- the runtime boundary is weakened for convenience
- migration depends on undocumented operator knowledge
- pilot users need unstated Roundcube fallback for normal daily use
- major new features are added without a migration-capable justification
