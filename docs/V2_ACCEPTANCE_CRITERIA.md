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

For the short operator procedure around routine host-side and off-host
Version 2 rehearsal runs, see `V2_PILOT_REHEARSAL_SOP.md`.

The current authoritative readiness step set is:

- `security-check`
- `login-send`
- `safe-html-attachment-download`
- `login-failure-normalization`
- `all-mailbox-search`
- `archive-shortcut`
- `session-surface`
- `send-throttle`
- `move-throttle`
- `helper-peer-auth`
- `request-guardrails`
- `mailbox-backend-unavailable`

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
- the validated host has a repo-owned rehearsal or apply path for installing
  the `/usr/local/bin/osmap` binary before the split `_osmap` plus `vmail`
  service install is attempted
- the validated host has a repo-owned rehearsal or apply path for creating the
  dedicated shared runtime group and adding `_osmap` to it before the split
  service install is attempted
- the validated host has a repo-owned rehearsal or apply path for installing
  the reviewed env, launcher, and `rc.d` service artifacts before full service
  activation is attempted
- the validated host has a repo-owned rehearsal or apply path for the final
  service-activation step that creates the reviewed runtime directories and
  exercises the `rcctl` startup path before the persistent-service install is
  declared ready
- the validated host has a repo-owned rehearsal or apply path for completing
  the remaining split `_osmap` plus `vmail` service activation instead of
  depending on ad hoc service wiring
- the repo-owned persistent-service validator passes for any host that claims
  the split `_osmap` plus `vmail` install is ready for edge cutover
- the repo-owned Version 2 readiness wrapper restores and revalidates the
  persistent `osmap_mailbox_helper` and `osmap_serve` services after a proof
  run when the reviewed `rc.d` service install is present
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
- session listing, one-session revocation, revoke-other-sessions,
  revoke-all-sessions, idle-timeout revocation, and logout
- safe HTML rendering through the narrow sanitizer path
- inline image metadata surfacing without inline image rendering, plus bounded
  forced-download retrieval for the surfaced attachment part

## Required Negative-Path And Abuse-Path Proof

The Version 2 candidate must also have current repo-owned evidence for:

- invalid-login normalization without credential or factor leakage
- login throttle enforcement with operator-visible audit evidence
- send throttle enforcement with operator-visible audit evidence
- move throttle enforcement with operator-visible audit evidence
- automatic persisted revocation for expired or inactive browser sessions
- rejection of non-existent archive shortcut destinations at settings save time
- rejection of invalid or mismatched message move mailbox/UID tuples without a
  success-style redirect
- deterministic search behavior for the exposed browser search forms, with
  invalid inputs returning 400-class responses and ordinary authenticated
  search avoiding generic 503 failures
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
- repo-owned current host exposure evidence exists for the candidate posture
- the persistent `_osmap` plus `vmail` service install exists on the candidate
  host before the public browser edge is switched away from Roundcube
- the repo-owned binary-deployment path has cleared the
  `/usr/local/bin/osmap` precondition before the service install is applied
- the repo-owned runtime-group provisioning path has cleared the
  shared-runtime-group and `_osmap` membership preconditions before the service
  install is applied
- the repo-owned service-artifact path has cleared the env, launcher, and
  `rc.d` preconditions before the final service-activation step is applied
- the repo-owned service-activation path has cleared the runtime-health,
  helper-socket, and loopback-listener blockers before the service gate is
  treated as passed
- the repo-owned service-enablement validator passes for the candidate host
- the canonical nginx route replacement, PF/listener changes, and rollback
  path are defined concretely in `EDGE_CUTOVER_PLAN.md`
- the repo-owned edge-cutover verifier passes for any host that claims the
  direct-public OSMAP edge posture
- repo-owned off-host browser-path evidence exists for the approved public
  HTTPS root, collected from outside the WireGuard-only management plane
- repo-owned auth-observability evidence confirms browser login failures emit
  structured auth events into a host-readable log instead of disappearing into
  `/dev/null`
- repo-owned public-send audit-correlation evidence confirms the same effective
  client IP appears across auth, session, mailbox, submission, and
  `http_request_completed` events for the main public browser send workflow
- TLS-only browser access through the hardened edge is configured and validated
- operators have usable auth, session, send, and error visibility for suspected
  hostile activity
- incident handling and rollback from the public browser path are rehearsed
- the project can still recommend a narrower fallback posture if operators have
  not met those prerequisites

## Migration And Pilot Gate

Before Version 2 is considered complete, the repo must also show:

- a repo-owned workflow inventory for the intended pilot users, currently
  recorded in `PILOT_WORKFLOW_INVENTORY.md`
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
