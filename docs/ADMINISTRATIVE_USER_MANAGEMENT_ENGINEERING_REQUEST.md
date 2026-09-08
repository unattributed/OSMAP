# Administrative User Management Engineering Request

## Status

Phase 1 interim TOTP initial-provisioning capability delivered and
production-contract qualified. The broader administrative control plane remains
future work, and this status does not authorize retirement of PostfixAdmin.

## Purpose

Design a secure OSMAP administrative capability for managing mail identities,
domains, mailboxes, aliases, credentials, account status, and TOTP lifecycle.
The long-term objective is to replace the current PostfixAdmin dependency with a
smaller, purpose-built, reviewable control plane that follows OSMAP security,
maintainability, and governance requirements.

## Current State

- PostfixAdmin remains the operational interface for mail-domain, mailbox, and
  alias administration.
- OSMAP authenticates existing mailbox users and requires TOTP for browser
  access.
- OSMAP now includes a reviewed interim operator CLI for canonical mailbox
  identity checks, read-only TOTP inspection, dry-run planning, and governed
  initial TOTP provisioning.
- Existing factors fail closed and are never implicitly overwritten or rotated.
  TOTP rotation, revocation, recovery, broader mailbox/domain/alias
  administration, and an administrative service or browser surface remain
  future work.
- PostfixAdmin must remain available until replacement capability, migration,
  rollback, and production evidence are complete.

## Engineering Objective

Provide a bounded administrative system that can safely perform the complete
mail-user lifecycle without exposing database credentials or privileged host
operations to the browser-facing OSMAP process.

The capability should begin with a reviewed operator tool and progress to an
administrative page only after the authorization, helper, audit, recovery, and
rollback boundaries are proven.

## Required Capability

The eventual administrative capability should support:

- domain creation, inspection, update, disablement, and retirement
- mailbox creation, inspection, password reset, disablement, and retirement
- alias creation, inspection, update, and removal
- explicit account-state and quota management where supported by the mail stack
- TOTP enrollment, verification, rotation, revocation, and recovery
- controlled session revocation after identity or factor changes
- dry-run output, explicit confirmation, validation, and reversible changes
- complete audit correlation without recording passwords, TOTP secrets, recovery
  material, or other sensitive values

## Security Requirements

The design must preserve OSMAP's narrow trust boundary and fail-closed posture.
At minimum, it must provide:

- a distinct administrative authorization boundary, separate from ordinary
  webmail access
- deny-by-default role and permission checks for every administrative action
- strong administrator authentication, MFA, bounded sessions, and
  reauthentication for high-risk operations
- CSRF, origin, Host, request-shape, and concurrency protections appropriate to
  privileged state changes
- a least-privilege administrative helper or service boundary, rather than
  direct browser-process access to mail databases, secret directories, or host
  administration commands
- cryptographically secure TOTP secret generation and one-time enrollment
  presentation
- strict prevention of secret disclosure through logs, audit records, command
  output, error responses, repository content, or browser history
- atomic or transactionally bounded changes with precondition checks and safe
  rollback
- canonical identity handling across OSMAP, Dovecot, Postfix, and the backing
  account data store
- explicit protection against cross-domain, cross-account, confused-deputy,
  replay, race, and partial-failure conditions
- immutable or tamper-evident audit records sufficient to reconstruct who
  changed what, when, through which authorized path, and with what result

## Delivery Sequence

### Phase 1: Operator Tool

The first bounded operator-tool slice is delivered for mailbox identity
inspection and initial TOTP provisioning. It provides read-only check, dry-run,
governed provisioning, local enrollment verification, fail-closed existing
factor handling, and bounded rollback on failed installation. Rotation,
revocation, recovery, and broader domain, mailbox, and alias administration
remain separate future slices.

### Phase 2: Administrative Service Boundary

Introduce a dedicated least-privilege helper or service with explicit typed
operations, authorization context, input validation, bounded resource use,
audit correlation, and negative-path tests.

### Phase 3: OSMAP Administrative Page

Add a separately authorized administrative page that invokes only the reviewed
administrative service boundary. The ordinary webmail process must not gain
general database, filesystem-secret, shell, or host-configuration authority.

### Phase 4: PostfixAdmin Migration And Retirement

Migrate existing administrative workflows only after capability parity,
production validation, operator acceptance, backup and restore testing, and a
successful rollback rehearsal. Remove PostfixAdmin exposure and dependencies
only through a separate reviewed retirement decision.

## Non-Goals

This request does not authorize:

- immediate removal or disabling of PostfixAdmin
- direct database administration from the browser-facing OSMAP process
- broad enterprise identity federation or multi-tenant SaaS administration
- weak self-service recovery that bypasses administrator authorization or MFA
- persistent display or retrieval of enrolled TOTP secrets
- unsupported bulk changes without dry-run, review, evidence, and rollback
- claims that current OSMAP releases already provide administrative replacement
  functionality

## Acceptance Gates

Implementation is not complete until evidence demonstrates:

- unauthorized and ordinary-user administrative requests fail closed
- administrative roles cannot exceed their documented scope
- mailbox, domain, alias, password, account-state, and TOTP operations preserve
  canonical identity and mail-stack consistency
- TOTP enrollment, verification, rotation, revocation, replay protection, and
  recovery paths are independently tested
- secrets and credentials are absent from logs, errors, evidence archives, and
  repository history
- concurrent, repeated, malformed, stale, and partially failed operations remain
  safe and deterministic
- each mutation produces attributable audit evidence and a verified post-change
  state
- backup, restore, rollback, and service-recovery procedures pass on the target
  OpenBSD environment
- the administrative surface is private by default and separately hardened
  before any network exposure
- independent security review and negative-path testing pass before production
  use


## Delivered Phase 1 Interim Evidence

The interim initial-provisioning slice is implemented by
`maint/live/osmap-provision-totp-over-ssh.sh`.

Fresh integration qualification on 2026-09-08 established:

- ShellCheck, local self-test, negative identity tests, the focused V3
  fail-closed regression, and the full developer security gate passed;
- the qualified operator script SHA-256 is
  `d6ea1d3926b0a00dfc6dff42ae872c95f85cc0799a547f0d80c6a467362e6634`;
- a production read-only `--check` confirmed an existing factor was a regular
  `_osmap:_osmap` file with mode `0600`;
- a production existing-factor `--dry-run` exited with the documented refusal
  status and `dry_run_disposition=existing_secret_refused`;
- the validation invoked no provisioning operation and performed no production
  mutation.

This evidence qualifies the delivered initial-provisioning boundary only. It
does not claim completion of rotation, revocation, recovery, the wider
administrative control plane, or PostfixAdmin migration and retirement.

## PostfixAdmin Retirement Criteria

PostfixAdmin must remain in service until all of the following are complete:

- an authoritative inventory of every required current administrative workflow
- approved OSMAP capability parity or an explicit disposition for each workflow
- successful migration and rollback rehearsals using production-representative
  data
- a defined coexistence period that prevents conflicting writes
- operator documentation, monitoring, incident response, and recovery procedures
- live production evidence covering representative domain, mailbox, alias,
  password, account-state, and TOTP operations
- a separately reviewed cutover and retirement plan
- verified removal of obsolete public routes, PHP dependencies, credentials,
  scheduled jobs, and database permissions that existed only for PostfixAdmin

## Required Engineering Artifacts

A future implementation should produce:

- requirements and threat model
- authorization and role model
- data ownership and mail-stack integration model
- administrative helper protocol and confinement design
- operator CLI specification and implementation
- TOTP lifecycle and recovery specification
- administrative page design only after the lower-level boundary is proven
- unit, integration, adversarial, concurrency, and live-host validation
- deployment, migration, coexistence, rollback, and retirement procedures
- sanitized evidence archives and release-governance records

## Decision Requested

Retain this document as the bounded engineering request and record the
interim initial-TOTP-provisioning slice as delivered. Remaining control-plane
capabilities should continue as separately reviewed slices. No PostfixAdmin
retirement claim is authorized until every acceptance and migration gate is
complete.
