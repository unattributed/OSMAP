# Migration Plan Roundcube

## Purpose

This document records the current public-safe migration baseline for replacing
Roundcube's core browser-mail role with OSMAP.

The project is not yet in general cutover. OSMAP remains prototype-grade, but
the repository now has limited direct-public browser exposure evidence, a
completed bounded Version 2 pilot, implemented workflow surface, host proof,
and deployment guidance. A formal migration plan is therefore more useful than
a stub.

## Migration Objective

The migration goal is narrow:

- replace Roundcube for the essential browser-mail workflows defined in the
  Version 1 product boundary
- preserve the existing OpenBSD mail stack as authoritative
- preserve native-client access during and after migration
- keep rollback to the legacy browser path straightforward until OSMAP is
  proven for the intended rollout group

This is not a "big bang" replacement of the whole mail platform.

## Current Readiness

The repo now provides real implementation and proof for:

- password-plus-TOTP browser login
- session issuance, listing, revocation, and logout
- mailbox listing, message-list retrieval, message view, and attachment
  download
- bounded search across one mailbox or all visible mailboxes
- compose, reply, forward, bounded attachment upload, and send
- one-message move plus a settings-backed archive shortcut
- safe HTML rendering with plain-text fallback
- helper-backed mailbox reads on the validated OpenBSD host
- a completed bounded Version 2 pilot for retrieve mail, send mail, and send
  mail with attachments

The repo does not yet prove a full production migration by itself. Important
limits still include:

- no draft persistence
- no original-message attachment reattachment in reply/forward flows
- no bulk message organization workflow
- prototype-grade rather than production-grade hardening posture

The migration plan should therefore start with low-disruption coexistence, not
immediate Roundcube retirement.

## Migration Principles

- keep IMAP, SMTP submission, and native clients unchanged
- treat limited direct public browser access as an evidence-gated posture that
  is currently approved for the validated Version 2 host shape, and repeat the
  exposure gate before any materially different rollout
- do not import risky Roundcube behavior only for parity theater
- avoid coupling migration success to Roundcube database or preference import
  unless a real blocker proves that necessary
- keep the Roundcube rollback path available until migration exit criteria are
  met for the chosen rollout group

## Preconditions

Before any broader real user migration begins, the operator should confirm:

- the authoritative Version 1 closeout gate passes on the intended host or an
  equivalent host posture
- the deployed snapshot matches the currently reviewed repo state
- the `_osmap` plus `vmail` helper-backed deployment shape is in place
- the operator has tested rollback of the browser path to Roundcube
- the affected user workflows have been checked against
  `PILOT_WORKFLOW_INVENTORY.md`, especially any current Roundcube-specific
  habits around drafts, attachment reuse, bulk actions, or filtering

## Recommended Migration Sequence

### 1. Workflow Inventory

Inventory the actual Roundcube behaviors relied on by the intended pilot users.
The current OSMAP product boundary is intentionally narrower than legacy
webmail, so migration should be driven by real required workflows rather than
by assumptions. Use `PILOT_WORKFLOW_INVENTORY.md` as the baseline operator
artifact for that confirmation.

### 2. Operator Shadow Use

Run or rerun OSMAP in a trusted operator posture first for any new rollout
group:

- keep Roundcube available
- keep native clients unchanged
- validate login, read, search, send, move, session, and settings flows on the
  intended host
- record any workflow blockers against the current Version 2 limitations

### 3. Small Pilot

The initial bounded Version 2 pilot is complete. For any future pilot rerun or
expansion, move only a small trusted user set to OSMAP for the supported
bounded workflows while Roundcube remains available as rollback and comparison
support. The pilot should follow `PILOT_DEPLOYMENT_PLAN.md`.

### 4. Controlled Default Switch

Only after the relevant pilot or expansion cohort is stable should OSMAP become
the default browser-mail entry path for the chosen user group. Keep Roundcube
reachable for rollback during the initial cutover window.

### 5. Legacy Retirement

Retire Roundcube only after:

- the required user workflows are confirmed on OSMAP
- the rollback window closes without unresolved blockers
- operators are satisfied with logs, closeout reruns, and helper-boundary
  stability

## Data And Preference Strategy

The current preferred migration posture is deliberately conservative:

- do not migrate Roundcube application state blindly
- keep OSMAP settings independent and intentionally small
- require any legacy preference or database import to justify its own risk

For the current Version 2 state, that means users should expect fresh OSMAP
browser settings rather than a promise that historical Roundcube preferences
will be ported.

## Workflow-Driven Cohort Selection

Future migration cohorts should prefer users whose daily browser-mail work
already fits the current inventory in `PILOT_WORKFLOW_INVENTORY.md`.

That means the current best-fit cohort is users who mainly need:

- login, read, search, attachment download, send, and light folder movement
- conservative HTML handling
- no dependency on drafts, bulk mailbox actions, or Roundcube-only filtering UI

Users whose daily workflow still depends on a `roundcube_fallback` item should
stay on the coexistence path until the operator is satisfied that fallback is
rare or no longer necessary.

## Rollback Strategy

Rollback must stay simple enough to use under pressure:

- keep the Roundcube installation and related state intact during migration
- keep nginx or the chosen edge path reversible
- keep OSMAP service accounts, env files, and helper socket boundaries separate
  so disabling OSMAP does not disturb native-client or core mail behavior
- prefer rollback to the last known-good browser path over ad hoc permission
  widening inside OSMAP

## Migration Exit Criteria

The migration can be considered successful for a given user group when:

- required browser-mail workflows are completed on OSMAP without falling back
  to Roundcube for normal use
- no blocker remains around auth, read, search, send, or required folder
  movement
- incident handling and closeout reruns remain operationally credible
- operators judge the remaining limitations acceptable for that user group

## Deferred Questions

These questions remain later-phase work rather than prerequisites for this
baseline migration plan:

- whether any Roundcube preference data is worth migrating at all
- whether broader folder ergonomics or draft persistence are mandatory for all
  target users
- whether any pilot cohort proves a narrow missing workflow is truly mandatory
  for migration-capable adoption
