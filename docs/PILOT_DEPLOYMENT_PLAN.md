# Pilot Deployment Plan

## Purpose

This document records the current pre-pilot deployment plan for OSMAP.

The project is not yet in active pilot rollout, but it now has enough
implementation depth, host validation, and operator scaffolding to define the
entry criteria and operating shape for a future small-user pilot.

## Pilot Objective

The pilot should prove that the current bounded OSMAP feature set can replace
Roundcube for a small trusted user group without destabilizing the underlying
mail platform or overstating production readiness.

## Pilot Scope

The pilot should remain intentionally small:

- one validated OpenBSD host shape at a time
- a small trusted user population
- browser-mail workflows only
- native clients left fully supported
- Roundcube retained as rollback path during the pilot window

The pilot should not be treated as general public launch.

## Entry Criteria

Do not start the pilot until all of the following are true:

- the authoritative Version 1 closeout gate passes on the intended pilot host
  or an equivalent deployment shape
- the deployed snapshot is synced to the reviewed `origin/main` state
- the helper-backed `_osmap` plus `vmail` runtime split is in place
- nginx, auth-socket, userdb-socket, and helper-socket integration are stable
- rollback to Roundcube has been rehearsed
- the selected pilot users understand the current product limitations

## Supported Pilot Workflows

The pilot may rely on the currently implemented bounded workflows:

- login with password plus TOTP
- mailbox listing, message view, attachment download, and search
- compose, reply, forward, bounded attachment upload, and send
- one-message move plus the archive shortcut
- session self-management and logout
- the limited settings surface for HTML display preference and archive mailbox

## Known Pilot Constraints

The pilot should be communicated with the current limitations up front:

- OSMAP remains prototype-grade
- draft persistence is not available
- reply and forward do not automatically reattach original attachments
- folder organization remains intentionally smaller than legacy webmail
- broader request-abuse hardening still depends on nginx, PF, and operator
  monitoring

Any user whose daily workflow depends on those missing behaviors should not be
treated as an early pilot candidate.

## Recommended Pilot Posture

The conservative first pilot posture is:

- keep the current VPN-first or similarly narrow exposure model
- keep nginx at the TLS edge
- run OSMAP `serve` as `_osmap`
- run OSMAP `mailbox-helper` as `vmail`
- keep mailbox reads behind the helper socket boundary
- keep OSMAP state and helper state on separate explicit roots
- keep OpenBSD confinement in `enforce` once the pilot snapshot is validated

## Day-One Pilot Checklist

Before pilot users start:

1. run `osmap bootstrap` or equivalent config validation with the pilot env
   files
2. confirm helper socket creation and connectivity
3. rerun the current closeout wrapper and archive the report
4. confirm rollback instructions are available to the operator
5. confirm incident notes and operator contacts are current

## Pilot Success Signals

The pilot is going well when:

- pilot users complete routine browser-mail workflows without falling back to
  Roundcube for normal use
- no auth, send, message-move, or helper-boundary regressions appear
- operator logs remain understandable and sufficient for triage
- closeout reruns still pass after any pilot-facing fix

## Abort Or Pause Conditions

Pause the pilot and prefer rollback if:

- browser auth or session behavior becomes unreliable
- send or message-move behavior raises integrity concerns
- helper-boundary or confinement failures require unsafe permission widening
- logs are insufficient to understand suspected abuse or malfunction
- the underlying mail platform is put at risk

## Exit Criteria

The pilot can be considered complete when:

- the chosen pilot group can rely on OSMAP for the required bounded workflows
- Roundcube fallback is no longer needed for ordinary use by that group
- operators are satisfied with incident handling, rollback confidence, and
  closeout repeatability
- the remaining known limitations are acceptable for the intended next rollout
  stage
