# Incident Response Plan

## Purpose

This document records the public-safe incident response baseline for the
current OSMAP prototype and the validated OpenBSD deployment posture around it.

The project is still prototype-grade, but it now has enough logging, session
control, closeout automation, and deployment structure to justify a real
operator response plan instead of a stub.

## Response Goals

When an incident or suspected incident affects OSMAP, the operator response
should prioritize:

- protecting mailbox accounts and active sessions
- preserving the integrity of the underlying mail stack
- containing abuse without widening the web-facing trust boundary
- preserving enough evidence to understand what happened
- restoring a known-good bounded deployment shape

## Incident Types In Scope

This plan should be used for events such as:

- suspected credential attack or repeated browser-login abuse
- suspicious session creation, reuse, or revocation behavior
- suspicious browser send or message-move activity
- unexpected helper-boundary, auth-socket, or confinement failures
- malformed-request or connection-pressure behavior that suggests active abuse
- evidence that the validated host or OSMAP runtime may be compromised

## Roles

The project assumes a small operator team. One person may hold more than one
role, but the responsibilities should remain distinct:

- primary operator: triage, containment, and service-level decisions
- mail-stack owner: verify Postfix, Dovecot, nginx, and adjacent controls
- repo maintainer: assess code, config, release state, and validation scripts

## Detection Inputs

Operators should gather evidence from:

- OSMAP structured logs
- nginx access and error logs
- Dovecot and Postfix logs
- PF or host firewall observations where available
- current session records and revocation behavior
- repo-owned validation wrappers and closeout reports
- direct user reports of failed login, unexpected sends, or missing access

## Initial Triage

At the start of an incident:

1. Record the time window, affected accounts, affected host, and observed
   symptoms.
2. Decide whether the issue is primarily auth abuse, session abuse, message
   abuse, availability pressure, or suspected host compromise.
3. Preserve the current git revision, deployment mode, and confinement mode in
   the incident notes.
4. Avoid changing more than necessary until the containment objective is clear.

If there is credible evidence of host compromise, treat that as more severe
than an application-only fault and prefer host-level containment immediately.

## Containment Actions

Use the narrowest action that safely stops ongoing harm.

### Account Or Session Abuse

- revoke affected sessions through the current session surface or by removing
  the relevant persisted session state
- rotate the affected mailbox password and, if warranted, the TOTP secret
- keep a record of which sessions were revoked and why

### Browser Send Or Message Abuse

- suspend or revoke the affected account sessions
- confirm whether throttle events fired as expected
- keep Postfix or adjacent mail controls in the loop rather than treating the
  browser event as isolated

### Service Or Boundary Failure

- if the helper socket, Dovecot socket boundary, or confinement posture has
  drifted, stop `osmap_serve` before widening permissions as a quick fix
- prefer restoring the documented `_osmap` plus `vmail` split-runtime shape
  over bypassing the helper boundary

### Suspected Host Compromise

- disable browser exposure at nginx or firewall level
- stop OSMAP services if leaving them running would destroy evidence or widen
  risk
- preserve host logs and relevant state before cleanup

## Evidence Preservation

Capture public-safe operational evidence before making broad changes:

- the relevant structured log excerpts
- nginx, Dovecot, and Postfix log windows
- the active OSMAP revision and any local config change notes
- the current closeout report, if one exists for the deployed snapshot
- the names of relevant env vars and paths, but not secret values

Do not commit secrets, raw mailbox credentials, or private host-only material
into the repository while documenting the incident.

## Recovery

After containment:

1. Restore the documented deployment posture and least-privilege boundaries.
2. Apply the smallest code or config correction that addresses the incident.
3. Run `osmap bootstrap` or the equivalent config validation path before
   restarting long-running services.
4. Rerun `make security-check` and the affected closeout-facing validation
   steps. If the incident changed release-facing behavior, rerun the
   authoritative closeout wrapper described in `V1_CLOSEOUT_SOP.md`.
5. Return to `OSMAP_OPENBSD_CONFINEMENT_MODE=enforce` once the corrected shape
   is proven again.

## Communications

For a small trusted-user deployment, communications should be direct and
truthful:

- tell affected users what changed in service availability or credentials
- avoid speculative statements until evidence exists
- record whether native-client access and the underlying mail stack remained
  unaffected

## Post-Incident Review

Every meaningful incident should end with a short review that records:

- root cause or best current explanation
- affected workflows and accounts
- whether existing logs and throttles were sufficient
- whether rollback, helper-boundary, or closeout procedures were adequate
- what doc, code, or operational change is now required

If the event exposes a gap in the release-facing proof set, update the related
docs and validation wrappers rather than relying on informal memory.
