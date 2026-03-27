# Deployment OpenBSD

## Purpose

This document records the OpenBSD deployment direction for OSMAP. It is still
pre-implementation, but the hosting strategy is clear enough to define now.

## Target Environment

OSMAP is intended for deployment on OpenBSD in an environment that already uses
OpenBSD-native operational tooling and a conservative mail-stack layout.

The deployment model should assume:

- OpenBSD is the primary supported operating system
- the existing mail stack remains authoritative
- an OpenBSD-friendly edge layer such as nginx remains part of the environment
- the application may initially coexist with the current VPN-first access model

## Current Prototype Deployment Shape

The current implemented prototype is small enough to describe concretely:

- `nginx` remains the public-facing TLS edge
- OSMAP serves HTTP on a local TCP listener
- development mode requires a loopback listener
- staging or production should also prefer loopback-only exposure behind nginx
- Dovecot remains authoritative for auth and mailbox reads
- the local sendmail compatibility surface remains authoritative for outbound
  submission handoff

At the current implementation stage, a local TCP listener is the truthful
deployment target. Unix sockets remain a possible later refinement, but they
are not yet part of the running code path.

## Filesystem Layout

The deployment should use a layout that is:

- predictable
- minimally writable
- understandable to operators
- compatible with privilege separation and restricted filesystem visibility

Application runtime state, logs, secrets, and static assets should be separated
deliberately rather than mixed into a broad writable tree.

Current OSMAP state boundaries already map to:

- `run`
- `sessions`
- `audit`
- `cache`
- `secrets/totp`

This is a useful starting point for OpenBSD file ownership and confinement work.

## Service Accounts

The runtime should avoid unnecessary root privileges.

Expectations:

- dedicated service accounts where practical
- no root-owned long-running app processes unless strictly required
- separation of roles between edge, app, and supporting service contexts where
  the architecture allows

## Permission Model

The deployment should make it easy to answer:

- which process can read secrets
- which process can reach mail backends
- which directories are writable
- which network paths are required

This should align with OpenBSD-native least-privilege design and make
`pledge(2)` and `unveil(2)` adoption feasible where appropriate.

## Reverse Proxy Configuration

The edge layer should:

- terminate TLS cleanly
- forward only the minimum required headers and paths
- avoid exposing unused routes
- support staged deployment behind the existing VPN-first model
- proxy to the application service over loopback rather than exposing the app
  service directly

The web edge should not become a dumping ground for unrelated convenience
features.

Useful first reverse-proxy expectations now include:

- pass `Host`
- pass `X-Real-IP`
- pass `X-Forwarded-For`
- pass `X-Forwarded-Proto`
- restrict methods to `GET` and `POST` for the current slice
- keep buffering and auxiliary edge behavior conservative until needed

## Logging Integration

Deployment should provide logs that operators can actually use to investigate:

- authentication failures
- suspicious session activity
- submission abuse
- unexpected app behavior

Logs should be easy to retain, review, and correlate with surrounding host
events.

## Backup Integration

The deployment model should clearly identify:

- what must be backed up
- what must not be treated as authoritative state
- how secrets and configuration are protected
- how rollback would be performed if deployment fails

## Upgrade Strategy

A credible OpenBSD deployment strategy should support:

- predictable upgrade steps
- rollback awareness
- minimal assumptions about orchestration complexity
- packaging and service-management approaches that feel native to OpenBSD

## Hosting Strategy

The default hosting strategy should remain conservative:

- favor simple single-host or small-footprint deployments first
- preserve the existing VPN-first option until broader exposure is justified
- keep the runtime and dependency model small enough that an operator can
  understand it end to end

Preferred Phase 4 baseline:

- nginx on the host edge
- one small OSMAP application service behind nginx
- existing Dovecot and Postfix services left authoritative
- minimal app-local state stored separately from static assets and secrets

Current prototype-specific deployment guidance:

- keep OSMAP on `127.0.0.1:<port>` behind nginx
- keep OSMAP under a dedicated service user once the service-management layer is
  written
- keep the state tree owned narrowly enough that later `unveil(2)` policy can
  be practical
- keep `doveadm` and `sendmail` execution paths explicit and reviewable
- use `OSMAP_OPENBSD_CONFINEMENT_MODE=log-only` or `enforce` when validating
  the OpenBSD serve runtime on hosts intended for real deployment

This is more likely to produce a system that OpenBSD operators, and eventually
potential downstream packagers, would consider credible.
