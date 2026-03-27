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

## Filesystem Layout

The deployment should use a layout that is:

- predictable
- minimally writable
- understandable to operators
- compatible with privilege separation and restricted filesystem visibility

Application runtime state, logs, secrets, and static assets should be separated
deliberately rather than mixed into a broad writable tree.

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

The web edge should not become a dumping ground for unrelated convenience
features.

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

This is more likely to produce a system that OpenBSD operators, and eventually
potential downstream packagers, would consider credible.
