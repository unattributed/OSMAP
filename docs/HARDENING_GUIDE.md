# Hardening Guide

## Purpose

This document captures the hardening direction OSMAP should follow as design and
implementation continue.

## Network Restrictions

The project should preserve the current instinct toward narrow exposure:

- keep only required listeners reachable
- prefer staged rollout behind the current VPN-first posture
- treat public exposure as a later, explicit decision
- avoid opening convenience ports or auxiliary surfaces without strong reason

## Exposure Rules

The deployed application should expose:

- only the paths needed for Version 1 mail workflows
- no plugin or scripting surface
- no mixed user/admin interface beyond what is strictly necessary
- no unnecessary backend reachability from edge-exposed components

## Isolation Model

The architecture should favor:

- least-privilege service boundaries
- minimal writable paths
- minimal network reachability between components
- OpenBSD-native confinement via `pledge(2)` and `unveil(2)` where practical
- deployment layouts that make process isolation understandable to operators

## Browser Hardening Baseline

The implemented browser slice now sets a real baseline that later work must
preserve or improve:

- `HttpOnly` session cookies
- `SameSite=Strict` session cookies
- `Secure` cookies outside development
- CSRF tokens on current state-changing form routes
- restrictive CSP on HTML responses
- `no-store` handling for sensitive pages
- frame and content-type hardening headers
- server-rendered pages without a JavaScript dependency

Future work should build on this posture rather than relaxing it for
convenience.

## Secret Handling

Hardening expectations include:

- keep secrets out of the repo and public docs
- limit which processes can read sensitive material
- avoid casual duplication of auth and session secrets across components
- document secret ownership and rotation expectations

The current runtime already gives those controls a concrete home:

- TOTP secrets under the dedicated OSMAP secret path
- session material under the dedicated OSMAP session path
- no raw session bearer tokens written to the persisted session store

## Configuration Protections

Configuration should be:

- explicit
- auditable
- environment-appropriate
- resistant to accidental weakening by convenience changes

The project should avoid configuration sprawl that makes secure review harder.

## Failure Modes

The system should fail in ways that are:

- visible
- recoverable
- understandable to operators

Security-sensitive failures should not silently degrade into an unsafe mode.

This principle now applies directly to the browser and submission paths:

- invalid CSRF values fail closed
- invalid compose input fails closed
- backend execution failures become bounded user-visible failures plus audit
  events

## Maintenance Considerations

Hardening is only credible if it remains operable.

The project should therefore prefer:

- controls that a small team can actually maintain
- fewer moving parts over larger "security stacks"
- security posture that improves operator understanding instead of depending on
  obscurity

## OpenBSD Alignment

If the project aims to be respectable in OpenBSD-oriented environments, its
hardening strategy should look like it belongs there:

- privilege separation where meaningful
- conservative defaults
- explicit file and process boundaries
- predictable behavior without Linux-specific assumptions
- practical use of the operating system's built-in security features

## Early Confinement Plan

The current code shape is now small enough to map the likely confinement
surface:

- read and write the bounded OSMAP state tree
- bind one local TCP listener
- execute `/usr/local/bin/doveadm`
- execute `/usr/sbin/sendmail`

That means later `pledge(2)` and `unveil(2)` work should be driven by the real
access graph rather than by generic promises. The next hardening step is to
turn this map into tested runtime enforcement on OpenBSD without breaking the
current auth, mailbox, and submission slices.
