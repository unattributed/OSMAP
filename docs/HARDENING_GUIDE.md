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

## Secret Handling

Hardening expectations include:

- keep secrets out of the repo and public docs
- limit which processes can read sensitive material
- avoid casual duplication of auth and session secrets across components
- document secret ownership and rotation expectations

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
