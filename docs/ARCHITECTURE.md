# Architecture Overview

## Status

This document is still an early architecture baseline. It now reflects both:

- Phase 0 constraints
- Phase 1 facts about the current environment

It does not yet lock in a final implementation design.

## Architectural Starting Point

The replacement is being designed on top of an existing OpenBSD mail platform,
not into a vacuum. That platform already provides mail transport, mailbox
storage access, filtering, database services, VPN access, firewall policy, and
multiple control-plane applications.

## Architectural Direction

The replacement should be:

- narrow in scope
- explicit about boundaries
- compatible with existing IMAP and submission services
- realistic for a small team to operate
- safe to stage behind the current VPN-first model before any broader exposure

## Proposed Shape For Later Phases

The likely architecture direction is:

- a tightly scoped web interface
- a small backend service or service set
- a deployment model that reuses existing mail services where safe
- strong logging and operational visibility
- deliberate separation between public-safe docs, private secrets, and runtime
  state

## Constraints From The Current System

- nginx currently fronts multiple applications on the same host
- Roundcube currently lives at the host root behind nginx and PHP-FPM
- mail access for users is presently constrained to WireGuard paths
- native clients are already part of the supported access model
- current auth and submission behavior is shared across web and non-web clients

## Architectural Guardrails

- Do not expand version 1 into groupware
- Do not require replacement of the underlying mail services
- Do not assume current VPN-only exposure will disappear immediately
- Do not trade maintainability for feature ambition
- Do not couple design decisions to hidden private notes without creating a
  public-safe equivalent
- Prefer architectures that can take advantage of OpenBSD-native confinement
  mechanisms such as `pledge(2)` and `unveil(2)` where practical

## Immediate Next Architectural Questions

- Whether OSMAP should speak directly to IMAP/SMTP or place a narrower service
  layer in between
- What minimum webmail feature set is sufficient to retire Roundcube
- How identity and session controls can be improved without harming native
  clients
- What runtime isolation model best fits OpenBSD and the operator's maintenance
  budget
