# Session Management Model

## Purpose

This document records the first implemented OSMAP session-management baseline.

The goal of this slice is to prove that browser session issuance can be kept
bounded, auditable, and operator-visible without introducing a large framework
or hiding important state in implicit runtime behavior.

## Status

As of March 28, 2026, the prototype now includes a real runtime session layer
plus a first browser-visible session-management page.

That layer currently covers:

- opaque session token issuance after successful MFA
- token validation against persisted session state
- explicit revocation for logout-style and operator-driven paths
- per-user session listing for visibility
- per-session CSRF token state for the current browser runtime
- a browser-visible session list for the current user
- self-service revocation of persisted session records from the browser
- structured session audit events

This is the first usable session core, not the final browser/session design.

## Current Session Shape

The current implementation uses:

- a high-entropy random browser token
- a SHA-256-derived persisted session identifier
- one file-backed session record per active or historical session
- one per-session CSRF token stored with the bounded session record
- explicit `issued_at`, `expires_at`, `last_seen_at`, and `revoked_at` fields
- the canonical username, second-factor type, remote address, and user-agent
  summary as operator-visible metadata

The browser-facing token and the persisted session identifier are intentionally
not the same value.

## Token Model

The current token model follows these rules:

- session tokens are generated from 32 random bytes
- the browser token is hex-encoded for transport simplicity
- presented tokens must match the exact expected format and length
- debug output redacts the bearer token
- the on-disk store keeps only the SHA-256-derived session identifier
- the CSRF token is derived from the same bearer token with a separate label so
  it remains stable for the session without reusing the session identifier

This does not make a stolen session harmless, but it does avoid casually
storing raw bearer tokens in local files.

## Persistence Model

Session records are stored under the configured session directory inside the
explicit OSMAP state root.

The current file-backed model is intentionally small:

- create the session directory on demand
- write records as a line-oriented format
- use an atomic temp-file-plus-rename path
- set restrictive permissions on Unix-like systems
- keep records simple enough to inspect during early implementation

This is a proof-of-concept persistence model, but it already preserves the
important security boundary: session state stays inside the bounded mutable
state tree.

## Lifetime And Validation Rules

The current runtime enforces:

- a required positive session lifetime in seconds
- explicit expiration timestamps on issued sessions
- validation failure for expired sessions
- validation failure for revoked sessions
- CSRF-token matching on the currently implemented state-changing browser routes
- last-seen updates on successful validation

These controls keep lifetime and revocation behavior explicit from the first
implementation slice instead of treating them as cleanup work for later phases.

## Logout And Revocation Model

The runtime currently supports two revocation paths:

- revoke by presented token for logout-style behavior
- revoke by persisted session identifier for operator-oriented handling

Both paths record `revoked_at` and emit a structured session audit event.

This is important because "logout" is not being treated as a UI nicety. It is
implemented as state transition and audit event generation in the runtime core.

## Visibility Model

The current visibility model is intentionally narrow but useful:

- sessions can be listed for a canonical user
- results include issuance, expiry, last-seen, revocation, remote address, and
  user-agent summary
- the records are sorted by newest issuance first

This gives operators and browser-facing code a concrete substrate for session
visibility without inventing a heavy device-management system too early.

## Logging And Audit Posture

The session layer emits structured session events for:

- session issuance
- session validation
- session revocation

Current event fields include:

- session identifier
- canonical username
- issued, expiry, or revocation timestamps as applicable
- factor type
- request identifier
- remote address
- user-agent summary

These events are intended to support later incident review and suspicious
session investigation.

## Security Posture

The current session slice deliberately favors explicitness over convenience:

- session lifetime is bounded by configuration
- logout is a real revocation path
- raw bearer tokens are not written to the file-backed store
- non-required SHA-1 is no longer used in session or CSRF derivation
- the browser runtime uses a strict cookie posture around the session token
- session metadata is small enough to inspect and test directly
- session issuance still depends on a completed primary-auth plus TOTP path

This keeps the runtime aligned with the Phase 3 and Phase 4 security model
instead of drifting toward an opaque convenience-first session layer.

## Validation Status

The current validation state is:

1. local Rust unit and runtime verification completed
2. an end-to-end test now exercises primary auth, real TOTP verification, and
   session issuance together
3. OpenBSD host validation on `mail.blackbagsecurity.com` remains part of the
   implementation workflow for this slice

The QEMU wrapper layer remains available for broader isolated OpenBSD testing as
later browser and mailbox work increases integration risk.

## What Is Still Missing

This slice does not yet include:

- rate limiting for session creation or validation abuse
- stronger session fixation defenses around future auth-flow refinements
- persistent audit-log storage beyond the current structured event stream
- richer device interpretation, geolocation, or anomaly scoring around the
  current session metadata
- operator-facing session revocation controls in the browser layer

Those belong to the later HTTP and mailbox/runtime slices rather than to this
state-and-lifecycle foundation.
