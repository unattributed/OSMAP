# Implementation Plan

## Purpose

This document defines how OSMAP should move from architecture and governance
into controlled implementation work.

Phase 6 is not the point where the project becomes feature-maximal. It is the
point where the project proves that the chosen architecture can satisfy the
Version 1 product requirements without violating the security, operational, and
OpenBSD-oriented constraints already documented.

## Phase 6 Objective

The implementation objective for Phase 6 is to produce a narrow proof of
concept that demonstrates:

- browser authentication can be added without breaking the existing mail stack
- mailbox read flows can be served through the application layer
- outbound sending can use the existing submission model
- session state can be tracked and audited
- the implementation direction remains small enough to review and maintain

## Implementation Posture

Phase 6 should follow these execution rules:

- build the smallest useful vertical slice first
- keep the prototype behind the current trusted deployment boundary
- treat every new dependency as a review event
- prefer server-rendered or otherwise low-complexity browser behavior over a
  large client-heavy frontend
- avoid introducing new infrastructure until an existing component is proven
  insufficient

The project should prove a narrow path before investing in polish, convenience
features, or broad settings surfaces.

## Proposed Prototype Shape

The Phase 6 proof of concept should assume:

- one small OSMAP application service behind nginx
- a local-only application listener or Unix socket
- the existing Dovecot and Postfix services remain authoritative
- local OSMAP state remains intentionally small
- a browser interface that uses minimal JavaScript and avoids SPA complexity

This preserves the Phase 4 architecture while keeping implementation small
enough to reason about.

## Workstreams

### Workstream 1: Runtime Foundation

Build the minimum runtime needed to start the service safely:

- process entrypoint
- configuration loading
- structured logging
- local state abstraction
- error handling model
- operator-visible health behavior

The purpose of this workstream is to establish a disciplined spine for the rest
of the implementation.

### Workstream 2: Authentication And Session Baseline

Implement the smallest security-critical user entry path:

- credential submission
- MFA challenge flow
- session issuance
- session validation
- logout and revocation behavior
- audit events for authentication outcomes

This workstream should be treated as the first high-risk implementation slice.

### Workstream 3: Mailbox Read Path

Implement the basic mailbox access slice:

- folder listing
- message list retrieval
- message view
- attachment retrieval path
- safe rendering policy enforcement

This slice demonstrates that the application can consume the existing IMAP path
without trying to become a second mail platform.

### Workstream 4: Send Path

Implement the minimum outbound send behavior:

- compose input handling
- reply and forward shape
- attachment upload handling
- submission handoff to the existing mail path
- audit visibility for send actions

### Workstream 5: Operational Verification

Add the minimum controls needed to evaluate the prototype responsibly:

- useful logs
- explicit error visibility
- basic integration checks
- staging notes for isolated validation
- performance observation capture

### Workstream 6: OpenBSD Runtime Hardening

As soon as the service shape is stable enough to support it, the implementation
should be evaluated for:

- dedicated runtime user and file ownership
- configuration and state path separation
- practical `pledge(2)` use
- practical `unveil(2)` use
- loopback or local-socket-only connectivity

Hardening should not be postponed until after the prototype is large.

## Sequencing Strategy

The preferred sequence is:

1. Runtime foundation
2. Login plus session baseline
3. Mailbox listing and message read
4. Message send path
5. Logging and audit tightening
6. Confinement and deployment shaping
7. Integration validation and performance observations

This sequence keeps the project on a thin vertical-slice path instead of a
horizontal "build every subsystem halfway" path.

WP0, WP1, and WP2 are now in place. WP3 now provides bounded credential
handling, a real Dovecot-oriented primary-auth path, and a real TOTP-backed
second-factor stage. WP4 now has a first real session-management baseline with
issuance, validation, revocation, and per-user visibility behavior. WP5 now
has mailbox-listing and message-list retrieval primitives behind the
validated-session gate. WP6 now has a first bounded message-view retrieval
slice on top of that read-path baseline, a first plain-text rendering policy
layer on top of the fetched message payload, and a dependency-light MIME-aware
attachment-metadata baseline for common mail layouts. The first bounded
HTTP/browser slice now exists too, including real request parsing, routing,
server-rendered HTML, session-cookie handling, a first compose/send path, and
CSRF enforcement on current state-changing routes. The deployment and hardening
baseline now also includes explicit nginx-facing guidance and an early OpenBSD
confinement map.

The next active implementation work should focus on:

- using the project-local QEMU lab wrappers and `mail.blackbagsecurity.com` for
  continued OpenBSD validation as the runtime broadens
- extending the send path toward reply, forward, and attachment-aware handling
  without discarding the current narrow HTTP and rendering posture
- validating the nginx-facing and OpenBSD confinement plan against real host and
  QEMU deployment steps
- carrying the current session model into broader browser-state handling
  without collapsing the security boundaries that now exist

## Implementation Guardrails

The following behaviors should be treated as Phase 6 anti-patterns:

- choosing a large framework before proving the required workflows
- building a broad administrative interface
- introducing public-internet exposure during the first prototype
- treating the proof of concept as a reason to relax review or release rules
- adding features that are not required by the Phase 6 control block

## Evidence Of Progress

Phase 6 progress should be demonstrated with evidence, not optimism.

Expected evidence includes:

- a running prototype in an isolated environment
- logs showing authentication and mailbox activity
- integration notes against the existing mail stack
- documented constraints discovered during implementation
- explicit updates to the decision log when major tradeoffs are made
- isolated validation notes from the QEMU OpenBSD path before wider host use

## Exit Shape

Phase 6 should be considered ready to close only when:

- the proof of concept demonstrates the required login, mailbox, send, and
  session behaviors
- the prototype does not destabilize the current host role
- the project has enough implementation evidence to begin focused subsystem
  refinement in later phases
- known blockers and architectural risks are captured honestly
