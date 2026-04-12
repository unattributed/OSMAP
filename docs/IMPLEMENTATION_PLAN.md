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
CSRF enforcement on current state-changing routes. The send path now also has
server-side reply and forward draft generation with attachment-aware notices.
The deployment and hardening baseline now also includes explicit nginx-facing
guidance plus an implemented OpenBSD confinement mode.

The next active implementation work should focus on:

- using the project-local QEMU lab wrappers and `mail.blackbagsecurity.com` for
  targeted reruns of the existing proof set when closeout-facing behavior
  changes
- keeping the custom HTTP runtime on a narrow hardening track only when repo
  evidence shows a concrete correctness or availability blocker
- reconciling the remaining Version 1 gaps against the actual repo state so the
  next work is driven by real product deficits rather than stale assumptions
- preserving the now-frozen authoritative closeout gate in
  `ACCEPTANCE_CRITERIA.md` across `README.md`, `KNOWN_LIMITATIONS.md`,
  `OPENBSD_RUNTIME_CONFINEMENT_BASELINE.md`, and the current `DECISION_LOG.md`
  status entries
- preserving the current production `serve` posture around the mailbox helper
  boundary and the explicit OpenBSD dependency view instead of reopening direct
  mailbox authority from the web process

The current implementation now also includes:

- a bounded backend-authoritative search slice for one mailbox or all visible
  mailboxes
- a browser-visible session-management slice
- a first one-message move path between existing mailboxes
- a bounded dual-bucket application-layer login-throttling slice for the
  browser auth path
- a bounded dual-bucket application-layer submission-throttling slice for the
  browser send path
- a bounded dual-bucket application-layer message-move throttling slice for the
  first folder-organization path
- a first bounded safe-HTML rendering slice with allowlist sanitization and
  plain-text fallback
- a first bounded end-user settings slice for HTML display preference plus a
  settings-backed archive shortcut
- live-host proof for the safe-HTML rendering and settings slice on
  `mail.blackbagsecurity.com`
- live-host proof for the first bounded browser mutation flows on
  `mail.blackbagsecurity.com`, including one-message move and send
- live-host proof for the current bounded message-move throttle on
  `mail.blackbagsecurity.com`
- live-host proof for the bounded all-mailboxes browser search flow on
  `mail.blackbagsecurity.com`
- live-host proof for the bounded browser session-management surface on
  `mail.blackbagsecurity.com`, including `/sessions`,
  `POST /sessions/revoke`, and `POST /logout`
- a first explicit Version 1 mailbox-boundary freeze step: production
  `serve` mode now requires `OSMAP_MAILBOX_HELPER_SOCKET_PATH` instead of
  treating direct mailbox backends as an acceptable deployment shape

Broader ergonomics around folder organization, such as bulk actions or archive
shortcuts from list views, remain later refinements rather than the first move
slice itself.

The current highest-confidence active hardening and Version 1 gaps are:

- closeout drift between the implemented proof surface and the status-facing
  docs
- any concrete correctness or availability blocker still exposed by the
  bounded-concurrency HTTP runtime
- disciplined reruns of the repo-owned host proofs when closeout-facing
  behavior changes

The current HTTP hardening work has now also moved past generic parse
rejection for some connection-lifecycle cases. The runtime distinguishes:

- read timeouts, which now return `408 Request Timeout`
- empty connections, which now close without an HTTP response
- truncated requests, which now close as incomplete instead of being
  normalized into a generic `400 Bad Request`

That was a narrow resilience improvement for the earlier sequential listener.

The runtime now also applies bounded backoff after repeated accept failures,
handles accepted connections concurrently up to an explicit configured cap, and
emits central request-completion events for parsed requests with status,
response size, and duration. Over-capacity connections now receive `503
Service Unavailable` with `Retry-After`. Connection pressure is now surfaced
through high-watermark and capacity-reached events, and write-failure logs now
carry richer request/response context. Sustained listener accept-failure
streaks now escalate explicitly and emit a recovery event once accepts resume.
Sustained response-write failure streaks now also escalate explicitly and emit
their own recovery event once writes resume.

The bounded runtime observability path is now also host-proven on
`mail.blackbagsecurity.com` under `enforce` through an isolated one-slot
validation run that exercised capacity-reached, over-capacity rejection,
request-timeout, and request-completion events.

For repeat host-side validation on `mail.blackbagsecurity.com`, the standard
checkout is now `~/OSMAP`, and the repo-owned wrapper
`maint/live/osmap-host-validate.ksh` should be used to run `make
security-check` and related commands with home-local Rust temp and cache paths
instead of `/tmp`.

That is a bounded concurrency upgrade, but not a full production-grade
request-resource control story.

Even so, the current repo-grounded reassessment no longer treats the bounded-
concurrency listener as the single most obvious remaining production risk in
the system.

The folder-organization workflow has also now moved past the earlier
"technically present" threshold. OSMAP now has:

- a general one-message move path
- a settings-backed archive mailbox shortcut
- archive actions on both mailbox-list and message-view pages
- live-host proof that the settings route, rendered shortcut forms, and
  helper-backed move path all work together under `enforce`

That means the remaining missing items in folder organization, such as bulk
move and archive mailbox discovery beyond the explicit user setting, now read
more like later workflow refinements than the first active Version 1 blocker.

The recent route review also found that the remaining authenticated POST routes
in the current browser surface are:

- `POST /settings`
- `POST /sessions/revoke`
- `POST /logout`

Those routes are CSRF-bound, low-volume, and lower abuse value than login,
send, or message move, so there is not yet a comparably strong case for
another narrow per-route throttle slice.

The recent maintainability refactors in the browser and mailbox layers have
reduced the largest implementation hotspots enough that internal decomposition
is no longer the first active priority. The next implementation decisions
should be driven by the product and security gaps above unless a new review
finds a concentrated hotspot that materially harms auditability again.

## Current V1 Closeout Sequence

The authoritative Version 1 closeout contract is now frozen in
`ACCEPTANCE_CRITERIA.md`, and the current official closeout sequence is:

1. keep `README.md`, `KNOWN_LIMITATIONS.md`, the relevant baselines, and the
   current decision-log status aligned with that gate and with the successful
   April 11, 2026 host rerun
2. rerun affected repo-owned proofs through
   `ksh ./maint/live/osmap-live-validate-v1-closeout.ksh` on
   `mail.blackbagsecurity.com`, or through
   `./maint/live/osmap-run-v1-closeout-over-ssh.sh` from a reachable
   workstation, only when closeout-facing behavior changes
3. only take narrower implementation or hardening work when a failing proof or
   repo inconsistency reveals a real blocker

The current implementation should not widen browser scope casually while these
items remain open.

## Defer To V2

Unless a narrower first-release requirement is proven, the following should be
treated as Version 2 work:

- broader folder ergonomics beyond the first practical move/archive baseline
- richer search behavior beyond ordinary daily-use needs
- richer session or device intelligence beyond first self-service visibility
- broader attachment convenience behavior such as preview-heavy workflows
- broader settings surface beyond the first bounded preference
- deeper runtime redesign such as worker-pool or async server architecture

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
- documented proof of the selected least-privilege mailbox-read path on the
  target host
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
