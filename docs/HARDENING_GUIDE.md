# Hardening Guide

## Purpose

This document captures the hardening direction OSMAP should follow as design and
implementation continue.

## Network Restrictions

The project should preserve the current instinct toward narrow exposure:

- keep only required listeners reachable
- allow staged rollout behind the current narrow host posture when appropriate
- treat direct public exposure as an explicit gate, not as either an automatic
  default or an indefinitely deferred non-goal
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
- runtime external command execution goes through the shared Rust command
  executor, avoids shell interpolation, clears inherited environment variables
  down to a small fixed set, and enforces both a timeout and per-stream output
  byte cap on auth, `doveadm`, and sendmail paths

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

- keep the top-level OSMAP state root read-only
- read and write only the bounded OSMAP state subdirectories that actually
  need mutation
- bind one local TCP listener
- execute `/usr/local/bin/doveadm`
- execute `/usr/sbin/sendmail`

That map is now being used by a real OpenBSD confinement mode in the running
code. The helper side of that map now narrows its `doveadm` support view to
explicit loader, Dovecot config, and config-socket paths plus exact resolved
shared-library files on the validated host. The browser-facing `_osmap` side
now does the same for its auth-backed `doveadm` and local sendmail/Postfix
paths. The next hardening step is to remove or further narrow the remaining
directory fallbacks and host-shape assumptions without breaking the current
auth, mailbox, and submission slices.

## Remaining Resource-Exhaustion Work

The current implementation has concrete limits for HTTP body and header
parsing, concurrent connections, compose body size, attachment count and byte
size, mailbox listing, message-list parsing, message rendering, search query
shape, helper socket reads and writes, external command runtime, and external
command stdout/stderr capture. Those limits reduce obvious unbounded request
and backend hangs, but they are not a complete denial-of-service design.

The MIME/HTML regression corpus now lives under `tests/fixtures/mime/` and
covers encoded headers, multipart alternative, multipart mixed, nested
mixed/related messages, calendar invites, delivery-status notifications,
malformed boundaries, hostile active HTML, `cid:` image references, remote
resources, data URIs, suspicious attachment names, nested attachments, and
unsupported charset fallback behavior. The browser routes now also cap rendered
mailbox links, search-result rows, and attachment metadata rows even if an
upstream gateway hands them over-limit collections.

Slow synchronous request occupancy is tracked in
`REQUEST_WORKER_BUDGET_MODEL.md`. The current implementation now has the first
independent route-class worker budgets for authenticated message search and
message view, in addition to the global concurrent connection cap and
lower-level parser, helper, and command timeouts. Budget exhaustion fails fast
with `503 Service Unavailable`, `Retry-After`, and bounded audit events. The
browser runtime now also propagates `OSMAP_EXPENSIVE_REQUEST_TIMEOUT_SECONDS`
into helper-backed search and message-view calls so admitted budget slots have
a hard helper-client route cap. The next hardening pass should extend the same
model to send/auth paths and the remaining expensive routes. Adjacent controls
such as nginx request limits, PF, and host monitoring remain part of the
credible DoS posture.
