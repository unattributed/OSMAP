# Request Worker Budget Model

## Purpose

This document records the Version 3 design direction for slow synchronous
request occupancy. It is a design baseline, not an implementation claim.

OSMAP already has a bounded concurrent connection cap, request read/write
timeouts, external command timeouts, helper I/O limits, parser limits, and
route-level rendered collection caps. Those controls bound many obvious
resource paths, but they do not yet distinguish cheap requests from expensive
authenticated mailbox, search, MIME, attachment, or send work once a request
has entered a worker thread.

The next runtime hardening step should add explicit work budgets without
rewriting the server around a broad async stack.

## Current Runtime Shape

The current serve runtime:

- accepts connections on the configured listener
- reserves one active-connection slot before spawning a worker thread
- rejects connections over `OSMAP_HTTP_MAX_CONCURRENT_CONNECTIONS` with `503`
  and `Retry-After`
- logs high-watermark, capacity, request-completion, accept-failure,
  response-write failure, worker-spawn failure, and worker-panic events
- enforces read and write timeouts around socket I/O
- enforces external process timeouts and output caps for auth, `doveadm`, and
  sendmail command boundaries

This is simple and auditable. The weakness is that the connection cap is the
only live occupancy budget. A small number of slow authenticated operations can
consume all request workers until their individual timeout or backend limit
fires.

## Design Goals

The worker-budget model should:

- keep the current no-framework, OpenBSD-friendly runtime shape
- bound expensive route occupancy independently from cheap routes
- fail closed with deterministic browser responses
- emit operator-visible budget events without logging bearer tokens, passwords,
  message bodies, attachment contents, or command details
- preserve existing per-command, per-helper, parser, and route caps
- make tests prove admission, rejection, slot release, timeout release, and
  panic release behavior

## Non-Goals

This design does not require:

- a full async runtime
- background mailbox indexing
- broad queueing semantics for user actions
- unbounded retry queues
- per-user mailbox content caching
- widening browser trust for HTML, images, attachments, or scripts

## Proposed Budget Dimensions

Start with a small set of independent semaphores or counters inside the
runtime gateway layer:

| Budget | Applies to | Initial direction |
| --- | --- | --- |
| connection slots | accepted TCP connections | existing `OSMAP_HTTP_MAX_CONCURRENT_CONNECTIONS` |
| authenticated mailbox workers | mailbox list, message list, message view, attachment download, move | lower than connection slots |
| search workers | mailbox search and all-visible-mailboxes search | lower than mailbox workers; all-mailbox search should consume one search slot for the whole aggregate request |
| send workers | compose submission through sendmail | lower than connection slots and still submission-throttled |
| auth workers | password/TOTP login path reaching external auth | low, with existing login throttles still first line of defense |

The first implementation should prefer fail-fast admission over internal
queues. When a budget is exhausted, return `503 Service Unavailable` with a
short `Retry-After` and an audit event such as `request_budget_exhausted`.

## Deadline Propagation

Each admitted expensive operation should carry a request budget deadline in
addition to existing lower-level timeouts.

The deadline should:

- be computed once near route admission
- be passed to external command/helper calls where possible
- never exceed the existing command timeout
- force a generic browser failure when exceeded
- release every budget guard on timeout or panic

This keeps one slow helper or command path from holding a route-class budget
longer than the route allows.

## Observability

Budget events should include:

- budget name
- action, such as `acquired`, `exhausted`, `released`, or `timed_out`
- active count
- configured maximum
- request id
- effective remote address
- route path or route class
- canonical username only after session validation succeeds

Budget events must not include session tokens, CSRF tokens, passwords, TOTP
codes, message bodies, attachment bytes, raw MIME content, or unbounded backend
diagnostics.

## Configuration

Keep the first configuration small:

- `OSMAP_HTTP_MAX_CONCURRENT_CONNECTIONS`
- `OSMAP_MAILBOX_WORKER_BUDGET`
- `OSMAP_SEARCH_WORKER_BUDGET`
- `OSMAP_SEND_WORKER_BUDGET`
- `OSMAP_AUTH_WORKER_BUDGET`
- `OSMAP_EXPENSIVE_REQUEST_TIMEOUT_SECONDS`

Each value should reject zero and should default conservatively when absent.
Budgets should not silently exceed the connection cap unless that is explicitly
documented and tested.

## Required Tests

The implementation gate should include tests for:

- cheap routes still working while an expensive budget is full
- mailbox budget exhaustion returning `503` and releasing after completion
- search budget exhaustion across all-mailbox search
- send budget exhaustion without bypassing submission throttles
- auth budget exhaustion without leaking which credential stage would have run
- budget guard release on backend error
- budget guard release on timeout
- budget guard release on worker panic
- no session id, bearer token, CSRF token, password, TOTP code, message body, or
  attachment body in budget logs

## Rollout Plan

1. Add a small budget guard type and unit tests independent of HTTP routes.
2. Wire the guard to the runtime gateway around expensive route classes.
3. Add route tests for exhausted budgets and release behavior.
4. Add config parsing with zero-value rejection.
5. Add operator docs and live-safe validation for one budget exhaustion path.
6. Only then consider a deeper worker-pool or async design if evidence shows
   the small budget model is not enough.
