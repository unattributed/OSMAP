# Request Worker Budget Model

## Purpose

This document records the Version 3 design direction and first implementation
slice for slow synchronous request occupancy.

OSMAP already has a bounded concurrent connection cap, request read/write
timeouts, external command timeouts, helper I/O limits, parser limits, and
route-level rendered collection caps. Those controls bound many obvious
resource paths. The worker-budget slice now also distinguishes cheap routes
from expensive authenticated search, mailbox, send, and auth work once a
request has entered a worker thread.

Future slices should extend the same model without rewriting the server around
a broad async stack.

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
- enforces `OSMAP_SEARCH_WORKER_BUDGET` around message search and
  all-visible-mailbox search
- enforces `OSMAP_MAILBOX_WORKER_BUDGET` around browser message view,
  compose reply/forward source loading, message move, and attachment download
- enforces `OSMAP_SEND_WORKER_BUDGET` around compose submission
- enforces `OSMAP_AUTH_WORKER_BUDGET` around login work that reaches the
  external auth/TOTP path

This is simple and auditable. Remaining V3 resource work should be treated as
evidence-driven hardening of specific newly identified route classes, not as a
reason to replace the current synchronous OpenBSD-friendly runtime shape.

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

Use a small set of independent fail-fast counters inside the browser runtime:

| Budget | Applies to | Initial direction |
| --- | --- | --- |
| connection slots | accepted TCP connections | existing `OSMAP_HTTP_MAX_CONCURRENT_CONNECTIONS` |
| authenticated mailbox workers | message view, compose source loading, message move, attachment download | lower than connection slots |
| search workers | mailbox search and all-visible-mailboxes search | implemented; lower than mailbox workers; all-mailbox search consumes one search slot for the whole aggregate request |
| send workers | compose submission through sendmail | lower than connection slots and still submission-throttled |
| auth workers | password/TOTP login path reaching external auth | low, with existing login throttles still first line of defense |

The first implementation uses fail-fast admission instead of internal queues.
When a budget is exhausted, it returns `503 Service Unavailable` with a short
`Retry-After` and an audit event such as `request_budget_exhausted`.

## Deadline Propagation

The current implementation adds route-level deadline propagation for
helper-backed message search, message view, message move, and attachment
download; direct `doveadm` message search/view/move commands; sendmail-backed
compose submission; and the external-auth stage of login.
`OSMAP_EXPENSIVE_REQUEST_TIMEOUT_SECONDS` is read during startup, reported in
the non-secret bootstrap summary, and propagated into the browser-facing helper
client policy or command timeout for those expensive route classes.

All-visible-mailbox search also computes one aggregate fanout deadline for the
route. Each per-mailbox search backend is built with the remaining whole-second
deadline budget, and the route fails with a generic temporary-unavailable
result if the deadline is exceeded while walking visible mailboxes. The
corresponding audit event records counts and the deadline, not the private
search query or mailbox contents.

The deadline should:

- be computed once near route admission
- be passed to external command/helper calls where possible; implemented for
  helper-backed search/view/move/attachment work, direct `doveadm`
  search/view/move commands, sendmail, and external auth commands
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

The first implemented configuration is:

- `OSMAP_HTTP_MAX_CONCURRENT_CONNECTIONS`
- `OSMAP_MAILBOX_WORKER_BUDGET`
- `OSMAP_SEARCH_WORKER_BUDGET`
- `OSMAP_SEND_WORKER_BUDGET`
- `OSMAP_AUTH_WORKER_BUDGET`
- `OSMAP_EXPENSIVE_REQUEST_TIMEOUT_SECONDS`

Each value rejects zero and defaults conservatively when absent. The route
budgets must not exceed the connection cap.

Planned later configuration:

- additional route budgets if new expensive route classes are added

## Required Tests

The implementation gate should include tests for:

- cheap routes still working while an expensive budget is full; implemented for
  login while search is saturated
- mailbox budget exhaustion returning `503` and releasing after completion;
  implemented for message-view failure and success retry, compose source
  loading, message move, and attachment download
- search budget exhaustion returning `503` with `Retry-After`; implemented for
  the shared search budget, including all-mailbox search fanout
- send budget exhaustion without bypassing session/CSRF validation; implemented
  for the compose submission route
- auth budget exhaustion without leaking which credential stage would have run;
  implemented for the login route before the gateway auth call
- budget guard release on backend error; partially implemented through
  message-view unavailable regression
- budget guard release on timeout; implemented for helper-backed
  mailbox/search/message-view helper socket timeouts, and now backed by
  route-level timeout propagation for helper-backed search/message
  view/move/attachment work, direct `doveadm` search/view/move commands,
  sendmail-backed submission, and external-auth login
- budget guard release on worker panic; implemented for the shared guard
- no session id, bearer token, CSRF token, password, TOTP code, message body, or
  attachment body in budget logs; implemented for search-budget events

## Rollout Plan

1. Add a small budget guard type and unit tests independent of HTTP routes.
   Done for the shared atomic guard.
2. Wire the guard to the runtime gateway around expensive route classes.
   Done for message search, message view, compose source loading, message move,
   attachment download, send, and login.
3. Add route tests for exhausted budgets and release behavior.
   Done for search exhaustion, cheap-route availability, message-view release,
   compose source loading, message move, attachment download, all-mailbox
   search fanout, panic release, and log redaction.
4. Add config parsing with zero-value rejection.
   Done for mailbox and search budgets, including connection-cap validation.
5. Add operator docs and live-safe validation for one budget exhaustion path.
   The release gate now requires
   `maint/live/osmap-v3-resource-timeout-evidence-2026-05-02.txt` plus
   `maint/live/latest-host-v3-resource-controls-report.txt`, which cover
   helper-backed mailbox-list, message-search, and message-view helper timeout
   tests; current search/mailbox/send/auth budget and HTTP timeout
   regressions; and live helper-backed route-budget evidence for compose source
   loading, attachment download, all-mailbox search fanout, and message move.
6. Extend the guard to send and auth route classes, then add request-deadline
   propagation.
   Done for send/auth and then extended to the remaining expensive browser
   route classes listed above.
7. Only then consider a deeper worker-pool or async design if evidence shows
   the small budget model is not enough.
