# Version 3 Security Gates

## Purpose

This document defines the security evidence required before OSMAP Version 3 can
be described as daily-driver ready.

Version 3 adds user-facing workflow continuity, so its security gate must prove
that convenience did not erode the Version 2 least-privilege runtime, public
edge posture, or browser hardening.

## Required Carry-Forward Gates

All Version 2 gates remain mandatory:

- `make security-check`
- Version 2 readiness wrapper
- persistent service guard
- internet-exposure assessment
- edge-cutover and rollback evidence
- auth observability evidence
- public-send audit-correlation evidence
- helper peer-auth rejection evidence
- request guardrail evidence
- backend-unavailable behavior evidence
- CSRF and same-origin rejection evidence

Version 3 cannot pass by replacing or weakening any of these gates.

## Version 3 Gate Additions

| Gate | Required evidence |
| --- | --- |
| MIME and HTML regression | Unit or route tests plus live or fixture evidence for encoded headers, multipart alternatives, sanitized HTML, malformed MIME, inline `cid:` metadata, attachment metadata, and oversized input rejection. |
| Draft storage boundary | Tests and docs proving draft ownership isolation, restrictive state paths, bounded draft and attachment sizes, CSRF and same-origin enforcement, expired-session rejection, and deterministic cleanup behavior. |
| Reply/forward attachment safety | Tests proving selected original attachments are helper-fetched, revalidated at send time, included in aggregate limits, and not silently dropped after confirmation. |
| Richer search guardrails | Tests proving query validation, mailbox visibility limits, result caps, sorting determinism, invalid-query 400-class behavior, and backend-unavailable behavior. |
| Bounded bulk action safety | Tests proving selection caps, per-message revalidation, partial-result reporting, move/delete/archive policy limits, throttling or equivalent abuse controls, CSRF rejection, and same-origin rejection. |
| Session/device policy | Tests and docs proving the chosen concurrent-session policy, device labels, revocation semantics, idle and absolute timeout behavior, and isolated-cookie retest of the revoke-race scenario. |
| TLS CBC disposition | Archived evidence that TLS 1.2 CBC suites are removed, or a documented exception with owner, date, reason, expiry, compatibility evidence, and compensating controls. |
| WSTG regression | Current WSTG testing-pack run covering the V3 browser surface, with pass/fail/non-applicable disposition archived under `maint/live/` or a successor evidence path. |

## TLS CBC Rule

The preferred Version 3 outcome is removal of TLS 1.2 CBC suites from the
reviewed public-edge configuration.

An exception is allowed only when all of the following are documented:

- affected client population
- exact suites retained
- reason removal is not yet acceptable
- compensating controls
- named owner
- expiry date
- retest command and archived output

An exception without expiry does not satisfy the Version 3 gate.

## Session And Device Policy Rule

Version 3 must choose one policy and implement it consistently:

- allow concurrent sessions with clear device labels and user-driven
  revocation, or
- cap sessions per user or per device class with deterministic eviction or
  denial behavior

The chosen policy must be visible in documentation, user-facing session pages,
logs, and tests. The April 2026 revoke-race observation must be retested with
isolated cookie jars before it is classified as either fixed, not reproducible,
or a confirmed server-side defect.

## WSTG Regression Rule

The WSTG testing pack must be treated as a living regression suite for the
browser slice. When Version 3 adds or changes routes, update the pack or record
why an existing script already covers the route.

At Version 3 closeout, archive evidence for:

- baseline routes
- authentication and throttling
- logout and CSRF
- search and reflected-input handling
- settings and mass-assignment checks
- upload and attachment paths
- business-logic checks for draft, send, move, bulk action, session revocation,
  and workflow circumvention
- HTML, CSS, DOM, template, and client-side injection applicability
- CORS, clickjacking, XSSI, reverse-tabnabbing, and API reconnaissance checks
- TLS transport checks, including CBC disposition

## Failure Rule

If a Version 3 feature passes ordinary functional tests but fails one of the
security gates above, the feature remains incomplete. The remedy is either a
scoped fix, a documented out-of-scope deferral, or removal from the Version 3
boundary.
